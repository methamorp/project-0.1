"""
Worker

Konsumsi domain baru dari Redis Stream (didorong oleh collector), lakukan:
  1. DNS resolve check -- pastikan domain benar-benar aktif
  2. HTTP(S) probe      -- ambil headers dan HTML
  3. Tech fingerprinting -- deteksi CMS/framework/server dari hasil probe
  4. Liveness check      -- pastikan situsnya benar-benar berjalan (bukan
     zombie/parked/default page), simpan ke PostgreSQL HANYA kalau lolos
  5. Simpan hasil ke PostgreSQL

Jalankan:
    python worker/worker.py

Bisa dijalankan lebih dari satu instance sekaligus (ganti CONSUMER_NAME)
untuk paralelisme, karena pakai Redis Consumer Group.
"""
import os
import time

import dns.resolver
import httpx
import psycopg
from psycopg.types.json import Json
import redis
from dotenv import load_dotenv

from fingerprint import detect_tech_stack
from liveness import assess_site_activity

load_dotenv()

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
STREAM_NAME = "domains:new"
GROUP_NAME = "worker-group"
CONSUMER_NAME = os.getenv("CONSUMER_NAME", "worker-1")

PG_DSN = os.getenv(
    "DATABASE_URL", "postgresql://certwatch:certwatch@localhost:5432/certwatch"
)

HTTP_TIMEOUT = 5.0
USER_AGENT = os.getenv(
    "HTTP_USER_AGENT",
    "certwatch-research-bot/1.0 (+contact: youremail@example.com)",
)

r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    decode_responses=True,
    socket_connect_timeout=3,
    socket_timeout=3,
)


def ensure_schema() -> None:
    conn = psycopg.connect(PG_DSN, connect_timeout=5)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS domains (
                    id BIGSERIAL PRIMARY KEY,
                    domain TEXT NOT NULL UNIQUE,
                    first_seen_cert TIMESTAMPTZ NOT NULL,
                    issuer TEXT,
                    resolved BOOLEAN DEFAULT FALSE,
                    ip_address INET,
                    http_status INT,
                    tech_stack JSONB,
                    raw_headers JSONB,
                    site_status TEXT,
                    site_status_reason TEXT,
                    content_length INT,
                    scanned_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ DEFAULT now()
                );
                -- ADD COLUMN IF NOT EXISTS supaya DB yang sudah pernah dibuat
                -- sebelumnya (sebelum kolom ini ada) otomatis ikut terupdate.
                ALTER TABLE domains ADD COLUMN IF NOT EXISTS site_status TEXT;
                ALTER TABLE domains ADD COLUMN IF NOT EXISTS site_status_reason TEXT;
                ALTER TABLE domains ADD COLUMN IF NOT EXISTS content_length INT;
                CREATE INDEX IF NOT EXISTS idx_domains_first_seen ON domains (first_seen_cert DESC);
                CREATE INDEX IF NOT EXISTS idx_domains_tech_stack ON domains USING GIN (tech_stack);
                CREATE INDEX IF NOT EXISTS idx_domains_resolved ON domains (resolved) WHERE resolved = TRUE;
                CREATE INDEX IF NOT EXISTS idx_domains_site_status ON domains (site_status);
                """
            )
            conn.commit()
    finally:
        conn.close()


def wait_for_redis():
    for attempt in range(1, 31):
        try:
            r.ping()
            return
        except redis.exceptions.ConnectionError as exc:
            if attempt == 30:
                raise RuntimeError(
                    f"Tidak bisa terhubung ke Redis di {REDIS_HOST}:{REDIS_PORT}"
                ) from exc
            print(
                f"Menunggu Redis di {REDIS_HOST}:{REDIS_PORT} ({attempt}/30)..."
            )
            time.sleep(2)


def ensure_group():
    wait_for_redis()
    ensure_schema()
    try:
        r.xgroup_create(STREAM_NAME, GROUP_NAME, id="0", mkstream=True)
    except redis.exceptions.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise


def resolve_domain(domain: str) -> str | None:
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=3.0)
        return str(answers[0])
    except Exception:
        return None


def probe_http(domain: str):
    headers = {"User-Agent": USER_AGENT}
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            return httpx.get(
                url, headers=headers, timeout=HTTP_TIMEOUT, follow_redirects=True
            )
        except Exception:
            continue
    return None


def save_to_db(record: dict):
    conn = psycopg.connect(PG_DSN, connect_timeout=5)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO domains (domain, first_seen_cert, issuer, resolved, ip_address,
                              http_status, tech_stack, raw_headers,
                              site_status, site_status_reason, content_length, scanned_at)
        VALUES (%(domain)s, to_timestamp(%(first_seen_cert)s), %(issuer)s, %(resolved)s,
                %(ip_address)s, %(http_status)s, %(tech_stack)s, %(raw_headers)s,
                %(site_status)s, %(site_status_reason)s, %(content_length)s, now())
        ON CONFLICT (domain) DO UPDATE SET
            resolved           = EXCLUDED.resolved,
            ip_address         = EXCLUDED.ip_address,
            http_status        = EXCLUDED.http_status,
            tech_stack         = EXCLUDED.tech_stack,
            raw_headers        = EXCLUDED.raw_headers,
            site_status        = EXCLUDED.site_status,
            site_status_reason = EXCLUDED.site_status_reason,
            content_length     = EXCLUDED.content_length,
            scanned_at         = now();
        """,
        record,
    )
    conn.commit()
    cur.close()
    conn.close()


def process_domain(fields: dict):
    domain = fields["domain"]
    issuer = fields.get("issuer", "unknown")
    first_seen_cert = fields.get("first_seen_cert", str(time.time()))

    ip = resolve_domain(domain)
    resolved = ip is not None

    http_status = None
    tech_stack: dict = {}
    raw_headers: dict = {}
    # Default kalau domain tidak resolve / tidak ada respons sama sekali --
    # jelas bukan "active" karena tidak ada apa pun buat dinilai.
    liveness = {"status": "unreachable", "reason": "domain tidak resolve", "content_length": 0}

    if resolved:
        resp = probe_http(domain)
        if resp is not None:
            http_status = resp.status_code
            raw_headers = dict(resp.headers)
            content_type = resp.headers.get("content-type", "")
            html = resp.text if "text/html" in content_type else ""
            tech_stack = detect_tech_stack(raw_headers, html)
            liveness = assess_site_activity(http_status, html, raw_headers)
        else:
            liveness = {
                "status": "unreachable",
                "reason": "resolve DNS berhasil tapi HTTP probe gagal/timeout",
                "content_length": 0,
            }

    # Syarat "masuk database": domain harus benar-benar berjalan sebagai web
    # normal -- bukan cuma resolve DNS / balas HTTP apa pun. Semua status
    # selain "active" (unreachable, no_content, default_page, parked,
    # thin_content, soft_404) SENGAJA TIDAK disimpan sama sekali, supaya
    # dataset di database cuma berisi domain yang memang layak diriset.
    if liveness["status"] != "active":
        print(
            f"[skip] {domain} | tidak disimpan (site_status={liveness['status']}) "
            f"| alasan: {liveness['reason']}"
        )
        return

    record = {
        "domain": domain,
        "first_seen_cert": float(first_seen_cert),
        "issuer": issuer,
        "resolved": resolved,
        "ip_address": ip,
        "http_status": http_status,
        "tech_stack": Json(tech_stack),
        "raw_headers": Json(raw_headers),
        "site_status": liveness["status"],
        "site_status_reason": liveness["reason"],
        "content_length": liveness["content_length"],
    }
    save_to_db(record)
    print(
        f"[v] {domain} | resolved={resolved} | status={http_status} "
        f"| site_status={liveness['status']} | tech={list(tech_stack.keys())}"
    )


def main():
    ensure_group()
    print(f"Worker '{CONSUMER_NAME}' siap, menunggu domain baru...")
    last_heartbeat = 0.0
    while True:
        try:
            entries = r.xreadgroup(
                GROUP_NAME, CONSUMER_NAME, {STREAM_NAME: ">"}, count=10, block=5000
            )
        except (redis.exceptions.TimeoutError, redis.exceptions.ConnectionError):
            time.sleep(2)
            continue

        if not entries:
            now = time.time()
            if now - last_heartbeat >= 30:
                print("Menunggu domain baru dari Redis Stream...")
                last_heartbeat = now
            continue
        for _stream, messages in entries:
            for msg_id, fields in messages:
                try:
                    process_domain(fields)
                except Exception as e:
                    print(f"Error memproses {fields.get('domain')}: {e}")

                try:
                    r.xack(STREAM_NAME, GROUP_NAME, msg_id)
                except (redis.exceptions.TimeoutError, redis.exceptions.ConnectionError) as exc:
                    print(f"Gagal ack message {msg_id}: {exc}")


if __name__ == "__main__":
    main()