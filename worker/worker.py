"""
Worker
======
Konsumsi domain baru dari Redis Stream (didorong oleh collector), lakukan:
  1. DNS resolve check -- pastikan domain benar-benar aktif
  2. HTTP(S) probe      -- ambil headers dan HTML
  3. Tech fingerprinting -- deteksi CMS/framework/server dari hasil probe
  4. Simpan hasil ke PostgreSQL

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

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


def ensure_group():
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
    conn = psycopg.connect(PG_DSN)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO domains (domain, first_seen_cert, issuer, resolved, ip_address,
                              http_status, tech_stack, raw_headers, scanned_at)
        VALUES (%(domain)s, to_timestamp(%(first_seen_cert)s), %(issuer)s, %(resolved)s,
                %(ip_address)s, %(http_status)s, %(tech_stack)s, %(raw_headers)s, now())
        ON CONFLICT (domain) DO UPDATE SET
            resolved    = EXCLUDED.resolved,
            ip_address  = EXCLUDED.ip_address,
            http_status = EXCLUDED.http_status,
            tech_stack  = EXCLUDED.tech_stack,
            raw_headers = EXCLUDED.raw_headers,
            scanned_at  = now();
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

    if resolved:
        resp = probe_http(domain)
        if resp is not None:
            http_status = resp.status_code
            raw_headers = dict(resp.headers)
            content_type = resp.headers.get("content-type", "")
            html = resp.text if "text/html" in content_type else ""
            tech_stack = detect_tech_stack(raw_headers, html)

    record = {
        "domain": domain,
        "first_seen_cert": float(first_seen_cert),
        "issuer": issuer,
        "resolved": resolved,
        "ip_address": ip,
        "http_status": http_status,
        "tech_stack": Json(tech_stack),
        "raw_headers": Json(raw_headers),
    }
    save_to_db(record)
    print(
        f"[v] {domain} | resolved={resolved} | status={http_status} "
        f"| tech={list(tech_stack.keys())}"
    )


def main():
    ensure_group()
    print(f"Worker '{CONSUMER_NAME}' siap, menunggu domain baru...")
    while True:
        entries = r.xreadgroup(
            GROUP_NAME, CONSUMER_NAME, {STREAM_NAME: ">"}, count=10, block=5000
        )
        if not entries:
            continue
        for _stream, messages in entries:
            for msg_id, fields in messages:
                try:
                    process_domain(fields)
                except Exception as e:
                    print(f"Error memproses {fields.get('domain')}: {e}")
                finally:
                    r.xack(STREAM_NAME, GROUP_NAME, msg_id)


if __name__ == "__main__":
    main()
