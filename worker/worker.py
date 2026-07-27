"""
Worker (async / concurrent)
============================
Konsumsi domain baru dari Redis Stream (didorong oleh collector), lakukan:
  1. DNS resolve check -- pastikan domain benar-benar aktif
  2. HTTP(S) probe      -- ambil headers dan HTML
  3. Tech fingerprinting -- deteksi CMS/framework/server dari hasil probe
  4. Liveness check      -- pastikan situsnya benar-benar berjalan (bukan
     zombie/parked/default page), simpan ke PostgreSQL HANYA kalau lolos
  5. Simpan hasil ke PostgreSQL

PENTING -- yang berubah dari versi sebelumnya HANYA cara eksekusi:
  - DNS resolve, HTTP probe, dan tulis ke Postgres sekarang jalan CONCURRENT
    (banyak domain diproses bersamaan dalam satu instance worker), bukan
    satu-per-satu berurutan.
  - Fungsi `detect_tech_stack()` (fingerprint.py) dan `assess_site_activity()`
    (liveness.py) TIDAK DIUBAH SAMA SEKALI -- dipanggil persis sama seperti
    sebelumnya, dengan input yang sama, urutan pengecekan yang sama, dan
    kriteria simpan/skip yang sama (`liveness["status"] != "active"` -> skip).
    Kedua modul itu murni CPU-bound (regex/dict lookup), tidak ada I/O di
    dalamnya, jadi tidak ada alasan untuk diubah.
  - Format log `[v] ...` / `[skip] ...` di terminal sama persis dengan versi
    sebelumnya, supaya gampang dibandingkan.

Kontrol concurrency lewat env var:
  WORKER_CONCURRENCY  -- jumlah domain yang boleh diproses bersamaan dalam
                          SATU instance worker (default 20). Ini yang jaga
                          supaya tidak membanjiri DNS resolver lokal / tidak
                          dianggap traffic mencurigakan oleh pemilik domain
                          (lihat catatan etika riset di README) -- meskipun
                          proses concurrent, tiap domain tetap cuma dapat
                          1-2 request HTTP total, jadi TIDAK menambah beban
                          per domain, cuma menghilangkan waktu tunggu antar
                          domain yang berbeda.
  WORKER_BATCH_SIZE   -- jumlah pesan yang diambil dari Redis Stream sekali
                          `xreadgroup` (default 20, disamakan dgn concurrency).

Jalankan:
    python worker/worker.py

Bisa dijalankan lebih dari satu instance sekaligus (ganti CONSUMER_NAME)
untuk paralelisme lintas-proses, karena pakai Redis Consumer Group --
sekarang bisa dikombinasikan dengan concurrency di dalam masing-masing
instance untuk throughput yang jauh lebih tinggi.
"""
import asyncio
import os
import time

import dns.asyncresolver
import dns.exception
import httpx
import psycopg
from psycopg.types.json import Json
import redis.asyncio as redis
import redis.exceptions as redis_exceptions
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

# Batas berapa banyak domain diproses BERSAMAAN dalam satu instance worker.
# Ini pengganti utama dari "worker lambat" -- bukan menambah jumlah request
# per domain, cuma menghilangkan waktu tunggu (idle) antar domain yang
# berbeda selama DNS/HTTP sedang berlangsung.
MAX_CONCURRENCY = int(os.getenv("WORKER_CONCURRENCY", 20))
BATCH_SIZE = int(os.getenv("WORKER_BATCH_SIZE", MAX_CONCURRENCY))

r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    decode_responses=True,
    socket_connect_timeout=3,
    socket_timeout=3,
)

_resolver = dns.asyncresolver.Resolver()
_resolver.lifetime = 3.0  # sama seperti lifetime=3.0 di versi sebelumnya

_semaphore = asyncio.Semaphore(MAX_CONCURRENCY)


def ensure_schema() -> None:
    # Tidak diubah -- dijalankan sekali saat startup, tidak perlu async.
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


async def wait_for_redis():
    for attempt in range(1, 31):
        try:
            await r.ping()
            return
        except redis_exceptions.ConnectionError as exc:
            if attempt == 30:
                raise RuntimeError(
                    f"Tidak bisa terhubung ke Redis di {REDIS_HOST}:{REDIS_PORT}"
                ) from exc
            print(
                f"Menunggu Redis di {REDIS_HOST}:{REDIS_PORT} ({attempt}/30)..."
            )
            await asyncio.sleep(2)


async def ensure_group():
    await wait_for_redis()
    ensure_schema()
    try:
        await r.xgroup_create(STREAM_NAME, GROUP_NAME, id="0", mkstream=True)
    except redis_exceptions.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise


async def resolve_domain(domain: str) -> str | None:
    # Sama seperti versi sinkron (dns.resolver.resolve A, lifetime=3.0),
    # cuma versi async (dns.asyncresolver) supaya tidak blocking event loop.
    try:
        answers = await _resolver.resolve(domain, "A")
        return str(answers[0])
    except (dns.exception.DNSException, Exception):
        return None


async def probe_http(client: httpx.AsyncClient, domain: str):
    # Urutan coba https lalu http -- SAMA seperti sebelumnya.
    headers = {"User-Agent": USER_AGENT}
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            return await client.get(
                url, headers=headers, timeout=HTTP_TIMEOUT, follow_redirects=True
            )
        except Exception:
            continue
    return None


def _save_to_db_sync(record: dict):
    # SQL & logic INSERT ... ON CONFLICT sama persis dengan versi sebelumnya.
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


async def save_to_db(record: dict):
    # psycopg dipakai secara sinkron tapi dijalankan di thread pool
    # (asyncio.to_thread) supaya tidak memblokir event loop saat domain lain
    # sedang diproses. Query & schema-nya tidak berubah sama sekali.
    await asyncio.to_thread(_save_to_db_sync, record)


async def process_domain(client: httpx.AsyncClient, msg_id: str, fields: dict):
    async with _semaphore:
        domain = fields.get("domain", "?")
        try:
            issuer = fields.get("issuer", "unknown")
            first_seen_cert = fields.get("first_seen_cert", str(time.time()))

            ip = await resolve_domain(domain)
            resolved = ip is not None

            http_status = None
            tech_stack: dict = {}
            raw_headers: dict = {}
            liveness = {
                "status": "unreachable",
                "reason": "domain tidak resolve",
                "content_length": 0,
            }

            if resolved:
                resp = await probe_http(client, domain)
                if resp is not None:
                    http_status = resp.status_code
                    raw_headers = dict(resp.headers)
                    content_type = resp.headers.get("content-type", "")
                    html = resp.text if "text/html" in content_type else ""
                    # --- TIDAK DIUBAH: fingerprint & liveness sama persis ---
                    tech_stack = detect_tech_stack(raw_headers, html)
                    liveness = assess_site_activity(http_status, html, raw_headers)
                    # ---------------------------------------------------------
                else:
                    liveness = {
                        "status": "unreachable",
                        "reason": "resolve DNS berhasil tapi HTTP probe gagal/timeout",
                        "content_length": 0,
                    }

            # --- TIDAK DIUBAH: kriteria simpan/skip sama persis ---
            if liveness["status"] != "active":
                print(
                    f"[skip] {domain} | tidak disimpan (site_status={liveness['status']}) "
                    f"| alasan: {liveness['reason']}"
                )
            else:
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
                await save_to_db(record)
                print(
                    f"[v] {domain} | resolved={resolved} | status={http_status} "
                    f"| site_status={liveness['status']} | tech={list(tech_stack.keys())}"
                )
            # -------------------------------------------------------
        except Exception as e:
            print(f"Error memproses {domain}: {e}")

        try:
            await r.xack(STREAM_NAME, GROUP_NAME, msg_id)
        except (redis_exceptions.TimeoutError, redis_exceptions.ConnectionError) as exc:
            print(f"Gagal ack message {msg_id}: {exc}")


async def main():
    await ensure_group()
    print(
        f"Worker '{CONSUMER_NAME}' siap (concurrency={MAX_CONCURRENCY}), "
        "menunggu domain baru..."
    )
    last_heartbeat = 0.0

    async with httpx.AsyncClient() as client:
        while True:
            try:
                entries = await r.xreadgroup(
                    GROUP_NAME, CONSUMER_NAME, {STREAM_NAME: ">"},
                    count=BATCH_SIZE, block=5000,
                )
            except (redis_exceptions.TimeoutError, redis_exceptions.ConnectionError):
                await asyncio.sleep(2)
                continue

            if not entries:
                now = time.time()
                if now - last_heartbeat >= 30:
                    print("Menunggu domain baru dari Redis Stream...")
                    last_heartbeat = now
                continue

            tasks = [
                process_domain(client, msg_id, fields)
                for _stream, messages in entries
                for msg_id, fields in messages
            ]
            # Semua domain di batch ini diproses bersamaan (dibatasi
            # _semaphore), bukan satu-per-satu berurutan seperti sebelumnya.
            await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())