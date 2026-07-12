"""
Collector
=========
Terhubung ke CertStream (lite stream), ambil domain-domain baru dari
sertifikat yang baru di-issue, filter dan dedupe, lalu dorong ke Redis
Stream supaya bisa diproses worker secara async.

Jalankan:
    python collector/collector.py
"""
import asyncio
import json
import os
import time

import redis
import tldextract
import websockets
from dotenv import load_dotenv

load_dotenv()

CERTSTREAM_URL = os.getenv("CERTSTREAM_URL", "wss://certstream.calidog.io/")
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
STREAM_NAME = "domains:new"

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

# Dedupe cache in-memory sederhana supaya domain yang sama (misal wildcard
# + apex domain dalam satu cert) tidak didorong berkali-kali dalam waktu dekat.
seen_cache: dict[str, float] = {}
DEDUPE_WINDOW_SECONDS = 60 * 10  # 10 menit


def extract_root_domain(domain: str) -> str | None:
    """Ambil root domain (registrable domain), buang subdomain."""
    ext = tldextract.extract(domain)
    if not ext.domain or not ext.suffix:
        return None
    return f"{ext.domain}.{ext.suffix}"


def is_duplicate(domain: str) -> bool:
    now = time.time()
    last_seen = seen_cache.get(domain)
    if last_seen and (now - last_seen) < DEDUPE_WINDOW_SECONDS:
        return True
    seen_cache[domain] = now
    return False


async def handle_message(message: dict):
    if message.get("message_type") != "certificate_update":
        return

    data = message["data"]
    leaf_cert = data.get("leaf_cert", {})
    all_domains = leaf_cert.get("all_domains", [])
    issuer = leaf_cert.get("issuer", {}).get("O", "unknown")
    seen_ts = data.get("seen", time.time())

    for raw_domain in all_domains:
        domain = raw_domain.lstrip("*.")  # buang prefix wildcard
        root = extract_root_domain(domain)
        if not root:
            continue
        if is_duplicate(root):
            continue

        payload = {
            "domain": root,
            "raw_domain": domain,
            "issuer": issuer,
            "first_seen_cert": str(seen_ts),
        }
        r.xadd(STREAM_NAME, payload)
        print(f"[+] domain baru: {root} (issuer: {issuer})")


async def listen():
    print(f"Menghubungkan ke {CERTSTREAM_URL} ...")
    async with websockets.connect(CERTSTREAM_URL, ping_interval=20) as ws:
        print("Terhubung. Mendengarkan sertifikat baru...")
        async for raw in ws:
            try:
                message = json.loads(raw)
                await handle_message(message)
            except Exception as e:
                print(f"Error memproses pesan: {e}")


async def main():
    while True:
        try:
            await listen()
        except Exception as e:
            print(f"Koneksi terputus: {e}. Reconnect dalam 5 detik...")
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
