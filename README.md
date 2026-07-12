# CertWatch

## Arsitektur

```
CertStream (lite stream)
        |
        v
Collector  --filter & dedupe-->  Redis Stream
        |
        v
Worker  --DNS check, HTTP probe, tech fingerprint-->  PostgreSQL
        |
        v
FastAPI + Swagger UI  (REST API buat query dataset)
```

## Prasyarat
- Docker & Docker Compose
- Python 3.10+

## Setup dari nol

### 1. Clone / siapkan folder project
Semua file sudah ada dalam folder ini.

### 2. Siapkan environment variables
```bash
cp .env.example .env
```
Buka `.env`, minimal ganti `HTTP_USER_AGENT` dengan kontak email kamu sendiri
(supaya pemilik domain yang kamu probe tahu ini traffic riset, bukan serangan).

### 3. Jalankan infrastruktur (Postgres + Redis)
```bash
docker compose up -d
```
Cek statusnya:
```bash
docker compose ps
```
Schema tabel `domains` otomatis dibuat saat container Postgres pertama kali
start (lihat `db/init.sql`).

### 4. Install dependency Python
Disarankan pakai virtual environment:
```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 5. Jalankan Collector (terminal 1)
```bash
python collector/collector.py
```
Kamu akan lihat log `[+] domain baru: ...` setiap ada sertifikat baru masuk.

### 6. Jalankan Worker (terminal 2)
```bash
cd worker
python worker.py
```
Worker akan konsumsi domain dari Redis, coba resolve DNS, probe HTTP, deteksi
tech stack, lalu simpan ke Postgres. Log `[v] domain.com | resolved=True | ...`
menandakan berhasil diproses.

> Mau lebih cepat? Jalankan beberapa instance worker sekaligus dengan
> `CONSUMER_NAME` yang berbeda-beda, misal:
> `CONSUMER_NAME=worker-2 python worker.py`

### 7. Jalankan Backend API (terminal 3)
```bash
uvicorn backend.main:app --reload --port 8000
```
Buka Swagger UI di browser:
```
http://localhost:8000/docs
```

## Endpoint yang tersedia
- `GET /domains` — daftar domain terbaru (bisa filter `?tech=wordpress`, `?resolved_only=true`)
- `GET /domains/{domain}` — detail satu domain
- `GET /stats` — ringkasan dataset (total domain, top CMS)

## Catatan etika riset
- Worker melakukan **HTTP request aktif** ke domain publik. Jangan jalankan
  banyak worker sekaligus tanpa rate limit — bisa dianggap traffic
  mencurigakan oleh pemilik domain.
- `User-Agent` sudah di-set jelas (`HTTP_USER_AGENT` di `.env`) — pastikan
  diisi kontak asli, bukan default.
- Kalau dataset ini nanti dipublikasikan, pertimbangkan agregasi/anonimisasi
  supaya tidak "menyorot" domain individu secara langsung.

## Pengembangan lanjutan (ide next steps)
- Ganti deteksi tech stack rule-based di `worker/fingerprint.py` dengan
  library `python-Wappalyzer` untuk akurasi lebih luas.
- Tambah endpoint `WebSocket` di backend buat live-feed domain baru
  (subscribe ke Redis Pub/Sub dari worker).
- Migrasi tabel `domains` ke TimescaleDB kalau volume data mulai besar,
  supaya query time-range dan retention policy lebih efisien.
- Tambah frontend (React/Next.js) yang consume REST API ini buat visualisasi.
