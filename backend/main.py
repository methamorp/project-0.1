"""
FastAPI Backend
===============
REST API (dengan Swagger UI otomatis di /docs) buat query dataset domain
hasil scan CertStream + tech fingerprint.

Jalankan:
    uvicorn backend.main:app --reload --port 8000

Lalu buka:
    http://localhost:8000/docs
"""
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

load_dotenv()

PG_DSN = os.getenv(
    "DATABASE_URL", "postgresql://certwatch:certwatch@localhost:5432/certwatch"
)

app = FastAPI(
    title="CertWatch API",
    description=(
        "Dataset domain baru dari Certificate Transparency log, "
        "beserta tech stack yang terdeteksi. Dibuat untuk kebutuhan riset."
    ),
    version="0.1.0",
)


def wait_for_postgres() -> None:
    """Coba connect berulang kali sebelum nyerah. Tanpa ini, backend akan
    langsung crash kalau dijalankan sesaat setelah `docker compose up -d`,
    sebelum container Postgres benar-benar siap menerima koneksi."""
    for attempt in range(1, 31):
        try:
            conn = psycopg.connect(PG_DSN, connect_timeout=5)
            conn.close()
            return
        except psycopg.OperationalError as exc:
            if attempt == 30:
                raise RuntimeError(
                    f"Tidak bisa terhubung ke Postgres ({PG_DSN}) setelah 30x percobaan. "
                    "Pastikan `docker compose up -d` sudah jalan dan DATABASE_URL di .env benar."
                ) from exc
            print(f"Menunggu Postgres ({attempt}/30)...")
            time.sleep(2)


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


wait_for_postgres()
ensure_schema()


def get_conn():
    return psycopg.connect(PG_DSN, row_factory=dict_row)


class DomainOut(BaseModel):
    domain: str
    first_seen_cert: Optional[datetime] = None
    issuer: Optional[str] = None
    resolved: bool
    ip_address: Optional[str] = None
    http_status: Optional[int] = None
    tech_stack: Optional[dict] = None
    site_status: Optional[str] = None
    site_status_reason: Optional[str] = None
    content_length: Optional[int] = None
    scanned_at: Optional[datetime] = None


def _build_domain_filters(
    tech: Optional[str],
    resolved_only: bool,
    active_only: bool,
    date_from: Optional[str],
    date_to: Optional[str],
):
    """Bangun klausa WHERE + params yang dipakai bareng oleh /domains,
    /domains/count, dan /domains/export supaya filternya selalu konsisten."""
    clauses = ["1=1"]
    params: list = []

    if tech:
        clauses.append("tech_stack::text ILIKE %s")
        params.append(f"%{tech}%")
    if resolved_only:
        clauses.append("resolved = TRUE")
    if active_only:
        clauses.append("site_status = 'active'")
    if date_from:
        clauses.append("first_seen_cert >= %s")
        params.append(date_from)
    if date_to:
        # date_to bersifat inklusif -> geser ke akhir hari
        clauses.append("first_seen_cert < (%s::date + interval '1 day')")
        params.append(date_to)

    return " AND ".join(clauses), params


@app.get("/domains", response_model=list[DomainOut], tags=["domains"])
def list_domains(
    limit: int = Query(50, le=200, description="Jumlah maksimal hasil"),
    offset: int = 0,
    tech: Optional[str] = Query(
        None, description="Filter berdasarkan tech, contoh: 'wordpress'"
    ),
    resolved_only: bool = Query(False, description="Hanya domain yang DNS-nya resolve"),
    active_only: bool = Query(
        False,
        description=(
            "Hanya domain yang benar-benar berjalan sebagai web normal -- "
            "buang parked domain, halaman default server, konten kosong, dsb."
        ),
    ),
    date_from: Optional[str] = Query(
        None, description="Filter first_seen_cert >= tanggal ini (format YYYY-MM-DD)"
    ),
    date_to: Optional[str] = Query(
        None, description="Filter first_seen_cert <= tanggal ini (format YYYY-MM-DD)"
    ),
):
    """Ambil daftar domain terbaru, urut dari yang paling baru muncul di CT log."""
    where_sql, params = _build_domain_filters(
        tech, resolved_only, active_only, date_from, date_to
    )
    conn = get_conn()
    cur = conn.cursor()
    query = (
        f"SELECT *, ip_address::text AS ip_address FROM domains WHERE {where_sql} "
        "ORDER BY first_seen_cert DESC LIMIT %s OFFSET %s"
    )
    cur.execute(query, [*params, limit, offset])
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


@app.get("/domains/count", tags=["domains"])
def count_domains(
    tech: Optional[str] = Query(None),
    resolved_only: bool = Query(False),
    active_only: bool = Query(False),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
):
    """Total baris yang cocok dengan filter -- dipakai frontend buat hitung
    jumlah halaman pagination."""
    where_sql, params = _build_domain_filters(
        tech, resolved_only, active_only, date_from, date_to
    )
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(f"SELECT count(*) AS total FROM domains WHERE {where_sql}", params)
    total = cur.fetchone()["total"]
    cur.close()
    conn.close()
    return {"total": total}


@app.get("/domains/export", tags=["domains"])
def export_domains(
    tech: Optional[str] = Query(None),
    resolved_only: bool = Query(False),
    active_only: bool = Query(False),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    max_rows: int = Query(
        20000, le=50000, description="Batas maksimal baris yang diexport"
    ),
):
    """Export domain yang cocok dengan filter sebagai file .txt (satu domain
    per baris, plus metadata ringkas dipisah tab)."""
    where_sql, params = _build_domain_filters(
        tech, resolved_only, active_only, date_from, date_to
    )
    conn = get_conn()
    cur = conn.cursor()
    query = (
        "SELECT domain, first_seen_cert, resolved, site_status, tech_stack "
        f"FROM domains WHERE {where_sql} ORDER BY first_seen_cert DESC LIMIT %s"
    )
    cur.execute(query, [*params, max_rows])
    rows = cur.fetchall()
    cur.close()
    conn.close()

    lines = ["# domain\tfirst_seen_cert\tresolved\tsite_status\ttech_stack"]
    for r in rows:
        tech_str = ",".join(f"{k}={v}" for k, v in (r["tech_stack"] or {}).items())
        lines.append(
            f"{r['domain']}\t{r['first_seen_cert']}\t{r['resolved']}\t"
            f"{r['site_status'] or '-'}\t{tech_str or '-'}"
        )
    content = "\n".join(lines) + "\n"

    filename_bits = ["certwatch"]
    if date_from:
        filename_bits.append(date_from)
    if date_to:
        filename_bits.append(date_to)
    filename = "_".join(filename_bits) + ".txt"

    from fastapi.responses import PlainTextResponse

    return PlainTextResponse(
        content,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/domains/{domain}", response_model=DomainOut, tags=["domains"])
def get_domain(domain: str):
    """Ambil detail satu domain."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT *, ip_address::text AS ip_address FROM domains WHERE domain = %s", (domain,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Domain tidak ditemukan")
    return row


@app.get("/stats", tags=["stats"])
def get_stats():
    """Statistik ringkas dataset: total domain dan top CMS yang terdeteksi."""
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT count(*) AS total FROM domains")
    total = cur.fetchone()["total"]

    cur.execute(
        """
        SELECT tech_stack->>'cms' AS cms, count(*) AS jumlah
        FROM domains
        WHERE tech_stack->>'cms' IS NOT NULL
        GROUP BY cms
        ORDER BY jumlah DESC
        LIMIT 10
        """
    )
    top_cms = cur.fetchall()

    cur.close()
    conn.close()
    return {"total_domains": total, "top_cms": top_cms}


@app.get("/stats/timeline", tags=["stats"])
def get_timeline(days: int = Query(14, le=90, description="Jumlah hari ke belakang")):
    """Jumlah domain baru per hari, buat chart tren dari waktu ke waktu."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            date_trunc('day', scanned_at) AS day,
            count(*) AS total,
            count(*) FILTER (WHERE resolved) AS resolved_count
        FROM domains
        WHERE scanned_at >= now() - (%s || ' days')::interval
        GROUP BY day
        ORDER BY day ASC
        """,
        (days,),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


@app.get("/stats/tech-breakdown", tags=["stats"])
def get_tech_breakdown():
    """Distribusi tech stack (server, cms, backend, framework) buat bar chart."""
    conn = get_conn()
    cur = conn.cursor()

    breakdown = {}
    for field in ("server", "cms", "backend", "framework"):
        cur.execute(
            f"""
            SELECT tech_stack->>'{field}' AS value, count(*) AS jumlah
            FROM domains
            WHERE tech_stack->>'{field}' IS NOT NULL
            GROUP BY value
            ORDER BY jumlah DESC
            LIMIT 8
            """
        )
        breakdown[field] = cur.fetchall()

    cur.close()
    conn.close()
    return breakdown


@app.get("/dashboard", response_class=HTMLResponse, tags=["dashboard"])
def dashboard():
    """Halaman dashboard visualisasi tren tech stack."""
    dashboard_path = Path(__file__).parent / "static" / "dashboard.html"
    return dashboard_path.read_text(encoding="utf-8")