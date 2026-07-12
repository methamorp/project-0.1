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
    scanned_at: Optional[datetime] = None


@app.get("/domains", response_model=list[DomainOut], tags=["domains"])
def list_domains(
    limit: int = Query(50, le=200, description="Jumlah maksimal hasil"),
    offset: int = 0,
    tech: Optional[str] = Query(
        None, description="Filter berdasarkan tech, contoh: 'wordpress'"
    ),
    resolved_only: bool = Query(False, description="Hanya domain yang aktif/resolve"),
):
    """Ambil daftar domain terbaru, urut dari yang paling baru muncul di CT log."""
    conn = get_conn()
    cur = conn.cursor()
    query = "SELECT *, ip_address::text AS ip_address FROM domains WHERE 1=1"
    params: list = []

    if tech:
        query += " AND tech_stack::text ILIKE %s"
        params.append(f"%{tech}%")
    if resolved_only:
        query += " AND resolved = TRUE"

    query += " ORDER BY first_seen_cert DESC LIMIT %s OFFSET %s"
    params.extend([limit, offset])

    cur.execute(query, params)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


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
