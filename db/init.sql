-- Tabel utama: hasil scan domain baru dari CertStream
CREATE TABLE IF NOT EXISTS domains (
    id              BIGSERIAL PRIMARY KEY,
    domain          TEXT NOT NULL UNIQUE,
    first_seen_cert TIMESTAMPTZ NOT NULL,
    issuer          TEXT,
    resolved        BOOLEAN DEFAULT FALSE,
    ip_address      INET,
    http_status     INT,
    tech_stack      JSONB,
    raw_headers     JSONB,
    scanned_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- Index buat query cepat berdasarkan waktu (dataset "domain terbaru")
CREATE INDEX IF NOT EXISTS idx_domains_first_seen ON domains (first_seen_cert DESC);

-- Index GIN buat filter cepat berdasarkan isi tech_stack (JSONB)
CREATE INDEX IF NOT EXISTS idx_domains_tech_stack ON domains USING GIN (tech_stack);

-- Index buat filter domain yang berhasil di-resolve saja
CREATE INDEX IF NOT EXISTS idx_domains_resolved ON domains (resolved) WHERE resolved = TRUE;
