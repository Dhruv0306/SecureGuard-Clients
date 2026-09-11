-- 0001_init.sql
-- Phase 1 schema: local scan history and the signature cache table shape.
-- Signature *sync* (populating this table from MalwareBazaar) is Phase 2
-- work; the table exists now so Phase 2 doesn't need its own migration for
-- storage shape, only for the fetch/sync logic.

CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_name TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('CLEAN', 'SUSPICIOUS', 'MALICIOUS')),
    score INTEGER NOT NULL,
    threat_type TEXT,
    scanned_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_results_scanned_at ON scan_results (scanned_at);
CREATE INDEX IF NOT EXISTS idx_scan_results_sha256 ON scan_results (sha256);

CREATE TABLE IF NOT EXISTS signature_cache (
    sha256 TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    added_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS blocked_domains (
    domain TEXT PRIMARY KEY,
    reason TEXT,
    added_at INTEGER NOT NULL
);
