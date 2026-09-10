-- SentinelScan Database Schema (PostgreSQL)

CREATE TABLE IF NOT EXISTS scans (
    id VARCHAR(64) PRIMARY KEY,
    target_url TEXT NOT NULL,
    target_hostname VARCHAR(255) NOT NULL,
    target_scheme VARCHAR(10) NOT NULL,
    target_port INTEGER NOT NULL,
    authorized BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    security_score INTEGER DEFAULT 100,
    grade VARCHAR(5) DEFAULT 'A',
    risk_level VARCHAR(32) DEFAULT 'LOW',
    pages_scanned INTEGER DEFAULT 0,
    duration_seconds NUMERIC(8, 2) DEFAULT 0,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id VARCHAR(64) PRIMARY KEY,
    scan_id VARCHAR(64) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    scanner VARCHAR(64) NOT NULL,
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    confidence VARCHAR(32) NOT NULL,
    category VARCHAR(128) NOT NULL,
    owasp VARCHAR(128) NOT NULL,
    url TEXT NOT NULL,
    evidence TEXT,
    description TEXT,
    impact TEXT,
    remediation TEXT,
    affected_urls JSONB DEFAULT '[]'::jsonb
);

CREATE TABLE IF NOT EXISTS attack_surface (
    id VARCHAR(64) PRIMARY KEY,
    scan_id VARCHAR(64) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    inventory JSONB NOT NULL DEFAULT '{}'::jsonb,
    technologies JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS ai_analyses (
    id VARCHAR(64) PRIMARY KEY,
    scan_id VARCHAR(64) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    provider VARCHAR(64) NOT NULL,
    executive_summary TEXT,
    risk_narrative TEXT,
    remediation_roadmap JSONB DEFAULT '[]'::jsonb
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(64) PRIMARY KEY,
    scan_id VARCHAR(64) REFERENCES scans(id) ON DELETE SET NULL,
    target_url TEXT NOT NULL,
    action VARCHAR(64) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    details JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_scan ON audit_logs(scan_id);
