CREATE TABLE IF NOT EXISTS certificates (
    fingerprint BLOB(32) PRIMARY KEY,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    sans TEXT,
    key_algorithm TEXT NOT NULL,
    key_size INTEGER NOT NULL,
    chain_depth INTEGER DEFAULT 1,
    issuer_fingerprint BLOB(32),
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    connection_count INTEGER DEFAULT 1,
    source_ip TEXT,
    destination_ip TEXT,
    sni_hostname TEXT,
    completeness_flags INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS action_directives (
    id TEXT PRIMARY KEY,
    correlation_id TEXT NOT NULL,
    cert_fingerprint BLOB(32) NOT NULL,
    action_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    reasoning TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    attempt_count INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    executed_at INTEGER,
    expired_at INTEGER,
    failure_reason TEXT,
    FOREIGN KEY (cert_fingerprint) REFERENCES certificates(fingerprint)
);

CREATE TABLE IF NOT EXISTS shadow_certificates (
    fingerprint BLOB(32) PRIMARY KEY,
    risk_level TEXT NOT NULL,
    first_classified INTEGER NOT NULL,
    last_escalated INTEGER,
    escalation_count INTEGER DEFAULT 0,
    source_ip TEXT,
    destination_ip TEXT,
    first_seen INTEGER NOT NULL,
    is_resolved INTEGER DEFAULT 0,
    resolved_at INTEGER,
    FOREIGN KEY (fingerprint) REFERENCES certificates(fingerprint)
);

CREATE TABLE IF NOT EXISTS renewal_predictions (
    cert_fingerprint BLOB(32) PRIMARY KEY,
    failure_probability REAL NOT NULL,
    severity TEXT NOT NULL,
    days_until_expiry INTEGER NOT NULL,
    renewal_activity_detected INTEGER DEFAULT 0,
    reasoning TEXT,
    last_evaluated INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (cert_fingerprint) REFERENCES certificates(fingerprint)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    correlation_id TEXT NOT NULL,
    cert_fingerprint BLOB(32) NOT NULL,
    stage TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    details TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS certificate_inventory (
    fingerprint BLOB(32) PRIMARY KEY,
    subject TEXT NOT NULL,
    source TEXT NOT NULL,
    imported_at INTEGER NOT NULL,
    last_refresh_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS inventory_refresh_log (
    id TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    source TEXT NOT NULL,
    total_entries INTEGER,
    new_entries INTEGER,
    removed_entries INTEGER,
    skipped_invalid INTEGER,
    success INTEGER NOT NULL
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_cert_not_after ON certificates(not_after);
CREATE INDEX IF NOT EXISTS idx_cert_last_seen ON certificates(last_seen);
CREATE INDEX IF NOT EXISTS idx_cert_issuer_fp ON certificates(issuer_fingerprint);
CREATE INDEX IF NOT EXISTS idx_directive_status ON action_directives(status);
CREATE INDEX IF NOT EXISTS idx_directive_cert ON action_directives(cert_fingerprint);
CREATE INDEX IF NOT EXISTS idx_directive_correlation ON action_directives(correlation_id);
CREATE INDEX IF NOT EXISTS idx_audit_correlation ON audit_log(correlation_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_cert ON audit_log(cert_fingerprint);
