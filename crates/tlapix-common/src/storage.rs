//! SQLite storage layer for the Tlapix Certificate Guardian.
//!
//! Provides async-compatible database operations using `rusqlite` with
//! `tokio::task::spawn_blocking` for non-blocking access from async contexts.

use std::path::Path;
use std::sync::Arc;

use rusqlite::{params, Connection, OptionalExtension};
use tokio::sync::Mutex;
use tracing;

use crate::types::{
    CertificateMetadata, RiskLevel,
};

/// Errors that can occur during storage operations.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// SQLite error from rusqlite.
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// Internal error (e.g., task join failure).
    #[error("Internal error: {0}")]
    Internal(String),

    /// Data conversion error.
    #[error("Data conversion error: {0}")]
    Conversion(String),
}

/// Result type alias for storage operations.
pub type StorageResult<T> = Result<T, StorageError>;

// ---------------------------------------------------------------------------
// Row types for tables without a direct domain type
// ---------------------------------------------------------------------------

/// A row from the `shadow_certificates` table.
#[derive(Debug, Clone)]
pub struct ShadowCertificateRow {
    pub fingerprint: [u8; 32],
    pub risk_level: RiskLevel,
    pub first_classified: i64,
    pub last_escalated: Option<i64>,
    pub escalation_count: i32,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub first_seen: i64,
    pub is_resolved: bool,
    pub resolved_at: Option<i64>,
}

/// A row from the `audit_log` table.
#[derive(Debug, Clone)]
pub struct AuditLogRow {
    pub id: i64,
    pub correlation_id: String,
    pub cert_fingerprint: [u8; 32],
    pub stage: String,
    pub timestamp: i64,
    pub details: String,
    pub created_at: i64,
}

/// A row from the `certificate_inventory` table.
#[derive(Debug, Clone)]
pub struct CertificateInventoryRow {
    pub fingerprint: [u8; 32],
    pub subject: String,
    pub source: String,
    pub imported_at: i64,
    pub last_refresh_id: String,
}

/// A row from the `inventory_refresh_log` table.
#[derive(Debug, Clone)]
pub struct InventoryRefreshLogRow {
    pub id: String,
    pub timestamp: i64,
    pub source: String,
    pub total_entries: Option<i32>,
    pub new_entries: Option<i32>,
    pub removed_entries: Option<i32>,
    pub skipped_invalid: Option<i32>,
    pub success: bool,
}

/// A row from the `action_directives` table.
#[derive(Debug, Clone)]
pub struct ActionDirectiveRow {
    pub id: String,
    pub correlation_id: String,
    pub cert_fingerprint: [u8; 32],
    pub action_type: String,
    pub severity: String,
    pub reasoning: Option<String>,
    pub status: String,
    pub attempt_count: i32,
    pub created_at: i64,
    pub executed_at: Option<i64>,
    pub expired_at: Option<i64>,
    pub failure_reason: Option<String>,
}

/// A row from the `renewal_predictions` table.
#[derive(Debug, Clone)]
pub struct RenewalPredictionRow {
    pub cert_fingerprint: [u8; 32],
    pub failure_probability: f64,
    pub severity: String,
    pub days_until_expiry: i32,
    pub renewal_activity_detected: bool,
    pub reasoning: Option<String>,
    pub last_evaluated: i64,
    pub created_at: i64,
}

// ---------------------------------------------------------------------------
// Storage struct
// ---------------------------------------------------------------------------

/// SQLite-backed storage for all Tlapix persistent data.
///
/// All operations use `tokio::task::spawn_blocking` internally to avoid
/// blocking the async runtime, since `rusqlite` is synchronous.
#[derive(Clone)]
pub struct Storage {
    conn: Arc<Mutex<Connection>>,
}

impl Storage {
    /// Open or create a SQLite database at the given path and initialize all schemas.
    pub async fn open(path: impl AsRef<Path>) -> StorageResult<Self> {
        let path = path.as_ref().to_path_buf();
        let conn = tokio::task::spawn_blocking(move || -> StorageResult<Connection> {
            let conn = Connection::open(&path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL;")?;
            conn.execute_batch("PRAGMA foreign_keys=ON;")?;
            Ok(conn)
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))??;

        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        storage.initialize_schema().await?;
        Ok(storage)
    }

    /// Create an in-memory database (useful for testing).
    pub async fn open_in_memory() -> StorageResult<Self> {
        let conn = tokio::task::spawn_blocking(|| -> StorageResult<Connection> {
            let conn = Connection::open_in_memory()?;
            conn.execute_batch("PRAGMA foreign_keys=ON;")?;
            Ok(conn)
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))??;

        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        storage.initialize_schema().await?;
        Ok(storage)
    }

    /// Initialize all database tables and indexes.
    async fn initialize_schema(&self) -> StorageResult<()> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<()> {
            let conn = conn.blocking_lock();
            conn.execute_batch(SCHEMA_SQL)?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    // -----------------------------------------------------------------------
    // Certificates CRUD
    // -----------------------------------------------------------------------

    /// Insert or update a certificate metadata record.
    pub async fn upsert_certificate(&self, cert: &CertificateMetadata) -> StorageResult<()> {
        let cert = cert.clone();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<()> {
            let conn = conn.blocking_lock();
            let sans_json = serde_json::to_string(&cert.sans)
                .map_err(|e| StorageError::Internal(e.to_string()))?;
            let now_ms = chrono::Utc::now().timestamp_millis();
            let not_before_ms = cert.not_before.timestamp_millis();
            let not_after_ms = cert.not_after.timestamp_millis();
            let first_seen_ms = cert.first_seen.timestamp_millis();
            let last_seen_ms = cert.last_seen.timestamp_millis();
            let issuer_fp: Option<Vec<u8>> =
                cert.issuer_fingerprint.map(|fp| fp.to_vec());

            conn.execute(
                "INSERT INTO certificates (
                    fingerprint, subject, issuer, serial_number,
                    not_before, not_after, sans, key_algorithm, key_size,
                    chain_depth, issuer_fingerprint, first_seen, last_seen,
                    connection_count, source_ip, destination_ip, sni_hostname,
                    completeness_flags, created_at, updated_at
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                    ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20
                ) ON CONFLICT(fingerprint) DO UPDATE SET
                    last_seen = ?13,
                    connection_count = connection_count + 1,
                    updated_at = ?20",
                params![
                    cert.fingerprint.as_slice(),
                    cert.subject,
                    cert.issuer,
                    cert.serial_number,
                    not_before_ms,
                    not_after_ms,
                    sans_json,
                    cert.key_algorithm,
                    cert.key_size,
                    cert.chain_depth as i32,
                    issuer_fp,
                    first_seen_ms,
                    last_seen_ms,
                    cert.connection_count as i64,
                    cert.source_ip,
                    cert.destination_ip,
                    cert.sni_hostname,
                    cert.completeness_flags as i64,
                    now_ms,
                    now_ms,
                ],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// Get a certificate by its SHA-256 fingerprint.
    pub async fn get_certificate(
        &self,
        fingerprint: &[u8; 32],
    ) -> StorageResult<Option<CertificateMetadata>> {
        let fp = fingerprint.to_vec();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<Option<CertificateMetadata>> {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT fingerprint, subject, issuer, serial_number,
                        not_before, not_after, sans, key_algorithm, key_size,
                        chain_depth, issuer_fingerprint, first_seen, last_seen,
                        connection_count, source_ip, destination_ip, sni_hostname,
                        completeness_flags
                 FROM certificates WHERE fingerprint = ?1",
            )?;
            let result = stmt
                .query_row(params![fp], |row| {
                    Ok(row_to_certificate_metadata(row))
                })
                .optional()?;
            match result {
                Some(Ok(cert)) => Ok(Some(cert)),
                Some(Err(e)) => Err(e),
                None => Ok(None),
            }
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// Update the last_seen timestamp and increment connection_count.
    pub async fn touch_certificate(
        &self,
        fingerprint: &[u8; 32],
        last_seen_ms: i64,
    ) -> StorageResult<()> {
        let fp = fingerprint.to_vec();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<()> {
            let conn = conn.blocking_lock();
            let now_ms = chrono::Utc::now().timestamp_millis();
            conn.execute(
                "UPDATE certificates SET last_seen = ?1, connection_count = connection_count + 1, updated_at = ?2 WHERE fingerprint = ?3",
                params![last_seen_ms, now_ms, fp],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// Delete a certificate by fingerprint.
    pub async fn delete_certificate(&self, fingerprint: &[u8; 32]) -> StorageResult<()> {
        let fp = fingerprint.to_vec();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<()> {
            let conn = conn.blocking_lock();
            conn.execute(
                "DELETE FROM certificates WHERE fingerprint = ?1",
                params![fp],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// List all certificate fingerprints (for reload on restart).
    pub async fn list_certificate_fingerprints(&self) -> StorageResult<Vec<[u8; 32]>> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<Vec<[u8; 32]>> {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare("SELECT fingerprint FROM certificates")?;
            let rows = stmt.query_map([], |row| {
                let fp_blob: Vec<u8> = row.get(0)?;
                Ok(fp_blob)
            })?;
            let mut fps = Vec::new();
            for row in rows {
                let blob = row?;
                if blob.len() == 32 {
                    let mut fp = [0u8; 32];
                    fp.copy_from_slice(&blob);
                    fps.push(fp);
                }
            }
            Ok(fps)
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// List the most recently seen certificate fingerprints, ordered by last_seen DESC.
    ///
    /// This is used on restart to pre-populate the LRU cache with the most recent
    /// fingerprints (up to the cache capacity), ensuring previously-seen certificates
    /// are not re-reported as new.
    pub async fn list_recent_fingerprints(&self, limit: usize) -> StorageResult<Vec<[u8; 32]>> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<Vec<[u8; 32]>> {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT fingerprint FROM certificates ORDER BY last_seen DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![limit as i64], |row| {
                let fp_blob: Vec<u8> = row.get(0)?;
                Ok(fp_blob)
            })?;
            let mut fps = Vec::new();
            for row in rows {
                let blob = row?;
                if blob.len() == 32 {
                    let mut fp = [0u8; 32];
                    fp.copy_from_slice(&blob);
                    fps.push(fp);
                }
            }
            Ok(fps)
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    // -----------------------------------------------------------------------
    // Action Directives CRUD
    // -----------------------------------------------------------------------

    /// Insert a new action directive.
    pub async fn insert_action_directive(
        &self,
        row: &ActionDirectiveRow,
    ) -> StorageResult<()> {
        let row = row.clone();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<()> {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT INTO action_directives (
                    id, correlation_id, cert_fingerprint, action_type,
                    severity, reasoning, status, attempt_count,
                    created_at, executed_at, expired_at, failure_reason
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    row.id,
                    row.correlation_id,
                    row.cert_fingerprint.as_slice(),
                    row.action_type,
                    row.severity,
                    row.reasoning,
                    row.status,
                    row.attempt_count,
                    row.created_at,
                    row.executed_at,
                    row.expired_at,
                    row.failure_reason,
                ],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// Get an action directive by ID.
    pub async fn get_action_directive(
        &self,
        id: &str,
    ) -> StorageResult<Option<ActionDirectiveRow>> {
        let id = id.to_string();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<Option<ActionDirectiveRow>> {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT id, correlation_id, cert_fingerprint, action_type,
                        severity, reasoning, status, attempt_count,
                        created_at, executed_at, expired_at, failure_reason
                 FROM action_directives WHERE id = ?1",
            )?;
            let result = stmt
                .query_row(params![id], |row| {
                    Ok(row_to_action_directive(row))
                })
                .optional()?;
            match result {
                Some(Ok(r)) => Ok(Some(r)),
                Some(Err(e)) => Err(e),
                None => Ok(None),
            }
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// Update the status of an action directive.
    pub async fn update_directive_status(
        &self,
        id: &str,
        status: &str,
        failure_reason: Option<&str>,
    ) -> StorageResult<()> {
        let id = id.to_string();
        let status = status.to_string();
        let failure_reason = failure_reason.map(|s| s.to_string());
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<()> {
            let conn = conn.blocking_lock();
            let now_ms = chrono::Utc::now().timestamp_millis();
            conn.execute(
                "UPDATE action_directives SET status = ?1, executed_at = ?2, failure_reason = ?3 WHERE id = ?4",
                params![status, now_ms, failure_reason, id],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// List action directives by status.
    pub async fn list_directives_by_status(
        &self,
        status: &str,
    ) -> StorageResult<Vec<ActionDirectiveRow>> {
        let status = status.to_string();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<Vec<ActionDirectiveRow>> {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT id, correlation_id, cert_fingerprint, action_type,
                        severity, reasoning, status, attempt_count,
                        created_at, executed_at, expired_at, failure_reason
                 FROM action_directives WHERE status = ?1",
            )?;
            let rows = stmt.query_map(params![status], |row| {
                Ok(row_to_action_directive(row))
            })?;
            let mut results = Vec::new();
            for row in rows {
                results.push(row??);
            }
            Ok(results)
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// List pending action directives for a specific certificate fingerprint.
    pub async fn list_pending_directives_by_fingerprint(
        &self,
        fingerprint: &[u8; 32],
    ) -> StorageResult<Vec<ActionDirectiveRow>> {
        let fp = fingerprint.to_vec();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<Vec<ActionDirectiveRow>> {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT id, correlation_id, cert_fingerprint, action_type,
                        severity, reasoning, status, attempt_count,
                        created_at, executed_at, expired_at, failure_reason
                 FROM action_directives WHERE cert_fingerprint = ?1 AND status = 'pending'",
            )?;
            let rows = stmt.query_map(params![fp], |row| {
                Ok(row_to_action_directive(row))
            })?;
            let mut results = Vec::new();
            for row in rows {
                results.push(row??);
            }
            Ok(results)
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// Mark a directive as failed, updating its status, attempt_count, and failure_reason.
    pub async fn mark_directive_failed(
        &self,
        id: &str,
        attempt_count: i32,
        failure_reason: &str,
    ) -> StorageResult<()> {
        let id = id.to_string();
        let failure_reason = failure_reason.to_string();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<()> {
            let conn = conn.blocking_lock();
            let now_ms = chrono::Utc::now().timestamp_millis();
            conn.execute(
                "UPDATE action_directives SET status = 'failed', attempt_count = ?1, failure_reason = ?2, executed_at = ?3 WHERE id = ?4",
                params![attempt_count, failure_reason, now_ms, id],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// Delete an action directive by ID.
    pub async fn delete_action_directive(&self, id: &str) -> StorageResult<()> {
        let id = id.to_string();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<()> {
            let conn = conn.blocking_lock();
            conn.execute(
                "DELETE FROM action_directives WHERE id = ?1",
                params![id],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    // -----------------------------------------------------------------------
    // Shadow Certificates CRUD
    // -----------------------------------------------------------------------

    /// Insert or update a shadow certificate record.
    pub async fn upsert_shadow_certificate(
        &self,
        row: &ShadowCertificateRow,
    ) -> StorageResult<()> {
        let row = row.clone();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<()> {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT INTO shadow_certificates (
                    fingerprint, risk_level, first_classified, last_escalated,
                    escalation_count, source_ip, destination_ip, first_seen,
                    is_resolved, resolved_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    risk_level = ?2,
                    last_escalated = ?4,
                    escalation_count = ?5,
                    is_resolved = ?9,
                    resolved_at = ?10",
                params![
                    row.fingerprint.as_slice(),
                    risk_level_to_str(row.risk_level),
                    row.first_classified,
                    row.last_escalated,
                    row.escalation_count,
                    row.source_ip,
                    row.destination_ip,
                    row.first_seen,
                    row.is_resolved as i32,
                    row.resolved_at,
                ],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// Get a shadow certificate by fingerprint.
    pub async fn get_shadow_certificate(
        &self,
        fingerprint: &[u8; 32],
    ) -> StorageResult<Option<ShadowCertificateRow>> {
        let fp = fingerprint.to_vec();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<Option<ShadowCertificateRow>> {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT fingerprint, risk_level, first_classified, last_escalated,
                        escalation_count, source_ip, destination_ip, first_seen,
                        is_resolved, resolved_at
                 FROM shadow_certificates WHERE fingerprint = ?1",
            )?;
            let result = stmt
                .query_row(params![fp], |row| {
                    Ok(row_to_shadow_certificate(row))
                })
                .optional()?;
            match result {
                Some(Ok(r)) => Ok(Some(r)),
                Some(Err(e)) => Err(e),
                None => Ok(None),
            }
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// List all unresolved shadow certificates.
    pub async fn list_unresolved_shadow_certificates(
        &self,
    ) -> StorageResult<Vec<ShadowCertificateRow>> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<Vec<ShadowCertificateRow>> {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT fingerprint, risk_level, first_classified, last_escalated,
                        escalation_count, source_ip, destination_ip, first_seen,
                        is_resolved, resolved_at
                 FROM shadow_certificates WHERE is_resolved = 0",
            )?;
            let rows = stmt.query_map([], |row| Ok(row_to_shadow_certificate(row)))?;
            let mut results = Vec::new();
            for row in rows {
                results.push(row??);
            }
            Ok(results)
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// Delete a shadow certificate by fingerprint.
    pub async fn delete_shadow_certificate(
        &self,
        fingerprint: &[u8; 32],
    ) -> StorageResult<()> {
        let fp = fingerprint.to_vec();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<()> {
            let conn = conn.blocking_lock();
            conn.execute(
                "DELETE FROM shadow_certificates WHERE fingerprint = ?1",
                params![fp],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    // -----------------------------------------------------------------------
    // Renewal Predictions CRUD
    // -----------------------------------------------------------------------

    /// Insert or update a renewal prediction.
    pub async fn upsert_renewal_prediction(
        &self,
        row: &RenewalPredictionRow,
    ) -> StorageResult<()> {
        let row = row.clone();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<()> {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT INTO renewal_predictions (
                    cert_fingerprint, failure_probability, severity,
                    days_until_expiry, renewal_activity_detected, reasoning,
                    last_evaluated, created_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                ON CONFLICT(cert_fingerprint) DO UPDATE SET
                    failure_probability = ?2,
                    severity = ?3,
                    days_until_expiry = ?4,
                    renewal_activity_detected = ?5,
                    reasoning = ?6,
                    last_evaluated = ?7",
                params![
                    row.cert_fingerprint.as_slice(),
                    row.failure_probability,
                    row.severity,
                    row.days_until_expiry,
                    row.renewal_activity_detected as i32,
                    row.reasoning,
                    row.last_evaluated,
                    row.created_at,
                ],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// Get a renewal prediction by certificate fingerprint.
    pub async fn get_renewal_prediction(
        &self,
        fingerprint: &[u8; 32],
    ) -> StorageResult<Option<RenewalPredictionRow>> {
        let fp = fingerprint.to_vec();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<Option<RenewalPredictionRow>> {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT cert_fingerprint, failure_probability, severity,
                        days_until_expiry, renewal_activity_detected, reasoning,
                        last_evaluated, created_at
                 FROM renewal_predictions WHERE cert_fingerprint = ?1",
            )?;
            let result = stmt
                .query_row(params![fp], |row| {
                    Ok(row_to_renewal_prediction(row))
                })
                .optional()?;
            match result {
                Some(Ok(r)) => Ok(Some(r)),
                Some(Err(e)) => Err(e),
                None => Ok(None),
            }
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// Delete a renewal prediction by certificate fingerprint.
    pub async fn delete_renewal_prediction(
        &self,
        fingerprint: &[u8; 32],
    ) -> StorageResult<()> {
        let fp = fingerprint.to_vec();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<()> {
            let conn = conn.blocking_lock();
            conn.execute(
                "DELETE FROM renewal_predictions WHERE cert_fingerprint = ?1",
                params![fp],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// List all active renewal predictions.
    pub async fn list_all_renewal_predictions(
        &self,
    ) -> StorageResult<Vec<RenewalPredictionRow>> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<Vec<RenewalPredictionRow>> {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT cert_fingerprint, failure_probability, severity,
                        days_until_expiry, renewal_activity_detected, reasoning,
                        last_evaluated, created_at
                 FROM renewal_predictions",
            )?;
            let rows = stmt.query_map([], |row| Ok(row_to_renewal_prediction(row)))?;
            let mut results = Vec::new();
            for row in rows {
                results.push(row??);
            }
            Ok(results)
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// List certificates whose `not_after` is within the given number of days from now.
    /// This returns certificates that are approaching expiry or already expired.
    pub async fn list_certificates_expiring_within_days(
        &self,
        days: i32,
    ) -> StorageResult<Vec<CertificateMetadata>> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<Vec<CertificateMetadata>> {
            let conn = conn.blocking_lock();
            let cutoff_ms = chrono::Utc::now().timestamp_millis()
                + (days as i64 * 24 * 60 * 60 * 1000);
            let mut stmt = conn.prepare(
                "SELECT fingerprint, subject, issuer, serial_number,
                        not_before, not_after, sans, key_algorithm, key_size,
                        chain_depth, issuer_fingerprint, first_seen, last_seen,
                        connection_count, source_ip, destination_ip, sni_hostname,
                        completeness_flags
                 FROM certificates WHERE not_after <= ?1",
            )?;
            let rows = stmt.query_map(params![cutoff_ms], |row| {
                Ok(row_to_certificate_metadata(row))
            })?;
            let mut results = Vec::new();
            for row in rows {
                results.push(row??);
            }
            Ok(results)
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// List all certificates, ordered by last_seen DESC, with an optional limit.
    pub async fn list_all_certificates(
        &self,
        limit: usize,
    ) -> StorageResult<Vec<CertificateMetadata>> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<Vec<CertificateMetadata>> {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT fingerprint, subject, issuer, serial_number,
                        not_before, not_after, sans, key_algorithm, key_size,
                        chain_depth, issuer_fingerprint, first_seen, last_seen,
                        connection_count, source_ip, destination_ip, sni_hostname,
                        completeness_flags
                 FROM certificates ORDER BY last_seen DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![limit as i64], |row| {
                Ok(row_to_certificate_metadata(row))
            })?;
            let mut results = Vec::new();
            for row in rows {
                results.push(row??);
            }
            Ok(results)
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// List recent action directives (executed or failed), ordered by executed_at DESC.
    pub async fn list_recent_directives(
        &self,
        limit: usize,
    ) -> StorageResult<Vec<ActionDirectiveRow>> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<Vec<ActionDirectiveRow>> {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT id, correlation_id, cert_fingerprint, action_type,
                        severity, reasoning, status, attempt_count,
                        created_at, executed_at, expired_at, failure_reason
                 FROM action_directives
                 WHERE status IN ('executed', 'failed', 'expired')
                 ORDER BY executed_at DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![limit as i64], |row| {
                Ok(row_to_action_directive(row))
            })?;
            let mut results = Vec::new();
            for row in rows {
                results.push(row??);
            }
            Ok(results)
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// Count certificates in the database.
    pub async fn count_certificates(&self) -> StorageResult<u64> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<u64> {
            let conn = conn.blocking_lock();
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM certificates",
                [],
                |row| row.get(0),
            )?;
            Ok(count as u64)
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// Count pending (active anomaly) directives.
    pub async fn count_pending_directives(&self) -> StorageResult<u64> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<u64> {
            let conn = conn.blocking_lock();
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM action_directives WHERE status = 'pending'",
                [],
                |row| row.get(0),
            )?;
            Ok(count as u64)
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    // -----------------------------------------------------------------------
    // Audit Log CRUD
    // -----------------------------------------------------------------------

    /// Insert an audit log entry.
    pub async fn insert_audit_log(&self, row: &AuditLogRow) -> StorageResult<()> {
        let row = row.clone();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<()> {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT INTO audit_log (
                    correlation_id, cert_fingerprint, stage,
                    timestamp, details, created_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    row.correlation_id,
                    row.cert_fingerprint.as_slice(),
                    row.stage,
                    row.timestamp,
                    row.details,
                    row.created_at,
                ],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// Get audit log entries by correlation ID.
    pub async fn get_audit_logs_by_correlation(
        &self,
        correlation_id: &str,
    ) -> StorageResult<Vec<AuditLogRow>> {
        let cid = correlation_id.to_string();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<Vec<AuditLogRow>> {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT id, correlation_id, cert_fingerprint, stage,
                        timestamp, details, created_at
                 FROM audit_log WHERE correlation_id = ?1
                 ORDER BY timestamp ASC",
            )?;
            let rows = stmt.query_map(params![cid], |row| Ok(row_to_audit_log(row)))?;
            let mut results = Vec::new();
            for row in rows {
                results.push(row??);
            }
            Ok(results)
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    // -----------------------------------------------------------------------
    // Certificate Inventory CRUD
    // -----------------------------------------------------------------------

    /// Insert or update a certificate inventory entry.
    pub async fn upsert_inventory_entry(
        &self,
        row: &CertificateInventoryRow,
    ) -> StorageResult<()> {
        let row = row.clone();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<()> {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT INTO certificate_inventory (
                    fingerprint, subject, source, imported_at, last_refresh_id
                ) VALUES (?1, ?2, ?3, ?4, ?5)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    subject = ?2,
                    source = ?3,
                    imported_at = ?4,
                    last_refresh_id = ?5",
                params![
                    row.fingerprint.as_slice(),
                    row.subject,
                    row.source,
                    row.imported_at,
                    row.last_refresh_id,
                ],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// Check if a fingerprint exists in the inventory.
    pub async fn inventory_contains(
        &self,
        fingerprint: &[u8; 32],
    ) -> StorageResult<bool> {
        let fp = fingerprint.to_vec();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<bool> {
            let conn = conn.blocking_lock();
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM certificate_inventory WHERE fingerprint = ?1",
                params![fp],
                |row| row.get(0),
            )?;
            Ok(count > 0)
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// Remove inventory entries not updated in the given refresh.
    pub async fn remove_stale_inventory_entries(
        &self,
        refresh_id: &str,
    ) -> StorageResult<u64> {
        let rid = refresh_id.to_string();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<u64> {
            let conn = conn.blocking_lock();
            let deleted = conn.execute(
                "DELETE FROM certificate_inventory WHERE last_refresh_id != ?1",
                params![rid],
            )?;
            Ok(deleted as u64)
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// Delete an inventory entry by fingerprint.
    pub async fn delete_inventory_entry(
        &self,
        fingerprint: &[u8; 32],
    ) -> StorageResult<()> {
        let fp = fingerprint.to_vec();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<()> {
            let conn = conn.blocking_lock();
            conn.execute(
                "DELETE FROM certificate_inventory WHERE fingerprint = ?1",
                params![fp],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    // -----------------------------------------------------------------------
    // Inventory Refresh Log CRUD
    // -----------------------------------------------------------------------

    /// Insert an inventory refresh log entry.
    pub async fn insert_refresh_log(
        &self,
        row: &InventoryRefreshLogRow,
    ) -> StorageResult<()> {
        let row = row.clone();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<()> {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT INTO inventory_refresh_log (
                    id, timestamp, source, total_entries, new_entries,
                    removed_entries, skipped_invalid, success
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    row.id,
                    row.timestamp,
                    row.source,
                    row.total_entries,
                    row.new_entries,
                    row.removed_entries,
                    row.skipped_invalid,
                    row.success as i32,
                ],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// Get the most recent refresh log entry.
    pub async fn get_latest_refresh_log(
        &self,
    ) -> StorageResult<Option<InventoryRefreshLogRow>> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<Option<InventoryRefreshLogRow>> {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT id, timestamp, source, total_entries, new_entries,
                        removed_entries, skipped_invalid, success
                 FROM inventory_refresh_log ORDER BY timestamp DESC LIMIT 1",
            )?;
            let result = stmt
                .query_row([], |row| Ok(row_to_refresh_log(row)))
                .optional()?;
            match result {
                Some(Ok(r)) => Ok(Some(r)),
                Some(Err(e)) => Err(e),
                None => Ok(None),
            }
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    // -----------------------------------------------------------------------
    // Data Retention Cleanup
    // -----------------------------------------------------------------------

    /// Delete certificates where `last_seen` is older than `retention_days` days.
    /// Returns the number of deleted records.
    pub async fn cleanup_old_certificates(
        &self,
        retention_days: u32,
    ) -> StorageResult<u64> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<u64> {
            let conn = conn.blocking_lock();
            let cutoff_ms = chrono::Utc::now().timestamp_millis()
                - (retention_days as i64 * 24 * 60 * 60 * 1000);
            let deleted = conn.execute(
                "DELETE FROM certificates WHERE last_seen < ?1",
                params![cutoff_ms],
            )?;
            Ok(deleted as u64)
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// Delete audit log entries older than `retention_days` days.
    /// Returns the number of deleted records.
    pub async fn cleanup_old_audit_logs(
        &self,
        retention_days: u32,
    ) -> StorageResult<u64> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> StorageResult<u64> {
            let conn = conn.blocking_lock();
            let cutoff_ms = chrono::Utc::now().timestamp_millis()
                - (retention_days as i64 * 24 * 60 * 60 * 1000);
            let deleted = conn.execute(
                "DELETE FROM audit_log WHERE created_at < ?1",
                params![cutoff_ms],
            )?;
            Ok(deleted as u64)
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    /// Run the full retention cleanup with the 90-day policy.
    /// Deletes certificates with last_seen > 90 days and audit logs > 90 days.
    pub async fn run_retention_cleanup(&self) -> StorageResult<(u64, u64)> {
        let certs_deleted = self.cleanup_old_certificates(90).await?;
        let logs_deleted = self.cleanup_old_audit_logs(90).await?;
        tracing::info!(
            certs_deleted,
            logs_deleted,
            "Retention cleanup completed"
        );
        Ok((certs_deleted, logs_deleted))
    }
}

// ---------------------------------------------------------------------------
// Helper functions for row conversion
// ---------------------------------------------------------------------------

fn row_to_certificate_metadata(
    row: &rusqlite::Row,
) -> StorageResult<CertificateMetadata> {
    use chrono::TimeZone;

    let fp_blob: Vec<u8> = row.get(0)?;
    let mut fingerprint = [0u8; 32];
    if fp_blob.len() == 32 {
        fingerprint.copy_from_slice(&fp_blob);
    }

    let subject: String = row.get(1)?;
    let issuer: String = row.get(2)?;
    let serial_number: String = row.get(3)?;
    let not_before_ms: i64 = row.get(4)?;
    let not_after_ms: i64 = row.get(5)?;
    let sans_json: Option<String> = row.get(6)?;
    let key_algorithm: String = row.get(7)?;
    let key_size: u32 = row.get(8)?;
    let chain_depth: i32 = row.get(9)?;
    let issuer_fp_blob: Option<Vec<u8>> = row.get(10)?;
    let first_seen_ms: i64 = row.get(11)?;
    let last_seen_ms: i64 = row.get(12)?;
    let connection_count: i64 = row.get(13)?;
    let source_ip: Option<String> = row.get(14)?;
    let destination_ip: Option<String> = row.get(15)?;
    let sni_hostname: Option<String> = row.get(16)?;
    let completeness_flags: i64 = row.get(17)?;

    let sans: Vec<String> = sans_json
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default();

    let issuer_fingerprint = issuer_fp_blob.and_then(|blob| {
        if blob.len() == 32 {
            let mut fp = [0u8; 32];
            fp.copy_from_slice(&blob);
            Some(fp)
        } else {
            None
        }
    });

    Ok(CertificateMetadata {
        fingerprint,
        subject,
        issuer,
        serial_number,
        not_before: chrono::Utc.timestamp_millis_opt(not_before_ms).unwrap(),
        not_after: chrono::Utc.timestamp_millis_opt(not_after_ms).unwrap(),
        sans,
        key_algorithm,
        key_size,
        chain_depth: chain_depth as u8,
        issuer_fingerprint,
        first_seen: chrono::Utc.timestamp_millis_opt(first_seen_ms).unwrap(),
        last_seen: chrono::Utc.timestamp_millis_opt(last_seen_ms).unwrap(),
        connection_count: connection_count as u64,
        source_ip,
        destination_ip,
        sni_hostname,
        completeness_flags: completeness_flags as u32,
    })
}

fn row_to_action_directive(row: &rusqlite::Row) -> StorageResult<ActionDirectiveRow> {
    let fp_blob: Vec<u8> = row.get(2)?;
    let mut cert_fingerprint = [0u8; 32];
    if fp_blob.len() == 32 {
        cert_fingerprint.copy_from_slice(&fp_blob);
    }

    Ok(ActionDirectiveRow {
        id: row.get(0)?,
        correlation_id: row.get(1)?,
        cert_fingerprint,
        action_type: row.get(3)?,
        severity: row.get(4)?,
        reasoning: row.get(5)?,
        status: row.get(6)?,
        attempt_count: row.get(7)?,
        created_at: row.get(8)?,
        executed_at: row.get(9)?,
        expired_at: row.get(10)?,
        failure_reason: row.get(11)?,
    })
}

fn row_to_shadow_certificate(row: &rusqlite::Row) -> StorageResult<ShadowCertificateRow> {
    let fp_blob: Vec<u8> = row.get(0)?;
    let mut fingerprint = [0u8; 32];
    if fp_blob.len() == 32 {
        fingerprint.copy_from_slice(&fp_blob);
    }
    let risk_level_str: String = row.get(1)?;
    let is_resolved_int: i32 = row.get(8)?;

    Ok(ShadowCertificateRow {
        fingerprint,
        risk_level: str_to_risk_level(&risk_level_str),
        first_classified: row.get(2)?,
        last_escalated: row.get(3)?,
        escalation_count: row.get(4)?,
        source_ip: row.get(5)?,
        destination_ip: row.get(6)?,
        first_seen: row.get(7)?,
        is_resolved: is_resolved_int != 0,
        resolved_at: row.get(9)?,
    })
}

fn row_to_renewal_prediction(row: &rusqlite::Row) -> StorageResult<RenewalPredictionRow> {
    let fp_blob: Vec<u8> = row.get(0)?;
    let mut cert_fingerprint = [0u8; 32];
    if fp_blob.len() == 32 {
        cert_fingerprint.copy_from_slice(&fp_blob);
    }
    let renewal_detected_int: i32 = row.get(4)?;

    Ok(RenewalPredictionRow {
        cert_fingerprint,
        failure_probability: row.get(1)?,
        severity: row.get(2)?,
        days_until_expiry: row.get(3)?,
        renewal_activity_detected: renewal_detected_int != 0,
        reasoning: row.get(5)?,
        last_evaluated: row.get(6)?,
        created_at: row.get(7)?,
    })
}

fn row_to_audit_log(row: &rusqlite::Row) -> StorageResult<AuditLogRow> {
    let fp_blob: Vec<u8> = row.get(2)?;
    let mut cert_fingerprint = [0u8; 32];
    if fp_blob.len() == 32 {
        cert_fingerprint.copy_from_slice(&fp_blob);
    }

    Ok(AuditLogRow {
        id: row.get(0)?,
        correlation_id: row.get(1)?,
        cert_fingerprint,
        stage: row.get(3)?,
        timestamp: row.get(4)?,
        details: row.get(5)?,
        created_at: row.get(6)?,
    })
}

fn row_to_refresh_log(row: &rusqlite::Row) -> StorageResult<InventoryRefreshLogRow> {
    let success_int: i32 = row.get(7)?;
    Ok(InventoryRefreshLogRow {
        id: row.get(0)?,
        timestamp: row.get(1)?,
        source: row.get(2)?,
        total_entries: row.get(3)?,
        new_entries: row.get(4)?,
        removed_entries: row.get(5)?,
        skipped_invalid: row.get(6)?,
        success: success_int != 0,
    })
}

// ---------------------------------------------------------------------------
// Enum serialization helpers
// ---------------------------------------------------------------------------

fn risk_level_to_str(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Critical => "critical",
    }
}

fn str_to_risk_level(s: &str) -> RiskLevel {
    match s {
        "low" => RiskLevel::Low,
        "medium" => RiskLevel::Medium,
        "high" => RiskLevel::High,
        "critical" => RiskLevel::Critical,
        _ => RiskLevel::Low,
    }
}

// ---------------------------------------------------------------------------
// Schema SQL
// ---------------------------------------------------------------------------

const SCHEMA_SQL: &str = include_str!("storage_schema.sql");

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_test_certificate(fingerprint: [u8; 32]) -> CertificateMetadata {
        let now = Utc::now();
        CertificateMetadata {
            fingerprint,
            subject: "CN=test.example.com".to_string(),
            issuer: "CN=Test CA".to_string(),
            serial_number: "01:02:03".to_string(),
            not_before: now - chrono::Duration::days(30),
            not_after: now + chrono::Duration::days(335),
            sans: vec!["test.example.com".to_string()],
            key_algorithm: "RSA".to_string(),
            key_size: 2048,
            chain_depth: 2,
            issuer_fingerprint: None,
            first_seen: now,
            last_seen: now,
            connection_count: 1,
            source_ip: Some("192.168.1.1".to_string()),
            destination_ip: Some("10.0.0.1".to_string()),
            sni_hostname: Some("test.example.com".to_string()),
            completeness_flags: 0x7F,
        }
    }

    #[tokio::test]
    async fn test_open_in_memory() {
        let storage = Storage::open_in_memory().await.unwrap();
        // Just verify it opens without error
        drop(storage);
    }

    #[tokio::test]
    async fn test_certificate_crud() {
        let storage = Storage::open_in_memory().await.unwrap();
        let fp = [1u8; 32];
        let cert = make_test_certificate(fp);

        // Insert
        storage.upsert_certificate(&cert).await.unwrap();

        // Read
        let loaded = storage.get_certificate(&fp).await.unwrap().unwrap();
        assert_eq!(loaded.fingerprint, fp);
        assert_eq!(loaded.subject, "CN=test.example.com");
        assert_eq!(loaded.key_algorithm, "RSA");
        assert_eq!(loaded.key_size, 2048);
        assert_eq!(loaded.sans, vec!["test.example.com".to_string()]);

        // Touch (update last_seen + increment count)
        let new_ts = Utc::now().timestamp_millis();
        storage.touch_certificate(&fp, new_ts).await.unwrap();
        let updated = storage.get_certificate(&fp).await.unwrap().unwrap();
        assert_eq!(updated.connection_count, 2);

        // List fingerprints
        let fps = storage.list_certificate_fingerprints().await.unwrap();
        assert_eq!(fps.len(), 1);
        assert_eq!(fps[0], fp);

        // Delete
        storage.delete_certificate(&fp).await.unwrap();
        let gone = storage.get_certificate(&fp).await.unwrap();
        assert!(gone.is_none());
    }

    #[tokio::test]
    async fn test_action_directive_crud() {
        let storage = Storage::open_in_memory().await.unwrap();
        let fp = [2u8; 32];
        let cert = make_test_certificate(fp);
        storage.upsert_certificate(&cert).await.unwrap();

        let now_ms = Utc::now().timestamp_millis();
        let row = ActionDirectiveRow {
            id: "dir-001".to_string(),
            correlation_id: "corr-001".to_string(),
            cert_fingerprint: fp,
            action_type: "alert".to_string(),
            severity: "high".to_string(),
            reasoning: Some("Test reasoning".to_string()),
            status: "pending".to_string(),
            attempt_count: 0,
            created_at: now_ms,
            executed_at: None,
            expired_at: None,
            failure_reason: None,
        };

        storage.insert_action_directive(&row).await.unwrap();

        let loaded = storage.get_action_directive("dir-001").await.unwrap().unwrap();
        assert_eq!(loaded.action_type, "alert");
        assert_eq!(loaded.severity, "high");
        assert_eq!(loaded.status, "pending");

        // Update status
        storage
            .update_directive_status("dir-001", "executed", None)
            .await
            .unwrap();
        let updated = storage.get_action_directive("dir-001").await.unwrap().unwrap();
        assert_eq!(updated.status, "executed");

        // List by status
        let pending = storage.list_directives_by_status("pending").await.unwrap();
        assert_eq!(pending.len(), 0);
        let executed = storage.list_directives_by_status("executed").await.unwrap();
        assert_eq!(executed.len(), 1);

        // Delete
        storage.delete_action_directive("dir-001").await.unwrap();
        let gone = storage.get_action_directive("dir-001").await.unwrap();
        assert!(gone.is_none());
    }

    #[tokio::test]
    async fn test_shadow_certificate_crud() {
        let storage = Storage::open_in_memory().await.unwrap();
        let fp = [3u8; 32];
        let cert = make_test_certificate(fp);
        storage.upsert_certificate(&cert).await.unwrap();

        let now_ms = Utc::now().timestamp_millis();
        let row = ShadowCertificateRow {
            fingerprint: fp,
            risk_level: RiskLevel::High,
            first_classified: now_ms,
            last_escalated: None,
            escalation_count: 0,
            source_ip: Some("192.168.1.1".to_string()),
            destination_ip: Some("10.0.0.1".to_string()),
            first_seen: now_ms,
            is_resolved: false,
            resolved_at: None,
        };

        storage.upsert_shadow_certificate(&row).await.unwrap();

        let loaded = storage.get_shadow_certificate(&fp).await.unwrap().unwrap();
        assert_eq!(loaded.risk_level, RiskLevel::High);
        assert!(!loaded.is_resolved);

        // List unresolved
        let unresolved = storage.list_unresolved_shadow_certificates().await.unwrap();
        assert_eq!(unresolved.len(), 1);

        // Resolve it
        let resolved_row = ShadowCertificateRow {
            is_resolved: true,
            resolved_at: Some(now_ms),
            ..row
        };
        storage.upsert_shadow_certificate(&resolved_row).await.unwrap();
        let unresolved = storage.list_unresolved_shadow_certificates().await.unwrap();
        assert_eq!(unresolved.len(), 0);

        // Delete
        storage.delete_shadow_certificate(&fp).await.unwrap();
        let gone = storage.get_shadow_certificate(&fp).await.unwrap();
        assert!(gone.is_none());
    }

    #[tokio::test]
    async fn test_renewal_prediction_crud() {
        let storage = Storage::open_in_memory().await.unwrap();
        let fp = [4u8; 32];
        let cert = make_test_certificate(fp);
        storage.upsert_certificate(&cert).await.unwrap();

        let now_ms = Utc::now().timestamp_millis();
        let row = RenewalPredictionRow {
            cert_fingerprint: fp,
            failure_probability: 0.85,
            severity: "critical".to_string(),
            days_until_expiry: 7,
            renewal_activity_detected: false,
            reasoning: Some("No renewal activity detected".to_string()),
            last_evaluated: now_ms,
            created_at: now_ms,
        };

        storage.upsert_renewal_prediction(&row).await.unwrap();

        let loaded = storage.get_renewal_prediction(&fp).await.unwrap().unwrap();
        assert_eq!(loaded.failure_probability, 0.85);
        assert_eq!(loaded.days_until_expiry, 7);
        assert!(!loaded.renewal_activity_detected);

        // Delete
        storage.delete_renewal_prediction(&fp).await.unwrap();
        let gone = storage.get_renewal_prediction(&fp).await.unwrap();
        assert!(gone.is_none());
    }

    #[tokio::test]
    async fn test_audit_log_crud() {
        let storage = Storage::open_in_memory().await.unwrap();
        let fp = [5u8; 32];
        let now_ms = Utc::now().timestamp_millis();

        let row = AuditLogRow {
            id: 0, // auto-increment, ignored on insert
            correlation_id: "corr-audit-001".to_string(),
            cert_fingerprint: fp,
            stage: "observation".to_string(),
            timestamp: now_ms,
            details: r#"{"src_ip":"192.168.1.1"}"#.to_string(),
            created_at: now_ms,
        };

        storage.insert_audit_log(&row).await.unwrap();

        let logs = storage
            .get_audit_logs_by_correlation("corr-audit-001")
            .await
            .unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].stage, "observation");
        assert_eq!(logs[0].correlation_id, "corr-audit-001");
    }

    #[tokio::test]
    async fn test_inventory_crud() {
        let storage = Storage::open_in_memory().await.unwrap();
        let fp = [6u8; 32];
        let now_ms = Utc::now().timestamp_millis();

        let row = CertificateInventoryRow {
            fingerprint: fp,
            subject: "CN=inventory.example.com".to_string(),
            source: "file".to_string(),
            imported_at: now_ms,
            last_refresh_id: "refresh-001".to_string(),
        };

        storage.upsert_inventory_entry(&row).await.unwrap();
        assert!(storage.inventory_contains(&fp).await.unwrap());

        let unknown_fp = [99u8; 32];
        assert!(!storage.inventory_contains(&unknown_fp).await.unwrap());

        // Remove stale entries (different refresh ID)
        let removed = storage
            .remove_stale_inventory_entries("refresh-002")
            .await
            .unwrap();
        assert_eq!(removed, 1);
        assert!(!storage.inventory_contains(&fp).await.unwrap());
    }

    #[tokio::test]
    async fn test_refresh_log_crud() {
        let storage = Storage::open_in_memory().await.unwrap();
        let now_ms = Utc::now().timestamp_millis();

        let row = InventoryRefreshLogRow {
            id: "refresh-001".to_string(),
            timestamp: now_ms,
            source: "file".to_string(),
            total_entries: Some(100),
            new_entries: Some(10),
            removed_entries: Some(5),
            skipped_invalid: Some(2),
            success: true,
        };

        storage.insert_refresh_log(&row).await.unwrap();

        let latest = storage.get_latest_refresh_log().await.unwrap().unwrap();
        assert_eq!(latest.id, "refresh-001");
        assert_eq!(latest.total_entries, Some(100));
        assert!(latest.success);
    }

    #[tokio::test]
    async fn test_retention_cleanup() {
        let storage = Storage::open_in_memory().await.unwrap();

        // Insert a certificate with last_seen 100 days ago
        let fp_old = [10u8; 32];
        let mut cert_old = make_test_certificate(fp_old);
        cert_old.last_seen = Utc::now() - chrono::Duration::days(100);
        storage.upsert_certificate(&cert_old).await.unwrap();

        // Insert a certificate with last_seen today
        let fp_new = [11u8; 32];
        let cert_new = make_test_certificate(fp_new);
        storage.upsert_certificate(&cert_new).await.unwrap();

        // Insert an old audit log (100 days ago)
        let old_ts = (Utc::now() - chrono::Duration::days(100)).timestamp_millis();
        let old_log = AuditLogRow {
            id: 0,
            correlation_id: "old-corr".to_string(),
            cert_fingerprint: fp_old,
            stage: "observation".to_string(),
            timestamp: old_ts,
            details: "{}".to_string(),
            created_at: old_ts,
        };
        storage.insert_audit_log(&old_log).await.unwrap();

        // Insert a recent audit log
        let new_ts = Utc::now().timestamp_millis();
        let new_log = AuditLogRow {
            id: 0,
            correlation_id: "new-corr".to_string(),
            cert_fingerprint: fp_new,
            stage: "observation".to_string(),
            timestamp: new_ts,
            details: "{}".to_string(),
            created_at: new_ts,
        };
        storage.insert_audit_log(&new_log).await.unwrap();

        // Run cleanup
        let (certs_deleted, logs_deleted) = storage.run_retention_cleanup().await.unwrap();
        assert_eq!(certs_deleted, 1);
        assert_eq!(logs_deleted, 1);

        // Verify old cert is gone, new cert remains
        assert!(storage.get_certificate(&fp_old).await.unwrap().is_none());
        assert!(storage.get_certificate(&fp_new).await.unwrap().is_some());

        // Verify old log is gone, new log remains
        let old_logs = storage
            .get_audit_logs_by_correlation("old-corr")
            .await
            .unwrap();
        assert_eq!(old_logs.len(), 0);
        let new_logs = storage
            .get_audit_logs_by_correlation("new-corr")
            .await
            .unwrap();
        assert_eq!(new_logs.len(), 1);
    }
}
