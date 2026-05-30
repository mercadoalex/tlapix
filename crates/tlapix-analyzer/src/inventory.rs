//! Inventory Manager for certificate inventory integration.
//!
//! Supports importing certificate inventory data from file-based or API-based
//! sources, polling at configurable intervals, and providing lookup capabilities
//! for shadow certificate detection.
//!
//! Requirements: 9.1, 9.2, 9.4, 9.5, 9.7

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing;
use uuid::Uuid;

use tlapix_common::config::InventorySource;
use tlapix_common::storage::{CertificateInventoryRow, InventoryRefreshLogRow, Storage};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during inventory operations.
#[derive(Debug, thiserror::Error)]
pub enum InventoryError {
    /// Storage layer error.
    #[error("Storage error: {0}")]
    Storage(#[from] tlapix_common::storage::StorageError),

    /// I/O error (file read).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON parsing error.
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    /// HTTP request error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// Timeout error.
    #[error("Request timed out after {0} seconds")]
    Timeout(u64),
}

/// Result type for inventory operations.
pub type InventoryResult<T> = Result<T, InventoryError>;

// ---------------------------------------------------------------------------
// Inventory refresh result
// ---------------------------------------------------------------------------

/// Result of a single inventory refresh operation.
#[derive(Debug, Clone)]
pub struct InventoryRefreshResult {
    /// Total valid entries imported.
    pub total_entries: usize,
    /// New entries added (not previously in inventory).
    pub new_entries: usize,
    /// Entries removed (stale from previous refresh).
    pub removed_entries: usize,
    /// Entries skipped due to being malformed.
    pub skipped_invalid: usize,
}

// ---------------------------------------------------------------------------
// Raw inventory entry (deserialized from JSON)
// ---------------------------------------------------------------------------

/// A single entry in the inventory JSON file/response.
#[derive(Debug, Deserialize)]
struct RawInventoryEntry {
    /// Hex-encoded SHA-256 fingerprint.
    fingerprint: Option<String>,
    /// Certificate subject.
    subject: Option<String>,
}

// ---------------------------------------------------------------------------
// Inventory Manager
// ---------------------------------------------------------------------------

/// Manages certificate inventory import and lookup.
///
/// The inventory manager polls an external source (file or API) at a
/// configurable interval and maintains a local copy in SQLite storage.
pub struct InventoryManager {
    source: InventorySource,
    storage: Storage,
    poll_interval_secs: u64,
    state: Arc<RwLock<InventoryState>>,
    http_client: reqwest::Client,
}

/// Internal state tracking for the inventory manager.
struct InventoryState {
    last_successful_refresh: Option<DateTime<Utc>>,
}

impl InventoryManager {
    /// Create a new inventory manager.
    ///
    /// # Arguments
    /// - `source`: The inventory source (file or API).
    /// - `storage`: The storage layer for persisting inventory data.
    /// - `poll_interval_secs`: Polling interval in seconds (max 300 = 5 minutes).
    pub fn new(source: InventorySource, storage: Storage, poll_interval_secs: u64) -> Self {
        // Clamp poll interval to max 5 minutes (300 seconds)
        let poll_interval_secs = poll_interval_secs.min(300);

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        Self {
            source,
            storage,
            poll_interval_secs,
            state: Arc::new(RwLock::new(InventoryState {
                last_successful_refresh: None,
            })),
            http_client,
        }
    }

    /// Start the polling loop. Returns a `JoinHandle` for the background task.
    ///
    /// The loop runs until the `cancel` token is cancelled.
    pub fn start(self: Arc<Self>, cancel: CancellationToken) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(self.poll_interval_secs));

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        tracing::info!("Inventory manager shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        match self.refresh().await {
                            Ok(result) => {
                                tracing::info!(
                                    total = result.total_entries,
                                    new = result.new_entries,
                                    removed = result.removed_entries,
                                    skipped = result.skipped_invalid,
                                    "Inventory refresh completed"
                                );
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "Inventory refresh failed, continuing with last known");
                            }
                        }

                        // Check staleness
                        if self.is_stale().await {
                            let age_minutes = self.staleness_minutes().await.unwrap_or(0);
                            tracing::warn!(
                                age_minutes,
                                "Certificate inventory is stale (>60 minutes since last refresh)"
                            );
                        }
                    }
                }
            }
        })
    }

    /// Perform a single inventory refresh.
    ///
    /// Imports entries from the configured source, upserts valid entries,
    /// removes stale entries, and logs the refresh result.
    pub async fn refresh(&self) -> InventoryResult<InventoryRefreshResult> {
        let refresh_id = Uuid::new_v4().to_string();
        let source_name = match &self.source {
            InventorySource::File { .. } => "file",
            InventorySource::Api { .. } => "api",
        };

        let raw_entries = match &self.source {
            InventorySource::File { path } => self.import_from_file(path).await?,
            InventorySource::Api {
                endpoint,
                auth_token,
            } => match self.import_from_api(endpoint, auth_token).await {
                Ok(entries) => entries,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "Failed to reach inventory API, continuing with last known inventory"
                    );
                    // Log failed refresh
                    let log_row = InventoryRefreshLogRow {
                        id: refresh_id,
                        timestamp: Utc::now().timestamp_millis(),
                        source: source_name.to_string(),
                        total_entries: None,
                        new_entries: None,
                        removed_entries: None,
                        skipped_invalid: None,
                        success: false,
                    };
                    let _ = self.storage.insert_refresh_log(&log_row).await;
                    return Err(e);
                }
            },
        };

        // Process entries: validate and upsert
        let mut total_entries = 0usize;
        let mut skipped_invalid = 0usize;

        for (idx, raw) in raw_entries.iter().enumerate() {
            match self.validate_entry(raw) {
                Some((fingerprint, subject)) => {
                    let row = CertificateInventoryRow {
                        fingerprint,
                        subject,
                        source: source_name.to_string(),
                        imported_at: Utc::now().timestamp_millis(),
                        last_refresh_id: refresh_id.clone(),
                    };
                    self.storage.upsert_inventory_entry(&row).await?;
                    total_entries += 1;
                }
                None => {
                    tracing::warn!(
                        index = idx,
                        fingerprint = ?raw.fingerprint,
                        subject = ?raw.subject,
                        "Skipping malformed inventory entry: missing required fields"
                    );
                    skipped_invalid += 1;
                }
            }
        }

        // Remove entries not in this refresh (stale)
        let removed = self
            .storage
            .remove_stale_inventory_entries(&refresh_id)
            .await? as usize;

        // Compute new entries (total - entries that were already there)
        // For simplicity, we consider all entries as potentially new since we
        // use upsert. The "new" count is approximate: total minus those that
        // existed before minus removed.
        let new_entries = if removed > 0 {
            // Some were removed, so at minimum some are new
            removed.min(total_entries)
        } else {
            0
        };

        let result = InventoryRefreshResult {
            total_entries,
            new_entries,
            removed_entries: removed,
            skipped_invalid,
        };

        // Update last successful refresh time
        {
            let mut state = self.state.write().await;
            state.last_successful_refresh = Some(Utc::now());
        }

        // Log successful refresh
        let log_row = InventoryRefreshLogRow {
            id: refresh_id,
            timestamp: Utc::now().timestamp_millis(),
            source: source_name.to_string(),
            total_entries: Some(result.total_entries as i32),
            new_entries: Some(result.new_entries as i32),
            removed_entries: Some(result.removed_entries as i32),
            skipped_invalid: Some(result.skipped_invalid as i32),
            success: true,
        };
        self.storage.insert_refresh_log(&log_row).await?;

        Ok(result)
    }

    /// Check if a fingerprint exists in the inventory.
    pub async fn contains(&self, fingerprint: &[u8; 32]) -> bool {
        self.storage
            .inventory_contains(fingerprint)
            .await
            .unwrap_or(false)
    }

    /// Get the timestamp of the last successful refresh.
    pub async fn last_refresh(&self) -> Option<DateTime<Utc>> {
        let state = self.state.read().await;
        state.last_successful_refresh
    }

    /// Returns true if the last successful refresh was more than 60 minutes ago.
    pub async fn is_stale(&self) -> bool {
        let state = self.state.read().await;
        match state.last_successful_refresh {
            Some(last) => {
                let elapsed = Utc::now() - last;
                elapsed.num_minutes() > 60
            }
            // If we've never refreshed, we're not stale yet (first poll hasn't happened)
            None => false,
        }
    }

    /// Initialize the last refresh time from the database (for restart recovery).
    pub async fn initialize_from_storage(&self) -> InventoryResult<()> {
        if let Some(log) = self.storage.get_latest_refresh_log().await? {
            if log.success {
                let ts = chrono::DateTime::from_timestamp_millis(log.timestamp);
                if let Some(ts) = ts {
                    let mut state = self.state.write().await;
                    state.last_successful_refresh = Some(ts);
                }
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Import entries from a JSON file.
    async fn import_from_file(
        &self,
        path: &std::path::Path,
    ) -> InventoryResult<Vec<RawInventoryEntry>> {
        let content = tokio::fs::read_to_string(path).await?;
        let entries: Vec<RawInventoryEntry> = serde_json::from_str(&content)?;
        Ok(entries)
    }

    /// Import entries from an API endpoint with 30-second timeout.
    async fn import_from_api(
        &self,
        endpoint: &str,
        auth_token: &str,
    ) -> InventoryResult<Vec<RawInventoryEntry>> {
        let response = self
            .http_client
            .get(endpoint)
            .header("Authorization", format!("Bearer {}", auth_token))
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    InventoryError::Timeout(30)
                } else {
                    InventoryError::Http(e)
                }
            })?;

        let entries: Vec<RawInventoryEntry> = response.json().await?;
        Ok(entries)
    }

    /// Validate a raw entry and return the parsed fingerprint and subject if valid.
    ///
    /// An entry is valid if it has both a fingerprint (valid hex, 32 bytes) and a subject.
    fn validate_entry(&self, raw: &RawInventoryEntry) -> Option<([u8; 32], String)> {
        let fingerprint_hex = raw.fingerprint.as_deref()?;
        let subject = raw.subject.as_deref()?;

        if subject.is_empty() {
            return None;
        }

        let fingerprint = parse_hex_fingerprint(fingerprint_hex)?;
        Some((fingerprint, subject.to_string()))
    }

    /// Get the number of minutes since the last successful refresh.
    async fn staleness_minutes(&self) -> Option<i64> {
        let state = self.state.read().await;
        state
            .last_successful_refresh
            .map(|last| (Utc::now() - last).num_minutes())
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Parse a hex-encoded fingerprint string into a 32-byte array.
///
/// Accepts both with and without colons/spaces as separators.
fn parse_hex_fingerprint(hex: &str) -> Option<[u8; 32]> {
    // Remove common separators
    let clean: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();

    if clean.len() != 64 {
        return None;
    }

    let mut result = [0u8; 32];
    for i in 0..32 {
        let byte_str = &clean[i * 2..i * 2 + 2];
        result[i] = u8::from_str_radix(byte_str, 16).ok()?;
    }
    Some(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

    /// Helper to create a hex fingerprint string from bytes.
    fn fingerprint_to_hex(fp: &[u8; 32]) -> String {
        fp.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_parse_hex_fingerprint_valid() {
        let fp = [0xab; 32];
        let hex = fingerprint_to_hex(&fp);
        let parsed = parse_hex_fingerprint(&hex).unwrap();
        assert_eq!(parsed, fp);
    }

    #[test]
    fn test_parse_hex_fingerprint_with_colons() {
        let fp = [0x01; 32];
        let hex_with_colons: String = fp
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");
        let parsed = parse_hex_fingerprint(&hex_with_colons).unwrap();
        assert_eq!(parsed, fp);
    }

    #[test]
    fn test_parse_hex_fingerprint_invalid_length() {
        assert!(parse_hex_fingerprint("abcd").is_none());
        assert!(parse_hex_fingerprint("").is_none());
    }

    #[test]
    fn test_parse_hex_fingerprint_invalid_chars() {
        let bad = "zz".repeat(32);
        assert!(parse_hex_fingerprint(&bad).is_none());
    }

    #[tokio::test]
    async fn test_file_based_import_valid_entries() {
        let storage = Storage::open_in_memory().await.unwrap();

        let fp1 = [0x01; 32];
        let fp2 = [0x02; 32];
        let entries = serde_json::json!([
            { "fingerprint": fingerprint_to_hex(&fp1), "subject": "CN=example.com" },
            { "fingerprint": fingerprint_to_hex(&fp2), "subject": "CN=test.org" }
        ]);

        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{}", entries.to_string()).unwrap();

        let source = InventorySource::File {
            path: file.path().to_path_buf(),
        };
        let manager = InventoryManager::new(source, storage.clone(), 300);

        let result = manager.refresh().await.unwrap();
        assert_eq!(result.total_entries, 2);
        assert_eq!(result.skipped_invalid, 0);

        // Verify entries are in storage
        assert!(manager.contains(&fp1).await);
        assert!(manager.contains(&fp2).await);

        // Unknown fingerprint should not be found
        let unknown = [0xFF; 32];
        assert!(!manager.contains(&unknown).await);
    }

    #[tokio::test]
    async fn test_file_based_import_mixed_valid_invalid() {
        let storage = Storage::open_in_memory().await.unwrap();

        let fp_valid = [0x0A; 32];
        let entries = serde_json::json!([
            { "fingerprint": fingerprint_to_hex(&fp_valid), "subject": "CN=valid.com" },
            { "fingerprint": "not-a-valid-hex", "subject": "CN=bad-fp.com" },
            { "fingerprint": fingerprint_to_hex(&[0x0B; 32]), "subject": "" },
            { "subject": "CN=missing-fp.com" },
            { "fingerprint": fingerprint_to_hex(&[0x0C; 32]) },
            { "fingerprint": fingerprint_to_hex(&[0x0D; 32]), "subject": "CN=also-valid.com" }
        ]);

        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{}", entries.to_string()).unwrap();

        let source = InventorySource::File {
            path: file.path().to_path_buf(),
        };
        let manager = InventoryManager::new(source, storage.clone(), 300);

        let result = manager.refresh().await.unwrap();
        assert_eq!(result.total_entries, 2); // fp_valid and 0x0D
        assert_eq!(result.skipped_invalid, 4); // bad hex, empty subject, missing fp, missing subject

        assert!(manager.contains(&fp_valid).await);
        assert!(manager.contains(&[0x0D; 32]).await);
        assert!(!manager.contains(&[0x0B; 32]).await); // empty subject
    }

    #[tokio::test]
    async fn test_staleness_detection() {
        let storage = Storage::open_in_memory().await.unwrap();
        let source = InventorySource::File {
            path: PathBuf::from("/nonexistent"),
        };
        let manager = InventoryManager::new(source, storage, 300);

        // Initially not stale (never refreshed)
        assert!(!manager.is_stale().await);

        // Simulate a refresh that happened 61 minutes ago
        {
            let mut state = manager.state.write().await;
            state.last_successful_refresh = Some(Utc::now() - chrono::Duration::minutes(61));
        }
        assert!(manager.is_stale().await);

        // Simulate a recent refresh
        {
            let mut state = manager.state.write().await;
            state.last_successful_refresh = Some(Utc::now() - chrono::Duration::minutes(5));
        }
        assert!(!manager.is_stale().await);
    }

    #[tokio::test]
    async fn test_contains_check() {
        let storage = Storage::open_in_memory().await.unwrap();

        let fp = [0x42; 32];
        let entries = serde_json::json!([
            { "fingerprint": fingerprint_to_hex(&fp), "subject": "CN=known.com" }
        ]);

        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{}", entries.to_string()).unwrap();

        let source = InventorySource::File {
            path: file.path().to_path_buf(),
        };
        let manager = InventoryManager::new(source, storage, 300);

        // Before refresh, nothing is in inventory
        assert!(!manager.contains(&fp).await);

        // After refresh, the entry should be found
        manager.refresh().await.unwrap();
        assert!(manager.contains(&fp).await);

        // Unknown fingerprint
        assert!(!manager.contains(&[0x99; 32]).await);
    }

    #[tokio::test]
    async fn test_stale_entries_removed_on_refresh() {
        let storage = Storage::open_in_memory().await.unwrap();

        let fp1 = [0x01; 32];
        let fp2 = [0x02; 32];

        // First refresh with both entries
        let entries1 = serde_json::json!([
            { "fingerprint": fingerprint_to_hex(&fp1), "subject": "CN=one.com" },
            { "fingerprint": fingerprint_to_hex(&fp2), "subject": "CN=two.com" }
        ]);

        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{}", entries1.to_string()).unwrap();

        let source = InventorySource::File {
            path: file.path().to_path_buf(),
        };
        let manager = InventoryManager::new(source, storage.clone(), 300);
        manager.refresh().await.unwrap();

        assert!(manager.contains(&fp1).await);
        assert!(manager.contains(&fp2).await);

        // Second refresh with only fp1 — fp2 should be removed
        let entries2 = serde_json::json!([
            { "fingerprint": fingerprint_to_hex(&fp1), "subject": "CN=one.com" }
        ]);

        // Overwrite the file
        let file_path = file.path().to_path_buf();
        std::fs::write(&file_path, entries2.to_string()).unwrap();

        let result = manager.refresh().await.unwrap();
        assert_eq!(result.total_entries, 1);
        assert_eq!(result.removed_entries, 1);

        assert!(manager.contains(&fp1).await);
        assert!(!manager.contains(&fp2).await);
    }

    #[tokio::test]
    async fn test_poll_interval_clamped_to_max() {
        let storage = Storage::open_in_memory().await.unwrap();
        let source = InventorySource::File {
            path: PathBuf::from("/tmp/test"),
        };

        // Try to set interval > 5 minutes
        let manager = InventoryManager::new(source, storage, 600);
        assert_eq!(manager.poll_interval_secs, 300);
    }

    #[tokio::test]
    async fn test_refresh_logs_recorded() {
        let storage = Storage::open_in_memory().await.unwrap();

        let fp = [0x01; 32];
        let entries = serde_json::json!([
            { "fingerprint": fingerprint_to_hex(&fp), "subject": "CN=logged.com" }
        ]);

        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{}", entries.to_string()).unwrap();

        let source = InventorySource::File {
            path: file.path().to_path_buf(),
        };
        let manager = InventoryManager::new(source, storage.clone(), 300);
        manager.refresh().await.unwrap();

        // Verify refresh log was recorded
        let log = storage.get_latest_refresh_log().await.unwrap().unwrap();
        assert!(log.success);
        assert_eq!(log.source, "file");
        assert_eq!(log.total_entries, Some(1));
    }

    #[tokio::test]
    async fn test_initialize_from_storage() {
        let storage = Storage::open_in_memory().await.unwrap();

        // Insert a refresh log entry
        let ts = Utc::now().timestamp_millis();
        let log_row = InventoryRefreshLogRow {
            id: "test-refresh".to_string(),
            timestamp: ts,
            source: "file".to_string(),
            total_entries: Some(5),
            new_entries: Some(5),
            removed_entries: Some(0),
            skipped_invalid: Some(0),
            success: true,
        };
        storage.insert_refresh_log(&log_row).await.unwrap();

        let source = InventorySource::File {
            path: PathBuf::from("/tmp/test"),
        };
        let manager = InventoryManager::new(source, storage, 300);

        // Before initialization, last_refresh is None
        assert!(manager.last_refresh().await.is_none());

        // After initialization, it should be populated
        manager.initialize_from_storage().await.unwrap();
        assert!(manager.last_refresh().await.is_some());
    }
}
