//! Directive expiry and conflict resolution for the Executor layer.
//!
//! - Expires directives for certificates not seen in traffic for 72+ hours.
//! - Resolves conflicts when multiple directives target the same certificate
//!   by applying the highest severity and discarding lower ones.

use std::collections::HashMap;

use chrono::{Duration, Utc};
use tracing;

use tlapix_common::storage::{ActionDirectiveRow, Storage};
use tlapix_common::types::Severity;

// ---------------------------------------------------------------------------
// BPF Map Writer trait
// ---------------------------------------------------------------------------

/// Trait abstracting BPF map write/remove operations for testability.
///
/// In production this is backed by real aya BPF map operations; in tests
/// it can be replaced with an in-memory mock.
pub trait BpfMapWriter: Send + Sync {
    /// Remove a directive entry from the BPF map by certificate fingerprint.
    fn remove_entry(&self, fingerprint: &[u8; 32]) -> Result<(), BpfMapError>;
}

/// Errors from BPF map operations.
#[derive(Debug, thiserror::Error)]
pub enum BpfMapError {
    #[error("entry not found in map")]
    NotFound,
    #[error("map operation failed: {0}")]
    OperationFailed(String),
}

// ---------------------------------------------------------------------------
// Expiry result
// ---------------------------------------------------------------------------

/// Result of running the directive expiry sweep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiryResult {
    /// Number of directives that were expired and removed.
    pub expired_count: usize,
    /// IDs of the expired directives.
    pub expired_ids: Vec<String>,
}

// ---------------------------------------------------------------------------
// Conflict resolution result
// ---------------------------------------------------------------------------

/// A directive that lost conflict resolution and was discarded.
#[derive(Debug, Clone)]
pub struct DiscardedDirective {
    pub id: String,
    pub severity: String,
    pub reason: String,
}

/// Result of conflict resolution.
#[derive(Debug, Clone)]
pub struct ConflictResolutionResult {
    /// The winning directives (one per unique fingerprint).
    pub winners: Vec<ActionDirectiveRow>,
    /// Directives that were discarded due to lower severity.
    pub discarded: Vec<DiscardedDirective>,
}

// ---------------------------------------------------------------------------
// Expiry logic
// ---------------------------------------------------------------------------

/// Expire directives for certificates not seen in traffic for more than
/// `expiry_hours` (default 72).
///
/// For each active/pending directive, checks the referenced certificate's
/// `last_seen` timestamp. If it's older than `expiry_hours`, the directive
/// is removed from the BPF map and marked as "expired" in storage.
pub async fn expire_stale_directives(
    storage: &Storage,
    map_writer: &dyn BpfMapWriter,
    expiry_hours: u64,
) -> Result<ExpiryResult, anyhow::Error> {
    let expiry_duration = Duration::hours(expiry_hours as i64);
    let cutoff = Utc::now() - expiry_duration;

    // Get all active and pending directives
    let mut candidates = storage.list_directives_by_status("active").await?;
    let pending = storage.list_directives_by_status("pending").await?;
    candidates.extend(pending);

    let mut expired_ids = Vec::new();

    for directive in &candidates {
        // Look up the certificate to check last_seen
        let cert = storage.get_certificate(&directive.cert_fingerprint).await?;

        let should_expire = match cert {
            Some(cert_meta) => cert_meta.last_seen < cutoff,
            // If the certificate doesn't exist in storage at all, it's definitely stale
            None => true,
        };

        if should_expire {
            // Remove from BPF map (best-effort; entry may not exist)
            match map_writer.remove_entry(&directive.cert_fingerprint) {
                Ok(()) => {}
                Err(BpfMapError::NotFound) => {
                    // Entry already gone from map, that's fine
                }
                Err(e) => {
                    tracing::warn!(
                        directive_id = %directive.id,
                        error = %e,
                        "Failed to remove expired directive from BPF map"
                    );
                }
            }

            // Mark as expired in storage
            storage
                .update_directive_status(&directive.id, "expired", None)
                .await?;

            expired_ids.push(directive.id.clone());

            tracing::info!(
                directive_id = %directive.id,
                fingerprint = ?directive.cert_fingerprint,
                "Expired stale directive"
            );
        }
    }

    let expired_count = expired_ids.len();
    tracing::info!(expired_count, "Directive expiry sweep completed");

    Ok(ExpiryResult {
        expired_count,
        expired_ids,
    })
}

// ---------------------------------------------------------------------------
// Conflict resolution logic
// ---------------------------------------------------------------------------

/// Parse a severity string into the `Severity` enum for comparison.
fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Low,
    }
}

/// Resolve conflicts among directives targeting the same certificate.
///
/// Groups directives by `cert_fingerprint` and for each group keeps only
/// the directive with the highest severity. If severities are equal, the
/// first directive (by position in the input slice) wins.
///
/// Lower-severity directives are marked as discarded.
pub fn resolve_conflicts(directives: &[ActionDirectiveRow]) -> ConflictResolutionResult {
    // Group by fingerprint
    let mut groups: HashMap<[u8; 32], Vec<&ActionDirectiveRow>> = HashMap::new();
    for d in directives {
        groups.entry(d.cert_fingerprint).or_default().push(d);
    }

    let mut winners = Vec::new();
    let mut discarded = Vec::new();

    for group in groups.values() {
        if group.is_empty() {
            continue;
        }

        // Find the winner: highest severity, ties broken by first occurrence
        let mut best_idx = 0;
        let mut best_severity = parse_severity(&group[0].severity);

        for (i, directive) in group.iter().enumerate().skip(1) {
            let sev = parse_severity(&directive.severity);
            if sev > best_severity {
                best_severity = sev;
                best_idx = i;
            }
        }

        winners.push(group[best_idx].clone());

        // Mark all others as discarded
        for (i, directive) in group.iter().enumerate() {
            if i != best_idx {
                discarded.push(DiscardedDirective {
                    id: directive.id.clone(),
                    severity: directive.severity.clone(),
                    reason: format!(
                        "Lower severity than winner (winner severity: {:?})",
                        best_severity
                    ),
                });
            }
        }
    }

    ConflictResolutionResult { winners, discarded }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Duration, Utc};
    use std::sync::Mutex;
    use tlapix_common::storage::Storage;
    use tlapix_common::types::CertificateMetadata;

    /// Mock BPF map writer that records removed fingerprints.
    struct MockBpfMapWriter {
        removed: Mutex<Vec<[u8; 32]>>,
    }

    impl MockBpfMapWriter {
        fn new() -> Self {
            Self {
                removed: Mutex::new(Vec::new()),
            }
        }

        fn removed_entries(&self) -> Vec<[u8; 32]> {
            self.removed.lock().unwrap().clone()
        }
    }

    impl BpfMapWriter for MockBpfMapWriter {
        fn remove_entry(&self, fingerprint: &[u8; 32]) -> Result<(), BpfMapError> {
            self.removed.lock().unwrap().push(*fingerprint);
            Ok(())
        }
    }

    fn make_test_certificate(fingerprint: [u8; 32], last_seen: DateTime<Utc>) -> CertificateMetadata {
        let now = Utc::now();
        CertificateMetadata {
            fingerprint,
            subject: "CN=test.example.com".to_string(),
            issuer: "CN=Test CA".to_string(),
            serial_number: "01:02:03".to_string(),
            not_before: now - Duration::days(30),
            not_after: now + Duration::days(335),
            sans: vec!["test.example.com".to_string()],
            key_algorithm: "RSA".to_string(),
            key_size: 2048,
            chain_depth: 2,
            issuer_fingerprint: None,
            first_seen: now - Duration::days(60),
            last_seen,
            connection_count: 1,
            source_ip: Some("192.168.1.1".to_string()),
            destination_ip: Some("10.0.0.1".to_string()),
            sni_hostname: Some("test.example.com".to_string()),
            completeness_flags: 0x7F,
        }
    }

    fn make_directive(
        id: &str,
        fingerprint: [u8; 32],
        severity: &str,
        status: &str,
    ) -> ActionDirectiveRow {
        let now_ms = Utc::now().timestamp_millis();
        ActionDirectiveRow {
            id: id.to_string(),
            correlation_id: format!("corr-{}", id),
            cert_fingerprint: fingerprint,
            action_type: "alert".to_string(),
            severity: severity.to_string(),
            reasoning: Some("Test directive".to_string()),
            status: status.to_string(),
            attempt_count: 0,
            created_at: now_ms,
            executed_at: None,
            expired_at: None,
            failure_reason: None,
        }
    }

    // -----------------------------------------------------------------------
    // Expiry tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_directive_expired_when_cert_last_seen_over_72h() {
        let storage = Storage::open_in_memory().await.unwrap();
        let map_writer = MockBpfMapWriter::new();

        let fp = [1u8; 32];
        // Certificate last seen 80 hours ago (> 72h threshold)
        let last_seen = Utc::now() - Duration::hours(80);
        let cert = make_test_certificate(fp, last_seen);
        storage.upsert_certificate(&cert).await.unwrap();

        // Insert an active directive for this certificate
        let directive = make_directive("dir-001", fp, "high", "active");
        storage.insert_action_directive(&directive).await.unwrap();

        // Run expiry
        let result = expire_stale_directives(&storage, &map_writer, 72)
            .await
            .unwrap();

        assert_eq!(result.expired_count, 1);
        assert_eq!(result.expired_ids, vec!["dir-001"]);

        // Verify BPF map entry was removed
        let removed = map_writer.removed_entries();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], fp);

        // Verify directive status updated in storage
        let updated = storage.get_action_directive("dir-001").await.unwrap().unwrap();
        assert_eq!(updated.status, "expired");
    }

    #[tokio::test]
    async fn test_directive_not_expired_when_cert_last_seen_under_72h() {
        let storage = Storage::open_in_memory().await.unwrap();
        let map_writer = MockBpfMapWriter::new();

        let fp = [2u8; 32];
        // Certificate last seen 24 hours ago (< 72h threshold)
        let last_seen = Utc::now() - Duration::hours(24);
        let cert = make_test_certificate(fp, last_seen);
        storage.upsert_certificate(&cert).await.unwrap();

        // Insert an active directive for this certificate
        let directive = make_directive("dir-002", fp, "medium", "active");
        storage.insert_action_directive(&directive).await.unwrap();

        // Run expiry
        let result = expire_stale_directives(&storage, &map_writer, 72)
            .await
            .unwrap();

        assert_eq!(result.expired_count, 0);
        assert!(result.expired_ids.is_empty());

        // Verify BPF map was NOT touched
        let removed = map_writer.removed_entries();
        assert!(removed.is_empty());

        // Verify directive status unchanged
        let unchanged = storage.get_action_directive("dir-002").await.unwrap().unwrap();
        assert_eq!(unchanged.status, "active");
    }

    #[tokio::test]
    async fn test_directive_expired_when_cert_not_in_storage() {
        let storage = Storage::open_in_memory().await.unwrap();
        let map_writer = MockBpfMapWriter::new();

        let fp = [3u8; 32];
        // Insert a certificate with last_seen very far in the past (200 hours ago)
        // to simulate a certificate that hasn't been seen and would be expired
        // even beyond the 72h threshold.
        let last_seen = Utc::now() - Duration::hours(200);
        let cert = make_test_certificate(fp, last_seen);
        storage.upsert_certificate(&cert).await.unwrap();

        let directive = make_directive("dir-003", fp, "low", "pending");
        storage.insert_action_directive(&directive).await.unwrap();

        // Run expiry - the cert exists but last_seen is 200h ago (well over 72h)
        let result = expire_stale_directives(&storage, &map_writer, 72)
            .await
            .unwrap();

        assert_eq!(result.expired_count, 1);
        assert_eq!(result.expired_ids, vec!["dir-003"]);
    }

    #[tokio::test]
    async fn test_expiry_handles_multiple_directives() {
        let storage = Storage::open_in_memory().await.unwrap();
        let map_writer = MockBpfMapWriter::new();

        // Stale cert (80h ago)
        let fp_stale = [4u8; 32];
        let cert_stale = make_test_certificate(fp_stale, Utc::now() - Duration::hours(80));
        storage.upsert_certificate(&cert_stale).await.unwrap();

        // Fresh cert (1h ago)
        let fp_fresh = [5u8; 32];
        let cert_fresh = make_test_certificate(fp_fresh, Utc::now() - Duration::hours(1));
        storage.upsert_certificate(&cert_fresh).await.unwrap();

        let dir_stale = make_directive("dir-stale", fp_stale, "high", "active");
        let dir_fresh = make_directive("dir-fresh", fp_fresh, "critical", "active");
        storage.insert_action_directive(&dir_stale).await.unwrap();
        storage.insert_action_directive(&dir_fresh).await.unwrap();

        let result = expire_stale_directives(&storage, &map_writer, 72)
            .await
            .unwrap();

        assert_eq!(result.expired_count, 1);
        assert_eq!(result.expired_ids, vec!["dir-stale"]);

        // Fresh directive should remain active
        let fresh = storage.get_action_directive("dir-fresh").await.unwrap().unwrap();
        assert_eq!(fresh.status, "active");
    }

    // -----------------------------------------------------------------------
    // Conflict resolution tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_conflict_resolution_highest_severity_wins() {
        let fp = [10u8; 32];
        let directives = vec![
            make_directive("d1", fp, "low", "pending"),
            make_directive("d2", fp, "critical", "pending"),
            make_directive("d3", fp, "medium", "pending"),
        ];

        let result = resolve_conflicts(&directives);

        assert_eq!(result.winners.len(), 1);
        assert_eq!(result.winners[0].id, "d2");
        assert_eq!(result.discarded.len(), 2);

        let discarded_ids: Vec<&str> = result.discarded.iter().map(|d| d.id.as_str()).collect();
        assert!(discarded_ids.contains(&"d1"));
        assert!(discarded_ids.contains(&"d3"));
    }

    #[test]
    fn test_conflict_resolution_equal_severity_keeps_first() {
        let fp = [11u8; 32];
        let directives = vec![
            make_directive("first", fp, "high", "pending"),
            make_directive("second", fp, "high", "pending"),
        ];

        let result = resolve_conflicts(&directives);

        assert_eq!(result.winners.len(), 1);
        // First occurrence wins on tie
        assert_eq!(result.winners[0].id, "first");
        assert_eq!(result.discarded.len(), 1);
        assert_eq!(result.discarded[0].id, "second");
    }

    #[test]
    fn test_conflict_resolution_different_fingerprints_no_conflict() {
        let fp1 = [20u8; 32];
        let fp2 = [21u8; 32];
        let directives = vec![
            make_directive("d1", fp1, "low", "pending"),
            make_directive("d2", fp2, "high", "pending"),
        ];

        let result = resolve_conflicts(&directives);

        // Both should be winners since they target different certificates
        assert_eq!(result.winners.len(), 2);
        assert!(result.discarded.is_empty());
    }

    #[test]
    fn test_conflict_resolution_single_directive_no_conflict() {
        let fp = [30u8; 32];
        let directives = vec![make_directive("only", fp, "medium", "pending")];

        let result = resolve_conflicts(&directives);

        assert_eq!(result.winners.len(), 1);
        assert_eq!(result.winners[0].id, "only");
        assert!(result.discarded.is_empty());
    }

    #[test]
    fn test_conflict_resolution_empty_input() {
        let directives: Vec<ActionDirectiveRow> = vec![];
        let result = resolve_conflicts(&directives);

        assert!(result.winners.is_empty());
        assert!(result.discarded.is_empty());
    }

    #[test]
    fn test_conflict_resolution_multiple_groups() {
        let fp1 = [40u8; 32];
        let fp2 = [41u8; 32];
        let directives = vec![
            make_directive("a1", fp1, "low", "pending"),
            make_directive("a2", fp1, "critical", "pending"),
            make_directive("b1", fp2, "medium", "pending"),
            make_directive("b2", fp2, "high", "pending"),
        ];

        let result = resolve_conflicts(&directives);

        assert_eq!(result.winners.len(), 2);
        assert_eq!(result.discarded.len(), 2);

        // Find winners by fingerprint
        let winner_fp1 = result.winners.iter().find(|w| w.cert_fingerprint == fp1).unwrap();
        let winner_fp2 = result.winners.iter().find(|w| w.cert_fingerprint == fp2).unwrap();

        assert_eq!(winner_fp1.id, "a2"); // critical wins
        assert_eq!(winner_fp2.id, "b2"); // high wins
    }
}
