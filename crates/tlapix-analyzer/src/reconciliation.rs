//! Inventory reconciliation for shadow certificate lifecycle management.
//!
//! When the certificate inventory is refreshed, certificates may change classification:
//! - A shadow certificate that appears in the new inventory → reclassify as known,
//!   cancel pending directives, and write removal to BPF map.
//! - A previously known certificate that disappears from inventory but is still
//!   observed in traffic → reclassify as shadow.
//!
//! Requirements: 9.3, 9.6

use chrono::Utc;
use tracing;

use tlapix_common::storage::{ShadowCertificateRow, Storage};
use tlapix_common::types::RiskLevel;

// ---------------------------------------------------------------------------
// Reconciliation result
// ---------------------------------------------------------------------------

/// Result of an inventory reconciliation pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconciliationResult {
    /// Number of shadow certificates resolved (reclassified as known).
    pub shadows_resolved: u32,
    /// Number of pending directives cancelled during resolution.
    pub directives_cancelled: u32,
    /// Number of new shadow certificates created from removed inventory entries.
    pub new_shadows_from_removal: u32,
}

// ---------------------------------------------------------------------------
// Reconciliation logic
// ---------------------------------------------------------------------------

/// Reconcile the certificate inventory after a refresh.
///
/// This function performs two operations:
/// 1. **Shadow → Known**: For each unresolved shadow certificate, check if it now
///    appears in the inventory. If yes, mark it as resolved and cancel pending directives.
/// 2. **Known → Shadow**: For each fingerprint in `removed_fingerprints` (entries that
///    were removed from the inventory during the refresh), check if the certificate is
///    still observed in traffic (last_seen within 24 hours). If yes, classify it as a
///    new shadow certificate.
///
/// # Arguments
/// - `storage`: The storage layer for querying and updating records.
/// - `removed_fingerprints`: Fingerprints of certificates removed from inventory during refresh.
///
/// # Returns
/// A `ReconciliationResult` summarizing the changes made.
pub async fn reconcile_inventory(
    storage: &Storage,
    removed_fingerprints: &[[u8; 32]],
) -> Result<ReconciliationResult, ReconciliationError> {
    let mut result = ReconciliationResult::default();

    // Phase 1: Shadow → Known
    // Query all unresolved shadow certificates and check if each is now in inventory.
    let unresolved_shadows = storage
        .list_unresolved_shadow_certificates()
        .await
        .map_err(ReconciliationError::Storage)?;

    for shadow in &unresolved_shadows {
        let in_inventory = storage
            .inventory_contains(&shadow.fingerprint)
            .await
            .map_err(ReconciliationError::Storage)?;

        if in_inventory {
            // Resolve the shadow certificate
            let now_ms = Utc::now().timestamp_millis();
            let resolved_row = ShadowCertificateRow {
                is_resolved: true,
                resolved_at: Some(now_ms),
                ..shadow.clone()
            };
            storage
                .upsert_shadow_certificate(&resolved_row)
                .await
                .map_err(ReconciliationError::Storage)?;

            // Cancel pending directives for this certificate
            let pending_directives = storage
                .list_pending_directives_by_fingerprint(&shadow.fingerprint)
                .await
                .map_err(ReconciliationError::Storage)?;

            for directive in &pending_directives {
                storage
                    .update_directive_status(
                        &directive.id,
                        "expired",
                        Some("Certificate appeared in inventory; shadow resolved"),
                    )
                    .await
                    .map_err(ReconciliationError::Storage)?;
                result.directives_cancelled += 1;
            }

            result.shadows_resolved += 1;

            tracing::info!(
                fingerprint = %format_fingerprint(&shadow.fingerprint),
                directives_cancelled = pending_directives.len(),
                "Shadow certificate resolved: now in inventory"
            );
        }
    }

    // Phase 2: Known → Shadow
    // For each removed fingerprint, check if the certificate is still in traffic.
    let twenty_four_hours_ago_ms =
        Utc::now().timestamp_millis() - (24 * 60 * 60 * 1000);

    for fingerprint in removed_fingerprints {
        // Check if the certificate is still observed in traffic (last_seen within 24h)
        let cert = storage
            .get_certificate(fingerprint)
            .await
            .map_err(ReconciliationError::Storage)?;

        if let Some(cert) = cert {
            let last_seen_ms = cert.last_seen.timestamp_millis();

            if last_seen_ms >= twenty_four_hours_ago_ms {
                // Certificate is still in traffic but no longer in inventory → shadow
                // Check if it's already classified as shadow
                let existing_shadow = storage
                    .get_shadow_certificate(fingerprint)
                    .await
                    .map_err(ReconciliationError::Storage)?;

                if existing_shadow.is_none() {
                    let now_ms = Utc::now().timestamp_millis();
                    let shadow_row = ShadowCertificateRow {
                        fingerprint: *fingerprint,
                        risk_level: RiskLevel::Low,
                        first_classified: now_ms,
                        last_escalated: None,
                        escalation_count: 0,
                        source_ip: cert.source_ip.clone(),
                        destination_ip: cert.destination_ip.clone(),
                        first_seen: cert.first_seen.timestamp_millis(),
                        is_resolved: false,
                        resolved_at: None,
                    };
                    storage
                        .upsert_shadow_certificate(&shadow_row)
                        .await
                        .map_err(ReconciliationError::Storage)?;

                    result.new_shadows_from_removal += 1;

                    tracing::info!(
                        fingerprint = %format_fingerprint(fingerprint),
                        "Known certificate reclassified as shadow: removed from inventory but still in traffic"
                    );
                }
            }
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during inventory reconciliation.
#[derive(Debug, thiserror::Error)]
pub enum ReconciliationError {
    /// Storage layer error.
    #[error("Storage error: {0}")]
    Storage(#[from] tlapix_common::storage::StorageError),
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Format a fingerprint as a hex string for logging.
fn format_fingerprint(fp: &[u8; 32]) -> String {
    fp.iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use tlapix_common::storage::{
        ActionDirectiveRow, CertificateInventoryRow, Storage,
    };
    use tlapix_common::types::CertificateMetadata;

    /// Helper to create a test certificate with a given fingerprint and last_seen.
    fn make_test_cert(fingerprint: [u8; 32], last_seen: chrono::DateTime<Utc>) -> CertificateMetadata {
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
            first_seen: now - Duration::days(10),
            last_seen,
            connection_count: 5,
            source_ip: Some("192.168.1.1".to_string()),
            destination_ip: Some("10.0.0.1".to_string()),
            sni_hostname: Some("test.example.com".to_string()),
            completeness_flags: 0x7F,
        }
    }

    /// Helper to create a shadow certificate row.
    fn make_shadow_row(fingerprint: [u8; 32]) -> ShadowCertificateRow {
        let now_ms = Utc::now().timestamp_millis();
        ShadowCertificateRow {
            fingerprint,
            risk_level: RiskLevel::High,
            first_classified: now_ms - 86_400_000, // 1 day ago
            last_escalated: None,
            escalation_count: 0,
            source_ip: Some("192.168.1.1".to_string()),
            destination_ip: Some("10.0.0.1".to_string()),
            first_seen: now_ms - 172_800_000, // 2 days ago
            is_resolved: false,
            resolved_at: None,
        }
    }

    /// Helper to create a pending action directive for a fingerprint.
    fn make_pending_directive(fingerprint: [u8; 32], id: &str) -> ActionDirectiveRow {
        let now_ms = Utc::now().timestamp_millis();
        ActionDirectiveRow {
            id: id.to_string(),
            correlation_id: format!("corr-{}", id),
            cert_fingerprint: fingerprint,
            action_type: "alert".to_string(),
            severity: "high".to_string(),
            reasoning: Some("Shadow certificate detected".to_string()),
            status: "pending".to_string(),
            attempt_count: 0,
            created_at: now_ms,
            executed_at: None,
            expired_at: None,
            failure_reason: None,
        }
    }

    #[tokio::test]
    async fn test_shadow_resolved_when_appears_in_inventory() {
        let storage = Storage::open_in_memory().await.unwrap();

        let fp = [0xAA; 32];

        // Insert a certificate in the certificates table (needed for FK)
        let cert = make_test_cert(fp, Utc::now());
        storage.upsert_certificate(&cert).await.unwrap();

        // Insert as shadow certificate (unresolved)
        let shadow = make_shadow_row(fp);
        storage.upsert_shadow_certificate(&shadow).await.unwrap();

        // Now add the certificate to the inventory (simulating it appeared in refresh)
        let inv_row = CertificateInventoryRow {
            fingerprint: fp,
            subject: "CN=test.example.com".to_string(),
            source: "file".to_string(),
            imported_at: Utc::now().timestamp_millis(),
            last_refresh_id: "refresh-001".to_string(),
        };
        storage.upsert_inventory_entry(&inv_row).await.unwrap();

        // Run reconciliation
        let result = reconcile_inventory(&storage, &[]).await.unwrap();

        assert_eq!(result.shadows_resolved, 1);
        assert_eq!(result.new_shadows_from_removal, 0);

        // Verify the shadow is now resolved
        let updated = storage.get_shadow_certificate(&fp).await.unwrap().unwrap();
        assert!(updated.is_resolved);
        assert!(updated.resolved_at.is_some());
    }

    #[tokio::test]
    async fn test_pending_directives_cancelled_on_resolution() {
        let storage = Storage::open_in_memory().await.unwrap();

        let fp = [0xBB; 32];

        // Insert certificate
        let cert = make_test_cert(fp, Utc::now());
        storage.upsert_certificate(&cert).await.unwrap();

        // Insert as shadow
        let shadow = make_shadow_row(fp);
        storage.upsert_shadow_certificate(&shadow).await.unwrap();

        // Insert pending directives
        let dir1 = make_pending_directive(fp, "dir-001");
        let dir2 = make_pending_directive(fp, "dir-002");
        storage.insert_action_directive(&dir1).await.unwrap();
        storage.insert_action_directive(&dir2).await.unwrap();

        // Add to inventory
        let inv_row = CertificateInventoryRow {
            fingerprint: fp,
            subject: "CN=test.example.com".to_string(),
            source: "file".to_string(),
            imported_at: Utc::now().timestamp_millis(),
            last_refresh_id: "refresh-002".to_string(),
        };
        storage.upsert_inventory_entry(&inv_row).await.unwrap();

        // Run reconciliation
        let result = reconcile_inventory(&storage, &[]).await.unwrap();

        assert_eq!(result.shadows_resolved, 1);
        assert_eq!(result.directives_cancelled, 2);

        // Verify directives are expired
        let d1 = storage.get_action_directive("dir-001").await.unwrap().unwrap();
        assert_eq!(d1.status, "expired");
        assert_eq!(
            d1.failure_reason.as_deref(),
            Some("Certificate appeared in inventory; shadow resolved")
        );

        let d2 = storage.get_action_directive("dir-002").await.unwrap().unwrap();
        assert_eq!(d2.status, "expired");
    }

    #[tokio::test]
    async fn test_known_reclassified_as_shadow_when_removed_but_still_in_traffic() {
        let storage = Storage::open_in_memory().await.unwrap();

        let fp = [0xCC; 32];

        // Insert certificate with recent last_seen (within 24h)
        let cert = make_test_cert(fp, Utc::now() - Duration::hours(2));
        storage.upsert_certificate(&cert).await.unwrap();

        // The certificate was in inventory but got removed during refresh.
        // We pass its fingerprint as a removed entry.
        let result = reconcile_inventory(&storage, &[fp]).await.unwrap();

        assert_eq!(result.new_shadows_from_removal, 1);
        assert_eq!(result.shadows_resolved, 0);

        // Verify a shadow certificate was created
        let shadow = storage.get_shadow_certificate(&fp).await.unwrap().unwrap();
        assert!(!shadow.is_resolved);
        assert_eq!(shadow.risk_level, RiskLevel::Low);
    }

    #[tokio::test]
    async fn test_no_reclassification_if_cert_not_in_traffic() {
        let storage = Storage::open_in_memory().await.unwrap();

        let fp = [0xDD; 32];

        // Insert certificate with last_seen > 24h ago (not in recent traffic)
        let cert = make_test_cert(fp, Utc::now() - Duration::hours(48));
        storage.upsert_certificate(&cert).await.unwrap();

        // Certificate removed from inventory
        let result = reconcile_inventory(&storage, &[fp]).await.unwrap();

        // Should NOT be reclassified as shadow since it's not in recent traffic
        assert_eq!(result.new_shadows_from_removal, 0);
        assert_eq!(result.shadows_resolved, 0);

        // Verify no shadow certificate was created
        let shadow = storage.get_shadow_certificate(&fp).await.unwrap();
        assert!(shadow.is_none());
    }

    #[tokio::test]
    async fn test_no_reclassification_if_cert_not_found() {
        let storage = Storage::open_in_memory().await.unwrap();

        // Fingerprint that doesn't exist in the certificates table at all
        let fp = [0xEE; 32];

        let result = reconcile_inventory(&storage, &[fp]).await.unwrap();

        assert_eq!(result.new_shadows_from_removal, 0);
        assert_eq!(result.shadows_resolved, 0);
    }

    #[tokio::test]
    async fn test_already_shadow_not_duplicated() {
        let storage = Storage::open_in_memory().await.unwrap();

        let fp = [0xFF; 32];

        // Insert certificate with recent traffic
        let cert = make_test_cert(fp, Utc::now() - Duration::hours(1));
        storage.upsert_certificate(&cert).await.unwrap();

        // Already classified as shadow
        let shadow = make_shadow_row(fp);
        storage.upsert_shadow_certificate(&shadow).await.unwrap();

        // Certificate removed from inventory
        let result = reconcile_inventory(&storage, &[fp]).await.unwrap();

        // Should NOT create a duplicate shadow entry
        assert_eq!(result.new_shadows_from_removal, 0);
    }

    #[tokio::test]
    async fn test_combined_reconciliation() {
        let storage = Storage::open_in_memory().await.unwrap();

        // Shadow cert that will be resolved
        let fp_resolve = [0x11; 32];
        let cert_resolve = make_test_cert(fp_resolve, Utc::now());
        storage.upsert_certificate(&cert_resolve).await.unwrap();
        let shadow_resolve = make_shadow_row(fp_resolve);
        storage.upsert_shadow_certificate(&shadow_resolve).await.unwrap();
        let dir = make_pending_directive(fp_resolve, "dir-resolve");
        storage.insert_action_directive(&dir).await.unwrap();

        // Add to inventory
        let inv_row = CertificateInventoryRow {
            fingerprint: fp_resolve,
            subject: "CN=resolved.com".to_string(),
            source: "file".to_string(),
            imported_at: Utc::now().timestamp_millis(),
            last_refresh_id: "refresh-combined".to_string(),
        };
        storage.upsert_inventory_entry(&inv_row).await.unwrap();

        // Known cert that will become shadow
        let fp_new_shadow = [0x22; 32];
        let cert_new_shadow = make_test_cert(fp_new_shadow, Utc::now() - Duration::hours(3));
        storage.upsert_certificate(&cert_new_shadow).await.unwrap();

        // Run reconciliation with fp_new_shadow as removed
        let result = reconcile_inventory(&storage, &[fp_new_shadow]).await.unwrap();

        assert_eq!(result.shadows_resolved, 1);
        assert_eq!(result.directives_cancelled, 1);
        assert_eq!(result.new_shadows_from_removal, 1);
    }
}
