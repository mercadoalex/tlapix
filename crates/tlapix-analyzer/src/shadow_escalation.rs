//! Shadow certificate escalation logic.
//!
//! Escalates the risk level of unresolved shadow certificates by one tier
//! every 24 hours. When a shadow certificate reaches Critical, a new
//! ActionDirective at critical severity is generated, replacing any prior
//! lower-severity directives for that certificate.
//!
//! Requirements: 5.5, 5.7

use chrono::Utc;
use tracing;
use uuid::Uuid;

use tlapix_common::storage::{ActionDirectiveRow, ShadowCertificateRow, Storage};
use tlapix_common::types::{ActionDirective, ActionType, RiskLevel, Severity};

/// Duration in milliseconds representing 24 hours.
const ESCALATION_INTERVAL_MS: i64 = 24 * 60 * 60 * 1000;

/// Format a fingerprint as a short hex string for logging.
fn fingerprint_hex(fp: &[u8; 32]) -> String {
    fp.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Escalate stale shadow certificates that have been unresolved for more than 24 hours
/// since their last escalation (or since first classification if never escalated).
///
/// For each escalated shadow certificate:
/// - The risk level is increased by one tier (Low → Medium → High → Critical)
/// - `last_escalated` and `escalation_count` are updated
/// - If the new risk level is Critical, a new ActionDirective at critical severity
///   is generated, and any prior pending lower-severity directives for the same
///   fingerprint are marked as "replaced"
///
/// Returns the list of new ActionDirectives generated (only for certificates
/// that reached Critical).
pub async fn escalate_stale_shadows(storage: &Storage) -> Vec<ActionDirective> {
    let unresolved = match storage.list_unresolved_shadow_certificates().await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "Failed to list unresolved shadow certificates");
            return Vec::new();
        }
    };

    let now_ms = Utc::now().timestamp_millis();
    let mut new_directives = Vec::new();

    for shadow in unresolved {
        // Determine the reference time for escalation check
        let reference_time = shadow.last_escalated.unwrap_or(shadow.first_classified);

        // Check if 24 hours have elapsed since last escalation
        let elapsed_ms = now_ms - reference_time;
        if elapsed_ms < ESCALATION_INTERVAL_MS {
            continue;
        }

        // Already at Critical — no further escalation possible
        if shadow.risk_level == RiskLevel::Critical {
            continue;
        }

        // Escalate the risk level
        let new_risk_level = shadow.risk_level.escalate();

        // Update the shadow certificate row
        let updated_row = ShadowCertificateRow {
            risk_level: new_risk_level,
            last_escalated: Some(now_ms),
            escalation_count: shadow.escalation_count + 1,
            ..shadow.clone()
        };

        if let Err(e) = storage.upsert_shadow_certificate(&updated_row).await {
            tracing::error!(
                error = %e,
                fingerprint = %fingerprint_hex(&shadow.fingerprint),
                "Failed to update shadow certificate during escalation"
            );
            continue;
        }

        tracing::info!(
            fingerprint = %fingerprint_hex(&shadow.fingerprint),
            old_level = ?shadow.risk_level,
            new_level = ?new_risk_level,
            escalation_count = updated_row.escalation_count,
            "Shadow certificate escalated"
        );

        // If escalated to Critical, generate a new directive and replace prior ones
        if new_risk_level == RiskLevel::Critical {
            // Replace prior lower-severity pending directives
            if let Err(e) = replace_prior_directives(storage, &shadow.fingerprint).await {
                tracing::error!(
                    error = %e,
                    fingerprint = %fingerprint_hex(&shadow.fingerprint),
                    "Failed to replace prior directives during escalation"
                );
            }

            // Generate new critical-severity directive
            let directive = ActionDirective {
                id: Uuid::new_v4(),
                correlation_id: Uuid::new_v4(),
                cert_fingerprint: shadow.fingerprint,
                action_type: ActionType::Alert,
                severity: Severity::Critical,
                reasoning: format!(
                    "Shadow certificate escalated to critical after {} escalation(s). \
                     Unresolved shadow certificate requires immediate attention.",
                    updated_row.escalation_count
                ),
                created_at: Utc::now(),
                source_anomaly: None,
                attempt_count: 0,
            };

            // Persist the new directive
            let directive_row = ActionDirectiveRow {
                id: directive.id.to_string(),
                correlation_id: directive.correlation_id.to_string(),
                cert_fingerprint: directive.cert_fingerprint,
                action_type: "alert".to_string(),
                severity: "critical".to_string(),
                reasoning: Some(directive.reasoning.clone()),
                status: "pending".to_string(),
                attempt_count: 0,
                created_at: directive.created_at.timestamp_millis(),
                executed_at: None,
                expired_at: None,
                failure_reason: None,
            };

            if let Err(e) = storage.insert_action_directive(&directive_row).await {
                tracing::error!(
                    error = %e,
                    fingerprint = %fingerprint_hex(&shadow.fingerprint),
                    "Failed to insert critical escalation directive"
                );
                continue;
            }

            new_directives.push(directive);
        }
    }

    if !new_directives.is_empty() {
        tracing::info!(
            count = new_directives.len(),
            "Generated critical-severity directives from shadow escalation"
        );
    }

    new_directives
}

/// Mark all pending directives for the given fingerprint as "replaced".
///
/// This is called when a shadow certificate is escalated to Critical, so that
/// the new critical-severity directive supersedes any prior lower-severity ones.
async fn replace_prior_directives(
    storage: &Storage,
    fingerprint: &[u8; 32],
) -> Result<(), tlapix_common::storage::StorageError> {
    let pending = storage
        .list_pending_directives_by_fingerprint(fingerprint)
        .await?;

    for directive in pending {
        storage
            .update_directive_status(&directive.id, "replaced", None)
            .await?;
        tracing::debug!(
            directive_id = %directive.id,
            severity = %directive.severity,
            "Replaced prior directive due to critical escalation"
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tlapix_common::storage::Storage;
    use tlapix_common::types::CertificateMetadata;

    /// Helper to create a test certificate and insert it into storage.
    async fn insert_test_certificate(storage: &Storage, fingerprint: [u8; 32]) {
        let now = Utc::now();
        let cert = CertificateMetadata {
            fingerprint,
            subject: "CN=shadow.example.com".to_string(),
            issuer: "CN=Unknown CA".to_string(),
            serial_number: "01:02:03".to_string(),
            not_before: now - chrono::Duration::days(30),
            not_after: now + chrono::Duration::days(335),
            sans: vec!["shadow.example.com".to_string()],
            key_algorithm: "RSA".to_string(),
            key_size: 2048,
            chain_depth: 1,
            issuer_fingerprint: None,
            first_seen: now,
            last_seen: now,
            connection_count: 1,
            source_ip: Some("192.168.1.100".to_string()),
            destination_ip: Some("10.0.0.50".to_string()),
            sni_hostname: Some("shadow.example.com".to_string()),
            completeness_flags: 0x7F,
        };
        storage.upsert_certificate(&cert).await.unwrap();
    }

    /// Helper to insert a shadow certificate row.
    async fn insert_shadow(
        storage: &Storage,
        fingerprint: [u8; 32],
        risk_level: RiskLevel,
        first_classified_ms: i64,
        last_escalated: Option<i64>,
        escalation_count: i32,
    ) {
        let row = ShadowCertificateRow {
            fingerprint,
            risk_level,
            first_classified: first_classified_ms,
            last_escalated,
            escalation_count,
            source_ip: Some("192.168.1.100".to_string()),
            destination_ip: Some("10.0.0.50".to_string()),
            first_seen: first_classified_ms,
            is_resolved: false,
            resolved_at: None,
        };
        storage.upsert_shadow_certificate(&row).await.unwrap();
    }

    #[tokio::test]
    async fn test_escalation_low_to_medium_after_24h() {
        let storage = Storage::open_in_memory().await.unwrap();
        let fp = [0xA1; 32];
        insert_test_certificate(&storage, fp).await;

        // Shadow classified 25 hours ago, never escalated
        let now_ms = Utc::now().timestamp_millis();
        let twenty_five_hours_ago = now_ms - (25 * 60 * 60 * 1000);
        insert_shadow(&storage, fp, RiskLevel::Low, twenty_five_hours_ago, None, 0).await;

        let directives = escalate_stale_shadows(&storage).await;

        // No critical directive generated (only escalated to Medium)
        assert!(directives.is_empty());

        // Verify the shadow was escalated
        let updated = storage.get_shadow_certificate(&fp).await.unwrap().unwrap();
        assert_eq!(updated.risk_level, RiskLevel::Medium);
        assert_eq!(updated.escalation_count, 1);
        assert!(updated.last_escalated.is_some());
    }

    #[tokio::test]
    async fn test_escalation_medium_to_high_after_24h() {
        let storage = Storage::open_in_memory().await.unwrap();
        let fp = [0xA2; 32];
        insert_test_certificate(&storage, fp).await;

        let now_ms = Utc::now().timestamp_millis();
        let twenty_five_hours_ago = now_ms - (25 * 60 * 60 * 1000);
        insert_shadow(
            &storage,
            fp,
            RiskLevel::Medium,
            now_ms - (50 * 60 * 60 * 1000), // first classified 50h ago
            Some(twenty_five_hours_ago),      // last escalated 25h ago
            1,
        )
        .await;

        let directives = escalate_stale_shadows(&storage).await;

        // No critical directive generated (only escalated to High)
        assert!(directives.is_empty());

        let updated = storage.get_shadow_certificate(&fp).await.unwrap().unwrap();
        assert_eq!(updated.risk_level, RiskLevel::High);
        assert_eq!(updated.escalation_count, 2);
    }

    #[tokio::test]
    async fn test_escalation_high_to_critical_generates_directive() {
        let storage = Storage::open_in_memory().await.unwrap();
        let fp = [0xA3; 32];
        insert_test_certificate(&storage, fp).await;

        let now_ms = Utc::now().timestamp_millis();
        let twenty_five_hours_ago = now_ms - (25 * 60 * 60 * 1000);
        insert_shadow(
            &storage,
            fp,
            RiskLevel::High,
            now_ms - (75 * 60 * 60 * 1000), // first classified 75h ago
            Some(twenty_five_hours_ago),      // last escalated 25h ago
            2,
        )
        .await;

        let directives = escalate_stale_shadows(&storage).await;

        // Should generate a critical directive
        assert_eq!(directives.len(), 1);
        let directive = &directives[0];
        assert_eq!(directive.severity, Severity::Critical);
        assert_eq!(directive.cert_fingerprint, fp);
        assert_eq!(directive.action_type, ActionType::Alert);
        assert!(directive.reasoning.contains("critical"));

        // Verify the shadow was escalated
        let updated = storage.get_shadow_certificate(&fp).await.unwrap().unwrap();
        assert_eq!(updated.risk_level, RiskLevel::Critical);
        assert_eq!(updated.escalation_count, 3);

        // Verify the directive was persisted
        let stored = storage
            .get_action_directive(&directive.id.to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.severity, "critical");
        assert_eq!(stored.status, "pending");
    }

    #[tokio::test]
    async fn test_no_escalation_if_less_than_24h() {
        let storage = Storage::open_in_memory().await.unwrap();
        let fp = [0xA4; 32];
        insert_test_certificate(&storage, fp).await;

        let now_ms = Utc::now().timestamp_millis();
        let twelve_hours_ago = now_ms - (12 * 60 * 60 * 1000);
        insert_shadow(&storage, fp, RiskLevel::Low, twelve_hours_ago, None, 0).await;

        let directives = escalate_stale_shadows(&storage).await;
        assert!(directives.is_empty());

        // Verify the shadow was NOT escalated
        let unchanged = storage.get_shadow_certificate(&fp).await.unwrap().unwrap();
        assert_eq!(unchanged.risk_level, RiskLevel::Low);
        assert_eq!(unchanged.escalation_count, 0);
        assert!(unchanged.last_escalated.is_none());
    }

    #[tokio::test]
    async fn test_critical_stays_at_critical() {
        let storage = Storage::open_in_memory().await.unwrap();
        let fp = [0xA5; 32];
        insert_test_certificate(&storage, fp).await;

        let now_ms = Utc::now().timestamp_millis();
        let twenty_five_hours_ago = now_ms - (25 * 60 * 60 * 1000);
        insert_shadow(
            &storage,
            fp,
            RiskLevel::Critical,
            now_ms - (100 * 60 * 60 * 1000),
            Some(twenty_five_hours_ago),
            3,
        )
        .await;

        let directives = escalate_stale_shadows(&storage).await;

        // No further escalation or directive generation
        assert!(directives.is_empty());

        // Verify it stayed at Critical and was not modified
        let unchanged = storage.get_shadow_certificate(&fp).await.unwrap().unwrap();
        assert_eq!(unchanged.risk_level, RiskLevel::Critical);
        assert_eq!(unchanged.escalation_count, 3);
    }

    #[tokio::test]
    async fn test_escalation_replaces_prior_directives() {
        let storage = Storage::open_in_memory().await.unwrap();
        let fp = [0xA6; 32];
        insert_test_certificate(&storage, fp).await;

        // Insert a prior pending directive at "high" severity
        let prior_directive = ActionDirectiveRow {
            id: "prior-dir-001".to_string(),
            correlation_id: "corr-001".to_string(),
            cert_fingerprint: fp,
            action_type: "alert".to_string(),
            severity: "high".to_string(),
            reasoning: Some("Shadow certificate detected".to_string()),
            status: "pending".to_string(),
            attempt_count: 0,
            created_at: Utc::now().timestamp_millis() - (48 * 60 * 60 * 1000),
            executed_at: None,
            expired_at: None,
            failure_reason: None,
        };
        storage.insert_action_directive(&prior_directive).await.unwrap();

        // Set up shadow at High, ready to escalate to Critical
        let now_ms = Utc::now().timestamp_millis();
        let twenty_five_hours_ago = now_ms - (25 * 60 * 60 * 1000);
        insert_shadow(
            &storage,
            fp,
            RiskLevel::High,
            now_ms - (75 * 60 * 60 * 1000),
            Some(twenty_five_hours_ago),
            2,
        )
        .await;

        let directives = escalate_stale_shadows(&storage).await;

        // New critical directive generated
        assert_eq!(directives.len(), 1);
        assert_eq!(directives[0].severity, Severity::Critical);

        // Prior directive should be marked as "replaced"
        let prior = storage
            .get_action_directive("prior-dir-001")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(prior.status, "replaced");
    }

    #[tokio::test]
    async fn test_resolved_shadows_not_escalated() {
        let storage = Storage::open_in_memory().await.unwrap();
        let fp = [0xA7; 32];
        insert_test_certificate(&storage, fp).await;

        let now_ms = Utc::now().timestamp_millis();
        let twenty_five_hours_ago = now_ms - (25 * 60 * 60 * 1000);

        // Insert as resolved
        let row = ShadowCertificateRow {
            fingerprint: fp,
            risk_level: RiskLevel::Low,
            first_classified: twenty_five_hours_ago,
            last_escalated: None,
            escalation_count: 0,
            source_ip: Some("192.168.1.100".to_string()),
            destination_ip: Some("10.0.0.50".to_string()),
            first_seen: twenty_five_hours_ago,
            is_resolved: true,
            resolved_at: Some(now_ms),
        };
        storage.upsert_shadow_certificate(&row).await.unwrap();

        let directives = escalate_stale_shadows(&storage).await;
        assert!(directives.is_empty());

        // Verify it was not modified
        let unchanged = storage.get_shadow_certificate(&fp).await.unwrap().unwrap();
        assert_eq!(unchanged.risk_level, RiskLevel::Low);
        assert_eq!(unchanged.escalation_count, 0);
    }
}
