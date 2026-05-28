//! Retry exhaustion and failure handling for the Executor layer.
//!
//! When an `ActionDirective` fails execution after all retry attempts are
//! exhausted (3 attempts), this module:
//! 1. Marks the directive as "failed" in storage with the failure reason
//! 2. Records the attempt count
//! 3. Logs the failure with structured fields
//! 4. Generates a new "alert" ActionDirective at Critical severity to notify operators
//!
//! Implements Requirement 6.7.

use chrono::Utc;
use tracing::{error, info};
use uuid::Uuid;

use tlapix_common::storage::{ActionDirectiveRow, Storage};
use tlapix_common::types::{ActionDirective, ExecutionOutcome};

// ---------------------------------------------------------------------------
// Failure handling result
// ---------------------------------------------------------------------------

/// Result of handling an execution failure.
#[derive(Debug, Clone)]
pub struct FailureHandlingResult {
    /// The ID of the directive that was marked as failed.
    pub failed_directive_id: String,
    /// The ID of the alert directive generated for operators.
    pub alert_directive_id: String,
    /// The number of attempts that were made.
    pub attempts: u8,
    /// The failure reason.
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Core failure handling logic
// ---------------------------------------------------------------------------

/// Handle an execution failure after all retry attempts are exhausted.
///
/// This function:
/// 1. Marks the directive as "failed" in storage with the failure reason
/// 2. Updates the attempt_count in storage
/// 3. Logs the failure with structured fields (directive_id, fingerprint, reason, attempts)
/// 4. Generates a new "alert" ActionDirective at Critical severity for operators
/// 5. Inserts the alert directive into storage
///
/// Returns `Ok(FailureHandlingResult)` on success, or an error if storage operations fail.
pub async fn handle_execution_failure(
    storage: &Storage,
    directive: &ActionDirective,
    outcome: &ExecutionOutcome,
) -> Result<FailureHandlingResult, anyhow::Error> {
    let (reason, attempts) = match outcome {
        ExecutionOutcome::Failed { reason, attempts } => (reason.clone(), *attempts),
        _ => {
            return Err(anyhow::anyhow!(
                "handle_execution_failure called with non-Failed outcome: {:?}",
                outcome
            ));
        }
    };

    let directive_id = directive.id.to_string();
    let fingerprint_hex = format_fingerprint(&directive.cert_fingerprint);

    // 1. Mark directive as failed in storage with the failure reason and attempt count
    storage
        .mark_directive_failed(&directive_id, attempts as i32, &reason)
        .await?;

    // 2. Log the failure with structured fields
    error!(
        directive_id = %directive_id,
        fingerprint = %fingerprint_hex,
        reason = %reason,
        attempts = attempts,
        action_type = ?directive.action_type,
        severity = ?directive.severity,
        "Directive execution failed after all retry attempts exhausted"
    );

    // 3. Generate an alert ActionDirective at Critical severity for operators
    let alert_id = Uuid::new_v4();
    let alert_reasoning = format!(
        "Directive execution failed after {} attempts: {}. Manual intervention required.",
        attempts, reason
    );

    let alert_row = ActionDirectiveRow {
        id: alert_id.to_string(),
        correlation_id: directive.correlation_id.to_string(),
        cert_fingerprint: directive.cert_fingerprint,
        action_type: "alert".to_string(),
        severity: "critical".to_string(),
        reasoning: Some(alert_reasoning.clone()),
        status: "pending".to_string(),
        attempt_count: 0,
        created_at: Utc::now().timestamp_millis(),
        executed_at: None,
        expired_at: None,
        failure_reason: None,
    };

    // 4. Insert the alert directive into storage
    storage.insert_action_directive(&alert_row).await?;

    info!(
        alert_directive_id = %alert_id,
        failed_directive_id = %directive_id,
        fingerprint = %fingerprint_hex,
        "Generated critical alert directive for operators due to execution failure"
    );

    Ok(FailureHandlingResult {
        failed_directive_id: directive_id,
        alert_directive_id: alert_id.to_string(),
        attempts,
        reason,
    })
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Format a fingerprint as a hex string for logging.
fn format_fingerprint(fp: &[u8; 32]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &b in fp.iter() {
        s.push(HEX_CHARS[(b >> 4) as usize] as char);
        s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use tlapix_common::storage::Storage;
    use tlapix_common::types::{ActionType, CertificateMetadata, Severity};
    use uuid::Uuid;

    /// Helper to create a test ActionDirective.
    fn make_test_directive(fingerprint: [u8; 32]) -> ActionDirective {
        ActionDirective {
            id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            cert_fingerprint: fingerprint,
            action_type: ActionType::Renew,
            severity: Severity::High,
            reasoning: "Certificate expiring soon".to_string(),
            created_at: Utc::now(),
            source_anomaly: None,
            attempt_count: 3,
        }
    }

    /// Helper to create a test certificate for the given fingerprint.
    fn make_test_certificate(fingerprint: [u8; 32]) -> CertificateMetadata {
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
            last_seen: now,
            connection_count: 1,
            source_ip: Some("192.168.1.1".to_string()),
            destination_ip: Some("10.0.0.1".to_string()),
            sni_hostname: Some("test.example.com".to_string()),
            completeness_flags: 0x7F,
        }
    }

    /// Helper to insert a certificate and directive into storage.
    async fn setup_directive_in_storage(storage: &Storage, directive: &ActionDirective) {
        // Insert the certificate first (FK constraint)
        let cert = make_test_certificate(directive.cert_fingerprint);
        storage.upsert_certificate(&cert).await.unwrap();

        // Insert the directive
        let row = ActionDirectiveRow {
            id: directive.id.to_string(),
            correlation_id: directive.correlation_id.to_string(),
            cert_fingerprint: directive.cert_fingerprint,
            action_type: "renew".to_string(),
            severity: "high".to_string(),
            reasoning: Some(directive.reasoning.clone()),
            status: "pending".to_string(),
            attempt_count: 0,
            created_at: directive.created_at.timestamp_millis(),
            executed_at: None,
            expired_at: None,
            failure_reason: None,
        };
        storage.insert_action_directive(&row).await.unwrap();
    }

    #[tokio::test]
    async fn test_directive_marked_as_failed_in_storage() {
        let storage = Storage::open_in_memory().await.unwrap();
        let fp = [0xAA; 32];
        let directive = make_test_directive(fp);

        // Insert the directive first so it can be updated
        setup_directive_in_storage(&storage, &directive).await;

        let outcome = ExecutionOutcome::Failed {
            reason: "BPF map write timeout".to_string(),
            attempts: 3,
        };

        let result = handle_execution_failure(&storage, &directive, &outcome)
            .await
            .unwrap();

        // Verify the directive was marked as failed
        let updated = storage
            .get_action_directive(&directive.id.to_string())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(updated.status, "failed");
        assert_eq!(updated.attempt_count, 3);
        assert_eq!(
            updated.failure_reason,
            Some("BPF map write timeout".to_string())
        );
        assert_eq!(result.failed_directive_id, directive.id.to_string());
        assert_eq!(result.attempts, 3);
        assert_eq!(result.reason, "BPF map write timeout");
    }

    #[tokio::test]
    async fn test_alert_directive_generated_for_operators() {
        let storage = Storage::open_in_memory().await.unwrap();
        let fp = [0xBB; 32];
        let directive = make_test_directive(fp);

        setup_directive_in_storage(&storage, &directive).await;

        let outcome = ExecutionOutcome::Failed {
            reason: "connection refused".to_string(),
            attempts: 3,
        };

        let result = handle_execution_failure(&storage, &directive, &outcome)
            .await
            .unwrap();

        // Verify the alert directive was created
        let alert = storage
            .get_action_directive(&result.alert_directive_id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(alert.action_type, "alert");
        assert_eq!(alert.severity, "critical");
        assert_eq!(alert.status, "pending");
        assert_eq!(alert.attempt_count, 0);
        assert_eq!(alert.cert_fingerprint, fp);
        assert_eq!(alert.correlation_id, directive.correlation_id.to_string());

        // Verify reasoning contains failure info
        let reasoning = alert.reasoning.unwrap();
        assert!(reasoning.contains("3 attempts"));
        assert!(reasoning.contains("connection refused"));
        assert!(reasoning.contains("Manual intervention required"));
    }

    #[tokio::test]
    async fn test_correct_attempt_count_recorded() {
        let storage = Storage::open_in_memory().await.unwrap();
        let fp = [0xCC; 32];
        let directive = make_test_directive(fp);

        setup_directive_in_storage(&storage, &directive).await;

        let outcome = ExecutionOutcome::Failed {
            reason: "simulated failure".to_string(),
            attempts: 3,
        };

        handle_execution_failure(&storage, &directive, &outcome)
            .await
            .unwrap();

        // Verify attempt count is correctly stored
        let updated = storage
            .get_action_directive(&directive.id.to_string())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(updated.attempt_count, 3);
    }

    #[tokio::test]
    async fn test_rejects_non_failed_outcome() {
        let storage = Storage::open_in_memory().await.unwrap();
        let fp = [0xDD; 32];
        let directive = make_test_directive(fp);

        // Try with a Success outcome - should error
        let outcome = ExecutionOutcome::Success;
        let result = handle_execution_failure(&storage, &directive, &outcome).await;
        assert!(result.is_err());

        // Try with MapFull outcome - should error
        let outcome = ExecutionOutcome::MapFull;
        let result = handle_execution_failure(&storage, &directive, &outcome).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_alert_has_no_source_anomaly_context() {
        let storage = Storage::open_in_memory().await.unwrap();
        let fp = [0xEE; 32];
        let directive = make_test_directive(fp);

        setup_directive_in_storage(&storage, &directive).await;

        let outcome = ExecutionOutcome::Failed {
            reason: "network error".to_string(),
            attempts: 3,
        };

        let result = handle_execution_failure(&storage, &directive, &outcome)
            .await
            .unwrap();

        // The alert directive should exist and be a standalone alert
        let alert = storage
            .get_action_directive(&result.alert_directive_id)
            .await
            .unwrap()
            .unwrap();

        // source_anomaly is None for the alert (it's stored as action_type "alert")
        assert_eq!(alert.action_type, "alert");
        // The failure_reason on the alert itself should be None (it's a new directive)
        assert_eq!(alert.failure_reason, None);
    }
}
