//! Periodic re-evaluation scheduler for renewal predictions.
//!
//! Runs a background task that re-evaluates all active renewal predictions
//! on a configurable interval (default 24 hours). On each tick it:
//! 1. Queries certificates whose `not_after` is within 30 days of now.
//! 2. Re-runs `RenewalPredictor::predict()` for each.
//! 3. Upserts the updated prediction into storage.
//! 4. Generates new `ActionDirective`s if severity has escalated (probability ≥ 0.7).

use std::time::Duration;

use chrono::Utc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing;

use tlapix_common::storage::{ActionDirectiveRow, RenewalPredictionRow, Storage};
use tlapix_common::types::Severity;

use crate::renewal::{RenewalHistory, RenewalPredictor};

// ---------------------------------------------------------------------------
// RenewalScheduler
// ---------------------------------------------------------------------------

/// Background scheduler that periodically re-evaluates renewal predictions.
pub struct RenewalScheduler;

impl RenewalScheduler {
    /// Start the periodic re-evaluation loop.
    ///
    /// The loop runs every `interval` duration. On each tick it queries
    /// certificates approaching expiry (within 30 days), re-evaluates
    /// predictions, and updates storage.
    ///
    /// The task runs until the `cancel` token is cancelled.
    pub fn start(
        storage: Storage,
        interval: Duration,
        cancel: CancellationToken,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // The first tick fires immediately; skip it so we don't run on startup.
            ticker.tick().await;

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        tracing::info!("Renewal scheduler shutting down");
                        break;
                    }
                    _ = ticker.tick() => {
                        if let Err(e) = Self::run_reevaluation(&storage).await {
                            tracing::error!(error = %e, "Renewal re-evaluation cycle failed");
                        }
                    }
                }
            }
        })
    }

    /// Execute a single re-evaluation cycle.
    ///
    /// This is also exposed publicly so it can be called directly in tests
    /// without waiting for the interval.
    pub async fn run_reevaluation(
        storage: &Storage,
    ) -> Result<ReevaluationResult, ReevaluationError> {
        let now = Utc::now();
        let predictor = RenewalPredictor::with_now(now);

        // Query certificates expiring within 30 days
        let certs = storage
            .list_certificates_expiring_within_days(30)
            .await
            .map_err(|e| ReevaluationError::Storage(e.to_string()))?;

        tracing::info!(
            cert_count = certs.len(),
            "Starting renewal prediction re-evaluation cycle"
        );

        let mut predictions_updated = 0u32;
        let mut directives_generated = 0u32;
        let mut errors = 0u32;

        for cert in &certs {
            // For now we don't have a way to retrieve full renewal history from
            // storage, so we pass None. Future iterations can incorporate
            // historical patterns from the renewal_predictions table.
            let history: Option<RenewalHistory> = None;

            match predictor.predict(cert, history.as_ref()) {
                Some(result) => {
                    // Convert prediction to storage row
                    let severity_str = severity_to_str(result.prediction.severity);
                    let row = RenewalPredictionRow {
                        cert_fingerprint: result.prediction.cert_fingerprint,
                        failure_probability: result.prediction.failure_probability,
                        severity: severity_str.to_string(),
                        days_until_expiry: result.prediction.days_until_expiry,
                        renewal_activity_detected: result.prediction.renewal_activity_detected,
                        reasoning: Some(result.prediction.reasoning.clone()),
                        last_evaluated: now.timestamp_millis(),
                        created_at: now.timestamp_millis(),
                    };

                    if let Err(e) = storage.upsert_renewal_prediction(&row).await {
                        tracing::warn!(
                            fingerprint = ?hex::short(&cert.fingerprint),
                            error = %e,
                            "Failed to upsert renewal prediction"
                        );
                        errors += 1;
                        continue;
                    }
                    predictions_updated += 1;

                    // If a directive was generated (probability >= 0.7 or expired),
                    // persist it to storage.
                    if let Some(directive) = result.directive {
                        let directive_row = ActionDirectiveRow {
                            id: directive.id.to_string(),
                            correlation_id: directive.correlation_id.to_string(),
                            cert_fingerprint: directive.cert_fingerprint,
                            action_type: action_type_to_str(&directive.action_type),
                            severity: severity_to_str(directive.severity).to_string(),
                            reasoning: Some(directive.reasoning.clone()),
                            status: "pending".to_string(),
                            attempt_count: 0,
                            created_at: directive.created_at.timestamp_millis(),
                            executed_at: None,
                            expired_at: None,
                            failure_reason: None,
                        };

                        if let Err(e) = storage.insert_action_directive(&directive_row).await {
                            tracing::warn!(
                                fingerprint = ?hex::short(&cert.fingerprint),
                                error = %e,
                                "Failed to insert action directive from re-evaluation"
                            );
                            errors += 1;
                        } else {
                            directives_generated += 1;
                            tracing::info!(
                                fingerprint = ?hex::short(&cert.fingerprint),
                                action_type = %directive_row.action_type,
                                severity = %directive_row.severity,
                                probability = result.prediction.failure_probability,
                                "Generated action directive from re-evaluation"
                            );
                        }
                    }
                }
                None => {
                    // Certificate has > 30 days until expiry (shouldn't happen
                    // given our query, but handle gracefully)
                }
            }
        }

        let result = ReevaluationResult {
            certificates_evaluated: certs.len() as u32,
            predictions_updated,
            directives_generated,
            errors,
        };

        tracing::info!(
            evaluated = result.certificates_evaluated,
            updated = result.predictions_updated,
            directives = result.directives_generated,
            errors = result.errors,
            "Renewal re-evaluation cycle complete"
        );

        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Result and Error types
// ---------------------------------------------------------------------------

/// Summary of a re-evaluation cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReevaluationResult {
    /// Number of certificates evaluated.
    pub certificates_evaluated: u32,
    /// Number of predictions updated in storage.
    pub predictions_updated: u32,
    /// Number of new action directives generated.
    pub directives_generated: u32,
    /// Number of errors encountered during the cycle.
    pub errors: u32,
}

/// Errors that can occur during re-evaluation.
#[derive(Debug, thiserror::Error)]
pub enum ReevaluationError {
    #[error("Storage error: {0}")]
    Storage(String),
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn action_type_to_str(action_type: &tlapix_common::types::ActionType) -> String {
    match action_type {
        tlapix_common::types::ActionType::Alert => "alert".to_string(),
        tlapix_common::types::ActionType::Renew => "renew".to_string(),
        tlapix_common::types::ActionType::Protect { .. } => "protect".to_string(),
        tlapix_common::types::ActionType::Isolate { .. } => "isolate".to_string(),
    }
}

/// Helper module for short hex display of fingerprints in logs.
mod hex {
    pub fn short(fp: &[u8; 32]) -> String {
        fp.iter()
            .take(4)
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;
    use std::time::Duration as StdDuration;
    use tlapix_common::types::{completeness, CertificateMetadata};

    /// Helper to create a certificate with a specific not_after date.
    fn make_cert(fingerprint: [u8; 32], not_after: chrono::DateTime<Utc>) -> CertificateMetadata {
        let now = Utc::now();
        CertificateMetadata {
            fingerprint,
            subject: "CN=test.example.com".to_string(),
            issuer: "CN=Test CA".to_string(),
            serial_number: "ABCD1234".to_string(),
            not_before: now - ChronoDuration::days(335),
            not_after,
            sans: vec!["test.example.com".to_string()],
            key_algorithm: "RSA".to_string(),
            key_size: 2048,
            chain_depth: 2,
            issuer_fingerprint: Some([1u8; 32]),
            first_seen: now - ChronoDuration::days(100),
            last_seen: now,
            connection_count: 50,
            source_ip: Some("10.0.0.1".to_string()),
            destination_ip: Some("10.0.0.2".to_string()),
            sni_hostname: Some("test.example.com".to_string()),
            completeness_flags: completeness::ALL_REQUIRED | completeness::SANS,
        }
    }

    #[tokio::test]
    async fn test_reevaluation_with_no_certificates() {
        let storage = Storage::open_in_memory().await.unwrap();

        let result = RenewalScheduler::run_reevaluation(&storage).await.unwrap();

        assert_eq!(result.certificates_evaluated, 0);
        assert_eq!(result.predictions_updated, 0);
        assert_eq!(result.directives_generated, 0);
        assert_eq!(result.errors, 0);
    }

    #[tokio::test]
    async fn test_reevaluation_with_expiring_certificate() {
        let storage = Storage::open_in_memory().await.unwrap();
        let now = Utc::now();

        // Insert a certificate expiring in 20 days
        let fp = [10u8; 32];
        let cert = make_cert(fp, now + ChronoDuration::days(20));
        storage.upsert_certificate(&cert).await.unwrap();

        let result = RenewalScheduler::run_reevaluation(&storage).await.unwrap();

        assert_eq!(result.certificates_evaluated, 1);
        assert_eq!(result.predictions_updated, 1);

        // Verify prediction was stored
        let prediction = storage.get_renewal_prediction(&fp).await.unwrap();
        assert!(prediction.is_some());
        let pred = prediction.unwrap();
        assert!(pred.failure_probability >= 0.5);
        // Allow ±1 day tolerance due to timing between now captures
        assert!(
            (pred.days_until_expiry - 20).abs() <= 1,
            "Expected ~20 days, got {}",
            pred.days_until_expiry
        );
    }

    #[tokio::test]
    async fn test_reevaluation_generates_directive_for_high_probability() {
        let storage = Storage::open_in_memory().await.unwrap();
        let now = Utc::now();

        // Insert a certificate expiring in 10 days (probability will be >= 0.7)
        let fp = [11u8; 32];
        let cert = make_cert(fp, now + ChronoDuration::days(10));
        storage.upsert_certificate(&cert).await.unwrap();

        let result = RenewalScheduler::run_reevaluation(&storage).await.unwrap();

        assert_eq!(result.certificates_evaluated, 1);
        assert_eq!(result.predictions_updated, 1);
        assert_eq!(result.directives_generated, 1);

        // Verify directive was stored
        let directives = storage.list_directives_by_status("pending").await.unwrap();
        assert_eq!(directives.len(), 1);
        assert_eq!(directives[0].action_type, "renew");
        assert_eq!(directives[0].cert_fingerprint, fp);
    }

    #[tokio::test]
    async fn test_reevaluation_skips_certificates_beyond_30_days() {
        let storage = Storage::open_in_memory().await.unwrap();
        let now = Utc::now();

        // Insert a certificate expiring in 60 days (should not be returned by query)
        let fp = [12u8; 32];
        let cert = make_cert(fp, now + ChronoDuration::days(60));
        storage.upsert_certificate(&cert).await.unwrap();

        let result = RenewalScheduler::run_reevaluation(&storage).await.unwrap();

        // The certificate should not be in the query results (not_after > 30 days from now)
        assert_eq!(result.certificates_evaluated, 0);
        assert_eq!(result.predictions_updated, 0);
    }

    #[tokio::test]
    async fn test_reevaluation_handles_expired_certificate() {
        let storage = Storage::open_in_memory().await.unwrap();
        let now = Utc::now();

        // Insert an already-expired certificate
        let fp = [13u8; 32];
        let cert = make_cert(fp, now - ChronoDuration::days(5));
        storage.upsert_certificate(&cert).await.unwrap();

        let result = RenewalScheduler::run_reevaluation(&storage).await.unwrap();

        assert_eq!(result.certificates_evaluated, 1);
        assert_eq!(result.predictions_updated, 1);
        assert_eq!(result.directives_generated, 1);

        // Verify the directive is an alert (expired cert)
        let directives = storage.list_directives_by_status("pending").await.unwrap();
        assert_eq!(directives.len(), 1);
        assert_eq!(directives[0].action_type, "alert");
        assert_eq!(directives[0].severity, "critical");
    }

    #[tokio::test]
    async fn test_reevaluation_multiple_certificates() {
        let storage = Storage::open_in_memory().await.unwrap();
        let now = Utc::now();

        // Insert multiple certificates with different expiry times
        let fp1 = [20u8; 32];
        let cert1 = make_cert(fp1, now + ChronoDuration::days(5)); // critical, will generate directive
        storage.upsert_certificate(&cert1).await.unwrap();

        let fp2 = [21u8; 32];
        let cert2 = make_cert(fp2, now + ChronoDuration::days(25)); // medium, probability ~0.575
        storage.upsert_certificate(&cert2).await.unwrap();

        let fp3 = [22u8; 32];
        let cert3 = make_cert(fp3, now + ChronoDuration::days(15)); // probability ~0.725, generates directive
        storage.upsert_certificate(&cert3).await.unwrap();

        let result = RenewalScheduler::run_reevaluation(&storage).await.unwrap();

        assert_eq!(result.certificates_evaluated, 3);
        assert_eq!(result.predictions_updated, 3);
        // fp1 (5 days) and fp3 (15 days) should generate directives
        assert!(result.directives_generated >= 2);
    }

    #[tokio::test]
    async fn test_scheduler_cancellation() {
        let storage = Storage::open_in_memory().await.unwrap();
        let cancel = CancellationToken::new();

        // Start with a very short interval
        let handle = RenewalScheduler::start(storage, StdDuration::from_millis(50), cancel.clone());

        // Let it run briefly
        tokio::time::sleep(StdDuration::from_millis(100)).await;

        // Cancel and verify it stops
        cancel.cancel();
        let result = tokio::time::timeout(StdDuration::from_secs(2), handle).await;
        assert!(result.is_ok(), "Scheduler should stop after cancellation");
    }

    #[tokio::test]
    async fn test_reevaluation_updates_existing_prediction() {
        let storage = Storage::open_in_memory().await.unwrap();
        let now = Utc::now();

        // Insert a certificate expiring in 20 days
        let fp = [30u8; 32];
        let cert = make_cert(fp, now + ChronoDuration::days(20));
        storage.upsert_certificate(&cert).await.unwrap();

        // Insert an existing prediction (simulating a previous evaluation)
        let old_row = RenewalPredictionRow {
            cert_fingerprint: fp,
            failure_probability: 0.3,
            severity: "low".to_string(),
            days_until_expiry: 25,
            renewal_activity_detected: false,
            reasoning: Some("Old prediction".to_string()),
            last_evaluated: (now - ChronoDuration::days(1)).timestamp_millis(),
            created_at: (now - ChronoDuration::days(5)).timestamp_millis(),
        };
        storage.upsert_renewal_prediction(&old_row).await.unwrap();

        // Run re-evaluation
        let result = RenewalScheduler::run_reevaluation(&storage).await.unwrap();
        assert_eq!(result.predictions_updated, 1);

        // Verify prediction was updated
        let updated = storage.get_renewal_prediction(&fp).await.unwrap().unwrap();
        // Allow ±1 day tolerance due to timing between now captures
        assert!(
            (updated.days_until_expiry - 20).abs() <= 1,
            "Expected ~20 days, got {}",
            updated.days_until_expiry
        );
        assert!(updated.failure_probability > 0.3); // Should be higher now
        assert!(updated.last_evaluated > old_row.last_evaluated);
    }
}
