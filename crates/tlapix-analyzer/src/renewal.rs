//! Certificate renewal failure prediction.
//!
//! Evaluates certificates approaching expiration and generates `RenewalPrediction`
//! structs along with `ActionDirective` entries when intervention is needed.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use tlapix_common::types::{
    ActionDirective, ActionType, CertificateMetadata, RenewalPrediction, Severity,
};

// ---------------------------------------------------------------------------
// Renewal History
// ---------------------------------------------------------------------------

/// Historical renewal data used to refine failure probability predictions.
#[derive(Debug, Clone)]
pub struct RenewalHistory {
    /// How many days before expiry previous renewals happened.
    pub previous_renewal_days: Vec<i32>,
    /// Number of past renewal failures.
    pub past_failures: u32,
    /// Average response time (in days) from the issuer for renewals.
    pub issuer_avg_response_days: f64,
}

// ---------------------------------------------------------------------------
// Prediction Result
// ---------------------------------------------------------------------------

/// The result of a renewal prediction evaluation.
#[derive(Debug, Clone)]
pub struct PredictionResult {
    /// The renewal prediction assessment.
    pub prediction: RenewalPrediction,
    /// An optional action directive generated when intervention is needed.
    pub directive: Option<ActionDirective>,
}

// ---------------------------------------------------------------------------
// Renewal Predictor
// ---------------------------------------------------------------------------

/// Predicts certificate renewal failures based on expiry proximity and historical data.
#[derive(Debug, Clone)]
pub struct RenewalPredictor {
    /// The current time provider (allows injection for testing).
    now: DateTime<Utc>,
}

impl RenewalPredictor {
    /// Create a new predictor using the current system time.
    pub fn new() -> Self {
        Self { now: Utc::now() }
    }

    /// Create a predictor with a fixed "now" timestamp (useful for testing).
    pub fn with_now(now: DateTime<Utc>) -> Self {
        Self { now }
    }

    /// Generate a renewal prediction for a certificate.
    ///
    /// Returns `None` if the certificate has more than 30 days until expiry.
    /// Otherwise returns a `PredictionResult` containing the prediction and
    /// an optional `ActionDirective`.
    pub fn predict(
        &self,
        metadata: &CertificateMetadata,
        history: Option<&RenewalHistory>,
    ) -> Option<PredictionResult> {
        let days_until_expiry = (metadata.not_after - self.now).num_days() as i32;

        // No prediction needed if more than 30 days remain
        if days_until_expiry > 30 {
            return None;
        }

        // Determine if renewal activity has been detected.
        // For now, we consider renewal activity as not detected unless
        // historical data shows a recent renewal pattern.
        let renewal_activity_detected = self.has_renewal_activity(history, days_until_expiry);

        // Calculate failure probability
        let failure_probability = self.calculate_probability(
            days_until_expiry,
            history,
            renewal_activity_detected,
        );

        // Determine severity
        let severity = self.determine_severity(days_until_expiry, renewal_activity_detected);

        // Build reasoning
        let reasoning = self.build_reasoning(
            days_until_expiry,
            failure_probability,
            history,
            renewal_activity_detected,
        );

        let prediction = RenewalPrediction {
            cert_fingerprint: metadata.fingerprint,
            failure_probability,
            days_until_expiry,
            severity,
            reasoning: reasoning.clone(),
            last_evaluated: self.now,
            renewal_activity_detected,
        };

        // Generate action directive if needed
        let directive = self.generate_directive(
            metadata,
            days_until_expiry,
            failure_probability,
            severity,
            &reasoning,
        );

        Some(PredictionResult {
            prediction,
            directive,
        })
    }

    /// Check if renewal activity has been detected based on historical data.
    fn has_renewal_activity(&self, history: Option<&RenewalHistory>, days_until_expiry: i32) -> bool {
        match history {
            Some(h) => {
                // If there are previous renewals and the average renewal timing
                // suggests a renewal should have started by now, check if it has.
                if h.previous_renewal_days.is_empty() {
                    return false;
                }
                // Consider renewal activity detected if the average previous renewal
                // happened at a point further from expiry than we currently are,
                // meaning the renewal process should already be underway.
                let avg_renewal_day: f64 = h.previous_renewal_days.iter()
                    .map(|&d| d as f64)
                    .sum::<f64>()
                    / h.previous_renewal_days.len() as f64;

                // If we're past the typical renewal window and there have been
                // no failures, assume renewal activity is happening
                if days_until_expiry > 0
                    && (days_until_expiry as f64) < avg_renewal_day
                    && h.past_failures == 0
                {
                    return true;
                }
                false
            }
            None => false,
        }
    }

    /// Calculate the failure probability based on days until expiry and history.
    fn calculate_probability(
        &self,
        days_until_expiry: i32,
        history: Option<&RenewalHistory>,
        renewal_activity_detected: bool,
    ) -> f64 {
        match history {
            None => {
                // Baseline: 0.5 + (30 - days_until_expiry) * 0.015
                // This increases as expiry approaches, starting at 0.5 for 30 days
                // and reaching ~0.95 at 0 days.
                let days_clamped = days_until_expiry.max(0).min(30);
                0.5 + (30 - days_clamped) as f64 * 0.015
            }
            Some(h) => {
                // Incorporate historical data
                let base = if renewal_activity_detected {
                    // Lower base probability when renewal is in progress
                    0.2
                } else {
                    0.4
                };

                // Factor in past failures
                let failure_factor = (h.past_failures as f64 * 0.1).min(0.3);

                // Factor in issuer response time vs remaining days
                let issuer_factor = if days_until_expiry > 0 {
                    let remaining = days_until_expiry as f64;
                    if h.issuer_avg_response_days > remaining {
                        // Issuer typically takes longer than we have left
                        0.3
                    } else {
                        0.0
                    }
                } else {
                    0.4 // Already expired
                };

                // Time pressure factor (increases as expiry approaches)
                let days_clamped = days_until_expiry.max(0).min(30);
                let time_factor = (30 - days_clamped) as f64 * 0.008;

                (base + failure_factor + issuer_factor + time_factor).min(1.0)
            }
        }
    }

    /// Determine the severity level for the prediction.
    fn determine_severity(
        &self,
        days_until_expiry: i32,
        renewal_activity_detected: bool,
    ) -> Severity {
        if days_until_expiry <= 0 {
            // Already expired
            Severity::Critical
        } else if days_until_expiry < 14 && !renewal_activity_detected {
            // Less than 14 days and no renewal activity → critical
            Severity::Critical
        } else if days_until_expiry < 14 {
            // Less than 14 days but renewal activity detected
            Severity::High
        } else {
            // 14-30 days remaining
            Severity::Medium
        }
    }

    /// Generate an action directive if the prediction warrants intervention.
    fn generate_directive(
        &self,
        metadata: &CertificateMetadata,
        days_until_expiry: i32,
        failure_probability: f64,
        severity: Severity,
        reasoning: &str,
    ) -> Option<ActionDirective> {
        if days_until_expiry <= 0 {
            // Certificate has expired without renewal → alert at critical
            Some(ActionDirective {
                id: Uuid::new_v4(),
                correlation_id: Uuid::new_v4(),
                cert_fingerprint: metadata.fingerprint,
                action_type: ActionType::Alert,
                severity: Severity::Critical,
                reasoning: format!(
                    "Certificate expired {} days ago without renewal. {}",
                    -days_until_expiry, reasoning
                )
                .chars()
                .take(500)
                .collect(),
                created_at: self.now,
                source_anomaly: None,
                attempt_count: 0,
            })
        } else if failure_probability >= 0.7 {
            // High failure probability → generate renew directive
            Some(ActionDirective {
                id: Uuid::new_v4(),
                correlation_id: Uuid::new_v4(),
                cert_fingerprint: metadata.fingerprint,
                action_type: ActionType::Renew,
                severity,
                reasoning: reasoning.chars().take(500).collect(),
                created_at: self.now,
                source_anomaly: None,
                attempt_count: 0,
            })
        } else {
            None
        }
    }

    /// Build a human-readable reasoning string for the prediction.
    fn build_reasoning(
        &self,
        days_until_expiry: i32,
        failure_probability: f64,
        history: Option<&RenewalHistory>,
        renewal_activity_detected: bool,
    ) -> String {
        let mut parts = Vec::new();

        if days_until_expiry <= 0 {
            parts.push(format!(
                "Certificate expired {} days ago",
                -days_until_expiry
            ));
        } else {
            parts.push(format!(
                "Certificate expires in {} days",
                days_until_expiry
            ));
        }

        parts.push(format!(
            "Failure probability: {:.0}%",
            failure_probability * 100.0
        ));

        if !renewal_activity_detected {
            parts.push("No renewal activity detected".to_string());
        } else {
            parts.push("Renewal activity detected".to_string());
        }

        match history {
            None => parts.push("No historical renewal data available".to_string()),
            Some(h) => {
                if !h.previous_renewal_days.is_empty() {
                    let avg: f64 = h.previous_renewal_days.iter()
                        .map(|&d| d as f64)
                        .sum::<f64>()
                        / h.previous_renewal_days.len() as f64;
                    parts.push(format!(
                        "Historical avg renewal: {:.0} days before expiry",
                        avg
                    ));
                }
                if h.past_failures > 0 {
                    parts.push(format!("{} past renewal failures", h.past_failures));
                }
            }
        }

        let reasoning = parts.join(". ");
        if reasoning.len() > 500 {
            format!("{}...", &reasoning[..497])
        } else {
            reasoning
        }
    }
}

impl Default for RenewalPredictor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use tlapix_common::types::completeness;

    /// Helper to create a certificate metadata with a specific not_after date.
    fn make_cert(not_after: DateTime<Utc>) -> CertificateMetadata {
        let now = Utc::now();
        CertificateMetadata {
            fingerprint: [42u8; 32],
            subject: "CN=test.example.com".to_string(),
            issuer: "CN=Test CA".to_string(),
            serial_number: "ABCD1234".to_string(),
            not_before: now - Duration::days(335),
            not_after,
            sans: vec!["test.example.com".to_string()],
            key_algorithm: "RSA".to_string(),
            key_size: 2048,
            chain_depth: 2,
            issuer_fingerprint: Some([1u8; 32]),
            first_seen: now - Duration::days(100),
            last_seen: now,
            connection_count: 50,
            source_ip: Some("10.0.0.1".to_string()),
            destination_ip: Some("10.0.0.2".to_string()),
            sni_hostname: Some("test.example.com".to_string()),
            completeness_flags: completeness::ALL_REQUIRED | completeness::SANS,
        }
    }

    #[test]
    fn test_no_prediction_when_more_than_30_days() {
        let now = Utc::now();
        let predictor = RenewalPredictor::with_now(now);
        let cert = make_cert(now + Duration::days(31));

        let result = predictor.predict(&cert, None);
        assert!(result.is_none(), "Should not generate prediction for >30 days");
    }

    #[test]
    fn test_no_prediction_at_exactly_31_days() {
        let now = Utc::now();
        let predictor = RenewalPredictor::with_now(now);
        let cert = make_cert(now + Duration::days(31));

        let result = predictor.predict(&cert, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_prediction_at_30_days_no_history() {
        let now = Utc::now();
        let predictor = RenewalPredictor::with_now(now);
        let cert = make_cert(now + Duration::days(30));

        let result = predictor.predict(&cert, None);
        assert!(result.is_some());

        let pr = result.unwrap();
        // Baseline probability at 30 days: 0.5 + (30-30)*0.015 = 0.5
        assert!(
            pr.prediction.failure_probability >= 0.5,
            "Baseline probability should be >= 0.5, got {}",
            pr.prediction.failure_probability
        );
        assert_eq!(pr.prediction.days_until_expiry, 30);
        assert_eq!(pr.prediction.severity, Severity::Medium);
        assert!(!pr.prediction.renewal_activity_detected);
    }

    #[test]
    fn test_prediction_at_20_days_no_history_baseline() {
        let now = Utc::now();
        let predictor = RenewalPredictor::with_now(now);
        let cert = make_cert(now + Duration::days(20));

        let result = predictor.predict(&cert, None).unwrap();

        // Baseline: 0.5 + (30-20)*0.015 = 0.5 + 0.15 = 0.65
        let expected = 0.5 + (30.0 - 20.0) * 0.015;
        assert!(
            (result.prediction.failure_probability - expected).abs() < 0.001,
            "Expected ~{}, got {}",
            expected,
            result.prediction.failure_probability
        );
        assert_eq!(result.prediction.days_until_expiry, 20);
        assert_eq!(result.prediction.severity, Severity::Medium);
        // probability 0.65 < 0.7, so no directive
        assert!(result.directive.is_none());
    }

    #[test]
    fn test_critical_severity_under_14_days_no_renewal_activity() {
        let now = Utc::now();
        let predictor = RenewalPredictor::with_now(now);
        let cert = make_cert(now + Duration::days(10));

        let result = predictor.predict(&cert, None).unwrap();

        assert_eq!(result.prediction.severity, Severity::Critical);
        assert_eq!(result.prediction.days_until_expiry, 10);
        assert!(!result.prediction.renewal_activity_detected);
    }

    #[test]
    fn test_renew_directive_when_probability_ge_0_7() {
        let now = Utc::now();
        let predictor = RenewalPredictor::with_now(now);
        // At 16 days: 0.5 + (30-16)*0.015 = 0.5 + 0.21 = 0.71 >= 0.7
        let cert = make_cert(now + Duration::days(16));

        let result = predictor.predict(&cert, None).unwrap();

        assert!(
            result.prediction.failure_probability >= 0.7,
            "Expected >= 0.7, got {}",
            result.prediction.failure_probability
        );
        assert!(result.directive.is_some());
        let directive = result.directive.unwrap();
        assert_eq!(directive.action_type, ActionType::Renew);
        assert_eq!(directive.cert_fingerprint, [42u8; 32]);
    }

    #[test]
    fn test_alert_directive_when_expired() {
        let now = Utc::now();
        let predictor = RenewalPredictor::with_now(now);
        let cert = make_cert(now - Duration::days(5));

        let result = predictor.predict(&cert, None).unwrap();

        assert_eq!(result.prediction.days_until_expiry, -5);
        assert_eq!(result.prediction.severity, Severity::Critical);
        assert!(result.directive.is_some());

        let directive = result.directive.unwrap();
        assert_eq!(directive.action_type, ActionType::Alert);
        assert_eq!(directive.severity, Severity::Critical);
    }

    #[test]
    fn test_good_renewal_history_lowers_probability() {
        let now = Utc::now();
        let predictor = RenewalPredictor::with_now(now);
        let cert = make_cert(now + Duration::days(20));

        let history = RenewalHistory {
            previous_renewal_days: vec![25, 28, 30], // Typically renews 25-30 days before
            past_failures: 0,
            issuer_avg_response_days: 2.0,
        };

        let result_with_history = predictor.predict(&cert, Some(&history)).unwrap();
        let result_without_history = predictor.predict(&cert, None).unwrap();

        // With good history and renewal activity detected, probability should be lower
        assert!(
            result_with_history.prediction.failure_probability
                < result_without_history.prediction.failure_probability,
            "With good history ({}) should be lower than without ({})",
            result_with_history.prediction.failure_probability,
            result_without_history.prediction.failure_probability
        );
    }

    #[test]
    fn test_past_failures_increase_probability() {
        let now = Utc::now();
        let predictor = RenewalPredictor::with_now(now);
        let cert = make_cert(now + Duration::days(20));

        let good_history = RenewalHistory {
            previous_renewal_days: vec![25, 28],
            past_failures: 0,
            issuer_avg_response_days: 2.0,
        };

        let bad_history = RenewalHistory {
            previous_renewal_days: vec![25, 28],
            past_failures: 3,
            issuer_avg_response_days: 2.0,
        };

        let result_good = predictor.predict(&cert, Some(&good_history)).unwrap();
        let result_bad = predictor.predict(&cert, Some(&bad_history)).unwrap();

        assert!(
            result_bad.prediction.failure_probability > result_good.prediction.failure_probability,
            "More failures ({}) should increase probability vs no failures ({})",
            result_bad.prediction.failure_probability,
            result_good.prediction.failure_probability
        );
    }

    #[test]
    fn test_probability_capped_at_1_0() {
        let now = Utc::now();
        let predictor = RenewalPredictor::with_now(now);
        // Expired certificate with bad history
        let cert = make_cert(now - Duration::days(10));

        let history = RenewalHistory {
            previous_renewal_days: vec![],
            past_failures: 10,
            issuer_avg_response_days: 30.0,
        };

        let result = predictor.predict(&cert, Some(&history)).unwrap();
        assert!(
            result.prediction.failure_probability <= 1.0,
            "Probability should be capped at 1.0, got {}",
            result.prediction.failure_probability
        );
    }

    #[test]
    fn test_reasoning_contains_relevant_info() {
        let now = Utc::now();
        let predictor = RenewalPredictor::with_now(now);
        let cert = make_cert(now + Duration::days(10));

        let result = predictor.predict(&cert, None).unwrap();

        assert!(result.prediction.reasoning.contains("10 days"));
        assert!(result.prediction.reasoning.contains("No renewal activity"));
        assert!(result.prediction.reasoning.contains("No historical"));
        assert!(result.prediction.reasoning.len() <= 500);
    }

    #[test]
    fn test_expired_alert_reasoning() {
        let now = Utc::now();
        let predictor = RenewalPredictor::with_now(now);
        let cert = make_cert(now - Duration::days(3));

        let result = predictor.predict(&cert, None).unwrap();
        let directive = result.directive.unwrap();

        assert!(directive.reasoning.contains("expired"));
        assert!(directive.reasoning.len() <= 500);
    }

    #[test]
    fn test_renewal_activity_detected_with_history() {
        let now = Utc::now();
        let predictor = RenewalPredictor::with_now(now);
        // 15 days until expiry, history shows renewals typically at 20 days
        let cert = make_cert(now + Duration::days(15));

        let history = RenewalHistory {
            previous_renewal_days: vec![20, 22, 18],
            past_failures: 0,
            issuer_avg_response_days: 2.0,
        };

        let result = predictor.predict(&cert, Some(&history)).unwrap();
        // Average renewal day is 20, we're at 15 which is < 20, so activity should be detected
        assert!(
            result.prediction.renewal_activity_detected,
            "Should detect renewal activity when past typical renewal window"
        );
    }

    #[test]
    fn test_high_severity_under_14_days_with_renewal_activity() {
        let now = Utc::now();
        let predictor = RenewalPredictor::with_now(now);
        let cert = make_cert(now + Duration::days(10));

        let history = RenewalHistory {
            previous_renewal_days: vec![20, 22, 18],
            past_failures: 0,
            issuer_avg_response_days: 2.0,
        };

        let result = predictor.predict(&cert, Some(&history)).unwrap();
        // Under 14 days but renewal activity detected → High (not Critical)
        assert_eq!(result.prediction.severity, Severity::High);
    }

    #[test]
    fn test_fingerprint_preserved_in_prediction() {
        let now = Utc::now();
        let predictor = RenewalPredictor::with_now(now);
        let cert = make_cert(now + Duration::days(20));

        let result = predictor.predict(&cert, None).unwrap();
        assert_eq!(result.prediction.cert_fingerprint, cert.fingerprint);
    }
}
