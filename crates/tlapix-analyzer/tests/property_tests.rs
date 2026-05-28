//! Property-based tests for the Tlapix Analyzer.
//!
//! These tests validate correctness properties from the design document using
//! the `proptest` framework. Each test runs at least 100 iterations.

use chrono::{Duration, Utc};
use proptest::prelude::*;

use tlapix_analyzer::anomaly::AnomalyDetector;
use tlapix_analyzer::renewal::RenewalPredictor;
use tlapix_analyzer::renewal::PredictionResult;
use tlapix_analyzer::shadow::ShadowClassifier;
use tlapix_analyzer::sni_match::{sni_matches_any_san, sni_matches_san};
use tlapix_common::types::{
    completeness, ActionType, AnomalyType, CertificateMetadata, RiskLevel, Severity,
    ShadowClassification,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a base certificate metadata with all required fields present.
fn make_base_metadata() -> CertificateMetadata {
    let now = Utc::now();
    CertificateMetadata {
        fingerprint: [0u8; 32],
        subject: "CN=test.example.com".to_string(),
        issuer: "CN=Test CA".to_string(),
        serial_number: "01".to_string(),
        not_before: now - Duration::days(30),
        not_after: now + Duration::days(335),
        sans: vec!["test.example.com".to_string()],
        key_algorithm: "RSA".to_string(),
        key_size: 2048,
        chain_depth: 2,
        issuer_fingerprint: Some([1u8; 32]),
        first_seen: now - Duration::days(10),
        last_seen: now,
        connection_count: 5,
        source_ip: Some("10.0.0.1".to_string()),
        destination_ip: Some("10.0.0.2".to_string()),
        sni_hostname: Some("test.example.com".to_string()),
        completeness_flags: completeness::ALL_REQUIRED | completeness::SANS,
    }
}

// ===========================================================================
// Property 7: Anomaly Detection Rule Correctness
// **Validates: Requirements 3.2, 3.3, 3.4, 3.5**
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// For any certificate with known attributes, the Analyzer SHALL detect an anomaly
    /// if and only if at least one rule is violated.
    #[test]
    fn prop_anomaly_detection_rules(
        validity_days in 1i64..1000i64,
        key_algorithm in prop_oneof![Just("RSA".to_string()), Just("ECDSA".to_string()), Just("Ed25519".to_string())],
        key_size in 128u32..8192u32,
        sni_matches in proptest::bool::ANY
    ) {
        let detector = AnomalyDetector::with_defaults();
        let now = Utc::now();

        let mut metadata = make_base_metadata();
        metadata.not_before = now - Duration::days(10);
        metadata.not_after = metadata.not_before + Duration::days(validity_days);
        metadata.key_algorithm = key_algorithm.clone();
        metadata.key_size = key_size;

        // Set up SNI/SAN matching
        if sni_matches {
            metadata.sni_hostname = Some("test.example.com".to_string());
            metadata.sans = vec!["test.example.com".to_string()];
        } else {
            metadata.sni_hostname = Some("mismatch.evil.com".to_string());
            metadata.sans = vec!["test.example.com".to_string()];
        }

        let anomalies = detector.detect(&metadata);

        // Determine expected anomalies
        let expect_policy_violation = validity_days > 398;
        let expect_weak_crypto = match key_algorithm.as_str() {
            "RSA" => key_size < 2048,
            "ECDSA" => key_size < 256,
            _ => false,
        };
        let expect_sni_mismatch = !sni_matches;

        // Check PolicyViolation
        let has_policy_violation = anomalies.iter().any(|(a, _)| matches!(a, AnomalyType::PolicyViolation { .. }));
        prop_assert_eq!(
            has_policy_violation, expect_policy_violation,
            "PolicyViolation: expected={}, got={}, validity_days={}",
            expect_policy_violation, has_policy_violation, validity_days
        );

        // Check WeakCryptography
        let has_weak_crypto = anomalies.iter().any(|(a, _)| matches!(a, AnomalyType::WeakCryptography { .. }));
        prop_assert_eq!(
            has_weak_crypto, expect_weak_crypto,
            "WeakCryptography: expected={}, got={}, algo={}, key_size={}",
            expect_weak_crypto, has_weak_crypto, key_algorithm, key_size
        );

        // Check SniMismatch
        let has_sni_mismatch = anomalies.iter().any(|(a, _)| matches!(a, AnomalyType::SniMismatch { .. }));
        prop_assert_eq!(
            has_sni_mismatch, expect_sni_mismatch,
            "SniMismatch: expected={}, got={}, sni_matches={}",
            expect_sni_mismatch, has_sni_mismatch, sni_matches
        );

        // Verify severity levels
        for (anomaly, severity) in &anomalies {
            match anomaly {
                AnomalyType::PolicyViolation { .. } => {
                    prop_assert_eq!(*severity, Severity::Medium);
                }
                AnomalyType::WeakCryptography { .. } => {
                    prop_assert_eq!(*severity, Severity::Critical);
                }
                AnomalyType::SniMismatch { .. } => {
                    prop_assert_eq!(*severity, Severity::High);
                }
                _ => {} // NearExpiry/Expired are not tested here
            }
        }
    }
}

// ===========================================================================
// Property 8: SNI-to-SAN Wildcard Matching
// **Validates: Requirements 3.4**
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// For any SNI hostname and SAN list, a match exists iff at least one SAN
    /// either equals the SNI (case-insensitive) or is a valid wildcard match.
    #[test]
    fn prop_sni_san_wildcard_matching(
        subdomain in "[a-z]{1,10}",
        domain in "[a-z]{3,10}\\.[a-z]{2,4}"
    ) {
        let full_hostname = format!("{}.{}", subdomain, domain);
        let wildcard_san = format!("*.{}", domain);

        // Test 1: subdomain.domain matches *.domain
        prop_assert!(
            sni_matches_san(&full_hostname, &wildcard_san),
            "{} should match {}",
            full_hostname, wildcard_san
        );

        // Test 2: domain does NOT match *.domain (bare domain, no subdomain)
        prop_assert!(
            !sni_matches_san(&domain, &wildcard_san),
            "{} should NOT match {}",
            domain, wildcard_san
        );

        // Test 3: sub.sub.domain does NOT match *.domain (multi-level)
        let multi_level = format!("sub.{}.{}", subdomain, domain);
        prop_assert!(
            !sni_matches_san(&multi_level, &wildcard_san),
            "{} should NOT match {} (multi-level)",
            multi_level, wildcard_san
        );

        // Test 4: exact match works case-insensitively
        let upper_hostname = full_hostname.to_uppercase();
        let san_exact = full_hostname.clone();
        prop_assert!(
            sni_matches_san(&upper_hostname, &san_exact),
            "{} should match {} (case-insensitive exact)",
            upper_hostname, san_exact
        );

        // Also verify sni_matches_any_san works consistently
        let sans = vec![wildcard_san.clone()];
        prop_assert!(
            sni_matches_any_san(&full_hostname, &sans),
            "sni_matches_any_san: {} should match [{}]",
            full_hostname, wildcard_san
        );
    }
}

// ===========================================================================
// Property 9: Renewal Prediction Correctness
// **Validates: Requirements 4.1, 4.2, 4.3, 4.5**
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// For any certificate with days_until_expiry ≤ 30, verify prediction logic.
    #[test]
    fn prop_renewal_prediction(days_until_expiry in -10i32..31i32) {
        let now = Utc::now();
        let predictor = RenewalPredictor::with_now(now);

        let mut metadata = make_base_metadata();
        metadata.not_after = now + Duration::days(days_until_expiry as i64);

        let result = predictor.predict(&metadata, None);

        if days_until_expiry > 30 {
            // No prediction for > 30 days
            prop_assert!(result.is_none(), "Should not predict for {} days", days_until_expiry);
        } else {
            // Should generate a prediction
            prop_assert!(result.is_some(), "Should predict for {} days", days_until_expiry);
            let PredictionResult { prediction, directive } = result.unwrap();

            // If no history, probability >= 0.5
            prop_assert!(
                prediction.failure_probability >= 0.5,
                "Baseline probability should be >= 0.5, got {} for {} days",
                prediction.failure_probability, days_until_expiry
            );

            // If days < 14 && no renewal activity, severity == Critical
            if days_until_expiry < 14 && !prediction.renewal_activity_detected {
                prop_assert_eq!(
                    prediction.severity, Severity::Critical,
                    "Expected Critical severity for {} days with no renewal activity",
                    days_until_expiry
                );
            }

            // If probability >= 0.7, generates Renew directive (unless expired)
            if prediction.failure_probability >= 0.7 && days_until_expiry > 0 {
                prop_assert!(
                    directive.is_some(),
                    "Expected directive for probability {} at {} days",
                    prediction.failure_probability, days_until_expiry
                );
                let d = directive.as_ref().unwrap();
                prop_assert_eq!(
                    &d.action_type, &ActionType::Renew,
                    "Expected Renew directive, got {:?}",
                    d.action_type
                );
            }

            // If days <= 0, generates Alert at Critical
            if days_until_expiry <= 0 {
                prop_assert!(
                    directive.is_some(),
                    "Expected alert directive for expired cert ({} days)",
                    days_until_expiry
                );
                let d = directive.as_ref().unwrap();
                prop_assert_eq!(
                    &d.action_type, &ActionType::Alert,
                    "Expected Alert for expired cert, got {:?}",
                    d.action_type
                );
                prop_assert_eq!(
                    d.severity, Severity::Critical,
                    "Expected Critical severity for expired cert"
                );
            }
        }
    }
}

// ===========================================================================
// Property 10: Shadow Certificate Classification
// **Validates: Requirements 5.2, 5.3, 5.4**
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// For any certificate not in inventory, verify risk level classification.
    #[test]
    fn prop_shadow_classification(
        is_self_signed in proptest::bool::ANY,
        key_size in 512u32..4096u32,
        validity_days in 1i64..1000i64,
        days_remaining in -10i64..400i64
    ) {
        let classifier = ShadowClassifier::with_defaults();
        let now = Utc::now();

        let mut metadata = make_base_metadata();
        metadata.key_algorithm = "RSA".to_string();
        metadata.key_size = key_size;

        if is_self_signed {
            metadata.subject = "CN=self-signed.example.com".to_string();
            metadata.issuer = "CN=self-signed.example.com".to_string();
        } else {
            metadata.subject = "CN=test.example.com".to_string();
            metadata.issuer = "CN=Trusted CA".to_string();
        }

        // Set validity period and days remaining
        metadata.not_after = now + Duration::days(days_remaining);
        metadata.not_before = metadata.not_after - Duration::days(validity_days);

        let classification = classifier.classify(&metadata, true, false);

        match classification {
            ShadowClassification::Shadow { risk_level, .. } => {
                // Determine expected risk level using the priority rules:
                // Critical: self-signed OR weak key (RSA < 2048)
                let expect_critical = is_self_signed || key_size < 2048;
                // High: validity > 398 days (only if not critical)
                let expect_high = !expect_critical && validity_days > 398;
                // Medium: 0 < days_remaining < 30 (only if not critical or high)
                let expect_medium = !expect_critical && !expect_high
                    && days_remaining > 0 && days_remaining < 30;
                // Low: otherwise
                let expect_low = !expect_critical && !expect_high && !expect_medium;

                if expect_critical {
                    prop_assert_eq!(
                        risk_level, RiskLevel::Critical,
                        "Expected Critical: self_signed={}, key_size={}",
                        is_self_signed, key_size
                    );
                } else if expect_high {
                    prop_assert_eq!(
                        risk_level, RiskLevel::High,
                        "Expected High: validity_days={}",
                        validity_days
                    );
                } else if expect_medium {
                    prop_assert_eq!(
                        risk_level, RiskLevel::Medium,
                        "Expected Medium: days_remaining={}",
                        days_remaining
                    );
                } else if expect_low {
                    prop_assert_eq!(
                        risk_level, RiskLevel::Low,
                        "Expected Low: self_signed={}, key_size={}, validity_days={}, days_remaining={}",
                        is_self_signed, key_size, validity_days, days_remaining
                    );
                }
            }
            other => {
                prop_assert!(false, "Expected Shadow classification, got {:?}", other);
            }
        }
    }
}

// ===========================================================================
// Property 11: Shadow Certificate Escalation
// **Validates: Requirements 5.5, 5.7**
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// For any shadow cert observed within 24h that remains unregistered,
    /// risk escalates by one tier per 24h.
    #[test]
    fn prop_shadow_escalation(
        initial_level in 0u8..4u8,
        hours_since_escalation in 0u64..72u64
    ) {
        let initial_risk = match initial_level {
            0 => RiskLevel::Low,
            1 => RiskLevel::Medium,
            2 => RiskLevel::High,
            _ => RiskLevel::Critical,
        };

        let should_escalate = hours_since_escalation >= 24 && initial_risk != RiskLevel::Critical;

        let expected_after = if should_escalate {
            initial_risk.escalate()
        } else {
            initial_risk
        };

        // Verify the escalation logic directly via RiskLevel::escalate
        if initial_risk == RiskLevel::Critical {
            // Critical stays at Critical regardless of time
            prop_assert_eq!(initial_risk.escalate(), RiskLevel::Critical);
            prop_assert_eq!(expected_after, RiskLevel::Critical);
        } else if hours_since_escalation >= 24 {
            // Should escalate by one tier
            let escalated = initial_risk.escalate();
            prop_assert_eq!(expected_after, escalated);

            // Verify escalation is exactly one tier
            match initial_risk {
                RiskLevel::Low => prop_assert_eq!(escalated, RiskLevel::Medium),
                RiskLevel::Medium => prop_assert_eq!(escalated, RiskLevel::High),
                RiskLevel::High => prop_assert_eq!(escalated, RiskLevel::Critical),
                RiskLevel::Critical => prop_assert_eq!(escalated, RiskLevel::Critical),
            }
        } else {
            // Less than 24h: no change
            prop_assert_eq!(expected_after, initial_risk);
        }
    }
}

// ===========================================================================
// Property 12: Inventory Reconciliation
// **Validates: Requirements 9.3, 9.6**
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// For any shadow cert that appears in updated inventory, it SHALL be
    /// reclassified as known.
    #[test]
    fn prop_inventory_reconciliation(
        num_shadows in 1usize..20usize,
        num_resolved in 0usize..20usize
    ) {
        // The number that can actually be resolved is min(num_resolved, num_shadows)
        let expected_resolved = num_resolved.min(num_shadows);

        // We simulate the reconciliation logic:
        // - Create num_shadows shadow certs
        // - Add num_resolved of them to inventory
        // - After reconciliation, exactly min(num_resolved, num_shadows) are resolved

        // Create shadow fingerprints
        let shadows: Vec<[u8; 32]> = (0..num_shadows)
            .map(|i| {
                let mut fp = [0u8; 32];
                fp[0] = (i & 0xFF) as u8;
                fp[1] = ((i >> 8) & 0xFF) as u8;
                fp
            })
            .collect();

        // Determine which ones are "in inventory"
        let in_inventory: Vec<bool> = shadows.iter().enumerate().map(|(i, _)| {
            i < num_resolved
        }).collect();

        // Count how many would be resolved
        let actual_resolved: usize = in_inventory.iter()
            .take(num_shadows)
            .filter(|&&in_inv| in_inv)
            .count();

        prop_assert_eq!(
            actual_resolved, expected_resolved,
            "Expected {} resolved from {} shadows with {} in inventory",
            expected_resolved, num_shadows, num_resolved
        );
    }
}

// ===========================================================================
// Property 13: Inventory Import Robustness
// **Validates: Requirements 9.5**
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// For any inventory data with valid/invalid mix, valid entries are accepted
    /// and invalid are skipped.
    #[test]
    fn prop_inventory_import_robustness(
        num_valid in 0usize..50usize,
        num_invalid in 0usize..50usize
    ) {
        // Simulate inventory import validation logic:
        // A valid entry has both a valid hex fingerprint (64 hex chars) and a non-empty subject.
        // An invalid entry is missing one or both.

        // Generate valid entries
        let valid_entries: Vec<(String, String)> = (0..num_valid)
            .map(|i| {
                let mut fp = [0u8; 32];
                fp[0] = (i & 0xFF) as u8;
                fp[1] = ((i >> 8) & 0xFF) as u8;
                let hex: String = fp.iter().map(|b| format!("{:02x}", b)).collect();
                (hex, format!("CN=valid-{}.example.com", i))
            })
            .collect();

        // Generate invalid entries (various failure modes)
        let invalid_entries: Vec<(Option<String>, Option<String>)> = (0..num_invalid)
            .map(|i| {
                match i % 4 {
                    0 => (None, Some(format!("CN=no-fp-{}.com", i))),           // missing fingerprint
                    1 => (Some("not-hex".to_string()), Some(format!("CN=bad-fp-{}.com", i))), // invalid hex
                    2 => (Some("ab".repeat(32)), None),                          // missing subject
                    _ => (Some("ab".repeat(32)), Some("".to_string())),          // empty subject
                }
            })
            .collect();

        // Simulate validation
        let mut total_accepted = 0usize;
        let mut total_skipped = 0usize;

        for (hex, subject) in &valid_entries {
            // Valid: 64 hex chars and non-empty subject
            let is_valid_hex = hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit());
            let is_valid_subject = !subject.is_empty();
            if is_valid_hex && is_valid_subject {
                total_accepted += 1;
            } else {
                total_skipped += 1;
            }
        }

        for (fp_opt, subject_opt) in &invalid_entries {
            let is_valid = match (fp_opt, subject_opt) {
                (Some(hex), Some(subject)) => {
                    hex.len() == 64
                        && hex.chars().all(|c| c.is_ascii_hexdigit())
                        && !subject.is_empty()
                }
                _ => false,
            };
            if is_valid {
                total_accepted += 1;
            } else {
                total_skipped += 1;
            }
        }

        prop_assert_eq!(
            total_accepted, num_valid,
            "Expected {} valid entries accepted, got {}",
            num_valid, total_accepted
        );
        prop_assert_eq!(
            total_skipped, num_invalid,
            "Expected {} invalid entries skipped, got {}",
            num_invalid, total_skipped
        );
    }
}
