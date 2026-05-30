//! Rule-based anomaly detection for TLS certificates.
//!
//! Evaluates `CertificateMetadata` against known anomaly patterns and generates
//! `ActionDirective` entries for each detected anomaly.

use chrono::Utc;
use uuid::Uuid;

use tlapix_common::types::{
    completeness, ActionDirective, ActionType, AnomalyType, CertificateMetadata, Severity,
};

use crate::sni_match::sni_matches_any_san;

/// Configuration for the anomaly detector.
#[derive(Debug, Clone)]
pub struct AnomalyDetectorConfig {
    /// Number of days before expiry to trigger a near-expiry warning.
    pub near_expiry_threshold_days: i64,
    /// Maximum allowed validity period in days before triggering a policy violation.
    pub max_validity_days: i64,
    /// Minimum RSA key size in bits.
    pub min_rsa_key_size: u32,
    /// Minimum ECDSA key size in bits.
    pub min_ecdsa_key_size: u32,
}

impl Default for AnomalyDetectorConfig {
    fn default() -> Self {
        Self {
            near_expiry_threshold_days: 30,
            max_validity_days: 398,
            min_rsa_key_size: 2048,
            min_ecdsa_key_size: 256,
        }
    }
}

/// Rule-based anomaly detector that evaluates certificates against known patterns.
#[derive(Debug, Clone)]
pub struct AnomalyDetector {
    config: AnomalyDetectorConfig,
}

impl AnomalyDetector {
    /// Create a new anomaly detector with the given configuration.
    pub fn new(config: AnomalyDetectorConfig) -> Self {
        Self { config }
    }

    /// Create a new anomaly detector with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(AnomalyDetectorConfig::default())
    }

    /// Evaluate a certificate against all anomaly rules.
    ///
    /// Returns a list of `(AnomalyType, Severity)` pairs for each detected anomaly.
    /// Only evaluates rules for which the required fields are present
    /// (as indicated by `completeness_flags`).
    pub fn detect(&self, metadata: &CertificateMetadata) -> Vec<(AnomalyType, Severity)> {
        let mut anomalies = Vec::new();

        self.check_policy_violation(metadata, &mut anomalies);
        self.check_weak_cryptography(metadata, &mut anomalies);
        self.check_sni_mismatch(metadata, &mut anomalies);
        self.check_expired(metadata, &mut anomalies);
        self.check_near_expiry(metadata, &mut anomalies);

        anomalies
    }

    /// Generate `ActionDirective` entries for all detected anomalies.
    pub fn generate_directives(&self, metadata: &CertificateMetadata) -> Vec<ActionDirective> {
        let anomalies = self.detect(metadata);
        let now = Utc::now();

        anomalies
            .into_iter()
            .map(|(anomaly_type, severity)| {
                let reasoning = self.build_reasoning(&anomaly_type);
                ActionDirective {
                    id: Uuid::new_v4(),
                    correlation_id: Uuid::new_v4(),
                    cert_fingerprint: metadata.fingerprint,
                    action_type: ActionType::Alert,
                    severity,
                    reasoning,
                    created_at: now,
                    source_anomaly: Some(anomaly_type),
                    attempt_count: 0,
                }
            })
            .collect()
    }

    /// Check if the certificate validity period exceeds the maximum allowed.
    /// Requires: NOT_BEFORE and NOT_AFTER fields.
    fn check_policy_violation(
        &self,
        metadata: &CertificateMetadata,
        anomalies: &mut Vec<(AnomalyType, Severity)>,
    ) {
        let required = completeness::NOT_BEFORE | completeness::NOT_AFTER;
        if metadata.completeness_flags & required != required {
            return;
        }

        let validity_duration = metadata.not_after - metadata.not_before;
        if validity_duration.num_days() > self.config.max_validity_days {
            anomalies.push((
                AnomalyType::PolicyViolation {
                    reason: format!(
                        "Validity period of {} days exceeds maximum of {} days",
                        validity_duration.num_days(),
                        self.config.max_validity_days
                    ),
                },
                Severity::Medium,
            ));
        }
    }

    /// Check if the certificate uses weak cryptographic parameters.
    /// Requires: KEY_ALGORITHM and KEY_SIZE fields.
    fn check_weak_cryptography(
        &self,
        metadata: &CertificateMetadata,
        anomalies: &mut Vec<(AnomalyType, Severity)>,
    ) {
        let required = completeness::KEY_ALGORITHM | completeness::KEY_SIZE;
        if metadata.completeness_flags & required != required {
            return;
        }

        let is_weak = match metadata.key_algorithm.to_uppercase().as_str() {
            "RSA" => metadata.key_size < self.config.min_rsa_key_size,
            "ECDSA" | "EC" => metadata.key_size < self.config.min_ecdsa_key_size,
            _ => false,
        };

        if is_weak {
            anomalies.push((
                AnomalyType::WeakCryptography {
                    algorithm: metadata.key_algorithm.clone(),
                    key_size: metadata.key_size,
                },
                Severity::Critical,
            ));
        }
    }

    /// Check if the SNI hostname does not match any SAN in the certificate.
    /// Requires: SANS field and a non-empty sni_hostname.
    fn check_sni_mismatch(
        &self,
        metadata: &CertificateMetadata,
        anomalies: &mut Vec<(AnomalyType, Severity)>,
    ) {
        // Need SANs field present
        if metadata.completeness_flags & completeness::SANS == 0 {
            return;
        }

        // Only check if SNI is present and SANs are non-empty
        let sni = match &metadata.sni_hostname {
            Some(sni) if !sni.is_empty() => sni,
            _ => return,
        };

        if metadata.sans.is_empty() {
            return;
        }

        let matches = sni_matches_any_san(sni, &metadata.sans);

        if !matches {
            anomalies.push((
                AnomalyType::SniMismatch {
                    sni: sni.clone(),
                    sans: metadata.sans.clone(),
                },
                Severity::High,
            ));
        }
    }

    /// Check if the certificate has expired.
    /// Requires: NOT_AFTER field.
    fn check_expired(
        &self,
        metadata: &CertificateMetadata,
        anomalies: &mut Vec<(AnomalyType, Severity)>,
    ) {
        if metadata.completeness_flags & completeness::NOT_AFTER == 0 {
            return;
        }

        let now = Utc::now();
        if metadata.not_after < now {
            anomalies.push((AnomalyType::ExpiredCertificate, Severity::Critical));
        }
    }

    /// Check if the certificate is near expiry.
    /// Requires: NOT_AFTER field.
    /// Only triggers if the certificate is NOT already expired.
    fn check_near_expiry(
        &self,
        metadata: &CertificateMetadata,
        anomalies: &mut Vec<(AnomalyType, Severity)>,
    ) {
        if metadata.completeness_flags & completeness::NOT_AFTER == 0 {
            return;
        }

        let now = Utc::now();
        // Don't flag near-expiry if already expired
        if metadata.not_after <= now {
            return;
        }

        let days_remaining = (metadata.not_after - now).num_days();
        if days_remaining < self.config.near_expiry_threshold_days {
            anomalies.push((
                AnomalyType::NearExpiry {
                    days_remaining: days_remaining as u32,
                },
                Severity::High,
            ));
        }
    }

    /// Build a human-readable reasoning string for an anomaly (max 500 chars).
    fn build_reasoning(&self, anomaly: &AnomalyType) -> String {
        let reasoning = match anomaly {
            AnomalyType::PolicyViolation { reason } => {
                format!("Policy violation: {}", reason)
            }
            AnomalyType::WeakCryptography {
                algorithm,
                key_size,
            } => {
                format!(
                    "Weak cryptography: {} with {} bits is below minimum requirements",
                    algorithm, key_size
                )
            }
            AnomalyType::SniMismatch { sni, sans } => {
                let san_list: String = sans.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
                format!(
                    "SNI mismatch: hostname '{}' does not match any SAN [{}]",
                    sni, san_list
                )
            }
            AnomalyType::ExpiredCertificate => "Certificate has expired".to_string(),
            AnomalyType::NearExpiry { days_remaining } => {
                format!(
                    "Certificate expires in {} days (threshold: {} days)",
                    days_remaining, self.config.near_expiry_threshold_days
                )
            }
        };
        // Truncate to 500 characters
        if reasoning.len() > 500 {
            format!("{}...", &reasoning[..497])
        } else {
            reasoning
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use tlapix_common::types::completeness;

    /// Helper to create a valid certificate metadata with all fields present.
    fn make_metadata() -> CertificateMetadata {
        let now = Utc::now();
        CertificateMetadata {
            fingerprint: [0u8; 32],
            subject: "CN=example.com".to_string(),
            issuer: "CN=Test CA".to_string(),
            serial_number: "01".to_string(),
            not_before: now - Duration::days(30),
            not_after: now + Duration::days(335),
            sans: vec!["example.com".to_string(), "*.example.com".to_string()],
            key_algorithm: "RSA".to_string(),
            key_size: 2048,
            chain_depth: 2,
            issuer_fingerprint: Some([1u8; 32]),
            first_seen: now - Duration::days(30),
            last_seen: now,
            connection_count: 10,
            source_ip: Some("10.0.0.1".to_string()),
            destination_ip: Some("10.0.0.2".to_string()),
            sni_hostname: Some("example.com".to_string()),
            completeness_flags: completeness::ALL_REQUIRED | completeness::SANS,
        }
    }

    #[test]
    fn test_no_anomalies_for_valid_cert() {
        let detector = AnomalyDetector::with_defaults();
        let metadata = make_metadata();
        let anomalies = detector.detect(&metadata);
        assert!(
            anomalies.is_empty(),
            "Expected no anomalies, got: {:?}",
            anomalies
        );
    }

    #[test]
    fn test_policy_violation_long_validity() {
        let detector = AnomalyDetector::with_defaults();
        let mut metadata = make_metadata();
        // Set validity to 400 days (exceeds 398)
        metadata.not_before = Utc::now() - Duration::days(10);
        metadata.not_after = metadata.not_before + Duration::days(400);

        let anomalies = detector.detect(&metadata);
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(
            anomalies[0].0,
            AnomalyType::PolicyViolation { .. }
        ));
        assert_eq!(anomalies[0].1, Severity::Medium);
    }

    #[test]
    fn test_policy_violation_exactly_398_days_no_anomaly() {
        let detector = AnomalyDetector::with_defaults();
        let mut metadata = make_metadata();
        metadata.not_before = Utc::now() - Duration::days(10);
        metadata.not_after = metadata.not_before + Duration::days(398);

        let anomalies = detector.detect(&metadata);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_weak_rsa_key() {
        let detector = AnomalyDetector::with_defaults();
        let mut metadata = make_metadata();
        metadata.key_algorithm = "RSA".to_string();
        metadata.key_size = 1024;

        let anomalies = detector.detect(&metadata);
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(
            anomalies[0].0,
            AnomalyType::WeakCryptography { ref algorithm, key_size }
            if algorithm == "RSA" && key_size == 1024
        ));
        assert_eq!(anomalies[0].1, Severity::Critical);
    }

    #[test]
    fn test_weak_ecdsa_key() {
        let detector = AnomalyDetector::with_defaults();
        let mut metadata = make_metadata();
        metadata.key_algorithm = "ECDSA".to_string();
        metadata.key_size = 128;

        let anomalies = detector.detect(&metadata);
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(
            anomalies[0].0,
            AnomalyType::WeakCryptography { ref algorithm, key_size }
            if algorithm == "ECDSA" && key_size == 128
        ));
        assert_eq!(anomalies[0].1, Severity::Critical);
    }

    #[test]
    fn test_ecdsa_256_no_anomaly() {
        let detector = AnomalyDetector::with_defaults();
        let mut metadata = make_metadata();
        metadata.key_algorithm = "ECDSA".to_string();
        metadata.key_size = 256;

        let anomalies = detector.detect(&metadata);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_rsa_2048_no_anomaly() {
        let detector = AnomalyDetector::with_defaults();
        let mut metadata = make_metadata();
        metadata.key_algorithm = "RSA".to_string();
        metadata.key_size = 2048;

        let anomalies = detector.detect(&metadata);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_sni_mismatch() {
        let detector = AnomalyDetector::with_defaults();
        let mut metadata = make_metadata();
        metadata.sni_hostname = Some("evil.com".to_string());
        metadata.sans = vec!["example.com".to_string(), "*.example.com".to_string()];

        let anomalies = detector.detect(&metadata);
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(anomalies[0].0, AnomalyType::SniMismatch { .. }));
        assert_eq!(anomalies[0].1, Severity::High);
    }

    #[test]
    fn test_sni_exact_match_no_anomaly() {
        let detector = AnomalyDetector::with_defaults();
        let mut metadata = make_metadata();
        metadata.sni_hostname = Some("example.com".to_string());
        metadata.sans = vec!["example.com".to_string()];

        let anomalies = detector.detect(&metadata);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_sni_wildcard_match_no_anomaly() {
        let detector = AnomalyDetector::with_defaults();
        let mut metadata = make_metadata();
        metadata.sni_hostname = Some("sub.example.com".to_string());
        metadata.sans = vec!["*.example.com".to_string()];

        let anomalies = detector.detect(&metadata);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_sni_wildcard_no_multi_level() {
        let detector = AnomalyDetector::with_defaults();
        let mut metadata = make_metadata();
        metadata.sni_hostname = Some("a.b.example.com".to_string());
        metadata.sans = vec!["*.example.com".to_string()];

        let anomalies = detector.detect(&metadata);
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(anomalies[0].0, AnomalyType::SniMismatch { .. }));
    }

    #[test]
    fn test_sni_case_insensitive_match() {
        let detector = AnomalyDetector::with_defaults();
        let mut metadata = make_metadata();
        metadata.sni_hostname = Some("EXAMPLE.COM".to_string());
        metadata.sans = vec!["example.com".to_string()];

        let anomalies = detector.detect(&metadata);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_expired_certificate() {
        let detector = AnomalyDetector::with_defaults();
        let mut metadata = make_metadata();
        metadata.not_after = Utc::now() - Duration::days(1);

        let anomalies = detector.detect(&metadata);
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(anomalies[0].0, AnomalyType::ExpiredCertificate));
        assert_eq!(anomalies[0].1, Severity::Critical);
    }

    #[test]
    fn test_near_expiry() {
        let detector = AnomalyDetector::with_defaults();
        let mut metadata = make_metadata();
        metadata.not_before = Utc::now() - Duration::days(360);
        metadata.not_after = Utc::now() + Duration::days(10);

        let anomalies = detector.detect(&metadata);
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(
            anomalies[0].0,
            AnomalyType::NearExpiry { days_remaining } if days_remaining <= 10
        ));
        assert_eq!(anomalies[0].1, Severity::High);
    }

    #[test]
    fn test_near_expiry_not_triggered_when_expired() {
        let detector = AnomalyDetector::with_defaults();
        let mut metadata = make_metadata();
        metadata.not_after = Utc::now() - Duration::hours(1);

        let anomalies = detector.detect(&metadata);
        // Should only get ExpiredCertificate, not NearExpiry
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(anomalies[0].0, AnomalyType::ExpiredCertificate));
    }

    #[test]
    fn test_multiple_anomalies() {
        let detector = AnomalyDetector::with_defaults();
        let mut metadata = make_metadata();
        // Weak key + long validity + SNI mismatch
        metadata.key_algorithm = "RSA".to_string();
        metadata.key_size = 1024;
        metadata.not_before = Utc::now() - Duration::days(10);
        metadata.not_after = metadata.not_before + Duration::days(500);
        metadata.sni_hostname = Some("evil.com".to_string());

        let anomalies = detector.detect(&metadata);
        assert_eq!(anomalies.len(), 3);
    }

    #[test]
    fn test_partial_metadata_skips_missing_fields() {
        let detector = AnomalyDetector::with_defaults();
        let mut metadata = make_metadata();
        // Only subject and issuer present — no validity, no key info, no SANs
        metadata.completeness_flags = completeness::SUBJECT | completeness::ISSUER;
        // Even with bad values, rules should be skipped
        metadata.key_size = 512;
        metadata.not_after = Utc::now() - Duration::days(100);

        let anomalies = detector.detect(&metadata);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_partial_metadata_evaluates_available_fields() {
        let detector = AnomalyDetector::with_defaults();
        let mut metadata = make_metadata();
        // Only key fields present
        metadata.completeness_flags = completeness::KEY_ALGORITHM | completeness::KEY_SIZE;
        metadata.key_algorithm = "RSA".to_string();
        metadata.key_size = 1024;

        let anomalies = detector.detect(&metadata);
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(
            anomalies[0].0,
            AnomalyType::WeakCryptography { .. }
        ));
    }

    #[test]
    fn test_generate_directives() {
        let detector = AnomalyDetector::with_defaults();
        let mut metadata = make_metadata();
        metadata.key_size = 1024; // Weak key

        let directives = detector.generate_directives(&metadata);
        assert_eq!(directives.len(), 1);

        let d = &directives[0];
        assert_eq!(d.cert_fingerprint, metadata.fingerprint);
        assert_eq!(d.action_type, ActionType::Alert);
        assert_eq!(d.severity, Severity::Critical);
        assert_eq!(d.attempt_count, 0);
        assert!(d.source_anomaly.is_some());
        assert!(d.reasoning.len() <= 500);
    }

    #[test]
    fn test_generate_directives_one_per_anomaly() {
        let detector = AnomalyDetector::with_defaults();
        let mut metadata = make_metadata();
        // Two anomalies: weak key + expired
        metadata.key_size = 1024;
        metadata.not_after = Utc::now() - Duration::days(5);

        let directives = detector.generate_directives(&metadata);
        assert_eq!(directives.len(), 2);
        // Each directive should have a unique ID
        assert_ne!(directives[0].id, directives[1].id);
    }

    #[test]
    fn test_sni_no_check_when_sni_absent() {
        let detector = AnomalyDetector::with_defaults();
        let mut metadata = make_metadata();
        metadata.sni_hostname = None;
        metadata.sans = vec!["example.com".to_string()];

        let anomalies = detector.detect(&metadata);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_sni_no_check_when_sans_empty() {
        let detector = AnomalyDetector::with_defaults();
        let mut metadata = make_metadata();
        metadata.sni_hostname = Some("example.com".to_string());
        metadata.sans = vec![];

        let anomalies = detector.detect(&metadata);
        assert!(anomalies.is_empty());
    }

    // --- SNI matching integration tests (using sni_match module) ---

    #[test]
    fn test_sni_matches_san_exact() {
        use crate::sni_match::sni_matches_san;
        assert!(sni_matches_san("example.com", "example.com"));
        assert!(sni_matches_san("Example.COM", "example.com"));
    }

    #[test]
    fn test_sni_matches_san_wildcard() {
        use crate::sni_match::sni_matches_san;
        assert!(sni_matches_san("foo.example.com", "*.example.com"));
        assert!(sni_matches_san("bar.example.com", "*.example.com"));
    }

    #[test]
    fn test_sni_no_match_wildcard_multi_level() {
        use crate::sni_match::sni_matches_san;
        assert!(!sni_matches_san("a.b.example.com", "*.example.com"));
    }

    #[test]
    fn test_sni_no_match_wildcard_base_domain() {
        use crate::sni_match::sni_matches_san;
        // "*.example.com" should NOT match "example.com" itself
        assert!(!sni_matches_san("example.com", "*.example.com"));
    }

    #[test]
    fn test_sni_no_match_different_domain() {
        use crate::sni_match::sni_matches_san;
        assert!(!sni_matches_san("evil.com", "example.com"));
        assert!(!sni_matches_san("evil.com", "*.example.com"));
    }

    #[test]
    fn test_configurable_near_expiry_threshold() {
        let config = AnomalyDetectorConfig {
            near_expiry_threshold_days: 7,
            ..Default::default()
        };
        let detector = AnomalyDetector::new(config);
        let mut metadata = make_metadata();
        // 10 days remaining — should NOT trigger with 7-day threshold
        metadata.not_before = Utc::now() - Duration::days(360);
        metadata.not_after = Utc::now() + Duration::days(10);

        let anomalies = detector.detect(&metadata);
        assert!(anomalies.is_empty());

        // 5 days remaining — should trigger
        metadata.not_after = Utc::now() + Duration::days(5);
        let anomalies = detector.detect(&metadata);
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(anomalies[0].0, AnomalyType::NearExpiry { .. }));
    }
}
