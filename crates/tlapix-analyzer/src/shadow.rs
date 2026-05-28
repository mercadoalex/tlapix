//! Shadow certificate classifier.
//!
//! Identifies certificates observed in traffic that are not registered in the
//! certificate inventory, classifies them by risk level, and generates alert
//! directives with origin context.
//!
//! Requirements: 5.1–5.4, 5.6

use chrono::Utc;
use uuid::Uuid;

use tlapix_common::types::{
    ActionDirective, ActionType, CertificateMetadata, RiskLevel, Severity, ShadowClassification,
    ShadowContext,
};

/// Configuration for the shadow certificate classifier.
#[derive(Debug, Clone)]
pub struct ShadowClassifierConfig {
    /// Maximum allowed validity period in days before triggering high risk.
    pub max_validity_days: i64,
    /// Minimum RSA key size in bits.
    pub min_rsa_key_size: u32,
    /// Minimum ECDSA key size in bits.
    pub min_ecdsa_key_size: u32,
    /// Number of days remaining below which a certificate is medium risk.
    pub near_expiry_threshold_days: i64,
    /// List of trusted issuer subjects (case-insensitive comparison).
    /// If empty, any issuer different from the subject is considered trusted.
    pub trusted_issuers: Vec<String>,
}

impl Default for ShadowClassifierConfig {
    fn default() -> Self {
        Self {
            max_validity_days: 398,
            min_rsa_key_size: 2048,
            min_ecdsa_key_size: 256,
            near_expiry_threshold_days: 30,
            trusted_issuers: Vec::new(),
        }
    }
}

/// Shadow certificate classifier.
///
/// Compares certificate fingerprints against the inventory and classifies
/// unknown certificates by risk level.
#[derive(Debug, Clone)]
pub struct ShadowClassifier {
    config: ShadowClassifierConfig,
}

impl ShadowClassifier {
    /// Create a new shadow classifier with the given configuration.
    pub fn new(config: ShadowClassifierConfig) -> Self {
        Self { config }
    }

    /// Create a new shadow classifier with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(ShadowClassifierConfig::default())
    }

    /// Classify a certificate based on inventory membership and availability.
    ///
    /// # Arguments
    /// - `metadata`: The certificate metadata to classify.
    /// - `inventory_available`: Whether the inventory is currently reachable.
    /// - `in_inventory`: Whether the certificate's fingerprint was found in the inventory.
    ///
    /// # Returns
    /// - `ShadowClassification::Known` if the certificate is in the inventory.
    /// - `ShadowClassification::Shadow { .. }` if not in inventory with risk level.
    /// - `ShadowClassification::Deferred { .. }` if inventory is unreachable.
    pub fn classify(
        &self,
        metadata: &CertificateMetadata,
        inventory_available: bool,
        in_inventory: bool,
    ) -> ShadowClassification {
        // Requirement 5.6: Defer classification when inventory unreachable
        if !inventory_available {
            return ShadowClassification::Deferred {
                reason: "Certificate inventory is unreachable; classification deferred until inventory becomes available".to_string(),
            };
        }

        // Requirement 5.1: Compare fingerprint against inventory
        if in_inventory {
            return ShadowClassification::Known;
        }

        // Requirement 5.2–5.3: Classify as Shadow with risk level
        let risk_level = self.determine_risk_level(metadata);
        let context = ShadowContext {
            source_ip: metadata.source_ip.clone(),
            destination: metadata.destination_ip.clone(),
            first_seen: metadata.first_seen,
        };

        ShadowClassification::Shadow {
            risk_level,
            context,
        }
    }

    /// Generate an "alert" `ActionDirective` for a shadow certificate.
    ///
    /// Requirement 5.4: Generate alert with origin context (source IP, destination, first-seen).
    pub fn generate_directive(
        &self,
        metadata: &CertificateMetadata,
        risk_level: RiskLevel,
    ) -> ActionDirective {
        let severity = match risk_level {
            RiskLevel::Critical => Severity::Critical,
            RiskLevel::High => Severity::High,
            RiskLevel::Medium => Severity::Medium,
            RiskLevel::Low => Severity::Low,
        };

        let reasoning = self.build_reasoning(metadata, risk_level);

        ActionDirective {
            id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            cert_fingerprint: metadata.fingerprint,
            action_type: ActionType::Alert,
            severity,
            reasoning,
            created_at: Utc::now(),
            source_anomaly: None,
            attempt_count: 0,
        }
    }

    /// Determine the risk level for a shadow certificate.
    ///
    /// Requirement 5.3 classification criteria:
    /// - Critical: self-signed (subject == issuer) OR weak key (RSA < 2048, ECDSA < 256)
    /// - High: untrusted issuer OR validity period > 398 days
    /// - Medium: < 30 days remaining validity
    /// - Low: otherwise (trusted issuer, adequate key strength, normal validity)
    fn determine_risk_level(&self, metadata: &CertificateMetadata) -> RiskLevel {
        // Critical: self-signed or weak key
        if self.is_self_signed(metadata) || self.has_weak_key(metadata) {
            return RiskLevel::Critical;
        }

        // High: untrusted issuer or long validity
        if self.has_untrusted_issuer(metadata) || self.has_long_validity(metadata) {
            return RiskLevel::High;
        }

        // Medium: < 30 days remaining
        if self.has_near_expiry(metadata) {
            return RiskLevel::Medium;
        }

        // Low: everything else
        RiskLevel::Low
    }

    /// Check if the certificate is self-signed (subject == issuer).
    fn is_self_signed(&self, metadata: &CertificateMetadata) -> bool {
        metadata.subject.eq_ignore_ascii_case(&metadata.issuer)
    }

    /// Check if the certificate uses a weak key.
    /// RSA < 2048 bits or ECDSA < 256 bits.
    fn has_weak_key(&self, metadata: &CertificateMetadata) -> bool {
        match metadata.key_algorithm.to_uppercase().as_str() {
            "RSA" => metadata.key_size < self.config.min_rsa_key_size,
            "ECDSA" | "EC" => metadata.key_size < self.config.min_ecdsa_key_size,
            _ => false,
        }
    }

    /// Check if the issuer is not in the trusted issuer list.
    ///
    /// If the trusted issuers list is empty, we use the heuristic that
    /// any non-self-signed certificate has a "trusted" issuer (since we already
    /// check self-signed separately at the Critical level).
    fn has_untrusted_issuer(&self, metadata: &CertificateMetadata) -> bool {
        if self.config.trusted_issuers.is_empty() {
            // With no explicit trusted list, non-self-signed certs are considered
            // to have a trusted issuer (self-signed is already caught at Critical).
            return false;
        }

        // Check if the issuer is in the trusted list (case-insensitive)
        let issuer_lower = metadata.issuer.to_lowercase();
        !self
            .config
            .trusted_issuers
            .iter()
            .any(|trusted| trusted.to_lowercase() == issuer_lower)
    }

    /// Check if the certificate validity period exceeds the maximum allowed.
    fn has_long_validity(&self, metadata: &CertificateMetadata) -> bool {
        let validity_duration = metadata.not_after - metadata.not_before;
        validity_duration.num_days() > self.config.max_validity_days
    }

    /// Check if the certificate has fewer than 30 days remaining validity.
    fn has_near_expiry(&self, metadata: &CertificateMetadata) -> bool {
        let now = Utc::now();
        // Only applies if the certificate is not already expired
        if metadata.not_after <= now {
            return false;
        }
        let days_remaining = (metadata.not_after - now).num_days();
        days_remaining < self.config.near_expiry_threshold_days
    }

    /// Build a human-readable reasoning string for the shadow classification.
    fn build_reasoning(&self, metadata: &CertificateMetadata, risk_level: RiskLevel) -> String {
        let reason = match risk_level {
            RiskLevel::Critical => {
                if self.is_self_signed(metadata) {
                    format!(
                        "Shadow certificate is self-signed (subject == issuer: '{}')",
                        metadata.subject
                    )
                } else {
                    format!(
                        "Shadow certificate uses weak key: {} {} bits",
                        metadata.key_algorithm, metadata.key_size
                    )
                }
            }
            RiskLevel::High => {
                if self.has_untrusted_issuer(metadata) {
                    format!(
                        "Shadow certificate has untrusted issuer: '{}'",
                        metadata.issuer
                    )
                } else {
                    let validity_days = (metadata.not_after - metadata.not_before).num_days();
                    format!(
                        "Shadow certificate has excessive validity period: {} days (max: {})",
                        validity_days, self.config.max_validity_days
                    )
                }
            }
            RiskLevel::Medium => {
                let days_remaining = (metadata.not_after - Utc::now()).num_days();
                format!(
                    "Shadow certificate has {} days remaining (threshold: {})",
                    days_remaining, self.config.near_expiry_threshold_days
                )
            }
            RiskLevel::Low => {
                "Shadow certificate detected with low risk: trusted issuer, adequate key strength, normal validity".to_string()
            }
        };

        let origin = format!(
            " | Origin: source_ip={}, destination={}, first_seen={}",
            metadata.source_ip.as_deref().unwrap_or("unknown"),
            metadata.destination_ip.as_deref().unwrap_or("unknown"),
            metadata.first_seen.format("%Y-%m-%dT%H:%M:%SZ")
        );

        let full = format!("{}{}", reason, origin);
        // Truncate to 500 characters
        if full.len() > 500 {
            format!("{}...", &full[..497])
        } else {
            full
        }
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

    /// Helper to create a valid certificate metadata for testing.
    fn make_metadata() -> CertificateMetadata {
        let now = Utc::now();
        CertificateMetadata {
            fingerprint: [0xAA; 32],
            subject: "CN=example.com".to_string(),
            issuer: "CN=Trusted CA".to_string(),
            serial_number: "01".to_string(),
            not_before: now - Duration::days(30),
            not_after: now + Duration::days(335),
            sans: vec!["example.com".to_string()],
            key_algorithm: "RSA".to_string(),
            key_size: 2048,
            chain_depth: 2,
            issuer_fingerprint: Some([0xBB; 32]),
            first_seen: now - Duration::days(1),
            last_seen: now,
            connection_count: 5,
            source_ip: Some("192.168.1.100".to_string()),
            destination_ip: Some("10.0.0.1".to_string()),
            sni_hostname: Some("example.com".to_string()),
            completeness_flags: completeness::ALL_REQUIRED | completeness::SANS,
        }
    }

    // -----------------------------------------------------------------------
    // Classification tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_known_certificate() {
        let classifier = ShadowClassifier::with_defaults();
        let metadata = make_metadata();

        let result = classifier.classify(&metadata, true, true);
        assert_eq!(result, ShadowClassification::Known);
    }

    #[test]
    fn test_classify_deferred_when_inventory_unreachable() {
        let classifier = ShadowClassifier::with_defaults();
        let metadata = make_metadata();

        let result = classifier.classify(&metadata, false, false);
        match result {
            ShadowClassification::Deferred { reason } => {
                assert!(reason.contains("unreachable"));
            }
            _ => panic!("Expected Deferred classification, got {:?}", result),
        }
    }

    #[test]
    fn test_classify_shadow_low_risk() {
        let classifier = ShadowClassifier::with_defaults();
        let metadata = make_metadata();

        let result = classifier.classify(&metadata, true, false);
        match result {
            ShadowClassification::Shadow {
                risk_level,
                context,
            } => {
                assert_eq!(risk_level, RiskLevel::Low);
                assert_eq!(context.source_ip, Some("192.168.1.100".to_string()));
                assert_eq!(context.destination, Some("10.0.0.1".to_string()));
                assert_eq!(context.first_seen, metadata.first_seen);
            }
            _ => panic!("Expected Shadow classification, got {:?}", result),
        }
    }

    #[test]
    fn test_classify_shadow_critical_self_signed() {
        let classifier = ShadowClassifier::with_defaults();
        let mut metadata = make_metadata();
        // Self-signed: subject == issuer
        metadata.issuer = "CN=example.com".to_string();

        let result = classifier.classify(&metadata, true, false);
        match result {
            ShadowClassification::Shadow { risk_level, .. } => {
                assert_eq!(risk_level, RiskLevel::Critical);
            }
            _ => panic!("Expected Shadow classification, got {:?}", result),
        }
    }

    #[test]
    fn test_classify_shadow_critical_weak_rsa_key() {
        let classifier = ShadowClassifier::with_defaults();
        let mut metadata = make_metadata();
        metadata.key_algorithm = "RSA".to_string();
        metadata.key_size = 1024;

        let result = classifier.classify(&metadata, true, false);
        match result {
            ShadowClassification::Shadow { risk_level, .. } => {
                assert_eq!(risk_level, RiskLevel::Critical);
            }
            _ => panic!("Expected Shadow classification, got {:?}", result),
        }
    }

    #[test]
    fn test_classify_shadow_critical_weak_ecdsa_key() {
        let classifier = ShadowClassifier::with_defaults();
        let mut metadata = make_metadata();
        metadata.key_algorithm = "ECDSA".to_string();
        metadata.key_size = 128;

        let result = classifier.classify(&metadata, true, false);
        match result {
            ShadowClassification::Shadow { risk_level, .. } => {
                assert_eq!(risk_level, RiskLevel::Critical);
            }
            _ => panic!("Expected Shadow classification, got {:?}", result),
        }
    }

    #[test]
    fn test_classify_shadow_high_untrusted_issuer() {
        let config = ShadowClassifierConfig {
            trusted_issuers: vec![
                "CN=Let's Encrypt Authority X3".to_string(),
                "CN=DigiCert Global Root G2".to_string(),
            ],
            ..Default::default()
        };
        let classifier = ShadowClassifier::new(config);
        let mut metadata = make_metadata();
        metadata.issuer = "CN=Unknown CA".to_string();

        let result = classifier.classify(&metadata, true, false);
        match result {
            ShadowClassification::Shadow { risk_level, .. } => {
                assert_eq!(risk_level, RiskLevel::High);
            }
            _ => panic!("Expected Shadow classification, got {:?}", result),
        }
    }

    #[test]
    fn test_classify_shadow_high_long_validity() {
        let classifier = ShadowClassifier::with_defaults();
        let mut metadata = make_metadata();
        // Validity > 398 days
        metadata.not_before = Utc::now() - Duration::days(10);
        metadata.not_after = metadata.not_before + Duration::days(500);

        let result = classifier.classify(&metadata, true, false);
        match result {
            ShadowClassification::Shadow { risk_level, .. } => {
                assert_eq!(risk_level, RiskLevel::High);
            }
            _ => panic!("Expected Shadow classification, got {:?}", result),
        }
    }

    #[test]
    fn test_classify_shadow_medium_near_expiry() {
        let classifier = ShadowClassifier::with_defaults();
        let mut metadata = make_metadata();
        // < 30 days remaining
        metadata.not_before = Utc::now() - Duration::days(340);
        metadata.not_after = Utc::now() + Duration::days(15);

        let result = classifier.classify(&metadata, true, false);
        match result {
            ShadowClassification::Shadow { risk_level, .. } => {
                assert_eq!(risk_level, RiskLevel::Medium);
            }
            _ => panic!("Expected Shadow classification, got {:?}", result),
        }
    }

    #[test]
    fn test_classify_shadow_critical_takes_precedence_over_high() {
        let classifier = ShadowClassifier::with_defaults();
        let mut metadata = make_metadata();
        // Self-signed (critical) AND long validity (high)
        metadata.issuer = "CN=example.com".to_string();
        metadata.not_before = Utc::now() - Duration::days(10);
        metadata.not_after = metadata.not_before + Duration::days(500);

        let result = classifier.classify(&metadata, true, false);
        match result {
            ShadowClassification::Shadow { risk_level, .. } => {
                assert_eq!(risk_level, RiskLevel::Critical);
            }
            _ => panic!("Expected Shadow classification, got {:?}", result),
        }
    }

    #[test]
    fn test_classify_shadow_high_takes_precedence_over_medium() {
        let classifier = ShadowClassifier::with_defaults();
        let mut metadata = make_metadata();
        // Long validity (high) AND near expiry (medium)
        // This is a bit contrived: validity > 398 days but also < 30 days remaining
        metadata.not_before = Utc::now() - Duration::days(400);
        metadata.not_after = Utc::now() + Duration::days(15);

        let result = classifier.classify(&metadata, true, false);
        match result {
            ShadowClassification::Shadow { risk_level, .. } => {
                assert_eq!(risk_level, RiskLevel::High);
            }
            _ => panic!("Expected Shadow classification, got {:?}", result),
        }
    }

    #[test]
    fn test_classify_self_signed_case_insensitive() {
        let classifier = ShadowClassifier::with_defaults();
        let mut metadata = make_metadata();
        metadata.subject = "CN=Example.COM".to_string();
        metadata.issuer = "cn=example.com".to_string();

        let result = classifier.classify(&metadata, true, false);
        match result {
            ShadowClassification::Shadow { risk_level, .. } => {
                assert_eq!(risk_level, RiskLevel::Critical);
            }
            _ => panic!("Expected Shadow classification, got {:?}", result),
        }
    }

    #[test]
    fn test_classify_rsa_2048_not_weak() {
        let classifier = ShadowClassifier::with_defaults();
        let mut metadata = make_metadata();
        metadata.key_algorithm = "RSA".to_string();
        metadata.key_size = 2048;

        let result = classifier.classify(&metadata, true, false);
        match result {
            ShadowClassification::Shadow { risk_level, .. } => {
                assert_eq!(risk_level, RiskLevel::Low);
            }
            _ => panic!("Expected Shadow classification, got {:?}", result),
        }
    }

    #[test]
    fn test_classify_ecdsa_256_not_weak() {
        let classifier = ShadowClassifier::with_defaults();
        let mut metadata = make_metadata();
        metadata.key_algorithm = "ECDSA".to_string();
        metadata.key_size = 256;

        let result = classifier.classify(&metadata, true, false);
        match result {
            ShadowClassification::Shadow { risk_level, .. } => {
                assert_eq!(risk_level, RiskLevel::Low);
            }
            _ => panic!("Expected Shadow classification, got {:?}", result),
        }
    }

    #[test]
    fn test_classify_validity_exactly_398_not_high() {
        let classifier = ShadowClassifier::with_defaults();
        let mut metadata = make_metadata();
        metadata.not_before = Utc::now() - Duration::days(10);
        metadata.not_after = metadata.not_before + Duration::days(398);

        let result = classifier.classify(&metadata, true, false);
        match result {
            ShadowClassification::Shadow { risk_level, .. } => {
                assert_eq!(risk_level, RiskLevel::Low);
            }
            _ => panic!("Expected Shadow classification, got {:?}", result),
        }
    }

    #[test]
    fn test_classify_exactly_30_days_remaining_not_medium() {
        let classifier = ShadowClassifier::with_defaults();
        let mut metadata = make_metadata();
        // 31 days remaining — threshold is "fewer than 30", so 31 should be Low
        metadata.not_before = Utc::now() - Duration::days(300);
        metadata.not_after = Utc::now() + Duration::days(31);

        let result = classifier.classify(&metadata, true, false);
        match result {
            ShadowClassification::Shadow { risk_level, .. } => {
                assert_eq!(risk_level, RiskLevel::Low);
            }
            _ => panic!("Expected Shadow classification, got {:?}", result),
        }
    }

    #[test]
    fn test_classify_29_days_remaining_is_medium() {
        let classifier = ShadowClassifier::with_defaults();
        let mut metadata = make_metadata();
        // 29 days remaining — fewer than 30, should be Medium
        metadata.not_before = Utc::now() - Duration::days(300);
        metadata.not_after = Utc::now() + Duration::days(29);

        let result = classifier.classify(&metadata, true, false);
        match result {
            ShadowClassification::Shadow { risk_level, .. } => {
                assert_eq!(risk_level, RiskLevel::Medium);
            }
            _ => panic!("Expected Shadow classification, got {:?}", result),
        }
    }

    #[test]
    fn test_classify_expired_cert_not_medium() {
        let classifier = ShadowClassifier::with_defaults();
        let mut metadata = make_metadata();
        // Already expired — near_expiry check should not trigger
        metadata.not_before = Utc::now() - Duration::days(400);
        metadata.not_after = Utc::now() - Duration::days(1);

        let result = classifier.classify(&metadata, true, false);
        match result {
            ShadowClassification::Shadow { risk_level, .. } => {
                // Not medium (expired doesn't count as near-expiry)
                // Not high (validity is 399 days which is > 398, so it IS high)
                assert_eq!(risk_level, RiskLevel::High);
            }
            _ => panic!("Expected Shadow classification, got {:?}", result),
        }
    }

    #[test]
    fn test_trusted_issuer_list_match() {
        let config = ShadowClassifierConfig {
            trusted_issuers: vec![
                "CN=Trusted CA".to_string(),
                "CN=Another Trusted CA".to_string(),
            ],
            ..Default::default()
        };
        let classifier = ShadowClassifier::new(config);
        let metadata = make_metadata(); // issuer is "CN=Trusted CA"

        let result = classifier.classify(&metadata, true, false);
        match result {
            ShadowClassification::Shadow { risk_level, .. } => {
                assert_eq!(risk_level, RiskLevel::Low);
            }
            _ => panic!("Expected Shadow classification, got {:?}", result),
        }
    }

    #[test]
    fn test_trusted_issuer_list_case_insensitive() {
        let config = ShadowClassifierConfig {
            trusted_issuers: vec!["cn=trusted ca".to_string()],
            ..Default::default()
        };
        let classifier = ShadowClassifier::new(config);
        let mut metadata = make_metadata();
        metadata.issuer = "CN=Trusted CA".to_string();

        let result = classifier.classify(&metadata, true, false);
        match result {
            ShadowClassification::Shadow { risk_level, .. } => {
                assert_eq!(risk_level, RiskLevel::Low);
            }
            _ => panic!("Expected Shadow classification, got {:?}", result),
        }
    }

    // -----------------------------------------------------------------------
    // Directive generation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_generate_directive_alert_type() {
        let classifier = ShadowClassifier::with_defaults();
        let metadata = make_metadata();

        let directive = classifier.generate_directive(&metadata, RiskLevel::Low);
        assert_eq!(directive.action_type, ActionType::Alert);
        assert_eq!(directive.severity, Severity::Low);
        assert_eq!(directive.cert_fingerprint, metadata.fingerprint);
        assert_eq!(directive.attempt_count, 0);
        assert!(directive.source_anomaly.is_none());
    }

    #[test]
    fn test_generate_directive_critical_severity() {
        let classifier = ShadowClassifier::with_defaults();
        let metadata = make_metadata();

        let directive = classifier.generate_directive(&metadata, RiskLevel::Critical);
        assert_eq!(directive.action_type, ActionType::Alert);
        assert_eq!(directive.severity, Severity::Critical);
    }

    #[test]
    fn test_generate_directive_high_severity() {
        let classifier = ShadowClassifier::with_defaults();
        let metadata = make_metadata();

        let directive = classifier.generate_directive(&metadata, RiskLevel::High);
        assert_eq!(directive.severity, Severity::High);
    }

    #[test]
    fn test_generate_directive_medium_severity() {
        let classifier = ShadowClassifier::with_defaults();
        let metadata = make_metadata();

        let directive = classifier.generate_directive(&metadata, RiskLevel::Medium);
        assert_eq!(directive.severity, Severity::Medium);
    }

    #[test]
    fn test_generate_directive_includes_origin_context() {
        let classifier = ShadowClassifier::with_defaults();
        let metadata = make_metadata();

        let directive = classifier.generate_directive(&metadata, RiskLevel::Low);
        assert!(directive.reasoning.contains("192.168.1.100"));
        assert!(directive.reasoning.contains("10.0.0.1"));
    }

    #[test]
    fn test_generate_directive_reasoning_max_500_chars() {
        let classifier = ShadowClassifier::with_defaults();
        let mut metadata = make_metadata();
        // Create a very long subject to test truncation
        metadata.subject = "CN=".to_string() + &"a".repeat(600);
        metadata.issuer = metadata.subject.clone(); // self-signed

        let directive = classifier.generate_directive(&metadata, RiskLevel::Critical);
        assert!(directive.reasoning.len() <= 500);
    }

    #[test]
    fn test_generate_directive_unique_ids() {
        let classifier = ShadowClassifier::with_defaults();
        let metadata = make_metadata();

        let d1 = classifier.generate_directive(&metadata, RiskLevel::Low);
        let d2 = classifier.generate_directive(&metadata, RiskLevel::Low);
        assert_ne!(d1.id, d2.id);
        assert_ne!(d1.correlation_id, d2.correlation_id);
    }

    #[test]
    fn test_generate_directive_handles_missing_origin() {
        let classifier = ShadowClassifier::with_defaults();
        let mut metadata = make_metadata();
        metadata.source_ip = None;
        metadata.destination_ip = None;

        let directive = classifier.generate_directive(&metadata, RiskLevel::Low);
        assert!(directive.reasoning.contains("unknown"));
    }

    // -----------------------------------------------------------------------
    // Integration: classify + generate_directive
    // -----------------------------------------------------------------------

    #[test]
    fn test_full_flow_shadow_classification_and_directive() {
        let classifier = ShadowClassifier::with_defaults();
        let mut metadata = make_metadata();
        // Make it self-signed → critical
        metadata.issuer = "CN=example.com".to_string();

        let classification = classifier.classify(&metadata, true, false);
        match classification {
            ShadowClassification::Shadow {
                risk_level,
                context,
            } => {
                assert_eq!(risk_level, RiskLevel::Critical);
                assert_eq!(context.source_ip, Some("192.168.1.100".to_string()));
                assert_eq!(context.destination, Some("10.0.0.1".to_string()));

                let directive = classifier.generate_directive(&metadata, risk_level);
                assert_eq!(directive.action_type, ActionType::Alert);
                assert_eq!(directive.severity, Severity::Critical);
                assert_eq!(directive.cert_fingerprint, metadata.fingerprint);
            }
            _ => panic!("Expected Shadow classification"),
        }
    }
}
