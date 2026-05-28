//! Property-based tests for the tlapix-common crate.
//!
//! Uses `proptest` to verify correctness properties across many random inputs.

use chrono::{Duration, Utc};
use proptest::prelude::*;
use tlapix_common::storage::{AuditLogRow, Storage};
use tlapix_common::types::CertificateMetadata;

/// Helper to create a CertificateMetadata with a specific last_seen offset from now.
fn make_certificate_with_age(fingerprint: [u8; 32], days_old: u32) -> CertificateMetadata {
    let now = Utc::now();
    let last_seen = now - Duration::days(days_old as i64);
    CertificateMetadata {
        fingerprint,
        subject: "CN=test.example.com".to_string(),
        issuer: "CN=Test CA".to_string(),
        serial_number: "01:02:03".to_string(),
        not_before: now - Duration::days(365),
        not_after: now + Duration::days(365),
        sans: vec!["test.example.com".to_string()],
        key_algorithm: "RSA".to_string(),
        key_size: 2048,
        chain_depth: 1,
        issuer_fingerprint: None,
        first_seen: now - Duration::days(days_old as i64 + 1),
        last_seen,
        connection_count: 1,
        source_ip: Some("192.168.1.1".to_string()),
        destination_ip: Some("10.0.0.1".to_string()),
        sni_hostname: Some("test.example.com".to_string()),
        completeness_flags: 0x7F,
    }
}

/// Helper to create an AuditLogRow with a specific age in days.
fn make_audit_log_with_age(fingerprint: [u8; 32], days_old: u32) -> AuditLogRow {
    let now = Utc::now();
    let created_at = (now - Duration::days(days_old as i64)).timestamp_millis();
    AuditLogRow {
        id: 0, // auto-increment
        correlation_id: uuid::Uuid::new_v4().to_string(),
        cert_fingerprint: fingerprint,
        stage: "observation".to_string(),
        timestamp: created_at,
        details: r#"{"test": true}"#.to_string(),
        created_at,
    }
}

proptest! {
    /// **Property 20: Data Retention Policy**
    ///
    /// For any stored CertificateMetadata with last_seen older than 90 days,
    /// the record SHALL be eligible for deletion. For any audit log entry
    /// younger than 90 days, the record SHALL NOT be deleted.
    ///
    /// **Validates: Requirements 2.6, 8.5**
    #[test]
    fn prop_data_retention_policy(days_old in 0u32..365) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let storage = Storage::open_in_memory().await.unwrap();

            // Create a unique fingerprint for this test iteration
            let mut fingerprint = [0u8; 32];
            fingerprint[0] = (days_old & 0xFF) as u8;
            fingerprint[1] = ((days_old >> 8) & 0xFF) as u8;
            // Add some randomness to avoid collisions
            fingerprint[2] = rand_byte(days_old);

            // Insert a certificate with the specified age
            let cert = make_certificate_with_age(fingerprint, days_old);
            storage.upsert_certificate(&cert).await.unwrap();

            // Insert an audit log with the same age
            let audit_log = make_audit_log_with_age(fingerprint, days_old);
            storage.insert_audit_log(&audit_log).await.unwrap();

            // Verify the certificate exists before cleanup
            let before = storage.get_certificate(&fingerprint).await.unwrap();
            prop_assert!(before.is_some(), "Certificate should exist before cleanup");

            // Run cleanup with 90-day retention
            let certs_deleted = storage.cleanup_old_certificates(90).await.unwrap();
            let logs_deleted = storage.cleanup_old_audit_logs(90).await.unwrap();

            // Check certificate retention
            let after = storage.get_certificate(&fingerprint).await.unwrap();

            if days_old > 90 {
                // Certificate with last_seen > 90 days should be deleted
                prop_assert!(
                    after.is_none(),
                    "Certificate with last_seen {} days old should be deleted (was not)",
                    days_old
                );
                prop_assert!(certs_deleted >= 1, "At least one cert should be deleted");
            } else {
                // Certificate with last_seen <= 90 days should be preserved
                prop_assert!(
                    after.is_some(),
                    "Certificate with last_seen {} days old should be preserved (was deleted)",
                    days_old
                );
            }

            // Check audit log retention
            let audit_logs = storage
                .get_audit_logs_by_correlation(&audit_log.correlation_id)
                .await
                .unwrap();

            if days_old > 90 {
                // Audit log older than 90 days should be deleted
                prop_assert!(
                    audit_logs.is_empty(),
                    "Audit log {} days old should be deleted",
                    days_old
                );
                prop_assert!(logs_deleted >= 1, "At least one audit log should be deleted");
            } else {
                // Audit log younger than 90 days should NOT be deleted
                prop_assert!(
                    !audit_logs.is_empty(),
                    "Audit log {} days old should NOT be deleted",
                    days_old
                );
            }

            Ok(())
        })?;
    }
}

/// Simple deterministic "random" byte based on input to avoid fingerprint collisions.
fn rand_byte(seed: u32) -> u8 {
    // Simple hash-like mixing
    let x = seed.wrapping_mul(2654435761);
    (x >> 16) as u8
}
