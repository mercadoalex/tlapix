//! End-to-end integration tests for the Tlapix Certificate Guardian pipeline.
//!
//! These tests exercise the userspace pipeline without eBPF:
//! - Feed synthetic `TlsCertEvent` into the ring buffer reader (via ChannelRingBufferSource)
//! - Verify flow through dedup → analyzer → executor → observability
//!
//! Full eBPF tests (veth pairs, real kernel programs) are gated with
//! `#[cfg(target_os = "linux")]` and require root privileges.

use std::path::PathBuf;
use std::time::Duration;

use chrono::{TimeDelta, Utc};
use tokio_util::sync::CancellationToken;

use tlapix_analyzer::ai_backend::AnalyzerService;
use tlapix_analyzer::anomaly::AnomalyDetector;
use tlapix_analyzer::inventory::InventoryManager;
use tlapix_analyzer::renewal_scheduler::RenewalScheduler;
use tlapix_analyzer::shadow::ShadowClassifier;
use tlapix_collector::dedup::DeduplicationEngine;
use tlapix_collector::ring_buffer::{
    ChannelRingBufferSource, RingBufferReader, RingBufferReaderConfig,
};
use tlapix_common::bpf::TlsCertEvent;
use tlapix_common::config::InventorySource;
use tlapix_common::storage::Storage;
use tlapix_common::types::{
    ActionType, AnomalyType, CertificateMetadata, RiskLevel, Severity, ShadowClassification,
};
use tlapix_executor::map_writer::{MapWriterService, MockBpfMapWriter};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a `TlsCertEvent` with the embedded test certificate.
fn create_test_event_with_cert() -> TlsCertEvent {
    let cert_der = include_bytes!("../../tlapix-collector/test_data/test_cert.der");
    let mut event = TlsCertEvent {
        timestamp_ns: 1_000_000_000,
        src_ip: 0xC0A80001, // 192.168.0.1
        dst_ip: 0x0A000001, // 10.0.0.1
        src_port: 54321,
        dst_port: 443,
        ip_version: 4,
        tls_version: 0x0303, // TLS 1.2
        sni_len: 0,
        sni: [0u8; 256],
        fingerprint: [0u8; 32],
        cert_len: cert_der.len() as u32,
        cert_data: [0u8; 4096],
        chain_depth: 1,
        issuer_fingerprint: [0u8; 32],
        is_new: 1,
    };
    let copy_len = cert_der.len().min(4096);
    event.cert_data[..copy_len].copy_from_slice(&cert_der[..copy_len]);
    event
}

/// Create a `CertificateMetadata` with a weak RSA 1024-bit key for anomaly testing.
fn make_weak_key_certificate(fingerprint: [u8; 32]) -> CertificateMetadata {
    let now = Utc::now();
    CertificateMetadata {
        fingerprint,
        subject: "CN=weak.example.com".to_string(),
        issuer: "CN=Test CA".to_string(),
        serial_number: "01".to_string(),
        not_before: now - TimeDelta::days(30),
        not_after: now + TimeDelta::days(300),
        sans: vec!["weak.example.com".to_string()],
        key_algorithm: "RSA".to_string(),
        key_size: 1024, // Weak key!
        chain_depth: 2,
        issuer_fingerprint: Some([0xAA; 32]),
        first_seen: now,
        last_seen: now,
        connection_count: 1,
        source_ip: Some("192.168.0.1".to_string()),
        destination_ip: Some("10.0.0.1".to_string()),
        sni_hostname: Some("weak.example.com".to_string()),
        completeness_flags: 0xFF, // all fields present
    }
}

/// Create a `CertificateMetadata` expiring in the given number of days.
fn make_expiring_certificate(fingerprint: [u8; 32], days_until_expiry: i64) -> CertificateMetadata {
    let now = Utc::now();
    CertificateMetadata {
        fingerprint,
        subject: "CN=expiring.example.com".to_string(),
        issuer: "CN=Test CA".to_string(),
        serial_number: "02".to_string(),
        not_before: now - TimeDelta::days(365),
        not_after: now + TimeDelta::days(days_until_expiry),
        sans: vec!["expiring.example.com".to_string()],
        key_algorithm: "RSA".to_string(),
        key_size: 2048,
        chain_depth: 2,
        issuer_fingerprint: Some([0xBB; 32]),
        first_seen: now - TimeDelta::days(30),
        last_seen: now,
        connection_count: 100,
        source_ip: Some("192.168.1.1".to_string()),
        destination_ip: Some("10.0.0.2".to_string()),
        sni_hostname: Some("expiring.example.com".to_string()),
        completeness_flags: 0xFF,
    }
}

/// Create a `CertificateMetadata` that is not in any inventory (shadow cert).
fn make_shadow_certificate(fingerprint: [u8; 32]) -> CertificateMetadata {
    let now = Utc::now();
    CertificateMetadata {
        fingerprint,
        subject: "CN=shadow.unknown.com".to_string(),
        issuer: "CN=Unknown CA".to_string(),
        serial_number: "FF".to_string(),
        not_before: now - TimeDelta::days(10),
        not_after: now + TimeDelta::days(200),
        sans: vec!["shadow.unknown.com".to_string()],
        key_algorithm: "RSA".to_string(),
        key_size: 2048,
        chain_depth: 1,
        issuer_fingerprint: None,
        first_seen: now,
        last_seen: now,
        connection_count: 1,
        source_ip: Some("10.10.10.10".to_string()),
        destination_ip: Some("10.0.0.5".to_string()),
        sni_hostname: Some("shadow.unknown.com".to_string()),
        completeness_flags: 0xFF,
    }
}

/// Helper to create a MapWriterService with mock maps.
fn create_mock_map_writer() -> MapWriterService {
    MapWriterService::new(
        Box::new(MockBpfMapWriter::new(10_000)),
        Box::new(MockBpfMapWriter::new(10_000)),
        Box::new(MockBpfMapWriter::new(10_000)),
        10_000,
        64,
        3,
        100,
    )
}

// ---------------------------------------------------------------------------
// Integration Tests
// ---------------------------------------------------------------------------

/// Test the full pipeline: certificate discovery → dedup → anomaly detection → directive generation → map writer.
///
/// Validates: Requirements 1.1, 3.1, 6.1
#[tokio::test]
async fn test_full_pipeline_certificate_discovery_to_action() {
    // 1. Set up in-memory storage
    let storage = Storage::open_in_memory().await.unwrap();

    // 2. Set up the ring buffer reader with a channel source
    let reader = RingBufferReader::new(RingBufferReaderConfig::default());
    let (source, tx) = ChannelRingBufferSource::new(64);
    let cancel = CancellationToken::new();

    // Start the reader
    let mut rx = reader.start(source, cancel.clone()).await;

    // 3. Feed a test event with a valid certificate
    let event = create_test_event_with_cert();
    tx.send(event).await.unwrap();

    // 4. Receive the processed event from the ring buffer reader
    let collector_event = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timeout waiting for event from ring buffer reader")
        .expect("channel closed unexpectedly");

    assert!(collector_event.is_new);
    assert_ne!(collector_event.metadata.fingerprint, [0u8; 32]);

    // 5. Run through deduplication
    let mut dedup = DeduplicationEngine::new(1000);
    let is_new = dedup.mark_seen(collector_event.metadata.fingerprint);
    assert!(is_new, "First observation should be marked as new");

    // Duplicate should not be new
    let is_new_again = dedup.mark_seen(collector_event.metadata.fingerprint);
    assert!(!is_new_again, "Duplicate should not be marked as new");

    // 6. Run anomaly detection on the certificate
    let detector = AnomalyDetector::with_defaults();
    let anomalies = detector.detect(&collector_event.metadata);
    let directives = detector.generate_directives(&collector_event.metadata);

    // Each anomaly should produce exactly one directive
    assert_eq!(directives.len(), anomalies.len());

    // 7. If there are directives, write them to the mock BPF map writer
    let map_writer = create_mock_map_writer();

    for directive in &directives {
        let result = map_writer.write_directive(directive).await;
        assert_eq!(
            result,
            tlapix_common::types::ExecutionOutcome::Success,
            "Map writer should accept valid directives"
        );
    }

    // 8. Persist to storage
    storage
        .upsert_certificate(&collector_event.metadata)
        .await
        .unwrap();
    let stored = storage
        .get_certificate(&collector_event.metadata.fingerprint)
        .await
        .unwrap();
    assert!(
        stored.is_some(),
        "Certificate should be persisted in storage"
    );

    // Cleanup
    cancel.cancel();
}

/// Test that a weak-key certificate flows through the full pipeline and generates
/// the expected critical-severity anomaly directive.
///
/// Validates: Requirements 3.1, 3.3, 6.1
#[tokio::test]
async fn test_weak_key_certificate_generates_critical_directive() {
    let fingerprint = [0x01; 32];
    let cert = make_weak_key_certificate(fingerprint);

    // Anomaly detection should flag the weak key
    let detector = AnomalyDetector::with_defaults();
    let anomalies = detector.detect(&cert);

    // Should detect WeakCryptography anomaly
    let weak_key_anomaly = anomalies
        .iter()
        .find(|(anomaly, _)| matches!(anomaly, AnomalyType::WeakCryptography { .. }));
    assert!(
        weak_key_anomaly.is_some(),
        "Should detect weak RSA 1024-bit key"
    );

    // Severity should be critical
    let (_, severity) = weak_key_anomaly.unwrap();
    assert_eq!(*severity, Severity::Critical);

    // Generate directives
    let directives = detector.generate_directives(&cert);
    assert!(
        !directives.is_empty(),
        "Should generate at least one directive"
    );

    // Write to mock map writer and verify success
    let map_writer = create_mock_map_writer();

    for directive in &directives {
        let result = map_writer.write_directive(directive).await;
        assert_eq!(result, tlapix_common::types::ExecutionOutcome::Success);
    }

    // Verify the total entry count increased
    let total_entries = map_writer.total_entry_count().await;
    assert!(
        total_entries > 0,
        "Map writer should have entries after writing directives"
    );
}

/// Test graceful degradation: AI timeout → rule-based fallback.
///
/// When the AI model is unavailable (nonexistent path), the AnalyzerService
/// should fall back to rule-based detection and still detect anomalies.
///
/// Validates: Requirements 3.6, 6.1
#[tokio::test]
async fn test_graceful_degradation_ai_fallback() {
    // Create AnalyzerService with a nonexistent model path → triggers fallback
    let analyzer = AnalyzerService::with_model(PathBuf::from("/nonexistent/model.onnx"), 5);

    // Verify it's in fallback mode
    let mode = analyzer.health_check().await;
    let mode_str = format!("{}", mode);
    assert!(
        mode_str.contains("Rule-Based") || mode_str.contains("RuleBased") || mode_str.contains("rule"),
        "Should be in rule-based fallback mode, got: {}",
        mode_str
    );

    // Feed a certificate with a known anomaly (weak key)
    let cert = make_weak_key_certificate([0x02; 32]);
    let anomalies = analyzer.evaluate(&cert).await;

    // Rule-based detection should still work
    let has_weak_key = anomalies
        .iter()
        .any(|(a, _)| matches!(a, AnomalyType::WeakCryptography { .. }));
    assert!(
        has_weak_key,
        "Rule-based fallback should still detect weak cryptography"
    );
}

/// Test graceful degradation: inventory unreachable → continue with last known (empty).
///
/// When the inventory file doesn't exist, the InventoryManager should handle
/// the error gracefully and continue operating with an empty inventory.
///
/// Validates: Requirements 9.4
#[tokio::test]
async fn test_graceful_degradation_inventory_unreachable() {
    let storage = Storage::open_in_memory().await.unwrap();

    // Create InventoryManager with a nonexistent file path
    let inventory = InventoryManager::new(
        InventorySource::File {
            path: PathBuf::from("/nonexistent/inventory.json"),
        },
        storage,
        300,
    );

    // Attempt to refresh - should fail gracefully (not panic)
    let result = inventory.refresh().await;
    assert!(
        result.is_err(),
        "Refresh should fail when file doesn't exist"
    );

    // The manager should still be usable - contains should return false
    let contains = inventory.contains(&[0x01; 32]).await;
    assert!(
        !contains,
        "Should return false for any fingerprint when inventory is empty"
    );

    // Last refresh should be None (never succeeded)
    let last = inventory.last_refresh().await;
    assert!(last.is_none(), "No successful refresh should have occurred");

    // Staleness check should not panic
    let stale = inventory.is_stale().await;
    assert!(!stale, "Should not be stale if never refreshed");
}

/// Test that a certificate expiring in 10 days generates a "renew" directive.
///
/// Validates: Requirements 4.1, 4.2, 4.5
#[tokio::test]
async fn test_renewal_prediction_generates_directive() {
    let storage = Storage::open_in_memory().await.unwrap();

    let fingerprint = [0x03; 32];
    let cert = make_expiring_certificate(fingerprint, 10);

    // Persist the certificate to storage
    storage.upsert_certificate(&cert).await.unwrap();

    // Run renewal re-evaluation
    let result = RenewalScheduler::run_reevaluation(&storage).await.unwrap();

    // Should have evaluated at least one certificate
    assert!(
        result.certificates_evaluated >= 1,
        "Should evaluate the expiring certificate"
    );

    // Should have generated a directive (10 days < 14 days → critical, probability ≥ 0.7)
    assert!(
        result.directives_generated >= 1,
        "Should generate a renew directive for certificate expiring in 10 days"
    );

    // Verify the prediction was stored
    let prediction = storage.get_renewal_prediction(&fingerprint).await.unwrap();
    assert!(
        prediction.is_some(),
        "Renewal prediction should be persisted"
    );
    let prediction = prediction.unwrap();
    assert!(
        prediction.failure_probability >= 0.5,
        "Failure probability should be at least 0.5 (no history baseline)"
    );
    assert_eq!(prediction.severity, "critical");

    // Verify the directive was stored
    let directives = storage.list_directives_by_status("pending").await.unwrap();
    let renew_directive = directives
        .iter()
        .find(|d| d.cert_fingerprint == fingerprint && d.action_type == "renew");
    assert!(
        renew_directive.is_some(),
        "A 'renew' directive should be stored for the expiring certificate"
    );
}

/// Test shadow certificate lifecycle:
/// 1. Feed a certificate not in inventory → classified as shadow
/// 2. Add to inventory, run reconciliation → shadow is resolved
///
/// Validates: Requirements 5.1, 5.2, 9.3
#[tokio::test]
async fn test_shadow_certificate_lifecycle() {
    let storage = Storage::open_in_memory().await.unwrap();

    let fingerprint = [0x04; 32];
    let cert = make_shadow_certificate(fingerprint);

    // Persist the certificate to storage (simulating observation)
    storage.upsert_certificate(&cert).await.unwrap();

    // 1. Classify the certificate - it's not in inventory, so it should be shadow
    let classifier = ShadowClassifier::with_defaults();

    // The classifier needs to check inventory via storage
    let in_inventory = storage.inventory_contains(&fingerprint).await.unwrap();
    assert!(
        !in_inventory,
        "Certificate should not be in inventory initially"
    );

    // Classify: since it's not in inventory, it's a shadow
    let classification = classifier.classify(&cert, true, false);
    match &classification {
        ShadowClassification::Shadow {
            risk_level,
            context,
        } => {
            assert!(
                *risk_level >= RiskLevel::Low,
                "Shadow certificate should have a risk level assigned"
            );
            assert_eq!(context.source_ip, cert.source_ip);
            assert_eq!(context.first_seen, cert.first_seen);
        }
        other => panic!("Expected Shadow classification, got: {:?}", other),
    }

    // Generate a directive for the shadow certificate
    if let ShadowClassification::Shadow { risk_level, .. } = &classification {
        let directive = classifier.generate_directive(&cert, *risk_level);
        assert_eq!(directive.action_type, ActionType::Alert);
        assert_eq!(directive.cert_fingerprint, fingerprint);

        // Store the shadow classification
        let shadow_row = tlapix_common::storage::ShadowCertificateRow {
            fingerprint,
            risk_level: *risk_level,
            first_classified: Utc::now().timestamp_millis(),
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
            .unwrap();
    }

    // 2. Now add the certificate to inventory (simulating inventory update)
    let inventory_row = tlapix_common::storage::CertificateInventoryRow {
        fingerprint,
        subject: cert.subject.clone(),
        source: "file".to_string(),
        imported_at: Utc::now().timestamp_millis(),
        last_refresh_id: "test-refresh-001".to_string(),
    };
    storage
        .upsert_inventory_entry(&inventory_row)
        .await
        .unwrap();

    // Verify it's now in inventory
    let in_inventory = storage.inventory_contains(&fingerprint).await.unwrap();
    assert!(in_inventory, "Certificate should now be in inventory");

    // 3. Run reconciliation - the shadow should be resolved
    let reconciliation_result =
        tlapix_analyzer::reconciliation::reconcile_inventory(&storage, &[]).await;
    assert!(
        reconciliation_result.is_ok(),
        "Reconciliation should succeed"
    );
    let recon = reconciliation_result.unwrap();
    assert!(
        recon.shadows_resolved >= 1,
        "At least one shadow should be resolved"
    );

    // Verify the shadow is marked as resolved
    let shadow = storage.get_shadow_certificate(&fingerprint).await.unwrap();
    match shadow {
        Some(row) => assert!(row.is_resolved, "Shadow should be marked as resolved"),
        None => {
            // It's also acceptable if the shadow was deleted entirely
        }
    }
}

/// Test that the deduplication engine correctly handles multiple events
/// and only forwards unique certificates downstream.
///
/// Validates: Requirements 2.2, 2.3
#[tokio::test]
async fn test_dedup_forwards_only_unique_certificates() {
    let (source, tx) = ChannelRingBufferSource::new(64);
    let cancel = CancellationToken::new();

    // Start the ring buffer reader
    let reader = RingBufferReader::new(RingBufferReaderConfig::default());
    let mut reader_rx = reader.start(source, cancel.clone()).await;

    // Send the same event 3 times
    let event = create_test_event_with_cert();
    for _ in 0..3 {
        tx.send(event).await.unwrap();
    }

    // Collect events from the reader
    let mut received_events = Vec::new();
    for _ in 0..3 {
        let evt = tokio::time::timeout(Duration::from_secs(5), reader_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        received_events.push(evt);
    }

    // All 3 events should be received by the reader (it doesn't dedup)
    assert_eq!(received_events.len(), 3);

    // Now run through dedup - only the first should be "new"
    let mut dedup = DeduplicationEngine::new(1000);
    let mut unique_count = 0;
    for evt in &received_events {
        if dedup.mark_seen(evt.metadata.fingerprint) {
            unique_count += 1;
        }
    }
    assert_eq!(
        unique_count, 1,
        "Only one unique certificate should pass dedup"
    );

    cancel.cancel();
}

// ---------------------------------------------------------------------------
// Linux-specific integration tests (require eBPF, root, veth pairs)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_integration {
    /// Full eBPF pipeline test using veth pairs.
    /// Requires root privileges and Linux 5.15+.
    ///
    /// This test:
    /// 1. Creates a veth pair
    /// 2. Attaches the eBPF collector to one end
    /// 3. Sends synthetic TLS traffic through the pair
    /// 4. Verifies events appear in the ring buffer
    /// 5. Verifies the full pipeline processes them
    #[tokio::test]
    #[ignore] // Requires root and Linux kernel with eBPF support
    async fn test_ebpf_veth_full_pipeline() {
        // This test is a placeholder for the full eBPF integration test.
        // It requires:
        // - Linux kernel 5.15+ with eBPF support
        // - Root privileges (CAP_BPF, CAP_NET_ADMIN)
        // - veth pair creation
        // - Synthetic TLS handshake generation
        //
        // Implementation would:
        // 1. Create veth pair: `ip link add veth0 type veth peer name veth1`
        // 2. Load and attach eBPF programs to veth0
        // 3. Send a TLS ClientHello + ServerHello through veth1
        // 4. Read events from the ring buffer
        // 5. Verify certificate metadata extraction
        // 6. Clean up veth pair
        todo!("Requires Linux with eBPF support and root privileges");
    }
}
