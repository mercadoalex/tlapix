//! Property-based tests for the Executor layer.
//!
//! Uses `proptest` to verify correctness properties across many random inputs.

use proptest::prelude::*;
use std::sync::Mutex;

use chrono::{Duration, Utc};
use tempfile::TempDir;
use uuid::Uuid;

use tlapix_common::storage::{ActionDirectiveRow, Storage};
use tlapix_common::types::{
    ActionDirective, ActionType, CertificateMetadata, ExecutionOutcome, Severity,
};
use tlapix_executor::expiry::{expire_stale_directives, resolve_conflicts, BpfMapWriter, BpfMapError};
use tlapix_executor::failure_handler::handle_execution_failure;
use tlapix_executor::integrity::{
    compute_sha256, validate_program_integrity, ProgramEntry, ProgramManifest,
};
use tlapix_executor::map_writer::{
    MapWriteError, MockBpfMapWriter as AsyncMockBpfMapWriter,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Mock BPF map writer for the expiry module (sync trait).
struct MockBpfMapWriterSync {
    removed: Mutex<Vec<[u8; 32]>>,
}

impl MockBpfMapWriterSync {
    fn new() -> Self {
        Self {
            removed: Mutex::new(Vec::new()),
        }
    }
}

impl BpfMapWriter for MockBpfMapWriterSync {
    fn remove_entry(&self, fingerprint: &[u8; 32]) -> Result<(), BpfMapError> {
        self.removed.lock().unwrap().push(*fingerprint);
        Ok(())
    }
}

fn make_test_certificate(fingerprint: [u8; 32], last_seen: chrono::DateTime<Utc>) -> CertificateMetadata {
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
        last_seen,
        connection_count: 1,
        source_ip: Some("192.168.1.1".to_string()),
        destination_ip: Some("10.0.0.1".to_string()),
        sni_hostname: Some("test.example.com".to_string()),
        completeness_flags: 0x7F,
    }
}

fn make_directive_row(
    id: &str,
    fingerprint: [u8; 32],
    severity: &str,
    status: &str,
) -> ActionDirectiveRow {
    let now_ms = Utc::now().timestamp_millis();
    ActionDirectiveRow {
        id: id.to_string(),
        correlation_id: format!("corr-{}", id),
        cert_fingerprint: fingerprint,
        action_type: "alert".to_string(),
        severity: severity.to_string(),
        reasoning: Some("Test directive".to_string()),
        status: status.to_string(),
        attempt_count: 0,
        created_at: now_ms,
        executed_at: None,
        expired_at: None,
        failure_reason: None,
    }
}

fn severity_from_u8(val: u8) -> &'static str {
    match val {
        0 => "low",
        1 => "medium",
        2 => "high",
        3 => "critical",
        _ => "low",
    }
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "low" => 0,
        "medium" => 1,
        "high" => 2,
        "critical" => 3,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Property 14: Directive Expiry
// **Validates: Requirements 6.5**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// For any ActionDirective referencing a certificate whose last_seen is more
    /// than 72 hours in the past, the Executor SHALL expire the directive.
    #[test]
    fn prop_directive_expiry(hours_since_seen in 0u64..200) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let result = rt.block_on(async {
            let storage = Storage::open_in_memory().await.unwrap();
            let map_writer = MockBpfMapWriterSync::new();

            let fp = [42u8; 32];
            let last_seen = Utc::now() - Duration::hours(hours_since_seen as i64);
            let cert = make_test_certificate(fp, last_seen);
            storage.upsert_certificate(&cert).await.unwrap();

            let directive_id = format!("dir-{}", hours_since_seen);
            let directive = make_directive_row(&directive_id, fp, "high", "active");
            storage.insert_action_directive(&directive).await.unwrap();

            let result = expire_stale_directives(&storage, &map_writer, 72)
                .await
                .unwrap();

            let updated = storage.get_action_directive(&directive_id).await.unwrap().unwrap();
            (result, updated, directive_id)
        });

        let (expiry_result, updated, directive_id) = result;

        if hours_since_seen >= 72 {
            // Directive should be expired (at exactly 72h, timing makes it slightly over)
            prop_assert_eq!(expiry_result.expired_count, 1);
            prop_assert_eq!(expiry_result.expired_ids, vec![directive_id]);
            prop_assert_eq!(updated.status.as_str(), "expired");
        } else {
            // Directive should remain active
            prop_assert_eq!(expiry_result.expired_count, 0);
            prop_assert!(expiry_result.expired_ids.is_empty());
            prop_assert_eq!(updated.status.as_str(), "active");
        }
    }
}

// ---------------------------------------------------------------------------
// Property 15: Directive Conflict Resolution
// **Validates: Requirements 6.9**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// For any pair of directives targeting the same certificate, the highest
    /// severity wins. If equal, the first one wins.
    #[test]
    fn prop_directive_conflict_resolution(
        severity_a in 0u8..4,
        severity_b in 0u8..4
    ) {
        let fp = [99u8; 32];
        let sev_a_str = severity_from_u8(severity_a);
        let sev_b_str = severity_from_u8(severity_b);

        let directives = vec![
            make_directive_row("first", fp, sev_a_str, "pending"),
            make_directive_row("second", fp, sev_b_str, "pending"),
        ];

        let result = resolve_conflicts(&directives);

        prop_assert_eq!(result.winners.len(), 1);
        prop_assert_eq!(result.discarded.len(), 1);

        let winner = &result.winners[0];
        let expected_max_severity = std::cmp::max(severity_a, severity_b);

        // Winner should have the highest severity
        prop_assert_eq!(severity_rank(&winner.severity), expected_max_severity);

        if severity_a == severity_b {
            // If equal, first one wins
            prop_assert_eq!(winner.id.as_str(), "first");
        } else if severity_a > severity_b {
            prop_assert_eq!(winner.id.as_str(), "first");
        } else {
            prop_assert_eq!(winner.id.as_str(), "second");
        }
    }
}

// ---------------------------------------------------------------------------
// Property 16: BPF Map Capacity Enforcement
// **Validates: Requirements 7.3, 7.8**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// For any sequence of writes exceeding max entries, the map SHALL reject
    /// new writes.
    #[test]
    fn prop_bpf_map_capacity(max_entries in 1usize..100, num_writes in 1usize..200) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (success_count, fail_count) = rt.block_on(async {
            let mock_map = AsyncMockBpfMapWriter::new(max_entries);

            let mut success_count = 0usize;
            let mut fail_count = 0usize;

            for i in 0..num_writes {
                let mut fp = [0u8; 32];
                // Create unique fingerprints
                fp[0] = (i & 0xFF) as u8;
                fp[1] = ((i >> 8) & 0xFF) as u8;
                fp[2] = ((i >> 16) & 0xFF) as u8;

                let entry = tlapix_common::BpfActionEntry {
                    fingerprint: fp,
                    action: 0,
                    severity: 2,
                    created_ts: 1000,
                    pinned_fp: [0u8; 32],
                    flags: 1,
                };

                use tlapix_executor::map_writer::BpfMapWriter as AsyncBpfMapWriterTrait;
                match mock_map.write_entry(fp, entry).await {
                    Ok(()) => success_count += 1,
                    Err(MapWriteError::MapFull { .. }) => fail_count += 1,
                    Err(e) => panic!("Unexpected error: {:?}", e),
                }
            }

            (success_count, fail_count)
        });

        // First max_entries writes should succeed
        let expected_successes = std::cmp::min(max_entries, num_writes);
        prop_assert_eq!(success_count, expected_successes);

        // Writes beyond max_entries should fail with MapFull
        if num_writes > max_entries {
            prop_assert_eq!(fail_count, num_writes - max_entries);
        } else {
            prop_assert_eq!(fail_count, 0usize);
        }
    }
}

// ---------------------------------------------------------------------------
// Property 17: Program Integrity Validation
// **Validates: Requirements 7.6, 7.7**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// For any set of program binaries with expected checksums, validation passes
    /// iff every checksum matches.
    #[test]
    fn prop_program_integrity(
        num_programs in 1usize..10,
        tamper_index in prop::option::of(0usize..10)
    ) {
        let dir = TempDir::new().unwrap();

        // Generate program files with deterministic content
        let mut entries = Vec::new();
        for i in 0..num_programs {
            let content = format!("program binary content {}", i);
            let path = dir.path().join(format!("prog_{}.o", i));
            std::fs::write(&path, content.as_bytes()).unwrap();
            let expected_sha256 = compute_sha256(content.as_bytes());

            entries.push(ProgramEntry {
                name: format!("program_{}", i),
                path,
                expected_sha256,
            });
        }

        // If tamper_index is Some(i) and i < num_programs, corrupt that file
        let should_tamper = tamper_index.filter(|&idx| idx < num_programs);

        if let Some(idx) = should_tamper {
            // Overwrite the file with different content
            std::fs::write(&entries[idx].path, b"TAMPERED CONTENT").unwrap();
        }

        let manifest = ProgramManifest { programs: entries };
        let result = validate_program_integrity(&manifest);

        if should_tamper.is_some() {
            // Validation should fail
            prop_assert!(result.is_err());
        } else {
            // Validation should pass
            prop_assert!(result.is_ok());
        }
    }
}

// ---------------------------------------------------------------------------
// Property 18: Retry Exhaustion State Transition
// **Validates: Requirements 6.7**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// For any directive that fails 3 times, it SHALL be marked as failed with
    /// an alert generated.
    #[test]
    fn prop_retry_exhaustion(attempts in 3u8..10) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (updated_status, updated_attempt_count, updated_failure_reason,
             alert_action_type, alert_severity, alert_status, alert_fp,
             result_attempts) = rt.block_on(async {
            let storage = Storage::open_in_memory().await.unwrap();

            let fp = [0xAB; 32];
            let directive = ActionDirective {
                id: Uuid::new_v4(),
                correlation_id: Uuid::new_v4(),
                cert_fingerprint: fp,
                action_type: ActionType::Renew,
                severity: Severity::High,
                reasoning: "Certificate expiring soon".to_string(),
                created_at: Utc::now(),
                source_anomaly: None,
                attempt_count: attempts,
            };

            // Insert the certificate (FK constraint)
            let cert = make_test_certificate(fp, Utc::now());
            storage.upsert_certificate(&cert).await.unwrap();

            // Insert the directive into storage
            let row = ActionDirectiveRow {
                id: directive.id.to_string(),
                correlation_id: directive.correlation_id.to_string(),
                cert_fingerprint: fp,
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

            let outcome = ExecutionOutcome::Failed {
                reason: format!("simulated failure after {} attempts", attempts),
                attempts,
            };

            let result = handle_execution_failure(&storage, &directive, &outcome)
                .await
                .unwrap();

            // Read back the updated directive
            let updated = storage
                .get_action_directive(&directive.id.to_string())
                .await
                .unwrap()
                .unwrap();

            // Read back the alert directive
            let alert = storage
                .get_action_directive(&result.alert_directive_id)
                .await
                .unwrap()
                .unwrap();

            (
                updated.status,
                updated.attempt_count,
                updated.failure_reason,
                alert.action_type,
                alert.severity,
                alert.status,
                alert.cert_fingerprint,
                result.attempts,
            )
        });

        // Assert: directive marked as failed
        prop_assert_eq!(updated_status.as_str(), "failed");
        prop_assert_eq!(updated_attempt_count, attempts as i32);
        prop_assert!(updated_failure_reason.is_some());

        // Assert: alert directive generated
        prop_assert_eq!(alert_action_type.as_str(), "alert");
        prop_assert_eq!(alert_severity.as_str(), "critical");
        prop_assert_eq!(alert_status.as_str(), "pending");
        prop_assert_eq!(alert_fp, [0xAB; 32]);

        // Assert: attempt_count matches
        prop_assert_eq!(result_attempts, attempts);
    }
}
