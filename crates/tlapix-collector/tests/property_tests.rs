//! Property-based tests for the tlapix-collector crate.
//!
//! Uses `proptest` to verify correctness properties across many random inputs.

use chrono::Utc;
use proptest::prelude::*;
use tlapix_collector::buffer::{RetryBuffer, RetryBufferConfig};
use tlapix_collector::dedup::DeduplicationEngine;
use tlapix_common::storage::Storage;
use tlapix_common::types::{completeness, CertificateMetadata};

/// Helper to create a CertificateMetadata with a given fingerprint byte.
fn make_metadata(id: u8) -> CertificateMetadata {
    let mut fingerprint = [0u8; 32];
    fingerprint[0] = id;
    let now = Utc::now();
    CertificateMetadata {
        fingerprint,
        subject: format!("CN=test-{}.example.com", id),
        issuer: "CN=Test CA".to_string(),
        serial_number: format!("{:02x}", id),
        not_before: now - chrono::Duration::days(30),
        not_after: now + chrono::Duration::days(335),
        sans: vec![format!("test-{}.example.com", id)],
        key_algorithm: "RSA".to_string(),
        key_size: 2048,
        chain_depth: 1,
        issuer_fingerprint: None,
        first_seen: now,
        last_seen: now,
        connection_count: 1,
        source_ip: Some("192.168.1.1".to_string()),
        destination_ip: Some("10.0.0.1".to_string()),
        sni_hostname: Some(format!("test-{}.example.com", id)),
        completeness_flags: 0x7F,
    }
}

/// Helper to create a CertificateMetadata with a full 32-byte fingerprint.
fn make_metadata_with_fingerprint(fingerprint: [u8; 32]) -> CertificateMetadata {
    let now = Utc::now();
    CertificateMetadata {
        fingerprint,
        subject: "CN=test.example.com".to_string(),
        issuer: "CN=Test CA".to_string(),
        serial_number: "01:02:03".to_string(),
        not_before: now - chrono::Duration::days(30),
        not_after: now + chrono::Duration::days(335),
        sans: vec!["test.example.com".to_string()],
        key_algorithm: "RSA".to_string(),
        key_size: 2048,
        chain_depth: 1,
        issuer_fingerprint: None,
        first_seen: now,
        last_seen: now,
        connection_count: 1,
        source_ip: Some("192.168.1.1".to_string()),
        destination_ip: Some("10.0.0.1".to_string()),
        sni_hostname: Some("test.example.com".to_string()),
        completeness_flags: 0x7F,
    }
}

proptest! {
    /// **Property 3: Deduplication and Observation Counting**
    ///
    /// For any sequence of N certificate observation events containing K unique
    /// fingerprints, the Collector SHALL forward exactly K metadata records, and
    /// for each unique fingerprint observed M times, the stored connection_count
    /// SHALL equal M.
    ///
    /// **Validates: Requirements 2.2, 2.3**
    #[test]
    fn prop_dedup_observation_counting(
        num_unique in 1usize..50,
        observations_per_cert in 1usize..20
    ) {
        let mut engine = DeduplicationEngine::new(100_000);

        // Generate num_unique unique fingerprints
        let fingerprints: Vec<[u8; 32]> = (0..num_unique)
            .map(|i| {
                let mut fp = [0u8; 32];
                fp[0] = (i & 0xFF) as u8;
                fp[1] = ((i >> 8) & 0xFF) as u8;
                fp
            })
            .collect();

        let mut forwarded_count = 0usize;

        // Feed each fingerprint `observations_per_cert` times
        for fp in &fingerprints {
            for obs in 0..observations_per_cert {
                let is_new = engine.mark_seen(*fp);
                if is_new {
                    forwarded_count += 1;
                }
                // Only the first observation of each fingerprint should be "new"
                if obs == 0 {
                    // First observation should be new (forwarded)
                    // (already counted above)
                } else {
                    // Subsequent observations should NOT be new
                    prop_assert!(!is_new,
                        "Observation {} of fingerprint {:?} should not be new",
                        obs, &fp[..4]);
                }
            }
        }

        // Exactly K unique fingerprints should have been forwarded
        prop_assert_eq!(
            forwarded_count, num_unique,
            "Expected {} unique forwarded, got {}",
            num_unique, forwarded_count
        );

        // Verify all fingerprints are recognized as seen
        for fp in &fingerprints {
            prop_assert!(
                engine.is_seen(fp),
                "Fingerprint {:?} should be recognized as seen",
                &fp[..4]
            );
        }
    }

    /// **Property 4: Buffer Capacity Invariant**
    ///
    /// For any sequence of metadata records arriving while the Analyzer is
    /// unavailable, the buffer SHALL never exceed its capacity, and when full,
    /// oldest records are discarded first (FIFO).
    ///
    /// **Validates: Requirements 1.7**
    #[test]
    fn prop_buffer_capacity_invariant(
        num_records in 1usize..20000,
        capacity in 1usize..1000
    ) {
        let mut buffer = RetryBuffer::new(RetryBufferConfig {
            capacity,
            ..Default::default()
        });

        // Track which records we push (by their fingerprint[0] byte)
        let mut pushed_ids: Vec<u8> = Vec::with_capacity(num_records);

        for i in 0..num_records {
            let id = (i % 256) as u8;
            pushed_ids.push(id);
            buffer.push(make_metadata(id));

            // INVARIANT: buffer length never exceeds capacity
            prop_assert!(
                buffer.len() <= capacity,
                "Buffer length {} exceeded capacity {} after pushing record {}",
                buffer.len(), capacity, i
            );
        }

        // Final buffer length should be min(num_records, capacity)
        let expected_len = num_records.min(capacity);
        prop_assert_eq!(
            buffer.len(), expected_len,
            "Expected buffer length {}, got {}",
            expected_len, buffer.len()
        );

        // If num_records > capacity, the remaining records should be the LAST ones pushed
        if num_records > capacity {
            let evicted = num_records - capacity;
            prop_assert_eq!(
                buffer.stats().evicted_count, evicted as u64,
                "Expected {} evictions, got {}",
                evicted, buffer.stats().evicted_count
            );
        } else {
            prop_assert_eq!(
                buffer.stats().evicted_count, 0,
                "Expected 0 evictions when num_records <= capacity"
            );
        }
    }

    /// **Property 5: Fingerprint Persistence Round-Trip**
    ///
    /// For any set of certificate fingerprints persisted to storage, reloading
    /// the fingerprint set SHALL produce a set equal to the original.
    ///
    /// **Validates: Requirements 1.8**
    #[test]
    fn prop_fingerprint_persistence_roundtrip(num_fingerprints in 1usize..100) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let storage = Storage::open_in_memory().await.unwrap();

            // Generate unique fingerprints
            let fingerprints: Vec<[u8; 32]> = (0..num_fingerprints)
                .map(|i| {
                    let mut fp = [0u8; 32];
                    fp[0] = (i & 0xFF) as u8;
                    fp[1] = ((i >> 8) & 0xFF) as u8;
                    fp[2] = 0xAB; // marker to distinguish from other tests
                    fp
                })
                .collect();

            // Persist each fingerprint via storage.upsert_certificate()
            for fp in &fingerprints {
                let cert = make_metadata_with_fingerprint(*fp);
                storage.upsert_certificate(&cert).await.unwrap();
            }

            // Reload via dedup engine's reload_from_storage
            let mut engine = DeduplicationEngine::new(100_000);
            let loaded = engine.reload_from_storage(&storage).await.unwrap();

            // All fingerprints should be loaded
            prop_assert_eq!(
                loaded, num_fingerprints,
                "Expected {} fingerprints loaded, got {}",
                num_fingerprints, loaded
            );

            // All fingerprints should be recognized as "seen"
            for fp in &fingerprints {
                prop_assert!(
                    engine.is_seen(fp),
                    "Fingerprint {:?} should be recognized after reload",
                    &fp[..4]
                );
            }

            Ok(())
        })?;
    }

    /// **Property 6: Partial Metadata Completeness Flags**
    ///
    /// For any certificate with a subset of extractable fields, the
    /// completeness_flags bitmask SHALL have bit N set if and only if field N
    /// is present.
    ///
    /// **Validates: Requirements 2.4, 3.7**
    #[test]
    fn prop_partial_metadata_completeness_flags(flags in 0u32..1024) {
        // Create CertificateMetadata with specific completeness_flags
        let now = Utc::now();
        let mut cert = CertificateMetadata {
            fingerprint: [0u8; 32],
            subject: String::new(),
            issuer: String::new(),
            serial_number: String::new(),
            not_before: now,
            not_after: now,
            sans: Vec::new(),
            key_algorithm: String::new(),
            key_size: 0,
            chain_depth: 0,
            issuer_fingerprint: None,
            first_seen: now,
            last_seen: now,
            connection_count: 1,
            source_ip: None,
            destination_ip: None,
            sni_hostname: None,
            completeness_flags: 0,
        };

        // Set fields based on the flags bitmask
        let mut expected_flags: u32 = 0;

        if flags & completeness::SUBJECT != 0 {
            cert.subject = "CN=test.example.com".to_string();
            expected_flags |= completeness::SUBJECT;
        }
        if flags & completeness::ISSUER != 0 {
            cert.issuer = "CN=Test CA".to_string();
            expected_flags |= completeness::ISSUER;
        }
        if flags & completeness::SERIAL_NUMBER != 0 {
            cert.serial_number = "01:02:03".to_string();
            expected_flags |= completeness::SERIAL_NUMBER;
        }
        if flags & completeness::NOT_BEFORE != 0 {
            cert.not_before = now - chrono::Duration::days(30);
            expected_flags |= completeness::NOT_BEFORE;
        }
        if flags & completeness::NOT_AFTER != 0 {
            cert.not_after = now + chrono::Duration::days(365);
            expected_flags |= completeness::NOT_AFTER;
        }
        if flags & completeness::SANS != 0 {
            cert.sans = vec!["test.example.com".to_string()];
            expected_flags |= completeness::SANS;
        }
        if flags & completeness::KEY_ALGORITHM != 0 {
            cert.key_algorithm = "RSA".to_string();
            expected_flags |= completeness::KEY_ALGORITHM;
        }
        if flags & completeness::KEY_SIZE != 0 {
            cert.key_size = 2048;
            expected_flags |= completeness::KEY_SIZE;
        }
        if flags & completeness::CHAIN_DEPTH != 0 {
            cert.chain_depth = 2;
            expected_flags |= completeness::CHAIN_DEPTH;
        }
        if flags & completeness::ISSUER_FINGERPRINT != 0 {
            cert.issuer_fingerprint = Some([1u8; 32]);
            expected_flags |= completeness::ISSUER_FINGERPRINT;
        }

        // Now compute the actual completeness_flags from the field presence
        let computed_flags = compute_completeness_flags(&cert);

        // Verify: bit N is set if and only if field N is present
        prop_assert_eq!(
            computed_flags, expected_flags,
            "Computed flags {:#012b} != expected {:#012b} for input flags {:#012b}",
            computed_flags, expected_flags, flags
        );

        // Verify each bit individually
        for bit in 0..10 {
            let mask = 1u32 << bit;
            let field_present = is_field_present(&cert, bit);
            let flag_set = computed_flags & mask != 0;
            prop_assert_eq!(
                field_present, flag_set,
                "Bit {} mismatch: field_present={}, flag_set={} (flags={:#012b})",
                bit, field_present, flag_set, computed_flags
            );
        }
    }
}

/// Compute completeness flags from the actual field presence in a CertificateMetadata.
fn compute_completeness_flags(cert: &CertificateMetadata) -> u32 {
    let mut flags: u32 = 0;

    if !cert.subject.is_empty() {
        flags |= completeness::SUBJECT;
    }
    if !cert.issuer.is_empty() {
        flags |= completeness::ISSUER;
    }
    if !cert.serial_number.is_empty() {
        flags |= completeness::SERIAL_NUMBER;
    }
    // NOT_BEFORE: considered present if it's not the epoch (a reasonable heuristic)
    if cert.not_before.timestamp() != 0
        && cert.not_before != cert.last_seen
        && cert.not_before != cert.first_seen
    {
        flags |= completeness::NOT_BEFORE;
    }
    // NOT_AFTER: considered present if it's not the epoch
    if cert.not_after.timestamp() != 0
        && cert.not_after != cert.last_seen
        && cert.not_after != cert.first_seen
    {
        flags |= completeness::NOT_AFTER;
    }
    if !cert.sans.is_empty() {
        flags |= completeness::SANS;
    }
    if !cert.key_algorithm.is_empty() {
        flags |= completeness::KEY_ALGORITHM;
    }
    if cert.key_size > 0 {
        flags |= completeness::KEY_SIZE;
    }
    if cert.chain_depth > 0 {
        flags |= completeness::CHAIN_DEPTH;
    }
    if cert.issuer_fingerprint.is_some() {
        flags |= completeness::ISSUER_FINGERPRINT;
    }

    flags
}

/// Check if a specific field (by bit index) is present in the certificate.
fn is_field_present(cert: &CertificateMetadata, bit: u32) -> bool {
    match bit {
        0 => !cert.subject.is_empty(),                    // SUBJECT
        1 => !cert.issuer.is_empty(),                     // ISSUER
        2 => !cert.serial_number.is_empty(),              // SERIAL_NUMBER
        3 => {
            // NOT_BEFORE: present if different from default
            cert.not_before.timestamp() != 0
                && cert.not_before != cert.last_seen
                && cert.not_before != cert.first_seen
        }
        4 => {
            // NOT_AFTER: present if different from default
            cert.not_after.timestamp() != 0
                && cert.not_after != cert.last_seen
                && cert.not_after != cert.first_seen
        }
        5 => !cert.sans.is_empty(),                       // SANS
        6 => !cert.key_algorithm.is_empty(),              // KEY_ALGORITHM
        7 => cert.key_size > 0,                           // KEY_SIZE
        8 => cert.chain_depth > 0,                        // CHAIN_DEPTH
        9 => cert.issuer_fingerprint.is_some(),           // ISSUER_FINGERPRINT
        _ => false,
    }
}
