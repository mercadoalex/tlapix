//! Deduplication engine for the Tlapix Collector.
//!
//! Uses an LRU cache to track previously-seen certificate fingerprints.
//! On startup, the cache is pre-populated from persistent storage (SQLite)
//! so that previously-observed certificates are not re-reported as new
//! after a restart.
//!
//! The engine sits between the ring buffer reader and the Analyzer:
//! - Consumes `CollectorEvent` from the ring buffer reader channel
//! - Deduplicates by SHA-256 fingerprint using the LRU cache
//! - Forwards only unique certificate metadata downstream to the Analyzer
//! - Updates `last_seen` and increments `connection_count` for duplicates
//! - Persists metadata to SQLite

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::Utc;
use lru::LruCache;
use tlapix_common::storage::Storage;
use tlapix_common::types::CertificateMetadata;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing;

use crate::ring_buffer::CollectorEvent;

/// Default maximum capacity of the fingerprint LRU cache.
pub const DEFAULT_CACHE_CAPACITY: usize = 100_000;

/// Default output channel capacity.
const DEFAULT_OUTPUT_CHANNEL_CAPACITY: usize = 1024;

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

/// Statistics tracked by the deduplication engine.
#[derive(Debug, Clone, Default)]
pub struct DeduplicationStats {
    /// Total events received from the ring buffer reader.
    pub total_events: u64,
    /// Unique certificates forwarded to the Analyzer.
    pub unique_forwarded: u64,
    /// Duplicate certificates seen (not forwarded).
    pub duplicates_seen: u64,
}

/// Shared atomic counters for stats accessible from outside the engine task.
#[derive(Debug)]
struct AtomicStats {
    total_events: AtomicU64,
    unique_forwarded: AtomicU64,
    duplicates_seen: AtomicU64,
}

impl AtomicStats {
    fn new() -> Self {
        Self {
            total_events: AtomicU64::new(0),
            unique_forwarded: AtomicU64::new(0),
            duplicates_seen: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> DeduplicationStats {
        DeduplicationStats {
            total_events: self.total_events.load(Ordering::Relaxed),
            unique_forwarded: self.unique_forwarded.load(Ordering::Relaxed),
            duplicates_seen: self.duplicates_seen.load(Ordering::Relaxed),
        }
    }
}

// ---------------------------------------------------------------------------
// DeduplicationEngine
// ---------------------------------------------------------------------------

/// The deduplication engine tracks which certificate fingerprints have been
/// seen, using an LRU cache bounded by a configurable capacity.
///
/// Key invariant: after a restart, any certificate that was previously observed
/// should NOT have `is_new = true` when observed again, because its fingerprint
/// is already in the LRU cache (loaded from persistent storage).
///
/// The engine also provides an async processing pipeline that:
/// - Consumes `CollectorEvent` from the ring buffer reader
/// - Forwards only unique certificates downstream
/// - Persists new certificates and touches duplicates in SQLite
pub struct DeduplicationEngine {
    /// LRU cache mapping fingerprint → last_seen timestamp (ms).
    cache: LruCache<[u8; 32], i64>,
    /// Shared statistics counters.
    stats: Arc<AtomicStats>,
}

impl DeduplicationEngine {
    /// Create a new deduplication engine with the given cache capacity.
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity)
            .unwrap_or(NonZeroUsize::new(DEFAULT_CACHE_CAPACITY).unwrap());
        Self {
            cache: LruCache::new(cap),
            stats: Arc::new(AtomicStats::new()),
        }
    }

    /// Create a new deduplication engine with the default capacity (100,000).
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_CACHE_CAPACITY)
    }

    /// Get a snapshot of the current deduplication statistics.
    pub fn stats(&self) -> DeduplicationStats {
        self.stats.snapshot()
    }

    /// Reload the fingerprint set from persistent storage.
    ///
    /// Loads the most recently seen fingerprints (up to the cache capacity)
    /// from SQLite, ordered by `last_seen DESC`. This ensures that after a
    /// restart, previously-seen certificates are recognized and not re-reported
    /// as new.
    ///
    /// Returns the number of fingerprints loaded into the cache.
    pub async fn reload_from_storage(
        &mut self,
        storage: &Storage,
    ) -> Result<usize, tlapix_common::storage::StorageError> {
        let capacity = self.cache.cap().get();
        let fingerprints = storage.list_recent_fingerprints(capacity).await?;
        let count = fingerprints.len();

        // Insert in reverse order so that the most recently seen fingerprints
        // end up as the most recently used in the LRU cache.
        // list_recent_fingerprints returns them ordered by last_seen DESC,
        // so the first element is the most recent. We insert from the end
        // so that the most recent ends up at the front of the LRU.
        let now_ms = Utc::now().timestamp_millis();
        for fp in fingerprints.into_iter().rev() {
            self.cache.put(fp, now_ms);
        }

        tracing::info!(
            fingerprints_loaded = count,
            cache_capacity = capacity,
            "Reloaded fingerprint set from persistent storage"
        );

        Ok(count)
    }

    /// Check if a fingerprint has been seen before.
    ///
    /// Returns `true` if the fingerprint is already in the cache (previously
    /// seen), `false` if it's new. Does NOT insert the fingerprint — call
    /// `mark_seen` for that.
    pub fn is_seen(&mut self, fingerprint: &[u8; 32]) -> bool {
        self.cache.get(fingerprint).is_some()
    }

    /// Mark a fingerprint as seen by inserting it into the LRU cache.
    ///
    /// If the cache is at capacity, the least recently used fingerprint is
    /// evicted. Returns `true` if this is a new fingerprint (was not previously
    /// in the cache), `false` if it was already present.
    pub fn mark_seen(&mut self, fingerprint: [u8; 32]) -> bool {
        let now_ms = Utc::now().timestamp_millis();
        if self.cache.get(&fingerprint).is_some() {
            // Already seen — touching it promotes it in the LRU and updates ts
            self.cache.put(fingerprint, now_ms);
            false
        } else {
            self.cache.put(fingerprint, now_ms);
            true
        }
    }

    /// Get the current number of fingerprints in the cache.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Get the cache capacity.
    pub fn capacity(&self) -> usize {
        self.cache.cap().get()
    }

    /// Start the async deduplication pipeline.
    ///
    /// Consumes events from `input_rx`, deduplicates them by fingerprint,
    /// persists to storage, and forwards unique metadata to the returned
    /// output channel.
    ///
    /// The engine runs until the cancellation token is triggered or the input
    /// channel is closed.
    pub fn run(
        mut self,
        mut input_rx: mpsc::Receiver<CollectorEvent>,
        storage: Storage,
        cancel: CancellationToken,
    ) -> mpsc::Receiver<CertificateMetadata> {
        let (output_tx, output_rx) = mpsc::channel(DEFAULT_OUTPUT_CHANNEL_CAPACITY);
        let stats = self.stats.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        let s = stats.snapshot();
                        tracing::info!(
                            total_events = s.total_events,
                            unique_forwarded = s.unique_forwarded,
                            duplicates_seen = s.duplicates_seen,
                            "deduplication engine shutting down"
                        );
                        break;
                    }
                    event = input_rx.recv() => {
                        match event {
                            Some(collector_event) => {
                                Self::handle_event(
                                    &mut self,
                                    collector_event,
                                    &storage,
                                    &output_tx,
                                    &stats,
                                ).await;
                            }
                            None => {
                                tracing::debug!(
                                    "input channel closed, dedup engine stopping"
                                );
                                break;
                            }
                        }
                    }
                }
            }
        });

        output_rx
    }

    /// Handle a single collector event: deduplicate, persist, and optionally
    /// forward downstream.
    async fn handle_event(
        engine: &mut Self,
        event: CollectorEvent,
        storage: &Storage,
        output_tx: &mpsc::Sender<CertificateMetadata>,
        stats: &Arc<AtomicStats>,
    ) {
        stats.total_events.fetch_add(1, Ordering::Relaxed);

        let fingerprint = event.metadata.fingerprint;
        let now_ms = Utc::now().timestamp_millis();

        if engine.cache.get(&fingerprint).is_some() {
            // Duplicate: update timestamp in cache and touch in storage
            engine.cache.put(fingerprint, now_ms);
            stats.duplicates_seen.fetch_add(1, Ordering::Relaxed);

            // Update last_seen and increment connection_count in SQLite
            if let Err(e) = storage.touch_certificate(&fingerprint, now_ms).await {
                tracing::warn!(
                    error = %e,
                    fingerprint = %hex_encode(fingerprint),
                    "failed to touch certificate in storage"
                );
            }
        } else {
            // New certificate: insert into cache, persist, and forward
            engine.cache.put(fingerprint, now_ms);
            stats.unique_forwarded.fetch_add(1, Ordering::Relaxed);

            // Persist full metadata to SQLite
            if let Err(e) = storage.upsert_certificate(&event.metadata).await {
                tracing::warn!(
                    error = %e,
                    fingerprint = %hex_encode(fingerprint),
                    "failed to upsert certificate in storage"
                );
            }

            // Forward unique metadata downstream to the Analyzer
            if output_tx.send(event.metadata).await.is_err() {
                tracing::warn!("downstream output channel closed, dedup cannot forward");
            }
        }
    }
}

/// Encode a fingerprint as a hex string for logging.
fn hex_encode(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tlapix_common::storage::Storage;
    use tlapix_common::types::CertificateMetadata;

    fn make_test_certificate(fingerprint: [u8; 32]) -> CertificateMetadata {
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
            chain_depth: 2,
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

    fn make_collector_event(fingerprint: [u8; 32]) -> CollectorEvent {
        CollectorEvent {
            metadata: make_test_certificate(fingerprint),
            is_truncated: false,
            is_new: true,
        }
    }

    // -----------------------------------------------------------------------
    // Basic LRU cache tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_new_engine_is_empty() {
        let engine = DeduplicationEngine::new(100);
        assert!(engine.is_empty());
        assert_eq!(engine.len(), 0);
        assert_eq!(engine.capacity(), 100);
    }

    #[test]
    fn test_mark_seen_new_fingerprint() {
        let mut engine = DeduplicationEngine::new(100);
        let fp = [1u8; 32];

        // First time seeing this fingerprint — should return true (is new)
        assert!(engine.mark_seen(fp));
        assert_eq!(engine.len(), 1);

        // Second time — should return false (already seen)
        assert!(!engine.mark_seen(fp));
        assert_eq!(engine.len(), 1);
    }

    #[test]
    fn test_is_seen() {
        let mut engine = DeduplicationEngine::new(100);
        let fp = [2u8; 32];

        assert!(!engine.is_seen(&fp));
        engine.mark_seen(fp);
        assert!(engine.is_seen(&fp));
    }

    #[test]
    fn test_lru_eviction() {
        let mut engine = DeduplicationEngine::new(3);

        let fp1 = [1u8; 32];
        let fp2 = [2u8; 32];
        let fp3 = [3u8; 32];
        let fp4 = [4u8; 32];

        engine.mark_seen(fp1);
        engine.mark_seen(fp2);
        engine.mark_seen(fp3);
        assert_eq!(engine.len(), 3);

        // Adding a 4th should evict fp1 (least recently used)
        engine.mark_seen(fp4);
        assert_eq!(engine.len(), 3);
        assert!(!engine.is_seen(&fp1)); // evicted
        assert!(engine.is_seen(&fp2));
        assert!(engine.is_seen(&fp3));
        assert!(engine.is_seen(&fp4));
    }

    #[test]
    fn test_mark_seen_promotes_in_lru() {
        let mut engine = DeduplicationEngine::new(3);

        let fp1 = [1u8; 32];
        let fp2 = [2u8; 32];
        let fp3 = [3u8; 32];
        let fp4 = [4u8; 32];

        engine.mark_seen(fp1);
        engine.mark_seen(fp2);
        engine.mark_seen(fp3);

        // Access fp1 again to promote it
        engine.mark_seen(fp1);

        // Now adding fp4 should evict fp2 (the new LRU), not fp1
        engine.mark_seen(fp4);
        assert!(engine.is_seen(&fp1)); // promoted, not evicted
        assert!(!engine.is_seen(&fp2)); // evicted
        assert!(engine.is_seen(&fp3));
        assert!(engine.is_seen(&fp4));
    }

    // -----------------------------------------------------------------------
    // Storage reload tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_reload_from_storage_empty() {
        let storage = Storage::open_in_memory().await.unwrap();
        let mut engine = DeduplicationEngine::new(100);

        let loaded = engine.reload_from_storage(&storage).await.unwrap();
        assert_eq!(loaded, 0);
        assert!(engine.is_empty());
    }

    #[tokio::test]
    async fn test_reload_from_storage_with_certificates() {
        let storage = Storage::open_in_memory().await.unwrap();

        let fp1 = [1u8; 32];
        let fp2 = [2u8; 32];
        let fp3 = [3u8; 32];

        let mut cert1 = make_test_certificate(fp1);
        cert1.last_seen = Utc::now() - chrono::Duration::hours(3);
        storage.upsert_certificate(&cert1).await.unwrap();

        let mut cert2 = make_test_certificate(fp2);
        cert2.last_seen = Utc::now() - chrono::Duration::hours(2);
        storage.upsert_certificate(&cert2).await.unwrap();

        let mut cert3 = make_test_certificate(fp3);
        cert3.last_seen = Utc::now() - chrono::Duration::hours(1);
        storage.upsert_certificate(&cert3).await.unwrap();

        let mut engine = DeduplicationEngine::new(100);
        let loaded = engine.reload_from_storage(&storage).await.unwrap();

        assert_eq!(loaded, 3);
        assert_eq!(engine.len(), 3);
        assert!(engine.is_seen(&fp1));
        assert!(engine.is_seen(&fp2));
        assert!(engine.is_seen(&fp3));
    }

    #[tokio::test]
    async fn test_reload_respects_capacity_limit() {
        let storage = Storage::open_in_memory().await.unwrap();

        // Insert 5 certificates
        for i in 0..5u8 {
            let mut fp = [0u8; 32];
            fp[0] = i;
            let mut cert = make_test_certificate(fp);
            cert.last_seen = Utc::now() - chrono::Duration::hours((5 - i) as i64);
            storage.upsert_certificate(&cert).await.unwrap();
        }

        // Create engine with capacity 3 — should only load the 3 most recent
        let mut engine = DeduplicationEngine::new(3);
        let loaded = engine.reload_from_storage(&storage).await.unwrap();

        assert_eq!(loaded, 3);
        assert_eq!(engine.len(), 3);

        // The 3 most recent should be loaded (i=2,3,4)
        let mut fp4 = [0u8; 32];
        fp4[0] = 4;
        let mut fp3 = [0u8; 32];
        fp3[0] = 3;
        let mut fp2 = [0u8; 32];
        fp2[0] = 2;

        assert!(engine.is_seen(&fp4));
        assert!(engine.is_seen(&fp3));
        assert!(engine.is_seen(&fp2));

        // The 2 oldest should NOT be loaded
        let mut fp0 = [0u8; 32];
        fp0[0] = 0;
        let mut fp1 = [0u8; 32];
        fp1[0] = 1;

        assert!(!engine.is_seen(&fp0));
        assert!(!engine.is_seen(&fp1));
    }

    #[tokio::test]
    async fn test_previously_seen_not_reported_as_new() {
        let storage = Storage::open_in_memory().await.unwrap();

        let fp = [42u8; 32];
        let cert = make_test_certificate(fp);
        storage.upsert_certificate(&cert).await.unwrap();

        let mut engine = DeduplicationEngine::new(100);
        engine.reload_from_storage(&storage).await.unwrap();

        assert!(engine.is_seen(&fp));
        assert!(!engine.mark_seen(fp));
    }

    #[tokio::test]
    async fn test_reload_ordering_most_recent_promoted() {
        let storage = Storage::open_in_memory().await.unwrap();

        let fp_oldest = [1u8; 32];
        let fp_middle = [2u8; 32];
        let fp_newest = [3u8; 32];

        let mut cert_oldest = make_test_certificate(fp_oldest);
        cert_oldest.last_seen = Utc::now() - chrono::Duration::hours(3);
        storage.upsert_certificate(&cert_oldest).await.unwrap();

        let mut cert_middle = make_test_certificate(fp_middle);
        cert_middle.last_seen = Utc::now() - chrono::Duration::hours(2);
        storage.upsert_certificate(&cert_middle).await.unwrap();

        let mut cert_newest = make_test_certificate(fp_newest);
        cert_newest.last_seen = Utc::now() - chrono::Duration::hours(1);
        storage.upsert_certificate(&cert_newest).await.unwrap();

        let mut engine = DeduplicationEngine::new(3);
        engine.reload_from_storage(&storage).await.unwrap();

        assert!(engine.is_seen(&fp_oldest));
        assert!(engine.is_seen(&fp_middle));
        assert!(engine.is_seen(&fp_newest));

        // Now add a new fingerprint — the oldest should be evicted
        let fp_new = [4u8; 32];
        engine.mark_seen(fp_new);

        assert!(!engine.is_seen(&fp_oldest));
        assert!(engine.is_seen(&fp_middle));
        assert!(engine.is_seen(&fp_newest));
        assert!(engine.is_seen(&fp_new));
    }

    // -----------------------------------------------------------------------
    // Async pipeline tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_run_forwards_unique_certificates() {
        let storage = Storage::open_in_memory().await.unwrap();
        let engine = DeduplicationEngine::new(100);
        let stats = engine.stats.clone();
        let cancel = CancellationToken::new();

        let (input_tx, input_rx) = mpsc::channel(16);
        let mut output_rx = engine.run(input_rx, storage, cancel.clone());

        // Send two events with different fingerprints
        let fp1 = [1u8; 32];
        let fp2 = [2u8; 32];
        input_tx.send(make_collector_event(fp1)).await.unwrap();
        input_tx.send(make_collector_event(fp2)).await.unwrap();

        // Both should be forwarded
        let out1 = tokio::time::timeout(std::time::Duration::from_secs(2), output_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(out1.fingerprint, fp1);

        let out2 = tokio::time::timeout(std::time::Duration::from_secs(2), output_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(out2.fingerprint, fp2);

        let s = stats.snapshot();
        assert_eq!(s.total_events, 2);
        assert_eq!(s.unique_forwarded, 2);
        assert_eq!(s.duplicates_seen, 0);

        cancel.cancel();
    }

    #[tokio::test]
    async fn test_run_filters_duplicates() {
        let storage = Storage::open_in_memory().await.unwrap();
        let engine = DeduplicationEngine::new(100);
        let stats = engine.stats.clone();
        let cancel = CancellationToken::new();

        let (input_tx, input_rx) = mpsc::channel(16);
        let mut output_rx = engine.run(input_rx, storage, cancel.clone());

        // Send the same fingerprint three times
        let fp = [42u8; 32];
        input_tx.send(make_collector_event(fp)).await.unwrap();
        input_tx.send(make_collector_event(fp)).await.unwrap();
        input_tx.send(make_collector_event(fp)).await.unwrap();

        // Only the first should be forwarded
        let out = tokio::time::timeout(std::time::Duration::from_secs(2), output_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(out.fingerprint, fp);

        // Give the engine time to process remaining events
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // No more events should be available
        let maybe =
            tokio::time::timeout(std::time::Duration::from_millis(200), output_rx.recv()).await;
        assert!(maybe.is_err(), "expected timeout, got an event");

        let s = stats.snapshot();
        assert_eq!(s.total_events, 3);
        assert_eq!(s.unique_forwarded, 1);
        assert_eq!(s.duplicates_seen, 2);

        cancel.cancel();
    }

    #[tokio::test]
    async fn test_run_persists_to_storage() {
        let storage = Storage::open_in_memory().await.unwrap();
        let storage_clone = storage.clone();
        let engine = DeduplicationEngine::new(100);
        let cancel = CancellationToken::new();

        let (input_tx, input_rx) = mpsc::channel(16);
        let mut output_rx = engine.run(input_rx, storage, cancel.clone());

        let fp = [99u8; 32];
        // Send the event twice
        input_tx.send(make_collector_event(fp)).await.unwrap();

        // Wait for the first to be forwarded
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), output_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        // Send duplicate
        input_tx.send(make_collector_event(fp)).await.unwrap();

        // Give time for processing
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Verify the certificate was persisted and connection_count updated
        let cert = storage_clone.get_certificate(&fp).await.unwrap();
        assert!(cert.is_some(), "certificate should be persisted");
        let cert = cert.unwrap();
        // connection_count should be 2 (initial 1 from upsert + 1 from touch)
        assert_eq!(cert.connection_count, 2);

        cancel.cancel();
    }

    #[tokio::test]
    async fn test_run_cancellation() {
        let storage = Storage::open_in_memory().await.unwrap();
        let engine = DeduplicationEngine::new(100);
        let cancel = CancellationToken::new();

        let (_input_tx, input_rx) = mpsc::channel::<CollectorEvent>(16);
        let mut output_rx = engine.run(input_rx, storage, cancel.clone());

        // Cancel immediately
        cancel.cancel();

        // Output channel should close
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), output_rx.recv())
            .await
            .expect("timeout");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_run_lru_eviction_re_forwards() {
        let storage = Storage::open_in_memory().await.unwrap();
        // Use a tiny cache to test eviction
        let engine = DeduplicationEngine::new(3);
        let stats = engine.stats.clone();
        let cancel = CancellationToken::new();

        let (input_tx, input_rx) = mpsc::channel(64);
        let mut output_rx = engine.run(input_rx, storage, cancel.clone());

        // Send 4 unique fingerprints (cache can only hold 3)
        let fps: Vec<[u8; 32]> = (0..4u8).map(|i| [i; 32]).collect();
        for fp in &fps {
            input_tx.send(make_collector_event(*fp)).await.unwrap();
        }

        // All 4 should be forwarded as unique
        for fp in &fps {
            let out = tokio::time::timeout(std::time::Duration::from_secs(2), output_rx.recv())
                .await
                .expect("timeout")
                .expect("channel closed");
            assert_eq!(out.fingerprint, *fp);
        }

        // Now send the first fingerprint again — it was evicted from cache,
        // so it should be forwarded again as "new"
        input_tx.send(make_collector_event(fps[0])).await.unwrap();
        let out = tokio::time::timeout(std::time::Duration::from_secs(2), output_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(out.fingerprint, fps[0]);

        let s = stats.snapshot();
        assert_eq!(s.total_events, 5);
        assert_eq!(s.unique_forwarded, 5);
        assert_eq!(s.duplicates_seen, 0);

        cancel.cancel();
    }

    #[tokio::test]
    async fn test_run_with_preloaded_cache() {
        let storage = Storage::open_in_memory().await.unwrap();

        // Pre-load a fingerprint into storage (simulating restart)
        let known_fp = [77u8; 32];
        let cert = make_test_certificate(known_fp);
        storage.upsert_certificate(&cert).await.unwrap();

        // Create engine and reload from storage
        let mut engine = DeduplicationEngine::new(100);
        engine.reload_from_storage(&storage).await.unwrap();

        let stats = engine.stats.clone();
        let cancel = CancellationToken::new();

        let (input_tx, input_rx) = mpsc::channel(16);
        let mut output_rx = engine.run(input_rx, storage, cancel.clone());

        // Send the known fingerprint — should be treated as duplicate
        input_tx.send(make_collector_event(known_fp)).await.unwrap();

        // Send a new fingerprint — should be forwarded
        let new_fp = [88u8; 32];
        input_tx.send(make_collector_event(new_fp)).await.unwrap();

        // Only the new one should come through
        let out = tokio::time::timeout(std::time::Duration::from_secs(2), output_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(out.fingerprint, new_fp);

        // Give time for processing
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let s = stats.snapshot();
        assert_eq!(s.total_events, 2);
        assert_eq!(s.unique_forwarded, 1);
        assert_eq!(s.duplicates_seen, 1);

        cancel.cancel();
    }
}
