//! Local buffer and retry logic for forwarding certificate metadata to the Analyzer.
//!
//! When the Analyzer is unavailable, the Collector buffers up to 10,000 pending
//! metadata records locally. When the buffer is full, the oldest records are
//! discarded (FIFO eviction). The Collector retries forwarding with exponential
//! backoff starting at 30 seconds, up to a maximum total buffering time of 1 hour.
//!
//! Requirements: 1.7, 2.5

use std::collections::VecDeque;
use std::time::Duration;

use tlapix_common::types::CertificateMetadata;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Maximum number of records the buffer can hold.
pub const DEFAULT_BUFFER_CAPACITY: usize = 10_000;

/// Initial retry interval (30 seconds).
pub const INITIAL_RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// Maximum total buffering time before records expire (1 hour).
pub const MAX_BUFFER_DURATION: Duration = Duration::from_secs(3600);

/// Maximum backoff interval cap (capped at 8 minutes to allow multiple retries within 1 hour).
pub const MAX_RETRY_INTERVAL: Duration = Duration::from_secs(480);

/// Statistics tracked by the retry buffer.
#[derive(Debug, Clone, Default)]
pub struct BufferStats {
    /// Current number of records in the buffer.
    pub buffered_count: usize,
    /// Total number of records evicted due to buffer full.
    pub evicted_count: u64,
    /// Total number of retry attempts made.
    pub retry_attempts: u64,
    /// Total number of successful flushes.
    pub successful_flushes: u64,
    /// Total number of records expired (buffered > 1 hour).
    pub expired_count: u64,
}

/// State of the retry mechanism.
#[derive(Debug, Clone)]
struct RetryState {
    /// When the first record was buffered (start of buffering period).
    buffering_started: Option<Instant>,
    /// When the last retry attempt was made.
    last_attempt: Option<Instant>,
    /// Number of consecutive retry attempts without success.
    attempt_count: u32,
    /// Current backoff duration (doubles each attempt).
    current_backoff: Duration,
}

impl RetryState {
    fn new() -> Self {
        Self {
            buffering_started: None,
            last_attempt: None,
            attempt_count: 0,
            current_backoff: INITIAL_RETRY_INTERVAL,
        }
    }

    /// Reset the retry state after a successful flush.
    fn reset(&mut self) {
        self.buffering_started = None;
        self.last_attempt = None;
        self.attempt_count = 0;
        self.current_backoff = INITIAL_RETRY_INTERVAL;
    }

    /// Record a failed retry attempt and advance the backoff.
    fn record_attempt(&mut self) {
        let now = Instant::now();
        if self.buffering_started.is_none() {
            self.buffering_started = Some(now);
        }
        self.last_attempt = Some(now);
        self.attempt_count += 1;
        // Exponential backoff: double the interval, capped at MAX_RETRY_INTERVAL
        self.current_backoff = (self.current_backoff * 2).min(MAX_RETRY_INTERVAL);
    }

    /// Check if the buffer has exceeded the maximum buffering duration.
    fn is_expired(&self, max_duration: Duration) -> bool {
        match self.buffering_started {
            Some(started) => started.elapsed() >= max_duration,
            None => false,
        }
    }

    /// Check if it's time to retry based on the current backoff.
    fn should_retry(&self) -> bool {
        match self.last_attempt {
            Some(last) => last.elapsed() >= self.current_backoff,
            None => true, // No attempt yet, retry immediately
        }
    }
}

/// Configuration for the retry buffer.
#[derive(Debug, Clone)]
pub struct RetryBufferConfig {
    /// Maximum number of records the buffer can hold.
    pub capacity: usize,
    /// Initial retry interval.
    pub initial_retry_interval: Duration,
    /// Maximum total buffering time.
    pub max_buffer_duration: Duration,
}

impl Default for RetryBufferConfig {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_BUFFER_CAPACITY,
            initial_retry_interval: INITIAL_RETRY_INTERVAL,
            max_buffer_duration: MAX_BUFFER_DURATION,
        }
    }
}

/// A trait representing the downstream consumer (Analyzer) that receives metadata.
///
/// This abstraction allows testing without a real Analyzer connection.
pub trait AnalyzerSink: Send + Sync + 'static {
    /// Attempt to send a batch of metadata records to the Analyzer.
    /// Returns `Ok(())` if all records were accepted, or `Err(records)` with
    /// the records that could not be delivered.
    fn send_batch(
        &self,
        records: Vec<CertificateMetadata>,
    ) -> impl std::future::Future<Output = Result<(), Vec<CertificateMetadata>>> + Send;

    /// Check if the Analyzer is currently available.
    fn is_available(&self) -> impl std::future::Future<Output = bool> + Send;
}

/// The retry buffer holds pending metadata records when the Analyzer is unavailable.
///
/// It implements:
/// - FIFO eviction when the buffer reaches capacity (oldest records discarded)
/// - Exponential backoff retry (starting at 30s, doubling each attempt)
/// - Maximum buffering duration of 1 hour (records expire after that)
pub struct RetryBuffer {
    /// The pending records queue (FIFO).
    records: VecDeque<CertificateMetadata>,
    /// Buffer configuration.
    config: RetryBufferConfig,
    /// Current retry state.
    retry_state: RetryState,
    /// Accumulated statistics.
    stats: BufferStats,
}

impl RetryBuffer {
    /// Create a new retry buffer with the given configuration.
    pub fn new(config: RetryBufferConfig) -> Self {
        Self {
            records: VecDeque::with_capacity(config.capacity.min(1024)),
            config,
            retry_state: RetryState::new(),
            stats: BufferStats::default(),
        }
    }

    /// Create a new retry buffer with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(RetryBufferConfig::default())
    }

    /// Push a record into the buffer.
    ///
    /// If the buffer is at capacity, the oldest record is evicted (FIFO).
    /// If the buffer has exceeded the maximum buffering duration, the record
    /// is discarded and the expired count is incremented.
    pub fn push(&mut self, record: CertificateMetadata) {
        // If buffering has exceeded max duration, discard incoming records
        if self.retry_state.is_expired(self.config.max_buffer_duration) {
            self.stats.expired_count += 1;
            tracing::debug!(
                expired_count = self.stats.expired_count,
                "buffer expired (>1 hour), discarding record"
            );
            return;
        }

        // Start tracking buffering time on first push
        if self.retry_state.buffering_started.is_none() {
            self.retry_state.buffering_started = Some(Instant::now());
        }

        // FIFO eviction: if at capacity, remove the oldest record
        if self.records.len() >= self.config.capacity {
            self.records.pop_front();
            self.stats.evicted_count += 1;
            tracing::debug!(
                evicted_count = self.stats.evicted_count,
                capacity = self.config.capacity,
                "buffer full, evicted oldest record (FIFO)"
            );
        }

        self.records.push_back(record);
        self.stats.buffered_count = self.records.len();
    }

    /// Attempt to flush all buffered records to the given sink.
    ///
    /// Returns `true` if the flush was successful (buffer is now empty),
    /// `false` if the flush failed (records remain in buffer).
    pub async fn try_flush<S: AnalyzerSink>(&mut self, sink: &S) -> bool {
        if self.records.is_empty() {
            return true;
        }

        // Check if it's time to retry
        if !self.retry_state.should_retry() {
            return false;
        }

        // Check if the Analyzer is available before attempting
        if !sink.is_available().await {
            self.retry_state.record_attempt();
            self.stats.retry_attempts += 1;
            tracing::debug!(
                attempt = self.retry_state.attempt_count,
                next_backoff_secs = self.retry_state.current_backoff.as_secs(),
                buffered = self.records.len(),
                "analyzer unavailable, will retry after backoff"
            );
            return false;
        }

        // Drain all records and attempt to send
        let batch: Vec<CertificateMetadata> = self.records.drain(..).collect();
        let batch_size = batch.len();

        match sink.send_batch(batch).await {
            Ok(()) => {
                self.retry_state.reset();
                self.stats.successful_flushes += 1;
                self.stats.buffered_count = 0;
                tracing::info!(
                    records_flushed = batch_size,
                    "successfully flushed buffer to analyzer"
                );
                true
            }
            Err(remaining) => {
                // Put the undelivered records back
                for record in remaining.into_iter().rev() {
                    self.records.push_front(record);
                }
                self.retry_state.record_attempt();
                self.stats.retry_attempts += 1;
                self.stats.buffered_count = self.records.len();
                tracing::warn!(
                    buffered = self.records.len(),
                    attempt = self.retry_state.attempt_count,
                    "flush failed, records returned to buffer"
                );
                false
            }
        }
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Get the current number of buffered records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Get the buffer capacity.
    pub fn capacity(&self) -> usize {
        self.config.capacity
    }

    /// Check if the buffer has expired (exceeded max buffering duration).
    pub fn is_expired(&self) -> bool {
        self.retry_state.is_expired(self.config.max_buffer_duration)
    }

    /// Get a snapshot of the current buffer statistics.
    pub fn stats(&self) -> BufferStats {
        BufferStats {
            buffered_count: self.records.len(),
            ..self.stats.clone()
        }
    }

    /// Get the time until the next retry attempt should be made.
    /// Returns `None` if the buffer is empty or expired.
    pub fn time_until_retry(&self) -> Option<Duration> {
        if self.records.is_empty() || self.retry_state.is_expired(self.config.max_buffer_duration) {
            return None;
        }
        match self.retry_state.last_attempt {
            Some(last) => {
                let elapsed = last.elapsed();
                if elapsed >= self.retry_state.current_backoff {
                    Some(Duration::ZERO)
                } else {
                    Some(self.retry_state.current_backoff - elapsed)
                }
            }
            None => Some(Duration::ZERO), // No attempt yet, retry immediately
        }
    }

    /// Clear all buffered records and reset state.
    pub fn clear(&mut self) {
        self.records.clear();
        self.retry_state.reset();
        self.stats.buffered_count = 0;
    }
}

/// A channel-based `AnalyzerSink` implementation that forwards records via an mpsc channel.
///
/// This is the primary production implementation: the Collector pushes records
/// into the channel, and the Analyzer reads from the other end.
pub struct ChannelAnalyzerSink {
    sender: mpsc::Sender<CertificateMetadata>,
}

impl ChannelAnalyzerSink {
    /// Create a new channel-based sink with the given sender.
    pub fn new(sender: mpsc::Sender<CertificateMetadata>) -> Self {
        Self { sender }
    }
}

impl AnalyzerSink for ChannelAnalyzerSink {
    async fn send_batch(
        &self,
        records: Vec<CertificateMetadata>,
    ) -> Result<(), Vec<CertificateMetadata>> {
        let mut failed = Vec::new();
        for record in records {
            if self.sender.send(record.clone()).await.is_err() {
                failed.push(record);
            }
        }
        if failed.is_empty() {
            Ok(())
        } else {
            Err(failed)
        }
    }

    async fn is_available(&self) -> bool {
        // Channel is available if it's not closed
        !self.sender.is_closed()
    }
}

/// Run the buffer flush loop as a background task.
///
/// This function periodically attempts to flush buffered records to the Analyzer.
/// It respects the exponential backoff schedule and stops when cancelled.
///
/// # Arguments
/// * `buffer` - Shared mutable reference to the retry buffer (wrapped in a Mutex)
/// * `sink` - The downstream Analyzer sink
/// * `cancel` - Cancellation token to stop the loop
pub async fn run_flush_loop<S: AnalyzerSink>(
    buffer: std::sync::Arc<tokio::sync::Mutex<RetryBuffer>>,
    sink: std::sync::Arc<S>,
    cancel: CancellationToken,
) {
    tracing::info!("buffer flush loop started");

    loop {
        // Determine how long to sleep before next retry
        let sleep_duration = {
            let buf = buffer.lock().await;
            if buf.is_empty() {
                // Nothing to flush, check again after the initial interval
                INITIAL_RETRY_INTERVAL
            } else if buf.is_expired() {
                tracing::warn!(
                    expired_count = buf.stats().expired_count,
                    "buffer expired, stopping flush attempts"
                );
                // Still check periodically in case new records come in
                // after the buffer is cleared
                INITIAL_RETRY_INTERVAL
            } else {
                buf.time_until_retry().unwrap_or(INITIAL_RETRY_INTERVAL)
            }
        };

        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!("buffer flush loop cancelled");
                break;
            }
            _ = tokio::time::sleep(sleep_duration) => {
                let mut buf = buffer.lock().await;
                if !buf.is_empty() && !buf.is_expired() {
                    buf.try_flush(sink.as_ref()).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    /// A mock AnalyzerSink for testing.
    struct MockSink {
        available: AtomicBool,
        received: tokio::sync::Mutex<Vec<CertificateMetadata>>,
        send_count: AtomicU64,
    }

    impl MockSink {
        fn new(available: bool) -> Self {
            Self {
                available: AtomicBool::new(available),
                received: tokio::sync::Mutex::new(Vec::new()),
                send_count: AtomicU64::new(0),
            }
        }

        fn set_available(&self, available: bool) {
            self.available.store(available, Ordering::SeqCst);
        }

        async fn received_count(&self) -> usize {
            self.received.lock().await.len()
        }
    }

    impl AnalyzerSink for MockSink {
        async fn send_batch(
            &self,
            records: Vec<CertificateMetadata>,
        ) -> Result<(), Vec<CertificateMetadata>> {
            self.send_count.fetch_add(1, Ordering::SeqCst);
            if self.available.load(Ordering::SeqCst) {
                let mut received = self.received.lock().await;
                received.extend(records);
                Ok(())
            } else {
                Err(records)
            }
        }

        async fn is_available(&self) -> bool {
            self.available.load(Ordering::SeqCst)
        }
    }

    /// Helper to create a test CertificateMetadata with a given fingerprint byte.
    fn make_metadata(id: u8) -> CertificateMetadata {
        let mut fingerprint = [0u8; 32];
        fingerprint[0] = id;
        CertificateMetadata {
            fingerprint,
            subject: format!("CN=test-{}", id),
            issuer: "CN=Test CA".to_string(),
            serial_number: format!("{:02x}", id),
            not_before: Utc::now(),
            not_after: Utc::now(),
            sans: vec![format!("test-{}.example.com", id)],
            key_algorithm: "RSA".to_string(),
            key_size: 2048,
            chain_depth: 1,
            issuer_fingerprint: None,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            connection_count: 1,
            source_ip: Some("192.168.0.1".to_string()),
            destination_ip: Some("10.0.0.1".to_string()),
            sni_hostname: Some(format!("test-{}.example.com", id)),
            completeness_flags: 0xFF,
        }
    }

    #[test]
    fn test_buffer_push_within_capacity() {
        let mut buffer = RetryBuffer::new(RetryBufferConfig {
            capacity: 5,
            ..Default::default()
        });

        for i in 0..5 {
            buffer.push(make_metadata(i));
        }

        assert_eq!(buffer.len(), 5);
        assert_eq!(buffer.stats().evicted_count, 0);
    }

    #[test]
    fn test_buffer_fifo_eviction() {
        let mut buffer = RetryBuffer::new(RetryBufferConfig {
            capacity: 3,
            ..Default::default()
        });

        // Fill the buffer
        buffer.push(make_metadata(1));
        buffer.push(make_metadata(2));
        buffer.push(make_metadata(3));
        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.stats().evicted_count, 0);

        // Push one more — oldest (id=1) should be evicted
        buffer.push(make_metadata(4));
        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.stats().evicted_count, 1);

        // The remaining records should be 2, 3, 4 (FIFO order)
        let records: Vec<u8> = buffer.records.iter().map(|r| r.fingerprint[0]).collect();
        assert_eq!(records, vec![2, 3, 4]);
    }

    #[test]
    fn test_buffer_fifo_eviction_multiple() {
        let mut buffer = RetryBuffer::new(RetryBufferConfig {
            capacity: 3,
            ..Default::default()
        });

        // Push 6 records into a buffer of capacity 3
        for i in 0..6 {
            buffer.push(make_metadata(i));
        }

        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.stats().evicted_count, 3);

        // Should have records 3, 4, 5
        let records: Vec<u8> = buffer.records.iter().map(|r| r.fingerprint[0]).collect();
        assert_eq!(records, vec![3, 4, 5]);
    }

    #[test]
    fn test_buffer_capacity_never_exceeded() {
        let capacity = 100;
        let mut buffer = RetryBuffer::new(RetryBufferConfig {
            capacity,
            ..Default::default()
        });

        // Push many more records than capacity
        for i in 0..255 {
            buffer.push(make_metadata(i));
            assert!(
                buffer.len() <= capacity,
                "buffer exceeded capacity: {} > {}",
                buffer.len(),
                capacity
            );
        }

        assert_eq!(buffer.len(), capacity);
        assert_eq!(buffer.stats().evicted_count, 155); // 255 - 100
    }

    #[test]
    fn test_buffer_default_capacity() {
        let buffer = RetryBuffer::with_defaults();
        assert_eq!(buffer.capacity(), DEFAULT_BUFFER_CAPACITY);
        assert_eq!(buffer.capacity(), 10_000);
    }

    #[tokio::test]
    async fn test_flush_success() {
        let sink = Arc::new(MockSink::new(true));
        let mut buffer = RetryBuffer::new(RetryBufferConfig {
            capacity: 10,
            ..Default::default()
        });

        buffer.push(make_metadata(1));
        buffer.push(make_metadata(2));
        buffer.push(make_metadata(3));

        let result = buffer.try_flush(sink.as_ref()).await;
        assert!(result);
        assert!(buffer.is_empty());
        assert_eq!(buffer.stats().successful_flushes, 1);
        assert_eq!(sink.received_count().await, 3);
    }

    #[tokio::test]
    async fn test_flush_failure_returns_records_to_buffer() {
        let sink = Arc::new(MockSink::new(false));
        let mut buffer = RetryBuffer::new(RetryBufferConfig {
            capacity: 10,
            ..Default::default()
        });

        buffer.push(make_metadata(1));
        buffer.push(make_metadata(2));

        let result = buffer.try_flush(sink.as_ref()).await;
        assert!(!result);
        // Records should still be in the buffer
        assert_eq!(buffer.len(), 2);
        assert_eq!(buffer.stats().retry_attempts, 1);
    }

    #[tokio::test]
    async fn test_flush_empty_buffer_returns_true() {
        let sink = Arc::new(MockSink::new(true));
        let mut buffer = RetryBuffer::with_defaults();

        let result = buffer.try_flush(sink.as_ref()).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_flush_resets_retry_state_on_success() {
        let sink = Arc::new(MockSink::new(false));
        let mut buffer = RetryBuffer::new(RetryBufferConfig {
            capacity: 10,
            ..Default::default()
        });

        buffer.push(make_metadata(1));

        // First attempt fails
        buffer.try_flush(sink.as_ref()).await;
        assert_eq!(buffer.stats().retry_attempts, 1);

        // Make sink available
        sink.set_available(true);

        // Need to wait for backoff or force retry
        // Since we just attempted, should_retry will be false until backoff elapses
        // For testing, we'll directly manipulate the state
        buffer.retry_state.last_attempt = Some(Instant::now() - Duration::from_secs(60));

        let result = buffer.try_flush(sink.as_ref()).await;
        assert!(result);
        assert!(buffer.is_empty());
        assert_eq!(buffer.stats().successful_flushes, 1);
    }

    #[tokio::test]
    async fn test_backoff_increases_exponentially() {
        let sink = Arc::new(MockSink::new(false));
        let mut buffer = RetryBuffer::new(RetryBufferConfig {
            capacity: 10,
            initial_retry_interval: Duration::from_secs(30),
            max_buffer_duration: MAX_BUFFER_DURATION,
        });

        buffer.push(make_metadata(1));

        // First attempt — backoff starts at 30s
        buffer.try_flush(sink.as_ref()).await;
        assert_eq!(buffer.retry_state.current_backoff, Duration::from_secs(60));

        // Force retry by moving last_attempt back
        buffer.retry_state.last_attempt = Some(Instant::now() - Duration::from_secs(61));

        // Second attempt — backoff doubles to 120s
        buffer.try_flush(sink.as_ref()).await;
        assert_eq!(buffer.retry_state.current_backoff, Duration::from_secs(120));

        // Force retry
        buffer.retry_state.last_attempt = Some(Instant::now() - Duration::from_secs(121));

        // Third attempt — backoff doubles to 240s
        buffer.try_flush(sink.as_ref()).await;
        assert_eq!(buffer.retry_state.current_backoff, Duration::from_secs(240));

        // Force retry
        buffer.retry_state.last_attempt = Some(Instant::now() - Duration::from_secs(241));

        // Fourth attempt — backoff doubles to 480s (MAX_RETRY_INTERVAL)
        buffer.try_flush(sink.as_ref()).await;
        assert_eq!(buffer.retry_state.current_backoff, Duration::from_secs(480));

        // Force retry
        buffer.retry_state.last_attempt = Some(Instant::now() - Duration::from_secs(481));

        // Fifth attempt — should stay capped at 480s
        buffer.try_flush(sink.as_ref()).await;
        assert_eq!(buffer.retry_state.current_backoff, Duration::from_secs(480));
    }

    #[tokio::test]
    async fn test_buffer_expiry() {
        let mut buffer = RetryBuffer::new(RetryBufferConfig {
            capacity: 10,
            initial_retry_interval: Duration::from_secs(30),
            max_buffer_duration: Duration::from_secs(1), // 1 second for testing
        });

        buffer.push(make_metadata(1));

        // Simulate expiry by setting buffering_started in the past
        buffer.retry_state.buffering_started = Some(Instant::now() - Duration::from_secs(2));

        assert!(buffer.is_expired());

        // New records should be discarded
        buffer.push(make_metadata(2));
        assert_eq!(buffer.len(), 1); // Only the original record
        assert_eq!(buffer.stats().expired_count, 1);
    }

    #[tokio::test]
    async fn test_channel_sink_available() {
        let (tx, _rx) = mpsc::channel::<CertificateMetadata>(10);
        let sink = ChannelAnalyzerSink::new(tx);
        assert!(sink.is_available().await);
    }

    #[tokio::test]
    async fn test_channel_sink_unavailable_when_closed() {
        let (tx, rx) = mpsc::channel::<CertificateMetadata>(10);
        let sink = ChannelAnalyzerSink::new(tx);
        drop(rx); // Close the receiver
        assert!(!sink.is_available().await);
    }

    #[tokio::test]
    async fn test_channel_sink_send_batch() {
        let (tx, mut rx) = mpsc::channel::<CertificateMetadata>(10);
        let sink = ChannelAnalyzerSink::new(tx);

        let records = vec![make_metadata(1), make_metadata(2), make_metadata(3)];
        let result = sink.send_batch(records).await;
        assert!(result.is_ok());

        // Verify records were sent
        let r1 = rx.recv().await.unwrap();
        assert_eq!(r1.fingerprint[0], 1);
        let r2 = rx.recv().await.unwrap();
        assert_eq!(r2.fingerprint[0], 2);
        let r3 = rx.recv().await.unwrap();
        assert_eq!(r3.fingerprint[0], 3);
    }

    #[tokio::test]
    async fn test_flush_loop_cancellation() {
        let buffer = Arc::new(tokio::sync::Mutex::new(RetryBuffer::with_defaults()));
        let sink = Arc::new(MockSink::new(true));
        let cancel = CancellationToken::new();

        let handle = tokio::spawn(run_flush_loop(buffer.clone(), sink.clone(), cancel.clone()));

        // Cancel immediately
        cancel.cancel();

        // Should complete without hanging
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("flush loop did not stop after cancellation")
            .expect("flush loop panicked");
    }

    #[test]
    fn test_clear_resets_buffer() {
        let mut buffer = RetryBuffer::new(RetryBufferConfig {
            capacity: 10,
            ..Default::default()
        });

        buffer.push(make_metadata(1));
        buffer.push(make_metadata(2));
        assert_eq!(buffer.len(), 2);

        buffer.clear();
        assert!(buffer.is_empty());
        assert_eq!(buffer.stats().buffered_count, 0);
    }

    #[test]
    fn test_time_until_retry_empty_buffer() {
        let buffer = RetryBuffer::with_defaults();
        assert_eq!(buffer.time_until_retry(), None);
    }
}
