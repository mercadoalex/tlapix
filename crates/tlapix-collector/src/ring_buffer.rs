//! Ring buffer reader for consuming `TlsCertEvent` from the BPF ring buffer.
//!
//! The actual BPF ring buffer reading is gated behind `#[cfg(target_os = "linux")]`
//! since `aya` only works on Linux. A trait-based interface allows testing on any platform.

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tlapix_common::bpf::TlsCertEvent;
use tlapix_common::types::CertificateMetadata;

use crate::event_processor::{self, EventProcessError, ProcessedEvent};

/// Trait for reading raw events from a ring buffer source.
///
/// This abstraction allows the actual BPF ring buffer (Linux-only) to be
/// swapped with a mock implementation for testing on any platform.
pub trait RingBufferSource: Send + 'static {
    /// Poll for the next event from the ring buffer.
    /// Returns `None` if the source is exhausted or cancelled.
    fn next_event(&mut self) -> impl std::future::Future<Output = Option<TlsCertEvent>> + Send;
}

/// Configuration for the ring buffer reader.
#[derive(Debug, Clone)]
pub struct RingBufferReaderConfig {
    /// Channel capacity for processed events
    pub channel_capacity: usize,
}

impl Default for RingBufferReaderConfig {
    fn default() -> Self {
        Self {
            channel_capacity: 1024,
        }
    }
}

/// Statistics tracked by the ring buffer reader.
#[derive(Debug, Clone, Default)]
pub struct ReaderStats {
    /// Total events received from the ring buffer
    pub events_received: u64,
    /// Events successfully processed into CertificateMetadata
    pub events_processed: u64,
    /// Events that failed processing (malformed certificates)
    pub events_malformed: u64,
    /// Events with truncated certificate data
    pub events_truncated: u64,
}

/// The ring buffer reader consumes raw `TlsCertEvent` from a source,
/// processes them into `CertificateMetadata`, and sends them downstream.
pub struct RingBufferReader {
    config: RingBufferReaderConfig,
    stats: Arc<std::sync::atomic::AtomicU64>,
}

/// Processed event output sent downstream from the reader.
#[derive(Debug, Clone)]
pub struct CollectorEvent {
    /// The parsed certificate metadata
    pub metadata: CertificateMetadata,
    /// Whether the original certificate data was truncated
    pub is_truncated: bool,
    /// Whether this is a new (previously unseen) certificate
    pub is_new: bool,
}

impl RingBufferReader {
    /// Create a new ring buffer reader with the given configuration.
    pub fn new(config: RingBufferReaderConfig) -> Self {
        Self {
            config,
            stats: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Start reading events from the given source, processing them, and
    /// sending results to the returned channel receiver.
    ///
    /// The reader runs until the cancellation token is triggered or the
    /// source is exhausted.
    pub async fn start<S: RingBufferSource>(
        &self,
        mut source: S,
        cancel: CancellationToken,
    ) -> mpsc::Receiver<CollectorEvent> {
        let (tx, rx) = mpsc::channel(self.config.channel_capacity);

        let _stats = self.stats.clone();

        tokio::spawn(async move {
            let mut stats = ReaderStats::default();

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        tracing::info!(
                            events_received = stats.events_received,
                            events_processed = stats.events_processed,
                            events_malformed = stats.events_malformed,
                            events_truncated = stats.events_truncated,
                            "ring buffer reader shutting down"
                        );
                        break;
                    }
                    event = source.next_event() => {
                        match event {
                            Some(raw_event) => {
                                stats.events_received += 1;
                                Self::handle_event(&raw_event, &tx, &mut stats).await;
                            }
                            None => {
                                tracing::debug!("ring buffer source exhausted");
                                break;
                            }
                        }
                    }
                }
            }
        });

        rx
    }

    /// Process a single event and send it downstream.
    async fn handle_event(
        event: &TlsCertEvent,
        tx: &mpsc::Sender<CollectorEvent>,
        stats: &mut ReaderStats,
    ) {
        match event_processor::process_event(event) {
            Ok(ProcessedEvent {
                metadata,
                is_truncated,
            }) => {
                if is_truncated {
                    stats.events_truncated += 1;
                    tracing::debug!(
                        src_ip = %format_ip(event.src_ip),
                        dst_ip = %format_ip(event.dst_ip),
                        dst_port = event.dst_port,
                        cert_len = event.cert_len,
                        "truncated certificate data (cert_len > 4096)"
                    );
                }

                let collector_event = CollectorEvent {
                    metadata,
                    is_truncated,
                    is_new: event.is_new == 1,
                };

                if tx.send(collector_event).await.is_err() {
                    tracing::warn!("downstream channel closed, stopping reader");
                }

                stats.events_processed += 1;
            }
            Err(EventProcessError::MalformedCertificate {
                reason,
                timestamp_ns,
                src_ip,
                dst_ip,
                dst_port,
                available_bytes,
            }) => {
                stats.events_malformed += 1;
                // Log malformed handshakes with context per requirement 1.5
                tracing::warn!(
                    reason = %reason,
                    timestamp_ns = timestamp_ns,
                    src_ip = %format_ip(src_ip),
                    dst_ip = %format_ip(dst_ip),
                    dst_port = dst_port,
                    available_bytes = available_bytes,
                    "malformed TLS handshake - skipping"
                );
            }
            Err(EventProcessError::PartialExtraction { missing_fields }) => {
                // This shouldn't normally happen since process_event handles
                // partial extraction internally, but log it just in case
                stats.events_malformed += 1;
                tracing::debug!(
                    missing_fields = %missing_fields,
                    "partial certificate extraction"
                );
            }
        }
    }
}

/// Format an IPv4 address from a u32 for logging.
fn format_ip(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF,
    )
}

// ---------------------------------------------------------------------------
// Linux-specific BPF ring buffer source
// ---------------------------------------------------------------------------

/// BPF ring buffer source using `aya::maps::RingBuf` (Linux only).
#[cfg(target_os = "linux")]
pub mod bpf_source {
    use super::*;

    /// A ring buffer source backed by an actual BPF ring buffer map.
    pub struct BpfRingBufferSource {
        ring_buf: aya::maps::RingBuf<aya::maps::MapData>,
    }

    impl BpfRingBufferSource {
        /// Create a new BPF ring buffer source from an aya RingBuf map.
        pub fn new(ring_buf: aya::maps::RingBuf<aya::maps::MapData>) -> Self {
            Self { ring_buf }
        }
    }

    impl RingBufferSource for BpfRingBufferSource {
        async fn next_event(&mut self) -> Option<TlsCertEvent> {
            // aya's RingBuf::next() returns the next item if available.
            // We poll with a small sleep to avoid busy-spinning.
            loop {
                match self.ring_buf.next() {
                    Some(item) => {
                        let data = item.as_ref();
                        if data.len() >= std::mem::size_of::<TlsCertEvent>() {
                            // Safety: TlsCertEvent is repr(C) and we verified the size
                            let event: TlsCertEvent =
                                unsafe { std::ptr::read_unaligned(data.as_ptr() as *const _) };
                            return Some(event);
                        } else {
                            tracing::warn!(
                                data_len = data.len(),
                                expected = std::mem::size_of::<TlsCertEvent>(),
                                "ring buffer item too small, skipping"
                            );
                            continue;
                        }
                    }
                    None => {
                        // No data available, yield and try again
                        tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Mock/channel-based ring buffer source for testing
// ---------------------------------------------------------------------------

/// A channel-based ring buffer source for testing purposes.
/// Events are fed in via the sender side.
pub struct ChannelRingBufferSource {
    receiver: mpsc::Receiver<TlsCertEvent>,
}

impl ChannelRingBufferSource {
    /// Create a new channel-based source with the given capacity.
    /// Returns the source and a sender for feeding events.
    pub fn new(capacity: usize) -> (Self, mpsc::Sender<TlsCertEvent>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self { receiver: rx }, tx)
    }
}

impl RingBufferSource for ChannelRingBufferSource {
    async fn next_event(&mut self) -> Option<TlsCertEvent> {
        self.receiver.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tlapix_common::bpf::TlsCertEvent;

    fn create_test_event_with_cert() -> TlsCertEvent {
        // A minimal self-signed DER certificate for testing
        // This is a real minimal X.509 v3 certificate
        let cert_der = include_bytes!("../test_data/test_cert.der");
        let mut event = TlsCertEvent {
            timestamp_ns: 1_000_000_000,
            src_ip: 0xC0A80001,
            dst_ip: 0x0A000001,
            src_port: 54321,
            dst_port: 443,
            ip_version: 4,
            tls_version: 0x0303,
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

    #[tokio::test]
    async fn test_ring_buffer_reader_processes_events() {
        let reader = RingBufferReader::new(RingBufferReaderConfig::default());
        let (source, tx) = ChannelRingBufferSource::new(16);
        let cancel = CancellationToken::new();

        let mut rx = reader.start(source, cancel.clone()).await;

        // Send a test event with a valid certificate
        let event = create_test_event_with_cert();
        tx.send(event).await.unwrap();

        // Receive the processed event
        let collector_event = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            rx.recv(),
        )
        .await
        .expect("timeout waiting for event")
        .expect("channel closed");

        assert!(!collector_event.is_truncated);
        assert!(collector_event.is_new);
        // The fingerprint should be computed from the actual cert data
        assert_ne!(collector_event.metadata.fingerprint, [0u8; 32]);

        // Shutdown
        cancel.cancel();
    }

    #[tokio::test]
    async fn test_ring_buffer_reader_handles_malformed() {
        let reader = RingBufferReader::new(RingBufferReaderConfig::default());
        let (source, tx) = ChannelRingBufferSource::new(16);
        let cancel = CancellationToken::new();

        let mut rx = reader.start(source, cancel.clone()).await;

        // Send a malformed event (garbage cert data, not truncated)
        let mut event = TlsCertEvent {
            timestamp_ns: 1_000_000_000,
            src_ip: 0xC0A80001,
            dst_ip: 0x0A000001,
            src_port: 54321,
            dst_port: 443,
            ip_version: 4,
            tls_version: 0x0303,
            sni_len: 0,
            sni: [0u8; 256],
            fingerprint: [0u8; 32],
            cert_len: 10,
            cert_data: [0u8; 4096],
            chain_depth: 1,
            issuer_fingerprint: [0u8; 32],
            is_new: 1,
        };
        event.cert_data[..10].copy_from_slice(&[0xFF; 10]);
        tx.send(event).await.unwrap();

        // Send a valid event after the malformed one to verify processing continues
        let valid_event = create_test_event_with_cert();
        tx.send(valid_event).await.unwrap();

        // The malformed event should be skipped, and we should get the valid one
        let collector_event = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            rx.recv(),
        )
        .await
        .expect("timeout waiting for event")
        .expect("channel closed");

        assert!(!collector_event.is_truncated);

        cancel.cancel();
    }

    #[tokio::test]
    async fn test_ring_buffer_reader_cancellation() {
        let reader = RingBufferReader::new(RingBufferReaderConfig::default());
        let (source, _tx) = ChannelRingBufferSource::new(16);
        let cancel = CancellationToken::new();

        let mut rx = reader.start(source, cancel.clone()).await;

        // Cancel immediately
        cancel.cancel();

        // The channel should close
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            rx.recv(),
        )
        .await
        .expect("timeout");

        assert!(result.is_none());
    }
}
