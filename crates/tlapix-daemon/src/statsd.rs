//! StatsD metric exporter for the Tlapix Certificate Guardian.
//!
//! Exports system metrics via the StatsD protocol (UDP) to a configurable endpoint.
//! StatsD is a fire-and-forget protocol — failures are logged but never block
//! the main processing pipeline.
//!
//! Metric names follow the convention `tlapix.<category>.<metric>` and are sent
//! as counters in the format `metric_name:value|c`.
//!
//! # Configuration
//!
//! Controlled by `ObservabilityConfig.statsd_endpoint`. If `None`, the exporter
//! is not started.
//!
//! # Example
//!
//! ```text
//! tlapix.certificates.discovered:5|c
//! tlapix.anomalies.detected:2|c
//! tlapix.predictions.generated:1|c
//! tlapix.actions.executed:3|c
//! tlapix.actions.failed:0|c
//! ```

use std::net::UdpSocket;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use tracing;

/// Accumulated metric counters that can be flushed to StatsD.
///
/// All counters use atomic operations for lock-free concurrent updates.
#[derive(Debug, Default)]
pub struct MetricCounters {
    /// Number of TLS certificates discovered in traffic.
    pub certificates_discovered: AtomicU64,
    /// Number of certificate anomalies detected.
    pub anomalies_detected: AtomicU64,
    /// Number of renewal predictions generated.
    pub predictions_generated: AtomicU64,
    /// Number of action directives successfully executed.
    pub actions_executed: AtomicU64,
    /// Number of action directives that failed execution.
    pub actions_failed: AtomicU64,
}

impl MetricCounters {
    /// Create a new set of zeroed counters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the certificates discovered counter.
    pub fn inc_certificates_discovered(&self) {
        self.certificates_discovered.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the anomalies detected counter.
    pub fn inc_anomalies_detected(&self) {
        self.anomalies_detected.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the predictions generated counter.
    pub fn inc_predictions_generated(&self) {
        self.predictions_generated.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the actions executed counter.
    pub fn inc_actions_executed(&self) {
        self.actions_executed.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the actions failed counter.
    pub fn inc_actions_failed(&self) {
        self.actions_failed.fetch_add(1, Ordering::Relaxed);
    }
}

/// StatsD metric exporter that sends metrics over UDP.
///
/// StatsD is a fire-and-forget protocol: metrics are sent as UDP datagrams
/// without expecting acknowledgment. This makes it lightweight but means
/// delivery is not guaranteed. Failures are logged at the `warn` level.
pub struct StatsdExporter {
    socket: UdpSocket,
    endpoint: String,
}

impl StatsdExporter {
    /// Create a new StatsD exporter that sends metrics to the given endpoint.
    ///
    /// The endpoint should be in the format `host:port` (e.g., `"localhost:8125"`).
    /// This binds a local UDP socket on an ephemeral port.
    ///
    /// # Errors
    ///
    /// Returns an error if the UDP socket cannot be created or connected.
    pub fn new(endpoint: &str) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .context("Failed to bind UDP socket for StatsD exporter")?;

        socket
            .connect(endpoint)
            .with_context(|| format!("Failed to connect StatsD socket to {}", endpoint))?;

        // Set non-blocking so sends never block the caller
        socket
            .set_nonblocking(true)
            .context("Failed to set StatsD socket to non-blocking")?;

        tracing::info!(endpoint = %endpoint, "StatsD exporter initialized");

        Ok(Self {
            socket,
            endpoint: endpoint.to_string(),
        })
    }

    /// Send a single counter metric in StatsD format.
    ///
    /// Format: `metric_name:value|c`
    ///
    /// Failures are logged but do not propagate — StatsD is fire-and-forget.
    pub fn send_counter(&self, name: &str, value: u64) -> Result<()> {
        let message = format_counter(name, value);
        self.send_raw(&message)
    }

    /// Flush all accumulated counters to the StatsD endpoint.
    ///
    /// Reads the current value of each counter and sends it. This does NOT
    /// reset the counters — callers should manage counter lifecycle externally
    /// if reset-on-flush semantics are desired.
    ///
    /// Individual send failures are logged but do not stop the flush of
    /// remaining metrics.
    pub fn flush_metrics(&self, counters: &MetricCounters) -> Result<()> {
        let metrics = [
            (
                "tlapix.certificates.discovered",
                counters.certificates_discovered.load(Ordering::Relaxed),
            ),
            (
                "tlapix.anomalies.detected",
                counters.anomalies_detected.load(Ordering::Relaxed),
            ),
            (
                "tlapix.predictions.generated",
                counters.predictions_generated.load(Ordering::Relaxed),
            ),
            (
                "tlapix.actions.executed",
                counters.actions_executed.load(Ordering::Relaxed),
            ),
            (
                "tlapix.actions.failed",
                counters.actions_failed.load(Ordering::Relaxed),
            ),
        ];

        for (name, value) in &metrics {
            if let Err(e) = self.send_counter(name, *value) {
                tracing::warn!(
                    metric = %name,
                    endpoint = %self.endpoint,
                    error = %e,
                    "Failed to send StatsD metric (fire-and-forget)"
                );
            }
        }

        Ok(())
    }

    /// Send a raw StatsD message over the UDP socket.
    fn send_raw(&self, message: &str) -> Result<()> {
        self.socket
            .send(message.as_bytes())
            .with_context(|| {
                format!(
                    "Failed to send StatsD packet to {}: {}",
                    self.endpoint, message
                )
            })?;
        Ok(())
    }
}

/// Start a periodic flush task that sends accumulated counters every `interval_secs`.
///
/// This spawns a Tokio task that runs until the provided `cancel` token is cancelled.
/// The task sends all current counter values to StatsD at the specified interval.
///
/// # Arguments
///
/// * `exporter` - The StatsD exporter (wrapped in Arc for sharing)
/// * `counters` - The metric counters to flush (wrapped in Arc for sharing)
/// * `interval_secs` - Seconds between flushes (default recommendation: 60)
/// * `cancel` - Cancellation token to stop the periodic task
pub fn start_periodic_flush(
    exporter: Arc<StatsdExporter>,
    counters: Arc<MetricCounters>,
    interval_secs: u64,
    cancel: tokio_util::sync::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        // Skip the first immediate tick
        interval.tick().await;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = exporter.flush_metrics(&counters) {
                        tracing::warn!(error = %e, "StatsD periodic flush failed");
                    }
                }
                _ = cancel.cancelled() => {
                    tracing::info!("StatsD periodic flush task shutting down");
                    break;
                }
            }
        }
    })
}

/// Format a counter metric in StatsD line protocol.
///
/// Returns a string in the format: `name:value|c`
fn format_counter(name: &str, value: u64) -> String {
    format!("{}:{}|c", name, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::time::Duration;

    /// Test that the StatsD counter format is correct.
    #[test]
    fn test_format_counter_basic() {
        assert_eq!(
            format_counter("tlapix.certificates.discovered", 1),
            "tlapix.certificates.discovered:1|c"
        );
    }

    /// Test counter format with zero value.
    #[test]
    fn test_format_counter_zero() {
        assert_eq!(
            format_counter("tlapix.actions.failed", 0),
            "tlapix.actions.failed:0|c"
        );
    }

    /// Test counter format with large value.
    #[test]
    fn test_format_counter_large_value() {
        assert_eq!(
            format_counter("tlapix.anomalies.detected", 999999),
            "tlapix.anomalies.detected:999999|c"
        );
    }

    /// Test that all expected metric names produce valid StatsD format.
    #[test]
    fn test_format_all_metric_names() {
        let metrics = [
            "tlapix.certificates.discovered",
            "tlapix.anomalies.detected",
            "tlapix.predictions.generated",
            "tlapix.actions.executed",
            "tlapix.actions.failed",
        ];

        for name in &metrics {
            let formatted = format_counter(name, 42);
            assert!(formatted.ends_with("|c"), "Should end with |c type indicator");
            assert!(
                formatted.contains(':'),
                "Should contain : separator between name and value"
            );
            let parts: Vec<&str> = formatted.splitn(2, ':').collect();
            assert_eq!(parts[0], *name);
            assert_eq!(parts[1], "42|c");
        }
    }

    /// Test that StatsdExporter can be created with a valid endpoint.
    #[test]
    fn test_exporter_creation() {
        // Bind a local UDP socket to get a valid port
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = receiver.local_addr().unwrap();

        let exporter = StatsdExporter::new(&addr.to_string());
        assert!(exporter.is_ok(), "Should create exporter for valid endpoint");
    }

    /// Test that send_counter sends correctly formatted data over UDP.
    #[test]
    fn test_send_counter_udp() {
        // Set up a local UDP receiver
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = receiver.local_addr().unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        // Create exporter pointing to our receiver
        let exporter = StatsdExporter::new(&addr.to_string()).unwrap();

        // Send a counter metric
        exporter
            .send_counter("tlapix.certificates.discovered", 5)
            .unwrap();

        // Verify the received data
        let mut buf = [0u8; 1024];
        let (len, _src) = receiver.recv_from(&mut buf).unwrap();
        let received = std::str::from_utf8(&buf[..len]).unwrap();

        assert_eq!(received, "tlapix.certificates.discovered:5|c");
    }

    /// Test that flush_metrics sends all counters over UDP.
    #[test]
    fn test_flush_metrics_sends_all() {
        // Set up a local UDP receiver
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = receiver.local_addr().unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        // Create exporter and counters
        let exporter = StatsdExporter::new(&addr.to_string()).unwrap();
        let counters = MetricCounters::new();

        // Set some counter values
        counters
            .certificates_discovered
            .store(10, Ordering::Relaxed);
        counters.anomalies_detected.store(3, Ordering::Relaxed);
        counters.predictions_generated.store(7, Ordering::Relaxed);
        counters.actions_executed.store(2, Ordering::Relaxed);
        counters.actions_failed.store(1, Ordering::Relaxed);

        // Flush all metrics
        exporter.flush_metrics(&counters).unwrap();

        // Collect all received packets
        let mut received_messages = Vec::new();
        let mut buf = [0u8; 1024];
        for _ in 0..5 {
            match receiver.recv_from(&mut buf) {
                Ok((len, _)) => {
                    let msg = std::str::from_utf8(&buf[..len]).unwrap().to_string();
                    received_messages.push(msg);
                }
                Err(_) => break,
            }
        }

        assert_eq!(received_messages.len(), 5, "Should receive 5 metric packets");
        assert!(received_messages.contains(&"tlapix.certificates.discovered:10|c".to_string()));
        assert!(received_messages.contains(&"tlapix.anomalies.detected:3|c".to_string()));
        assert!(received_messages.contains(&"tlapix.predictions.generated:7|c".to_string()));
        assert!(received_messages.contains(&"tlapix.actions.executed:2|c".to_string()));
        assert!(received_messages.contains(&"tlapix.actions.failed:1|c".to_string()));
    }

    /// Test that MetricCounters increment correctly.
    #[test]
    fn test_metric_counters_increment() {
        let counters = MetricCounters::new();

        counters.inc_certificates_discovered();
        counters.inc_certificates_discovered();
        counters.inc_anomalies_detected();
        counters.inc_predictions_generated();
        counters.inc_actions_executed();
        counters.inc_actions_executed();
        counters.inc_actions_executed();
        counters.inc_actions_failed();

        assert_eq!(
            counters.certificates_discovered.load(Ordering::Relaxed),
            2
        );
        assert_eq!(counters.anomalies_detected.load(Ordering::Relaxed), 1);
        assert_eq!(counters.predictions_generated.load(Ordering::Relaxed), 1);
        assert_eq!(counters.actions_executed.load(Ordering::Relaxed), 3);
        assert_eq!(counters.actions_failed.load(Ordering::Relaxed), 1);
    }

    /// Test that MetricCounters starts at zero.
    #[test]
    fn test_metric_counters_default_zero() {
        let counters = MetricCounters::new();

        assert_eq!(
            counters.certificates_discovered.load(Ordering::Relaxed),
            0
        );
        assert_eq!(counters.anomalies_detected.load(Ordering::Relaxed), 0);
        assert_eq!(counters.predictions_generated.load(Ordering::Relaxed), 0);
        assert_eq!(counters.actions_executed.load(Ordering::Relaxed), 0);
        assert_eq!(counters.actions_failed.load(Ordering::Relaxed), 0);
    }

    /// Test that exporter handles unreachable endpoint gracefully (fire-and-forget).
    #[test]
    fn test_send_to_unreachable_does_not_panic() {
        // Use a port that's unlikely to have a listener
        // Note: UDP send to a connected socket may still succeed at the OS level
        // since UDP is connectionless. The packet just gets dropped.
        let exporter = StatsdExporter::new("127.0.0.1:1").unwrap();

        // This should not panic — StatsD is fire-and-forget
        let result = exporter.send_counter("tlapix.test.metric", 1);
        // On most systems, UDP send succeeds even if no one is listening
        // The important thing is it doesn't panic or block
        let _ = result;
    }

    /// Test the periodic flush task with cancellation.
    #[tokio::test]
    async fn test_periodic_flush_cancellation() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = receiver.local_addr().unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();

        let exporter = Arc::new(StatsdExporter::new(&addr.to_string()).unwrap());
        let counters = Arc::new(MetricCounters::new());
        counters
            .certificates_discovered
            .store(1, Ordering::Relaxed);

        let cancel = tokio_util::sync::CancellationToken::new();
        let handle = start_periodic_flush(exporter, counters, 1, cancel.clone());

        // Wait a bit for at least one flush
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // Cancel and wait for task to finish
        cancel.cancel();
        handle.await.unwrap();

        // Verify at least one packet was received
        let mut buf = [0u8; 1024];
        let result = receiver.recv_from(&mut buf);
        assert!(
            result.is_ok(),
            "Should have received at least one metric packet"
        );
    }
}
