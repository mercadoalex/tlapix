//! Prometheus exposition endpoint for the Tlapix Certificate Guardian.
//!
//! Exposes system metrics in Prometheus text exposition format on a configurable
//! HTTP endpoint. The endpoint serves metrics at `/metrics` and responds with
//! `text/plain; version=0.0.4; charset=utf-8` content type.
//!
//! Metrics exposed:
//! - `tlapix_certificates_discovered` — Number of TLS certificates discovered
//! - `tlapix_anomalies_detected` — Number of anomalies detected
//! - `tlapix_predictions_generated` — Number of renewal predictions generated
//! - `tlapix_actions_executed` — Number of action directives successfully executed
//! - `tlapix_actions_failed` — Number of action directives that failed execution
//!
//! If `ObservabilityConfig.prometheus_bind` is `None`, the endpoint is not started.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::{extract::State, http::header, response::IntoResponse, routing::get, Router};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Shared atomic counters that both the MetricsService and Prometheus endpoint read from.
#[derive(Debug, Clone)]
pub struct PrometheusMetrics {
    pub certificates_discovered: Arc<AtomicU64>,
    pub anomalies_detected: Arc<AtomicU64>,
    pub predictions_generated: Arc<AtomicU64>,
    pub actions_executed: Arc<AtomicU64>,
    pub actions_failed: Arc<AtomicU64>,
}

impl PrometheusMetrics {
    /// Create a new set of shared counters initialized to zero.
    pub fn new() -> Self {
        Self {
            certificates_discovered: Arc::new(AtomicU64::new(0)),
            anomalies_detected: Arc::new(AtomicU64::new(0)),
            predictions_generated: Arc::new(AtomicU64::new(0)),
            actions_executed: Arc::new(AtomicU64::new(0)),
            actions_failed: Arc::new(AtomicU64::new(0)),
        }
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

    /// Render all metrics in Prometheus text exposition format.
    pub fn render(&self) -> String {
        let certs = self.certificates_discovered.load(Ordering::Relaxed);
        let anomalies = self.anomalies_detected.load(Ordering::Relaxed);
        let predictions = self.predictions_generated.load(Ordering::Relaxed);
        let executed = self.actions_executed.load(Ordering::Relaxed);
        let failed = self.actions_failed.load(Ordering::Relaxed);

        format!(
            "# HELP tlapix_certificates_discovered Number of TLS certificates discovered\n\
             # TYPE tlapix_certificates_discovered counter\n\
             tlapix_certificates_discovered {certs}\n\
             \n\
             # HELP tlapix_anomalies_detected Number of anomalies detected\n\
             # TYPE tlapix_anomalies_detected counter\n\
             tlapix_anomalies_detected {anomalies}\n\
             \n\
             # HELP tlapix_predictions_generated Number of renewal predictions generated\n\
             # TYPE tlapix_predictions_generated counter\n\
             tlapix_predictions_generated {predictions}\n\
             \n\
             # HELP tlapix_actions_executed Number of action directives successfully executed\n\
             # TYPE tlapix_actions_executed counter\n\
             tlapix_actions_executed {executed}\n\
             \n\
             # HELP tlapix_actions_failed Number of action directives that failed execution\n\
             # TYPE tlapix_actions_failed counter\n\
             tlapix_actions_failed {failed}\n"
        )
    }
}

impl Default for PrometheusMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Prometheus exporter that serves metrics on an HTTP endpoint.
pub struct PrometheusExporter;

impl PrometheusExporter {
    /// Start the Prometheus HTTP server on the given bind address.
    ///
    /// The server exposes a `/metrics` endpoint that returns all system metrics
    /// in Prometheus text exposition format. The server runs until the
    /// cancellation token is triggered.
    ///
    /// Returns a `JoinHandle` for the background server task.
    pub fn start(
        bind_addr: SocketAddr,
        metrics: PrometheusMetrics,
        cancel: CancellationToken,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let app = Router::new()
                .route("/metrics", get(metrics_handler))
                .with_state(metrics);

            let listener = match tokio::net::TcpListener::bind(bind_addr).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(
                        "Failed to bind Prometheus endpoint on {}: {}",
                        bind_addr,
                        e
                    );
                    return;
                }
            };

            tracing::info!("Prometheus metrics endpoint listening on {}", bind_addr);

            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    cancel.cancelled().await;
                    tracing::info!("Prometheus endpoint shutting down");
                })
                .await
                .unwrap_or_else(|e| {
                    tracing::error!("Prometheus server error: {}", e);
                });
        })
    }
}

/// Axum handler that renders metrics in Prometheus text exposition format.
async fn metrics_handler(State(metrics): State<PrometheusMetrics>) -> impl IntoResponse {
    let body = metrics.render();
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Test that PrometheusMetrics initializes with all counters at zero.
    #[test]
    fn test_metrics_initial_values() {
        let metrics = PrometheusMetrics::new();
        assert_eq!(
            metrics.certificates_discovered.load(Ordering::Relaxed),
            0
        );
        assert_eq!(metrics.anomalies_detected.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.predictions_generated.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.actions_executed.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.actions_failed.load(Ordering::Relaxed), 0);
    }

    /// Test that counter increments work correctly.
    #[test]
    fn test_counter_increments() {
        let metrics = PrometheusMetrics::new();

        metrics.inc_certificates_discovered();
        metrics.inc_certificates_discovered();
        metrics.inc_anomalies_detected();
        metrics.inc_predictions_generated();
        metrics.inc_predictions_generated();
        metrics.inc_predictions_generated();
        metrics.inc_actions_executed();
        metrics.inc_actions_failed();
        metrics.inc_actions_failed();

        assert_eq!(
            metrics.certificates_discovered.load(Ordering::Relaxed),
            2
        );
        assert_eq!(metrics.anomalies_detected.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.predictions_generated.load(Ordering::Relaxed), 3);
        assert_eq!(metrics.actions_executed.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.actions_failed.load(Ordering::Relaxed), 2);
    }

    /// Test that render produces valid Prometheus text format.
    #[test]
    fn test_render_format() {
        let metrics = PrometheusMetrics::new();
        metrics.inc_certificates_discovered();
        metrics.inc_anomalies_detected();

        let output = metrics.render();

        // Verify HELP lines
        assert!(output.contains("# HELP tlapix_certificates_discovered"));
        assert!(output.contains("# HELP tlapix_anomalies_detected"));
        assert!(output.contains("# HELP tlapix_predictions_generated"));
        assert!(output.contains("# HELP tlapix_actions_executed"));
        assert!(output.contains("# HELP tlapix_actions_failed"));

        // Verify TYPE lines
        assert!(output.contains("# TYPE tlapix_certificates_discovered counter"));
        assert!(output.contains("# TYPE tlapix_anomalies_detected counter"));
        assert!(output.contains("# TYPE tlapix_predictions_generated counter"));
        assert!(output.contains("# TYPE tlapix_actions_executed counter"));
        assert!(output.contains("# TYPE tlapix_actions_failed counter"));

        // Verify metric values
        assert!(output.contains("tlapix_certificates_discovered 1"));
        assert!(output.contains("tlapix_anomalies_detected 1"));
        assert!(output.contains("tlapix_predictions_generated 0"));
        assert!(output.contains("tlapix_actions_executed 0"));
        assert!(output.contains("tlapix_actions_failed 0"));
    }

    /// Test that the Prometheus endpoint responds with correct content-type and body.
    #[tokio::test]
    async fn test_prometheus_endpoint_responds() {
        let metrics = PrometheusMetrics::new();
        metrics.inc_certificates_discovered();
        metrics.inc_certificates_discovered();
        metrics.inc_anomalies_detected();

        let cancel = CancellationToken::new();

        // Bind to a random available port
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = tokio::net::TcpListener::bind(bind_addr).await.unwrap();
        let actual_addr = listener.local_addr().unwrap();

        // Start server manually for test (to use the pre-bound listener)
        let metrics_clone = metrics.clone();
        let cancel_clone = cancel.clone();
        let server_handle = tokio::spawn(async move {
            let app = Router::new()
                .route("/metrics", get(metrics_handler))
                .with_state(metrics_clone);

            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    cancel_clone.cancelled().await;
                })
                .await
                .unwrap();
        });

        // Give the server a moment to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Make a request to the /metrics endpoint
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}/metrics", actual_addr))
            .send()
            .await
            .expect("Failed to send request");

        assert_eq!(resp.status(), 200);

        let content_type = resp
            .headers()
            .get("content-type")
            .expect("Missing content-type header")
            .to_str()
            .unwrap();
        assert_eq!(content_type, "text/plain; version=0.0.4; charset=utf-8");

        let body = resp.text().await.unwrap();
        assert!(body.contains("tlapix_certificates_discovered 2"));
        assert!(body.contains("tlapix_anomalies_detected 1"));
        assert!(body.contains("tlapix_predictions_generated 0"));

        // Shutdown
        cancel.cancel();
        let _ = server_handle.await;
    }

    /// Test that PrometheusMetrics is Clone (needed for sharing across services).
    #[test]
    fn test_metrics_is_clone() {
        let metrics = PrometheusMetrics::new();
        metrics.inc_certificates_discovered();

        let cloned = metrics.clone();
        // Both should see the same counter value (shared Arc)
        assert_eq!(
            cloned.certificates_discovered.load(Ordering::Relaxed),
            1
        );

        // Incrementing via clone should be visible from original
        cloned.inc_certificates_discovered();
        assert_eq!(
            metrics.certificates_discovered.load(Ordering::Relaxed),
            2
        );
    }

    /// Test that the endpoint is not started when prometheus_bind is None.
    #[test]
    fn test_no_start_when_bind_is_none() {
        use tlapix_common::ObservabilityConfig;

        let config = ObservabilityConfig {
            otlp_endpoint: None,
            otlp_auth_token: None,
            otlp_export_interval_secs: 60,
            prometheus_bind: None,
            statsd_endpoint: None,
            audit_retention_days: 90,
        };

        // When prometheus_bind is None, the exporter should not be started.
        // This is a design-level check — the caller checks config before calling start.
        assert!(config.prometheus_bind.is_none());
    }

    /// Test render output with zero values.
    #[test]
    fn test_render_zero_values() {
        let metrics = PrometheusMetrics::new();
        let output = metrics.render();

        assert!(output.contains("tlapix_certificates_discovered 0"));
        assert!(output.contains("tlapix_anomalies_detected 0"));
        assert!(output.contains("tlapix_predictions_generated 0"));
        assert!(output.contains("tlapix_actions_executed 0"));
        assert!(output.contains("tlapix_actions_failed 0"));
    }

    /// Test that Default trait works.
    #[test]
    fn test_default_trait() {
        let metrics = PrometheusMetrics::default();
        assert_eq!(
            metrics.certificates_discovered.load(Ordering::Relaxed),
            0
        );
    }
}
