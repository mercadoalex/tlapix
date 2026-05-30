//! Independent multi-target export service for the Tlapix Certificate Guardian.
//!
//! Configures multiple simultaneous export targets (OTLP, Prometheus, StatsD,
//! and webhooks) that operate independently. Failure of one export channel
//! does not affect delivery to other channels.
//!
//! Validates: Requirement 10.10

use std::sync::Arc;

use anyhow::Result;
use tracing::warn;

use tlapix_common::config::{ObservabilityConfig, WebhookConfig};

use crate::metrics::MetricsService;
use crate::prometheus::PrometheusMetrics;
use crate::statsd::{MetricCounters, StatsdExporter};
use crate::webhooks::{WebhookDispatcher, WebhookEvent};

/// Represents an export event that can be fanned out to all channels.
#[derive(Debug, Clone)]
pub struct ExportEvent {
    /// Correlation ID for cross-referencing with audit trail
    pub correlation_id: String,
    /// Hex-encoded SHA-256 fingerprint of the affected certificate
    pub cert_fingerprint: String,
    /// The action type (alert, renew, protect, isolate)
    pub action_type: String,
    /// Severity level (low, medium, high, critical)
    pub severity: String,
    /// ISO 8601 timestamp
    pub timestamp: String,
    /// The metric to record
    pub metric_name: MetricName,
    /// Optional reasoning for the action
    pub reasoning: Option<String>,
}

/// Named metrics that the export service can record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetricName {
    CertificatesDiscovered,
    AnomaliesDetected,
    PredictionsGenerated,
    ActionsExecuted,
    ActionsFailed,
}

/// Health status of an individual export channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelHealth {
    /// Channel is operating normally
    Healthy,
    /// Channel encountered an error but may recover
    Degraded,
    /// Channel is not configured / disabled
    Disabled,
}

/// Per-channel health tracking.
#[derive(Debug, Clone)]
pub struct ChannelStatus {
    pub otlp: ChannelHealth,
    pub prometheus: ChannelHealth,
    pub statsd: ChannelHealth,
    pub webhooks: ChannelHealth,
}

/// Unified export service that fans out events to all configured channels.
///
/// Each channel operates independently — errors in one channel do not
/// propagate to or affect delivery to other channels.
pub struct ExportService {
    /// OTLP metrics exporter (may be None if not configured)
    otlp: Option<MetricsService>,
    /// Prometheus shared atomic counters (may be None if not configured)
    prometheus: Option<PrometheusMetrics>,
    /// StatsD exporter (may be None if not configured)
    statsd: Option<Arc<StatsdExporter>>,
    /// StatsD metric counters (shared with periodic flush task)
    statsd_counters: Option<Arc<MetricCounters>>,
    /// Webhook dispatcher for action notifications
    webhooks: Option<WebhookDispatcher>,
    /// Per-channel health status
    health: Arc<tokio::sync::RwLock<ChannelStatus>>,
}

impl ExportService {
    /// Create a new export service from the observability configuration.
    ///
    /// Initializes all configured export channels. Channels with `None`
    /// configuration are disabled and will not receive events.
    pub fn new(config: &ObservabilityConfig, webhook_configs: Vec<WebhookConfig>) -> Result<Self> {
        // Initialize OTLP if endpoint is configured
        let otlp = if config.otlp_endpoint.is_some() {
            Some(MetricsService::init(config)?)
        } else {
            None
        };

        // Initialize Prometheus if bind address is configured
        let prometheus = config.prometheus_bind.map(|_| PrometheusMetrics::new());

        // Initialize StatsD if endpoint is configured
        let (statsd, statsd_counters) = if let Some(ref endpoint) = config.statsd_endpoint {
            match StatsdExporter::new(endpoint) {
                Ok(exporter) => (
                    Some(Arc::new(exporter)),
                    Some(Arc::new(MetricCounters::new())),
                ),
                Err(e) => {
                    warn!(error = %e, "Failed to initialize StatsD exporter");
                    (None, None)
                }
            }
        } else {
            (None, None)
        };

        // Initialize webhooks if any endpoints are configured
        let webhooks = if webhook_configs.is_empty() {
            None
        } else {
            Some(WebhookDispatcher::new(webhook_configs))
        };

        let health = ChannelStatus {
            otlp: if otlp.is_some() {
                ChannelHealth::Healthy
            } else {
                ChannelHealth::Disabled
            },
            prometheus: if prometheus.is_some() {
                ChannelHealth::Healthy
            } else {
                ChannelHealth::Disabled
            },
            statsd: if statsd.is_some() {
                ChannelHealth::Healthy
            } else {
                ChannelHealth::Disabled
            },
            webhooks: if webhooks.is_some() {
                ChannelHealth::Healthy
            } else {
                ChannelHealth::Disabled
            },
        };

        Ok(Self {
            otlp,
            prometheus,
            statsd,
            statsd_counters,
            webhooks,
            health: Arc::new(tokio::sync::RwLock::new(health)),
        })
    }

    /// Record an event across all configured export channels.
    ///
    /// Each channel is invoked independently. If one channel fails,
    /// the others continue to receive the event. Errors are logged
    /// but do not propagate.
    pub async fn record_event(&self, event: &ExportEvent) {
        // Channel 1: OTLP (synchronous counter increment, always fast)
        if let Some(ref otlp) = self.otlp {
            self.record_otlp(otlp, event);
        }

        // Channel 2: Prometheus (atomic counter, always available)
        if let Some(ref prom) = self.prometheus {
            self.record_prometheus(prom, event);
        }

        // Channel 3: StatsD (fire-and-forget UDP, spawned independently)
        if let Some(ref counters) = self.statsd_counters {
            self.record_statsd(counters, event);
            // Optionally flush immediately via the exporter
            if let Some(ref exporter) = self.statsd {
                let exporter = exporter.clone();
                let counters = counters.clone();
                tokio::spawn(async move {
                    if let Err(e) = exporter.flush_metrics(&counters) {
                        warn!(error = %e, "StatsD flush failed");
                    }
                });
            }
        }

        // Channel 4: Webhooks (async dispatch, independent of other channels)
        if let Some(ref webhooks) = self.webhooks {
            // Only dispatch webhooks for action events
            if matches!(
                event.metric_name,
                MetricName::ActionsExecuted | MetricName::ActionsFailed
            ) {
                let webhook_event = WebhookEvent {
                    correlation_id: event.correlation_id.clone(),
                    cert_fingerprint: event.cert_fingerprint.clone(),
                    action_type: event.action_type.clone(),
                    severity: event.severity.clone(),
                    timestamp: event.timestamp.clone(),
                    reasoning: event.reasoning.clone(),
                };
                let results = webhooks.dispatch(&webhook_event).await;
                let any_failed = results.iter().any(|r| !r.success);
                if any_failed {
                    let mut h = self.health.write().await;
                    h.webhooks = ChannelHealth::Degraded;
                }
            }
        }
    }

    /// Record a metric to the OTLP channel.
    fn record_otlp(&self, otlp: &MetricsService, event: &ExportEvent) {
        match event.metric_name {
            MetricName::CertificatesDiscovered => {
                otlp.record_certificate_discovered();
            }
            MetricName::AnomaliesDetected => {
                otlp.record_anomaly_detected();
            }
            MetricName::PredictionsGenerated => {
                otlp.record_prediction_generated();
            }
            MetricName::ActionsExecuted => {
                otlp.record_action_executed();
            }
            MetricName::ActionsFailed => {
                otlp.record_action_failed();
            }
        }
    }

    /// Record a metric to the Prometheus channel.
    fn record_prometheus(&self, prom: &PrometheusMetrics, event: &ExportEvent) {
        match event.metric_name {
            MetricName::CertificatesDiscovered => {
                prom.inc_certificates_discovered();
            }
            MetricName::AnomaliesDetected => {
                prom.inc_anomalies_detected();
            }
            MetricName::PredictionsGenerated => {
                prom.inc_predictions_generated();
            }
            MetricName::ActionsExecuted => {
                prom.inc_actions_executed();
            }
            MetricName::ActionsFailed => {
                prom.inc_actions_failed();
            }
        }
    }

    /// Record a metric to the StatsD channel.
    fn record_statsd(&self, counters: &MetricCounters, event: &ExportEvent) {
        match event.metric_name {
            MetricName::CertificatesDiscovered => {
                counters.inc_certificates_discovered();
            }
            MetricName::AnomaliesDetected => {
                counters.inc_anomalies_detected();
            }
            MetricName::PredictionsGenerated => {
                counters.inc_predictions_generated();
            }
            MetricName::ActionsExecuted => {
                counters.inc_actions_executed();
            }
            MetricName::ActionsFailed => {
                counters.inc_actions_failed();
            }
        }
    }

    /// Get the current health status of all channels.
    pub async fn channel_status(&self) -> ChannelStatus {
        self.health.read().await.clone()
    }

    /// Get a reference to the Prometheus metrics (if configured).
    pub fn prometheus(&self) -> Option<&PrometheusMetrics> {
        self.prometheus.as_ref()
    }

    /// Get a reference to the StatsD exporter (if configured).
    pub fn statsd(&self) -> Option<&Arc<StatsdExporter>> {
        self.statsd.as_ref()
    }

    /// Get a reference to the StatsD counters (if configured).
    pub fn statsd_counters(&self) -> Option<&Arc<MetricCounters>> {
        self.statsd_counters.as_ref()
    }

    /// Get a reference to the OTLP metrics service (if configured).
    pub fn otlp(&self) -> Option<&MetricsService> {
        self.otlp.as_ref()
    }

    /// Get a reference to the webhook dispatcher (if configured).
    pub fn webhooks(&self) -> Option<&WebhookDispatcher> {
        self.webhooks.as_ref()
    }

    /// Check if any export channels are configured.
    pub fn has_any_channel(&self) -> bool {
        self.otlp.is_some()
            || self.prometheus.is_some()
            || self.statsd.is_some()
            || self.webhooks.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::atomic::Ordering;

    fn config_all_disabled() -> ObservabilityConfig {
        ObservabilityConfig {
            otlp_endpoint: None,
            otlp_auth_token: None,
            otlp_export_interval_secs: 60,
            prometheus_bind: None,
            statsd_endpoint: None,
            audit_retention_days: 90,
        }
    }

    fn make_event(metric: MetricName) -> ExportEvent {
        ExportEvent {
            correlation_id: "test-corr-001".to_string(),
            cert_fingerprint: "aa".repeat(32),
            action_type: "alert".to_string(),
            severity: "critical".to_string(),
            timestamp: "2024-06-15T12:00:00Z".to_string(),
            metric_name: metric,
            reasoning: Some("Test event".to_string()),
        }
    }

    #[test]
    fn test_export_service_no_channels() {
        let config = config_all_disabled();
        let service = ExportService::new(&config, vec![]).expect("Should create with no channels");
        assert!(!service.has_any_channel());
    }

    #[test]
    fn test_export_service_with_prometheus() {
        let config = ObservabilityConfig {
            prometheus_bind: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))),
            ..config_all_disabled()
        };
        let service = ExportService::new(&config, vec![]).expect("Should create");
        assert!(service.has_any_channel());
        assert!(service.prometheus().is_some());
        assert!(service.statsd().is_none());
        assert!(service.otlp().is_none());
        assert!(service.webhooks().is_none());
    }

    #[test]
    fn test_export_service_with_statsd() {
        // Bind a local UDP socket to get a valid port for StatsD
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = receiver.local_addr().unwrap();

        let config = ObservabilityConfig {
            statsd_endpoint: Some(addr.to_string()),
            ..config_all_disabled()
        };
        let service = ExportService::new(&config, vec![]).expect("Should create");
        assert!(service.has_any_channel());
        assert!(service.statsd().is_some());
        assert!(service.statsd_counters().is_some());
        assert!(service.prometheus().is_none());
    }

    #[test]
    fn test_export_service_with_webhooks() {
        let webhook_configs = vec![WebhookConfig {
            endpoint: "http://localhost:9999/hook".to_string(),
            timeout_secs: 10,
            retry_max: 3,
            retry_base_secs: 1,
        }];
        let config = config_all_disabled();
        let service = ExportService::new(&config, webhook_configs).expect("Should create");
        assert!(service.has_any_channel());
        assert!(service.webhooks().is_some());
    }

    #[test]
    fn test_export_service_multiple_channels() {
        // Bind a local UDP socket for StatsD
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = receiver.local_addr().unwrap();

        let config = ObservabilityConfig {
            prometheus_bind: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))),
            statsd_endpoint: Some(addr.to_string()),
            ..config_all_disabled()
        };
        let webhook_configs = vec![WebhookConfig {
            endpoint: "http://localhost:9999/hook".to_string(),
            timeout_secs: 10,
            retry_max: 3,
            retry_base_secs: 1,
        }];
        let service = ExportService::new(&config, webhook_configs).expect("Should create");
        assert!(service.has_any_channel());
        assert!(service.prometheus().is_some());
        assert!(service.statsd().is_some());
        assert!(service.webhooks().is_some());
    }

    #[tokio::test]
    async fn test_record_event_prometheus_receives() {
        let config = ObservabilityConfig {
            prometheus_bind: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))),
            ..config_all_disabled()
        };
        let service = ExportService::new(&config, vec![]).expect("Should create");

        let event = make_event(MetricName::CertificatesDiscovered);
        service.record_event(&event).await;

        // Prometheus counter should be incremented
        let prom = service.prometheus().unwrap();
        assert_eq!(prom.certificates_discovered.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_record_event_multiple_increments() {
        let config = ObservabilityConfig {
            prometheus_bind: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))),
            ..config_all_disabled()
        };
        let service = ExportService::new(&config, vec![]).expect("Should create");

        for _ in 0..5 {
            let event = make_event(MetricName::AnomaliesDetected);
            service.record_event(&event).await;
        }

        let prom = service.prometheus().unwrap();
        assert_eq!(prom.anomalies_detected.load(Ordering::Relaxed), 5);
    }

    #[tokio::test]
    async fn test_channel_failure_isolation_statsd_unreachable() {
        // StatsD pointing to unreachable endpoint should not affect Prometheus
        // Use a non-routable address for StatsD
        let config = ObservabilityConfig {
            prometheus_bind: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))),
            statsd_endpoint: Some("192.0.2.1:1".to_string()),
            ..config_all_disabled()
        };
        let service = ExportService::new(&config, vec![]).expect("Should create");

        let event = make_event(MetricName::ActionsExecuted);
        service.record_event(&event).await;

        // Give the spawned StatsD task a moment to attempt
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Prometheus should still have received the event
        let prom = service.prometheus().unwrap();
        assert_eq!(prom.actions_executed.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_channel_failure_isolation_webhook_fails() {
        // Webhook pointing to unreachable endpoint should not affect Prometheus
        let config = ObservabilityConfig {
            prometheus_bind: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))),
            ..config_all_disabled()
        };
        let webhook_configs = vec![WebhookConfig {
            endpoint: "http://192.0.2.1:1/hook".to_string(),
            timeout_secs: 1,
            retry_max: 0, // no retries for speed
            retry_base_secs: 1,
        }];
        let service = ExportService::new(&config, webhook_configs).expect("Should create");

        // Use ActionsExecuted to trigger webhook dispatch
        let event = make_event(MetricName::ActionsExecuted);
        service.record_event(&event).await;

        // Prometheus should still have received the event despite webhook failure
        let prom = service.prometheus().unwrap();
        assert_eq!(prom.actions_executed.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_disabled_channels_not_affected() {
        // Only Prometheus enabled — StatsD and webhooks are None
        let config = ObservabilityConfig {
            prometheus_bind: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))),
            ..config_all_disabled()
        };
        let service = ExportService::new(&config, vec![]).expect("Should create");

        let event = make_event(MetricName::PredictionsGenerated);
        service.record_event(&event).await;

        // Should not panic and Prometheus should work
        let prom = service.prometheus().unwrap();
        assert_eq!(prom.predictions_generated.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_channel_status_initial_all_enabled() {
        // Bind a local UDP socket for StatsD
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = receiver.local_addr().unwrap();

        let config = ObservabilityConfig {
            prometheus_bind: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))),
            statsd_endpoint: Some(addr.to_string()),
            ..config_all_disabled()
        };
        let webhook_configs = vec![WebhookConfig {
            endpoint: "http://localhost:9999/hook".to_string(),
            timeout_secs: 10,
            retry_max: 3,
            retry_base_secs: 1,
        }];
        let service = ExportService::new(&config, webhook_configs).expect("Should create");

        let status = service.channel_status().await;
        // OTLP is None (no endpoint configured), so it's Disabled
        assert_eq!(status.otlp, ChannelHealth::Disabled);
        assert_eq!(status.prometheus, ChannelHealth::Healthy);
        assert_eq!(status.statsd, ChannelHealth::Healthy);
        assert_eq!(status.webhooks, ChannelHealth::Healthy);
    }

    #[tokio::test]
    async fn test_channel_status_all_disabled() {
        let config = config_all_disabled();
        let service = ExportService::new(&config, vec![]).expect("Should create");

        let status = service.channel_status().await;
        assert_eq!(status.otlp, ChannelHealth::Disabled);
        assert_eq!(status.prometheus, ChannelHealth::Disabled);
        assert_eq!(status.statsd, ChannelHealth::Disabled);
        assert_eq!(status.webhooks, ChannelHealth::Disabled);
    }

    #[tokio::test]
    async fn test_statsd_receives_events() {
        // Set up a local UDP receiver for StatsD
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = receiver.local_addr().unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();

        let config = ObservabilityConfig {
            statsd_endpoint: Some(addr.to_string()),
            ..config_all_disabled()
        };
        let service = ExportService::new(&config, vec![]).expect("Should create");

        let event = make_event(MetricName::CertificatesDiscovered);
        service.record_event(&event).await;

        // Give the spawned task time to send
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Verify StatsD received the metric
        let mut buf = [0u8; 1024];
        let result = receiver.recv_from(&mut buf);
        assert!(result.is_ok(), "Should receive StatsD packet");
        let (len, _) = result.unwrap();
        let received = std::str::from_utf8(&buf[..len]).unwrap();
        // Should contain the certificates discovered counter
        assert!(
            received.contains("tlapix.certificates.discovered"),
            "Received: {}",
            received
        );
    }

    #[tokio::test]
    async fn test_webhook_degraded_status_on_failure() {
        let config = ObservabilityConfig {
            prometheus_bind: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))),
            ..config_all_disabled()
        };
        let webhook_configs = vec![WebhookConfig {
            endpoint: "http://192.0.2.1:1/hook".to_string(),
            timeout_secs: 1,
            retry_max: 0,
            retry_base_secs: 1,
        }];
        let service = ExportService::new(&config, webhook_configs).expect("Should create");

        // Trigger an action event that dispatches webhooks
        let event = make_event(MetricName::ActionsExecuted);
        service.record_event(&event).await;

        // Health should be degraded after webhook failure
        let status = service.channel_status().await;
        assert_eq!(status.webhooks, ChannelHealth::Degraded);
        // But Prometheus should still be healthy
        assert_eq!(status.prometheus, ChannelHealth::Healthy);
    }
}
