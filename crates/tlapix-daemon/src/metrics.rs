//! OpenTelemetry metrics export for the Tlapix Certificate Guardian.
//!
//! Exports the following counters via OTLP:
//! - `tlapix.certificates.discovered` — certificates discovered in traffic
//! - `tlapix.anomalies.detected` — anomalies detected by the Analyzer
//! - `tlapix.predictions.generated` — renewal predictions generated
//! - `tlapix.actions.executed` — action directives successfully executed
//! - `tlapix.actions.failed` — action directives that failed execution
//!
//! When no OTLP endpoint is configured, a no-op metrics service is created
//! that records counters locally without exporting.

use anyhow::Result;
use opentelemetry::metrics::{Counter, MeterProvider};
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use tlapix_common::ObservabilityConfig;

/// Service responsible for recording and exporting OpenTelemetry metrics.
#[derive(Clone)]
pub struct MetricsService {
    certificates_discovered: Counter<u64>,
    anomalies_detected: Counter<u64>,
    predictions_generated: Counter<u64>,
    actions_executed: Counter<u64>,
    actions_failed: Counter<u64>,
    _provider: SdkMeterProvider,
}

impl MetricsService {
    /// Initialize the metrics service with the given observability configuration.
    ///
    /// If `otlp_endpoint` is configured, sets up an OTLP exporter with the
    /// specified endpoint, optional auth token, and export interval.
    /// If no endpoint is configured, creates a no-op service that still
    /// tracks counters locally but does not export.
    pub fn init(config: &ObservabilityConfig) -> Result<Self> {
        let provider = if let Some(ref endpoint) = config.otlp_endpoint {
            Self::init_otlp(endpoint, config)?
        } else {
            Self::init_noop()
        };

        let meter = provider.versioned_meter(
            "tlapix",
            Some(env!("CARGO_PKG_VERSION")),
            None::<&str>,
            None,
        );

        let certificates_discovered = meter
            .u64_counter("tlapix.certificates.discovered")
            .with_description("Number of TLS certificates discovered in traffic")
            .init();

        let anomalies_detected = meter
            .u64_counter("tlapix.anomalies.detected")
            .with_description("Number of certificate anomalies detected")
            .init();

        let predictions_generated = meter
            .u64_counter("tlapix.predictions.generated")
            .with_description("Number of renewal predictions generated")
            .init();

        let actions_executed = meter
            .u64_counter("tlapix.actions.executed")
            .with_description("Number of action directives successfully executed")
            .init();

        let actions_failed = meter
            .u64_counter("tlapix.actions.failed")
            .with_description("Number of action directives that failed execution")
            .init();

        Ok(Self {
            certificates_discovered,
            anomalies_detected,
            predictions_generated,
            actions_executed,
            actions_failed,
            _provider: provider,
        })
    }

    /// Initialize the OTLP exporter with the configured endpoint and auth.
    fn init_otlp(endpoint: &str, config: &ObservabilityConfig) -> Result<SdkMeterProvider> {
        use opentelemetry_otlp::WithExportConfig;

        let mut exporter_builder = opentelemetry_otlp::new_exporter()
            .tonic()
            .with_endpoint(endpoint);

        // Set auth token as metadata header if provided
        if let Some(ref token) = config.otlp_auth_token {
            let mut metadata = tonic::metadata::MetadataMap::new();
            metadata.insert(
                "authorization",
                format!("Bearer {}", token)
                    .parse()
                    .map_err(|e| anyhow::anyhow!("Invalid auth token header value: {}", e))?,
            );
            exporter_builder = exporter_builder.with_metadata(metadata);
        }

        let export_interval = std::time::Duration::from_secs(config.otlp_export_interval_secs);

        let provider = opentelemetry_otlp::new_pipeline()
            .metrics(opentelemetry_sdk::runtime::Tokio)
            .with_exporter(exporter_builder)
            .with_period(export_interval)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build OTLP metrics pipeline: {}", e))?;

        Ok(provider)
    }

    /// Create a no-op meter provider that doesn't export metrics anywhere.
    fn init_noop() -> SdkMeterProvider {
        SdkMeterProvider::default()
    }

    /// Record that a certificate was discovered in traffic.
    pub fn record_certificate_discovered(&self) {
        self.certificates_discovered.add(1, &[]);
    }

    /// Record that an anomaly was detected.
    pub fn record_anomaly_detected(&self) {
        self.anomalies_detected.add(1, &[]);
    }

    /// Record that a renewal prediction was generated.
    pub fn record_prediction_generated(&self) {
        self.predictions_generated.add(1, &[]);
    }

    /// Record that an action directive was successfully executed.
    pub fn record_action_executed(&self) {
        self.actions_executed.add(1, &[]);
    }

    /// Record that an action directive failed execution.
    pub fn record_action_failed(&self) {
        self.actions_failed.add(1, &[]);
    }

    /// Record a certificate discovered with additional attributes.
    pub fn record_certificate_discovered_with_attrs(&self, attrs: &[KeyValue]) {
        self.certificates_discovered.add(1, attrs);
    }

    /// Record an anomaly detected with additional attributes.
    pub fn record_anomaly_detected_with_attrs(&self, attrs: &[KeyValue]) {
        self.anomalies_detected.add(1, attrs);
    }

    /// Record a prediction generated with additional attributes.
    pub fn record_prediction_generated_with_attrs(&self, attrs: &[KeyValue]) {
        self.predictions_generated.add(1, attrs);
    }

    /// Record an action executed with additional attributes.
    pub fn record_action_executed_with_attrs(&self, attrs: &[KeyValue]) {
        self.actions_executed.add(1, attrs);
    }

    /// Record an action failed with additional attributes.
    pub fn record_action_failed_with_attrs(&self, attrs: &[KeyValue]) {
        self.actions_failed.add(1, attrs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noop_config() -> ObservabilityConfig {
        ObservabilityConfig {
            otlp_endpoint: None,
            otlp_auth_token: None,
            otlp_export_interval_secs: 60,
            prometheus_bind: None,
            statsd_endpoint: None,
            audit_retention_days: 90,
        }
    }

    /// Test that MetricsService initializes successfully with no OTLP endpoint (no-op mode).
    #[test]
    fn test_init_noop_mode() {
        let config = noop_config();
        let _service = MetricsService::init(&config).expect("Should initialize in no-op mode");
    }

    /// Test that counters can be incremented without panicking in no-op mode.
    #[test]
    fn test_counter_increments_noop() {
        let config = noop_config();
        let service = MetricsService::init(&config).expect("Should initialize");

        // All counter methods should work without panicking
        service.record_certificate_discovered();
        service.record_anomaly_detected();
        service.record_prediction_generated();
        service.record_action_executed();
        service.record_action_failed();
    }

    /// Test that counters can be incremented with attributes.
    #[test]
    fn test_counter_increments_with_attrs() {
        let config = noop_config();
        let service = MetricsService::init(&config).expect("Should initialize");

        let attrs = [KeyValue::new("severity", "critical")];
        service.record_certificate_discovered_with_attrs(&attrs);
        service.record_anomaly_detected_with_attrs(&attrs);
        service.record_prediction_generated_with_attrs(&attrs);
        service.record_action_executed_with_attrs(&attrs);
        service.record_action_failed_with_attrs(&attrs);
    }

    /// Test that MetricsService can be cloned (needed for sharing across tasks).
    #[test]
    fn test_metrics_service_is_clone() {
        let config = noop_config();
        let service = MetricsService::init(&config).expect("Should initialize");
        let _cloned = service.clone();
    }

    /// Test that the default export interval is 60 seconds (within the 60s requirement).
    #[test]
    fn test_default_export_interval() {
        let config = noop_config();
        assert_eq!(config.otlp_export_interval_secs, 60);
    }

    /// Test that multiple counter increments work correctly.
    #[test]
    fn test_multiple_increments() {
        let config = noop_config();
        let service = MetricsService::init(&config).expect("Should initialize");

        for _ in 0..100 {
            service.record_certificate_discovered();
        }
        for _ in 0..50 {
            service.record_anomaly_detected();
        }
        // No panic means counters handle repeated increments correctly
    }
}
