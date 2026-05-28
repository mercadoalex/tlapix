//! Configuration types for the Tlapix Certificate Guardian.
//!
//! These types are deserialized from TOML/YAML configuration files and
//! control the behavior of all system components.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Top-level configuration for the Tlapix daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlapixConfig {
    /// Collector layer configuration
    pub collector: CollectorConfig,
    /// Analyzer layer configuration
    pub analyzer: AnalyzerConfig,
    /// Executor layer configuration
    pub executor: ExecutorConfig,
    /// Observability and metrics configuration
    pub observability: ObservabilityConfig,
    /// Optional built-in web UI configuration
    pub web_ui: Option<WebUiConfig>,
}

/// Configuration for the eBPF Collector layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorConfig {
    /// Network interfaces to monitor (e.g., ["eth0", "lo"])
    pub interfaces: Vec<String>,
    /// Ring buffer size in megabytes (default: 16)
    #[serde(default = "default_ring_buffer_size_mb")]
    pub ring_buffer_size_mb: u32,
    /// Maximum number of metadata records to buffer locally when the Analyzer
    /// is unavailable (default: 10,000)
    #[serde(default = "default_local_buffer_capacity")]
    pub local_buffer_capacity: usize,
    /// Number of days to retain certificate metadata (default: 90)
    #[serde(default = "default_metadata_retention_days")]
    pub metadata_retention_days: u32,
}

/// Configuration for the Analyzer layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzerConfig {
    /// Path to the ONNX model file for AI-powered anomaly detection
    pub ai_model_path: PathBuf,
    /// Timeout in seconds for AI model backend connection (default: 5)
    #[serde(default = "default_ai_timeout_secs")]
    pub ai_timeout_secs: u64,
    /// Source for the certificate inventory
    pub inventory_source: InventorySource,
    /// Interval in seconds between inventory polls (default: 300 = 5 minutes)
    #[serde(default = "default_inventory_poll_interval_secs")]
    pub inventory_poll_interval_secs: u64,
    /// Interval in hours between renewal prediction re-evaluations (default: 24)
    #[serde(default = "default_prediction_reevaluation_hours")]
    pub prediction_reevaluation_hours: u64,
    /// Failure probability threshold that triggers a "renew" action (default: 0.7)
    #[serde(default = "default_renewal_threshold_probability")]
    pub renewal_threshold_probability: f64,
}

/// Source for the certificate inventory used in shadow certificate detection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum InventorySource {
    /// File-based inventory (e.g., CSV or JSON file)
    File { path: PathBuf },
    /// API-based inventory with authentication
    Api { endpoint: String, auth_token: String },
}

/// Configuration for the Executor layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorConfig {
    /// Maximum number of entries per BPF action map (default: 10,000)
    #[serde(default = "default_max_map_entries")]
    pub max_map_entries: u32,
    /// Maximum total BPF map memory allocation in megabytes (default: 64)
    #[serde(default = "default_max_map_memory_mb")]
    pub max_map_memory_mb: u32,
    /// Optional ACME configuration for automated certificate renewal
    pub acme_config: Option<AcmeConfig>,
    /// Webhook endpoints for alert delivery
    #[serde(default)]
    pub webhooks: Vec<WebhookConfig>,
    /// Hours after which a directive expires if the certificate is not seen (default: 72)
    #[serde(default = "default_directive_expiry_hours")]
    pub directive_expiry_hours: u64,
    /// Maximum number of retry attempts for failed actions (default: 3)
    #[serde(default = "default_retry_max_attempts")]
    pub retry_max_attempts: u8,
    /// Base delay in milliseconds for exponential backoff retries (default: 100)
    #[serde(default = "default_retry_base_ms")]
    pub retry_base_ms: u64,
}

/// ACME (Automatic Certificate Management Environment) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    /// ACME directory URL (e.g., Let's Encrypt production or staging)
    pub directory_url: String,
    /// Contact email for the ACME account
    pub contact_email: String,
    /// Path to store ACME account credentials
    pub credentials_path: PathBuf,
}

/// Configuration for a webhook notification endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// HTTP endpoint URL for webhook delivery
    pub endpoint: String,
    /// Request timeout in seconds (default: 10)
    #[serde(default = "default_webhook_timeout_secs")]
    pub timeout_secs: u64,
    /// Maximum number of delivery retry attempts (default: 3)
    #[serde(default = "default_webhook_retry_max")]
    pub retry_max: u8,
    /// Base delay in seconds for exponential backoff retries (default: 1)
    #[serde(default = "default_webhook_retry_base_secs")]
    pub retry_base_secs: u64,
}

/// Configuration for the observability and metrics layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// OTLP exporter endpoint URL (e.g., "http://localhost:4317")
    pub otlp_endpoint: Option<String>,
    /// Authentication token for the OTLP endpoint
    pub otlp_auth_token: Option<String>,
    /// Interval in seconds between OTLP metric exports (default: 60)
    #[serde(default = "default_otlp_export_interval_secs")]
    pub otlp_export_interval_secs: u64,
    /// Socket address for the Prometheus metrics endpoint (e.g., "0.0.0.0:9090")
    pub prometheus_bind: Option<SocketAddr>,
    /// StatsD endpoint for metric export (e.g., "localhost:8125")
    pub statsd_endpoint: Option<String>,
    /// Number of days to retain audit log entries (default: 90)
    #[serde(default = "default_audit_retention_days")]
    pub audit_retention_days: u32,
}

/// Configuration for the optional built-in web UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebUiConfig {
    /// Socket address to bind the web UI server
    pub bind: SocketAddr,
}

// ---------------------------------------------------------------------------
// Default value functions for serde
// ---------------------------------------------------------------------------

fn default_ring_buffer_size_mb() -> u32 {
    16
}

fn default_local_buffer_capacity() -> usize {
    10_000
}

fn default_metadata_retention_days() -> u32 {
    90
}

fn default_ai_timeout_secs() -> u64 {
    5
}

fn default_inventory_poll_interval_secs() -> u64 {
    300
}

fn default_prediction_reevaluation_hours() -> u64 {
    24
}

fn default_renewal_threshold_probability() -> f64 {
    0.7
}

fn default_max_map_entries() -> u32 {
    10_000
}

fn default_max_map_memory_mb() -> u32 {
    64
}

fn default_directive_expiry_hours() -> u64 {
    72
}

fn default_retry_max_attempts() -> u8 {
    3
}

fn default_retry_base_ms() -> u64 {
    100
}

fn default_webhook_timeout_secs() -> u64 {
    10
}

fn default_webhook_retry_max() -> u8 {
    3
}

fn default_webhook_retry_base_secs() -> u64 {
    1
}

fn default_otlp_export_interval_secs() -> u64 {
    60
}

fn default_audit_retention_days() -> u32 {
    90
}
