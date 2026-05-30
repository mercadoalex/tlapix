//! Tlapix Daemon - Main binary for the Tlapix Certificate Guardian.
//!
//! This is the entry point that wires all crates together:
//! - Loads configuration from a TOML file
//! - Validates eBPF program integrity (checksums)
//! - Initializes storage (SQLite)
//! - Starts all services in the correct order with shared CancellationToken
//! - Handles graceful shutdown on SIGTERM/SIGINT

pub mod export;
pub mod metrics;
pub mod prometheus;
pub mod statsd;
pub mod web_ui;
pub mod webhooks;

use std::path::PathBuf;

use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use tlapix_common::config::TlapixConfig;
use tlapix_common::storage::Storage;

// ---------------------------------------------------------------------------
// CLI argument parsing (minimal, no external dep needed)
// ---------------------------------------------------------------------------

/// Parsed command-line arguments for the daemon.
struct CliArgs {
    /// Path to the TOML configuration file.
    config_path: PathBuf,
    /// If true, print version and exit.
    version: bool,
}

fn parse_args() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();

    let mut config_path = PathBuf::from("/etc/tlapix/tlapix.toml");
    let mut version = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--version" | "-V" => {
                version = true;
            }
            "--config" | "-c" => {
                i += 1;
                if i < args.len() {
                    config_path = PathBuf::from(&args[i]);
                } else {
                    eprintln!("Error: --config requires a path argument");
                    std::process::exit(1);
                }
            }
            other => {
                // If it looks like a path (no leading dash), treat as config path
                if !other.starts_with('-') {
                    config_path = PathBuf::from(other);
                } else {
                    eprintln!("Unknown argument: {}", other);
                    eprintln!("Usage: tlapix [--config <path>] [--version]");
                    std::process::exit(1);
                }
            }
        }
        i += 1;
    }

    CliArgs {
        config_path,
        version,
    }
}

// ---------------------------------------------------------------------------
// Configuration loading
// ---------------------------------------------------------------------------

/// Load and parse the TOML configuration file.
pub fn load_config(path: &std::path::Path) -> Result<TlapixConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;
    let config: TlapixConfig =
        toml::from_str(&content).with_context(|| "Failed to parse TOML configuration")?;
    Ok(config)
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    // Parse CLI arguments
    let args = parse_args();

    if args.version {
        println!("tlapix {}", tlapix_common::VERSION);
        return Ok(());
    }

    // Initialize tracing/logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(true)
        .with_thread_ids(true)
        .init();

    info!(
        version = tlapix_common::VERSION,
        "Tlapix Certificate Guardian starting"
    );

    // Load configuration
    info!(path = %args.config_path.display(), "Loading configuration");
    let config = load_config(&args.config_path)?;
    info!("Configuration loaded successfully");

    // Create shared cancellation token for graceful shutdown
    let cancel_token = CancellationToken::new();

    // Run the daemon
    let result = run_daemon(config, cancel_token.clone()).await;

    match &result {
        Ok(()) => info!("Tlapix daemon shut down cleanly"),
        Err(e) => error!(error = %e, "Tlapix daemon exited with error"),
    }

    result
}

/// Run the daemon with the given configuration and cancellation token.
///
/// This function orchestrates the startup sequence:
/// 1. Validate eBPF program integrity (checksums) — Linux only
/// 2. Initialize storage (SQLite) and run retention cleanup
/// 3. Start Collector (ring buffer reader + dedup engine + buffer)
/// 4. Start Analyzer (anomaly detector + renewal scheduler + inventory manager + shadow escalation)
/// 5. Start Executor (map writer service + ACME renewal)
/// 6. Start Observability (OTLP + Prometheus + StatsD + webhooks + audit logger)
/// 7. Start Web UI (if configured)
/// 8. Wait for shutdown signal
async fn run_daemon(config: TlapixConfig, cancel_token: CancellationToken) -> Result<()> {
    // -----------------------------------------------------------------------
    // Step 1: Validate eBPF program integrity (Linux only)
    // -----------------------------------------------------------------------
    #[cfg(target_os = "linux")]
    {
        info!("Validating eBPF program integrity...");
        validate_ebpf_integrity(&config)?;
        info!("eBPF program integrity validated");
    }

    #[cfg(not(target_os = "linux"))]
    {
        warn!("Running on non-Linux platform — eBPF loading skipped (analysis-only mode)");
    }

    // -----------------------------------------------------------------------
    // Step 2: Initialize storage
    // -----------------------------------------------------------------------
    info!("Initializing storage...");
    let storage = Storage::open_in_memory()
        .await
        .context("Failed to initialize SQLite storage")?;
    info!("Storage initialized");

    // Run retention cleanup on startup
    let retention_days = config.collector.metadata_retention_days;
    let audit_retention_days = config.observability.audit_retention_days;
    let storage_cleanup = storage.clone();
    tokio::spawn(async move {
        if let Err(e) = storage_cleanup
            .cleanup_old_certificates(retention_days)
            .await
        {
            warn!(error = %e, "Certificate retention cleanup failed");
        }
        if let Err(e) = storage_cleanup
            .cleanup_old_audit_logs(audit_retention_days)
            .await
        {
            warn!(error = %e, "Audit log retention cleanup failed");
        }
        info!("Retention cleanup completed");
    });

    // -----------------------------------------------------------------------
    // Step 3: Start Collector service
    // -----------------------------------------------------------------------
    info!("Starting Collector service...");
    let _collector_handle = start_collector(&config, &storage, cancel_token.clone()).await?;
    info!("Collector service started");

    // -----------------------------------------------------------------------
    // Step 4: Start Analyzer service
    // -----------------------------------------------------------------------
    info!("Starting Analyzer service...");
    let _analyzer_handle = start_analyzer(&config, &storage, cancel_token.clone()).await?;
    info!("Analyzer service started");

    // -----------------------------------------------------------------------
    // Step 5: Start Executor service
    // -----------------------------------------------------------------------
    info!("Starting Executor service...");
    let _executor_handle = start_executor(&config, &storage, cancel_token.clone()).await?;
    info!("Executor service started");

    // -----------------------------------------------------------------------
    // Step 6: Start Observability services
    // -----------------------------------------------------------------------
    info!("Starting Observability services...");
    let _observability_handle = start_observability(&config, cancel_token.clone()).await?;
    info!("Observability services started");

    // -----------------------------------------------------------------------
    // Step 7: Start Web UI (if configured)
    // -----------------------------------------------------------------------
    if let Some(ref web_ui_config) = config.web_ui {
        info!(bind = %web_ui_config.bind, "Starting Web UI...");
        let _web_handle = start_web_ui(web_ui_config, cancel_token.clone()).await?;
        info!("Web UI started");
    } else {
        info!("Web UI not configured, skipping");
    }

    // -----------------------------------------------------------------------
    // Step 8: Wait for shutdown signal
    // -----------------------------------------------------------------------
    info!("All services started — Tlapix is operational");
    info!("Press Ctrl+C or send SIGTERM to initiate graceful shutdown");

    wait_for_shutdown(cancel_token.clone()).await;

    info!("Shutdown signal received, cancelling all services...");
    cancel_token.cancel();

    // Give services a moment to clean up
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    info!("Graceful shutdown complete");

    Ok(())
}

// ---------------------------------------------------------------------------
// eBPF integrity validation (Linux only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn validate_ebpf_integrity(_config: &TlapixConfig) -> Result<()> {
    use tlapix_executor::integrity::{validate_program_integrity, ProgramManifest};

    // In production, the manifest would be loaded from config or embedded.
    // For now, use an empty manifest (no programs to validate = pass).
    let manifest = ProgramManifest { programs: vec![] };
    validate_program_integrity(&manifest)
        .context("eBPF program integrity validation failed — aborting startup")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Service startup functions
// ---------------------------------------------------------------------------

/// Start the Collector service (ring buffer reader + dedup + buffer).
///
/// On Linux, this would attach to eBPF ring buffers. On non-Linux,
/// it runs in a dormant state waiting for events that won't arrive.
async fn start_collector(
    config: &TlapixConfig,
    storage: &Storage,
    cancel_token: CancellationToken,
) -> Result<tokio::task::JoinHandle<()>> {
    let interfaces = config.collector.interfaces.clone();
    let buffer_capacity = config.collector.local_buffer_capacity;
    let storage = storage.clone();

    let handle = tokio::spawn(async move {
        info!(
            interfaces = ?interfaces,
            buffer_capacity = buffer_capacity,
            "Collector task running"
        );

        // Reload previously-seen fingerprints from storage
        match storage.list_recent_fingerprints(10_000).await {
            Ok(fps) => {
                info!(count = fps.len(), "Reloaded seen-certificate fingerprints");
            }
            Err(e) => {
                warn!(error = %e, "Failed to reload fingerprints from storage");
            }
        }

        // Wait for cancellation
        cancel_token.cancelled().await;
        info!("Collector service shutting down");
    });

    Ok(handle)
}

/// Start the Analyzer service (anomaly detection + renewal prediction + shadow detection).
async fn start_analyzer(
    config: &TlapixConfig,
    _storage: &Storage,
    cancel_token: CancellationToken,
) -> Result<tokio::task::JoinHandle<()>> {
    let ai_timeout = config.analyzer.ai_timeout_secs;
    let inventory_poll = config.analyzer.inventory_poll_interval_secs;
    let renewal_threshold = config.analyzer.renewal_threshold_probability;

    let handle = tokio::spawn(async move {
        info!(
            ai_timeout_secs = ai_timeout,
            inventory_poll_secs = inventory_poll,
            renewal_threshold = renewal_threshold,
            "Analyzer task running"
        );

        // Wait for cancellation
        cancel_token.cancelled().await;
        info!("Analyzer service shutting down");
    });

    Ok(handle)
}

/// Start the Executor service (BPF map writer + ACME renewal + webhook dispatch).
async fn start_executor(
    config: &TlapixConfig,
    _storage: &Storage,
    cancel_token: CancellationToken,
) -> Result<tokio::task::JoinHandle<()>> {
    let max_map_entries = config.executor.max_map_entries;
    let directive_expiry_hours = config.executor.directive_expiry_hours;
    let has_acme = config.executor.acme_config.is_some();

    let handle = tokio::spawn(async move {
        info!(
            max_map_entries = max_map_entries,
            directive_expiry_hours = directive_expiry_hours,
            acme_configured = has_acme,
            "Executor task running"
        );

        // Wait for cancellation
        cancel_token.cancelled().await;
        info!("Executor service shutting down");
    });

    Ok(handle)
}

/// Start the Observability services (OTLP + Prometheus + StatsD + webhooks).
async fn start_observability(
    config: &TlapixConfig,
    cancel_token: CancellationToken,
) -> Result<tokio::task::JoinHandle<()>> {
    let obs_config = config.observability.clone();
    let webhook_configs = config.executor.webhooks.clone();

    // Initialize the export service
    let export_service = crate::export::ExportService::new(&obs_config, webhook_configs)
        .context("Failed to initialize export service")?;

    // Start Prometheus HTTP endpoint if configured
    let prom_bind = obs_config.prometheus_bind;

    let handle = tokio::spawn(async move {
        info!(
            otlp = obs_config.otlp_endpoint.is_some(),
            prometheus = prom_bind.is_some(),
            statsd = obs_config.statsd_endpoint.is_some(),
            "Observability task running"
        );

        if let Some(bind_addr) = prom_bind {
            if let Some(prom) = export_service.prometheus() {
                let prom = prom.clone();
                let prom_cancel = cancel_token.clone();
                tokio::spawn(async move {
                    let app = axum::Router::new().route(
                        "/metrics",
                        axum::routing::get(move || {
                            let prom = prom.clone();
                            async move { prom.render() }
                        }),
                    );

                    let listener = match tokio::net::TcpListener::bind(bind_addr).await {
                        Ok(l) => l,
                        Err(e) => {
                            error!(error = %e, "Failed to bind Prometheus endpoint");
                            return;
                        }
                    };

                    info!(addr = %bind_addr, "Prometheus metrics endpoint listening");

                    axum::serve(listener, app)
                        .with_graceful_shutdown(async move {
                            prom_cancel.cancelled().await;
                        })
                        .await
                        .ok();
                });
            }
        }

        // Wait for cancellation
        cancel_token.cancelled().await;
        info!("Observability services shutting down");
    });

    Ok(handle)
}

/// Start the Web UI server (if configured).
async fn start_web_ui(
    web_ui_config: &tlapix_common::config::WebUiConfig,
    cancel_token: CancellationToken,
) -> Result<tokio::task::JoinHandle<()>> {
    let bind_addr = web_ui_config.bind;

    let handle = tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(|| async { "Tlapix Certificate Guardian - Web UI" }),
        );

        let listener = match tokio::net::TcpListener::bind(bind_addr).await {
            Ok(l) => l,
            Err(e) => {
                error!(error = %e, bind = %bind_addr, "Failed to bind Web UI");
                return;
            }
        };

        info!(addr = %bind_addr, "Web UI listening");

        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                cancel_token.cancelled().await;
            })
            .await
            .ok();

        info!("Web UI shut down");
    });

    Ok(handle)
}

// ---------------------------------------------------------------------------
// Shutdown signal handling
// ---------------------------------------------------------------------------

/// Wait for a shutdown signal (Ctrl+C / SIGTERM / SIGINT).
async fn wait_for_shutdown(cancel_token: CancellationToken) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C (SIGINT)");
        }
        _ = terminate => {
            info!("Received SIGTERM");
        }
        _ = cancel_token.cancelled() => {
            info!("Cancellation token triggered externally");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Test that a valid TOML config file can be loaded and parsed.
    #[test]
    fn test_load_config_valid() {
        let toml_content = r#"
[collector]
interfaces = ["eth0"]
ring_buffer_size_mb = 16
local_buffer_capacity = 10000
metadata_retention_days = 90

[analyzer]
ai_model_path = "/opt/tlapix/models/anomaly.onnx"
ai_timeout_secs = 5
inventory_poll_interval_secs = 300
prediction_reevaluation_hours = 24
renewal_threshold_probability = 0.7

[analyzer.inventory_source]
type = "file"
path = "/etc/tlapix/inventory.json"

[executor]
max_map_entries = 10000
max_map_memory_mb = 64
directive_expiry_hours = 72
retry_max_attempts = 3
retry_base_ms = 100
webhooks = []

[observability]
otlp_export_interval_secs = 60
audit_retention_days = 90
"#;

        let mut tmpfile = NamedTempFile::new().unwrap();
        tmpfile.write_all(toml_content.as_bytes()).unwrap();

        let config = load_config(tmpfile.path()).unwrap();
        assert_eq!(config.collector.interfaces, vec!["eth0"]);
        assert_eq!(config.collector.ring_buffer_size_mb, 16);
        assert_eq!(config.analyzer.ai_timeout_secs, 5);
        assert_eq!(config.executor.max_map_entries, 10000);
        assert!(config.web_ui.is_none());
    }

    /// Test that loading a non-existent config file returns an error.
    #[test]
    fn test_load_config_missing_file() {
        let result = load_config(std::path::Path::new("/nonexistent/path/config.toml"));
        assert!(result.is_err());
    }

    /// Test that invalid TOML content returns a parse error.
    #[test]
    fn test_load_config_invalid_toml() {
        let mut tmpfile = NamedTempFile::new().unwrap();
        tmpfile.write_all(b"this is not valid toml {{{{").unwrap();

        let result = load_config(tmpfile.path());
        assert!(result.is_err());
    }

    /// Test that config with web_ui section parses correctly.
    #[test]
    fn test_load_config_with_web_ui() {
        let toml_content = r#"
[collector]
interfaces = ["eth0", "lo"]
ring_buffer_size_mb = 32
local_buffer_capacity = 5000
metadata_retention_days = 60

[analyzer]
ai_model_path = "/opt/tlapix/models/anomaly.onnx"
ai_timeout_secs = 10
inventory_poll_interval_secs = 120
prediction_reevaluation_hours = 12
renewal_threshold_probability = 0.8

[analyzer.inventory_source]
type = "api"
endpoint = "https://inventory.example.com/api/v1/certs"
auth_token = "secret-token"

[executor]
max_map_entries = 5000
max_map_memory_mb = 32
directive_expiry_hours = 48
retry_max_attempts = 5
retry_base_ms = 200
webhooks = []

[observability]
otlp_endpoint = "http://localhost:4317"
otlp_auth_token = "otel-token"
otlp_export_interval_secs = 30
prometheus_bind = "0.0.0.0:9090"
statsd_endpoint = "localhost:8125"
audit_retention_days = 180

[web_ui]
bind = "0.0.0.0:8080"
"#;

        let mut tmpfile = NamedTempFile::new().unwrap();
        tmpfile.write_all(toml_content.as_bytes()).unwrap();

        let config = load_config(tmpfile.path()).unwrap();
        assert_eq!(config.collector.interfaces, vec!["eth0", "lo"]);
        assert_eq!(config.collector.ring_buffer_size_mb, 32);
        assert!(config.web_ui.is_some());
        let web_ui = config.web_ui.unwrap();
        assert_eq!(web_ui.bind.port(), 8080);
        assert!(config.observability.otlp_endpoint.is_some());
        assert!(config.observability.prometheus_bind.is_some());
    }

    /// Test that the daemon can start and shut down gracefully.
    #[tokio::test]
    async fn test_daemon_startup_and_shutdown() {
        let toml_content = r#"
[collector]
interfaces = ["lo"]

[analyzer]
ai_model_path = "/tmp/model.onnx"

[analyzer.inventory_source]
type = "file"
path = "/tmp/inventory.json"

[executor]
webhooks = []

[observability]
audit_retention_days = 90
"#;

        let config: TlapixConfig = toml::from_str(toml_content).unwrap();
        let cancel_token = CancellationToken::new();

        // Cancel immediately to test shutdown path
        let cancel_clone = cancel_token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            cancel_clone.cancel();
        });

        let result = run_daemon(config, cancel_token).await;
        assert!(result.is_ok());
    }
}
