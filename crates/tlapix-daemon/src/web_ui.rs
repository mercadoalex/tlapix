//! Lightweight built-in web UI for the Tlapix Certificate Guardian.
//!
//! Provides a server-rendered HTML dashboard with htmx for interactivity.
//! This is an optional component, only started when `WebUiConfig` is present.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::State,
    response::Html,
    routing::get,
    Router,
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tlapix_common::storage::Storage;
use tracing;

// ---------------------------------------------------------------------------
// State shared across all handlers
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    storage: Storage,
}

// ---------------------------------------------------------------------------
// WebUiServer
// ---------------------------------------------------------------------------

/// Lightweight web UI server for operator dashboards.
pub struct WebUiServer;

impl WebUiServer {
    /// Start the web UI server on the given address.
    ///
    /// Returns a `JoinHandle` that resolves when the server shuts down.
    /// The server will stop gracefully when the `cancel` token is cancelled.
    pub fn start(
        bind_addr: SocketAddr,
        storage: Storage,
        cancel: CancellationToken,
    ) -> JoinHandle<()> {
        let state = AppState { storage };

        let app = Router::new()
            .route("/", get(dashboard_handler))
            .route("/certificates", get(certificates_handler))
            .route("/anomalies", get(anomalies_handler))
            .route("/actions", get(actions_handler))
            .route("/predictions", get(predictions_handler))
            .with_state(Arc::new(state));

        tokio::spawn(async move {
            let listener = match tokio::net::TcpListener::bind(bind_addr).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!("Web UI failed to bind to {}: {}", bind_addr, e);
                    return;
                }
            };
            tracing::info!("Web UI listening on http://{}", bind_addr);

            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    cancel.cancelled().await;
                    tracing::info!("Web UI shutting down");
                })
                .await
                .unwrap_or_else(|e| {
                    tracing::error!("Web UI server error: {}", e);
                });
        })
    }
}

// ---------------------------------------------------------------------------
// Route Handlers
// ---------------------------------------------------------------------------

async fn dashboard_handler(State(state): State<Arc<AppState>>) -> Html<String> {
    let cert_count = state.storage.count_certificates().await.unwrap_or(0);
    let anomaly_count = state.storage.count_pending_directives().await.unwrap_or(0);
    let recent_actions = state.storage.list_recent_directives(5).await.unwrap_or_default();

    let actions_html: String = if recent_actions.is_empty() {
        "<tr><td colspan=\"4\" style=\"text-align:center;color:#888;\">No recent actions</td></tr>".to_string()
    } else {
        recent_actions
            .iter()
            .map(|d| {
                format!(
                    "<tr><td>{}</td><td><span class=\"badge badge-{}\">{}</span></td><td>{}</td><td>{}</td></tr>",
                    d.action_type,
                    d.severity,
                    d.severity,
                    d.status,
                    format_timestamp(d.executed_at.unwrap_or(d.created_at)),
                )
            })
            .collect()
    };

    let html = format!(
        "<!DOCTYPE html>\n\
<html lang=\"en\">\n\
<head>\n\
    <meta charset=\"utf-8\">\n\
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
    <title>Tlapix Certificate Guardian</title>\n\
    <script src=\"https://unpkg.com/htmx.org@1.9.12\"></script>\n\
    {STYLES}\n\
</head>\n\
<body>\n\
    {NAV}\n\
    <main>\n\
        <h1>Dashboard</h1>\n\
        <div class=\"stats\">\n\
            <div class=\"stat-card\">\n\
                <div class=\"stat-value\">{cert_count}</div>\n\
                <div class=\"stat-label\">Certificates</div>\n\
            </div>\n\
            <div class=\"stat-card\">\n\
                <div class=\"stat-value\">{anomaly_count}</div>\n\
                <div class=\"stat-label\">Active Anomalies</div>\n\
            </div>\n\
            <div class=\"stat-card\">\n\
                <div class=\"stat-value\">{action_count}</div>\n\
                <div class=\"stat-label\">Recent Actions</div>\n\
            </div>\n\
        </div>\n\
        <h2>Recent Actions</h2>\n\
        <div hx-get=\"/actions\" hx-trigger=\"every 30s\" hx-select=\"table\" hx-swap=\"outerHTML\">\n\
            <table>\n\
                <thead><tr><th>Action</th><th>Severity</th><th>Status</th><th>Time</th></tr></thead>\n\
                <tbody>{actions_html}</tbody>\n\
            </table>\n\
        </div>\n\
    </main>\n\
</body>\n\
</html>",
        cert_count = cert_count,
        anomaly_count = anomaly_count,
        action_count = recent_actions.len(),
        actions_html = actions_html,
        STYLES = STYLES,
        NAV = NAV,
    );

    Html(html)
}

async fn certificates_handler(State(state): State<Arc<AppState>>) -> Html<String> {
    let certs = state.storage.list_all_certificates(100).await.unwrap_or_default();

    let rows_html: String = if certs.is_empty() {
        "<tr><td colspan=\"6\" style=\"text-align:center;color:#888;\">No certificates discovered</td></tr>".to_string()
    } else {
        certs
            .iter()
            .map(|c| {
                let fp_hex = hex_short(&c.fingerprint);
                let days_left = (c.not_after - chrono::Utc::now()).num_days();
                let expiry_class = if days_left < 0 {
                    "expired"
                } else if days_left < 14 {
                    "critical"
                } else if days_left < 30 {
                    "warning"
                } else {
                    "ok"
                };
                format!(
                    "<tr><td title=\"{}\">{}</td><td>{}</td><td>{}</td><td class=\"{}\">{} days</td><td>{}</td><td>{}</td></tr>",
                    hex_full(&c.fingerprint),
                    fp_hex,
                    c.subject,
                    c.issuer,
                    expiry_class,
                    days_left,
                    c.key_algorithm,
                    c.connection_count,
                )
            })
            .collect()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Certificates - Tlapix</title>
    <script src="https://unpkg.com/htmx.org@1.9.12"></script>
    {STYLES}
</head>
<body>
    {NAV}
    <main>
        <h1>Certificate Inventory</h1>
        <div hx-get="/certificates" hx-trigger="every 30s" hx-swap="outerHTML" hx-select="table">
            <table>
                <thead><tr><th>Fingerprint</th><th>Subject</th><th>Issuer</th><th>Expires</th><th>Algorithm</th><th>Connections</th></tr></thead>
                <tbody>{rows_html}</tbody>
            </table>
        </div>
    </main>
</body>
</html>"#,
        rows_html = rows_html,
        STYLES = STYLES,
        NAV = NAV,
    );

    Html(html)
}

async fn anomalies_handler(State(state): State<Arc<AppState>>) -> Html<String> {
    let anomalies = state
        .storage
        .list_directives_by_status("pending")
        .await
        .unwrap_or_default();

    let rows_html: String = if anomalies.is_empty() {
        "<tr><td colspan=\"5\" style=\"text-align:center;color:#888;\">No active anomalies</td></tr>".to_string()
    } else {
        anomalies
            .iter()
            .map(|d| {
                let fp_hex = hex_short(&d.cert_fingerprint);
                format!(
                    "<tr><td title=\"{}\">{}</td><td>{}</td><td><span class=\"badge badge-{}\">{}</span></td><td>{}</td><td>{}</td></tr>",
                    hex_full(&d.cert_fingerprint),
                    fp_hex,
                    d.action_type,
                    d.severity,
                    d.severity,
                    d.reasoning.as_deref().unwrap_or("-"),
                    format_timestamp(d.created_at),
                )
            })
            .collect()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Anomalies - Tlapix</title>
    <script src="https://unpkg.com/htmx.org@1.9.12"></script>
    {STYLES}
</head>
<body>
    {NAV}
    <main>
        <h1>Active Anomalies</h1>
        <div hx-get="/anomalies" hx-trigger="every 30s" hx-swap="outerHTML" hx-select="table">
            <table>
                <thead><tr><th>Certificate</th><th>Action</th><th>Severity</th><th>Reason</th><th>Detected</th></tr></thead>
                <tbody>{rows_html}</tbody>
            </table>
        </div>
    </main>
</body>
</html>"#,
        rows_html = rows_html,
        STYLES = STYLES,
        NAV = NAV,
    );

    Html(html)
}

async fn actions_handler(State(state): State<Arc<AppState>>) -> Html<String> {
    let actions = state.storage.list_recent_directives(50).await.unwrap_or_default();

    let rows_html: String = if actions.is_empty() {
        "<tr><td colspan=\"6\" style=\"text-align:center;color:#888;\">No actions recorded</td></tr>".to_string()
    } else {
        actions
            .iter()
            .map(|d| {
                let fp_hex = hex_short(&d.cert_fingerprint);
                let status_class = match d.status.as_str() {
                    "executed" => "ok",
                    "failed" => "critical",
                    "expired" => "warning",
                    _ => "",
                };
                format!(
                    "<tr><td title=\"{}\">{}</td><td>{}</td><td><span class=\"badge badge-{}\">{}</span></td><td class=\"{}\">{}</td><td>{}</td><td>{}</td></tr>",
                    hex_full(&d.cert_fingerprint),
                    fp_hex,
                    d.action_type,
                    d.severity,
                    d.severity,
                    status_class,
                    d.status,
                    d.failure_reason.as_deref().unwrap_or("-"),
                    format_timestamp(d.executed_at.unwrap_or(d.created_at)),
                )
            })
            .collect()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Actions - Tlapix</title>
    <script src="https://unpkg.com/htmx.org@1.9.12"></script>
    {STYLES}
</head>
<body>
    {NAV}
    <main>
        <h1>Recent Actions</h1>
        <div hx-get="/actions" hx-trigger="every 30s" hx-swap="outerHTML" hx-select="table">
            <table>
                <thead><tr><th>Certificate</th><th>Action</th><th>Severity</th><th>Status</th><th>Reason</th><th>Time</th></tr></thead>
                <tbody>{rows_html}</tbody>
            </table>
        </div>
    </main>
</body>
</html>"#,
        rows_html = rows_html,
        STYLES = STYLES,
        NAV = NAV,
    );

    Html(html)
}

async fn predictions_handler(State(state): State<Arc<AppState>>) -> Html<String> {
    let predictions = state
        .storage
        .list_all_renewal_predictions()
        .await
        .unwrap_or_default();

    let rows_html: String = if predictions.is_empty() {
        "<tr><td colspan=\"5\" style=\"text-align:center;color:#888;\">No active predictions</td></tr>".to_string()
    } else {
        predictions
            .iter()
            .map(|p| {
                let fp_hex = hex_short(&p.cert_fingerprint);
                let prob_class = if p.failure_probability >= 0.7 {
                    "critical"
                } else if p.failure_probability >= 0.5 {
                    "warning"
                } else {
                    "ok"
                };
                let renewal_icon = if p.renewal_activity_detected {
                    "&#10003;"
                } else {
                    "&#10007;"
                };
                format!(
                    "<tr><td title=\"{}\">{}</td><td>{} days</td><td class=\"{}\">{:.0}%</td><td><span class=\"badge badge-{}\">{}</span></td><td>{}</td></tr>",
                    hex_full(&p.cert_fingerprint),
                    fp_hex,
                    p.days_until_expiry,
                    prob_class,
                    p.failure_probability * 100.0,
                    p.severity,
                    p.severity,
                    renewal_icon,
                )
            })
            .collect()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Predictions - Tlapix</title>
    <script src="https://unpkg.com/htmx.org@1.9.12"></script>
    {STYLES}
</head>
<body>
    {NAV}
    <main>
        <h1>Renewal Predictions</h1>
        <div hx-get="/predictions" hx-trigger="every 30s" hx-swap="outerHTML" hx-select="table">
            <table>
                <thead><tr><th>Certificate</th><th>Expires In</th><th>Failure Prob.</th><th>Severity</th><th>Renewal Activity</th></tr></thead>
                <tbody>{rows_html}</tbody>
            </table>
        </div>
    </main>
</body>
</html>"#,
        rows_html = rows_html,
        STYLES = STYLES,
        NAV = NAV,
    );

    Html(html)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_short(bytes: &[u8; 32]) -> String {
    format!("{}..{}", hex::encode(&bytes[..3]), hex::encode(&bytes[29..]))
}

fn hex_full(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

fn format_timestamp(ms: i64) -> String {
    use chrono::TimeZone;
    chrono::Utc
        .timestamp_millis_opt(ms)
        .single()
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "-".to_string())
}

// ---------------------------------------------------------------------------
// Static content
// ---------------------------------------------------------------------------

const NAV: &str = r#"<nav>
    <a href="/" class="brand">&#128026; Tlapix</a>
    <a href="/certificates">Certificates</a>
    <a href="/anomalies">Anomalies</a>
    <a href="/actions">Actions</a>
    <a href="/predictions">Predictions</a>
</nav>"#;

const STYLES: &str = r#"<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #1a1a2e; color: #e0e0e0; line-height: 1.6; }
    nav { background: #16213e; padding: 0.75rem 1.5rem; display: flex; gap: 1.5rem; align-items: center; border-bottom: 1px solid #0f3460; }
    nav a { color: #a0c4ff; text-decoration: none; font-size: 0.9rem; }
    nav a:hover { color: #fff; }
    nav .brand { font-weight: bold; font-size: 1.1rem; margin-right: auto; }
    main { max-width: 1200px; margin: 2rem auto; padding: 0 1.5rem; }
    h1 { margin-bottom: 1.5rem; color: #fff; }
    h2 { margin: 1.5rem 0 1rem; color: #ccc; font-size: 1.1rem; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
    .stat-card { background: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 1.25rem; text-align: center; }
    .stat-value { font-size: 2rem; font-weight: bold; color: #a0c4ff; }
    .stat-label { font-size: 0.85rem; color: #888; margin-top: 0.25rem; }
    table { width: 100%; border-collapse: collapse; background: #16213e; border-radius: 8px; overflow: hidden; }
    th, td { padding: 0.6rem 0.8rem; text-align: left; border-bottom: 1px solid #0f3460; font-size: 0.85rem; }
    th { background: #0f3460; color: #a0c4ff; font-weight: 600; }
    tr:hover { background: #1a2744; }
    .badge { padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
    .badge-critical { background: #ff4444; color: #fff; }
    .badge-high { background: #ff8800; color: #fff; }
    .badge-medium { background: #ffcc00; color: #000; }
    .badge-low { background: #44aa44; color: #fff; }
    .expired, .critical { color: #ff4444; }
    .warning { color: #ffcc00; }
    .ok { color: #44aa44; }
</style>"#;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tlapix_common::storage::Storage;

    #[tokio::test]
    async fn test_web_ui_starts_and_responds() {
        let storage = Storage::open_in_memory().await.unwrap();
        let cancel = CancellationToken::new();

        // Bind to port 0 to get a random available port
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        // We need to start the server on a known port, so let's bind first
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let bound_addr = listener.local_addr().unwrap();

        let state = Arc::new(AppState {
            storage: storage.clone(),
        });

        let app = Router::new()
            .route("/", get(dashboard_handler))
            .route("/certificates", get(certificates_handler))
            .route("/anomalies", get(anomalies_handler))
            .route("/actions", get(actions_handler))
            .route("/predictions", get(predictions_handler))
            .with_state(state);

        let cancel_clone = cancel.clone();
        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    cancel_clone.cancelled().await;
                })
                .await
                .unwrap();
        });

        // Give the server a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Test GET /
        let resp = reqwest::get(format!("http://{}/", bound_addr))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        assert!(body.contains("Tlapix"));
        assert!(body.contains("Dashboard"));

        // Test GET /certificates
        let resp = reqwest::get(format!("http://{}/certificates", bound_addr))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        assert!(body.contains("Certificate Inventory"));

        // Test GET /anomalies
        let resp = reqwest::get(format!("http://{}/anomalies", bound_addr))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        assert!(body.contains("Active Anomalies"));

        // Test GET /actions
        let resp = reqwest::get(format!("http://{}/actions", bound_addr))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        assert!(body.contains("Recent Actions"));

        // Test GET /predictions
        let resp = reqwest::get(format!("http://{}/predictions", bound_addr))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        assert!(body.contains("Renewal Predictions"));

        // Shutdown
        cancel.cancel();
        let _ = server_handle.await;
    }
}
