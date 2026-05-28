//! Webhook dispatcher for delivering action notifications to external services.
//!
//! Supports PagerDuty, OpsGenie, and Slack integrations via HTTP POST with JSON payloads.
//! Implements retry with exponential backoff and failure tracking.

use std::time::Duration;

use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tlapix_common::config::WebhookConfig;
use tracing::{error, info, warn};

/// Event data to be dispatched via webhooks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    /// Correlation ID linking this event to the audit trail
    pub correlation_id: String,
    /// Hex-encoded SHA-256 fingerprint of the affected certificate
    pub cert_fingerprint: String,
    /// The action type that was executed (alert, renew, protect, isolate)
    pub action_type: String,
    /// Severity level (low, medium, high, critical)
    pub severity: String,
    /// ISO 8601 timestamp of the event
    pub timestamp: String,
    /// Optional reasoning for the action
    pub reasoning: Option<String>,
}

/// JSON payload sent to webhook endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    /// Source system identifier
    pub source: String,
    /// Payload format version
    pub version: String,
    /// Correlation ID for cross-referencing with audit trail
    pub correlation_id: String,
    /// Hex-encoded certificate fingerprint
    pub cert_fingerprint: String,
    /// Action type (alert, renew, protect, isolate)
    pub action_type: String,
    /// Severity level
    pub severity: String,
    /// ISO 8601 timestamp
    pub timestamp: String,
    /// Optional reasoning
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<String>,
}

impl WebhookPayload {
    /// Create a payload from a webhook event.
    pub fn from_event(event: &WebhookEvent) -> Self {
        Self {
            source: "tlapix".to_string(),
            version: "0.1.0".to_string(),
            correlation_id: event.correlation_id.clone(),
            cert_fingerprint: event.cert_fingerprint.clone(),
            action_type: event.action_type.clone(),
            severity: event.severity.clone(),
            timestamp: event.timestamp.clone(),
            reasoning: event.reasoning.clone(),
        }
    }
}

/// Result of a webhook delivery attempt to a single endpoint.
#[derive(Debug, Clone)]
pub struct WebhookDeliveryResult {
    /// The endpoint URL that was targeted
    pub endpoint: String,
    /// Whether delivery was successful (received 2xx response)
    pub success: bool,
    /// Number of attempts made (1 = first try succeeded, up to retry_max + 1)
    pub attempts: u8,
    /// Error description if delivery failed
    pub error: Option<String>,
}

/// Dispatches webhook notifications to configured endpoints.
///
/// Sends HTTP POST requests with JSON payloads to all configured webhook
/// endpoints. Supports PagerDuty, OpsGenie, and Slack integrations.
pub struct WebhookDispatcher {
    configs: Vec<WebhookConfig>,
    client: Client,
}

impl WebhookDispatcher {
    /// Create a new webhook dispatcher with the given endpoint configurations.
    pub fn new(configs: Vec<WebhookConfig>) -> Self {
        let client = Client::builder()
            .user_agent("tlapix/0.1.0")
            .build()
            .expect("failed to build HTTP client");

        Self { configs, client }
    }

    /// Dispatch a webhook event to all configured endpoints (fan-out).
    ///
    /// Returns a delivery result for each configured endpoint. All endpoints
    /// are attempted regardless of individual failures.
    pub async fn dispatch(&self, event: &WebhookEvent) -> Vec<WebhookDeliveryResult> {
        let payload = WebhookPayload::from_event(event);
        let mut results = Vec::with_capacity(self.configs.len());

        for config in &self.configs {
            let result = self.deliver_to_endpoint(config, &payload).await;
            results.push(result);
        }

        results
    }

    /// Deliver a payload to a single endpoint with retry logic.
    async fn deliver_to_endpoint(
        &self,
        config: &WebhookConfig,
        payload: &WebhookPayload,
    ) -> WebhookDeliveryResult {
        let timeout = Duration::from_secs(config.timeout_secs);
        let max_attempts = config.retry_max + 1; // initial attempt + retries

        let mut last_error: Option<String> = None;

        for attempt in 1..=max_attempts {
            match self.send_request(config, payload, timeout).await {
                Ok(()) => {
                    info!(
                        endpoint = %config.endpoint,
                        attempt,
                        correlation_id = %payload.correlation_id,
                        "Webhook delivered successfully"
                    );
                    return WebhookDeliveryResult {
                        endpoint: config.endpoint.clone(),
                        success: true,
                        attempts: attempt,
                        error: None,
                    };
                }
                Err(err) => {
                    last_error = Some(err.clone());

                    if attempt < max_attempts {
                        // Exponential backoff: base * 2^(attempt-1)
                        // For attempt 1 (first retry): base * 1 = 1s
                        // For attempt 2 (second retry): base * 2 = 2s
                        // For attempt 3 (third retry): base * 4 = 4s
                        let backoff_secs =
                            config.retry_base_secs * 2u64.pow((attempt - 1) as u32);
                        warn!(
                            endpoint = %config.endpoint,
                            attempt,
                            next_retry_secs = backoff_secs,
                            error = %err,
                            correlation_id = %payload.correlation_id,
                            "Webhook delivery failed, retrying"
                        );
                        tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    }
                }
            }
        }

        // All retries exhausted
        error!(
            endpoint = %config.endpoint,
            attempts = max_attempts,
            error = %last_error.as_deref().unwrap_or("unknown"),
            correlation_id = %payload.correlation_id,
            action_type = %payload.action_type,
            severity = %payload.severity,
            "Webhook delivery failed after all retries exhausted"
        );

        WebhookDeliveryResult {
            endpoint: config.endpoint.clone(),
            success: false,
            attempts: max_attempts,
            error: last_error,
        }
    }

    /// Send a single HTTP POST request to the endpoint.
    async fn send_request(
        &self,
        config: &WebhookConfig,
        payload: &WebhookPayload,
        timeout: Duration,
    ) -> Result<(), String> {
        let response = self
            .client
            .post(&config.endpoint)
            .timeout(timeout)
            .header("Content-Type", "application/json")
            .json(payload)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    format!("request timed out after {}s", timeout.as_secs())
                } else if e.is_connect() {
                    format!("connection failed: {}", e)
                } else {
                    format!("request failed: {}", e)
                }
            })?;

        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(format!("non-2xx response: {} {}", status.as_u16(), status.canonical_reason().unwrap_or("Unknown")))
        }
    }

    /// Create a `WebhookEvent` from action directive components.
    ///
    /// Helper to construct a webhook event from the typical fields available
    /// when an action directive is executed.
    pub fn create_event(
        correlation_id: &str,
        cert_fingerprint: &[u8; 32],
        action_type: &str,
        severity: &str,
        reasoning: Option<&str>,
    ) -> WebhookEvent {
        let fingerprint_hex = hex_encode(cert_fingerprint);
        let timestamp = Utc::now().to_rfc3339();

        WebhookEvent {
            correlation_id: correlation_id.to_string(),
            cert_fingerprint: fingerprint_hex,
            action_type: action_type.to_string(),
            severity: severity.to_string(),
            timestamp,
            reasoning: reasoning.map(|s| s.to_string()),
        }
    }
}

/// Encode bytes as lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;

    #[test]
    fn test_webhook_payload_from_event() {
        let event = WebhookEvent {
            correlation_id: "corr-123".to_string(),
            cert_fingerprint: "abcdef0123456789".to_string(),
            action_type: "alert".to_string(),
            severity: "critical".to_string(),
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            reasoning: Some("Certificate expired".to_string()),
        };

        let payload = WebhookPayload::from_event(&event);

        assert_eq!(payload.source, "tlapix");
        assert_eq!(payload.version, "0.1.0");
        assert_eq!(payload.correlation_id, "corr-123");
        assert_eq!(payload.cert_fingerprint, "abcdef0123456789");
        assert_eq!(payload.action_type, "alert");
        assert_eq!(payload.severity, "critical");
        assert_eq!(payload.timestamp, "2024-01-15T10:30:00Z");
        assert_eq!(payload.reasoning, Some("Certificate expired".to_string()));
    }

    #[test]
    fn test_webhook_payload_serialization() {
        let payload = WebhookPayload {
            source: "tlapix".to_string(),
            version: "0.1.0".to_string(),
            correlation_id: "id-1".to_string(),
            cert_fingerprint: "aabb".to_string(),
            action_type: "renew".to_string(),
            severity: "high".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            reasoning: None,
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"source\":\"tlapix\""));
        assert!(json.contains("\"version\":\"0.1.0\""));
        assert!(json.contains("\"correlation_id\":\"id-1\""));
        assert!(json.contains("\"cert_fingerprint\":\"aabb\""));
        assert!(json.contains("\"action_type\":\"renew\""));
        assert!(json.contains("\"severity\":\"high\""));
        assert!(json.contains("\"timestamp\":\"2024-01-01T00:00:00Z\""));
        // reasoning should be omitted when None
        assert!(!json.contains("reasoning"));
    }

    #[test]
    fn test_hex_encode() {
        let bytes = [0xab, 0xcd, 0xef, 0x01, 0x23];
        assert_eq!(hex_encode(&bytes), "abcdef0123");
    }

    #[test]
    fn test_hex_encode_all_zeros() {
        let bytes = [0u8; 32];
        let hex = hex_encode(&bytes);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c == '0'));
    }

    #[test]
    fn test_create_event() {
        let fingerprint = [0xaa; 32];
        let event = WebhookDispatcher::create_event(
            "corr-456",
            &fingerprint,
            "isolate",
            "critical",
            Some("Shadow cert detected"),
        );

        assert_eq!(event.correlation_id, "corr-456");
        assert_eq!(event.cert_fingerprint, "aa".repeat(32));
        assert_eq!(event.action_type, "isolate");
        assert_eq!(event.severity, "critical");
        assert_eq!(event.reasoning, Some("Shadow cert detected".to_string()));
        // timestamp should be a valid ISO 8601 string
        assert!(DateTime::parse_from_rfc3339(&event.timestamp).is_ok());
    }

    #[test]
    fn test_dispatcher_new_empty_configs() {
        let dispatcher = WebhookDispatcher::new(vec![]);
        // Should not panic with empty config
        assert_eq!(dispatcher.configs.len(), 0);
    }

    #[tokio::test]
    async fn test_dispatch_no_endpoints() {
        let dispatcher = WebhookDispatcher::new(vec![]);
        let event = WebhookEvent {
            correlation_id: "test".to_string(),
            cert_fingerprint: "ff".repeat(32),
            action_type: "alert".to_string(),
            severity: "low".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            reasoning: None,
        };

        let results = dispatcher.dispatch(&event).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_delivery_to_unreachable_endpoint() {
        let config = WebhookConfig {
            endpoint: "http://127.0.0.1:1".to_string(), // unreachable port
            timeout_secs: 1,
            retry_max: 0, // no retries for speed
            retry_base_secs: 1,
        };

        let dispatcher = WebhookDispatcher::new(vec![config]);
        let event = WebhookEvent {
            correlation_id: "test-unreachable".to_string(),
            cert_fingerprint: "00".repeat(32),
            action_type: "alert".to_string(),
            severity: "medium".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            reasoning: None,
        };

        let results = dispatcher.dispatch(&event).await;
        assert_eq!(results.len(), 1);
        assert!(!results[0].success);
        assert_eq!(results[0].attempts, 1);
        assert!(results[0].error.is_some());
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_event() -> WebhookEvent {
        WebhookEvent {
            correlation_id: "corr-integration-001".to_string(),
            cert_fingerprint: "ab".repeat(32),
            action_type: "alert".to_string(),
            severity: "critical".to_string(),
            timestamp: "2024-06-15T12:00:00Z".to_string(),
            reasoning: Some("Certificate near expiry".to_string()),
        }
    }

    #[tokio::test]
    async fn test_successful_delivery() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("content-type", "application/json"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = WebhookConfig {
            endpoint: mock_server.uri(),
            timeout_secs: 10,
            retry_max: 3,
            retry_base_secs: 1,
        };

        let dispatcher = WebhookDispatcher::new(vec![config]);
        let event = make_event();
        let results = dispatcher.dispatch(&event).await;

        assert_eq!(results.len(), 1);
        assert!(results[0].success);
        assert_eq!(results[0].attempts, 1);
        assert!(results[0].error.is_none());
    }

    #[tokio::test]
    async fn test_payload_contains_required_fields() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = WebhookConfig {
            endpoint: mock_server.uri(),
            timeout_secs: 10,
            retry_max: 3,
            retry_base_secs: 1,
        };

        let dispatcher = WebhookDispatcher::new(vec![config]);
        let event = make_event();
        dispatcher.dispatch(&event).await;

        // Verify the request was received
        let requests = mock_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);

        let body: serde_json::Value =
            serde_json::from_slice(&requests[0].body).unwrap();

        // Verify all required fields are present (Requirement 10.9)
        assert_eq!(body["correlation_id"], "corr-integration-001");
        assert_eq!(body["cert_fingerprint"], "ab".repeat(32));
        assert_eq!(body["action_type"], "alert");
        assert_eq!(body["severity"], "critical");
        assert_eq!(body["timestamp"], "2024-06-15T12:00:00Z");
        assert_eq!(body["source"], "tlapix");
        assert_eq!(body["version"], "0.1.0");
    }

    #[tokio::test]
    async fn test_retry_on_server_error() {
        let mock_server = MockServer::start().await;

        // First 2 requests return 500, third returns 200
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(2)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let config = WebhookConfig {
            endpoint: mock_server.uri(),
            timeout_secs: 10,
            retry_max: 3,
            retry_base_secs: 1,
        };

        let dispatcher = WebhookDispatcher::new(vec![config]);
        let event = make_event();
        let results = dispatcher.dispatch(&event).await;

        assert_eq!(results.len(), 1);
        assert!(results[0].success);
        assert_eq!(results[0].attempts, 3); // 2 failures + 1 success
    }

    #[tokio::test]
    async fn test_exhausted_retries() {
        let mock_server = MockServer::start().await;

        // Always return 503
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock_server)
            .await;

        let config = WebhookConfig {
            endpoint: mock_server.uri(),
            timeout_secs: 10,
            retry_max: 2, // 2 retries = 3 total attempts
            retry_base_secs: 1,
        };

        let dispatcher = WebhookDispatcher::new(vec![config]);
        let event = make_event();
        let results = dispatcher.dispatch(&event).await;

        assert_eq!(results.len(), 1);
        assert!(!results[0].success);
        assert_eq!(results[0].attempts, 3); // initial + 2 retries
        assert!(results[0].error.is_some());
        assert!(results[0].error.as_ref().unwrap().contains("503"));
    }

    #[tokio::test]
    async fn test_fan_out_to_multiple_endpoints() {
        let server1 = MockServer::start().await;
        let server2 = MockServer::start().await;
        let server3 = MockServer::start().await;

        for server in [&server1, &server2, &server3] {
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
                .mount(server)
                .await;
        }

        let configs = vec![
            WebhookConfig {
                endpoint: server1.uri(),
                timeout_secs: 10,
                retry_max: 3,
                retry_base_secs: 1,
            },
            WebhookConfig {
                endpoint: server2.uri(),
                timeout_secs: 10,
                retry_max: 3,
                retry_base_secs: 1,
            },
            WebhookConfig {
                endpoint: server3.uri(),
                timeout_secs: 10,
                retry_max: 3,
                retry_base_secs: 1,
            },
        ];

        let dispatcher = WebhookDispatcher::new(configs);
        let event = make_event();
        let results = dispatcher.dispatch(&event).await;

        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.success));
    }

    #[tokio::test]
    async fn test_partial_failure_does_not_block_others() {
        let server1 = MockServer::start().await;
        let server2 = MockServer::start().await;

        // Server 1 always fails
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server1)
            .await;

        // Server 2 succeeds
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server2)
            .await;

        let configs = vec![
            WebhookConfig {
                endpoint: server1.uri(),
                timeout_secs: 10,
                retry_max: 0, // no retries for speed
                retry_base_secs: 1,
            },
            WebhookConfig {
                endpoint: server2.uri(),
                timeout_secs: 10,
                retry_max: 0,
                retry_base_secs: 1,
            },
        ];

        let dispatcher = WebhookDispatcher::new(configs);
        let event = make_event();
        let results = dispatcher.dispatch(&event).await;

        assert_eq!(results.len(), 2);
        assert!(!results[0].success); // server1 failed
        assert!(results[1].success); // server2 succeeded
    }

    #[tokio::test]
    async fn test_pagerduty_compatible_payload() {
        // PagerDuty expects JSON with specific fields — our payload includes
        // all required fields that PagerDuty/OpsGenie/Slack can consume
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(header("content-type", "application/json"))
            .respond_with(ResponseTemplate::new(202)) // PagerDuty returns 202
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = WebhookConfig {
            endpoint: format!("{}/v2/enqueue", mock_server.uri()),
            timeout_secs: 10,
            retry_max: 3,
            retry_base_secs: 1,
        };

        let dispatcher = WebhookDispatcher::new(vec![config]);
        let event = WebhookEvent {
            correlation_id: "pd-corr-001".to_string(),
            cert_fingerprint: "ff".repeat(32),
            action_type: "isolate".to_string(),
            severity: "critical".to_string(),
            timestamp: "2024-06-15T12:00:00Z".to_string(),
            reasoning: Some("Shadow certificate with weak key detected".to_string()),
        };

        let results = dispatcher.dispatch(&event).await;
        assert_eq!(results.len(), 1);
        assert!(results[0].success);
    }

    #[tokio::test]
    async fn test_timeout_handling() {
        let mock_server = MockServer::start().await;

        // Respond with a 2-second delay (exceeds our 1s timeout)
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("ok").set_delay(
                    std::time::Duration::from_secs(2),
                ),
            )
            .mount(&mock_server)
            .await;

        let config = WebhookConfig {
            endpoint: mock_server.uri(),
            timeout_secs: 1, // 1 second timeout
            retry_max: 0,    // no retries for speed
            retry_base_secs: 1,
        };

        let dispatcher = WebhookDispatcher::new(vec![config]);
        let event = make_event();
        let results = dispatcher.dispatch(&event).await;

        assert_eq!(results.len(), 1);
        assert!(!results[0].success);
        assert!(results[0].error.as_ref().unwrap().contains("timed out"));
    }
}
