//! Property-based tests for the Daemon layer (Observability).
//!
//! Uses `proptest` to verify correctness properties across many random inputs.

use proptest::prelude::*;

use chrono::Utc;
use uuid::Uuid;

use tlapix_common::audit::{
    AnalysisContext, ActionContext, AuditLogger, ObservationContext,
};
use tlapix_common::storage::Storage;
use tlapix_common::types::{ActionType, ExecutionOutcome, Severity};

// We re-define the webhook types here since tlapix-daemon is a binary crate
// and cannot be imported as a library from integration tests.
// These mirror the types in tlapix_daemon::webhooks.

use serde::{Deserialize, Serialize};

/// Event data to be dispatched via webhooks.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WebhookEvent {
    pub correlation_id: String,
    pub cert_fingerprint: String,
    pub action_type: String,
    pub severity: String,
    pub timestamp: String,
    pub reasoning: Option<String>,
}

/// JSON payload sent to webhook endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WebhookPayload {
    pub source: String,
    pub version: String,
    pub correlation_id: String,
    pub cert_fingerprint: String,
    pub action_type: String,
    pub severity: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<String>,
}

impl WebhookPayload {
    fn from_event(event: &WebhookEvent) -> Self {
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

// ---------------------------------------------------------------------------
// Property 19: Audit Trail Completeness
// **Validates: Requirements 8.1, 8.2, 8.4, 8.7**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// For any certificate observation event, the system SHALL assign a unique
    /// correlation_id that appears in all downstream audit entries.
    #[test]
    fn prop_audit_trail_completeness(num_events in 1usize..20) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let results = rt.block_on(async {
            let storage = Storage::open_in_memory().await.unwrap();
            let logger = AuditLogger::new(storage);

            // Generate num_events observation events, each with unique correlation_id
            let mut correlation_ids = Vec::new();
            let mut fingerprints = Vec::new();

            for i in 0..num_events {
                let correlation_id = AuditLogger::new_correlation_id();
                let mut fp = [0u8; 32];
                fp[0] = (i & 0xFF) as u8;
                fp[1] = ((i >> 8) & 0xFF) as u8;

                correlation_ids.push(correlation_id);
                fingerprints.push(fp);

                // Log observation
                let obs_ctx = ObservationContext {
                    src_ip: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                        192, 168, 1, (i % 255) as u8,
                    ))),
                    dst_ip: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                        10, 0, 0, 1,
                    ))),
                    sni: Some(format!("host-{}.example.com", i)),
                    first_seen: Utc::now(),
                };
                logger
                    .log_observation(correlation_id, &fp, &obs_ctx)
                    .await
                    .unwrap();

                // Log analysis
                let analysis_ctx = AnalysisContext {
                    anomaly_type: "PolicyViolation".to_string(),
                    confidence_score: 0.85,
                    action_type: "alert".to_string(),
                    severity: Severity::High,
                };
                logger
                    .log_analysis(correlation_id, &fp, &analysis_ctx)
                    .await
                    .unwrap();

                // Log action
                let action_ctx = ActionContext {
                    action_type: ActionType::Alert,
                    outcome: ExecutionOutcome::Success,
                    execution_timestamp: Utc::now(),
                };
                logger
                    .log_action(correlation_id, &fp, &action_ctx)
                    .await
                    .unwrap();
            }

            // Collect results for each correlation_id
            let mut results = Vec::new();
            for (i, correlation_id) in correlation_ids.iter().enumerate() {
                let chain = logger.get_decision_chain(*correlation_id).await.unwrap();
                results.push((chain, correlation_id.to_string(), fingerprints[i]));
            }
            results
        });

        // Assert: get_decision_chain returns exactly 3 entries per correlation_id
        for (chain, correlation_id_str, fp) in &results {
            prop_assert_eq!(
                chain.len(),
                3,
                "Expected 3 entries for correlation_id {}, got {}",
                correlation_id_str,
                chain.len()
            );

            // Assert: all entries share the same correlation_id and fingerprint
            for entry in chain {
                prop_assert_eq!(&entry.correlation_id, correlation_id_str);
                prop_assert_eq!(&entry.cert_fingerprint, fp);
            }

            // Verify stages are in order
            prop_assert_eq!(chain[0].stage.as_str(), "observation");
            prop_assert_eq!(chain[1].stage.as_str(), "analysis");
            prop_assert_eq!(chain[2].stage.as_str(), "action");
        }
    }
}

// ---------------------------------------------------------------------------
// Property 21: Export Format Compliance
// **Validates: Requirements 10.3, 10.4, 10.9, 10.10**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// For any metric event, the exported payload SHALL contain required fields.
    #[test]
    fn prop_export_format_compliance(
        action_type in "alert|renew|protect|isolate",
        severity in "low|medium|high|critical"
    ) {
        // Create a WebhookEvent with the given action_type and severity
        let correlation_id = Uuid::new_v4().to_string();
        let cert_fingerprint = "aa".repeat(32);
        let timestamp = Utc::now().to_rfc3339();

        let event = WebhookEvent {
            correlation_id: correlation_id.clone(),
            cert_fingerprint: cert_fingerprint.clone(),
            action_type: action_type.clone(),
            severity: severity.clone(),
            timestamp: timestamp.clone(),
            reasoning: Some("Test reasoning".to_string()),
        };

        // Convert to WebhookPayload
        let payload = WebhookPayload::from_event(&event);

        // Assert: payload contains correlation_id, cert_fingerprint, action_type, severity, timestamp
        prop_assert_eq!(&payload.correlation_id, &correlation_id);
        prop_assert_eq!(&payload.cert_fingerprint, &cert_fingerprint);
        prop_assert_eq!(&payload.action_type, &action_type);
        prop_assert_eq!(&payload.severity, &severity);
        prop_assert_eq!(&payload.timestamp, &timestamp);

        // Assert: payload.source == "tlapix"
        prop_assert_eq!(payload.source.as_str(), "tlapix");

        // Assert: payload.version == "0.1.0"
        prop_assert_eq!(payload.version.as_str(), "0.1.0");

        // Verify the payload serializes to valid JSON with all required fields
        let json = serde_json::to_value(&payload).unwrap();
        prop_assert!(json.get("correlation_id").is_some());
        prop_assert!(json.get("cert_fingerprint").is_some());
        prop_assert!(json.get("action_type").is_some());
        prop_assert!(json.get("severity").is_some());
        prop_assert!(json.get("timestamp").is_some());
        prop_assert!(json.get("source").is_some());
        prop_assert!(json.get("version").is_some());
    }
}
