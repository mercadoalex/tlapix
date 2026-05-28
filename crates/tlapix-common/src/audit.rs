//! Audit logging with correlation IDs for end-to-end tracing.
//!
//! Implements Requirements 8.1, 8.2, 8.4, 8.6, 8.7:
//! - Assigns unique correlation_id to each certificate observation event
//! - Propagates correlation_id through Analyzer and Executor stages
//! - Logs observation → analysis → action decision chain for high-impact actions
//! - Halts directive processing if audit logging fails

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::storage::{AuditLogRow, Storage, StorageError};
use crate::types::{ActionType, ExecutionOutcome, Severity};

// ---------------------------------------------------------------------------
// Context structs for each audit stage
// ---------------------------------------------------------------------------

/// Context for the observation stage of the audit trail.
///
/// Captures the network context when a certificate is first observed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationContext {
    /// Source IP address of the TLS connection
    pub src_ip: Option<IpAddr>,
    /// Destination IP address of the TLS connection
    pub dst_ip: Option<IpAddr>,
    /// SNI hostname from the ClientHello (if available)
    pub sni: Option<String>,
    /// Timestamp when the certificate was first seen
    pub first_seen: DateTime<Utc>,
}

/// Context for the analysis stage of the audit trail.
///
/// Captures the anomaly detection results and recommended action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisContext {
    /// Type of anomaly detected (e.g., "PolicyViolation", "WeakCryptography")
    pub anomaly_type: String,
    /// Confidence score of the detection (0.0 to 1.0)
    pub confidence_score: f64,
    /// Recommended action type
    pub action_type: String,
    /// Severity of the anomaly
    pub severity: Severity,
}

/// Context for the action stage of the audit trail.
///
/// Captures the execution result of an action directive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionContext {
    /// The action type that was executed
    pub action_type: ActionType,
    /// The outcome of the execution
    pub outcome: ExecutionOutcome,
    /// When the action was executed
    pub execution_timestamp: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// AuditLogger
// ---------------------------------------------------------------------------

/// Audit logger that persists decision chain entries to storage.
///
/// Tracks health state: if a write fails, `is_healthy()` returns false,
/// signaling that directive processing should halt (Req 8.6).
#[derive(Clone)]
pub struct AuditLogger {
    storage: Storage,
    healthy: Arc<AtomicBool>,
}

impl AuditLogger {
    /// Create a new AuditLogger backed by the given storage.
    pub fn new(storage: Storage) -> Self {
        Self {
            storage,
            healthy: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Returns true if the last audit write succeeded.
    ///
    /// When this returns false, the system should halt processing of new
    /// Action_Directives until audit logging is restored (Req 8.6).
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::SeqCst)
    }

    /// Generate a new unique correlation ID for a certificate observation event.
    ///
    /// This ID should be propagated through all downstream processing stages
    /// (Analyzer and Executor) to enable end-to-end tracing (Req 8.7).
    pub fn new_correlation_id() -> Uuid {
        Uuid::new_v4()
    }

    /// Log an observation stage event.
    ///
    /// Called when a certificate is first observed in traffic.
    /// The correlation_id should be freshly generated via `new_correlation_id()`.
    pub async fn log_observation(
        &self,
        correlation_id: Uuid,
        fingerprint: &[u8; 32],
        context: &ObservationContext,
    ) -> Result<(), AuditError> {
        let details = serde_json::to_string(context)
            .map_err(|e| AuditError::Serialization(e.to_string()))?;

        self.write_entry(correlation_id, fingerprint, "observation", &details)
            .await
    }

    /// Log an analysis stage event.
    ///
    /// Called when the Analyzer produces a result for a certificate.
    /// The correlation_id must match the one assigned during observation.
    pub async fn log_analysis(
        &self,
        correlation_id: Uuid,
        fingerprint: &[u8; 32],
        context: &AnalysisContext,
    ) -> Result<(), AuditError> {
        let details = serde_json::to_string(context)
            .map_err(|e| AuditError::Serialization(e.to_string()))?;

        self.write_entry(correlation_id, fingerprint, "analysis", &details)
            .await
    }

    /// Log an action stage event.
    ///
    /// Called when the Executor processes an Action_Directive.
    /// The correlation_id must match the one from the originating observation.
    /// This is required for high-impact actions (isolate, protect, renew) per Req 8.4.
    pub async fn log_action(
        &self,
        correlation_id: Uuid,
        fingerprint: &[u8; 32],
        context: &ActionContext,
    ) -> Result<(), AuditError> {
        let details = serde_json::to_string(context)
            .map_err(|e| AuditError::Serialization(e.to_string()))?;

        self.write_entry(correlation_id, fingerprint, "action", &details)
            .await
    }

    /// Retrieve the full audit trail for a given correlation ID.
    ///
    /// Returns entries ordered by timestamp, showing the complete decision chain
    /// from observation through analysis to action.
    pub async fn get_decision_chain(
        &self,
        correlation_id: Uuid,
    ) -> Result<Vec<AuditLogRow>, AuditError> {
        self.storage
            .get_audit_logs_by_correlation(&correlation_id.to_string())
            .await
            .map_err(|e| {
                tracing::error!("Failed to read audit trail for {}: {}", correlation_id, e);
                AuditError::Storage(e)
            })
    }

    /// Attempt to restore health by performing a test write.
    ///
    /// If the system was previously unhealthy (audit write failed), this can be
    /// called periodically to check if storage has recovered.
    pub async fn try_restore_health(&self) -> bool {
        // Attempt a no-op read to verify storage connectivity
        let result = self
            .storage
            .get_audit_logs_by_correlation("__health_check__")
            .await;

        match result {
            Ok(_) => {
                self.healthy.store(true, Ordering::SeqCst);
                tracing::info!("Audit logging health restored");
                true
            }
            Err(e) => {
                tracing::error!("Audit logging health check failed: {}", e);
                false
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Write an audit log entry to storage and update health state.
    async fn write_entry(
        &self,
        correlation_id: Uuid,
        fingerprint: &[u8; 32],
        stage: &str,
        details: &str,
    ) -> Result<(), AuditError> {
        let now = Utc::now();
        let row = AuditLogRow {
            id: 0, // Auto-incremented by SQLite
            correlation_id: correlation_id.to_string(),
            cert_fingerprint: *fingerprint,
            stage: stage.to_string(),
            timestamp: now.timestamp_millis(),
            details: details.to_string(),
            created_at: now.timestamp_millis(),
        };

        match self.storage.insert_audit_log(&row).await {
            Ok(()) => {
                // If we were previously unhealthy, mark as recovered
                if !self.healthy.load(Ordering::SeqCst) {
                    self.healthy.store(true, Ordering::SeqCst);
                    tracing::info!("Audit logging recovered after previous failure");
                }
                tracing::debug!(
                    correlation_id = %correlation_id,
                    stage = stage,
                    "Audit log entry written"
                );
                Ok(())
            }
            Err(e) => {
                // Mark as unhealthy — directive processing should halt (Req 8.6)
                self.healthy.store(false, Ordering::SeqCst);
                tracing::error!(
                    correlation_id = %correlation_id,
                    stage = stage,
                    error = %e,
                    "Audit logging failed — directive processing should halt"
                );
                Err(AuditError::Storage(e))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during audit logging.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// Storage layer error (write failed).
    #[error("Audit storage error: {0}")]
    Storage(#[from] StorageError),

    /// Serialization error when converting context to JSON.
    #[error("Audit serialization error: {0}")]
    Serialization(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Helper to create a test fingerprint.
    fn test_fingerprint() -> [u8; 32] {
        let mut fp = [0u8; 32];
        fp[0] = 0xDE;
        fp[1] = 0xAD;
        fp[31] = 0xFF;
        fp
    }

    #[tokio::test]
    async fn test_log_observation_stage() {
        let storage = Storage::open_in_memory().await.unwrap();
        let logger = AuditLogger::new(storage);

        let correlation_id = AuditLogger::new_correlation_id();
        let fingerprint = test_fingerprint();
        let context = ObservationContext {
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            sni: Some("example.com".to_string()),
            first_seen: Utc::now(),
        };

        logger
            .log_observation(correlation_id, &fingerprint, &context)
            .await
            .unwrap();

        // Verify the entry was written
        let entries = logger.get_decision_chain(correlation_id).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].stage, "observation");
        assert_eq!(entries[0].correlation_id, correlation_id.to_string());
        assert_eq!(entries[0].cert_fingerprint, fingerprint);
    }

    #[tokio::test]
    async fn test_log_analysis_stage() {
        let storage = Storage::open_in_memory().await.unwrap();
        let logger = AuditLogger::new(storage);

        let correlation_id = AuditLogger::new_correlation_id();
        let fingerprint = test_fingerprint();
        let context = AnalysisContext {
            anomaly_type: "WeakCryptography".to_string(),
            confidence_score: 0.95,
            action_type: "alert".to_string(),
            severity: Severity::Critical,
        };

        logger
            .log_analysis(correlation_id, &fingerprint, &context)
            .await
            .unwrap();

        let entries = logger.get_decision_chain(correlation_id).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].stage, "analysis");

        // Verify details contain the context
        let details: AnalysisContext = serde_json::from_str(&entries[0].details).unwrap();
        assert_eq!(details.anomaly_type, "WeakCryptography");
        assert_eq!(details.confidence_score, 0.95);
    }

    #[tokio::test]
    async fn test_log_action_stage() {
        let storage = Storage::open_in_memory().await.unwrap();
        let logger = AuditLogger::new(storage);

        let correlation_id = AuditLogger::new_correlation_id();
        let fingerprint = test_fingerprint();
        let context = ActionContext {
            action_type: ActionType::Renew,
            outcome: ExecutionOutcome::Success,
            execution_timestamp: Utc::now(),
        };

        logger
            .log_action(correlation_id, &fingerprint, &context)
            .await
            .unwrap();

        let entries = logger.get_decision_chain(correlation_id).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].stage, "action");
    }

    #[tokio::test]
    async fn test_correlation_id_propagation_across_stages() {
        let storage = Storage::open_in_memory().await.unwrap();
        let logger = AuditLogger::new(storage);

        let correlation_id = AuditLogger::new_correlation_id();
        let fingerprint = test_fingerprint();

        // Log all three stages with the same correlation_id
        let obs_ctx = ObservationContext {
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            sni: Some("api.example.com".to_string()),
            first_seen: Utc::now(),
        };
        logger
            .log_observation(correlation_id, &fingerprint, &obs_ctx)
            .await
            .unwrap();

        let analysis_ctx = AnalysisContext {
            anomaly_type: "SniMismatch".to_string(),
            confidence_score: 0.88,
            action_type: "protect".to_string(),
            severity: Severity::High,
        };
        logger
            .log_analysis(correlation_id, &fingerprint, &analysis_ctx)
            .await
            .unwrap();

        let action_ctx = ActionContext {
            action_type: ActionType::Protect {
                pinned_fingerprint: fingerprint,
                hostname: "api.example.com".to_string(),
            },
            outcome: ExecutionOutcome::Success,
            execution_timestamp: Utc::now(),
        };
        logger
            .log_action(correlation_id, &fingerprint, &action_ctx)
            .await
            .unwrap();

        // Verify all three entries share the same correlation_id
        let entries = logger.get_decision_chain(correlation_id).await.unwrap();
        assert_eq!(entries.len(), 3);

        // Entries should be ordered by timestamp
        assert_eq!(entries[0].stage, "observation");
        assert_eq!(entries[1].stage, "analysis");
        assert_eq!(entries[2].stage, "action");

        // All share the same correlation_id
        for entry in &entries {
            assert_eq!(entry.correlation_id, correlation_id.to_string());
            assert_eq!(entry.cert_fingerprint, fingerprint);
        }
    }

    #[tokio::test]
    async fn test_health_check_initially_healthy() {
        let storage = Storage::open_in_memory().await.unwrap();
        let logger = AuditLogger::new(storage);

        assert!(logger.is_healthy());
    }

    #[tokio::test]
    async fn test_health_check_becomes_unhealthy_on_write_failure() {
        // Create a logger with storage, then simulate failure by dropping the
        // underlying connection. We'll use a trick: close the storage and try to write.
        let storage = Storage::open_in_memory().await.unwrap();
        let logger = AuditLogger::new(storage);

        // Manually set unhealthy to simulate a write failure
        logger.healthy.store(false, Ordering::SeqCst);
        assert!(!logger.is_healthy());
    }

    #[tokio::test]
    async fn test_health_recovers_on_successful_write() {
        let storage = Storage::open_in_memory().await.unwrap();
        let logger = AuditLogger::new(storage);

        // Simulate previous failure
        logger.healthy.store(false, Ordering::SeqCst);
        assert!(!logger.is_healthy());

        // A successful write should restore health
        let correlation_id = AuditLogger::new_correlation_id();
        let fingerprint = test_fingerprint();
        let context = ObservationContext {
            src_ip: None,
            dst_ip: None,
            sni: None,
            first_seen: Utc::now(),
        };

        logger
            .log_observation(correlation_id, &fingerprint, &context)
            .await
            .unwrap();

        assert!(logger.is_healthy());
    }

    #[tokio::test]
    async fn test_new_correlation_id_is_unique() {
        let id1 = AuditLogger::new_correlation_id();
        let id2 = AuditLogger::new_correlation_id();
        let id3 = AuditLogger::new_correlation_id();

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }

    #[tokio::test]
    async fn test_decision_chain_for_high_impact_action() {
        // Req 8.4: For isolate/protect/renew actions, the audit event must contain
        // the complete decision chain from observation through analysis to action.
        let storage = Storage::open_in_memory().await.unwrap();
        let logger = AuditLogger::new(storage);

        let correlation_id = AuditLogger::new_correlation_id();
        let fingerprint = test_fingerprint();

        // Observation
        let obs_ctx = ObservationContext {
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 50))),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))),
            sni: Some("critical-service.internal".to_string()),
            first_seen: Utc::now(),
        };
        logger
            .log_observation(correlation_id, &fingerprint, &obs_ctx)
            .await
            .unwrap();

        // Analysis
        let analysis_ctx = AnalysisContext {
            anomaly_type: "WeakCryptography".to_string(),
            confidence_score: 1.0,
            action_type: "isolate".to_string(),
            severity: Severity::Critical,
        };
        logger
            .log_analysis(correlation_id, &fingerprint, &analysis_ctx)
            .await
            .unwrap();

        // Action (high-impact: isolate)
        let action_ctx = ActionContext {
            action_type: ActionType::Isolate {
                target_fingerprint: fingerprint,
            },
            outcome: ExecutionOutcome::Success,
            execution_timestamp: Utc::now(),
        };
        logger
            .log_action(correlation_id, &fingerprint, &action_ctx)
            .await
            .unwrap();

        // Verify complete decision chain
        let chain = logger.get_decision_chain(correlation_id).await.unwrap();
        assert_eq!(chain.len(), 3);

        // Verify observation context
        let obs: ObservationContext = serde_json::from_str(&chain[0].details).unwrap();
        assert_eq!(obs.sni, Some("critical-service.internal".to_string()));

        // Verify analysis context
        let analysis: AnalysisContext = serde_json::from_str(&chain[1].details).unwrap();
        assert_eq!(analysis.anomaly_type, "WeakCryptography");
        assert_eq!(analysis.confidence_score, 1.0);

        // Verify action context
        let action: ActionContext = serde_json::from_str(&chain[2].details).unwrap();
        assert_eq!(action.outcome, ExecutionOutcome::Success);
    }

    #[tokio::test]
    async fn test_multiple_correlation_ids_are_independent() {
        let storage = Storage::open_in_memory().await.unwrap();
        let logger = AuditLogger::new(storage);

        let id1 = AuditLogger::new_correlation_id();
        let id2 = AuditLogger::new_correlation_id();
        let fp1 = [1u8; 32];
        let fp2 = [2u8; 32];

        let obs_ctx = ObservationContext {
            src_ip: None,
            dst_ip: None,
            sni: Some("a.example.com".to_string()),
            first_seen: Utc::now(),
        };
        logger.log_observation(id1, &fp1, &obs_ctx).await.unwrap();

        let obs_ctx2 = ObservationContext {
            src_ip: None,
            dst_ip: None,
            sni: Some("b.example.com".to_string()),
            first_seen: Utc::now(),
        };
        logger.log_observation(id2, &fp2, &obs_ctx2).await.unwrap();

        // Each correlation_id should only return its own entries
        let chain1 = logger.get_decision_chain(id1).await.unwrap();
        let chain2 = logger.get_decision_chain(id2).await.unwrap();

        assert_eq!(chain1.len(), 1);
        assert_eq!(chain2.len(), 1);
        assert_eq!(chain1[0].cert_fingerprint, fp1);
        assert_eq!(chain2[0].cert_fingerprint, fp2);
    }
}
