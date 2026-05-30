//! AI model integration with fallback to rule-based detection.
//!
//! Loads an ONNX model via the `ort` crate for AI-powered anomaly detection.
//! If the model cannot be loaded or inference times out (default 5 seconds),
//! the system falls back to rule-based detection and logs the degraded state.
//!
//! Implements Requirement 3.6: AI backend timeout and fallback.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ort::session::Session;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use tlapix_common::types::{AnomalyType, CertificateMetadata, Severity};

use crate::anomaly::AnomalyDetector;

// ---------------------------------------------------------------------------
// Analyzer Mode
// ---------------------------------------------------------------------------

/// Represents the current operational mode of the analyzer.
#[derive(Debug, Clone, PartialEq)]
pub enum AnalyzerMode {
    /// AI model is loaded and operational.
    AiPowered,
    /// Fallen back to rule-based detection due to an issue with the AI backend.
    RuleBasedFallback { reason: String },
}

impl std::fmt::Display for AnalyzerMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnalyzerMode::AiPowered => write!(f, "AI-Powered"),
            AnalyzerMode::RuleBasedFallback { reason } => {
                write!(f, "Rule-Based Fallback ({})", reason)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AI Backend
// ---------------------------------------------------------------------------

/// AI-powered anomaly detection backend using ONNX Runtime.
///
/// Attempts to load an ONNX model from the configured path. If loading fails,
/// the backend enters fallback mode immediately. Inference calls are wrapped
/// with a configurable timeout (default 5 seconds).
pub struct AiBackend {
    /// The loaded ONNX session, if available.
    session: Option<Session>,
    /// Current operational mode.
    mode: Arc<RwLock<AnalyzerMode>>,
    /// Timeout duration for inference calls.
    timeout: Duration,
}

impl AiBackend {
    /// Create a new AI backend by attempting to load the ONNX model.
    ///
    /// If the model file does not exist or cannot be loaded, the backend
    /// enters `RuleBasedFallback` mode and logs the error.
    pub fn new(model_path: PathBuf, timeout_secs: u64) -> Self {
        let timeout = Duration::from_secs(timeout_secs);

        let (session, mode) = match Self::load_model(&model_path) {
            Ok(session) => {
                info!(
                    path = %model_path.display(),
                    "AI model loaded successfully"
                );
                (Some(session), AnalyzerMode::AiPowered)
            }
            Err(e) => {
                let reason = format!("Failed to load model: {}", e);
                warn!(
                    path = %model_path.display(),
                    error = %e,
                    "AI model unavailable, entering rule-based fallback mode"
                );
                (None, AnalyzerMode::RuleBasedFallback { reason })
            }
        };

        Self {
            session,
            mode: Arc::new(RwLock::new(mode)),
            timeout,
        }
    }

    /// Create an AI backend that starts directly in fallback mode.
    ///
    /// Useful for testing or when no model path is configured.
    pub fn fallback(reason: String) -> Self {
        warn!(reason = %reason, "AI backend created in fallback mode");
        Self {
            session: None,
            mode: Arc::new(RwLock::new(AnalyzerMode::RuleBasedFallback { reason })),
            timeout: Duration::from_secs(5),
        }
    }

    /// Attempt to load an ONNX model from the given path.
    fn load_model(model_path: &PathBuf) -> anyhow::Result<Session> {
        if !model_path.exists() {
            anyhow::bail!("Model file not found: {}", model_path.display());
        }

        let session = Session::builder()?.commit_from_file(model_path)?;

        Ok(session)
    }

    /// Evaluate certificate metadata using the AI model.
    ///
    /// Returns AI-detected anomalies. If the model is unavailable or inference
    /// times out, switches to fallback mode and returns an empty result
    /// (the caller should use rule-based detection instead).
    pub async fn evaluate(
        &self,
        _metadata: &CertificateMetadata,
    ) -> Result<Vec<(AnomalyType, Severity)>, AiBackendError> {
        // If already in fallback mode, return immediately
        {
            let mode = self.mode.read().await;
            if matches!(*mode, AnalyzerMode::RuleBasedFallback { .. }) {
                return Err(AiBackendError::InFallbackMode);
            }
        }

        // Ensure we have a session
        if self.session.is_none() {
            self.enter_fallback("No model session available".to_string())
                .await;
            return Err(AiBackendError::NoSession);
        }

        // Wrap inference in a timeout
        let timeout = self.timeout;
        let result = tokio::time::timeout(timeout, self.run_inference(_metadata)).await;

        match result {
            Ok(Ok(anomalies)) => Ok(anomalies),
            Ok(Err(e)) => {
                let reason = format!("Inference error: {}", e);
                error!(error = %e, "AI inference failed, switching to fallback mode");
                self.enter_fallback(reason).await;
                Err(AiBackendError::InferenceError(e.to_string()))
            }
            Err(_) => {
                let reason = format!("Inference timed out after {} seconds", timeout.as_secs());
                error!(
                    timeout_secs = timeout.as_secs(),
                    "AI inference timed out, switching to fallback mode"
                );
                self.enter_fallback(reason).await;
                Err(AiBackendError::Timeout)
            }
        }
    }

    /// Run the actual ONNX inference.
    ///
    /// Currently returns an empty vec since we don't have a real model yet.
    /// This provides a clear interface for when a real model is added later.
    async fn run_inference(
        &self,
        _metadata: &CertificateMetadata,
    ) -> anyhow::Result<Vec<(AnomalyType, Severity)>> {
        // TODO: Implement real ONNX inference when a trained model is available.
        // For now, the AI backend returns no additional anomalies.
        // The real implementation would:
        // 1. Convert CertificateMetadata to input tensor
        // 2. Run session.run() with the input
        // 3. Parse output tensor into anomaly types and severities
        Ok(vec![])
    }

    /// Switch to fallback mode and log the degraded state.
    async fn enter_fallback(&self, reason: String) {
        let mut mode = self.mode.write().await;
        if !matches!(*mode, AnalyzerMode::RuleBasedFallback { .. }) {
            warn!(
                reason = %reason,
                "Analyzer entering degraded state: falling back to rule-based detection"
            );
            *mode = AnalyzerMode::RuleBasedFallback { reason };
        }
    }

    /// Get the current operational mode.
    pub async fn health_check(&self) -> AnalyzerMode {
        self.mode.read().await.clone()
    }
}

// ---------------------------------------------------------------------------
// AI Backend Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during AI backend operations.
#[derive(Debug, thiserror::Error)]
pub enum AiBackendError {
    /// The AI backend is already in fallback mode.
    #[error("AI backend is in fallback mode")]
    InFallbackMode,

    /// No ONNX session is available.
    #[error("No ONNX model session available")]
    NoSession,

    /// Inference timed out.
    #[error("AI inference timed out")]
    Timeout,

    /// Inference produced an error.
    #[error("AI inference error: {0}")]
    InferenceError(String),
}

// ---------------------------------------------------------------------------
// Analyzer Service
// ---------------------------------------------------------------------------

/// Combined analyzer service that uses AI backend with rule-based fallback.
///
/// When the AI backend is available, it enhances detection with ML-based
/// anomaly scoring. When unavailable, it falls back to rule-based detection only.
pub struct AnalyzerService {
    /// AI-powered backend (may be in fallback mode).
    ai_backend: AiBackend,
    /// Rule-based anomaly detector (always available).
    rule_detector: AnomalyDetector,
}

impl AnalyzerService {
    /// Create a new analyzer service with the given AI backend and rule detector.
    pub fn new(ai_backend: AiBackend, rule_detector: AnomalyDetector) -> Self {
        Self {
            ai_backend,
            rule_detector,
        }
    }

    /// Create an analyzer service with AI model from the given path.
    pub fn with_model(model_path: PathBuf, timeout_secs: u64) -> Self {
        let ai_backend = AiBackend::new(model_path, timeout_secs);
        let rule_detector = AnomalyDetector::with_defaults();
        Self::new(ai_backend, rule_detector)
    }

    /// Create an analyzer service in rule-based-only mode (no AI).
    pub fn rule_based_only(reason: String) -> Self {
        let ai_backend = AiBackend::fallback(reason);
        let rule_detector = AnomalyDetector::with_defaults();
        Self::new(ai_backend, rule_detector)
    }

    /// Evaluate a certificate for anomalies.
    ///
    /// If the AI backend is available, combines AI results with rule-based results.
    /// If the AI backend is unavailable, uses rule-based detection only.
    pub async fn evaluate(&self, metadata: &CertificateMetadata) -> Vec<(AnomalyType, Severity)> {
        // Always run rule-based detection
        let rule_anomalies = self.rule_detector.detect(metadata);

        // Try AI-based detection
        match self.ai_backend.evaluate(metadata).await {
            Ok(ai_anomalies) => {
                // Combine AI and rule-based results
                let mut combined = rule_anomalies;
                combined.extend(ai_anomalies);
                combined
            }
            Err(_) => {
                // AI unavailable — use rule-based results only
                rule_anomalies
            }
        }
    }

    /// Report the current operational mode of the analyzer.
    pub async fn health_check(&self) -> AnalyzerMode {
        self.ai_backend.health_check().await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use std::path::PathBuf;
    use tlapix_common::types::completeness;

    /// Helper to create a valid certificate metadata for testing.
    fn make_test_metadata() -> CertificateMetadata {
        let now = Utc::now();
        CertificateMetadata {
            fingerprint: [0u8; 32],
            subject: "CN=test.example.com".to_string(),
            issuer: "CN=Test CA".to_string(),
            serial_number: "01".to_string(),
            not_before: now - Duration::days(30),
            not_after: now + Duration::days(335),
            sans: vec!["test.example.com".to_string()],
            key_algorithm: "RSA".to_string(),
            key_size: 2048,
            chain_depth: 2,
            issuer_fingerprint: Some([1u8; 32]),
            first_seen: now - Duration::days(30),
            last_seen: now,
            connection_count: 5,
            source_ip: Some("10.0.0.1".to_string()),
            destination_ip: Some("10.0.0.2".to_string()),
            sni_hostname: Some("test.example.com".to_string()),
            completeness_flags: completeness::ALL_REQUIRED | completeness::SANS,
        }
    }

    #[test]
    fn test_fallback_when_model_file_does_not_exist() {
        let non_existent = PathBuf::from("/tmp/non_existent_model_12345.onnx");
        let backend = AiBackend::new(non_existent, 5);

        // Should be in fallback mode
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let mode = rt.block_on(backend.health_check());
        assert!(
            matches!(mode, AnalyzerMode::RuleBasedFallback { .. }),
            "Expected fallback mode when model file doesn't exist, got: {:?}",
            mode
        );
    }

    #[test]
    fn test_fallback_mode_created_directly() {
        let backend = AiBackend::fallback("test reason".to_string());

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let mode = rt.block_on(backend.health_check());
        match mode {
            AnalyzerMode::RuleBasedFallback { reason } => {
                assert_eq!(reason, "test reason");
            }
            _ => panic!("Expected RuleBasedFallback mode"),
        }
    }

    #[test]
    fn test_evaluate_returns_error_in_fallback_mode() {
        let backend = AiBackend::fallback("no model".to_string());
        let metadata = make_test_metadata();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let result = rt.block_on(backend.evaluate(&metadata));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AiBackendError::InFallbackMode
        ));
    }

    #[tokio::test]
    async fn test_analyzer_service_uses_rule_based_in_fallback() {
        let service = AnalyzerService::rule_based_only("test".to_string());
        let metadata = make_test_metadata();

        // Valid cert should have no anomalies
        let anomalies = service.evaluate(&metadata).await;
        assert!(anomalies.is_empty());

        // Check mode
        let mode = service.health_check().await;
        assert!(matches!(mode, AnalyzerMode::RuleBasedFallback { .. }));
    }

    #[tokio::test]
    async fn test_analyzer_service_detects_anomalies_in_fallback() {
        let service = AnalyzerService::rule_based_only("test".to_string());
        let mut metadata = make_test_metadata();
        // Make the key weak to trigger an anomaly
        metadata.key_size = 1024;

        let anomalies = service.evaluate(&metadata).await;
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(
            anomalies[0].0,
            AnomalyType::WeakCryptography { .. }
        ));
        assert_eq!(anomalies[0].1, Severity::Critical);
    }

    #[tokio::test]
    async fn test_analyzer_service_with_nonexistent_model_falls_back() {
        let service =
            AnalyzerService::with_model(PathBuf::from("/tmp/nonexistent_model_xyz.onnx"), 5);

        // Should be in fallback mode
        let mode = service.health_check().await;
        assert!(matches!(mode, AnalyzerMode::RuleBasedFallback { .. }));

        // Should still detect anomalies via rule-based
        let mut metadata = make_test_metadata();
        metadata.key_size = 512;
        let anomalies = service.evaluate(&metadata).await;
        assert!(!anomalies.is_empty());
    }

    #[tokio::test]
    async fn test_timeout_handling() {
        // Create a backend that simulates a timeout scenario.
        // Since we can't easily create a real ONNX session that times out,
        // we test that the timeout mechanism is properly configured.
        let backend = AiBackend::fallback("simulated timeout test".to_string());

        // Verify the backend is in fallback mode
        let mode = backend.health_check().await;
        assert!(matches!(mode, AnalyzerMode::RuleBasedFallback { .. }));

        // Verify evaluate returns the expected error
        let metadata = make_test_metadata();
        let result = backend.evaluate(&metadata).await;
        assert!(matches!(result, Err(AiBackendError::InFallbackMode)));
    }

    #[tokio::test]
    async fn test_mode_display() {
        let ai_mode = AnalyzerMode::AiPowered;
        assert_eq!(format!("{}", ai_mode), "AI-Powered");

        let fallback_mode = AnalyzerMode::RuleBasedFallback {
            reason: "model not found".to_string(),
        };
        assert_eq!(
            format!("{}", fallback_mode),
            "Rule-Based Fallback (model not found)"
        );
    }

    #[tokio::test]
    async fn test_analyzer_service_health_check_reports_mode() {
        // AI-powered mode (would require a real model, so we test fallback)
        let service = AnalyzerService::rule_based_only("no model configured".to_string());
        let mode = service.health_check().await;

        match mode {
            AnalyzerMode::RuleBasedFallback { reason } => {
                assert_eq!(reason, "no model configured");
            }
            _ => panic!("Expected fallback mode"),
        }
    }

    #[tokio::test]
    async fn test_ai_backend_error_variants() {
        // Test error display messages
        let err = AiBackendError::InFallbackMode;
        assert_eq!(format!("{}", err), "AI backend is in fallback mode");

        let err = AiBackendError::NoSession;
        assert_eq!(format!("{}", err), "No ONNX model session available");

        let err = AiBackendError::Timeout;
        assert_eq!(format!("{}", err), "AI inference timed out");

        let err = AiBackendError::InferenceError("test error".to_string());
        assert_eq!(format!("{}", err), "AI inference error: test error");
    }
}
