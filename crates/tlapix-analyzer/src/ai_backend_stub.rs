//! Stub AI backend when the `onnx` feature is not enabled.
//!
//! Provides the same public API as the real `ai_backend` module but always
//! operates in rule-based fallback mode. No ONNX Runtime dependency required.

use std::path::PathBuf;

use tlapix_common::types::{AnomalyType, CertificateMetadata, Severity};

use crate::anomaly::AnomalyDetector;

/// Represents the current operational mode of the analyzer.
#[derive(Debug, Clone, PartialEq)]
pub enum AnalyzerMode {
    /// AI model is loaded and operational.
    AiPowered,
    /// Fallen back to rule-based detection.
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

/// Combined analyzer service (stub — always rule-based).
pub struct AnalyzerService {
    rule_detector: AnomalyDetector,
}

impl AnalyzerService {
    /// Create an analyzer service with AI model path (ignored in stub).
    pub fn with_model(_model_path: PathBuf, _timeout_secs: u64) -> Self {
        Self {
            rule_detector: AnomalyDetector::with_defaults(),
        }
    }

    /// Create an analyzer service in rule-based-only mode.
    pub fn rule_based_only(_reason: String) -> Self {
        Self {
            rule_detector: AnomalyDetector::with_defaults(),
        }
    }

    /// Evaluate a certificate for anomalies (rule-based only).
    pub async fn evaluate(&self, metadata: &CertificateMetadata) -> Vec<(AnomalyType, Severity)> {
        self.rule_detector.detect(metadata)
    }

    /// Report the current operational mode (always fallback in stub).
    pub async fn health_check(&self) -> AnalyzerMode {
        AnalyzerMode::RuleBasedFallback {
            reason: "ONNX feature not enabled (compile without 'onnx' feature)".to_string(),
        }
    }
}
