//! Tlapix Analyzer - AI-driven anomaly detection, renewal prediction, and shadow certificate identification.

pub mod ai_backend;
pub mod anomaly;
pub mod inventory;
pub mod reconciliation;
pub mod renewal;
pub mod renewal_scheduler;
pub mod shadow;
pub mod shadow_escalation;
pub mod sni_match;

pub const CRATE_NAME: &str = "tlapix-analyzer";
