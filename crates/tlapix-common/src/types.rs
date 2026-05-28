//! Core userspace type definitions shared across all Tlapix crates.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Crate version from Cargo.toml.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------------------
// Certificate Metadata
// ---------------------------------------------------------------------------

/// Comprehensive metadata extracted from an observed TLS certificate.
///
/// Corresponds to the `certificates` table in the SQLite schema and is the
/// primary data structure passed from the Collector to the Analyzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateMetadata {
    /// SHA-256 fingerprint of the leaf certificate DER encoding
    pub fingerprint: [u8; 32],
    /// Certificate subject (up to 2048 characters)
    pub subject: String,
    /// Certificate issuer (up to 2048 characters)
    pub issuer: String,
    /// Serial number as hex string
    pub serial_number: String,
    /// Validity start date
    pub not_before: DateTime<Utc>,
    /// Validity end date
    pub not_after: DateTime<Utc>,
    /// Subject Alternative Names (up to 100 entries)
    pub sans: Vec<String>,
    /// Key algorithm (e.g., "RSA", "ECDSA", "Ed25519")
    pub key_algorithm: String,
    /// Key size in bits (e.g., 2048, 4096 for RSA; 256, 384 for ECDSA)
    pub key_size: u32,
    /// Number of certificates in the chain
    pub chain_depth: u8,
    /// SHA-256 fingerprint of the immediate issuing CA
    pub issuer_fingerprint: Option<[u8; 32]>,
    /// First time this certificate was observed
    pub first_seen: DateTime<Utc>,
    /// Most recent time this certificate was observed
    pub last_seen: DateTime<Utc>,
    /// Number of connections where this certificate was observed
    pub connection_count: u64,
    /// Source IP address where the certificate was observed
    pub source_ip: Option<String>,
    /// Destination IP address
    pub destination_ip: Option<String>,
    /// SNI hostname from the ClientHello
    pub sni_hostname: Option<String>,
    /// Bitmask indicating which fields are present (for partial extractions)
    pub completeness_flags: u32,
}

/// Bitmask constants for `CertificateMetadata::completeness_flags`.
///
/// Each bit indicates whether the corresponding field was successfully extracted.
pub mod completeness {
    pub const SUBJECT: u32 = 1 << 0;
    pub const ISSUER: u32 = 1 << 1;
    pub const SERIAL_NUMBER: u32 = 1 << 2;
    pub const NOT_BEFORE: u32 = 1 << 3;
    pub const NOT_AFTER: u32 = 1 << 4;
    pub const SANS: u32 = 1 << 5;
    pub const KEY_ALGORITHM: u32 = 1 << 6;
    pub const KEY_SIZE: u32 = 1 << 7;
    pub const CHAIN_DEPTH: u32 = 1 << 8;
    pub const ISSUER_FINGERPRINT: u32 = 1 << 9;

    /// All required fields present.
    pub const ALL_REQUIRED: u32 = SUBJECT
        | ISSUER
        | SERIAL_NUMBER
        | NOT_BEFORE
        | NOT_AFTER
        | KEY_ALGORITHM
        | KEY_SIZE;
}

// ---------------------------------------------------------------------------
// Action Directives
// ---------------------------------------------------------------------------

/// A structured directive from the Analyzer instructing the Executor to
/// perform a specific action on a target certificate or connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionDirective {
    /// Unique identifier for this directive
    pub id: Uuid,
    /// Correlation ID for end-to-end tracing through the decision chain
    pub correlation_id: Uuid,
    /// SHA-256 fingerprint of the target certificate
    pub cert_fingerprint: [u8; 32],
    /// The action to perform
    pub action_type: ActionType,
    /// Severity level of this directive
    pub severity: Severity,
    /// Human-readable reasoning (max 500 characters)
    pub reasoning: String,
    /// When this directive was created
    pub created_at: DateTime<Utc>,
    /// The anomaly that triggered this directive, if any
    pub source_anomaly: Option<AnomalyType>,
    /// Number of execution attempts so far
    pub attempt_count: u8,
}

/// The type of action the Executor should perform.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionType {
    /// Deliver a notification to the configured operator channel
    Alert,
    /// Trigger certificate renewal workflow (ACME or custom webhook)
    Renew,
    /// Reject new TLS handshakes that do not present the pinned certificate
    Protect {
        /// The expected (pinned) certificate fingerprint
        pinned_fingerprint: [u8; 32],
        /// The hostname to protect
        hostname: String,
    },
    /// Drop new connections presenting the targeted certificate
    Isolate {
        /// The fingerprint of the certificate to isolate
        target_fingerprint: [u8; 32],
    },
}

/// Severity levels for anomalies and action directives.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl Severity {
    /// Convert from the numeric representation used in BPF maps.
    pub fn from_bpf_value(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Low),
            1 => Some(Self::Medium),
            2 => Some(Self::High),
            3 => Some(Self::Critical),
            _ => None,
        }
    }

    /// Convert to the numeric representation used in BPF maps.
    pub fn to_bpf_value(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// Anomaly Types
// ---------------------------------------------------------------------------

/// Types of anomalies detected by the Analyzer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AnomalyType {
    /// Certificate validity period exceeds policy (e.g., > 398 days)
    PolicyViolation { reason: String },
    /// Certificate uses weak cryptographic parameters
    WeakCryptography { algorithm: String, key_size: u32 },
    /// Observed SNI hostname does not match any SAN in the certificate
    SniMismatch { sni: String, sans: Vec<String> },
    /// Certificate has already expired
    ExpiredCertificate,
    /// Certificate is approaching expiration
    NearExpiry { days_remaining: u32 },
}

// ---------------------------------------------------------------------------
// Shadow Certificate Classification
// ---------------------------------------------------------------------------

/// Risk levels for shadow certificate classification.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RiskLevel {
    /// Trusted issuer, adequate key strength, normal validity
    Low = 0,
    /// Less than 30 days remaining validity
    Medium = 1,
    /// Untrusted issuer or validity > 398 days
    High = 2,
    /// Self-signed or weak key (RSA < 2048, ECDSA < 256)
    Critical = 3,
}

impl RiskLevel {
    /// Escalate risk level by one tier, capped at Critical.
    pub fn escalate(self) -> Self {
        match self {
            Self::Low => Self::Medium,
            Self::Medium => Self::High,
            Self::High => Self::Critical,
            Self::Critical => Self::Critical,
        }
    }
}

/// Classification result for a certificate checked against the inventory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ShadowClassification {
    /// Certificate is registered in the inventory
    Known,
    /// Certificate is not in the inventory (shadow certificate)
    Shadow {
        risk_level: RiskLevel,
        context: ShadowContext,
    },
    /// Classification deferred because the inventory is unreachable
    Deferred { reason: String },
}

/// Context information for a shadow certificate classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ShadowContext {
    /// Source IP where the certificate was observed
    pub source_ip: Option<String>,
    /// Destination IP/hostname
    pub destination: Option<String>,
    /// When the certificate was first seen
    pub first_seen: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Renewal Prediction
// ---------------------------------------------------------------------------

/// AI-generated prediction about the likelihood of a certificate renewal failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewalPrediction {
    /// SHA-256 fingerprint of the certificate
    pub cert_fingerprint: [u8; 32],
    /// Probability of renewal failure (0.0 to 1.0)
    pub failure_probability: f64,
    /// Days until the certificate expires (negative if already expired)
    pub days_until_expiry: i32,
    /// Current severity assessment
    pub severity: Severity,
    /// Human-readable reasoning for the prediction
    pub reasoning: String,
    /// When this prediction was last evaluated
    pub last_evaluated: DateTime<Utc>,
    /// Whether renewal activity has been detected for this certificate
    pub renewal_activity_detected: bool,
}

// ---------------------------------------------------------------------------
// Execution Outcomes
// ---------------------------------------------------------------------------

/// Result of executing an action directive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExecutionOutcome {
    /// Action executed successfully
    Success,
    /// Action failed after the specified number of attempts
    Failed { reason: String, attempts: u8 },
    /// Directive expired (certificate not seen in 72+ hours)
    Expired,
    /// BPF map is at capacity, write rejected
    MapFull,
    /// Conflicting directive resolved; the winner is included
    Conflict { winner_id: Uuid },
}
