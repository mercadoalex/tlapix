//! BPF Map Writer - Writes ActionDirectives to appropriate BPF action maps.
//!
//! This module provides a trait-based interface for writing to BPF maps,
//! allowing platform-independent testing while supporting real BPF map
//! operations on Linux via `aya`.

use std::sync::Arc;

use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use tlapix_common::{
    ActionDirective, ActionType, BpfActionEntry, ExecutionOutcome,
};

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Format a fingerprint as a hex string for logging.
fn format_fingerprint(fp: &[u8; 32]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &b in fp.iter() {
        s.push(HEX_CHARS[(b >> 4) as usize] as char);
        s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    s
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during BPF map write operations.
#[derive(Debug, Error, Clone)]
pub enum MapWriteError {
    /// The target map has reached its maximum entry capacity.
    #[error("map is full ({current}/{max} entries)")]
    MapFull { current: usize, max: usize },

    /// Total memory across all maps would exceed the configured cap.
    #[error("total memory cap exceeded ({current_bytes}/{max_bytes} bytes)")]
    MemoryCapExceeded { current_bytes: usize, max_bytes: usize },

    /// A transient write failure (retryable).
    #[error("write failed: {reason}")]
    WriteFailed { reason: String },

    /// A permanent failure after all retries exhausted.
    #[error("permanent failure after {attempts} attempts: {reason}")]
    PermanentFailure { reason: String, attempts: u8 },
}

// ---------------------------------------------------------------------------
// Notification callback for Analyzer
// ---------------------------------------------------------------------------

/// Notification sent to the Analyzer when a map operation fails permanently
/// or a map reaches capacity.
#[derive(Debug, Clone)]
pub enum MapNotification {
    /// A map has reached its maximum entry capacity.
    MapFull {
        map_name: String,
        entry_count: usize,
    },
    /// A write operation failed permanently after all retries.
    PermanentFailure {
        directive: ActionDirective,
        reason: String,
        attempts: u8,
    },
}

/// Trait for receiving notifications from the map writer.
/// The Analyzer implements this to be informed of failures.
#[async_trait::async_trait]
pub trait MapWriterNotifier: Send + Sync {
    async fn notify(&self, notification: MapNotification);
}

// ---------------------------------------------------------------------------
// BpfMapWriter trait
// ---------------------------------------------------------------------------

/// Trait abstracting BPF map write operations.
///
/// On Linux, this is implemented using `aya` to write to real kernel BPF maps.
/// For testing on any platform, a mock in-memory implementation is provided.
#[async_trait::async_trait]
pub trait BpfMapWriter: Send + Sync {
    /// Write an entry to the map, keyed by certificate fingerprint.
    async fn write_entry(
        &self,
        fingerprint: [u8; 32],
        entry: BpfActionEntry,
    ) -> Result<(), MapWriteError>;

    /// Remove an entry from the map by fingerprint.
    async fn remove_entry(&self, fingerprint: [u8; 32]) -> Result<(), MapWriteError>;

    /// Current number of entries in the map.
    fn entry_count(&self) -> usize;

    /// Returns true if the map has reached its maximum capacity.
    fn is_full(&self) -> bool;
}

// ---------------------------------------------------------------------------
// MapWriterService
// ---------------------------------------------------------------------------

/// Size of a single BpfActionEntry in bytes (used for memory accounting).
const BPF_ACTION_ENTRY_SIZE: usize = std::mem::size_of::<BpfActionEntry>();

/// The service that routes ActionDirectives to the correct BPF map,
/// enforces capacity/memory limits, and implements retry logic.
pub struct MapWriterService {
    /// Map for alert actions
    alert_map: Arc<Mutex<Box<dyn BpfMapWriter>>>,
    /// Map for protect actions
    protect_map: Arc<Mutex<Box<dyn BpfMapWriter>>>,
    /// Map for isolate actions
    isolate_map: Arc<Mutex<Box<dyn BpfMapWriter>>>,
    /// Maximum entries per map
    max_entries_per_map: usize,
    /// Maximum total memory in bytes across all maps
    max_total_memory_bytes: usize,
    /// Maximum retry attempts
    max_retries: u8,
    /// Base delay for exponential backoff in milliseconds
    retry_base_ms: u64,
    /// Notifier for the Analyzer
    notifier: Option<Arc<dyn MapWriterNotifier>>,
}

impl MapWriterService {
    /// Create a new MapWriterService with the given map implementations.
    pub fn new(
        alert_map: Box<dyn BpfMapWriter>,
        protect_map: Box<dyn BpfMapWriter>,
        isolate_map: Box<dyn BpfMapWriter>,
        max_entries_per_map: usize,
        max_total_memory_mb: u32,
        max_retries: u8,
        retry_base_ms: u64,
    ) -> Self {
        Self {
            alert_map: Arc::new(Mutex::new(alert_map)),
            protect_map: Arc::new(Mutex::new(protect_map)),
            isolate_map: Arc::new(Mutex::new(isolate_map)),
            max_entries_per_map,
            max_total_memory_bytes: (max_total_memory_mb as usize) * 1024 * 1024,
            max_retries,
            retry_base_ms,
            notifier: None,
        }
    }

    /// Set the notifier for Analyzer callbacks.
    pub fn with_notifier(mut self, notifier: Arc<dyn MapWriterNotifier>) -> Self {
        self.notifier = Some(notifier);
        self
    }

    /// Get total entry count across all maps.
    pub async fn total_entry_count(&self) -> usize {
        let alert = self.alert_map.lock().await.entry_count();
        let protect = self.protect_map.lock().await.entry_count();
        let isolate = self.isolate_map.lock().await.entry_count();
        alert + protect + isolate
    }

    /// Get total memory usage across all maps in bytes.
    pub async fn total_memory_bytes(&self) -> usize {
        self.total_entry_count().await * BPF_ACTION_ENTRY_SIZE
    }

    /// Convert an ActionDirective to a BpfActionEntry.
    fn directive_to_entry(directive: &ActionDirective) -> BpfActionEntry {
        let action = match &directive.action_type {
            ActionType::Alert => 0,
            ActionType::Renew => 1,
            ActionType::Protect { .. } => 2,
            ActionType::Isolate { .. } => 3,
        };

        let pinned_fp = match &directive.action_type {
            ActionType::Protect {
                pinned_fingerprint, ..
            } => *pinned_fingerprint,
            _ => [0u8; 32],
        };

        BpfActionEntry {
            fingerprint: directive.cert_fingerprint,
            action,
            severity: directive.severity.to_bpf_value(),
            created_ts: directive.created_at.timestamp_nanos_opt().unwrap_or(0) as u64,
            pinned_fp,
            flags: BpfActionEntry::FLAG_ACTIVE,
        }
    }

    /// Select the appropriate map based on action type.
    fn select_map(&self, action_type: &ActionType) -> &Arc<Mutex<Box<dyn BpfMapWriter>>> {
        match action_type {
            ActionType::Alert => &self.alert_map,
            ActionType::Renew => &self.alert_map, // renew uses alert map
            ActionType::Protect { .. } => &self.protect_map,
            ActionType::Isolate { .. } => &self.isolate_map,
        }
    }

    /// Get the map name for logging purposes.
    fn map_name(action_type: &ActionType) -> &'static str {
        match action_type {
            ActionType::Alert => "action_alert",
            ActionType::Renew => "action_alert",
            ActionType::Protect { .. } => "action_protect",
            ActionType::Isolate { .. } => "action_isolate",
        }
    }

    /// Write an ActionDirective to the appropriate BPF map with retry logic.
    ///
    /// Returns `ExecutionOutcome::Success` on success, or an appropriate
    /// failure/map-full outcome.
    pub async fn write_directive(
        &self,
        directive: &ActionDirective,
    ) -> ExecutionOutcome {
        let map_ref = self.select_map(&directive.action_type);
        let map_name = Self::map_name(&directive.action_type);
        let entry = Self::directive_to_entry(directive);

        // Check capacity before attempting write
        {
            let map = map_ref.lock().await;
            if map.entry_count() >= self.max_entries_per_map {
                warn!(
                    map = map_name,
                    entries = map.entry_count(),
                    max = self.max_entries_per_map,
                    "BPF map is full, rejecting write"
                );
                if let Some(notifier) = &self.notifier {
                    notifier
                        .notify(MapNotification::MapFull {
                            map_name: map_name.to_string(),
                            entry_count: map.entry_count(),
                        })
                        .await;
                }
                return ExecutionOutcome::MapFull;
            }
        }

        // Check total memory cap
        let total_memory = self.total_memory_bytes().await;
        if total_memory + BPF_ACTION_ENTRY_SIZE > self.max_total_memory_bytes {
            warn!(
                current_bytes = total_memory,
                max_bytes = self.max_total_memory_bytes,
                "Total BPF map memory cap would be exceeded"
            );
            if let Some(notifier) = &self.notifier {
                notifier
                    .notify(MapNotification::MapFull {
                        map_name: map_name.to_string(),
                        entry_count: self.total_entry_count().await,
                    })
                    .await;
            }
            return ExecutionOutcome::MapFull;
        }

        // Retry loop with exponential backoff
        let mut last_error = String::new();
        for attempt in 0..self.max_retries {
            let map = map_ref.lock().await;
            match map
                .write_entry(directive.cert_fingerprint, entry)
                .await
            {
                Ok(()) => {
                    info!(
                        map = map_name,
                        fingerprint = %format_fingerprint(&directive.cert_fingerprint),
                        "Successfully wrote directive to BPF map"
                    );
                    return ExecutionOutcome::Success;
                }
                Err(e) => {
                    last_error = e.to_string();
                    drop(map); // release lock before sleeping
                    if attempt < self.max_retries - 1 {
                        let delay_ms =
                            self.retry_base_ms * 2u64.pow(attempt as u32);
                        warn!(
                            map = map_name,
                            attempt = attempt + 1,
                            max_attempts = self.max_retries,
                            delay_ms,
                            error = %e,
                            "BPF map write failed, retrying"
                        );
                        tokio::time::sleep(
                            std::time::Duration::from_millis(delay_ms),
                        )
                        .await;
                    }
                }
            }
        }

        // All retries exhausted — permanent failure
        error!(
            map = map_name,
            attempts = self.max_retries,
            error = %last_error,
            "Permanent BPF map write failure after all retries exhausted"
        );

        if let Some(notifier) = &self.notifier {
            notifier
                .notify(MapNotification::PermanentFailure {
                    directive: directive.clone(),
                    reason: last_error.clone(),
                    attempts: self.max_retries,
                })
                .await;
        }

        ExecutionOutcome::Failed {
            reason: last_error,
            attempts: self.max_retries,
        }
    }
}

// ---------------------------------------------------------------------------
// Mock implementation for testing
// ---------------------------------------------------------------------------

/// In-memory mock implementation of `BpfMapWriter` for testing on any platform.
pub struct MockBpfMapWriter {
    entries: Arc<Mutex<std::collections::HashMap<[u8; 32], BpfActionEntry>>>,
    max_entries: usize,
    /// If set, the mock will fail writes with this error message.
    fail_writes: Arc<Mutex<Option<String>>>,
}

impl MockBpfMapWriter {
    /// Create a new mock map writer with the given capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Arc::new(Mutex::new(std::collections::HashMap::new())),
            max_entries,
            fail_writes: Arc::new(Mutex::new(None)),
        }
    }

    /// Configure the mock to fail all subsequent writes with the given reason.
    pub async fn set_fail_writes(&self, reason: Option<String>) {
        *self.fail_writes.lock().await = reason;
    }

    /// Get a snapshot of all entries currently in the mock map.
    pub async fn get_entries(
        &self,
    ) -> std::collections::HashMap<[u8; 32], BpfActionEntry> {
        self.entries.lock().await.clone()
    }
}

#[async_trait::async_trait]
impl BpfMapWriter for MockBpfMapWriter {
    async fn write_entry(
        &self,
        fingerprint: [u8; 32],
        entry: BpfActionEntry,
    ) -> Result<(), MapWriteError> {
        // Check if we should simulate failures
        if let Some(reason) = self.fail_writes.lock().await.as_ref() {
            return Err(MapWriteError::WriteFailed {
                reason: reason.clone(),
            });
        }

        let mut entries = self.entries.lock().await;
        if entries.len() >= self.max_entries && !entries.contains_key(&fingerprint) {
            return Err(MapWriteError::MapFull {
                current: entries.len(),
                max: self.max_entries,
            });
        }
        entries.insert(fingerprint, entry);
        Ok(())
    }

    async fn remove_entry(&self, fingerprint: [u8; 32]) -> Result<(), MapWriteError> {
        if let Some(reason) = self.fail_writes.lock().await.as_ref() {
            return Err(MapWriteError::WriteFailed {
                reason: reason.clone(),
            });
        }
        self.entries.lock().await.remove(&fingerprint);
        Ok(())
    }

    fn entry_count(&self) -> usize {
        // Use try_lock for sync context; in tests this is fine
        self.entries.try_lock().map(|e| e.len()).unwrap_or(0)
    }

    fn is_full(&self) -> bool {
        self.entry_count() >= self.max_entries
    }
}

// ---------------------------------------------------------------------------
// Mock notifier for testing
// ---------------------------------------------------------------------------

/// A mock notifier that collects all notifications for test assertions.
pub struct MockNotifier {
    notifications: Arc<Mutex<Vec<MapNotification>>>,
}

impl MockNotifier {
    pub fn new() -> Self {
        Self {
            notifications: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn get_notifications(&self) -> Vec<MapNotification> {
        self.notifications.lock().await.clone()
    }
}

#[async_trait::async_trait]
impl MapWriterNotifier for MockNotifier {
    async fn notify(&self, notification: MapNotification) {
        self.notifications.lock().await.push(notification);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tlapix_common::Severity;
    use uuid::Uuid;

    /// Helper to create a test ActionDirective with the given action type.
    fn make_directive(action_type: ActionType) -> ActionDirective {
        ActionDirective {
            id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            cert_fingerprint: [0xAA; 32],
            action_type,
            severity: Severity::High,
            reasoning: "test directive".to_string(),
            created_at: Utc::now(),
            source_anomaly: None,
            attempt_count: 0,
        }
    }

    fn make_directive_with_fp(
        action_type: ActionType,
        fingerprint: [u8; 32],
    ) -> ActionDirective {
        ActionDirective {
            id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            cert_fingerprint: fingerprint,
            action_type,
            severity: Severity::High,
            reasoning: "test directive".to_string(),
            created_at: Utc::now(),
            source_anomaly: None,
            attempt_count: 0,
        }
    }

    fn create_service(max_entries: usize) -> MapWriterService {
        MapWriterService::new(
            Box::new(MockBpfMapWriter::new(max_entries)),
            Box::new(MockBpfMapWriter::new(max_entries)),
            Box::new(MockBpfMapWriter::new(max_entries)),
            max_entries,
            64, // 64 MB
            3,  // max retries
            1,  // 1ms base for fast tests
        )
    }

    fn create_service_with_notifier(
        max_entries: usize,
    ) -> (MapWriterService, Arc<MockNotifier>) {
        let notifier = Arc::new(MockNotifier::new());
        let service = MapWriterService::new(
            Box::new(MockBpfMapWriter::new(max_entries)),
            Box::new(MockBpfMapWriter::new(max_entries)),
            Box::new(MockBpfMapWriter::new(max_entries)),
            max_entries,
            64,
            3,
            1,
        )
        .with_notifier(notifier.clone());
        (service, notifier)
    }

    #[tokio::test]
    async fn test_successful_write_alert() {
        let service = create_service(10_000);
        let directive = make_directive(ActionType::Alert);

        let outcome = service.write_directive(&directive).await;
        assert_eq!(outcome, ExecutionOutcome::Success);
        assert_eq!(service.total_entry_count().await, 1);
    }

    #[tokio::test]
    async fn test_successful_write_protect() {
        let service = create_service(10_000);
        let directive = make_directive(ActionType::Protect {
            pinned_fingerprint: [0xBB; 32],
            hostname: "example.com".to_string(),
        });

        let outcome = service.write_directive(&directive).await;
        assert_eq!(outcome, ExecutionOutcome::Success);
        assert_eq!(service.total_entry_count().await, 1);
    }

    #[tokio::test]
    async fn test_successful_write_isolate() {
        let service = create_service(10_000);
        let directive = make_directive(ActionType::Isolate {
            target_fingerprint: [0xCC; 32],
        });

        let outcome = service.write_directive(&directive).await;
        assert_eq!(outcome, ExecutionOutcome::Success);
        assert_eq!(service.total_entry_count().await, 1);
    }

    #[tokio::test]
    async fn test_routing_by_action_type() {
        let service = create_service(10_000);

        // Write one of each type
        let alert = make_directive_with_fp(ActionType::Alert, [1; 32]);
        let protect = make_directive_with_fp(
            ActionType::Protect {
                pinned_fingerprint: [0xBB; 32],
                hostname: "a.com".to_string(),
            },
            [2; 32],
        );
        let isolate = make_directive_with_fp(
            ActionType::Isolate {
                target_fingerprint: [0xCC; 32],
            },
            [3; 32],
        );

        service.write_directive(&alert).await;
        service.write_directive(&protect).await;
        service.write_directive(&isolate).await;

        // Each map should have exactly 1 entry
        assert_eq!(service.alert_map.lock().await.entry_count(), 1);
        assert_eq!(service.protect_map.lock().await.entry_count(), 1);
        assert_eq!(service.isolate_map.lock().await.entry_count(), 1);
        assert_eq!(service.total_entry_count().await, 3);
    }

    #[tokio::test]
    async fn test_map_full_rejection_at_max_entries() {
        let max_entries = 5;
        let (service, notifier) = create_service_with_notifier(max_entries);

        // Fill the alert map to capacity
        for i in 0..max_entries {
            let mut fp = [0u8; 32];
            fp[0] = i as u8;
            let directive = make_directive_with_fp(ActionType::Alert, fp);
            let outcome = service.write_directive(&directive).await;
            assert_eq!(outcome, ExecutionOutcome::Success);
        }

        // Next write should be rejected
        let directive = make_directive_with_fp(ActionType::Alert, [0xFF; 32]);
        let outcome = service.write_directive(&directive).await;
        assert_eq!(outcome, ExecutionOutcome::MapFull);

        // Notifier should have received a MapFull notification
        let notifications = notifier.get_notifications().await;
        assert_eq!(notifications.len(), 1);
        match &notifications[0] {
            MapNotification::MapFull { map_name, .. } => {
                assert_eq!(map_name, "action_alert");
            }
            _ => panic!("Expected MapFull notification"),
        }
    }

    #[tokio::test]
    async fn test_retry_logic_succeeds_on_transient_failure() {
        // Use a FailCountMapWriter that fails first 2 attempts, succeeds on 3rd
        let service = MapWriterService::new(
            Box::new(FailCountMapWriter::new(2, 10_000)), // fail first 2, succeed on 3rd
            Box::new(MockBpfMapWriter::new(10_000)),
            Box::new(MockBpfMapWriter::new(10_000)),
            10_000,
            64,
            3,
            1, // 1ms for fast tests
        );

        let directive = make_directive(ActionType::Alert);
        let outcome = service.write_directive(&directive).await;
        assert_eq!(outcome, ExecutionOutcome::Success);
    }

    #[tokio::test]
    async fn test_permanent_failure_after_retries_exhausted() {
        let (service, notifier) = {
            let notifier = Arc::new(MockNotifier::new());
            let service = MapWriterService::new(
                Box::new(FailCountMapWriter::new(5, 10_000)), // always fails (5 > 3 retries)
                Box::new(MockBpfMapWriter::new(10_000)),
                Box::new(MockBpfMapWriter::new(10_000)),
                10_000,
                64,
                3,
                1,
            )
            .with_notifier(notifier.clone());
            (service, notifier)
        };

        let directive = make_directive(ActionType::Alert);
        let outcome = service.write_directive(&directive).await;

        match outcome {
            ExecutionOutcome::Failed { attempts, .. } => {
                assert_eq!(attempts, 3);
            }
            other => panic!("Expected Failed outcome, got {:?}", other),
        }

        // Notifier should have received a PermanentFailure notification
        let notifications = notifier.get_notifications().await;
        assert_eq!(notifications.len(), 1);
        match &notifications[0] {
            MapNotification::PermanentFailure { attempts, .. } => {
                assert_eq!(*attempts, 3);
            }
            _ => panic!("Expected PermanentFailure notification"),
        }
    }

    #[tokio::test]
    async fn test_memory_cap_enforcement() {
        // Use a very small memory cap (1 byte effectively means 0 entries allowed
        // after the first). We'll set max_total_memory_mb to 0 to trigger the cap.
        // Actually, let's compute: BpfActionEntry is ~76 bytes.
        // With max_total_memory_mb = 0, no entries can be written.
        // But 0 MB = 0 bytes, so even 1 entry would exceed.
        let notifier = Arc::new(MockNotifier::new());
        let service = MapWriterService::new(
            Box::new(MockBpfMapWriter::new(10_000)),
            Box::new(MockBpfMapWriter::new(10_000)),
            Box::new(MockBpfMapWriter::new(10_000)),
            10_000,
            0, // 0 MB = 0 bytes cap
            3,
            1,
        )
        .with_notifier(notifier.clone());

        let directive = make_directive(ActionType::Alert);
        let outcome = service.write_directive(&directive).await;
        assert_eq!(outcome, ExecutionOutcome::MapFull);
    }

    #[tokio::test]
    async fn test_directive_to_entry_conversion() {
        let directive = ActionDirective {
            id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            cert_fingerprint: [0x42; 32],
            action_type: ActionType::Protect {
                pinned_fingerprint: [0xBB; 32],
                hostname: "test.com".to_string(),
            },
            severity: Severity::Critical,
            reasoning: "test".to_string(),
            created_at: Utc::now(),
            source_anomaly: None,
            attempt_count: 0,
        };

        let entry = MapWriterService::directive_to_entry(&directive);
        assert_eq!(entry.fingerprint, [0x42; 32]);
        assert_eq!(entry.action, 2); // protect
        assert_eq!(entry.severity, 3); // critical
        assert_eq!(entry.pinned_fp, [0xBB; 32]);
        assert_eq!(entry.flags, BpfActionEntry::FLAG_ACTIVE);
    }

    // -----------------------------------------------------------------------
    // Test helper: a map writer that fails the first N writes then succeeds
    // -----------------------------------------------------------------------

    /// A map writer that fails the first `fail_count` writes, then succeeds.
    struct FailCountMapWriter {
        inner: MockBpfMapWriter,
        attempts: Arc<Mutex<usize>>,
        fail_count: usize,
    }

    impl FailCountMapWriter {
        fn new(fail_count: usize, max_entries: usize) -> Self {
            Self {
                inner: MockBpfMapWriter::new(max_entries),
                attempts: Arc::new(Mutex::new(0)),
                fail_count,
            }
        }
    }

    #[async_trait::async_trait]
    impl BpfMapWriter for FailCountMapWriter {
        async fn write_entry(
            &self,
            fingerprint: [u8; 32],
            entry: BpfActionEntry,
        ) -> Result<(), MapWriteError> {
            let mut attempts = self.attempts.lock().await;
            *attempts += 1;
            if *attempts <= self.fail_count {
                return Err(MapWriteError::WriteFailed {
                    reason: format!("simulated failure #{}", *attempts),
                });
            }
            drop(attempts);
            self.inner.write_entry(fingerprint, entry).await
        }

        async fn remove_entry(
            &self,
            fingerprint: [u8; 32],
        ) -> Result<(), MapWriteError> {
            self.inner.remove_entry(fingerprint).await
        }

        fn entry_count(&self) -> usize {
            self.inner.entry_count()
        }

        fn is_full(&self) -> bool {
            self.inner.is_full()
        }
    }
}
