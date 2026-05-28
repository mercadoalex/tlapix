//! BPF maps for the Collector and Executor layers.
//!
//! Defines all kernel-resident data structures shared between eBPF programs
//! and userspace. These maps are accessed from userspace via the `aya` library.
//!
//! ## Map Summary
//!
//! | Map | Type | Key | Value | Max Entries |
//! |-----|------|-----|-------|-------------|
//! | `SEEN_CERTS` | HASH | `[u8; 32]` (fingerprint) | `u64` (first_seen_ns) | 100,000 |
//! | `CERT_STATS` | PERCPU_HASH | `[u8; 32]` (fingerprint) | `u64` (conn_count) | 100,000 |
//! | `DROP_COUNTER` | PERCPU_ARRAY | `u32` (index) | `u64` (count) | 4 |
//! | `EVENTS` | RINGBUF | — | `TlsCertEvent` | 16 MB |
//! | `ACTION_PROTECT` | HASH | `[u8; 32]` (fingerprint) | `BpfActionEntry` | 10,000 |
//! | `ACTION_ISOLATE` | HASH | `[u8; 32]` (fingerprint) | `BpfActionEntry` | 10,000 |

use aya_ebpf::{
    macros::map,
    maps::{HashMap, PerCpuArray, PerCpuHashMap, RingBuf},
};

// =============================================================================
// Map capacity constants
// =============================================================================

/// Maximum number of unique certificate fingerprints tracked in the seen-set.
/// Sized for large deployments observing many distinct certificates.
pub const MAX_SEEN_CERTS: u32 = 100_000;

/// Maximum number of entries in the per-CPU stats map.
pub const MAX_CERT_STATS: u32 = 100_000;

/// Number of drop counter slots.
pub const DROP_COUNTER_ENTRIES: u32 = 4;

/// Ring buffer size in bytes (16 MB).
/// Configurable at load time by userspace via map resize.
pub const RING_BUF_SIZE: u32 = 16 * 1024 * 1024;

// =============================================================================
// Drop counter indices
// =============================================================================

/// Drop counter index: ring buffer full — handshake event could not be pushed.
pub const DROP_IDX_RING_FULL: u32 = 0;
/// Drop counter index: malformed packet encountered during parsing.
pub const DROP_IDX_MALFORMED: u32 = 1;
/// Drop counter index: total handshakes observed (not a "drop" — used for stats).
pub const DROP_IDX_TOTAL: u32 = 2;
/// Drop counter index: reserved for future use.
pub const DROP_IDX_RESERVED: u32 = 3;

// =============================================================================
// BPF Map definitions
// =============================================================================

/// Hash map tracking previously-seen certificate fingerprints.
///
/// - **Key**: `[u8; 32]` — SHA-256 fingerprint of the leaf certificate DER encoding
///   (or pseudo-fingerprint computed in eBPF from first 32 bytes of cert data)
/// - **Value**: `u64` — timestamp (nanoseconds, from `bpf_ktime_get_ns`) when first seen
/// - **Max entries**: 100,000
///
/// Used by the `is_new_cert` check: if a fingerprint is not in this map, the certificate
/// is considered newly discovered and `is_new` is set to 1 in the event.
#[map]
pub static SEEN_CERTS: HashMap<[u8; 32], u64> = HashMap::with_max_entries(MAX_SEEN_CERTS, 0);

/// Per-CPU hash map tracking connection counts per certificate fingerprint.
///
/// - **Key**: `[u8; 32]` — SHA-256 fingerprint of the leaf certificate
/// - **Value**: `u64` — number of connections observed presenting this certificate
/// - **Max entries**: 100,000
///
/// Incremented each time a certificate (whether new or already seen) is observed.
/// Per-CPU to avoid lock contention on multi-core systems.
#[map]
pub static CERT_STATS: PerCpuHashMap<[u8; 32], u64> =
    PerCpuHashMap::with_max_entries(MAX_CERT_STATS, 0);

/// Per-CPU array for drop/event counters.
///
/// - **Key**: `u32` — counter index (0–3)
/// - **Value**: `u64` — count of events
/// - **Max entries**: 4
///
/// Counter indices (see `DROP_IDX_*` constants):
/// - 0: Handshakes dropped due to ring buffer full
/// - 1: Malformed packets encountered
/// - 2: Total handshakes observed
/// - 3: Reserved for future use
#[map]
pub static DROP_COUNTER: PerCpuArray<u64> = PerCpuArray::with_max_entries(DROP_COUNTER_ENTRIES, 0);

/// Ring buffer for pushing `TlsCertEvent` structs to userspace.
///
/// - **Size**: 16 MB (configurable at load time)
///
/// Events are pushed after certificate extraction and the `is_new` check.
/// Userspace reads events asynchronously via `aya::maps::RingBuf`.
#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BUF_SIZE, 0);

// =============================================================================
// Executor action map constants
// =============================================================================

/// Maximum entries in each action map (protect, isolate).
pub const MAX_ACTION_ENTRIES: u32 = 10_000;

// =============================================================================
// BpfActionEntry — shared type for action maps (mirrored from tlapix-common)
// =============================================================================

/// Entry stored in BPF action maps, read by kernel-side executor programs.
///
/// Used by `tlapix_protect` and `tlapix_isolate` eBPF programs to enforce
/// actions at kernel speed. This struct is `repr(C)` for direct map access.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfActionEntry {
    /// SHA-256 fingerprint of the target certificate
    pub fingerprint: [u8; 32],
    /// Action type: 0=alert, 1=renew, 2=protect, 3=isolate
    pub action: u8,
    /// Severity level: 0=low, 1=medium, 2=high, 3=critical
    pub severity: u8,
    /// Creation timestamp in nanoseconds since epoch
    pub created_ts: u64,
    /// For protect actions: the expected (pinned) certificate fingerprint
    pub pinned_fp: [u8; 32],
    /// Flags: bit 0 = active, bit 1 = failed
    pub flags: u8,
}

impl BpfActionEntry {
    /// Flag bit indicating the entry is active.
    pub const FLAG_ACTIVE: u8 = 0b0000_0001;
    /// Flag bit indicating the entry has failed execution.
    pub const FLAG_FAILED: u8 = 0b0000_0010;
}

// =============================================================================
// Executor BPF Maps
// =============================================================================

/// Hash map for protect action directives.
///
/// - **Key**: `[u8; 32]` — SHA-256 fingerprint of the certificate to protect
/// - **Value**: `BpfActionEntry` — action entry with pinned_fp set to the expected cert
/// - **Max entries**: 10,000
///
/// Read by `tlapix_protect` program: if an observed certificate fingerprint is
/// found in this map AND the observed cert doesn't match `pinned_fp`, the
/// connection is rejected (TC_ACT_SHOT).
#[map]
pub static ACTION_PROTECT: HashMap<[u8; 32], BpfActionEntry> =
    HashMap::with_max_entries(MAX_ACTION_ENTRIES, 0);

/// Hash map for isolate action directives.
///
/// - **Key**: `[u8; 32]` — SHA-256 fingerprint of the certificate to isolate
/// - **Value**: `BpfActionEntry` — action entry with FLAG_ACTIVE set
/// - **Max entries**: 10,000
///
/// Read by `tlapix_isolate` program: if an observed certificate fingerprint is
/// found in this map AND the entry has FLAG_ACTIVE set, the connection is
/// dropped (TC_ACT_SHOT).
#[map]
pub static ACTION_ISOLATE: HashMap<[u8; 32], BpfActionEntry> =
    HashMap::with_max_entries(MAX_ACTION_ENTRIES, 0);

// =============================================================================
// Map operation helpers
// =============================================================================

/// Check if a certificate fingerprint has been seen before and update maps accordingly.
///
/// # Logic
///
/// 1. Look up `fingerprint` in `SEEN_CERTS`
/// 2. If **not found** → certificate is new:
///    - Insert fingerprint into `SEEN_CERTS` with current timestamp
///    - Initialize connection count to 1 in `CERT_STATS`
///    - Return `1` (is_new)
/// 3. If **found** → certificate was previously seen:
///    - Increment connection count in `CERT_STATS`
///    - Return `0` (not new)
///
/// # Arguments
///
/// * `fingerprint` - SHA-256 fingerprint (or pseudo-fingerprint) of the leaf certificate
/// * `timestamp_ns` - Current kernel timestamp in nanoseconds
///
/// # Returns
///
/// `1` if the certificate is new (not previously seen), `0` otherwise.
#[inline(always)]
pub fn is_new_cert(fingerprint: &[u8; 32], timestamp_ns: u64) -> u8 {
    let existing = unsafe { SEEN_CERTS.get(fingerprint) };

    match existing {
        Some(_) => {
            // Certificate already seen — increment connection count
            update_cert_stats(fingerprint);
            0 // not new
        }
        None => {
            // New certificate — record first-seen timestamp
            let _ = SEEN_CERTS.insert(fingerprint, &timestamp_ns, 0);
            // Initialize connection count to 1
            let _ = CERT_STATS.insert(fingerprint, &1u64, 0);
            1 // is new
        }
    }
}

/// Increment the per-CPU connection count for a certificate.
///
/// If the fingerprint already has a count on this CPU, increments it.
/// Otherwise, initializes the count to 1.
#[inline(always)]
pub fn update_cert_stats(fingerprint: &[u8; 32]) {
    unsafe {
        if let Some(count) = CERT_STATS.get_ptr_mut(fingerprint) {
            *count += 1;
        } else {
            let _ = CERT_STATS.insert(fingerprint, &1u64, 0);
        }
    }
}

/// Increment a drop/event counter at the given index.
///
/// # Arguments
///
/// * `index` - Counter index (0–3). Use the `DROP_IDX_*` constants.
#[inline(always)]
pub fn increment_drop_counter(index: u32) {
    unsafe {
        if let Some(counter) = DROP_COUNTER.get_ptr_mut(index) {
            *counter += 1;
        }
    }
}
