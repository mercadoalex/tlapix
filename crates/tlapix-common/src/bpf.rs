//! BPF-shared data structures.
//!
//! These types use `#[repr(C)]` for direct sharing between kernel-space eBPF
//! programs and userspace via ring buffers and BPF maps.

/// Event pushed from the eBPF Collector to userspace via the ring buffer.
///
/// Contains raw certificate data extracted from observed TLS handshakes.
/// This struct is shared between kernel and userspace and must remain `repr(C)`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TlsCertEvent {
    /// Kernel timestamp in nanoseconds (from `bpf_ktime_get_ns`)
    pub timestamp_ns: u64,
    /// Source IPv4 address, or first 4 bytes of IPv6
    pub src_ip: u32,
    /// Destination IPv4 address, or first 4 bytes of IPv6
    pub dst_ip: u32,
    /// Source TCP port
    pub src_port: u16,
    /// Destination TCP port
    pub dst_port: u16,
    /// IP version: 4 or 6
    pub ip_version: u8,
    /// TLS version: 0x0303 = TLS 1.2, 0x0304 = TLS 1.3
    pub tls_version: u16,
    /// Length of the SNI hostname
    pub sni_len: u16,
    /// SNI hostname from ClientHello (null-padded)
    pub sni: [u8; 256],
    /// SHA-256 fingerprint of the leaf certificate DER encoding
    pub fingerprint: [u8; 32],
    /// Length of the DER-encoded certificate data
    pub cert_len: u32,
    /// DER-encoded leaf certificate (truncated to 4096 bytes)
    pub cert_data: [u8; 4096],
    /// Number of certificates in the chain
    pub chain_depth: u8,
    /// SHA-256 fingerprint of the immediate issuing CA certificate
    pub issuer_fingerprint: [u8; 32],
    /// 1 if this fingerprint was not previously in the seen-set, 0 otherwise
    pub is_new: u8,
}

/// Entry stored in BPF action maps, read by kernel-side executor programs.
///
/// Used by the `protect_program` and `isolate_program` eBPF programs to
/// enforce actions at kernel speed.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    /// Returns true if the entry is marked as active.
    pub fn is_active(&self) -> bool {
        self.flags & Self::FLAG_ACTIVE != 0
    }

    /// Returns true if the entry is marked as failed.
    pub fn is_failed(&self) -> bool {
        self.flags & Self::FLAG_FAILED != 0
    }
}

// Safety: These types are plain data with no pointers, safe to send across threads.
unsafe impl Send for TlsCertEvent {}
unsafe impl Sync for TlsCertEvent {}
unsafe impl Send for BpfActionEntry {}
unsafe impl Sync for BpfActionEntry {}
