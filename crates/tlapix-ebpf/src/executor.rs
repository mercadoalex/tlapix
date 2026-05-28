//! Executor eBPF programs — kernel-space action enforcement.
//!
//! These TC classifier programs read from pre-defined BPF action maps and
//! enforce protective actions at kernel speed. They do NOT generate or load
//! any new eBPF code at runtime — they only read from maps populated by
//! userspace.
//!
//! ## Programs
//!
//! - `tlapix_protect`: Rejects TLS handshakes presenting a certificate that
//!   doesn't match the pinned fingerprint for a protected entry.
//! - `tlapix_isolate`: Drops TLS handshakes presenting a certificate that
//!   matches an active isolate entry.
//!
//! Both programs parse the same TLS Certificate message format as the collector
//! to extract the leaf certificate's pseudo-fingerprint, then look it up in
//! their respective action maps.

use aya_ebpf::{bindings::TC_ACT_OK, macros::classifier, programs::TcContext};

use crate::maps::{ACTION_ISOLATE, ACTION_PROTECT, BpfActionEntry};
use crate::{
    ctx_load_u8, ctx_load_u16, ETH_HDR_LEN, ETH_P_IP, IPPROTO_TCP,
    TLS_CONTENT_TYPE_HANDSHAKE, TLS_HANDSHAKE_CERTIFICATE,
};

/// TC_ACT_SHOT — drop the packet.
const TC_ACT_SHOT: i32 = 2;

// =============================================================================
// Protect Program
// =============================================================================

/// TC classifier that enforces certificate pinning.
///
/// For each incoming TLS Certificate handshake message:
/// 1. Extracts the leaf certificate's pseudo-fingerprint (first 32 bytes of DER)
/// 2. Looks up the fingerprint in the `ACTION_PROTECT` map
/// 3. If found AND the observed fingerprint does NOT match the entry's `pinned_fp`:
///    → Returns TC_ACT_SHOT (reject/drop the connection)
/// 4. Otherwise → Returns TC_ACT_OK (allow)
///
/// This enforces that only the pinned certificate is accepted for protected
/// hostnames, rejecting any certificate substitution within 100ms.
#[classifier]
pub fn tlapix_protect(ctx: TcContext) -> i32 {
    match try_protect(&ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_OK, // On parse error, allow traffic (fail-open)
    }
}

/// Internal protect logic. Returns the TC action to take.
#[inline(always)]
fn try_protect(ctx: &TcContext) -> Result<i32, u32> {
    let fingerprint = extract_cert_fingerprint(ctx)?;

    // Look up in protect map
    let entry = unsafe { ACTION_PROTECT.get(&fingerprint) };

    match entry {
        Some(entry) => {
            // Entry found — check if the observed cert matches the pinned fingerprint.
            // If the observed fingerprint does NOT match pinned_fp, reject.
            if !fingerprints_equal(&fingerprint, &entry.pinned_fp) {
                // The observed cert is NOT the pinned cert → reject
                Ok(TC_ACT_SHOT)
            } else {
                // The observed cert IS the pinned cert → allow
                Ok(TC_ACT_OK)
            }
        }
        None => {
            // No protect entry for this cert → allow
            Ok(TC_ACT_OK)
        }
    }
}

// =============================================================================
// Isolate Program
// =============================================================================

/// TC classifier that isolates connections presenting a targeted certificate.
///
/// For each incoming TLS Certificate handshake message:
/// 1. Extracts the leaf certificate's pseudo-fingerprint (first 32 bytes of DER)
/// 2. Looks up the fingerprint in the `ACTION_ISOLATE` map
/// 3. If found AND the entry has FLAG_ACTIVE set:
///    → Returns TC_ACT_SHOT (drop the connection)
/// 4. Otherwise → Returns TC_ACT_OK (allow)
///
/// This drops connections presenting a certificate that has been marked for
/// isolation (e.g., compromised or shadow certificates) within 100ms.
#[classifier]
pub fn tlapix_isolate(ctx: TcContext) -> i32 {
    match try_isolate(&ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_OK, // On parse error, allow traffic (fail-open)
    }
}

/// Internal isolate logic. Returns the TC action to take.
#[inline(always)]
fn try_isolate(ctx: &TcContext) -> Result<i32, u32> {
    let fingerprint = extract_cert_fingerprint(ctx)?;

    // Look up in isolate map
    let entry = unsafe { ACTION_ISOLATE.get(&fingerprint) };

    match entry {
        Some(entry) => {
            // Entry found — check if active
            if entry.flags & BpfActionEntry::FLAG_ACTIVE != 0 {
                // Active isolate entry → drop the connection
                Ok(TC_ACT_SHOT)
            } else {
                // Entry exists but not active (e.g., failed) → allow
                Ok(TC_ACT_OK)
            }
        }
        None => {
            // No isolate entry for this cert → allow
            Ok(TC_ACT_OK)
        }
    }
}

// =============================================================================
// Shared fingerprint extraction (reused from collector parsing logic)
// =============================================================================

/// Error codes for executor parsing.
const ERR_PKT_TOO_SHORT: u32 = 1;
const ERR_NOT_IPV4: u32 = 2;
const ERR_NOT_TCP: u32 = 3;
const ERR_NOT_TLS: u32 = 4;
const ERR_NOT_CERTIFICATE: u32 = 5;

/// Extract the leaf certificate's pseudo-fingerprint from a TLS Certificate
/// handshake message in the packet.
///
/// Parses: Ethernet → IPv4 → TCP → TLS Record → Handshake → Certificate
/// Then reads the first 32 bytes of the leaf certificate DER as the
/// pseudo-fingerprint (same approach as the collector).
#[inline(always)]
fn extract_cert_fingerprint(ctx: &TcContext) -> Result<[u8; 32], u32> {
    let pkt_len = ctx.len() as usize;

    // Minimum: Eth(14) + IPv4(20) + TCP(20) + TLS record(5) + HS header(4) + cert_len(3) + cert_entry_len(3) + 1 byte
    if pkt_len < ETH_HDR_LEN + 20 + 20 + 5 + 4 + 3 + 3 + 1 {
        return Err(ERR_PKT_TOO_SHORT);
    }

    // --- Ethernet ---
    let eth_proto = u16::from_be(ctx_load_u16(ctx, 12)?);
    if eth_proto != ETH_P_IP {
        return Err(ERR_NOT_IPV4);
    }

    // --- IPv4 ---
    let ip_offset = ETH_HDR_LEN;
    let ip_version_ihl = ctx_load_u8(ctx, ip_offset)?;
    let ip_ihl = (ip_version_ihl & 0x0F) as usize * 4;
    if ip_ihl < 20 || ip_ihl > 60 {
        return Err(ERR_NOT_IPV4);
    }

    let ip_protocol = ctx_load_u8(ctx, ip_offset + 9)?;
    if ip_protocol != IPPROTO_TCP {
        return Err(ERR_NOT_TCP);
    }

    // --- TCP ---
    let tcp_offset = ip_offset + ip_ihl;
    if pkt_len < tcp_offset + 20 {
        return Err(ERR_PKT_TOO_SHORT);
    }

    let tcp_data_offset_byte = ctx_load_u8(ctx, tcp_offset + 12)?;
    let tcp_hdr_len = ((tcp_data_offset_byte >> 4) & 0x0F) as usize * 4;
    if tcp_hdr_len < 20 || tcp_hdr_len > 60 {
        return Err(ERR_NOT_TCP);
    }

    // --- TLS Record Layer ---
    let tls_offset = tcp_offset + tcp_hdr_len;
    if pkt_len < tls_offset + 5 {
        return Err(ERR_NOT_TLS);
    }

    let content_type = ctx_load_u8(ctx, tls_offset)?;
    if content_type != TLS_CONTENT_TYPE_HANDSHAKE {
        return Err(ERR_NOT_TLS);
    }

    // Validate TLS record length
    let tls_record_len = u16::from_be(ctx_load_u16(ctx, tls_offset + 3)?) as usize;
    if tls_record_len == 0 || tls_record_len > 16384 {
        return Err(ERR_NOT_TLS);
    }

    // --- TLS Handshake ---
    let hs_offset = tls_offset + 5;
    if pkt_len < hs_offset + 4 {
        return Err(ERR_NOT_CERTIFICATE);
    }

    let hs_type = ctx_load_u8(ctx, hs_offset)?;
    if hs_type != TLS_HANDSHAKE_CERTIFICATE {
        return Err(ERR_NOT_CERTIFICATE);
    }

    // --- Certificate message ---
    // Handshake header: type(1) + length(3) = 4 bytes
    // Certificate message: certificates_length(3) + first_cert_length(3) + cert_data
    let cert_msg_offset = hs_offset + 4;
    if pkt_len < cert_msg_offset + 3 {
        return Err(ERR_NOT_CERTIFICATE);
    }

    // Skip certificates_length (3 bytes)
    let first_cert_offset = cert_msg_offset + 3;
    if pkt_len < first_cert_offset + 3 {
        return Err(ERR_NOT_CERTIFICATE);
    }

    // Read first certificate length (3 bytes, big-endian)
    let cert_len_b0 = ctx_load_u8(ctx, first_cert_offset)? as u32;
    let cert_len_b1 = ctx_load_u8(ctx, first_cert_offset + 1)? as u32;
    let cert_len_b2 = ctx_load_u8(ctx, first_cert_offset + 2)? as u32;
    let cert_der_len = (cert_len_b0 << 16) | (cert_len_b1 << 8) | cert_len_b2;

    if cert_der_len == 0 {
        return Err(ERR_NOT_CERTIFICATE);
    }

    let cert_data_offset = first_cert_offset + 3;

    // Read first 32 bytes of cert DER as pseudo-fingerprint
    let mut fingerprint: [u8; 32] = [0u8; 32];
    let available = if pkt_len > cert_data_offset {
        pkt_len - cert_data_offset
    } else {
        0
    };

    let fp_len = if cert_der_len < 32 {
        cert_der_len as usize
    } else {
        32
    };
    let fp_len = if fp_len > available { available } else { fp_len };

    if fp_len == 0 {
        return Err(ERR_NOT_CERTIFICATE);
    }

    // Bounded loop to read fingerprint bytes
    let mut i: usize = 0;
    while i < fp_len && i < 32 {
        if let Ok(b) = ctx_load_u8(ctx, cert_data_offset + i) {
            fingerprint[i] = b;
        }
        i += 1;
    }

    Ok(fingerprint)
}

/// Compare two 32-byte fingerprints for equality.
/// Uses a bounded loop (eBPF-verifier friendly).
#[inline(always)]
fn fingerprints_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut i: usize = 0;
    while i < 32 {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}
