//! Tlapix eBPF Programs - Kernel-space TLS handshake observation and action execution.
//!
//! This crate is compiled for the `bpfel-unknown-none` target and runs inside the Linux kernel.
//! It uses `aya-ebpf` for the eBPF runtime and must be `no_std`.
//!
//! ## Architecture
//!
//! - `tlapix_ingress`: TC ingress classifier that observes incoming TLS handshakes
//!   (ServerHello/Certificate messages from remote servers).
//! - `tlapix_egress`: TC egress classifier that observes outgoing TLS handshakes
//!   (for server-side certificate observation).
//!
//! Both programs parse TCP packets looking for TLS record layer (content type 0x16),
//! extract certificate data from Certificate messages, and push events to a ring buffer
//! for userspace processing.

#![no_std]
#![no_main]

pub mod executor;
pub mod maps;

use aya_ebpf::{bindings::TC_ACT_OK, macros::classifier, programs::TcContext};

use maps::{
    increment_drop_counter, is_new_cert, DROP_IDX_MALFORMED, DROP_IDX_RING_FULL, DROP_IDX_TOTAL,
    EVENTS,
};

// =============================================================================
// Shared repr(C) types (mirrored from tlapix-common for no_std compatibility)
// =============================================================================

/// Maximum certificate DER data we can capture in a single event.
const MAX_CERT_DATA: usize = 4096;
/// Maximum SNI hostname length.
const MAX_SNI_LEN: usize = 256;

/// Event pushed from the eBPF Collector to userspace via the ring buffer.
#[repr(C)]
#[derive(Clone, Copy)]
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
    pub sni: [u8; MAX_SNI_LEN],
    /// SHA-256 fingerprint placeholder (computed in userspace from cert_data)
    pub fingerprint: [u8; 32],
    /// Length of the DER-encoded certificate data
    pub cert_len: u32,
    /// DER-encoded leaf certificate (truncated to MAX_CERT_DATA bytes)
    pub cert_data: [u8; MAX_CERT_DATA],
    /// Number of certificates in the chain
    pub chain_depth: u8,
    /// SHA-256 fingerprint of the immediate issuing CA (computed in userspace)
    pub issuer_fingerprint: [u8; 32],
    /// 1 if this certificate was not previously in the seen-set, 0 otherwise
    pub is_new: u8,
}

// =============================================================================
// Constants for protocol parsing
// =============================================================================

/// Ethernet header size (no VLAN tags).
pub const ETH_HDR_LEN: usize = 14;
/// EtherType for IPv4.
pub const ETH_P_IP: u16 = 0x0800;
/// IP protocol number for TCP.
pub const IPPROTO_TCP: u8 = 6;
/// TLS record content type: Handshake.
pub const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
/// TLS handshake type: Certificate (used in TLS 1.2).
pub const TLS_HANDSHAKE_CERTIFICATE: u8 = 11;
/// TLS handshake type: ServerHello.
pub const TLS_HANDSHAKE_SERVER_HELLO: u8 = 2;

// =============================================================================
// TC Ingress Classifier
// =============================================================================

/// TC ingress classifier - observes incoming TLS handshakes.
///
/// Parses incoming TCP packets for TLS Certificate messages and pushes
/// certificate data to the ring buffer for userspace processing.
#[classifier]
pub fn tlapix_ingress(ctx: TcContext) -> i32 {
    match try_tlapix_ingress(&ctx) {
        Ok(_) => TC_ACT_OK,
        Err(_) => TC_ACT_OK, // Always pass traffic through (observation only)
    }
}

/// TC egress classifier - observes outgoing TLS handshakes.
///
/// Parses outgoing TCP packets for TLS Certificate messages (server-side).
#[classifier]
pub fn tlapix_egress(ctx: TcContext) -> i32 {
    match try_tlapix_egress(&ctx) {
        Ok(_) => TC_ACT_OK,
        Err(_) => TC_ACT_OK, // Always pass traffic through (observation only)
    }
}

// =============================================================================
// Core parsing logic
// =============================================================================

/// Result type for eBPF operations (no std::error::Error available).
type EbpfResult = Result<(), u32>;

/// Error codes for internal use.
const ERR_PKT_TOO_SHORT: u32 = 1;
const ERR_NOT_IPV4: u32 = 2;
const ERR_NOT_TCP: u32 = 3;
const ERR_NOT_TLS: u32 = 4;
const ERR_NOT_HANDSHAKE: u32 = 5;
const ERR_RINGBUF_FULL: u32 = 6;
const ERR_READ_FAILED: u32 = 7;

#[inline(always)]
fn try_tlapix_ingress(ctx: &TcContext) -> EbpfResult {
    parse_tls_handshake(ctx)
}

#[inline(always)]
fn try_tlapix_egress(ctx: &TcContext) -> EbpfResult {
    parse_tls_handshake(ctx)
}

/// Main TLS handshake parsing function.
///
/// Parses: Ethernet → IPv4 → TCP → TLS Record → Handshake → Certificate
///
/// Due to eBPF constraints:
/// - All loops are bounded
/// - Stack usage is minimized (large data goes to ring buffer directly)
/// - No heap allocation
/// - Uses packet data access via TcContext helpers
#[inline(always)]
fn parse_tls_handshake(ctx: &TcContext) -> EbpfResult {
    let pkt_len = ctx.len() as usize;

    // Minimum: Eth(14) + IPv4(20) + TCP(20) + TLS record header(5) = 59 bytes
    if pkt_len < ETH_HDR_LEN + 20 + 20 + 5 {
        return Err(ERR_PKT_TOO_SHORT);
    }

    // --- Parse Ethernet header ---
    let eth_proto = u16::from_be(ctx_load_u16(ctx, 12)?);
    if eth_proto != ETH_P_IP {
        return Err(ERR_NOT_IPV4);
    }

    // --- Parse IPv4 header ---
    let ip_offset = ETH_HDR_LEN;
    let ip_version_ihl = ctx_load_u8(ctx, ip_offset)?;
    let ip_ihl = (ip_version_ihl & 0x0F) as usize * 4;

    // Validate IHL (minimum 20 bytes)
    if ip_ihl < 20 || ip_ihl > 60 {
        increment_drop_counter(DROP_IDX_MALFORMED);
        return Err(ERR_NOT_IPV4);
    }

    let ip_protocol = ctx_load_u8(ctx, ip_offset + 9)?;
    if ip_protocol != IPPROTO_TCP {
        return Err(ERR_NOT_TCP);
    }

    let src_ip = u32::from_be(ctx_load_u32(ctx, ip_offset + 12)?);
    let dst_ip = u32::from_be(ctx_load_u32(ctx, ip_offset + 16)?);

    // --- Parse TCP header ---
    let tcp_offset = ip_offset + ip_ihl;
    if pkt_len < tcp_offset + 20 {
        return Err(ERR_PKT_TOO_SHORT);
    }

    let src_port = u16::from_be(ctx_load_u16(ctx, tcp_offset)?);
    let dst_port = u16::from_be(ctx_load_u16(ctx, tcp_offset + 2)?);

    let tcp_data_offset_byte = ctx_load_u8(ctx, tcp_offset + 12)?;
    let tcp_hdr_len = ((tcp_data_offset_byte >> 4) & 0x0F) as usize * 4;

    if tcp_hdr_len < 20 || tcp_hdr_len > 60 {
        increment_drop_counter(DROP_IDX_MALFORMED);
        return Err(ERR_NOT_TCP);
    }

    // --- Parse TLS record layer ---
    let tls_offset = tcp_offset + tcp_hdr_len;
    if pkt_len < tls_offset + 5 {
        return Err(ERR_NOT_TLS);
    }

    let content_type = ctx_load_u8(ctx, tls_offset)?;
    if content_type != TLS_CONTENT_TYPE_HANDSHAKE {
        return Err(ERR_NOT_TLS);
    }

    // TLS version in record layer
    let tls_version = u16::from_be(ctx_load_u16(ctx, tls_offset + 1)?);
    let tls_record_len = u16::from_be(ctx_load_u16(ctx, tls_offset + 3)?) as usize;

    // Sanity check record length
    if tls_record_len == 0 || tls_record_len > 16384 {
        increment_drop_counter(DROP_IDX_MALFORMED);
        return Err(ERR_NOT_TLS);
    }

    // Increment total handshakes observed
    increment_drop_counter(DROP_IDX_TOTAL);

    // --- Parse TLS Handshake message ---
    let hs_offset = tls_offset + 5;
    if pkt_len < hs_offset + 4 {
        return Err(ERR_NOT_HANDSHAKE);
    }

    let hs_type = ctx_load_u8(ctx, hs_offset)?;

    // We're interested in Certificate messages (type 11) for TLS 1.2
    // and ServerHello (type 2) to detect TLS version
    if hs_type == TLS_HANDSHAKE_SERVER_HELLO {
        // Parse ServerHello to get actual TLS version negotiated
        // For TLS 1.3, the version is in supported_versions extension
        // but the record layer says 0x0303. We note this for the event.
        return Err(ERR_NOT_HANDSHAKE); // Not a certificate message
    }

    if hs_type != TLS_HANDSHAKE_CERTIFICATE {
        return Err(ERR_NOT_HANDSHAKE);
    }

    // --- Parse Certificate handshake message (TLS 1.2 format) ---
    // Handshake header: type(1) + length(3) = 4 bytes
    // Certificate message: certificates_length(3) + certificate_list
    let cert_msg_offset = hs_offset + 4;
    if pkt_len < cert_msg_offset + 3 {
        return Err(ERR_NOT_HANDSHAKE);
    }

    // Read certificates_length (3 bytes, big-endian)
    let certs_len_b0 = ctx_load_u8(ctx, cert_msg_offset)? as u32;
    let certs_len_b1 = ctx_load_u8(ctx, cert_msg_offset + 1)? as u32;
    let certs_len_b2 = ctx_load_u8(ctx, cert_msg_offset + 2)? as u32;
    let _certs_total_len = (certs_len_b0 << 16) | (certs_len_b1 << 8) | certs_len_b2;

    // First certificate entry: length(3) + certificate_data
    let first_cert_offset = cert_msg_offset + 3;
    if pkt_len < first_cert_offset + 3 {
        return Err(ERR_NOT_HANDSHAKE);
    }

    // Read first certificate length (3 bytes, big-endian)
    let cert_len_b0 = ctx_load_u8(ctx, first_cert_offset)? as u32;
    let cert_len_b1 = ctx_load_u8(ctx, first_cert_offset + 1)? as u32;
    let cert_len_b2 = ctx_load_u8(ctx, first_cert_offset + 2)? as u32;
    let cert_der_len = (cert_len_b0 << 16) | (cert_len_b1 << 8) | cert_len_b2;

    // Sanity check certificate length
    if cert_der_len == 0 || cert_der_len > 65535 {
        increment_drop_counter(DROP_IDX_MALFORMED);
        return Err(ERR_NOT_HANDSHAKE);
    }

    let cert_data_offset = first_cert_offset + 3;

    // Determine how many bytes we can actually copy (bounded by packet and buffer)
    let available_in_pkt = if pkt_len > cert_data_offset {
        pkt_len - cert_data_offset
    } else {
        0
    };

    let copy_len = if cert_der_len as usize > MAX_CERT_DATA {
        MAX_CERT_DATA
    } else {
        cert_der_len as usize
    };

    let copy_len = if copy_len > available_in_pkt {
        available_in_pkt
    } else {
        copy_len
    };

    if copy_len == 0 {
        return Err(ERR_NOT_HANDSHAKE);
    }

    // --- Count chain depth ---
    // Walk through certificate entries to count chain depth (bounded loop)
    let chain_depth = count_chain_depth(ctx, cert_msg_offset + 3, pkt_len, _certs_total_len);

    // --- Build pseudo-fingerprint for dedup (first 32 bytes of cert data) ---
    let mut pseudo_fp: [u8; 32] = [0u8; 32];
    let fp_len = if copy_len < 32 { copy_len } else { 32 };

    // Read first 32 bytes for pseudo-fingerprint (bounded)
    let mut i: usize = 0;
    while i < fp_len && i < 32 {
        if let Ok(b) = ctx_load_u8(ctx, cert_data_offset + i) {
            pseudo_fp[i] = b;
        }
        i += 1;
    }

    // --- Check if certificate is new (not in seen_certs map) ---
    let timestamp_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    let is_new = is_new_cert(&pseudo_fp, timestamp_ns);

    // --- Push event to ring buffer ---
    if let Some(mut buf) = EVENTS.reserve::<TlsCertEvent>(0) {
        let event = buf.as_mut_ptr();
        unsafe {
            (*event).timestamp_ns = timestamp_ns;
            (*event).src_ip = src_ip;
            (*event).dst_ip = dst_ip;
            (*event).src_port = src_port;
            (*event).dst_port = dst_port;
            (*event).ip_version = 4; // IPv4 only for now
            (*event).tls_version = tls_version;
            (*event).sni_len = 0; // SNI is in ClientHello, not Certificate msg
            (*event).sni = [0u8; MAX_SNI_LEN];
            (*event).fingerprint = pseudo_fp; // Pseudo-fingerprint; real SHA-256 in userspace
            (*event).cert_len = copy_len as u32;
            (*event).cert_data = [0u8; MAX_CERT_DATA];
            (*event).chain_depth = chain_depth;
            (*event).issuer_fingerprint = [0u8; 32];
            (*event).is_new = is_new;

            // Copy certificate data into event (bounded loop)
            copy_cert_data(ctx, cert_data_offset, copy_len, &mut (*event).cert_data);

            // Extract issuer fingerprint (pseudo: first 32 bytes of second cert)
            if chain_depth > 1 {
                extract_issuer_pseudo_fp(
                    ctx,
                    first_cert_offset,
                    cert_der_len,
                    pkt_len,
                    &mut (*event).issuer_fingerprint,
                );
            }
        }
        buf.submit(0);
    } else {
        // Ring buffer full - increment drop counter
        increment_drop_counter(DROP_IDX_RING_FULL);
        return Err(ERR_RINGBUF_FULL);
    }

    Ok(())
}

// =============================================================================
// Helper functions
// =============================================================================

// =============================================================================
// Certificate chain and data helpers
// =============================================================================

/// Count the number of certificates in the chain (bounded to 10 max).
#[inline(always)]
fn count_chain_depth(ctx: &TcContext, start: usize, pkt_len: usize, total_len: u32) -> u8 {
    let mut offset = start;
    let end = start + total_len as usize;
    let mut depth: u8 = 0;

    // Bounded loop: max 10 certificates in chain
    let mut iter = 0u32;
    while iter < 10 {
        if offset + 3 > pkt_len || offset + 3 > end {
            break;
        }

        let len_b0 = match ctx_load_u8(ctx, offset) {
            Ok(b) => b as u32,
            Err(_) => break,
        };
        let len_b1 = match ctx_load_u8(ctx, offset + 1) {
            Ok(b) => b as u32,
            Err(_) => break,
        };
        let len_b2 = match ctx_load_u8(ctx, offset + 2) {
            Ok(b) => b as u32,
            Err(_) => break,
        };

        let cert_len = (len_b0 << 16) | (len_b1 << 8) | len_b2;
        if cert_len == 0 {
            break;
        }

        depth += 1;
        offset += 3 + cert_len as usize;
        iter += 1;
    }

    if depth == 0 {
        1 // At minimum, we have the leaf cert
    } else {
        depth
    }
}

/// Copy certificate DER data from packet into the event buffer.
/// Uses a bounded loop to satisfy the eBPF verifier.
#[inline(always)]
fn copy_cert_data(ctx: &TcContext, offset: usize, len: usize, dest: &mut [u8; MAX_CERT_DATA]) {
    // Copy in chunks to stay within verifier bounds.
    // We use a bounded loop with a maximum of MAX_CERT_DATA iterations.
    let mut i: usize = 0;
    // The verifier needs a compile-time bound. We unroll in blocks of 64 bytes.
    while i < len && i < MAX_CERT_DATA {
        // Copy up to 64 bytes per inner iteration to reduce loop count
        let chunk_end = if i + 64 < len && i + 64 < MAX_CERT_DATA {
            i + 64
        } else if len < MAX_CERT_DATA {
            len
        } else {
            MAX_CERT_DATA
        };

        while i < chunk_end {
            if let Ok(b) = ctx_load_u8(ctx, offset + i) {
                dest[i] = b;
            } else {
                return;
            }
            i += 1;
        }
    }
}

/// Extract a pseudo-fingerprint for the issuer certificate (second cert in chain).
/// Reads the first 32 bytes of the second certificate's DER data.
#[inline(always)]
fn extract_issuer_pseudo_fp(
    ctx: &TcContext,
    first_cert_offset: usize,
    first_cert_len: u32,
    pkt_len: usize,
    dest: &mut [u8; 32],
) {
    // Second cert starts after: first_cert_length_field(3) + first_cert_data
    let second_cert_offset = first_cert_offset + 3 + first_cert_len as usize;

    // Read second cert's length
    if second_cert_offset + 3 > pkt_len {
        return;
    }

    let len_b0 = match ctx_load_u8(ctx, second_cert_offset) {
        Ok(b) => b as u32,
        Err(_) => return,
    };
    let len_b1 = match ctx_load_u8(ctx, second_cert_offset + 1) {
        Ok(b) => b as u32,
        Err(_) => return,
    };
    let len_b2 = match ctx_load_u8(ctx, second_cert_offset + 2) {
        Ok(b) => b as u32,
        Err(_) => return,
    };

    let second_cert_len = (len_b0 << 16) | (len_b1 << 8) | len_b2;
    if second_cert_len == 0 {
        return;
    }

    let second_cert_data_offset = second_cert_offset + 3;
    let fp_len = if second_cert_len < 32 {
        second_cert_len as usize
    } else {
        32
    };

    let mut i: usize = 0;
    while i < fp_len && i < 32 {
        if second_cert_data_offset + i >= pkt_len {
            break;
        }
        if let Ok(b) = ctx_load_u8(ctx, second_cert_data_offset + i) {
            dest[i] = b;
        } else {
            break;
        }
        i += 1;
    }
}

// =============================================================================
// Packet data access helpers
// =============================================================================

/// Load a single byte from the packet at the given offset.
#[inline(always)]
pub fn ctx_load_u8(ctx: &TcContext, offset: usize) -> Result<u8, u32> {
    ctx.load::<u8>(offset).map_err(|_| ERR_READ_FAILED)
}

/// Load a u16 (in network byte order) from the packet at the given offset.
#[inline(always)]
pub fn ctx_load_u16(ctx: &TcContext, offset: usize) -> Result<u16, u32> {
    ctx.load::<u16>(offset).map_err(|_| ERR_READ_FAILED)
}

/// Load a u32 (in network byte order) from the packet at the given offset.
#[inline(always)]
pub fn ctx_load_u32(ctx: &TcContext, offset: usize) -> Result<u32, u32> {
    ctx.load::<u32>(offset).map_err(|_| ERR_READ_FAILED)
}

// =============================================================================
// Panic handler (required for no_std)
// =============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
