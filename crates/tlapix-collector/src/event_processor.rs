//! Event processing: converts raw `TlsCertEvent` from the ring buffer into
//! structured `CertificateMetadata` using x509-parser and SHA-256 fingerprinting.

use chrono::{DateTime, TimeZone, Utc};
use sha2::{Digest, Sha256};
use tlapix_common::bpf::TlsCertEvent;
use tlapix_common::types::{completeness, CertificateMetadata};
use x509_parser::prelude::*;

/// Errors that can occur during event processing.
#[derive(Debug, thiserror::Error)]
pub enum EventProcessError {
    /// The certificate DER data could not be parsed at all.
    #[error("malformed certificate: {reason}")]
    MalformedCertificate {
        reason: String,
        timestamp_ns: u64,
        src_ip: u32,
        dst_ip: u32,
        dst_port: u16,
        available_bytes: u32,
    },

    /// The certificate was partially parsed but some fields are missing.
    #[error("partial certificate extraction: {missing_fields}")]
    PartialExtraction { missing_fields: String },
}

/// Result of processing a single `TlsCertEvent`.
#[derive(Debug)]
pub struct ProcessedEvent {
    /// The extracted certificate metadata.
    pub metadata: CertificateMetadata,
    /// Whether the certificate data was truncated (cert_len > 4096).
    pub is_truncated: bool,
}

/// Process a raw `TlsCertEvent` into a `CertificateMetadata`.
///
/// This function:
/// 1. Computes the real SHA-256 fingerprint from `cert_data[0..effective_len]`
/// 2. Parses the DER data using `x509-parser`
/// 3. Extracts all fields into `CertificateMetadata`
/// 4. Sets `completeness_flags` for any fields that could not be extracted
/// 5. Returns an error for completely malformed certificates (logged by caller)
pub fn process_event(event: &TlsCertEvent) -> Result<ProcessedEvent, EventProcessError> {
    // Determine effective certificate length (capped at buffer size)
    let effective_len = (event.cert_len as usize).min(event.cert_data.len());
    let is_truncated = event.cert_len as usize > event.cert_data.len();

    if effective_len == 0 {
        return Err(EventProcessError::MalformedCertificate {
            reason: "zero-length certificate data".to_string(),
            timestamp_ns: event.timestamp_ns,
            src_ip: event.src_ip,
            dst_ip: event.dst_ip,
            dst_port: event.dst_port,
            available_bytes: 0,
        });
    }

    let cert_bytes = &event.cert_data[..effective_len];

    // Compute real SHA-256 fingerprint in userspace
    let fingerprint = compute_sha256(cert_bytes);

    // Attempt to parse the DER-encoded certificate
    let parse_result = X509Certificate::from_der(cert_bytes);

    match parse_result {
        Ok((_remaining, cert)) => {
            let metadata = extract_metadata(&cert, event, fingerprint, is_truncated);
            Ok(ProcessedEvent {
                metadata,
                is_truncated,
            })
        }
        Err(_parse_err) => {
            // If the certificate is truncated, we can still try to extract partial metadata
            if is_truncated {
                // Try partial extraction — even if full parse fails, we have the fingerprint
                // and network-level metadata from the event
                let metadata = build_partial_metadata(event, fingerprint, is_truncated);
                Ok(ProcessedEvent {
                    metadata,
                    is_truncated,
                })
            } else {
                Err(EventProcessError::MalformedCertificate {
                    reason: "failed to parse DER-encoded certificate".to_string(),
                    timestamp_ns: event.timestamp_ns,
                    src_ip: event.src_ip,
                    dst_ip: event.dst_ip,
                    dst_port: event.dst_port,
                    available_bytes: effective_len as u32,
                })
            }
        }
    }
}

/// Compute SHA-256 fingerprint of the given bytes.
pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&result);
    fingerprint
}

/// Extract full metadata from a successfully parsed X.509 certificate.
fn extract_metadata(
    cert: &X509Certificate<'_>,
    event: &TlsCertEvent,
    fingerprint: [u8; 32],
    is_truncated: bool,
) -> CertificateMetadata {
    let mut flags: u32 = 0;

    // Subject
    let subject = cert.subject().to_string();
    if !subject.is_empty() {
        flags |= completeness::SUBJECT;
    }

    // Issuer
    let issuer = cert.issuer().to_string();
    if !issuer.is_empty() {
        flags |= completeness::ISSUER;
    }

    // Serial number
    let serial_number = cert.serial.to_str_radix(16);
    flags |= completeness::SERIAL_NUMBER;

    // Validity dates
    let not_before = asn1_time_to_datetime(cert.validity().not_before);
    let not_after = asn1_time_to_datetime(cert.validity().not_after);
    flags |= completeness::NOT_BEFORE;
    flags |= completeness::NOT_AFTER;

    // Subject Alternative Names
    let sans = extract_sans(cert);
    if !sans.is_empty() {
        flags |= completeness::SANS;
    }

    // Key algorithm and size
    let (key_algorithm, key_size) = extract_key_info(cert);
    if !key_algorithm.is_empty() {
        flags |= completeness::KEY_ALGORITHM;
    }
    if key_size > 0 {
        flags |= completeness::KEY_SIZE;
    }

    // Chain depth
    flags |= completeness::CHAIN_DEPTH;

    // Issuer fingerprint (from the event, computed by eBPF or set to zeros)
    let issuer_fingerprint = if event.issuer_fingerprint != [0u8; 32] {
        flags |= completeness::ISSUER_FINGERPRINT;
        Some(event.issuer_fingerprint)
    } else {
        None
    };

    // If truncated, mark that we may be missing data
    if is_truncated {
        // SANs might be incomplete in a truncated cert
        // We keep whatever we extracted but note the truncation
        // The completeness flags already reflect what we actually got
    }

    let now = Utc::now();
    let sni_hostname = extract_sni(event);

    CertificateMetadata {
        fingerprint,
        subject,
        issuer,
        serial_number,
        not_before,
        not_after,
        sans,
        key_algorithm,
        key_size,
        chain_depth: event.chain_depth,
        issuer_fingerprint,
        first_seen: now,
        last_seen: now,
        connection_count: 1,
        source_ip: Some(format_ipv4(event.src_ip)),
        destination_ip: Some(format_ipv4(event.dst_ip)),
        sni_hostname,
        completeness_flags: flags,
    }
}

/// Build partial metadata when the certificate cannot be fully parsed
/// (e.g., due to truncation) but we still have network-level information.
fn build_partial_metadata(
    event: &TlsCertEvent,
    fingerprint: [u8; 32],
    _is_truncated: bool,
) -> CertificateMetadata {
    // We can only populate fields from the event itself, not from parsing
    let now = Utc::now();
    let sni_hostname = extract_sni(event);

    // Only chain_depth is available from the event without parsing
    let flags: u32 = completeness::CHAIN_DEPTH;

    CertificateMetadata {
        fingerprint,
        subject: String::new(),
        issuer: String::new(),
        serial_number: String::new(),
        not_before: Utc.timestamp_opt(0, 0).unwrap(),
        not_after: Utc.timestamp_opt(0, 0).unwrap(),
        sans: Vec::new(),
        key_algorithm: String::new(),
        key_size: 0,
        chain_depth: event.chain_depth,
        issuer_fingerprint: if event.issuer_fingerprint != [0u8; 32] {
            Some(event.issuer_fingerprint)
        } else {
            None
        },
        first_seen: now,
        last_seen: now,
        connection_count: 1,
        source_ip: Some(format_ipv4(event.src_ip)),
        destination_ip: Some(format_ipv4(event.dst_ip)),
        sni_hostname,
        completeness_flags: flags,
    }
}

/// Extract Subject Alternative Names from the certificate.
fn extract_sans(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut sans = Vec::new();

    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            match name {
                GeneralName::DNSName(dns) => {
                    sans.push(dns.to_string());
                }
                GeneralName::IPAddress(ip_bytes) => {
                    if ip_bytes.len() == 4 {
                        sans.push(format!(
                            "{}.{}.{}.{}",
                            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
                        ));
                    } else if ip_bytes.len() == 16 {
                        // IPv6
                        let mut parts = Vec::new();
                        for chunk in ip_bytes.chunks(2) {
                            parts.push(format!("{:02x}{:02x}", chunk[0], chunk[1]));
                        }
                        sans.push(parts.join(":"));
                    }
                }
                GeneralName::RFC822Name(email) => {
                    sans.push(email.to_string());
                }
                GeneralName::URI(uri) => {
                    sans.push(uri.to_string());
                }
                _ => {}
            }
        }
    }

    // Cap at 100 entries per requirements
    sans.truncate(100);
    sans
}

/// Extract key algorithm and key size from the certificate's public key.
fn extract_key_info(cert: &X509Certificate<'_>) -> (String, u32) {
    let spki = cert.public_key();
    let oid_str = spki.algorithm.algorithm.to_string();
    let algorithm = match oid_str.as_str() {
        // RSA OIDs
        "1.2.840.113549.1.1.1" => "RSA".to_string(),
        // EC OIDs
        "1.2.840.10045.2.1" => "ECDSA".to_string(),
        // Ed25519
        "1.3.101.112" => "Ed25519".to_string(),
        // Ed448
        "1.3.101.113" => "Ed448".to_string(),
        other => other.to_string(),
    };

    let key_size = match algorithm.as_str() {
        "RSA" => {
            // RSA key size is the bit length of the modulus
            let raw_len = spki.subject_public_key.data.len();
            estimate_rsa_key_size(raw_len)
        }
        "ECDSA" => {
            // EC key size is determined by the curve parameter OID
            if let Some(params) = &spki.algorithm.parameters {
                // Try to interpret parameters as an OID for the curve
                estimate_ec_key_size_from_params(params.data)
            } else {
                // Fallback: estimate from key data length
                let raw_len = spki.subject_public_key.data.len();
                match raw_len {
                    65 => 256,  // P-256 uncompressed point
                    97 => 384,  // P-384 uncompressed point
                    133 => 521, // P-521 uncompressed point
                    _ => 0,
                }
            }
        }
        "Ed25519" => 256,
        "Ed448" => 448,
        _ => 0,
    };

    (algorithm, key_size)
}

/// Estimate RSA key size from the raw public key byte length.
fn estimate_rsa_key_size(raw_len: usize) -> u32 {
    // RSA public key contains modulus + exponent in DER encoding
    // Common sizes: 2048-bit = ~270 bytes, 4096-bit = ~526 bytes
    if raw_len >= 512 {
        4096
    } else if raw_len >= 384 {
        3072
    } else if raw_len >= 256 {
        2048
    } else if raw_len >= 128 {
        1024
    } else {
        (raw_len * 8) as u32
    }
}

/// Estimate EC key size from the algorithm parameters (curve OID encoded in DER).
fn estimate_ec_key_size_from_params(param_data: &[u8]) -> u32 {
    // The parameters for EC keys are typically an OID identifying the curve.
    // We match known curve OID byte patterns directly.

    // P-256 (secp256r1): OID 1.2.840.10045.3.1.7
    const P256_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

    // P-384 (secp384r1): OID 1.3.132.0.34
    const P384_OID: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];

    // P-521 (secp521r1): OID 1.3.132.0.35
    const P521_OID: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];

    if contains_oid_bytes(param_data, P256_OID) {
        256
    } else if contains_oid_bytes(param_data, P384_OID) {
        384
    } else if contains_oid_bytes(param_data, P521_OID) {
        521
    } else {
        0
    }
}

/// Check if the data contains the given OID byte sequence.
fn contains_oid_bytes(data: &[u8], oid_bytes: &[u8]) -> bool {
    data.windows(oid_bytes.len()).any(|w| w == oid_bytes)
}

/// Convert an ASN.1 time to a chrono DateTime<Utc>.
fn asn1_time_to_datetime(time: ASN1Time) -> DateTime<Utc> {
    // ASN1Time provides a timestamp() method that returns seconds since epoch
    Utc.timestamp_opt(time.timestamp(), 0)
        .single()
        .unwrap_or_else(Utc::now)
}

/// Extract SNI hostname from the event.
fn extract_sni(event: &TlsCertEvent) -> Option<String> {
    let sni_len = event.sni_len as usize;
    if sni_len == 0 || sni_len > event.sni.len() {
        return None;
    }
    String::from_utf8(event.sni[..sni_len].to_vec()).ok()
}

/// Format an IPv4 address from a u32 (network byte order).
fn format_ipv4(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_sha256() {
        let data = b"hello world";
        let hash = compute_sha256(data);
        // Known SHA-256 of "hello world"
        let expected = [
            0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d,
            0xab, 0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac,
            0xe2, 0xef, 0xcd, 0xe9,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_format_ipv4() {
        assert_eq!(format_ipv4(0xC0A80001), "192.168.0.1");
        assert_eq!(format_ipv4(0x7F000001), "127.0.0.1");
        assert_eq!(format_ipv4(0x0A000001), "10.0.0.1");
    }

    #[test]
    fn test_extract_sni_empty() {
        let mut event = create_test_event();
        event.sni_len = 0;
        assert_eq!(extract_sni(&event), None);
    }

    #[test]
    fn test_extract_sni_valid() {
        let mut event = create_test_event();
        let hostname = b"example.com";
        event.sni[..hostname.len()].copy_from_slice(hostname);
        event.sni_len = hostname.len() as u16;
        assert_eq!(extract_sni(&event), Some("example.com".to_string()));
    }

    #[test]
    fn test_process_event_zero_length_cert() {
        let mut event = create_test_event();
        event.cert_len = 0;
        let result = process_event(&event);
        assert!(result.is_err());
        match result.unwrap_err() {
            EventProcessError::MalformedCertificate { reason, .. } => {
                assert!(reason.contains("zero-length"));
            }
            _ => panic!("expected MalformedCertificate error"),
        }
    }

    #[test]
    fn test_process_event_invalid_der() {
        let mut event = create_test_event();
        // Fill with garbage data that isn't valid DER
        event.cert_data[..10].copy_from_slice(&[0xFF; 10]);
        event.cert_len = 10;
        let result = process_event(&event);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_event_truncated_cert_returns_partial() {
        let mut event = create_test_event();
        // Set cert_len larger than buffer to indicate truncation
        event.cert_len = 8192;
        // Fill with some data (won't parse as valid cert, but truncation path
        // should return partial metadata)
        event.cert_data[..100].copy_from_slice(&[0x30; 100]);
        let result = process_event(&event);
        // Truncated certs should return partial metadata, not an error
        assert!(result.is_ok());
        let processed = result.unwrap();
        assert!(processed.is_truncated);
        // Completeness flags should only have CHAIN_DEPTH set (partial extraction)
        assert_eq!(
            processed.metadata.completeness_flags & completeness::SUBJECT,
            0
        );
    }

    #[test]
    fn test_process_event_valid_certificate() {
        // Use the real test certificate
        let cert_der = include_bytes!("../test_data/test_cert.der");
        let mut event = create_test_event();
        let copy_len = cert_der.len().min(4096);
        event.cert_data[..copy_len].copy_from_slice(&cert_der[..copy_len]);
        event.cert_len = cert_der.len() as u32;

        // Set SNI
        let sni = b"test.example.com";
        event.sni[..sni.len()].copy_from_slice(sni);
        event.sni_len = sni.len() as u16;

        let result = process_event(&event);
        assert!(result.is_ok(), "failed to process valid cert: {:?}", result.err());

        let processed = result.unwrap();
        assert!(!processed.is_truncated);

        let meta = &processed.metadata;

        // Fingerprint should be the SHA-256 of the DER data
        let expected_fp = compute_sha256(&cert_der[..copy_len]);
        assert_eq!(meta.fingerprint, expected_fp);

        // Subject should contain "test.example.com"
        assert!(
            meta.subject.contains("test.example.com"),
            "subject was: {}",
            meta.subject
        );

        // Key algorithm should be RSA
        assert_eq!(meta.key_algorithm, "RSA");

        // Key size should be 2048
        assert_eq!(meta.key_size, 2048);

        // SNI should be extracted
        assert_eq!(meta.sni_hostname, Some("test.example.com".to_string()));

        // Completeness flags should have all required fields set
        assert_ne!(meta.completeness_flags & completeness::SUBJECT, 0);
        assert_ne!(meta.completeness_flags & completeness::ISSUER, 0);
        assert_ne!(meta.completeness_flags & completeness::SERIAL_NUMBER, 0);
        assert_ne!(meta.completeness_flags & completeness::NOT_BEFORE, 0);
        assert_ne!(meta.completeness_flags & completeness::NOT_AFTER, 0);
        assert_ne!(meta.completeness_flags & completeness::KEY_ALGORITHM, 0);
        assert_ne!(meta.completeness_flags & completeness::KEY_SIZE, 0);

        // SANs should include the test domains
        assert!(
            meta.sans.iter().any(|s| s == "test.example.com"),
            "SANs were: {:?}",
            meta.sans
        );
    }

    #[test]
    fn test_process_event_completeness_flags_bitmask() {
        // Verify that completeness flags correctly reflect which fields are present
        let cert_der = include_bytes!("../test_data/test_cert.der");
        let mut event = create_test_event();
        let copy_len = cert_der.len().min(4096);
        event.cert_data[..copy_len].copy_from_slice(&cert_der[..copy_len]);
        event.cert_len = cert_der.len() as u32;

        let result = process_event(&event).unwrap();
        let flags = result.metadata.completeness_flags;

        // For a valid cert, ALL_REQUIRED should be set
        assert_eq!(
            flags & completeness::ALL_REQUIRED,
            completeness::ALL_REQUIRED,
            "not all required flags set: got {:#010b}, expected {:#010b}",
            flags & completeness::ALL_REQUIRED,
            completeness::ALL_REQUIRED
        );
    }

    /// Helper to create a zeroed-out test event.
    fn create_test_event() -> TlsCertEvent {
        TlsCertEvent {
            timestamp_ns: 1_000_000_000,
            src_ip: 0xC0A80001, // 192.168.0.1
            dst_ip: 0x0A000001, // 10.0.0.1
            src_port: 54321,
            dst_port: 443,
            ip_version: 4,
            tls_version: 0x0303,
            sni_len: 0,
            sni: [0u8; 256],
            fingerprint: [0u8; 32],
            cert_len: 0,
            cert_data: [0u8; 4096],
            chain_depth: 1,
            issuer_fingerprint: [0u8; 32],
            is_new: 1,
        }
    }
}
