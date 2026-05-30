//! Program integrity validation at startup.
//!
//! Before activating the Collector (loading eBPF programs), the system validates
//! that all pre-loaded eBPF program binaries match their expected SHA-256 checksums.
//! If any program fails validation, startup aborts immediately — ensuring the kernel
//! never executes tampered or corrupted eBPF code.

use std::fmt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{error, info};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A manifest listing all eBPF programs and their expected checksums.
#[derive(Debug, Clone)]
pub struct ProgramManifest {
    pub programs: Vec<ProgramEntry>,
}

/// A single eBPF program entry with its expected SHA-256 checksum.
#[derive(Debug, Clone)]
pub struct ProgramEntry {
    /// Human-readable name of the program (e.g., "tls_collector", "isolate_program").
    pub name: String,
    /// Path to the compiled eBPF binary on disk.
    pub path: PathBuf,
    /// Expected SHA-256 checksum of the binary file contents.
    pub expected_sha256: [u8; 32],
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during program integrity validation.
#[derive(Debug, Error)]
pub enum IntegrityError {
    /// The computed checksum does not match the expected checksum.
    #[error(
        "checksum mismatch for program '{program_name}': expected {expected}, actual {actual}"
    )]
    ChecksumMismatch {
        program_name: String,
        expected: HexDigest,
        actual: HexDigest,
    },

    /// The program binary file was not found on disk.
    #[error("program file not found for '{program_name}': {path}")]
    FileNotFound { program_name: String, path: PathBuf },

    /// An I/O error occurred while reading the program binary.
    #[error("I/O error reading program '{program_name}': {error}")]
    IoError {
        program_name: String,
        error: std::io::Error,
    },
}

/// A wrapper around a 32-byte SHA-256 digest for display as hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexDigest(pub [u8; 32]);

impl fmt::Display for HexDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Validation logic
// ---------------------------------------------------------------------------

/// Validate all programs in the manifest against their expected SHA-256 checksums.
///
/// Returns `Ok(())` if every program's computed checksum matches its expected value.
/// Returns the first `IntegrityError` encountered on any mismatch or I/O failure.
///
/// # Startup sequence
///
/// 1. Load manifest (from config or embedded)
/// 2. Call `validate_program_integrity()`
/// 3. If `Ok(())`: proceed to load eBPF programs and activate the Collector
/// 4. If `Err(e)`: log the error with full details, abort startup
pub fn validate_program_integrity(manifest: &ProgramManifest) -> Result<(), IntegrityError> {
    for entry in &manifest.programs {
        validate_single_program(entry)?;
    }

    info!(
        program_count = manifest.programs.len(),
        "All eBPF programs passed integrity validation"
    );

    Ok(())
}

/// Validate a single program entry.
fn validate_single_program(entry: &ProgramEntry) -> Result<(), IntegrityError> {
    let path = &entry.path;

    // Check file existence
    if !path.exists() {
        error!(
            program = %entry.name,
            path = %path.display(),
            "eBPF program file not found"
        );
        return Err(IntegrityError::FileNotFound {
            program_name: entry.name.clone(),
            path: path.clone(),
        });
    }

    // Read file contents
    let contents = std::fs::read(path).map_err(|e| {
        error!(
            program = %entry.name,
            path = %path.display(),
            error = %e,
            "Failed to read eBPF program file"
        );
        IntegrityError::IoError {
            program_name: entry.name.clone(),
            error: e,
        }
    })?;

    // Compute SHA-256
    let actual_hash = compute_sha256(&contents);

    // Compare
    if actual_hash != entry.expected_sha256 {
        error!(
            program = %entry.name,
            expected = %HexDigest(entry.expected_sha256),
            actual = %HexDigest(actual_hash),
            "eBPF program checksum mismatch — possible tampering detected"
        );
        return Err(IntegrityError::ChecksumMismatch {
            program_name: entry.name.clone(),
            expected: HexDigest(entry.expected_sha256),
            actual: HexDigest(actual_hash),
        });
    }

    info!(
        program = %entry.name,
        checksum = %HexDigest(actual_hash),
        "Program integrity validated"
    );

    Ok(())
}

/// Compute the SHA-256 hash of the given data.
pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Helper to compute the expected SHA-256 checksum for a file on disk.
/// Useful for generating manifest entries during build or deployment.
pub fn compute_file_sha256(path: &Path) -> Result<[u8; 32], std::io::Error> {
    let contents = std::fs::read(path)?;
    Ok(compute_sha256(&contents))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Helper: create a temp file with given contents and return its path.
    fn create_temp_program(dir: &TempDir, name: &str, contents: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn test_validation_passes_with_correct_checksums() {
        let dir = TempDir::new().unwrap();
        let contents = b"valid ebpf program binary data";
        let path = create_temp_program(&dir, "collector.o", contents);
        let expected = compute_sha256(contents);

        let manifest = ProgramManifest {
            programs: vec![ProgramEntry {
                name: "tls_collector".to_string(),
                path,
                expected_sha256: expected,
            }],
        };

        let result = validate_program_integrity(&manifest);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validation_passes_with_multiple_correct_programs() {
        let dir = TempDir::new().unwrap();

        let contents_a = b"collector program bytes";
        let contents_b = b"isolate program bytes";
        let contents_c = b"protect program bytes";

        let path_a = create_temp_program(&dir, "collector.o", contents_a);
        let path_b = create_temp_program(&dir, "isolate.o", contents_b);
        let path_c = create_temp_program(&dir, "protect.o", contents_c);

        let manifest = ProgramManifest {
            programs: vec![
                ProgramEntry {
                    name: "tls_collector".to_string(),
                    path: path_a,
                    expected_sha256: compute_sha256(contents_a),
                },
                ProgramEntry {
                    name: "isolate_program".to_string(),
                    path: path_b,
                    expected_sha256: compute_sha256(contents_b),
                },
                ProgramEntry {
                    name: "protect_program".to_string(),
                    path: path_c,
                    expected_sha256: compute_sha256(contents_c),
                },
            ],
        };

        let result = validate_program_integrity(&manifest);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validation_fails_on_checksum_mismatch() {
        let dir = TempDir::new().unwrap();
        let contents = b"original program binary";
        let path = create_temp_program(&dir, "collector.o", contents);

        // Use a wrong expected checksum
        let wrong_expected = [0xAA; 32];

        let manifest = ProgramManifest {
            programs: vec![ProgramEntry {
                name: "tls_collector".to_string(),
                path,
                expected_sha256: wrong_expected,
            }],
        };

        let result = validate_program_integrity(&manifest);
        assert!(result.is_err());

        match result.unwrap_err() {
            IntegrityError::ChecksumMismatch {
                program_name,
                expected,
                actual,
            } => {
                assert_eq!(program_name, "tls_collector");
                assert_eq!(expected, HexDigest(wrong_expected));
                assert_eq!(actual, HexDigest(compute_sha256(contents)));
            }
            other => panic!("Expected ChecksumMismatch, got: {:?}", other),
        }
    }

    #[test]
    fn test_validation_fails_on_tampered_file() {
        let dir = TempDir::new().unwrap();
        let original = b"original program binary";
        let tampered = b"tampered program binary";

        // Write the tampered version but use the original's checksum
        let path = create_temp_program(&dir, "collector.o", tampered);
        let expected = compute_sha256(original);

        let manifest = ProgramManifest {
            programs: vec![ProgramEntry {
                name: "tls_collector".to_string(),
                path,
                expected_sha256: expected,
            }],
        };

        let result = validate_program_integrity(&manifest);
        assert!(result.is_err());

        match result.unwrap_err() {
            IntegrityError::ChecksumMismatch {
                expected: exp,
                actual: act,
                ..
            } => {
                assert_eq!(exp, HexDigest(compute_sha256(original)));
                assert_eq!(act, HexDigest(compute_sha256(tampered)));
            }
            other => panic!("Expected ChecksumMismatch, got: {:?}", other),
        }
    }

    #[test]
    fn test_validation_fails_on_missing_file() {
        let manifest = ProgramManifest {
            programs: vec![ProgramEntry {
                name: "missing_program".to_string(),
                path: PathBuf::from("/nonexistent/path/program.o"),
                expected_sha256: [0u8; 32],
            }],
        };

        let result = validate_program_integrity(&manifest);
        assert!(result.is_err());

        match result.unwrap_err() {
            IntegrityError::FileNotFound { program_name, path } => {
                assert_eq!(program_name, "missing_program");
                assert_eq!(path, PathBuf::from("/nonexistent/path/program.o"));
            }
            other => panic!("Expected FileNotFound, got: {:?}", other),
        }
    }

    #[test]
    fn test_empty_manifest_passes() {
        let manifest = ProgramManifest { programs: vec![] };

        let result = validate_program_integrity(&manifest);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validation_aborts_on_first_mismatch() {
        let dir = TempDir::new().unwrap();

        let contents_a = b"program A";
        let contents_b = b"program B";

        let path_a = create_temp_program(&dir, "a.o", contents_a);
        let path_b = create_temp_program(&dir, "b.o", contents_b);

        let manifest = ProgramManifest {
            programs: vec![
                ProgramEntry {
                    name: "program_a".to_string(),
                    path: path_a,
                    expected_sha256: compute_sha256(contents_a), // correct
                },
                ProgramEntry {
                    name: "program_b".to_string(),
                    path: path_b,
                    expected_sha256: [0xFF; 32], // wrong — should abort here
                },
            ],
        };

        let result = validate_program_integrity(&manifest);
        assert!(result.is_err());

        match result.unwrap_err() {
            IntegrityError::ChecksumMismatch { program_name, .. } => {
                assert_eq!(program_name, "program_b");
            }
            other => panic!("Expected ChecksumMismatch for program_b, got: {:?}", other),
        }
    }

    #[test]
    fn test_compute_sha256_deterministic() {
        let data = b"hello world";
        let hash1 = compute_sha256(data);
        let hash2 = compute_sha256(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_sha256_different_inputs() {
        let hash1 = compute_sha256(b"input A");
        let hash2 = compute_sha256(b"input B");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_file_sha256() {
        let dir = TempDir::new().unwrap();
        let contents = b"file contents for hashing";
        let path = create_temp_program(&dir, "test.bin", contents);

        let file_hash = compute_file_sha256(&path).unwrap();
        let direct_hash = compute_sha256(contents);
        assert_eq!(file_hash, direct_hash);
    }

    #[test]
    fn test_compute_file_sha256_nonexistent() {
        let result = compute_file_sha256(Path::new("/nonexistent/file.bin"));
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_digest_display() {
        let digest = HexDigest([0u8; 32]);
        let display = format!("{}", digest);
        assert_eq!(
            display,
            "0000000000000000000000000000000000000000000000000000000000000000"
        );

        let digest2 = HexDigest([0xFF; 32]);
        let display2 = format!("{}", digest2);
        assert_eq!(
            display2,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    fn test_integrity_error_display_messages() {
        let err = IntegrityError::ChecksumMismatch {
            program_name: "test_prog".to_string(),
            expected: HexDigest([0xAA; 32]),
            actual: HexDigest([0xBB; 32]),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("test_prog"));
        assert!(msg.contains("expected"));
        assert!(msg.contains("actual"));

        let err2 = IntegrityError::FileNotFound {
            program_name: "missing".to_string(),
            path: PathBuf::from("/some/path.o"),
        };
        let msg2 = format!("{}", err2);
        assert!(msg2.contains("missing"));
        assert!(msg2.contains("/some/path.o"));
    }
}
