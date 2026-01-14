//! Tests for certificate-based authentication mode.
//!
//! These tests verify that X25519 key exchange works correctly as an alternative
//! to Argon2 password-based key derivation.

use era_engine::{ArchiveWriterBuilder, EraKeyPair};
use std::fs;
use tempfile::TempDir;

/// Test that certificate mode creates an archive successfully.
#[test]
fn test_certificate_mode_creates_archive() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("test.era");
    let test_file = temp_dir.path().join("test.txt");

    // Create a test file
    fs::write(&test_file, "Hello, certificate mode!").unwrap();

    // Generate a keypair for the recipient
    let keypair = EraKeyPair::generate().unwrap();
    let cert = keypair.certificate();

    // Create archive using certificate mode
    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .certificate(cert)
        .build()
        .expect("Failed to create writer with certificate mode");

    // Verify certificate mode is active
    assert!(writer.is_certificate_mode());
    assert!(writer.key_encapsulation().is_some());

    // Add a file
    writer.add_file(&test_file).expect("Failed to add file");

    // Finalize
    writer.finalize().expect("Failed to finalize");

    // Verify archive was created
    assert!(archive_path.exists());
}

/// Test that certificate mode is significantly faster than password mode.
#[test]
fn test_certificate_mode_performance() {
    use std::time::Instant;

    let temp_dir = TempDir::new().unwrap();

    // Generate keypair
    let keypair = EraKeyPair::generate().unwrap();
    let cert = keypair.certificate();

    // Measure certificate mode
    let cert_times: Vec<_> = (0..5)
        .map(|i| {
            let archive_path = temp_dir.path().join(format!("cert_{}.era", i));
            let start = Instant::now();
            let _writer = ArchiveWriterBuilder::new(&archive_path)
                .certificate(cert.clone())
                .build()
                .unwrap();
            start.elapsed()
        })
        .collect();

    // Measure password mode (with fast KDF params to not wait forever)
    let password_times: Vec<_> = (0..5)
        .map(|i| {
            let archive_path = temp_dir.path().join(format!("pass_{}.era", i));
            let start = Instant::now();
            let _writer = ArchiveWriterBuilder::new(&archive_path)
                .password("test_password")
                .build()
                .unwrap();
            start.elapsed()
        })
        .collect();

    let cert_avg = cert_times.iter().sum::<std::time::Duration>() / cert_times.len() as u32;
    let pass_avg = password_times.iter().sum::<std::time::Duration>() / password_times.len() as u32;

    println!("Certificate mode average: {:?}", cert_avg);
    println!("Password mode average: {:?}", pass_avg);

    // Certificate mode should be at least 10x faster (typically 100-1000x)
    assert!(
        cert_avg < pass_avg / 10,
        "Certificate mode ({:?}) should be at least 10x faster than password mode ({:?})",
        cert_avg,
        pass_avg
    );
}

/// Test that key encapsulation contains valid data.
#[test]
fn test_key_encapsulation_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("test.era");
    let test_file = temp_dir.path().join("test.txt");

    // Create test file
    fs::write(&test_file, "Secret data").unwrap();

    // Generate keypair
    let keypair = EraKeyPair::generate().unwrap();
    let cert = keypair.certificate();

    // Create archive
    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .certificate(cert)
        .build()
        .unwrap();

    // Get the key encapsulation
    let encapsulation = writer
        .key_encapsulation()
        .expect("Should have key encapsulation");

    // Verify we can decapsulate the key
    let decapsulated = keypair
        .decapsulate(encapsulation)
        .expect("Should be able to decapsulate");

    // The master key should be 32 bytes
    assert_eq!(
        decapsulated.as_bytes().len(),
        32,
        "Master key should be 32 bytes"
    );

    writer.add_file(&test_file).unwrap();
    writer.finalize().unwrap();
}
