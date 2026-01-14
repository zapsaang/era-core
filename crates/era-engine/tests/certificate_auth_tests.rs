//! Tests for certificate-based authentication mode.
//!
//! These tests verify that X25519 key exchange works correctly as an alternative
//! to Argon2 password-based key derivation.

use era_engine::{ArchiveReader, ArchiveWriterBuilder, EraKeyPair};
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

/// Test full roundtrip: create with certificate, extract with keypair
#[test]
fn test_certificate_mode_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("roundtrip.era");
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");

    fs::create_dir(&input_dir).unwrap();
    fs::create_dir(&output_dir).unwrap();

    // Create test files
    let test_file1 = input_dir.join("file1.txt");
    let test_file2 = input_dir.join("file2.txt");
    fs::write(&test_file1, b"Content of file 1").unwrap();
    fs::write(&test_file2, b"Content of file 2 - larger content here").unwrap();

    // Generate keypair
    let keypair = EraKeyPair::generate().unwrap();
    let cert = keypair.certificate();

    // Create archive
    {
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .certificate(cert)
            .build()
            .unwrap();

        writer.add_file(&test_file1).unwrap();
        writer.add_file(&test_file2).unwrap();
        writer.finalize().unwrap();
    }

    println!(
        "Archive created, size: {} bytes",
        fs::metadata(&archive_path).unwrap().len()
    );

    // Extract with keypair
    {
        let mut reader = ArchiveReader::open_with_keypair(&archive_path, &keypair)
            .expect("Failed to open archive with keypair");

        reader.load_catalog().expect("Failed to load catalog");

        let options = era_engine::ExtractOptions::new(&output_dir);
        let stats = reader.extract_all(&options).expect("Failed to extract");

        assert_eq!(stats.extracted, 2);
        assert!(stats.bytes_written > 0);
    }

    // Verify extracted files
    let extracted1 = output_dir.join("file1.txt");
    let extracted2 = output_dir.join("file2.txt");

    assert!(extracted1.exists(), "file1.txt not extracted");
    assert!(extracted2.exists(), "file2.txt not extracted");

    assert_eq!(
        fs::read(&extracted1).unwrap(),
        b"Content of file 1",
        "file1.txt content mismatch"
    );
    assert_eq!(
        fs::read(&extracted2).unwrap(),
        b"Content of file 2 - larger content here",
        "file2.txt content mismatch"
    );
}

/// Test that password-mode archive rejects keypair authentication
#[test]
fn test_password_archive_rejects_keypair() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("password.era");
    let test_file = temp_dir.path().join("test.txt");

    fs::write(&test_file, "password protected").unwrap();

    // Create with password mode
    {
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .password("test123")
            .build()
            .unwrap();

        writer.add_file(&test_file).unwrap();
        writer.finalize().unwrap();
    }

    // Try to open with keypair - should fail
    let keypair = EraKeyPair::generate().unwrap();
    let result = ArchiveReader::open_with_keypair(&archive_path, &keypair);

    assert!(
        result.is_err(),
        "Should reject keypair for password-mode archive"
    );
    let err_msg = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("Expected error"),
    };
    assert!(
        err_msg.contains("password authentication"),
        "Error should mention password authentication: {}",
        err_msg
    );
}

/// Test that wrong keypair is rejected
#[test]
fn test_wrong_keypair_rejected() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("test.era");
    let test_file = temp_dir.path().join("test.txt");

    fs::write(&test_file, "secret data").unwrap();

    // Create with one keypair
    let correct_keypair = EraKeyPair::generate().unwrap();
    let cert = correct_keypair.certificate();

    {
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .certificate(cert)
            .build()
            .unwrap();

        writer.add_file(&test_file).unwrap();
        writer.finalize().unwrap();
    }

    // Try to open with different keypair - should fail
    let wrong_keypair = EraKeyPair::generate().unwrap();
    let result = ArchiveReader::open_with_keypair(&archive_path, &wrong_keypair);

    assert!(result.is_err(), "Should reject wrong keypair");
    let err_msg = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("Expected error"),
    };
    assert!(
        err_msg.contains("Decryption error") || err_msg.contains("does not match"),
        "Error should indicate keypair mismatch: {}",
        err_msg
    );
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
