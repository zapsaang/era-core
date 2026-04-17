//! Tests for certificate-based authentication mode.
//!
//! These tests verify that X25519 key exchange works correctly as an alternative
//! to Argon2 password-based key derivation.

use era_common::ArchiveConfig;
use era_common::EraError;
use era_engine::auth::{AuthProvider, CertificateProvider};
use era_engine::{ArchiveReader, ArchiveWriterBuilder, EraKeyPair};
use era_volume::{RecipientSlot, RecipientType};
use std::fs;
use tempfile::TempDir;

/// Helper: Create a config with EC disabled for single-volume tests
fn test_config_no_ec() -> ArchiveConfig {
    ArchiveConfig {
        erasure: None,
        ..Default::default()
    }
}

/// Test that certificate mode creates an archive successfully.
#[tokio::test]
async fn test_certificate_mode_creates_archive() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("test.era");
    let test_file = temp_dir.path().join("test.txt");

    // Create a test file
    fs::write(&test_file, "Hello, certificate mode!").unwrap();

    // Generate a keypair for the recipient
    let keypair = EraKeyPair::generate().unwrap();
    let cert = keypair.certificate();

    // Create archive using certificate mode (EC disabled for single-volume test)
    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .certificate(cert)
        .config(test_config_no_ec())
        .build()
        .await
        .expect("Failed to create writer with certificate mode");

    // Verify certificate mode is active
    assert!(writer.is_certificate_mode());
    assert!(writer.key_encapsulation().is_some());

    // Add a file
    writer
        .add_file(&test_file)
        .await
        .expect("Failed to add file");

    // Finalize
    writer.finalize().await.expect("Failed to finalize");

    // Verify archive was created
    assert!(archive_path.exists());
}

/// Test full roundtrip: create with certificate, extract with keypair
#[tokio::test]
async fn test_certificate_mode_roundtrip() {
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

    // Create archive (EC disabled for single-volume test)
    {
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .certificate(cert)
            .config(test_config_no_ec())
            .build()
            .await
            .unwrap();

        writer.add_file(&test_file1).await.unwrap();
        writer.add_file(&test_file2).await.unwrap();
        writer.finalize().await.unwrap();
    }

    println!(
        "Archive created, size: {} bytes",
        fs::metadata(&archive_path).unwrap().len()
    );

    // Extract with keypair
    {
        let mut reader = ArchiveReader::open_with_keypair(&archive_path, &keypair)
            .await
            .expect("Failed to open archive with keypair");

        reader.load_catalog().await.expect("Failed to load catalog");

        let options = era_engine::ExtractOptions::new(&output_dir);
        let stats = reader
            .extract_all(&options)
            .await
            .expect("Failed to extract");

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
#[tokio::test]
async fn test_password_archive_rejects_keypair() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("password.era");
    let test_file = temp_dir.path().join("test.txt");

    fs::write(&test_file, "password protected").unwrap();

    // Create with password mode (EC disabled for single-volume test)
    {
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .password("test123")
            .config(test_config_no_ec())
            .build()
            .await
            .unwrap();

        writer.add_file(&test_file).await.unwrap();
        writer.finalize().await.unwrap();
    }

    // Try to open with keypair - should fail
    let keypair = EraKeyPair::generate().unwrap();
    let result = ArchiveReader::open_with_keypair(&archive_path, &keypair).await;

    assert!(
        result.is_err(),
        "Should reject keypair for password-mode archive"
    );
    let err_msg = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("Expected error"),
    };
    assert!(
        err_msg.contains("password authentication")
            || err_msg.contains("No valid credentials found"),
        "Error should mention password authentication or no creds: {}",
        err_msg
    );
}

/// Test that wrong keypair is rejected
#[tokio::test]
async fn test_wrong_keypair_rejected() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("test.era");
    let test_file = temp_dir.path().join("test.txt");

    fs::write(&test_file, "secret data").unwrap();

    // Create with one keypair (EC disabled for single-volume test)
    let correct_keypair = EraKeyPair::generate().unwrap();
    let cert = correct_keypair.certificate();

    {
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .certificate(cert)
            .config(test_config_no_ec())
            .build()
            .await
            .unwrap();

        writer.add_file(&test_file).await.unwrap();
        writer.finalize().await.unwrap();
    }

    // Try to open with different keypair - should fail
    let wrong_keypair = EraKeyPair::generate().unwrap();
    let result = ArchiveReader::open_with_keypair(&archive_path, &wrong_keypair).await;

    assert!(result.is_err(), "Should reject wrong keypair");
    let err_msg = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("Expected error"),
    };
    assert!(
        err_msg.contains("Decryption error")
            || err_msg.contains("does not match")
            || err_msg.contains("No valid credentials found"),
        "Error should indicate keypair mismatch or no creds: {}",
        err_msg
    );
}

#[test]
fn test_certificate_provider_wrong_key_decapsulation_returns_none() {
    let correct_keypair = EraKeyPair::generate().unwrap();
    let wrong_keypair = EraKeyPair::generate().unwrap();
    let provider = CertificateProvider::new(wrong_keypair);

    let encapsulation =
        EraKeyPair::encapsulate_for(&correct_keypair.certificate(), &[0x55; 32]).unwrap();
    let slot = RecipientSlot::new(
        RecipientType::X25519PubKey,
        None,
        encapsulation.ephemeral_public.to_vec(),
        encapsulation.encrypted_master_key,
    );

    let unlocked = provider.try_unlock(&slot).unwrap();
    assert!(
        unlocked.is_none(),
        "wrong-key decapsulation should short-circuit to Ok(None)"
    );
}

#[test]
fn test_certificate_provider_malformed_params_error_is_not_swallowed() {
    let keypair = EraKeyPair::generate().unwrap();
    let provider = CertificateProvider::new(keypair.clone());

    let mut slot_kid = [0u8; 8];
    slot_kid.copy_from_slice(&keypair.key_id()[..8]);

    let slot = RecipientSlot::new(
        RecipientType::X25519PubKey,
        Some(slot_kid),
        vec![0xAA; 31],
        vec![0xBB; 48],
    );

    let result = provider.try_unlock(&slot);
    match result {
        Err(EraError::InvalidKey(msg)) => {
            assert!(msg.contains("Invalid ephemeral public"));
        }
        other => panic!(
            "expected InvalidKey for malformed slot params, got: {:?}",
            other
        ),
    }
}

/// Test that certificate mode is significantly faster than password mode.
#[tokio::test]
async fn test_certificate_mode_performance() {
    use std::time::Instant;

    let temp_dir = TempDir::new().unwrap();

    // Generate keypair
    let keypair = EraKeyPair::generate().unwrap();
    let cert = keypair.certificate();

    // Measure certificate mode (EC disabled for single-volume test)
    let mut cert_times = Vec::new();
    for i in 0..5 {
        let archive_path = temp_dir.path().join(format!("cert_{}.era", i));
        let start = Instant::now();
        let _writer = ArchiveWriterBuilder::new(&archive_path)
            .certificate(cert.clone())
            .config(test_config_no_ec())
            .build()
            .await
            .unwrap();
        cert_times.push(start.elapsed());
    }

    // Measure password mode (with fast KDF params to not wait forever) (EC disabled for single-volume test)
    let mut password_times = Vec::new();
    for i in 0..5 {
        let archive_path = temp_dir.path().join(format!("pass_{}.era", i));
        let start = Instant::now();
        let _writer = ArchiveWriterBuilder::new(&archive_path)
            .password("test_password")
            .config(test_config_no_ec())
            .build()
            .await
            .unwrap();
        password_times.push(start.elapsed());
    }

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
#[tokio::test]
async fn test_key_encapsulation_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("test.era");
    let test_file = temp_dir.path().join("test.txt");

    // Create test file
    fs::write(&test_file, "Secret data").unwrap();

    // Generate keypair
    let keypair = EraKeyPair::generate().unwrap();
    let cert = keypair.certificate();

    // Create archive (EC disabled for single-volume test)
    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .certificate(cert)
        .config(test_config_no_ec())
        .build()
        .await
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

    writer.add_file(&test_file).await.unwrap();
    writer.finalize().await.unwrap();
}

/// Test full roundtrip with hybrid KEM certificate mode.
#[tokio::test]
async fn test_hybrid_kem_certificate_mode_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("hybrid.era");
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");

    fs::create_dir(&input_dir).unwrap();
    fs::create_dir(&output_dir).unwrap();

    let test_file = input_dir.join("file.txt");
    fs::write(&test_file, b"Hybrid PQ content").unwrap();

    let keypair = era_engine::HybridKeyPair::generate();
    let cert = keypair.certificate();

    // Create archive with hybrid certificate
    {
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .hybrid_certificate(cert)
            .config(test_config_no_ec())
            .build()
            .await
            .unwrap();

        writer.add_file(&test_file).await.unwrap();
        writer.finalize().await.unwrap();
    }

    // Extract with hybrid keypair
    {
        let mut reader = ArchiveReader::open_with_hybrid_keypair(&archive_path, &keypair)
            .await
            .expect("Failed to open hybrid archive");

        reader.load_catalog().await.unwrap();
        let options = era_engine::ExtractOptions::new(&output_dir);
        let stats = reader.extract_all(&options).await.unwrap();
        assert_eq!(stats.extracted, 1);
    }

    let extracted = output_dir.join("file.txt");
    assert!(extracted.exists());
    assert_eq!(fs::read(&extracted).unwrap(), b"Hybrid PQ content");
}

/// Test that hybrid provider returns None for wrong key.
#[test]
fn test_hybrid_provider_wrong_key_returns_none() {
    use era_engine::auth::{AuthProvider, HybridCertificateProvider};
    use era_volume::RecipientSlot;

    let keypair1 = era_engine::HybridKeyPair::generate();
    let cert1 = keypair1.certificate();
    let keypair2 = era_engine::HybridKeyPair::generate();

    let master_key = [0xABu8; 32];
    let (params, encrypted_mk) =
        era_engine::HybridKeyPair::encapsulate_for(&cert1, &master_key).unwrap();

    let slot = RecipientSlot::new(RecipientType::HybridKem, None, params, encrypted_mk);

    let provider = HybridCertificateProvider::new(keypair2);
    let result = provider.try_unlock(&slot);
    assert!(
        result.is_err() || result.unwrap().is_none(),
        "Wrong hybrid key should fail to unlock"
    );
}

/// Test that legacy X25519 archives still open after hybrid support lands.
#[tokio::test]
async fn test_legacy_x25519_archive_still_opens_after_hybrid_support() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("legacy.era");
    let output_dir = temp_dir.path().join("output");
    fs::create_dir(&output_dir).unwrap();

    let test_file = temp_dir.path().join("legacy.txt");
    fs::write(&test_file, b"Legacy content").unwrap();

    let keypair = EraKeyPair::generate().unwrap();
    let cert = keypair.certificate();

    {
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .certificate(cert)
            .config(test_config_no_ec())
            .build()
            .await
            .unwrap();
        writer.add_file(&test_file).await.unwrap();
        writer.finalize().await.unwrap();
    }

    let mut reader = ArchiveReader::open_with_keypair(&archive_path, &keypair)
        .await
        .unwrap();
    reader.load_catalog().await.unwrap();
    let options = era_engine::ExtractOptions::new(&output_dir);
    let stats = reader.extract_all(&options).await.unwrap();
    assert_eq!(stats.extracted, 1);
    assert_eq!(
        fs::read(output_dir.join("legacy.txt")).unwrap(),
        b"Legacy content"
    );
}

/// Test that repair with private key unlocks hybrid archive.
#[tokio::test]
async fn test_repair_archive_with_private_key_unlocks_hybrid_archive() {
    // Skip if no erasure coding (repair requires EC)
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("hybrid_ec.era");

    let kp = era_engine::HybridKeyPair::generate();
    let cert = kp.certificate();

    let mut config = test_config_no_ec();
    config.erasure = Some(era_common::ErasureCodeConfig {
        data_shards: 2,
        parity_shards: 1,
    });

    {
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .hybrid_certificate(cert)
            .config(config)
            .build()
            .await
            .unwrap();
        let test_file = temp_dir.path().join("data.txt");
        fs::write(&test_file, b"repair me").unwrap();
        writer.add_file(&test_file).await.unwrap();
        writer.finalize().await.unwrap();
    }

    let keypairs = vec![era_crypto::EitherKeyPair::Hybrid(Box::new(kp))];
    let options = era_engine::RepairOptions::default();
    let result =
        era_engine::repair_archive_with_private_keys(&archive_path, &keypairs, options).await;
    assert!(
        result.is_ok(),
        "Hybrid key repair should succeed: {:?}",
        result
    );
}

/// Test that repack with private keys preserves hybrid access.
#[tokio::test]
async fn test_repack_archive_with_private_keys_preserves_hybrid_access() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("hybrid_src.era");
    let repacked_path = temp_dir.path().join("hybrid_repacked.era");
    let output_dir = temp_dir.path().join("output");
    fs::create_dir(&output_dir).unwrap();

    let kp = era_engine::HybridKeyPair::generate();

    {
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .hybrid_certificate(kp.certificate())
            .config(test_config_no_ec())
            .build()
            .await
            .unwrap();
        let test_file = temp_dir.path().join("data.txt");
        fs::write(&test_file, b"repack me").unwrap();
        writer.add_file(&test_file).await.unwrap();
        writer.finalize().await.unwrap();
    }

    let keypairs = vec![era_crypto::EitherKeyPair::Hybrid(Box::new(kp.clone()))];
    let result = era_engine::repack_archive_with_private_keys(
        &archive_path,
        &repacked_path,
        &keypairs,
        test_config_no_ec(),
    )
    .await;
    assert!(
        result.is_ok(),
        "Repack with hybrid key should succeed: {:?}",
        result
    );

    let mut reader = ArchiveReader::open_with_hybrid_keypair(&repacked_path, &kp)
        .await
        .unwrap();
    reader.load_catalog().await.unwrap();
    let stats = reader
        .extract_all(&era_engine::ExtractOptions::new(&output_dir))
        .await
        .unwrap();
    assert_eq!(stats.extracted, 1);
    assert_eq!(fs::read(output_dir.join("data.txt")).unwrap(), b"repack me");
}

/// Test that repack with private keys preserves threshold hybrid certificate access.
#[tokio::test]
async fn test_repack_archive_with_private_keys_preserves_threshold_hybrid_access() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("hybrid_thresh_src.era");
    let repacked_path = temp_dir.path().join("hybrid_thresh_repacked.era");
    let output_dir = temp_dir.path().join("output");
    fs::create_dir(&output_dir).unwrap();

    let kp1 = era_engine::HybridKeyPair::generate();
    let kp2 = era_engine::HybridKeyPair::generate();

    {
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .hybrid_certificate(kp1.certificate())
            .add_hybrid_certificate(kp2.certificate())
            .access_policy(era_volume::AccessPolicy::Threshold(2))
            .config(test_config_no_ec())
            .build()
            .await
            .unwrap();
        let test_file = temp_dir.path().join("data.txt");
        fs::write(&test_file, b"repack threshold hybrid").unwrap();
        writer.add_file(&test_file).await.unwrap();
        writer.finalize().await.unwrap();
    }

    let keypairs = vec![
        era_crypto::EitherKeyPair::Hybrid(Box::new(kp1.clone())),
        era_crypto::EitherKeyPair::Hybrid(Box::new(kp2.clone())),
    ];
    let result = era_engine::repack_archive_with_private_keys(
        &archive_path,
        &repacked_path,
        &keypairs,
        test_config_no_ec(),
    )
    .await;
    assert!(
        result.is_ok(),
        "Repack with threshold hybrid keys should succeed: {:?}",
        result
    );

    let providers: Vec<Box<dyn era_engine::auth::AuthProvider>> = vec![
        Box::new(era_engine::auth::HybridCertificateProvider::new(
            kp1.clone(),
        )),
        Box::new(era_engine::auth::HybridCertificateProvider::new(
            kp2.clone(),
        )),
    ];
    let mut reader = ArchiveReader::open_with_providers(&repacked_path, providers)
        .await
        .unwrap();
    reader.load_catalog().await.unwrap();
    let stats = reader
        .extract_all(&era_engine::ExtractOptions::new(&output_dir))
        .await
        .unwrap();
    assert_eq!(stats.extracted, 1);
    assert_eq!(
        fs::read(output_dir.join("data.txt")).unwrap(),
        b"repack threshold hybrid"
    );
}
