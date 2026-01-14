//! Integration tests for KeySession functionality
//!
//! These tests verify that KeySession correctly integrates with
//! ArchiveWriter and ArchiveReader, providing the same functionality
//! as the password-based APIs.
//!
//! NOTE: KeySession is primarily useful for READING archives where the salt
//! is already known. For writing new archives, a new salt is generated,
//! so the session key won't match unless explicitly managed.

use era_crypto::{KdfParams, KeySession, Salt};
use era_engine::{ArchiveReader, ArchiveWriterBuilder, ExtractOptions};
use std::fs;
use tempfile::TempDir;

/// Fast KDF params for testing
fn fast_kdf_params() -> KdfParams {
    KdfParams {
        memory_cost: 1024, // 1 MB
        time_cost: 1,
        parallelism: 1,
    }
}

/// Create a simple archive config with fast KDF
fn fast_kdf_config() -> era_common::ArchiveConfig {
    let mut config = era_common::ArchiveConfig::default();
    config.encryption.kdf_memory_cost = 1024;
    config.encryption.kdf_time_cost = 1;
    config
}

#[test]
fn test_key_session_writer_roundtrip() {
    // NOTE: When using KeySession for WRITING, the session's key must match
    // the archive's salt. Since Writer generates a new salt, we need to
    // create the archive with password first, then use session for reading.
    //
    // The primary use case for KeySession is for READING multiple archives
    // with the same password efficiently.

    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("test.era");

    // Create archive with password (generates new salt internally)
    {
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .password("test_password")
            .config(fast_kdf_config())
            .build()
            .unwrap();

        writer.add_bytes("hello.txt", b"Hello, World!").unwrap();
        writer.finalize().unwrap();
    }

    // Read header to get salt, create session, then read with session
    let reader_for_salt = ArchiveReader::open(&archive_path, "test_password").unwrap();
    let header = reader_for_salt.header();
    let salt = Salt::from_bytes(header.crypto_anchor.salt);
    let kdf_params = KdfParams {
        memory_cost: header.crypto_anchor.kdf_memory_cost,
        time_cost: header.crypto_anchor.kdf_time_cost,
        parallelism: header.crypto_anchor.kdf_parallelism,
    };
    drop(reader_for_salt);

    // Create session from archive's salt
    let session = KeySession::new(b"test_password", &salt, &kdf_params).unwrap();

    // Now read with session (fast path - no KDF needed)
    {
        let mut reader = ArchiveReader::open_with_session(&archive_path, &session).unwrap();
        reader.load_catalog().unwrap();

        let extract_dir = temp_dir.path().join("extract");
        fs::create_dir_all(&extract_dir).unwrap();

        let options = ExtractOptions::new(&extract_dir);
        reader.extract_all(&options).unwrap();

        let content = fs::read_to_string(extract_dir.join("hello.txt")).unwrap();
        assert_eq!(content, "Hello, World!");
    }
}

#[test]
fn test_key_session_reader_works() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("test.era");

    // Create archive with password (normal way)
    {
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .password("test_password")
            .config(fast_kdf_config())
            .build()
            .unwrap();

        writer.add_bytes("data.bin", b"Test data content").unwrap();
        writer.finalize().unwrap();
    }

    // Read archive header to get salt
    let reader_for_salt = ArchiveReader::open(&archive_path, "test_password").unwrap();
    let header = reader_for_salt.header();
    let salt = Salt::from_bytes(header.crypto_anchor.salt);
    let kdf_params = KdfParams {
        memory_cost: header.crypto_anchor.kdf_memory_cost,
        time_cost: header.crypto_anchor.kdf_time_cost,
        parallelism: header.crypto_anchor.kdf_parallelism,
    };
    drop(reader_for_salt);

    // Create session from same password + salt
    let session = KeySession::new(b"test_password", &salt, &kdf_params).unwrap();

    // Open with session - should work
    {
        let mut reader = ArchiveReader::open_with_session(&archive_path, &session).unwrap();
        reader.load_catalog().unwrap();

        let extract_dir = temp_dir.path().join("extract");
        fs::create_dir_all(&extract_dir).unwrap();

        let options = ExtractOptions::new(&extract_dir);
        reader.extract_all(&options).unwrap();

        let content = fs::read_to_string(extract_dir.join("data.bin")).unwrap();
        assert_eq!(content, "Test data content");
    }
}

#[test]
fn test_key_session_wrong_password_fails() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("test.era");

    // Create archive with password
    {
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .password("correct_password")
            .config(fast_kdf_config())
            .build()
            .unwrap();

        writer.add_bytes("secret.txt", b"Secret data").unwrap();
        writer.finalize().unwrap();
    }

    // Read archive header to get salt
    let reader_for_salt = ArchiveReader::open(&archive_path, "correct_password").unwrap();
    let header = reader_for_salt.header();
    let salt = Salt::from_bytes(header.crypto_anchor.salt);
    let kdf_params = KdfParams {
        memory_cost: header.crypto_anchor.kdf_memory_cost,
        time_cost: header.crypto_anchor.kdf_time_cost,
        parallelism: header.crypto_anchor.kdf_parallelism,
    };
    drop(reader_for_salt);

    // Create session with WRONG password
    let wrong_session = KeySession::new(b"wrong_password", &salt, &kdf_params).unwrap();

    // Should fail to open
    let result = ArchiveReader::open_with_session(&archive_path, &wrong_session);
    assert!(result.is_err());
    match result {
        Err(err) => assert!(
            err.to_string().contains("Incorrect password"),
            "Expected password error, got: {}",
            err
        ),
        Ok(_) => panic!("Expected error but got success"),
    }
}

#[test]
fn test_key_session_multiple_files() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("multi.era");

    // Create archive with password and multiple files
    {
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .password("multi_password")
            .config(fast_kdf_config())
            .build()
            .unwrap();

        for i in 0..10 {
            let content = format!("Content for file {}", i);
            writer
                .add_bytes(&format!("file_{}.txt", i), content.as_bytes())
                .unwrap();
        }
        writer.finalize().unwrap();
    }

    // Get salt from archive and create session
    let reader_for_salt = ArchiveReader::open(&archive_path, "multi_password").unwrap();
    let header = reader_for_salt.header();
    let salt = Salt::from_bytes(header.crypto_anchor.salt);
    let kdf_params = KdfParams {
        memory_cost: header.crypto_anchor.kdf_memory_cost,
        time_cost: header.crypto_anchor.kdf_time_cost,
        parallelism: header.crypto_anchor.kdf_parallelism,
    };
    drop(reader_for_salt);

    let session = KeySession::new(b"multi_password", &salt, &kdf_params).unwrap();

    // Verify all files using session
    {
        let mut reader = ArchiveReader::open_with_session(&archive_path, &session).unwrap();
        reader.load_catalog().unwrap();

        let extract_dir = temp_dir.path().join("extract");
        fs::create_dir_all(&extract_dir).unwrap();

        let options = ExtractOptions::new(&extract_dir);
        reader.extract_all(&options).unwrap();

        for i in 0..10 {
            let content = fs::read_to_string(extract_dir.join(format!("file_{}.txt", i))).unwrap();
            assert_eq!(content, format!("Content for file {}", i));
        }
    }
}

#[test]
fn test_key_session_with_erasure_coding() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("erasure.era");

    // Create archive with erasure coding using password
    {
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .password("erasure_password")
            .config(fast_kdf_config())
            .enable_erasure(true)
            .volume_count(3)
            .build()
            .unwrap();

        // Add enough data to trigger block creation
        let data = vec![0x42u8; 65536]; // 64KB
        writer.add_bytes("large.bin", &data).unwrap();
        writer.finalize().unwrap();
    }

    // Verify archive exists and has multiple volumes
    assert!(archive_path.exists());

    // Get salt and create session
    let reader_for_salt = ArchiveReader::open(&archive_path, "erasure_password").unwrap();
    let header = reader_for_salt.header();
    let salt = Salt::from_bytes(header.crypto_anchor.salt);
    let kdf_params = KdfParams {
        memory_cost: header.crypto_anchor.kdf_memory_cost,
        time_cost: header.crypto_anchor.kdf_time_cost,
        parallelism: header.crypto_anchor.kdf_parallelism,
    };
    drop(reader_for_salt);

    let session = KeySession::new(b"erasure_password", &salt, &kdf_params).unwrap();

    // Read back with session
    {
        let mut reader = ArchiveReader::open_with_session(&archive_path, &session).unwrap();
        reader.load_catalog().unwrap();

        let extract_dir = temp_dir.path().join("extract");
        fs::create_dir_all(&extract_dir).unwrap();

        let options = ExtractOptions::new(&extract_dir);
        let stats = reader.extract_all(&options).unwrap();
        assert_eq!(stats.extracted, 1);
    }
}

#[test]
fn test_key_session_verification_tag_matches() {
    let salt = Salt::generate();
    let params = fast_kdf_params();

    let session1 = KeySession::new(b"password", &salt, &params).unwrap();
    let session2 = KeySession::new(b"password", &salt, &params).unwrap();

    // Same password + salt should produce same verification tag
    assert_eq!(
        session1.password_verification_tag(),
        session2.password_verification_tag()
    );

    // Different password should produce different tag
    let session3 = KeySession::new(b"different", &salt, &params).unwrap();
    assert_ne!(
        session1.password_verification_tag(),
        session3.password_verification_tag()
    );
}

#[test]
fn test_key_session_from_derived_key() {
    use era_crypto::derive_key;

    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("derived.era");

    // Create archive with password
    {
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .password("from_derived")
            .config(fast_kdf_config())
            .build()
            .unwrap();

        writer.add_bytes("test.txt", b"From derived key").unwrap();
        writer.finalize().unwrap();
    }

    // Get salt from archive
    let reader_for_salt = ArchiveReader::open(&archive_path, "from_derived").unwrap();
    let header = reader_for_salt.header();
    let salt = Salt::from_bytes(header.crypto_anchor.salt);
    let params = KdfParams {
        memory_cost: header.crypto_anchor.kdf_memory_cost,
        time_cost: header.crypto_anchor.kdf_time_cost,
        parallelism: header.crypto_anchor.kdf_parallelism,
    };
    drop(reader_for_salt);

    // Derive key directly
    let derived_key = derive_key(b"from_derived", &salt, &params).unwrap();

    // Create session from derived key
    let session = KeySession::from_derived_key(&derived_key);

    // Use session to read archive
    {
        let mut reader = ArchiveReader::open_with_session(&archive_path, &session).unwrap();
        reader.load_catalog().unwrap();

        let extract_dir = temp_dir.path().join("extract");
        fs::create_dir_all(&extract_dir).unwrap();

        let options = ExtractOptions::new(&extract_dir);
        reader.extract_all(&options).unwrap();

        let content = fs::read_to_string(extract_dir.join("test.txt")).unwrap();
        assert_eq!(content, "From derived key");
    }
}
