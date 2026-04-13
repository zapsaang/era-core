//! Gap coverage tests for engine features not fully exercised by existing test suites.
//!
//! These tests cover:
//! - Threshold authentication (T-of-N Shamir secret sharing)
//! - Interrupt recovery (checkpoint-based crash recovery)
//! - Hybrid KEM (X25519 + Kyber-768 post-quantum key encapsulation)
//! - Repack password change (manual extract → re-create flow)

use era_common::{ArchiveConfig, EraError};
use era_crypto::hybrid_kem::{
    decapsulate, encapsulate, generate_keypair, HybridPublicKey, HYBRID_CIPHERTEXT_SIZE,
};
use era_engine::{
    ArchiveReader, ArchiveWriterBuilder, ExtractOptions, RecoverableWriter, RecoveryManager,
    RecoveryOptions,
};
use era_volume::AccessPolicy;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

// ============================================================================
// Module 1: Threshold Auth Tests (8 tests)
// ============================================================================

mod threshold_auth_tests {
    use super::*;

    /// Test 1: 2-of-3 threshold - all pairs succeed, singles fail
    #[tokio::test]
    async fn test_threshold_2of3_all_combinations() {
        let temp = TempDir::new().unwrap();
        let input_dir = temp.path().join("input");
        fs::create_dir_all(&input_dir).unwrap();
        let archive_path = temp.path().join("threshold_2of3.era");

        // Create test file
        let test_data = b"THRESHOLD 2-OF-3 TEST DATA";
        fs::write(input_dir.join("secret.txt"), test_data).unwrap();

        // Create 2-of-3 threshold archive
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .password("alice")
            .add_password("bob")
            .add_password("carol")
            .access_policy(AccessPolicy::Threshold(2))
            .build()
            .await
            .unwrap();
        writer.add_path(&input_dir, true).await.unwrap();
        writer.finalize().await.unwrap();

        // All 3 possible pairs should succeed
        let pairs = [["alice", "bob"], ["alice", "carol"], ["bob", "carol"]];
        for passwords in &pairs {
            let mut reader = ArchiveReader::open_with_passwords(&archive_path, passwords)
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "Password pair {:?} should open threshold(2) archive",
                        passwords
                    )
                });
            let output_dir = temp.path().join(format!("output_{}", passwords[0]));
            reader
                .extract_all(&ExtractOptions::new(&output_dir))
                .await
                .unwrap();
        }

        // Each single password should fail
        for single in &["alice", "bob", "carol"] {
            let result = ArchiveReader::open(&archive_path, single).await;
            assert!(
                result.is_err(),
                "Single password '{}' must not open threshold(2) archive",
                single
            );
            match result.err().unwrap() {
                EraError::ThresholdNotMet { required, provided } => {
                    assert_eq!(required, 2);
                    assert_eq!(provided, 1);
                }
                other => panic!("Expected ThresholdNotMet, got: {:?}", other),
            }
        }
    }

    /// Test 2: 3-of-5 threshold - 2 fail, 3 succeed, 5 succeed
    #[tokio::test]
    async fn test_threshold_3of5_minimum_shares() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("threshold_3of5.era");

        let passwords = ["p1", "p2", "p3", "p4", "p5"];

        // Create 3-of-5 threshold archive
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .password(passwords[0])
            .add_password(passwords[1])
            .add_password(passwords[2])
            .add_password(passwords[3])
            .add_password(passwords[4])
            .access_policy(AccessPolicy::Threshold(3))
            .build()
            .await
            .unwrap();
        writer
            .add_bytes("data.txt", b"3-of-5 threshold test")
            .await
            .unwrap();
        writer.finalize().await.unwrap();

        // 2 passwords → fail with ThresholdNotMet(3, 2)
        let result =
            ArchiveReader::open_with_passwords(&archive_path, &[passwords[0], passwords[1]]).await;
        assert!(result.is_err());
        match result.err().unwrap() {
            EraError::ThresholdNotMet { required, provided } => {
                assert_eq!(required, 3);
                assert_eq!(provided, 2);
            }
            other => panic!("Expected ThresholdNotMet(3, 2), got: {:?}", other),
        }

        // 3 passwords → success
        let mut reader = ArchiveReader::open_with_passwords(
            &archive_path,
            &[passwords[0], passwords[1], passwords[2]],
        )
        .await
        .expect("3-of-5 should succeed with 3 passwords");
        let output_dir = temp.path().join("output_3");
        reader
            .extract_all(&ExtractOptions::new(&output_dir))
            .await
            .unwrap();

        // 5 passwords → success
        let reader = ArchiveReader::open_with_passwords(&archive_path, &passwords).await;
        assert!(
            reader.is_ok(),
            "5-of-5 should always succeed: {:?}",
            reader.err()
        );
    }

    /// Test 3: 2-of-2 exact threshold - both succeed, either alone fails
    #[tokio::test]
    async fn test_threshold_2of2_exact() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("threshold_2of2.era");

        // Create 2-of-2 threshold archive
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .password("key1")
            .add_password("key2")
            .access_policy(AccessPolicy::Threshold(2))
            .build()
            .await
            .unwrap();
        writer
            .add_bytes("exact.txt", b"2-of-2 exact threshold")
            .await
            .unwrap();
        writer.finalize().await.unwrap();

        // Both passwords → success
        let mut reader = ArchiveReader::open_with_passwords(&archive_path, &["key1", "key2"])
            .await
            .expect("Both passwords should open 2-of-2 archive");
        let output_dir = temp.path().join("output_both");
        reader
            .extract_all(&ExtractOptions::new(&output_dir))
            .await
            .unwrap();

        // Either alone → fail
        for single in &["key1", "key2"] {
            let result = ArchiveReader::open(&archive_path, single).await;
            assert!(
                result.is_err(),
                "Single password '{}' must not open 2-of-2 archive",
                single
            );
        }
    }

    /// Test 4: Threshold works with similar-but-different passwords
    #[tokio::test]
    async fn test_threshold_similar_passwords_accepted() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("similar_pwds.era");

        // Create archive with similar but distinct passwords
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .password("password123")
            .add_password("password124")
            .add_password("password125")
            .access_policy(AccessPolicy::Threshold(2))
            .build()
            .await
            .unwrap();
        writer
            .add_bytes("data.txt", b"Similar passwords test")
            .await
            .unwrap();
        writer.finalize().await.unwrap();

        // All similar passwords should work in combinations
        let mut reader =
            ArchiveReader::open_with_passwords(&archive_path, &["password123", "password124"])
                .await
                .expect("Should open with 2-of-3 similar passwords");
        let output_dir = temp.path().join("output");
        reader
            .extract_all(&ExtractOptions::new(&output_dir))
            .await
            .unwrap();
    }

    /// Test 5: All wrong passwords → ThresholdNotMet(2, 0)
    #[tokio::test]
    async fn test_threshold_wrong_passwords_zero_shares() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("wrong_pwds.era");

        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .password("real1")
            .add_password("real2")
            .access_policy(AccessPolicy::Threshold(2))
            .build()
            .await
            .unwrap();
        writer
            .add_bytes("data.txt", b"Wrong passwords test")
            .await
            .unwrap();
        writer.finalize().await.unwrap();

        // All wrong → 0 shares
        let result =
            ArchiveReader::open_with_passwords(&archive_path, &["wrong1", "wrong2", "wrong3"])
                .await;
        assert!(result.is_err());
        match result.err().unwrap() {
            EraError::ThresholdNotMet { required, provided } => {
                assert_eq!(required, 2);
                assert_eq!(provided, 0);
            }
            other => panic!("Expected ThresholdNotMet(2, 0), got: {:?}", other),
        }
    }

    /// Test 6: 1 correct + 2 wrong → ThresholdNotMet(2, 1)
    #[tokio::test]
    async fn test_threshold_mixed_correct_wrong() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("mixed_pwds.era");

        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .password("correct")
            .add_password("also_correct")
            .add_password("third")
            .access_policy(AccessPolicy::Threshold(2))
            .build()
            .await
            .unwrap();
        writer
            .add_bytes("mixed.txt", b"Mixed correct/wrong passwords")
            .await
            .unwrap();
        writer.finalize().await.unwrap();

        // 1 correct + 2 wrong → only 1 valid share
        let result =
            ArchiveReader::open_with_passwords(&archive_path, &["correct", "wrong1", "wrong2"])
                .await;
        assert!(result.is_err());
        match result.err().unwrap() {
            EraError::ThresholdNotMet { required, provided } => {
                assert_eq!(required, 2);
                assert_eq!(provided, 1);
            }
            other => panic!("Expected ThresholdNotMet(2, 1), got: {:?}", other),
        }
    }

    /// Test 7: 1MB data integrity roundtrip with threshold
    #[tokio::test]
    async fn test_threshold_data_integrity_roundtrip() {
        let temp = TempDir::new().unwrap();
        let input_dir = temp.path().join("input");
        let output_dir = temp.path().join("output");
        fs::create_dir_all(&input_dir).unwrap();
        fs::create_dir_all(&output_dir).unwrap();
        let archive_path = temp.path().join("integrity.era");

        // Create 1MB of deterministic data
        let test_data: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
        fs::write(input_dir.join("large.bin"), &test_data).unwrap();

        // Create 2-of-3 threshold archive
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .password("alpha")
            .add_password("beta")
            .add_password("gamma")
            .access_policy(AccessPolicy::Threshold(2))
            .build()
            .await
            .unwrap();
        writer.add_path(&input_dir, true).await.unwrap();
        writer.finalize().await.unwrap();

        // Extract with 2 passwords
        let mut reader = ArchiveReader::open_with_passwords(&archive_path, &["alpha", "beta"])
            .await
            .expect("Should open with 2-of-3 passwords");
        reader
            .extract_all(&ExtractOptions::new(&output_dir))
            .await
            .unwrap();

        // Verify bit-exact
        let extracted = fs::read(output_dir.join("large.bin")).unwrap();
        assert_eq!(
            extracted, test_data,
            "Extracted data must be bit-exact match of input"
        );
    }

    /// Test 8: Builder rejects Threshold(1) and Threshold(0)
    #[tokio::test]
    async fn test_threshold_rejects_threshold_1_and_0() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("reject_t1.era");

        // Threshold(0) should be rejected
        let result = ArchiveWriterBuilder::new(&archive_path)
            .password("test")
            .access_policy(AccessPolicy::Threshold(0))
            .build()
            .await;
        assert!(result.is_err(), "Writer should reject Threshold(0)");

        // Threshold(1) should be rejected
        let archive_path2 = temp.path().join("reject_t1b.era");
        let result = ArchiveWriterBuilder::new(&archive_path2)
            .password("test")
            .access_policy(AccessPolicy::Threshold(1))
            .build()
            .await;
        assert!(result.is_err(), "Writer should reject Threshold(1)");
    }
}

// ============================================================================
// Module 2: Interrupt Recovery Tests (6 tests)
// ============================================================================

mod interrupt_recovery_tests {
    use super::*;
    use era_storage::LocalStorageBackend;
    use era_volume::VolumeReader;

    /// Test 9: Drop without finalize does NOT persist checkpoint (V2.2 behavior)
    #[tokio::test]
    async fn test_interrupt_drop_without_finalize_no_checkpoint() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("drop_no_finalize.era");

        {
            let mut writer = ArchiveWriterBuilder::new(&archive_path)
                .password("test")
                .enable_checkpoint(true)
                .build()
                .await
                .unwrap();
            writer
                .add_bytes("file1.txt", b"Data before crash")
                .await
                .unwrap();
            drop(writer);
        }

        // V2.2: checkpoint is only persisted on finalize(), not on drop
        let status = RecoveryManager::analyze(&archive_path).await.unwrap();
        assert!(
            !status.checkpoint_exists,
            "V2.2: no checkpoint should exist after drop without finalize"
        );
    }

    /// Test 10: Resume fails when no checkpoint was persisted (drop without finalize)
    #[tokio::test]
    async fn test_interrupt_resume_fails_without_checkpoint() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("resume_no_cp.era");

        {
            let mut writer = ArchiveWriterBuilder::new(&archive_path)
                .password("test")
                .enable_checkpoint(true)
                .build()
                .await
                .unwrap();
            writer
                .add_bytes("file1.txt", b"Data before crash")
                .await
                .unwrap();
            drop(writer);
        }

        // Resume should fail because no checkpoint was persisted
        let resume_result = ArchiveWriterBuilder::new(&archive_path)
            .password("test")
            .enable_checkpoint(true)
            .recovery_options(RecoveryOptions::resume())
            .build()
            .await;

        assert!(
            resume_result.is_err(),
            "Resume should fail when no checkpoint exists after drop"
        );
    }

    /// Test 11: Finalize writes durable checkpoint, start_fresh clears it
    #[tokio::test]
    async fn test_interrupt_finalize_then_start_fresh_clears() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("finalize_fresh.era");

        {
            let mut writer = ArchiveWriterBuilder::new(&archive_path)
                .password("test")
                .enable_checkpoint(true)
                .build()
                .await
                .unwrap();
            writer.add_bytes("old.txt", b"Old data").await.unwrap();
            writer.finalize().await.unwrap();
        }

        let status = RecoveryManager::analyze(&archive_path).await.unwrap();
        assert!(
            status.checkpoint_exists,
            "Checkpoint should exist after finalize"
        );

        // start_fresh clears the checkpoint
        let _fresh = RecoverableWriter::new(&archive_path, RecoveryOptions::start_fresh())
            .await
            .unwrap();

        let status_after = RecoveryManager::analyze(&archive_path).await.unwrap();
        assert!(
            !status_after.checkpoint_exists,
            "Checkpoint should be cleared after start_fresh"
        );
    }

    /// Test 12: Finalize persists checkpoint with non-zero offset in footer
    #[tokio::test]
    async fn test_interrupt_checkpoint_offset_in_footer() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("cp_offset.era");

        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .password("test")
            .enable_checkpoint(true)
            .build()
            .await
            .unwrap();
        writer
            .add_bytes("data.txt", b"Checkpoint offset test")
            .await
            .unwrap();
        writer.finalize().await.unwrap();

        let backend = LocalStorageBackend::new(temp.path());
        let reader = VolumeReader::open(&backend, Path::new("cp_offset.era"))
            .await
            .unwrap();
        let footer = reader.footer().unwrap();

        assert!(
            footer.last_checkpoint_offset() > 0,
            "Checkpoint offset should be non-zero after finalize, got {}",
            footer.last_checkpoint_offset()
        );
    }

    /// Test 13: RecoveryManager correctly reports state for non-existent archive
    #[tokio::test]
    async fn test_interrupt_recovery_manager_no_archive() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("nonexistent.era");

        let status = RecoveryManager::analyze(&archive_path).await.unwrap();
        assert!(!status.checkpoint_exists);
        assert!(!status.archive_exists);
        assert!(!status.recovery_needed);
    }

    /// Test 14: Archive without checkpoint enabled has no checkpoint in footer
    #[tokio::test]
    async fn test_interrupt_no_checkpoint_when_disabled() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("no_cp.era");

        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .password("test")
            .enable_checkpoint(false)
            .build()
            .await
            .unwrap();
        writer
            .add_bytes("data.txt", b"No checkpoint data")
            .await
            .unwrap();
        writer.finalize().await.unwrap();

        let status = RecoveryManager::analyze(&archive_path).await.unwrap();
        assert!(
            !status.checkpoint_exists,
            "No checkpoint should exist when checkpoint is disabled"
        );
    }
}

// ============================================================================
// Module 3: Hybrid KEM Crypto Tests (5 tests)
// ============================================================================

mod hybrid_kem_tests {
    use super::*;

    /// Test 15: Key agreement roundtrip - encapsulate then decapsulate
    #[tokio::test]
    async fn test_hybrid_kem_roundtrip_key_agreement() {
        // Generate keypair
        let (recipient_pk, recipient_sk) = generate_keypair();

        // Encapsulate
        let (ciphertext, encap_key) =
            encapsulate(&recipient_pk).expect("Encapsulation should succeed");
        assert_eq!(
            ciphertext.len(),
            HYBRID_CIPHERTEXT_SIZE,
            "Ciphertext should be {} bytes",
            HYBRID_CIPHERTEXT_SIZE
        );

        // Decapsulate
        let decap_key = decapsulate(&recipient_sk, &recipient_pk, &ciphertext)
            .expect("Decapsulation should succeed");

        // Keys should match
        assert_eq!(
            encap_key.as_bytes(),
            decap_key.as_bytes(),
            "Encapsulated and decapsulated keys should match"
        );
    }

    /// Test 16: Wrong secret key produces different key
    #[tokio::test]
    async fn test_hybrid_kem_wrong_secret_key_fails() {
        let (recipient_pk1, _recipient_sk1) = generate_keypair();
        let (_recipient_pk2, recipient_sk2) = generate_keypair();

        // Encapsulate with pk1
        let (ciphertext, encap_key) =
            encapsulate(&recipient_pk1).expect("Encapsulation should succeed");

        // Try to decapsulate with sk2 (wrong key)
        let decap_key = decapsulate(&recipient_sk2, &recipient_pk1, &ciphertext)
            .expect("Decapsulation should succeed (returns random on wrong key)");

        // Keys should NOT match (Kyber decapsulation with wrong key produces pseudorandom)
        assert_ne!(
            encap_key.as_bytes(),
            decap_key.as_bytes(),
            "Wrong secret key should produce different shared secret"
        );
    }

    /// Test 17: Ciphertext size is exactly 1120 bytes (32 X25519 + 1088 Kyber)
    #[tokio::test]
    async fn test_hybrid_kem_ciphertext_size_1120() {
        let (recipient_pk, _recipient_sk) = generate_keypair();

        let (ciphertext, _encap_key) =
            encapsulate(&recipient_pk).expect("Encapsulation should succeed");

        assert_eq!(
            ciphertext.len(),
            HYBRID_CIPHERTEXT_SIZE,
            "Hybrid KEM ciphertext should be {} bytes (32 X25519 + 1088 Kyber)",
            HYBRID_CIPHERTEXT_SIZE
        );
        assert_eq!(HYBRID_CIPHERTEXT_SIZE, 1120);
    }

    /// Test 18: Invalid ciphertext is rejected
    #[tokio::test]
    async fn test_hybrid_kem_invalid_ciphertext_rejected() {
        let (recipient_pk, recipient_sk) = generate_keypair();

        // Too short
        let short_ct = vec![0u8; 100];
        let result = decapsulate(&recipient_sk, &recipient_pk, &short_ct);
        assert!(result.is_err(), "Too-short ciphertext should be rejected");

        // Too long
        let long_ct = vec![0u8; HYBRID_CIPHERTEXT_SIZE + 100];
        let result = decapsulate(&recipient_sk, &recipient_pk, &long_ct);
        assert!(result.is_err(), "Too-long ciphertext should be rejected");

        // Corrupted (wrong but valid length)
        let mut corrupted = vec![0u8; HYBRID_CIPHERTEXT_SIZE];
        // XOR the middle to corrupt Kyber ciphertext portion
        for byte in corrupted.iter_mut().skip(1000).take(50) {
            *byte ^= 0xFF;
        }
        // This may or may not fail depending on Kyber error handling
        // The important thing is malformed input doesn't panic
        let _ = decapsulate(&recipient_sk, &recipient_pk, &corrupted);
    }

    /// Test 19: Public key serialization roundtrip
    #[tokio::test]
    async fn test_hybrid_kem_public_key_serialization_roundtrip() {
        // Generate keypair
        let (public_key, secret_key) = generate_keypair();

        // Serialize
        let serialized = public_key.to_bytes();

        // Deserialize
        let deserialized =
            HybridPublicKey::from_bytes(&serialized).expect("Deserialization should succeed");

        // Verify X25519 component matches
        assert_eq!(
            public_key.x25519.as_bytes(),
            deserialized.x25519.as_bytes(),
            "X25519 public key should match after roundtrip"
        );

        // Verify encapsulate/decapsulate still works with deserialized key
        let (ciphertext, encap_key) =
            encapsulate(&deserialized).expect("Encapsulation should succeed");
        let decap_key = decapsulate(&secret_key, &deserialized, &ciphertext)
            .expect("Decapsulation should succeed");

        assert_eq!(
            encap_key.as_bytes(),
            decap_key.as_bytes(),
            "Roundtripped key should work for encapsulation"
        );
    }
}

// ============================================================================
// Module 4: Repack Password Change Tests (4 tests)
// ============================================================================

mod repack_password_tests {
    use super::*;

    /// Test 20: Create with "alpha", repack with "beta", extract with "beta"
    #[tokio::test]
    async fn test_repack_engine_different_passwords() {
        let temp = TempDir::new().unwrap();
        let source_path = temp.path().join("source.era");
        let new_path = temp.path().join("repacked.era");
        let extract_dir = temp.path().join("extracted");

        fs::create_dir_all(&extract_dir).unwrap();

        // Create source archive with "alpha"
        let test_data = b"Repack password change test - alpha to beta";
        {
            let mut writer = ArchiveWriterBuilder::new(&source_path)
                .password("alpha")
                .build()
                .await
                .unwrap();
            writer.add_bytes("secret.txt", test_data).await.unwrap();
            writer.finalize().await.unwrap();
        }

        // Open with old password, extract to temp
        {
            let mut reader = ArchiveReader::open(&source_path, "alpha")
                .await
                .expect("Should open with alpha");
            reader
                .extract_all(&ExtractOptions::new(&extract_dir))
                .await
                .unwrap();
        }

        // Re-create with new password "beta"
        {
            let mut writer = ArchiveWriterBuilder::new(&new_path)
                .password("beta")
                .build()
                .await
                .unwrap();
            // Add all files from extracted directory
            writer.add_path(&extract_dir, true).await.unwrap();
            writer.finalize().await.unwrap();
        }

        // Extract with new password "beta" - should succeed
        let output_beta = temp.path().join("output_beta");
        fs::create_dir_all(&output_beta).unwrap();
        {
            let mut reader = ArchiveReader::open(&new_path, "beta")
                .await
                .expect("Should open with new password beta");
            reader
                .extract_all(&ExtractOptions::new(&output_beta))
                .await
                .unwrap();
        }

        // Verify data matches
        let extracted = fs::read(output_beta.join("secret.txt")).unwrap();
        assert_eq!(extracted, test_data, "Extracted data should match original");
    }

    /// Test 21: Old password fails on new archive
    #[tokio::test]
    async fn test_repack_engine_old_password_fails_on_new() {
        let temp = TempDir::new().unwrap();
        let source_path = temp.path().join("old_pwd_fail.era");
        let new_path = temp.path().join("new_pwd_only.era");
        let extract_dir = temp.path().join("extract_old");

        fs::create_dir_all(&extract_dir).unwrap();

        // Create source archive with "alpha"
        {
            let mut writer = ArchiveWriterBuilder::new(&source_path)
                .password("alpha")
                .build()
                .await
                .unwrap();
            writer
                .add_bytes("data.txt", b"Old password test")
                .await
                .unwrap();
            writer.finalize().await.unwrap();
        }

        // Extract and repack with "beta"
        {
            let mut reader = ArchiveReader::open(&source_path, "alpha").await.unwrap();
            reader
                .extract_all(&ExtractOptions::new(&extract_dir))
                .await
                .unwrap();
        }
        {
            let mut writer = ArchiveWriterBuilder::new(&new_path)
                .password("beta")
                .build()
                .await
                .unwrap();
            writer.add_path(&extract_dir, true).await.unwrap();
            writer.finalize().await.unwrap();
        }

        // Try to open new archive with old password "alpha" - should fail
        let result = ArchiveReader::open(&new_path, "alpha").await;
        assert!(
            result.is_err(),
            "Old password 'alpha' should not open archive created with 'beta'"
        );
    }

    /// Test 22: Repack preserves all 10 files
    #[tokio::test]
    async fn test_repack_engine_preserves_all_files() {
        let temp = TempDir::new().unwrap();
        let source_path = temp.path().join("preserve_all.era");
        let new_path = temp.path().join("preserve_all_new.era");
        let extract_dir = temp.path().join("extract_preserve");

        fs::create_dir_all(&extract_dir).unwrap();

        // Create source with 10 files
        let file_count = 10;
        let test_contents: Vec<(String, Vec<u8>)> = (0..file_count)
            .map(|i| {
                (
                    format!("file{}.txt", i),
                    format!("Content of file {}", i).into_bytes(),
                )
            })
            .collect();

        {
            let mut writer = ArchiveWriterBuilder::new(&source_path)
                .password("original")
                .build()
                .await
                .unwrap();
            for (name, content) in &test_contents {
                writer.add_bytes(name, content).await.unwrap();
            }
            writer.finalize().await.unwrap();
        }

        // Extract and repack with new password
        {
            let mut reader = ArchiveReader::open(&source_path, "original").await.unwrap();
            reader
                .extract_all(&ExtractOptions::new(&extract_dir))
                .await
                .unwrap();
        }
        {
            let mut writer = ArchiveWriterBuilder::new(&new_path)
                .password("newpassword")
                .build()
                .await
                .unwrap();
            writer.add_path(&extract_dir, true).await.unwrap();
            writer.finalize().await.unwrap();
        }

        // Extract with new password and verify all files
        let output_dir = temp.path().join("output_preserve");
        fs::create_dir_all(&output_dir).unwrap();
        {
            let mut reader = ArchiveReader::open(&new_path, "newpassword").await.unwrap();
            reader
                .extract_all(&ExtractOptions::new(&output_dir))
                .await
                .unwrap();
        }

        // Verify all 10 files exist and have correct content
        for (name, expected_content) in &test_contents {
            let extracted_path = output_dir.join(name);
            assert!(
                extracted_path.exists(),
                "File {} should exist after repack",
                name
            );
            let extracted_content = fs::read(&extracted_path).unwrap();
            assert_eq!(
                extracted_content, *expected_content,
                "File {} content should match original",
                name
            );
        }
    }

    /// Test 23: Repack with different erasure coding config
    #[tokio::test]
    async fn test_repack_engine_password_change_with_erasure() {
        let temp = TempDir::new().unwrap();
        let source_path = temp.path().join("erasure_change.era");
        let new_path = temp.path().join("erasure_change_new.era");
        let extract_dir = temp.path().join("extract_erasure");

        fs::create_dir_all(&extract_dir).unwrap();

        // Create source with 4:2 erasure coding
        let config_4_2 = ArchiveConfig {
            erasure: Some(era_common::ErasureCodeConfig {
                data_shards: 4,
                parity_shards: 2,
            }),
            ..Default::default()
        };
        let test_data =
            b"Erasure coding repack test data with lots of content to ensure erasure matters";

        {
            let mut writer = ArchiveWriterBuilder::new(&source_path)
                .password("alpha")
                .config(config_4_2.clone())
                .build()
                .await
                .unwrap();
            writer
                .add_bytes("erasure_test.bin", test_data)
                .await
                .unwrap();
            writer.finalize().await.unwrap();
        }

        // Extract and repack with 6:3 erasure and new password
        {
            let mut reader = ArchiveReader::open(&source_path, "alpha").await.unwrap();
            reader
                .extract_all(&ExtractOptions::new(&extract_dir))
                .await
                .unwrap();
        }

        let config_6_3 = ArchiveConfig {
            erasure: Some(era_common::ErasureCodeConfig {
                data_shards: 6,
                parity_shards: 3,
            }),
            ..Default::default()
        };
        {
            let mut writer = ArchiveWriterBuilder::new(&new_path)
                .password("beta")
                .config(config_6_3)
                .build()
                .await
                .unwrap();
            writer.add_path(&extract_dir, true).await.unwrap();
            writer.finalize().await.unwrap();
        }

        // Verify opens with new password and data is correct
        let output_dir = temp.path().join("output_erasure");
        fs::create_dir_all(&output_dir).unwrap();
        {
            let mut reader = ArchiveReader::open(&new_path, "beta").await.unwrap();
            reader
                .extract_all(&ExtractOptions::new(&output_dir))
                .await
                .unwrap();
        }

        let extracted = fs::read(output_dir.join("erasure_test.bin")).unwrap();
        assert_eq!(
            extracted, test_data,
            "Data should be preserved after erasure config change and password change"
        );

        // Verify old password still works on source
        let old_reader = ArchiveReader::open(&source_path, "alpha").await;
        assert!(
            old_reader.is_ok(),
            "Original archive should still be accessible with original password"
        );
    }
}
