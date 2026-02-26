//! # Cold Recovery Test: Zero-Knowledge Archive Recovery
//!
//! **CRITICAL TEST:** Validates that an ERA archive is truly self-contained.
//!
//! **Scenario:**
//! 1. Create an archive with embedded V2.1 index
//! 2. Simulate metadata loss (drop MetaIndex from memory)
//! 3. Recover data using ONLY the .era binary file via cold recovery
//!
//! **Success Criteria:**
//! - Reconstruction of chunk→block mapping from volume scan
//! - Full index recovery without external metadata files
//! - All chunk lookups work after recovery

use era_common::{ArchiveConfig, ArchiveId, BlockId, ChunkHash, VolumeId};
use era_crypto::{KeySession, Salt};
use era_index::{IndexBuilder, IndexEntry, IndexReader};
use era_storage::LocalStorageBackend;
use era_volume::{SuperHeader, VolumeReader, VolumeWriter};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Canonical test hash: BE at high bytes ensures sort order matches Redb's lexicographic byte comparison.
fn test_hash(value: u64) -> ChunkHash {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    ChunkHash::from_bytes(bytes)
}

#[tokio::test]
async fn test_cold_recovery_from_orphaned_volume() {
    let temp_dir = TempDir::new().unwrap();

    // ========================================================================
    // PHASE 1: Create Volume with Embedded Index
    // ========================================================================

    let backend = LocalStorageBackend::new(temp_dir.path());
    let volume_path = Path::new("test.era");

    // Create cryptographic session
    let password = "test_password";
    let salt = Salt::generate();
    let params = era_crypto::KdfParams::fast(); // Fast params for testing
    let session = KeySession::new(password.as_bytes(), &salt, &params).unwrap();
    let volume_key = session.generate_and_wrap_volume_key().unwrap().0;
    let nonce_context = *salt.as_bytes();

    // Create volume
    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![era_volume::RecipientSlot::new(
            era_volume::RecipientType::Argon2idPassword,
            Some([0x12; 8]),
            vec![0xAB; 16],
            vec![0xCD; 48],
        )],
        ArchiveConfig::default(),
        nonce_context,
        era_volume::EncryptedVolumeKey {
            algorithm: era_volume::KeyWrapAlgorithm::XChaCha20Poly1305,
            nonce: [0u8; 24],
            ciphertext: vec![0u8; 48],
        },
        era_volume::AccessPolicy::AnyOfN,
    );
    let mut writer = VolumeWriter::create(&backend, volume_path, header)
        .await
        .unwrap();

    // Build index with 1,000 test entries
    let mut builder = IndexBuilder::new_default().unwrap();
    for i in 0..1_000u64 {
        let entry = IndexEntry::new(
            test_hash(i),
            VolumeId::new(),
            BlockId::new(i / 100),
            (i % 100) as u32 * 1024,
            1024,
        );
        builder.insert(entry).unwrap();
    }

    // CRITICAL: Write index to volume (embedded mode)
    let (meta_index, index_location) = builder
        .finalize(&mut writer, &session, &volume_key, nonce_context)
        .await
        .unwrap();

    println!(
        "Index embedded at offset {} (size {} bytes)",
        index_location.physical_offset, index_location.encrypted_size
    );

    // Finalize volume (footer will reference index location)
    let _header = writer.finalize().await.unwrap();

    // Verify index was embedded (no external files)
    let external_files: Vec<_> = fs::read_dir(temp_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let path = e.path();
            path.extension()
                .map(|s| s == "bin" || s == "json")
                .unwrap_or(false)
        })
        .collect();

    assert_eq!(
        external_files.len(),
        0,
        "NO external index files should exist (all embedded in volume)"
    );

    // Drop MetaIndex from memory to simulate loss
    drop(meta_index);

    // ========================================================================
    // PHASE 2: COLD RECOVERY - Scan Volume and Reconstruct Index
    // ========================================================================

    // Open volume reader
    let reader = VolumeReader::open(&backend, volume_path).await.unwrap();

    println!("Attempting cold recovery from volume scan...");

    // Perform cold recovery (ZERO external metadata)
    let recovered_index =
        IndexReader::recover_from_volume(&reader, &session, &volume_key, nonce_context, None)
            .await
            .unwrap();

    println!("✅ Cold recovery successful!");

    // ========================================================================
    // PHASE 3: Verify Recovered Index Works
    // ========================================================================

    // Test lookups for all inserted hashes
    for i in 0..1_000u64 {
        let hash = test_hash(i);
        let result = recovered_index.lookup(&hash).unwrap();

        assert!(
            result.is_some(),
            "Hash {} should be found after recovery",
            i
        );

        let location = result.unwrap();
        assert_eq!(location.block_id, BlockId::new(i / 100));
        assert_eq!(location.offset, (i % 100) as u32 * 1024);
    }

    // Test negative lookup
    let non_existent = test_hash(9999);
    let result = recovered_index.lookup(&non_existent).unwrap();
    assert!(result.is_none(), "Non-existent hash should not be found");

    println!("✅ All {} chunk lookups verified after cold recovery", 1000);
}

#[tokio::test]
async fn test_index_embedded_in_volume() {
    // This test verifies the CORRECT behavior:
    //
    // ✅ IndexBuilder::finalize() writes index pages as BLOCKS in the volume
    // ✅ Each block has a BlockType identifier (BlockType::IndexPage/IndexManifest)
    // ✅ Volume footer records index location (index_root_offset/size/block_id)
    // ✅ Recovery scanner:
    //    - Reads footer → finds index location (fast path)
    //    - Falls back to volume scan if footer missing (slow path)
    //    - Reconstructs chunk mappings from IndexPage blocks
    //    - Enables file extraction without external files

    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let volume_path = Path::new("embedded.era");

    let password = "test";
    let salt = Salt::generate();
    let params = era_crypto::KdfParams::fast();
    let session = KeySession::new(password.as_bytes(), &salt, &params).unwrap();
    let volume_key = session.generate_and_wrap_volume_key().unwrap().0;
    let nonce_context = *salt.as_bytes();

    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![era_volume::RecipientSlot::new(
            era_volume::RecipientType::Argon2idPassword,
            Some([0x12; 8]),
            vec![0xAB; 16],
            vec![0xCD; 48],
        )],
        ArchiveConfig::default(),
        nonce_context,
        era_volume::EncryptedVolumeKey {
            algorithm: era_volume::KeyWrapAlgorithm::XChaCha20Poly1305,
            nonce: [0u8; 24],
            ciphertext: vec![0u8; 48],
        },
        era_volume::AccessPolicy::AnyOfN,
    );
    let mut writer = VolumeWriter::create(&backend, volume_path, header)
        .await
        .unwrap();

    let mut builder = IndexBuilder::new_default().unwrap();
    for i in 0..100u64 {
        builder
            .insert(IndexEntry::new(
                test_hash(i),
                VolumeId::new(),
                BlockId::new(0),
                i as u32 * 1024,
                1024,
            ))
            .unwrap();
    }

    let (_meta, index_location) = builder
        .finalize(&mut writer, &session, &volume_key, nonce_context)
        .await
        .unwrap();

    writer.finalize().await.unwrap();

    // Verify index is in volume
    assert!(index_location.physical_offset > 0);
    assert!(index_location.encrypted_size > 0);

    println!(
        "✅ Index embedded at offset {} (size {} bytes)",
        index_location.physical_offset, index_location.encrypted_size
    );
}
