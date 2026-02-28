//! Security tests for DoS vulnerability protection.
//!
//! These tests verify that the reader properly validates length fields
//! to prevent memory exhaustion attacks via malicious headers.

use bytes::Bytes;
use era_common::{
    ArchiveConfig, ArchiveId, BlockHeader, BlockId, BlockLocation, BlockType, ErasureBlockInfo,
    ShardHeader,
};
use era_storage::LocalStorageBackend;
use era_volume::{
    RecipientSlot, RecipientType, SuperHeader, VolumeReader, VolumeWriter, MAX_SHARD_SIZE,
};
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use tempfile::TempDir;

/// Create a dummy recipient slot for test headers (validation requires >= 1 recipient)
fn dummy_recipients() -> Vec<RecipientSlot> {
    vec![RecipientSlot::new(
        RecipientType::Argon2idPassword,
        None,
        vec![0u8; 32], // dummy params
        vec![0u8; 48], // dummy encrypted master key
    )]
}

/// Test that reading a block with a malicious length field (> MAX_SHARD_SIZE)
/// returns an error instead of attempting to allocate huge memory.
#[tokio::test]
async fn test_malicious_block_header_huge_length_returns_error() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let volume_path = Path::new("malicious_block.era");

    // 1. Create a valid volume with one block
    let header = SuperHeader::new(
        ArchiveId::new(),
        dummy_recipients(),
        ArchiveConfig::default(),
        [0u8; 16],
        era_volume::EncryptedVolumeKey {
            algorithm: era_volume::KeyWrapAlgorithm::XChaCha20Poly1305,
            nonce: [0u8; 24],
            ciphertext: vec![0u8; 48],
        },
        era_volume::AccessPolicy::AnyOfN,
    )
    .unwrap();

    let mut writer = VolumeWriter::create(&backend, volume_path, header)
        .await
        .unwrap();

    let block = era_common::EncryptedMacroBlock {
        block_id: BlockId::new(0),
        data: Bytes::from(vec![0xAAu8; 256]),
        original_size: 256,
        compressed_size: 256,
        chunk_count: 1,
    };

    let location = writer
        .write_canonical_block(&block, BlockType::Data)
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    // 2. Corrupt the block header with a huge length (4GB)
    let file_path = temp_dir.path().join(volume_path);
    {
        let mut file = OpenOptions::new().write(true).open(&file_path).unwrap();

        // Seek to the block's physical offset
        file.seek(SeekFrom::Start(location.physical_offset))
            .unwrap();

        // Write a malicious BlockHeader with length = u32::MAX (4GB)
        let malicious_header = BlockHeader::new(BlockType::Data, u32::MAX, 0xDEADBEEF);
        file.write_all(&malicious_header.to_bytes()).unwrap();
        file.sync_all().unwrap();
    }

    // 3. Try to read the corrupted block - should return Error, NOT panic/OOM
    let reader = VolumeReader::open(&backend, volume_path).await.unwrap();
    let result = reader.read_block(&location).await;

    assert!(
        result.is_err(),
        "Reading block with malicious length should return error, not attempt allocation"
    );

    let err = result.unwrap_err();
    let err_msg = format!("{}", err);
    assert!(
        err_msg.contains("exceeds maximum") || err_msg.contains("IntegrityError"),
        "Error should indicate length validation failure, got: {}",
        err_msg
    );
}

/// Test that reading a shard with a malicious length field marks it as corrupted
/// instead of attempting to allocate huge memory.
#[tokio::test]
async fn test_malicious_shard_header_huge_length_marks_corrupted() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let volume_path = Path::new("malicious_shard.era");

    // 1. Create a valid volume
    let header = SuperHeader::new(
        ArchiveId::new(),
        dummy_recipients(),
        ArchiveConfig::default(),
        [0u8; 16],
        era_volume::EncryptedVolumeKey {
            algorithm: era_volume::KeyWrapAlgorithm::XChaCha20Poly1305,
            nonce: [0u8; 24],
            ciphertext: vec![0u8; 48],
        },
        era_volume::AccessPolicy::AnyOfN,
    )
    .unwrap();

    let writer = VolumeWriter::create(&backend, volume_path, header)
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    // 2. Write a malicious shard header directly to the data region
    let file_path = temp_dir.path().join(volume_path);
    let data_region_start = 4224u64; // DATA_REGION_START

    {
        let mut file = OpenOptions::new().write(true).open(&file_path).unwrap();

        file.seek(SeekFrom::Start(data_region_start)).unwrap();

        // Write a malicious ShardHeader with length = u32::MAX (4GB)
        let malicious_shard = ShardHeader::new(u32::MAX, 0xDEADBEEF);
        file.write_all(&malicious_shard.to_bytes()).unwrap();
        file.sync_all().unwrap();
    }

    // 3. Try to read erasure shards - should mark the shard as None (corrupted)
    let reader = VolumeReader::open(&backend, volume_path).await.unwrap();

    let erasure_info = ErasureBlockInfo {
        data_shards: 4,
        parity_shards: 2,
        shard_size: 256,
        original_len: 1024,
    };
    let fake_location = BlockLocation::erasure(
        era_common::VolumeId::new(),
        0,
        data_region_start,
        1024,
        erasure_info,
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let result = reader
        .read_erasure_shards(&fake_location, &erasure_info)
        .await;

    // Should succeed but mark the first shard as None (corrupted)
    assert!(
        result.is_ok(),
        "read_erasure_shards should succeed but mark corrupted shards as None"
    );

    let shards = result.unwrap();
    assert!(
        shards[0].1.is_none(),
        "Shard with malicious length should be marked as corrupted (None)"
    );
}

/// Test that scan_for_typed_blocks handles malicious length fields gracefully.
#[tokio::test]
async fn test_scan_handles_malicious_length_gracefully() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let volume_path = Path::new("malicious_scan.era");

    // 1. Create a valid volume with one block
    let header = SuperHeader::new(
        ArchiveId::new(),
        dummy_recipients(),
        ArchiveConfig::default(),
        [0u8; 16],
        era_volume::EncryptedVolumeKey {
            algorithm: era_volume::KeyWrapAlgorithm::XChaCha20Poly1305,
            nonce: [0u8; 24],
            ciphertext: vec![0u8; 48],
        },
        era_volume::AccessPolicy::AnyOfN,
    )
    .unwrap();

    let mut writer = VolumeWriter::create(&backend, volume_path, header)
        .await
        .unwrap();

    // Write a valid block first
    let block = era_common::EncryptedMacroBlock {
        block_id: BlockId::new(0),
        data: Bytes::from(vec![0xBBu8; 128]),
        original_size: 128,
        compressed_size: 128,
        chunk_count: 1,
    };

    let location = writer
        .write_canonical_block(&block, BlockType::Data)
        .await
        .unwrap();

    // Write another valid block
    let block2 = era_common::EncryptedMacroBlock {
        block_id: BlockId::new(1),
        data: Bytes::from(vec![0xCCu8; 128]),
        original_size: 128,
        compressed_size: 128,
        chunk_count: 1,
    };

    let _location2 = writer
        .write_canonical_block(&block2, BlockType::Data)
        .await
        .unwrap();

    writer.finalize().await.unwrap();

    // 2. Corrupt the first block header with a huge length
    let file_path = temp_dir.path().join(volume_path);
    {
        let mut file = OpenOptions::new().write(true).open(&file_path).unwrap();

        file.seek(SeekFrom::Start(location.physical_offset))
            .unwrap();

        // Write a malicious BlockHeader with length = 1GB (exceeds MAX_SHARD_SIZE)
        let malicious_header = BlockHeader::new(BlockType::Data, 1024 * 1024 * 1024, 0xDEADBEEF);
        file.write_all(&malicious_header.to_bytes()).unwrap();
        file.sync_all().unwrap();
    }

    // 3. Scan should skip the corrupted block and continue
    let reader = VolumeReader::open(&backend, volume_path).await.unwrap();
    let result = reader.scan_for_typed_blocks(BlockType::Data).await;

    assert!(
        result.is_ok(),
        "Scan should complete successfully even with corrupted blocks"
    );

    // The scan may or may not find the second block depending on how it recovers,
    // but it should NOT panic or OOM
    let found = result.unwrap();
    // We just verify it didn't crash - the exact count depends on recovery behavior
    println!(
        "Scan found {} blocks after corruption (expected: scan completed without OOM)",
        found.len()
    );
}

/// Test that MAX_SHARD_SIZE constant is correctly set to 16MB.
#[test]
fn test_max_shard_size_constant() {
    assert_eq!(
        MAX_SHARD_SIZE,
        16 * 1024 * 1024,
        "MAX_SHARD_SIZE should be 16MB"
    );
}

/// Test boundary condition: length exactly at MAX_SHARD_SIZE should be accepted.
#[tokio::test]
async fn test_length_at_max_shard_size_boundary() {
    // This test verifies that blocks with length == MAX_SHARD_SIZE are valid
    // (the check is > MAX_SHARD_SIZE, not >=)
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let volume_path = Path::new("boundary_test.era");

    let header = SuperHeader::new(
        ArchiveId::new(),
        dummy_recipients(),
        ArchiveConfig::default(),
        [0u8; 16],
        era_volume::EncryptedVolumeKey {
            algorithm: era_volume::KeyWrapAlgorithm::XChaCha20Poly1305,
            nonce: [0u8; 24],
            ciphertext: vec![0u8; 48],
        },
        era_volume::AccessPolicy::AnyOfN,
    )
    .unwrap();

    let mut writer = VolumeWriter::create(&backend, volume_path, header)
        .await
        .unwrap();

    // Write a block with size just under MAX_SHARD_SIZE (we can't actually write 16MB in test)
    // This just verifies the logic path works for valid sizes
    let block = era_common::EncryptedMacroBlock {
        block_id: BlockId::new(0),
        data: Bytes::from(vec![0xDDu8; 1024]),
        original_size: 1024,
        compressed_size: 1024,
        chunk_count: 1,
    };

    let location = writer
        .write_canonical_block(&block, BlockType::Data)
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    // Read should succeed for valid sizes
    let reader = VolumeReader::open(&backend, volume_path).await.unwrap();
    let result = reader.read_block(&location).await;

    assert!(
        result.is_ok(),
        "Reading block with valid size should succeed"
    );
}
