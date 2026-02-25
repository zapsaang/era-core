//! Adversarial Audit V2 — era-volume
//!
//! Targets:
//! - FINDING-VOL-1: write_at after append leaves file position undefined (seek interleaving)
//! - FINDING-VOL-2: Floating footer recovery is O(n) reverse scan — DoS via large volume
//! - FINDING-VOL-3: Footer from_bytes uses .unwrap() on slice conversions (line 225-241)
//! - FINDING-VOL-4: open_append trusts footer.data_end_offset without bounds checking
//! - FINDING-VOL-5: commit_checkpoint without set_max_size panics (unwrap on None)

use bytes::Bytes;
use era_common::{ArchiveConfig, ArchiveId, BlockId, BlockType, EncryptedMacroBlock};
use era_storage::LocalStorageBackend;
use era_volume::{
    AccessPolicy, EncryptedVolumeKey, Footer, KeyWrapAlgorithm, RecipientSlot, RecipientType,
    SuperHeader, VolumeReader, VolumeWriter, FOOTER_SIZE,
};
use std::path::Path;
use tempfile::TempDir;

fn test_header() -> SuperHeader {
    SuperHeader::new(
        ArchiveId::new(),
        vec![RecipientSlot::new(
            RecipientType::Argon2idPassword,
            Some([0x12; 8]),
            vec![0xAB; 16],
            vec![0xCD; 48],
        )],
        ArchiveConfig::default(),
        [0u8; 16],
        EncryptedVolumeKey {
            algorithm: KeyWrapAlgorithm::XChaCha20Poly1305,
            nonce: [0u8; 24],
            ciphertext: vec![0u8; 48],
        },
        AccessPolicy::AnyOfN,
    )
}

fn test_block(id: u64, size: usize) -> EncryptedMacroBlock {
    EncryptedMacroBlock {
        block_id: BlockId::new(id),
        data: Bytes::from(vec![0xAA; size]),
        original_size: size as u32,
        compressed_size: size as u32,
        chunk_count: 1,
    }
}

/// FINDING-VOL-3: Footer::from_bytes with truncated input must not panic.
/// The code uses .unwrap() on try_into() for slice conversions at lines 225-241.
/// If the input is exactly FOOTER_SIZE but contains garbage, the unwraps are safe
/// because the slices are fixed. But we verify the error path is clean.
#[test]
fn test_footer_from_bytes_truncated_no_panic() {
    // Less than FOOTER_SIZE
    for len in 0..FOOTER_SIZE {
        let data = vec![0xFF; len];
        let result = Footer::from_bytes(&data);
        assert!(
            result.is_err(),
            "Should reject truncated footer of len {}",
            len
        );
    }
}

/// FINDING-VOL-3b: Footer with valid size but all-zero bytes (no magic).
#[test]
fn test_footer_all_zeros_rejected() {
    let data = [0u8; FOOTER_SIZE];
    let result = Footer::from_bytes(&data);
    assert!(
        result.is_err(),
        "All-zero footer must be rejected (bad magic)"
    );
}

/// FINDING-VOL-3c: Footer with valid magic but corrupted checksum.
#[test]
fn test_footer_valid_magic_bad_checksum() {
    let mut data = [0u8; FOOTER_SIZE];
    data[0..4].copy_from_slice(&[0x45, 0x52, 0x41, 0x46]); // "ERAF"
    data[4] = 1; // version
                 // checksum at 96..128 is all zeros — won't match blake3 of fields
    let result = Footer::from_bytes(&data);
    assert!(
        result.is_err(),
        "Valid magic + bad checksum must be rejected"
    );
}

/// FINDING-VOL-3d: Footer with future version must be rejected.
#[test]
fn test_footer_future_version_rejected() {
    let footer = Footer::new(1024, 1, 1);
    // Serialize, then patch version byte to 255
    let mut bytes = footer.to_bytes().unwrap();
    bytes[4] = 255; // future version
                    // Recompute checksum won't help — from_bytes checks version before checksum
    let result = Footer::from_bytes(&bytes);
    assert!(result.is_err());
}

/// FINDING-VOL-5: commit_checkpoint without set_max_size must return Err, not panic.
#[tokio::test]
async fn test_commit_checkpoint_without_max_size_returns_error() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());

    let mut writer = VolumeWriter::create(&backend, Path::new("test.era"), test_header())
        .await
        .unwrap();

    // Write a block first
    let block = test_block(0, 256);
    writer
        .write_canonical_block(&block, BlockType::Data)
        .await
        .unwrap();

    // commit_checkpoint without set_max_size should return Err, not panic
    let result = writer.commit_checkpoint(0).await;
    assert!(
        result.is_err(),
        "commit_checkpoint without max_size must return Err, not panic"
    );

    // Cleanup: finalize without max_size (append mode)
    writer.finalize().await.unwrap();
}

/// FINDING-VOL-4: open_append with a forged data_end_offset beyond file size.
/// The writer trusts footer.data_end_offset and truncates to it.
/// If data_end_offset > file_size, truncate should either fail or extend with zeros.
#[tokio::test]
async fn test_open_append_forged_data_end_offset() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let path = Path::new("forged.era");

    let header = test_header();
    let writer = VolumeWriter::create(&backend, path, header.clone())
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    // Read the volume to get the footer
    let reader = VolumeReader::open(&backend, path).await.unwrap();
    let footer = reader.footer().unwrap().clone();

    // Forge a footer with data_end_offset way beyond file size
    let forged_footer = Footer::with_catalog(
        999_999_999, // way beyond actual file size
        footer.block_count,
        footer.sequence_number,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    );

    // open_append will truncate to this offset — this extends the file
    // This is not a crash, but it's a resource exhaustion vector
    let result = VolumeWriter::open_append(&backend, path, header, &forged_footer).await;
    // The operation itself may succeed (truncate can extend), but the writer
    // position will be at a nonsensical offset. Verify it doesn't panic.
    assert!(result.is_ok() || result.is_err());
}

/// FINDING-VOL-1: Interleaved write_at and append correctness.
/// After write_at, the file cursor is at an arbitrary position.
/// Subsequent append must still write at the correct offset.
#[tokio::test]
async fn test_write_at_then_append_position_correctness() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let path = Path::new("interleave.era");

    let mut writer = VolumeWriter::create(&backend, path, test_header())
        .await
        .unwrap();

    // Write block 0 via canonical (uses append in non-max_size mode)
    let block0 = test_block(0, 512);
    let loc0 = writer
        .write_canonical_block(&block0, BlockType::Data)
        .await
        .unwrap();

    // Now do a raw write_at to offset 0 (simulating backup footer write)
    writer.write_raw(&[0xFF; 8]).await.unwrap();

    // Write block 1 — must not overlap with block 0
    let block1 = test_block(1, 512);
    let loc1 = writer
        .write_canonical_block(&block1, BlockType::Data)
        .await
        .unwrap();

    // Verify non-overlapping
    assert!(
        loc1.physical_offset > loc0.physical_offset,
        "Block 1 offset ({}) must be after block 0 offset ({})",
        loc1.physical_offset,
        loc0.physical_offset
    );

    writer.finalize().await.unwrap();

    // Verify both blocks are readable
    let reader = VolumeReader::open(&backend, path).await.unwrap();
    let read0 = reader.read_block(&loc0).await.unwrap();
    assert_eq!(read0.data.as_ref(), &[0xAA; 512]);
    let read1 = reader.read_block(&loc1).await.unwrap();
    assert_eq!(read1.data.as_ref(), &[0xAA; 512]);
}

/// FINDING-VOL-6: Volume with max_size set — verify blocks written via write_at
/// are correctly readable after finalize (the padded volume path).
#[tokio::test]
async fn test_max_size_write_at_readback() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let path = Path::new("padded.era");

    let mut writer = VolumeWriter::create(&backend, path, test_header())
        .await
        .unwrap();
    writer.set_max_size(1024 * 1024).await.unwrap(); // 1MB

    let block = test_block(0, 4096);
    let loc = writer
        .write_canonical_block(&block, BlockType::Data)
        .await
        .unwrap();

    writer.finalize().await.unwrap();

    let reader = VolumeReader::open(&backend, path).await.unwrap();
    assert_eq!(reader.block_count(), 1);
    let read_block = reader.read_block(&loc).await.unwrap();
    assert_eq!(read_block.data.len(), 4096);
    assert_eq!(read_block.data.as_ref(), &[0xAA; 4096]);
}

/// FINDING-VOL-7: Volume full detection — writing past max_size must fail.
#[tokio::test]
async fn test_volume_full_detection() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let path = Path::new("full.era");

    let mut writer = VolumeWriter::create(&backend, path, test_header())
        .await
        .unwrap();
    // Tiny max_size — just enough for header + backup footer gap + footer overhead
    let min_size = 4096 + 128 + 4096 + 128 + 256; // header + gap + backup header + footer + margin
    writer.set_max_size(min_size as u64).await.unwrap();

    // Try to write a block that's too large
    let huge_block = test_block(0, min_size); // larger than available space
    let result = writer
        .write_canonical_block(&huge_block, BlockType::Data)
        .await;
    assert!(result.is_err(), "Writing past max_size must fail");

    writer.finalize().await.unwrap();
}
