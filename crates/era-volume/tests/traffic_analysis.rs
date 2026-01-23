use bytes::Bytes;
use era_common::{ArchiveConfig, ArchiveId, BlockId};
use era_storage::LocalStorageBackend;
use era_volume::{SuperHeader, VolumeWriter};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn test_volume_traffic_fingerprint_padding() {
    // 1. Setup
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let volume_path = Path::new("traffic_test.era");

    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![],
        ArchiveConfig::default(),
        [0u8; 16],
    );

    // 2. Create Writer
    let mut writer = VolumeWriter::create(&backend, volume_path, header).unwrap();

    // Set a fixed max size (e.g., 1MB)
    let max_size = 1024 * 1024; // 1MB
    writer.set_max_size(max_size).unwrap();

    // 3. Write a small amount of data (much less than 1MB)
    let block = era_common::EncryptedMacroBlock {
        block_id: BlockId::new(0),
        data: Bytes::from(vec![0xAAu8; 1024]), // 1KB data
        original_size: 1024,
        compressed_size: 1024,
        chunk_count: 1,
    };
    writer
        .write_canonical_block(&block, era_common::BlockType::Data)
        .unwrap();

    // 4. Finalize
    writer.finalize().unwrap();

    // 5. Verify File Size
    let file_path = temp_dir.path().join(volume_path);
    let metadata = fs::metadata(&file_path).unwrap();

    // Assertion 1: File size matches max_size exactly
    assert_eq!(
        metadata.len(),
        max_size,
        "Extension prevents traffic analysis: Volume size {} should match max_size {}",
        metadata.len(),
        max_size
    );

    // 6. Verify Entropy (Padding should not be zero)
    let content = fs::read(&file_path).unwrap();
    // Check the area after the written block and before the footer
    // Header is approx ~100 bytes (variable with protobuf now, but small)
    // Block is 1024 bytes + 4 bytes(len)
    // Footer is fixed size at end

    // Let's sample the middle of the file suitable for padding
    let sample_start = 5000;
    let sample_end = (max_size - 1000) as usize;
    let sample = &content[sample_start..sample_end];

    let non_zero_count = sample.iter().filter(|&&b| b != 0).count();
    // Allow for some zeros, but it should be high entropy.
    // If it was zero-padded, this would be 0.
    assert!(
        non_zero_count > 0,
        "Padding traffic analysis defense: Padding area should contain random data, found all zeros"
    );

    // A crude entropy check: approx 50% bits set, or at least many bytes are non-zero.
    // For 1MB of random data, seeing ALL zeros is impossible.
    // Seeing > 90% zeros is also highly unlikely unless RNG is broken.
    let zero_ratio = (sample.len() - non_zero_count) as f64 / sample.len() as f64;
    assert!(
        zero_ratio < 0.9,
        "Padding traffic analysis defense: Padding looks suspicious (too many zeros: {:.2}%)",
        zero_ratio * 100.0
    );
}

#[test]
fn test_checkpoint_traffic_safety() {
    // 1. Setup
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let volume_path = Path::new("checkpoint_traffic.era");

    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![],
        ArchiveConfig::default(),
        [0u8; 16],
    );

    // 2. Create Writer & Set Max Size
    let mut writer = VolumeWriter::create(&backend, volume_path, header).unwrap();
    let max_size = 1024 * 1024; // 1MB
    writer.set_max_size(max_size).unwrap();

    // 3. Write Data
    let block = era_common::EncryptedMacroBlock {
        block_id: BlockId::new(1),
        data: Bytes::from(vec![0xBBu8; 1024]),
        original_size: 1024,
        compressed_size: 1024,
        chunk_count: 1,
    };
    writer
        .write_canonical_block(&block, era_common::BlockType::Data)
        .unwrap();

    // 4. Commit Checkpoint (mid-stream)
    // This should trigger padding to max_size if we are to prevent traffic analysis
    // during upload of this snapshot.
    writer.commit_checkpoint(12345).unwrap();

    // 5. Verify File Size & Entropy
    let file_path = temp_dir.path().join(volume_path);
    let metadata = fs::metadata(&file_path).unwrap();

    assert_eq!(
        metadata.len(),
        max_size,
        "Checkpoint should ensure volume is fully padded to max_size to hide actual usage. Found: {}",
        metadata.len()
    );

    let content = fs::read(&file_path).unwrap();
    let sample_start = 5000;
    let sample_end = (max_size - 1000) as usize;
    let sample = &content[sample_start..sample_end];

    let non_zero_count = sample.iter().filter(|&&b| b != 0).count();
    let zero_ratio = (sample.len() - non_zero_count) as f64 / sample.len() as f64;

    assert!(
        non_zero_count > 0 && zero_ratio < 0.9,
        "Checkpoint padding should be random data vs zeros (Found {:.2}% zeros).",
        zero_ratio * 100.0
    );
}
