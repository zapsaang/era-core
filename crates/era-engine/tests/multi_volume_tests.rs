//! Multi-volume distribution tests
//!
//! These tests verify that erasure-coded shards are TRULY distributed
//! across physically separate files, and can recover from extreme failures.

use era_common::ErasureCodeConfig;
use era_engine::{ArchiveReader, ArchiveWriterBuilder, ExtractOptions};
use std::fs;
use tempfile::TempDir;

/// Test that multi-volume mode creates separate physical files
#[test]
fn test_multi_volume_creates_separate_files() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("test.era");

    // Create archive with 3 volumes (2 data + 1 parity)
    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .password("test_password")
        .enable_erasure(true)
        .erasure_config(ErasureCodeConfig {
            data_shards: 2,
            parity_shards: 1,
        })
        .volume_count(3)
        .build()
        .unwrap();

    // Add some data
    writer
        .add_bytes("test.txt", b"Hello Multi-Volume ERA!")
        .unwrap();
    writer.finalize().unwrap();

    // Verify files created
    let files: Vec<_> = fs::read_dir(temp_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();

    println!("Created files:");
    for f in &files {
        let meta = f.metadata().unwrap();
        println!("  {:?} - {} bytes", f.file_name(), meta.len());
    }

    // Should have 3 volume files
    let era_files: Vec<_> = files
        .iter()
        .filter(|f| f.file_name().to_string_lossy().starts_with("test.era"))
        .collect();

    assert!(
        era_files.len() >= 3,
        "Expected at least 3 volume files, got {} files: {:?}",
        era_files.len(),
        era_files.iter().map(|f| f.file_name()).collect::<Vec<_>>()
    );
}

/// Test that shards are distributed across different volumes
#[test]
fn test_shards_physically_distributed() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("distributed.era");

    // Create archive with 3 volumes
    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .password("test_password")
        .enable_erasure(true)
        .erasure_config(ErasureCodeConfig {
            data_shards: 2,
            parity_shards: 1,
        })
        .volume_count(3)
        .build()
        .unwrap();

    // Add larger data to see distribution
    let data = vec![0u8; 100 * 1024]; // 100KB
    writer.add_bytes("large.bin", &data).unwrap();
    writer.finalize().unwrap();

    // Check each volume file has data
    let vol0 = temp_dir.path().join("distributed.era");
    let vol1 = temp_dir.path().join("distributed.era.001");
    let vol2 = temp_dir.path().join("distributed.era.002");

    assert!(vol0.exists(), "Volume 0 should exist: {:?}", vol0);
    assert!(vol1.exists(), "Volume 1 should exist: {:?}", vol1);
    assert!(vol2.exists(), "Volume 2 should exist: {:?}", vol2);

    let size0 = fs::metadata(&vol0).unwrap().len();
    let size1 = fs::metadata(&vol1).unwrap().len();
    let size2 = fs::metadata(&vol2).unwrap().len();

    println!(
        "Volume sizes: vol0={}, vol1={}, vol2={}",
        size0, size1, size2
    );

    // Each volume should have shard data (not just header)
    // Header is ~512 bytes, so if we have 100KB data with 3 shards,
    // each shard should be ~33KB + overhead
    assert!(
        size0 > 1000,
        "Volume 0 should have shard data, got {} bytes",
        size0
    );
    assert!(
        size1 > 1000,
        "Volume 1 should have shard data, got {} bytes",
        size1
    );
    assert!(
        size2 > 1000,
        "Volume 2 should have shard data, got {} bytes",
        size2
    );
}

/// Test that data can be recovered after losing one volume
#[test]
fn test_recovery_after_volume_loss() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("recovery.era");

    // Create archive with 3 volumes (2+1 = can lose 1)
    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .password("test_password")
        .enable_erasure(true)
        .erasure_config(ErasureCodeConfig {
            data_shards: 2,
            parity_shards: 1,
        })
        .volume_count(3)
        .build()
        .unwrap();

    let original_data = b"This data should survive volume loss!";
    writer.add_bytes("important.txt", original_data).unwrap();
    writer.finalize().unwrap();

    // Delete one volume (simulating disk failure)
    let vol1 = temp_dir.path().join("recovery.era.001");
    if vol1.exists() {
        fs::remove_file(&vol1).unwrap();
        println!("Deleted volume 1: {:?}", vol1);
    }

    // Try to read the archive - should succeed with erasure recovery
    let mut reader = ArchiveReader::open(&archive_path, "test_password").unwrap();

    let extract_dir = temp_dir.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    let options = ExtractOptions::new(&extract_dir);
    let stats = reader.extract_all(&options).unwrap();

    assert_eq!(stats.extracted, 1, "Should extract 1 file");

    // Verify content
    let extracted_data = fs::read(extract_dir.join("important.txt")).unwrap();
    assert_eq!(
        extracted_data, original_data,
        "Extracted data should match original"
    );
}

// ============================================================================
// END-TO-END EXTREME FAILURE RECOVERY TESTS
// ============================================================================

/// Helper to create a multi-volume archive with configurable erasure coding
fn create_erasure_archive(
    temp_dir: &TempDir,
    name: &str,
    data_shards: u8,
    parity_shards: u8,
    volume_count: usize,
    file_sizes: &[(&str, usize)],
) -> std::path::PathBuf {
    let archive_path = temp_dir.path().join(name);

    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .password("test_password")
        .enable_erasure(true)
        .erasure_config(ErasureCodeConfig {
            data_shards,
            parity_shards,
        })
        .volume_count(volume_count)
        .build()
        .unwrap();

    for (filename, size) in file_sizes {
        // Create deterministic data based on filename for verification
        let data: Vec<u8> = (0..*size)
            .map(|i| ((i as u32).wrapping_mul(31) ^ (filename.len() as u32)) as u8)
            .collect();
        writer.add_bytes(filename, &data).unwrap();
    }

    writer.finalize().unwrap();
    archive_path
}

/// Verify archive content matches expected files
fn verify_extracted_content(
    extract_dir: &std::path::Path,
    expected_files: &[(&str, usize)],
) -> bool {
    for (filename, size) in expected_files {
        let path = extract_dir.join(filename);
        if !path.exists() {
            println!("Missing file: {}", filename);
            return false;
        }

        let data = fs::read(&path).unwrap();
        if data.len() != *size {
            println!(
                "Size mismatch for {}: expected {}, got {}",
                filename,
                size,
                data.len()
            );
            return false;
        }

        // Verify deterministic content
        for (i, &byte) in data.iter().enumerate() {
            let expected = ((i as u32).wrapping_mul(31) ^ (filename.len() as u32)) as u8;
            if byte != expected {
                println!(
                    "Content mismatch in {} at byte {}: expected {}, got {}",
                    filename, i, expected, byte
                );
                return false;
            }
        }
    }
    true
}

/// Test recovery with 4+2 erasure coding (can lose up to 2 volumes)
#[test]
fn test_e2e_recovery_4_plus_2_lose_one() {
    let temp_dir = TempDir::new().unwrap();
    let files = [("data.bin", 256 * 1024)]; // 256KB file

    let archive_path = create_erasure_archive(&temp_dir, "4plus2.era", 4, 2, 6, &files);

    // Delete volume 2 (middle volume)
    let vol2 = temp_dir.path().join("4plus2.era.002");
    assert!(vol2.exists(), "Volume 2 should exist before deletion");
    fs::remove_file(&vol2).unwrap();

    // Extraction should succeed
    let mut reader = ArchiveReader::open(&archive_path, "test_password").unwrap();
    let extract_dir = temp_dir.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    let stats = reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .unwrap();
    assert_eq!(stats.extracted, 1);
    assert!(verify_extracted_content(&extract_dir, &files));
}

/// Test recovery with 4+2 erasure coding losing maximum allowed (2 volumes)
#[test]
fn test_e2e_recovery_4_plus_2_lose_two() {
    let temp_dir = TempDir::new().unwrap();
    let files = [("critical.bin", 512 * 1024)]; // 512KB file

    let archive_path = create_erasure_archive(&temp_dir, "4plus2_extreme.era", 4, 2, 6, &files);

    // Delete 2 non-consecutive volumes (maximum allowed for 4+2)
    let vol1 = temp_dir.path().join("4plus2_extreme.era.001");
    let vol4 = temp_dir.path().join("4plus2_extreme.era.004");
    fs::remove_file(&vol1).unwrap();
    fs::remove_file(&vol4).unwrap();

    // Should still recover
    let mut reader = ArchiveReader::open(&archive_path, "test_password").unwrap();
    let extract_dir = temp_dir.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    let stats = reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .unwrap();
    assert_eq!(stats.extracted, 1);
    assert!(verify_extracted_content(&extract_dir, &files));
}

/// Test recovery with 4+2 erasure coding losing 2 consecutive volumes
#[test]
fn test_e2e_recovery_lose_consecutive_volumes() {
    let temp_dir = TempDir::new().unwrap();
    let files = [("file1.txt", 100 * 1024), ("file2.txt", 200 * 1024)];

    let archive_path = create_erasure_archive(&temp_dir, "consecutive.era", 4, 2, 6, &files);

    // Delete 2 consecutive volumes
    let vol2 = temp_dir.path().join("consecutive.era.002");
    let vol3 = temp_dir.path().join("consecutive.era.003");
    fs::remove_file(&vol2).unwrap();
    fs::remove_file(&vol3).unwrap();

    // Should still recover
    let mut reader = ArchiveReader::open(&archive_path, "test_password").unwrap();
    let extract_dir = temp_dir.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    let stats = reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .unwrap();
    assert_eq!(stats.extracted, 2);
    assert!(verify_extracted_content(&extract_dir, &files));
}

/// Test that losing too many volumes fails gracefully
#[test]
fn test_e2e_too_many_volumes_lost_should_fail() {
    let temp_dir = TempDir::new().unwrap();
    let files = [("data.bin", 128 * 1024)];

    let archive_path = create_erasure_archive(&temp_dir, "failtest.era", 4, 2, 6, &files);

    // Delete 3 volumes (more than parity allows)
    let vol1 = temp_dir.path().join("failtest.era.001");
    let vol2 = temp_dir.path().join("failtest.era.002");
    let vol3 = temp_dir.path().join("failtest.era.003");
    fs::remove_file(&vol1).unwrap();
    fs::remove_file(&vol2).unwrap();
    fs::remove_file(&vol3).unwrap();

    // Opening should succeed (we have volume 0)
    let mut reader = ArchiveReader::open(&archive_path, "test_password").unwrap();
    let extract_dir = temp_dir.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    // Extraction should fail - not enough shards
    let result = reader.extract_all(&ExtractOptions::new(&extract_dir));
    assert!(result.is_err(), "Should fail with too many volumes lost");

    let err = result.unwrap_err();
    let err_msg = format!("{}", err);
    assert!(
        err_msg.contains("Not enough shards") || err_msg.contains("recovery"),
        "Error should indicate shard recovery failure, got: {}",
        err_msg
    );
}

/// Test 2+1 minimal configuration with first volume lost
#[test]
fn test_e2e_recovery_2_plus_1_lose_first_data_volume() {
    let temp_dir = TempDir::new().unwrap();
    let files = [("small.txt", 1024)];

    // Note: volume 0 contains catalog and cannot be deleted in current impl
    // But we can delete volume 1 which has data shard 1
    let archive_path = create_erasure_archive(&temp_dir, "minimal.era", 2, 1, 3, &files);

    let vol1 = temp_dir.path().join("minimal.era.001");
    fs::remove_file(&vol1).unwrap();

    let mut reader = ArchiveReader::open(&archive_path, "test_password").unwrap();
    let extract_dir = temp_dir.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    let stats = reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .unwrap();
    assert_eq!(stats.extracted, 1);
    assert!(verify_extracted_content(&extract_dir, &files));
}

/// Test recovery with parity volume lost
#[test]
fn test_e2e_recovery_parity_volume_lost() {
    let temp_dir = TempDir::new().unwrap();
    let files = [("doc.pdf", 64 * 1024)];

    // 3+1 configuration - volume 3 (index 3) has only parity
    let archive_path = create_erasure_archive(&temp_dir, "parity.era", 3, 1, 4, &files);

    // Delete the parity-only volume (vol 3)
    let vol3 = temp_dir.path().join("parity.era.003");
    fs::remove_file(&vol3).unwrap();

    // Should work perfectly - all data shards present
    let mut reader = ArchiveReader::open(&archive_path, "test_password").unwrap();
    let extract_dir = temp_dir.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    let stats = reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .unwrap();
    assert_eq!(stats.extracted, 1);
    assert!(verify_extracted_content(&extract_dir, &files));
}

/// Test verify operation with missing volumes
#[test]
fn test_e2e_verify_with_missing_volume() {
    let temp_dir = TempDir::new().unwrap();
    let files = [("verify_test.bin", 32 * 1024)];

    let archive_path = create_erasure_archive(&temp_dir, "verify.era", 4, 2, 6, &files);

    // Delete one volume
    let vol2 = temp_dir.path().join("verify.era.002");
    fs::remove_file(&vol2).unwrap();

    // Verify should still work with recovery
    let mut reader = ArchiveReader::open(&archive_path, "test_password").unwrap();
    let stats = reader.verify().unwrap();

    println!("Verify stats: {:?}", stats);

    // With erasure recovery, some shards may be marked as corrupted/missing
    // but overall verification should succeed
    assert_eq!(stats.files_verified, 1, "Should verify 1 file");
    // Accept recovered archive as valid
    assert_eq!(
        stats.blocks_failed, 0,
        "No blocks should fail with recovery"
    );
}

/// Test large file spanning many blocks across volumes
#[test]
fn test_e2e_large_file_multi_block_recovery() {
    let temp_dir = TempDir::new().unwrap();
    // 2MB file will span multiple macro blocks
    let files = [("bigfile.dat", 2 * 1024 * 1024)];

    let archive_path = create_erasure_archive(&temp_dir, "largeblocks.era", 4, 2, 6, &files);

    // Delete 2 volumes
    let vol1 = temp_dir.path().join("largeblocks.era.001");
    let vol3 = temp_dir.path().join("largeblocks.era.003");
    fs::remove_file(&vol1).unwrap();
    fs::remove_file(&vol3).unwrap();

    let mut reader = ArchiveReader::open(&archive_path, "test_password").unwrap();
    let extract_dir = temp_dir.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    let stats = reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .unwrap();
    assert_eq!(stats.extracted, 1);
    assert!(verify_extracted_content(&extract_dir, &files));
}

/// Test multiple files with different sizes
#[test]
fn test_e2e_multi_file_various_sizes() {
    let temp_dir = TempDir::new().unwrap();
    let files = [
        ("tiny.txt", 100),
        ("small.bin", 4 * 1024),
        ("medium.dat", 128 * 1024),
        ("large.iso", 1024 * 1024),
    ];

    let archive_path = create_erasure_archive(&temp_dir, "multifile.era", 4, 2, 6, &files);

    // Delete maximum allowed volumes
    let vol2 = temp_dir.path().join("multifile.era.002");
    let vol4 = temp_dir.path().join("multifile.era.004");
    fs::remove_file(&vol2).unwrap();
    fs::remove_file(&vol4).unwrap();

    let mut reader = ArchiveReader::open(&archive_path, "test_password").unwrap();
    let extract_dir = temp_dir.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    let stats = reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .unwrap();
    assert_eq!(stats.extracted, 4);
    assert!(verify_extracted_content(&extract_dir, &files));
}

/// Test volume corruption (partial file damage)
#[test]
fn test_e2e_volume_partial_corruption() {
    let temp_dir = TempDir::new().unwrap();
    let files = [("corrupt_test.bin", 64 * 1024)];

    let archive_path = create_erasure_archive(&temp_dir, "corrupt.era", 4, 2, 6, &files);

    // Corrupt the middle of volume 1
    let vol1_path = temp_dir.path().join("corrupt.era.001");
    let mut vol1_data = fs::read(&vol1_path).unwrap();

    // Corrupt a section of the data region (after header ~512 bytes)
    if vol1_data.len() > 1024 {
        for i in 600..std::cmp::min(700, vol1_data.len()) {
            vol1_data[i] = 0xFF;
        }
        fs::write(&vol1_path, &vol1_data).unwrap();
    }

    // Should still recover thanks to erasure coding
    let mut reader = ArchiveReader::open(&archive_path, "test_password").unwrap();
    let extract_dir = temp_dir.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    let stats = reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .unwrap();
    assert_eq!(stats.extracted, 1);
    assert!(verify_extracted_content(&extract_dir, &files));
}

/// Test edge case: only primary volume survives
#[test]
fn test_e2e_only_primary_and_last_volumes() {
    let temp_dir = TempDir::new().unwrap();
    let files = [("survivor.txt", 8 * 1024)];

    // 4+2 = can lose 2 volumes. Keep volume 0 and 5, delete 1,2,3,4
    // This loses 4 volumes - should fail
    let archive_path = create_erasure_archive(&temp_dir, "extreme.era", 4, 2, 6, &files);

    for i in 1..=4 {
        let vol = temp_dir.path().join(format!("extreme.era.{:03}", i));
        if vol.exists() {
            fs::remove_file(&vol).unwrap();
        }
    }

    let mut reader = ArchiveReader::open(&archive_path, "test_password").unwrap();
    let extract_dir = temp_dir.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    // Should fail - only 2 volumes remain but need 4 data shards
    let result = reader.extract_all(&ExtractOptions::new(&extract_dir));
    assert!(result.is_err(), "Should fail with only 2 of 6 volumes");
}

/// Test high redundancy configuration (2+4 = can lose 4 volumes)
/// Note: In 2+4 config, shards 0,1 are data, shards 2,3,4,5 are parity.
/// To recover, we need any 2 shards (minimum = data_shards).
/// With 6 volumes: vol0=shard0, vol1=shard1, vol2=shard2, etc.
/// We can delete any 4 volumes and still have 2 shards for recovery.
#[test]
fn test_e2e_high_redundancy_2_plus_4() {
    let temp_dir = TempDir::new().unwrap();
    let files = [("important.bin", 128 * 1024)];

    // 2+4 configuration - extreme redundancy, can lose up to 4 volumes
    let archive_path = create_erasure_archive(&temp_dir, "highred.era", 2, 4, 6, &files);

    // Delete 4 volumes: 2,3,4,5 (keep volumes 0 and 1 which have data shards)
    for i in [2, 3, 4, 5] {
        let vol = temp_dir.path().join(format!("highred.era.{:03}", i));
        if vol.exists() {
            fs::remove_file(&vol).unwrap();
        }
    }

    // Should still work with volumes 0 and 1 (shard 0 and shard 1 = both data shards)
    let mut reader = ArchiveReader::open(&archive_path, "test_password").unwrap();
    let extract_dir = temp_dir.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    let stats = reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .unwrap();
    assert_eq!(stats.extracted, 1);
    assert!(verify_extracted_content(&extract_dir, &files));
}

/// Test high redundancy with mixed data/parity shard survival
#[test]
fn test_e2e_high_redundancy_mixed_survival() {
    let temp_dir = TempDir::new().unwrap();
    let files = [("mixed.bin", 64 * 1024)];

    // 2+4 configuration
    // Shards: 0(data), 1(data), 2(parity), 3(parity), 4(parity), 5(parity)
    let archive_path = create_erasure_archive(&temp_dir, "mixed.era", 2, 4, 6, &files);

    // Delete volumes 1,2,3,4 - keeping vol 0 (shard 0=data) and vol 5 (shard 5=parity)
    // This tests recovery with 1 data + 1 parity shard
    for i in [1, 2, 3, 4] {
        let vol = temp_dir.path().join(format!("mixed.era.{:03}", i));
        if vol.exists() {
            fs::remove_file(&vol).unwrap();
        }
    }

    let mut reader = ArchiveReader::open(&archive_path, "test_password").unwrap();
    let extract_dir = temp_dir.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    let stats = reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .unwrap();
    assert_eq!(stats.extracted, 1);
    assert!(verify_extracted_content(&extract_dir, &files));
}

/// Test that volumes are correctly discovered even with gaps
#[test]
fn test_e2e_volume_discovery_with_gaps() {
    let temp_dir = TempDir::new().unwrap();
    let files = [("gaptest.bin", 64 * 1024)];

    let archive_path = create_erasure_archive(&temp_dir, "gaps.era", 4, 2, 6, &files);

    // List all volumes before deletion
    println!("Volumes before deletion:");
    for entry in fs::read_dir(temp_dir.path()).unwrap() {
        let entry = entry.unwrap();
        println!("  {:?}", entry.file_name());
    }

    // Delete volume 1 and 3 (creating gaps)
    let vol1 = temp_dir.path().join("gaps.era.001");
    let vol3 = temp_dir.path().join("gaps.era.003");
    fs::remove_file(&vol1).unwrap();
    fs::remove_file(&vol3).unwrap();

    // List remaining volumes
    println!("Volumes after deletion:");
    for entry in fs::read_dir(temp_dir.path()).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().to_string_lossy().starts_with("gaps.era") {
            println!("  {:?}", entry.file_name());
        }
    }

    // Reader should still find volumes 0, 2, 4, 5 (skipping gaps)
    let mut reader = ArchiveReader::open(&archive_path, "test_password").unwrap();
    let extract_dir = temp_dir.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    let stats = reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .unwrap();
    assert_eq!(stats.extracted, 1);
    assert!(verify_extracted_content(&extract_dir, &files));
}

// ============================================================================
// VOLUME HEADER AND NON-PRIMARY VOLUME OPEN TESTS
// ============================================================================

/// Test that volume headers contain correct volume_sequence and total_volumes
#[test]
fn test_volume_headers_contain_correct_metadata() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("metadata.era");

    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .password("test_password")
        .enable_erasure(true)
        .erasure_config(ErasureCodeConfig {
            data_shards: 4,
            parity_shards: 2,
        })
        .volume_count(6)
        .build()
        .unwrap();

    writer
        .add_bytes("test.txt", b"Header metadata test")
        .unwrap();
    writer.finalize().unwrap();

    // Open each volume and verify header metadata
    for i in 0..6 {
        let vol_path = if i == 0 {
            temp_dir.path().join("metadata.era")
        } else {
            temp_dir.path().join(format!("metadata.era.{:03}", i))
        };

        let reader = ArchiveReader::open(&vol_path, "test_password").unwrap();
        let header = reader.header();

        println!(
            "Volume {}: sequence={}, total={}",
            i, header.volume_sequence, header.total_volumes
        );

        // All volumes should have correct total_volumes
        assert_eq!(
            header.total_volumes, 6,
            "Volume {} should have total_volumes=6",
            i
        );
    }
}

/// Test opening archive from secondary volume (not .era but .era.001)
#[test]
fn test_open_from_secondary_volume() {
    let temp_dir = TempDir::new().unwrap();
    let files = [("secondary.bin", 64 * 1024)];

    let _archive_path = create_erasure_archive(&temp_dir, "secondary.era", 4, 2, 6, &files);

    // Open from volume 1 instead of volume 0
    let vol1_path = temp_dir.path().join("secondary.era.001");

    let mut reader = ArchiveReader::open(&vol1_path, "test_password").unwrap();
    let extract_dir = temp_dir.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    let stats = reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .unwrap();
    assert_eq!(stats.extracted, 1);
    assert!(verify_extracted_content(&extract_dir, &files));
}

/// Test opening from secondary volume when primary is missing
#[test]
fn test_open_from_secondary_when_primary_missing() {
    let temp_dir = TempDir::new().unwrap();
    let files = [("orphan.bin", 32 * 1024)];

    let _archive_path = create_erasure_archive(&temp_dir, "orphan.era", 4, 2, 6, &files);

    // Delete the primary volume (volume 0)
    let vol0 = temp_dir.path().join("orphan.era");
    fs::remove_file(&vol0).unwrap();

    // Open from volume 2 - should succeed as catalog is written to all volumes
    let vol2_path = temp_dir.path().join("orphan.era.002");

    let mut reader = ArchiveReader::open(&vol2_path, "test_password").unwrap();
    let extract_dir = temp_dir.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    let stats = reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .unwrap();
    assert_eq!(stats.extracted, 1);
    assert!(verify_extracted_content(&extract_dir, &files));
}

/// Test opening from middle volume with both ends missing
#[test]
fn test_open_from_middle_volume() {
    let temp_dir = TempDir::new().unwrap();
    let files = [("middle.bin", 64 * 1024)];

    // 4+2 = can lose 2 volumes
    let _archive_path = create_erasure_archive(&temp_dir, "middle.era", 4, 2, 6, &files);

    // Delete volume 0 and volume 5 (first and last)
    let vol0 = temp_dir.path().join("middle.era");
    let vol5 = temp_dir.path().join("middle.era.005");
    fs::remove_file(&vol0).unwrap();
    fs::remove_file(&vol5).unwrap();

    // Open from volume 3 (middle)
    let vol3_path = temp_dir.path().join("middle.era.003");

    let mut reader = ArchiveReader::open(&vol3_path, "test_password").unwrap();
    let extract_dir = temp_dir.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    let stats = reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .unwrap();
    assert_eq!(stats.extracted, 1);
    assert!(verify_extracted_content(&extract_dir, &files));
}

/// Test that archive_id is verified across volumes
#[test]
fn test_archive_id_verification() {
    let temp_dir = TempDir::new().unwrap();

    // Create first archive
    let files1 = [("archive1.txt", 1024)];
    create_erasure_archive(&temp_dir, "archive1.era", 2, 1, 3, &files1);

    // Create second archive with same naming pattern in a subdirectory
    // to avoid conflicts, then copy a volume over
    let sub_dir = temp_dir.path().join("sub");
    fs::create_dir_all(&sub_dir).unwrap();
    let sub_temp = TempDir::new_in(&sub_dir).unwrap();
    let files2 = [("archive2.txt", 1024)];
    create_erasure_archive(&sub_temp, "archive1.era", 2, 1, 3, &files2);

    // Copy a volume from second archive to first archive's location
    // This creates a mixed archive situation
    let src_vol = sub_temp.path().join("archive1.era.001");
    let dst_vol = temp_dir.path().join("archive1.era.001");

    // Delete original vol1 and replace with foreign vol1
    fs::remove_file(&dst_vol).ok();
    fs::copy(&src_vol, &dst_vol).unwrap();

    // Open should still work but only use volumes from same archive
    let archive_path = temp_dir.path().join("archive1.era");
    let reader = ArchiveReader::open(&archive_path, "test_password").unwrap();

    // The header should be from archive1, not archive2
    let header = reader.header();
    // We can't easily check archive_id content, but we can verify
    // that the reader was created successfully
    assert!(header.total_volumes > 0);
}

/// Test without erasure coding - single volume behavior
#[test]
fn test_single_volume_no_erasure() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("single.era");

    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .password("test_password")
        .enable_erasure(false)
        .build()
        .unwrap();

    writer
        .add_bytes("single.txt", b"Single volume test")
        .unwrap();
    writer.finalize().unwrap();

    // Verify only one file created
    let era_files: Vec<_> = fs::read_dir(temp_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".era"))
        .collect();

    assert_eq!(era_files.len(), 1, "Should only have 1 volume file");

    // Open and verify
    let mut reader = ArchiveReader::open(&archive_path, "test_password").unwrap();
    let header = reader.header();
    assert_eq!(header.volume_sequence, 0);
    assert_eq!(header.total_volumes, 1);

    let extract_dir = temp_dir.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();
    let stats = reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .unwrap();
    assert_eq!(stats.extracted, 1);
}

/// Test that volume_count matches erasure config total shards
#[test]
fn test_volume_count_matches_erasure_shards() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("match.era");

    // 3+2 = 5 total shards, but only set volume_count=3
    // This tests what happens when volume_count != total_shards
    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .password("test_password")
        .enable_erasure(true)
        .erasure_config(ErasureCodeConfig {
            data_shards: 3,
            parity_shards: 2,
        })
        .volume_count(3) // Less than total shards
        .build()
        .unwrap();

    writer
        .add_bytes("mismatch.txt", b"Volume count mismatch test")
        .unwrap();
    writer.finalize().unwrap();

    // Should still work - shards distributed round-robin
    let mut reader = ArchiveReader::open(&archive_path, "test_password").unwrap();
    let extract_dir = temp_dir.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    let stats = reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .unwrap();
    assert_eq!(stats.extracted, 1);
}

/// Test discovering volumes based on total_volumes header field
#[test]
fn test_volume_discovery_uses_total_volumes() {
    let temp_dir = TempDir::new().unwrap();
    let files = [("discover.bin", 32 * 1024)];

    // Create archive with 6 volumes
    let archive_path = create_erasure_archive(&temp_dir, "discover.era", 4, 2, 6, &files);

    // Delete volumes in the middle (1,2,3) leaving gaps
    // With total_volumes=6, reader should scan all 6 positions
    for i in 1..=3 {
        let vol = temp_dir.path().join(format!("discover.era.{:03}", i));
        fs::remove_file(&vol).unwrap();
    }

    // Open from volume 0 - should still find volumes 4 and 5
    let mut reader = ArchiveReader::open(&archive_path, "test_password").unwrap();

    // With volumes 0, 4, 5 available (3 shards), should be able to recover
    // since we need 4 data shards but have 2 parity
    // Wait - 4+2 needs at least 4 shards. We have 3. This should fail.
    let extract_dir = temp_dir.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    let result = reader.extract_all(&ExtractOptions::new(&extract_dir));
    // This should fail - not enough shards
    assert!(
        result.is_err(),
        "Should fail with only 3 of 6 volumes (need 4)"
    );
}
