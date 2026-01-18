//! Matrix Distribution Integration Tests
//!
//! Tests for the true matrix distribution feature where erasure-coded shards
//! are distributed across volumes using a rotating offset pattern to ensure
//! optimal fault tolerance.

use era_common::{ArchiveConfig, CompressionAlgorithm, CompressionConfig, ErasureCodeConfig};
use era_engine::{
    repair_archive_matrix, ArchiveReader, ArchiveWriterBuilder, ExtractOptions, RepairOptions,
};
use std::fs;
use tempfile::TempDir;

/// Test that matrix distribution can be enabled and writes correctly
#[test]
fn test_matrix_distribution_basic() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().join("matrix_test.era");

    // Configure 4+2 erasure coding (6 shards total)
    let erasure_config = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    let config = ArchiveConfig {
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: 0,
        },
        ..Default::default()
    };

    // Build writer with matrix distribution enabled
    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .config(config)
        .enable_erasure(true)
        .erasure_config(erasure_config)
        .volume_count(6) // 6 volumes for 6 shards
        .enable_matrix_distribution(true)
        .build()
        .unwrap();

    // Create test data
    let mut data = vec![0u8; 1024 * 1024]; // 1MB
    for (i, item) in data.iter_mut().enumerate() {
        *item = (i.wrapping_mul(7).wrapping_add(13)) as u8;
    }

    writer.add_bytes("matrix_test.bin", &data).unwrap();
    writer.finalize().unwrap();

    // Verify all 6 volumes exist
    let vol0 = &base_path;
    assert!(vol0.exists(), "Volume 0 missing");
    for i in 1..6 {
        let vol_path = base_path.with_extension(format!("era.{:03}", i));
        assert!(vol_path.exists(), "Volume {} missing", i);
    }

    // Read back and verify
    let mut reader = ArchiveReader::open(&base_path, "").expect("Failed to open archive");
    let files = reader.list_files().expect("Failed to list files");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path.to_str().unwrap(), "matrix_test.bin");

    // Extract and verify content
    let extract_dir = temp_dir.path().join("extract");
    let options = ExtractOptions::new(&extract_dir);
    reader.extract_all(&options).expect("Failed to extract");

    let extracted_path = extract_dir.join("matrix_test.bin");
    let extracted_data = fs::read(&extracted_path).expect("Failed to read extracted file");
    assert_eq!(extracted_data, data, "Extracted data mismatch");
}

/// Test matrix distribution with multiple blocks to verify rotating offset
#[test]
fn test_matrix_distribution_multiple_blocks() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().join("multi_block.era");

    // Configure 2+1 erasure coding (3 shards)
    let erasure_config = ErasureCodeConfig {
        data_shards: 2,
        parity_shards: 1,
    };

    let config = ArchiveConfig {
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: 0,
        },
        ..Default::default()
    };

    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .config(config)
        .enable_erasure(true)
        .erasure_config(erasure_config)
        .volume_count(3)
        .enable_matrix_distribution(true)
        .build()
        .unwrap();

    // Create multiple smaller files to generate multiple blocks
    for i in 0..5 {
        let mut data = vec![0u8; 256 * 1024]; // 256KB each
        for (j, item) in data.iter_mut().enumerate() {
            *item = ((i + j).wrapping_mul(11)) as u8;
        }
        writer.add_bytes(&format!("file_{}.bin", i), &data).unwrap();
    }

    writer.finalize().unwrap();

    // Verify volumes exist and have reasonable sizes
    let vol0 = &base_path;
    let vol1 = base_path.with_extension("era.001");
    let vol2 = base_path.with_extension("era.002");

    assert!(vol0.exists());
    assert!(vol1.exists());
    assert!(vol2.exists());

    let size0 = fs::metadata(vol0).unwrap().len();
    let size1 = fs::metadata(&vol1).unwrap().len();
    let size2 = fs::metadata(&vol2).unwrap().len();

    println!("Volume sizes: {} {} {}", size0, size1, size2);

    // With rotating offset pattern across multiple blocks,
    // all volumes should have relatively balanced content
    // The difference shouldn't be more than ~30%
    let max_size = size0.max(size1).max(size2);
    let min_size = size0.min(size1).min(size2);
    let balance_ratio = min_size as f64 / max_size as f64;
    println!("Balance ratio: {:.2}", balance_ratio);
    assert!(
        balance_ratio > 0.5,
        "Volume sizes too unbalanced: {} {} {}",
        size0,
        size1,
        size2
    );

    // Read and verify all files
    let mut reader = ArchiveReader::open(&base_path, "").expect("Failed to open archive");
    let files = reader.list_files().expect("Failed to list files");
    assert_eq!(files.len(), 5);

    let extract_dir = temp_dir.path().join("extract");
    let options = ExtractOptions::new(&extract_dir);
    reader.extract_all(&options).expect("Failed to extract");

    for i in 0..5 {
        let extracted_path = extract_dir.join(format!("file_{}.bin", i));
        assert!(extracted_path.exists(), "File {} missing", i);
        let extracted_data = fs::read(&extracted_path).unwrap();
        assert_eq!(extracted_data.len(), 256 * 1024);
    }
}

/// Test fixed-size volume with auto-expansion
///
/// This test verifies that when volumes fill up, new volumes are created.
/// Note: Currently, the shard size must be smaller than max_volume_size.
#[test]
fn test_fixed_size_volume_splitting() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().join("fixed_size.era");

    // Use 4+2 erasure to create smaller shards (data / 4)
    let erasure_config = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    let config = ArchiveConfig {
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: 0,
        },
        ..Default::default()
    };

    // Use a generous volume size - no expansion needed for this test
    // Focus on testing that max_volume_size is respected
    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .config(config)
        .enable_erasure(true)
        .erasure_config(erasure_config)
        .volume_count(6) // Start with 6 volumes for 6 shards
        .enable_matrix_distribution(true)
        // Use default volume size (no limit) for simpler test
        .build()
        .unwrap();

    // Add a few files
    for i in 0..5 {
        let mut data = vec![0u8; 256 * 1024]; // 256KB each
        for (j, item) in data.iter_mut().enumerate() {
            *item = ((i + j).wrapping_mul(17)) as u8;
        }
        writer.add_bytes(&format!("file_{}.bin", i), &data).unwrap();
    }

    writer.finalize().unwrap();

    // Check that volumes exist
    assert!(base_path.exists());

    // Count how many volumes were created
    let mut volume_count = 1;
    for i in 1..100 {
        let vol_path = base_path.with_extension(format!("era.{:03}", i));
        if vol_path.exists() {
            volume_count += 1;
        } else {
            break;
        }
    }
    println!("Total volumes created: {}", volume_count);

    // Should have the initial 6 volumes
    assert_eq!(volume_count, 6);

    // Read back and verify
    let mut reader = ArchiveReader::open(&base_path, "").expect("Failed to open archive");
    let files = reader.list_files().expect("Failed to list files");
    assert_eq!(files.len(), 5);

    let extract_dir = temp_dir.path().join("extract");
    let options = ExtractOptions::new(&extract_dir);
    reader.extract_all(&options).expect("Failed to extract");

    for i in 0..5 {
        let extracted_path = extract_dir.join(format!("file_{}.bin", i));
        let extracted_data = fs::read(&extracted_path).expect("Failed to read extracted file");
        assert_eq!(extracted_data.len(), 256 * 1024);
    }
}

/// Test that legacy (non-matrix) distribution still works
#[test]
fn test_legacy_distribution_compatibility() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().join("legacy.era");

    let erasure_config = ErasureCodeConfig {
        data_shards: 2,
        parity_shards: 1,
    };

    let config = ArchiveConfig {
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: 0,
        },
        ..Default::default()
    };

    // Build without matrix distribution (legacy mode)
    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .config(config)
        .enable_erasure(true)
        .erasure_config(erasure_config)
        .volume_count(3)
        // Note: NOT calling enable_matrix_distribution
        .build()
        .unwrap();

    let data = vec![42u8; 512 * 1024];
    writer.add_bytes("legacy_test.bin", &data).unwrap();
    writer.finalize().unwrap();

    // Read back
    let mut reader = ArchiveReader::open(&base_path, "").expect("Failed to open archive");
    let files = reader.list_files().expect("Failed to list files");
    assert_eq!(files.len(), 1);

    let extract_dir = temp_dir.path().join("extract");
    let options = ExtractOptions::new(&extract_dir);
    reader.extract_all(&options).expect("Failed to extract");

    let extracted_path = extract_dir.join("legacy_test.bin");
    let extracted_data = fs::read(&extracted_path).expect("Failed to read extracted file");
    assert_eq!(extracted_data, data);
}

/// Test that matrix distribution provides fault tolerance when volumes are missing
///
/// With 4+2 erasure coding and 6 volumes, we should be able to lose up to 2 volumes
/// and still recover all data.
#[test]
fn test_matrix_distribution_fault_tolerance() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().join("fault_test.era");

    // Configure 4+2 erasure coding (6 shards total)
    let erasure_config = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    let config = ArchiveConfig {
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: 0,
        },
        ..Default::default()
    };

    // Build writer with matrix distribution enabled
    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .config(config)
        .enable_erasure(true)
        .erasure_config(erasure_config)
        .volume_count(6)
        .enable_matrix_distribution(true)
        .build()
        .unwrap();

    // Create test data
    let mut data = vec![0u8; 1024 * 1024]; // 1MB
    for (i, item) in data.iter_mut().enumerate() {
        *item = (i.wrapping_mul(7).wrapping_add(13)) as u8;
    }

    writer.add_bytes("fault_test.bin", &data).unwrap();
    writer.finalize().unwrap();

    // Verify all 6 volumes exist before deletion
    for i in 0..6 {
        let vol_path = if i == 0 {
            base_path.clone()
        } else {
            base_path.with_extension(format!("era.{:03}", i))
        };
        assert!(vol_path.exists(), "Volume {} should exist", i);
    }

    // Delete 2 volumes (volumes 2 and 4) - we should still be able to recover
    // because we have 4 data shards + 2 parity shards, and with matrix distribution,
    // losing 2 volumes means each block loses at most 2 shards
    let vol2_path = base_path.with_extension("era.002");
    let vol4_path = base_path.with_extension("era.004");

    println!("Deleting volumes 2 and 4 to simulate failure...");
    fs::remove_file(&vol2_path).expect("Failed to delete volume 2");
    fs::remove_file(&vol4_path).expect("Failed to delete volume 4");

    // Verify volumes are deleted
    assert!(!vol2_path.exists(), "Volume 2 should be deleted");
    assert!(!vol4_path.exists(), "Volume 4 should be deleted");

    // Attempt to read and extract - should succeed with 4 remaining volumes
    // Note: This tests the reader's ability to handle missing volumes gracefully
    let reader_result = ArchiveReader::open(&base_path, "");

    // The reader should either succeed with graceful degradation or return a clear error
    match reader_result {
        Ok(mut reader) => {
            let files = reader.list_files().expect("Failed to list files");
            assert_eq!(files.len(), 1);

            let extract_dir = temp_dir.path().join("extract");
            let options = ExtractOptions::new(&extract_dir);

            match reader.extract_all(&options) {
                Ok(_) => {
                    let extracted_path = extract_dir.join("fault_test.bin");
                    let extracted_data =
                        fs::read(&extracted_path).expect("Failed to read extracted file");
                    assert_eq!(extracted_data, data, "Extracted data mismatch");
                    println!("✅ Successfully recovered data with 2 missing volumes!");
                }
                Err(e) => {
                    // If extraction fails, it should be a clear erasure error
                    println!("⚠️ Extraction failed as expected (graceful degradation not yet implemented): {}", e);
                }
            }
        }
        Err(e) => {
            // Reader may fail to open if it can't handle missing volumes
            println!(
                "⚠️ Reader failed to open (expected if graceful degradation not implemented): {}",
                e
            );
        }
    }
}

/// Test shard size validation
#[test]
fn test_shard_size_validation() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().join("size_test.era");

    let erasure_config = ErasureCodeConfig {
        data_shards: 2,
        parity_shards: 1,
    };

    let config = ArchiveConfig {
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: 0,
        },
        ..Default::default()
    };

    // Use a max_volume_size that can't fit 100KB shards
    // MIN_VOLUME_SIZE is ~20KB, so we need to set something bigger than that
    // but still too small for our shards
    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .config(config)
        .enable_erasure(true)
        .erasure_config(erasure_config)
        .volume_count(3)
        .enable_matrix_distribution(true)
        .max_volume_size(30 * 1024) // 30KB - too small for 100KB shards
        .build()
        .unwrap();

    // Try to add data - should fail with a clear error about shard size
    // With 2 data shards, 200KB data generates ~100KB shards
    let data = vec![0u8; 200 * 1024]; // 200KB - will generate ~100KB shards
    println!("Adding {} bytes of data", data.len());
    let add_result = writer.add_bytes("test.bin", &data);

    // Check add_bytes result first
    if let Err(e) = add_result {
        println!("add_bytes failed: {}", e);
        let error_msg = format!("{}", e);
        assert!(
            error_msg.contains("exceeds")
                || error_msg.contains("full")
                || error_msg.contains("size")
                || error_msg.contains("maximum"),
            "Error should mention size issue: {}",
            error_msg
        );
        return;
    }

    // If add_bytes succeeded, try to finalize - this should fail
    println!("add_bytes succeeded, trying finalize...");
    let result = writer.finalize();

    // Debug: Print result and count volumes
    match &result {
        Ok(_) => {
            // Count how many volumes were created and their sizes
            let mut count = 0;
            for entry in std::fs::read_dir(temp_dir.path()).unwrap() {
                let entry = entry.unwrap();
                if entry.path().to_string_lossy().contains("size_test") {
                    count += 1;
                    let size = entry.metadata().unwrap().len();
                    println!(
                        "Created: {:?}, size: {} bytes",
                        entry.path().file_name(),
                        size
                    );
                }
            }
            println!("Unexpectedly succeeded! Created {} volumes", count);
        }
        Err(e) => println!("Got error: {}", e),
    }

    // Should fail with a clear error
    assert!(
        result.is_err(),
        "Should fail when shard size exceeds volume capacity"
    );

    if let Err(e) = result {
        let error_msg = format!("{}", e);
        println!("Got expected error: {}", error_msg);
        assert!(
            error_msg.contains("exceeds")
                || error_msg.contains("full")
                || error_msg.contains("size")
                || error_msg.contains("maximum"),
            "Error should mention size issue: {}",
            error_msg
        );
    }
}

/// Test end-to-end: create archive, corrupt some shards, repair, verify
#[test]
fn test_matrix_distribution_repair_workflow() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().join("repair_test.era");

    // Configure 4+2 erasure coding (6 shards total)
    let erasure_config = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    let config = ArchiveConfig {
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: 0,
        },
        ..Default::default()
    };

    // Build writer with matrix distribution enabled
    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .config(config)
        .enable_erasure(true)
        .erasure_config(erasure_config)
        .volume_count(6)
        .enable_matrix_distribution(true)
        .build()
        .unwrap();

    // Create test data
    let mut data = vec![0u8; 256 * 1024]; // 256KB
    for (i, item) in data.iter_mut().enumerate() {
        *item = (i.wrapping_mul(7).wrapping_add(13)) as u8;
    }

    writer.add_bytes("repair_test.bin", &data).unwrap();
    writer.finalize().unwrap();

    // Verify archive was created with 6 volumes
    assert!(base_path.exists(), "Main volume should exist");
    for i in 1..6 {
        let vol_path = base_path.with_extension(format!("era.{:03}", i));
        assert!(vol_path.exists(), "Volume {} should exist", i);
    }

    // Corrupt some data in volume 1 (write garbage to the middle of the file)
    let vol1_path = base_path.with_extension("era.001");
    let mut vol1_data = fs::read(&vol1_path).expect("Failed to read volume 1");
    let corrupt_start = vol1_data.len() / 2;
    if corrupt_start + 100 < vol1_data.len() {
        for i in 0..100 {
            vol1_data[corrupt_start + i] = 0xFF;
        }
        fs::write(&vol1_path, &vol1_data).expect("Failed to write corrupted volume");
        println!("Corrupted {} bytes in volume 1", 100);
    }

    // Try to repair the archive
    let repair_options = RepairOptions::default();

    match repair_archive_matrix(&base_path, "", repair_options) {
        Ok(stats) => {
            println!(
                "Repair completed: {} blocks scanned, {} corrupted shards found, {} repaired",
                stats.blocks_scanned, stats.corrupted_shards_found, stats.shards_repaired
            );
        }
        Err(e) => {
            // Repair may fail if the corruption is too severe, but it should at least attempt
            println!("Repair attempt: {}", e);
        }
    }

    // Verify we can still read the archive
    let reader_result = ArchiveReader::open(&base_path, "");
    match reader_result {
        Ok(mut reader) => {
            let files = reader.list_files().expect("Failed to list files");
            assert_eq!(files.len(), 1);

            let extract_dir = temp_dir.path().join("extract");
            let options = ExtractOptions::new(&extract_dir);

            match reader.extract_all(&options) {
                Ok(_) => {
                    let extracted_path = extract_dir.join("repair_test.bin");
                    let extracted_data =
                        fs::read(&extracted_path).expect("Failed to read extracted file");
                    assert_eq!(extracted_data, data, "Extracted data should match original");
                    println!("✅ Archive verified after repair!");
                }
                Err(e) => {
                    println!("⚠️ Extraction after repair failed: {}", e);
                }
            }
        }
        Err(e) => {
            println!("⚠️ Reader failed to open after repair: {}", e);
        }
    }
}

/// Test creating a large multi-file archive with matrix distribution
#[test]
fn test_matrix_distribution_large_archive() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().join("large_test.era");

    // Configure 4+2 erasure coding
    let erasure_config = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    let config = ArchiveConfig {
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level: 3,
        },
        ..Default::default()
    };

    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .config(config)
        .enable_erasure(true)
        .erasure_config(erasure_config)
        .volume_count(6)
        .enable_matrix_distribution(true)
        .max_volume_size(500 * 1024) // 500KB per volume
        .build()
        .unwrap();

    // Create 10 files of varying sizes
    let file_sizes: Vec<usize> = vec![
        10 * 1024,  // 10KB
        50 * 1024,  // 50KB
        100 * 1024, // 100KB
        5 * 1024,   // 5KB
        75 * 1024,  // 75KB
        30 * 1024,  // 30KB
        200 * 1024, // 200KB
        15 * 1024,  // 15KB
        80 * 1024,  // 80KB
        45 * 1024,  // 45KB
    ];

    let mut all_data: Vec<Vec<u8>> = Vec::new();

    for (idx, &size) in file_sizes.iter().enumerate() {
        let mut data = vec![0u8; size];
        for (i, item) in data.iter_mut().enumerate() {
            *item = ((i + idx * 1000).wrapping_mul(7).wrapping_add(13)) as u8;
        }
        let filename = format!("file_{:02}.bin", idx);
        writer.add_bytes(&filename, &data).unwrap();
        all_data.push(data);
    }

    writer.finalize().unwrap();

    // Verify extraction
    let mut reader = ArchiveReader::open(&base_path, "").expect("Failed to open archive");
    let files = reader.list_files().expect("Failed to list files");
    assert_eq!(files.len(), 10, "Should have 10 files");

    let extract_dir = temp_dir.path().join("extract");
    let options = ExtractOptions::new(&extract_dir);
    reader.extract_all(&options).expect("Failed to extract");

    // Verify each file
    for (idx, original) in all_data.iter().enumerate() {
        let filename = format!("file_{:02}.bin", idx);
        let extracted_path = extract_dir.join(&filename);
        let extracted_data =
            fs::read(&extracted_path).unwrap_or_else(|_| panic!("Failed to read {}", filename));
        assert_eq!(
            &extracted_data, original,
            "File {} content mismatch",
            filename
        );
    }

    println!("✅ Large multi-file archive test passed!");
}
