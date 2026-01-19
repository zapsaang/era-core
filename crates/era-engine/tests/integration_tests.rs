//! Integration tests for ERA Engine.
//!
//! These tests verify end-to-end functionality of archive creation and extraction.

use era_engine::{repair_archive, ArchiveReader, ArchiveWriter, ExtractOptions, RepairOptions};
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::TempDir;

/// Create a test file with the given content
fn create_test_file(dir: &Path, name: &str, content: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut file = fs::File::create(&path).unwrap();
    file.write_all(content).unwrap();
    path
}

#[test]
fn test_create_and_extract_single_file() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    // Create a test file
    let content = b"Hello, ERA Archive!";
    let file_path = create_test_file(&input_dir, "test.txt", content);

    // Create archive
    let archive_path = temp_dir.path().join("test.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("test_password")
        .build()
        .unwrap();

    writer.add_file(&file_path).unwrap();
    let _stats = writer.finalize().unwrap();

    // Extract archive
    let output_dir = temp_dir.path().join("output");
    let mut reader = ArchiveReader::open(&archive_path, "test_password").unwrap();
    reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .unwrap();

    // Verify extracted content
    let extracted_path = output_dir.join("test.txt");
    let extracted_content = fs::read(&extracted_path).unwrap();
    assert_eq!(extracted_content, content);
}

#[test]
fn test_create_and_extract_multiple_files() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    // Create multiple test files
    let files = vec![
        ("file1.txt", vec![1u8; 100]),
        ("file2.txt", vec![2u8; 200]),
        ("file3.txt", vec![3u8; 300]),
    ];

    for (name, content) in &files {
        create_test_file(&input_dir, name, content);
    }

    // Create archive
    let archive_path = temp_dir.path().join("multi.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("secure_pass")
        .build()
        .unwrap();

    for (name, _) in &files {
        writer.add_file(&input_dir.join(name)).unwrap();
    }
    let stats = writer.finalize().unwrap();

    assert_eq!(stats.total_files, 3);

    // Extract archive
    let output_dir = temp_dir.path().join("output");
    let mut reader = ArchiveReader::open(&archive_path, "secure_pass").unwrap();
    reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .unwrap();

    // Verify all extracted files
    for (name, content) in &files {
        let extracted = fs::read(output_dir.join(name)).unwrap();
        assert_eq!(extracted, *content, "Content mismatch for {}", name);
    }
}

#[test]
fn test_wrong_password_fails() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    // Create a test file
    let file_path = create_test_file(&input_dir, "secret.txt", b"Top secret!");

    // Create archive with password
    let archive_path = temp_dir.path().join("protected.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("correct_password")
        .build()
        .unwrap();

    writer.add_file(&file_path).unwrap();
    writer.finalize().unwrap();

    // Try to open with wrong password - should fail
    let result = ArchiveReader::open(&archive_path, "wrong_password");
    assert!(result.is_err());

    // The error should indicate incorrect password
    match result {
        Err(err) => {
            assert!(
                err.to_string().contains("Incorrect password")
                    || err.to_string().contains("InvalidKey"),
                "Expected password error, got: {}",
                err
            );
        }
        Ok(_) => panic!("Expected an error for wrong password"),
    }
}

#[test]
fn test_list_files() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    // Create test files
    let files = vec!["alpha.txt", "beta.txt", "gamma.txt"];
    for name in &files {
        create_test_file(&input_dir, name, b"content");
    }

    // Create archive
    let archive_path = temp_dir.path().join("listing.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("list_test")
        .build()
        .unwrap();

    for name in &files {
        writer.add_file(&input_dir.join(name)).unwrap();
    }
    writer.finalize().unwrap();

    // Open and list files
    let mut reader = ArchiveReader::open(&archive_path, "list_test").unwrap();
    let listed = reader.list_files().unwrap();

    assert_eq!(listed.len(), files.len());

    // Check all files are listed (order may vary)
    for entry in &listed {
        let filename = entry.path.file_name().unwrap().to_str().unwrap();
        assert!(
            files.contains(&filename),
            "Unexpected file in listing: {}",
            filename
        );
    }
}

#[test]
fn test_empty_password() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    let file_path = create_test_file(&input_dir, "test.txt", b"data");

    // Create archive with empty password
    let archive_path = temp_dir.path().join("empty_pass.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("")
        .build()
        .unwrap();

    writer.add_file(&file_path).unwrap();
    writer.finalize().unwrap();

    // Open with empty password
    let reader = ArchiveReader::open(&archive_path, "");
    assert!(reader.is_ok(), "Should open with empty password");

    // Open with non-empty password should fail
    let wrong = ArchiveReader::open(&archive_path, "any_password");
    assert!(wrong.is_err(), "Should fail with non-empty password");
}

#[test]
fn test_archive_info() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    let file_path = create_test_file(&input_dir, "info_test.txt", b"Archive info test content");

    // Create archive
    let archive_path = temp_dir.path().join("info.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("info_pass")
        .build()
        .unwrap();

    writer.add_file(&file_path).unwrap();
    writer.finalize().unwrap();

    // Open and check header info
    let reader = ArchiveReader::open(&archive_path, "info_pass").unwrap();
    let header = reader.header();

    // Verify header is valid
    assert_eq!(&header.magic[..3], b"ERA");
    assert!(header.creation_time > 0);
}

#[test]
fn test_large_file() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    // Create a larger file (100KB) to test compression
    let content: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
    let file_path = create_test_file(&input_dir, "large.bin", &content);

    // Create archive
    let archive_path = temp_dir.path().join("large.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("large_test")
        .build()
        .unwrap();

    writer.add_file(&file_path).unwrap();
    let stats = writer.finalize().unwrap();

    assert_eq!(stats.total_size, content.len() as u64);

    // Extract and verify
    let output_dir = temp_dir.path().join("output");
    let mut reader = ArchiveReader::open(&archive_path, "large_test").unwrap();
    reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .unwrap();

    let extracted = fs::read(output_dir.join("large.bin")).unwrap();
    assert_eq!(extracted, content);
}

#[test]
fn test_binary_file() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    // Create binary file with all byte values
    let content: Vec<u8> = (0..=255).collect();
    let file_path = create_test_file(&input_dir, "binary.bin", &content);

    // Create archive
    let archive_path = temp_dir.path().join("binary.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("binary_test")
        .build()
        .unwrap();

    writer.add_file(&file_path).unwrap();
    writer.finalize().unwrap();

    // Extract and verify
    let output_dir = temp_dir.path().join("output");
    let mut reader = ArchiveReader::open(&archive_path, "binary_test").unwrap();
    reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .unwrap();

    let extracted = fs::read(output_dir.join("binary.bin")).unwrap();
    assert_eq!(extracted, content);
}

#[test]
fn test_cdc_large_file_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    // Create a file larger than CDC threshold (256KB)
    // Use semi-random content to ensure proper CDC boundary detection
    let content: Vec<u8> = (0..512 * 1024)
        .map(|i| ((i * 17 + i / 256) % 256) as u8)
        .collect();
    let file_path = create_test_file(&input_dir, "large.bin", &content);

    // Create archive with CDC enabled
    let archive_path = temp_dir.path().join("cdc_test.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("cdc_password")
        .enable_cdc(true)
        .build()
        .unwrap();

    writer.add_file(&file_path).unwrap();
    let stats = writer.finalize().unwrap();

    // The file should be chunked into multiple pieces
    assert!(stats.total_size > 0);

    // Extract archive
    let output_dir = temp_dir.path().join("output");
    let mut reader = ArchiveReader::open(&archive_path, "cdc_password").unwrap();
    let extract_stats = reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .unwrap();

    assert_eq!(extract_stats.extracted, 1);

    // Verify extracted content matches original exactly
    let extracted = fs::read(output_dir.join("large.bin")).unwrap();
    assert_eq!(extracted.len(), content.len());
    assert_eq!(extracted, content);
}

#[test]
fn test_cdc_deduplication() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    // Create content that repeats (simulating dedup opportunity)
    // 128KB block repeated 4 times = 512KB
    let block: Vec<u8> = (0..128 * 1024).map(|i| (i % 256) as u8).collect();
    let content: Vec<u8> = block.iter().cycle().take(512 * 1024).cloned().collect();
    let file_path = create_test_file(&input_dir, "repeated.bin", &content);

    // Create archive with CDC enabled
    let archive_path = temp_dir.path().join("dedup_test.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("dedup_password")
        .enable_cdc(true)
        .build()
        .unwrap();

    writer.add_file(&file_path).unwrap();
    let _stats = writer.finalize().unwrap();

    // Extract and verify
    let output_dir = temp_dir.path().join("output");
    let mut reader = ArchiveReader::open(&archive_path, "dedup_password").unwrap();
    reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .unwrap();

    let extracted = fs::read(output_dir.join("repeated.bin")).unwrap();
    assert_eq!(extracted.len(), content.len());
    assert_eq!(extracted, content);
}

#[test]
fn test_cdc_mixed_files() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    // Create a small file (should use single-chunk mode)
    let small_content = b"This is a small file under CDC threshold.";
    let small_path = create_test_file(&input_dir, "small.txt", small_content);

    // Create a large file (should use CDC chunking)
    let large_content: Vec<u8> = (0..300 * 1024)
        .map(|i| ((i * 31 + i / 128) % 256) as u8)
        .collect();
    let large_path = create_test_file(&input_dir, "large.bin", &large_content);

    // Create archive with CDC enabled
    let archive_path = temp_dir.path().join("mixed_test.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("mixed_password")
        .enable_cdc(true)
        .build()
        .unwrap();

    writer.add_file(&small_path).unwrap();
    writer.add_file(&large_path).unwrap();
    writer.finalize().unwrap();

    // Extract and verify both files
    let output_dir = temp_dir.path().join("output");
    let mut reader = ArchiveReader::open(&archive_path, "mixed_password").unwrap();
    let stats = reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .unwrap();

    assert_eq!(stats.extracted, 2);

    let extracted_small = fs::read(output_dir.join("small.txt")).unwrap();
    assert_eq!(extracted_small, small_content);

    let extracted_large = fs::read(output_dir.join("large.bin")).unwrap();
    assert_eq!(extracted_large, large_content);
}

#[test]
fn test_multifile_packing_efficiency() {
    // Test that multiple small files are packed into fewer blocks
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    // Create 100 small files (each 1KB)
    let file_count = 100;
    let file_size = 1024;
    let mut paths = Vec::new();

    for i in 0..file_count {
        let content: Vec<u8> = (0..file_size).map(|j| ((i * 17 + j) % 256) as u8).collect();
        let name = format!("file_{:03}.bin", i);
        let path = create_test_file(&input_dir, &name, &content);
        paths.push(path);
    }

    // Create archive
    let archive_path = temp_dir.path().join("packed.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("pack_test")
        .build()
        .unwrap();

    for path in &paths {
        writer.add_file(path).unwrap();
    }

    let stats = writer.finalize().unwrap();

    // With 100 files of 1KB each = 100KB total
    // Should be packed into just a few blocks (not 100 blocks!).
    // Target block size is 4MB, so data should fit in 1 block, plus
    // overhead blocks for catalog + embedded metadata/LSM manifest.
    assert!(
        stats.blocks_written <= 4,
        "Expected <=4 blocks for 100KB, got {}",
        stats.blocks_written
    );

    // Verify all files extract correctly
    let output_dir = temp_dir.path().join("output");
    let mut reader = ArchiveReader::open(&archive_path, "pack_test").unwrap();
    let extract_stats = reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .unwrap();

    assert_eq!(extract_stats.extracted, file_count as u64);

    // Verify content
    for i in 0..file_count {
        let name = format!("file_{:03}.bin", i);
        let extracted = fs::read(output_dir.join(&name)).unwrap();
        let expected: Vec<u8> = (0..file_size).map(|j| ((i * 17 + j) % 256) as u8).collect();
        assert_eq!(extracted, expected, "File {} content mismatch", name);
    }
}

// ============ Erasure Coding E2E Tests ============

#[test]
fn test_erasure_coding_roundtrip() {
    use era_common::ErasureCodeConfig;

    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    // Create test files
    let files = vec![
        ("small.txt", b"Small file content".to_vec()),
        ("medium.bin", vec![0xABu8; 10_000]),
        ("large.bin", vec![0xCDu8; 100_000]),
    ];

    for (name, content) in &files {
        create_test_file(&input_dir, name, content);
    }

    // Create archive with erasure coding (4+2 config)
    let archive_path = temp_dir.path().join("erasure.era");
    let erasure_config = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("erasure_test")
        .erasure_config(erasure_config)
        .build()
        .unwrap();

    for (name, _) in &files {
        writer.add_file(&input_dir.join(name)).unwrap();
    }

    let stats = writer.finalize().unwrap();
    assert_eq!(stats.total_files, 3);

    // Verify erasure config is stored in header
    let reader = ArchiveReader::open(&archive_path, "erasure_test").unwrap();
    let header = reader.header();
    assert!(
        header.config.erasure.is_some(),
        "Erasure config should be stored in header"
    );
    let stored_erasure = header.config.erasure.as_ref().unwrap();
    assert_eq!(stored_erasure.data_shards, 4);
    assert_eq!(stored_erasure.parity_shards, 2);
    drop(reader);

    // Extract and verify all files
    let output_dir = temp_dir.path().join("output");
    let mut reader = ArchiveReader::open(&archive_path, "erasure_test").unwrap();
    let extract_stats = reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .unwrap();

    assert_eq!(extract_stats.extracted, 3);

    for (name, content) in &files {
        let extracted = fs::read(output_dir.join(name)).unwrap();
        assert_eq!(extracted, *content, "Content mismatch for {}", name);
    }
}

#[test]
fn test_erasure_verify_integration() {
    use era_common::ErasureCodeConfig;

    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    // Create test file
    let content = vec![0xFFu8; 50_000];
    create_test_file(&input_dir, "data.bin", &content);

    // Create archive with erasure coding
    let archive_path = temp_dir.path().join("verify_erasure.era");
    let erasure_config = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("verify_test")
        .erasure_config(erasure_config)
        .build()
        .unwrap();

    writer.add_file(&input_dir.join("data.bin")).unwrap();
    writer.finalize().unwrap();

    // Verify archive integrity
    let mut reader = ArchiveReader::open(&archive_path, "verify_test").unwrap();
    let verify_stats = reader.verify().unwrap();

    assert!(
        verify_stats.is_ok(),
        "Verification should pass: {:?}",
        verify_stats.errors
    );
    assert!(verify_stats.blocks_verified > 0);
    assert_eq!(verify_stats.blocks_failed, 0);
}

#[test]
fn test_erasure_different_configs() {
    use era_common::ErasureCodeConfig;

    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    // Create test file
    let content = vec![0x42u8; 20_000];
    create_test_file(&input_dir, "test.bin", &content);

    // Test different erasure configurations
    let configs = vec![
        (2, 1), // 2+1: 50% overhead
        (4, 2), // 4+2: 50% overhead (default)
        (8, 4), // 8+4: 50% overhead
        (6, 3), // 6+3: 50% overhead
    ];

    for (data, parity) in configs {
        let archive_path = temp_dir
            .path()
            .join(format!("erasure_{}_{}.era", data, parity));
        let erasure_config = ErasureCodeConfig {
            data_shards: data,
            parity_shards: parity,
        };

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("config_test")
            .erasure_config(erasure_config)
            .build()
            .unwrap();

        writer.add_file(&input_dir.join("test.bin")).unwrap();
        writer.finalize().unwrap();

        // Verify extraction works
        let output_dir = temp_dir.path().join(format!("output_{}_{}", data, parity));
        let mut reader = ArchiveReader::open(&archive_path, "config_test").unwrap();

        // Check header
        let header = reader.header();
        let stored = header.config.erasure.as_ref().unwrap();
        assert_eq!(stored.data_shards, data);
        assert_eq!(stored.parity_shards, parity);

        // Extract and verify
        let stats = reader
            .extract_all(&ExtractOptions::new(&output_dir))
            .unwrap();
        assert_eq!(stats.extracted, 1);

        let extracted = fs::read(output_dir.join("test.bin")).unwrap();
        assert_eq!(extracted, content, "Config {}:{} failed", data, parity);
    }
}

/// Test repair on a healthy erasure archive (should report no repairs needed)
#[test]
fn test_repair_healthy_archive() {
    use era_common::ErasureCodeConfig;

    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    // Create test file
    let content = vec![0x55u8; 30_000];
    create_test_file(&input_dir, "healthy.bin", &content);

    // Create archive with erasure coding
    let archive_path = temp_dir.path().join("healthy_repair.era");
    let erasure_config = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("repair_test")
        .erasure_config(erasure_config)
        .build()
        .unwrap();

    writer.add_file(&input_dir.join("healthy.bin")).unwrap();
    writer.finalize().unwrap();

    // Run repair in dry-run mode
    let repair_options = RepairOptions {
        create_backup: false,
        dry_run: true,
        continue_on_error: true,
    };

    let stats = repair_archive(&archive_path, "repair_test", repair_options).unwrap();

    // Should find no corruption
    assert_eq!(stats.corrupted_shards_found, 0);
    assert_eq!(stats.shards_repaired, 0);
    assert_eq!(stats.unrecoverable_blocks, 0);
    assert!(stats.fully_repaired());
}

/// Test repair on non-erasure archive (should fail gracefully)
#[test]
fn test_repair_non_erasure_archive() {
    let temp_dir = TempDir::new().unwrap();

    // Create a standard archive without erasure coding
    let archive_path = temp_dir.path().join("standard.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("test_pass")
        .build()
        .unwrap();

    writer.add_bytes("test.txt", b"Hello, World!").unwrap();
    writer.finalize().unwrap();

    // Repair should fail because no erasure coding
    let repair_options = RepairOptions::default();
    let result = repair_archive(&archive_path, "test_pass", repair_options);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("erasure coding"),
        "Error should mention erasure coding: {}",
        err
    );
}

/// Test repair with wrong password (should fail)
#[test]
fn test_repair_wrong_password() {
    use era_common::ErasureCodeConfig;

    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("secure.era");

    // Create archive
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("correct_password")
        .erasure_config(ErasureCodeConfig::default())
        .build()
        .unwrap();

    writer.add_bytes("secret.txt", b"Secret data").unwrap();
    writer.finalize().unwrap();

    // Try repair with wrong password
    let result = repair_archive(&archive_path, "wrong_password", RepairOptions::default());

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("password") || err.to_string().contains("InvalidKey"),
        "Error should mention password: {}",
        err
    );
}

// TODO: Add real corruption tests that manipulate shard data correctly
// Current file-level corruption affects catalog/footer and causes bincode errors
// Need to implement precise shard-level corruption after understanding exact archive layout
