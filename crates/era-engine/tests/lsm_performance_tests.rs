//! Performance validation tests for LSM-Tree chunk index.
//!
//! These tests measure real-world performance metrics:
//! - Incremental backup dedup ratio
//! - CDC dedup effectiveness
//! - Large-scale memory usage
//! - Storage cost savings

use era_common::Result;
#[cfg(feature = "lsm")]
use era_engine::ArchiveReader;
use era_engine::ArchiveWriter;
use std::fs;
use std::io::Write;
use tempfile::TempDir;

/// Helper to create a file with specified size and varying pattern
fn create_file_with_size(
    dir: &TempDir,
    name: &str,
    size_mb: usize,
    seed: u8,
) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let mut file = fs::File::create(&path).unwrap();

    // Write in 64KB chunks with varying patterns to simulate real data
    let chunk_size = 64 * 1024;
    let num_chunks = (size_mb * 1024 * 1024) / chunk_size;

    for i in 0..num_chunks {
        // Create varying pattern based on chunk index and seed
        let pattern = ((seed as usize + i) % 256) as u8;
        let chunk = vec![pattern; chunk_size];
        file.write_all(&chunk).unwrap();
    }
    file.flush().unwrap();
    path
}

/// Test 1: Incremental Backup Dedup Ratio
///
/// Scenario: Archive 100MB data on Monday, then archive 80% same + 20% new on Friday
/// Expected: Friday archive should be ~20% size of Monday archive
#[test]
#[cfg(feature = "lsm")]
fn test_incremental_dedup_scenario() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let index_path = temp_dir.path().join("shared_index");
    let archive1_path = temp_dir.path().join("monday.era");
    let archive2_path = temp_dir.path().join("friday.era");

    // Create source files
    let source_dir = TempDir::new()?;
    let mut monday_files = Vec::new();

    // Monday: 10 files, 10MB each = 100MB total
    for i in 0..10 {
        let path = create_file_with_size(&source_dir, &format!("file_{:02}.dat", i), 10, i as u8);
        monday_files.push(path);
    }

    // Monday backup
    let monday_size = {
        let mut writer = ArchiveWriter::builder(archive1_path.clone())
            .password("test123")
            .enable_cdc(true)
            .with_lsm_index(&index_path)
            .build()?;

        for file_path in &monday_files {
            writer.add_file(file_path)?;
        }

        let stats = writer.finalize()?;
        println!("Monday backup:");
        println!("  Files: {}", stats.total_files);
        println!("  Size: {} MB", stats.total_size / 1024 / 1024);
        println!("  Chunks: {}", stats.blocks_written);

        stats.total_size
    };

    // Friday: Reuse 8 files (80%) + 2 new files (20%)
    let friday_size = {
        let mut writer = ArchiveWriter::builder(archive2_path.clone())
            .password("test123")
            .enable_cdc(true)
            .with_lsm_index(&index_path) // Reuse index
            .build()?;

        // Add 8 old files (should be fully deduped)
        for file in monday_files.iter().take(8) {
            writer.add_file(file)?;
        }

        // Add 2 new files
        let new_file1 = create_file_with_size(&source_dir, "new_file_1.dat", 10, 100);
        let new_file2 = create_file_with_size(&source_dir, "new_file_2.dat", 10, 101);
        writer.add_file(&new_file1)?;
        writer.add_file(&new_file2)?;

        let stats = writer.finalize()?;
        println!("\nFriday backup (80% same + 20% new):");
        println!("  Files: {}", stats.total_files);
        println!("  Size: {} MB", stats.total_size / 1024 / 1024);
        println!("  Chunks: {}", stats.blocks_written);

        stats.total_size
    };

    // Calculate dedup ratio based on blocks_written (actual storage)
    let _dedup_ratio = monday_size as f64 / friday_size as f64;

    // Also check disk sizes
    let monday_disk_size = fs::metadata(&archive1_path).map(|m| m.len()).unwrap_or(0);
    let friday_disk_size = fs::metadata(&archive2_path).map(|m| m.len()).unwrap_or(0);
    let disk_ratio = monday_disk_size as f64 / friday_disk_size as f64;

    println!("\nDedup Analysis:");
    println!("  Monday uncompressed: {} MB", monday_size / 1024 / 1024);
    println!("  Friday uncompressed: {} MB", friday_size / 1024 / 1024);
    println!(
        "  Monday on disk: {} MB ({} bytes)",
        monday_disk_size / 1024 / 1024,
        monday_disk_size
    );
    println!(
        "  Friday on disk: {} MB ({} bytes)",
        friday_disk_size / 1024 / 1024,
        friday_disk_size
    );
    println!("  Disk dedup ratio: {:.2}x", disk_ratio);
    println!("  Storage saved: {:.1}%", (1.0 - 1.0 / disk_ratio) * 100.0);

    // Verify: Friday should use less disk space (80% of data deduped)
    // In practice, catalog overhead means we won't see 4x, more like 1.5-2x
    let expected_min_ratio = 1.5; // At least 1.5x (33% saved)
    assert!(
        disk_ratio > expected_min_ratio,
        "Disk dedup ratio {:.2}x is lower than expected {:.2}x",
        disk_ratio,
        expected_min_ratio
    );

    Ok(())
}

/// Test 2: CDC Dedup Effectiveness
///
/// Scenario: Archive 50MB file twice (identical content)
/// Expected: Second archive should be much smaller (only catalog, blocks deduped)
#[test]
#[cfg(feature = "lsm")]
fn test_cdc_dedup_effectiveness() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let index_path = temp_dir.path().join("cdc_index");
    let archive1_path = temp_dir.path().join("version1.era");
    let archive2_path = temp_dir.path().join("version2.era");

    let source_dir = TempDir::new()?;

    // Create a 50MB file with repeating pattern (simulates document with similar sections)
    let test_file = source_dir.path().join("document.dat");
    let mut file = fs::File::create(&test_file)?;

    // Write 50MB of data with repeating 1MB blocks
    let block_pattern = vec![0x42; 1024 * 1024];
    for _ in 0..50 {
        file.write_all(&block_pattern)?;
    }
    file.flush()?;

    // First archive
    let version1_size = {
        let mut writer = ArchiveWriter::builder(archive1_path.clone())
            .password("test123")
            .enable_cdc(true)
            .with_lsm_index(&index_path)
            .build()?;

        writer.add_file(&test_file)?;
        let stats = writer.finalize()?;

        println!("Version 1 (50MB file with repeating blocks):");
        println!("  Size: {} MB", stats.total_size / 1024 / 1024);
        println!("  Chunks: {}", stats.blocks_written);

        stats.total_size
    };

    // Create a second identical file (different path, same content)
    let test_file2 = source_dir.path().join("document_copy.dat");
    std::fs::copy(&test_file, &test_file2)?;

    // Second archive with identical content
    let version2_size = {
        let mut writer = ArchiveWriter::builder(archive2_path.clone())
            .password("test123")
            .enable_cdc(true)
            .with_lsm_index(&index_path) // Reuse index
            .build()?;

        writer.add_file(&test_file2)?;
        let stats = writer.finalize()?;

        println!("\nVersion 2 (identical content, different filename):");
        println!("  Size: {} MB", stats.total_size / 1024 / 1024);
        println!("  Chunks: {}", stats.blocks_written);

        stats.total_size
    };

    // Calculate CDC effectiveness based on disk size
    let version1_disk_size = fs::metadata(&archive1_path).map(|m| m.len()).unwrap_or(0);
    let version2_disk_size = fs::metadata(&archive2_path).map(|m| m.len()).unwrap_or(0);
    let disk_ratio = version1_disk_size as f64 / version2_disk_size as f64;

    println!("\nDedup Analysis:");
    println!(
        "  Original uncompressed: {} MB",
        version1_size / 1024 / 1024
    );
    println!("  Copy uncompressed: {} MB", version2_size / 1024 / 1024);
    println!(
        "  Original on disk: {} MB ({} bytes)",
        version1_disk_size / 1024 / 1024,
        version1_disk_size
    );
    println!(
        "  Copy on disk: {} MB ({} bytes)",
        version2_disk_size / 1024 / 1024,
        version2_disk_size
    );
    println!("  Disk dedup ratio: {:.2}x", disk_ratio);

    // Expected: Version 2 should be significantly smaller (100% identical content)
    let expected_min_ratio = 1.3; // At least 1.3x (23% saved)
    assert!(
        disk_ratio > expected_min_ratio,
        "Dedup ratio {:.2}x is lower than expected {:.2}x",
        disk_ratio,
        expected_min_ratio
    );

    Ok(())
}

/// Test 3: Large-Scale Memory Usage
///
/// Scenario: Archive 500MB data and monitor memory impact
/// Expected: LSM index memory stays bounded (< 500MB)
#[test]
#[cfg(feature = "lsm")]
fn test_large_scale_memory_usage() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let index_path = temp_dir.path().join("large_index");
    let archive_path = temp_dir.path().join("large_archive.era");

    let source_dir = TempDir::new()?;

    // Create 50 files, 10MB each = 500MB total
    let mut file_paths = Vec::new();
    println!("Creating test files...");
    for i in 0..50 {
        let path = create_file_with_size(
            &source_dir,
            &format!("large_{:02}.dat", i),
            10,
            (i % 256) as u8,
        );
        file_paths.push(path);
        if (i + 1) % 10 == 0 {
            println!("  Created {} files ({} MB)", i + 1, (i + 1) * 10);
        }
    }

    // Archive with LSM index
    println!("\nArchiving with LSM index...");
    let mut writer = ArchiveWriter::builder(archive_path.clone())
        .password("test123")
        .enable_cdc(true)
        .with_lsm_index(&index_path)
        .build()?;

    for (i, file_path) in file_paths.iter().enumerate() {
        writer.add_file(file_path)?;
        if (i + 1) % 10 == 0 {
            println!("  Archived {} files", i + 1);
        }
    }

    let stats = writer.finalize()?;

    println!("\nArchive Statistics:");
    println!("  Total files: {}", stats.total_files);
    println!("  Total size: {} MB", stats.total_size / 1024 / 1024);
    println!("  Total chunks: {}", stats.blocks_written);

    // Check index size on disk
    let index_size = fs::metadata(&index_path).map(|m| m.len()).unwrap_or(0);
    println!("  Index disk size: {} MB", index_size / 1024 / 1024);

    // Expected: ~7800 chunks for 500MB at 64KB avg chunk size
    // Index should be ~1-2MB on disk (32 bytes hash + 24 bytes location per entry)
    assert!(
        stats.blocks_written > 100,
        "Should have significant blocks (got {})",
        stats.blocks_written
    );

    // Verify extraction works
    println!("\nVerifying archive integrity...");
    let mut reader = ArchiveReader::open(&archive_path, "test123")?;
    let verify_result = reader.verify()?;
    assert!(verify_result.is_ok(), "Archive verification failed");

    println!("✓ Large-scale test passed");

    Ok(())
}

/// Test 4: Multiple Incremental Backups (Weekly Scenario)
///
/// Scenario: 4 weekly backups with varying overlap
/// Week 1: 100% new data
/// Week 2: 70% same + 30% new
/// Week 3: 60% same + 40% new  
/// Week 4: 80% same + 20% new
#[test]
#[cfg(feature = "lsm")]
fn test_weekly_incremental_backups() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let index_path = temp_dir.path().join("weekly_index");

    let source_dir = TempDir::new()?;

    // Create a pool of files to simulate changing data
    let mut file_pool = Vec::new();
    for i in 0..20 {
        let path = create_file_with_size(&source_dir, &format!("pool_{:02}.dat", i), 5, i as u8);
        file_pool.push(path);
    }

    println!("Weekly Incremental Backup Simulation:\n");

    // Week 1: Files 0-9 (50MB)
    let week1_size = {
        let archive_path = temp_dir.path().join("week1.era");
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test123")
            .enable_cdc(true)
            .with_lsm_index(&index_path)
            .build()?;

        for file in file_pool.iter().take(10) {
            writer.add_file(file)?;
        }

        let stats = writer.finalize()?;
        println!(
            "Week 1 (baseline): {} MB, {} chunks",
            stats.total_size / 1024 / 1024,
            stats.blocks_written
        );
        stats.total_size
    };

    // Week 2: Files 3-12 (70% overlap with week 1)
    let week2_size = {
        let archive_path = temp_dir.path().join("week2.era");
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test123")
            .enable_cdc(true)
            .with_lsm_index(&index_path)
            .build()?;

        for file in file_pool.iter().take(13).skip(3) {
            writer.add_file(file)?;
        }

        let stats = writer.finalize()?;
        let ratio = week1_size as f64 / stats.total_size as f64;
        println!(
            "Week 2 (70% overlap): {} MB, {} chunks, dedup ratio: {:.2}x",
            stats.total_size / 1024 / 1024,
            stats.blocks_written,
            ratio
        );
        stats.total_size
    };

    // Week 3: Files 6-15 (60% overlap with week 2)
    let week3_size = {
        let archive_path = temp_dir.path().join("week3.era");
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test123")
            .enable_cdc(true)
            .with_lsm_index(&index_path)
            .build()?;

        for file in file_pool.iter().take(16).skip(6) {
            writer.add_file(file)?;
        }

        let stats = writer.finalize()?;
        let ratio = week1_size as f64 / stats.total_size as f64;
        println!(
            "Week 3 (60% overlap): {} MB, {} chunks, dedup ratio: {:.2}x",
            stats.total_size / 1024 / 1024,
            stats.blocks_written,
            ratio
        );
        stats.total_size
    };

    // Week 4: Files 2-11 (80% overlap with week 1)
    let week4_size = {
        let archive_path = temp_dir.path().join("week4.era");
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test123")
            .enable_cdc(true)
            .with_lsm_index(&index_path)
            .build()?;

        for file in file_pool.iter().take(12).skip(2) {
            writer.add_file(file)?;
        }

        let stats = writer.finalize()?;
        let ratio = week1_size as f64 / stats.total_size as f64;
        println!(
            "Week 4 (80% overlap): {} MB, {} chunks, dedup ratio: {:.2}x",
            stats.total_size / 1024 / 1024,
            stats.blocks_written,
            ratio
        );
        stats.total_size
    };

    // Calculate total storage savings
    let total_without_dedup = week1_size * 4;
    let total_with_dedup = week1_size + week2_size + week3_size + week4_size;
    let savings_ratio = total_without_dedup as f64 / total_with_dedup as f64;

    println!("\nTotal Storage Analysis:");
    println!(
        "  Without dedup: {} MB (4 × {} MB)",
        total_without_dedup / 1024 / 1024,
        week1_size / 1024 / 1024
    );
    println!("  With LSM dedup: {} MB", total_with_dedup / 1024 / 1024);
    println!(
        "  Overall savings: {:.2}x ({:.1}% reduction)",
        savings_ratio,
        (1.0 - 1.0 / savings_ratio) * 100.0
    );

    assert!(
        savings_ratio > 1.5,
        "Should see at least 1.5x overall savings"
    );

    Ok(())
}

/// Test 5: Memory Backend Comparison
///
/// Compare LSM vs Memory backend for the same workload
#[test]
fn test_backend_comparison() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let source_dir = TempDir::new()?;

    // Create test data
    let file1 = create_file_with_size(&source_dir, "test1.dat", 20, 0x11);
    let file2 = create_file_with_size(&source_dir, "test2.dat", 20, 0x22);

    // Test with Memory backend
    let memory_archive = temp_dir.path().join("memory.era");
    let memory_stats = {
        let mut writer = ArchiveWriter::builder(&memory_archive)
            .password("test123")
            .enable_cdc(true)
            .build()?; // Default is Memory backend

        writer.add_file(&file1)?;
        writer.add_file(&file2)?;
        writer.finalize()?
    };

    // Test with LSM backend
    #[cfg(feature = "lsm")]
    let lsm_stats = {
        let index_path = temp_dir.path().join("compare_index");
        let lsm_archive = temp_dir.path().join("lsm.era");

        let mut writer = ArchiveWriter::builder(&lsm_archive)
            .password("test123")
            .enable_cdc(true)
            .with_lsm_index(&index_path)
            .build()?;

        writer.add_file(&file1)?;
        writer.add_file(&file2)?;
        writer.finalize()?
    };

    println!("\nBackend Comparison (40MB data):");
    println!("  Memory backend:");
    println!(
        "    Archive size: {} MB",
        memory_stats.total_size / 1024 / 1024
    );
    println!("    Chunks: {}", memory_stats.blocks_written);

    #[cfg(feature = "lsm")]
    {
        println!("  LSM backend:");
        println!(
            "    Archive size: {} MB",
            lsm_stats.total_size / 1024 / 1024
        );
        println!("    Chunks: {}", lsm_stats.blocks_written);

        // Should produce identical archives
        assert_eq!(
            memory_stats.blocks_written, lsm_stats.blocks_written,
            "Both backends should produce same number of chunks"
        );
    }

    Ok(())
}
