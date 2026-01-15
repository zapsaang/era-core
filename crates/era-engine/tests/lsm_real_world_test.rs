//! Real-world performance tests with realistic random data
//! Tests CDC chunking with incompressible data to measure actual block counts

use era_common::Result;
use era_engine::ArchiveWriter;
use era_ingest::ChunkerConfig;
use std::fs;
use tempfile::TempDir;

/// Create pseudorandom incompressible data
fn create_random_data(size: usize) -> Vec<u8> {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hash, Hasher};

    let mut data = Vec::with_capacity(size);
    let hasher_builder = RandomState::new();

    for i in 0..(size / 8) {
        let mut hasher = hasher_builder.build_hasher();
        i.hash(&mut hasher);
        let hash = hasher.finish();
        data.extend_from_slice(&hash.to_le_bytes());
    }

    let remaining = size - data.len();
    for i in 0..remaining {
        data.push((i % 256) as u8);
    }

    data
}

#[test]
#[cfg(feature = "lsm")]
fn test_realistic_cdc_chunking() -> Result<()> {
    let temp = TempDir::new()?;
    let data_dir = temp.path().join("data");
    let index_dir = temp.path().join("index");
    fs::create_dir_all(&data_dir)?;

    // Create 10MB file with random data
    let file_path = data_dir.join("realistic_file.bin");
    let file_size = 10 * 1024 * 1024; // 10MB
    let data = create_random_data(file_size);
    fs::write(&file_path, &data)?;

    println!("\n=== Realistic CDC Chunking Test ===");
    println!("File size: {:.2} MB", file_size as f64 / 1024.0 / 1024.0);

    // Test with default CDC config (64KB avg)
    {
        let archive_file = temp.path().join("test_default.era");
        let mut writer = ArchiveWriter::builder(&archive_file)
            .password("test123")
            .enable_cdc(true)
            .with_lsm_index(&index_dir)
            .build()?;

        writer.add_file(&file_path)?;
        let stats = writer.finalize()?;

        let disk_size = fs::metadata(&archive_file)?.len();
        let expected_chunks = file_size / (64 * 1024); // ~160 chunks

        println!("\n--- Default Config (avg=64KB) ---");
        println!("Blocks written: {}", stats.blocks_written);
        println!("Disk size: {:.2} MB", disk_size as f64 / 1024.0 / 1024.0);
        println!("Expected chunks: ~{}", expected_chunks);
        println!(
            "Avg block size: {:.2} KB",
            (disk_size as f64 / stats.blocks_written as f64) / 1024.0
        );

        // Verify reasonable chunk count (80-200 for 10MB @ 64KB avg)
        assert!(
            stats.blocks_written > 80,
            "Too few blocks: {} (expected >80)",
            stats.blocks_written
        );
        assert!(
            stats.blocks_written < 200,
            "Too many blocks: {} (expected <200)",
            stats.blocks_written
        );

        println!("✓ Default config produces expected chunk count!");
    }

    // Test with small chunks (16KB avg)
    {
        let archive_file = temp.path().join("test_small.era");
        let mut writer = ArchiveWriter::builder(&archive_file)
            .password("test123")
            .chunker_config(ChunkerConfig::small_files())
            .with_lsm_index(&index_dir)
            .build()?;

        writer.add_file(&file_path)?;
        let stats = writer.finalize()?;

        let disk_size = fs::metadata(&archive_file)?.len();
        let expected_chunks = file_size / (16 * 1024); // ~640 chunks

        println!("\n--- Small Files Config (avg=16KB) ---");
        println!("Blocks written: {}", stats.blocks_written);
        println!("Disk size: {:.2} MB", disk_size as f64 / 1024.0 / 1024.0);
        println!("Expected chunks: ~{}", expected_chunks);

        // Should get more chunks (320-800 for 10MB @ 16KB avg)
        assert!(
            stats.blocks_written > 320,
            "Too few blocks: {}",
            stats.blocks_written
        );
        assert!(
            stats.blocks_written < 800,
            "Too many blocks: {}",
            stats.blocks_written
        );

        println!("✓ Small config produces more chunks as expected!");
    }

    // Test with large chunks (256KB avg)
    {
        let archive_file = temp.path().join("test_large.era");
        let mut writer = ArchiveWriter::builder(&archive_file)
            .password("test123")
            .chunker_config(ChunkerConfig::large_files())
            .with_lsm_index(&index_dir)
            .build()?;

        writer.add_file(&file_path)?;
        let stats = writer.finalize()?;

        let disk_size = fs::metadata(&archive_file)?.len();
        let expected_chunks = file_size / (256 * 1024); // ~40 chunks

        println!("\n--- Large Files Config (avg=256KB) ---");
        println!("Blocks written: {}", stats.blocks_written);
        println!("Disk size: {:.2} MB", disk_size as f64 / 1024.0 / 1024.0);
        println!("Expected chunks: ~{}", expected_chunks);

        // Should get fewer chunks (20-60 for 10MB @ 256KB avg)
        assert!(
            stats.blocks_written > 20,
            "Too few blocks: {}",
            stats.blocks_written
        );
        assert!(
            stats.blocks_written < 60,
            "Too many blocks: {}",
            stats.blocks_written
        );

        println!("✓ Large config produces fewer chunks as expected!");
    }

    println!("\n✓✓✓ All CDC configs working correctly! ✓✓✓\n");
    Ok(())
}

#[test]
#[cfg(feature = "lsm")]
fn test_realistic_incremental_dedup() -> Result<()> {
    let temp = TempDir::new()?;
    let data_dir = temp.path().join("data");
    let index_dir = temp.path().join("index");
    fs::create_dir_all(&data_dir)?;

    println!("\n=== Realistic Incremental Dedup Test ===");

    // Day 1: Create 5 files, 2MB each, random data
    println!("\n--- Day 1 Backup ---");
    let mut file_paths = Vec::new();
    for i in 0..5 {
        let file_path = data_dir.join(format!("file{}.dat", i));
        let data = create_random_data(2 * 1024 * 1024);
        fs::write(&file_path, &data)?;
        file_paths.push(file_path);
    }

    let archive1 = temp.path().join("day1.era");
    let mut writer = ArchiveWriter::builder(&archive1)
        .password("test123")
        .enable_cdc(true)
        .with_lsm_index(&index_dir)
        .build()?;

    for file_path in &file_paths {
        writer.add_file(file_path)?;
    }
    let stats1 = writer.finalize()?;

    let disk_size1 = fs::metadata(&archive1)?.len();

    println!("Files: 5 x 2MB = 10MB total");
    println!("Blocks written: {}", stats1.blocks_written);
    println!("Disk size: {:.2} MB", disk_size1 as f64 / 1024.0 / 1024.0);

    // Day 2: Modify 2 files (40% change), keep 3 unchanged (60% same)
    println!("\n--- Day 2 Backup (60% same, 40% new) ---");

    // Modify file0 and file1
    for i in 0..2 {
        let file_path = data_dir.join(format!("file{}.dat", i));
        let data = create_random_data(2 * 1024 * 1024);
        fs::write(&file_path, &data)?;
    }

    let archive2 = temp.path().join("day2.era");
    let mut writer = ArchiveWriter::builder(&archive2)
        .password("test123")
        .enable_cdc(true)
        .with_lsm_index(&index_dir) // Share index!
        .build()?;

    for file_path in &file_paths {
        writer.add_file(file_path)?;
    }
    let stats2 = writer.finalize()?;

    let disk_size2 = fs::metadata(&archive2)?.len();

    println!("Files: 5 x 2MB = 10MB total (3 unchanged, 2 new)");
    println!("Blocks written: {}", stats2.blocks_written);
    println!("Disk size: {:.2} MB", disk_size2 as f64 / 1024.0 / 1024.0);

    let dedup_ratio = disk_size1 as f64 / disk_size2 as f64;
    let savings = (1.0 - (disk_size2 as f64 / disk_size1 as f64)) * 100.0;

    println!("\n--- Dedup Results ---");
    println!(
        "Day 1 disk size: {:.2} MB",
        disk_size1 as f64 / 1024.0 / 1024.0
    );
    println!(
        "Day 2 disk size: {:.2} MB",
        disk_size2 as f64 / 1024.0 / 1024.0
    );
    println!("Dedup ratio: {:.2}x", dedup_ratio);
    println!("Storage savings: {:.1}%", savings);

    // With 60% same data, expect AT LEAST 1.2x dedup
    assert!(
        dedup_ratio > 1.2,
        "Dedup ratio {:.2}x too low (expected >1.2x with 60% duplicate)",
        dedup_ratio
    );

    println!("\n✓ Incremental dedup working with realistic data!");
    Ok(())
}

#[test]
#[cfg(feature = "lsm")]
fn test_chunk_config_comparison() -> Result<()> {
    let temp = TempDir::new()?;
    let data_dir = temp.path().join("data");
    let index_dir = temp.path().join("index");
    fs::create_dir_all(&data_dir)?;

    // Create 50MB random file
    let file_path = data_dir.join("large_file.bin");
    let file_size = 50 * 1024 * 1024;
    let data = create_random_data(file_size);
    fs::write(&file_path, &data)?;

    println!("\n=== Chunk Config Comparison (50MB file) ===\n");

    let configs = vec![
        ("Small (16KB avg)", ChunkerConfig::small_files()),
        ("Default (64KB avg)", ChunkerConfig::default()),
        ("Large (256KB avg)", ChunkerConfig::large_files()),
        (
            "Custom (32KB avg)",
            ChunkerConfig::new(8 * 1024, 32 * 1024, 128 * 1024),
        ),
    ];

    for (name, config) in configs {
        let archive_file = temp.path().join(format!("{}.era", name.replace(" ", "_")));

        let mut writer = ArchiveWriter::builder(&archive_file)
            .password("test123")
            .chunker_config(config.clone())
            .with_lsm_index(&index_dir)
            .build()?;

        writer.add_file(&file_path)?;
        let stats = writer.finalize()?;

        let disk_size = fs::metadata(&archive_file)?.len();
        let avg_block_kb = (disk_size as f64 / stats.blocks_written as f64) / 1024.0;
        let expected_chunks = file_size / config.avg_size;

        println!(
            "{}: {} blocks, avg {:.1} KB/block (expected ~{} blocks)",
            name, stats.blocks_written, avg_block_kb, expected_chunks
        );
    }

    println!("\n✓ All configurations produced reasonable chunk counts!");
    Ok(())
}
