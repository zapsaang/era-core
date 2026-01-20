#![cfg(feature = "lsm")]
//! Minimal debug test to trace CDC path

use era_common::Result;
use era_engine::ArchiveWriter;
use era_ingest::ChunkerConfig;
use std::fs;
use tempfile::TempDir;

#[tokio::test]
async fn test_debug_cdc_path() -> Result<()> {
    let temp = TempDir::new()?;
    let data_dir = temp.path().join("data");
    let index_dir = temp.path().join("index");
    fs::create_dir_all(&data_dir)?;

    // Create 10MB file with INCOMPRESSIBLE random data
    let file_path = data_dir.join("testfile.bin");
    let file_size = 10 * 1024 * 1024;

    // Read from /dev/urandom for true random incompressible data
    let mut urandom = fs::File::open("/dev/urandom")?;
    use std::io::Read;
    let mut data = vec![0u8; file_size];
    urandom.read_exact(&mut data)?;

    fs::write(&file_path, &data)?;

    println!("\nFile size: {:.2} MB", file_size as f64 / 1024.0 / 1024.0);

    // Create writer with CDC explicitly enabled
    let archive_file = temp.path().join("test.era");
    let mut writer = ArchiveWriter::builder(&archive_file)
        .password("test123")
        .enable_cdc(true)
        .chunker_config(ChunkerConfig::default())
        .with_lsm_index(&index_dir)
        .build()?;

    println!("CDC enabled in writer");

    writer.add_file(&file_path).await?;
    let stats = writer.finalize()?;

    let disk_size = fs::metadata(&archive_file)?.len();

    println!("\nResults:");
    println!("Blocks written: {}", stats.blocks_written);
    println!("Disk size: {:.2} MB", disk_size as f64 / 1024.0 / 1024.0);
    println!(
        "Avg block size: {:.2} KB\n",
        (disk_size as f64 / stats.blocks_written as f64) / 1024.0
    );

    // Expected: ~160 chunks at 64KB avg
    if stats.blocks_written < 50 {
        eprintln!(
            "❌ CDC NOT WORKING: only {} blocks for 10MB file",
            stats.blocks_written
        );
        eprintln!("This suggests the file is being treated as a single unit");
    } else {
        println!("✓ CDC working: {} chunks produced", stats.blocks_written);
    }

    Ok(())
}
