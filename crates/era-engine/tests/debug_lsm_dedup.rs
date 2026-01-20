#![cfg(feature = "lsm")]
//! Simple debug test to verify LSM index dedup

use era_common::Result;
use era_engine::ArchiveWriter;
use std::fs;
use std::io::Write;
use tempfile::TempDir;

#[tokio::test]
async fn test_simple_lsm_dedup_debug() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let index_path = temp_dir.path().join("debug_index");

    // Create a simple 1MB file
    let source_dir = TempDir::new()?;
    let test_file = source_dir.path().join("test.dat");
    let mut file = fs::File::create(&test_file)?;
    file.write_all(&vec![0x42; 1024 * 1024])?; // 1MB of 0x42
    file.flush()?;

    println!("=== First archive ===");
    let archive1_path = temp_dir.path().join("archive1.era");
    let stats1 = {
        let mut writer = ArchiveWriter::builder(&archive1_path)
            .password("test")
            .with_lsm_index(&index_path)
            .build()?;

        writer.add_file(&test_file).await?;
        writer.finalize()?
    };

    println!("Archive 1:");
    println!("  Files: {}", stats1.total_files);
    println!("  Size: {} bytes", stats1.total_size);
    println!("  Blocks: {}", stats1.blocks_written);

    // Check if index directory was created and has data
    println!("\nIndex status after first archive:");
    if index_path.exists() {
        let entries: Vec<_> = fs::read_dir(&index_path)?.collect();
        println!("  Index directory exists with {} entries", entries.len());
        for entry in entries.into_iter().flatten() {
            let meta = entry.metadata()?;
            println!(
                "    {}: {} bytes",
                entry.file_name().to_string_lossy(),
                meta.len()
            );
        }
    } else {
        println!("  ❌ Index directory NOT created!");
    }

    println!("\n=== Second archive (same file) ===");
    let archive2_path = temp_dir.path().join("archive2.era");
    let stats2 = {
        let mut writer = ArchiveWriter::builder(&archive2_path)
            .password("test")
            .with_lsm_index(&index_path) // Should reuse index
            .build()?;

        writer.add_file(&test_file).await?; // Same file again
        writer.finalize()?
    };

    println!("Archive 2:");
    println!("  Files: {}", stats2.total_files);
    println!("  Size: {} bytes", stats2.total_size);
    println!("  Blocks: {}", stats2.blocks_written);

    println!("\nComparison:");
    println!("  Archive 1 size (stats): {} bytes", stats1.total_size);
    println!("  Archive 2 size (stats): {} bytes", stats2.total_size);
    println!("  Blocks 1: {}", stats1.blocks_written);
    println!("  Blocks 2: {}", stats2.blocks_written);

    // Check actual file sizes
    let archive1_disk_size = fs::metadata(&archive1_path)?.len();
    let archive2_disk_size = fs::metadata(&archive2_path)?.len();
    println!("\n  Archive 1 on disk: {} bytes", archive1_disk_size);
    println!("  Archive 2 on disk: {} bytes", archive2_disk_size);

    if stats2.blocks_written < stats1.blocks_written {
        let ratio = stats1.blocks_written as f64 / stats2.blocks_written as f64;
        println!(
            "\n✓ DEDUP WORKING at block level: {:.2}x fewer blocks",
            ratio
        );
        println!("  (total_size is uncompressed source size, not archive size)");
    } else if archive2_disk_size < archive1_disk_size {
        let ratio = archive1_disk_size as f64 / archive2_disk_size as f64;
        println!(
            "\n✓ DEDUP WORKING at disk level: {:.2}x smaller on disk",
            ratio
        );
    } else {
        println!("\n❌ DEDUP FAILED: No reduction in blocks or disk size!");
        println!("Expected: Archive 2 should have fewer blocks or be smaller on disk");
    }

    Ok(())
}
