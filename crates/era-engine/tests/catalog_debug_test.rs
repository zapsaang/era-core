//! Debug catalog recovery

use era_common::{ArchiveConfig, CompressionAlgorithm, CompressionConfig, ErasureCodeConfig};
use era_engine::{ArchiveReader, ArchiveWriterBuilder};
use std::fs;
use tempfile::TempDir;

#[tokio::test]
async fn test_catalog_recovery_debug() {
    println!("\n=== CATALOG RECOVERY DEBUG ===\n");

    let erasure_config = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().join("archive.era");

    let config = ArchiveConfig {
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: 0,
        },
        ..Default::default()
    };

    // Create archive with 4 volumes
    println!("Creating archive with 4 volumes");
    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .config(config)
        .enable_erasure(true)
        .erasure_config(erasure_config)
        .volume_count(4)
        .build()
        .await
        .expect("Failed to create writer");

    let data = vec![0xAB; 256 * 1024]; // 256KB
    writer
        .add_bytes("test.bin", &data)
        .await
        .expect("Failed to add file");
    writer.finalize().await.expect("Failed to finalize");

    // Check file sizes and structure
    println!("\nFiles created:");
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(temp_dir.path()) {
        for entry in entries.flatten() {
            let path = entry.path();
            let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            println!("  {} ({} bytes)", name, size);
            files.push((name, size, path));
        }
    }

    // Test losing 2 volumes
    println!("\n=== TEST LOSING 2 VOLUMES ===");
    println!("Deleting volume 1 and 2");
    if let Some((_, _, path)) = files.iter().find(|(name, _, _)| name == "archive.era.001") {
        fs::remove_file(path).ok();
    }
    if let Some((_, _, path)) = files.iter().find(|(name, _, _)| name == "archive.era.002") {
        fs::remove_file(path).ok();
    }

    println!("Remaining files:");
    if let Ok(entries) = fs::read_dir(temp_dir.path()) {
        for entry in entries.flatten() {
            if entry.path().is_file() {
                println!("  {:?}", entry.path().file_name());
            }
        }
    }

    println!("\nAttempting to open with archive.era (volume 0)");
    let vol0_path = temp_dir.path().join("archive.era");

    match ArchiveReader::open(&vol0_path, "").await {
        Ok(mut reader) => {
            println!("✅ Successfully opened");
            let extract_dir = temp_dir.path().join("extract_vol0");
            match reader
                .extract_all(&era_engine::ExtractOptions::new(&extract_dir))
                .await
            {
                Ok(_) => println!("✅ Successfully extracted"),
                Err(e) => println!("❌ Failed to extract: {}", e),
            }
        }
        Err(e) => {
            println!("❌ Failed: {}", e);
        }
    }

    println!("\nAttempting to open with archive.era.003 (volume 3)");
    let vol3_path = temp_dir.path().join("archive.era.003");

    match ArchiveReader::open(&vol3_path, "").await {
        Ok(mut reader) => {
            println!("✅ Successfully opened");
            let extract_dir = temp_dir.path().join("extract_vol3");
            match reader
                .extract_all(&era_engine::ExtractOptions::new(&extract_dir))
                .await
            {
                Ok(_) => println!("✅ Successfully extracted"),
                Err(e) => println!("❌ Failed to extract: {}", e),
            }
        }
        Err(e) => {
            println!("❌ Failed: {}", e);
        }
    }
}
