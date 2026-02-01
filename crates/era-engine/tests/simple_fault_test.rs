//! Simple fault tolerance test

use era_common::{ArchiveConfig, CompressionAlgorithm, CompressionConfig, ErasureCodeConfig};
use era_engine::{ArchiveReader, ArchiveWriterBuilder};
use std::fs;
use tempfile::TempDir;

#[tokio::test]
async fn test_simple_multivolume_read() {
    println!("\n=== SIMPLE MULTIVOLUME READ TEST ===\n");

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

    // Create archive with 3 volumes
    println!("Creating archive at: {}", base_path.display());
    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .config(config)
        .enable_erasure(true)
        .erasure_config(erasure_config)
        .volume_count(3)
        .enable_matrix_distribution(true)
        .build()
        .await
        .expect("Failed to create writer");

    let data = vec![0xAB; 256 * 1024]; // 256KB
    writer
        .add_bytes("test.bin", &data)
        .await
        .expect("Failed to add file");
    writer.finalize().await.expect("Failed to finalize");

    // Check created files
    println!("\nFiles created:");
    if let Ok(entries) = fs::read_dir(temp_dir.path()) {
        for entry in entries.flatten() {
            let path = entry.path();
            let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            println!("  {:?} ({} bytes)", path.file_name(), size);
        }
    }

    // Try to read with all volumes
    println!("\nTest 1: Reading with all 3 volumes");
    match ArchiveReader::open(&base_path, "").await {
        Ok(mut reader) => {
            println!("✅ Successfully opened archive with 3 volumes");
            match reader
                .extract_all(&era_engine::ExtractOptions::new(
                    temp_dir.path().join("extract1"),
                ))
                .await
            {
                Ok(_) => println!("✅ Successfully extracted with 3 volumes"),
                Err(e) => println!("❌ Failed to extract: {}", e),
            }
        }
        Err(e) => println!("❌ Failed to open archive: {}", e),
    }

    // Try to read with 2 volumes (delete one)
    println!("\nTest 2: Reading with 2 volumes (delete volume 0)");
    let vol0_path = temp_dir.path().join("archive.era");
    fs::remove_file(&vol0_path).expect("Failed to delete volume 0");

    // List remaining files
    println!("  Remaining files:");
    if let Ok(entries) = fs::read_dir(temp_dir.path()) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                println!("    {:?}", path.file_name());
            }
        }
    }

    // Use first remaining volume to open - this should find all available volumes
    let vol1_path = temp_dir.path().join("archive.era.001");
    match ArchiveReader::open(&vol1_path, "").await {
        Ok(mut reader) => {
            println!("✅ Successfully opened archive with 2 volumes");
            match reader
                .extract_all(&era_engine::ExtractOptions::new(
                    temp_dir.path().join("extract2"),
                ))
                .await
            {
                Ok(_) => println!("✅ Successfully extracted with 2 volumes"),
                Err(e) => println!("❌ Failed to extract: {}", e),
            }
        }
        Err(e) => println!("❌ Failed to open archive: {}", e),
    }
}
