//! Precise fault tolerance testing

use era_common::{ArchiveConfig, CompressionAlgorithm, CompressionConfig, ErasureCodeConfig};
use era_engine::{ArchiveReader, ArchiveWriterBuilder};
use std::fs;
use tempfile::TempDir;

/// Test exact fault tolerance: can we lose N volumes and still recover?
#[tokio::test]
async fn test_precise_fault_tolerance_limits() {
    println!("\n=== PRECISE FAULT TOLERANCE TEST ===\n");

    let erasure_config = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    for volume_count in [3, 4, 6, 8].iter() {
        println!(
            "\nTest Configuration: {} volumes, 4+2 erasure",
            volume_count
        );

        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("fault_test.era");

        let config = ArchiveConfig {
            compression: CompressionConfig {
                algorithm: CompressionAlgorithm::None,
                level: 0,
            },
            ..Default::default()
        };

        // Create archive
        let mut writer = ArchiveWriterBuilder::new(&base_path)
            .config(config)
            .enable_erasure(true)
            .erasure_config(erasure_config)
            .volume_count(*volume_count)
            .enable_matrix_distribution(true)
            .build()
            .await
            .unwrap();

        let data = vec![0xAB; 256 * 1024]; // 256KB
        writer.add_bytes("test.bin", &data).await.unwrap();
        writer.finalize().await.unwrap();

        // Test losing different numbers of volumes
        for volumes_to_lose in 1..=(*volume_count - 1) {
            let test_dir = TempDir::new().unwrap();

            // Copy volumes to test directory with CORRECT naming
            for i in 0..*volume_count {
                let src = if i == 0 {
                    base_path.clone()
                } else {
                    base_path.with_extension(format!("era.{:03}", i))
                };
                // Destination must use same naming convention
                let dst = if i == 0 {
                    test_dir.path().join("test.era")
                } else {
                    test_dir
                        .path()
                        .join("test")
                        .with_extension(format!("era.{:03}", i))
                };
                if src.exists() {
                    fs::copy(&src, &dst).ok();
                }
            }

            // Delete volumes starting from index 0
            for i in 0..volumes_to_lose {
                let vol_path = if i == 0 {
                    test_dir.path().join("test.era")
                } else {
                    test_dir
                        .path()
                        .join("test")
                        .with_extension(format!("era.{:03}", i))
                };
                fs::remove_file(&vol_path).ok();
            }

            // Find first remaining volume to open
            let mut open_path = None;
            for i in 0..*volume_count {
                let vol_path = if i == 0 {
                    test_dir.path().join("test.era")
                } else {
                    test_dir
                        .path()
                        .join("test")
                        .with_extension(format!("era.{:03}", i))
                };
                if vol_path.exists() {
                    open_path = Some(vol_path);
                    break;
                }
            }

            let Some(test_path) = open_path else {
                println!(
                    "  ❌ Lost {} volumes -> NO VOLUMES REMAINING",
                    volumes_to_lose
                );
                continue;
            };

            // Debug: list files in test directory
            if volumes_to_lose == 1 {
                println!("  Files in test dir before read:");
                if let Ok(entries) = fs::read_dir(test_dir.path()) {
                    for entry in entries.flatten() {
                        println!("    {:?}", entry.path().file_name());
                    }
                }
            }

            match ArchiveReader::open(&test_path, "").await {
                Ok(mut reader) => {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        tokio::runtime::Handle::current().block_on(async {
                            reader
                                .extract_all(&era_engine::ExtractOptions::new(
                                    test_dir.path().join("extract"),
                                ))
                                .await
                        })
                    }));

                    match result {
                        Ok(Ok(_)) => {
                            println!("  ✅ Lost {} volumes -> RECOVERED", volumes_to_lose);
                        }
                        Ok(Err(_)) => {
                            println!("  ❌ Lost {} volumes -> FAILED TO RECOVER", volumes_to_lose);
                        }
                        Err(_) => {
                            println!(
                                "  ❌ Lost {} volumes -> PANIC DURING EXTRACTION",
                                volumes_to_lose
                            );
                        }
                    }
                }
                Err(_) => {
                    println!("  ❌ Lost {} volumes -> READER FAILED", volumes_to_lose);
                }
            }
        }
    }
}

/// Analyze the shard distribution pattern
#[test]
fn test_shard_distribution_pattern() {
    println!("\n=== SHARD DISTRIBUTION ANALYSIS ===\n");

    let configs = vec![
        (3, 6), // 3 volumes, 6 shards (2:1 ratio)
        (4, 6), // 4 volumes, 6 shards (1.5:1 ratio)
        (6, 6), // 6 volumes, 6 shards (1:1 ratio)
    ];

    for (volumes, total_shards) in configs {
        println!(
            "Configuration: {} volumes, {} shards",
            volumes, total_shards
        );

        // Analyze 5 blocks
        for block_seq in 0..5 {
            let mut vol_shards: Vec<Vec<usize>> = vec![Vec::new(); volumes];

            for shard_idx in 0..total_shards {
                let vol_idx = (shard_idx + block_seq) % volumes;
                vol_shards[vol_idx].push(shard_idx);
            }

            println!("  Block {}: {:?}", block_seq, vol_shards);

            // Check distribution
            let shards_per_vol: Vec<_> = vol_shards.iter().map(|v| v.len()).collect();
            println!("    Shards per volume: {:?}", shards_per_vol);
        }
        println!();
    }
}
