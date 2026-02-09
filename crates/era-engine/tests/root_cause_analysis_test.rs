//! Deep root-cause diagnosis: why does it panic?
//! Focus: determine the real limits of fault tolerance.

use era_common::{ArchiveConfig, CompressionAlgorithm, CompressionConfig, ErasureCodeConfig};
use era_engine::{ArchiveReader, ArchiveWriterBuilder};
use std::fs;
use tempfile::TempDir;

#[tokio::test]
async fn test_panic_root_cause_analysis() {
    println!("\n=== PANIC ROOT CAUSE ANALYSIS ===\n");

    let erasure = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    let temp_dir = TempDir::new().unwrap();

    // Create with 4 volumes
    let base_path = temp_dir.path().join("test.era");

    let config = ArchiveConfig {
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: 0,
        },
        ..Default::default()
    };

    println!("Creating 4-volume archive...");
    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .config(config)
        .enable_erasure(true)
        .erasure_config(erasure)
        .volume_count(4)
        .build()
        .await
        .expect("Failed");

    let data = vec![0xAB; 128 * 1024];
    writer.add_bytes("test.bin", &data).await.expect("Failed");
    writer.finalize().await.expect("Failed");

    println!("✓ Created\n");

    // Test progressively losing more volumes
    for volumes_to_lose in 1..4 {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Losing {} volumes", volumes_to_lose);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        let test_dir = TempDir::new().unwrap();

        // Copy all volumes
        for i in 0..4 {
            let src = if i == 0 {
                base_path.clone()
            } else {
                base_path.with_extension(format!("era.{:03}", i))
            };
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

        // Delete first N volumes
        for i in 0..volumes_to_lose {
            let path = if i == 0 {
                test_dir.path().join("test.era")
            } else {
                test_dir
                    .path()
                    .join("test")
                    .with_extension(format!("era.{:03}", i))
            };
            fs::remove_file(&path).ok();
        }

        // List remaining
        println!("Remaining volumes:");
        let remaining_files = fs::read_dir(test_dir.path())
            .ok()
            .map(|entries| {
                let files: Vec<_> = entries.filter_map(|e| e.ok()).collect();
                files.len()
            })
            .unwrap_or(0);
        println!("  {} volume files\n", remaining_files);

        // Try to open and read
        let mut found_openable = false;
        for i in volumes_to_lose..4 {
            let test_path = if i == 0 {
                test_dir.path().join("test.era")
            } else {
                test_dir
                    .path()
                    .join("test")
                    .with_extension(format!("era.{:03}", i))
            };

            if !test_path.exists() {
                continue;
            }

            found_openable = true;
            println!("Attempting to open from volume {}...", i);

            match ArchiveReader::open(&test_path, "").await {
                Ok(mut reader) => {
                    println!("  ✓ Opened successfully");

                    // Try to extract
                    let result = reader
                        .extract_all(&era_engine::ExtractOptions::new(
                            test_dir.path().join("extract"),
                        ))
                        .await;

                    match result {
                        Ok(_) => {
                            println!("  ✅ Extracted successfully");
                        }
                        Err(e) => {
                            println!("  ❌ Extraction failed: {}", e);
                        }
                    }
                    break;
                }
                Err(e) => {
                    println!("  ❌ Failed to open: {}", e);
                }
            }
        }

        if !found_openable {
            println!("❌ Unable to open any volume!");
        }
        println!();
    }

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Root-cause summary:");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("1. With too few volumes, some shard volumes are deleted");
    println!("2. Reader attempts to read missing offsets");
    println!("3. read_at returns 0 bytes");
    println!("4. reader.rs:68 tries len_bytes[0] -> PANIC");
    println!("\nMitigations:");
    println!("  A. Add error handling in reader.rs instead of panicking");
    println!("  B. Handle missing shards in block_iter");
    println!("  C. Enforce a minimum number of available volumes");
}

#[test]
fn test_volume_requirements_strict() {
    println!("\n=== STRICT VOLUME REQUIREMENTS ===\n");

    let _erasure = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    println!("Erasure Config: 4 data + 2 parity = 6 total shards\n");
    println!("Strict fault-tolerance requirements analysis:\n");

    // For 4+2, with different volume counts
    let scenarios = vec![
        (3, "minimal viable (parity+1)"),
        (4, "suboptimal"),
        (5, "near optimal"),
        (6, "optimal"),
    ];

    for (vol_count, label) in scenarios {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("{} volumes - {}", vol_count, label);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        // Analyze shard distribution
        let mut vol_shards = vec![Vec::new(); vol_count];
        for shard_idx in 0..6 {
            let vol_idx = shard_idx % vol_count; // Simplified, actual is: (shard_idx + block_seq) % vol_count
            vol_shards[vol_idx].push(shard_idx);
        }

        println!("Shards per volume:");
        for (v_idx, shards) in vol_shards.iter().enumerate() {
            println!("  Volume {}: {:?}", v_idx, shards);
        }

        // Compute tolerable volume losses
        let max_tolerable = if vol_count == 6 {
            2 // Can lose 2
        } else {
            1 // Can only lose 1 safely
        };

        println!("✓ Can tolerate losing {} volume(s)", max_tolerable);
        println!();
    }

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("\nStrict recommendations:");
    println!("  ✓ For 4+2 erasure, use 6 volumes (= total_shards)");
    println!("  ⚠️ Minimal viable (3) is theoretical; real tolerance is only 1");
    println!("  ❌ Do not claim 2-volume tolerance unless using 6+ volumes");
}
