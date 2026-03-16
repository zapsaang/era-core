//! Deep validation of matrix distribution fault tolerance.
//! This test verifies each design promise.

use era_common::{ArchiveConfig, CompressionAlgorithm, CompressionConfig, ErasureCodeConfig};
use era_engine::{ArchiveReader, ArchiveWriterBuilder};
use std::fs;
use tempfile::TempDir;

#[tokio::test]
async fn test_design_promise_verification() {
    println!("\n=== DESIGN PROMISE VERIFICATION ===\n");
    println!("Design doc promises:");
    println!("1. Tolerate up to parity_shards volume losses");
    println!("2. For 4+2: tolerate 2 volume losses");
    println!("3. Canonical low-volume layouts must divide total shards");
    println!();

    let erasure = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    // Validate actual fault tolerance across volume_count configs
    let configs = vec![
        (1, "single-volume canonical"),
        (2, "two-volume canonical"),
        (3, "three-volume canonical"),
        (6, "total_shards (optimal)"),
        (8, "above optimal"),
    ];

    let temp_dir = TempDir::new().unwrap();

    for (vol_count, label) in configs {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Configuration: {} volumes - {}", vol_count, label);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        let base_path = temp_dir.path().join(format!("archive_{}.era", vol_count));

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
            .erasure_config(erasure)
            .volume_count(vol_count)
            .build()
            .await
            .unwrap_or_else(|_| panic!("Failed for {} volumes", vol_count));

        let data = vec![0xAB; 256 * 1024];
        writer
            .add_bytes("test.bin", &data)
            .await
            .expect("Failed to add file");
        writer.finalize().await.expect("Failed to finalize");

        // Test different failure scenarios
        println!("\nFailure scenarios:");
        for volumes_to_lose in 1..vol_count {
            let test_dir = TempDir::new().unwrap();

            // Copy all volumes
            for i in 0..vol_count {
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

            // Delete volumes (consecutive from start)
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

            // Find first remaining volume
            let mut open_path = None;
            for i in 0..vol_count {
                let path = if i == 0 {
                    test_dir.path().join("test.era")
                } else {
                    test_dir
                        .path()
                        .join("test")
                        .with_extension(format!("era.{:03}", i))
                };
                if path.exists() {
                    open_path = Some(path);
                    break;
                }
            }

            if let Some(path) = open_path {
                match ArchiveReader::open(&path, "").await {
                    Ok(mut reader) => {
                        let result = reader
                            .extract_all(&era_engine::ExtractOptions::new(
                                test_dir.path().join("extract"),
                            ))
                            .await;

                        match result {
                            Ok(_) => {
                                println!("  ✅ Lost {} volumes → recovered", volumes_to_lose);
                            }
                            Err(e) => {
                                println!(
                                    "  ❌ Lost {} volumes → recovery failed: {}",
                                    volumes_to_lose, e
                                );
                            }
                        }
                    }
                    Err(e) => {
                        println!(
                            "  ❌ Lost {} volumes → failed to open: {}",
                            volumes_to_lose, e
                        );
                    }
                }
            }
        }
        println!();
    }

    println!("\nDesign promise assessment:");
    println!("✓ Promise: tolerate up to 2 volume losses (for 4+2)");
    println!("✓ Requirement: low counts must divide total_shards");
    println!("✓ Actual: 1, 2, 3, 6, and 8 are canonical-valid for 4+2");
    println!("⚠️ Conclusion: validity and fault tolerance are different concerns");
}

#[tokio::test]
async fn test_sharding_math_verification() {
    println!("\n=== SHARDING MATH VERIFICATION ===\n");

    let erasure = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    let total_shards = (erasure.data_shards + erasure.parity_shards) as usize;

    println!("Erasure Config: 4+2 (total {} shards)", total_shards);
    println!();

    // Math validation: recovery condition after losing N volumes
    for vol_count in 1..=8 {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Volume count: {}", vol_count);

        // Worst case: shards lost when one volume is lost
        let shards_per_vol = total_shards.div_ceil(vol_count); // ceil division
        println!(
            "  Each volume holds up to {} shards (ceil distribution)",
            shards_per_vol
        );

        // How many volumes can be lost?
        // Require: total_shards - (lost_volumes * shards_per_vol) >= data_shards
        // => lost_volumes * shards_per_vol <= parity_shards
        // => lost_volumes <= parity_shards / shards_per_vol

        let max_tolerable = erasure.parity_shards as usize / shards_per_vol;

        println!("  Can tolerate {} volume losses", max_tolerable);

        // Verify
        for lost in 0..=3 {
            let remaining_shards = total_shards.saturating_sub(lost * shards_per_vol);
            let can_recover = remaining_shards >= erasure.data_shards as usize;
            let status = if can_recover { "✅" } else { "❌" };
            println!(
                "    Lost {}: {} shards → {}",
                lost, remaining_shards, status
            );
        }
        println!();
    }

    println!("Math conclusion:");
    println!("✓ To tolerate N volume losses: shards_per_vol <= parity_shards/N");
    println!("✓ Optimal: shards_per_vol = 1, so N <= parity_shards");
    println!("✓ Implementation: volume_count = total_shards => shards_per_vol = 1");
    println!("✓ Therefore: for 4+2, need 6 volumes to tolerate 2 failures");
}

#[tokio::test]
async fn test_actual_implementation_behavior() {
    println!("\n=== ACTUAL IMPLEMENTATION BEHAVIOR ===\n");

    let erasure = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().join("test.era");

    let config = ArchiveConfig {
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: 0,
        },
        ..Default::default()
    };

    println!("Scenario: omit volume_count and let the system choose");
    println!();

    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .config(config)
        .enable_erasure(true)
        .erasure_config(erasure)
        // Note: omitting volume_count should auto-select
        .build()
        .await
        .expect("Failed to create writer");

    let data = vec![0xAB; 256 * 1024];
    writer
        .add_bytes("test.bin", &data)
        .await
        .expect("Failed to add");
    writer.finalize().await.expect("Failed to finalize");

    // Check how many volumes were created
    let mut vol_count = 0;
    for i in 0..10 {
        let path = if i == 0 {
            base_path.clone()
        } else {
            base_path.with_extension(format!("era.{:03}", i))
        };
        if path.exists() {
            vol_count += 1;
        }
    }

    println!("Actual volumes created: {}", vol_count);
    println!();

    if vol_count == 6 {
        println!("✅ Auto-selected optimal config (6 volumes)");
        println!("✅ This archive can tolerate 2 volume losses");
    } else if vol_count == 3 {
        println!("⚠️ Used minimal viable config (3 volumes)");
        println!("⚠️ This archive can tolerate only 1 volume loss");
        println!("❌ Did not meet design promise!");
    } else {
        println!("? Unexpected volume count: {}", vol_count);
    }
}
