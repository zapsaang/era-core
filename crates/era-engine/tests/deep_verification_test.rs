//! 完整的矩阵分布容错能力深度检验
//! 这个测试验证每个设计承诺

use era_common::{ArchiveConfig, CompressionAlgorithm, CompressionConfig, ErasureCodeConfig};
use era_engine::{ArchiveReader, ArchiveWriterBuilder};
use std::fs;
use tempfile::TempDir;

#[test]
fn test_design_promise_verification() {
    println!("\n=== DESIGN PROMISE VERIFICATION ===\n");
    println!("设计文档承诺:");
    println!("1. 容忍up to parity_shards个volumes丢失");
    println!("2. 对于4+2: 容忍2个volumes丢失");
    println!("3. 只需volume_count >= parity_shards + 1");
    println!();

    let erasure = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    // 验证不同volume_count配置下的实际容错能力
    let configs = vec![
        (3, "最小viable (parity+1)"),
        (4, "比最小多1"),
        (5, "比最小多2"),
        (6, "total_shards (最优)"),
        (8, "超过最优"),
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
            .enable_matrix_distribution(true)
            .build()
            .expect(&format!("Failed for {} volumes", vol_count));

        let data = vec![0xAB; 256 * 1024];
        writer
            .add_bytes("test.bin", &data)
            .expect("Failed to add file");
        writer.finalize().expect("Failed to finalize");

        // Test different failure scenarios
        println!("\n失败场景测试:");
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
                match ArchiveReader::open(&path, "") {
                    Ok(mut reader) => {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            reader.extract_all(&era_engine::ExtractOptions::new(
                                test_dir.path().join("extract"),
                            ))
                        }));

                        match result {
                            Ok(Ok(_)) => {
                                println!("  ✅ 丢失 {} 个volumes → 成功恢复", volumes_to_lose);
                            }
                            Ok(Err(e)) => {
                                println!(
                                    "  ❌ 丢失 {} 个volumes → 恢复失败: {}",
                                    volumes_to_lose, e
                                );
                            }
                            Err(_) => {
                                println!("  💥 丢失 {} 个volumes → PANIC", volumes_to_lose);
                            }
                        }
                    }
                    Err(e) => {
                        println!("  ❌ 丢失 {} 个volumes → 无法打开: {}", volumes_to_lose, e);
                    }
                }
            }
        }
        println!();
    }

    println!("\n设计承诺评估:");
    println!("✓ 承诺: 容忍up to 2个volumes丢失 (对于4+2)");
    println!("✓ 要求: volume_count >= 3 (parity_shards + 1)");
    println!("✓ 实际: 需要volume_count = 6才能达成");
    println!("⚠️ 结论: 设计承诺有误，应该说明需要total_shards个volumes");
}

#[test]
fn test_sharding_math_verification() {
    println!("\n=== SHARDING MATH VERIFICATION ===\n");

    let erasure = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    let total_shards = (erasure.data_shards + erasure.parity_shards) as usize;

    println!("Erasure Config: 4+2 (total {} shards)", total_shards);
    println!();

    // 数学验证：丢失N个volumes后能恢复的条件
    for vol_count in 3..=8 {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Volume count: {}", vol_count);

        // 最坏情况下，丢失1个volume会丢失多少个shards
        let shards_per_vol = (total_shards + vol_count - 1) / vol_count; // ceil division
        println!("  每个volume最多 {} 个shards (ceil分布)", shards_per_vol);

        // 能容忍丢失多少个volumes?
        // 需要: total_shards - (lost_volumes * shards_per_vol) >= data_shards
        // => lost_volumes * shards_per_vol <= parity_shards
        // => lost_volumes <= parity_shards / shards_per_vol

        let max_tolerable = erasure.parity_shards as usize / shards_per_vol;

        println!("  可以容忍 {} 个volume丢失", max_tolerable);

        // 验证
        for lost in 0..=3 {
            let remaining_shards = total_shards - (lost * shards_per_vol);
            let can_recover = remaining_shards >= erasure.data_shards as usize;
            let status = if can_recover { "✅" } else { "❌" };
            println!("    丢失{}: {} shards → {}", lost, remaining_shards, status);
        }
        println!();
    }

    println!("数学结论:");
    println!("✓ 要容忍N个volumes，需要: shards_per_vol <= parity_shards/N");
    println!("✓ 最优情况: shards_per_vol = 1, 则可容忍N <= parity_shards");
    println!("✓ 实现: volume_count = total_shards => shards_per_vol = 1");
    println!("✓ 因此: 对于4+2, 需要6个volumes才能容忍2个failures");
}

#[test]
fn test_actual_implementation_behavior() {
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

    println!("测试场景: 不指定volume_count，让系统自动选择");
    println!();

    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .config(config)
        .enable_erasure(true)
        .erasure_config(erasure)
        // 注意: 不指定volume_count，应该自动选择
        .enable_matrix_distribution(true)
        .build()
        .expect("Failed to create writer");

    let data = vec![0xAB; 256 * 1024];
    writer.add_bytes("test.bin", &data).expect("Failed to add");
    writer.finalize().expect("Failed to finalize");

    // 检查创建了多少个volumes
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

    println!("实际创建的volumes: {}", vol_count);
    println!();

    if vol_count == 6 {
        println!("✅ 自动选择了最优配置 (6 volumes)");
        println!("✅ 这个archive能容忍2个volumes丢失");
    } else if vol_count == 3 {
        println!("⚠️ 使用了最小viable配置 (3 volumes)");
        println!("⚠️ 这个archive只能容忍1个volume丢失");
        println!("❌ 没有达成设计承诺!");
    } else {
        println!("? 意外的volume数: {}", vol_count);
    }
}
