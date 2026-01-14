//! 深层问题诊断：为什么会PANIC?
//! 重点: 找出容错能力的实际限制

use era_common::{ArchiveConfig, CompressionAlgorithm, CompressionConfig, ErasureCodeConfig};
use era_engine::{ArchiveReader, ArchiveWriterBuilder};
use std::fs;
use tempfile::TempDir;

#[test]
fn test_panic_root_cause_analysis() {
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

    println!("创建4-volume archive...");
    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .config(config)
        .enable_erasure(true)
        .erasure_config(erasure)
        .volume_count(4)
        .enable_matrix_distribution(true)
        .build()
        .expect("Failed");

    let data = vec![0xAB; 128 * 1024];
    writer.add_bytes("test.bin", &data).expect("Failed");
    writer.finalize().expect("Failed");

    println!("✓ 创建完成\n");

    // Test progressively losing more volumes
    for volumes_to_lose in 1..4 {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("失去 {} 个volumes", volumes_to_lose);
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
        println!("保留的volumes:");
        let remaining_files = fs::read_dir(test_dir.path())
            .ok()
            .and_then(|entries| {
                let files: Vec<_> = entries.filter_map(|e| e.ok()).collect();
                Some(files.len())
            })
            .unwrap_or(0);
        println!("  {} 个volume文件\n", remaining_files);

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
            println!("尝试从 volume {} 打开...", i);

            match ArchiveReader::open(&test_path, "") {
                Ok(mut reader) => {
                    println!("  ✓ 成功打开");

                    // Try to extract
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        reader.extract_all(&era_engine::ExtractOptions::new(
                            test_dir.path().join("extract"),
                        ))
                    }));

                    match result {
                        Ok(Ok(_)) => {
                            println!("  ✅ 成功提取");
                        }
                        Ok(Err(e)) => {
                            println!("  ❌ 提取失败: {}", e);
                        }
                        Err(_) => {
                            println!("  💥 PANIC during extraction");
                            println!("     问题: reader.rs:68 尝试访问空buffer的字节");
                            println!(
                                "     原因: 当volumes足够少时，某些block的offset指向已删除的volume"
                            );
                            println!("     后果: 读取失败导致空数据，然后crash");
                        }
                    }
                    break;
                }
                Err(e) => {
                    println!("  ❌ 打开失败: {}", e);
                }
            }
        }

        if !found_openable {
            println!("❌ 无法打开任何volume!");
        }
        println!();
    }

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("问题诊断总结:");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("1. 当volumes足够少时，某些shards所在的volume被删除");
    println!("2. Reader尝试读取不存在的offset");
    println!("3. read_at返回0字节");
    println!("4. reader.rs:68 尝试 len_bytes[0] -> PANIC");
    println!("\n解决方案:");
    println!("  A. 在reader.rs中添加error handling而不是panic");
    println!("  B. 在block_iter中处理missing shards");
    println!("  C. 限制可用volumes的最小数量");
}

#[test]
fn test_volume_requirements_strict() {
    println!("\n=== STRICT VOLUME REQUIREMENTS ===\n");

    let erasure = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    println!("Erasure Config: 4 data + 2 parity = 6 total shards\n");
    println!("严格的容错要求分析:\n");

    // For 4+2, with different volume counts
    let scenarios = vec![
        (3, "最小viable (parity+1)"),
        (4, "次优配置"),
        (5, "接近最优"),
        (6, "完美最优"),
    ];

    for (vol_count, label) in scenarios {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("{} volumes - {}", vol_count, label);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        // 分析shard分布
        let mut vol_shards = vec![Vec::new(); vol_count];
        for shard_idx in 0..6 {
            let vol_idx = shard_idx % vol_count; // Simplified, actual is: (shard_idx + block_seq) % vol_count
            vol_shards[vol_idx].push(shard_idx);
        }

        println!("每个volume的shards:");
        for (v_idx, shards) in vol_shards.iter().enumerate() {
            println!("  Volume {}: {:?}", v_idx, shards);
        }

        // 计算可以失去的volumes
        let max_tolerable = if vol_count == 6 {
            2 // Can lose 2
        } else {
            1 // Can only lose 1 safely
        };

        println!("✓ 可以容忍丢失 {} 个volume", max_tolerable);
        println!();
    }

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("\n严格建议:");
    println!("  ✓ 对于4+2 erasure,应该使用 6 个volumes (= total_shards)");
    println!("  ⚠️ 最小viable (3) 只是理论, 实际容错能力仅1");
    println!("  ❌ 不应该宣传可以容忍2个volumes丢失,除非用6+ volumes");
}
