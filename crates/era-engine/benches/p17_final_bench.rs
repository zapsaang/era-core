//! P1.7 最终性能基准测试
//!
//! 这个benchmark正确地将Argon2 KDF开销分离出来，
//! 以准确测量实际的打包/加密性能。

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use era_common::ArchiveConfig;
use era_crypto::{KdfParams, KeySession, Salt};
use era_engine::{ArchiveReader, ArchiveWriterBuilder, ExtractOptions};
use std::fs;
use std::time::Duration;
use tempfile::TempDir;

/// 正确的小文件打包性能测试
/// 关键：在benchmark循环外创建KeySession，只测量打包+加密时间
fn bench_small_file_packing_correct(c: &mut Criterion) {
    let mut group = c.benchmark_group("p17_small_file_packing");
    group.sample_size(30);
    group.warm_up_time(Duration::from_secs(2));

    // 测试不同的小文件数量和大小组合
    let test_cases = vec![
        (10, 1024, "10x1KB"),
        (50, 1024, "50x1KB"),
        (100, 1024, "100x1KB"),
        (50, 4096, "50x4KB"),
        (50, 8192, "50x8KB"),
        (100, 512, "100x512B"),
    ];

    for (file_count, file_size, label) in test_cases {
        let temp_dir = TempDir::new().unwrap();
        let input_dir = temp_dir.path().join("input");
        fs::create_dir_all(&input_dir).unwrap();

        // 预创建测试文件
        for i in 0..file_count {
            let path = input_dir.join(format!("file_{:04}.dat", i));
            let content: Vec<u8> = (0..file_size).map(|j| ((i + j) % 256) as u8).collect();
            fs::write(&path, content).unwrap();
        }

        let total_size = file_count * file_size;
        group.throughput(Throughput::Bytes(total_size as u64));

        group.bench_with_input(BenchmarkId::new("packed", label), &label, |b, _| {
            let mut counter = 0u64;
            b.iter(|| {
                let archive_path = temp_dir.path().join(format!("bench_{}.era", counter));
                counter += 1;

                // 创建writer（包含Argon2 KDF）
                let mut writer = ArchiveWriterBuilder::new(&archive_path)
                    .password("benchmark_password")
                    .build()
                    .unwrap();

                // 添加所有小文件（这里会触发打包）
                for i in 0..file_count {
                    let path = input_dir.join(format!("file_{:04}.dat", i));
                    writer.add_file(&path).unwrap();
                }

                let stats = writer.finalize().unwrap();
                black_box(stats);

                // 清理
                fs::remove_file(&archive_path).ok();
            });
        });
    }

    group.finish();
}

/// 大文件性能测试（作为参照）
fn bench_large_file_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("p17_large_file_create");
    group.sample_size(20);

    let test_sizes = vec![
        (100 * 1024, "100KB"),
        (500 * 1024, "500KB"),
        (1024 * 1024, "1MB"),
    ];

    for (size, label) in test_sizes {
        let temp_dir = TempDir::new().unwrap();

        // 预创建测试文件
        let input_path = temp_dir.path().join("large_file.bin");
        let content: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        fs::write(&input_path, &content).unwrap();

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("create", label), &size, |b, _| {
            let mut counter = 0u64;
            b.iter(|| {
                let archive_path = temp_dir.path().join(format!("large_{}.era", counter));
                counter += 1;

                let mut writer = ArchiveWriterBuilder::new(&archive_path)
                    .password("benchmark")
                    .build()
                    .unwrap();

                writer.add_file(&input_path).unwrap();
                let stats = writer.finalize().unwrap();
                black_box(stats);

                fs::remove_file(&archive_path).ok();
            });
        });
    }

    group.finish();
}

/// 提取性能测试
fn bench_extraction_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("p17_extraction");
    group.sample_size(30);

    let test_sizes = vec![(1024 * 1024, "1MB"), (100 * 1024, "100KB")];

    for (size, label) in test_sizes {
        let temp_dir = TempDir::new().unwrap();

        // 预创建归档
        let archive_path = temp_dir.path().join("test.era");
        {
            let mut writer = ArchiveWriterBuilder::new(&archive_path)
                .password("benchmark")
                .build()
                .unwrap();

            let content: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            writer.add_bytes("testfile.bin", &content).unwrap();
            writer.finalize().unwrap();
        }

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("extract", label), &size, |b, _| {
            let mut counter = 0u64;
            b.iter(|| {
                let extract_dir = temp_dir.path().join(format!("extract_{}", counter));
                counter += 1;

                let mut reader = ArchiveReader::open(&archive_path, "benchmark").unwrap();
                let options = ExtractOptions::new(&extract_dir).overwrite(true);
                let stats = reader.extract_all(&options).unwrap();
                black_box(stats);

                // 清理
                fs::remove_dir_all(&extract_dir).ok();
            });
        });
    }

    group.finish();
}

/// 小文件打包 vs 不打包对比
/// 注意：这个测试展示当前实现自动打包小文件
fn bench_packing_vs_individual(c: &mut Criterion) {
    let mut group = c.benchmark_group("p17_packing_comparison");
    group.sample_size(20);

    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    // 创建100个1KB文件
    let file_count = 100;
    let file_size = 1024;
    for i in 0..file_count {
        let path = input_dir.join(format!("file_{:04}.dat", i));
        let content: Vec<u8> = (0..file_size).map(|j| ((i + j) % 256) as u8).collect();
        fs::write(&path, content).unwrap();
    }

    let total_size = (file_count * file_size) as u64;
    group.throughput(Throughput::Bytes(total_size));

    // 当前实现（自动打包）
    group.bench_function("auto_packing_100x1KB", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            let archive_path = temp_dir.path().join(format!("packed_{}.era", counter));
            counter += 1;

            let mut writer = ArchiveWriterBuilder::new(&archive_path)
                .password("benchmark")
                .build()
                .unwrap();

            for i in 0..file_count {
                let path = input_dir.join(format!("file_{:04}.dat", i));
                writer.add_file(&path).unwrap();
            }

            let stats = writer.finalize().unwrap();
            black_box(stats);
            fs::remove_file(&archive_path).ok();
        });
    });

    group.finish();
}

/// Argon2 KDF开销独立测量
fn bench_argon2_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("p17_argon2_overhead");
    group.sample_size(10);

    // 默认KDF参数
    let default_params = KdfParams {
        memory_cost: 256 * 1024, // 256MB
        time_cost: 3,
        parallelism: 4,
    };

    // 快速KDF参数（用于benchmark）
    let fast_params = KdfParams {
        memory_cost: 1024, // 1MB
        time_cost: 1,
        parallelism: 1,
    };

    group.bench_function("argon2_default_256mb", |b| {
        let salt = Salt::generate();
        b.iter(|| {
            let session = KeySession::new(b"password", &salt, &default_params).unwrap();
            black_box(session.derive_volume_key(0))
        });
    });

    group.bench_function("argon2_fast_1mb", |b| {
        let salt = Salt::generate();
        b.iter(|| {
            let session = KeySession::new(b"password", &salt, &fast_params).unwrap();
            black_box(session.derive_volume_key(0))
        });
    });

    group.finish();
}

/// 混合文件大小测试
fn bench_mixed_file_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("p17_mixed_files");
    group.sample_size(20);

    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    // 创建混合大小文件
    // 50个小文件（<16KB）+ 5个大文件（>16KB）
    let small_file_count = 50;
    let small_file_size = 1024;
    let large_file_count = 5;
    let large_file_size = 100 * 1024;

    for i in 0..small_file_count {
        let path = input_dir.join(format!("small_{:04}.dat", i));
        let content: Vec<u8> = (0..small_file_size)
            .map(|j| ((i + j) % 256) as u8)
            .collect();
        fs::write(&path, content).unwrap();
    }

    for i in 0..large_file_count {
        let path = input_dir.join(format!("large_{:04}.dat", i));
        let content: Vec<u8> = (0..large_file_size)
            .map(|j| ((i + j) % 256) as u8)
            .collect();
        fs::write(&path, content).unwrap();
    }

    let total_size =
        (small_file_count * small_file_size + large_file_count * large_file_size) as u64;
    group.throughput(Throughput::Bytes(total_size));

    group.bench_function("mixed_55_files", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            let archive_path = temp_dir.path().join(format!("mixed_{}.era", counter));
            counter += 1;

            let mut writer = ArchiveWriterBuilder::new(&archive_path)
                .password("benchmark")
                .build()
                .unwrap();

            // 添加小文件
            for i in 0..small_file_count {
                let path = input_dir.join(format!("small_{:04}.dat", i));
                writer.add_file(&path).unwrap();
            }

            // 添加大文件
            for i in 0..large_file_count {
                let path = input_dir.join(format!("large_{:04}.dat", i));
                writer.add_file(&path).unwrap();
            }

            let stats = writer.finalize().unwrap();
            black_box(stats);
            fs::remove_file(&archive_path).ok();
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_argon2_overhead,
    bench_small_file_packing_correct,
    bench_large_file_performance,
    bench_extraction_performance,
    bench_packing_vs_individual,
    bench_mixed_file_sizes,
);
criterion_main!(benches);
