//! End-to-End Performance Benchmarks for ERA Archive System
//!
//! These benchmarks demonstrate ERA's real-world performance characteristics
//! for potential users and competitors.
//!
//! Run with: cargo bench -p era-engine --bench e2e_performance_bench

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use era_engine::{ArchiveReader, ArchiveWriter, ExtractOptions};
use std::fs;
use std::hint::black_box;
use tempfile::TempDir;

/// Create a test file with random-like content
fn create_test_data(size: usize) -> Vec<u8> {
    // Use a deterministic pattern that's not highly compressible
    (0..size)
        .map(|i| (i.wrapping_mul(17) ^ (i >> 3)) as u8)
        .collect()
}

/// Benchmark archive creation with different file sizes
fn bench_archive_creation(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let sizes = [
        (64 * 1024, "64KB"),
        (256 * 1024, "256KB"),
        (1024 * 1024, "1MB"),
        (4 * 1024 * 1024, "4MB"),
        (16 * 1024 * 1024, "16MB"),
    ];

    let mut group = c.benchmark_group("e2e_archive_create");
    group.sample_size(20);

    for (size, label) in sizes.iter() {
        let data = create_test_data(*size);
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("standard", label), &data, |b, data| {
            b.iter_with_setup(
                || TempDir::new().unwrap(),
                |temp_dir| {
                    rt.block_on(async {
                        let archive_path = temp_dir.path().join("benchmark.era");
                        let mut writer = ArchiveWriter::builder(&archive_path)
                            .password("benchmark_password")
                            .build()
                            .await
                            .unwrap();
                        writer.add_bytes("data.bin", data).await.unwrap();
                        black_box(writer.finalize().await.unwrap());
                    });
                },
            );
        });
    }

    group.finish();
}

/// Benchmark archive extraction with different file sizes
fn bench_archive_extraction(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let sizes = [
        (64 * 1024, "64KB"),
        (256 * 1024, "256KB"),
        (1024 * 1024, "1MB"),
        (4 * 1024 * 1024, "4MB"),
        (16 * 1024 * 1024, "16MB"),
    ];

    let mut group = c.benchmark_group("e2e_archive_extract");
    group.sample_size(20);

    for (size, label) in sizes.iter() {
        let data = create_test_data(*size);
        group.throughput(Throughput::Bytes(*size as u64));

        // Pre-create the archive
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("benchmark.era");
        rt.block_on(async {
            let mut writer = ArchiveWriter::builder(&archive_path)
                .password("benchmark_password")
                .build()
                .await
                .unwrap();
            writer.add_bytes("data.bin", &data).await.unwrap();
            writer.finalize().await.unwrap();
        });

        group.bench_with_input(BenchmarkId::new("standard", label), &(), |b, _| {
            b.iter_with_setup(
                || {
                    let extract_dir = temp_dir
                        .path()
                        .join(format!("extract_{}", rand::random::<u32>()));
                    fs::create_dir_all(&extract_dir).unwrap();
                    extract_dir
                },
                |extract_dir| {
                    rt.block_on(async {
                        let mut reader = ArchiveReader::open(&archive_path, "benchmark_password")
                            .await
                            .unwrap();
                        let stats = reader
                            .extract_all(&ExtractOptions::new(&extract_dir).overwrite(true))
                            .await
                            .unwrap();
                        black_box(stats);
                    });
                },
            );
        });
    }

    group.finish();
}

/// Benchmark erasure coding overhead
fn bench_erasure_overhead(c: &mut Criterion) {
    use era_common::ErasureCodeConfig;

    let rt = tokio::runtime::Runtime::new().unwrap();
    let data = create_test_data(1024 * 1024); // 1MB
    let mut group = c.benchmark_group("e2e_erasure_overhead");
    group.sample_size(20);
    group.throughput(Throughput::Bytes(data.len() as u64));

    // Standard (no erasure)
    group.bench_function("standard_1MB", |b| {
        b.iter_with_setup(
            || TempDir::new().unwrap(),
            |temp_dir| {
                rt.block_on(async {
                    let archive_path = temp_dir.path().join("benchmark.era");
                    let mut writer = ArchiveWriter::builder(&archive_path)
                        .password("benchmark_password")
                        .build()
                        .await
                        .unwrap();
                    writer.add_bytes("data.bin", &data).await.unwrap();
                    black_box(writer.finalize().await.unwrap());
                });
            },
        );
    });

    // Erasure 4+2 (50% overhead)
    group.bench_function("erasure_4_2_1MB", |b| {
        b.iter_with_setup(
            || TempDir::new().unwrap(),
            |temp_dir| {
                rt.block_on(async {
                    let archive_path = temp_dir.path().join("benchmark.era");
                    let mut writer = ArchiveWriter::builder(&archive_path)
                        .password("benchmark_password")
                        .erasure_config(ErasureCodeConfig {
                            data_shards: 4,
                            parity_shards: 2,
                        })
                        .build()
                        .await
                        .unwrap();
                    writer.add_bytes("data.bin", &data).await.unwrap();
                    black_box(writer.finalize().await.unwrap());
                });
            },
        );
    });

    // Erasure 8+4 (50% overhead, more shards)
    group.bench_function("erasure_8_4_1MB", |b| {
        b.iter_with_setup(
            || TempDir::new().unwrap(),
            |temp_dir| {
                rt.block_on(async {
                    let archive_path = temp_dir.path().join("benchmark.era");
                    let mut writer = ArchiveWriter::builder(&archive_path)
                        .password("benchmark_password")
                        .erasure_config(ErasureCodeConfig {
                            data_shards: 8,
                            parity_shards: 4,
                        })
                        .build()
                        .await
                        .unwrap();
                    writer.add_bytes("data.bin", &data).await.unwrap();
                    black_box(writer.finalize().await.unwrap());
                });
            },
        );
    });

    group.finish();
}

/// Benchmark multiple file packing efficiency
fn bench_multi_file_packing(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("e2e_multi_file");
    group.sample_size(20);

    // Simulate many small files (common scenario)
    let small_files: Vec<(String, Vec<u8>)> = (0..100)
        .map(|i| {
            (
                format!("file_{:03}.txt", i),
                create_test_data(1024 + i * 10),
            )
        })
        .collect();

    let total_size: u64 = small_files.iter().map(|(_, d)| d.len() as u64).sum();
    group.throughput(Throughput::Bytes(total_size));

    group.bench_function("100_small_files", |b| {
        b.iter_with_setup(
            || TempDir::new().unwrap(),
            |temp_dir| {
                rt.block_on(async {
                    let archive_path = temp_dir.path().join("benchmark.era");
                    let mut writer = ArchiveWriter::builder(&archive_path)
                        .password("benchmark_password")
                        .build()
                        .await
                        .unwrap();

                    for (name, data) in &small_files {
                        writer.add_bytes(name, data).await.unwrap();
                    }

                    black_box(writer.finalize().await.unwrap());
                });
            },
        );
    });

    group.finish();
}

/// Benchmark verification performance
fn bench_verification(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let sizes = [
        (256 * 1024, "256KB"),
        (1024 * 1024, "1MB"),
        (4 * 1024 * 1024, "4MB"),
    ];

    let mut group = c.benchmark_group("e2e_verification");
    group.sample_size(20);

    for (size, label) in sizes.iter() {
        let data = create_test_data(*size);
        group.throughput(Throughput::Bytes(*size as u64));

        // Pre-create archive
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("verify.era");
        rt.block_on(async {
            let mut writer = ArchiveWriter::builder(&archive_path)
                .password("verify_password")
                .build()
                .await
                .unwrap();
            writer.add_bytes("data.bin", &data).await.unwrap();
            writer.finalize().await.unwrap();
        });

        group.bench_with_input(BenchmarkId::new("verify", label), &(), |b, _| {
            b.iter(|| {
                rt.block_on(async {
                    let mut reader = ArchiveReader::open(&archive_path, "verify_password")
                        .await
                        .unwrap();
                    let stats = reader.verify().await.unwrap();
                    black_box(stats);
                });
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_archive_creation,
    bench_archive_extraction,
    bench_erasure_overhead,
    bench_multi_file_packing,
    bench_verification,
);

criterion_main!(benches);
