//! End-to-end benchmarks for the ERA engine.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use era_engine::{ArchiveReader, ArchiveWriterBuilder, ExtractOptions};
use std::fs;
use std::sync::atomic::{AtomicU32, Ordering};
use tempfile::TempDir;

/// Atomic counter for unique output directories
static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Create test files with the specified total size
fn create_test_files(dir: &std::path::Path, file_count: usize, file_size: usize) {
    for i in 0..file_count {
        let file_path = dir.join(format!("file_{}.bin", i));
        let data: Vec<u8> = (0..file_size).map(|j| ((i + j) % 256) as u8).collect();
        fs::write(&file_path, &data).unwrap();
    }
}

/// Create a fast KDF config for benchmarking
fn fast_kdf_config() -> era_common::ArchiveConfig {
    let mut config = era_common::ArchiveConfig::default();
    config.encryption.kdf_memory_cost = 1024;
    config.encryption.kdf_time_cost = 1;
    config
}

fn bench_archive_creation(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("archive_creation");

    // Test different file sizes
    for file_size in [1024, 10 * 1024, 100 * 1024] {
        group.throughput(Throughput::Bytes(file_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", file_size / 1024)),
            &file_size,
            |b, &size| {
                b.iter_with_setup(
                    || {
                        let temp_dir = TempDir::new().unwrap();
                        let input_dir = temp_dir.path().join("input");
                        fs::create_dir_all(&input_dir).unwrap();
                        create_test_files(&input_dir, 1, size);
                        temp_dir
                    },
                    |temp_dir| {
                        let input_dir = temp_dir.path().join("input");
                        let archive_path = temp_dir.path().join("test.era");

                        let mut writer = ArchiveWriterBuilder::new(&archive_path)
                            .password("benchmark_password")
                            .config(fast_kdf_config())
                            .build()
                            .unwrap();

                        let file_path = input_dir.join("file_0.bin");
                        rt.block_on(async {
                            writer.add_file(&file_path).await.unwrap();
                        });
                        writer.finalize().unwrap();

                        black_box(archive_path)
                    },
                );
            },
        );
    }

    group.finish();
}

fn bench_archive_extraction(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("archive_extraction");

    for file_size in [1024, 10 * 1024, 100 * 1024] {
        group.throughput(Throughput::Bytes(file_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", file_size / 1024)),
            &file_size,
            |b, &size| {
                // Setup: create archive once
                let temp_dir = TempDir::new().unwrap();
                let input_dir = temp_dir.path().join("input");
                fs::create_dir_all(&input_dir).unwrap();
                create_test_files(&input_dir, 1, size);

                let archive_path = temp_dir.path().join("test.era");
                let mut writer = ArchiveWriterBuilder::new(&archive_path)
                    .password("benchmark_password")
                    .config(fast_kdf_config())
                    .build()
                    .unwrap();

                let file_path = input_dir.join("file_0.bin");
                rt.block_on(async {
                    writer.add_file(&file_path).await.unwrap();
                });
                writer.finalize().unwrap();

                // Benchmark extraction
                b.iter(|| {
                    let count = COUNTER.fetch_add(1, Ordering::SeqCst);
                    let output_dir = temp_dir.path().join(format!("output_{}", count));
                    fs::create_dir_all(&output_dir).unwrap();

                    let mut reader =
                        ArchiveReader::open(&archive_path, "benchmark_password").unwrap();
                    let options = ExtractOptions::new(&output_dir).overwrite(true);
                    reader.extract_all(&options).unwrap();

                    black_box(output_dir)
                });
            },
        );
    }

    group.finish();
}

fn bench_multiple_files(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("multiple_files");

    for file_count in [1, 5, 10, 20] {
        let file_size = 10 * 1024; // 10KB each
        let total_size = file_count * file_size;

        group.throughput(Throughput::Bytes(total_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_files", file_count)),
            &file_count,
            |b, &count| {
                b.iter_with_setup(
                    || {
                        let temp_dir = TempDir::new().unwrap();
                        let input_dir = temp_dir.path().join("input");
                        fs::create_dir_all(&input_dir).unwrap();
                        create_test_files(&input_dir, count, file_size);
                        temp_dir
                    },
                    |temp_dir| {
                        let input_dir = temp_dir.path().join("input");
                        let archive_path = temp_dir.path().join("test.era");

                        let mut writer = ArchiveWriterBuilder::new(&archive_path)
                            .password("benchmark_password")
                            .config(fast_kdf_config())
                            .build()
                            .unwrap();

                        for i in 0..count {
                            let file_path = input_dir.join(format!("file_{}.bin", i));
                            rt.block_on(async {
                                writer.add_file(&file_path).await.unwrap();
                            });
                        }
                        writer.finalize().unwrap();

                        black_box(archive_path)
                    },
                );
            },
        );
    }

    group.finish();
}

fn bench_roundtrip(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("roundtrip");

    let file_size = 50 * 1024; // 50KB
    group.throughput(Throughput::Bytes(file_size as u64));

    group.bench_function("create_and_extract_50KB", |b| {
        b.iter_with_setup(
            || {
                let temp_dir = TempDir::new().unwrap();
                let input_dir = temp_dir.path().join("input");
                fs::create_dir_all(&input_dir).unwrap();
                create_test_files(&input_dir, 1, file_size);
                temp_dir
            },
            |temp_dir| {
                let input_dir = temp_dir.path().join("input");
                let archive_path = temp_dir.path().join("test.era");
                let output_dir = temp_dir.path().join("output");
                fs::create_dir_all(&output_dir).unwrap();

                // Create archive
                let mut writer = ArchiveWriterBuilder::new(&archive_path)
                    .password("benchmark_password")
                    .config(fast_kdf_config())
                    .build()
                    .unwrap();

                let file_path = input_dir.join("file_0.bin");
                rt.block_on(async {
                    writer.add_file(&file_path).await.unwrap();
                });
                writer.finalize().unwrap();

                // Extract archive
                let mut reader = ArchiveReader::open(&archive_path, "benchmark_password").unwrap();
                let options = ExtractOptions::new(&output_dir);
                reader.extract_all(&options).unwrap();

                black_box((archive_path, output_dir))
            },
        );
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_archive_creation,
    bench_archive_extraction,
    bench_multiple_files,
    bench_roundtrip
);
criterion_main!(benches);
