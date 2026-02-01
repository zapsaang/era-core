//! Batch API Performance Benchmarks
//!
//! This benchmark compares the performance of batch file operations vs individual adds.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use era_engine::ArchiveWriterBuilder;
use std::fs;
use tempfile::TempDir;

/// Create test files with specified sizes
fn create_test_files(
    dir: &std::path::Path,
    count: usize,
    file_size: usize,
) -> Vec<std::path::PathBuf> {
    (0..count)
        .map(|i| {
            let file_path = dir.join(format!("file_{}.bin", i));
            let data: Vec<u8> = (0..file_size).map(|j| ((i + j) % 256) as u8).collect();
            fs::write(&file_path, &data).unwrap();
            file_path
        })
        .collect()
}

fn fast_kdf_config() -> era_common::ArchiveConfig {
    let mut config = era_common::ArchiveConfig::default();
    config.encryption.kdf_memory_cost = 1024;
    config.encryption.kdf_time_cost = 1;
    config
}

fn bench_batch_vs_individual(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("batch_vs_individual");

    for (file_count, file_size) in [(10, 1024), (50, 10240), (100, 10240)] {
        let total_size = file_count * file_size;
        group.throughput(Throughput::Bytes(total_size as u64));

        // Benchmark batch API
        group.bench_with_input(
            BenchmarkId::new("batch", format!("{}x{}KB", file_count, file_size / 1024)),
            &(file_count, file_size),
            |b, &(count, size)| {
                b.iter_with_setup(
                    || {
                        let temp_dir = TempDir::new().unwrap();
                        let input_dir = temp_dir.path().join("input");
                        fs::create_dir_all(&input_dir).unwrap();
                        let files = create_test_files(&input_dir, count, size);
                        (temp_dir, files)
                    },
                    |(temp_dir, files)| {
                        rt.block_on(async {
                            let archive_path = temp_dir.path().join("test.era");
                            let mut writer = ArchiveWriterBuilder::new(&archive_path)
                                .password("bench")
                                .config(fast_kdf_config())
                                .build()
                                .await
                                .unwrap();

                            let file_refs: Vec<&std::path::Path> =
                                files.iter().map(|p| p.as_path()).collect();
                            writer.add_files(&file_refs).await.unwrap();
                            writer.finalize().await.unwrap();

                            black_box(archive_path)
                        })
                    },
                );
            },
        );

        // Benchmark individual adds
        group.bench_with_input(
            BenchmarkId::new(
                "individual",
                format!("{}x{}KB", file_count, file_size / 1024),
            ),
            &(file_count, file_size),
            |b, &(count, size)| {
                b.iter_with_setup(
                    || {
                        let temp_dir = TempDir::new().unwrap();
                        let input_dir = temp_dir.path().join("input");
                        fs::create_dir_all(&input_dir).unwrap();
                        let files = create_test_files(&input_dir, count, size);
                        (temp_dir, files)
                    },
                    |(temp_dir, files)| {
                        rt.block_on(async {
                            let archive_path = temp_dir.path().join("test.era");
                            let mut writer = ArchiveWriterBuilder::new(&archive_path)
                                .password("bench")
                                .config(fast_kdf_config())
                                .build()
                                .await
                                .unwrap();

                            for file in &files {
                                writer.add_file(file.as_path()).await.unwrap();
                            }
                            writer.finalize().await.unwrap();

                            black_box(archive_path)
                        })
                    },
                );
            },
        );
    }

    group.finish();
}

fn bench_small_files_batch(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("small_files_batch");

    for file_count in [10, 50, 100, 200] {
        let file_size = 1024; // 1KB files
        let total_size = file_count * file_size;
        group.throughput(Throughput::Bytes(total_size as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}x1KB", file_count)),
            &file_count,
            |b, &count| {
                b.iter_with_setup(
                    || {
                        let temp_dir = TempDir::new().unwrap();
                        let input_dir = temp_dir.path().join("input");
                        fs::create_dir_all(&input_dir).unwrap();
                        let files = create_test_files(&input_dir, count, file_size);
                        (temp_dir, files)
                    },
                    |(temp_dir, files)| {
                        rt.block_on(async {
                            let archive_path = temp_dir.path().join("test.era");
                            let mut writer = ArchiveWriterBuilder::new(&archive_path)
                                .password("bench")
                                .config(fast_kdf_config())
                                .build()
                                .await
                                .unwrap();

                            let file_refs: Vec<&std::path::Path> =
                                files.iter().map(|p| p.as_path()).collect();
                            writer.add_files(&file_refs).await.unwrap();
                            writer.finalize().await.unwrap();

                            black_box(archive_path)
                        })
                    },
                );
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_batch_vs_individual, bench_small_files_batch);
criterion_main!(benches);
