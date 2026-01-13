//! Real-world performance test with PRODUCTION KDF settings
//!
//! This benchmark uses the actual default KDF configuration (256MB memory)
//! to measure TRUE performance that users will experience.
//!
//! Run with: cargo bench --bench real_world_perf_test

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use era_engine::{ArchiveReader, ArchiveWriterBuilder, ExtractOptions};
use std::fs;
use tempfile::TempDir;

/// Create test data with specified pattern
fn create_test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

/// Benchmark: Small file with PRODUCTION KDF (shows the KDF bottleneck)
fn bench_small_file_production_kdf(c: &mut Criterion) {
    c.bench_function("small_file_1kb_production_kdf", |b| {
        b.iter_with_setup(
            || {
                let temp_dir = TempDir::new().unwrap();
                let archive_path = temp_dir.path().join("test.era");
                let data = create_test_data(1024);
                (temp_dir, archive_path, data)
            },
            |(temp_dir, archive_path, data)| {
                // NOTE: Using DEFAULT KDF config (256MB memory, time_cost=3)
                let mut writer = ArchiveWriterBuilder::new(&archive_path)
                    .password("benchmark_password")
                    // NO custom config - use production defaults
                    .build()
                    .unwrap();

                writer.add_bytes("file.bin", &data).unwrap();
                writer.finalize().unwrap();

                black_box(temp_dir);
            },
        );
    });
}

/// Benchmark: Multiple small files to expose KDF re-derivation cost
fn bench_multiple_small_files_production_kdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("multiple_small_files_production");
    group.sample_size(10); // Reduce samples due to long execution time

    for file_count in [10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}files", file_count)),
            &file_count,
            |b, &count| {
                b.iter_with_setup(
                    || {
                        let temp_dir = TempDir::new().unwrap();
                        let archive_path = temp_dir.path().join("test.era");
                        (temp_dir, archive_path)
                    },
                    |(temp_dir, archive_path)| {
                        let mut writer = ArchiveWriterBuilder::new(&archive_path)
                            .password("benchmark_password")
                            .build()
                            .unwrap();

                        for i in 0..count {
                            let data = format!("Content for file {}", i);
                            writer
                                .add_bytes(&format!("file_{}.txt", i), data.as_bytes())
                                .unwrap();
                        }
                        writer.finalize().unwrap();

                        black_box(temp_dir);
                    },
                );
            },
        );
    }

    group.finish();
}

/// Benchmark: Large file to show KDF overhead is amortized
fn bench_large_file_production_kdf(c: &mut Criterion) {
    c.bench_function("large_file_10mb_production_kdf", |b| {
        b.iter_with_setup(
            || {
                let temp_dir = TempDir::new().unwrap();
                let archive_path = temp_dir.path().join("test.era");
                let data = create_test_data(10 * 1024 * 1024);
                (temp_dir, archive_path, data)
            },
            |(temp_dir, archive_path, data)| {
                let mut writer = ArchiveWriterBuilder::new(&archive_path)
                    .password("benchmark_password")
                    .build()
                    .unwrap();

                writer.add_bytes("large.bin", &data).unwrap();
                writer.finalize().unwrap();

                black_box(temp_dir);
            },
        );
    });
}

/// Benchmark: Extraction with PRODUCTION KDF
fn bench_extract_production_kdf(c: &mut Criterion) {
    // Setup: Create an archive first
    let setup_dir = TempDir::new().unwrap();
    let archive_path = setup_dir.path().join("test.era");

    {
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .password("benchmark_password")
            .build()
            .unwrap();

        let data = create_test_data(1024 * 1024); // 1MB
        writer.add_bytes("file.bin", &data).unwrap();
        writer.finalize().unwrap();
    }

    c.bench_function("extract_1mb_production_kdf", |b| {
        b.iter_with_setup(
            || {
                let extract_dir = TempDir::new().unwrap();
                extract_dir
            },
            |extract_dir| {
                let mut reader = ArchiveReader::open(&archive_path, "benchmark_password").unwrap();

                let options = ExtractOptions::new(extract_dir.path());
                reader.extract_all(&options).unwrap();

                black_box(extract_dir);
            },
        );
    });
}

/// Benchmark: KDF-only overhead measurement
fn bench_kdf_only(c: &mut Criterion) {
    use era_crypto::{derive_key, KdfParams, Salt};

    c.bench_function("kdf_derivation_production_256mb", |b| {
        b.iter(|| {
            let salt = Salt::generate();
            let params = KdfParams {
                memory_cost: 256 * 1024, // 256MB (production default)
                time_cost: 3,
                parallelism: 4,
            };

            let _key = derive_key(b"test_password", &salt, &params).unwrap();
            black_box(_key);
        });
    });

    c.bench_function("kdf_derivation_fast_1mb", |b| {
        b.iter(|| {
            let salt = Salt::generate();
            let params = KdfParams {
                memory_cost: 1024, // 1MB (benchmark default)
                time_cost: 1,
                parallelism: 4,
            };

            let _key = derive_key(b"test_password", &salt, &params).unwrap();
            black_box(_key);
        });
    });
}

criterion_group! {
    name = real_world_benches;
    config = Criterion::default()
        .sample_size(10)  // Small sample size due to long KDF times
        .measurement_time(std::time::Duration::from_secs(30));
    targets =
        bench_small_file_production_kdf,
        bench_multiple_small_files_production_kdf,
        bench_large_file_production_kdf,
        bench_extract_production_kdf,
        bench_kdf_only
}

criterion_main!(real_world_benches);
