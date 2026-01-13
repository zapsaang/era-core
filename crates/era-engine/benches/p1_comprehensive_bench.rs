//! P1 Comprehensive Benchmarks
//!
//! This benchmark suite tests all critical paths in the ERA engine:
//! - Standard archive creation/extraction
//! - Erasure-coded archive creation/extraction
//! - CDC chunking performance
//! - Deduplication efficiency
//! - Large file handling
//! - Multi-file archives
//!
//! Run with: cargo bench -p era-engine --bench p1_comprehensive_bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use era_common::ErasureCodeConfig;
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

/// Create compressible test data (for realistic compression benchmarks)
fn create_compressible_data(size: usize) -> Vec<u8> {
    // Mix of repeated patterns and random-ish data (about 50% compressible)
    let mut data = Vec::with_capacity(size);
    for i in 0..size {
        if i % 4 == 0 {
            data.push(b'A');
        } else {
            data.push((i * 7 % 256) as u8);
        }
    }
    data
}

/// Create a fast KDF config for benchmarking (reduces key derivation overhead)
fn fast_kdf_config() -> era_common::ArchiveConfig {
    let mut config = era_common::ArchiveConfig::default();
    config.encryption.kdf_memory_cost = 1024;
    config.encryption.kdf_time_cost = 1;
    config
}

// ============================================================================
// STANDARD ARCHIVE BENCHMARKS
// ============================================================================

fn bench_standard_create(c: &mut Criterion) {
    let mut group = c.benchmark_group("p1_standard_create");

    for size_kb in [1, 10, 100, 1000] {
        let file_size = size_kb * 1024;
        group.throughput(Throughput::Bytes(file_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", size_kb)),
            &file_size,
            |b, &size| {
                b.iter_with_setup(
                    || {
                        let temp_dir = TempDir::new().unwrap();
                        let data = create_compressible_data(size);
                        temp_dir
                            .path()
                            .join("input")
                            .pipe(|p| fs::create_dir_all(&p).unwrap());
                        fs::write(temp_dir.path().join("input/file.bin"), &data).unwrap();
                        temp_dir
                    },
                    |temp_dir| {
                        let archive_path = temp_dir.path().join("test.era");

                        let mut writer = ArchiveWriterBuilder::new(&archive_path)
                            .password("benchmark")
                            .config(fast_kdf_config())
                            .build()
                            .unwrap();

                        writer
                            .add_file(&temp_dir.path().join("input/file.bin"))
                            .unwrap();
                        writer.finalize().unwrap();

                        black_box(archive_path)
                    },
                );
            },
        );
    }

    group.finish();
}

fn bench_standard_extract(c: &mut Criterion) {
    let mut group = c.benchmark_group("p1_standard_extract");

    for size_kb in [1, 10, 100, 1000] {
        let file_size = size_kb * 1024;
        group.throughput(Throughput::Bytes(file_size as u64));

        // Pre-create the archive
        let temp_dir = TempDir::new().unwrap();
        let data = create_compressible_data(file_size);
        fs::create_dir_all(temp_dir.path().join("input")).unwrap();
        fs::write(temp_dir.path().join("input/file.bin"), &data).unwrap();

        let archive_path = temp_dir.path().join("test.era");
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .password("benchmark")
            .config(fast_kdf_config())
            .build()
            .unwrap();
        writer
            .add_file(&temp_dir.path().join("input/file.bin"))
            .unwrap();
        writer.finalize().unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", size_kb)),
            &file_size,
            |b, _| {
                b.iter(|| {
                    let count = COUNTER.fetch_add(1, Ordering::SeqCst);
                    let output_dir = temp_dir.path().join(format!("output_{}", count));
                    fs::create_dir_all(&output_dir).unwrap();

                    let mut reader = ArchiveReader::open(&archive_path, "benchmark").unwrap();
                    let options = ExtractOptions::new(&output_dir).overwrite(true);
                    reader.extract_all(&options).unwrap();

                    black_box(output_dir)
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// ERASURE CODING BENCHMARKS
// ============================================================================

fn bench_erasure_create(c: &mut Criterion) {
    let mut group = c.benchmark_group("p1_erasure_create");
    group.sample_size(20); // Erasure coding is slow, reduce samples

    for size_kb in [10, 100, 500] {
        let file_size = size_kb * 1024;
        group.throughput(Throughput::Bytes(file_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB_4+2", size_kb)),
            &file_size,
            |b, &size| {
                b.iter_with_setup(
                    || {
                        let temp_dir = TempDir::new().unwrap();
                        let data = create_compressible_data(size);
                        fs::create_dir_all(temp_dir.path().join("input")).unwrap();
                        fs::write(temp_dir.path().join("input/file.bin"), &data).unwrap();
                        temp_dir
                    },
                    |temp_dir| {
                        let archive_path = temp_dir.path().join("test.era");

                        let mut writer = ArchiveWriterBuilder::new(&archive_path)
                            .password("benchmark")
                            .config(fast_kdf_config())
                            .erasure_config(ErasureCodeConfig::new(4, 2))
                            .build()
                            .unwrap();

                        writer
                            .add_file(&temp_dir.path().join("input/file.bin"))
                            .unwrap();
                        writer.finalize().unwrap();

                        black_box(archive_path)
                    },
                );
            },
        );
    }

    group.finish();
}

fn bench_erasure_extract(c: &mut Criterion) {
    let mut group = c.benchmark_group("p1_erasure_extract");
    group.sample_size(20);

    for size_kb in [10, 100, 500] {
        let file_size = size_kb * 1024;
        group.throughput(Throughput::Bytes(file_size as u64));

        // Pre-create erasure archive
        let temp_dir = TempDir::new().unwrap();
        let data = create_compressible_data(file_size);
        fs::create_dir_all(temp_dir.path().join("input")).unwrap();
        fs::write(temp_dir.path().join("input/file.bin"), &data).unwrap();

        let archive_path = temp_dir.path().join("test.era");
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .password("benchmark")
            .config(fast_kdf_config())
            .erasure_config(ErasureCodeConfig::new(4, 2))
            .build()
            .unwrap();
        writer
            .add_file(&temp_dir.path().join("input/file.bin"))
            .unwrap();
        writer.finalize().unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB_4+2", size_kb)),
            &file_size,
            |b, _| {
                b.iter(|| {
                    let count = COUNTER.fetch_add(1, Ordering::SeqCst);
                    let output_dir = temp_dir.path().join(format!("output_{}", count));
                    fs::create_dir_all(&output_dir).unwrap();

                    let mut reader = ArchiveReader::open(&archive_path, "benchmark").unwrap();
                    let options = ExtractOptions::new(&output_dir).overwrite(true);
                    reader.extract_all(&options).unwrap();

                    black_box(output_dir)
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// CDC CHUNKING BENCHMARKS
// ============================================================================

fn bench_cdc_create(c: &mut Criterion) {
    let mut group = c.benchmark_group("p1_cdc_create");

    for size_kb in [100, 500, 1000] {
        let file_size = size_kb * 1024;
        group.throughput(Throughput::Bytes(file_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", size_kb)),
            &file_size,
            |b, &size| {
                b.iter_with_setup(
                    || {
                        let temp_dir = TempDir::new().unwrap();
                        let data = create_compressible_data(size);
                        fs::create_dir_all(temp_dir.path().join("input")).unwrap();
                        fs::write(temp_dir.path().join("input/file.bin"), &data).unwrap();
                        temp_dir
                    },
                    |temp_dir| {
                        let archive_path = temp_dir.path().join("test.era");

                        let mut writer = ArchiveWriterBuilder::new(&archive_path)
                            .password("benchmark")
                            .config(fast_kdf_config())
                            .enable_cdc(true)
                            .build()
                            .unwrap();

                        writer
                            .add_file(&temp_dir.path().join("input/file.bin"))
                            .unwrap();
                        writer.finalize().unwrap();

                        black_box(archive_path)
                    },
                );
            },
        );
    }

    group.finish();
}

// ============================================================================
// MULTI-FILE BENCHMARKS
// ============================================================================

fn bench_multi_file_create(c: &mut Criterion) {
    let mut group = c.benchmark_group("p1_multi_file_create");

    for file_count in [5, 20, 50] {
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
                            .password("benchmark")
                            .config(fast_kdf_config())
                            .build()
                            .unwrap();

                        for i in 0..count {
                            let file_path = input_dir.join(format!("file_{}.bin", i));
                            writer.add_file(&file_path).unwrap();
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

// ============================================================================
// VERIFY BENCHMARKS
// ============================================================================

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("p1_verify");

    for size_kb in [10, 100, 500] {
        let file_size = size_kb * 1024;
        group.throughput(Throughput::Bytes(file_size as u64));

        // Pre-create archive
        let temp_dir = TempDir::new().unwrap();
        let data = create_compressible_data(file_size);
        fs::create_dir_all(temp_dir.path().join("input")).unwrap();
        fs::write(temp_dir.path().join("input/file.bin"), &data).unwrap();

        let archive_path = temp_dir.path().join("test.era");
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .password("benchmark")
            .config(fast_kdf_config())
            .build()
            .unwrap();
        writer
            .add_file(&temp_dir.path().join("input/file.bin"))
            .unwrap();
        writer.finalize().unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", size_kb)),
            &file_size,
            |b, _| {
                b.iter(|| {
                    let mut reader = ArchiveReader::open(&archive_path, "benchmark").unwrap();
                    let stats = reader.verify().unwrap();
                    black_box(stats)
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// ERASURE VS STANDARD COMPARISON
// ============================================================================

fn bench_erasure_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("p1_erasure_overhead");
    group.sample_size(15);

    let file_size = 100 * 1024; // 100KB
    group.throughput(Throughput::Bytes(file_size as u64));

    // Standard archive
    group.bench_function("standard_100KB", |b| {
        b.iter_with_setup(
            || {
                let temp_dir = TempDir::new().unwrap();
                let data = create_compressible_data(file_size);
                fs::create_dir_all(temp_dir.path().join("input")).unwrap();
                fs::write(temp_dir.path().join("input/file.bin"), &data).unwrap();
                temp_dir
            },
            |temp_dir| {
                let archive_path = temp_dir.path().join("test.era");

                let mut writer = ArchiveWriterBuilder::new(&archive_path)
                    .password("benchmark")
                    .config(fast_kdf_config())
                    .build()
                    .unwrap();

                writer
                    .add_file(&temp_dir.path().join("input/file.bin"))
                    .unwrap();
                writer.finalize().unwrap();

                black_box(archive_path)
            },
        );
    });

    // Erasure 4+2
    group.bench_function("erasure_4+2_100KB", |b| {
        b.iter_with_setup(
            || {
                let temp_dir = TempDir::new().unwrap();
                let data = create_compressible_data(file_size);
                fs::create_dir_all(temp_dir.path().join("input")).unwrap();
                fs::write(temp_dir.path().join("input/file.bin"), &data).unwrap();
                temp_dir
            },
            |temp_dir| {
                let archive_path = temp_dir.path().join("test.era");

                let mut writer = ArchiveWriterBuilder::new(&archive_path)
                    .password("benchmark")
                    .config(fast_kdf_config())
                    .erasure_config(ErasureCodeConfig::new(4, 2))
                    .build()
                    .unwrap();

                writer
                    .add_file(&temp_dir.path().join("input/file.bin"))
                    .unwrap();
                writer.finalize().unwrap();

                black_box(archive_path)
            },
        );
    });

    // Erasure 8+4
    group.bench_function("erasure_8+4_100KB", |b| {
        b.iter_with_setup(
            || {
                let temp_dir = TempDir::new().unwrap();
                let data = create_compressible_data(file_size);
                fs::create_dir_all(temp_dir.path().join("input")).unwrap();
                fs::write(temp_dir.path().join("input/file.bin"), &data).unwrap();
                temp_dir
            },
            |temp_dir| {
                let archive_path = temp_dir.path().join("test.era");

                let mut writer = ArchiveWriterBuilder::new(&archive_path)
                    .password("benchmark")
                    .config(fast_kdf_config())
                    .erasure_config(ErasureCodeConfig::new(8, 4))
                    .build()
                    .unwrap();

                writer
                    .add_file(&temp_dir.path().join("input/file.bin"))
                    .unwrap();
                writer.finalize().unwrap();

                black_box(archive_path)
            },
        );
    });

    group.finish();
}

// Helper trait for chaining
trait Pipe: Sized {
    fn pipe<F, R>(self, f: F) -> R
    where
        F: FnOnce(Self) -> R,
    {
        f(self)
    }
}
impl<T> Pipe for T {}

criterion_group!(
    benches,
    bench_standard_create,
    bench_standard_extract,
    bench_erasure_create,
    bench_erasure_extract,
    bench_cdc_create,
    bench_multi_file_create,
    bench_verify,
    bench_erasure_overhead,
);
criterion_main!(benches);
