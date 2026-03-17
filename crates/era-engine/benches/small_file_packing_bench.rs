//! Benchmark for small file packing performance

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use era_engine::ArchiveWriterBuilder;
use std::fs;
use std::hint::black_box;
use tempfile::TempDir;

fn bench_small_files_packing(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("small_file_performance");

    for file_count in [10, 50, 100, 200] {
        // Setup: create test files
        let temp_dir = TempDir::new().unwrap();
        let input_dir = temp_dir.path().join("input");
        fs::create_dir_all(&input_dir).unwrap();

        let file_size = 1024; // 1KB per file
        for i in 0..file_count {
            let path = input_dir.join(format!("file_{:03}.dat", i));
            let content = vec![i as u8; file_size];
            fs::write(&path, content).unwrap();
        }

        let total_size = file_count * file_size;
        group.throughput(Throughput::Bytes(total_size as u64));

        group.bench_with_input(
            BenchmarkId::new("packed", file_count),
            &file_count,
            |b, &count| {
                b.iter(|| {
                    rt.block_on(async {
                        let archive_path = temp_dir.path().join(format!("packed_{}.era", count));
                        let mut writer = ArchiveWriterBuilder::new(&archive_path)
                            .password("benchmark")
                            .build()
                            .await
                            .unwrap();

                        for i in 0..count {
                            let path = input_dir.join(format!("file_{:03}.dat", i));
                            writer.add_file(&path).await.unwrap();
                        }

                        black_box(writer.finalize().await.unwrap());
                        fs::remove_file(&archive_path).ok();
                    })
                });
            },
        );
    }

    group.finish();
}

fn bench_various_file_sizes(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("file_size_vs_packing");

    for file_size in [512, 1024, 4096, 8192, 16384] {
        let temp_dir = TempDir::new().unwrap();
        let input_dir = temp_dir.path().join("input");
        fs::create_dir_all(&input_dir).unwrap();

        let file_count = 50;
        for i in 0..file_count {
            let path = input_dir.join(format!("file_{:03}.dat", i));
            let content = vec![i as u8; file_size];
            fs::write(&path, content).unwrap();
        }

        let total_size = file_count * file_size;
        group.throughput(Throughput::Bytes(total_size as u64));

        group.bench_with_input(
            BenchmarkId::new("size_bytes", file_size),
            &file_size,
            |b, _size| {
                b.iter(|| {
                    rt.block_on(async {
                        let archive_path = temp_dir.path().join(format!("size_{}.era", file_size));
                        let mut writer = ArchiveWriterBuilder::new(&archive_path)
                            .password("benchmark")
                            .build()
                            .await
                            .unwrap();

                        for i in 0..file_count {
                            let path = input_dir.join(format!("file_{:03}.dat", i));
                            writer.add_file(&path).await.unwrap();
                        }

                        black_box(writer.finalize().await.unwrap());
                        fs::remove_file(&archive_path).ok();
                    })
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_small_files_packing, bench_various_file_sizes);
criterion_main!(benches);
