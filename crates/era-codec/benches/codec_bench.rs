//! Benchmarks for ERA compression operations.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use era_codec::{Compressor, ZstdCompressor};
use std::hint::black_box;

/// Generate test data with varying compressibility
fn generate_compressible_data(size: usize) -> Vec<u8> {
    // Repeating pattern is highly compressible
    (0..size).map(|i| (i % 256) as u8).collect()
}

fn generate_random_data(size: usize) -> Vec<u8> {
    // Random data is less compressible
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    (0..size)
        .map(|i| {
            let mut hasher = DefaultHasher::new();
            i.hash(&mut hasher);
            hasher.finish() as u8
        })
        .collect()
}

fn bench_zstd_compress(c: &mut Criterion) {
    let compressor = ZstdCompressor::default();

    let mut group = c.benchmark_group("zstd_compress");

    for size in [1024, 4096, 16384, 65536, 262144, 1048576] {
        let data = generate_compressible_data(size);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| compressor.compress(black_box(data)))
        });
    }

    group.finish();
}

fn bench_zstd_decompress(c: &mut Criterion) {
    let compressor = ZstdCompressor::default();

    let mut group = c.benchmark_group("zstd_decompress");

    for size in [1024, 4096, 16384, 65536, 262144, 1048576] {
        let data = generate_compressible_data(size);
        let compressed = compressor.compress(&data).unwrap();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &compressed,
            |b, compressed| b.iter(|| compressor.decompress(black_box(compressed))),
        );
    }

    group.finish();
}

fn bench_zstd_levels(c: &mut Criterion) {
    let data = generate_compressible_data(65536);

    let mut group = c.benchmark_group("zstd_compression_levels");

    for level in [1, 3, 6, 9, 15, 22] {
        let compressor = ZstdCompressor::new(level);

        group.bench_function(BenchmarkId::from_parameter(level), |b| {
            b.iter(|| compressor.compress(black_box(&data)))
        });
    }

    group.finish();
}

fn bench_compression_ratio(c: &mut Criterion) {
    let compressor = ZstdCompressor::default();

    let mut group = c.benchmark_group("compression_data_types");

    // Test with different data types
    let compressible = generate_compressible_data(65536);
    let random = generate_random_data(65536);
    let zeros = vec![0u8; 65536];
    let text = "The quick brown fox jumps over the lazy dog. "
        .repeat(1000)
        .into_bytes();

    for (name, data) in [
        ("compressible", &compressible),
        ("random", &random),
        ("zeros", &zeros),
        ("text", &text),
    ] {
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(BenchmarkId::new("compress", name), data, |b, data| {
            b.iter(|| compressor.compress(black_box(data)))
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_zstd_compress,
    bench_zstd_decompress,
    bench_zstd_levels,
    bench_compression_ratio
);
criterion_main!(benches);
