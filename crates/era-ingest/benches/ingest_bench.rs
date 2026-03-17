//! Benchmarks for FastCDC chunking operations.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use era_ingest::{Chunker, ChunkerConfig};
use std::hint::black_box;
use std::time::Duration;

/// Generate data with specified entropy level
fn generate_data(size: usize, compressibility: f64) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut data = Vec::with_capacity(size);

    if compressibility > 0.8 {
        // Highly compressible: mostly zeros with some varied bytes
        data.resize(size, 0);
        let varied_bytes = (size as f64 * (1.0 - compressibility)) as usize;
        for i in 0..varied_bytes {
            let mut hasher = DefaultHasher::new();
            i.hash(&mut hasher);
            let pos = (hasher.finish() as usize) % size;
            data[pos] = (i & 0xFF) as u8;
        }
    } else if compressibility > 0.5 {
        // Medium compressibility: text-like data
        let text_chars: &[u8] =
            b"abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n";
        for i in 0..size {
            data.push(text_chars[i % text_chars.len()]);
        }
    } else {
        // Low compressibility: pseudo-random bytes
        for i in 0..size {
            let mut hasher = DefaultHasher::new();
            i.hash(&mut hasher);
            data.push((hasher.finish() & 0xFF) as u8);
        }
    }
    data
}

/// Benchmark FastCDC chunking at various data sizes
fn bench_chunking_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunking_sizes");
    group.measurement_time(Duration::from_secs(5));

    for size_kb in [64, 256, 1024, 4096] {
        let size = size_kb * 1024;
        let data = generate_data(size, 0.3);
        let chunker = Chunker::default_config();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("fastcdc", format!("{}KB", size_kb)),
            &data,
            |b, data| {
                b.iter(|| {
                    let chunks = chunker.chunk_all(black_box(data));
                    black_box(chunks.len())
                })
            },
        );
    }
    group.finish();
}

/// Benchmark FastCDC with different chunk size configurations
fn bench_chunking_configs(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunking_configs");
    group.measurement_time(Duration::from_secs(5));

    let size = 1024 * 1024; // 1MB
    let data = generate_data(size, 0.3);

    // Different avg chunk sizes
    for avg_kb in [4, 8, 16, 32, 64] {
        let avg = avg_kb * 1024;
        let config = ChunkerConfig {
            min_size: avg / 4,
            avg_size: avg,
            max_size: avg * 4,
            normalization_level: Default::default(),
            rolling_hash_seed: 0,
        };
        let chunker = Chunker::new(config);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("avg_chunk", format!("{}KB", avg_kb)),
            &data,
            |b, data| {
                b.iter(|| {
                    let chunks = chunker.chunk_all(black_box(data));
                    black_box(chunks.len())
                })
            },
        );
    }
    group.finish();
}

/// Benchmark chunking on different data types
fn bench_chunking_data_types(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunking_data_types");
    group.measurement_time(Duration::from_secs(5));

    let size = 1024 * 1024; // 1MB
    let chunker = Chunker::default_config();

    for (name, compressibility) in [("random", 0.1), ("text", 0.6), ("sparse", 0.95)] {
        let data = generate_data(size, compressibility);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("data_type", name), &data, |b, data| {
            b.iter(|| {
                let chunks = chunker.chunk_all(black_box(data));
                black_box(chunks.len())
            })
        });
    }
    group.finish();
}

/// Benchmark chunk count analysis (how many chunks are produced)
fn bench_chunk_distribution(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunk_distribution");
    group.measurement_time(Duration::from_secs(3));
    group.sample_size(20);

    let size = 4 * 1024 * 1024; // 4MB
    let chunker = Chunker::default_config();

    // Sequential pattern
    let sequential: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();
    group.throughput(Throughput::Bytes(size as u64));
    group.bench_with_input(
        BenchmarkId::new("pattern", "sequential"),
        &sequential,
        |b, data| {
            b.iter(|| {
                let chunks = chunker.chunk_all(black_box(data));
                black_box(chunks.len())
            })
        },
    );

    // Alternating pattern
    let alternating: Vec<u8> = (0..size)
        .map(|i| if i % 2 == 0 { 0 } else { 255 })
        .collect();
    group.bench_with_input(
        BenchmarkId::new("pattern", "alternating"),
        &alternating,
        |b, data| {
            b.iter(|| {
                let chunks = chunker.chunk_all(black_box(data));
                black_box(chunks.len())
            })
        },
    );

    // 4K blocks pattern
    let blocks: Vec<u8> = (0..size).map(|i| ((i / 4096) & 0xFF) as u8).collect();
    group.bench_with_input(
        BenchmarkId::new("pattern", "blocks_4k"),
        &blocks,
        |b, data| {
            b.iter(|| {
                let chunks = chunker.chunk_all(black_box(data));
                black_box(chunks.len())
            })
        },
    );

    group.finish();
}

criterion_group!(
    benches,
    bench_chunking_sizes,
    bench_chunking_configs,
    bench_chunking_data_types,
    bench_chunk_distribution,
);

criterion_main!(benches);
