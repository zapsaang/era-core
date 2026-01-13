//! Benchmarks for Reed-Solomon erasure coding operations.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use era_codec::{ErasureCoder, ErasureConfig};

/// Generate test data of specified size
fn generate_test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

fn bench_erasure_encode(c: &mut Criterion) {
    let coder = ErasureCoder::default_config().unwrap();

    let mut group = c.benchmark_group("erasure_encode");

    // Test different data sizes
    for size in [1024, 4096, 16384, 65536, 262144, 1048576] {
        let data = generate_test_data(size);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", size / 1024)),
            &data,
            |b, data| b.iter(|| coder.encode(black_box(data))),
        );
    }

    group.finish();
}

fn bench_erasure_decode_no_loss(c: &mut Criterion) {
    let coder = ErasureCoder::default_config().unwrap();

    let mut group = c.benchmark_group("erasure_decode_no_loss");

    for size in [1024, 4096, 16384, 65536, 262144, 1048576] {
        let data = generate_test_data(size);
        let shards = coder.encode(&data).unwrap();
        let shard_options: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", size / 1024)),
            &(shard_options, size),
            |b, (shards, orig_len)| b.iter(|| coder.decode(black_box(shards), *orig_len)),
        );
    }

    group.finish();
}

fn bench_erasure_decode_with_recovery(c: &mut Criterion) {
    let coder = ErasureCoder::default_config().unwrap();

    let mut group = c.benchmark_group("erasure_decode_recovery");

    for size in [1024, 4096, 16384, 65536, 262144, 1048576] {
        let data = generate_test_data(size);
        let shards = coder.encode(&data).unwrap();

        // Simulate loss of 2 shards (maximum recoverable with 4+2)
        let mut shard_options: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        shard_options[0] = None; // Lose first data shard
        shard_options[3] = None; // Lose last data shard

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", size / 1024)),
            &(shard_options, size),
            |b, (shards, orig_len)| b.iter(|| coder.decode(black_box(shards), *orig_len)),
        );
    }

    group.finish();
}

fn bench_erasure_configurations(c: &mut Criterion) {
    let data = generate_test_data(65536); // 64KB test data

    let mut group = c.benchmark_group("erasure_configurations");
    group.throughput(Throughput::Bytes(65536));

    // Test different configurations
    for (data_shards, parity_shards) in [(2, 1), (4, 2), (8, 4), (16, 8), (32, 16)] {
        let config = ErasureConfig::new(data_shards, parity_shards).unwrap();
        let coder = ErasureCoder::new(config).unwrap();

        let label = format!("{}+{}", data_shards, parity_shards);
        group.bench_function(BenchmarkId::new("encode", &label), |b| {
            b.iter(|| coder.encode(black_box(&data)))
        });
    }

    group.finish();
}

fn bench_erasure_overhead(c: &mut Criterion) {
    // Measure the overhead of erasure coding vs raw data
    let coder = ErasureCoder::default_config().unwrap();

    let mut group = c.benchmark_group("erasure_overhead_analysis");

    for size in [4096, 65536, 1048576] {
        let data = generate_test_data(size);

        // Benchmark encode + decode roundtrip
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("roundtrip_{}KB", size / 1024)),
            &data,
            |b, data| {
                b.iter(|| {
                    let shards = coder.encode(black_box(data)).unwrap();
                    let shard_options: Vec<Option<Vec<u8>>> =
                        shards.into_iter().map(Some).collect();
                    coder.decode(&shard_options, data.len()).unwrap()
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_erasure_encode,
    bench_erasure_decode_no_loss,
    bench_erasure_decode_with_recovery,
    bench_erasure_configurations,
    bench_erasure_overhead,
);
criterion_main!(benches);
