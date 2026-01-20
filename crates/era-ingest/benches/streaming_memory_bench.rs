//! Benchmark to expose memory copy overhead in StreamingChunker
//!
//! This benchmark demonstrates the performance impact of the `copy_within`
//! operation that occurs on every chunk when the buffer position exceeds
//! half the buffer size.
//!
//! Run with: cargo bench --bench streaming_memory_bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use era_ingest::{ChunkerConfig, StreamingChunker, StreamingChunkerZeroCopy};
use std::io::Cursor;
use std::time::Duration;

/// Generate deterministic test data
fn generate_data(size: usize, pattern: u8) -> Vec<u8> {
    (0..size).map(|i| pattern.wrapping_add(i as u8)).collect()
}

/// Benchmark StreamingChunker to expose copy_within overhead
///
/// The current implementation calls `copy_within` when position > buffer_len/2.
/// This benchmark will show:
/// 1. Throughput degradation as file size increases (more copies)
/// 2. Memory bandwidth waste from redundant copies
/// 3. CPU cycles spent on memmove instead of actual work
fn bench_streaming_chunker_memory_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("streaming_chunker_memory_overhead");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(20);

    // Test with increasing data sizes to expose the copy overhead
    // The overhead is proportional to file size because copy_within
    // is called repeatedly
    for size_mb in [1, 10, 50, 100] {
        let size = size_mb * 1024 * 1024;
        let data = generate_data(size, 0x42);

        group.throughput(Throughput::Bytes(size as u64));

        // Benchmark ORIGINAL implementation (with copy_within)
        group.bench_with_input(
            BenchmarkId::new("streaming_current", format!("{}MB", size_mb)),
            &data,
            |b, data| {
                b.iter(|| {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    rt.block_on(async {
                        let config = ChunkerConfig::default();
                        let reader = Cursor::new(data.clone());
                        let mut chunker = StreamingChunker::new(reader, config);

                        let mut chunk_count = 0;
                        let mut total_bytes = 0;

                        while let Ok(Some(chunk)) = chunker.next_chunk().await {
                            chunk_count += 1;
                            total_bytes += chunk.data.len();
                            black_box(&chunk);
                        }

                        black_box((chunk_count, total_bytes))
                    })
                })
            },
        );

        // Benchmark ZERO-COPY implementation (ring buffer)
        group.bench_with_input(
            BenchmarkId::new("streaming_zerocopy", format!("{}MB", size_mb)),
            &data,
            |b, data| {
                b.iter(|| {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    rt.block_on(async {
                        let config = ChunkerConfig::default();
                        let reader = Cursor::new(data.clone());
                        let mut chunker = StreamingChunkerZeroCopy::new(reader, config);

                        let mut chunk_count = 0;
                        let mut total_bytes = 0;

                        while let Ok(Some(chunk)) = chunker.next_chunk().await {
                            chunk_count += 1;
                            total_bytes += chunk.data.len();
                            black_box(&chunk);
                        }

                        black_box((chunk_count, total_bytes))
                    })
                })
            },
        );
    }

    group.finish();
}

/// Benchmark that counts actual memory copies
///
/// This simulates the worst-case scenario where every chunk triggers
/// a buffer compaction (copy_within).
fn bench_buffer_compaction_cost(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_compaction_cost");
    group.measurement_time(Duration::from_secs(5));

    // Simulate the copy_within operation directly
    for buffer_kb in [256, 512, 1024, 2048] {
        let buffer_size = buffer_kb * 1024;
        let mut buffer = vec![0u8; buffer_size];

        // Fill with pattern
        for i in 0..buffer_size {
            buffer[i] = (i & 0xFF) as u8;
        }

        group.throughput(Throughput::Bytes(buffer_size as u64));
        group.bench_with_input(
            BenchmarkId::new("copy_within", format!("{}KB", buffer_kb)),
            &buffer_size,
            |b, &size| {
                b.iter(|| {
                    // This simulates what happens in StreamingChunker::ensure_data()
                    // when position > buffer.len() / 2
                    let position = size / 2 + 1024; // Just past the threshold
                    let valid_len = size;
                    let remaining = valid_len - position;

                    // THE EXPENSIVE OPERATION:
                    buffer.copy_within(position..valid_len, 0);

                    black_box(remaining)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark different chunking strategies to show performance variance
fn bench_chunking_strategies(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunking_strategies");
    group.measurement_time(Duration::from_secs(8));

    let size = 50 * 1024 * 1024; // 50MB - enough to see the problem
    let data = generate_data(size, 0x42);

    // Test with different chunk size configs
    // Smaller chunks = more frequent copy_within calls
    for (name, min, avg, max) in [
        ("small_chunks", 4 * 1024, 16 * 1024, 64 * 1024),
        ("default_chunks", 4 * 1024, 64 * 1024, 256 * 1024),
        ("large_chunks", 16 * 1024, 256 * 1024, 1024 * 1024),
    ] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("config", name), &data, |b, data| {
            b.iter(|| {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let config = ChunkerConfig::new(min, avg, max);
                    let reader = Cursor::new(data.clone());
                    let mut chunker = StreamingChunker::new(reader, config);

                    let mut chunk_count = 0;
                    while let Ok(Some(chunk)) = chunker.next_chunk().await {
                        chunk_count += 1;
                        black_box(&chunk);
                    }

                    black_box(chunk_count)
                })
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_streaming_chunker_memory_overhead,
    bench_buffer_compaction_cost,
    bench_chunking_strategies,
);

criterion_main!(benches);
