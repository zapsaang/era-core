//! Benchmarks for MacroBlock packing operations.

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use era_codec::ZstdCompressor;
use era_common::UniqueChunk;
use era_crypto::{derive_key, hash, DerivedKey, KdfParams, Salt};
use era_packing::{MacroBlockBuilder, MacroBlockUnpacker};
use std::hint::black_box;

/// Test nonce context
const TEST_NONCE_CONTEXT: [u8; 16] = [42u8; 16];
const TEST_ARCHIVE_ID: [u8; 16] = [0x42u8; 16];
const TEST_EPOCH_ID: u32 = 1;

/// Create a test key with fast KDF parameters
fn fast_test_key() -> DerivedKey {
    let salt = Salt::from_bytes([0u8; 16]);
    let params = KdfParams {
        memory_cost: 1024,
        time_cost: 1,
        parallelism: 1,
    };
    derive_key(b"benchmark_password", &salt, &params).unwrap()
}

/// Generate a chunk with the given size
fn generate_chunk(size: usize) -> UniqueChunk {
    let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
    let chunk_hash = hash(&data);
    UniqueChunk::new(Bytes::from(data), chunk_hash)
}

fn bench_pack_single(c: &mut Criterion) {
    let key = fast_test_key();

    let mut group = c.benchmark_group("pack_single");

    for size in [1024, 4096, 16384, 65536, 262144] {
        let chunk = generate_chunk(size);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &chunk, |b, chunk| {
            let compressor = Box::new(ZstdCompressor::default());
            let builder = MacroBlockBuilder::new(
                key.try_clone().unwrap(),
                TEST_NONCE_CONTEXT,
                TEST_ARCHIVE_ID,
                TEST_EPOCH_ID,
                compressor,
            );
            b.iter(|| builder.pack_single(black_box(chunk.clone())))
        });
    }

    group.finish();
}

fn bench_unpack(c: &mut Criterion) {
    let key = fast_test_key();

    let mut group = c.benchmark_group("unpack");

    for size in [1024, 4096, 16384, 65536, 262144] {
        let chunk = generate_chunk(size);
        let compressor = Box::new(ZstdCompressor::default());
        let builder = MacroBlockBuilder::new(
            key.try_clone().unwrap(),
            TEST_NONCE_CONTEXT,
            TEST_ARCHIVE_ID,
            TEST_EPOCH_ID,
            compressor,
        );
        let encrypted = builder.pack_single(chunk).unwrap();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &encrypted,
            |b, encrypted| {
                let unpacker = MacroBlockUnpacker::new(
                    key.try_clone().unwrap(),
                    TEST_NONCE_CONTEXT,
                    TEST_ARCHIVE_ID,
                    TEST_EPOCH_ID,
                    Box::new(ZstdCompressor::default()),
                );
                b.iter(|| unpacker.unpack(black_box(encrypted)))
            },
        );
    }

    group.finish();
}

fn bench_pack_multiple_chunks(c: &mut Criterion) {
    let key = fast_test_key();

    let mut group = c.benchmark_group("pack_multiple_chunks");

    for count in [1, 5, 10, 20] {
        let chunks: Vec<UniqueChunk> = (0..count)
            .map(|i| {
                let data: Vec<u8> = (0..4096).map(|j| ((i * j) % 256) as u8).collect();
                let chunk_hash = hash(&data);
                UniqueChunk::new(Bytes::from(data), chunk_hash)
            })
            .collect();

        let total_size = count * 4096;
        group.throughput(Throughput::Bytes(total_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_chunks", count)),
            &chunks,
            |b, chunks| {
                let compressor = Box::new(ZstdCompressor::default());
                let builder = MacroBlockBuilder::new(
                    key.try_clone().unwrap(),
                    TEST_NONCE_CONTEXT,
                    TEST_ARCHIVE_ID,
                    TEST_EPOCH_ID,
                    compressor,
                );
                b.iter(|| builder.pack_chunks(black_box(chunks.clone())))
            },
        );
    }

    group.finish();
}

fn bench_roundtrip(c: &mut Criterion) {
    let key = fast_test_key();

    let mut group = c.benchmark_group("pack_unpack_roundtrip");

    for size in [4096, 65536] {
        let chunk = generate_chunk(size);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &chunk, |b, chunk| {
            b.iter(|| {
                let compressor = Box::new(ZstdCompressor::default());
                let builder = MacroBlockBuilder::new(
                    key.try_clone().unwrap(),
                    TEST_NONCE_CONTEXT,
                    TEST_ARCHIVE_ID,
                    TEST_EPOCH_ID,
                    compressor,
                );
                let encrypted = builder.pack_single(chunk.clone()).unwrap();

                let unpacker = MacroBlockUnpacker::new(
                    key.try_clone().unwrap(),
                    TEST_NONCE_CONTEXT,
                    TEST_ARCHIVE_ID,
                    TEST_EPOCH_ID,
                    Box::new(ZstdCompressor::default()),
                );
                unpacker.unpack(&encrypted).unwrap()
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_pack_single,
    bench_unpack,
    bench_pack_multiple_chunks,
    bench_roundtrip
);
criterion_main!(benches);
