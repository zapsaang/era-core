//! Performance benchmarks for era-index.
//!
//! Run with: cargo bench -p era-index

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use era_common::{BlockLocation, ChunkHash, VolumeId};
use era_index::{IndexConfig, LsmChunkIndex};
use rand::Rng;
use std::time::Duration;
use tempfile::TempDir;

fn create_test_location(slot: u32) -> BlockLocation {
    BlockLocation {
        volume_id: VolumeId::new(),
        slot_index: slot,
        physical_offset: slot as u64 * 4096,
        encrypted_size: 4096,
        erasure_info: None,
        shard_offsets: None,
        shard_volumes: None,
    }
}

fn random_hash() -> ChunkHash {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    ChunkHash::from_bytes(bytes)
}

fn bench_put(c: &mut Criterion) {
    let tmp = TempDir::new().unwrap();
    let index = LsmChunkIndex::open(tmp.path().join("index")).unwrap();

    let mut group = c.benchmark_group("put");
    group.throughput(Throughput::Elements(1));

    let mut slot = 0u32;
    group.bench_function("single_put", |b| {
        b.iter(|| {
            let hash = random_hash();
            let location = create_test_location(slot);
            slot += 1;
            index.put(hash, location).unwrap();
        });
    });

    group.finish();
}

fn bench_batch_put(c: &mut Criterion) {
    let tmp = TempDir::new().unwrap();
    let index = LsmChunkIndex::open(tmp.path().join("index")).unwrap();

    let batch_sizes = [100, 1000, 10000];

    let mut group = c.benchmark_group("batch_put");

    for &size in &batch_sizes {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_function(format!("batch_{}", size), |b| {
            let mut slot = 0u32;
            b.iter(|| {
                index.start_batch();
                for _ in 0..size {
                    let hash = random_hash();
                    let location = create_test_location(slot);
                    slot += 1;
                    index.put(hash, location).unwrap();
                }
                index.commit_batch().unwrap();
            });
        });
    }

    group.finish();
}

fn bench_get(c: &mut Criterion) {
    let tmp = TempDir::new().unwrap();
    let index = LsmChunkIndex::open(tmp.path().join("index")).unwrap();

    // Pre-populate with 100K entries
    let mut hashes = Vec::with_capacity(100_000);
    index.start_batch();
    for i in 0..100_000u32 {
        let hash = random_hash();
        hashes.push(hash);
        index.put(hash, create_test_location(i)).unwrap();
    }
    index.commit_batch().unwrap();
    index.flush().unwrap();

    let mut group = c.benchmark_group("get");
    group.throughput(Throughput::Elements(1));

    let mut idx = 0usize;
    group.bench_function("hit", |b| {
        b.iter(|| {
            let hash = &hashes[idx % hashes.len()];
            idx += 1;
            black_box(index.get(hash).unwrap())
        });
    });

    group.bench_function("miss", |b| {
        b.iter(|| {
            let hash = random_hash();
            black_box(index.get(&hash).unwrap())
        });
    });

    group.finish();
}

fn bench_contains(c: &mut Criterion) {
    let tmp = TempDir::new().unwrap();
    let index = LsmChunkIndex::open(tmp.path().join("index")).unwrap();

    // Pre-populate with 100K entries
    let mut hashes = Vec::with_capacity(100_000);
    index.start_batch();
    for i in 0..100_000u32 {
        let hash = random_hash();
        hashes.push(hash);
        index.put(hash, create_test_location(i)).unwrap();
    }
    index.commit_batch().unwrap();
    index.flush().unwrap();

    let mut group = c.benchmark_group("contains");
    group.throughput(Throughput::Elements(1));

    let mut idx = 0usize;
    group.bench_function("hit_bloom_filter", |b| {
        b.iter(|| {
            let hash = &hashes[idx % hashes.len()];
            idx += 1;
            black_box(index.contains(hash).unwrap())
        });
    });

    group.bench_function("miss_bloom_filter", |b| {
        b.iter(|| {
            let hash = random_hash();
            black_box(index.contains(&hash).unwrap())
        });
    });

    group.finish();
}

fn bench_persistence(c: &mut Criterion) {
    let mut group = c.benchmark_group("persistence");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(20);

    group.bench_function("reopen_100k", |b| {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("index");

        // Create index with 100K entries
        {
            let index = LsmChunkIndex::open(&path).unwrap();
            index.start_batch();
            for i in 0..100_000u32 {
                let hash = random_hash();
                index.put(hash, create_test_location(i)).unwrap();
            }
            index.commit_batch().unwrap();
            index.flush().unwrap();
        }

        b.iter(|| {
            let index = LsmChunkIndex::open(&path).unwrap();
            black_box(index.len())
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_put,
    bench_batch_put,
    bench_get,
    bench_contains,
    bench_persistence
);
criterion_main!(benches);
