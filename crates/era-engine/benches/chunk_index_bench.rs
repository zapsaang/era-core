//! Performance benchmarks for ChunkIndex backends.
//!
//! Compares Memory vs LSM (RocksDB) backends for different workloads.
//!
//! Run with: cargo bench -p era-engine --features lsm

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use era_common::{BlockLocation, ChunkHash, VolumeId};
use era_engine::chunk_index::{create_chunk_index, ChunkIndex, ChunkIndexBackend, MemoryChunkIndex};
use std::sync::Arc;
use tempfile::TempDir;

/// Create a test BlockLocation
fn test_location(slot: u32) -> BlockLocation {
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

/// Generate a deterministic hash from an index
fn hash_from_index(i: usize) -> ChunkHash {
    let data = format!("chunk_data_{:016}", i);
    era_crypto::hash(data.as_bytes())
}

/// Benchmark single put operations
fn bench_put_single(c: &mut Criterion) {
    let mut group = c.benchmark_group("put_single");
    
    // Memory backend
    group.bench_function("memory", |b| {
        let index = Arc::new(MemoryChunkIndex::new());
        let mut i = 0usize;
        b.iter(|| {
            let hash = hash_from_index(i);
            let loc = test_location(i as u32);
            index.put(black_box(hash), black_box(loc)).unwrap();
            i += 1;
        });
    });

    #[cfg(feature = "lsm")]
    {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("bench_put_single");
        let index = create_chunk_index(ChunkIndexBackend::Lsm { path }).unwrap();
        
        group.bench_function("lsm", |b| {
            let mut i = 0usize;
            b.iter(|| {
                let hash = hash_from_index(i);
                let loc = test_location(i as u32);
                index.put(black_box(hash), black_box(loc)).unwrap();
                i += 1;
            });
        });
    }
    
    group.finish();
}

/// Benchmark batch put operations
fn bench_put_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("put_batch");
    
    for batch_size in [100, 1000, 10000].iter() {
        // Memory backend
        group.bench_with_input(
            BenchmarkId::new("memory", batch_size),
            batch_size,
            |b, &size| {
                b.iter(|| {
                    let index = Arc::new(MemoryChunkIndex::new());
                    for i in 0..size {
                        let hash = hash_from_index(i);
                        let loc = test_location(i as u32);
                        index.put(hash, loc).unwrap();
                    }
                    black_box(index.len())
                });
            },
        );

        #[cfg(feature = "lsm")]
        {
            group.bench_with_input(
                BenchmarkId::new("lsm", batch_size),
                batch_size,
                |b, &size| {
                    b.iter(|| {
                        let temp_dir = TempDir::new().unwrap();
                        let path = temp_dir.path().join("bench");
                        let index = create_chunk_index(ChunkIndexBackend::Lsm { path }).unwrap();
                        
                        index.start_batch();
                        for i in 0..size {
                            let hash = hash_from_index(i);
                            let loc = test_location(i as u32);
                            index.put(hash, loc).unwrap();
                        }
                        index.commit_batch().unwrap();
                        black_box(index.len())
                    });
                },
            );
        }
    }
    
    group.finish();
}

/// Benchmark contains (lookup) operations on pre-populated index
fn bench_contains(c: &mut Criterion) {
    let mut group = c.benchmark_group("contains");
    
    let populate_size = 100_000;
    
    // Prepare memory index
    let memory_index = Arc::new(MemoryChunkIndex::new());
    for i in 0..populate_size {
        let hash = hash_from_index(i);
        let loc = test_location(i as u32);
        memory_index.put(hash, loc).unwrap();
    }
    
    group.bench_function("memory", |b| {
        let mut i = 0usize;
        b.iter(|| {
            let hash = hash_from_index(i % populate_size);
            let result = memory_index.contains(black_box(&hash)).unwrap();
            i += 1;
            black_box(result)
        });
    });

    #[cfg(feature = "lsm")]
    {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("bench_contains");
        let lsm_index = create_chunk_index(ChunkIndexBackend::Lsm { path }).unwrap();
        
        lsm_index.start_batch();
        for i in 0..populate_size {
            let hash = hash_from_index(i);
            let loc = test_location(i as u32);
            lsm_index.put(hash, loc).unwrap();
        }
        lsm_index.commit_batch().unwrap();
        lsm_index.flush().unwrap();
        
        group.bench_function("lsm", |b| {
            let mut i = 0usize;
            b.iter(|| {
                let hash = hash_from_index(i % populate_size);
                let result = lsm_index.contains(black_box(&hash)).unwrap();
                i += 1;
                black_box(result)
            });
        });
    }
    
    group.finish();
}

/// Benchmark get operations
fn bench_get(c: &mut Criterion) {
    let mut group = c.benchmark_group("get");
    
    let populate_size = 100_000;
    
    // Prepare memory index
    let memory_index = Arc::new(MemoryChunkIndex::new());
    for i in 0..populate_size {
        let hash = hash_from_index(i);
        let loc = test_location(i as u32);
        memory_index.put(hash, loc).unwrap();
    }
    
    group.bench_function("memory", |b| {
        let mut i = 0usize;
        b.iter(|| {
            let hash = hash_from_index(i % populate_size);
            let result = memory_index.get(black_box(&hash)).unwrap();
            i += 1;
            black_box(result)
        });
    });

    #[cfg(feature = "lsm")]
    {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("bench_get");
        let lsm_index = create_chunk_index(ChunkIndexBackend::Lsm { path }).unwrap();
        
        lsm_index.start_batch();
        for i in 0..populate_size {
            let hash = hash_from_index(i);
            let loc = test_location(i as u32);
            lsm_index.put(hash, loc).unwrap();
        }
        lsm_index.commit_batch().unwrap();
        lsm_index.flush().unwrap();
        
        group.bench_function("lsm", |b| {
            let mut i = 0usize;
            b.iter(|| {
                let hash = hash_from_index(i % populate_size);
                let result = lsm_index.get(black_box(&hash)).unwrap();
                i += 1;
                black_box(result)
            });
        });
    }
    
    group.finish();
}

/// Benchmark mixed read/write workload (80% reads, 20% writes)
fn bench_mixed_workload(c: &mut Criterion) {
    let mut group = c.benchmark_group("mixed_workload");
    
    let initial_size = 10_000;
    
    // Prepare memory index
    let memory_index = Arc::new(MemoryChunkIndex::new());
    for i in 0..initial_size {
        let hash = hash_from_index(i);
        let loc = test_location(i as u32);
        memory_index.put(hash, loc).unwrap();
    }
    
    group.bench_function("memory", |b| {
        let mut read_i = 0usize;
        let mut write_i = initial_size;
        let mut op = 0usize;
        b.iter(|| {
            if op % 5 == 0 {
                // Write (20%)
                let hash = hash_from_index(write_i);
                let loc = test_location(write_i as u32);
                memory_index.put(hash, loc).unwrap();
                write_i += 1;
            } else {
                // Read (80%)
                let hash = hash_from_index(read_i % initial_size);
                black_box(memory_index.contains(&hash).unwrap());
                read_i += 1;
            }
            op += 1;
        });
    });

    #[cfg(feature = "lsm")]
    {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("bench_mixed");
        let lsm_index = create_chunk_index(ChunkIndexBackend::Lsm { path }).unwrap();
        
        lsm_index.start_batch();
        for i in 0..initial_size {
            let hash = hash_from_index(i);
            let loc = test_location(i as u32);
            lsm_index.put(hash, loc).unwrap();
        }
        lsm_index.commit_batch().unwrap();
        lsm_index.flush().unwrap();
        
        group.bench_function("lsm", |b| {
            let mut read_i = 0usize;
            let mut write_i = initial_size;
            let mut op = 0usize;
            b.iter(|| {
                if op % 5 == 0 {
                    // Write (20%)
                    let hash = hash_from_index(write_i);
                    let loc = test_location(write_i as u32);
                    lsm_index.put(hash, loc).unwrap();
                    write_i += 1;
                } else {
                    // Read (80%)
                    let hash = hash_from_index(read_i % initial_size);
                    black_box(lsm_index.contains(&hash).unwrap());
                    read_i += 1;
                }
                op += 1;
            });
        });
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_put_single,
    bench_put_batch,
    bench_contains,
    bench_get,
    bench_mixed_workload
);

criterion_main!(benches);
