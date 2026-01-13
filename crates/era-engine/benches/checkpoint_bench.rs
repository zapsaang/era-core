//! Benchmarks for checkpoint mechanism operations.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use era_common::{BlockLocation, ChunkHash, VolumeId};
use era_engine::{Checkpoint, CheckpointManager};
use tempfile::TempDir;

/// Create a test ChunkHash
fn test_hash(index: u32) -> ChunkHash {
    let mut bytes = [0u8; 32];
    bytes[0..4].copy_from_slice(&index.to_le_bytes());
    ChunkHash::from_bytes(bytes)
}

/// Create a test BlockLocation
fn test_location(offset: u64, size: u32) -> BlockLocation {
    BlockLocation {
        volume_id: VolumeId::default(),
        slot_index: 0,
        physical_offset: offset,
        encrypted_size: size,
    }
}

fn bench_checkpoint_create(c: &mut Criterion) {
    let mut group = c.benchmark_group("checkpoint_create");

    for chunk_count in [100, 1000, 10000, 100000] {
        group.throughput(Throughput::Elements(chunk_count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_chunks", chunk_count)),
            &chunk_count,
            |b, &count| {
                b.iter(|| {
                    let mut cp = Checkpoint::new("/tmp/test.era");
                    for i in 0..count {
                        cp.record_chunk(test_hash(i as u32), test_location(i as u64 * 1024, 512));
                    }
                    black_box(cp)
                })
            },
        );
    }

    group.finish();
}

fn bench_checkpoint_save(c: &mut Criterion) {
    let mut group = c.benchmark_group("checkpoint_save");

    for chunk_count in [100, 1000, 10000] {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("test.era");

        let mut manager = CheckpointManager::new(&archive_path);
        for i in 0..chunk_count {
            manager.record_chunk(test_hash(i as u32), test_location(i as u64 * 1024, 512));
        }

        group.throughput(Throughput::Elements(chunk_count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_chunks", chunk_count)),
            &archive_path,
            |b, _path| b.iter(|| manager.save().unwrap()),
        );
    }

    group.finish();
}

fn bench_checkpoint_load(c: &mut Criterion) {
    let mut group = c.benchmark_group("checkpoint_load");

    for chunk_count in [100, 1000, 10000] {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("test.era");

        // Create and save checkpoint
        {
            let mut manager = CheckpointManager::new(&archive_path);
            for i in 0..chunk_count {
                manager.record_chunk(test_hash(i as u32), test_location(i as u64 * 1024, 512));
            }
            for i in 0..100 {
                manager
                    .mark_file_completed(format!("/path/to/file_{}.txt", i))
                    .unwrap();
            }
            manager.save().unwrap();
        }

        group.throughput(Throughput::Elements(chunk_count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_chunks", chunk_count)),
            &archive_path,
            |b, path| b.iter(|| CheckpointManager::load_or_create(black_box(path)).unwrap()),
        );
    }

    group.finish();
}

fn bench_checkpoint_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("checkpoint_chunk_lookup");

    for chunk_count in [1000, 10000, 100000] {
        let mut cp = Checkpoint::new("/tmp/test.era");
        for i in 0..chunk_count {
            cp.record_chunk(test_hash(i as u32), test_location(i as u64 * 1024, 512));
        }

        // Create lookup targets (mix of existing and non-existing)
        let existing_hash = test_hash(chunk_count / 2);
        let missing_hash = test_hash(chunk_count + 1000);

        group.bench_function(
            BenchmarkId::new("existing", format!("{}_chunks", chunk_count)),
            |b| b.iter(|| cp.get_chunk_location(black_box(&existing_hash))),
        );

        group.bench_function(
            BenchmarkId::new("missing", format!("{}_chunks", chunk_count)),
            |b| b.iter(|| cp.get_chunk_location(black_box(&missing_hash))),
        );
    }

    group.finish();
}

fn bench_checkpoint_file_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("checkpoint_file_ops");

    for file_count in [10, 100, 1000] {
        let mut cp = Checkpoint::new("/tmp/test.era");
        for i in 0..file_count {
            cp.mark_file_completed(format!("/path/to/file_{}.txt", i));
        }

        let existing_path = std::path::Path::new("/path/to/file_50.txt");
        let missing_path = std::path::Path::new("/path/to/missing.txt");

        group.bench_function(
            BenchmarkId::new("is_completed_hit", format!("{}_files", file_count)),
            |b| b.iter(|| cp.is_file_completed(black_box(existing_path))),
        );

        group.bench_function(
            BenchmarkId::new("is_completed_miss", format!("{}_files", file_count)),
            |b| b.iter(|| cp.is_file_completed(black_box(missing_path))),
        );
    }

    group.finish();
}

fn bench_checkpoint_serialization_size(c: &mut Criterion) {
    // This benchmark measures serialization size, not time
    // Useful for understanding checkpoint file growth
    let mut group = c.benchmark_group("checkpoint_serialization_roundtrip");

    for chunk_count in [100, 1000, 10000] {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("test.era");

        // Setup
        let mut manager = CheckpointManager::new(&archive_path);
        for i in 0..chunk_count {
            manager.record_chunk(test_hash(i as u32), test_location(i as u64 * 1024, 512));
        }

        group.throughput(Throughput::Elements(chunk_count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_chunks", chunk_count)),
            &archive_path,
            |b, path| {
                b.iter(|| {
                    manager.save().unwrap();
                    CheckpointManager::load_or_create(path).unwrap()
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_checkpoint_create,
    bench_checkpoint_save,
    bench_checkpoint_load,
    bench_checkpoint_lookup,
    bench_checkpoint_file_operations,
    bench_checkpoint_serialization_size,
);
criterion_main!(benches);
