//! Performance benchmarks for era-index (V2.1 Redb-backed implementation).
//!
//! Run with: cargo bench -p era-index

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use era_common::{BlockId, ChunkHash, VolumeId};
use era_index::{IndexEntry, ChunkIndex, ChunkIndexConfig};
use rand::RngCore;

fn random_hash() -> ChunkHash {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    ChunkHash::from_bytes(bytes)
}

fn make_entry(hash: ChunkHash, i: u64) -> IndexEntry {
    IndexEntry::new(
        hash,
        VolumeId::new(),
        BlockId::new(i / 100),
        (i % 100) as u32 * 1024,
        1024,
    )
}

fn insert_throughput(c: &mut Criterion) {
    c.bench_function("insert_throughput", |b| {
        b.iter_with_setup(
            || {
                let hashes: Vec<ChunkHash> = (0..10_000).map(|_| random_hash()).collect();
                let tree = ChunkIndex::new(ChunkIndexConfig::default()).unwrap();
                (tree, hashes)
            },
            |(mut tree, hashes)| {
                for (i, hash) in hashes.into_iter().enumerate() {
                    tree.insert(make_entry(hash, i as u64)).unwrap();
                }
                black_box(&mut tree);
            },
        );
    });
}

fn lookup_hit(c: &mut Criterion) {
    let mut tree = ChunkIndex::new(ChunkIndexConfig::default()).unwrap();
    let mut hashes = Vec::with_capacity(5_000);
    for i in 0..5_000u64 {
        let hash = random_hash();
        hashes.push(hash);
        tree.insert(make_entry(hash, i)).unwrap();
    }
    let reader = tree.finalize().unwrap();

    let lookup_hashes: Vec<ChunkHash> = (0..1_000).map(|i| hashes[i % hashes.len()]).collect();

    c.bench_function("lookup_hit", |b| {
        b.iter(|| {
            for hash in &lookup_hashes {
                black_box(reader.lookup(hash).unwrap());
            }
        });
    });
}

fn lookup_miss(c: &mut Criterion) {
    let mut tree = ChunkIndex::new(ChunkIndexConfig::default()).unwrap();
    for i in 0..5_000u64 {
        tree.insert(make_entry(random_hash(), i)).unwrap();
    }
    let reader = tree.finalize().unwrap();

    let miss_hashes: Vec<ChunkHash> = (0..1_000).map(|_| random_hash()).collect();

    c.bench_function("lookup_miss", |b| {
        b.iter(|| {
            for hash in &miss_hashes {
                black_box(reader.lookup(hash).unwrap());
            }
        });
    });
}

fn finalize(c: &mut Criterion) {
    c.bench_function("finalize", |b| {
        b.iter_with_setup(
            || {
                let mut tree = ChunkIndex::new(ChunkIndexConfig::default()).unwrap();
                for i in 0..5_000u64 {
                    tree.insert(make_entry(random_hash(), i)).unwrap();
                }
                tree
            },
            |mut tree| {
                black_box(tree.finalize().unwrap());
            },
        );
    });
}

criterion_group!(
    benches,
    insert_throughput,
    lookup_hit,
    lookup_miss,
    finalize
);
criterion_main!(benches);
