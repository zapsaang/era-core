//! Integration tests for era-index.
//!
//! NOTE: These tests are for the legacy RocksDB-based implementation.
//! They are disabled as ERA-Index V2.1 has replaced the RocksDB backend.
//! See v2_architecture_spec.rs for V2.1 tests.

#![cfg(any())] // Disable all tests in this file

use era_common::{BlockLocation, ChunkHash, ErasureBlockInfo, VolumeId};
use era_index::{IndexConfigBuilder, LsmChunkIndex};
use std::collections::HashMap;
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

fn create_erasure_location(slot: u32) -> BlockLocation {
    BlockLocation {
        volume_id: VolumeId::new(),
        slot_index: slot,
        physical_offset: slot as u64 * 4096,
        encrypted_size: 4096,
        erasure_info: Some(ErasureBlockInfo {
            data_shards: 4,
            parity_shards: 2,
            shard_size: 1024,
            original_len: 4000,
        }),
        shard_offsets: Some(vec![4096, 8192, 12288, 16384, 20480]),
        shard_volumes: Some(vec![0, 1, 2, 0, 1, 2]),
    }
}

/// Test that LSM-Tree can fully replace HashMap for deduplication.
#[test]
fn test_hashmap_replacement_equivalence() {
    let tmp = TempDir::new().unwrap();
    let index = LsmChunkIndex::open(tmp.path().join("index")).unwrap();
    let mut hashmap: HashMap<ChunkHash, BlockLocation> = HashMap::new();

    // Simulate typical archive workflow
    let chunk_count = 10_000;

    // Write phase - both implementations should work identically
    for i in 0..chunk_count {
        let hash = ChunkHash::from_bytes([(i % 256) as u8; 32]);
        let location = create_test_location(i);

        // Check for deduplication
        let lsm_exists = index.contains(&hash).unwrap();
        let hashmap_exists = hashmap.contains_key(&hash);
        assert_eq!(
            lsm_exists, hashmap_exists,
            "Existence check mismatch at iteration {i}"
        );

        // Store if new
        if !hashmap_exists {
            hashmap.insert(hash, location.clone());
            index.put(hash, location).unwrap();
        }
    }

    // Verify all entries match
    for (hash, expected_location) in &hashmap {
        let retrieved = index.get(hash).unwrap().expect("Entry should exist");
        assert_eq!(
            retrieved.slot_index, expected_location.slot_index,
            "Slot mismatch for hash {:?}",
            hash
        );
        assert_eq!(
            retrieved.encrypted_size, expected_location.encrypted_size,
            "Size mismatch for hash {:?}",
            hash
        );
    }
}

/// Test persistence across reopens.
#[test]
fn test_persistence_across_sessions() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("index");

    let mut hashes = Vec::new();

    // Helper to generate unique hash from u32
    fn make_hash(i: u32) -> ChunkHash {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&i.to_le_bytes());
        ChunkHash::from_bytes(bytes)
    }

    // Session 1: Initial writes
    {
        let index = LsmChunkIndex::open(&path).unwrap();
        for i in 0..1000u32 {
            let hash = make_hash(i);
            hashes.push(hash);
            index.put(hash, create_test_location(i)).unwrap();
        }
        index.flush().unwrap();
    }

    // Session 2: Verify and add more
    {
        let index = LsmChunkIndex::open(&path).unwrap();

        // Verify previous entries
        for (i, hash) in hashes.iter().enumerate() {
            let location = index.get(hash).unwrap().expect("Should exist");
            assert_eq!(location.slot_index, i as u32);
        }

        // Add more entries
        for i in 1000..2000u32 {
            let hash = make_hash(i);
            hashes.push(hash);
            index.put(hash, create_test_location(i)).unwrap();
        }
        index.flush().unwrap();
    }

    // Session 3: Verify all entries
    {
        let index = LsmChunkIndex::open(&path).unwrap();
        for (i, hash) in hashes.iter().enumerate() {
            let location = index.get(hash).unwrap().expect("Should exist");
            assert_eq!(location.slot_index, i as u32);
        }
    }
}

/// Test concurrent read access with read-only mode.
#[test]
fn test_concurrent_read_only_access() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("index");

    // Create and populate index
    {
        let index = LsmChunkIndex::open(&path).unwrap();
        for i in 0..100 {
            let hash = ChunkHash::from_bytes([i as u8; 32]);
            index.put(hash, create_test_location(i)).unwrap();
        }
        index.flush().unwrap();
    }

    // Open multiple read-only instances
    let ro1 = LsmChunkIndex::open_read_only(&path).unwrap();
    let ro2 = LsmChunkIndex::open_read_only(&path).unwrap();

    // Both should be able to read
    for i in 0..100 {
        let hash = ChunkHash::from_bytes([i as u8; 32]);
        assert!(ro1.get(&hash).unwrap().is_some());
        assert!(ro2.get(&hash).unwrap().is_some());
    }
}

/// Test with erasure-coded block locations.
#[test]
fn test_erasure_coded_locations() {
    let tmp = TempDir::new().unwrap();
    let index = LsmChunkIndex::open(tmp.path().join("index")).unwrap();

    for i in 0..100 {
        let hash = ChunkHash::from_bytes([i as u8; 32]);
        let location = create_erasure_location(i);
        index.put(hash, location.clone()).unwrap();

        // Verify immediately
        let retrieved = index.get(&hash).unwrap().unwrap();
        assert!(retrieved.is_erasure_coded());
        let info = retrieved.erasure_info.unwrap();
        assert_eq!(info.data_shards, 4);
        assert_eq!(info.parity_shards, 2);
        assert_eq!(retrieved.shard_offsets.as_ref().unwrap().len(), 5);
        assert_eq!(retrieved.shard_volumes.as_ref().unwrap().len(), 6);
    }
}

/// Test custom configuration.
#[test]
fn test_custom_configuration() {
    let tmp = TempDir::new().unwrap();

    let config = IndexConfigBuilder::low_memory(tmp.path().join("index"))
        .bloom_filter_bits(14) // Higher precision
        .build();

    let index = LsmChunkIndex::open_with_config(config).unwrap();

    for i in 0..100 {
        let hash = ChunkHash::from_bytes([i as u8; 32]);
        index.put(hash, create_test_location(i)).unwrap();
    }

    assert!(index.len() >= 100);
}

/// Test batch operations improve throughput.
#[test]
fn test_batch_write_performance() {
    let tmp = TempDir::new().unwrap();
    let index = LsmChunkIndex::open(tmp.path().join("index")).unwrap();

    // Batch mode
    index.start_batch();
    for i in 0..10_000 {
        let hash = ChunkHash::from_bytes([(i % 256) as u8; 32]);
        let location = create_test_location(i);
        index.put(hash, location).unwrap();
    }
    index.commit_batch().unwrap();

    // Verify entries exist (256 unique hashes)
    assert!(index.len() >= 256);
}

/// Test index destruction.
#[test]
fn test_destroy() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("index");

    // Create index
    {
        let index = LsmChunkIndex::open(&path).unwrap();
        for i in 0..100 {
            let hash = ChunkHash::from_bytes([i as u8; 32]);
            index.put(hash, create_test_location(i)).unwrap();
        }
    }

    // Verify it exists
    assert!(path.exists());

    // Destroy
    LsmChunkIndex::destroy(&path).unwrap();

    // Verify it's gone (or empty)
    let index = LsmChunkIndex::open(&path).unwrap();
    assert_eq!(index.len(), 0);
}

/// Test metrics tracking.
#[test]
fn test_metrics_tracking() {
    let tmp = TempDir::new().unwrap();
    let index = LsmChunkIndex::open(tmp.path().join("index")).unwrap();

    let hash = ChunkHash::from_bytes([42u8; 32]);
    let location = create_test_location(0);

    // Put
    index.put(hash, location).unwrap();

    // Get hit
    index.get(&hash).unwrap();

    // Get miss
    let missing_hash = ChunkHash::from_bytes([99u8; 32]);
    index.get(&missing_hash).unwrap();

    let metrics = index.metrics();
    let snapshot = metrics.snapshot();

    assert_eq!(snapshot.puts, 1);
    assert_eq!(snapshot.gets, 2);
    assert_eq!(snapshot.get_hits, 1);
    assert_eq!(snapshot.get_misses, 1);
}

/// Test high-throughput configuration.
#[test]
fn test_high_throughput_config() {
    let tmp = TempDir::new().unwrap();

    let config = IndexConfigBuilder::high_throughput(tmp.path().join("index")).build();

    let index = LsmChunkIndex::open_with_config(config).unwrap();

    // Should handle many writes efficiently
    for i in 0..10_000 {
        let hash = ChunkHash::from_bytes([(i % 256) as u8; 32]);
        let location = create_test_location(i);
        index.put(hash, location).unwrap();
    }

    index.flush().unwrap();
}

/// Test iteration over all entries.
#[test]
fn test_iteration() {
    let tmp = TempDir::new().unwrap();
    let index = LsmChunkIndex::open(tmp.path().join("index")).unwrap();

    let mut expected: HashMap<[u8; 32], u32> = HashMap::new();

    for i in 0..100 {
        let hash = ChunkHash::from_bytes([i as u8; 32]);
        let location = create_test_location(i);
        expected.insert(*hash.as_bytes(), location.slot_index);
        index.put(hash, location).unwrap();
    }

    index.flush().unwrap();

    // Iterate and verify
    let mut count = 0;
    for result in index.iter() {
        let (hash, location) = result.unwrap();
        let expected_slot = expected.get(hash.as_bytes()).unwrap();
        assert_eq!(location.slot_index, *expected_slot);
        count += 1;
    }

    assert_eq!(count, 100);
}
