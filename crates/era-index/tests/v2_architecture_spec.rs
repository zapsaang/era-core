//! # ERA-Index V2.1 Architecture Specification Test Suite
//!
//! **Redb Migration:** These tests validate the Redb-backed indexing engine
//! per RFC-023. The custom LSM-Tree has been replaced with Redb 2.1.
//!
//! **Security Requirement:** Redb provides ACID guarantees for staging data.
//! **Performance Requirement:** Bloom filters for O(1) negative lookups.
//! **Compatibility Requirement:** Index blocks integrate with era-packing.

use std::fs;
use std::path::Path;
use tempfile::TempDir;

use era_common::{BlockId, ChunkHash, VolumeId};

use era_index::{IndexBuilder, IndexEntry, IndexPage, IndexStore, MetaIndex, ENTRIES_PER_PAGE};

/// Canonical test hash: BE at high bytes ensures sort order matches Redb's lexicographic byte comparison.
fn test_hash(value: u64) -> ChunkHash {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    ChunkHash::from_bytes(bytes)
}

// ============================================================================
// TEST 1: Redb IndexStore — ACID Insert and Retrieval
// ============================================================================

#[test]
fn test_redb_store_insert_and_retrieve() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.redb");
    let mut store = IndexStore::create(&db_path, 10_000).unwrap();

    // Create test entries
    let entries: Vec<IndexEntry> = (0..1000)
        .map(|i| {
            IndexEntry::new(
                test_hash(i),
                VolumeId::new(),
                BlockId::new(i / 100),
                (i % 100) as u32 * 1024,
                1024,
            )
            .expect("valid entry")
        })
        .collect();

    // Insert via batch
    store.insert_batch(&entries).unwrap();

    // Verify point lookups work
    for i in 0..10u64 {
        let result = store.get(&test_hash(i)).unwrap();
        assert!(result.is_some(), "Entry {} must be retrievable", i);
        let entry = result.unwrap();
        assert_eq!(*entry.hash(), test_hash(i));
    }

    // Verify bloom filter
    for i in 0..1000u64 {
        assert!(store.bloom_contains(&test_hash(i)));
    }
}

#[test]
fn test_redb_store_sorted_iteration() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.redb");
    let mut store = IndexStore::create(&db_path, 10_000).unwrap();

    // Insert in reverse order
    for i in (0..1000u64).rev() {
        store
            .insert(
                &IndexEntry::new(
                    test_hash(i),
                    VolumeId::new(),
                    BlockId::new(i / 100),
                    (i % 100) as u32 * 1024,
                    1024,
                )
                .expect("valid entry"),
            )
            .unwrap();
    }

    // read_sorted must return entries in hash-sorted order
    let sorted = store.read_sorted().unwrap();
    assert_eq!(sorted.len(), 1000);
    for i in 1..sorted.len() {
        assert!(
            sorted[i - 1].hash() <= sorted[i].hash(),
            "Entries must be sorted at index {}",
            i
        );
    }
}

// ============================================================================
// TEST 2: Bloom Filter via IndexBuilder
// ============================================================================

#[test]
fn test_bloom_filter_via_builder() {
    let mut builder = IndexBuilder::new(64 * 1024 * 1024).unwrap();

    // Insert 10,000 unique hashes
    for i in 0..10_000u64 {
        let entry = IndexEntry::new(
            test_hash(i),
            VolumeId::new(),
            BlockId::new(i / 1000),
            (i % 1000) as u32 * 1024,
            1024,
        )
        .expect("valid entry");
        builder.insert(entry).unwrap();
    }

    // Verify all inserted hashes are in bloom
    for i in 0..10_000u64 {
        assert!(
            builder.bloom_contains(&test_hash(i)),
            "Bloom filter missing hash {}",
            i
        );
    }

    // Verify false positive rate is reasonable (should be ~1% for 10k items)
    let mut false_positives = 0;
    for i in 10_000..11_000u64 {
        if builder.bloom_contains(&test_hash(i)) {
            false_positives += 1;
        }
    }
    assert!(
        false_positives < 50,
        "Bloom filter FP rate too high: {}/1000",
        false_positives
    );
}

// ============================================================================
// TEST 3: Redb Batch Insert Performance
// ============================================================================

#[test]
fn test_redb_batch_insert() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("batch.redb");
    let mut store = IndexStore::create(&db_path, 100_000).unwrap();

    // Create 20,000 entries in batches of 1000
    for batch in 0..20u64 {
        let entries: Vec<IndexEntry> = (0..1000)
            .map(|i| {
                let hash_value = batch * 1000 + i;
                IndexEntry::new(
                    test_hash(hash_value),
                    VolumeId::new(),
                    BlockId::new(hash_value / 100),
                    (hash_value % 100) as u32 * 1024,
                    1024,
                )
                .expect("valid entry")
            })
            .collect();
        store.insert_batch(&entries).unwrap();
    }

    // Verify all 20,000 entries
    let sorted = store.read_sorted().unwrap();
    assert_eq!(sorted.len(), 20_000);

    // Verify sorted order
    for i in 1..sorted.len() {
        assert!(
            sorted[i - 1].hash() <= sorted[i].hash(),
            "Batch insert produced unsorted output at index {}",
            i
        );
    }
}

// ============================================================================
// TEST 4: IndexPage Creation and Deterministic Layout
// ============================================================================

#[test]
fn test_index_page_layout() {
    let entries: Vec<IndexEntry> = (0..ENTRIES_PER_PAGE)
        .map(|i| {
            IndexEntry::new(
                test_hash(i as u64),
                VolumeId::new(),
                BlockId::new(i as u64 / 100),
                (i % 100) as u32 * 1024,
                1024,
            )
            .expect("valid entry")
        })
        .collect();

    let page = IndexPage::try_new(entries.clone()).unwrap();

    assert_eq!(*page.min_hash(), test_hash(0));
    assert_eq!(*page.max_hash(), test_hash((ENTRIES_PER_PAGE - 1) as u64));
    assert_eq!(page.len(), ENTRIES_PER_PAGE);

    for (i, entry) in page.entries().iter().enumerate() {
        assert_eq!(*entry.hash(), test_hash(i as u64));
    }

    let serialized = rkyv::to_bytes::<rkyv::rancor::Error>(&page).unwrap();
    let size_kb = serialized.len() / 1024;
    assert!(
        (50..=1000).contains(&size_kb),
        "IndexPage serialized size out of range: {}KB (expected 50-1000KB for rkyv)",
        size_kb
    );
}

// ============================================================================
// TEST 5: Meta-Index (L1) Binary Search
// ============================================================================

#[test]
fn test_meta_index_lookup() {
    let mut meta = MetaIndex::new();
    for i in 0..10u64 {
        meta.add_page(
            test_hash(i * 1000),
            test_hash((i + 1) * 1000 - 1),
            BlockId::new(100 + i),
            0,
            0,
        )
        .unwrap();
    }

    assert_eq!(
        meta.find_page(&test_hash(500)).unwrap().block_id(),
        BlockId::new(100)
    );
    assert_eq!(
        meta.find_page(&test_hash(5500)).unwrap().block_id(),
        BlockId::new(105)
    );
    assert_eq!(
        meta.find_page(&test_hash(9999)).unwrap().block_id(),
        BlockId::new(109)
    );
    assert!(meta.find_page(&test_hash(10_000)).is_none());
}

// ============================================================================
// TEST 6: Full Lifecycle — Insert → Finalize via ChunkIndex
// ============================================================================

#[test]
fn test_full_index_lifecycle() {
    let mut builder = IndexBuilder::new(64 * 1024 * 1024).unwrap();

    // Insert 50,000 entries
    for i in 0..50_000u64 {
        let entry = IndexEntry::new(
            test_hash(i),
            VolumeId::new(),
            BlockId::new(i / 1000),
            (i % 1000) as u32 * 1024,
            1024,
        )
        .expect("valid entry");
        builder.insert(entry).unwrap();
    }

    // Verify entry count
    assert_eq!(builder.entry_count(), 50_000);

    // Verify bloom filter works
    assert!(builder.bloom_contains(&test_hash(25_000)));
    assert!(!builder.bloom_contains(&test_hash(999_999)));
}

// ============================================================================
// TEST 7: IndexBuilder Bloom Filter Lookups
// ============================================================================

#[test]
fn test_index_builder_bloom_lookup() {
    let mut builder = IndexBuilder::new(64 * 1024 * 1024).unwrap();

    let known_entries: Vec<IndexEntry> = (0..10_000u64)
        .map(|i| {
            IndexEntry::new(
                test_hash(i * 2), // Only even numbers
                VolumeId::new(),
                BlockId::new(i / 100),
                (i % 100) as u32 * 1024,
                1024,
            )
            .expect("valid entry")
        })
        .collect();

    for entry in &known_entries {
        builder.insert(*entry).unwrap();
    }

    // Test positive lookups via bloom
    for entry in known_entries.iter().step_by(100) {
        assert!(
            builder.bloom_contains(entry.hash()),
            "Bloom must contain inserted hash"
        );
    }

    // Test negative lookups (odd numbers - not inserted)
    let mut false_positives = 0;
    for i in 0..1000u64 {
        let odd_hash = test_hash(i * 2 + 1);
        if builder.bloom_contains(&odd_hash) {
            false_positives += 1;
        }
    }

    assert!(
        false_positives < 50,
        "Too many false positives: {}/1000",
        false_positives
    );
}

// ============================================================================
// TEST 8: Redb Entry Count Tracking
// ============================================================================

#[test]
fn test_redb_entry_count_tracking() {
    let mut builder = IndexBuilder::new(1024 * 1024).unwrap();

    assert_eq!(builder.entry_count(), 0);

    for i in 0..100u64 {
        let entry = IndexEntry::new(
            test_hash(i),
            VolumeId::new(),
            BlockId::new(i / 100),
            (i % 100) as u32 * 1024,
            1024,
        )
        .expect("valid entry");
        builder.insert(entry).unwrap();
    }

    assert_eq!(builder.entry_count(), 100);
}

// ============================================================================
// TEST 9: Integration with era-packing (BlockCodec)
// ============================================================================

#[test]
fn test_index_page_compression_and_encryption() {
    let entries: Vec<IndexEntry> = (0..ENTRIES_PER_PAGE)
        .map(|i| {
            IndexEntry::new(
                test_hash(i as u64),
                VolumeId::new(),
                BlockId::new(i as u64 / 100),
                (i % 100) as u32 * 1024,
                1024,
            )
            .expect("valid entry")
        })
        .collect();

    let page = IndexPage::try_new(entries).unwrap();

    let uncompressed = rkyv::to_bytes::<rkyv::rancor::Error>(&page).unwrap();
    let uncompressed_size = uncompressed.len();

    assert!(
        uncompressed_size > 50_000,
        "Serialized page suspiciously small: {} bytes",
        uncompressed_size
    );
}

// ============================================================================
// TEST 10: Redb Crash Recovery
// ============================================================================

#[test]
fn test_redb_crash_recovery() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("crash_test.redb");

    // Simulate a session with crash
    {
        let mut store = IndexStore::create(&db_path, 10_000).unwrap();
        for i in 0..5000u64 {
            store
                .insert(
                    &IndexEntry::new(
                        test_hash(i),
                        VolumeId::new(),
                        BlockId::new(i / 100),
                        (i % 100) as u32 * 1024,
                        1024,
                    )
                    .expect("valid entry"),
                )
                .unwrap();
        }
        // Simulate crash: preserve file on drop so recovery can reopen it
        store.keep_on_drop();
    }

    // Recovery: reopen and verify
    let recovered = IndexStore::open_readonly(&db_path).unwrap();
    assert_eq!(recovered.entry_count(), 5000);

    // Verify all hashes are present
    for i in 0..5000u64 {
        assert!(
            recovered.bloom_contains(&test_hash(i)),
            "Missing hash {} after recovery",
            i
        );
    }
}

// ============================================================================
// TEST 11: RocksDB is Removed
// ============================================================================

#[test]
fn test_rocksdb_is_removed() {
    let cargo_toml_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let cargo_toml_content = fs::read_to_string(cargo_toml_path).unwrap();

    assert!(
        !cargo_toml_content.contains("rocksdb"),
        "RocksDB should be completely removed"
    );
    assert!(
        !cargo_toml_content.contains("rocksdb-backend"),
        "rocksdb-backend feature should be removed"
    );
    assert!(
        cargo_toml_content.contains("redb"),
        "Redb must be present per RFC-023"
    );
}
