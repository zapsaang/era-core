//! # ERA-Index V2.1 Architecture Specification Test Suite
//!
//! **TDD Red State:** These tests define the expected behavior of the native,
//! log-structured indexing engine. They MUST fail initially and drive implementation.
//!
//! **Security Requirement:** All temporary spill files must be encrypted.
//! **Performance Requirement:** Bounded memory usage (64MB MemTable limit).
//! **Compatibility Requirement:** Index blocks must integrate with era-packing.

use std::fs;
use std::io::Read;
use std::path::Path;
use tempfile::TempDir;

use era_common::{BlockId, ChunkHash, VolumeId};

// NOTE: These imports will fail initially - they define the V2.1 API
use era_index::{
    IndexBuilder, IndexEntry, IndexPage, IndexReader, MetaIndex, Spiller, ENTRIES_PER_PAGE,
};

/// Helper to create a deterministic ChunkHash for testing
fn test_hash(value: u64) -> ChunkHash {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes()); // Use big-endian for lexicographic ordering
    ChunkHash::from_bytes(bytes)
}

// ============================================================================
// TEST 1: Secure Spilling - Ephemeral Encryption
// ============================================================================

#[test]
fn test_spiller_encrypts_temp_files() {
    let temp_dir = TempDir::new().unwrap();
    let spiller = Spiller::new();

    // Create test entries
    let entries: Vec<IndexEntry> = (0..1000)
        .map(|i| IndexEntry {
            hash: test_hash(i),
            volume_id: VolumeId::new(),
            block_id: BlockId::new(i / 100),
            offset: (i % 100) as u32 * 1024,
            length: 1024,
        })
        .collect();

    // Spill to encrypted temp file
    let spill_path = spiller.spill(&entries, temp_dir.path()).unwrap();

    // SECURITY VERIFICATION: Temp file must NOT contain plaintext hashes
    let mut file_content = Vec::new();
    fs::File::open(&spill_path)
        .unwrap()
        .read_to_end(&mut file_content)
        .unwrap();

    // Check that none of the test hash values appear in plaintext
    for i in 0..10 {
        let test_hash_value = test_hash(i);
        let hash_bytes = test_hash_value.as_bytes();
        assert!(
            !file_content.windows(32).any(|window| window == hash_bytes),
            "SECURITY VIOLATION: Plaintext hash found in spill file at index {}",
            i
        );
    }

    // Verify we can decrypt with the Spiller's session key
    let decrypted_entries = spiller.read_spill(&spill_path).unwrap();
    assert_eq!(decrypted_entries.len(), entries.len());
    assert_eq!(decrypted_entries, entries);
}

#[test]
fn test_spiller_with_wrong_key_fails() {
    let temp_dir = TempDir::new().unwrap();
    let spiller1 = Spiller::new();
    let spiller2 = Spiller::new(); // Different ephemeral key

    let entries: Vec<IndexEntry> = (0..100)
        .map(|i| IndexEntry {
            hash: test_hash(i),
            volume_id: VolumeId::new(),
            block_id: BlockId::new(0),
            offset: i as u32 * 1024,
            length: 1024,
        })
        .collect();

    let spill_path = spiller1.spill(&entries, temp_dir.path()).unwrap();

    // Attempting to read with a different Spiller (different key) should fail
    let result = spiller2.read_spill(&spill_path);
    assert!(
        result.is_err(),
        "SECURITY FAILURE: Spill file readable with wrong key"
    );
}

// ============================================================================
// TEST 2: Bloom Filter Persistence
// ============================================================================

#[test]
fn test_bloom_filter_snapshot_and_restore() {
    let temp_dir = TempDir::new().unwrap();
    let mut builder = IndexBuilder::new(64 * 1024 * 1024); // 64MB limit

    // Insert 10,000 unique hashes
    for i in 0..10_000 {
        let entry = IndexEntry {
            hash: test_hash(i),
            volume_id: VolumeId::new(),
            block_id: BlockId::new(i / 1000),
            offset: (i % 1000) as u32 * 1024,
            length: 1024,
        };
        builder.insert(entry, temp_dir.path()).unwrap();
    }

    // Snapshot Bloom filter
    let snapshot_path = temp_dir.path().join("bloom.snap");
    builder.snapshot_bloom(&snapshot_path).unwrap();

    // Verify snapshot file exists and is non-trivial
    assert!(snapshot_path.exists());
    let metadata = fs::metadata(&snapshot_path).unwrap();
    assert!(
        metadata.len() > 1000,
        "Bloom filter snapshot too small: {} bytes",
        metadata.len()
    );

    // Create a new builder and restore from snapshot
    let restored_builder = IndexBuilder::restore_from_snapshot(&snapshot_path).unwrap();

    // Verify that the restored Bloom filter contains the same hashes
    for i in 0..10_000 {
        let hash = test_hash(i);
        assert!(
            restored_builder.bloom_contains(&hash),
            "Restored Bloom filter missing hash {}",
            i
        );
    }

    // Verify false positive rate is reasonable (should be ~1% for 10k items)
    let mut false_positives = 0;
    for i in 10_000..11_000 {
        if restored_builder.bloom_contains(&test_hash(i)) {
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
// TEST 3: Tiered Merger with Low File Descriptor Limits
// ============================================================================

#[test]
fn test_tiered_merger_with_many_segments() {
    let temp_dir = TempDir::new().unwrap();
    let spiller = Spiller::new();

    // Simulate 200 spill segments (would crash with naive merging)
    let mut spill_paths = Vec::new();
    for segment_id in 0..200 {
        // Each segment contains 100 sorted entries
        let entries: Vec<IndexEntry> = (0..100)
            .map(|i| {
                let hash_value = (segment_id * 100 + i) as u64;
                IndexEntry {
                    hash: test_hash(hash_value),
                    volume_id: VolumeId::new(),
                    block_id: BlockId::new(hash_value / 100),
                    offset: (hash_value % 100) as u32 * 1024,
                    length: 1024,
                }
            })
            .collect();

        let path = spiller.spill(&entries, temp_dir.path()).unwrap();
        spill_paths.push(path);
    }

    // Perform tiered merge (should not exceed 64 FDs)
    let merger = era_index::TieredMerger::new(spill_paths, &spiller).unwrap();

    // Verify that the merged stream produces ALL 20,000 entries in sorted order
    let merged_entries: Vec<IndexEntry> = merger.collect();
    assert_eq!(merged_entries.len(), 20_000);

    // Verify sorted order
    for i in 1..merged_entries.len() {
        assert!(
            merged_entries[i - 1].hash <= merged_entries[i].hash,
            "Merge produced unsorted output at index {}",
            i
        );
    }
}

// ============================================================================
// TEST 4: IndexPage Creation and Deterministic Layout
// ============================================================================

#[test]
fn test_index_page_layout() {
    // Create exactly ENTRIES_PER_PAGE entries
    let entries: Vec<IndexEntry> = (0..ENTRIES_PER_PAGE)
        .map(|i| IndexEntry {
            hash: test_hash(i as u64),
            volume_id: VolumeId::new(),
            block_id: BlockId::new(i as u64 / 100),
            offset: (i % 100) as u32 * 1024,
            length: 1024,
        })
        .collect();

    let page = IndexPage::new(entries.clone());

    // Verify min/max hashes
    assert_eq!(page.min_hash, test_hash(0));
    assert_eq!(page.max_hash, test_hash((ENTRIES_PER_PAGE - 1) as u64));

    // Verify all entries are present and sorted
    assert_eq!(page.entries.len(), ENTRIES_PER_PAGE);
    for (i, entry) in page.entries.iter().enumerate() {
        assert_eq!(entry.hash, test_hash(i as u64));
    }

    // Verify serialization size is reasonable
    // Note: JSON is more verbose than bincode, so we expect larger sizes
    let serialized = serde_json::to_vec(&page).unwrap();
    let size_kb = serialized.len() / 1024;
    assert!(
        (100..=2000).contains(&size_kb),
        "IndexPage serialized size out of range: {}KB (expected 100-2000KB for JSON)",
        size_kb
    );
}

// ============================================================================
// TEST 5: Meta-Index (L1) Binary Search
// ============================================================================

#[test]
fn test_meta_index_lookup() {
    // Create a meta-index with 10 pages
    let mut meta = MetaIndex::new();
    for i in 0..10 {
        meta.add_page(
            test_hash(i * 1000),
            test_hash((i + 1) * 1000 - 1),
            BlockId::new(100 + i),
        );
    }

    // Test lookups
    assert_eq!(
        meta.find_page(&test_hash(500)).unwrap().block_id,
        BlockId::new(100)
    );
    assert_eq!(
        meta.find_page(&test_hash(5500)).unwrap().block_id,
        BlockId::new(105)
    );
    assert_eq!(
        meta.find_page(&test_hash(9999)).unwrap().block_id,
        BlockId::new(109)
    );

    // Out of range
    assert!(meta.find_page(&test_hash(10_000)).is_none());
}

// ============================================================================
// TEST 6: Full Lifecycle - Ingest -> Spill -> Merge -> Finalize
// ============================================================================

#[test]
fn test_full_index_lifecycle() {
    let temp_dir = TempDir::new().unwrap();
    let mut builder = IndexBuilder::new(64 * 1024 * 1024);

    // Insert 50,000 entries (will trigger multiple spills)
    for i in 0..50_000 {
        let entry = IndexEntry {
            hash: test_hash(i),
            volume_id: VolumeId::new(),
            block_id: BlockId::new(i / 1000),
            offset: (i % 1000) as u32 * 1024,
            length: 1024,
        };
        builder.insert(entry, temp_dir.path()).unwrap();
    }

    // Finalize the index (merge all spills into L2 pages)
    // Note: Using deprecated external file API for this legacy test
    let index_dir = temp_dir.path().join("final_index");
    fs::create_dir_all(&index_dir).unwrap();
    #[allow(deprecated)]
    let meta_index = builder.finalize_external(&index_dir).unwrap();

    // Verify the MetaIndex was created
    assert!(!meta_index.pages.is_empty());
    let total_capacity = meta_index.pages.len() * ENTRIES_PER_PAGE;
    assert!(
        total_capacity >= 50_000,
        "MetaIndex capacity {} too small for 50k entries",
        total_capacity
    );

    // Verify L2 page files were written
    for page_ptr in &meta_index.pages {
        let page_path = index_dir.join(format!("page_{}.bin", page_ptr.block_id.sequence()));
        assert!(page_path.exists(), "Missing L2 page file: {:?}", page_path);
    }
}

// ============================================================================
// TEST 7: IndexReader - Bloom + L1 + L2 Lookup
// ============================================================================

#[test]
fn test_index_reader_lookup() {
    let temp_dir = TempDir::new().unwrap();
    let mut builder = IndexBuilder::new(64 * 1024 * 1024);

    // Insert known entries
    let known_entries: Vec<IndexEntry> = (0..10_000)
        .map(|i| IndexEntry {
            hash: test_hash(i * 2), // Only even numbers
            volume_id: VolumeId::new(),
            block_id: BlockId::new(i / 100),
            offset: (i % 100) as u32 * 1024,
            length: 1024,
        })
        .collect();

    for entry in &known_entries {
        builder.insert(*entry, temp_dir.path()).unwrap();
    }

    // Finalize
    let index_dir = temp_dir.path().join("index");
    fs::create_dir_all(&index_dir).unwrap();
    #[allow(deprecated)]
    let meta_index = builder.finalize_external(&index_dir).unwrap();

    // Create reader
    let mut reader = IndexReader::open(&index_dir, meta_index).unwrap();

    // Test positive lookups
    for entry in known_entries.iter().step_by(100) {
        let result = reader.lookup(&entry.hash).unwrap();
        assert!(
            result.is_some(),
            "Failed to find known hash: {}",
            entry.hash
        );
        let loc = result.unwrap();
        assert_eq!(loc.block_id, entry.block_id);
        assert_eq!(loc.offset, entry.offset);
    }

    // Test negative lookups (odd numbers - not inserted)
    let mut false_positives = 0;
    for i in 0..1000 {
        let odd_hash = test_hash(i * 2 + 1);
        if reader.lookup(&odd_hash).unwrap().is_some() {
            false_positives += 1;
        }
    }

    // Bloom filter should reject most (>95%) of non-existent keys
    assert!(
        false_positives < 50,
        "Too many false positives: {}/1000",
        false_positives
    );
}

// ============================================================================
// TEST 8: Memory Bounds - MemTable Spill Trigger
// ============================================================================

#[test]
fn test_memtable_spill_enforcement() {
    let temp_dir = TempDir::new().unwrap();
    let mem_limit = 1024 * 1024; // 1MB limit for testing
    let mut builder = IndexBuilder::new(mem_limit);

    // Insert entries until spill is triggered
    // Each IndexEntry is ~80 bytes (32 hash + 16 UUID + 8 BlockId + 8 offset + 4 length)
    let entries_per_spill = mem_limit / 80;

    // Insert 2x the limit to ensure at least one spill
    for i in 0..(entries_per_spill * 2) {
        let entry = IndexEntry {
            hash: test_hash(i as u64),
            volume_id: VolumeId::new(),
            block_id: BlockId::new(i as u64 / 100),
            offset: (i % 100) as u32 * 1024,
            length: 1024,
        };
        builder.insert(entry, temp_dir.path()).unwrap();
    }

    // Verify that spill files were created
    let spill_count = builder.spill_count();
    assert!(
        spill_count >= 1,
        "No spills triggered despite exceeding memory limit"
    );

    // Verify current MemTable is within bounds
    let mem_usage = builder.memtable_size_bytes();
    assert!(
        mem_usage <= mem_limit,
        "MemTable size {} exceeds limit {}",
        mem_usage,
        mem_limit
    );
}

// ============================================================================
// TEST 9: Integration with era-packing (BlockCodec)
// ============================================================================

#[test]
fn test_index_page_compression_and_encryption() {
    // This test verifies that IndexPage can be packed using era-packing
    // NOTE: This requires era-packing to expose a pack_index_page function
    // or we use the generic block packing API

    let entries: Vec<IndexEntry> = (0..ENTRIES_PER_PAGE)
        .map(|i| IndexEntry {
            hash: test_hash(i as u64),
            volume_id: VolumeId::new(),
            block_id: BlockId::new(i as u64 / 100),
            offset: (i % 100) as u32 * 1024,
            length: 1024,
        })
        .collect();

    let page = IndexPage::new(entries);

    // Serialize and measure uncompressed size
    let uncompressed = serde_json::to_vec(&page).unwrap();
    let uncompressed_size = uncompressed.len();

    // NOTE: This will fail initially until we integrate with era-packing
    // For now, we'll just verify serialization works
    assert!(
        uncompressed_size > 100_000,
        "Serialized page suspiciously small: {} bytes",
        uncompressed_size
    );

    // TODO: Once era-packing integration is done:
    // let packed = era_packing::pack_block(&uncompressed, &encryption_key).unwrap();
    // assert!(packed.len() < uncompressed_size, "Compression failed");
}

// ============================================================================
// TEST 10: Crash Recovery via Bloom Snapshot
// ============================================================================

#[test]
fn test_crash_recovery_from_bloom_snapshot() {
    let temp_dir = TempDir::new().unwrap();
    let mut builder = IndexBuilder::new(64 * 1024 * 1024);

    // Simulate a long-running session
    for i in 0..5000 {
        let entry = IndexEntry {
            hash: test_hash(i),
            volume_id: VolumeId::new(),
            block_id: BlockId::new(i / 100),
            offset: (i % 100) as u32 * 1024,
            length: 1024,
        };
        builder.insert(entry, temp_dir.path()).unwrap();
    }

    // Snapshot at checkpoint
    let snapshot_path = temp_dir.path().join("checkpoint.bloom");
    builder.snapshot_bloom(&snapshot_path).unwrap();

    // Simulate crash - drop builder
    drop(builder);

    // Recovery: Restore from snapshot
    let mut recovered_builder = IndexBuilder::restore_from_snapshot(&snapshot_path).unwrap();

    // Re-ingest data that was processed after the snapshot (simulated)
    for i in 5000..6000 {
        let entry = IndexEntry {
            hash: test_hash(i),
            volume_id: VolumeId::new(),
            block_id: BlockId::new(i / 100),
            offset: (i % 100) as u32 * 1024,
            length: 1024,
        };
        recovered_builder.insert(entry, temp_dir.path()).unwrap();
    }

    // Verify all hashes are present in Bloom filter
    for i in 0..6000 {
        assert!(
            recovered_builder.bloom_contains(&test_hash(i)),
            "Missing hash {} after recovery",
            i
        );
    }
}

// ============================================================================
// TEST 11: RocksDB as Optional Dependency Only
// ============================================================================

#[test]
fn test_rocksdb_is_removed() {
    // This verifies that RocksDB has been completely removed in V2.1.
    // The V2 implementation is now the only implementation.

    let cargo_toml_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let cargo_toml_content = fs::read_to_string(cargo_toml_path).unwrap();

    // RocksDB should NOT exist in dependencies
    assert!(
        !cargo_toml_content.contains("rocksdb"),
        "RocksDB should be completely removed in V2.1"
    );

    // Verify the rocksdb-backend feature does NOT exist
    assert!(
        !cargo_toml_content.contains("rocksdb-backend"),
        "rocksdb-backend feature should be removed"
    );
}
