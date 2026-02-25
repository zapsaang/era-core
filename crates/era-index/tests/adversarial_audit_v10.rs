//! # Adversarial Audit V10 — Rename Verification, Allocation Guards, Bloom Ordering
//!
//! **Audit Date:** 2026-02-25
//! **Target:** `era-index` crate — ChunkIndex rename, allocation guards, bloom safety
//! **Scope:** Verify type renames, guard correctness, bloom ordering, hash sort, cold recovery
//! **Methodology:** Pure behavioral testing — zero source scanning

use bloomfilter::Bloom;
use era_common::{BlockId, ChunkHash, VolumeId};
use era_index::{
    deserialize_bloom, serialize_bloom, ChunkIndex, ChunkIndexConfig, IndexBuilder, IndexEntry,
    IndexPage, IndexReader, MetaIndex, ENTRIES_PER_PAGE,
};
use tempfile::TempDir;

// ═══════════════════════════════════════════════════════════════════════
// Test Utilities
// ═══════════════════════════════════════════════════════════════════════

/// Canonical test hash: big-endian at tail for natural byte ordering
fn test_hash(value: u64) -> ChunkHash {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    ChunkHash::from_bytes(bytes)
}

/// Make a standard test entry
fn make_entry(i: u64) -> IndexEntry {
    IndexEntry::new(
        test_hash(i),
        VolumeId::new(),
        BlockId::new(i / 100),
        (i % 100) as u32 * 1024,
        1024,
    )
}

/// Build a valid Bloom<ChunkHash> with n items inserted
fn make_bloom(n: usize) -> Bloom<ChunkHash> {
    let mut bloom = Bloom::new_for_fp_rate(n.max(100), 0.01);
    for i in 0..n as u64 {
        bloom.set(&test_hash(i));
    }
    bloom
}

// ═══════════════════════════════════════════════════════════════════════
// Group A — Rename Verification (3 tests)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v10_a1_chunk_index_type_exists() {
    // Verifies the type is named ChunkIndex (not LsmTree)
    let result = ChunkIndex::new_default();
    assert!(result.is_ok(), "ChunkIndex::new_default() must succeed");
}

#[test]
fn v10_a2_chunk_index_config_type_exists() {
    // Verifies ChunkIndexConfig is the renamed config type
    let config = ChunkIndexConfig::default();
    // mem_limit should be a reasonable default (64MB)
    assert!(
        config.mem_limit > 0,
        "ChunkIndexConfig::default() must have positive mem_limit"
    );
}

#[test]
fn v10_a3_chunk_index_reader_type_exists() {
    // Verifies finalize() returns a ChunkIndexReader (renamed from LsmTreeReader)
    let mut index = ChunkIndex::new_default().expect("ChunkIndex::new_default must succeed");
    index.insert(make_entry(1)).expect("insert must succeed");
    let reader = index.finalize().expect("finalize must succeed");
    // ChunkIndexReader must support lookup
    let result = reader.lookup(&test_hash(1)).expect("lookup must not error");
    assert!(
        result.is_some(),
        "Inserted entry must be found via ChunkIndexReader"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Group B — Allocation Guards (5 tests)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v10_b1_read_sorted_accepts_normal_count() {
    // IndexBuilder::read_sorted() with 100 entries must succeed (well under MAX_SORTED_ENTRIES)
    let mut builder = IndexBuilder::new(1024 * 1024).expect("IndexBuilder::new must succeed");
    for i in 0..100u64 {
        builder.insert(make_entry(i)).expect("insert must succeed");
    }
    let entries = builder
        .read_sorted()
        .expect("read_sorted must succeed for 100 entries");
    assert_eq!(
        entries.len(),
        100,
        "read_sorted must return all 100 entries"
    );
}

#[test]
fn v10_b2_read_sorted_pages_accepts_normal_count() {
    // IndexBuilder::read_sorted_pages() with 100 entries must succeed
    let mut builder = IndexBuilder::new(1024 * 1024).expect("IndexBuilder::new must succeed");
    for i in 0..100u64 {
        builder.insert(make_entry(i)).expect("insert must succeed");
    }
    let pages = builder
        .read_sorted_pages()
        .expect("read_sorted_pages must succeed for 100 entries");
    // 100 entries < ENTRIES_PER_PAGE (8192), so exactly 1 page
    assert_eq!(pages.len(), 1, "100 entries must produce exactly 1 page");
    assert_eq!(pages[0].0.len(), 100, "Page must contain all 100 entries");
}

#[test]
fn v10_b3_from_memory_accepts_normal_entries() {
    // IndexReader::from_memory with 100 entries must succeed
    let meta = MetaIndex::new();
    let bloom = make_bloom(100);
    let entries: Vec<IndexEntry> = (0..100u64).map(make_entry).collect();
    let result = IndexReader::from_memory(meta, bloom, entries);
    assert!(
        result.is_ok(),
        "from_memory must accept 100 entries (well under MAX_MEMORY_ENTRIES)"
    );
}

#[test]
fn v10_b4_from_pages_accepts_normal_pages() {
    // IndexReader::from_pages with 5 pages must succeed
    let meta = MetaIndex::new();
    let bloom = make_bloom(5);
    // Build 5 non-overlapping pages with distinct hash ranges
    let pages: Vec<(IndexPage, BlockId)> = (0..5u64)
        .map(|i| {
            // Each page gets entries in range [i*10, i*10+9]
            let entries: Vec<IndexEntry> = (0..10u64).map(|j| make_entry(i * 1000 + j)).collect();
            let page = IndexPage::try_new(entries).expect("IndexPage::try_new must succeed");
            (page, BlockId::new(i))
        })
        .collect();
    let result = IndexReader::from_pages(meta, bloom, pages);
    assert!(
        result.is_ok(),
        "from_pages must accept 5 pages (well under MAX_PAGES)"
    );
}

#[test]
fn v10_b5_from_pages_rejects_oversized() {
    // IndexReader::from_pages with MAX_PAGES + 1 pages must return Err
    // MAX_PAGES = 10_000; we build 10_001 single-entry pages with distinct hashes
    let meta = MetaIndex::new();
    let bloom = make_bloom(10_001);
    let pages: Vec<(IndexPage, BlockId)> = (0..10_001u64)
        .map(|i| {
            let entry = make_entry(i);
            let page = IndexPage::try_new(vec![entry]).expect("single-entry page must succeed");
            (page, BlockId::new(i))
        })
        .collect();
    let result = IndexReader::from_pages(meta, bloom, pages);
    assert!(
        result.is_err(),
        "from_pages must reject 10_001 pages (exceeds MAX_PAGES=10_000)"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Group C — Bloom Ordering Safety (2 tests)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v10_c1_bloom_set_before_redb_commit() {
    // Bloom is set BEFORE the Redb commit (bloom-before-commit invariant).
    // After insert(), bloom_contains() must return true immediately.
    let mut index = ChunkIndex::new_default().expect("ChunkIndex::new_default must succeed");
    let hash = test_hash(42);
    index.insert(make_entry(42)).expect("insert must succeed");
    // Bloom must reflect the insert before finalize
    assert!(
        index.bloom_contains(&hash),
        "bloom_contains must return true immediately after insert (bloom-before-commit)"
    );
}

#[test]
fn v10_c2_bloom_no_false_negatives_after_finalize() {
    // After finalize, all 1000 inserted entries must be found via bloom_contains.
    // A false negative would mean data loss in dedup decisions.
    let mut index = ChunkIndex::new_default().expect("ChunkIndex::new_default must succeed");
    for i in 0..1000u64 {
        index.insert(make_entry(i)).expect("insert must succeed");
    }
    let reader = index.finalize().expect("finalize must succeed");
    let mut misses = 0usize;
    for i in 0..1000u64 {
        if !reader.bloom_contains(&test_hash(i)) {
            misses += 1;
        }
    }
    assert_eq!(
        misses, 0,
        "Bloom must have zero false negatives after finalize (got {} misses)",
        misses
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Group D — Hash Sort Order (2 tests)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v10_d1_test_hash_be_ordering() {
    // test_hash uses BE bytes at tail — hash(1) < hash(256) in byte order
    let h1 = test_hash(1);
    let h256 = test_hash(256);
    assert!(
        h1 < h256,
        "BE ordering: test_hash(1) must be less than test_hash(256)"
    );
    // Also verify monotonicity across a range
    for i in 0..99u64 {
        assert!(
            test_hash(i) < test_hash(i + 1),
            "test_hash({}) must be less than test_hash({})",
            i,
            i + 1
        );
    }
}

#[test]
fn v10_d2_read_sorted_returns_ascending_order() {
    // Insert hashes out of order; read_sorted() must return them in ascending hash order
    let mut builder = IndexBuilder::new(1024 * 1024).expect("IndexBuilder::new must succeed");
    // Insert in reverse order
    for i in (0..50u64).rev() {
        builder.insert(make_entry(i)).expect("insert must succeed");
    }
    let entries = builder.read_sorted().expect("read_sorted must succeed");
    assert_eq!(entries.len(), 50, "Must have 50 entries");
    // Verify ascending order
    for window in entries.windows(2) {
        assert!(
            window[0].hash <= window[1].hash,
            "read_sorted must return entries in ascending hash order"
        );
    }
    // Verify first and last are correct
    assert_eq!(entries[0].hash, test_hash(0), "First entry must be hash(0)");
    assert_eq!(
        entries[49].hash,
        test_hash(49),
        "Last entry must be hash(49)"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Group E — Bloom Roundtrip (2 tests)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v10_e1_bloom_serde_roundtrip() {
    // Serialize then deserialize a bloom filter; membership must be preserved
    let mut bloom: Bloom<ChunkHash> = Bloom::new_for_fp_rate(500, 0.01);
    for i in 0..100u64 {
        bloom.set(&test_hash(i));
    }
    let bytes = serialize_bloom(&bloom).expect("serialize_bloom must succeed");
    let restored = deserialize_bloom(&bytes).expect("deserialize_bloom must succeed");
    // All inserted hashes must still be present (no false negatives)
    for i in 0..100u64 {
        assert!(
            restored.check(&test_hash(i)),
            "Deserialized bloom must contain hash({}) — false negative detected",
            i
        );
    }
}

#[test]
fn v10_e2_bloom_empty_bytes_rejected() {
    // deserialize_bloom(&[]) must return Err — empty bytes are not a valid bloom
    let result = deserialize_bloom(&[]);
    assert!(
        result.is_err(),
        "deserialize_bloom must reject empty byte slice"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Group F — Cold Recovery Fast Path (2 tests)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v10_f1_from_memory_empty_entries_ok() {
    // IndexReader::from_memory with empty entries must succeed (cold recovery with no chunks)
    let meta = MetaIndex::new();
    let bloom: Bloom<ChunkHash> = Bloom::new_for_fp_rate(100, 0.01);
    let result = IndexReader::from_memory(meta, bloom, vec![]);
    assert!(
        result.is_ok(),
        "from_memory must accept empty entries for cold recovery fast path"
    );
    // Lookup on empty reader must return None (not error)
    let reader = result.unwrap();
    let lookup = reader
        .lookup(&test_hash(1))
        .expect("lookup must not error on empty reader");
    assert!(
        lookup.is_none(),
        "Empty reader must return None for any lookup"
    );
}

#[test]
fn v10_f2_from_pages_empty_ok() {
    // IndexReader::from_pages with empty pages must succeed
    let meta = MetaIndex::new();
    let bloom: Bloom<ChunkHash> = Bloom::new_for_fp_rate(100, 0.01);
    let result = IndexReader::from_pages(meta, bloom, vec![]);
    assert!(
        result.is_ok(),
        "from_pages must accept empty pages for cold recovery fast path"
    );
    // Lookup on empty reader must return None
    let reader = result.unwrap();
    let lookup = reader
        .lookup(&test_hash(99))
        .expect("lookup must not error on empty reader");
    assert!(
        lookup.is_none(),
        "Empty reader must return None for any lookup"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Bonus: IndexStore allocation guard (uses TempDir)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v10_bonus_index_store_create_and_insert() {
    // IndexStore::create + insert + read_sorted basic smoke test
    use era_index::IndexStore;
    let tmp = TempDir::new().expect("TempDir::new must succeed");
    let mut store = IndexStore::create(&tmp.path().join("test.redb"), 1000)
        .expect("IndexStore::create must succeed");
    for i in 0..50u64 {
        store.insert(&make_entry(i)).expect("insert must succeed");
    }
    let entries = store.read_sorted().expect("read_sorted must succeed");
    assert_eq!(entries.len(), 50, "read_sorted must return all 50 entries");
    // Verify ascending order
    for window in entries.windows(2) {
        assert!(
            window[0].hash <= window[1].hash,
            "Entries must be in ascending hash order"
        );
    }
}

// Verify ENTRIES_PER_PAGE constant is accessible and correct
#[test]
fn v10_bonus_entries_per_page_constant() {
    assert_eq!(ENTRIES_PER_PAGE, 8192, "ENTRIES_PER_PAGE must be 8192");
}
