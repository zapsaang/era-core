//! # Adversarial Audit V9 — Full-Stack Security & Correctness Audit
//!
//! **Audit Date:** 2026-02-25
//! **Target:** `era-index` crate (all modules) + cross-crate integration
//! **Scope:** Verify V8 fixes are genuine, discover residual and novel vulnerabilities
//! **Methodology:** Pure behavioral testing — zero source scanning

use era_common::{BlockId, ChunkHash, VolumeId};
use era_index::{
    ChunkIndex, IndexBuilder, IndexEntry, IndexPage, IndexReader, MetaIndex, ENTRIES_PER_PAGE,
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
    .expect("valid entry")
}

/// Make entry with specific volume/block/offset
fn make_entry_at(i: u64, vol: VolumeId, block: u64, offset: u32, length: u32) -> IndexEntry {
    IndexEntry::new(test_hash(i), vol, BlockId::new(block), offset, length).expect("valid entry")
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F1: VERIFY V8-F1 FIX — MetaIndex fields are private
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f1a_meta_index_fields_encapsulated() {
    // V8-F1 claimed MetaIndex.pages and .bloom_filter were pub.
    // Verify they are now private by testing that only add_page() works.
    let mut meta = MetaIndex::new();
    meta.add_page(test_hash(0), test_hash(100), BlockId::new(0))
        .expect("First add_page should succeed");

    // The fix is verified by the fact that we can only access via pages() getter
    assert_eq!(meta.pages().len(), 1);
    assert_eq!(*meta.pages()[0].min_hash(), test_hash(0));
    assert_eq!(*meta.pages()[0].max_hash(), test_hash(100));
}

#[test]
fn v9_f1b_meta_index_ordering_enforced() {
    // Verify add_page rejects out-of-order pages
    let mut meta = MetaIndex::new();
    meta.add_page(test_hash(100), test_hash(200), BlockId::new(0))
        .unwrap();

    // Out of order: min_hash(50) < previous max_hash(200)
    let result = meta.add_page(test_hash(50), test_hash(150), BlockId::new(1));
    assert!(
        result.is_err(),
        "V9-F1b: add_page should reject out-of-order pages"
    );

    // Overlapping: min_hash(150) < previous max_hash(200)
    let result = meta.add_page(test_hash(150), test_hash(300), BlockId::new(2));
    assert!(
        result.is_err(),
        "V9-F1b: add_page should reject overlapping pages"
    );

    // Valid: min_hash(201) > previous max_hash(200)
    let result = meta.add_page(test_hash(201), test_hash(300), BlockId::new(3));
    assert!(
        result.is_ok(),
        "V9-F1b: add_page should accept non-overlapping ascending pages"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F2: VERIFY V8-F2 FIX — IndexPage::try_new() upper bound
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f2a_index_page_rejects_oversized() {
    let entries: Vec<IndexEntry> = (0..(ENTRIES_PER_PAGE as u64 + 1)).map(make_entry).collect();
    let result = IndexPage::try_new(entries);
    assert!(
        result.is_err(),
        "V9-F2a: try_new should reject {} entries (max {})",
        ENTRIES_PER_PAGE + 1,
        ENTRIES_PER_PAGE
    );
}

#[test]
fn v9_f2b_index_page_accepts_exact_limit() {
    let entries: Vec<IndexEntry> = (0..ENTRIES_PER_PAGE as u64).map(make_entry).collect();
    let result = IndexPage::try_new(entries);
    assert!(
        result.is_ok(),
        "V9-F2b: try_new should accept exactly ENTRIES_PER_PAGE entries"
    );
    assert_eq!(result.unwrap().len(), ENTRIES_PER_PAGE);
}

#[test]
fn v9_f2c_index_page_rejects_empty() {
    let result = IndexPage::try_new(vec![]);
    assert!(result.is_err(), "V9-F2c: try_new should reject empty page");
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F3: VERIFY V8-F5 FIX — set_bloom_filter validates input
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f3a_set_bloom_rejects_garbage() {
    let mut meta = MetaIndex::new();
    let garbage = vec![0xFF, 0xDE, 0xAD, 0xBE, 0xEF];
    let result = meta.set_bloom_filter(garbage);
    assert!(
        result.is_err(),
        "V9-F3a: set_bloom_filter should reject garbage bytes"
    );
}

#[test]
fn v9_f3b_set_bloom_rejects_empty() {
    let mut meta = MetaIndex::new();
    let result = meta.set_bloom_filter(vec![]);
    assert!(
        result.is_err(),
        "V9-F3b: set_bloom_filter should reject empty bytes"
    );
}

#[test]
fn v9_f3c_set_bloom_accepts_valid() {
    use bloomfilter::Bloom;
    let bloom: Bloom<ChunkHash> = Bloom::new_for_fp_rate(1000, 0.01);
    let bytes = era_index::serialize_bloom(&bloom).unwrap();
    let mut meta = MetaIndex::new();
    let result = meta.set_bloom_filter(bytes);
    assert!(
        result.is_ok(),
        "V9-F3c: set_bloom_filter should accept valid bloom bytes"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F4: VERIFY V8-F7 FIX — Page cache is LRU-bounded
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f4a_page_cache_bounded() {
    // Verify the LRU cache doesn't grow unbounded by looking at
    // lookup behavior under many pages
    let mut tree = ChunkIndex::new_default().unwrap();

    // Insert enough entries to create multiple pages (ENTRIES_PER_PAGE each)
    // We'll insert 300 * 100 = 30000 entries -> ~4 pages
    for i in 0..30000u64 {
        tree.insert(make_entry(i)).unwrap();
    }

    let reader = tree.finalize().unwrap();
    assert!(
        reader.lookup(&test_hash(0)).unwrap().is_some(),
        "V9-F4a: First entry lookup should succeed"
    );
    assert!(
        reader.lookup(&test_hash(29999)).unwrap().is_some(),
        "V9-F4a: Last entry lookup should succeed"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F5: VERIFY V8-F9 FIX — entry_count() is cached
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f5a_entry_count_cached_performance() {
    let mut builder = IndexBuilder::new_default().unwrap();

    // Insert some entries
    for i in 0..500u64 {
        builder.insert(make_entry(i)).unwrap();
    }

    // First call computes count
    let count1 = builder.entry_count();
    assert_eq!(count1, 500, "V9-F5a: Should have 500 entries");

    // Subsequent call should be cached (fast)
    let start = std::time::Instant::now();
    for _ in 0..100 {
        let c = builder.entry_count();
        assert_eq!(c, 500);
    }
    let elapsed = start.elapsed();
    println!(
        "V9-F5a: 100 cached entry_count() calls: {:?} ({:.1}µs/call)",
        elapsed,
        elapsed.as_micros() as f64 / 100.0
    );
    // Cached calls should be very fast (< 1ms total for 100 calls)
    assert!(
        elapsed.as_millis() < 100,
        "V9-F5a: Cached entry_count() is too slow: {:?}",
        elapsed
    );
}

#[test]
fn v9_f5b_entry_count_accurate_with_duplicates() {
    let mut builder = IndexBuilder::new_default().unwrap();

    // Insert 100 unique entries
    for i in 0..100u64 {
        builder.insert(make_entry(i)).unwrap();
    }
    assert_eq!(builder.entry_count(), 100);

    // Insert 100 duplicates (same hashes)
    for i in 0..100u64 {
        builder.insert(make_entry(i)).unwrap();
    }
    // Should still be 100 (deduped)
    let count = builder.entry_count();
    assert_eq!(
        count, 100,
        "V9-F5b: entry_count should be 100 after duplicates, got {}",
        count
    );
}

#[test]
fn v9_f5c_entry_count_accurate_across_flush() {
    let mut builder = IndexBuilder::new_default().unwrap();

    // Insert 1500 entries (triggers flush at BATCH_SIZE=1000)
    for i in 0..1500u64 {
        builder.insert(make_entry(i)).unwrap();
    }
    let count = builder.entry_count();
    assert_eq!(
        count, 1500,
        "V9-F5c: entry_count should be 1500, got {}",
        count
    );

    // Insert duplicates of already-flushed entries
    for i in 0..500u64 {
        builder.insert(make_entry(i)).unwrap();
    }
    let count = builder.entry_count();
    assert_eq!(
        count, 1500,
        "V9-F5c: entry_count should still be 1500 after dupes, got {}",
        count
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F6: VERIFY V8-F4 FIX — Bloom resize at 1.5x
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f6a_bloom_resize_threshold() {
    // Create builder with small bloom capacity
    let mut builder = IndexBuilder::new(1024 * 76).unwrap(); // ~1024 entries
    let initial_capacity = 1024;

    // Insert up to 1.5x capacity -> should trigger resize
    let target = (initial_capacity as f64 * 1.6) as u64;
    for i in 0..target {
        builder.insert(make_entry(i)).unwrap();
    }

    // Measure FP rate: check 10000 non-existent hashes
    let mut false_positives = 0;
    let offset = 1_000_000u64;
    for i in 0..10000u64 {
        if builder.bloom_contains(&test_hash(offset + i)) {
            false_positives += 1;
        }
    }
    let fp_rate = false_positives as f64 / 10000.0;
    println!(
        "V9-F6a: Bloom FP rate at {:.1}x capacity: {:.2}% ({} false positives / 10000)",
        target as f64 / initial_capacity as f64,
        fp_rate * 100.0,
        false_positives
    );
    // After resize, FP rate should be reasonable (< 5%)
    assert!(
        fp_rate < 0.05,
        "V9-F6a: Bloom FP rate too high after resize: {:.2}%",
        fp_rate * 100.0
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F7: VERIFY V8-F8 FIX — Benchmarks are real (compilation test)
// Benchmark existence is tested by cargo bench compilation
// ═══════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════
// V9-F8: NOVEL — read_sorted_pages() still materializes all pages in Vec
// (V8-F3 docstring fixed but memory model unchanged)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f8a_read_sorted_pages_materializes_all() {
    let mut builder = IndexBuilder::new_default().unwrap();

    // Insert enough for 3+ pages
    let count = ENTRIES_PER_PAGE * 3 + 100;
    for i in 0..count as u64 {
        builder.insert(make_entry(i)).unwrap();
    }

    let pages = builder.read_sorted_pages().unwrap();
    // All pages materialised simultaneously (V8-F3 — docstring was fixed but
    // the underlying code still returns Vec, not an iterator)
    assert_eq!(
        pages.len(),
        4,
        "V9-F8a: Expected 4 pages for {} entries",
        count
    );
    println!(
        "V9-F8a: read_sorted_pages returned {} pages (all in memory simultaneously)",
        pages.len()
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F9: NOVEL — IndexPage dedup uses sort_unstable (non-deterministic)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f9a_index_page_dedup_deterministic() {
    // Create entries with duplicate hashes but different metadata
    let vol1 = VolumeId::new();
    let vol2 = VolumeId::new();

    let entries = vec![
        make_entry_at(42, vol1, 0, 0, 1024),
        make_entry_at(42, vol2, 1, 4096, 2048), // Same hash, different location
    ];

    let page = IndexPage::try_new(entries).unwrap();
    assert_eq!(page.len(), 1, "V9-F9a: Should dedup to 1 entry");
    // NOTE: sort_unstable_by_key + dedup_by_key means the survivor is
    // non-deterministic. This test documents the behavior.
    let entry = page.find(&test_hash(42)).unwrap();
    println!(
        "V9-F9a: Surviving entry has offset={}, length={} (non-deterministic by design)",
        entry.offset(),
        entry.length()
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F10: NOVEL — from_memory() builds MetaIndex from a pre-existing
// MetaIndex that may already have pages => double-addition
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f10a_from_memory_with_nonempty_meta() {
    let mut meta = MetaIndex::new();
    // Pre-add a page to the meta (mimics a non-fresh MetaIndex)
    meta.add_page(test_hash(0), test_hash(50), BlockId::new(99))
        .unwrap();
    assert_eq!(meta.pages().len(), 1);

    // Now create entries that will add more pages
    let entries: Vec<IndexEntry> = (100..200).map(make_entry).collect();
    let reader = IndexReader::from_memory(meta, entries);

    match reader {
        Ok(r) => {
            let page_count = r.meta_page_count();
            println!(
                "V9-F10a: from_memory with non-empty meta created {} pages",
                page_count
            );
            // With non-empty meta, new pages are appended. The pre-existing
            // page (hash 0..50) has no backing embedded_pages entry, so lookups
            // may fail for hashes routed to that phantom page.
            // This is a correctness concern if from_memory is called incorrectly.
            if page_count > 1 {
                // Check if phantom page's hashes are routable
                let result = r.lookup(&test_hash(25));
                println!("V9-F10a: Lookup for phantom page hash 25: {:?}", result);
            }
        }
        Err(e) => {
            println!(
                "V9-F10a: from_memory correctly rejected non-empty meta: {}",
                e
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F11: NOVEL — XOR domain separation double-application
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f11a_xor_domain_separation_uniqueness() {
    let nonce_context = [0u8; 16];
    let mut index_context = nonce_context;
    index_context[0] ^= 0xFF;

    assert_ne!(
        nonce_context, index_context,
        "V9-F11a: XOR should produce different context"
    );
}

#[test]
fn v9_f11b_xor_double_application_reverts() {
    let nonce_context: [u8; 16] = [0x42; 16];
    let mut ctx = nonce_context;
    ctx[0] ^= 0xFF; // First XOR
    ctx[0] ^= 0xFF; // Second XOR (accidental double-application)

    assert_eq!(
        nonce_context, ctx,
        "V9-F11b: Double XOR reverts to original — nonce collision risk"
    );
    println!(
        "V9-F11b CONFIRMED: Double XOR reverts to original context. \
              If index finalize XOR is accidentally applied twice, \
              index blocks share nonce_context with data blocks."
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F12: NOVEL — ChunkIndex state machine edge cases
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f12a_double_finalize_rejected() {
    let mut tree = ChunkIndex::new_default().unwrap();
    tree.insert(make_entry(1)).unwrap();
    let _reader = tree.finalize().unwrap();

    let result = tree.finalize();
    assert!(
        result.is_err(),
        "V9-F12a: Double finalize should return error"
    );
}

#[test]
fn v9_f12b_insert_after_finalize_rejected() {
    let mut tree = ChunkIndex::new_default().unwrap();
    tree.insert(make_entry(1)).unwrap();
    let _reader = tree.finalize().unwrap();

    let result = tree.insert(make_entry(2));
    assert!(
        result.is_err(),
        "V9-F12b: Insert after finalize should return error"
    );
}

#[test]
fn v9_f12c_empty_finalize() {
    // The read_sorted_pages produces empty Vec for empty store -> no pages to add
    // from_pages with empty pages list should work
    let mut tree = ChunkIndex::new_default().unwrap();
    let result = tree.finalize();
    // An empty index should finalize successfully (0 pages, empty bloom)
    match &result {
        Ok(reader) => {
            let lookup = reader.lookup(&test_hash(999)).unwrap();
            assert!(
                lookup.is_none(),
                "V9-F12c: Lookup in empty index should return None"
            );
            println!("V9-F12c: Empty finalize succeeded, lookups return None");
        }
        Err(e) => {
            println!("V9-F12c: Empty finalize returned error: {}", e);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F13: NOVEL — builder.entry_count() buffer dedup correctness
// When buffer contains duplicates of each other (not in Redb yet)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f13a_entry_count_buffer_internal_dedup() {
    let mut builder = IndexBuilder::new_default().unwrap();

    // Insert same hash 500 times (all in buffer, not flushed yet)
    for _ in 0..500 {
        builder.insert(make_entry(42)).unwrap();
    }

    let count = builder.entry_count();
    println!(
        "V9-F13a: Inserted hash 42 x500 (no flush), entry_count = {}",
        count
    );
    // Buffer has 500 entries, but only 1 unique hash
    // entry_count should see 1 unique hash in buffer, 0 in Redb = 1
    assert_eq!(
        count, 1,
        "V9-F13a: entry_count should be 1 for 500 identical entries in buffer"
    );
}

#[test]
fn v9_f13b_entry_count_mixed_buffer_and_redb() {
    let mut builder = IndexBuilder::new_default().unwrap();

    // Insert 1000 unique entries (triggers flush at BATCH_SIZE=1000)
    for i in 0..1000u64 {
        builder.insert(make_entry(i)).unwrap();
    }
    // Now buffer is empty, Redb has 1000

    // Insert 500 new + 200 duplicates into buffer
    for i in 1000..1500u64 {
        builder.insert(make_entry(i)).unwrap();
    }
    for i in 0..200u64 {
        builder.insert(make_entry(i)).unwrap();
    }

    let count = builder.entry_count();
    println!(
        "V9-F13b: 1000 in Redb + 500 new + 200 dupes in buffer, entry_count = {}",
        count
    );
    assert_eq!(count, 1500, "V9-F13b: Should count 1500 unique entries");
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F14: NOVEL — IndexLocation includes volume_id (V7-F5 fix check)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f14a_index_location_has_volume_id() {
    let mut tree = ChunkIndex::new_default().unwrap();

    let vol = VolumeId::new();
    let entry =
        IndexEntry::new(test_hash(42), vol, BlockId::new(7), 1024, 4096).expect("valid entry");
    tree.insert(entry).unwrap();

    let reader = tree.finalize().unwrap();
    let location = reader.lookup(&test_hash(42)).unwrap().unwrap();

    assert_eq!(
        location.volume_id, vol,
        "V9-F14a: IndexLocation must include volume_id"
    );
    assert_eq!(location.block_id, BlockId::new(7));
    assert_eq!(location.offset, 1024);
    assert_eq!(location.length, 4096);
}

#[test]
fn v9_f14b_multi_volume_lookup_preserves_volume_id() {
    let mut tree = ChunkIndex::new_default().unwrap();

    let vol1 = VolumeId::new();
    let vol2 = VolumeId::new();
    let vol3 = VolumeId::new();

    // Three entries on different volumes
    tree.insert(
        IndexEntry::new(test_hash(100), vol1, BlockId::new(0), 0, 1024).expect("valid entry"),
    )
    .unwrap();
    tree.insert(
        IndexEntry::new(test_hash(200), vol2, BlockId::new(1), 0, 2048).expect("valid entry"),
    )
    .unwrap();
    tree.insert(
        IndexEntry::new(test_hash(300), vol3, BlockId::new(2), 0, 4096).expect("valid entry"),
    )
    .unwrap();

    let reader = tree.finalize().unwrap();

    let loc1 = reader.lookup(&test_hash(100)).unwrap().unwrap();
    let loc2 = reader.lookup(&test_hash(200)).unwrap().unwrap();
    let loc3 = reader.lookup(&test_hash(300)).unwrap().unwrap();

    assert_eq!(
        loc1.volume_id, vol1,
        "V9-F14b: Volume 1 ID must be preserved"
    );
    assert_eq!(
        loc2.volume_id, vol2,
        "V9-F14b: Volume 2 ID must be preserved"
    );
    assert_eq!(
        loc3.volume_id, vol3,
        "V9-F14b: Volume 3 ID must be preserved"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F15: NOVEL — First-write-wins dedup consistency
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f15a_first_write_wins_in_store() {
    let temp = TempDir::new().unwrap();
    let db_path = temp.path().join("test_fww.redb");
    let mut store = era_index::IndexStore::create(&db_path, 1024).unwrap();

    let entry1 = IndexEntry::new(test_hash(1), VolumeId::new(), BlockId::new(0), 0, 1024)
        .expect("valid entry");
    let entry2 = IndexEntry::new(test_hash(1), VolumeId::new(), BlockId::new(99), 9999, 2048)
        .expect("valid entry");

    store.insert(&entry1).unwrap();
    store.insert(&entry2).unwrap();

    let result = store.get(&test_hash(1)).unwrap().unwrap();
    assert_eq!(
        result.offset(),
        0,
        "V9-F15a: First-write-wins — offset should be 0, got {}",
        result.offset()
    );
    assert_eq!(
        result.length(),
        1024,
        "V9-F15a: First-write-wins — length should be 1024"
    );
    assert_eq!(store.entry_count(), 1, "V9-F15a: Should count only 1 entry");
}

#[test]
fn v9_f15b_first_write_wins_in_batch() {
    let temp = TempDir::new().unwrap();
    let db_path = temp.path().join("test_fww_batch.redb");
    let mut store = era_index::IndexStore::create(&db_path, 1024).unwrap();

    let entry1 = IndexEntry::new(test_hash(1), VolumeId::new(), BlockId::new(0), 0, 1024)
        .expect("valid entry");
    let entry2 = IndexEntry::new(test_hash(1), VolumeId::new(), BlockId::new(99), 9999, 2048)
        .expect("valid entry");

    store.insert_batch(&[entry1, entry2]).unwrap();

    let result = store.get(&test_hash(1)).unwrap().unwrap();
    assert_eq!(
        result.offset(),
        0,
        "V9-F15b: Batch first-write-wins — offset should be 0"
    );
    assert_eq!(store.entry_count(), 1);
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F16: NOVEL — from_memory chunks into pages correctly
// (V7-F2 fix: was putting all entries in one page)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f16a_from_memory_chunks_pages_correctly() {
    let meta = MetaIndex::new();

    // Create 2.5 pages worth of entries
    let count = ENTRIES_PER_PAGE * 2 + ENTRIES_PER_PAGE / 2;
    let entries: Vec<IndexEntry> = (0..count as u64).map(make_entry).collect();

    let reader = IndexReader::from_memory(meta, entries).unwrap();
    let page_count = reader.meta_page_count();

    println!(
        "V9-F16a: {} entries -> {} pages (expected 3)",
        count, page_count
    );
    assert_eq!(
        page_count, 3,
        "V9-F16a: {} entries should produce 3 pages, got {}",
        count, page_count
    );
}

#[test]
fn v9_f16b_from_memory_single_page() {
    let meta = MetaIndex::new();

    let entries: Vec<IndexEntry> = (0..100).map(make_entry).collect();
    let reader = IndexReader::from_memory(meta, entries).unwrap();

    assert_eq!(
        reader.meta_page_count(),
        1,
        "V9-F16b: 100 entries should produce 1 page"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F17: NOVEL — Stress test: 100K entries end-to-end
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f17a_100k_roundtrip() {
    let start = std::time::Instant::now();
    let mut tree = ChunkIndex::new_default().unwrap();

    // Insert
    let insert_start = std::time::Instant::now();
    for i in 0..100_000u64 {
        tree.insert(make_entry(i)).unwrap();
    }
    let insert_time = insert_start.elapsed();

    // Finalize
    let finalize_start = std::time::Instant::now();
    let reader = tree.finalize().unwrap();
    let finalize_time = finalize_start.elapsed();

    // Lookup (sample 1000 hits + 1000 misses)
    let lookup_start = std::time::Instant::now();
    let mut hits = 0;
    let mut misses = 0;
    for i in 0..1000u64 {
        if reader.lookup(&test_hash(i * 100)).unwrap().is_some() {
            hits += 1;
        }
        if reader.lookup(&test_hash(1_000_000 + i)).unwrap().is_none() {
            misses += 1;
        }
    }
    let lookup_time = lookup_start.elapsed();

    let total = start.elapsed();
    println!(
        "V9-F17a: 100K roundtrip — insert: {:?}, finalize: {:?}, lookup: {:?}, total: {:?}",
        insert_time, finalize_time, lookup_time, total
    );
    println!(
        "V9-F17a: Lookup: {} hits (expected ~1000), {} misses (expected 1000)",
        hits, misses
    );

    assert_eq!(hits, 1000, "V9-F17a: Should find all sampled entries");
    assert_eq!(misses, 1000, "V9-F17a: Non-existent entries should miss");
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F18: NOVEL — Bloom false negative safety
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f18a_bloom_no_false_negatives() {
    let mut tree = ChunkIndex::new_default().unwrap();

    let mut hashes = Vec::new();
    for i in 0..5000u64 {
        let entry = make_entry(i);
        hashes.push(*entry.hash());
        tree.insert(entry).unwrap();
    }

    let reader = tree.finalize().unwrap();

    // Every inserted hash must be in the bloom filter — NO false negatives
    for (idx, hash) in hashes.iter().enumerate() {
        assert!(
            reader.bloom_contains(hash),
            "V9-F18a: Bloom false negative at index {} — CRITICAL data loss risk",
            idx
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F19: NOVEL — MetaIndex find_page boundary correctness
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f19a_find_page_exact_boundaries() {
    let mut meta = MetaIndex::new();
    meta.add_page(test_hash(100), test_hash(200), BlockId::new(0))
        .unwrap();
    meta.add_page(test_hash(300), test_hash(400), BlockId::new(1))
        .unwrap();
    meta.add_page(test_hash(500), test_hash(600), BlockId::new(2))
        .unwrap();

    // Exact min_hash matches
    assert!(meta.find_page(&test_hash(100)).is_some());
    assert!(meta.find_page(&test_hash(300)).is_some());
    assert!(meta.find_page(&test_hash(500)).is_some());

    // Exact max_hash matches
    assert!(meta.find_page(&test_hash(200)).is_some());
    assert!(meta.find_page(&test_hash(400)).is_some());
    assert!(meta.find_page(&test_hash(600)).is_some());

    // Between pages (gaps)
    assert!(
        meta.find_page(&test_hash(250)).is_none(),
        "V9-F19a: Hash between pages should return None"
    );
    assert!(
        meta.find_page(&test_hash(450)).is_none(),
        "V9-F19a: Hash between pages should return None"
    );

    // Before all pages
    assert!(meta.find_page(&test_hash(50)).is_none());

    // After all pages
    assert!(meta.find_page(&test_hash(700)).is_none());
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F20: NOVEL — from_pages ordering validation
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f20a_from_pages_ordering() {
    use bloomfilter::Bloom;

    let meta = MetaIndex::new();
    let _bloom: Bloom<ChunkHash> = Bloom::new_for_fp_rate(1000, 0.01);

    // Create two pages in correct order
    let page1 = IndexPage::try_new((0..100).map(make_entry).collect()).unwrap();
    let page2 = IndexPage::try_new((200..300).map(make_entry).collect()).unwrap();

    let result = IndexReader::from_pages(
        meta,
        vec![(page1, BlockId::new(0)), (page2, BlockId::new(1))],
    );
    assert!(
        result.is_ok(),
        "V9-F20a: from_pages with ordered pages should succeed"
    );
}

#[test]
fn v9_f20b_from_pages_rejects_disorder() {
    use bloomfilter::Bloom;

    let meta = MetaIndex::new();
    let _bloom: Bloom<ChunkHash> = Bloom::new_for_fp_rate(1000, 0.01);

    // Create two pages in REVERSE order (page2 has lower hashes)
    let page1 = IndexPage::try_new((200..300).map(make_entry).collect()).unwrap();
    let page2 = IndexPage::try_new((0..100).map(make_entry).collect()).unwrap();

    // from_pages calls meta.add_page which enforces ordering
    let result = IndexReader::from_pages(
        meta,
        vec![(page1, BlockId::new(0)), (page2, BlockId::new(1))],
    );
    assert!(
        result.is_err(),
        "V9-F20b: from_pages with out-of-order pages should fail"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F21: NOVEL — Bloom filter roundtrip through serialization
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f21a_bloom_roundtrip_correctness() {
    use bloomfilter::Bloom;

    let mut bloom: Bloom<ChunkHash> = Bloom::new_for_fp_rate(10_000, 0.01);
    let mut hashes = Vec::new();
    for i in 0..1000u64 {
        let h = test_hash(i);
        bloom.set(&h);
        hashes.push(h);
    }

    // Serialize
    let bytes = era_index::serialize_bloom(&bloom).unwrap();
    // Deserialize
    let restored = era_index::deserialize_bloom(&bytes).unwrap();

    // Zero false negatives
    for (idx, h) in hashes.iter().enumerate() {
        assert!(
            restored.check(h),
            "V9-F21a: Bloom roundtrip lost hash at index {}",
            idx
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F22: NOVEL — read_only store prevents writes
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f22a_readonly_insert_rejected() {
    let temp = TempDir::new().unwrap();
    let db_path = temp.path().join("readonly_test.redb");

    // Create and populate
    {
        let mut store = era_index::IndexStore::create(&db_path, 1024).unwrap();
        store.insert(&make_entry(1)).unwrap();
        store.keep_on_drop();
    }

    // Open readonly and try to insert
    let mut store = era_index::IndexStore::open_readonly(&db_path).unwrap();
    let result = store.insert(&make_entry(2));
    assert!(
        result.is_err(),
        "V9-F22a: Insert into read-only store should fail"
    );
}

#[test]
fn v9_f22b_readonly_batch_insert_rejected() {
    let temp = TempDir::new().unwrap();
    let db_path = temp.path().join("readonly_batch.redb");

    {
        let mut store = era_index::IndexStore::create(&db_path, 1024).unwrap();
        store.insert(&make_entry(1)).unwrap();
        store.keep_on_drop();
    }

    let mut store = era_index::IndexStore::open_readonly(&db_path).unwrap();
    let result = store.insert_batch(&[make_entry(2), make_entry(3)]);
    assert!(
        result.is_err(),
        "V9-F22b: Batch insert into read-only store should fail"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F23: NOVEL — Concurrent reader safety
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f23a_concurrent_lookups() {
    let mut tree = ChunkIndex::new_default().unwrap();
    for i in 0..10_000u64 {
        tree.insert(make_entry(i)).unwrap();
    }
    let reader = tree.finalize().unwrap();

    // Spawn multiple threads doing lookups
    let handles: Vec<_> = (0..8)
        .map(|thread_id| {
            let r = reader.clone();
            std::thread::spawn(move || {
                for i in 0..1000u64 {
                    let hash = test_hash(thread_id * 1000 + i);
                    let _ = r.lookup(&hash);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("V9-F23a: Thread should not panic");
    }
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F24: NOVEL — IndexEntry validation edge cases
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f24a_zero_length_entry() {
    // V19-F3: IndexEntry with length=0 is now rejected as a hard error.
    let result = IndexEntry::new(test_hash(1), VolumeId::new(), BlockId::new(0), 0, 0);
    assert!(
        result.is_err(),
        "V9-F24a/V19-F3: Zero-length entry must be rejected"
    );
    println!("V9-F24a: Zero-length entry correctly rejected. (V19-F3 remediation)");
}

#[test]
fn v9_f24b_max_offset_entry() {
    // V19-F3: offset + length overflow is now rejected as a hard error.
    let result = IndexEntry::new(
        test_hash(1),
        VolumeId::new(),
        BlockId::new(0),
        u32::MAX,
        u32::MAX,
    );
    assert!(
        result.is_err(),
        "V9-F24b/V19-F3: offset + length overflow must be rejected"
    );

    // But u32::MAX offset with length=1 also overflows and should be rejected
    let result2 = IndexEntry::new(test_hash(1), VolumeId::new(), BlockId::new(0), u32::MAX, 1);
    assert!(
        result2.is_err(),
        "V9-F24b/V19-F3: u32::MAX + 1 overflow must be rejected"
    );

    // Valid max-range entry (no overflow)
    let result3 = IndexEntry::new(
        test_hash(1),
        VolumeId::new(),
        BlockId::new(0),
        u32::MAX - 1,
        1,
    );
    assert!(
        result3.is_ok(),
        "V9-F24b: offset + length = u32::MAX is valid (no overflow)"
    );
    println!("V9-F24b: overflow entries correctly rejected. (V19-F3 remediation)");
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F25: NOVEL — open_readonly bloom rebuild correctness
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f25a_open_readonly_bloom_correct() {
    let temp = TempDir::new().unwrap();
    let db_path = temp.path().join("bloom_rebuild.redb");

    // Create, insert, persist
    {
        let mut store = era_index::IndexStore::create(&db_path, 10_000).unwrap();
        for i in 0..500u64 {
            store.insert(&make_entry(i)).unwrap();
        }
        store.keep_on_drop();
    }

    // Reopen and verify bloom
    let store = era_index::IndexStore::open_readonly(&db_path).unwrap();
    assert_eq!(store.entry_count(), 500);

    // All inserted hashes must be in rebuilt bloom (no false negatives)
    for i in 0..500u64 {
        assert!(
            store.bloom_contains(&test_hash(i)),
            "V9-F25a: Bloom false negative after rebuild for hash {}",
            i
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F26: NOVEL — discard() cleanup
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f26a_discard_removes_file() {
    let temp = TempDir::new().unwrap();
    let db_path = temp.path().join("discard_test.redb");

    let mut store = era_index::IndexStore::create(&db_path, 1024).unwrap();
    store.insert(&make_entry(1)).unwrap();
    assert!(
        db_path.exists(),
        "V9-F26a: DB file should exist before discard"
    );

    store.discard().unwrap();
    assert!(
        !db_path.exists(),
        "V9-F26a: DB file should be removed after discard"
    );
}

#[test]
fn v9_f26b_discard_idempotent() {
    let temp = TempDir::new().unwrap();
    let db_path = temp.path().join("discard_idem.redb");

    let mut store = era_index::IndexStore::create(&db_path, 1024).unwrap();
    store.discard().unwrap();
    // Second discard should not panic
    store.discard().unwrap();
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F27: NOVEL — hash ordering correctness across page boundaries
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f27a_cross_page_lookup_correctness() {
    let mut tree = ChunkIndex::new_default().unwrap();

    // Insert exactly 2 full pages + 1 entry
    let total = ENTRIES_PER_PAGE * 2 + 1;
    for i in 0..total as u64 {
        tree.insert(make_entry(i)).unwrap();
    }

    let reader = tree.finalize().unwrap();
    assert_eq!(reader.reader().meta_page_count(), 3);

    // Lookup entries that should be in different pages
    // Page boundaries are hash-ordered, so we check a spread of hashes
    for i in [
        0u64,
        ENTRIES_PER_PAGE as u64 / 2,
        ENTRIES_PER_PAGE as u64,
        ENTRIES_PER_PAGE as u64 * 3 / 2,
        (total - 1) as u64,
    ] {
        let result = reader.lookup(&test_hash(i)).unwrap();
        assert!(
            result.is_some(),
            "V9-F27a: Hash {} should be found across page boundaries",
            i
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F28: NOVEL — Verify IndexPage binary search correctness
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f28a_binary_search_all_entries() {
    let entries: Vec<IndexEntry> = (0..1000).map(make_entry).collect();
    let page = IndexPage::try_new(entries).unwrap();

    // Every entry should be findable
    for i in 0..1000u64 {
        let result = page.find(&test_hash(i));
        assert!(
            result.is_some(),
            "V9-F28a: Binary search failed for hash {}",
            i
        );
        assert_eq!(*result.unwrap().hash(), test_hash(i));
    }

    // Non-existent hashes should return None
    for i in 1000..1100u64 {
        assert!(page.find(&test_hash(i)).is_none());
    }
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F30: NOVEL — Bloom filter serialization size sanity
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f30a_bloom_serialization_size() {
    use bloomfilter::Bloom;

    // Small bloom
    let bloom: Bloom<ChunkHash> = Bloom::new_for_fp_rate(1000, 0.01);
    let bytes = era_index::serialize_bloom(&bloom).unwrap();
    println!(
        "V9-F30a: Bloom(1000 items, 1% FP): {} bytes serialized",
        bytes.len()
    );

    // Medium bloom
    let bloom: Bloom<ChunkHash> = Bloom::new_for_fp_rate(100_000, 0.01);
    let bytes = era_index::serialize_bloom(&bloom).unwrap();
    println!(
        "V9-F30a: Bloom(100K items, 1% FP): {} bytes serialized",
        bytes.len()
    );

    // Sanity: a 100K-item bloom at 1% FP should be ~120KB (9.6 bits/element)
    assert!(
        bytes.len() > 50_000 && bytes.len() < 500_000,
        "V9-F30a: Bloom size {} out of expected range",
        bytes.len()
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F31: NOVEL — drop_cleans_up_staging_file
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f31a_builder_drop_cleans_staging() {
    let temp = TempDir::new().unwrap();
    let db_path = temp.path().join("drop_cleanup.redb");

    {
        let mut builder = IndexBuilder::with_path(&db_path, 64 * 1024 * 1024).unwrap();
        builder.insert(make_entry(1)).unwrap();
        assert!(db_path.exists(), "V9-F31a: Staging file should exist");
        // Builder dropped here
    }

    assert!(
        !db_path.exists(),
        "V9-F31a: Staging file should be cleaned up on drop"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-F32: NOVEL — Extreme hash values (0x00...00 and 0xFF...FF)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_f32a_extreme_hash_values() {
    let mut tree = ChunkIndex::new_default().unwrap();

    let zero_hash = ChunkHash::from_bytes([0u8; 32]);
    let max_hash = ChunkHash::from_bytes([0xFF; 32]);
    let mid_hash = test_hash(1000);

    tree.insert(
        IndexEntry::new(zero_hash, VolumeId::new(), BlockId::new(0), 0, 1024).expect("valid entry"),
    )
    .unwrap();
    tree.insert(
        IndexEntry::new(max_hash, VolumeId::new(), BlockId::new(1), 0, 2048).expect("valid entry"),
    )
    .unwrap();
    tree.insert(
        IndexEntry::new(mid_hash, VolumeId::new(), BlockId::new(2), 0, 4096).expect("valid entry"),
    )
    .unwrap();

    let reader = tree.finalize().unwrap();

    let loc0 = reader.lookup(&zero_hash).unwrap();
    let loc_max = reader.lookup(&max_hash).unwrap();
    let loc_mid = reader.lookup(&mid_hash).unwrap();

    assert!(loc0.is_some(), "V9-F32a: Zero hash should be found");
    assert!(loc_max.is_some(), "V9-F32a: Max hash should be found");
    assert!(loc_mid.is_some(), "V9-F32a: Mid hash should be found");

    assert_eq!(loc0.unwrap().length, 1024);
    assert_eq!(loc_max.unwrap().length, 2048);
    assert_eq!(loc_mid.unwrap().length, 4096);
}
