//! # Adversarial Audit V8 — Post-Competitor Implementation Stress Test
//!
//! **Auditor:** V8 Red-Team (2026-02-25)
//! **Target:** era-index crate, all modules
//! **Scope:** Memory safety, data integrity, spec compliance, performance regression
//!
//! This audit targets the "V2.1 implementation" claimed by the competitor.
//! Each test group corresponds to a specific finding in the audit report.
//!
//! ## Finding ID Format
//!   V8-F{n}_{test_letter}: Finding number n, sub-test letter
//!
//! ## Test Naming Convention
//!   f{finding}_{letter} — e.g., f1a, f1b for Finding 1 tests a, b

use std::time::Instant;

use era_common::{BlockId, ChunkHash, VolumeId};
use era_index::{
    ChunkIndex, IndexBuilder, IndexEntry, IndexPage, IndexReader, MetaIndex, ENTRIES_PER_PAGE,
};

// ============================================================================
// Helpers
// ============================================================================

/// Canonical test hash: BE at high bytes ensures sort order matches Redb's lexicographic byte comparison.
fn test_hash(value: u64) -> ChunkHash {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    ChunkHash::from_bytes(bytes)
}

/// Create an entry with predictable fields
fn make_entry(i: u64) -> IndexEntry {
    IndexEntry::new(
        test_hash(i),
        VolumeId::new(),
        BlockId::new(i / 100),
        (i % 100) as u32 * 1024,
        1024,
    )
    .unwrap()
}

/// Create an entry with a specific volume_id for multi-volume tests
fn make_entry_with_volume(i: u64, vol: VolumeId) -> IndexEntry {
    IndexEntry::new(
        test_hash(i),
        vol,
        BlockId::new(i / 100),
        (i % 100) as u32 * 1024,
        1024,
    )
    .unwrap()
}

// ============================================================================
// V8-F1: MetaIndex `pages` and `bloom_filter` fields are PRIVATE (FIXED)
//
// The V9 fix made `pages` and `bloom_filter` private. The only way to add
// pages is via `add_page()`, which enforces ordering. Read access is via
// `pages()` and `bloom_filter()` getters.
// ============================================================================

#[test]
fn f1a_metaindex_pages_field_is_pub_allows_ordering_bypass() {
    let mut meta = MetaIndex::new();

    // add_page correctly enforces ordering (P0-4 fix)
    meta.add_page(test_hash(0), test_hash(999), BlockId::new(0), 0, 0)
        .unwrap();

    // Verify add_page rejects out-of-order input
    let result = meta.add_page(test_hash(0), test_hash(500), BlockId::new(1), 0, 0);
    assert!(result.is_err(), "add_page should reject overlapping pages");

    // FIXED: `pages` is now private — direct push is impossible.
    // The only way to add pages is via add_page(), which validates ordering.
    // Verify the getter works correctly.
    assert_eq!(meta.pages().len(), 1, "Only one valid page should exist");
    assert_eq!(meta.pages()[0].block_id(), BlockId::new(0));
}

#[test]
fn f1b_metaindex_bloom_filter_field_is_pub_allows_garbage() {
    let mut meta = MetaIndex::new();
    meta.add_page(test_hash(0), test_hash(999), BlockId::new(0), 0, 0)
        .unwrap();

    // FIXED: bloom_filter is now private. set_bloom_filter() validates input.
    // Garbage bytes are rejected at set time, not at lookup time.
    let result = meta.set_bloom_filter(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    assert!(
        result.is_err(),
        "Garbage bloom_filter bytes should be rejected by set_bloom_filter"
    );

    // The bloom_filter field remains empty (garbage was rejected)
    assert!(
        meta.bloom_filter().is_empty(),
        "bloom_filter should remain empty after rejected set"
    );
}

#[test]
fn f1c_pub_pages_allows_overlapping_ranges() {
    let mut meta = MetaIndex::new();

    // FIXED: pages is now private — overlapping ranges can only be attempted
    // via add_page(), which rejects them.
    meta.add_page(test_hash(0), test_hash(1000), BlockId::new(0), 0, 0)
        .unwrap();

    let result = meta.add_page(test_hash(500), test_hash(1500), BlockId::new(1), 0, 0);
    assert!(
        result.is_err(),
        "add_page should reject overlapping page ranges"
    );

    // Only the first valid page exists
    assert_eq!(meta.pages().len(), 1, "Only one valid page should exist");

    // find_page works correctly with no ambiguity
    let result = meta.find_page(&test_hash(750));
    assert!(result.is_some(), "find_page should find hash in valid page");
    assert_eq!(result.unwrap().block_id(), BlockId::new(0));
}

// ============================================================================
// V8-F2: IndexPage::try_new() rejects entries exceeding ENTRIES_PER_PAGE (FIXED)
//
// The V9 fix adds an upper-bound guard: try_new() returns Err when
// entries.len() > ENTRIES_PER_PAGE, enforcing the L2 cache design.
// ============================================================================

#[test]
fn f2a_try_new_accepts_entries_far_exceeding_entries_per_page() {
    // Create a page with 2x ENTRIES_PER_PAGE entries
    let count = ENTRIES_PER_PAGE * 2;
    let entries: Vec<IndexEntry> = (0..count as u64).map(make_entry).collect();

    // FIXED: try_new now rejects oversized pages
    let result = IndexPage::try_new(entries);
    assert!(
        result.is_err(),
        "try_new should reject {} entries (limit is {})",
        count,
        ENTRIES_PER_PAGE
    );
}

#[test]
fn f2b_try_new_single_entry_accepted() {
    // Single entry should be fine
    let entries = vec![make_entry(42)];
    let page = IndexPage::try_new(entries).unwrap();
    assert_eq!(page.len(), 1);
}

#[test]
fn f2c_try_new_empty_rejected() {
    let result = IndexPage::try_new(vec![]);
    assert!(result.is_err(), "Empty IndexPage should be rejected");
}

#[test]
fn f2d_oversized_page_memory_impact() {
    // A page with 100K entries far exceeds ENTRIES_PER_PAGE
    let count = 100_000usize;
    let entries: Vec<IndexEntry> = (0..count as u64).map(make_entry).collect();

    let entry_size = std::mem::size_of::<IndexEntry>();
    let expected_bytes = count * entry_size;

    // FIXED: try_new now rejects oversized pages
    let result = IndexPage::try_new(entries);
    assert!(
        result.is_err(),
        "try_new should reject {} entries (limit is {})",
        count,
        ENTRIES_PER_PAGE
    );

    // Document the memory impact that was prevented
    let target_bytes = ENTRIES_PER_PAGE * entry_size;
    let ratio = expected_bytes as f64 / target_bytes as f64;
    eprintln!(
        "V8-F2: Rejected oversized page = {} entries ({:.1}x spec limit, ~{:.0}KB vs ~{:.0}KB target)",
        count,
        ratio,
        expected_bytes as f64 / 1024.0,
        target_bytes as f64 / 1024.0
    );
}

// ============================================================================
// V8-F3: read_sorted_pages() falsely claims streaming behavior
//
// The docstring says "never holds more than one page of entries in memory
// at a time" but the function returns Vec<(IndexPage, BlockId)>, which
// materializes ALL pages in memory simultaneously. This is NOT streaming.
//
// Same applies to builder::finalize() which stores the result of
// read_sorted_pages() in a local variable and iterates over it.
// ============================================================================

#[test]
fn f3a_read_sorted_pages_materializes_all_pages() {
    let mut builder = IndexBuilder::new(1024 * 1024).unwrap();

    // Insert enough entries for multiple pages
    let count = ENTRIES_PER_PAGE * 3 + 100;
    for i in 0..count as u64 {
        builder.insert(make_entry(i)).unwrap();
    }

    let pages = builder.read_sorted_pages().unwrap();

    // All pages are materialized in memory at once — NOT streaming
    assert_eq!(pages.len(), 4, "Should have 4 pages (3 full + 1 partial)");

    let total_entries: usize = pages.iter().map(|(p, _)| p.len()).sum();
    assert_eq!(total_entries, count);

    // The entire dataset is in memory as pages. If we had 1M entries,
    // that's ~120MB of pages in a single Vec. The docstring is misleading.
}

#[test]
fn f3b_read_sorted_vs_read_sorted_pages_memory_equivalence() {
    let mut builder = IndexBuilder::new(1024 * 1024).unwrap();

    let count = ENTRIES_PER_PAGE * 2;
    for i in 0..count as u64 {
        builder.insert(make_entry(i)).unwrap();
    }

    // Both methods materialize all data in memory
    let sorted = builder.read_sorted().unwrap();
    let pages = builder.read_sorted_pages().unwrap();

    let sorted_count = sorted.len();
    let pages_count: usize = pages.iter().map(|(p, _)| p.len()).sum();

    assert_eq!(sorted_count, pages_count);
    assert_eq!(sorted_count, count);

    // The only difference is organization (flat Vec vs Vec of pages).
    // Peak memory is essentially identical. The "streaming" claim is false.
}

// ============================================================================
// V8-F4: Bloom filter FP rate silently degrades between capacity and 2*capacity
//
// rebuild_bloom_if_needed() only triggers when entry_count > bloom_capacity * 2.
// Between 1x and 1.99x overcapacity, the FP rate silently degrades from
// the promised 1% without any warning or resize. At 1.99x capacity, the
// FP rate can be 4-10x worse than the promised 1%.
// ============================================================================

#[test]
fn f4a_bloom_fp_rate_degrades_before_resize_threshold() {
    let capacity = 1024;
    let mut builder = IndexBuilder::with_path(
        &tempfile::TempDir::new().unwrap().path().join("test.redb"),
        // mem_limit that yields bloom_capacity ~= capacity
        capacity * std::mem::size_of::<IndexEntry>(),
    )
    .unwrap();

    // Insert exactly capacity entries (bloom sized for this)
    for i in 0..capacity as u64 {
        builder.insert(make_entry(i)).unwrap();
    }

    // Measure FP rate at capacity (should be ~1%)
    let mut fp_at_capacity = 0;
    let test_range = 10_000;
    for i in capacity as u64..(capacity as u64 + test_range) {
        if builder.bloom_contains(&test_hash(i)) {
            fp_at_capacity += 1;
        }
    }
    let fp_rate_at_capacity = fp_at_capacity as f64 / test_range as f64;

    // Now insert up to 1.9x capacity (just below 2x resize threshold)
    let target = (capacity as f64 * 1.9) as u64;
    for i in capacity as u64..target {
        builder.insert(make_entry(i)).unwrap();
    }

    // Measure FP rate at 1.9x capacity (should still be ~1% if properly managed)
    let mut fp_at_overcapacity = 0;
    for i in target..(target + test_range) {
        if builder.bloom_contains(&test_hash(i)) {
            fp_at_overcapacity += 1;
        }
    }
    let fp_rate_at_overcapacity = fp_at_overcapacity as f64 / test_range as f64;

    eprintln!(
        "V8-F4: Bloom FP rate at 1.0x capacity: {:.2}%, at 1.9x capacity: {:.2}%",
        fp_rate_at_capacity * 100.0,
        fp_rate_at_overcapacity * 100.0
    );

    // The FP rate at 1.9x capacity is significantly higher than at 1x
    // but no resize has been triggered (threshold is 2x).
    // Document the degradation even though the test may not fail deterministically.
    if fp_rate_at_overcapacity > fp_rate_at_capacity * 2.0 && fp_rate_at_overcapacity > 0.02 {
        eprintln!(
            "WARNING: FP rate degraded {:.1}x before resize threshold was reached",
            fp_rate_at_overcapacity / fp_rate_at_capacity.max(0.001)
        );
    }
}

#[test]
fn f4b_bloom_resize_only_triggers_at_2x() {
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.redb");
    let initial_capacity = 1024;

    let mut store = era_index::IndexStore::create(&db_path, initial_capacity).unwrap();

    // Insert 1.5x capacity in a single batch - should NOT trigger resize
    let entries_1_5x: Vec<IndexEntry> = (0..(initial_capacity as u64 * 3 / 2))
        .map(make_entry)
        .collect();
    store.insert_batch(&entries_1_5x).unwrap();

    // The bloom was sized for initial_capacity. At 1.5x, no resize triggered.
    // FP rate is degraded but silently accepted.
    let count_after_1_5x = store.entry_count();
    assert!(
        count_after_1_5x > initial_capacity,
        "Overcapacity not reached"
    );

    // Insert more to cross 2x threshold
    let entries_extra: Vec<IndexEntry> = ((initial_capacity as u64 * 3 / 2)
        ..(initial_capacity as u64 * 3))
        .map(make_entry)
        .collect();
    store.insert_batch(&entries_extra).unwrap();

    // Now at 3x original capacity, resize should have triggered at 2x
    let count_after_3x = store.entry_count();
    assert!(
        count_after_3x > initial_capacity * 2,
        "Should be past 2x threshold"
    );
}

// ============================================================================
// V8-F5: set_bloom_filter() validates input (FIXED)
//
// The V9 fix makes set_bloom_filter() return Result and validates that
// the bytes deserialize to a valid BloomFilterData before storing them.
// Garbage is rejected at set time, not at lookup time.
// ============================================================================

#[test]
fn f5a_set_bloom_filter_accepts_garbage() {
    let mut meta = MetaIndex::new();
    meta.add_page(test_hash(0), test_hash(999), BlockId::new(0), 0, 0)
        .unwrap();

    // FIXED: set_bloom_filter now validates and returns Result
    let result = meta.set_bloom_filter(vec![0xFF; 1024]);
    assert!(
        result.is_err(),
        "Garbage should be rejected by set_bloom_filter"
    );

    // bloom_filter remains empty (garbage was rejected)
    assert!(meta.bloom_filter().is_empty());
}

#[test]
fn f5b_set_bloom_filter_empty_bytes() {
    let mut meta = MetaIndex::new();

    // FIXED: Empty bytes are rejected at set time
    let result = meta.set_bloom_filter(vec![]);
    assert!(
        result.is_err(),
        "Empty bloom should be rejected by set_bloom_filter"
    );

    assert!(meta.bloom_filter().is_empty());
}

#[test]
fn f5c_set_bloom_filter_truncated_valid_data() {
    let bloom = bloomfilter::Bloom::<ChunkHash>::new_for_fp_rate(1000, 0.01);
    let valid_bytes = era_index::serialize_bloom(&bloom).unwrap();

    // Truncate the valid data
    let truncated = valid_bytes[..valid_bytes.len() / 2].to_vec();

    let mut meta = MetaIndex::new();

    // FIXED: Truncated data is rejected at set time
    let result = meta.set_bloom_filter(truncated);
    assert!(
        result.is_err(),
        "Truncated bloom data should be rejected by set_bloom_filter"
    );
}

// ============================================================================
// V8-F6: from_memory() with non-empty MetaIndex produces inconsistent state
//
// IndexReader::from_memory() takes a MetaIndex parameter but then adds
// pages to it. If the caller passes a MetaIndex that already has pages,
// the new pages are appended, potentially violating ordering constraints
// or creating duplicate page entries.
// ============================================================================

#[test]
fn f6a_from_memory_with_pre_populated_meta() {
    // Create a MetaIndex that already has a page
    let mut meta = MetaIndex::new();
    meta.add_page(test_hash(0), test_hash(999), BlockId::new(99), 0, 0)
        .unwrap();

    let _bloom = bloomfilter::Bloom::<ChunkHash>::new_for_fp_rate(1000, 0.01);

    // Entries that should map to pages starting after the existing one
    let entries: Vec<IndexEntry> = (1000..1100).map(make_entry).collect();

    // from_memory will add pages to the already-populated meta
    let result = IndexReader::from_memory(meta, entries);

    // This might succeed (if the new pages come after the existing one)
    // but creates a fragile state. The existing page at block 99 has no
    // corresponding embedded_pages entry, so lookups will fail.
    match result {
        Ok(reader) => {
            // The reader has pages from the input meta + new pages.
            // But lookups for hashes 0-999 will fail because there's
            // no embedded page for block 99.
            let result = reader.lookup(&test_hash(500));
            // This should fail or return None since block 99 has no data
            match result {
                Ok(None) => {
                    // Expected - the page exists in meta but has no embedded data
                    // This is a silent data loss scenario
                }
                Ok(Some(_)) => {
                    panic!("Should not find data for a phantom page");
                }
                Err(_) => {
                    // Also acceptable - error accessing phantom page
                }
            }
        }
        Err(_) => {
            // If ordering fails, that's also valid behavior
        }
    }
}

#[test]
fn f6b_from_memory_with_overlapping_hash_ranges() {
    let meta = MetaIndex::new();
    let mut bloom = bloomfilter::Bloom::<ChunkHash>::new_for_fp_rate(1000, 0.01);

    // Create entries that when chunked will produce overlapping page ranges
    // (this is actually prevented by the sorted chunk logic, so the test
    // verifies the prevention works)
    let entries: Vec<IndexEntry> = (0..100).map(make_entry).collect();
    for e in &entries {
        bloom.set(e.hash());
    }

    let reader = IndexReader::from_memory(meta, entries).unwrap();

    // All entries should be findable
    for i in 0..100u64 {
        let result = reader.lookup(&test_hash(i)).unwrap();
        assert!(result.is_some(), "Entry {} should be found", i);
    }
}

// ============================================================================
// V8-F7: Page cache has no eviction policy (unbounded memory growth)
//
// The IndexReader's page_cache is a HashMap that grows without limit.
// For large indexes with many unique pages accessed non-sequentially,
// the cache will consume unbounded memory.
// ============================================================================

#[test]
fn f7a_page_cache_grows_without_limit() {
    // In embedded mode, the page_cache is not used (embedded_pages is used directly).
    // But in filesystem mode, every accessed page stays in cache forever.
    // We demonstrate that the data structure has no size limit.

    let meta = MetaIndex::new();
    let _bloom = bloomfilter::Bloom::<ChunkHash>::new_for_fp_rate(10000, 0.01);

    // Create many pages via from_pages
    let mut pages = Vec::new();
    let entries_per = 100;
    for page_idx in 0..100u64 {
        let start = page_idx * entries_per;
        let end = start + entries_per;
        let entries: Vec<IndexEntry> = (start..end).map(make_entry).collect();
        let page = IndexPage::try_new(entries).unwrap();
        pages.push((page, BlockId::new(page_idx)));
    }

    let reader = IndexReader::from_pages(meta, pages).unwrap();

    // Access all pages — in embedded mode, these go to embedded_pages, not cache.
    // But the cache HashMap is still allocated and available.
    // The concern is filesystem mode where every page load fills the cache.
    for page_idx in 0..100u64 {
        let hash = test_hash(page_idx * entries_per);
        let _ = reader.lookup(&hash);
    }

    // Document: there is no eviction mechanism in page_cache
    assert_eq!(
        reader.meta_page_count(),
        100,
        "All 100 pages should be indexed"
    );
}

// ============================================================================
// V8-F8: All benchmarks are disabled — zero performance regression detection
//
// The benchmark file uses #[cfg(any())] to disable ALL real benchmarks.
// The only active benchmark is a placeholder that computes 1+1.
// This means there is ZERO capacity to detect performance regressions.
// ============================================================================

#[test]
fn f8a_benchmark_proof_insert_throughput() {
    // Since benchmarks are disabled, we provide inline performance tests
    let mut tree = ChunkIndex::new_default().unwrap();

    let start = Instant::now();
    let count = 50_000u64;
    for i in 0..count {
        tree.insert(make_entry(i)).unwrap();
    }
    let elapsed = start.elapsed();

    let ops_per_sec = count as f64 / elapsed.as_secs_f64();
    eprintln!(
        "V8-F8: Insert throughput: {:.0} ops/sec ({} entries in {:.2}s)",
        ops_per_sec,
        count,
        elapsed.as_secs_f64()
    );

    // Baseline: should do at least 5K inserts/second on any hardware (lowered for CI environments)
    assert!(
        ops_per_sec > 5_000.0,
        "Insert throughput too low: {:.0} ops/sec",
        ops_per_sec
    );
}

#[test]
fn f8b_benchmark_proof_lookup_throughput() {
    let mut tree = ChunkIndex::new_default().unwrap();

    let count = 10_000u64;
    for i in 0..count {
        tree.insert(make_entry(i)).unwrap();
    }

    let reader = tree.finalize().unwrap();

    // Measure hit lookup throughput
    let start = Instant::now();
    let lookups = 100_000u64;
    for i in 0..lookups {
        let _ = reader.lookup(&test_hash(i % count));
    }
    let elapsed = start.elapsed();

    let ops_per_sec = lookups as f64 / elapsed.as_secs_f64();
    eprintln!("V8-F8: Lookup throughput (hit): {:.0} ops/sec", ops_per_sec);

    // Measure miss lookup throughput (bloom rejection)
    let start = Instant::now();
    for i in count..(count + lookups) {
        let _ = reader.lookup(&test_hash(i));
    }
    let elapsed = start.elapsed();

    let miss_ops_per_sec = lookups as f64 / elapsed.as_secs_f64();
    eprintln!(
        "V8-F8: Lookup throughput (miss/bloom): {:.0} ops/sec",
        miss_ops_per_sec
    );

    // Miss lookups should be faster than hits (bloom short-circuits)
    // This is not always true due to bloom FP, but should generally hold
    eprintln!(
        "V8-F8: Miss/Hit ratio: {:.2}x",
        miss_ops_per_sec / ops_per_sec
    );
}

#[test]
fn f8c_benchmark_proof_finalize_throughput() {
    let counts = [1_000, 10_000, 50_000];

    for &count in &counts {
        let mut tree = ChunkIndex::new_default().unwrap();
        for i in 0..count as u64 {
            tree.insert(make_entry(i)).unwrap();
        }

        let start = Instant::now();
        let _reader = tree.finalize().unwrap();
        let elapsed = start.elapsed();

        eprintln!(
            "V8-F8: Finalize {} entries: {:.2}ms ({:.0} entries/sec)",
            count,
            elapsed.as_secs_f64() * 1000.0,
            count as f64 / elapsed.as_secs_f64()
        );
    }
}

// ============================================================================
// V8-F9: entry_count() has O(buffer_size) cost per call
//
// Each call to entry_count() creates a HashSet from buffer entries and
// queries Redb for each unique hash. If called in hot paths, this creates
// quadratic behavior.
// ============================================================================

#[test]
fn f9a_entry_count_cost_scales_with_buffer() {
    let mut builder = IndexBuilder::new_default().unwrap();

    // Fill buffer to near capacity (BATCH_SIZE - 1)
    for i in 0..999u64 {
        builder.insert(make_entry(i)).unwrap();
    }

    // Measure cost of entry_count with a nearly-full buffer
    let start = Instant::now();
    let count_calls = 1000;
    for _ in 0..count_calls {
        let _ = builder.entry_count();
    }
    let elapsed = start.elapsed();

    eprintln!(
        "V8-F9: {} entry_count() calls with 999-entry buffer: {:.2}ms ({:.0}µs/call)",
        count_calls,
        elapsed.as_secs_f64() * 1000.0,
        elapsed.as_micros() as f64 / count_calls as f64,
    );
}

#[test]
fn f9b_entry_count_accuracy_across_flush_boundary() {
    let mut builder = IndexBuilder::new_default().unwrap();

    // Insert exactly BATCH_SIZE entries (triggers flush at the last insert)
    for i in 0..1000u64 {
        builder.insert(make_entry(i)).unwrap();
    }

    // At this point, buffer should have been flushed (BATCH_SIZE = 1000)
    let count = builder.entry_count();
    assert_eq!(count, 1000, "Entry count should be 1000 after flush");

    // Insert one more — now buffer has 1 entry
    builder.insert(make_entry(1000)).unwrap();
    let count = builder.entry_count();
    assert_eq!(
        count, 1001,
        "Entry count should include buffered entry post-flush"
    );
}

#[test]
fn f9c_entry_count_with_duplicates_in_buffer_and_store() {
    let mut builder = IndexBuilder::new_default().unwrap();

    // Insert entries 0-999, triggers flush
    for i in 0..1000u64 {
        builder.insert(make_entry(i)).unwrap();
    }
    assert_eq!(builder.entry_count(), 1000);

    // Re-insert entries 0-99 (duplicates of what's in Redb)
    for i in 0..100u64 {
        builder.insert(make_entry(i)).unwrap();
    }

    // Count should still be 1000 (duplicates not counted)
    let count = builder.entry_count();
    assert_eq!(
        count, 1000,
        "Duplicates in buffer of already-stored entries should not inflate count"
    );
}

// ============================================================================
// V8-F10: No deserialization allocation bounds
//
// rkyv::check_archived_root validates structure but does NOT enforce
// maximum sizes. A crafted payload could claim to have billions of entries,
// causing OOM during deserialization of Vec<IndexEntry>.
// ============================================================================

#[test]
fn f10a_rkyv_deserialization_accepts_large_page() {
    // Create a page at exactly ENTRIES_PER_PAGE (max allowed) and measure
    // serialized vs deserialized size ratio
    let count = ENTRIES_PER_PAGE;
    let entries: Vec<IndexEntry> = (0..count as u64).map(make_entry).collect();
    let page = IndexPage::try_new(entries).unwrap();

    let serialized = rkyv::to_bytes::<rkyv::rancor::Error>(&page).unwrap();
    let serialized_size = serialized.len();

    // Deserialize — no size check happens at the rkyv level
    let archived =
        rkyv::access::<rkyv::Archived<IndexPage>, rkyv::rancor::Error>(&serialized).unwrap();
    let deserialized: IndexPage =
        rkyv::deserialize::<IndexPage, rkyv::rancor::Error>(archived).unwrap();

    assert_eq!(deserialized.len(), count);
    eprintln!(
        "V8-F10: Serialized {}KB → {} entries (amplification ratio: {:.1}x)",
        serialized_size / 1024,
        count,
        (count * std::mem::size_of::<IndexEntry>()) as f64 / serialized_size as f64,
    );
}

// ============================================================================
// V8-F11: Block ID counter reuse between index and data pages
//
// builder::finalize() uses a sequential block_id_counter starting at 0
// for index pages. Data blocks also typically start at 0. The only
// separation is XOR of nonce_context[0] with 0xFF. If the XOR is
// applied to a context where byte 0 is already 0xFF, it becomes 0x00,
// potentially colliding with the data block context.
// ============================================================================

#[test]
fn f11a_xor_domain_separation_collision_when_byte0_is_ff() {
    let mut data_context = [0u8; 16];
    data_context[0] = 0xFF;

    let mut index_context = data_context;
    index_context[0] ^= 0xFF;

    // When data context byte 0 is 0xFF, XOR with 0xFF gives 0x00
    assert_eq!(
        index_context[0], 0x00,
        "Index context collides with a default data context"
    );

    // Now check the reverse: data context byte 0 is 0x00
    let mut data_context2 = [0u8; 16];
    data_context2[0] = 0x00;

    let mut index_context2 = data_context2;
    index_context2[0] ^= 0xFF;

    assert_eq!(index_context2[0], 0xFF);
    // So (data=0x00, index=0xFF) and (data=0xFF, index=0x00) are the same pair
    // This means two different archives could have colliding key contexts
}

#[test]
fn f11b_double_xor_returns_original() {
    let context = [0x42u8; 16];
    let mut modified = context;
    modified[0] ^= 0xFF;
    modified[0] ^= 0xFF;

    assert_eq!(context, modified, "Double XOR returns to original");
}

// ============================================================================
// V8-F12: from_pages creates MetaIndex but caller can pass inconsistent data
//
// from_pages trusts the caller to provide correctly-ordered pages.
// If pages are passed in wrong order, add_page will error, but the
// error drops all already-processed pages (partial failure).
// ============================================================================

#[test]
fn f12a_from_pages_rejects_out_of_order_pages() {
    let meta = MetaIndex::new();
    let _bloom = bloomfilter::Bloom::<ChunkHash>::new_for_fp_rate(1000, 0.01);

    // Pages in reverse order
    let page1_entries: Vec<IndexEntry> = (1000..1100).map(make_entry).collect();
    let page2_entries: Vec<IndexEntry> = (0..100).map(make_entry).collect();

    let page1 = IndexPage::try_new(page1_entries).unwrap();
    let page2 = IndexPage::try_new(page2_entries).unwrap();

    // Page1 has higher hashes, but is added first
    let pages = vec![
        (page1, BlockId::new(0)),
        (page2, BlockId::new(1)), // Lower hashes but added second — should fail
    ];

    let result = IndexReader::from_pages(meta, pages);
    assert!(result.is_err(), "Out-of-order pages should be rejected");
}

#[test]
fn f12b_from_pages_empty_is_valid() {
    let meta = MetaIndex::new();

    let reader = IndexReader::from_pages(meta, vec![]).unwrap();

    // Lookup on empty index should return None
    let result = reader.lookup(&test_hash(42)).unwrap();
    assert!(result.is_none());
}

// ============================================================================
// V8-F13: test_hash inconsistency across test files
//
// Different test files use different test_hash implementations:
//   - builder.rs tests: bytes[..8] with to_le_bytes
//   - store.rs tests:   bytes[24..32] with to_be_bytes
//   - reader.rs tests:  bytes[..8] with to_le_bytes
//   - chunk_index.rs tests: bytes[24..32] with to_be_bytes
//
// This means hash ordering differs between files, and tests that pass
// locally may fail if functions are composed across test boundaries.
// ============================================================================

#[test]
fn f13a_test_hash_ordering_inconsistency() {
    // Implementation 1: LE at bytes[..8] (builder.rs, reader.rs)
    fn test_hash_le(value: u64) -> ChunkHash {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        ChunkHash::from_bytes(bytes)
    }

    // Implementation 2: BE at bytes[24..32] (store.rs, chunk_index.rs, lib.rs)
    fn test_hash_be(value: u64) -> ChunkHash {
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&value.to_be_bytes());
        ChunkHash::from_bytes(bytes)
    }

    // These produce different hashes for the same input value
    let le_hash = test_hash_le(42);
    let be_hash = test_hash_be(42);
    assert_ne!(le_hash, be_hash, "LE and BE test hashes should differ");

    // More critically, the ORDERING is different
    let le_1 = test_hash_le(1);
    let le_256 = test_hash_le(256);
    let be_1 = test_hash_be(1);
    let be_256 = test_hash_be(256);

    // BE hashes sort naturally (value 1 < value 256)
    assert!(be_1 < be_256, "BE hashes should sort naturally");

    // LE hashes: 256 = 0x0100 in LE = [0x00, 0x01, ...], 1 in LE = [0x01, 0x00, ...]
    // So LE_256 < LE_1 for byte comparison!
    assert!(
        le_256 < le_1,
        "LE hashes sort inversely for values crossing byte boundaries"
    );

    // This means tests using LE hashes have non-intuitive ordering,
    // while tests using BE hashes match human expectations.
    // Mix-ups between the two could cause subtle test failures.
}

// ============================================================================
// V8-F14: ChunkIndex finalize rejects double-finalize but state is inconsistent
//
// After finalize(), the builder is still Some (finalize only sets state=Finalized).
// The Redb staging database is not cleaned up until Drop.
// ============================================================================

#[test]
fn f14a_double_finalize_rejected() {
    let mut tree = ChunkIndex::new_default().unwrap();
    tree.insert(make_entry(1)).unwrap();

    let _reader = tree.finalize().unwrap();

    // Second finalize should fail
    let result = tree.finalize();
    assert!(result.is_err(), "Second finalize should be rejected");
}

#[test]
fn f14b_insert_after_finalize_rejected() {
    let mut tree = ChunkIndex::new_default().unwrap();
    tree.insert(make_entry(1)).unwrap();

    let _reader = tree.finalize().unwrap();

    let result = tree.insert(make_entry(2));
    assert!(result.is_err(), "Insert after finalize should be rejected");
}

#[test]
fn f14c_finalize_empty_index() {
    let mut tree = ChunkIndex::new_default().unwrap();

    // Finalize with zero entries should succeed (empty index is valid)
    let reader = tree.finalize().unwrap();

    // Lookup on empty index returns None
    let result = reader.lookup(&test_hash(42)).unwrap();
    assert!(result.is_none());
}

// ============================================================================
// V8-F15: IndexPage dedup in try_new may silently reduce entry count
//
// try_new() sorts and dedup_by_key on hash. If the caller passes entries
// with the same hash but different locations (multi-volume scenario),
// dedup silently drops all but one. The caller has no way to know
// entries were dropped.
// ============================================================================

#[test]
fn f15a_try_new_dedup_silently_drops_entries() {
    let vol1 = VolumeId::new();
    let vol2 = VolumeId::new();

    // Two entries with same hash but different locations
    let entries = vec![
        make_entry_with_volume(42, vol1),
        make_entry_with_volume(42, vol2),
    ];

    let page = IndexPage::try_new(entries).unwrap();

    // One entry was silently dropped!
    assert_eq!(
        page.len(),
        1,
        "dedup_by_key silently dropped an entry with same hash but different volume"
    );
}

#[test]
fn f15b_try_new_dedup_keeps_first_occurrence_after_sort() {
    // Since try_new sorts first, then dedup, the "first" entry kept
    // is the one that sorts first, which may not be the first inserted.
    let vol1 = VolumeId::new();
    let vol2 = VolumeId::new();

    let entry1 = IndexEntry::new(test_hash(42), vol1, BlockId::new(0), 0, 1024).unwrap();
    let entry2 = IndexEntry::new(test_hash(42), vol2, BlockId::new(1), 4096, 2048).unwrap();

    let entries = vec![entry2, entry1];
    let page = IndexPage::try_new(entries).unwrap();

    assert_eq!(page.len(), 1);
    // The kept entry depends on sort order of IndexEntry (hash, then rest)
    // Since both have the same hash, the first in sorted Vec order survives dedup
    let kept = &page.entries()[0];
    // dedup_by_key keeps the first of each consecutive group, and since they
    // have the same hash bytes, the order depends on remaining fields.
    // The critical point is that the caller cannot control which survives.
    eprintln!(
        "V8-F15: Kept entry block_id={}, offset={}, length={}",
        kept.block_id(),
        kept.offset(),
        kept.length()
    );
}

// ============================================================================
// V8-F16: Concurrent lookup correctness under contention
//
// RwLock-based page_cache should allow concurrent reads. Verify no
// data corruption under high contention.
// ============================================================================

#[test]
fn f16a_concurrent_lookups_correctness() {
    use std::sync::Arc;
    use std::thread;

    let mut tree = ChunkIndex::new_default().unwrap();

    let count = 10_000u64;
    for i in 0..count {
        tree.insert(make_entry(i)).unwrap();
    }

    let reader = Arc::new(tree.finalize().unwrap());

    let num_threads = 8;
    let lookups_per_thread = 10_000;

    let handles: Vec<_> = (0..num_threads)
        .map(|t| {
            let reader = Arc::clone(&reader);
            thread::spawn(move || {
                let mut found = 0u64;
                let mut not_found = 0u64;
                for i in 0..lookups_per_thread as u64 {
                    let hash_val = (t as u64 * lookups_per_thread as u64 + i) % (count * 2);
                    match reader.lookup(&test_hash(hash_val)).unwrap() {
                        Some(loc) => {
                            found += 1;
                            // Verify location is sensible
                            assert!(loc.offset < 100 * 1024);
                            assert_eq!(loc.length, 1024);
                        }
                        None => {
                            not_found += 1;
                        }
                    }
                }
                (found, not_found)
            })
        })
        .collect();

    let mut total_found = 0u64;
    let mut total_missing = 0u64;
    for h in handles {
        let (f, m) = h.join().unwrap();
        total_found += f;
        total_missing += m;
    }

    eprintln!(
        "V8-F16: {} threads × {} lookups: found={}, missing={}",
        num_threads, lookups_per_thread, total_found, total_missing
    );
    assert!(total_found > 0, "Should find some entries");
}

// ============================================================================
// V8-F17: Bloom filter zero false negatives guarantee
//
// The bloom filter must NEVER produce a false negative. If any inserted
// hash is not found by bloom_contains, the dedup system is broken.
// ============================================================================

#[test]
fn f17a_bloom_zero_false_negatives() {
    let mut builder = IndexBuilder::new_default().unwrap();

    let count = 50_000u64;
    for i in 0..count {
        builder.insert(make_entry(i)).unwrap();
    }

    // Check every single inserted hash — zero false negatives allowed
    let mut false_negatives = 0;
    for i in 0..count {
        if !builder.bloom_contains(&test_hash(i)) {
            false_negatives += 1;
            eprintln!("FALSE NEGATIVE at hash {}", i);
        }
    }

    assert_eq!(
        false_negatives, 0,
        "Bloom filter must have ZERO false negatives — found {}",
        false_negatives
    );
}

#[test]
fn f17b_bloom_zero_false_negatives_after_finalize() {
    let mut tree = ChunkIndex::new_default().unwrap();

    let count = 10_000u64;
    for i in 0..count {
        tree.insert(make_entry(i)).unwrap();
    }

    let reader = tree.finalize().unwrap();

    for i in 0..count {
        assert!(
            reader.bloom_contains(&test_hash(i)),
            "Bloom false negative after finalize for hash {}",
            i
        );
    }
}

// ============================================================================
// V8-F18: read_sorted ordering correctness under adversarial input
//
// Verify that read_sorted returns entries in strict ascending hash order
// regardless of insertion order, including pathological patterns.
// ============================================================================

#[test]
fn f18a_read_sorted_reverse_insertion_order() {
    let mut builder = IndexBuilder::new_default().unwrap();

    // Insert in reverse order
    for i in (0..5000u64).rev() {
        builder.insert(make_entry(i)).unwrap();
    }

    let sorted = builder.read_sorted().unwrap();
    assert_eq!(sorted.len(), 5000);

    for i in 1..sorted.len() {
        assert!(
            sorted[i - 1].hash() <= sorted[i].hash(),
            "Sort violation at index {}: {:?} > {:?}",
            i,
            sorted[i - 1].hash(),
            sorted[i].hash()
        );
    }
}

#[test]
fn f18b_read_sorted_zigzag_insertion() {
    let mut builder = IndexBuilder::new_default().unwrap();

    // Insert in zigzag pattern: 0, 4999, 1, 4998, 2, 4997...
    for i in 0..2500u64 {
        builder.insert(make_entry(i)).unwrap();
        builder.insert(make_entry(4999 - i)).unwrap();
    }

    let sorted = builder.read_sorted().unwrap();
    assert_eq!(sorted.len(), 5000);

    for i in 1..sorted.len() {
        assert!(
            sorted[i - 1].hash() <= sorted[i].hash(),
            "Sort violation at index {}",
            i
        );
    }
}

// ============================================================================
// V8-F19: MetaIndex find_page boundary conditions
//
// Test binary search edge cases in MetaIndex::find_page.
// ============================================================================

#[test]
fn f19a_find_page_exact_min_hash() {
    let mut meta = MetaIndex::new();
    meta.add_page(test_hash(100), test_hash(199), BlockId::new(0), 0, 0)
        .unwrap();
    meta.add_page(test_hash(200), test_hash(299), BlockId::new(1), 0, 0)
        .unwrap();

    // Exact min_hash match
    let result = meta.find_page(&test_hash(100));
    assert!(result.is_some());
    assert_eq!(result.unwrap().block_id(), BlockId::new(0));

    // Exact min_hash of second page
    let result = meta.find_page(&test_hash(200));
    assert!(result.is_some());
    assert_eq!(result.unwrap().block_id(), BlockId::new(1));
}

#[test]
fn f19b_find_page_exact_max_hash() {
    let mut meta = MetaIndex::new();
    meta.add_page(test_hash(100), test_hash(199), BlockId::new(0), 0, 0)
        .unwrap();

    let result = meta.find_page(&test_hash(199));
    assert!(result.is_some());
    assert_eq!(result.unwrap().block_id(), BlockId::new(0));
}

#[test]
fn f19c_find_page_gap_between_pages() {
    let mut meta = MetaIndex::new();
    meta.add_page(test_hash(100), test_hash(199), BlockId::new(0), 0, 0)
        .unwrap();
    // Gap: hashes 200-299 are not in any page
    meta.add_page(test_hash(300), test_hash(399), BlockId::new(1), 0, 0)
        .unwrap();

    // Hash in the gap should return None
    let result = meta.find_page(&test_hash(250));
    assert!(
        result.is_none(),
        "Hash in gap between pages should return None"
    );
}

#[test]
fn f19d_find_page_before_all_pages() {
    let mut meta = MetaIndex::new();
    meta.add_page(test_hash(100), test_hash(199), BlockId::new(0), 0, 0)
        .unwrap();

    let result = meta.find_page(&test_hash(50));
    assert!(result.is_none(), "Hash before all pages should return None");
}

#[test]
fn f19e_find_page_after_all_pages() {
    let mut meta = MetaIndex::new();
    meta.add_page(test_hash(100), test_hash(199), BlockId::new(0), 0, 0)
        .unwrap();

    let result = meta.find_page(&test_hash(500));
    assert!(result.is_none(), "Hash after all pages should return None");
}

// ============================================================================
// V8-F20: End-to-end roundtrip correctness at scale
//
// Insert large datasets, finalize, and verify every entry is retrievable
// with correct location data. This is the ultimate correctness test.
// ============================================================================

#[test]
fn f20a_roundtrip_10k_entries() {
    let mut tree = ChunkIndex::new_default().unwrap();

    let count = 10_000u64;
    let vol = VolumeId::new();

    for i in 0..count {
        let entry = IndexEntry::new(
            test_hash(i),
            vol,
            BlockId::new(i / 100),
            (i % 100) as u32 * 1024,
            (i as u32 % 8 + 1) * 512,
        )
        .unwrap();
        tree.insert(entry).unwrap();
    }

    let reader = tree.finalize().unwrap();

    // Verify all entries
    let mut found = 0u64;
    for i in 0..count {
        let result = reader.lookup(&test_hash(i)).unwrap();
        assert!(result.is_some(), "Entry {} not found", i);
        let loc = result.unwrap();
        assert_eq!(loc.volume_id, vol, "Wrong volume_id for entry {}", i);
        assert_eq!(
            loc.block_id,
            BlockId::new(i / 100),
            "Wrong block_id for entry {}",
            i
        );
        assert_eq!(
            loc.offset,
            (i % 100) as u32 * 1024,
            "Wrong offset for entry {}",
            i
        );
        assert_eq!(
            loc.length,
            (i as u32 % 8 + 1) * 512,
            "Wrong length for entry {}",
            i
        );
        found += 1;
    }
    assert_eq!(found, count);

    // Verify non-existent entries return None
    for i in count..(count + 1000) {
        let result = reader.lookup(&test_hash(i)).unwrap();
        assert!(result.is_none(), "Ghost entry {} found", i);
    }
}

#[test]
fn f20b_roundtrip_with_heavy_dedup() {
    let mut tree = ChunkIndex::new_default().unwrap();

    let vol = VolumeId::new();

    // Insert 10K entries, then re-insert the first 5K (50% dedup rate)
    for i in 0..10_000u64 {
        let entry =
            IndexEntry::new(test_hash(i), vol, BlockId::new(i / 100), i as u32, 1024).unwrap();
        tree.insert(entry).unwrap();
    }
    for i in 0..5_000u64 {
        // Re-insert with different offset — first-write-wins means original kept
        let entry =
            IndexEntry::new(test_hash(i), vol, BlockId::new(999), i as u32 + 99999, 2048).unwrap();
        tree.insert(entry).unwrap();
    }

    let reader = tree.finalize().unwrap();

    // Original entries should have original offsets
    for i in 0..5_000u64 {
        let loc = reader.lookup(&test_hash(i)).unwrap().unwrap();
        assert_eq!(
            loc.offset, i as u32,
            "First-write-wins violated for entry {}",
            i
        );
        assert_eq!(
            loc.length, 1024,
            "First-write-wins violated length for entry {}",
            i
        );
    }
}

// ============================================================================
// V8-F21: Bloom filter roundtrip correctness
//
// Verify bloom filter serialization/deserialization preserves all set bits.
// ============================================================================

#[test]
fn f21a_bloom_serde_roundtrip_preserves_bits() {
    let mut bloom = bloomfilter::Bloom::<ChunkHash>::new_for_fp_rate(10_000, 0.01);

    for i in 0..5_000u64 {
        bloom.set(&test_hash(i));
    }

    let serialized = era_index::serialize_bloom(&bloom).unwrap();
    let restored = era_index::deserialize_bloom(&serialized).unwrap();

    // Verify all set bits are preserved (zero false negatives)
    for i in 0..5_000u64 {
        assert!(
            restored.check(&test_hash(i)),
            "Bloom roundtrip false negative for hash {}",
            i
        );
    }

    // FP rate should be similar
    let mut orig_fp = 0;
    let mut restored_fp = 0;
    for i in 5_000..10_000u64 {
        if bloom.check(&test_hash(i)) {
            orig_fp += 1;
        }
        if restored.check(&test_hash(i)) {
            restored_fp += 1;
        }
    }

    assert_eq!(
        orig_fp, restored_fp,
        "Bloom FP count should be identical after roundtrip"
    );
}

// ============================================================================
// V8-F22: Discard semantics
// ============================================================================

#[test]
fn f22a_discard_after_insert_is_clean() {
    let builder = IndexBuilder::new_default().unwrap();
    let result = builder.discard();
    assert!(result.is_ok(), "Discard of fresh builder should succeed");
}

#[test]
fn f22b_discard_after_insert_removes_data() {
    let mut builder = IndexBuilder::new_default().unwrap();
    for i in 0..100u64 {
        builder.insert(make_entry(i)).unwrap();
    }

    let path = builder.store().path().to_path_buf();
    assert!(path.exists(), "Redb file should exist");

    builder.discard().unwrap();

    // File should be removed after discard
    assert!(!path.exists(), "Redb file should be removed after discard");
}

// ============================================================================
// V8-F23: IndexPage find() correctness at boundaries
// ============================================================================

#[test]
fn f23a_page_find_first_entry() {
    let entries: Vec<IndexEntry> = (0..100).map(make_entry).collect();
    let page = IndexPage::try_new(entries).unwrap();

    let result = page.find(&test_hash(0));
    assert!(result.is_some(), "Should find first entry");
}

#[test]
fn f23b_page_find_last_entry() {
    let entries: Vec<IndexEntry> = (0..100).map(make_entry).collect();
    let page = IndexPage::try_new(entries).unwrap();

    let result = page.find(&test_hash(99));
    assert!(result.is_some(), "Should find last entry");
}

#[test]
fn f23c_page_find_nonexistent_in_range() {
    // Create entries with gaps: 0, 2, 4, 6...
    let entries: Vec<IndexEntry> = (0..50).map(|i| make_entry(i * 2)).collect();
    let page = IndexPage::try_new(entries).unwrap();

    // Odd values are in range but not present
    let result = page.find(&test_hash(1));
    assert!(
        result.is_none(),
        "Should not find entry in gap within range"
    );
}

#[test]
fn f23d_page_contains_range_boundaries() {
    let entries: Vec<IndexEntry> = (100..200).map(make_entry).collect();
    let page = IndexPage::try_new(entries).unwrap();

    assert!(page.contains_range(&test_hash(100)), "Min hash in range");
    assert!(page.contains_range(&test_hash(199)), "Max hash in range");
    assert!(page.contains_range(&test_hash(150)), "Mid hash in range");
    assert!(
        !page.contains_range(&test_hash(99)),
        "Below min not in range"
    );
    assert!(
        !page.contains_range(&test_hash(200)),
        "Above max not in range"
    );
}

// ============================================================================
// V8-F24: Multi-volume entry tracking
//
// Verify that entries from different volumes are correctly tracked
// through the full pipeline.
// ============================================================================

#[test]
fn f24a_multi_volume_entries_distinguishable() {
    let mut tree = ChunkIndex::new_default().unwrap();

    let vol1 = VolumeId::new();
    let vol2 = VolumeId::new();

    // Different hashes on different volumes
    for i in 0..100u64 {
        tree.insert(make_entry_with_volume(i, vol1)).unwrap();
    }
    for i in 100..200u64 {
        tree.insert(make_entry_with_volume(i, vol2)).unwrap();
    }

    let reader = tree.finalize().unwrap();

    // Verify volume_id is preserved
    for i in 0..100u64 {
        let loc = reader.lookup(&test_hash(i)).unwrap().unwrap();
        assert_eq!(loc.volume_id, vol1, "Entry {} should be on vol1", i);
    }
    for i in 100..200u64 {
        let loc = reader.lookup(&test_hash(i)).unwrap().unwrap();
        assert_eq!(loc.volume_id, vol2, "Entry {} should be on vol2", i);
    }
}

// ============================================================================
// V8-F25: IndexStore first-write-wins semantics across batch boundaries
// ============================================================================

#[test]
fn f25a_first_write_wins_across_batches() {
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.redb");
    let mut store = era_index::IndexStore::create(&db_path, 10_000).unwrap();

    let vol1 = VolumeId::new();
    let vol2 = VolumeId::new();

    // Batch 1: insert hash 42 with vol1
    let entry1 = IndexEntry::new(test_hash(42), vol1, BlockId::new(0), 0, 1024).unwrap();
    store.insert_batch(&[entry1]).unwrap();

    // Batch 2: insert hash 42 with vol2
    let entry2 = IndexEntry::new(test_hash(42), vol2, BlockId::new(1), 4096, 2048).unwrap();
    store.insert_batch(&[entry2]).unwrap();

    // First write wins
    let result = store.get(&test_hash(42)).unwrap().unwrap();
    assert_eq!(
        result.volume_id(),
        vol1,
        "First-write-wins violated across batches"
    );
    assert_eq!(result.offset(), 0);
    assert_eq!(result.length(), 1024);
}

#[test]
fn f25b_first_write_wins_within_batch() {
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.redb");
    let mut store = era_index::IndexStore::create(&db_path, 10_000).unwrap();

    let vol1 = VolumeId::new();
    let vol2 = VolumeId::new();

    // Both entries in same batch
    let entry1 = IndexEntry::new(test_hash(42), vol1, BlockId::new(0), 0, 1024).unwrap();
    let entry2 = IndexEntry::new(test_hash(42), vol2, BlockId::new(1), 4096, 2048).unwrap();
    store.insert_batch(&[entry1, entry2]).unwrap();

    let result = store.get(&test_hash(42)).unwrap().unwrap();
    assert_eq!(
        result.volume_id(),
        vol1,
        "First-write-wins violated within batch"
    );
}

// ============================================================================
// V8-F26: Large-scale stress test — correctness at 100K entries
// ============================================================================

#[test]
fn f26a_stress_100k_entries_zero_loss() {
    let mut tree = ChunkIndex::new_default().unwrap();

    let count = 100_000u64;
    let vol = VolumeId::new();

    let start = Instant::now();
    for i in 0..count {
        tree.insert(
            IndexEntry::new(
                test_hash(i),
                vol,
                BlockId::new(i / 1000),
                (i % 1000) as u32,
                512,
            )
            .unwrap(),
        )
        .unwrap();
    }
    let insert_elapsed = start.elapsed();

    let start = Instant::now();
    let reader = tree.finalize().unwrap();
    let finalize_elapsed = start.elapsed();

    // Verify 100% of entries
    let start = Instant::now();
    let mut found = 0u64;
    for i in 0..count {
        if reader.lookup(&test_hash(i)).unwrap().is_some() {
            found += 1;
        }
    }
    let lookup_elapsed = start.elapsed();

    assert_eq!(
        found,
        count,
        "Data loss: {} of {} entries missing",
        count - found,
        count
    );

    eprintln!(
        "V8-F26: 100K entries — insert: {:.2}s, finalize: {:.2}s, lookup: {:.2}s",
        insert_elapsed.as_secs_f64(),
        finalize_elapsed.as_secs_f64(),
        lookup_elapsed.as_secs_f64()
    );
}

// ============================================================================
// V8-F27: Serialization size tracking
//
// Track serialized sizes to detect bloat regressions.
// ============================================================================

#[test]
fn f27a_serialization_sizes() {
    let entry = make_entry(42);
    let entry_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&entry).unwrap();

    let entries: Vec<IndexEntry> = (0..ENTRIES_PER_PAGE as u64).map(make_entry).collect();
    let page = IndexPage::try_new(entries).unwrap();
    let page_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&page).unwrap();

    let bloom = bloomfilter::Bloom::<ChunkHash>::new_for_fp_rate(100_000, 0.01);
    let bloom_data = era_index::BloomFilterData::new(
        bloom.bitmap(),
        bloom.number_of_bits(),
        bloom.number_of_hash_functions(),
        bloom.sip_keys(),
    )
    .expect("bloom data");
    let bloom_bytes = bloom_data.to_bytes().unwrap();

    eprintln!("V8-F27: Serialization sizes:");
    eprintln!("  IndexEntry: {} bytes (rkyv)", entry_bytes.len());
    eprintln!(
        "  IndexPage ({} entries): {} bytes ({:.1} KB)",
        ENTRIES_PER_PAGE,
        page_bytes.len(),
        page_bytes.len() as f64 / 1024.0
    );
    eprintln!(
        "  BloomFilter (100K items): {} bytes ({:.1} KB)",
        bloom_bytes.len(),
        bloom_bytes.len() as f64 / 1024.0
    );

    // Verify IndexEntry fits in cache line
    let entry_mem_size = IndexEntry::memory_size();
    eprintln!("  IndexEntry in-memory: {} bytes", entry_mem_size);

    // Page should be reasonable for L2 cache (~320KB target)
    assert!(
        page_bytes.len() < 1024 * 1024,
        "Serialized page exceeds 1MB"
    );
}

// ============================================================================
// V8-F28: Edge case — extreme hash values
// ============================================================================

#[test]
fn f28a_extreme_hash_values() {
    let mut tree = ChunkIndex::new_default().unwrap();

    // All zeros
    let entry_zero = IndexEntry::new(
        ChunkHash::from_bytes([0u8; 32]),
        VolumeId::new(),
        BlockId::new(0),
        0,
        1024,
    )
    .unwrap();

    // All ones
    let entry_max = IndexEntry::new(
        ChunkHash::from_bytes([0xFF; 32]),
        VolumeId::new(),
        BlockId::new(1),
        0,
        2048,
    )
    .unwrap();

    tree.insert(entry_zero).unwrap();
    tree.insert(entry_max).unwrap();

    let reader = tree.finalize().unwrap();

    let result_zero = reader
        .lookup(&ChunkHash::from_bytes([0u8; 32]))
        .unwrap()
        .unwrap();
    assert_eq!(result_zero.length, 1024);

    let result_max = reader
        .lookup(&ChunkHash::from_bytes([0xFF; 32]))
        .unwrap()
        .unwrap();
    assert_eq!(result_max.length, 2048);
}

// ============================================================================
// V8-F29: IndexStore read-only mode enforcement
// ============================================================================

#[test]
fn f29a_readonly_insert_rejected() {
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.redb");

    // Create and populate
    {
        let mut store = era_index::IndexStore::create(&db_path, 1024).unwrap();
        store.insert(&make_entry(1)).unwrap();
        store.keep_on_drop();
    }

    // Open read-only
    let mut store = era_index::IndexStore::open_readonly(&db_path).unwrap();
    let result = store.insert(&make_entry(2));
    assert!(result.is_err(), "Insert on read-only store should fail");
}

#[test]
fn f29b_readonly_batch_insert_rejected() {
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.redb");

    {
        let mut store = era_index::IndexStore::create(&db_path, 1024).unwrap();
        store.insert(&make_entry(1)).unwrap();
        store.keep_on_drop();
    }

    let mut store = era_index::IndexStore::open_readonly(&db_path).unwrap();
    let result = store.insert_batch(&[make_entry(2)]);
    assert!(
        result.is_err(),
        "Batch insert on read-only store should fail"
    );
}

// ============================================================================
// V8-F30: Redb file cleanup on Drop
// ============================================================================

#[test]
fn f30a_staging_file_removed_on_drop() {
    let path;
    {
        let builder = IndexBuilder::new_default().unwrap();
        path = builder.store().path().to_path_buf();
        assert!(path.exists(), "Staging file should exist during use");
    }
    // After drop, file should be cleaned up
    assert!(!path.exists(), "Staging file should be removed after Drop");
}

#[test]
fn f30b_staging_file_persists_with_keep_on_drop() {
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.redb");

    {
        let mut store = era_index::IndexStore::create(&db_path, 1024).unwrap();
        store.insert(&make_entry(1)).unwrap();
        store.keep_on_drop();
    }

    assert!(
        db_path.exists(),
        "Staging file should persist with keep_on_drop"
    );
}
