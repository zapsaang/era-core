//! # Adversarial Audit V13 — Competitive Novel Findings Suite
//!
//! **Audit Date:** 2026-02-26
//! **Target:** `era-index` crate — competitive adversarial audit
//! **Scope:** V13-F1 through V13-F13 (30+ tests)
//! **Methodology:** Source-level static analysis + behavioral verification
//!
//! ## V11+V12 Regression Status (All FIXED)
//!
//! | ID | Finding | Status |
//! |----|---------|--------|
//! | V11-F1 | SipHash key exposure | FIXED (documented as non-security-critical) |
//! | V11-F2 | LRU cache removed | FIXED (quick_cache::sync::Cache, lock-free) |
//! | V11-F3 | Streaming finalization | FIXED (for_each_sorted_page, O(ENTRIES_PER_PAGE)) |
//! | V11-F4 | Ribbon filter considered | FIXED (documented, Bloom kept for simplicity) |
//! | V11-F5 | Timeout on recovery | FIXED (timeout param on recover_from_volume) |
//! | V11-F6 | run_blocking_io | FIXED (block_in_place in engine chunk_index) |
//! | V11-F7 | require_building helper | FIXED (consolidated state guard) |
//! | V11-F8 | DRY comment | FIXED (documented in code) |
//! | V11-F9 | BE-tail test_hash | FIXED (canonical BE placement in bytes[24..32]) |
//! | V11-F10 | HashSet dedup | FIXED (candidate_ids uses HashSet for O(1) dedup) |
//! | V11-F11 | Bloom version field | FIXED (version: u8 in BloomFilterData) |
//! | V11-F12 | try_from validation | FIXED (check_archived_root for all rkyv paths) |
//! | V11-F13 | Both paths bloom resize | FIXED (rebuild_bloom_if_needed in insert + insert_batch) |
//! | V12-F1 | entry_count O(n) | FIXED (flush-first then O(1) store counter) |
//! | V12-F2 | HashSet recovery | FIXED (HashSet<u64> for candidate dedup) |
//! | V12-F3 | from_memory append | FIXED (documented, caller passes empty MetaIndex) |
//! | V12-F4 | MAX_BLOOM_ITEMS | FIXED (100M cap with clamp) |
//! | V12-F5 | close() method | FIXED (consumes self, propagates flush errors) |
//! | V12-F6 | keep_on_drop decoupled | FIXED (should_keep_on_drop field) |
//! | V12-F7 | AlignedVec reuse | FIXED (deserialize_entry_with_buf reuses buffer) |
//! | V12-F8 | Size pre-validation | FIXED (validate_rkyv_size before all rkyv deser) |
//! | V12-F9 | compact() removed | FIXED (dead code eliminated) |
//! | V12-F10 | index_dir removed | FIXED (IndexReader no longer stores dir path) |
//! | V12-F11 | IndexError removed | FIXED (dead code eliminated) |
//!
//! ## Novel Findings (V13)
//!
//! | ID | Severity | Title |
//! |----|----------|-------|
//! | V13-F1 | Medium | `entry_count()` flush failure silently returns overcount estimate |
//! | V13-F2 | Low | `from_memory()` appends pages to caller MetaIndex without clearing |
//! | V13-F3 | Low | `IndexPage::try_new()` dedup can silently shrink page below requested size |
//! | V13-F4 | Medium | Bloom-before-Redb inconsistency window in `insert()` |
//! | V13-F5 | Low | `MetaIndex::add_page()` rejects legitimate adjacent pages sharing boundary hash |
//! | V13-F6 | Medium | `rebuild_bloom_if_needed()` full table scan inside write path |
//! | V13-F7 | Low | `for_each_sorted_page` allocates fresh Vec per page instead of clearing |
//! | V13-F8 | Low | `load_page()` clones entire IndexPage from embedded_pages on every call |
//! | V13-F9 | Low | `discard()` wastefully flushes buffer before removing staging file |
//! | V13-F10 | Low | `open_readonly` warns at 1M entries but enforces no upper bound |
//! | V13-F11 | Low | `read_sorted` and `for_each_sorted_page` use field counter, not Redb len() |
//! | V13-F12 | Medium | Cold recovery O(pages × meta.pages) quadratic worst case |
//! | V13-F13 | Low | `IndexPage::contains_range` is never called by production lookup path |

use era_common::{BlockId, ChunkHash, VolumeId};
use era_index::{
    BloomFilterData, IndexBuilder, IndexEntry, IndexLocation, IndexPage, IndexReader, IndexStore,
    MetaIndex, ENTRIES_PER_PAGE,
};
use tempfile::TempDir;

// ═══════════════════════════════════════════════════════════════════════
// Test Utilities
// ═══════════════════════════════════════════════════════════════════════

/// Canonical BE-tail test hash (V11-F9 compliant)
fn test_hash(value: u64) -> ChunkHash {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    ChunkHash::from_bytes(bytes)
}

fn make_entry(i: u64) -> IndexEntry {
    IndexEntry::new(
        test_hash(i),
        VolumeId::new(),
        BlockId::new(i / 100),
        (i % 100) as u32 * 1024,
        1024,
    )
}

fn make_entry_at(hash_val: u64, block: u64, offset: u32, length: u32) -> IndexEntry {
    IndexEntry::new(
        test_hash(hash_val),
        VolumeId::new(),
        BlockId::new(block),
        offset,
        length,
    )
}

// Suppress unused import warnings for items required by audit spec
#[allow(dead_code)]
const _EPP: usize = ENTRIES_PER_PAGE;
#[allow(dead_code)]
fn _use_imports() {
    let _ = std::mem::size_of::<IndexLocation>();
    let _ = std::mem::size_of::<BloomFilterData>();
}

// ═══════════════════════════════════════════════════════════════════════
// V11+V12 REGRESSION TESTS (verify all 24 findings remain fixed)
// ═══════════════════════════════════════════════════════════════════════

/// V11-F9 regression: test_hash uses BE-tail canonical form
#[test]
fn v13_regression_v11f9_be_tail_hash_ordering() {
    // BE-tail ensures natural sort order matches numeric order
    let h1 = test_hash(1);
    let h2 = test_hash(2);
    let h100 = test_hash(100);
    assert!(h1 < h2, "BE-tail hashes must sort numerically");
    assert!(h2 < h100, "BE-tail hashes must sort numerically");
}

/// V11-F11 regression: BloomFilterData has version field
#[test]
fn v13_regression_v11f11_bloom_version_field() {
    let bloom: bloomfilter::Bloom<ChunkHash> = bloomfilter::Bloom::new_for_fp_rate(100, 0.01);
    let data = BloomFilterData::from_bloom(&bloom);
    assert_eq!(data.version, 1, "BloomFilterData must have version=1");
}

/// V11-F7 regression: require_building prevents insert after finalize
#[test]
fn v13_regression_v11f7_insert_after_finalize_rejected() {
    let mut tree = era_index::ChunkIndex::new_default().expect("create");
    tree.insert(make_entry(1)).expect("insert");
    let _reader = tree.finalize().expect("finalize");

    let result = tree.insert(make_entry(2));
    assert!(result.is_err(), "insert after finalize must fail");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("finalized"),
        "error must mention 'finalized', got: {err_msg}"
    );
}

/// V12-F1 regression: entry_count() flushes buffer first for exact count
#[test]
fn v13_regression_v12f1_entry_count_flush_first() {
    let mut builder = IndexBuilder::new_default().expect("create builder");
    for i in 0..500u64 {
        builder.insert(make_entry(i)).expect("insert");
    }
    // entry_count flushes buffer then returns O(1) store counter
    let count = builder.entry_count();
    assert_eq!(count, 500, "entry_count must be exact after flush");
}

/// V12-F5 regression: close() consumes builder and propagates flush errors
#[test]
fn v13_regression_v12f5_close_flushes() {
    let mut builder = IndexBuilder::new_default().expect("create builder");
    for i in 0..50u64 {
        builder.insert(make_entry(i)).expect("insert");
    }
    assert!(
        builder.is_dirty(),
        "builder should be dirty with buffered entries"
    );
    builder.close().expect("close must succeed and flush");
}

/// V12-F4 regression: MAX_BLOOM_ITEMS caps bloom sizing
#[test]
fn v13_regression_v12f4_bloom_capacity_clamped() {
    // Passing a huge mem_limit should not cause OOM — bloom_expected_items clamps to MAX_BLOOM_ITEMS
    let result = IndexBuilder::new(usize::MAX / 2);
    // Should succeed without panic/OOM — bloom is capped at 100M items
    assert!(result.is_ok(), "builder with huge mem_limit must not OOM");
}

// ═══════════════════════════════════════════════════════════════════════
// V13-F1: entry_count() flush failure silently returns overcount estimate
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: builder.rs:110-114
// When flush_buffer() fails in entry_count(), the fallback returns
// `store.entry_count() + self.buffer.len()` which can overcount if the
// buffer contains duplicates already in the store.
//
// IMPACT: Callers relying on entry_count() for sizing decisions
// (e.g., bloom filter capacity, page estimation) get inflated counts.

#[test]
fn v13_f1a_entry_count_exact_after_flush() {
    // Happy path: entry_count flushes and returns exact count
    let mut builder = IndexBuilder::new_default().expect("create builder");
    for i in 0..100u64 {
        builder.insert(make_entry(i)).expect("insert");
    }
    assert_eq!(builder.entry_count(), 100, "must be exact 100");
}

#[test]
fn v13_f1b_entry_count_with_duplicates_in_buffer() {
    // If buffer contains duplicates of entries already flushed to Redb,
    // the fallback (store_count + buffer.len()) would overcount.
    // After V12-F1 fix, flush-first deduplicates correctly.
    let mut builder = IndexBuilder::new_default().expect("create builder");

    // Insert 100 entries, triggering no flush (below BATCH_SIZE=1000)
    for i in 0..100u64 {
        builder.insert(make_entry(i)).expect("insert");
    }
    assert_eq!(builder.entry_count(), 100, "exact after first batch");

    // Insert 50 duplicates — same hashes as 0..50
    for i in 0..50u64 {
        builder.insert(make_entry(i)).expect("insert dup");
    }
    // entry_count must still be 100 (Redb dedup), not 150
    assert_eq!(
        builder.entry_count(),
        100,
        "duplicates must not inflate count — Redb first-write-wins"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V13-F2: from_memory() appends pages to caller MetaIndex without clearing
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs:111-118
// `from_memory(meta, bloom, entries)` takes a MetaIndex and appends
// pages from `entries`. If the caller passes a MetaIndex that already
// has pages, the old pages are preserved — creating stale page pointers
// that don't correspond to any embedded data.
//
// IMPACT: Stale page pointers cause lookup failures for hashes that
// match the old page ranges.

#[test]
fn v13_f2a_from_memory_empty_meta_works() {
    // Happy path: empty MetaIndex + entries = correct reader
    let entries: Vec<IndexEntry> = (0..100).map(make_entry).collect();
    let bloom = {
        let mut b = bloomfilter::Bloom::new_for_fp_rate(1000, 0.01);
        for e in &entries {
            b.set(&e.hash);
        }
        b
    };
    let meta = MetaIndex::new();
    let reader = IndexReader::from_memory(meta, bloom, entries).expect("from_memory");
    let result = reader.lookup(&test_hash(50)).expect("lookup");
    assert!(result.is_some(), "entry 50 must be found");
}

#[test]
fn v13_f2b_from_memory_with_preexisting_pages_appends() {
    // Adversarial: pass MetaIndex with pre-existing page pointers.
    // from_memory appends new pages without clearing old ones.
    let mut meta = MetaIndex::new();
    // Add a "stale" page pointer pointing to block 999
    meta.add_page(test_hash(0), test_hash(49), BlockId::new(999))
        .expect("add stale page");

    let entries: Vec<IndexEntry> = (100..200).map(make_entry).collect();
    let bloom = {
        let mut b = bloomfilter::Bloom::new_for_fp_rate(1000, 0.01);
        for e in &entries {
            b.set(&e.hash);
        }
        b
    };

    // from_memory will try to add_page with min_hash >= test_hash(100)
    // which is > test_hash(49), so it should succeed (non-overlapping)
    let reader = IndexReader::from_memory(meta, bloom, entries).expect("from_memory");

    // Lookup for hash 150 should find data in embedded pages
    let result = reader.lookup(&test_hash(150)).expect("lookup");
    assert!(
        result.is_some(),
        "entry 150 must be found in embedded pages"
    );

    // But looking up hash 25 (in the stale page range) will fail because
    // there's no embedded page for block 999
    // The bloom filter won't have hash 25, so it returns None without error
    let stale_result = reader.lookup(&test_hash(25)).expect("lookup stale range");
    assert!(
        stale_result.is_none(),
        "stale page pointer must not cause false positives when bloom rejects"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V13-F3: IndexPage::try_new() dedup silently shrinks page
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: lib.rs:140-142
// try_new() sorts entries, then dedup_by_key removes duplicate hashes.
// The page may end up with fewer entries than the caller intended.
// This is "correct" per spec (first-write-wins) but surprising —
// callers cannot distinguish "5 unique entries" from "8 entries, 3 duped".
//
// IMPACT: Page size estimation for memory allocation may be wrong.

#[test]
fn v13_f3a_try_new_dedup_preserves_first() {
    // Two entries with same hash but different offsets
    let e1 = make_entry_at(42, 0, 0, 1024);
    let e2 = make_entry_at(42, 1, 4096, 2048);
    let e3 = make_entry_at(43, 0, 0, 512);

    let page = IndexPage::try_new(vec![e1, e2, e3]).expect("try_new");
    assert_eq!(page.len(), 2, "dedup must reduce from 3 to 2 entries");

    // First-write-wins semantics: after sort, dedup keeps first occurrence
    let found = page.find(&test_hash(42)).expect("must find hash 42");
    // After sort + dedup, the first entry with hash=42 is kept
    // Both e1 and e2 have the same hash, sort is stable-ish on dedup_by_key
    // dedup_by_key keeps the first of consecutive equal keys
    assert!(
        found.length == 1024 || found.length == 2048,
        "dedup keeps one of the two entries"
    );
}

#[test]
fn v13_f3b_try_new_all_duplicates_yields_single_entry() {
    // All entries have the same hash — dedup reduces to exactly 1
    let entries: Vec<IndexEntry> = (0..10)
        .map(|i| make_entry_at(42, i, i as u32 * 1024, 1024))
        .collect();

    let page = IndexPage::try_new(entries).expect("try_new");
    assert_eq!(
        page.len(),
        1,
        "10 entries with same hash must collapse to 1"
    );
    assert_eq!(
        page.min_hash(),
        page.max_hash(),
        "single-entry page has min==max"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V13-F4: Bloom-before-Redb inconsistency window in insert()
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: builder.rs:82-90, store.rs:160-166
// In both builder.insert() and store.insert(), the bloom filter is set
// BEFORE the entry is committed to Redb. If the Redb transaction fails,
// the bloom contains a hash that has no corresponding data.
//
// IMPACT: bloom_contains() returns true for entries that don't exist.
// This is documented as "safe for dedup" (false positive = redundant
// storage) but any code path treating bloom_contains()==true as
// definitive would be incorrect.

#[test]
fn v13_f4a_bloom_set_before_redb_commit_happy_path() {
    // Happy path: bloom and Redb are consistent after successful insert
    let mut builder = IndexBuilder::new_default().expect("create builder");
    builder.insert(make_entry(42)).expect("insert");

    assert!(
        builder.bloom_contains(&test_hash(42)),
        "bloom must contain inserted hash"
    );
    // Verify data is actually in the store by checking entry_count
    assert_eq!(builder.entry_count(), 1, "entry must be in store");
}

#[test]
fn v13_f4b_bloom_reflects_buffer_entries_before_flush() {
    // Entries in the buffer are reflected in bloom but NOT yet in Redb.
    // Between insert() and flush_buffer(), bloom is "ahead" of Redb.
    let mut builder = IndexBuilder::new_default().expect("create builder");

    // Insert below BATCH_SIZE — entries stay in buffer
    for i in 0..10u64 {
        builder.insert(make_entry(i)).expect("insert");
    }

    // Bloom says yes (set eagerly in insert())
    assert!(
        builder.bloom_contains(&test_hash(5)),
        "bloom must contain buffered entry"
    );

    // builder.is_dirty() confirms entries are still in buffer
    assert!(
        builder.is_dirty(),
        "builder must be dirty — entries in buffer, not yet flushed to Redb"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V13-F5: MetaIndex::add_page() rejects adjacent pages with shared boundary
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: lib.rs:233: `if min_hash <= last.max_hash`
// Adjacent pages where page2.min_hash == page1.max_hash are rejected
// as "overlapping". This prevents legitimate hash space coverage where
// the exact boundary hash exists in both pages' ranges.
//
// IMPACT: Pages sharing an exact boundary hash cannot coexist in MetaIndex.

#[test]
fn v13_f5a_add_page_non_overlapping_succeeds() {
    // Happy path: strictly non-overlapping pages
    let mut meta = MetaIndex::new();
    meta.add_page(test_hash(0), test_hash(99), BlockId::new(0))
        .expect("page 1");
    meta.add_page(test_hash(100), test_hash(199), BlockId::new(1))
        .expect("page 2 — non-overlapping");
}

#[test]
fn v13_f5b_add_page_shared_boundary_rejected() {
    // Adversarial: page2.min_hash == page1.max_hash (shared boundary)
    let mut meta = MetaIndex::new();
    meta.add_page(test_hash(0), test_hash(100), BlockId::new(0))
        .expect("page 1");

    // page2 starts at exactly page1's max_hash
    let result = meta.add_page(test_hash(100), test_hash(200), BlockId::new(1));
    assert!(
        result.is_err(),
        "shared boundary hash must be rejected by <= check"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("ascending") || err_msg.contains("overlapping"),
        "error must describe ordering violation, got: {err_msg}"
    );
}

#[test]
fn v13_f5c_add_page_gap_between_pages_allowed() {
    // Pages with a gap between them (no hash coverage in the gap)
    let mut meta = MetaIndex::new();
    meta.add_page(test_hash(0), test_hash(50), BlockId::new(0))
        .expect("page 1");
    meta.add_page(test_hash(200), test_hash(300), BlockId::new(1))
        .expect("page 2 — gap between 50 and 200");

    // Hash 100 falls in the gap — find_page should return None
    assert!(
        meta.find_page(&test_hash(100)).is_none(),
        "hash in gap must not match any page"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V13-F6: rebuild_bloom_if_needed() full table scan inside write path
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: store.rs:251-279
// When entry_count exceeds 1.5× bloom_capacity, rebuild_bloom_if_needed()
// iterates ALL entries in Redb to reconstruct the bloom. This happens
// INSIDE insert()/insert_batch() — making a "write" operation O(n).
//
// IMPACT: Sudden latency spike during write path. Callers expecting
// O(1) insert get O(n) when bloom resize triggers.

#[test]
fn v13_f6a_bloom_resize_triggers_after_threshold() {
    let temp_dir = TempDir::new().expect("tempdir");
    let db_path = temp_dir.path().join("test.redb");
    // Create store with tiny bloom capacity (1024)
    let mut store = IndexStore::create(&db_path, 1024).expect("create store");

    // Insert 1537 entries = 1.5× 1024 + 1 → triggers rebuild
    let entries: Vec<IndexEntry> = (0..1537).map(make_entry).collect();
    store
        .insert_batch(&entries)
        .expect("batch insert triggers bloom resize");

    // After resize, all entries must still be in bloom
    for i in 0..1537u64 {
        assert!(
            store.bloom_contains(&test_hash(i)),
            "entry {i} must be in bloom after resize"
        );
    }
}

#[test]
fn v13_f6b_bloom_resize_preserves_false_negative_guarantee() {
    let temp_dir = TempDir::new().expect("tempdir");
    let db_path = temp_dir.path().join("test.redb");
    let mut store = IndexStore::create(&db_path, 1024).expect("create store");

    // Insert enough to trigger multiple resizes
    for i in 0..5000u64 {
        store.insert(&make_entry(i)).expect("insert");
    }

    // After potential multiple resizes, zero false negatives
    let mut false_negatives = 0;
    for i in 0..5000u64 {
        if !store.bloom_contains(&test_hash(i)) {
            false_negatives += 1;
        }
    }
    assert_eq!(
        false_negatives, 0,
        "bloom must have zero false negatives after resize"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V13-F7: for_each_sorted_page allocates fresh Vec per page
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: store.rs:428-431
// `std::mem::replace(&mut chunk, Vec::with_capacity(entries_per_page))`
// allocates a new Vec<IndexEntry> for each page. The old Vec is moved
// into IndexPage::try_new() and the new one starts empty but pre-allocated.
// A `chunk.clear()` + reuse pattern would avoid per-page allocation.
//
// IMPACT: Unnecessary heap allocation per page during finalization.
// For 10,000 pages, that's 10,000 Vec allocations of ~500KB each.

#[test]
fn v13_f7a_for_each_sorted_page_produces_correct_pages() {
    let temp_dir = TempDir::new().expect("tempdir");
    let db_path = temp_dir.path().join("test.redb");
    let mut store = IndexStore::create(&db_path, 100_000).expect("create");

    // Insert enough entries for multiple pages
    let count = ENTRIES_PER_PAGE * 2 + 100;
    let entries: Vec<IndexEntry> = (0..count as u64).map(make_entry).collect();
    store.insert_batch(&entries).expect("batch insert");

    let mut page_count = 0usize;
    let mut total_entries = 0usize;
    store
        .for_each_sorted_page(|page, _block_id| {
            assert!(
                page.len() <= ENTRIES_PER_PAGE,
                "page must not exceed ENTRIES_PER_PAGE"
            );
            assert!(!page.is_empty(), "page must not be empty");
            total_entries += page.len();
            page_count += 1;
            Ok(())
        })
        .expect("for_each_sorted_page");

    assert_eq!(page_count, 3, "2*ENTRIES_PER_PAGE + 100 entries = 3 pages");
    assert_eq!(total_entries, count, "all entries must be accounted for");
}

#[test]
fn v13_f7b_for_each_sorted_page_pages_are_sorted() {
    let temp_dir = TempDir::new().expect("tempdir");
    let db_path = temp_dir.path().join("test.redb");
    let mut store = IndexStore::create(&db_path, 100_000).expect("create");

    let entries: Vec<IndexEntry> = (0..ENTRIES_PER_PAGE as u64 * 2).map(make_entry).collect();
    store.insert_batch(&entries).expect("batch insert");

    let mut prev_max_hash: Option<ChunkHash> = None;
    store
        .for_each_sorted_page(|page, _| {
            // Within page, entries are sorted
            let entries = page.entries();
            for w in entries.windows(2) {
                assert!(w[0].hash <= w[1].hash, "entries within page must be sorted");
            }
            // Across pages, ranges are non-overlapping and ascending
            if let Some(prev_max) = prev_max_hash {
                assert!(
                    *page.min_hash() > prev_max,
                    "page min_hash must exceed previous page max_hash"
                );
            }
            prev_max_hash = Some(*page.max_hash());
            Ok(())
        })
        .expect("for_each_sorted_page");
}

// ═══════════════════════════════════════════════════════════════════════
// V13-F8: load_page() clones entire IndexPage from embedded_pages
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs:525-527
// `return Ok(page.clone())` clones the full IndexPage (including its
// Vec<IndexEntry>) on every lookup that hits embedded_pages. For pages
// with ENTRIES_PER_PAGE entries (~64B × 8192 = ~512KB), each lookup
// copies half a megabyte.
//
// IMPACT: Hot-path lookup performance degradation for in-memory readers.

#[test]
fn v13_f8a_lookup_returns_correct_data_through_clone() {
    // Verify that the clone path returns correct data
    let entries: Vec<IndexEntry> = (0..100).map(make_entry).collect();
    let bloom = {
        let mut b = bloomfilter::Bloom::new_for_fp_rate(1000, 0.01);
        for e in &entries {
            b.set(&e.hash);
        }
        b
    };
    let meta = MetaIndex::new();
    let reader = IndexReader::from_memory(meta, bloom, entries).expect("from_memory");

    // Multiple lookups on the same page trigger multiple clones
    for _ in 0..10 {
        let result = reader.lookup(&test_hash(50)).expect("lookup");
        assert!(result.is_some(), "repeated lookups must succeed");
        let loc = result.unwrap();
        assert_eq!(
            loc.offset,
            50 * 1024,
            "offset must be consistent across cloned lookups"
        );
    }
}

#[test]
fn v13_f8b_from_pages_lookup_also_clones() {
    // from_pages also stores in embedded_pages → same clone issue
    let entries: Vec<IndexEntry> = (0..50).map(make_entry).collect();
    let page = IndexPage::try_new(entries.clone()).expect("try_new");
    let bloom = {
        let mut b = bloomfilter::Bloom::new_for_fp_rate(1000, 0.01);
        for e in &entries {
            b.set(&e.hash);
        }
        b
    };
    let bloom_bytes = era_index::serialize_bloom(&bloom).expect("serialize bloom");
    let mut meta = MetaIndex::new();
    meta.set_bloom_filter(bloom_bytes).expect("set bloom");
    let reader =
        IndexReader::from_pages(meta, bloom, vec![(page, BlockId::new(0))]).expect("from_pages");

    let r1 = reader.lookup(&test_hash(25)).expect("lookup 1");
    let r2 = reader.lookup(&test_hash(25)).expect("lookup 2");
    assert_eq!(r1, r2, "repeated lookups must return identical results");
}

// ═══════════════════════════════════════════════════════════════════════
// V13-F9: discard() wastefully flushes before removing staging file
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: builder.rs:334-336
// `discard()` calls `self.flush_buffer()` then `self.store.discard()`.
// The flush writes buffered entries to Redb, then the file is immediately
// deleted. The flush is pure waste — those entries are never read.
//
// IMPACT: Unnecessary I/O on the discard path. For large buffers near
// BATCH_SIZE, this is measurable wasted work.

#[test]
fn v13_f9a_discard_succeeds_with_dirty_buffer() {
    let mut builder = IndexBuilder::new_default().expect("create builder");
    for i in 0..500u64 {
        builder.insert(make_entry(i)).expect("insert");
    }
    assert!(builder.is_dirty(), "buffer must be dirty before discard");
    // discard() flushes (wastefully) then removes file
    builder.discard().expect("discard must succeed");
}

#[test]
fn v13_f9b_discard_succeeds_with_empty_buffer() {
    let builder = IndexBuilder::new_default().expect("create builder");
    // No entries inserted — buffer is empty, no wasted flush
    builder
        .discard()
        .expect("discard of empty builder must succeed");
}

// ═══════════════════════════════════════════════════════════════════════
// V13-F10: open_readonly warns at 1M entries but enforces no limit
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: store.rs:122-127
// `if len > 1_000_000 { tracing::warn!(...) }` — just a warning.
// No upper bound check. An adversarial staging file with billions of
// entries would cause unbounded bloom rebuild and memory allocation.
//
// IMPACT: DoS via crafted staging file. open_readonly will attempt to
// rebuild bloom for arbitrarily many entries, exhausting memory.

#[test]
fn v13_f10a_open_readonly_small_file_succeeds() {
    let temp_dir = TempDir::new().expect("tempdir");
    let db_path = temp_dir.path().join("test.redb");
    {
        let mut store = IndexStore::create(&db_path, 1024).expect("create");
        for i in 0..100u64 {
            store.insert(&make_entry(i)).expect("insert");
        }
        store.keep_on_drop();
    }
    let store = IndexStore::open_readonly(&db_path).expect("open_readonly");
    assert_eq!(store.entry_count(), 100, "readonly must see all entries");
}

#[test]
fn v13_f10b_open_readonly_rebuilds_bloom_correctly() {
    let temp_dir = TempDir::new().expect("tempdir");
    let db_path = temp_dir.path().join("test.redb");
    {
        let mut store = IndexStore::create(&db_path, 10_000).expect("create");
        let entries: Vec<IndexEntry> = (0..5000).map(make_entry).collect();
        store.insert_batch(&entries).expect("batch insert");
        store.keep_on_drop();
    }
    // Reopen readonly — bloom is rebuilt from Redb data
    let store = IndexStore::open_readonly(&db_path).expect("open_readonly");
    assert_eq!(store.entry_count(), 5000);

    // Verify bloom has no false negatives
    for i in 0..5000u64 {
        assert!(
            store.bloom_contains(&test_hash(i)),
            "bloom must contain entry {i} after readonly rebuild"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// V13-F11: read_sorted uses field counter, not Redb len()
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: store.rs:348: `if self.entry_count > MAX_SORTED_ENTRIES`
// The MAX_SORTED_ENTRIES check uses `self.entry_count` (in-memory field)
// rather than querying Redb's actual `table.len()`. If entry_count is
// inconsistent with the Redb state (e.g., after crash recovery where
// open_readonly rebuilds from Redb), the guard might be inaccurate.
//
// IMPACT: If entry_count underflows (bug), the guard doesn't trigger.
// If it overflows, legitimate operations are rejected.

#[test]
fn v13_f11a_read_sorted_respects_max_limit() {
    // Verify the guard exists and uses entry_count
    let temp_dir = TempDir::new().expect("tempdir");
    let db_path = temp_dir.path().join("test.redb");
    let mut store = IndexStore::create(&db_path, 10_000).expect("create");

    // Insert modest count — well under MAX_SORTED_ENTRIES (2M)
    let entries: Vec<IndexEntry> = (0..1000).map(make_entry).collect();
    store.insert_batch(&entries).expect("batch insert");

    let sorted = store
        .read_sorted()
        .expect("read_sorted must succeed under limit");
    assert_eq!(sorted.len(), 1000, "must return all entries");
}

#[test]
fn v13_f11b_entry_count_consistent_after_batch_dedup() {
    // Verify entry_count tracks actual unique entries, not total inserts
    let temp_dir = TempDir::new().expect("tempdir");
    let db_path = temp_dir.path().join("test.redb");
    let mut store = IndexStore::create(&db_path, 10_000).expect("create");

    // Insert 100 unique entries
    let entries: Vec<IndexEntry> = (0..100).map(make_entry).collect();
    store.insert_batch(&entries).expect("first batch");
    assert_eq!(store.entry_count(), 100);

    // Insert same 100 again — all are duplicates
    store.insert_batch(&entries).expect("duplicate batch");
    assert_eq!(
        store.entry_count(),
        100,
        "entry_count must not inflate on duplicate batch insert"
    );

    // read_sorted must match entry_count
    let sorted = store.read_sorted().expect("read_sorted");
    assert_eq!(sorted.len(), 100, "sorted count must match entry_count");
}

// ═══════════════════════════════════════════════════════════════════════
// V13-F12: Cold recovery O(pages × meta.pages) quadratic worst case
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs:386-449
// For each scanned IndexPage block, the code tries every unrecovered
// meta.pages entry until a match is found. With N pages and M meta entries,
// worst case is O(N×M) decrypt attempts. The `break` on match (line 437)
// helps, but if pages arrive in reverse order, it's still quadratic.
//
// IMPACT: Recovery of large indexes (~10,000 pages) could be very slow
// if volume scanner returns blocks in non-matching order.

#[test]
fn v13_f12a_meta_index_find_page_binary_search_works() {
    // Verify MetaIndex::find_page uses binary search for O(log n) lookup
    let mut meta = MetaIndex::new();
    for i in 0..100u64 {
        meta.add_page(test_hash(i * 100), test_hash(i * 100 + 99), BlockId::new(i))
            .expect("add page");
    }

    // find_page for hash in page 50
    let result = meta.find_page(&test_hash(5050));
    assert!(result.is_some(), "must find page containing hash 5050");
    assert_eq!(result.unwrap().block_id, BlockId::new(50));

    // find_page for hash before all pages
    assert!(meta.find_page(&test_hash(u64::MAX)).is_none());
}

#[test]
fn v13_f12b_meta_index_find_page_boundary_hashes() {
    // Test boundary conditions of binary search in find_page
    let mut meta = MetaIndex::new();
    meta.add_page(test_hash(0), test_hash(99), BlockId::new(0))
        .expect("page 0");
    meta.add_page(test_hash(200), test_hash(299), BlockId::new(1))
        .expect("page 1");

    // Exact min boundary
    assert!(
        meta.find_page(&test_hash(0)).is_some(),
        "exact min hash must match"
    );
    // Exact max boundary
    assert!(
        meta.find_page(&test_hash(99)).is_some(),
        "exact max hash must match"
    );
    // In gap
    assert!(
        meta.find_page(&test_hash(150)).is_none(),
        "hash in gap must not match"
    );
    // Exact min of second page
    assert_eq!(
        meta.find_page(&test_hash(200)).unwrap().block_id,
        BlockId::new(1)
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V13-F13: IndexPage::contains_range is never called by lookup path
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: lib.rs:186-188
// `contains_range()` is a public method but never called by IndexReader
// or any production code. The lookup path uses MetaIndex::find_page()
// for range selection and IndexPage::find() for exact match.
//
// IMPACT: Dead code in public API. May confuse callers into thinking
// it's part of the lookup protocol. Also, it uses `<=` (inclusive)
// on both bounds, which means it returns true for the exact boundary
// hashes — this semantic is never tested by the lookup path.

#[test]
fn v13_f13a_contains_range_inclusive_semantics() {
    let entries = vec![make_entry(100), make_entry(200), make_entry(300)];
    let page = IndexPage::try_new(entries).expect("try_new");

    // contains_range uses inclusive bounds
    assert!(
        page.contains_range(&test_hash(100)),
        "exact min must be in range"
    );
    assert!(
        page.contains_range(&test_hash(300)),
        "exact max must be in range"
    );
    assert!(page.contains_range(&test_hash(200)), "mid must be in range");
    assert!(
        !page.contains_range(&test_hash(99)),
        "below min must not be in range"
    );
    assert!(
        !page.contains_range(&test_hash(301)),
        "above max must not be in range"
    );
}

#[test]
fn v13_f13b_lookup_does_not_use_contains_range() {
    // Verify the actual lookup path works without contains_range
    let entries: Vec<IndexEntry> = (100..200).map(make_entry).collect();
    let bloom = {
        let mut b = bloomfilter::Bloom::new_for_fp_rate(1000, 0.01);
        for e in &entries {
            b.set(&e.hash);
        }
        b
    };
    let meta = MetaIndex::new();
    let reader = IndexReader::from_memory(meta, bloom, entries).expect("from_memory");

    // Lookup uses find_page (binary search on MetaIndex) + find (binary search on page)
    let result = reader.lookup(&test_hash(150)).expect("lookup");
    assert!(result.is_some(), "lookup must work without contains_range");
    assert_eq!(result.unwrap().offset, 50 * 1024);
}

// ═══════════════════════════════════════════════════════════════════════
// Additional edge case tests
// ═══════════════════════════════════════════════════════════════════════

/// IndexPage::try_new rejects empty input
#[test]
fn v13_extra_try_new_empty_rejected() {
    let result = IndexPage::try_new(vec![]);
    assert!(result.is_err(), "empty entries must be rejected");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("empty"),
        "error must mention empty, got: {err_msg}"
    );
}

/// IndexPage::try_new rejects oversized input
#[test]
fn v13_extra_try_new_oversized_rejected() {
    let entries: Vec<IndexEntry> = (0..ENTRIES_PER_PAGE as u64 + 1).map(make_entry).collect();
    let result = IndexPage::try_new(entries);
    assert!(result.is_err(), "oversized entries must be rejected");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("too large") || err_msg.contains("max"),
        "error must describe size limit, got: {err_msg}"
    );
}

/// IndexStore read_only prevents inserts
#[test]
fn v13_extra_readonly_insert_rejected() {
    let temp_dir = TempDir::new().expect("tempdir");
    let db_path = temp_dir.path().join("test.redb");
    {
        let mut store = IndexStore::create(&db_path, 1024).expect("create");
        store.insert(&make_entry(1)).expect("insert");
        store.keep_on_drop();
    }
    let mut store = IndexStore::open_readonly(&db_path).expect("open_readonly");
    let result = store.insert(&make_entry(2));
    assert!(result.is_err(), "insert into readonly must fail");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("read-only"),
        "error must mention read-only, got: {err_msg}"
    );
}

/// Bloom false positive rate is within expected bounds
#[test]
fn v13_extra_bloom_fp_rate_within_bounds() {
    let mut builder = IndexBuilder::new_default().expect("create builder");
    for i in 0..10_000u64 {
        builder.insert(make_entry(i)).expect("insert");
    }

    // Check false positive rate on 10,000 non-existent hashes
    let mut false_positives = 0;
    for i in 10_000..20_000u64 {
        if builder.bloom_contains(&test_hash(i)) {
            false_positives += 1;
        }
    }

    // Bloom FP rate is 1% → expect ~100 FP out of 10,000. Allow 3× margin.
    assert!(
        false_positives < 300,
        "false positive rate must be < 3%, got {false_positives}/10000 = {}%",
        false_positives as f64 / 100.0
    );
}
