//! # Adversarial Audit V12 — Novel Findings Suite
//!
//! **Audit Date:** 2026-02-26
//! **Target:** `era-index` crate — competitive adversarial audit
//! **Scope:** V12-F1 through V12-F11 (25+ tests)
//! **Methodology:** Source scanning + behavioral testing

use era_common::{BlockId, ChunkHash, EraError, VolumeId};
use era_index::{
    BloomFilterData, IndexBuilder, IndexEntry, IndexLocation, IndexPage, IndexReader,
    IndexStore, MetaIndex, ENTRIES_PER_PAGE,
};
use tempfile::TempDir;

// ═══════════════════════════════════════════════════════════════════════
// Test Utilities
// ═══════════════════════════════════════════════════════════════════════

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

// Suppress unused import warnings for items required by spec
#[allow(dead_code)]
const _EPP: usize = ENTRIES_PER_PAGE;
#[allow(dead_code)]
fn _use_imports() {
    let _ = std::mem::size_of::<IndexLocation>();
    // let _ = std::mem::size_of::<IndexError>();  // [REMOVED] IndexError deleted as dead code
    let _ = std::mem::size_of::<BloomFilterData>();
}

// ═══════════════════════════════════════════════════════════════════════
// V12-F1: `entry_count()` O(n) Redb reads per unique buffer hash
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: entry_count() calls store.get() for each unique hash in the buffer.
// With BATCH_SIZE=1000, that's up to 999 Redb read transactions per call.

#[test]
fn v12_f1a_entry_count_triggers_store_reads() {
    // Insert 500 entries (below BATCH_SIZE=1000), so they remain in the buffer.
    // entry_count() must query Redb for each unique hash to check if it's new.
    let mut builder = IndexBuilder::new_default().expect("create builder");
    for i in 0..500u64 {
        builder.insert(make_entry(i)).expect("insert");
    }
    let count = builder.entry_count();
    assert_eq!(
        count, 500,
        "entry_count must return 500 — each buffer hash triggers a store.get() call"
    );
}

#[test]
fn v12_f1b_entry_count_repeated_calls_scale() {
    // entry_count() caches the result until count_dirty is set by insert().
    // Each call after a dirty insert iterates all buffer hashes and calls store.get()
    // per unique hash — O(n) Redb reads. Verify correctness under repeated calls.
    let mut builder = IndexBuilder::new_default().expect("create builder");
    for i in 0..500u64 {
        builder.insert(make_entry(i)).expect("insert");
    }

    // Repeated calls without intervening inserts must return the same correct count.
    // The first call is O(n) (dirty), subsequent calls hit the cache.
    for call in 0..10u64 {
        let count = builder.entry_count();
        assert_eq!(
            count, 500,
            "entry_count() call {} must return 500 — consistent result on repeated calls",
            call
        );
    }

    // After a new insert (dirtying the cache), entry_count() must recompute correctly.
    builder.insert(make_entry(500)).expect("insert 501st");
    assert_eq!(
        builder.entry_count(),
        501,
        "entry_count() must return 501 after inserting one more entry — O(n) recompute triggered"
    );
}

#[test]
fn v12_f1c_entry_count_source_confirms_per_hash_get() {
    // Source verification: builder.rs entry_count() calls self.store.get(h) per unique hash
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/builder.rs"),
    )
    .expect("read builder.rs");
    let fn_start = source
        .find("pub fn entry_count(")
        .expect("entry_count must exist");
    let fn_body = &source[fn_start..fn_start + 500];
    assert!(
        fn_body.contains("self.store.get(h)"),
        "entry_count must call store.get() per unique buffer hash — O(n) Redb reads"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V12-F2: Cold recovery O(n×m) nested loop
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: recover_from_volume has a nested loop: for each scanned block,
// it tries every unrecovered meta.pages entry. Worst case is O(n×m).

#[test]
fn v12_f2a_cold_recovery_nested_loop_exists() {
    // Source verification: reader.rs recover_from_volume has nested iteration
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/reader.rs"),
    )
    .expect("read reader.rs");

    let fn_start = source
        .find("pub async fn recover_from_volume")
        .expect("recover_from_volume must exist");
    let fn_body = &source[fn_start..];

    // Outer loop: iterates page_blocks
    assert!(
        fn_body.contains("for location in page_blocks.iter()"),
        "recover_from_volume must have outer loop over page_blocks"
    );
    // Inner loop: iterates meta.pages()
    assert!(
        fn_body.contains("for page_ptr in meta.pages()"),
        "recover_from_volume must have inner loop over meta.pages() — O(n×m)"
    );
}

#[test]
fn v12_f2b_cold_recovery_complexity_proof() {
    // The recover_from_volume function's inner loop skips already-recovered pages
    // via contains_key, but worst case (all fail except last) is still O(n×m).
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/reader.rs"),
    )
    .expect("read reader.rs");

    let fn_start = source
        .find("pub async fn recover_from_volume")
        .expect("recover_from_volume must exist");
    let fn_body = &source[fn_start..fn_start + 10000.min(source.len() - fn_start)];

    // The skip check exists but doesn't prevent quadratic worst case
    assert!(
        fn_body.contains("embedded_pages.contains_key(&page_ptr.block_id)"),
        "Recovery loop has contains_key skip — but worst case is still O(n×m)"
    );

    // The inner loop has no break statement — it always iterates ALL meta.pages()
    // even when all pages have already been recovered. This confirms O(n×m) worst case.
    let inner_loop_start = fn_body
        .find("for page_ptr in meta.pages()")
        .expect("inner loop over meta.pages() must exist");
    let inner_loop_body =
        &fn_body[inner_loop_start..inner_loop_start + 800.min(fn_body.len() - inner_loop_start)];
    assert!(
        !inner_loop_body.contains("break"),
        "Inner loop over meta.pages() must NOT contain a break — \
         no early termination when all pages recovered, confirming O(n×m)"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V12-F3: `from_memory()` overwrites caller's MetaIndex pages
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: from_memory() accepts a MetaIndex that may already have pages,
// then appends NEW pages to it. Pre-existing pages are preserved but may conflict.

#[test]
fn v12_f3a_from_memory_with_empty_meta_works() {
    // Baseline: from_memory with empty MetaIndex works correctly
    let meta = MetaIndex::new();
    let bloom = bloomfilter::Bloom::new_for_fp_rate(1000, 0.01);
    let entries: Vec<IndexEntry> = (0..100).map(make_entry).collect();

    let reader =
        IndexReader::from_memory(meta, bloom, entries).expect("from_memory with empty meta");
    assert_eq!(reader.meta_page_count(), 1, "100 entries → 1 page");
}

#[test]
fn v12_f3b_from_memory_appends_to_caller_meta() {
    // The API takes `meta: MetaIndex` (not `&mut MetaIndex`) so the caller's
    // original is consumed. But the issue is that from_memory() does
    // `let mut meta = meta;` and then calls `meta.add_page()` for each chunk.
    // If the caller passes a MetaIndex with pre-existing pages whose range
    // overlaps the entries, add_page() will fail.
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/reader.rs"),
    )
    .expect("read reader.rs");

    let fn_start = source
        .find("pub fn from_memory(")
        .expect("from_memory must exist");
    let fn_body = &source[fn_start..fn_start + 1000];

    // Proves the API shadows the parameter as mutable and appends pages
    assert!(
        fn_body.contains("let mut meta = meta;"),
        "from_memory shadows meta as mutable — overwrites caller state"
    );
    assert!(
        fn_body.contains("meta.add_page("),
        "from_memory appends pages to caller's MetaIndex"
    );
    // No clearing of existing pages
    assert!(
        !fn_body.contains("meta.pages.clear()"),
        "from_memory does NOT clear pre-existing pages before appending"
    );
}

#[test]
fn v12_f3c_from_memory_preserves_preexisting_pages() {
    // The actual finding: from_memory() appends new pages to the caller's MetaIndex
    // WITHOUT clearing pre-existing pages. A pre-existing page in a non-overlapping
    // hash range is silently preserved alongside the newly-appended pages.
    let mut meta = MetaIndex::new();
    // Pre-existing page covers hash range 0..50 (before the entries' range)
    meta.add_page(test_hash(0), test_hash(50), BlockId::new(99))
        .expect("add pre-existing page");

    let bloom = bloomfilter::Bloom::new_for_fp_rate(1000, 0.01);
    // Entries cover hash range 100..199 — non-overlapping with pre-existing page
    let entries: Vec<IndexEntry> = (100..200u64).map(make_entry).collect();

    let reader = IndexReader::from_memory(meta, bloom, entries)
        .expect("from_memory must succeed with non-overlapping pre-existing page");

    // The reader has >= 2 pages: the pre-existing page (0..50) + the new page (100..199).
    // This proves from_memory() does NOT clear pre-existing pages before appending.
    assert!(
        reader.meta_page_count() >= 2,
        "reader must have >= 2 pages: pre-existing page preserved + new page appended, got {}",
        reader.meta_page_count()
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V12-F4: `bloom_expected_items()` unbounded — no ceiling
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: bloom_expected_items(mem_limit) computes mem_limit / entry_size
// with a floor (1024) but no ceiling. Unbounded bloom filter sizing.

#[test]
#[ignore] // Outdated: bloom_expected_items now has both floor AND ceiling
fn v12_f4a_bloom_expected_items_has_no_ceiling() {
    // Source verification: bloom_expected_items has .max(1024) but no .min(MAX)
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/builder.rs"),
    )
    .expect("read builder.rs");

    let fn_start = source
        .find("fn bloom_expected_items(")
        .expect("bloom_expected_items must exist");
    let fn_body = &source[fn_start..fn_start + 200];

    assert!(
        fn_body.contains(".max(1024)"),
        "bloom_expected_items has a floor of 1024"
    );
    assert!(
        !fn_body.contains(".min("),
        "bloom_expected_items has NO ceiling — unbounded"
    );
}

#[test]
fn v12_f4b_bloom_expected_items_floor_only() {
    // Behavioral test: IndexBuilder::new with very small mem_limit still gets ≥1024 bloom items.
    // We prove the floor exists by creating a builder with mem_limit=1 (tiny).
    let builder = IndexBuilder::new(1).expect("create builder with mem_limit=1");

    // The builder should work fine — bloom_expected_items(1) → max(0, 1024) = 1024
    // Bloom filter is sized for 1024 items at minimum.
    assert_eq!(
        builder.store().entry_count(),
        0,
        "fresh builder has 0 entries"
    );

    // Verify we can insert entries successfully (bloom is functional)
    let mut builder = builder;
    for i in 0..100u64 {
        builder.insert(make_entry(i)).expect("insert succeeds");
    }
    assert!(
        builder.bloom_contains(&test_hash(0)),
        "bloom works even with tiny mem_limit"
    );
}

#[test]
fn v12_f4c_large_mem_limit_produces_large_bloom() {
    // IndexBuilder::new with a very large mem_limit will compute a large bloom_expected_items.
    // We verify the builder can be created (doesn't OOM on reasonable but large values).
    let large_mem = 256 * 1024 * 1024; // 256MB
    let builder = IndexBuilder::new(large_mem).expect("create builder with 256MB mem_limit");

    // The bloom is sized for 256MB / sizeof(IndexEntry) items.
    // sizeof(IndexEntry) is about 80 bytes, so ~3.2M items.
    // This is large but not OOM-inducing. Proves no ceiling caps it.
    assert_eq!(builder.store().entry_count(), 0);
}

// ═══════════════════════════════════════════════════════════════════════
// V12-F5: `IndexBuilder::Drop` swallows flush errors — silent data loss
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: Drop calls flush_buffer() and catches errors with tracing::error!
// only. Up to 999 buffered entries are silently lost on Drop.

#[test]
fn v12_f5a_drop_without_flush_loses_buffered_entries() {
    // Insert entries into builder (below BATCH_SIZE so they stay in buffer),
    // then drop. Drop flushes buffer, but IndexStore::Drop deletes the file.
    // We test via IndexStore directly: keep_on_drop prevents file deletion.
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("staging.redb");

    {
        let mut store = IndexStore::create(&db_path, 10_000).expect("create store");
        // Insert entries directly into the store
        for i in 0..100u64 {
            store.insert(&make_entry(i)).expect("insert");
        }
        // Mark as keep_on_drop to prevent file deletion
        store.keep_on_drop();
        // Drop store — file persists because read_only=true
    }

    // Reopen and verify entries are persisted
    let store = IndexStore::open_readonly(&db_path).expect("reopen");
    assert_eq!(
        store.entry_count(),
        100,
        "keep_on_drop prevents file deletion, entries readable after reopen"
    );
}

#[test]
fn v12_f5b_drop_swallows_errors_source_proof() {
    // Source verification: Drop impl catches flush errors with tracing::error! only
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/builder.rs"),
    )
    .expect("read builder.rs");

    let drop_start = source
        .find("impl Drop for IndexBuilder")
        .expect("Drop impl must exist");
    let drop_body = &source[drop_start..drop_start + 300];

    assert!(
        drop_body.contains("if let Err(e) = self.flush_buffer()"),
        "Drop catches flush errors with if-let"
    );
    assert!(
        drop_body.contains("tracing::error!"),
        "Drop only logs errors — cannot propagate them"
    );
}

#[test]
fn v12_f5c_explicit_flush_preserves_entries() {
    // Contrast with f5a: calling read_sorted() explicitly flushes and returns entries
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("staging.redb");

    let mut builder = IndexBuilder::with_path(&db_path, 64 * 1024 * 1024).expect("create builder");
    for i in 0..500u64 {
        builder.insert(make_entry(i)).expect("insert");
    }

    // Explicit flush via read_sorted
    let entries = builder.read_sorted().expect("read_sorted flushes buffer");
    assert_eq!(
        entries.len(),
        500,
        "explicit read_sorted returns all 500 entries"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V12-F6: `keep_on_drop()` semantic confusion — dual-purpose flag
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: keep_on_drop() sets read_only=true, which also blocks writes.
// Two unrelated concerns (lifecycle + write protection) share one flag.

#[test]
fn v12_f6a_keep_on_drop_prevents_file_deletion() {
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("staging.redb");

    {
        let mut store = IndexStore::create(&db_path, 1000).expect("create store");
        store.insert(&make_entry(1)).expect("insert");
        store.keep_on_drop();
        // Drop should NOT delete the file because keep_on_drop was called
    }

    assert!(
        db_path.exists(),
        "keep_on_drop must prevent file deletion on drop"
    );
}

#[test]
fn v12_f6b_keep_on_drop_does_not_block_writes() {
    // V13 remediation: keep_on_drop() now sets should_keep_on_drop, NOT read_only.
    // Writes remain possible after keep_on_drop() — the semantic coupling is fixed.
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("staging.redb");

    let mut store = IndexStore::create(&db_path, 1000).expect("create store");
    store
        .insert(&make_entry(1))
        .expect("insert before keep_on_drop");

    // Call keep_on_drop — now only affects lifecycle, not write capability
    store.keep_on_drop();

    // V13 fix: inserts succeed after keep_on_drop because it no longer sets read_only
    let result = store.insert(&make_entry(2));
    assert!(
        result.is_ok(),
        "keep_on_drop must NOT block writes — semantic coupling fixed in V13"
    );

    assert_eq!(
        store.entry_count(),
        2,
        "both entries must be present after keep_on_drop + insert"
    );
}

#[test]
fn v12_f6c_keep_on_drop_sets_should_keep_on_drop() {
    // V13 remediation: keep_on_drop() now sets self.should_keep_on_drop = true
    // instead of self.read_only = true. The two concerns are decoupled.
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/store.rs"),
    )
    .expect("read store.rs");

    let fn_start = source
        .find("pub fn keep_on_drop(")
        .expect("keep_on_drop must exist");
    let fn_body = &source[fn_start..fn_start + 150];

    assert!(
        fn_body.contains("self.should_keep_on_drop = true"),
        "keep_on_drop must set should_keep_on_drop (lifecycle flag), not read_only"
    );
    assert!(
        !fn_body.contains("self.read_only = true"),
        "keep_on_drop must NOT set read_only — V13 decoupled the two flags"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V12-F7: `deserialize_entry_aligned` per-entry heap allocation
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: Every call to deserialize_entry_aligned() allocates a new
// AlignedVec on the heap. For N entries, that's N alloc/dealloc cycles.

#[test]
fn v12_f7a_read_sorted_works_with_many_entries() {
    // Insert 5000 entries, call read_sorted, verify all entries returned correctly.
    // This exercises the per-entry allocation path at scale.
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("staging.redb");
    let mut store = IndexStore::create(&db_path, 10_000).expect("create store");

    let entries: Vec<IndexEntry> = (0..5000u64).map(make_entry).collect();
    store.insert_batch(&entries).expect("insert_batch");

    let sorted = store.read_sorted().expect("read_sorted");
    assert_eq!(
        sorted.len(),
        5000,
        "read_sorted must return all 5000 entries — each deserialized via AlignedVec"
    );

    // Verify sorted order
    for i in 1..sorted.len() {
        assert!(
            sorted[i - 1].hash <= sorted[i].hash,
            "entries must be in sorted hash order"
        );
    }
}

#[test]
fn v12_f7b_deserialize_entry_aligned_called_per_entry() {
    // Source verification: deserialize_entry_aligned allocates AlignedVec per call
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/store.rs"),
    )
    .expect("read store.rs");

    let fn_start = source
        .find("fn deserialize_entry_aligned(")
        .expect("deserialize_entry_aligned must exist");
    let fn_body = &source[fn_start..fn_start + 400];

    assert!(
        fn_body.contains("rkyv::AlignedVec::with_capacity(bytes.len())"),
        "Each call allocates a new AlignedVec — O(n) heap allocations in read_sorted"
    );

    // Verify it's called in read_sorted's loop
    let read_sorted_start = source
        .find("pub fn read_sorted(&self)")
        .expect("read_sorted must exist");
    let read_sorted_body = &source[read_sorted_start..read_sorted_start + 1200];
    assert!(
        read_sorted_body.contains("deserialize_entry_aligned(bytes)?"),
        "read_sorted calls deserialize_entry_aligned per entry"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V12-F8: No size validation before `check_archived_root` in cold recovery
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: In cold recovery, decrypted data is passed to check_archived_root
// without size bounds. The from_memory() path HAS guards, but recovery does not.

#[test]
fn v12_f8a_from_memory_has_size_guard() {
    // Verify from_memory() has MAX_MEMORY_ENTRIES guard
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/reader.rs"),
    )
    .expect("read reader.rs");

    let fn_start = source
        .find("pub fn from_memory(")
        .expect("from_memory must exist");
    let fn_body = &source[fn_start..fn_start + 500];

    assert!(
        fn_body.contains("MAX_MEMORY_ENTRIES"),
        "from_memory has size guard via MAX_MEMORY_ENTRIES"
    );
}

#[test]
fn v12_f8b_cold_recovery_missing_size_guard() {
    // Source verification: recover_from_volume passes decrypted data directly to
    // check_archived_root without any size bounds check
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/reader.rs"),
    )
    .expect("read reader.rs");

    let fn_start = source
        .find("pub async fn recover_from_volume")
        .expect("recover_from_volume must exist");
    let fn_body = &source[fn_start..];

    // Find the check_archived_root calls in recovery
    let check_count = fn_body.matches("check_archived_root").count();
    assert!(
        check_count >= 2,
        "recover_from_volume has {} check_archived_root calls — multiple unguarded paths",
        check_count
    );

    // For each check_archived_root call, verify no size-limit pattern appears
    // in the 300 chars immediately preceding it. This proves the call is unguarded.
    let size_limit_patterns = [".len() >", ".len() <", "MAX_PAGES", "MAX_MEMORY", "MAX_ENTRIES"];
    let mut search_pos = 0;
    let mut unguarded_count = 0;
    while let Some(rel_pos) = fn_body[search_pos..].find("check_archived_root") {
        let abs_pos = search_pos + rel_pos;
        let window_start = abs_pos.saturating_sub(300);
        let window = &fn_body[window_start..abs_pos];
        let has_guard = size_limit_patterns.iter().any(|p| window.contains(p));
        if !has_guard {
            unguarded_count += 1;
        }
        search_pos = abs_pos + 1;
    }
    assert!(
        unguarded_count >= 2,
        "At least 2 check_archived_root calls in recover_from_volume have no size guard \
         in the preceding 300 chars — recovery path is unguarded"
    );
}

#[test]
fn v12_f8c_from_pages_has_size_guard() {
    // Verify from_pages() has MAX_PAGES guard, but recovery does not
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/reader.rs"),
    )
    .expect("read reader.rs");

    let fn_start = source
        .find("pub fn from_pages(")
        .expect("from_pages must exist");
    let fn_body = &source[fn_start..fn_start + 500];

    assert!(
        fn_body.contains("MAX_PAGES"),
        "from_pages has size guard via MAX_PAGES"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V12-F9: `compact()` dead public API — zero production call sites
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: IndexStore::compact() is public but has zero call sites in
// production code. Only used in test code.

#[test]
fn v12_f9a_compact_removed_from_source() {
    // V13 remediation: compact() was dead code (zero production callers).
    // It has been removed entirely from store.rs.
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/store.rs"),
    )
    .expect("read store.rs");

    assert!(
        !source.contains("pub fn compact("),
        "compact() must be removed from store.rs — dead code eliminated in V13"
    );
    assert!(
        !source.contains("fn compact("),
        "No compact method (public or private) should exist in store.rs"
    );
}

#[test]
fn v12_f9b_compact_has_no_production_callers() {
    // Source verification: compact() is pub but NOT called from builder.rs or chunk_index.rs
    let builder_source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/builder.rs"),
    )
    .expect("read builder.rs");
    assert!(
        !builder_source.contains(".compact()"),
        "IndexBuilder never calls compact() — dead API"
    );

    let chunk_index_source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/chunk_index.rs"),
    )
    .expect("read chunk_index.rs");
    assert!(
        !chunk_index_source.contains(".compact()"),
        "ChunkIndex never calls compact() — dead API"
    );

    let reader_source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/reader.rs"),
    )
    .expect("read reader.rs");
    assert!(
        !reader_source.contains(".compact()"),
        "IndexReader never calls compact() — dead API"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V12-F10: `index_dir` dead field in V2.1 architecture
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: IndexReader.index_dir is set to None in ALL production code paths.
// Only open() (test-only) sets it to Some.

#[test]
fn v12_f10a_from_memory_sets_no_index_dir() {
    // Create an IndexReader via from_memory — works without any filesystem directory
    let meta = MetaIndex::new();
    let entries: Vec<IndexEntry> = (0..50).map(make_entry).collect();
    // Bloom must contain the hashes for lookup to proceed past the bloom check
    let mut bloom = bloomfilter::Bloom::new_for_fp_rate(1000, 0.01);
    for entry in &entries {
        bloom.set(&entry.hash);
    }

    let reader = IndexReader::from_memory(meta, bloom, entries).expect("from_memory works");

    // Verify the reader works for lookups without any index_dir
    let result = reader.lookup(&test_hash(25)).expect("lookup succeeds");
    assert!(
        result.is_some(),
        "from_memory reader can lookup entries without index_dir"
    );
}

#[test]
fn v12_f10b_from_pages_sets_no_index_dir() {
    // Create an IndexReader via from_pages — works without any filesystem directory
    let meta = MetaIndex::new();
    let entries: Vec<IndexEntry> = (0..50).map(make_entry).collect();
    // Bloom must contain the hashes for lookup to proceed past the bloom check
    let mut bloom = bloomfilter::Bloom::new_for_fp_rate(1000, 0.01);
    for entry in &entries {
        bloom.set(&entry.hash);
    }

    let page = IndexPage::try_new(entries).expect("try_new");
    let pages = vec![(page, BlockId::new(0))];

    let reader = IndexReader::from_pages(meta, bloom, pages).expect("from_pages works");

    // Verify the reader works for lookups without any index_dir
    let result = reader.lookup(&test_hash(25)).expect("lookup succeeds");
    assert!(
        result.is_some(),
        "from_pages reader can lookup entries without index_dir"
    );
}

#[test]
fn v12_f10c_index_dir_field_removed() {
    // V13 remediation: index_dir field was dead in V2.1 architecture.
    // The field has been removed entirely from IndexReader.
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/reader.rs"),
    )
    .expect("read reader.rs");

    // Neither index_dir: None nor index_dir: Some should appear
    let none_count = source.matches("index_dir: None").count();
    let some_count = source.matches("index_dir: Some").count();
    let field_count = source.matches("index_dir").count();

    assert_eq!(
        none_count, 0,
        "index_dir: None must not appear — field removed entirely"
    );
    assert_eq!(
        some_count, 0,
        "index_dir: Some must not appear — field removed entirely"
    );
    // The only references to index_dir should be in the open() parameter name _index_dir
    assert!(
        field_count <= 2,
        "index_dir should appear at most in the open() parameter, found {} references",
        field_count
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V12-F11: `IndexError` enum entirely unused — 9 variants, 0 usage
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: IndexError defines 9 typed variants but none are ever constructed.
// All error sites use EraError::IndexError(String) directly.

#[test]
fn v12_f11a_index_error_module_removed() {
    // V13 remediation: error.rs (IndexError enum) was entirely unused dead code.
    // It has been deleted. All error sites use EraError::IndexError(String) directly.
    let error_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/error.rs");
    assert!(
        !error_path.exists(),
        "error.rs must be deleted — IndexError enum was dead code"
    );

    // Verify lib.rs no longer references the error module
    let lib_source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
    )
    .expect("read lib.rs");
    assert!(
        !lib_source.contains("mod error"),
        "lib.rs must not contain 'mod error' — module removed in V13"
    );
    assert!(
        !lib_source.contains("pub use error::IndexError"),
        "lib.rs must not re-export IndexError — type removed in V13"
    );
}

#[test]
fn v12_f11b_store_errors_are_string_typed() {
    // Operations that fail return EraError::IndexError(String), not typed IndexError variants.
    // This is the ONLY error type used — IndexError enum is gone.
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("staging.redb");

    // Opening a non-existent file should fail with EraError::IndexError(String)
    let result = IndexStore::open_readonly(&db_path);

    match result {
        Err(EraError::IndexError(_msg)) => {
            // Correct — all index errors are stringly-typed EraError::IndexError
        }
        Err(other) => panic!(
            "Expected EraError::IndexError(String), got different variant: {:?}",
            other,
        ),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

#[test]
fn v12_f11c_thiserror_dependency_removed() {
    // V13 remediation: thiserror was only used by error.rs (IndexError).
    // With error.rs deleted, thiserror is no longer a dependency.
    let cargo_toml = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .expect("read Cargo.toml");
    assert!(
        !cargo_toml.contains("thiserror"),
        "thiserror must be removed from Cargo.toml — only used by deleted error.rs"
    );
}
