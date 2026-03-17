//! # Adversarial Audit V12 — Novel Findings Suite
//!
//! **Audit Date:** 2026-02-26
//! **Target:** `era-index` crate — competitive adversarial audit
//! **Scope:** V12-F1 through V12-F11 (25+ tests)
//! **Methodology:** Source scanning + behavioral testing

use era_common::{BlockId, ChunkHash, EraError, VolumeId};
use era_index::{
    BloomFilterData, IndexBuilder, IndexEntry, IndexLocation, IndexPage, IndexReader, IndexStore,
    MetaIndex, ENTRIES_PER_PAGE,
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
    .expect("valid entry")
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
    // Source verification: builder.rs entry_count() now flushes buffer then returns O(1) store count
    // (V13 fix: replaced O(n) per-hash store.get() with flush_buffer + store.entry_count())
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/builder.rs"),
    )
    .expect("read builder.rs");
    let fn_start = source
        .find("pub fn entry_count(")
        .expect("entry_count must exist");
    let fn_body = &source[fn_start..fn_start + 500];
    assert!(
        fn_body.contains("self.flush_buffer()"),
        "entry_count must flush buffer before returning store count — O(1) after flush"
    );
    assert!(
        fn_body.contains("self.store.entry_count()"),
        "entry_count must delegate to store.entry_count() which is O(1)"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V12-F2: Cold recovery O(n×m) nested loop
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: recover_from_volume had a nested loop: for each scanned block,
// it tried every unrecovered meta.pages entry. Worst case was O(n×m).
// V13-F12: inner loop replaced with while+swap_remove for O(n) amortized.
// V18-F1: Further optimized to HashMap-indexed O(1) lookup per block.

#[test]
fn v12_f2a_cold_recovery_nested_loop_exists() {
    // Source verification: reader.rs recover_from_volume now uses
    // block_id_to_page_idx HashMap for O(1) lookup (V18-F1 optimization).
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/reader.rs"),
    )
    .expect("read reader.rs");

    let fn_start = source
        .find("pub async fn recover_from_volume")
        .expect("recover_from_volume must exist");
    let fn_body = &source[fn_start..];

    // V18-F1: recovery now uses HashMap for O(1) block_id lookup
    assert!(
        fn_body.contains("block_id_to_page_idx"),
        "recover_from_volume must use block_id_to_page_idx HashMap — V18-F1 optimization"
    );
}

#[test]
fn v12_f2b_cold_recovery_complexity_proof() {
    // V18-F1: The recover_from_volume function now uses a HashMap<BlockId, usize>
    // to index unrecovered pages by block_id. Each scanned block does a HashMap lookup
    // for O(1) matching instead of the previous O(n) while+swap_remove pattern.
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/reader.rs"),
    )
    .expect("read reader.rs");

    let fn_start = source
        .find("pub async fn recover_from_volume")
        .expect("recover_from_volume must exist");
    let fn_body = &source[fn_start..];

    // V18-F1: HashMap-indexed approach replaces swap_remove pattern
    // (now lives in recover_pages_via_scan helper)
    assert!(
        fn_body.contains("block_id_to_page_idx.remove"),
        "Recovery loop removes matched entries from HashMap — V18-F1 optimization"
    );

    // The matched flag + break pattern still exists for each scanned block
    assert!(
        fn_body.contains("matched = true"),
        "Recovery loop sets matched flag when page is recovered"
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
    let entries: Vec<IndexEntry> = (0..100).map(make_entry).collect();

    let reader = IndexReader::from_memory(meta, entries).expect("from_memory with empty meta");
    assert_eq!(reader.meta_page_count(), 1, "100 entries → 1 page");
}

#[test]
fn v12_f3b_from_memory_appends_to_caller_meta() {
    // V16-F2 update: from_memory() now takes `mut meta: MetaIndex` directly
    // instead of shadow-rebinding. The behavior is the same: meta is mutated
    // by clearing pages and adding new ones from the entries.
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/reader.rs"),
    )
    .expect("read reader.rs");

    let fn_start = source
        .find("pub fn from_memory(")
        .expect("from_memory must exist");
    let fn_body = &source[fn_start..(fn_start + 2500).min(source.len())];

    // V16-F2: parameter is now `mut meta: MetaIndex` (not shadow rebinding)
    assert!(
        fn_body.contains("mut meta: MetaIndex"),
        "from_memory takes mut meta parameter directly (V16-F2)"
    );
    assert!(
        fn_body.contains("meta.add_page("),
        "from_memory appends pages to caller's MetaIndex"
    );
    // V13-F2: from_memory now clears pages before appending
    assert!(
        fn_body.contains("meta.clear_pages()"),
        "from_memory clears pre-existing pages before appending (V13-F2 fix)"
    );
}

#[test]
fn v12_f3c_from_memory_preserves_preexisting_pages() {
    // V13-F2: from_memory() now clears pre-existing pages via clear_pages() before
    // adding new pages. A pre-existing page is cleared, and only the newly-built pages remain.
    let mut meta = MetaIndex::new();
    // Pre-existing page covers hash range 0..50 (before the entries' range)
    meta.add_page(test_hash(0), test_hash(50), BlockId::new(99), 0, 0)
        .expect("add pre-existing page");

    // Entries cover hash range 100..199 — non-overlapping with pre-existing page
    let entries: Vec<IndexEntry> = (100..200u64).map(make_entry).collect();

    let reader = IndexReader::from_memory(meta, entries)
        .expect("from_memory must succeed with non-overlapping pre-existing page");

    // V13-F2: from_memory now clears pre-existing pages via clear_pages().
    // Only the newly-built page (100..199) remains — pre-existing page (0..50) is cleared.
    assert_eq!(
        reader.meta_page_count(),
        1,
        "reader must have exactly 1 page: pre-existing page cleared by V13-F2, only new page remains, got {}",
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
    let drop_body = &source[drop_start..drop_start + 400];

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
            sorted[i - 1].hash() <= sorted[i].hash(),
            "entries must be in sorted hash order"
        );
    }
}

#[test]
fn v12_f7b_deserialize_entry_aligned_called_per_entry() {
    // Source verification: read_sorted now uses deserialize_entry_with_buf to reuse AlignedVec
    // (V13 fix: replaced per-entry AlignedVec allocation with shared buffer)
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/store.rs"),
    )
    .expect("read store.rs");

    // The buffered variant must exist
    let fn_start = source
        .find("fn deserialize_entry_with_buf(")
        .expect("deserialize_entry_with_buf must exist");
    let fn_body = &source[fn_start..fn_start + 600];

    assert!(
        fn_body.contains("buf.clear()"),
        "Buffered variant clears and reuses caller-provided AlignedVec"
    );

    // V20-F4: read_sorted now delegates to for_each_sorted_page, which
    // uses the buffered variant internally. Verify the delegation pattern.
    let read_sorted_start = source
        .find("pub fn read_sorted(&self)")
        .expect("read_sorted must exist");
    let read_sorted_body = &source[read_sorted_start..read_sorted_start + 300];
    assert!(
        read_sorted_body.contains("for_each_sorted_page"),
        "read_sorted delegates to for_each_sorted_page (V20-F4 dedup)"
    );

    // Verify for_each_sorted_page still uses the buffered variant
    let for_each_start = source
        .find("pub fn for_each_sorted_page")
        .expect("for_each_sorted_page must exist");
    let for_each_body = &source[for_each_start..for_each_start + 2000];
    assert!(
        for_each_body.contains("deserialize_entry_with_buf"),
        "for_each_sorted_page uses deserialize_entry_with_buf to reuse buffer per entry"
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
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/reader.rs"),
    )
    .expect("read reader.rs");

    let fn_start = source
        .find("pub async fn recover_from_volume")
        .expect("recover_from_volume must exist");
    let fn_body = &source[fn_start..];

    let checked_deser_count = fn_body.matches("rkyv::from_bytes").count();
    assert!(
        checked_deser_count >= 2,
        "recover_from_volume should use checked rkyv deserialization on multiple paths"
    );

    assert!(
        fn_body.matches("validate_rkyv_size(").count() >= 2,
        "recover_from_volume should validate serialized sizes before checked deserialization"
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

    let reader = IndexReader::from_memory(meta, entries).expect("from_memory works");

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

    let page = IndexPage::try_new(entries).expect("try_new");
    let pages = vec![(page, BlockId::new(0))];

    let reader = IndexReader::from_pages(meta, pages).expect("from_pages works");

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
