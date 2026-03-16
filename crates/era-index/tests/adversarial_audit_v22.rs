//! # Adversarial Audit V22 — Comprehensive Test Suite
//!
//! **Audit Date:** 2026-02-27
//! **Target:** `era-index` crate — V22 adversarial audit
//! **Scope:** V22-F1 through V22-F12
//! **Methodology:** Source-level static analysis + behavioral verification
//!
//! ## V21 Regression Status (All FIXED)
//!
//! | ID | Finding | Status |
//! |----|---------|--------|
//! | V21-F1 | insert() inline read_txn avoids double bloom check | FIXED |
//! | V21-F2 | candidates Vec lacks capacity pre-computation | FIXED |
//! | V21-F3 | try_new_presorted is pub(crate) | FIXED |
//! | V21-F4 | to_bloom() panics on invalid BloomFilterData | FIXED |
//! | V21-F5 | rebuild_bloom_if_needed is silent | FIXED |
//! | V21-F6 | finalize() logs after bloom serialization | FIXED |
//! | V21-F7 | MIN/MAX_INDEX_PAGE_SIZE lack derivation docs | FIXED |
//! | V21-F8 | BATCH_SIZE hardcoded | FIXED |
//! | V21-F9 | insert_batch() doesn't bloom pre-filter | FIXED |
//! | V21-F10 | find_page Err(0) no trace logging | FIXED |
//! | V21-F11 | IndexReader missing total_entry_count() | FIXED |
//! | V21-F12 | for_each_sorted_page align_buf hardcoded 256 | FIXED |
//!
//! ## V22 Findings
//!
//! | ID | Severity | Title |
//! |----|----------|-------|
//! | V22-F1 | MEDIUM | insert_batch() opens per-candidate read_txn for bloom-confirmed duplicates |
//! | V22-F2 | LOW | builder finalize() Vec::new() causes encrypted_blocks reallocation |
//! | V22-F3 | LOW | from_memory() uses try_new() on already-sorted entries |
//! | V22-F4 | LOW | add_page() duplicate block_id scan O(n) cost undocumented |
//! | V22-F5 | MEDIUM | BloomFilterData lacks validated constructor |
//! | V22-F6 | LOW | for_each_sorted_page has no progress logging for large iterations |
//! | V22-F7 | LOW | recover_from_volume allocates new candidate_block_ids Vec per iteration |
//! | V22-F8 | MEDIUM | finalize() clones entire bloom bitmap just to serialize |
//! | V22-F9 | LOW | IndexEntry has no Display impl for human-readable logging |
//! | V22-F10 | LOW | IndexStore has no way to query staging database disk usage |
//! | V22-F11 | LOW | recover_from_volume embedded_pages HashMap uses default capacity |
//! | V22-F12 | LOW | with_batch_size(0) silently clamps to 1 |

#[allow(unused_imports)]
use era_common::{BlockId, ChunkHash, VolumeId};
#[allow(unused_imports)]
use era_index::{
    BloomFilterData, ChunkIndex, ChunkIndexConfig, IndexBuilder, IndexEntry, IndexLocation,
    IndexReader, IndexStore, MetaIndex, ENTRIES_PER_PAGE,
};

// ═══════════════════════════════════════════════════════════════════════
// Test Utilities
// ═══════════════════════════════════════════════════════════════════════

#[allow(dead_code)]
/// Canonical BE-tail test hash (V11-F9 compliant)
fn test_hash(value: u64) -> ChunkHash {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    ChunkHash::from_bytes(bytes)
}

#[allow(dead_code)]
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

#[allow(dead_code)]
fn read_source_file(relative_path: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = std::path::Path::new(manifest_dir).join(relative_path);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e))
}

#[allow(dead_code)]
fn extract_fn_body(source: &str, fn_signature: &str, max_chars: usize) -> String {
    let pos = source
        .find(fn_signature)
        .unwrap_or_else(|| panic!("Function '{}' not found in source", fn_signature));
    let end = (pos + max_chars).min(source.len());
    source[pos..end].to_string()
}

// ═══════════════════════════════════════════════════════════════════════
// V22-F1 (MEDIUM): insert_batch() single read_txn for bloom-hit candidates
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: store.rs, IndexStore::insert_batch()
// Previously, each bloom-confirmed candidate opened its own read_txn.
// Now uses a single read_txn for all bloom hits (O(1) transactions).

#[test]
fn v22_f1a_insert_batch_single_read_txn() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "fn insert_batch(", 2000);

    // There should be exactly ONE begin_read in the bloom_hits block
    let bloom_hits_section = fn_body
        .find("bloom_hits")
        .expect("V22-F1: insert_batch must have bloom_hits filtering");
    let after_bloom = &fn_body[bloom_hits_section..];
    let read_txn_count = after_bloom.matches("begin_read()").count();
    assert_eq!(
        read_txn_count, 1,
        "V22-F1: bloom_hits section must use exactly 1 begin_read() (got {})",
        read_txn_count
    );
}

#[test]
fn v22_f1b_insert_batch_has_v22_comment() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "fn insert_batch(", 2000);

    assert!(
        fn_body.contains("V22-F1"),
        "V22-F1: insert_batch must have V22-F1 comment"
    );
}

#[test]
fn v22_f1c_insert_batch_dedup_behavioral() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.redb");
    let mut store = IndexStore::create(&db_path, 10_000).unwrap();

    // Insert initial batch
    let batch1: Vec<IndexEntry> = (0..100).map(make_entry).collect();
    store.insert_batch(&batch1).unwrap();
    assert_eq!(store.entry_count(), 100);

    // Insert overlapping batch — duplicates should be filtered
    let batch2: Vec<IndexEntry> = (50..150).map(make_entry).collect();
    store.insert_batch(&batch2).unwrap();
    assert_eq!(store.entry_count(), 150);
}

// ═══════════════════════════════════════════════════════════════════════
// V22-F2 (LOW): builder finalize() pre-allocates encrypted_blocks Vec
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: builder.rs, IndexBuilder::finalize()
// Previously used Vec::new() — now uses Vec::with_capacity based on
// entry_count / ENTRIES_PER_PAGE estimate.

#[test]
fn v22_f2a_builder_finalize_has_prealloc() {
    let source = read_source_file("src/builder.rs");
    let fn_body = extract_fn_body(&source, "pub async fn finalize<W: StorageWriter>", 3000);

    assert!(
        fn_body.contains("Vec::with_capacity"),
        "V22-F2: finalize must pre-allocate encrypted_blocks"
    );
    assert!(
        fn_body.contains("estimated_pages"),
        "V22-F2: finalize must compute estimated_pages"
    );
}

#[test]
fn v22_f2b_builder_finalize_has_v22_comment() {
    let source = read_source_file("src/builder.rs");
    let fn_body = extract_fn_body(&source, "pub async fn finalize<W: StorageWriter>", 3000);

    assert!(
        fn_body.contains("V22-F2"),
        "V22-F2: finalize must have V22-F2 comment"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V22-F3 (LOW): from_memory() uses try_new_presorted for sorted entries
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs, IndexReader::from_memory()
// Entries are already sorted from a sorted Vec, so try_new() re-sorting
// was unnecessary. Now uses try_new_presorted + HashMap::with_capacity.

#[test]
fn v22_f3a_from_memory_uses_presorted() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "pub fn from_memory(", 2000);

    assert!(
        fn_body.contains("try_new_presorted"),
        "V22-F3: from_memory must use try_new_presorted"
    );
}

#[test]
fn v22_f3b_from_memory_has_v22_comment() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "pub fn from_memory(", 2000);

    assert!(
        fn_body.contains("V22-F3"),
        "V22-F3: from_memory must have V22-F3 comment"
    );
}

#[test]
fn v22_f3c_from_memory_has_with_capacity() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "pub fn from_memory(", 2000);

    assert!(
        fn_body.contains("HashMap::with_capacity"),
        "V22-F3: from_memory must pre-allocate HashMap"
    );
}

#[test]
fn v22_f3d_from_memory_behavioral() {
    let entries: Vec<IndexEntry> = (0..500).map(make_entry).collect();
    let meta = MetaIndex::new();
    let reader = IndexReader::from_memory(meta, entries).unwrap();

    // Verify lookup works correctly
    let result = reader.lookup(&test_hash(250)).unwrap();
    assert!(
        result.is_some(),
        "V22-F3: from_memory lookup must find inserted entry"
    );

    let result = reader.lookup(&test_hash(9999)).unwrap();
    assert!(
        result.is_none(),
        "V22-F3: from_memory lookup must not find absent entry"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V22-F4 (LOW): add_page() duplicate block_id scan O(n) cost documented
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: lib.rs, MetaIndex::add_page()
// The linear scan for duplicate block_ids is bounded by MAX_META_PAGES.
// Now documented with a comment explaining the bounded cost.

#[test]
fn v22_f4a_add_page_has_bounded_cost_comment() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "pub fn add_page(", 1500);

    assert!(
        fn_body.contains("V22-F4"),
        "V22-F4: add_page must have V22-F4 comment"
    );
}

#[test]
fn v22_f4b_add_page_mentions_bounded() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "pub fn add_page(", 1500);

    assert!(
        fn_body.contains("bounded") || fn_body.contains("MAX_META_PAGES"),
        "V22-F4: add_page comment must mention bounded cost or MAX_META_PAGES"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V22-F5 (MEDIUM): BloomFilterData validated constructor
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: bloom_serde.rs, BloomFilterData::new()
// Previously, BloomFilterData could only be constructed via from_bloom()
// or struct literal. Now has a validated constructor + accessor methods.

#[test]
fn v22_f5a_bloom_filter_data_has_new_constructor() {
    let source = read_source_file("src/bloom_serde.rs");

    assert!(
        source.contains("pub fn new("),
        "V22-F5: BloomFilterData must have pub fn new()"
    );
    assert!(
        source.contains("V22-F5"),
        "V22-F5: bloom_serde.rs must have V22-F5 comment"
    );
}

#[test]
fn v22_f5b_bloom_filter_data_has_accessors() {
    let source = read_source_file("src/bloom_serde.rs");

    assert!(
        source.contains("pub fn version("),
        "V22-F5: must have version()"
    );
    assert!(
        source.contains("pub fn bitmap_ref("),
        "V22-F5: must have bitmap_ref()"
    );
    assert!(
        source.contains("pub fn bitmap_bits("),
        "V22-F5: must have bitmap_bits()"
    );
    assert!(
        source.contains("pub fn k_num("),
        "V22-F5: must have k_num()"
    );
    assert!(
        source.contains("pub fn sip_keys("),
        "V22-F5: must have sip_keys()"
    );
}

#[test]
fn v22_f5c_new_rejects_zero_bitmap_bits() {
    let result = BloomFilterData::new(vec![0u8; 8], 0, 3, [(1, 2), (3, 4)]);
    assert!(result.is_err(), "V22-F5: new() must reject bitmap_bits=0");
}

#[test]
fn v22_f5d_new_rejects_zero_k_num() {
    let result = BloomFilterData::new(vec![0u8; 8], 64, 0, [(1, 2), (3, 4)]);
    assert!(result.is_err(), "V22-F5: new() must reject k_num=0");
}

#[test]
fn v22_f5e_new_rejects_short_bitmap() {
    let result = BloomFilterData::new(vec![0u8; 1], 64, 3, [(1, 2), (3, 4)]);
    assert!(
        result.is_err(),
        "V22-F5: new() must reject bitmap shorter than bitmap_bits"
    );
}

#[test]
fn v22_f5f_new_rejects_zero_sip_keys() {
    let result = BloomFilterData::new(vec![0u8; 8], 64, 3, [(0, 0), (0, 0)]);
    assert!(
        result.is_err(),
        "V22-F5: new() must reject all-zero sip_keys"
    );
}

#[test]
fn v22_f5g_new_accepts_valid_params() {
    let result = BloomFilterData::new(vec![0u8; 8], 64, 3, [(1, 2), (3, 4)]);
    assert!(result.is_ok(), "V22-F5: new() must accept valid parameters");
    let data = result.unwrap();
    assert_eq!(data.version(), 1);
    assert_eq!(data.bitmap_bits(), 64);
    assert_eq!(data.k_num(), 3);
    assert_eq!(data.sip_keys(), [(1, 2), (3, 4)]);
    assert_eq!(data.bitmap_ref().len(), 8);
}

// ═══════════════════════════════════════════════════════════════════════
// V22-F6 (LOW): for_each_sorted_page progress logging
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: store.rs, IndexStore::for_each_sorted_page()
// No progress logging existed for large iterations. Now logs every 100 pages.

#[test]
fn v22_f6a_for_each_sorted_page_has_progress_logging() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "pub fn for_each_sorted_page<F>", 2500);

    assert!(
        fn_body.contains("V22-F6") || fn_body.contains("V23-F8"),
        "V22-F6: for_each_sorted_page must have V22-F6 or V23-F8 comment"
    );
    assert!(
        fn_body.contains("tracing::debug!"),
        "V22-F6: for_each_sorted_page must have debug logging"
    );
}

#[test]
fn v22_f6b_progress_logging_checks_interval() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "pub fn for_each_sorted_page<F>", 2500);

    // Should check every 100 pages
    assert!(
        fn_body.contains("100"),
        "V22-F6: progress logging must use 100-page interval"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V22-F7 (LOW): recover_from_volume reuses candidate_block_ids Vec
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs, IndexReader::recover_from_volume()
// Previously allocated a new Vec per scan iteration. Now reuses via .clear().

#[test]
fn v22_f7a_recover_uses_reusable_candidate_vec() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "pub async fn recover_from_volume", 25000);

    assert!(
        fn_body.contains("candidate_block_ids"),
        "V22-F7: recover must have candidate_block_ids Vec"
    );
    assert!(
        fn_body.contains("candidate_block_ids.clear()"),
        "V22-F7: recover must clear candidate_block_ids per iteration"
    );
}

#[test]
fn v22_f7b_recover_has_v22_comment() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_pages_via_scan", 15000);

    assert!(
        fn_body.contains("V22-F7"),
        "V22-F7: recover must have V22-F7 comment"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V22-F8 (MEDIUM): finalize() serializes bloom directly (no clone)
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: chunk_index.rs, ChunkIndex::finalize()
// Previously cloned the bloom bitmap. Now serializes directly from
// builder.bloom() reference.

#[test]
fn v22_f8a_finalize_no_bloom_clone() {
    let source = read_source_file("src/chunk_index.rs");
    let fn_body = extract_fn_body(&source, "pub fn finalize(&mut self)", 2000);

    // Should NOT have bloom().clone() in actual code (ignore comments)
    // The V22-F8 comment mentions the old pattern; check that no uncommented line has it
    let has_code_clone = fn_body.lines().any(|line| {
        let trimmed = line.trim();
        !trimmed.starts_with("//") && trimmed.contains("bloom().clone()")
    });
    assert!(
        !has_code_clone,
        "V22-F8: finalize must NOT clone the bloom filter in code"
    );
    // Should have builder.bloom() directly in serialize_bloom call
    assert!(
        fn_body.contains("serialize_bloom(builder.bloom())"),
        "V22-F8: finalize must serialize directly from builder.bloom()"
    );
}

#[test]
fn v22_f8b_finalize_has_v22_comment() {
    let source = read_source_file("src/chunk_index.rs");
    let fn_body = extract_fn_body(&source, "pub fn finalize(&mut self)", 2000);

    assert!(
        fn_body.contains("V22-F8"),
        "V22-F8: finalize must have V22-F8 comment"
    );
}

#[test]
fn v22_f8c_finalize_bloom_serialization_after_log() {
    // V21-F6 invariant preserved: log comes before bloom serialization
    let source = read_source_file("src/chunk_index.rs");
    let fn_body = extract_fn_body(&source, "pub fn finalize(&mut self)", 2000);

    let log_pos = fn_body
        .find("tracing::info!")
        .expect("V22-F8: finalize must have info log");
    let bloom_pos = fn_body
        .find("serialize_bloom")
        .expect("V22-F8: finalize must call serialize_bloom");

    assert!(
        log_pos < bloom_pos,
        "V22-F8: log must come BEFORE bloom serialization (V21-F6 invariant)"
    );
}

#[test]
fn v22_f8d_finalize_behavioral() {
    let mut tree = ChunkIndex::new_default().unwrap();

    for i in 0..500u64 {
        let entry = IndexEntry::new(test_hash(i), VolumeId::new(), BlockId::new(i), 0, 4096)
            .expect("valid entry");
        tree.insert(entry).unwrap();
    }

    let reader = tree.finalize().expect("finalize must succeed");

    // Verify bloom filter works correctly after serialization
    for i in 0..500u64 {
        assert!(
            reader.bloom_contains(&test_hash(i)),
            "V22-F8: bloom must contain entry {} after finalize",
            i
        );
    }
    assert!(
        !reader.bloom_contains(&test_hash(9999)),
        "V22-F8: bloom must not contain absent entry"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V22-F9 (LOW): IndexEntry Display impl
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: lib.rs, impl Display for IndexEntry
// Debug formatting showed raw byte arrays. Display provides concise hex
// summary suitable for tracing::info! and similar contexts.

#[test]
fn v22_f9a_index_entry_has_display() {
    let source = read_source_file("src/lib.rs");

    assert!(
        source.contains("impl std::fmt::Display for IndexEntry"),
        "V22-F9: IndexEntry must implement Display"
    );
    assert!(
        source.contains("V22-F9"),
        "V22-F9: lib.rs must have V22-F9 comment"
    );
}

#[test]
fn v22_f9b_display_includes_hex_hash() {
    let entry = make_entry(42);
    let display = format!("{}", entry);

    assert!(
        display.contains("IndexEntry("),
        "V22-F9: Display must include 'IndexEntry('"
    );
    assert!(
        display.contains("hash="),
        "V22-F9: Display must include hash field"
    );
    assert!(
        display.contains(".."),
        "V22-F9: Display must use truncated hex (with ..)"
    );
}

#[test]
fn v22_f9c_display_includes_location_fields() {
    let entry = make_entry(42);
    let display = format!("{}", entry);

    assert!(
        display.contains("blk="),
        "V22-F9: Display must include block_id"
    );
    assert!(
        display.contains("off="),
        "V22-F9: Display must include offset"
    );
    assert!(
        display.contains("len="),
        "V22-F9: Display must include length"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V22-F10 (LOW): IndexStore::db_file_size()
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: store.rs, IndexStore::db_file_size()
// No way to query staging database disk usage. Now returns Option<u64>.

#[test]
fn v22_f10a_db_file_size_exists() {
    let source = read_source_file("src/store.rs");

    assert!(
        source.contains("pub fn db_file_size("),
        "V22-F10: IndexStore must have db_file_size()"
    );
    assert!(
        source.contains("V22-F10"),
        "V22-F10: store.rs must have V22-F10 comment"
    );
}

#[test]
fn v22_f10b_db_file_size_returns_option() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "pub fn db_file_size(", 200);

    assert!(
        fn_body.contains("Option<u64>"),
        "V22-F10: db_file_size must return Option<u64>"
    );
}

#[test]
fn v22_f10c_db_file_size_behavioral() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.redb");
    let store = IndexStore::create(&db_path, 1024).unwrap();

    let size = store.db_file_size();
    assert!(
        size.is_some(),
        "V22-F10: db_file_size must return Some for existing store"
    );
    assert!(
        size.unwrap() > 0,
        "V22-F10: db_file_size must be > 0 for existing store"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V22-F11 (LOW): recover_from_volume pre-allocates embedded_pages HashMap
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs, IndexReader::recover_from_volume()
// HashMap used default capacity. Now uses with_capacity(meta.pages().len()).

#[test]
fn v22_f11a_recover_has_hashmap_prealloc() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "pub async fn recover_from_volume", 15000);

    // Should pre-allocate embedded_pages with capacity
    assert!(
        fn_body.contains("HashMap::with_capacity(meta.pages().len())"),
        "V22-F11: recover must pre-allocate embedded_pages HashMap"
    );
}

#[test]
fn v22_f11b_recover_has_v22_comment() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_pages_via_scan", 15000);

    assert!(
        fn_body.contains("V22-F11"),
        "V22-F11: recover must have V22-F11 comment"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V22-F12 (LOW): with_batch_size(0) logs warning before clamping
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: builder.rs, IndexBuilder::with_batch_size()
// Previously silently clamped 0→1 via .max(1). Now warns before clamping.

#[test]
fn v22_f12a_with_batch_size_has_warning() {
    let source = read_source_file("src/builder.rs");
    let fn_body = extract_fn_body(&source, "pub fn with_batch_size(", 500);

    assert!(
        fn_body.contains("tracing::warn!"),
        "V22-F12: with_batch_size must log warning for 0"
    );
    // V22-F12 comment is in the doc comment above the fn signature,
    // so check the source directly for the comment near with_batch_size
    assert!(
        source.contains("V22-F12"),
        "V22-F12: with_batch_size must have V22-F12 comment"
    );
}

#[test]
fn v22_f12b_with_batch_size_zero_still_clamps() {
    let builder = IndexBuilder::new_default().unwrap().with_batch_size(0);

    // Should still work — clamped to 1
    let mut builder = builder;
    let entry = make_entry(1);
    builder.insert(entry).unwrap();
    assert_eq!(builder.entry_count(), 1);
}

#[test]
fn v22_f12c_with_batch_size_valid_works() {
    let builder = IndexBuilder::new_default().unwrap().with_batch_size(500);

    let mut builder = builder;
    for i in 0..100 {
        builder.insert(make_entry(i)).unwrap();
    }
    assert_eq!(builder.entry_count(), 100);
}

// ═══════════════════════════════════════════════════════════════════════
// V21 Regression Checks
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v22_regression_v21_f1_insert_inline_read_txn() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(
        &source,
        "pub fn insert(&mut self, entry: &IndexEntry)",
        2000,
    );

    assert!(
        fn_body.contains("V21-F1"),
        "Regression: V21-F1 insert inline read_txn comment must be preserved"
    );
}

#[test]
fn v22_regression_v21_f4_to_bloom_returns_result() {
    let source = read_source_file("src/bloom_serde.rs");
    let fn_body = extract_fn_body(&source, "pub fn to_bloom", 500);

    assert!(
        fn_body.contains("Result<Bloom<T>>"),
        "Regression: V21-F4 to_bloom must return Result"
    );
}

#[test]
fn v22_regression_v21_f6_log_before_bloom() {
    let source = read_source_file("src/chunk_index.rs");
    let fn_body = extract_fn_body(&source, "pub fn finalize(&mut self)", 2000);

    let log_pos = fn_body
        .find("tracing::info!")
        .expect("Regression: finalize must have info log");
    let bloom_pos = fn_body
        .find("serialize_bloom")
        .expect("Regression: finalize must call serialize_bloom");

    assert!(
        log_pos < bloom_pos,
        "Regression: V21-F6 invariant — log must come before bloom serialization"
    );
}

#[test]
fn v22_regression_v20_f1_from_pages_rebuilds_bloom() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "pub fn from_pages(", 2000);

    assert!(
        fn_body.contains("verified_bloom"),
        "Regression: V20-F1 from_pages must rebuild bloom from entries"
    );
}

#[test]
fn v22_regression_v19_f3_zero_length_rejected() {
    let result = IndexEntry::new(test_hash(1), VolumeId::new(), BlockId::new(0), 0, 0);
    assert!(
        result.is_err(),
        "Regression: V19-F3 zero-length must be rejected"
    );
}
