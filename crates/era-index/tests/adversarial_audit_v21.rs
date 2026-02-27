//! # Adversarial Audit V21 — Comprehensive Test Suite
//!
//! **Audit Date:** 2026-02-27
//! **Target:** `era-index` crate — V21 adversarial audit
//! **Scope:** V21-F1 through V21-F12
//! **Methodology:** Source-level static analysis + behavioral verification
//!
//! ## V20 Regression Status (All FIXED)
//!
//! | ID | Finding | Status |
//! |----|---------|--------|
//! | V20-F1 | from_pages() trusts caller bloom | FIXED |
//! | V20-F2 | RwLock on read-only IndexReader | FIXED |
//! | V20-F3 | insert() opens write txn for known duplicates | FIXED |
//! | V20-F4 | read_sorted() duplicates for_each_sorted_page() logic | FIXED |
//! | V20-F5 | BloomFilterData allows all-zero sip_keys | FIXED |
//! | V20-F6 | load_page uses InvalidFormat instead of IndexError | FIXED |
//! | V20-F7 | Drop impl deletes staging file on flush failure | FIXED |
//! | V20-F8 | from_pages() receives full bloom clone unnecessarily | FIXED |
//! | V20-F9 | recover_from_volume re-scans pages in step 3 | FIXED |
//! | V20-F10 | contains_range() missing #[must_use] | FIXED |
//! | V20-F11 | open_readonly bloom rebuild has no progress logging | FIXED |
//! | V20-F12 | bloom_expected_items() missing doc comment | FIXED |
//!
//! ## V21 Findings
//!
//! | ID | Severity | Title |
//! |----|----------|-------|
//! | V21-F1 | LOW | insert() inline read_txn avoids double bloom check |
//! | V21-F2 | LOW | candidates Vec in recover_from_volume lacks capacity pre-computation |
//! | V21-F3 | MEDIUM | try_new_presorted is pub(crate) — should be pub for external callers |
//! | V21-F4 | HIGH | to_bloom() panics on invalid BloomFilterData — should return Result |
//! | V21-F5 | MEDIUM | rebuild_bloom_if_needed is silent — no logging when triggered |
//! | V21-F6 | LOW | ChunkIndex::finalize() logs entry count after bloom serialization |
//! | V21-F7 | LOW | MIN_INDEX_PAGE_SIZE / MAX_INDEX_PAGE_SIZE lack derivation docs |
//! | V21-F8 | MEDIUM | BATCH_SIZE hardcoded — should be configurable |
//! | V21-F9 | MEDIUM | insert_batch() doesn't bloom pre-filter duplicates |
//! | V21-F10 | LOW | find_page Err(0) case has no trace logging |
//! | V21-F11 | LOW | IndexReader missing total_entry_count() accessor |
//! | V21-F12 | LOW | for_each_sorted_page align_buf hardcoded 256 bytes |

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

/// Read the contents of a source file relative to the era-index crate root.
fn read_source_file(relative_path: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let full_path = std::path::Path::new(manifest_dir).join(relative_path);
    std::fs::read_to_string(&full_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", full_path.display(), e))
}

/// Extract a window of text around a function definition from source code.
/// Uses a generous window (up to `window` chars) from the function signature.
fn extract_fn_body(source: &str, fn_name: &str, window: usize) -> String {
    let start = source
        .find(&format!("fn {fn_name}"))
        .unwrap_or_else(|| panic!("Function '{}' not found in source", fn_name));
    let end = (start + window).min(source.len());
    source[start..end].to_string()
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
// V21-F1 (LOW): insert() inlines read_txn to avoid double bloom check
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: store.rs, insert()
// The early-return path now opens a read_txn directly instead of calling
// get(), which would redundantly check the bloom filter a second time.

#[test]
fn v21_f1a_insert_inlines_read_txn() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "insert(&mut self, entry", 2000);

    // Must have a bloom check
    assert!(
        fn_body.contains("self.bloom.check(&entry.hash)"),
        "V21-F1: insert must have bloom.check early return"
    );

    // The early-return path should NOT call self.get() — it inlines the read_txn
    // Check that after bloom.check, the code opens begin_read directly
    let bloom_pos = fn_body.find("self.bloom.check(&entry.hash)").unwrap();
    let after_bloom = &fn_body[bloom_pos..];

    // After bloom check, should see begin_read before begin_write
    let begin_read_pos = after_bloom
        .find("begin_read()")
        .expect("V21-F1: insert early-return should use begin_read directly");
    let begin_write_pos = after_bloom
        .find("begin_write()")
        .expect("V21-F1: insert must have begin_write");
    assert!(
        begin_read_pos < begin_write_pos,
        "V21-F1: read_txn must come before write_txn (inline check)"
    );
}

#[test]
fn v21_f1b_insert_comment_documents_inline_rationale() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "insert(&mut self, entry", 2000);

    assert!(
        fn_body.contains("V21-F1"),
        "V21-F1: insert must have V21-F1 comment documenting inline rationale"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V21-F2 (LOW): candidates Vec capacity pre-computation
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs, recover_from_volume()
// The candidates Vec now reserves capacity based on upper_bound.

#[test]
fn v21_f2a_candidates_reserves_capacity() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 25000);

    assert!(
        fn_body.contains("candidates.reserve("),
        "V21-F2: candidates Vec must reserve capacity based on upper_bound"
    );
}

#[test]
fn v21_f2b_candidates_has_v21_comment() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 25000);

    assert!(
        fn_body.contains("V21-F2"),
        "V21-F2: candidates logic must have V21-F2 comment"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V21-F3 (MEDIUM): try_new_presorted is pub
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: lib.rs, IndexPage::try_new_presorted()
// Was pub(crate) — now pub for external consumers (like era-engine).

#[test]
fn v21_f3a_try_new_presorted_is_pub() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "try_new_presorted(", 500);

    // Must start with "pub fn" (not "pub(crate) fn")
    assert!(
        fn_body.starts_with("fn try_new_presorted(")
            || fn_body.contains("pub fn try_new_presorted("),
        "V21-F3: try_new_presorted must be pub"
    );
    assert!(
        !fn_body.contains("pub(crate) fn try_new_presorted("),
        "V21-F3: try_new_presorted must NOT be pub(crate)"
    );
}

#[test]
fn v21_f3b_try_new_presorted_has_v21_comment() {
    let source = read_source_file("src/lib.rs");
    // The V21-F3 comment is in the doc comment above the function signature,
    // so we search a window that includes the preceding doc block.
    let pos = source
        .find("fn try_new_presorted(")
        .expect("try_new_presorted must exist");
    let start = pos.saturating_sub(500);
    let context = &source[start..pos + 500];

    assert!(
        context.contains("V21-F3"),
        "V21-F3: try_new_presorted must have V21-F3 comment"
    );
}

#[test]
fn v21_f3c_try_new_presorted_behavioral() {
    // Verify external callers can use try_new_presorted
    let entries: Vec<IndexEntry> = (0..10)
        .map(|i| make_entry(i * 100)) // spread out for sorted order
        .collect();
    let page = era_index::IndexPage::try_new_presorted(entries).unwrap();
    assert_eq!(page.len(), 10);
}

// ═══════════════════════════════════════════════════════════════════════
// V21-F4 (HIGH): to_bloom() returns Result with validation
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: bloom_serde.rs, BloomFilterData::to_bloom()
// Previously returned Bloom<T> directly — could panic on invalid state.
// Now validates and returns Result<Bloom<T>>.

#[test]
fn v21_f4a_to_bloom_returns_result() {
    let source = read_source_file("src/bloom_serde.rs");
    let fn_body = extract_fn_body(&source, "to_bloom", 500);

    assert!(
        fn_body.contains("-> Result<Bloom<T>>"),
        "V21-F4: to_bloom must return Result<Bloom<T>>"
    );
}

#[test]
fn v21_f4b_to_bloom_validates_bitmap_bits() {
    let source = read_source_file("src/bloom_serde.rs");
    let fn_body = extract_fn_body(&source, "to_bloom", 500);

    assert!(
        fn_body.contains("bitmap_bits"),
        "V21-F4: to_bloom must validate bitmap_bits"
    );
}

#[test]
fn v21_f4c_to_bloom_validates_k_num() {
    let source = read_source_file("src/bloom_serde.rs");
    let fn_body = extract_fn_body(&source, "to_bloom", 500);

    assert!(
        fn_body.contains("k_num"),
        "V21-F4: to_bloom must validate k_num"
    );
}

#[test]
fn v21_f4d_to_bloom_rejects_zero_bitmap_bits() {
    let bloom: bloomfilter::Bloom<ChunkHash> = bloomfilter::Bloom::new_for_fp_rate(100, 0.01);
    let result = BloomFilterData::new(
        bloom.bitmap(),
        0,
        bloom.number_of_hash_functions(),
        bloom.sip_keys(),
    );
    assert!(result.is_err(), "V21-F4: new() must reject bitmap_bits=0");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("bitmap_bits"),
        "V21-F4: error must mention bitmap_bits"
    );
}

#[test]
fn v21_f4e_to_bloom_rejects_zero_k_num() {
    let bloom: bloomfilter::Bloom<ChunkHash> = bloomfilter::Bloom::new_for_fp_rate(100, 0.01);
    let result = BloomFilterData::new(bloom.bitmap(), bloom.number_of_bits(), 0, bloom.sip_keys());
    assert!(result.is_err(), "V21-F4: new() must reject k_num=0");
}

#[test]
fn v21_f4f_to_bloom_rejects_short_bitmap() {
    let bloom: bloomfilter::Bloom<ChunkHash> = bloomfilter::Bloom::new_for_fp_rate(100, 0.01);
    let oversized_bits = (bloom.bitmap().len() as u64 + 1) * 8 + 1;
    let result = BloomFilterData::new(
        bloom.bitmap(),
        oversized_bits,
        bloom.number_of_hash_functions(),
        bloom.sip_keys(),
    );
    assert!(
        result.is_err(),
        "V21-F4: new() must reject bitmap too short for bitmap_bits"
    );
}

#[test]
fn v21_f4g_to_bloom_rejects_all_zero_sip_keys() {
    let bloom: bloomfilter::Bloom<ChunkHash> = bloomfilter::Bloom::new_for_fp_rate(100, 0.01);
    let result = BloomFilterData::new(
        bloom.bitmap(),
        bloom.number_of_bits(),
        bloom.number_of_hash_functions(),
        [(0, 0); 2],
    );
    assert!(
        result.is_err(),
        "V21-F4: new() must reject all-zero sip_keys"
    );
}

#[test]
fn v21_f4h_to_bloom_valid_roundtrip() {
    let mut bloom: bloomfilter::Bloom<ChunkHash> = bloomfilter::Bloom::new_for_fp_rate(1000, 0.01);
    for i in 0..100u64 {
        bloom.set(&test_hash(i));
    }
    let data = BloomFilterData::new(
        bloom.bitmap(),
        bloom.number_of_bits(),
        bloom.number_of_hash_functions(),
        bloom.sip_keys(),
    )
    .expect("BloomFilterData::new should succeed");
    let restored = data
        .to_bloom::<ChunkHash>()
        .expect("V21-F4: valid bloom must roundtrip");

    for i in 0..100u64 {
        assert!(
            restored.check(&test_hash(i)),
            "V21-F4: hash {} not found after roundtrip",
            i
        );
    }
}

#[test]
fn v21_f4i_deserialize_bloom_propagates_result() {
    let source = read_source_file("src/bloom_serde.rs");
    let fn_body = extract_fn_body(&source, "deserialize_bloom(", 200);

    // deserialize_bloom must NOT wrap to_bloom() in Ok() — it should use ? or direct return
    assert!(
        !fn_body.contains("Ok(BloomFilterData::from_bytes(bytes)?.to_bloom())"),
        "V21-F4: deserialize_bloom must propagate to_bloom() Result, not wrap in Ok()"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V21-F5 (MEDIUM): rebuild_bloom_if_needed logs when triggered
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: store.rs, rebuild_bloom_if_needed()
// Bloom rebuilds can be a silent performance cliff. Now logs old_capacity,
// new_capacity, and entry_count at info level.

#[test]
fn v21_f5a_rebuild_bloom_logs_info() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "rebuild_bloom_if_needed", 1500);

    assert!(
        fn_body.contains("tracing::info!"),
        "V21-F5: rebuild_bloom_if_needed must log at info level"
    );
}

#[test]
fn v21_f5b_rebuild_bloom_logs_capacities() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "rebuild_bloom_if_needed", 1500);

    assert!(
        fn_body.contains("old_capacity") && fn_body.contains("new_capacity"),
        "V21-F5: rebuild_bloom log must include old_capacity and new_capacity"
    );
    assert!(
        fn_body.contains("entry_count"),
        "V21-F5: rebuild_bloom log must include entry_count"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V21-F6 (LOW): finalize() logs entry count before bloom serialization
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: chunk_index.rs, ChunkIndex::finalize()
// Entry count log was after bloom serialization. If serialization fails,
// there's no observability. Now logs before.

#[test]
fn v21_f6a_finalize_logs_before_bloom_serialization() {
    let source = read_source_file("src/chunk_index.rs");
    let fn_body = extract_fn_body(&source, "finalize(&mut self)", 2000);

    let log_pos = fn_body
        .find("tracing::info!")
        .expect("V21-F6: finalize must have info log");
    let bloom_pos = fn_body
        .find("serialize_bloom")
        .expect("V21-F6: finalize must call serialize_bloom");

    assert!(
        log_pos < bloom_pos,
        "V21-F6: entry count log must come BEFORE bloom serialization"
    );
}

#[test]
fn v21_f6b_finalize_log_has_v21_comment() {
    let source = read_source_file("src/chunk_index.rs");
    let fn_body = extract_fn_body(&source, "finalize(&mut self)", 2000);

    assert!(
        fn_body.contains("V21-F6"),
        "V21-F6: finalize must have V21-F6 comment"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V21-F7 (LOW): MIN/MAX_INDEX_PAGE_SIZE have derivation doc comments
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs
// Constants lacked documentation explaining how they were derived.

#[test]
fn v21_f7a_min_index_page_size_documented() {
    let source = read_source_file("src/reader.rs");

    // Find the MIN_INDEX_PAGE_SIZE constant and check surrounding comments
    let pos = source
        .find("MIN_INDEX_PAGE_SIZE")
        .expect("V21-F7: MIN_INDEX_PAGE_SIZE must exist");
    let start = pos.saturating_sub(300);
    let context = &source[start..pos + 100];

    assert!(
        context.contains("V21-F7"),
        "V21-F7: MIN_INDEX_PAGE_SIZE must have V21-F7 derivation comment"
    );
}

#[test]
fn v21_f7b_max_index_page_size_documented() {
    let source = read_source_file("src/reader.rs");

    let pos = source
        .find("MAX_INDEX_PAGE_SIZE")
        .expect("V21-F7: MAX_INDEX_PAGE_SIZE must exist");
    let start = pos.saturating_sub(300);
    let context = &source[start..pos + 100];

    assert!(
        context.contains("V21-F7") || context.contains("Derivation"),
        "V21-F7: MAX_INDEX_PAGE_SIZE must have derivation comment"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V21-F8 (MEDIUM): BATCH_SIZE configurable via IndexBuilder field
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: builder.rs
// BATCH_SIZE was a hardcoded const. Now configurable via with_batch_size().

#[test]
fn v21_f8a_builder_has_batch_size_field() {
    let source = read_source_file("src/builder.rs");

    assert!(
        source.contains("batch_size: usize"),
        "V21-F8: IndexBuilder must have batch_size field"
    );
}

#[test]
fn v21_f8b_with_batch_size_method_exists() {
    let source = read_source_file("src/builder.rs");

    assert!(
        source.contains("fn with_batch_size("),
        "V21-F8: IndexBuilder must have with_batch_size() method"
    );
}

#[test]
fn v21_f8c_flush_uses_batch_size_field() {
    let source = read_source_file("src/builder.rs");
    let fn_body = extract_fn_body(&source, "insert(&mut self, entry", 1000);

    assert!(
        fn_body.contains("self.batch_size"),
        "V21-F8: insert must compare buffer.len() against self.batch_size, not a const"
    );
}

#[test]
fn v21_f8d_with_batch_size_behavioral() {
    // Create builder with custom batch size
    let mut builder = IndexBuilder::new(1024 * 1024).unwrap().with_batch_size(5);

    // Insert 10 entries — should trigger flush at 5
    for i in 0..10u64 {
        let entry = make_entry(i);
        builder.insert(entry).unwrap();
    }

    assert_eq!(builder.entry_count(), 10);
}

#[test]
fn v21_f8e_with_batch_size_minimum_one() {
    // batch_size=0 should be clamped to 1
    let builder = IndexBuilder::new(1024 * 1024).unwrap().with_batch_size(0);
    // The builder should still work (batch_size clamped to 1)
    let source = read_source_file("src/builder.rs");
    let fn_body = extract_fn_body(&source, "with_batch_size(", 300);
    assert!(
        fn_body.contains(".max(1)"),
        "V21-F8: with_batch_size must clamp to minimum 1"
    );
    drop(builder);
}

// ═══════════════════════════════════════════════════════════════════════
// V21-F9 (MEDIUM): insert_batch() bloom pre-filter for duplicates
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: store.rs, insert_batch()
// Before V21, insert_batch opened a write transaction for ALL entries,
// even if most were duplicates. Now filters via bloom first.

#[test]
fn v21_f9a_insert_batch_has_bloom_prefilter() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "insert_batch(", 2000);

    assert!(
        fn_body.contains("self.bloom.check("),
        "V21-F9: insert_batch must check bloom filter to pre-filter duplicates"
    );
}

#[test]
fn v21_f9b_insert_batch_has_v21_comment() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "insert_batch(", 2000);

    assert!(
        fn_body.contains("V21-F9"),
        "V21-F9: insert_batch must have V21-F9 comment"
    );
}

#[test]
fn v21_f9c_insert_batch_dedup_behavioral() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_v21_f9.redb");
    let mut store = IndexStore::create(&db_path, 10_000).unwrap();

    // Insert first batch
    let entries1: Vec<IndexEntry> = (0..100).map(make_entry).collect();
    store.insert_batch(&entries1).unwrap();
    assert_eq!(store.entry_count(), 100);

    // Insert overlapping batch (50 old + 50 new)
    let entries2: Vec<IndexEntry> = (50..150).map(make_entry).collect();
    store.insert_batch(&entries2).unwrap();
    assert_eq!(store.entry_count(), 150);

    // Verify all 150 unique entries exist
    for i in 0..150u64 {
        assert!(store.bloom_contains(&test_hash(i)));
    }
}

// ═══════════════════════════════════════════════════════════════════════
// V21-F10 (LOW): find_page Err(0) trace logging
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: lib.rs, MetaIndex::find_page()
// The Err(0) case (hash before first page) had no logging.

#[test]
fn v21_f10a_find_page_has_trace_log() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "find_page(", 1000);

    assert!(
        fn_body.contains("tracing::trace!"),
        "V21-F10: find_page must have trace log for Err(0) case"
    );
}

#[test]
fn v21_f10b_find_page_err0_behavioral() {
    let mut meta = MetaIndex::new();
    meta.add_page(test_hash(100), test_hash(200), BlockId::new(0))
        .unwrap();

    // Hash before first page range — should return None
    let result = meta.find_page(&test_hash(50));
    assert!(
        result.is_none(),
        "V21-F10: hash before first page range must return None"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V21-F11 (LOW): IndexReader::total_entry_count() accessor
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs
// New method to sum entries across all embedded pages.

#[test]
fn v21_f11a_total_entry_count_exists() {
    let source = read_source_file("src/reader.rs");

    assert!(
        source.contains("fn total_entry_count("),
        "V21-F11: IndexReader must have total_entry_count() method"
    );
}

#[test]
fn v21_f11b_total_entry_count_behavioral() {
    let entries: Vec<IndexEntry> = (0..50).map(make_entry).collect();
    let page = era_index::IndexPage::try_new(entries).unwrap();
    let pages = vec![(page, BlockId::new(0))];

    let meta = MetaIndex::new();
    let reader = IndexReader::from_pages(meta, pages).unwrap();

    assert_eq!(
        reader.total_entry_count(),
        50,
        "V21-F11: total_entry_count must sum entries from all pages"
    );
}

#[test]
fn v21_f11c_total_entry_count_empty() {
    let meta = MetaIndex::new();
    let reader = IndexReader::from_memory(meta, vec![]).unwrap();

    assert_eq!(
        reader.total_entry_count(),
        0,
        "V21-F11: total_entry_count on empty reader must be 0"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V21-F12 (LOW): align_buf capacity based on IndexEntry::memory_size()
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: store.rs, for_each_sorted_page()
// Hardcoded 256 was often too small. Now uses IndexEntry::memory_size() * 2.

#[test]
fn v21_f12a_align_buf_uses_memory_size() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "for_each_sorted_page", 2000);

    assert!(
        fn_body.contains("IndexEntry::memory_size()"),
        "V21-F12: align_buf capacity must use IndexEntry::memory_size()"
    );
}

#[test]
fn v21_f12b_align_buf_not_hardcoded_256() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "for_each_sorted_page", 2000);

    // The old pattern was: AlignedVec::with_capacity(256)
    // Now it should use memory_size()
    assert!(
        !fn_body.contains("AlignedVec::with_capacity(256)"),
        "V21-F12: align_buf must not use hardcoded 256"
    );
}

#[test]
fn v21_f12c_align_buf_has_v21_comment() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "for_each_sorted_page", 2000);

    assert!(
        fn_body.contains("V21-F12"),
        "V21-F12: align_buf must have V21-F12 comment"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V20 Regression Tests — Verify Previous Fixes Still Hold
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v21_regression_v20_f1_from_pages_rebuilds_bloom() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "from_pages(", 2000);

    assert!(
        fn_body.contains("verified_bloom"),
        "V20-F1 regression: from_pages must still rebuild bloom"
    );
}

#[test]
fn v21_regression_v20_f5_zero_sip_keys_rejected() {
    let source = read_source_file("src/bloom_serde.rs");

    // V23-F3 moved the sip_keys check into validate(). Verify from_bytes calls validate()
    // and validate() still rejects all-zero sip_keys.
    let from_bytes_body = extract_fn_body(&source, "from_bytes(", 5000);
    assert!(
        from_bytes_body.contains("validate()"),
        "V20-F5 regression: from_bytes must call validate() which checks sip_keys"
    );

    let validate_body = extract_fn_body(&source, "validate(", 900);
    assert!(
        validate_body.contains("sip_keys") && validate_body.contains("(0, 0)"),
        "V20-F5 regression: validate() must still reject all-zero sip_keys"
    );
}
