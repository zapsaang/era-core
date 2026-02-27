//! # Adversarial Audit V19 — Comprehensive Test Suite
//!
//! **Audit Date:** 2026-02-27
//! **Target:** `era-index` crate — V19 adversarial audit
//! **Scope:** V19-F1 through V19-F12
//! **Methodology:** Source-level static analysis + behavioral verification
//!
//! ## V18 Regression Status (All FIXED)
//!
//! | ID | Finding | Status |
//! |----|---------|--------|
//! | V18-F1 | O(M×N) → O(M) recovery via HashMap index | FIXED |
//! | V18-F2 | validate_meta_index() after deserialization | FIXED |
//! | V18-F3 | Manifest fallback iteration (reverse, prefer last valid) | FIXED |
//! | V18-F4 | Pre-decrypt size check on encrypted blocks | FIXED |
//! | V18-F5 | Stable sort for deterministic dedup | FIXED |
//! | V18-F6 | BloomFilterData bitmap_bits/k_num/bitmap validation | FIXED |
//! | V18-F7 | finalize() blocks async (documented limitation) | DOCUMENTED |
//! | V18-F8 | open_readonly caps bloom at 10M entries | FIXED |
//! | V18-F9 | add_page rejects inverted hash ranges | FIXED |
//! | V18-F10 | ChunkIndex::finalize materializes all pages (documented) | DOCUMENTED |
//! | V18-F11 | try_new_presorted runtime sorted check | FIXED |
//! | V18-F12 | Recovery error includes missing block_ids | FIXED |
//!
//! ## V19 Findings
//!
//! | ID | Severity | Title |
//! |----|----------|-------|
//! | V19-F1 | HIGH | IndexReader::open() missing validate_meta_index call |
//! | V19-F2 | HIGH | MetaIndex::add_page duplicate block_id was debug_assert only |
//! | V19-F3 | HIGH | IndexEntry::new() accepted length=0 and offset+length overflow |
//! | V19-F4 | MEDIUM | BloomFilterData missing max bitmap size limit |
//! | V19-F5 | MEDIUM | from_memory() trusts caller-provided bloom (false negative risk) |
//! | V19-F6 | MEDIUM | ChunkIndex::finalize doesn't drop builder after finalization |
//! | V19-F7 | MEDIUM | finalize() CPU-heavy work without spawn_blocking (documented) |
//! | V19-F8 | MEDIUM | rebuild_bloom_if_needed has no upper capacity bound |
//! | V19-F9 | LOW | try_new/try_new_presorted missing post-dedup sorted assertion |
//! | V19-F10 | MEDIUM | MetaIndex::add_page has no MAX_META_PAGES cap |
//! | V19-F11 | LOW | bloom_set naming hides unchecked nature |
//! | V19-F12 | MEDIUM | No post-decrypt timeout check in recovery slow path |

#[allow(unused_imports)]
use era_common::{BlockId, ChunkHash, VolumeId};
#[allow(unused_imports)]
use era_index::{BloomFilterData, ChunkIndexConfig, IndexEntry, IndexLocation, ENTRIES_PER_PAGE};

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
// V19-F1 (HIGH): IndexReader::open() must call validate_meta_index
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs, IndexReader::open()
// The open() path was the only entry point that skipped structural
// validation of the MetaIndex. A caller with a corrupt MetaIndex
// could create an IndexReader with inverted ranges or overlapping pages.

#[test]
fn v19_f1a_open_calls_validate_meta_index() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "open(meta", 1000);

    assert!(
        fn_body.contains("validate_meta_index"),
        "V19-F1: IndexReader::open() must call validate_meta_index"
    );
}

#[test]
fn v19_f1b_validate_before_bloom_deserialize() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "open(meta", 1000);

    let validate_pos = fn_body
        .find("validate_meta_index")
        .expect("validate_meta_index must exist in open()");
    let bloom_pos = fn_body
        .find("deserialize_bloom")
        .expect("deserialize_bloom must exist in open()");

    assert!(
        validate_pos < bloom_pos,
        "V19-F1: validate_meta_index (at {}) must come BEFORE deserialize_bloom (at {})",
        validate_pos,
        bloom_pos
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V19-F2 (HIGH): MetaIndex::add_page runtime duplicate block_id check
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: lib.rs, MetaIndex::add_page()
// Previously only had debug_assert for unique block_ids. In release builds,
// duplicate block_ids silently entered the structure causing ambiguous lookups.

#[test]
fn v19_f2a_runtime_dup_check_in_source() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "add_page", 2000);

    assert!(
        fn_body.contains("duplicate block_id"),
        "V19-F2: add_page must check for duplicate block_ids at runtime"
    );
}

#[test]
fn v19_f2b_duplicate_block_id_returns_error() {
    let mut meta = era_index::MetaIndex::new();
    // First add succeeds
    meta.add_page(test_hash(0), test_hash(100), BlockId::new(0))
        .expect("first add should succeed");
    // Second add with same block_id should fail
    let result = meta.add_page(test_hash(200), test_hash(300), BlockId::new(0));
    assert!(
        result.is_err(),
        "V19-F2: duplicate block_id must be rejected"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("duplicate block_id"),
        "V19-F2: error must mention 'duplicate block_id', got: {}",
        err_msg
    );
}

#[test]
fn v19_f2c_unique_block_ids_accepted() {
    let mut meta = era_index::MetaIndex::new();
    meta.add_page(test_hash(0), test_hash(100), BlockId::new(0))
        .unwrap();
    meta.add_page(test_hash(200), test_hash(300), BlockId::new(1))
        .unwrap();
    meta.add_page(test_hash(400), test_hash(500), BlockId::new(2))
        .unwrap();
    assert_eq!(meta.pages().len(), 3);
}

// ═══════════════════════════════════════════════════════════════════════
// V19-F3 (HIGH): IndexEntry::new() validates length and offset+length
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: lib.rs, IndexEntry::new()
// Previously returned Self directly, accepting length=0 and
// offset+length overflow silently.

#[test]
fn v19_f3a_new_returns_result() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "new(\n", 2000);

    assert!(
        fn_body.contains("Result<Self>") || fn_body.contains("era_common::Result<Self>"),
        "V19-F3: IndexEntry::new() must return Result<Self>"
    );
}

#[test]
fn v19_f3b_zero_length_rejected() {
    let result = IndexEntry::new(test_hash(1), VolumeId::new(), BlockId::new(0), 0, 0);
    assert!(result.is_err(), "V19-F3: length=0 must be rejected");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("length"),
        "V19-F3: error must mention 'length', got: {}",
        err_msg
    );
}

#[test]
fn v19_f3c_offset_length_overflow_rejected() {
    let result = IndexEntry::new(test_hash(1), VolumeId::new(), BlockId::new(0), u32::MAX, 1);
    assert!(
        result.is_err(),
        "V19-F3: offset+length overflow must be rejected"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("overflow"),
        "V19-F3: error must mention 'overflow', got: {}",
        err_msg
    );
}

#[test]
fn v19_f3d_valid_entry_accepted() {
    let result = IndexEntry::new(test_hash(1), VolumeId::new(), BlockId::new(0), 100, 1024);
    assert!(result.is_ok(), "V19-F3: valid entry must be accepted");
    let entry = result.unwrap();
    assert_eq!(entry.offset(), 100);
    assert_eq!(entry.length(), 1024);
}

// ═══════════════════════════════════════════════════════════════════════
// V19-F4 (MEDIUM): BloomFilterData max bitmap size limit
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: bloom_serde.rs, BloomFilterData::from_bytes()
// Without a max bitmap size, a crafted bloom filter with a huge bitmap
// could exhaust memory during deserialization.

#[test]
fn v19_f4a_max_bloom_bitmap_size_exists() {
    let source = read_source_file("src/bloom_serde.rs");
    let fn_body = extract_fn_body(&source, "from_bytes", 2000);

    assert!(
        fn_body.contains("MAX_BLOOM_BITMAP_SIZE"),
        "V19-F4: from_bytes must check MAX_BLOOM_BITMAP_SIZE"
    );
}

#[test]
fn v19_f4b_max_bitmap_size_is_128mib() {
    let source = read_source_file("src/bloom_serde.rs");

    assert!(
        source.contains("128 * 1024 * 1024"),
        "V19-F4: MAX_BLOOM_BITMAP_SIZE must be 128 MiB (128 * 1024 * 1024)"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V19-F5 (MEDIUM): from_memory() rebuilds bloom from entries
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs, IndexReader::from_memory()
// Previously trusted the caller-provided bloom filter. A malicious or
// buggy caller could pass a bloom that omits entries (false negatives).

#[test]
fn v19_f5a_from_memory_rebuilds_bloom() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "from_memory", 2000);

    assert!(
        fn_body.contains("verified_bloom"),
        "V19-F5: from_memory must rebuild bloom as 'verified_bloom'"
    );
}

#[test]
fn v19_f5b_caller_bloom_param_removed() {
    let source = read_source_file("src/reader.rs");
    let fn_sig = extract_fn_body(&source, "from_memory", 100);

    // The caller bloom parameter should be removed (no longer in the signature)
    assert!(
        !fn_sig.contains("_caller_bloom") && !fn_sig.contains("Bloom<"),
        "V19-F5: from_memory should no longer have a bloom parameter"
    );
}

#[test]
fn v19_f5c_from_memory_behavioral_bloom_consistency() {
    // Create an IndexReader from memory and verify the bloom contains all entries
    let meta = era_index::MetaIndex::new();
    // Don't add any entries to the caller bloom — from_memory should rebuild

    let entries: Vec<IndexEntry> = (0..50).map(make_entry).collect();
    let reader =
        era_index::IndexReader::from_memory(meta, entries).expect("from_memory should succeed");

    // Even though the caller bloom was empty, rebuilt bloom must contain entries
    for i in 0..50u64 {
        assert!(
            reader.bloom_contains(&test_hash(i)),
            "V19-F5: rebuilt bloom must contain entry {}",
            i
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// V19-F6 (MEDIUM): ChunkIndex::finalize drops builder
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: chunk_index.rs, ChunkIndex::finalize()
// Previously kept the builder alive after finalization, wasting the
// Redb file descriptor and mmap resources.

#[test]
fn v19_f6a_finalize_drops_builder() {
    let source = read_source_file("src/chunk_index.rs");
    let fn_body = extract_fn_body(&source, "finalize", 3000);

    assert!(
        fn_body.contains("self.builder.take()"),
        "V19-F6: finalize must call self.builder.take() to drop the builder"
    );
}

#[test]
fn v19_f6b_builder_is_option() {
    let source = read_source_file("src/chunk_index.rs");

    assert!(
        source.contains("builder: Option<IndexBuilder>"),
        "V19-F6: builder field must be Option<IndexBuilder> to support take()"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V19-F7 (MEDIUM): finalize() spawn_blocking documented
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: builder.rs, finalize()
// The CPU-heavy work (rkyv + AEAD) runs synchronously. Documented as
// deferred due to Redb ReadTransaction being !Send.

#[test]
fn v19_f7_spawn_blocking_documented() {
    let source = read_source_file("src/builder.rs");
    let fn_body = extract_fn_body(&source, "finalize", 3000);

    assert!(
        fn_body.contains("spawn_blocking") || fn_body.contains("V19-F7"),
        "V19-F7: finalize must document the spawn_blocking limitation"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V19-F8 (MEDIUM): rebuild_bloom_if_needed caps capacity
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: store.rs, rebuild_bloom_if_needed()
// Without a cap, a store with many entries would allocate an unbounded
// bloom filter during rebuild.

#[test]
fn v19_f8a_rebuild_bloom_has_cap() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "rebuild_bloom_if_needed", 2000);

    assert!(
        fn_body.contains("MAX_BLOOM_ITEMS"),
        "V19-F8: rebuild_bloom_if_needed must cap capacity at MAX_BLOOM_ITEMS"
    );
}

#[test]
fn v19_f8b_max_bloom_items_value() {
    let source = read_source_file("src/lib.rs");

    assert!(
        source.contains("MAX_BLOOM_ITEMS: usize = 100_000_000"),
        "V25-F3: MAX_BLOOM_ITEMS must be 100_000_000 and defined in lib.rs"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V19-F9 (LOW): Post-dedup sorted assertion in try_new/try_new_presorted
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: lib.rs, IndexPage::try_new() and try_new_presorted()
// After dedup, entries should be strictly sorted (no duplicates remain).
// A debug_assert catches subtle bugs in dedup logic.

#[test]
fn v19_f9a_try_new_has_post_dedup_assert() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "try_new(", 2000);

    assert!(
        fn_body.contains("post-dedup entries must be strictly sorted"),
        "V19-F9: try_new must have post-dedup sorted assertion"
    );
}

#[test]
fn v19_f9b_try_new_presorted_has_post_dedup_assert() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "try_new_presorted", 2000);

    assert!(
        fn_body.contains("post-dedup entries must be strictly sorted"),
        "V19-F9: try_new_presorted must have post-dedup sorted assertion"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V19-F10 (MEDIUM): MetaIndex::add_page MAX_META_PAGES cap
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: lib.rs, MetaIndex::add_page()
// Without a cap, an attacker could add millions of pages causing OOM.

#[test]
fn v19_f10a_add_page_has_max_meta_pages() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "add_page", 2000);

    assert!(
        fn_body.contains("MAX_META_PAGES"),
        "V19-F10: add_page must enforce MAX_META_PAGES"
    );
}

#[test]
fn v19_f10b_max_meta_pages_is_10000() {
    let source = read_source_file("src/lib.rs");
    // V24-F7: MAX_META_PAGES is now defined at module level, not inside add_page()
    assert!(
        source.contains("pub(crate) const MAX_META_PAGES: usize = 10_000;"),
        "V24-F7: MAX_META_PAGES must be 10_000 and defined at module level"
    );
}

#[test]
fn v19_f10c_exceeding_max_meta_pages_returns_error() {
    // We can't easily add 10,001 pages without generating unique non-overlapping
    // ranges, so we check the source logic instead. The behavioral test would
    // require generating 10,001 unique hash ranges.
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "add_page", 2000);

    // Must check pages.len() >= MAX_META_PAGES and return Err
    assert!(
        fn_body.contains("self.pages.len() >= MAX_META_PAGES"),
        "V19-F10: add_page must check pages.len() >= MAX_META_PAGES"
    );
    let check_pos = fn_body
        .find("self.pages.len() >= MAX_META_PAGES")
        .expect("MAX_META_PAGES check must exist");
    let region_end = (check_pos + 300).min(fn_body.len());
    let region = &fn_body[check_pos..region_end];
    assert!(
        region.contains("Err(") || region.contains("return Err"),
        "V19-F10: exceeding MAX_META_PAGES must return Err, got:\n{}",
        region
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V19-F11 (LOW): bloom_set renamed to bloom_set_unchecked
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: store.rs
// The old `bloom_set` name hid the fact that it sets the bloom filter
// without verifying the entry has been committed to the store.

#[test]
fn v19_f11a_bloom_set_unchecked_exists() {
    let source = read_source_file("src/store.rs");

    assert!(
        source.contains("bloom_set_unchecked"),
        "V19-F11: store.rs must contain bloom_set_unchecked"
    );
}

#[test]
fn v19_f11b_builder_uses_bloom_set_unchecked() {
    let source = read_source_file("src/builder.rs");

    assert!(
        source.contains("bloom_set_unchecked"),
        "V19-F11: builder.rs must call bloom_set_unchecked"
    );
}

#[test]
fn v19_f11c_no_bare_bloom_set() {
    let source = read_source_file("src/store.rs");

    // The old `fn bloom_set(` should not exist (it was renamed)
    assert!(
        !source.contains("fn bloom_set("),
        "V19-F11: the old 'fn bloom_set(' must not exist (renamed to bloom_set_unchecked)"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V19-F12 (MEDIUM): Post-decrypt timeout check in recovery
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs, recover_from_volume() slow path
// Without a timeout check after decrypt, a crafted volume could stall
// recovery indefinitely with many decryptable-but-invalid blocks.

#[test]
fn v19_f12a_post_decrypt_timeout_check() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 25000);

    assert!(
        fn_body.contains("timed out after successful decrypt"),
        "V19-F12: recovery must check timeout after successful decrypt"
    );
}

#[test]
fn v19_f12b_timeout_before_rkyv_deserialization() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 25000);

    // The slow-path timeout check must appear between decrypt_with_context
    // and check_archived_root for the MetaIndex candidate loop
    let decrypt_pos = fn_body
        .find("decrypt_with_context")
        .expect("decrypt_with_context must exist");
    let timeout_msg = "timed out after successful decrypt";
    let timeout_pos = fn_body
        .find(timeout_msg)
        .expect("post-decrypt timeout message must exist");

    assert!(
        timeout_pos > decrypt_pos,
        "V19-F12: post-decrypt timeout (at {}) must come AFTER decrypt (at {})",
        timeout_pos,
        decrypt_pos
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Regression Tests — V18 Findings Still Fixed
// ═══════════════════════════════════════════════════════════════════════

/// V18-F1 regression: HashMap index in recovery
#[test]
fn v19_regression_v18f1_hashmap_index() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 25000);

    assert!(
        fn_body.contains("block_id_to_page_idx"),
        "V18-F1 regression: recovery must use block_id_to_page_idx HashMap"
    );
}

/// V18-F2 regression: validate_meta_index exists
#[test]
fn v19_regression_v18f2_validate_meta_index() {
    let source = read_source_file("src/reader.rs");
    assert!(
        source.contains("fn validate_meta_index"),
        "V18-F2 regression: validate_meta_index function must exist"
    );
}

/// V18-F5 regression: stable sort in try_new
#[test]
fn v19_regression_v18f5_stable_sort() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "try_new(", 2000);

    assert!(
        fn_body.contains("sort_by_key"),
        "V18-F5 regression: try_new must use stable sort_by_key"
    );
    assert!(
        !fn_body.contains("sort_unstable_by_key"),
        "V18-F5 regression: try_new must NOT use sort_unstable_by_key"
    );
}

/// V18-F6 regression: BloomFilterData validation (now delegated to validate() method)
#[test]
fn v19_regression_v18f6_bloom_validation() {
    let source = read_source_file("src/bloom_serde.rs");

    // Check that from_bytes calls validate() which performs all checks
    let from_bytes_body = extract_fn_body(&source, "from_bytes", 2000);
    assert!(
        from_bytes_body.contains("validate()"),
        "V18-F6 regression: from_bytes must call validate()"
    );

    // Check that validate() method contains the checks
    let validate_body = extract_fn_body(&source, "validate", 500);
    assert!(
        validate_body.contains("bitmap_bits == 0"),
        "V18-F6 regression: validate() must check bitmap_bits == 0"
    );
    assert!(
        validate_body.contains("k_num == 0"),
        "V18-F6 regression: validate() must check k_num == 0"
    );
}

/// V18-F9 regression: inverted hash range rejection
#[test]
fn v19_regression_v18f9_inverted_range() {
    let mut meta = era_index::MetaIndex::new();
    let result = meta.add_page(test_hash(200), test_hash(100), BlockId::new(0));
    assert!(
        result.is_err(),
        "V18-F9 regression: inverted hash range must be rejected"
    );
}

/// V18-F11 regression: runtime sorted check in try_new_presorted
#[test]
fn v19_regression_v18f11_runtime_sorted_check() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "try_new_presorted", 2000);

    assert!(
        fn_body.contains("windows(2)"),
        "V18-F11 regression: try_new_presorted must use windows(2) for sorted check"
    );
}

/// V17-F1 regression: collision check BEFORE insert in recovery
#[test]
fn v19_regression_v17f1_contains_key_before_insert() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 25000);

    let contains_key_pos = fn_body
        .find("embedded_pages.contains_key")
        .expect("embedded_pages.contains_key must exist");
    let insert_pos = fn_body
        .find("embedded_pages.insert")
        .expect("embedded_pages.insert must exist");

    assert!(
        contains_key_pos < insert_pos,
        "V17-F1 regression: contains_key must come BEFORE insert"
    );
}

/// V14-F1 regression: 4-byte domain tag
#[test]
fn v19_regression_v14f1_domain_tag() {
    let builder_source = read_source_file("src/builder.rs");
    let reader_source = read_source_file("src/reader.rs");

    assert!(
        builder_source.contains(r#"b"IDX\x01""#),
        "V14-F1 regression: builder.rs must contain domain tag"
    );
    assert!(
        reader_source.contains(r#"b"IDX\x01""#),
        "V14-F1 regression: reader.rs must contain domain tag"
    );
}
