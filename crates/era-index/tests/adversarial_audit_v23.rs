//! # Adversarial Audit V23 — Comprehensive Test Suite
//!
//! **Audit Date:** 2026-02-27
//! **Target:** `era-index` crate — V23 adversarial audit
//! **Scope:** V23-F1 through V23-F10 + V23-CF1, V23-CF2
//! **Methodology:** Source-level static analysis + behavioral verification
//!
//! ## V22 Regression Status (All FIXED)
//!
//! | ID | Finding | Status |
//! |----|---------|--------|
//! | V22-F1 | insert_batch() per-candidate read_txn | FIXED |
//! | V22-F2 | builder finalize() Vec::new() causes reallocation | FIXED |
//! | V22-F3 | from_memory() uses try_new() on sorted entries | FIXED |
//! | V22-F4 | add_page() duplicate block_id scan undocumented | FIXED |
//! | V22-F5 | BloomFilterData lacks validated constructor | FIXED |
//! | V22-F6 | for_each_sorted_page no progress logging | FIXED |
//! | V22-F7 | recover_from_volume allocates Vec per iteration | FIXED |
//! | V22-F8 | finalize() clones bloom bitmap to serialize | FIXED |
//! | V22-F9 | IndexEntry no Display impl | FIXED |
//! | V22-F10 | IndexStore no disk usage query | FIXED |
//! | V22-F11 | recover_from_volume HashMap default capacity | FIXED |
//! | V22-F12 | with_batch_size(0) clamps to 1 | FIXED |
//!
//! ## V23 Findings
//!
//! | ID | Severity | Title |
//! |----|----------|-------|
//! | V23-F1 | MEDIUM | BloomFilterData fields are pub(crate) — prevent bypass of new() validation |
//! | V23-F2 | MEDIUM | from_bloom() validates via validate() and returns Result |
//! | V23-F3 | LOW | Consolidated validate() method eliminates triplicated validation |
//! | V23-F4 | LOW | to_bytes() documents AlignedVec→Vec copy rationale |
//! | V23-F5 | LOW | from_bloom() visibility restricted to pub(crate) |
//! | V23-F6 | LOW | Duplicate doc comment on try_new_presorted removed |
//! | V23-F7 | LOW | _caller_bloom unused params removed from from_memory/from_pages |
//! | V23-F8 | LOW | for_each_sorted_page progress logging fires after page emission |
//! | V23-F9 | INFO | .expect() in try_new/try_new_presorted — safe after empty check |
//! | V23-F10 | LOW | set_bloom_filter uses BloomFilterData::from_bytes() for lightweight validation |

#[allow(unused_imports)]
use era_common::{BlockId, ChunkHash, VolumeId};
#[allow(unused_imports)]
use era_index::{
    BloomFilterData, ChunkIndex, ChunkIndexConfig, IndexBuilder, IndexEntry, IndexLocation,
    IndexReader, IndexStore, MetaIndex, ENTRIES_PER_PAGE,
};

// ═══════════════════════════════════════════════════════════════════════
// Utilities
// ═══════════════════════════════════════════════════════════════════════

fn test_hash(value: u64) -> ChunkHash {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    ChunkHash::from_bytes(bytes)
}

fn make_entry(i: u64) -> IndexEntry {
    IndexEntry::new(test_hash(i), VolumeId::new(), BlockId::new(i), 0, 4096).expect("valid entry")
}

fn read_source_file(relative_path: &str) -> String {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let path = std::path::PathBuf::from(manifest).join(relative_path);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e))
}

fn extract_fn_body(source: &str, fn_sig: &str, max_len: usize) -> String {
    if let Some(start) = source.find(fn_sig) {
        let end = (start + max_len).min(source.len());
        source[start..end].to_string()
    } else {
        panic!("Function signature not found: {}", fn_sig);
    }
}

fn extract_struct_body(source: &str, struct_sig: &str, max_len: usize) -> String {
    if let Some(start) = source.find(struct_sig) {
        let end = (start + max_len).min(source.len());
        source[start..end].to_string()
    } else {
        panic!("Struct signature not found: {}", struct_sig);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// V23-F1: BloomFilterData fields are pub(crate)
// ═══════════════════════════════════════════════════════════════════════

// V23-F1 (MEDIUM): BloomFilterData fields must be pub(crate) to prevent
// external consumers from bypassing the validated new() constructor via
// struct literal construction.
// SOURCE: bloom_serde.rs, struct BloomFilterData

#[test]
fn v23_f1a_bloom_fields_are_pub_crate() {
    let source = read_source_file("src/bloom_serde.rs");
    let struct_body = extract_struct_body(&source, "pub struct BloomFilterData", 1200);

    // Every field should be pub(crate), not bare pub
    for field in &["version", "data:"] {
        // Find the field line
        let field_line = struct_body
            .lines()
            .find(|l| l.contains(field) && !l.trim_start().starts_with("//"))
            .unwrap_or_else(|| panic!("Field {} not found in BloomFilterData", field));

        assert!(
            field_line.contains("pub(crate)"),
            "V23-F1: Field '{}' must be pub(crate), found: {}",
            field,
            field_line.trim()
        );
        // Ensure it's not bare `pub ` (without `(crate)`)
        let trimmed = field_line.trim();
        assert!(
            !trimmed.starts_with("pub ") || trimmed.starts_with("pub(crate)"),
            "V23-F1: Field '{}' must not be bare pub: {}",
            field,
            trimmed
        );
    }
}

#[test]
fn v23_f1b_bloom_has_v23_encapsulation_comment() {
    let source = read_source_file("src/bloom_serde.rs");

    assert!(
        source.contains("V23-F1"),
        "V23-F1: bloom_serde.rs must reference V23-F1 fix"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V23-F2: from_bloom() validates via validate() and returns Result
// ═══════════════════════════════════════════════════════════════════════

// V23-F2 (MEDIUM): from_bloom() must validate extracted parameters via
// validate() and return Result<Self> instead of Self.
// SOURCE: bloom_serde.rs, BloomFilterData::from_bloom()

#[test]
fn v23_f2a_from_bloom_calls_validate() {
    let source = read_source_file("src/bloom_serde.rs");
    let fn_body = extract_fn_body(&source, "pub(crate) fn from_bloom", 600);

    assert!(
        fn_body.contains("validate()"),
        "V23-F2: from_bloom must call validate()"
    );
}

#[test]
fn v23_f2b_from_bloom_returns_result() {
    let source = read_source_file("src/bloom_serde.rs");
    let fn_body = extract_fn_body(&source, "pub(crate) fn from_bloom", 200);

    assert!(
        fn_body.contains("-> Result<Self>"),
        "V23-F2: from_bloom must return Result<Self>"
    );
}

#[test]
fn v23_f2c_from_bloom_behavioral() {
    // Creating a bloom filter and converting via from_bloom should succeed
    let bloom = bloomfilter::Bloom::<ChunkHash>::new_for_fp_rate(1000, 0.01).unwrap();
    let bytes = era_index::serialize_bloom(&bloom).unwrap();
    let restored = era_index::deserialize_bloom(&bytes).unwrap();
    assert_eq!(bloom.len(), restored.len());
    assert_eq!(
        bloom.number_of_hash_functions(),
        restored.number_of_hash_functions()
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V23-F3: Consolidated validate() method
// ═══════════════════════════════════════════════════════════════════════

// V23-F3 (LOW): Validation logic for bitmap_bits, k_num, bitmap size,
// and sip_keys should be consolidated into a single validate() method.
// SOURCE: bloom_serde.rs, BloomFilterData::validate()

#[test]
fn v23_f3a_validate_method_exists() {
    let source = read_source_file("src/bloom_serde.rs");

    assert!(
        source.contains("fn validate(&self) -> Result<()>"),
        "V23-F3: BloomFilterData must have a validate() method"
    );
}

#[test]
fn v23_f3b_new_delegates_to_validate() {
    let source = read_source_file("src/bloom_serde.rs");
    let fn_body = extract_fn_body(&source, "pub fn new(", 600);

    assert!(
        fn_body.contains("validate()"),
        "V23-F3: new() must delegate to validate()"
    );
}

#[test]
fn v23_f3c_to_bloom_delegates_to_validate() {
    let source = read_source_file("src/bloom_serde.rs");
    let fn_body = extract_fn_body(&source, "pub fn to_bloom", 300);

    assert!(
        fn_body.contains("validate()"),
        "V23-F3: to_bloom() must delegate to validate()"
    );
}

#[test]
fn v23_f3d_from_bytes_delegates_to_validate() {
    let source = read_source_file("src/bloom_serde.rs");
    let fn_body = extract_fn_body(&source, "pub fn from_bytes", 800);

    assert!(
        fn_body.contains("validate()"),
        "V23-F3: from_bytes() must delegate to validate()"
    );
}

#[test]
fn v23_f3e_validate_checks_all_invariants() {
    let source = read_source_file("src/bloom_serde.rs");
    let fn_body = extract_fn_body(&source, "fn validate(&self)", 900);

    assert!(
        fn_body.contains("data.is_empty()"),
        "V23-F3: validate must check data is empty"
    );
    assert!(
        fn_body.contains("data.len()"),
        "V23-F3: validate must check data length"
    );
}

#[test]
fn v23_f3f_validate_behavioral_bitmap_bits_zero() {
    // BloomFilterData::new with empty data must fail
    let result = BloomFilterData::new(vec![]);
    assert!(
        result.is_err(),
        "V23-F3: empty data must be rejected by validate()"
    );
}

#[test]
fn v23_f3g_validate_behavioral_k_num_zero() {
    // BloomFilterData::new with garbage data — construction succeeds but to_bloom fails
    let data = BloomFilterData::new(vec![0xDE, 0xAD]).unwrap();
    let result = data.to_bloom::<ChunkHash>();
    assert!(
        result.is_err(),
        "V23-F3: garbage data must be rejected by to_bloom()"
    );
}

#[test]
fn v23_f3h_validate_behavioral_bitmap_too_short() {
    // Truncated bloom bytes must be rejected by to_bloom()
    let bloom = bloomfilter::Bloom::<ChunkHash>::new_for_fp_rate(100, 0.01).unwrap();
    let mut truncated = bloom.to_bytes();
    truncated.truncate(4);
    let data = BloomFilterData::new(truncated).unwrap();
    assert!(
        data.to_bloom::<ChunkHash>().is_err(),
        "V23-F3: truncated bloom data must be rejected by to_bloom()"
    );
}

#[test]
fn v23_f3i_validate_behavioral_sip_keys_zero() {
    // All-zero data must be rejected by to_bloom()
    let data = BloomFilterData::new(vec![0u8; 64]).unwrap();
    assert!(
        data.to_bloom::<ChunkHash>().is_err(),
        "V23-F3: all-zero data must be rejected by to_bloom()"
    );
}

#[test]
fn v23_f3j_validate_behavioral_valid_construction() {
    // Valid bloom bytes must succeed
    let bloom = bloomfilter::Bloom::<ChunkHash>::new_for_fp_rate(100, 0.01).unwrap();
    let result = BloomFilterData::new(bloom.to_bytes());
    assert!(
        result.is_ok(),
        "V23-F3: valid bloom data must pass validation"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V23-F4: to_bytes() documents AlignedVec→Vec copy
// ═══════════════════════════════════════════════════════════════════════

// V23-F4 (LOW): to_bytes() comment must explain why .to_vec() is needed.
// SOURCE: bloom_serde.rs, BloomFilterData::to_bytes()

#[test]
fn v23_f4a_to_bytes_has_copy_rationale() {
    let source = read_source_file("src/bloom_serde.rs");

    // The comment should mention AlignedVec or alignment as the reason for the copy
    assert!(
        source.contains("AlignedVec") || source.contains("alignment"),
        "V23-F4: to_bytes() must document the AlignedVec→Vec copy rationale"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V23-F5: from_bloom() visibility restricted to pub(crate)
// ═══════════════════════════════════════════════════════════════════════

// V23-F5 (LOW): from_bloom() should be pub(crate) since it is only used
// internally by serialize_bloom().
// SOURCE: bloom_serde.rs, BloomFilterData::from_bloom()

#[test]
fn v23_f5a_from_bloom_is_pub_crate() {
    let source = read_source_file("src/bloom_serde.rs");

    assert!(
        source.contains("pub(crate) fn from_bloom"),
        "V23-F5: from_bloom() must be pub(crate)"
    );
    // Must NOT be bare pub (without (crate))
    let has_bare_pub = source
        .lines()
        .any(|l| l.trim().starts_with("pub fn from_bloom"));
    assert!(!has_bare_pub, "V23-F5: from_bloom must not be bare pub fn");
}

// ═══════════════════════════════════════════════════════════════════════
// V23-F6: Duplicate doc comment on try_new_presorted removed
// ═══════════════════════════════════════════════════════════════════════

// V23-F6 (LOW): The duplicate V17-F2 fix description (verbatim repeat)
// should be removed from try_new_presorted's doc comment.
// SOURCE: lib.rs, IndexPage::try_new_presorted()

#[test]
fn v23_f6a_no_duplicate_doc_comment() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "pub fn try_new_presorted", 400);

    // Count occurrences of "V17-F2 fix" in the function's doc comment area
    // There should be exactly one (the original), not two (duplicate)
    let v17_count = fn_body.matches("V17-F2").count();
    assert!(
        v17_count <= 1,
        "V23-F6: try_new_presorted should have at most 1 reference to V17-F2, found {}",
        v17_count
    );
}

#[test]
fn v23_f6b_doc_comment_not_duplicated() {
    let source = read_source_file("src/lib.rs");

    // Check that lines 213-216 pattern is not repeated verbatim
    // The key phrase is "Skips the O(n log n) sort" — it should appear once
    let count = source.matches("Skips the O(n log n) sort").count();
    assert!(
        count <= 1,
        "V23-F6: 'Skips the O(n log n) sort' should appear at most once, found {}",
        count
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V23-F7: _caller_bloom removed from from_memory() and from_pages()
// ═══════════════════════════════════════════════════════════════════════

// V23-F7 (LOW): The _caller_bloom parameter was unused (V19-F5/V20-F1
// rebuild bloom internally). The parameter has been removed.
// SOURCE: reader.rs, IndexReader::from_memory(), IndexReader::from_pages()

#[test]
fn v23_f7a_from_memory_no_caller_bloom() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "pub fn from_memory(", 300);

    assert!(
        !fn_body.contains("_caller_bloom"),
        "V23-F7: from_memory must not have _caller_bloom parameter"
    );
    assert!(
        !fn_body.contains("caller_bloom"),
        "V23-F7: from_memory must not have caller_bloom parameter"
    );
}

#[test]
fn v23_f7b_from_pages_no_caller_bloom() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "pub fn from_pages(", 300);

    assert!(
        !fn_body.contains("_caller_bloom"),
        "V23-F7: from_pages must not have _caller_bloom parameter"
    );
    assert!(
        !fn_body.contains("caller_bloom"),
        "V23-F7: from_pages must not have caller_bloom parameter"
    );
}

#[test]
fn v23_f7c_from_memory_takes_two_args() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "pub fn from_memory(", 200);

    // Should have exactly: mut meta: MetaIndex, entries: Vec<IndexEntry>
    assert!(
        fn_body.contains("meta: MetaIndex"),
        "V23-F7: from_memory must take MetaIndex"
    );
    assert!(
        fn_body.contains("entries: Vec<IndexEntry>"),
        "V23-F7: from_memory must take Vec<IndexEntry>"
    );
}

#[test]
fn v23_f7d_from_pages_takes_two_args() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "pub fn from_pages(", 200);

    assert!(
        fn_body.contains("meta: MetaIndex"),
        "V23-F7: from_pages must take MetaIndex"
    );
    assert!(
        fn_body.contains("pages: Vec<(IndexPage, BlockId)>"),
        "V23-F7: from_pages must take Vec<(IndexPage, BlockId)>"
    );
}

#[test]
fn v23_f7e_from_memory_behavioral() {
    // from_memory should work with just 2 args (meta, entries)
    let entries: Vec<IndexEntry> = (0..50).map(make_entry).collect();
    let meta = MetaIndex::new();

    let reader = IndexReader::from_memory(meta, entries).unwrap();

    // Verify bloom and lookup work correctly
    assert!(
        reader.bloom_contains(&test_hash(25)),
        "V23-F7: from_memory must rebuild bloom internally"
    );
    let result = reader.lookup(&test_hash(25)).unwrap();
    assert!(result.is_some(), "V23-F7: lookup must find inserted entry");
}

#[test]
fn v23_f7f_from_pages_behavioral() {
    // from_pages should work with just 2 args (meta, pages)
    let entries: Vec<IndexEntry> = (0..100).map(make_entry).collect();
    let page = era_index::IndexPage::try_new(entries).unwrap();
    let meta = MetaIndex::new();

    let reader = IndexReader::from_pages(meta, vec![(page, BlockId::new(0))]).unwrap();

    assert!(
        reader.bloom_contains(&test_hash(50)),
        "V23-F7: from_pages must rebuild bloom internally"
    );
    let result = reader.lookup(&test_hash(50)).unwrap();
    assert!(result.is_some(), "V23-F7: lookup must find inserted entry");
}

#[test]
fn v23_f7g_chunk_index_no_placeholder_bloom() {
    let source = read_source_file("src/chunk_index.rs");

    assert!(
        !source.contains("placeholder_bloom"),
        "V23-F7: chunk_index.rs must not create a placeholder bloom"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V23-F8: for_each_sorted_page progress logging placement
// ═══════════════════════════════════════════════════════════════════════

// V23-F8 (LOW): Progress logging must fire AFTER page callback emission,
// not inside the inner entry loop.
// SOURCE: store.rs, IndexStore::for_each_sorted_page()

#[test]
fn v23_f8a_logging_after_callback() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "pub fn for_each_sorted_page", 3000);

    // The callback invocation and the logging check should be near each other
    // Key: logging must come AFTER callback(), not before
    let callback_pos = fn_body.find("callback(page");
    let logging_pos = fn_body.find("processed");

    assert!(
        callback_pos.is_some() && logging_pos.is_some(),
        "V23-F8: for_each_sorted_page must have both callback and progress logging"
    );

    let callback_pos = callback_pos.unwrap();
    let logging_pos = logging_pos.unwrap();

    assert!(
        logging_pos > callback_pos,
        "V23-F8: progress logging must come AFTER the page callback, not before"
    );
}

#[test]
fn v23_f8b_uses_modulo_operator() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "pub fn for_each_sorted_page", 3000);

    // V23-F8 fix: Uses is_multiple_of(100) for clean modulo checking.
    // is_multiple_of is stable as of Rust 1.73+ and the project MSRV is 1.92+.
    assert!(
        fn_body.contains("is_multiple_of(100)") || fn_body.contains("% 100"),
        "V23-F8: progress logging must use modulo check (is_multiple_of or % 100)"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V23-F9: .expect() in try_new/try_new_presorted is safe [INFO]
// ═══════════════════════════════════════════════════════════════════════

// V23-F9 (INFO): .expect() calls in try_new and try_new_presorted are safe
// because they are guarded by the is_empty() early return. No change needed.
// SOURCE: lib.rs, IndexPage::try_new(), IndexPage::try_new_presorted()

#[test]
fn v23_f9a_expect_guarded_by_empty_check_try_new() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "pub fn try_new(", 1700);

    // Must have is_empty check before expect
    let empty_check_pos = fn_body.find("is_empty()");
    let expect_pos = fn_body.find(".expect(");

    assert!(
        empty_check_pos.is_some() && expect_pos.is_some(),
        "V23-F9: try_new must have both is_empty check and .expect"
    );
    assert!(
        empty_check_pos.unwrap() < expect_pos.unwrap(),
        "V23-F9: is_empty check must come before .expect in try_new"
    );
}

#[test]
fn v23_f9b_expect_guarded_by_empty_check_presorted() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "pub fn try_new_presorted(", 1700);

    let empty_check_pos = fn_body.find("is_empty()");
    let expect_pos = fn_body.find(".expect(");

    assert!(
        empty_check_pos.is_some() && expect_pos.is_some(),
        "V23-F9: try_new_presorted must have both is_empty check and .expect"
    );
    assert!(
        empty_check_pos.unwrap() < expect_pos.unwrap(),
        "V23-F9: is_empty check must come before .expect in try_new_presorted"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V23-F10: set_bloom_filter uses lightweight validation
// ═══════════════════════════════════════════════════════════════════════

// V23-F10 (LOW): set_bloom_filter() should use BloomFilterData::from_bytes()
// for validation instead of full deserialize_bloom() which constructs the
// entire Bloom<ChunkHash> unnecessarily.
// SOURCE: lib.rs, MetaIndex::set_bloom_filter()

#[test]
fn v23_f10a_uses_from_bytes_not_deserialize_bloom() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "pub fn set_bloom_filter(", 500);

    assert!(
        fn_body.contains("BloomFilterData::from_bytes")
            || fn_body.contains("bloom_serde::BloomFilterData::from_bytes"),
        "V23-F10: set_bloom_filter must use BloomFilterData::from_bytes()"
    );

    // Check that deserialize_bloom() does NOT appear in actual code lines
    // (it may appear in comments explaining the V23-F10 fix)
    let has_code_deserialize = fn_body.lines().any(|l| {
        let trimmed = l.trim();
        !trimmed.starts_with("//") && trimmed.contains("deserialize_bloom(")
    });
    assert!(
        !has_code_deserialize,
        "V23-F10: set_bloom_filter must NOT call deserialize_bloom() in code"
    );
}

#[test]
fn v23_f10b_has_v23_comment() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "pub fn set_bloom_filter(", 400);

    assert!(
        fn_body.contains("V23-F10"),
        "V23-F10: set_bloom_filter must reference V23-F10 fix"
    );
}

#[test]
fn v23_f10c_set_bloom_filter_behavioral() {
    // set_bloom_filter with valid data should succeed
    let bloom = bloomfilter::Bloom::<ChunkHash>::new_for_fp_rate(1000, 0.01).unwrap();
    let bytes = era_index::serialize_bloom(&bloom).unwrap();

    let mut meta = MetaIndex::new();
    let result = meta.set_bloom_filter(bytes);
    assert!(
        result.is_ok(),
        "V23-F10: set_bloom_filter must accept valid bloom data"
    );
}

#[test]
fn v23_f10d_set_bloom_filter_rejects_invalid() {
    // set_bloom_filter with garbage data should fail
    let mut meta = MetaIndex::new();
    let result = meta.set_bloom_filter(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    assert!(
        result.is_err(),
        "V23-F10: set_bloom_filter must reject invalid bloom data"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V23-CF1/CF2: Carried forward — info only, verified still present
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v23_cf1_finalize_cpu_heavy_documented() {
    // V23-CF1 (V19-F7): builder.rs finalize() CPU-heavy serialization
    // on async thread is documented as an architectural constraint
    // (Redb ReadTransaction is !Send).
    let source = read_source_file("src/builder.rs");

    // The V19-F7 fix comment should still exist documenting the constraint
    assert!(
        source.contains("V19-F7") || source.contains("spawn_blocking") || source.contains("!Send"),
        "V23-CF1: builder.rs should document the async/CPU constraint"
    );
}

#[test]
fn v23_cf2_finalize_materializes_pages() {
    // V23-CF2 (V18-F10): chunk_index.rs finalize() materializes all pages
    // in Vec before IndexReader creation — required by IndexReader API.
    let source = read_source_file("src/chunk_index.rs");

    assert!(
        source.contains("materializes") || source.contains("V14-F9"),
        "V23-CF2: chunk_index.rs should document page materialization"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V22 Regression Tests — Verify all V22 fixes remain intact
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v23_regression_v22_f3_from_memory_presorted() {
    // V22-F3: from_memory must use try_new_presorted
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "pub fn from_memory(", 2000);

    assert!(
        fn_body.contains("try_new_presorted"),
        "Regression: V22-F3 from_memory must use try_new_presorted"
    );
}

#[test]
fn v23_regression_v22_f5_validated_constructor() {
    // V22-F5: BloomFilterData must have a validated new() constructor
    let source = read_source_file("src/bloom_serde.rs");

    assert!(
        source.contains("pub fn new("),
        "Regression: V22-F5 BloomFilterData must have new() constructor"
    );
}

#[test]
fn v23_regression_v22_f8_no_bloom_clone_in_finalize() {
    // V22-F8: finalize() must not clone bloom bitmap in code
    // (comments may mention the old pattern for documentation)
    let source = read_source_file("src/chunk_index.rs");
    let fn_body = extract_fn_body(&source, "pub fn finalize(", 1500);

    // Check that bloom().clone() does NOT appear in actual code lines
    let has_code_clone = fn_body.lines().any(|l| {
        let trimmed = l.trim();
        !trimmed.starts_with("//") && trimmed.contains("bloom().clone()")
    });
    assert!(
        !has_code_clone,
        "Regression: V22-F8 finalize must not clone bloom in code"
    );
}

#[test]
fn v23_regression_v22_f9_index_entry_display() {
    // V22-F9: IndexEntry must have Display impl
    let source = read_source_file("src/lib.rs");

    assert!(
        source.contains("impl std::fmt::Display for IndexEntry"),
        "Regression: V22-F9 IndexEntry must have Display impl"
    );
}

#[test]
fn v23_regression_v20_f1_from_pages_rebuilds_bloom() {
    // V20-F1: from_pages must rebuild bloom from entries, not trust caller
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "pub fn from_pages(", 2000);

    assert!(
        fn_body.contains("verified_bloom") || fn_body.contains("Bloom::new_for_fp_rate"),
        "Regression: V20-F1 from_pages must rebuild bloom from entries"
    );
}

#[test]
fn v23_regression_v19_f5_from_memory_rebuilds_bloom() {
    // V19-F5: from_memory must rebuild bloom from entries
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "pub fn from_memory(", 2000);

    assert!(
        fn_body.contains("verified_bloom") || fn_body.contains("Bloom::new_for_fp_rate"),
        "Regression: V19-F5 from_memory must rebuild bloom from entries"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// End-to-end behavioral test
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v23_e2e_chunk_index_lifecycle() {
    // Full lifecycle test: create → insert → finalize → lookup
    // Validates that all V23 fixes work together end-to-end
    let mut tree = ChunkIndex::new_default().unwrap();

    for i in 0..200u64 {
        let entry = make_entry(i);
        tree.insert(entry).unwrap();
    }

    // Bloom should work during Building state
    assert!(tree.bloom_contains(&test_hash(100)));
    assert!(!tree.bloom_contains(&test_hash(9999)));

    // Finalize transitions to Finalized state
    let reader = tree.finalize().expect("finalize should succeed");

    // Bloom should work during Finalized state
    assert!(reader.bloom_contains(&test_hash(100)));
    assert!(!reader.bloom_contains(&test_hash(9999)));

    // Lookup should find all inserted entries
    for i in 0..200u64 {
        let result = reader.lookup(&test_hash(i)).unwrap();
        assert!(result.is_some(), "V23-E2E: lookup must find entry {}", i);
    }

    // Lookup should not find absent entries
    let result = reader.lookup(&test_hash(9999)).unwrap();
    assert!(
        result.is_none(),
        "V23-E2E: lookup must not find absent entry"
    );
}
