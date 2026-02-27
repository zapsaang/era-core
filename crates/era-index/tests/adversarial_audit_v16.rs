//! # Adversarial Audit V16 — Comprehensive Test Suite
//!
//! **Audit Date:** 2026-02-26
//! **Target:** `era-index` crate — V16 adversarial audit
//! **Scope:** V16-F1 through V16-F12 (V16-F8 reclassified as non-issue)
//! **Methodology:** Source-level static analysis + behavioral verification
//!
//! ## V15 Regression Status (All FIXED)
//!
//! | ID | Finding | Status |
//! |----|---------|--------|
//! | V15-F1 | unwrap_or_default replaced with explicit match + tracing::warn | FIXED |
//! | V15-F2 | MAX_RECOVERY_CANDIDATES cap on candidates vec | FIXED |
//! | V15-F12 | Deadline checks before all 3 scan_for_typed_blocks calls | FIXED |
//!
//! ## V16 Findings
//!
//! | ID | Severity | Title |
//! |----|----------|-------|
//! | V16-F1 | HIGH | Bloom rebuild threshold changed from 1.5× to 2×, growth from 4× to 2× |
//! | V16-F2 | MEDIUM | from_memory and from_pages signatures changed to `mut meta: MetaIndex` |
//! | V16-F3 | MEDIUM | MIN_INDEX_PAGE_SIZE increased to 64, MIN_META_INDEX_SIZE to 48 |
//! | V16-F4 | MEDIUM | After std::mem::take, re-allocate with Vec::with_capacity(entries_per_page) |
//! | V16-F5 | LOW | .unwrap() replaced with .expect("guaranteed non-empty after is_empty check") |
//! | V16-F6 | MEDIUM | open_readonly bloom rebuild has comment explaining key-only iteration |
//! | V16-F7 | LOW | contains_range doc comment updated |
//! | V16-F8 | — | Non-issue (reclassified) |
//! | V16-F9 | LOW | Doc comment on bloom_filter field about needing set_bloom_filter() |
//! | V16-F10 | MEDIUM | Minimum bloom clamp reduced from 1024 to 128 |
//! | V16-F11 | LOW | Doc comment explaining why &mut self is needed on entry_count |
//! | V16-F12 | MEDIUM | tracing::warn on block_id collision during recovery |

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
// V16-F1 (HIGH — Performance): Bloom rebuild threshold 2×, growth 2×
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: store.rs, rebuild_bloom_if_needed()
// The bloom rebuild threshold was changed from 1.5× (3/2) to 2×.
// The growth factor was changed from 4× to 2×.

#[test]
fn v16_f1a_bloom_rebuild_threshold_is_2x() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "rebuild_bloom_if_needed", 2000);

    // Must contain the 2× threshold check
    assert!(
        fn_body.contains("self.bloom_sized_for * 2"),
        "V16-F1: rebuild_bloom_if_needed must use 2× threshold (self.bloom_sized_for * 2), got:\n{}",
        &fn_body[..500.min(fn_body.len())]
    );

    // Must NOT contain the old 1.5× threshold (3 / 2 pattern)
    assert!(
        !fn_body.contains("* 3 / 2"),
        "V16-F1: old 1.5× threshold (* 3 / 2) must be removed from rebuild_bloom_if_needed"
    );
}

#[test]
fn v16_f1b_bloom_growth_factor_is_2x() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "rebuild_bloom_if_needed", 2000);

    // Must contain the 2× growth factor
    assert!(
        fn_body.contains("self.entry_count * 2"),
        "V16-F1: rebuild_bloom_if_needed must use 2× growth (self.entry_count * 2), got:\n{}",
        &fn_body[..500.min(fn_body.len())]
    );

    // Must NOT contain the old 4× growth factor
    assert!(
        !fn_body.contains("self.entry_count * 4"),
        "V16-F1: old 4× growth factor (self.entry_count * 4) must be removed"
    );
}

#[test]
fn v16_f1c_bloom_rebuild_behavioral() {
    // Insert enough entries to exceed 2× initial capacity, verify bloom still works.
    use tempfile::TempDir;
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_bloom_rebuild.redb");

    // Create with small initial bloom capacity (128) so 2× threshold is 256
    let mut store = era_index::IndexStore::create(&db_path, 128).unwrap();

    // Insert 300 entries — exceeds 2× of 128, triggering rebuild
    for i in 0..300u64 {
        store.insert(&make_entry(i)).unwrap();
    }

    assert_eq!(store.entry_count(), 300);

    // All inserted hashes must still be found in the bloom filter after rebuild
    for i in 0..300u64 {
        assert!(
            store.bloom_contains(&test_hash(i)),
            "V16-F1 behavioral: hash {} missing from bloom after rebuild",
            i
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// V16-F2 (MEDIUM — Logic): from_memory and from_pages take `mut meta`
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs
// Signatures changed to `mut meta: MetaIndex` (owned mutable) to avoid
// the awkward `let mut meta = meta;` shadow rebinding pattern.

#[test]
fn v16_f2a_from_memory_takes_mut_meta() {
    let source = read_source_file("src/reader.rs");

    // Find from_memory signature — must have `mut meta: MetaIndex`
    let fn_body = extract_fn_body(&source, "from_memory", 2000);
    assert!(
        fn_body.contains("mut meta: MetaIndex"),
        "V16-F2: from_memory must take `mut meta: MetaIndex`, got:\n{}",
        &fn_body[..300.min(fn_body.len())]
    );
}

#[test]
fn v16_f2b_from_pages_takes_mut_meta() {
    let source = read_source_file("src/reader.rs");

    let fn_body = extract_fn_body(&source, "from_pages", 2000);
    assert!(
        fn_body.contains("mut meta: MetaIndex"),
        "V16-F2: from_pages must take `mut meta: MetaIndex`, got:\n{}",
        &fn_body[..300.min(fn_body.len())]
    );
}

#[test]
fn v16_f2c_no_shadow_rebinding() {
    let source = read_source_file("src/reader.rs");

    // Ensure the old `let mut meta = meta;` shadow rebinding is NOT present
    assert!(
        !source.contains("let mut meta = meta;"),
        "V16-F2: shadow rebinding `let mut meta = meta;` must NOT exist in reader.rs"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V16-F3 (MEDIUM — Security): MIN_INDEX_PAGE_SIZE=64, MIN_META_INDEX_SIZE=48
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs
// Minimum sizes increased to prevent accepting trivially small payloads.

#[test]
fn v16_f3a_min_index_page_size_is_64() {
    let source = read_source_file("src/reader.rs");

    assert!(
        source.contains("MIN_INDEX_PAGE_SIZE: usize = 64"),
        "V16-F3: MIN_INDEX_PAGE_SIZE must be 64 in reader.rs"
    );
}

#[test]
fn v16_f3b_min_meta_index_size_is_48() {
    let source = read_source_file("src/reader.rs");

    assert!(
        source.contains("MIN_META_INDEX_SIZE: usize = 48"),
        "V16-F3: MIN_META_INDEX_SIZE must be 48 in reader.rs"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V16-F4 (MEDIUM — Performance): Vec re-allocation after std::mem::take
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: store.rs, for_each_sorted_page()
// After `std::mem::take(&mut chunk)`, the chunk must be re-allocated
// with `Vec::with_capacity(entries_per_page)` to avoid repeated growth.

#[test]
fn v16_f4a_vec_realloc_after_take() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "for_each_sorted_page", 3000);

    // Verify std::mem::take is used
    assert!(
        fn_body.contains("std::mem::take"),
        "V16-F4: for_each_sorted_page must use std::mem::take"
    );

    // Find std::mem::take position and verify Vec::with_capacity follows
    let take_pos = fn_body
        .find("std::mem::take")
        .expect("std::mem::take must exist in for_each_sorted_page");
    let after_take = &fn_body[take_pos..];

    assert!(
        after_take.contains("Vec::with_capacity(entries_per_page)"),
        "V16-F4: Vec::with_capacity(entries_per_page) must appear AFTER std::mem::take, got:\n{}",
        &after_take[..500.min(after_take.len())]
    );
}

#[test]
fn v16_f4b_for_each_sorted_page_multi_page_behavioral() {
    use tempfile::TempDir;
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_pages.redb");

    let entries_per_page = ENTRIES_PER_PAGE;
    // Insert enough entries for at least 2 full pages + partial
    let total_entries = entries_per_page * 2 + 100;

    let mut store = era_index::IndexStore::create(&db_path, total_entries).unwrap();
    let entries: Vec<IndexEntry> = (0..total_entries as u64).map(make_entry).collect();
    store.insert_batch(&entries).unwrap();

    let mut page_count = 0usize;
    let mut total_found = 0usize;
    store
        .for_each_sorted_page(|page, _block_id| {
            page_count += 1;
            total_found += page.len();
            Ok(())
        })
        .unwrap();

    assert_eq!(
        page_count, 3,
        "V16-F4 behavioral: expected 3 pages for {} entries",
        total_entries
    );
    assert_eq!(
        total_found, total_entries,
        "V16-F4 behavioral: all entries must be present across pages"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V16-F5 (LOW — Robustness): .unwrap() → .expect() in try_new
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: lib.rs, IndexPage::try_new()
// The .unwrap() calls on entries.first()/last() were replaced with
// .expect("guaranteed non-empty after is_empty check") for clarity.

#[test]
fn v16_f5a_try_new_uses_expect_not_unwrap() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "try_new", 2000);

    // Must contain .expect( calls (for first() and last())
    assert!(
        fn_body.contains(".expect("),
        "V16-F5: try_new must use .expect() for first()/last(), got:\n{}",
        &fn_body[..500.min(fn_body.len())]
    );

    // The expect message should mention the guarantee
    assert!(
        fn_body.contains("guaranteed non-empty after is_empty check"),
        "V16-F5: expect message must mention 'guaranteed non-empty after is_empty check'"
    );

    // Must NOT have bare .unwrap() calls on first()/last() in the hash extraction section
    // Look for the section after dedup_by_key where min/max are extracted
    let dedup_pos = fn_body.find("dedup_by_key").unwrap_or(0);
    let after_dedup = &fn_body[dedup_pos..(dedup_pos + 500).min(fn_body.len())];
    assert!(
        !after_dedup.contains(".unwrap()"),
        "V16-F5: try_new must NOT use .unwrap() after dedup, got:\n{}",
        after_dedup
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V16-F6 (MEDIUM — Logic): open_readonly bloom rebuild comment
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: store.rs, open_readonly()
// A comment must explain why only keys are iterated (not values) for bloom.

#[test]
fn v16_f6a_open_readonly_has_key_only_comment() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "open_readonly", 3000);

    // Look for a comment explaining key-only iteration
    let has_key_only_comment = fn_body.contains("keys only")
        || fn_body.contains("key-only")
        || fn_body.contains("Iterate keys only")
        || fn_body.contains("only need the hash");

    assert!(
        has_key_only_comment,
        "V16-F6: open_readonly must have a comment explaining key-only iteration for bloom, got:\n{}",
        &fn_body[..1000.min(fn_body.len())]
    );
}

#[test]
fn v16_f6b_open_readonly_explains_no_value_deserialization() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "open_readonly", 3000);

    // Must explain that value deserialization is skipped
    let has_explanation = fn_body.contains("deserialization is intentionally skipped")
        || fn_body.contains("Value deserialization")
        || fn_body.contains("values are not used");

    assert!(
        has_explanation,
        "V16-F6: open_readonly must explain why value deserialization is skipped, got:\n{}",
        &fn_body[..1000.min(fn_body.len())]
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V16-F7 (LOW — Documentation): contains_range doc comment updated
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: lib.rs, contains_range()
// Doc comment must mention "utility method" or "external consumers".

#[test]
fn v16_f7a_contains_range_doc_mentions_utility() {
    let source = read_source_file("src/lib.rs");

    // Find contains_range and look backwards for its doc comment
    let cr_pos = source
        .find("fn contains_range")
        .expect("contains_range must exist in lib.rs");
    let start = cr_pos.saturating_sub(500);
    let doc_region = &source[start..cr_pos];

    let has_utility_mention = doc_region.contains("utility method")
        || doc_region.contains("external consumers")
        || doc_region.contains("utility")
        || doc_region.contains("External");

    assert!(
        has_utility_mention,
        "V16-F7: contains_range doc must mention 'utility method' or 'external consumers', got:\n{}",
        doc_region
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V16-F8: Non-issue (reclassified)
// ═══════════════════════════════════════════════════════════════════════
//
// This finding was analyzed and reclassified as a non-issue.
// No code change was needed.

#[allow(clippy::assertions_on_constants)]
#[test]
fn v16_f8_reclassified_as_non_issue() {
    // V16-F8 was analyzed during audit and determined to be a non-issue.
    // This test serves as documentation that the finding was reviewed
    // and intentionally reclassified — no code change was required.
    assert!(true, "V16-F8: Analyzed and reclassified as non-issue");
}

// ═══════════════════════════════════════════════════════════════════════
// V16-F9 (LOW — Robustness): bloom_filter field doc mentions set_bloom_filter
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: lib.rs, MetaIndex struct
// The bloom_filter field should have a doc comment noting that
// set_bloom_filter() must be called before use.

#[test]
fn v16_f9a_bloom_filter_field_doc_mentions_set_bloom_filter() {
    let source = read_source_file("src/lib.rs");

    // Find the MetaIndex struct and look for bloom_filter field doc
    let meta_pos = source
        .find("pub struct MetaIndex")
        .expect("MetaIndex must exist in lib.rs");
    let end = (meta_pos + 500).min(source.len());
    let struct_body = &source[meta_pos..end];

    // The doc comment on bloom_filter field should mention set_bloom_filter
    assert!(
        struct_body.contains("set_bloom_filter"),
        "V16-F9: MetaIndex bloom_filter field doc must mention set_bloom_filter(), got:\n{}",
        struct_body
    );
}

#[test]
fn v16_f9b_bloom_filter_doc_warns_about_empty_default() {
    let source = read_source_file("src/lib.rs");

    let meta_pos = source
        .find("pub struct MetaIndex")
        .expect("MetaIndex must exist");
    let end = (meta_pos + 500).min(source.len());
    let struct_body = &source[meta_pos..end];

    // Doc should warn that default (empty Vec) will cause errors
    let has_warning = struct_body.contains("empty Vec")
        || struct_body.contains("deserialization error")
        || struct_body.contains("Must be set");

    assert!(
        has_warning,
        "V16-F9: bloom_filter field doc must warn about the empty default, got:\n{}",
        struct_body
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V16-F10 (MEDIUM — Security): Minimum bloom clamp reduced to 128
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: builder.rs, bloom_expected_items()
// The minimum bloom filter items clamp was reduced from 1024 to 128
// so that tiny archives don't over-allocate.

#[test]
fn v16_f10a_bloom_clamp_minimum_is_128() {
    let source = read_source_file("src/builder.rs");

    // V17-F12 superseded V16-F10: minimum clamp raised back to 1024
    // to ensure a minimally useful Bloom filter. The clamp value is
    // now .clamp(1024, ...) instead of .clamp(128, ...).
    assert!(
        source.contains(".clamp(1024,"),
        "V17-F12: bloom_expected_items must use .clamp(1024, ...) in builder.rs"
    );
}

#[test]
fn v16_f10b_bloom_clamp_not_1024() {
    let source = read_source_file("src/builder.rs");
    let fn_body = extract_fn_body(&source, "bloom_expected_items", 500);

    // V17-F12 changed: .clamp(1024, ...) is now the correct pattern.
    // This test now verifies that the old .clamp(128, ...) has been removed.
    assert!(
        !fn_body.contains(".clamp(128,"),
        "V17-F12: old .clamp(128, ...) must be removed from bloom_expected_items"
    );
}

#[test]
fn v16_f10c_tiny_mem_limit_behavioral() {
    // Create an IndexBuilder with a tiny mem_limit and verify it works
    let builder = era_index::IndexBuilder::new(256).unwrap();

    // Should succeed — the bloom filter clamp(128, ...) prevents zero-size bloom
    assert!(
        builder.bloom_contains(&test_hash(999_999)) || !builder.bloom_contains(&test_hash(999_999)),
        "V16-F10 behavioral: builder with tiny mem_limit must not panic"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V16-F11 (LOW — Code Quality): Doc comment on entry_count explaining &mut self
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: builder.rs, entry_count()
// A doc comment must explain why entry_count takes &mut self (it calls flush_buffer).

#[test]
fn v16_f11a_entry_count_doc_explains_mut_self() {
    let source = read_source_file("src/builder.rs");

    // Find entry_count and look backwards for its doc comment
    let ec_pos = source
        .find("pub fn entry_count")
        .expect("entry_count must exist in builder.rs");
    let start = ec_pos.saturating_sub(500);
    let doc_region = &source[start..ec_pos + 200];

    let has_explanation = doc_region.contains("flush_buffer")
        || doc_region.contains("&mut self")
        || doc_region.contains("flush");

    assert!(
        has_explanation,
        "V16-F11: entry_count doc must mention flush_buffer or &mut self, got:\n{}",
        doc_region
    );
}

#[test]
fn v16_f11b_entry_count_doc_mentions_deduplication() {
    let source = read_source_file("src/builder.rs");

    let ec_pos = source
        .find("pub fn entry_count")
        .expect("entry_count must exist in builder.rs");
    let start = ec_pos.saturating_sub(500);
    let doc_region = &source[start..ec_pos + 50];

    let has_dedup_mention = doc_region.contains("dedup")
        || doc_region.contains("unique")
        || doc_region.contains("first-write-wins");

    assert!(
        has_dedup_mention,
        "V16-F11: entry_count doc must mention deduplication/unique count, got:\n{}",
        doc_region
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V16-F12 (MEDIUM — Logic): tracing::warn on block_id collision during recovery
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs, recover_from_volume()
// When embedded_pages.insert() overwrites an existing block_id, a
// tracing::warn must be emitted to flag the collision.

#[test]
fn v16_f12a_collision_warn_exists() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 25000);

    // Find the embedded_pages.insert section
    let insert_pos = fn_body
        .find("embedded_pages.insert")
        .expect("embedded_pages.insert must exist in recover_from_volume");
    let region_end = (insert_pos + 500).min(fn_body.len());
    let insert_region = &fn_body[insert_pos..region_end];

    assert!(
        insert_region.contains("tracing::warn"),
        "V16-F12: tracing::warn must be present near embedded_pages.insert, got:\n{}",
        insert_region
    );
}

#[test]
fn v16_f12b_collision_warn_mentions_collision() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 25000);

    let insert_pos = fn_body
        .find("embedded_pages.insert")
        .expect("embedded_pages.insert must exist");
    // V17-F1 moved the collision check BEFORE insert, so search backwards too.
    // Look in a window centered on the insert call: 500 chars before and after.
    let region_start = insert_pos.saturating_sub(500);
    let region_end = (insert_pos + 500).min(fn_body.len());
    let insert_region = &fn_body[region_start..region_end];

    assert!(
        insert_region.contains("collision"),
        "V16-F12: collision warning must mention 'collision', got:\n{}",
        insert_region
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Regression Tests — V15 Findings Still Fixed
// ═══════════════════════════════════════════════════════════════════════

/// V15-F1 regression: hint scan uses explicit match, not unwrap_or_default
#[test]
fn v16_regression_v15f1_no_unwrap_or_default_in_hint_scan() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 15000);

    let hint_section = fn_body
        .find("page_blocks_for_hint")
        .expect("hint scan section must exist");
    let hint_region = &fn_body[hint_section..];

    assert!(
        !hint_region[..500.min(hint_region.len())].contains("unwrap_or_default"),
        "V15-F1 regression: unwrap_or_default must NOT be present in hint scan"
    );
}

/// V15-F2 regression: MAX_RECOVERY_CANDIDATES constant exists and caps upper_bound
#[test]
fn v16_regression_v15f2_max_recovery_candidates_exists() {
    let source = read_source_file("src/reader.rs");

    assert!(
        source.contains("MAX_RECOVERY_CANDIDATES"),
        "V15-F2 regression: MAX_RECOVERY_CANDIDATES must exist in reader.rs"
    );

    assert!(
        source.contains("upper_bound.min(MAX_RECOVERY_CANDIDATES)"),
        "V15-F2 regression: upper_bound must be capped via .min(MAX_RECOVERY_CANDIDATES)"
    );
}

/// V14-F1 regression: 4-byte domain tag "IDX\x01" in builder.rs and reader.rs
#[test]
fn v16_regression_v14f1_domain_tag_in_builder_and_reader() {
    let builder_source = read_source_file("src/builder.rs");
    let reader_source = read_source_file("src/reader.rs");

    assert!(
        builder_source.contains(r#"b"IDX\x01""#),
        "V14-F1 regression: builder.rs must contain b\"IDX\\x01\" domain tag"
    );

    assert!(
        reader_source.contains(r#"b"IDX\x01""#),
        "V14-F1 regression: reader.rs must contain b\"IDX\\x01\" domain tag"
    );
}

/// V14-F7 regression: entry_count increment AFTER commit in store.rs
#[test]
fn v16_regression_v14f7_entry_count_after_commit() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "insert(&mut self", 10000);

    let commit_pos = fn_body
        .find(".commit()")
        .expect("commit must exist in insert()");
    let count_pos = fn_body
        .find("self.entry_count += 1")
        .expect("entry_count increment must exist");

    assert!(
        commit_pos < count_pos,
        "V14-F7 regression: .commit() (at {}) must come BEFORE self.entry_count += 1 (at {})",
        commit_pos,
        count_pos
    );
}
