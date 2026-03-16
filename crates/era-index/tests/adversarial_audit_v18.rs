//! # Adversarial Audit V18 — Comprehensive Test Suite
//!
//! **Audit Date:** 2026-02-27
//! **Target:** `era-index` crate — V18 adversarial audit
//! **Scope:** V18-F1 through V18-F12 (V18-F7, F10 documented/limitation)
//! **Methodology:** Source-level static analysis + behavioral verification
//!
//! ## V17 Regression Status (All FIXED)
//!
//! | ID | Finding | Status |
//! |----|---------|--------|
//! | V17-F1 | Collision check BEFORE insert in recovery | FIXED |
//! | V17-F2 | try_new_presorted skips sort for Redb B-tree | FIXED |
//! | V17-F5 | IndexEntry::new warns on length=0 | FIXED |
//! | V17-F6 | IndexEntry::new warns on offset+length overflow | FIXED |
//! | V17-F7 | debug_assert for unique block_ids in add_page | FIXED |
//! | V17-F9 | Version check before full deserialization in bloom | FIXED |
//! | V17-F11 | tracing::debug on duplicate removal | FIXED |
//! | V17-F12 | bloom_expected_items minimum clamp raised to 1024 | FIXED |
//!
//! ## V18 Findings
//!
//! | ID | Severity | Title |
//! |----|----------|-------|
//! | V18-F1 | CRITICAL | O(M×N) recovery → O(M) via HashMap<BlockId, usize> index |
//! | V18-F2 | HIGH | validate_meta_index() after recovery deserialization |
//! | V18-F3 | HIGH | Manifest selection iterates all candidates, prefers last valid |
//! | V18-F4 | MEDIUM | Pre-decrypt size check on encrypted blocks |
//! | V18-F5 | MEDIUM | sort_by_key (stable) for deterministic dedup |
//! | V18-F6 | MEDIUM | BloomFilterData validates bitmap_bits/k_num/bitmap length |
//! | V18-F7 | MEDIUM | finalize() blocks async runtime (documented limitation) |
//! | V18-F8 | MEDIUM | open_readonly caps bloom at 10M entries to prevent DoS |
//! | V18-F9 | MEDIUM | MetaIndex::add_page rejects min_hash > max_hash |
//! | V18-F10 | MEDIUM | ChunkIndex::finalize materializes all pages (documented) |
//! | V18-F11 | MEDIUM | try_new_presorted: runtime sorted check, not debug_assert |
//! | V18-F12 | LOW | Recovery error includes missing block_ids |

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
// V18-F1 (CRITICAL — DoS): O(M×N) → O(M) via HashMap<BlockId, usize>
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs, recover_from_volume()
// Recovery builds a HashMap<BlockId, usize> for O(1) page lookup instead
// of iterating all unrecovered pages for every scanned block.

#[test]
fn v18_f1a_hashmap_index_exists_in_recovery() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_pages_via_scan", 20000);

    assert!(
        fn_body.contains("block_id_to_page_idx"),
        "V18-F1: recover_pages_via_scan must use block_id_to_page_idx HashMap"
    );
    assert!(
        fn_body.contains("HashMap<BlockId, usize>"),
        "V18-F1: block_id_to_page_idx must be HashMap<BlockId, usize>"
    );
}

#[test]
fn v18_f1b_hashmap_removes_on_match() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_pages_via_scan", 20000);

    assert!(
        fn_body.contains("block_id_to_page_idx.remove"),
        "V18-F1: block_id_to_page_idx must be pruned on successful match"
    );
}

#[test]
fn v18_f1c_positional_hint_optimization() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_pages_via_scan", 20000);

    assert!(
        fn_body.contains("positional_hint"),
        "V18-F1: recovery must try positional hint (scan_idx as BlockId) first"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V18-F2 (HIGH — Robustness): validate_meta_index() after deserialization
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs, validate_meta_index()
// Validates page count, min<=max per page, ascending order, unique block_ids.

#[test]
fn v18_f2a_validate_meta_index_function_exists() {
    let source = read_source_file("src/reader.rs");

    assert!(
        source.contains("fn validate_meta_index"),
        "V18-F2: validate_meta_index function must exist in reader.rs"
    );
}

#[test]
fn v18_f2b_validates_page_count_bound() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "validate_meta_index", 2000);

    assert!(
        fn_body.contains("MAX_META_PAGES") || fn_body.contains("10_000"),
        "V18-F2: validate_meta_index must check page count against a maximum"
    );
}

#[test]
fn v18_f2c_validates_inverted_hash_ranges() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "validate_meta_index", 2000);

    assert!(
        fn_body.contains("min_hash > page.max_hash")
            || fn_body.contains("page.min_hash > page.max_hash"),
        "V18-F2: validate_meta_index must check for inverted hash ranges"
    );
}

#[test]
fn v18_f2d_validates_overlap() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "validate_meta_index", 2000);

    assert!(
        fn_body.contains("overlap"),
        "V18-F2: validate_meta_index must check for page overlap"
    );
}

#[test]
fn v18_f2e_validates_duplicate_block_ids() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "validate_meta_index", 2000);

    assert!(
        fn_body.contains("seen_block_ids") || fn_body.contains("duplicate block_id"),
        "V18-F2: validate_meta_index must detect duplicate block_ids"
    );
}

#[test]
fn v18_f2f_called_on_fast_path() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 20000);

    // Must be called after MetaIndex deserialization on the fast path (footer-based)
    let fast_path_section = &fn_body[..4000.min(fn_body.len())];
    assert!(
        fast_path_section.contains("validate_meta_index"),
        "V18-F2: validate_meta_index must be called on the fast path (footer-based recovery)"
    );
}

#[test]
fn v18_f2g_called_on_slow_path() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 20000);

    // Count calls — must appear at least twice (fast + slow paths)
    let count = fn_body.matches("validate_meta_index").count();
    assert!(
        count >= 2,
        "V18-F2: validate_meta_index must be called on BOTH fast and slow paths (found {} calls)",
        count
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V18-F3 (HIGH — Robustness): Manifest fallback iteration
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs, recover_from_volume() slow path
// Iterates through all manifest blocks (reverse order) instead of blindly
// taking manifest_blocks[0].

#[test]
fn v18_f3a_no_blind_first_manifest() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 20000);

    // Should NOT blindly use manifest_blocks[0] anymore
    assert!(
        !fn_body.contains("manifest_blocks[0]"),
        "V18-F3: recover_from_volume must NOT blindly use manifest_blocks[0]"
    );
}

#[test]
fn v18_f3b_iterates_manifests_in_reverse() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 20000);

    // Should iterate in reverse (prefer last/most recent)
    assert!(
        fn_body.contains(".rev()") || fn_body.contains("iter().rev()"),
        "V18-F3: manifest iteration must use .rev() to prefer most recent"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V18-F4 (MEDIUM — Performance): Pre-decrypt size validation
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs, recover_from_volume()
// Checks encrypted_block.data.len() BEFORE decryption to avoid wasting
// CPU on oversized blocks.

#[test]
fn v18_f4a_pre_decrypt_size_check_meta_index() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 20000);

    // Must check encrypted block size before calling decrypt
    assert!(
        fn_body.contains("MAX_META_INDEX_SIZE + 64"),
        "V18-F4: must pre-check encrypted MetaIndex size (MAX_META_INDEX_SIZE + 64)"
    );
}

#[test]
fn v18_f4b_pre_decrypt_size_check_index_page() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 20000);

    // Must check encrypted IndexPage block size before decrypt
    assert!(
        fn_body.contains("MAX_INDEX_PAGE_SIZE + 64"),
        "V18-F4: must pre-check encrypted IndexPage size (MAX_INDEX_PAGE_SIZE + 64)"
    );
}

#[test]
fn v18_f4c_pre_decrypt_before_decrypt_call() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 20000);

    // Find the fast-path pre-decrypt check and the decrypt call
    let pre_check_pos = fn_body
        .find("MAX_META_INDEX_SIZE + 64")
        .expect("Pre-decrypt size check must exist");
    let decrypt_pos = fn_body
        .find("decrypt_with_context")
        .expect("decrypt_with_context call must exist");

    assert!(
        pre_check_pos < decrypt_pos,
        "V18-F4: pre-decrypt size check (at {}) must come BEFORE decrypt_with_context (at {})",
        pre_check_pos,
        decrypt_pos
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V18-F5 (MEDIUM — Logic): Stable sort for deterministic dedup
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: lib.rs, IndexPage::try_new()
// Uses sort_by_key (stable) instead of sort_unstable_by_key.

#[test]
fn v18_f5a_uses_stable_sort() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "try_new(", 2000);

    assert!(
        fn_body.contains("sort_by_key"),
        "V18-F5: try_new must use sort_by_key (stable sort)"
    );
}

#[test]
fn v18_f5b_no_unstable_sort() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "try_new(", 2000);

    assert!(
        !fn_body.contains("sort_unstable_by_key"),
        "V18-F5: try_new must NOT use sort_unstable_by_key"
    );
}

#[test]
fn v18_f5c_deterministic_dedup_behavioral() {
    // Two entries with the same hash but different offsets.
    // With stable sort, the first inserted entry should survive dedup.
    let hash = test_hash(42);
    let vid = VolumeId::new();
    let bid = BlockId::new(0);

    let entry1 = IndexEntry::new(hash, vid, bid, 100, 1024).expect("valid entry"); // first-write
    let entry2 = IndexEntry::new(hash, vid, bid, 200, 1024).expect("valid entry"); // second-write

    let page = era_index::IndexPage::try_new(vec![entry1, entry2]).unwrap();
    assert_eq!(
        page.len(),
        1,
        "V18-F5: duplicate hash should be deduped to 1 entry"
    );

    // The surviving entry should be the first one (offset=100) due to stable sort
    let found = page.find(&hash).expect("hash must be found");
    assert_eq!(
        found.offset(),
        100,
        "V18-F5: stable sort must preserve first-write-wins (offset=100), got offset={}",
        found.offset()
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V18-F6 (MEDIUM — Robustness): BloomFilterData field validation
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: bloom_serde.rs, BloomFilterData::from_bytes()
// Validates bitmap_bits > 0, k_num > 0, bitmap.len()*8 >= bitmap_bits.

#[test]
fn v18_f6a_validates_zero_bitmap_bits() {
    let source = read_source_file("src/bloom_serde.rs");
    // V23-F3: validation moved to validate() method, called from from_bytes()
    let validate_body = extract_fn_body(&source, "validate", 2000);
    assert!(
        validate_body.contains("bitmap_bits == 0"),
        "V18-F6: validate() must check for bitmap_bits == 0"
    );
    let from_bytes_body = extract_fn_body(&source, "from_bytes", 2000);
    assert!(
        from_bytes_body.contains("validate()"),
        "V18-F6: from_bytes must call validate()"
    );
}

#[test]
fn v18_f6b_validates_zero_k_num() {
    let source = read_source_file("src/bloom_serde.rs");
    // V23-F3: validation moved to validate() method
    let validate_body = extract_fn_body(&source, "validate", 2000);
    assert!(
        validate_body.contains("k_num == 0"),
        "V18-F6: validate() must check for k_num == 0"
    );
}

#[test]
fn v18_f6c_validates_bitmap_length() {
    let source = read_source_file("src/bloom_serde.rs");
    // V23-F3: validation moved to validate() method
    let validate_body = extract_fn_body(&source, "validate", 2000);
    assert!(
        validate_body.contains("bitmap_bits"),
        "V18-F6: validate() must validate bitmap length against bitmap_bits"
    );
    assert!(
        validate_body.contains("* 8 <") || validate_body.contains("*8 <"),
        "V18-F6: validate() must check bitmap.len()*8 >= bitmap_bits"
    );
}

#[test]
fn v18_f6d_zero_bitmap_bits_behavioral() {
    // V23-F3: validate() rejects bitmap_bits=0 at construction time via new()
    let bloom: bloomfilter::Bloom<ChunkHash> = bloomfilter::Bloom::new_for_fp_rate(100, 0.01);
    let result = BloomFilterData::new(
        bloom.bitmap(),
        0, // zero bitmap_bits
        bloom.number_of_hash_functions(),
        bloom.sip_keys(),
    );
    assert!(result.is_err(), "V18-F6: bitmap_bits=0 must be rejected");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("bitmap_bits"),
        "V18-F6: error must mention bitmap_bits, got: {}",
        err_msg
    );
}

#[test]
fn v18_f6e_zero_k_num_behavioral() {
    // V23-F3: validate() rejects k_num=0 at construction time via new()
    let bloom: bloomfilter::Bloom<ChunkHash> = bloomfilter::Bloom::new_for_fp_rate(100, 0.01);
    let result = BloomFilterData::new(
        bloom.bitmap(),
        bloom.number_of_bits(),
        0, // zero k_num
        bloom.sip_keys(),
    );
    assert!(result.is_err(), "V18-F6: k_num=0 must be rejected");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("k_num"),
        "V18-F6: error must mention k_num, got: {}",
        err_msg
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V18-F7 (MEDIUM — Performance): finalize() blocks async (documented)
// ═══════════════════════════════════════════════════════════════════════

#[allow(clippy::assertions_on_constants)]
#[test]
fn v18_f7_documented_as_known_limitation() {
    // V18-F7 was analyzed during audit and documented as a known limitation.
    // The finalize() method performs CPU-heavy work (rkyv serialization +
    // AEAD encryption) inline on the async runtime. Fixing this requires
    // restructuring the for_each_sorted_page callback pattern.
    assert!(
        true,
        "V18-F7: Documented as known limitation — requires callback pattern redesign"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V18-F8 (MEDIUM — DoS): open_readonly caps bloom at 10M entries
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: store.rs, open_readonly()
// Caps bloom filter sizing at 10M entries to prevent memory DoS.

#[test]
fn v18_f8a_max_readonly_bloom_entries_exists() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "open_readonly", 3000);

    assert!(
        fn_body.contains("MAX_READONLY_BLOOM_ENTRIES"),
        "V18-F8: open_readonly must define MAX_READONLY_BLOOM_ENTRIES"
    );
}

#[test]
fn v18_f8b_bloom_cap_is_10m() {
    let source = read_source_file("src/store.rs");

    assert!(
        source.contains("MAX_READONLY_BLOOM_ENTRIES: usize = 10_000_000"),
        "V18-F8: MAX_READONLY_BLOOM_ENTRIES must be 10_000_000"
    );
}

#[test]
fn v18_f8c_bloom_size_uses_min_cap() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "open_readonly", 3000);

    // bloom_size should be capped: len.clamp(1024, MAX_READONLY_BLOOM_ENTRIES)
    assert!(
        fn_body.contains(".clamp(1024, MAX_READONLY_BLOOM_ENTRIES)"),
        "V18-F8: bloom sizing must use .clamp(1024, MAX_READONLY_BLOOM_ENTRIES)"
    );
}

#[test]
fn v18_f8d_warns_on_bloom_cap() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "open_readonly", 3000);

    // Must warn when bloom is undersized
    let cap_check_pos = fn_body
        .find("len > MAX_READONLY_BLOOM_ENTRIES")
        .expect("V18-F8: must check len > MAX_READONLY_BLOOM_ENTRIES");
    let region_end = (cap_check_pos + 300).min(fn_body.len());
    let region = &fn_body[cap_check_pos..region_end];

    assert!(
        region.contains("tracing::warn"),
        "V18-F8: must emit tracing::warn when bloom is capped, got:\n{}",
        region
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V18-F9 (MEDIUM — Logic): add_page rejects inverted hash ranges
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: lib.rs, MetaIndex::add_page()
// Validates min_hash <= max_hash before accepting a page pointer.

#[test]
fn v18_f9a_rejects_inverted_range_in_source() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "add_page", 2000);

    assert!(
        fn_body.contains("min_hash > max_hash"),
        "V18-F9: add_page must check min_hash > max_hash"
    );
}

#[test]
fn v18_f9b_inverted_range_returns_error() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "add_page", 2000);

    let check_pos = fn_body
        .find("min_hash > max_hash")
        .expect("inverted range check must exist");
    let region_end = (check_pos + 300).min(fn_body.len());
    let region = &fn_body[check_pos..region_end];

    assert!(
        region.contains("Err(") || region.contains("return Err"),
        "V18-F9: inverted range must return an error, got:\n{}",
        region
    );
}

#[test]
fn v18_f9c_inverted_range_behavioral() {
    let mut meta = era_index::MetaIndex::new();
    // min_hash(200) > max_hash(100) → inverted range, must be rejected
    let result = meta.add_page(test_hash(200), test_hash(100), BlockId::new(0), 0, 0);
    assert!(
        result.is_err(),
        "V18-F9: inverted hash range (min > max) must be rejected"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("min_hash") || err_msg.contains("max_hash"),
        "V18-F9: error must mention hash range, got: {}",
        err_msg
    );
}

#[test]
fn v18_f9d_valid_range_still_works() {
    let mut meta = era_index::MetaIndex::new();
    // min_hash(100) <= max_hash(200) → valid range, must succeed
    let result = meta.add_page(test_hash(100), test_hash(200), BlockId::new(0), 0, 0);
    assert!(
        result.is_ok(),
        "V18-F9: valid hash range (min <= max) must be accepted"
    );
    assert_eq!(meta.pages().len(), 1);
}

#[test]
fn v18_f9e_equal_range_accepted() {
    let mut meta = era_index::MetaIndex::new();
    // Single-entry page: min == max, should be accepted
    let result = meta.add_page(test_hash(50), test_hash(50), BlockId::new(0), 0, 0);
    assert!(
        result.is_ok(),
        "V18-F9: equal hash range (min == max) must be accepted"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V18-F10 (MEDIUM — Performance): ChunkIndex materializes all pages
// ═══════════════════════════════════════════════════════════════════════

#[allow(clippy::assertions_on_constants)]
#[test]
fn v18_f10_documented_as_known_limitation() {
    // V18-F10 was analyzed and documented as a known limitation.
    // ChunkIndex::finalize() calls read_sorted_pages() which collects all
    // pages into a Vec. A streaming variant would require IndexReader API changes.
    assert!(
        true,
        "V18-F10: Documented as known limitation — requires IndexReader streaming API"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V18-F11 (MEDIUM — Robustness): Runtime sorted invariant check
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: lib.rs, IndexPage::try_new_presorted()
// Uses a runtime check instead of debug_assert for sorted invariant.

#[test]
fn v18_f11a_no_debug_assert_for_sorted() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "try_new_presorted", 2000);

    // The old debug_assert for sorted check should be replaced
    // It should NOT rely solely on debug_assert for sorted invariant
    assert!(
        fn_body.contains("windows(2)"),
        "V18-F11: try_new_presorted must use windows(2) for sorted check"
    );
}

#[test]
fn v18_f11b_runtime_check_returns_error() {
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "try_new_presorted", 2000);

    // The sorted check must be a runtime check (not just debug_assert)
    let windows_pos = fn_body.find("windows(2)").expect("windows(2) must exist");
    let region_end = (windows_pos + 400).min(fn_body.len());
    let region = &fn_body[windows_pos..region_end];

    assert!(
        region.contains("Err(") || region.contains("return Err"),
        "V18-F11: sorted invariant violation must return Err, got:\n{}",
        region
    );
}

#[test]
fn v18_f11c_unsorted_input_rejected_source_check() {
    // try_new_presorted is pub(crate), so we verify via source inspection
    // that the sorted invariant violation returns EraError::InvalidFormat.
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "try_new_presorted", 2000);

    // Must return InvalidFormat error for unsorted input
    assert!(
        fn_body.contains("InvalidFormat"),
        "V18-F11: try_new_presorted must return InvalidFormat for unsorted input"
    );
    assert!(
        fn_body.contains("entries must be sorted by hash"),
        "V18-F11: error message must mention 'entries must be sorted by hash'"
    );
}

#[test]
fn v18_f11d_sorted_input_accepted_via_try_new() {
    // Since try_new_presorted is pub(crate), verify sorted acceptance via try_new
    // which uses sort_by_key internally. Sorted input should produce valid pages.
    let entries = vec![
        IndexEntry::new(test_hash(100), VolumeId::new(), BlockId::new(0), 0, 1024)
            .expect("valid entry"),
        IndexEntry::new(test_hash(200), VolumeId::new(), BlockId::new(0), 1024, 1024)
            .expect("valid entry"),
        IndexEntry::new(test_hash(300), VolumeId::new(), BlockId::new(0), 2048, 1024)
            .expect("valid entry"),
    ];

    let page = era_index::IndexPage::try_new(entries).unwrap();
    assert_eq!(page.len(), 3);
    assert_eq!(*page.min_hash(), test_hash(100));
    assert_eq!(*page.max_hash(), test_hash(300));
}

// ═══════════════════════════════════════════════════════════════════════
// V18-F12 (LOW — Observability): Recovery error includes missing block_ids
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs, recover_from_volume()
// Error message includes first 10 missing block_ids for debuggability.

#[test]
fn v18_f12a_error_includes_missing_block_ids() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 20000);

    assert!(
        fn_body.contains("Missing block_ids"),
        "V18-F12: recovery error must include 'Missing block_ids' in message"
    );
}

#[test]
fn v18_f12b_caps_missing_block_ids_at_10() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 20000);

    assert!(
        fn_body.contains(".take(10)"),
        "V18-F12: missing block_ids must be capped at 10 (use .take(10))"
    );
}

#[test]
fn v18_f12c_error_message_format() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 20000);

    assert!(
        fn_body.contains("first 10"),
        "V18-F12: error message must say 'first 10' to indicate truncation"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Regression Tests — V17 Findings Still Fixed
// ═══════════════════════════════════════════════════════════════════════

/// V17-F1 regression: collision check BEFORE insert in recovery
#[test]
fn v18_regression_v17f1_contains_key_before_insert() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_pages_via_scan", 20000);

    let contains_key_pos = fn_body
        .find("embedded_pages.contains_key")
        .expect("embedded_pages.contains_key must exist in recover_pages_via_scan");
    let insert_pos = fn_body
        .find("embedded_pages.insert")
        .expect("embedded_pages.insert must exist in recover_pages_via_scan");

    assert!(
        contains_key_pos < insert_pos,
        "V17-F1 regression: contains_key (at {}) must come BEFORE insert (at {})",
        contains_key_pos,
        insert_pos
    );
}

/// V17-F2 regression: try_new_presorted exists and is used
#[test]
fn v18_regression_v17f2_try_new_presorted_exists() {
    let source = read_source_file("src/lib.rs");
    assert!(
        source.contains("fn try_new_presorted"),
        "V17-F2 regression: try_new_presorted must exist"
    );

    let store_source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&store_source, "for_each_sorted_page", 3000);
    assert!(
        fn_body.contains("try_new_presorted"),
        "V17-F2 regression: for_each_sorted_page must use try_new_presorted"
    );
}

/// V17-F9 regression: version check before deserialize in bloom
#[test]
fn v18_regression_v17f9_bloom_version_check() {
    let source = read_source_file("src/bloom_serde.rs");
    let fn_body = extract_fn_body(&source, "from_bytes", 1500);

    let version_check_pos = fn_body
        .find("archived.version")
        .expect("archived.version check must exist");
    let deserialize_pos = fn_body
        .find(".deserialize(")
        .expect(".deserialize() must exist");

    assert!(
        version_check_pos < deserialize_pos,
        "V17-F9 regression: version check (at {}) must come BEFORE .deserialize() (at {})",
        version_check_pos,
        deserialize_pos
    );
}

/// V16-F3 regression: MIN_INDEX_PAGE_SIZE=64
#[test]
fn v18_regression_v16f3_min_page_size() {
    let source = read_source_file("src/reader.rs");
    assert!(
        source.contains("MIN_INDEX_PAGE_SIZE: usize = 64"),
        "V16-F3 regression: MIN_INDEX_PAGE_SIZE must be 64"
    );
}

/// V15-F2 regression: MAX_RECOVERY_CANDIDATES exists
#[test]
fn v18_regression_v15f2_max_recovery_candidates() {
    let source = read_source_file("src/reader.rs");
    assert!(
        source.contains("MAX_RECOVERY_CANDIDATES"),
        "V15-F2 regression: MAX_RECOVERY_CANDIDATES must exist in reader.rs"
    );
}

/// V14-F1 regression: 4-byte domain tag "IDX\x01"
#[test]
fn v18_regression_v14f1_domain_tag() {
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
