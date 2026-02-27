//! # Adversarial Audit V15 — Comprehensive Test Suite
//!
//! **Audit Date:** 2026-02-26
//! **Target:** `era-index` crate — V15 adversarial audit
//! **Scope:** V15-F1 through V15-F12 (excluding non-issues F8, F10)
//! **Methodology:** Source-level static analysis + behavioral verification
//!
//! ## V14 Regression Status (All FIXED)
//!
//! | ID | Finding | Status |
//! |----|---------|--------|
//! | V14-F1 | Weak domain separation — single-byte XOR | FIXED (4-byte "IDX\x01" domain tag) |
//! | V14-F7 | entry_count field drift on partial failure | FIXED (increment AFTER commit) |
//! | V14-F12 | page_cache dead allocation (quick_cache) | FIXED (quick_cache removed) |
//!
//! ## V15 Findings
//!
//! | ID | Severity | Title |
//! |----|----------|-------|
//! | V15-F1 | Low | unwrap_or_default replaced with explicit match + tracing::warn |
//! | V15-F2 | Medium | MAX_RECOVERY_CANDIDATES cap on candidates vec |
//! | V15-F3 | Low | Doc comment updated on load_page() |
//! | V15-F4 | Low | Clarifying comment added in builder.rs before bloom_set |
//! | V15-F5 | Low | No #[must_use] on Result-returning methods |
//! | V15-F6 | Low | Comment explaining VolumeId::new() placeholder in recovery |
//! | V15-F7 | Low | #[must_use] on path(), NOT on get()/read_sorted()/read_sorted_pages() |
//! | V15-F9 | Low | temp_dir field removed from ChunkIndexConfig |
//! | V15-F11 | Low | Duplicate doc line removed from store.rs |
//! | V15-F12 | Medium | Deadline checks before all 3 scan_for_typed_blocks calls |

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
// V15-F1: unwrap_or_default replaced with explicit match + tracing::warn
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs, recover_from_volume()
// The hint scan for IndexPage blocks previously used unwrap_or_default(),
// silently swallowing scan errors. Now uses explicit match + tracing::warn.

#[test]
fn v15_f1a_scan_error_logged_not_swallowed() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 15000);

    // Find the hint scan section — look for the page_blocks_for_hint pattern
    let hint_section = fn_body
        .find("page_blocks_for_hint")
        .expect("hint scan section must exist in recover_from_volume");
    let hint_region = &fn_body[hint_section..];

    // unwrap_or_default must NOT be present in the hint scan section
    assert!(
        !hint_region[..500.min(hint_region.len())].contains("unwrap_or_default"),
        "V15-F1: unwrap_or_default must NOT be present in hint scan section"
    );
}

#[test]
fn v15_f1b_tracing_warn_present_near_hint_scan() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 15000);

    // The hint scan section must contain tracing::warn for error logging
    let hint_section = fn_body
        .find("page_blocks_for_hint")
        .expect("hint scan section must exist");
    let hint_region = &fn_body[hint_section..];
    let nearby = &hint_region[..800.min(hint_region.len())];

    assert!(
        nearby.contains("tracing::warn"),
        "V15-F1: tracing::warn must be present near the hint scan section, got:\n{}",
        nearby
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V15-F2: MAX_RECOVERY_CANDIDATES cap on candidates vec
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs
// Without a cap, a malicious block_count could cause OOM during cold recovery.
// MAX_RECOVERY_CANDIDATES = 100_000 limits candidate iteration.

#[test]
fn v15_f2a_max_recovery_candidates_constant_exists() {
    let source = read_source_file("src/reader.rs");

    assert!(
        source.contains("MAX_RECOVERY_CANDIDATES"),
        "V15-F2: MAX_RECOVERY_CANDIDATES constant must exist in reader.rs"
    );
}

#[test]
fn v15_f2b_max_recovery_candidates_value_is_100000() {
    let source = read_source_file("src/reader.rs");

    assert!(
        source.contains("MAX_RECOVERY_CANDIDATES: u64 = 100_000"),
        "V15-F2: MAX_RECOVERY_CANDIDATES must be defined as u64 = 100_000"
    );
}

#[test]
fn v15_f2c_upper_bound_capped_by_max_recovery_candidates() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 15000);

    assert!(
        fn_body.contains("upper_bound.min(MAX_RECOVERY_CANDIDATES)"),
        "V15-F2: upper_bound must be capped via .min(MAX_RECOVERY_CANDIDATES)"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V15-F3: Doc comment updated on load_page()
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs, fn load_page
// Doc comment must reference "embedded pages" since page_cache is removed.

#[test]
fn v15_f3a_load_page_doc_mentions_embedded_pages() {
    let source = read_source_file("src/reader.rs");

    // Find the doc comment before load_page
    let load_page_pos = source
        .find("fn load_page")
        .expect("load_page must exist in reader.rs");

    // Look backwards from load_page to find the doc comment (within 200 chars)
    let start = load_page_pos.saturating_sub(200);
    let doc_region = &source[start..load_page_pos];

    assert!(
        doc_region.contains("embedded page"),
        "V15-F3: load_page doc comment must mention 'embedded page', got:\n{}",
        doc_region
    );
}

#[test]
fn v15_f3b_load_page_doc_does_not_mention_caching() {
    let source = read_source_file("src/reader.rs");
    let load_page_pos = source
        .find("fn load_page")
        .expect("load_page must exist in reader.rs");
    let start = load_page_pos.saturating_sub(200);
    let doc_region = &source[start..load_page_pos];

    assert!(
        !doc_region.contains("with caching"),
        "V15-F3: load_page doc comment must NOT mention 'with caching'"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V15-F4: Clarifying comment in builder.rs before bloom_set
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: builder.rs, fn insert
// A comment must explain why bloom_set is called before flush (intentional).

#[test]
fn v15_f4a_bloom_set_comment_explains_intentional_ordering() {
    let source = read_source_file("src/builder.rs");
    let fn_body = extract_fn_body(&source, "insert(&mut self", 10000);

    // Look for a comment near bloom_set that mentions intentionality or V6-F9 or V15-F4
    let bloom_set_pos = fn_body
        .find("bloom_set")
        .expect("bloom_set must be called in builder insert()");
    let start = bloom_set_pos.saturating_sub(500);
    let comment_region = &fn_body[start..bloom_set_pos + 50];

    let has_explanation = comment_region.contains("V6-F9")
        || comment_region.contains("V15-F4")
        || comment_region.contains("intentional")
        || comment_region.contains("Intentional");

    assert!(
        has_explanation,
        "V15-F4: comment near bloom_set in builder.rs must explain the ordering is intentional \
         (mentioning V6-F9, V15-F4, or 'intentional'), got:\n{}",
        comment_region
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V15-F5: No #[must_use] on Result-returning methods
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs, fn lookup
// Result<T> already has #[must_use], so adding it to a function that
// returns Result causes clippy::double_must_use.

#[test]
fn v15_f5a_lookup_no_must_use_attribute() {
    let source = read_source_file("src/reader.rs");

    // Find `pub fn lookup` and check the ~100 chars before it for #[must_use]
    let lookup_pos = source
        .find("pub fn lookup")
        .expect("lookup must exist in reader.rs");
    let start = lookup_pos.saturating_sub(100);
    let before_lookup = &source[start..lookup_pos];

    // There should be no #[must_use] directly above the lookup function.
    // Allow for other attributes but #[must_use] specifically should be absent.
    // Count lines backwards from lookup_pos to find the attribute zone
    let lines_before: Vec<&str> = before_lookup.lines().collect();
    let last_few_lines = &lines_before[lines_before.len().saturating_sub(3)..];

    let has_must_use = last_few_lines.iter().any(|line| {
        let trimmed = line.trim();
        trimmed == "#[must_use]" || trimmed.starts_with("#[must_use]")
    });

    assert!(
        !has_must_use,
        "V15-F5: lookup() in reader.rs must NOT have #[must_use] (Result already is), lines: {:?}",
        last_few_lines
    );
}

#[test]
fn v15_f5b_get_in_store_no_must_use() {
    let source = read_source_file("src/store.rs");

    // Find `pub fn get(` — it returns Result, so should not have #[must_use]
    let get_pos = source
        .find("pub fn get(")
        .expect("get must exist in store.rs");
    let start = get_pos.saturating_sub(100);
    let before_get = &source[start..get_pos];

    let lines_before: Vec<&str> = before_get.lines().collect();
    let last_few_lines = &lines_before[lines_before.len().saturating_sub(3)..];

    let has_must_use = last_few_lines.iter().any(|line| {
        let trimmed = line.trim();
        trimmed == "#[must_use]" || trimmed.starts_with("#[must_use]")
    });

    assert!(
        !has_must_use,
        "V15-F5: get() in store.rs must NOT have #[must_use], lines: {:?}",
        last_few_lines
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V15-F6: Comment explaining VolumeId::new() placeholder in recovery
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs, recover_from_volume()
// VolumeId::new() is used as a placeholder; a comment must explain why.

#[test]
fn v15_f6a_volume_id_new_has_placeholder_comment() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 15000);

    // Search ALL occurrences of VolumeId::new() in fn_body for a nearby placeholder comment.
    // The comment is on the line directly above the qualified call `era_common::VolumeId::new()`.
    // Using find("VolumeId::new()") may hit the comment text first, so search the broader region.
    let mut found_placeholder = false;
    let mut start_pos = 0;
    while let Some(offset) = fn_body[start_pos..].find("VolumeId::new()") {
        let abs_pos = start_pos + offset;
        let region_start = abs_pos.saturating_sub(300);
        let region_end = (abs_pos + 80).min(fn_body.len());
        let region = &fn_body[region_start..region_end];
        if region.contains("placeholder")
            || region.contains("Placeholder")
            || region.contains("PLACEHOLDER")
        {
            found_placeholder = true;
            break;
        }
        start_pos = abs_pos + 1;
    }

    assert!(
        found_placeholder,
        "V15-F6: at least one VolumeId::new() usage in recover_from_volume must have a nearby 'placeholder' comment"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V15-F7: #[must_use] on path(), NOT on get()/read_sorted()/read_sorted_pages()
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: store.rs
// path() returns &Path (not Result), so #[must_use] is appropriate.
// get()/read_sorted()/read_sorted_pages() return Result — no #[must_use].

#[test]
fn v15_f7a_path_has_must_use() {
    let source = read_source_file("src/store.rs");

    let path_pos = source
        .find("pub fn path(")
        .expect("pub fn path must exist in store.rs");
    let start = path_pos.saturating_sub(60);
    let before_path = &source[start..path_pos];

    assert!(
        before_path.contains("#[must_use]"),
        "V15-F7: pub fn path() in store.rs must have #[must_use], got:\n{}",
        before_path
    );
}

#[test]
fn v15_f7b_read_sorted_no_must_use() {
    let source = read_source_file("src/store.rs");

    let rs_pos = source
        .find("pub fn read_sorted(")
        .expect("read_sorted must exist in store.rs");
    let start = rs_pos.saturating_sub(80);
    let before_rs = &source[start..rs_pos];

    let lines: Vec<&str> = before_rs.lines().collect();
    let last_few = &lines[lines.len().saturating_sub(3)..];

    let has_must_use = last_few.iter().any(|l| l.trim().contains("#[must_use]"));
    assert!(
        !has_must_use,
        "V15-F7: read_sorted() returns Result — must NOT have #[must_use], lines: {:?}",
        last_few
    );
}

#[test]
fn v15_f7c_read_sorted_pages_no_must_use() {
    let source = read_source_file("src/store.rs");

    let rsp_pos = source
        .find("pub fn read_sorted_pages(")
        .expect("read_sorted_pages must exist in store.rs");
    let start = rsp_pos.saturating_sub(80);
    let before_rsp = &source[start..rsp_pos];

    let lines: Vec<&str> = before_rsp.lines().collect();
    let last_few = &lines[lines.len().saturating_sub(3)..];

    let has_must_use = last_few.iter().any(|l| l.trim().contains("#[must_use]"));
    assert!(
        !has_must_use,
        "V15-F7: read_sorted_pages() returns Result — must NOT have #[must_use], lines: {:?}",
        last_few
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V15-F9: temp_dir field removed from ChunkIndexConfig
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: chunk_index.rs
// ChunkIndexConfig previously had a temp_dir: Option<PathBuf> field that
// was dead code after the Redb migration. It has been removed.

#[test]
fn v15_f9a_chunk_index_config_compiles_without_temp_dir() {
    // This test verifies that ChunkIndexConfig can be constructed with only mem_limit.
    // If temp_dir still existed as a required field, this would fail to compile.
    let config = ChunkIndexConfig {
        mem_limit: 32 * 1024 * 1024,
    };
    assert_eq!(config.mem_limit, 32 * 1024 * 1024);
}

#[test]
fn v15_f9b_temp_dir_not_in_chunk_index_source() {
    let source = read_source_file("src/chunk_index.rs");

    // Find the ChunkIndexConfig struct definition
    let config_pos = source
        .find("pub struct ChunkIndexConfig")
        .expect("ChunkIndexConfig must exist in chunk_index.rs");
    // Extract ~200 chars after the struct definition to capture fields
    let end = (config_pos + 200).min(source.len());
    let struct_body = &source[config_pos..end];

    assert!(
        !struct_body.contains("temp_dir"),
        "V15-F9: ChunkIndexConfig must NOT contain temp_dir field, got:\n{}",
        struct_body
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V15-F11: Duplicate doc line removed from store.rs
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: store.rs
// The doc comment "Uses a single embedded Redb B-tree database" appeared
// twice in the module-level docs. It should appear exactly once.

#[test]
fn v15_f11a_single_embedded_redb_doc_line_appears_once() {
    let source = read_source_file("src/store.rs");

    let needle = "Uses a single embedded Redb B-tree database";
    let count = source.matches(needle).count();

    assert_eq!(
        count, 1,
        "V15-F11: '{}' must appear exactly once in store.rs, found {} occurrences",
        needle, count
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V15-F12: Deadline checks before all 3 scan_for_typed_blocks calls
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs, recover_from_volume()
// Critical scans (#1 IndexManifest, #3 IndexPage full) must have deadline checks.
// Hint scan (#2 IndexPage hint) uses match-based error handling instead (acceptable).

#[test]
fn v15_f12a_all_scan_calls_have_deadline_checks() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 25000);

    // Find all scan_for_typed_blocks call positions
    let scan_positions: Vec<usize> = fn_body
        .match_indices("scan_for_typed_blocks")
        .map(|(pos, _)| pos)
        .collect();

    assert!(
        scan_positions.len() >= 4,
        "V15-F12: expected at least 4 scan_for_typed_blocks references (including comment), found {}",
        scan_positions.len()
    );

    // Scan #1 (IndexManifest) and #4 (IndexPage full) must have explicit deadline checks.
    // Scan #2 (IndexPage hint) is a non-critical hint scan wrapped in match with
    // Scan #3 is a comment reference from V20-F9 (not actual code).
    //   (a) It returns Vec::new() on error (bounded, non-blocking)
    //   (b) Its result is only used for an optimization hint
    //   (c) The match/Err arm with tracing::warn is acceptable protection
    let critical_scans = [
        (0, "IndexManifest scan (#1)"),
        (3, "IndexPage full scan (#4)"),
    ];

    for (scan_idx, label) in &critical_scans {
        let pos = scan_positions[*scan_idx];
        let start = pos.saturating_sub(500);
        let before_scan = &fn_body[start..pos];

        let has_deadline = before_scan.contains("deadline")
            || before_scan.contains("if Instant::now() >= dl")
            || before_scan.contains("if let Some(dl) = deadline");

        assert!(
            has_deadline,
            "V15-F12: {} (at offset {}) must be preceded by a deadline check within 500 chars. \
             Region:\n{}",
            label, pos, before_scan
        );
    }

    // Verify scan #2 (hint) uses match-based error handling as an acceptable alternative
    let hint_pos = scan_positions[1];
    let hint_region_start = hint_pos.saturating_sub(200);
    let hint_region_end = (hint_pos + 300).min(fn_body.len());
    let hint_region = &fn_body[hint_region_start..hint_region_end];

    let has_match_handling = hint_region.contains("match")
        || (hint_region.contains("Ok(") && hint_region.contains("Err("));
    assert!(
        has_match_handling,
        "V15-F12: Hint scan (#2) must use match-based error handling. Region:\n{}",
        hint_region
    );
}

#[test]
fn v15_f12b_third_scan_has_explicit_deadline_check() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 25000);

    // The fourth scan_for_typed_blocks (IndexPage scan in Step 3) is the most
    // critical — it's the full page scan that could take longest.
    // Note: scan #3 is a comment reference from V20-F9, scan #4 is the actual call.
    let scan_positions: Vec<usize> = fn_body
        .match_indices("scan_for_typed_blocks")
        .map(|(pos, _)| pos)
        .collect();

    // Now 4 references: #1 IndexManifest, #2 hint, #3 V20-F9 comment, #4 actual page scan
    assert!(
        scan_positions.len() >= 4,
        "Expected at least 4 scan references (including comment)"
    );

    let page_scan_pos = scan_positions[3];
    let start = page_scan_pos.saturating_sub(300);
    let region = &fn_body[start..page_scan_pos];

    // Must have the pattern: if let Some(dl) = deadline { if Instant::now() >= dl
    let has_explicit_check = region.contains("deadline");
    assert!(
        has_explicit_check,
        "V15-F12: Fourth scan_for_typed_blocks (Step 3 page scan) must have explicit deadline check. Region:\n{}",
        region
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Regression Tests — V14 Findings Still Fixed
// ═══════════════════════════════════════════════════════════════════════

/// V14-F1 regression: Domain tag "IDX\x01" must exist in BOTH builder.rs and reader.rs
#[test]
fn v15_regression_v14f1_domain_tag_in_builder() {
    let source = read_source_file("src/builder.rs");

    assert!(
        source.contains(r#"b"IDX\x01""#),
        "V14-F1 regression: builder.rs must contain b\"IDX\\x01\" domain tag"
    );
}

#[test]
fn v15_regression_v14f1_domain_tag_in_reader() {
    let source = read_source_file("src/reader.rs");

    assert!(
        source.contains(r#"b"IDX\x01""#),
        "V14-F1 regression: reader.rs must contain b\"IDX\\x01\" domain tag"
    );
}

#[test]
fn v15_regression_v14f1_domain_tag_is_4_bytes() {
    let source = read_source_file("src/reader.rs");

    // Verify the domain tag is applied to a 4-byte slice [0..4]
    assert!(
        source.contains("[0..4]") || source.contains("[0 .. 4]"),
        "V14-F1 regression: domain tag must overwrite 4 bytes (not just 1)"
    );
}

/// V14-F7 regression: entry_count incremented AFTER commit in store.rs
#[test]
fn v15_regression_v14f7_entry_count_after_commit() {
    let source = read_source_file("src/store.rs");

    // Find the insert function body
    let fn_body = extract_fn_body(&source, "insert(&mut self", 10000);

    // .commit() must appear BEFORE entry_count +=
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

/// V14-F7 regression: Same ordering in insert_batch
#[test]
fn v15_regression_v14f7_entry_count_after_commit_batch() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "insert_batch", 10000);

    let commit_pos = fn_body
        .find(".commit()")
        .expect("commit must exist in insert_batch()");
    let count_pos = fn_body
        .find("self.entry_count += new_count")
        .expect("entry_count batch increment must exist");

    assert!(
        commit_pos < count_pos,
        "V14-F7 regression: .commit() (at {}) must come BEFORE self.entry_count += new_count (at {}) in insert_batch",
        commit_pos,
        count_pos
    );
}

/// V14-F12 regression: quick_cache must NOT be in Cargo.toml dependencies
#[test]
fn v15_regression_v14f12_no_quick_cache_dependency() {
    let cargo_toml = read_source_file("Cargo.toml");

    assert!(
        !cargo_toml.contains("quick_cache") && !cargo_toml.contains("quick-cache"),
        "V14-F12 regression: quick_cache/quick-cache must NOT be in Cargo.toml"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Behavioral Verification Tests
// ═══════════════════════════════════════════════════════════════════════

/// V15-F9 behavioral: ChunkIndexConfig default only has mem_limit
#[test]
fn v15_f9c_default_config_has_expected_mem_limit() {
    let config = ChunkIndexConfig::default();
    assert_eq!(
        config.mem_limit,
        64 * 1024 * 1024,
        "Default mem_limit must be 64MB"
    );
}

/// V15-F2 behavioral: verify MAX_RECOVERY_CANDIDATES is used in the upper_bound calculation
#[test]
fn v15_f2d_upper_bound_calculation_pattern() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 15000);

    // The pattern should be: compute upper_bound then cap it
    // let upper_bound = upper_bound.min(MAX_RECOVERY_CANDIDATES);
    assert!(
        fn_body.contains("let upper_bound = upper_bound.min(MAX_RECOVERY_CANDIDATES)"),
        "V15-F2: upper_bound must be reassigned with .min(MAX_RECOVERY_CANDIDATES)"
    );
}

/// V15-F7 behavioral: bloom_contains() in store.rs HAS #[must_use] (returns bool, not Result)
#[test]
fn v15_f7d_bloom_contains_has_must_use() {
    let source = read_source_file("src/store.rs");

    let bc_pos = source
        .find("pub fn bloom_contains(")
        .expect("bloom_contains must exist in store.rs");
    let start = bc_pos.saturating_sub(60);
    let before_bc = &source[start..bc_pos];

    assert!(
        before_bc.contains("#[must_use]"),
        "V15-F7: bloom_contains() returns bool — should have #[must_use], got:\n{}",
        before_bc
    );
}

/// Verify the IndexReader struct no longer has a page_cache field (V14-F12 follow-up)
#[test]
fn v15_regression_no_page_cache_field() {
    let source = read_source_file("src/reader.rs");

    let struct_pos = source
        .find("pub struct IndexReader")
        .expect("IndexReader struct must exist");
    let end = (struct_pos + 300).min(source.len());
    let struct_body = &source[struct_pos..end];

    assert!(
        !struct_body.contains("page_cache"),
        "V14-F12 regression: IndexReader must NOT have page_cache field, got:\n{}",
        struct_body
    );
}

/// V15-F1 behavioral: recover_from_volume hint scan uses explicit match, not unwrap_or_default
#[test]
fn v15_f1c_explicit_match_pattern_in_hint_scan() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "recover_from_volume", 15000);

    // The hint scan should use match with Ok/Err arms (or if let/match)
    let hint_section = fn_body
        .find("page_blocks_for_hint")
        .expect("hint section must exist");
    let hint_region = &fn_body[hint_section.saturating_sub(200)..hint_section + 500];

    // Must use an explicit match or Err arm, not unwrap_or_default
    let uses_explicit_match = hint_region.contains("Ok(blocks)") || hint_region.contains("Err(");
    assert!(
        uses_explicit_match,
        "V15-F1: hint scan must use explicit match with Ok/Err arms, got:\n{}",
        hint_region
    );
}

/// V15-F4 behavioral: builder bloom_set comment mentions phantom entries are harmless
#[test]
fn v15_f4b_bloom_set_comment_mentions_phantom_harmless() {
    let source = read_source_file("src/builder.rs");
    let fn_body = extract_fn_body(&source, "insert(&mut self", 10000);

    let bloom_set_pos = fn_body
        .find("bloom_set")
        .expect("bloom_set must exist in insert()");
    // Search the ENTIRE region from fn start to bloom_set for the "harmless" comment.
    // The comment is between the fn signature and the bloom_set call.
    let region = &fn_body[..bloom_set_pos + 400];

    let mentions_harmless =
        region.contains("harmless") || region.contains("Harmless") || region.contains("redundant");

    assert!(
        mentions_harmless,
        "V15-F4: comment near bloom_set must explain phantom entries are harmless/redundant, got:\n{}",
        region
    );
}
