//! # Adversarial Audit V25 — Comprehensive Test Suite
//!
//! **Audit Date:** 2026-02-27
//! **Target:** `era-index` crate — V25 adversarial audit
//! **Scope:** V25-F1 through V25-F4 + V24 regressions + carry-forwards
//! **Methodology:** Source-level static analysis + behavioral verification
//!
//! ## V24 Regression Status (All FIXED)
//!
//! | ID | Finding | Status |
//! |----|---------|--------|
//! | V24-F1 | IndexEntry pub fields → pub(crate) | FIXED |
//! | V24-F2 | PagePointer pub fields → pub(crate) | FIXED |
//! | V24-F5 | Integer overflow in recovery (saturating arithmetic) | FIXED |
//! | V24-F6 | Timeout in decrypt loop (deadline checkpoint) | FIXED |
//! | V24-F7 | MAX_META_PAGES consolidation | FIXED |
//! | V24-F8 | Bloom pre-deserialize validation | FIXED |
//! | V24-F9 | SipHash degenerate key check | FIXED |
//! | V24-F10 | rkyv buffer pre-validation | FIXED |
//!
//! ## V25 Findings
//!
//! | ID | Severity | Title |
//! |----|----------|-------|
//! | V25-F1 | LOW | IndexLocation accessor methods for encapsulation parity |
//! | V25-F2 | LOW | MAX_BLOOM_BITMAP_SIZE consolidation (module-level const) |
//! | V25-F3 | LOW | MAX_BLOOM_ITEMS consolidation (single pub(crate) const in lib.rs) |
//! | V25-F4 | MEDIUM | ChunkIndexConfig mem_limit validation (zero + absurdly large) |

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
// V25-F1: IndexLocation encapsulation — accessor methods
// ═══════════════════════════════════════════════════════════════════════

// V25-F1 (LOW): IndexLocation lacked accessor methods despite IndexEntry and
// PagePointer having them (V24-F1, V24-F2). Added volume_id(), block_id(),
// offset(), length() accessor methods for encapsulation parity.
// SOURCE: reader.rs, struct IndexLocation + impl IndexLocation

#[test]
fn v25_f1a_index_location_has_impl_block() {
    let source = read_source_file("src/reader.rs");

    assert!(
        source.contains("impl IndexLocation"),
        "V25-F1: reader.rs must have an impl IndexLocation block"
    );
}

#[test]
fn v25_f1b_index_location_has_accessors() {
    let source = read_source_file("src/reader.rs");
    let impl_body = extract_fn_body(&source, "impl IndexLocation", 1200);

    for accessor in &[
        "fn volume_id(&self)",
        "fn block_id(&self)",
        "fn offset(&self)",
        "fn length(&self)",
    ] {
        assert!(
            impl_body.contains(accessor),
            "V25-F1: IndexLocation must have accessor method: {}",
            accessor
        );
    }
}

#[test]
fn v25_f1c_accessors_return_correct_values() {
    let vol = VolumeId::new();
    let loc = IndexLocation {
        volume_id: vol,
        block_id: BlockId::new(42),
        offset: 100,
        length: 4096,
    };

    assert_eq!(
        loc.volume_id(),
        vol,
        "V25-F1: volume_id() accessor must return correct value"
    );
    assert_eq!(
        loc.block_id(),
        BlockId::new(42),
        "V25-F1: block_id() accessor must return correct value"
    );
    assert_eq!(
        loc.offset(),
        100u32,
        "V25-F1: offset() accessor must return correct value"
    );
    assert_eq!(
        loc.length(),
        4096u32,
        "V25-F1: length() accessor must return correct value"
    );
}

#[test]
fn v25_f1d_fix_comment_present() {
    let source = read_source_file("src/reader.rs");

    assert!(
        source.contains("V25-F1 fix:"),
        "V25-F1: reader.rs must contain V25-F1 fix comment"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V25-F2: MAX_BLOOM_BITMAP_SIZE consolidation (module-level const)
// ═══════════════════════════════════════════════════════════════════════

// V25-F2 (LOW): MAX_BLOOM_BITMAP_SIZE was defined as a function-scoped constant
// inside from_bytes() and validate_archived(). Consolidated to a single
// module-level const to eliminate duplication and ensure consistency.
// SOURCE: bloom_serde.rs

#[test]
fn v25_f2a_single_module_level_definition() {
    let source = read_source_file("src/bloom_serde.rs");

    // Count non-comment lines containing `const MAX_BLOOM_BITMAP_SIZE`
    let def_count = source
        .lines()
        .filter(|l| {
            let trimmed = l.trim();
            !trimmed.starts_with("//") && trimmed.contains("const MAX_BLOOM_BITMAP_SIZE")
        })
        .count();

    assert_eq!(
        def_count, 1,
        "V25-F2: bloom_serde.rs must have exactly 1 MAX_BLOOM_BITMAP_SIZE definition, found {}",
        def_count
    );
}

#[test]
fn v25_f2b_no_function_scoped_definitions() {
    let source = read_source_file("src/bloom_serde.rs");

    // Find all `const MAX_BLOOM_BITMAP_SIZE` lines and verify they appear
    // before the first `fn ` line (i.e., at module level, not inside a function)
    let first_fn_line = source
        .lines()
        .enumerate()
        .find(|(_, l)| {
            let trimmed = l.trim();
            !trimmed.starts_with("//")
                && !trimmed.starts_with("///")
                && (trimmed.starts_with("fn ") || trimmed.starts_with("pub fn "))
        })
        .map(|(i, _)| i);

    let const_lines: Vec<usize> = source
        .lines()
        .enumerate()
        .filter(|(_, l)| {
            let trimmed = l.trim();
            !trimmed.starts_with("//") && trimmed.contains("const MAX_BLOOM_BITMAP_SIZE")
        })
        .map(|(i, _)| i)
        .collect();

    assert!(
        !const_lines.is_empty(),
        "V25-F2: bloom_serde.rs must contain MAX_BLOOM_BITMAP_SIZE definition"
    );

    if let Some(first_fn) = first_fn_line {
        for line_num in &const_lines {
            assert!(
                *line_num < first_fn,
                "V25-F2: MAX_BLOOM_BITMAP_SIZE at line {} must be at module level (before first fn at line {})",
                line_num + 1,
                first_fn + 1
            );
        }
    }
}

#[test]
fn v25_f2c_fix_comment_present() {
    let source = read_source_file("src/bloom_serde.rs");

    assert!(
        source.contains("V25-F2 fix:"),
        "V25-F2: bloom_serde.rs must contain V25-F2 fix comment"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V25-F3: MAX_BLOOM_ITEMS consolidation (single pub(crate) const in lib.rs)
// ═══════════════════════════════════════════════════════════════════════

// V25-F3 (LOW): MAX_BLOOM_ITEMS was duplicated in builder.rs and store.rs.
// Consolidated to a single pub(crate) const in lib.rs. builder.rs and store.rs
// now import via `use crate::MAX_BLOOM_ITEMS`.
// SOURCE: lib.rs, builder.rs, store.rs

#[test]
fn v25_f3a_single_definition_in_lib() {
    let source = read_source_file("src/lib.rs");

    let def_lines: Vec<&str> = source
        .lines()
        .filter(|l| {
            let trimmed = l.trim();
            !trimmed.starts_with("//") && trimmed.contains("const MAX_BLOOM_ITEMS")
        })
        .collect();

    assert_eq!(
        def_lines.len(),
        1,
        "V25-F3: lib.rs must have exactly 1 MAX_BLOOM_ITEMS definition, found {}",
        def_lines.len()
    );

    assert!(
        def_lines[0].contains("pub(crate)"),
        "V25-F3: MAX_BLOOM_ITEMS must be pub(crate), found: {}",
        def_lines[0].trim()
    );
}

#[test]
fn v25_f3b_no_duplicate_in_builder() {
    let source = read_source_file("src/builder.rs");

    let def_count = source
        .lines()
        .filter(|l| {
            let trimmed = l.trim();
            !trimmed.starts_with("//") && trimmed.contains("const MAX_BLOOM_ITEMS")
        })
        .count();

    assert_eq!(
        def_count, 0,
        "V25-F3: builder.rs must have 0 MAX_BLOOM_ITEMS definitions (uses import), found {}",
        def_count
    );
}

#[test]
fn v25_f3c_no_duplicate_in_store() {
    let source = read_source_file("src/store.rs");

    let def_count = source
        .lines()
        .filter(|l| {
            let trimmed = l.trim();
            !trimmed.starts_with("//") && trimmed.contains("const MAX_BLOOM_ITEMS")
        })
        .count();

    assert_eq!(
        def_count, 0,
        "V25-F3: store.rs must have 0 MAX_BLOOM_ITEMS definitions (uses import), found {}",
        def_count
    );
}

#[test]
fn v25_f3d_fix_comment_present() {
    let source = read_source_file("src/lib.rs");

    assert!(
        source.contains("V25-F3 fix:"),
        "V25-F3: lib.rs must contain V25-F3 fix comment"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V25-F4: ChunkIndexConfig mem_limit validation
// ═══════════════════════════════════════════════════════════════════════

// V25-F4 (MEDIUM): ChunkIndex::new() accepted any mem_limit including 0 and
// usize::MAX. Zero causes division-by-zero in bloom sizing. Absurdly large
// values cause allocation failures. Added validation: reject 0 and values
// exceeding 64 GiB.
// SOURCE: chunk_index.rs, ChunkIndex::new()

#[test]
fn v25_f4a_zero_mem_limit_rejected() {
    let config = ChunkIndexConfig { mem_limit: 0 };
    let result = ChunkIndex::new(config);

    assert!(
        result.is_err(),
        "V25-F4: ChunkIndex::new with mem_limit=0 must return Err"
    );
}

#[test]
fn v25_f4b_absurdly_large_mem_limit_rejected() {
    let config = ChunkIndexConfig {
        mem_limit: usize::MAX,
    };
    let result = ChunkIndex::new(config);

    assert!(
        result.is_err(),
        "V25-F4: ChunkIndex::new with mem_limit=usize::MAX must return Err"
    );
}

#[test]
fn v25_f4c_valid_mem_limit_accepted() {
    let config = ChunkIndexConfig {
        mem_limit: 64 * 1024 * 1024, // 64 MiB
    };
    let result = ChunkIndex::new(config);

    assert!(
        result.is_ok(),
        "V25-F4: ChunkIndex::new with mem_limit=64MiB must succeed"
    );
}

#[test]
fn v25_f4d_fix_comment_present() {
    let source = read_source_file("src/chunk_index.rs");

    assert!(
        source.contains("V25-F4 fix:"),
        "V25-F4: chunk_index.rs must contain V25-F4 fix comment"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V24 Regression Tests — Verify V24 fixes remain intact
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v25_regression_v24_f1_index_entry_encapsulation() {
    // V24-F1: IndexEntry fields must still be pub(crate)
    let source = read_source_file("src/lib.rs");
    let struct_body = extract_struct_body(&source, "pub struct IndexEntry", 500);

    for field in &["hash:", "volume_id:", "block_id:", "offset:", "length:"] {
        let field_line = struct_body
            .lines()
            .find(|l| l.contains(field) && !l.trim_start().starts_with("//"))
            .unwrap_or_else(|| panic!("Field {} not found in IndexEntry", field));

        assert!(
            field_line.contains("pub(crate)"),
            "Regression V24-F1: IndexEntry field '{}' must be pub(crate), found: {}",
            field,
            field_line.trim()
        );
    }
}

#[test]
fn v25_regression_v24_f2_page_pointer_encapsulation() {
    // V24-F2: PagePointer fields must still be pub(crate)
    let source = read_source_file("src/lib.rs");
    let struct_body = extract_struct_body(&source, "pub struct PagePointer", 400);

    for field in &["min_hash:", "max_hash:", "block_id:"] {
        let field_line = struct_body
            .lines()
            .find(|l| l.contains(field) && !l.trim_start().starts_with("//"))
            .unwrap_or_else(|| panic!("Field {} not found in PagePointer", field));

        assert!(
            field_line.contains("pub(crate)"),
            "Regression V24-F2: PagePointer field '{}' must be pub(crate), found: {}",
            field,
            field_line.trim()
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// End-to-end behavioral test
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v25_e2e_full_index_lifecycle_with_accessors() {
    // Full lifecycle: create → insert → finalize → lookup → verify V25-F1 accessors
    let config = ChunkIndexConfig {
        mem_limit: 64 * 1024 * 1024,
    };
    let mut tree = ChunkIndex::new(config).expect("ChunkIndex creation should succeed");

    for i in 0..200u64 {
        let entry = make_entry(i);
        tree.insert(entry).expect("insert should succeed");
    }

    // Bloom should work during Building state
    assert!(tree.bloom_contains(&test_hash(100)));
    assert!(!tree.bloom_contains(&test_hash(9999)));

    // Finalize transitions to Finalized state
    let reader = tree.finalize().expect("finalize should succeed");

    // Bloom should work during Finalized state
    assert!(reader.bloom_contains(&test_hash(100)));
    assert!(!reader.bloom_contains(&test_hash(9999)));

    // Lookup should find all inserted entries — verify V25-F1 accessors work
    for i in 0..200u64 {
        let result = reader
            .lookup(&test_hash(i))
            .expect("lookup should not error");
        assert!(result.is_some(), "V25-E2E: lookup must find entry {}", i);
        let loc = result.expect("entry must exist");
        // V25-F1: Use accessor methods instead of direct field access
        assert_eq!(
            loc.block_id(),
            BlockId::new(i),
            "V25-E2E: block_id() accessor must match"
        );
        assert_eq!(loc.offset(), 0u32, "V25-E2E: offset() accessor must match");
        assert_eq!(
            loc.length(),
            4096u32,
            "V25-E2E: length() accessor must match"
        );
    }

    // Lookup should not find absent entries
    let result = reader
        .lookup(&test_hash(9999))
        .expect("lookup should not error");
    assert!(
        result.is_none(),
        "V25-E2E: lookup must not find absent entry"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Carry-forward documentation tests
// ═══════════════════════════════════════════════════════════════════════

// V25-CF1: IndexBuilder::finalize() runs on an async thread via spawn_blocking.
// This is by design — Redb I/O and bloom serialization are CPU-heavy.
// Documenting as carry-forward: verified the function exists.

#[test]
fn v25_cf1_builder_finalize_on_async_thread() {
    let source = read_source_file("src/builder.rs");

    assert!(
        source.contains("fn finalize"),
        "V25-CF1: builder.rs must contain a finalize function"
    );
}

// V25-CF2: ChunkIndex::finalize() materializes ALL pages in memory via
// read_sorted_pages(). For the volume-write path, builder.rs uses streaming
// for_each_sorted_page() which is O(ENTRIES_PER_PAGE) memory per page.
// Documenting as carry-forward: verified the function exists.

#[test]
fn v25_cf2_chunk_index_materializes_pages() {
    let source = read_source_file("src/chunk_index.rs");

    assert!(
        source.contains("fn finalize"),
        "V25-CF2: chunk_index.rs must contain a finalize function"
    );
}
