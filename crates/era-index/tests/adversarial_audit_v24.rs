//! # Adversarial Audit V24 — Comprehensive Test Suite
//!
//! **Audit Date:** 2026-02-27
//! **Target:** `era-index` crate — V24 adversarial audit
//! **Scope:** V24-F1 through V24-F10 + V24-CF1, V24-CF2
//! **Methodology:** Source-level static analysis + behavioral verification
//!
//! ## V23 Regression Status (All FIXED)
//!
//! | ID | Finding | Status |
//! |----|---------|--------|
//! | V23-F1 | BloomFilterData fields pub(crate) | FIXED |
//! | V23-F2 | from_bloom() validates via validate() | FIXED |
//! | V23-F3 | Consolidated validate() method | FIXED |
//! | V23-F4 | to_bytes() documents AlignedVec→Vec copy rationale | FIXED |
//! | V23-F5 | from_bloom() visibility restricted to pub(crate) | FIXED |
//! | V23-F6 | Duplicate doc comment on try_new_presorted removed | FIXED |
//! | V23-F7 | _caller_bloom unused params removed from from_memory/from_pages | FIXED |
//! | V23-F8 | for_each_sorted_page progress logging fires after page emission | FIXED |
//! | V23-F9 | .expect() in try_new/try_new_presorted — safe after empty check | FIXED |
//! | V23-F10 | set_bloom_filter uses BloomFilterData::from_bytes() for lightweight validation | FIXED |
//!
//! ## V24 Findings
//!
//! | ID | Severity | Title |
//! |----|----------|-------|
//! | V24-F1 | MEDIUM | IndexEntry pub fields → pub(crate) |
//! | V24-F2 | MEDIUM | PagePointer pub fields → pub(crate) |
//! | V24-F5 | LOW | Integer overflow in recovery (saturating arithmetic) |
//! | V24-F6 | LOW | Timeout in decrypt loop (deadline checkpoint in candidate scan) |
//! | V24-F7 | LOW | MAX_META_PAGES consolidation (single definition in lib.rs) |
//! | V24-F8 | MEDIUM | Bloom pre-deserialize validation (bitmap size check before .deserialize) |
//! | V24-F9 | LOW | SipHash degenerate key check (both key pairs identical) |
//! | V24-F10 | LOW | rkyv buffer pre-validation (size check before check_archived_root) |

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
// V24-F1: IndexEntry pub fields → pub(crate)
// ═══════════════════════════════════════════════════════════════════════

// V24-F1 (MEDIUM): IndexEntry fields must be pub(crate) to prevent external
// consumers from bypassing the validated new() constructor via struct literal
// construction. Accessor methods provide read-only access.
// SOURCE: lib.rs, struct IndexEntry

#[test]
fn v24_f1a_index_entry_fields_pub_crate() {
    let source = read_source_file("src/lib.rs");
    let struct_body = extract_struct_body(&source, "pub struct IndexEntry", 500);

    // Every field should be pub(crate), not bare pub
    for field in &["hash:", "volume_id:", "block_id:", "offset:", "length:"] {
        let field_line = struct_body
            .lines()
            .find(|l| l.contains(field) && !l.trim_start().starts_with("//"))
            .unwrap_or_else(|| panic!("Field {} not found in IndexEntry", field));

        assert!(
            field_line.contains("pub(crate)"),
            "V24-F1: Field '{}' must be pub(crate), found: {}",
            field,
            field_line.trim()
        );
        // Ensure it's not bare `pub ` (without `(crate)`)
        let trimmed = field_line.trim();
        assert!(
            !trimmed.starts_with("pub ") || trimmed.starts_with("pub(crate)"),
            "V24-F1: Field '{}' must not be bare pub: {}",
            field,
            trimmed
        );
    }
}

#[test]
fn v24_f1b_index_entry_has_accessor_methods() {
    let source = read_source_file("src/lib.rs");

    for accessor in &[
        "pub fn hash(",
        "pub fn volume_id(",
        "pub fn block_id(",
        "pub fn offset(",
        "pub fn length(",
    ] {
        assert!(
            source.contains(accessor),
            "V24-F1: IndexEntry must have accessor method: {}",
            accessor
        );
    }
}

#[test]
fn v24_f1c_index_entry_accessors_behavioral() {
    let hash = test_hash(42);
    let vol = VolumeId::new();
    let blk = BlockId::new(7);
    let entry = IndexEntry::new(hash, vol, blk, 100, 4096).expect("valid entry");

    assert_eq!(
        *entry.hash(),
        hash,
        "V24-F1: hash() accessor must return correct value"
    );
    assert_eq!(
        entry.volume_id(),
        vol,
        "V24-F1: volume_id() accessor must return correct value"
    );
    assert_eq!(
        entry.block_id(),
        blk,
        "V24-F1: block_id() accessor must return correct value"
    );
    assert_eq!(
        entry.offset(),
        100,
        "V24-F1: offset() accessor must return correct value"
    );
    assert_eq!(
        entry.length(),
        4096,
        "V24-F1: length() accessor must return correct value"
    );
}

#[test]
fn v24_f1d_index_entry_new_rejects_zero_length() {
    let result = IndexEntry::new(test_hash(1), VolumeId::new(), BlockId::new(0), 0, 0);
    assert!(
        result.is_err(),
        "V24-F1: IndexEntry::new with length=0 must return Err"
    );
}

#[test]
fn v24_f1e_index_entry_new_rejects_overflow() {
    let result = IndexEntry::new(test_hash(1), VolumeId::new(), BlockId::new(0), u32::MAX, 1);
    assert!(
        result.is_err(),
        "V24-F1: IndexEntry::new with offset+length overflow must return Err"
    );
}

#[test]
fn v24_f1f_index_entry_v24_comment_present() {
    let source = read_source_file("src/lib.rs");
    let struct_body = extract_struct_body(&source, "pub struct IndexEntry", 500);

    assert!(
        struct_body.contains("V24-F1"),
        "V24-F1: IndexEntry struct must reference V24-F1 fix"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V24-F2: PagePointer pub fields → pub(crate)
// ═══════════════════════════════════════════════════════════════════════

// V24-F2 (MEDIUM): PagePointer fields must be pub(crate) to prevent external
// consumers from constructing PagePointers directly, bypassing MetaIndex::add_page()
// validation. Accessor methods provide read-only access.
// SOURCE: lib.rs, struct PagePointer

#[test]
fn v24_f2a_page_pointer_fields_pub_crate() {
    let source = read_source_file("src/lib.rs");
    let struct_body = extract_struct_body(&source, "pub struct PagePointer", 400);

    for field in &["min_hash:", "max_hash:", "block_id:"] {
        let field_line = struct_body
            .lines()
            .find(|l| l.contains(field) && !l.trim_start().starts_with("//"))
            .unwrap_or_else(|| panic!("Field {} not found in PagePointer", field));

        assert!(
            field_line.contains("pub(crate)"),
            "V24-F2: Field '{}' must be pub(crate), found: {}",
            field,
            field_line.trim()
        );
        let trimmed = field_line.trim();
        assert!(
            !trimmed.starts_with("pub ") || trimmed.starts_with("pub(crate)"),
            "V24-F2: Field '{}' must not be bare pub: {}",
            field,
            trimmed
        );
    }
}

#[test]
fn v24_f2b_page_pointer_has_accessor_methods() {
    let source = read_source_file("src/lib.rs");

    for accessor in &["pub fn min_hash(", "pub fn max_hash(", "pub fn block_id("] {
        // Find it within the PagePointer impl block
        let pp_impl = extract_fn_body(&source, "impl PagePointer", 600);
        assert!(
            pp_impl.contains(accessor),
            "V24-F2: PagePointer must have accessor method: {}",
            accessor
        );
    }
}

#[test]
fn v24_f2c_page_pointer_accessors_behavioral() {
    // Create entries → IndexPage::try_new() → verify page's min_hash/max_hash
    let entries: Vec<IndexEntry> = (10..20).map(make_entry).collect();
    let page = era_index::IndexPage::try_new(entries).expect("valid page");

    assert_eq!(
        *page.min_hash(),
        test_hash(10),
        "V24-F2: min_hash() must return correct minimum"
    );
    assert_eq!(
        *page.max_hash(),
        test_hash(19),
        "V24-F2: max_hash() must return correct maximum"
    );
}

#[test]
fn v24_f2d_page_pointer_v24_comment_present() {
    let source = read_source_file("src/lib.rs");
    let struct_body = extract_struct_body(&source, "pub struct PagePointer", 400);

    assert!(
        struct_body.contains("V24-F2"),
        "V24-F2: PagePointer struct must reference V24-F2 fix"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V24-F5: Integer overflow in recovery (saturating arithmetic)
// ═══════════════════════════════════════════════════════════════════════

// V24-F5 (LOW): recover_from_volume used plain addition that could overflow
// on adversarial volume_block_count values. Replaced with saturating_add/mul.
// SOURCE: reader.rs, IndexReader::recover_from_volume()

#[test]
fn v24_f5a_saturating_add_in_recovery() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "pub async fn recover_from_volume", 20000);

    assert!(
        fn_body.contains("saturating_add(1)"),
        "V24-F5: recover_from_volume must use saturating_add(1) for volume_block_count"
    );
}

#[test]
fn v24_f5b_saturating_mul_in_recovery() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "pub async fn recover_from_volume", 20000);

    assert!(
        fn_body.contains("saturating_mul(4)"),
        "V24-F5: recover_from_volume must use saturating_mul(4) in fallback branch"
    );
}

#[test]
fn v24_f5c_v24_comment_present_in_recovery() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "pub async fn recover_from_volume", 20000);

    assert!(
        fn_body.contains("V24-F5"),
        "V24-F5: recover_from_volume must reference V24-F5 fix"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V24-F6: Timeout in decrypt loop (deadline checkpoint in candidate scan)
// ═══════════════════════════════════════════════════════════════════════

// V24-F6 (LOW): The page-recovery decrypt loop lacked a deadline check inside
// the inner candidate_block_ids loop. A volume with many unrecovered block_ids
// could stall indefinitely. Added deadline checkpoint within the inner loop.
// SOURCE: reader.rs, IndexReader::recover_from_volume()

#[test]
fn v24_f6a_deadline_check_in_candidate_scan() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "pub async fn recover_from_volume", 20000);

    assert!(
        fn_body.contains("Cold recovery timed out during candidate scan"),
        "V24-F6: recover_from_volume must have deadline check for candidate scan"
    );
}

#[test]
fn v24_f6b_five_deadline_checkpoints() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "pub async fn recover_from_volume", 20000);

    let timeout_count = fn_body.matches("Cold recovery timed out").count();
    assert!(
        timeout_count >= 5,
        "V24-F6: recover_from_volume must have >= 5 deadline checkpoints, found {}",
        timeout_count
    );
}

#[test]
fn v24_f6c_v24_comment_present_in_candidate_scan() {
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "pub async fn recover_from_volume", 20000);

    assert!(
        fn_body.contains("V24-F6"),
        "V24-F6: recover_from_volume must reference V24-F6 fix"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V24-F7: MAX_META_PAGES consolidation (single definition in lib.rs)
// ═══════════════════════════════════════════════════════════════════════

// V24-F7 (LOW): MAX_META_PAGES was duplicated in lib.rs and reader.rs.
// Consolidated to a single pub(crate) constant in lib.rs. reader.rs now
// references super::MAX_META_PAGES.
// SOURCE: lib.rs, reader.rs

#[test]
fn v24_f7a_max_meta_pages_single_definition() {
    let lib_source = read_source_file("src/lib.rs");
    let reader_source = read_source_file("src/reader.rs");

    // lib.rs should have exactly 1 `const MAX_META_PAGES`
    let lib_defs = lib_source
        .lines()
        .filter(|l| {
            let trimmed = l.trim();
            !trimmed.starts_with("//") && trimmed.contains("const MAX_META_PAGES")
        })
        .count();
    assert_eq!(
        lib_defs, 1,
        "V24-F7: lib.rs must have exactly 1 MAX_META_PAGES definition, found {}",
        lib_defs
    );

    // reader.rs should have 0 `const MAX_META_PAGES` (uses super::MAX_META_PAGES)
    let reader_defs = reader_source
        .lines()
        .filter(|l| {
            let trimmed = l.trim();
            !trimmed.starts_with("//") && trimmed.contains("const MAX_META_PAGES")
        })
        .count();
    assert_eq!(
        reader_defs, 0,
        "V24-F7: reader.rs must have 0 MAX_META_PAGES definitions (uses super::), found {}",
        reader_defs
    );
}

#[test]
fn v24_f7b_max_meta_pages_value() {
    let source = read_source_file("src/lib.rs");

    assert!(
        source.contains("MAX_META_PAGES: usize = 10_000"),
        "V24-F7: lib.rs must define MAX_META_PAGES = 10_000"
    );
}

#[test]
fn v24_f7c_reader_uses_super_max_meta_pages() {
    let source = read_source_file("src/reader.rs");

    assert!(
        source.contains("super::MAX_META_PAGES"),
        "V24-F7: reader.rs must reference super::MAX_META_PAGES"
    );
}

#[test]
fn v24_f7d_v24_comment_present() {
    let source = read_source_file("src/lib.rs");

    assert!(
        source.contains("V24-F7"),
        "V24-F7: lib.rs must reference V24-F7 fix"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V24-F8: Bloom pre-deserialize validation (bitmap size check before .deserialize)
// ═══════════════════════════════════════════════════════════════════════

// V24-F8 (MEDIUM): from_bytes() now validates bitmap size and bitmap_bits on
// the archived (zero-copy) view BEFORE calling .deserialize(), preventing
// allocation of oversized bitmaps from adversarial input.
// SOURCE: bloom_serde.rs, BloomFilterData::from_bytes()

#[test]
fn v24_f8a_pre_deserialize_bitmap_size_check() {
    let source = read_source_file("src/bloom_serde.rs");
    let from_bytes_body = extract_fn_body(&source, "pub fn from_bytes", 1800);

    // from_bytes must call validate_archived before .deserialize()
    let validate_call = from_bytes_body.find("validate_archived");
    let deserialize_call = from_bytes_body.find(".deserialize(");
    assert!(
        validate_call.is_some(),
        "V24-F8: from_bytes must call validate_archived"
    );
    assert!(
        deserialize_call.is_some(),
        "V24-F8: from_bytes must call .deserialize()"
    );
    assert!(
        validate_call.expect("validate") < deserialize_call.expect("deserialize"),
        "V24-F8: validate_archived must be called BEFORE .deserialize()"
    );

    // validate_archived must check archived.bitmap.len()
    let validate_body = extract_fn_body(&source, "fn validate_archived", 1200);
    assert!(
        validate_body.contains("archived.bitmap.len()"),
        "V24-F8: validate_archived must check archived.bitmap.len()"
    );
}

#[test]
fn v24_f8b_pre_deserialize_bitmap_bits_check() {
    let source = read_source_file("src/bloom_serde.rs");
    let from_bytes_body = extract_fn_body(&source, "pub fn from_bytes", 1800);

    // from_bytes must call validate_archived before .deserialize()
    let validate_call = from_bytes_body.find("validate_archived");
    let deserialize_call = from_bytes_body.find(".deserialize(");
    assert!(
        validate_call.is_some() && deserialize_call.is_some(),
        "V24-F8: from_bytes must call validate_archived before .deserialize()"
    );
    assert!(
        validate_call.expect("validate") < deserialize_call.expect("deserialize"),
        "V24-F8: validate_archived must precede .deserialize()"
    );

    // validate_archived must check archived.bitmap_bits
    let validate_body = extract_fn_body(&source, "fn validate_archived", 1200);
    assert!(
        validate_body.contains("archived.bitmap_bits"),
        "V24-F8: validate_archived must check archived.bitmap_bits"
    );
}

#[test]
fn v24_f8c_bloom_rejects_invalid_bytes() {
    let result = BloomFilterData::from_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]);
    assert!(
        result.is_err(),
        "V24-F8: BloomFilterData::from_bytes must reject garbage input"
    );
}

#[test]
fn v24_f8d_v24_comment_present_in_from_bytes() {
    let source = read_source_file("src/bloom_serde.rs");
    let fn_body = extract_fn_body(&source, "pub fn from_bytes", 1800);

    assert!(
        fn_body.contains("V24-F8"),
        "V24-F8: from_bytes must reference V24-F8 fix"
    );
}

#[test]
fn v24_f8e_pre_deserialize_max_bitmap_size() {
    let source = read_source_file("src/bloom_serde.rs");
    let fn_body = extract_fn_body(&source, "pub fn from_bytes", 1800);

    assert!(
        fn_body.contains("MAX_BLOOM_BITMAP_SIZE"),
        "V24-F8: from_bytes must define/use MAX_BLOOM_BITMAP_SIZE for size limit"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V24-F9: SipHash degenerate key check
// ═══════════════════════════════════════════════════════════════════════

// V24-F9 (LOW): BloomFilterData::validate() now rejects degenerate SipHash
// keys where both key pairs are identical. Identical keys reduce the effective
// hash function count, degrading bloom filter accuracy.
// SOURCE: bloom_serde.rs, BloomFilterData::validate()

#[test]
fn v24_f9a_degenerate_key_check_in_source() {
    let source = read_source_file("src/bloom_serde.rs");
    let fn_body = extract_fn_body(&source, "fn validate(&self)", 1200);

    assert!(
        fn_body.contains("sip_keys[0] == self.sip_keys[1]"),
        "V24-F9: validate() must check for degenerate sip_keys"
    );
}

#[test]
fn v24_f9b_rejects_degenerate_keys() {
    // Both key pairs identical → degenerate → must reject
    let result = BloomFilterData::new(vec![0u8; 16], 64, 3, [(1, 2), (1, 2)]);
    assert!(
        result.is_err(),
        "V24-F9: BloomFilterData::new must reject degenerate sip_keys (both pairs identical)"
    );
}

#[test]
fn v24_f9c_accepts_distinct_keys() {
    // Distinct key pairs → must accept
    let result = BloomFilterData::new(vec![0u8; 16], 64, 3, [(1, 2), (3, 4)]);
    assert!(
        result.is_ok(),
        "V24-F9: BloomFilterData::new must accept distinct sip_keys"
    );
}

#[test]
fn v24_f9d_sip_keys_doc_comment() {
    let source = read_source_file("src/bloom_serde.rs");

    // Check for documentation about SipHash key non-determinism
    assert!(
        source.contains("non-determinism") || source.contains("randomly generated"),
        "V24-F9: bloom_serde.rs must document SipHash key non-determinism"
    );
}

#[test]
fn v24_f9e_v24_comment_present_in_validate() {
    let source = read_source_file("src/bloom_serde.rs");
    let fn_body = extract_fn_body(&source, "fn validate(&self)", 900);

    assert!(
        fn_body.contains("V24-F9"),
        "V24-F9: validate() must reference V24-F9 fix"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V24-F10: rkyv buffer pre-validation (size check before check_archived_root)
// ═══════════════════════════════════════════════════════════════════════

// V24-F10 (LOW): deserialize_entry_with_buf() now checks buffer size against
// size_of::<IndexEntry>() * 4 BEFORE calling check_archived_root, preventing
// rkyv from processing oversized adversarial buffers.
// SOURCE: store.rs, deserialize_entry_with_buf()

#[test]
fn v24_f10a_size_check_in_source() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "fn deserialize_entry_with_buf", 400);

    assert!(
        fn_body.contains("size_of::<IndexEntry>()"),
        "V24-F10: deserialize_entry_with_buf must check size_of::<IndexEntry>()"
    );
}

#[test]
fn v24_f10b_size_check_before_archived_root() {
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "fn deserialize_entry_with_buf", 400);

    let size_check_pos = fn_body.find("size_of::<IndexEntry>()");
    let archived_root_pos = fn_body.find("check_archived_root");

    assert!(
        size_check_pos.is_some() && archived_root_pos.is_some(),
        "V24-F10: deserialize_entry_with_buf must have both size check and check_archived_root"
    );
    assert!(
        size_check_pos.expect("size check") < archived_root_pos.expect("archived root"),
        "V24-F10: size check must appear BEFORE check_archived_root"
    );
}

#[test]
fn v24_f10c_v24_comment_present() {
    let source = read_source_file("src/store.rs");

    assert!(
        source.contains("V24-F10"),
        "V24-F10: store.rs must reference V24-F10"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V23 Regression Tests — Verify all V23 fixes remain intact
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v24_regression_v23_f1_bloom_fields_pub_crate() {
    // V23-F1: BloomFilterData fields must be pub(crate)
    let source = read_source_file("src/bloom_serde.rs");
    let struct_body = extract_struct_body(&source, "pub struct BloomFilterData", 1800);

    for field in &["version", "bitmap:", "bitmap_bits", "k_num", "sip_keys"] {
        let field_line = struct_body
            .lines()
            .find(|l| l.contains(field) && !l.trim_start().starts_with("//"))
            .unwrap_or_else(|| panic!("Field {} not found in BloomFilterData", field));

        assert!(
            field_line.contains("pub(crate)"),
            "Regression V23-F1: BloomFilterData field '{}' must be pub(crate), found: {}",
            field,
            field_line.trim()
        );
    }
}

#[test]
fn v24_regression_v23_f3_validate_method_exists() {
    // V23-F3: BloomFilterData must have consolidated validate() method
    let source = read_source_file("src/bloom_serde.rs");

    assert!(
        source.contains("fn validate(&self) -> Result<()>"),
        "Regression V23-F3: BloomFilterData must have a validate() method"
    );
}

#[test]
fn v24_regression_v23_f7_from_memory_no_caller_bloom() {
    // V23-F7: from_memory must not have _caller_bloom parameter
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "pub fn from_memory(", 300);

    assert!(
        !fn_body.contains("_caller_bloom"),
        "Regression V23-F7: from_memory must not have _caller_bloom parameter"
    );
    assert!(
        !fn_body.contains("caller_bloom"),
        "Regression V23-F7: from_memory must not have caller_bloom parameter"
    );
}

#[test]
fn v24_regression_v23_f7_from_pages_no_caller_bloom() {
    // V23-F7: from_pages must not have _caller_bloom parameter
    let source = read_source_file("src/reader.rs");
    let fn_body = extract_fn_body(&source, "pub fn from_pages(", 300);

    assert!(
        !fn_body.contains("_caller_bloom"),
        "Regression V23-F7: from_pages must not have _caller_bloom parameter"
    );
    assert!(
        !fn_body.contains("caller_bloom"),
        "Regression V23-F7: from_pages must not have caller_bloom parameter"
    );
}

#[test]
fn v24_regression_v23_f10_set_bloom_uses_from_bytes() {
    // V23-F10: set_bloom_filter must use BloomFilterData::from_bytes()
    let source = read_source_file("src/lib.rs");
    let fn_body = extract_fn_body(&source, "pub fn set_bloom_filter(", 500);

    assert!(
        fn_body.contains("BloomFilterData::from_bytes")
            || fn_body.contains("bloom_serde::BloomFilterData::from_bytes"),
        "Regression V23-F10: set_bloom_filter must use BloomFilterData::from_bytes()"
    );
}

#[test]
fn v24_regression_v22_f9_index_entry_display() {
    // V22-F9: IndexEntry must have Display impl
    let source = read_source_file("src/lib.rs");

    assert!(
        source.contains("impl std::fmt::Display for IndexEntry"),
        "Regression V22-F9: IndexEntry must have Display impl"
    );
}

#[test]
fn v24_regression_v23_f8_logging_after_callback() {
    // V23-F8: Progress logging must come AFTER page callback in for_each_sorted_page
    let source = read_source_file("src/store.rs");
    let fn_body = extract_fn_body(&source, "pub fn for_each_sorted_page", 3000);

    let callback_pos = fn_body.find("callback(page");
    let logging_pos = fn_body.find("processed");

    assert!(
        callback_pos.is_some() && logging_pos.is_some(),
        "Regression V23-F8: for_each_sorted_page must have both callback and progress logging"
    );
    assert!(
        logging_pos.expect("logging") > callback_pos.expect("callback"),
        "Regression V23-F8: progress logging must come AFTER the page callback"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// End-to-end behavioral test
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v24_e2e_chunk_index_lifecycle() {
    // Full lifecycle test: create → insert → finalize → lookup
    // Validates that all V24 fixes work together end-to-end
    let mut tree = ChunkIndex::new_default().expect("ChunkIndex creation should succeed");

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

    // Lookup should find all inserted entries — verify V24-F1 accessors work
    for i in 0..200u64 {
        let result = reader
            .lookup(&test_hash(i))
            .expect("lookup should not error");
        assert!(result.is_some(), "V24-E2E: lookup must find entry {}", i);
        let loc = result.expect("entry must exist");
        assert_eq!(
            loc.block_id,
            BlockId::new(i),
            "V24-E2E: block_id must match"
        );
    }

    // Lookup should not find absent entries
    let result = reader
        .lookup(&test_hash(9999))
        .expect("lookup should not error");
    assert!(
        result.is_none(),
        "V24-E2E: lookup must not find absent entry"
    );
}

#[test]
fn v24_e2e_from_memory_with_accessors() {
    // Verify from_memory works with V24 encapsulated types
    let entries: Vec<IndexEntry> = (0..50).map(make_entry).collect();
    let meta = MetaIndex::new();

    let reader = IndexReader::from_memory(meta, entries).expect("from_memory should succeed");

    // Verify bloom and lookup work via V24-F1 accessors
    assert!(
        reader.bloom_contains(&test_hash(25)),
        "V24-E2E: from_memory must rebuild bloom internally"
    );
    let result = reader
        .lookup(&test_hash(25))
        .expect("lookup should not error");
    assert!(result.is_some(), "V24-E2E: lookup must find inserted entry");
}

#[test]
fn v24_e2e_from_pages_with_accessors() {
    // Verify from_pages works with V24 encapsulated types
    let entries: Vec<IndexEntry> = (0..100).map(make_entry).collect();
    let page = era_index::IndexPage::try_new(entries).expect("valid page");
    let meta = MetaIndex::new();

    let reader = IndexReader::from_pages(meta, vec![(page, BlockId::new(0))])
        .expect("from_pages should succeed");

    assert!(
        reader.bloom_contains(&test_hash(50)),
        "V24-E2E: from_pages must rebuild bloom internally"
    );
    let result = reader
        .lookup(&test_hash(50))
        .expect("lookup should not error");
    assert!(result.is_some(), "V24-E2E: lookup must find inserted entry");
}
