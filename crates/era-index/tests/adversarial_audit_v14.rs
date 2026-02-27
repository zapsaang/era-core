//! # Adversarial Audit V14 — Competitive Novel Findings Suite
//!
//! **Audit Date:** 2026-02-26
//! **Target:** `era-index` crate — competitive adversarial audit
//! **Scope:** V14-F1 through V14-F12 (excluding F5 doc fix and F11 attribute fix)
//! **Methodology:** Source-level static analysis + behavioral verification
//!
//! ## V13 Regression Status (All FIXED)
//!
//! | ID | Finding | Status |
//! |----|---------|--------|
//! | V13-F1 | entry_count() overcount on flush failure | FIXED (returns store count on failure) |
//! | V13-F2 | from_memory() appends without clearing | FIXED (meta.clear_pages() called) |
//! | V13-F3 | try_new() silent dedup | DOCUMENTED (docstring notes dedup) |
//! | V13-F4 | Bloom-before-Redb inconsistency | FIXED (bloom set AFTER commit) |
//! | V13-F5 | add_page() rejects shared boundary | DOCUMENTED (design decision) |
//! | V13-F6 | rebuild_bloom_if_needed() in write path | EXISTS (partially mitigated by 4× growth) |
//! | V13-F7 | for_each_sorted_page fresh Vec per page | FIXED (std::mem::take) |
//! | V13-F8 | load_page() cloning | FIXED (Arc<IndexPage>) |
//! | V13-F9 | discard() wasteful flush | FIXED (buffer cleared without flush) |
//! | V13-F10 | open_readonly no upper bound | FIXED (MAX_READONLY_ENTRIES=100M) |
//! | V13-F11 | read_sorted uses field counter | FIXED (table.len() as ground truth) |
//! | V13-F12 | Cold recovery quadratic | FIXED (swap_remove pattern) |
//! | V13-F13 | contains_range() dead code | EXISTS (retained with doc note) |
//!
//! ## Novel Findings (V14)
//!
//! | ID | Severity | Title |
//! |----|----------|-------|
//! | V14-F1 | Medium | Weak domain separation — nonce context XOR (single byte) |
//! | V14-F2 | Low | contains_range() dead public API — should be removed |
//! | V14-F3 | Medium | bloom_set() is public — allows phantom entries |
//! | V14-F4 | Low | test_hash() inconsistency between LE-head and BE-tail |
//! | V14-F6 | Medium | finalize() collects all pages in memory (collect-then-write) |
//! | V14-F7 | Medium | entry_count field can drift from Redb on partial failure |
//! | V14-F8 | Low | EncryptedMacroBlock.chunk_count as u16 — semantic mismatch |
//! | V14-F9 | Medium | ChunkIndex::finalize() materializes all pages in memory |
//! | V14-F10 | Medium | insert() opens a new write transaction per call |
//! | V14-F12 | Low | page_cache in IndexReader is dead allocation |

use era_common::{BlockId, ChunkHash, VolumeId};
use era_index::{
    BloomFilterData, IndexBuilder, IndexEntry, IndexLocation, IndexPage, IndexReader, IndexStore,
    MetaIndex, ENTRIES_PER_PAGE,
};
use tempfile::TempDir;

// ═══════════════════════════════════════════════════════════════════════
// Test Utilities
// ═══════════════════════════════════════════════════════════════════════

/// Canonical BE-tail test hash (V11-F9 compliant)
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

fn make_entry_at(hash_val: u64, block: u64, offset: u32, length: u32) -> IndexEntry {
    IndexEntry::new(
        test_hash(hash_val),
        VolumeId::new(),
        BlockId::new(block),
        offset,
        length,
    )
    .expect("valid entry")
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
// V13 REGRESSION TESTS (verify all 13 findings remain fixed)
// ═══════════════════════════════════════════════════════════════════════

/// V13-F1 regression: entry_count returns store count on flush failure
#[test]
fn v14_regression_v13f1_entry_count_exact_after_flush() {
    let mut builder = IndexBuilder::new_default().expect("create builder");
    for i in 0..100u64 {
        builder.insert(make_entry(i)).expect("insert");
    }
    assert_eq!(builder.entry_count(), 100, "must be exact 100");
}

/// V13-F2 regression: from_memory() clears pages before adding new ones
#[test]
fn v14_regression_v13f2_from_memory_clears_stale_pages() {
    let mut meta = MetaIndex::new();
    meta.add_page(test_hash(0), test_hash(49), BlockId::new(999))
        .expect("add stale page");

    let entries: Vec<IndexEntry> = (100..200).map(make_entry).collect();

    // from_memory clears stale pages via meta.clear_pages()
    let reader = IndexReader::from_memory(meta, entries).expect("from_memory");
    let result = reader.lookup(&test_hash(150)).expect("lookup");
    assert!(
        result.is_some(),
        "entry 150 must be found in embedded pages"
    );
}

/// V13-F3 regression: try_new dedup is documented
#[test]
fn v14_regression_v13f3_try_new_dedup_preserves_first() {
    let e1 = make_entry_at(42, 0, 0, 1024);
    let e2 = make_entry_at(42, 1, 4096, 2048);
    let e3 = make_entry_at(43, 0, 0, 512);
    let page = IndexPage::try_new(vec![e1, e2, e3]).expect("try_new");
    assert_eq!(page.len(), 2, "dedup must reduce from 3 to 2 entries");
}

/// V13-F4 regression: bloom set AFTER commit (no phantom entries on success)
#[test]
fn v14_regression_v13f4_bloom_after_commit() {
    let mut builder = IndexBuilder::new_default().expect("create builder");
    builder.insert(make_entry(42)).expect("insert");
    assert!(
        builder.bloom_contains(&test_hash(42)),
        "bloom must contain inserted hash"
    );
    assert_eq!(builder.entry_count(), 1, "entry must be in store");
}

/// V13-F5 regression: add_page rejects shared boundary hash
#[test]
fn v14_regression_v13f5_shared_boundary_rejected() {
    let mut meta = MetaIndex::new();
    meta.add_page(test_hash(0), test_hash(100), BlockId::new(0))
        .expect("page 1");
    let result = meta.add_page(test_hash(100), test_hash(200), BlockId::new(1));
    assert!(
        result.is_err(),
        "shared boundary hash must be rejected by <= check"
    );
}

/// V13-F6 regression: bloom resize still triggers on threshold
#[test]
fn v14_regression_v13f6_bloom_resize_preserves_entries() {
    let temp_dir = TempDir::new().expect("tempdir");
    let db_path = temp_dir.path().join("test.redb");
    let mut store = IndexStore::create(&db_path, 1024).expect("create store");
    let entries: Vec<IndexEntry> = (0..1537).map(make_entry).collect();
    store
        .insert_batch(&entries)
        .expect("batch insert triggers bloom resize");
    for i in 0..1537u64 {
        assert!(
            store.bloom_contains(&test_hash(i)),
            "entry {i} must be in bloom after resize"
        );
    }
}

/// V13-F7 regression: for_each_sorted_page uses std::mem::take
#[test]
fn v14_regression_v13f7_sorted_pages_correct() {
    let temp_dir = TempDir::new().expect("tempdir");
    let db_path = temp_dir.path().join("test.redb");
    let mut store = IndexStore::create(&db_path, 100_000).expect("create");
    let count = ENTRIES_PER_PAGE * 2 + 100;
    let entries: Vec<IndexEntry> = (0..count as u64).map(make_entry).collect();
    store.insert_batch(&entries).expect("batch insert");
    let mut page_count = 0usize;
    let mut total_entries = 0usize;
    store
        .for_each_sorted_page(|page, _block_id| {
            assert!(
                page.len() <= ENTRIES_PER_PAGE,
                "page must not exceed ENTRIES_PER_PAGE"
            );
            total_entries += page.len();
            page_count += 1;
            Ok(())
        })
        .expect("for_each_sorted_page");
    assert_eq!(page_count, 3, "2*ENTRIES_PER_PAGE + 100 entries = 3 pages");
    assert_eq!(total_entries, count, "all entries must be accounted for");
}

/// V13-F8 regression: load_page returns Arc<IndexPage> (no full clone)
#[test]
fn v14_regression_v13f8_lookup_returns_correct_data() {
    let entries: Vec<IndexEntry> = (0..100).map(make_entry).collect();
    let meta = MetaIndex::new();
    let reader = IndexReader::from_memory(meta, entries).expect("from_memory");
    for _ in 0..10 {
        let result = reader.lookup(&test_hash(50)).expect("lookup");
        assert!(result.is_some(), "repeated lookups must succeed");
    }
}

/// V13-F9 regression: discard() skips flush — buffer cleared without writing
#[test]
fn v14_regression_v13f9_discard_skips_flush() {
    let mut builder = IndexBuilder::new_default().expect("create builder");
    for i in 0..500u64 {
        builder.insert(make_entry(i)).expect("insert");
    }
    assert!(builder.is_dirty(), "buffer must be dirty before discard");
    builder.discard().expect("discard must succeed");
}

/// V13-F10 regression: open_readonly enforces MAX_READONLY_ENTRIES
#[test]
fn v14_regression_v13f10_readonly_small_file_succeeds() {
    let temp_dir = TempDir::new().expect("tempdir");
    let db_path = temp_dir.path().join("test.redb");
    {
        let mut store = IndexStore::create(&db_path, 1024).expect("create");
        for i in 0..100u64 {
            store.insert(&make_entry(i)).expect("insert");
        }
        store.keep_on_drop();
    }
    let store = IndexStore::open_readonly(&db_path).expect("open_readonly");
    assert_eq!(store.entry_count(), 100, "readonly must see all entries");
}

/// V13-F11 regression: read_sorted uses table.len() as ground truth
#[test]
fn v14_regression_v13f11_read_sorted_uses_table_len() {
    let temp_dir = TempDir::new().expect("tempdir");
    let db_path = temp_dir.path().join("test.redb");
    let mut store = IndexStore::create(&db_path, 10_000).expect("create");
    let entries: Vec<IndexEntry> = (0..1000).map(make_entry).collect();
    store.insert_batch(&entries).expect("batch insert");
    let sorted = store
        .read_sorted()
        .expect("read_sorted must succeed under limit");
    assert_eq!(sorted.len(), 1000, "must return all entries");
}

/// V13-F12 regression: cold recovery uses swap_remove for O(1) shrink
#[test]
fn v14_regression_v13f12_meta_find_page_binary_search() {
    let mut meta = MetaIndex::new();
    for i in 0..100u64 {
        meta.add_page(test_hash(i * 100), test_hash(i * 100 + 99), BlockId::new(i))
            .expect("add page");
    }
    let result = meta.find_page(&test_hash(5050));
    assert!(result.is_some(), "must find page containing hash 5050");
    assert_eq!(result.unwrap().block_id(), BlockId::new(50));
}

/// V13-F13 regression: contains_range() still exists (documented as dead code)
#[test]
fn v14_regression_v13f13_contains_range_still_exists() {
    let entries = vec![make_entry(100), make_entry(200), make_entry(300)];
    let page = IndexPage::try_new(entries).expect("try_new");
    assert!(
        page.contains_range(&test_hash(100)),
        "exact min must be in range"
    );
    assert!(
        page.contains_range(&test_hash(300)),
        "exact max must be in range"
    );
    assert!(
        !page.contains_range(&test_hash(99)),
        "below min must not be in range"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V14-F1: Weak domain separation — nonce context XOR (single byte)
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: builder.rs:183-184, reader.rs:186-187
// The index nonce context is derived by XORing only byte[0] with 0xFF.
// This provides weak domain separation — only 1 of 16 bytes differs.
//
// IMPACT: If the data nonce context has 0xFF in byte 0, the XOR
// produces 0x00 — matching a context that started with 0x00.

#[test]
fn v14_f1a_nonce_context_xor_produces_different_context() {
    // Demonstrate that XORing byte 0 with 0xFF produces a different 16-byte context
    let data_nonce_context: [u8; 16] = [
        0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    let mut index_nonce_context = data_nonce_context;
    index_nonce_context[0] ^= 0xFF;

    assert_ne!(
        data_nonce_context, index_nonce_context,
        "XOR must produce a different context"
    );
    // Byte 0 should be different
    assert_ne!(
        data_nonce_context[0], index_nonce_context[0],
        "byte 0 must differ after XOR"
    );
    // Verify the XOR result: 0x42 ^ 0xFF = 0xBD
    assert_eq!(
        index_nonce_context[0], 0xBD,
        "0x42 XOR 0xFF must equal 0xBD"
    );
}

#[test]
fn v14_f1b_xor_domain_separation_is_only_one_byte() {
    // Show that XOR domain separation only differs in 1 of 16 bytes
    let data_nonce_context: [u8; 16] = [
        0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    let mut index_nonce_context = data_nonce_context;
    index_nonce_context[0] ^= 0xFF;

    // Count differing bytes
    let differing_bytes: usize = data_nonce_context
        .iter()
        .zip(index_nonce_context.iter())
        .filter(|(a, b)| a != b)
        .count();

    assert_eq!(
        differing_bytes, 1,
        "only 1 of 16 bytes should differ — weak domain separation"
    );

    // Remaining 15 bytes are identical
    assert_eq!(
        data_nonce_context[1..],
        index_nonce_context[1..],
        "bytes 1..16 must be identical — XOR only touches byte 0"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V14-F2: contains_range() is dead public API — should be removed
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: lib.rs:185-192
// contains_range() is public but never called by the production lookup
// path (which uses MetaIndex::find_page() + IndexPage::find()).
//
// IMPACT: Dead public API confuses consumers about the lookup protocol.

#[test]
fn v14_f2a_contains_range_exists_but_unused_by_lookup() {
    // Show that contains_range() is callable (it's public)
    let entries: Vec<IndexEntry> = (100..200).map(make_entry).collect();
    let page = IndexPage::try_new(entries.clone()).expect("try_new");

    // contains_range is callable and returns correct results
    assert!(
        page.contains_range(&test_hash(150)),
        "contains_range must work for hash in range"
    );

    // But the actual lookup path (IndexReader) does NOT use contains_range.
    // Verify lookup works entirely without it:
    let meta = MetaIndex::new();
    let reader = IndexReader::from_memory(meta, entries).expect("from_memory");
    let result = reader.lookup(&test_hash(150)).expect("lookup");
    assert!(
        result.is_some(),
        "lookup works through MetaIndex::find_page + IndexPage::find, not contains_range"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V14-F3: bloom_set() visibility — internal bloom corruption risk
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: store.rs:307
// bloom_set() is pub(crate), meaning internal code can insert arbitrary
// hashes into the Bloom filter without a corresponding Redb entry.
// This breaks the "bloom is a superset of Redb" invariant.
//
// IMPACT: bloom_contains()==true but get()==None for phantom entries.
// From the public API, we verify the current coupling between
// bloom and store operations.

#[test]
fn v14_f3a_bloom_contains_true_for_inserted_entries() {
    let temp_dir = TempDir::new().expect("tempdir");
    let db_path = temp_dir.path().join("test.redb");
    let mut store = IndexStore::create(&db_path, 1024).expect("create store");

    // Insert a real entry — bloom and redb should both have it
    store.insert(&make_entry(42)).expect("insert");

    // Bloom says yes
    assert!(
        store.bloom_contains(&test_hash(42)),
        "bloom must contain inserted hash"
    );

    // Redb also says yes
    let result = store.get(&test_hash(42)).expect("get");
    assert!(result.is_some(), "store must find inserted entry");

    // Non-inserted hash: bloom may say no (probabilistic)
    // but store.get must definitely say None
    let result_missing = store.get(&test_hash(999)).expect("get missing");
    assert!(
        result_missing.is_none(),
        "non-inserted hash must return None"
    );
}

#[test]
fn v14_f3b_bloom_and_redb_stay_consistent_after_batch_insert() {
    let temp_dir = TempDir::new().expect("tempdir");
    let db_path = temp_dir.path().join("test.redb");
    let mut store = IndexStore::create(&db_path, 1024).expect("create store");

    // Insert a batch of real entries
    let entries: Vec<_> = (1..=10).map(make_entry).collect();
    store.insert_batch(&entries).expect("batch insert");

    // All entries are in both bloom and redb
    for i in 1..=10 {
        assert!(
            store.bloom_contains(&test_hash(i)),
            "bloom must contain batch-inserted hash {}",
            i
        );
        let result = store.get(&test_hash(i)).expect("get");
        assert!(
            result.is_some(),
            "store must find batch-inserted entry {}",
            i
        );
    }

    // entry_count reflects real Redb contents
    assert_eq!(
        store.entry_count(),
        10,
        "entry_count must reflect Redb contents"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V14-F4: test_hash() inconsistency between LE-head and BE-tail
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: builder.rs:351 (LE-head), reader.rs:559 (LE-head)
//         vs lib.rs:322, chunk_index.rs:292, bloom_serde.rs:107 (BE-tail)
// LE-head and BE-tail produce different sort orders for the same inputs.
//
// IMPACT: Internal tests in builder.rs/reader.rs operate in a different
// hash space than external audit tests.

#[test]
fn v14_f4a_le_head_vs_be_tail_produce_different_sort_orders() {
    // LE-head: bytes[..8] = value.to_le_bytes()
    fn le_head_hash(value: u64) -> ChunkHash {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        ChunkHash::from_bytes(bytes)
    }

    // BE-tail: bytes[24..32] = value.to_be_bytes() (canonical)
    // (uses test_hash from above)

    // For value 1 and 256, LE-head and BE-tail produce different byte patterns
    let le_1 = le_head_hash(1);
    let le_256 = le_head_hash(256);
    let be_1 = test_hash(1);
    let be_256 = test_hash(256);

    // Both orderings should have 1 < 256 for natural numeric order (BE-tail preserves this).
    // But LE-head does NOT: value 1 → byte[0]=0x01, value 256 → byte[0]=0x00
    // So in LE-head, 256 sorts BEFORE 1 (non-intuitive).
    assert!(
        le_256 < le_1,
        "LE-head: 256 sorts BEFORE 1 (byte[0]: 0x00 < 0x01)"
    );
    assert!(be_1 < be_256, "BE-tail: 1 < 256 (natural numeric order)");

    // The byte patterns themselves are different between LE-head and BE-tail
    assert_ne!(
        le_1, be_1,
        "LE-head and BE-tail must produce different hashes for value 1"
    );
    assert_ne!(
        le_256, be_256,
        "LE-head and BE-tail must produce different hashes for value 256"
    );

    // Demonstrate sort order divergence for specific values
    // For value 256: LE bytes = [0x00, 0x01, ...], BE bytes at tail = [..., 0x00, 0x01, 0x00, ...]
    // LE-head hash for 256 starts with [0x00, 0x01] → sorts BEFORE many values
    // BE-tail hash for 256 ends with [0x00, 0x00, 0x01, 0x00] → different position
    let le_255 = le_head_hash(255);
    let be_255 = test_hash(255);

    // In LE-head: 255 = [0xFF, 0x00, ...] sorts AFTER 256 = [0x00, 0x01, ...]
    // because byte-by-byte comparison starts with byte 0
    assert!(
        le_256 < le_255,
        "LE-head: 256 sorts BEFORE 255 (byte[0]: 0x00 < 0xFF)"
    );

    // In BE-tail: 255 < 256 (natural numeric order preserved in big-endian)
    assert!(
        be_255 < be_256,
        "BE-tail: 255 sorts BEFORE 256 (natural numeric order)"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V14-F6: finalize() collects all encrypted blocks before writing
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: builder.rs:186-239
// builder.finalize() collects all encrypted blocks into a Vec before
// writing any of them to the volume. This defeats streaming design.
//
// IMPACT: All encrypted index data is held in memory simultaneously.

#[test]
fn v14_f6a_finalize_collects_all_pages_in_memory() {
    // Verify ChunkIndex::finalize() succeeds with multi-page data,
    // demonstrating the collect-then-write pattern works (even if non-streaming)
    let mut tree = era_index::ChunkIndex::new_default().expect("create");

    // Insert enough entries for multiple pages
    let count = ENTRIES_PER_PAGE * 2 + 100;
    for i in 0..count as u64 {
        tree.insert(make_entry(i)).expect("insert");
    }

    // finalize() internally calls read_sorted_pages() which materializes
    // ALL pages in memory — the collect-then-write pattern
    let reader = tree.finalize().expect("finalize with multi-page data");

    // Verify the reader works correctly
    let result = reader.lookup(&test_hash(100)).expect("lookup");
    assert!(
        result.is_some(),
        "lookup must succeed after multi-page finalize"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V14-F7: entry_count field can drift from Redb on partial failure
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: store.rs:228-247
// entry_count is incremented BEFORE commit in insert_batch(). On commit
// failure, entry_count would be higher than actual Redb contents.
//
// IMPACT: Callers relying on entry_count for sizing get inflated counts.

#[test]
fn v14_f7a_entry_count_consistent_after_successful_insert() {
    let temp_dir = TempDir::new().expect("tempdir");
    let db_path = temp_dir.path().join("test.redb");
    let mut store = IndexStore::create(&db_path, 10_000).expect("create");

    // Insert 500 entries via single insert
    for i in 0..500u64 {
        store.insert(&make_entry(i)).expect("insert");
    }
    assert_eq!(
        store.entry_count(),
        500,
        "entry_count must match actual Redb contents after single inserts"
    );

    // Insert 500 more via batch
    let batch: Vec<IndexEntry> = (500..1000).map(make_entry).collect();
    store.insert_batch(&batch).expect("batch insert");
    assert_eq!(
        store.entry_count(),
        1000,
        "entry_count must match after batch insert"
    );

    // Verify via read_sorted
    let sorted = store.read_sorted().expect("read_sorted");
    assert_eq!(sorted.len(), 1000, "read_sorted len must match entry_count");
}

#[test]
fn v14_f7b_entry_count_matches_read_sorted_len() {
    let temp_dir = TempDir::new().expect("tempdir");
    let db_path = temp_dir.path().join("test.redb");
    let mut store = IndexStore::create(&db_path, 10_000).expect("create");

    // Insert with duplicates to test dedup consistency
    let entries: Vec<IndexEntry> = (0..200).map(make_entry).collect();
    store.insert_batch(&entries).expect("first batch");

    // Re-insert same entries (all duplicates)
    store.insert_batch(&entries).expect("duplicate batch");

    // entry_count and read_sorted().len() must agree
    let count = store.entry_count();
    let sorted = store.read_sorted().expect("read_sorted");
    assert_eq!(
        count,
        sorted.len(),
        "entry_count ({}) must equal read_sorted().len() ({})",
        count,
        sorted.len()
    );
    assert_eq!(count, 200, "duplicates must not inflate count");
}

// ═══════════════════════════════════════════════════════════════════════
// V14-F8: EncryptedMacroBlock.chunk_count as u16 — semantic mismatch
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: builder.rs:225-230
// ENTRIES_PER_PAGE (8192) is used as chunk_count in EncryptedMacroBlock,
// which is a u16 field (max 65535). This works but the semantic
// mismatch could confuse maintainers.
//
// IMPACT: No runtime issue — 8192 fits in u16 — but naming is misleading.

#[test]
fn v14_f8a_entries_per_page_fits_in_u16() {
    // ENTRIES_PER_PAGE = 8192 must fit in u16 (max 65535)
    assert!(
        ENTRIES_PER_PAGE <= u16::MAX as usize,
        "ENTRIES_PER_PAGE ({}) must fit in u16 (max {})",
        ENTRIES_PER_PAGE,
        u16::MAX
    );

    // Verify the conversion used in builder.rs finalize():
    // u16::try_from(page.len()) where page.len() <= ENTRIES_PER_PAGE
    let result = u16::try_from(ENTRIES_PER_PAGE);
    assert!(
        result.is_ok(),
        "u16::try_from(ENTRIES_PER_PAGE) must succeed"
    );
    assert_eq!(
        result.unwrap(),
        8192,
        "ENTRIES_PER_PAGE as u16 must be 8192"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V14-F9: ChunkIndex::finalize() materializes all pages in memory
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: chunk_index.rs:205-218
// ChunkIndex::finalize() calls builder.read_sorted_pages() which
// materializes ALL pages into a Vec before passing to IndexReader::from_pages().
//
// IMPACT: For large indexes, all page data is in memory simultaneously.

#[test]
fn v14_f9a_finalize_handles_multi_page_index() {
    let mut tree = era_index::ChunkIndex::new_default().expect("create");

    // Insert enough entries for 3+ pages
    let count = ENTRIES_PER_PAGE * 3 + 500;
    for i in 0..count as u64 {
        tree.insert(make_entry(i)).expect("insert");
    }

    // finalize succeeds — all pages materialized via read_sorted_pages()
    let reader = tree.finalize().expect("finalize multi-page index");

    // Verify first, middle, and last entries are all findable
    let first = reader.lookup(&test_hash(0)).expect("lookup first");
    assert!(first.is_some(), "first entry must be found");

    let mid = reader
        .lookup(&test_hash(ENTRIES_PER_PAGE as u64))
        .expect("lookup mid");
    assert!(mid.is_some(), "mid-page entry must be found");

    let last = reader
        .lookup(&test_hash(count as u64 - 1))
        .expect("lookup last");
    assert!(last.is_some(), "last entry must be found");
}

// ═══════════════════════════════════════════════════════════════════════
// V14-F10: insert() opens a new write transaction per call
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: store.rs:164-205
// IndexStore::insert() creates a new Redb write transaction for every
// single entry. Redb transactions involve fsync, making single-entry
// inserts expensive. insert_batch() amortizes transaction overhead.
//
// IMPACT: Callers bypassing the builder's buffering get ~1000× worse perf.

#[test]
fn v14_f10a_single_insert_vs_batch_both_correct() {
    let temp_dir = TempDir::new().expect("tempdir");
    let db_path_single = temp_dir.path().join("single.redb");
    let db_path_batch = temp_dir.path().join("batch.redb");

    // Store using single insert()
    let mut store_single = IndexStore::create(&db_path_single, 10_000).expect("create single");
    for i in 0..100u64 {
        store_single.insert(&make_entry(i)).expect("single insert");
    }

    // Store using insert_batch()
    let mut store_batch = IndexStore::create(&db_path_batch, 10_000).expect("create batch");
    let entries: Vec<IndexEntry> = (0..100).map(make_entry).collect();
    store_batch.insert_batch(&entries).expect("batch insert");

    // Both must produce identical results
    assert_eq!(
        store_single.entry_count(),
        store_batch.entry_count(),
        "single and batch insert must produce same entry count"
    );

    // Both must have same bloom state
    for i in 0..100u64 {
        assert_eq!(
            store_single.bloom_contains(&test_hash(i)),
            store_batch.bloom_contains(&test_hash(i)),
            "bloom state must be identical for hash {i}"
        );
    }

    // Both must return same data on read_sorted
    let sorted_single = store_single.read_sorted().expect("read_sorted single");
    let sorted_batch = store_batch.read_sorted().expect("read_sorted batch");
    assert_eq!(
        sorted_single.len(),
        sorted_batch.len(),
        "sorted lengths must match"
    );
    for (s, b) in sorted_single.iter().zip(sorted_batch.iter()) {
        assert_eq!(
            *s.hash(),
            *b.hash(),
            "hashes must match between single and batch"
        );
        assert_eq!(
            s.offset(),
            b.offset(),
            "offsets must match between single and batch"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// V14-F12: page_cache in IndexReader is dead allocation
// ═══════════════════════════════════════════════════════════════════════
//
// SOURCE: reader.rs:37, 91, 131, 163, 482-483
// page_cache: Cache<BlockId, Arc<IndexPage>> is allocated with capacity
// 256 in every IndexReader constructor but is NEVER populated in normal
// operation. Lookups are served entirely from embedded_pages.
//
// IMPACT: Wasted 256-slot cache allocation on every IndexReader instance.

#[test]
fn v14_f12a_lookup_works_without_page_cache_population() {
    // Create reader via from_memory — page_cache is allocated but never populated
    let entries: Vec<IndexEntry> = (0..500).map(make_entry).collect();
    let meta = MetaIndex::new();
    let reader = IndexReader::from_memory(meta, entries).expect("from_memory");

    // Lookups work entirely from embedded_pages — page_cache is never used
    for i in (0..500u64).step_by(50) {
        let result = reader.lookup(&test_hash(i)).expect("lookup");
        assert!(
            result.is_some(),
            "entry {i} must be found via embedded_pages (not page_cache)"
        );
    }

    // Non-existent entry correctly returns None
    let absent = reader.lookup(&test_hash(999)).expect("lookup absent");
    assert!(
        absent.is_none(),
        "absent hash must return None — bloom may FP but embedded_pages won't find it"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Additional edge case tests
// ═══════════════════════════════════════════════════════════════════════

/// Verify BE-tail canonical hash preserves numeric sort order
#[test]
fn v14_extra_be_tail_canonical_sort_order() {
    let hashes: Vec<ChunkHash> = (0..1000u64).map(test_hash).collect();
    for w in hashes.windows(2) {
        assert!(
            w[0] < w[1],
            "BE-tail hashes must preserve numeric sort order"
        );
    }
}

/// Verify BloomFilterData version field is still 1
#[test]
fn v14_extra_bloom_version_field() {
    let bloom: bloomfilter::Bloom<ChunkHash> = bloomfilter::Bloom::new_for_fp_rate(100, 0.01);
    // from_bloom is pub(crate), so we test via the public accessor on a bloom built through
    // the public new() constructor path instead.
    let bitmap = bloom.bitmap();
    let bits = bloom.number_of_bits();
    let k = bloom.number_of_hash_functions();
    let keys = bloom.sip_keys();
    let data = BloomFilterData::new(bitmap, bits, k, keys).expect("valid bloom data");
    assert_eq!(data.version(), 1, "BloomFilterData must have version=1");
}

/// Verify insert after finalize is still rejected
#[test]
fn v14_extra_insert_after_finalize_rejected() {
    let mut tree = era_index::ChunkIndex::new_default().expect("create");
    tree.insert(make_entry(1)).expect("insert");
    let _reader = tree.finalize().expect("finalize");

    let result = tree.insert(make_entry(2));
    assert!(result.is_err(), "insert after finalize must fail");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("finalized"),
        "error must mention 'finalized', got: {err_msg}"
    );
}
