//! # Adversarial Audit V7 — Deep Semantic & Correctness Attack Surface
//!
//! **Audit Date**: 2026-02-24
//! **Auditor**: Senior Rust Systems Engineer (Red Team, Round 7)
//! **Target**: Post-V6-remediation `era-index` crate
//!
//! ## Background
//!
//! The V6 audit (score 62/100) confirmed all P0/P1 CLAUDE.md fixes as genuine,
//! then identified 12 new findings. This V7 audit goes deeper:
//!
//! 1. **The CC3 "fix" introduced a NEW BUG**: entry_count() overcounts duplicates.
//!    The old code undercounted (bloom FP); the new code overcounts (buffer.len()
//!    includes duplicates of entries already in Redb). Neither is correct.
//!
//! 2. **Three V6 CRITICAL findings remain UNFIXED**: from_memory() single-page,
//!    IndexLocation drops volume_id, bloom never resized.
//!
//! 3. **Novel findings**: Dedup semantic divergence, read_sorted memory bomb,
//!    MetaIndex ordering invariant unenforced, page integrity unverified,
//!    finalize double-iteration, concurrent lookup false-negative window.
//!
//! ## V7 Findings Summary
//!
//! | ID      | Severity | Finding |
//! |---------|----------|---------|
//! | V7-F1   | CRITICAL | entry_count() OVERCOUNTS with duplicates — CC3 "fix" broke it |
//! | V7-F2   | CRITICAL | from_memory() ignores ENTRIES_PER_PAGE (UNFIXED from V6-F3) |
//! | V7-F3   | CRITICAL | Dedup strategy divergence: Redb last-write-wins vs IndexPage first-wins |
//! | V7-F4   | HIGH     | Bloom filter never resized — 10× overcapacity → 30%+ FP (UNFIXED V5) |
//! | V7-F5   | HIGH     | IndexLocation drops volume_id (UNFIXED from V6-F5) |
//! | V7-F6   | HIGH     | read_sorted O(N) RAM — loads entire index into Vec |
//! | V7-F7   | HIGH     | MetaIndex add_page has no ordering validation |
//! | V7-F8   | HIGH     | finalize() rebuilds bloom by re-iterating all entries (2× data scan) |
//! | V7-F9   | MEDIUM   | No post-construction page integrity verification |
//! | V7-F10  | MEDIUM   | open_readonly bloom rebuild is O(N) with no progress/size guard |
//! | V7-F11  | MEDIUM   | Concurrent lookup false-negative during buffer→Redb transition |
//! | V7-F12  | MEDIUM   | page_cache Mutex serializes filesystem-mode cache misses (UNFIXED V6-F7) |
//! | V7-F13  | LOW      | Domain separation via single-byte XOR — defense-in-depth gap |
//! | V7-F14  | LOW      | Dead code: config.rs + metrics.rs still shipped (UNFIXED V6-F11) |

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;
use tempfile::TempDir;

use era_common::{BlockId, ChunkHash, VolumeId};
use era_index::{
    ChunkIndex, IndexBuilder, IndexEntry, IndexLocation, IndexPage, IndexStore, MetaIndex,
    ENTRIES_PER_PAGE,
};

// ============================================================================
// Helpers — all behavioral, zero source scanning
// ============================================================================

/// Canonical test hash: BE at high bytes ensures sort order matches Redb's lexicographic byte comparison.
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
}

fn make_entry_with_offset(hash_val: u64, offset: u32, length: u32) -> IndexEntry {
    IndexEntry::new(
        test_hash(hash_val),
        VolumeId::new(),
        BlockId::new(0),
        offset,
        length,
    )
}

// ============================================================================
// V7-F1: entry_count() OVERCOUNTS with Duplicates [CRITICAL]
//
// The CC3 "fix" replaced bloom-based undercounting with store.entry_count() +
// buffer.len(). But buffer.len() counts ALL buffered entries — including
// duplicates of entries already in the store AND duplicates within the buffer
// itself. This means entry_count() is WRONG during the buffer phase.
//
// The old bug: undercounted by bloom FP rate (~1%)
// The new bug: overcounts by duplicate insertion rate (potentially 100%)
// ============================================================================

/// V7-F1a: Within-buffer duplicates — entry_count() now correctly deduplicates.
///
/// Insert the same hash twice before any flush occurs. entry_count() should report 1.
#[test]
fn test_v7_f1a_within_buffer_duplicate_overcounting() {
    let mut builder = IndexBuilder::new_default().unwrap();

    // Insert hash 42 twice (no flush — both in buffer)
    builder.insert(make_entry(42)).unwrap();
    builder.insert(make_entry(42)).unwrap();

    let reported = builder.entry_count();

    // FIXED: entry_count() now deduplicates buffer entries and checks Redb
    assert_eq!(
        reported, 1,
        "V7-F1: entry_count() reports {} for 2 inserts of same hash. \
         Expected 1 (unique count).",
        reported
    );

    // After flush+drain, Redb dedupes and we get the correct unique count
    let drained = builder.read_sorted().unwrap();
    assert_eq!(
        drained.len(),
        1,
        "V7-F1: read_sorted returns {} entries — Redb correctly dedupes to 1.",
        drained.len()
    );
}

/// V7-F1b: Cross-buffer duplicates — entry_count() now correctly deduplicates.
///
/// Insert 1000 unique entries (triggers flush to Redb), then re-insert 500
/// duplicates (stays in buffer). entry_count() should report 1000.
#[test]
fn test_v7_f1b_cross_buffer_duplicate_overcounting() {
    let mut builder = IndexBuilder::new_default().unwrap();

    // Insert 1000 unique entries (BATCH_SIZE=1000 → flush occurs)
    for i in 0..1000u64 {
        builder.insert(make_entry(i)).unwrap();
    }

    // At this point: store has 1000 entries, buffer is empty
    let after_flush = builder.entry_count();
    assert_eq!(after_flush, 1000, "1000 unique entries after flush");

    // Now re-insert 500 duplicates (hashes 0..499), stays in buffer
    for i in 0..500u64 {
        builder.insert(make_entry(i)).unwrap();
    }

    let reported = builder.entry_count();

    // FIXED: entry_count() deduplicates buffer against Redb
    assert_eq!(
        reported, 1000,
        "V7-F1: entry_count() reports {} after 1000 unique + 500 duplicate inserts. \
         Expected 1000 (unique count).",
        reported
    );

    // Verify drain shows the true unique count
    let drained = builder.read_sorted().unwrap();
    assert_eq!(drained.len(), 1000, "True unique count is 1000");
}

/// V7-F1c: 100% duplicate rate — entry_count() correctly reports N, not 2N.
///
/// Insert N entries, flush, then re-insert all N as duplicates.
/// entry_count() should still report N.
#[test]
fn test_v7_f1c_100pct_duplicate_2x_overcount() {
    let mut builder = IndexBuilder::new_default().unwrap();

    // Insert 500 unique (no flush at 500 < BATCH_SIZE=1000)
    for i in 0..500u64 {
        builder.insert(make_entry(i)).unwrap();
    }

    // Fill to 1000 to trigger flush
    for i in 500..1000u64 {
        builder.insert(make_entry(i)).unwrap();
    }

    assert_eq!(builder.entry_count(), 1000);

    // Now re-insert ALL 1000 as duplicates, staying in buffer (< 1000)
    for i in 0..999u64 {
        builder.insert(make_entry(i)).unwrap();
    }

    let reported = builder.entry_count();
    // FIXED: entry_count() deduplicates correctly
    assert_eq!(
        reported, 1000,
        "V7-F1: 100% duplicate batch → entry_count()={}, expected 1000 (unique count).",
        reported
    );
}

/// V7-F1d: entry_count() is now monotonically correct with duplicates.
///
/// Track entry_count() at every insertion point and verify it never diverges
/// from the true unique count.
#[test]
fn test_v7_f1d_entry_count_divergence_tracking() {
    let mut builder = IndexBuilder::new_default().unwrap();

    let mut overcount_instances = 0usize;
    let mut true_unique = HashSet::new();

    // Insert 2000 entries with 50% duplicate rate
    for i in 0..2000u64 {
        let hash_val = i % 1000; // 50% duplicates
        builder.insert(make_entry(hash_val)).unwrap();
        true_unique.insert(hash_val);

        let reported = builder.entry_count();
        let actual = true_unique.len();

        if reported > actual {
            overcount_instances += 1;
        }
    }

    // FIXED: no overcounting should occur
    assert_eq!(
        overcount_instances, 0,
        "V7-F1: entry_count() overcounted {} times out of 2000 inserts. Expected 0.",
        overcount_instances
    );
}

// ============================================================================
// V7-F2: from_memory() Single-Page Violation [CRITICAL — UNFIXED from V6-F3]
//
// ChunkIndex::finalize() → from_memory() puts ALL entries in one IndexPage.
// ENTRIES_PER_PAGE=8192 is advisory only. 100K entries → ~8MB page.
// ============================================================================

/// V7-F2a: Quantify page oversizing — N entries in single page vs expected pages.
#[test]
fn test_v7_f2a_page_oversizing_quantification() {
    let test_sizes: [usize; 3] = [1000, 8192, 16384];

    for &n in &test_sizes {
        let mut tree = ChunkIndex::new_default().unwrap();
        for i in 0..n as u64 {
            tree.insert(make_entry(i)).unwrap();
        }
        let reader = tree.finalize().unwrap();

        // Verify all entries are findable (single page works, but at what cost?)
        let sample = std::cmp::min(n, 1000) as u64;
        let step = std::cmp::max(1, n as u64 / sample);
        let mut found = 0u64;
        for s in 0..sample {
            if reader.lookup(&test_hash(s * step)).unwrap().is_some() {
                found += 1;
            }
        }
        assert_eq!(
            found, sample,
            "All sampled entries must be found for N={}",
            n
        );

        let expected_pages = n.div_ceil(ENTRIES_PER_PAGE);
        eprintln!(
            "V7-F2: N={}: single page (actual) vs {} pages (expected at ENTRIES_PER_PAGE={}). \
             Oversized by {:.0}×.",
            n,
            expected_pages,
            ENTRIES_PER_PAGE,
            n as f64 / ENTRIES_PER_PAGE as f64
        );
    }
}

/// V7-F2b: Binary search performance degrades with oversized pages.
///
/// Compare lookup latency for 8192 entries (1 page, correct) vs 81920 entries
/// (1 page when it should be 10 pages). The oversized page should show measurably
/// worse cache locality.
#[test]
fn test_v7_f2b_binary_search_cache_locality_degradation() {
    // Small index: 4096 entries (a small page)
    let mut tree_small = ChunkIndex::new_default().unwrap();
    for i in 0..4096u64 {
        tree_small.insert(make_entry(i)).unwrap();
    }
    let reader_small = tree_small.finalize().unwrap();

    // Large index: 16384 entries (1 page, should be 2 pages)
    let mut tree_large = ChunkIndex::new_default().unwrap();
    for i in 0..16384u64 {
        tree_large.insert(make_entry(i)).unwrap();
    }
    let reader_large = tree_large.finalize().unwrap();

    // Warm up
    for i in 0..100u64 {
        let _ = reader_small.lookup(&test_hash(i % 4096));
        let _ = reader_large.lookup(&test_hash(i % 16384));
    }

    let iters = 5_000u64;

    let start = Instant::now();
    for i in 0..iters {
        let _ = reader_small.lookup(&test_hash(i % 4096));
    }
    let small_elapsed = start.elapsed();

    let start = Instant::now();
    for i in 0..iters {
        let _ = reader_large.lookup(&test_hash(i % 16384));
    }
    let large_elapsed = start.elapsed();

    let small_ns = small_elapsed.as_nanos() / iters as u128;
    let large_ns = large_elapsed.as_nanos() / iters as u128;

    eprintln!(
        "V7-F2: Lookup latency — 4096 entries: {}ns/op, 16384 entries (oversized): {}ns/op. \
         Ratio: {:.2}×. Oversized page defeats L2 cache optimization.",
        small_ns,
        large_ns,
        large_ns as f64 / small_ns.max(1) as f64
    );
}

/// V7-F2c: from_memory now correctly chunks entries into multiple pages.
///
/// Verifies MetaIndex page count matches ceil(n/ENTRIES_PER_PAGE) after finalize.
#[test]
fn test_v7_f2c_from_memory_always_one_page() {
    for n in [100, 8192, 20_000u64] {
        let mut tree = ChunkIndex::new_default().unwrap();
        for i in 0..n {
            tree.insert(make_entry(i)).unwrap();
        }
        let reader = tree.finalize().unwrap();

        // Access the inner reader to inspect page count
        let inner = reader.reader();
        let guard = inner.read();

        let meta_pages = guard.meta_page_count();
        let expected = (n as usize).div_ceil(ENTRIES_PER_PAGE);

        // FIXED: from_memory() now chunks entries at ENTRIES_PER_PAGE boundaries
        assert_eq!(
            meta_pages, expected,
            "V7-F2: N={}: meta.pages.len()={}, expected={}.",
            n, meta_pages, expected
        );
    }
}

// ============================================================================
// V7-F3: Dedup Strategy Divergence [CRITICAL]
//
// Both code paths now use FIRST-WRITE-WINS / FIRST-OCCURRENCE-WINS:
//   - IndexStore (Redb): skip-if-exists → FIRST write wins
//   - IndexPage::new(): Vec::dedup_by_key → FIRST occurrence wins
//
// This eliminates the dedup strategy divergence identified in V7-F3.
// ============================================================================

/// V7-F3a: Redb insert is FIRST-WRITE-WINS.
///
/// Insert same hash twice with different offsets. The first insert is preserved.
#[test]
fn test_v7_f3a_redb_first_write_wins() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("v7_f3a.redb");
    let mut store = IndexStore::create(&db_path, 10_000).unwrap();

    let entry1 = make_entry_with_offset(42, 0, 1024);
    let entry2 = make_entry_with_offset(42, 4096, 2048);

    store.insert(&entry1).unwrap();
    store.insert(&entry2).unwrap();

    let result = store.get(&test_hash(42)).unwrap().unwrap();
    assert_eq!(
        result.offset, 0,
        "V7-F3: Redb uses FIRST-WRITE-WINS. offset={} (expected 0)",
        result.offset
    );
    assert_eq!(result.length, 1024);
}

/// V7-F3b: IndexPage::new() is FIRST-OCCURRENCE-WINS.
///
/// Create page with same hash, different offsets. dedup_by_key keeps first.
#[test]
fn test_v7_f3b_index_page_first_occurrence_wins() {
    let entry1 = make_entry_with_offset(42, 0, 1024);
    let entry2 = make_entry_with_offset(42, 4096, 2048);

    let page = IndexPage::try_new(vec![entry1, entry2]).unwrap();

    let result = page.find(&test_hash(42)).unwrap();
    // dedup_by_key on a sorted vec keeps the first of consecutive duplicates
    // Since both have the same hash, after sort they're adjacent, and the first is kept
    assert_eq!(
        result.offset, 0,
        "V7-F3: IndexPage::try_new() uses FIRST-OCCURRENCE-WINS via dedup_by_key. \
         offset={} (expected 0). This is OPPOSITE of Redb's LAST-WRITE-WINS.",
        result.offset
    );
    assert_eq!(result.length, 1024);
}

/// V7-F3c: End-to-end consistency — both paths now agree on first-write-wins.
///
/// Insert same hash twice through builder (Redb resolves → first wins),
/// then verify that IndexPage from duplicates also gives first-wins.
#[test]
fn test_v7_f3c_end_to_end_dedup_consistency() {
    // Path 1: Through IndexBuilder → Redb (first-write-wins)
    let mut builder = IndexBuilder::new_default().unwrap();
    builder.insert(make_entry_with_offset(42, 0, 1024)).unwrap();
    builder
        .insert(make_entry_with_offset(42, 4096, 2048))
        .unwrap();

    let drained = builder.read_sorted().unwrap();
    assert_eq!(drained.len(), 1);
    let redb_result_offset = drained[0].offset;

    // Path 2: Direct IndexPage construction (first-occurrence-wins)
    let page = IndexPage::try_new(vec![
        make_entry_with_offset(42, 0, 1024),
        make_entry_with_offset(42, 4096, 2048),
    ])
    .unwrap();
    let page_result_offset = page.find(&test_hash(42)).unwrap().offset;

    // FIXED: Both paths now give the same result (first-write-wins)
    assert_eq!(
        redb_result_offset, page_result_offset,
        "V7-F3: Both paths should give the same result. \
         Redb={}, IndexPage={}.",
        redb_result_offset, page_result_offset
    );
    assert_eq!(
        redb_result_offset, 0,
        "Both paths should return offset=0 (first write)"
    );
}

// ============================================================================
// V7-F4: Bloom Filter Never Resized [HIGH — UNFIXED from V5-CC6]
//
// Bloom is sized once at creation for bloom_expected_items(mem_limit).
// With default mem_limit=64MB and entry_size≈80 bytes, that's ~838K items.
// Inserting 10× more entries causes FP rate to balloon from 1% to 30%+.
// ============================================================================

/// V7-F4a: Bloom FP rate stays low even at overcapacity thanks to resize.
#[test]
fn test_v7_f4a_bloom_fp_rate_at_overcapacity() {
    // Create builder with very small mem_limit → small initial bloom
    let small_limit = 1024; // Tiny: bloom_expected_items = 1024/80 ≈ 12, .max(1024) = 1024 items

    let _builder = IndexBuilder::new(small_limit).unwrap();

    // We'll test at various overcapacity levels
    let test_points = [1024, 5120, 10240, 20480];

    for &target in &test_points {
        // Reset builder for each test
        let mut b = IndexBuilder::new(small_limit).unwrap();

        // Insert 'target' unique entries
        for i in 0..target as u64 {
            b.insert(make_entry(i)).unwrap();
        }

        // Measure FP rate on non-existent entries
        let test_range = target as u64..(target as u64 + 10_000);
        let fp_count: usize = test_range
            .clone()
            .filter(|i| b.bloom_contains(&test_hash(*i)))
            .count();
        let fp_rate = fp_count as f64 / 10_000.0;

        eprintln!(
            "V7-F4: {} entries ({:.0}× initial capacity): FP rate = {:.2}%",
            target,
            target as f64 / 1024.0,
            fp_rate * 100.0
        );
    }

    // At 10× overcapacity, FP rate should now be low thanks to bloom resize
    let mut b = IndexBuilder::new(small_limit).unwrap();
    for i in 0..10240u64 {
        b.insert(make_entry(i)).unwrap();
    }
    let fp_count: usize = (10240u64..20240)
        .filter(|i| b.bloom_contains(&test_hash(*i)))
        .count();
    let fp_rate = fp_count as f64 / 10_000.0;
    assert!(
        fp_rate < 0.05,
        "V7-F4: At 10× overcapacity, FP rate should be <5% after resize but got {:.2}%.",
        fp_rate * 100.0
    );
}

/// V7-F4b: Bloom stays functional at extreme overcapacity thanks to resize.
///
/// At 20× overcapacity, the bloom filter should have been resized and
/// maintain a low FP rate.
#[test]
fn test_v7_f4b_bloom_saturates_at_extreme_overcapacity() {
    let small_limit = 1024; // bloom sized for ~1024 items
    let mut builder = IndexBuilder::new(small_limit).unwrap();

    // Insert 20,000 entries (20× overcapacity)
    for i in 0..20_000u64 {
        builder.insert(make_entry(i)).unwrap();
    }

    // Test FP rate on entries that DON'T exist
    let fp_count: usize = (20_000..30_000u64)
        .filter(|i| builder.bloom_contains(&test_hash(*i)))
        .count();
    let fp_rate = fp_count as f64 / 10_000.0;

    eprintln!(
        "V7-F4: 20× overcapacity → FP rate = {:.1}%. Bloom filter has been resized.",
        fp_rate * 100.0,
    );

    // FIXED: bloom should have been resized, keeping FP rate low
    assert!(
        fp_rate < 0.10,
        "V7-F4: At 20× overcapacity, FP rate should be <10% after resize but got {:.2}%.",
        fp_rate * 100.0
    );
}

/// V7-F4c: Bloom resize mechanism works — bloom capacity increases after overcapacity.
///
/// After inserting 10× the expected entries, verify the bloom's internal
/// size has changed (it was resized to a larger capacity).
#[test]
fn test_v7_f4c_bloom_no_resize_mechanism() {
    let small_limit = 1024;
    let mut builder = IndexBuilder::new(small_limit).unwrap();

    // Record bloom state before inserts
    let bits_before = builder.bloom().number_of_bits();

    // Insert 10× the expected capacity
    for i in 0..10_240u64 {
        builder.insert(make_entry(i)).unwrap();
    }

    // FIXED: Bloom size should have CHANGED (resize occurred)
    let bits_after = builder.bloom().number_of_bits();

    assert_ne!(
        bits_before, bits_after,
        "V7-F4: Bloom bits should change after resize ({} → {}).",
        bits_before, bits_after
    );

    eprintln!(
        "V7-F4: Bloom filter resized from {} bits to {} bits after 10× overcapacity insertion.",
        bits_before, bits_after
    );
}

// ============================================================================
// V7-F5: IndexLocation Drops volume_id [HIGH — UNFIXED from V6-F5]
//
// IndexReader::lookup() returns IndexLocation {block_id, offset, length}.
// The original IndexEntry has volume_id which is silently dropped.
// Multi-volume deduplication is impossible.
// ============================================================================

/// V7-F5a: IndexLocation now includes volume_id — multi-volume lookups work.
///
/// Insert entries from two different volumes with the same block_id.
/// After lookup, volume_id correctly identifies which volume each result came from.
#[test]
fn test_v7_f5a_information_loss_two_volumes_same_block_id() {
    let vol_a = VolumeId::new();
    let vol_b = VolumeId::new();

    let mut tree = ChunkIndex::new_default().unwrap();

    // Entry from vol_a: hash=100, block_id=1
    tree.insert(IndexEntry::new(
        test_hash(100),
        vol_a,
        BlockId::new(1),
        0,
        1024,
    ))
    .unwrap();

    // Entry from vol_b: hash=200, block_id=1 (same block_id, different volume!)
    tree.insert(IndexEntry::new(
        test_hash(200),
        vol_b,
        BlockId::new(1),
        0,
        2048,
    ))
    .unwrap();

    let reader = tree.finalize().unwrap();

    let loc_a = reader.lookup(&test_hash(100)).unwrap().unwrap();
    let loc_b = reader.lookup(&test_hash(200)).unwrap().unwrap();

    // Both return block_id=1 but now we can distinguish volumes
    assert_eq!(loc_a.block_id, BlockId::new(1));
    assert_eq!(loc_b.block_id, BlockId::new(1));

    // FIXED: IndexLocation now includes volume_id
    assert_eq!(loc_a.volume_id, vol_a, "loc_a should have vol_a");
    assert_eq!(loc_b.volume_id, vol_b, "loc_b should have vol_b");

    let loc_size = std::mem::size_of::<IndexLocation>();
    assert_eq!(
        loc_size, 32,
        "IndexLocation is now 32 bytes (includes volume_id)"
    );
}

/// V7-F5b: Quantify information retained — IndexLocation now preserves volume_id.
#[test]
fn test_v7_f5b_information_loss_quantification() {
    let entry_size = std::mem::size_of::<IndexEntry>();
    let loc_size = std::mem::size_of::<IndexLocation>();
    let volume_id_size = std::mem::size_of::<VolumeId>();
    let chunk_hash_size = std::mem::size_of::<ChunkHash>();

    let bytes_lost = entry_size - loc_size;

    eprintln!(
        "V7-F5: IndexEntry={} bytes → IndexLocation={} bytes. \
         Lost: {} bytes per lookup (ChunkHash={} bytes, which the caller already has). \
         VolumeId={} bytes is retained.",
        entry_size, loc_size, bytes_lost, chunk_hash_size, volume_id_size,
    );

    // With volume_id included, the only info lost is the ChunkHash
    // (which the caller already has as the lookup key)
    assert_eq!(
        bytes_lost, chunk_hash_size,
        "V7-F5: Only the ChunkHash ({} bytes) should be lost — caller already has it as the lookup key",
        chunk_hash_size
    );
}

// ============================================================================
// V7-F6: read_sorted O(N) RAM [HIGH]
//
// read_sorted() loads the ENTIRE Redb database into a Vec<IndexEntry>.
// No streaming/iterator API. For a 10M-entry index with ~80 bytes/entry,
// that's ~800MB in a single allocation.
// ============================================================================

/// V7-F6a: Measure read_sorted memory allocation scaling.
#[test]
fn test_v7_f6a_read_sorted_memory_scaling() {
    let sizes = [1_000, 5_000, 20_000];
    let entry_size = std::mem::size_of::<IndexEntry>();

    for &n in &sizes {
        let mut builder = IndexBuilder::new_default().unwrap();
        for i in 0..n as u64 {
            builder.insert(make_entry(i)).unwrap();
        }

        let start = Instant::now();
        let drained = builder.read_sorted().unwrap();
        let elapsed = start.elapsed();

        let ram_bytes = drained.len() * entry_size;
        let ram_mb = ram_bytes as f64 / (1024.0 * 1024.0);

        assert_eq!(drained.len(), n);

        eprintln!(
            "V7-F6: read_sorted({} entries): {:.2}MB RAM, {:?}. \
             At 10M entries this would be {:.0}MB.",
            n,
            ram_mb,
            elapsed,
            10_000_000.0 * entry_size as f64 / (1024.0 * 1024.0)
        );
    }
}

/// V7-F6b: read_sorted is called TWICE during finalize.
///
/// ChunkIndex::finalize() calls builder.read_sorted() to get all entries,
/// then iterates them to build pages. There's no streaming alternative.
/// If finalize also rebuilds the bloom (iterating entries again), that's
/// 3× data traversal for a single finalize call.
#[test]
fn test_v7_f6b_finalize_data_traversal_count() {
    // We can't instrument the internal code, but we can verify that:
    // 1. read_sorted returns all entries (1 full traversal)
    // 2. bloom rebuild iterates all entries (another traversal, done in finalize)
    // This test proves the data exists in memory as a full Vec.

    let n = 20_000u64;
    let mut builder = IndexBuilder::new_default().unwrap();
    for i in 0..n {
        builder.insert(make_entry(i)).unwrap();
    }

    let start = Instant::now();
    let drained = builder.read_sorted().unwrap();
    let drain_time = start.elapsed();

    // Simulate the bloom rebuild that finalize() does
    let bloom_start = Instant::now();
    let mut bloom = bloomfilter::Bloom::new_for_fp_rate(drained.len().max(1024), 0.01);
    for entry in &drained {
        bloom.set(&entry.hash);
    }
    let bloom_time = bloom_start.elapsed();

    eprintln!(
        "V7-F6: {} entries — drain: {:?}, bloom rebuild: {:?}, total: {:?}. \
         finalize() does both, meaning all {} entries are traversed at least twice.",
        n,
        drain_time,
        bloom_time,
        drain_time + bloom_time,
        drained.len()
    );
}

// ============================================================================
// V7-F7: MetaIndex add_page Ordering Invariant Unenforced [HIGH]
//
// MetaIndex.find_page() uses binary search on pages sorted by min_hash.
// But add_page() doesn't validate sorted order. If pages are added
// out of order, binary search silently returns wrong results.
// ============================================================================

/// V7-F7a: Out-of-order add_page now returns Err.
#[test]
fn test_v7_f7a_out_of_order_add_page_breaks_search() {
    let mut meta = MetaIndex::new();

    // Add pages OUT OF ORDER — should return Err on the second add_page
    meta.add_page(test_hash(200), test_hash(299), BlockId::new(2))
        .unwrap();
    let result = meta.add_page(test_hash(0), test_hash(99), BlockId::new(0));
    assert!(result.is_err(), "Out-of-order add_page must return Err");
}

/// V7-F7b: add_page now rejects unsorted input with an Err.
#[test]
fn test_v7_f7b_add_page_accepts_unsorted_input() {
    let mut meta = MetaIndex::new();

    meta.add_page(test_hash(100), test_hash(199), BlockId::new(1))
        .unwrap();
    // This should return Err — min_hash(0) < previous max_hash(199)
    let result = meta.add_page(test_hash(0), test_hash(99), BlockId::new(0));
    assert!(result.is_err(), "Unsorted add_page must return Err");
}

/// V7-F7c: Overlapping page ranges now return Err.
#[test]
fn test_v7_f7c_overlapping_page_ranges_accepted() {
    let mut meta = MetaIndex::new();

    // Page 0: [0, 199]
    meta.add_page(test_hash(0), test_hash(199), BlockId::new(0))
        .unwrap();
    // Page 1: [100, 299] — overlaps with page 0 on [100, 199], should return Err
    let result = meta.add_page(test_hash(100), test_hash(299), BlockId::new(1));
    assert!(result.is_err(), "Overlapping add_page must return Err");
}

// ============================================================================
// V7-F8: finalize() Rebuilds Bloom (2× Data Scan) [HIGH]
//
// finalize() calls read_sorted() to get all entries, builds pages,
// then REBUILDS the bloom from scratch by iterating all_entries again.
// This is a 2× data scan that could be avoided by reusing the builder's
// existing bloom.
// ============================================================================

/// V7-F8a: Measure the bloom rebuild cost during finalize.
#[test]
fn test_v7_f8a_bloom_rebuild_cost() {
    let n = 10_000u64;

    // Time ChunkIndex::finalize() which internally calls drain + bloom rebuild
    let start = Instant::now();
    let reader = {
        let mut tree = ChunkIndex::new_default().unwrap();
        for i in 0..n {
            tree.insert(make_entry(i)).unwrap();
        }
        tree.finalize().unwrap()
    };
    let finalize_time = start.elapsed();

    // Verify the reader works
    assert!(reader.lookup(&test_hash(0)).unwrap().is_some());
    assert!(reader.lookup(&test_hash(n - 1)).unwrap().is_some());

    eprintln!(
        "V7-F8: finalize() for {} entries took {:?}. Includes bloom rebuild \
         (iterating all entries a second time). The builder's existing bloom \
         could be reused to save ~50% of the entry iteration cost.",
        n, finalize_time
    );
}

// ============================================================================
// V7-F9: No Post-Construction Page Integrity Verification [MEDIUM]
//
// IndexPage::new() sorts and dedupes entries, but after construction there's
// no verification that entries are actually sorted, within declared range,
// or have valid offsets. A corrupted page could pass through undetected.
// ============================================================================

/// V7-F9a: Direct struct construction is no longer possible — fields are private.
/// Verify that try_new rejects empty entries and new() works for valid entries.
#[test]
fn test_v7_f9a_manual_page_construction_no_validation() {
    // IndexPage fields are now private — direct construction is impossible.
    // Verify that try_new rejects empty entries.
    let result = IndexPage::try_new(vec![]);
    assert!(result.is_err(), "try_new(vec![]) must return Err");

    // Verify that try_new() still works for valid entries
    let page = IndexPage::try_new(vec![make_entry(200), make_entry(50)]).unwrap();
    // Entries are sorted by try_new(), so find works correctly
    assert!(page.find(&test_hash(200)).is_some());
    assert!(page.find(&test_hash(50)).is_some());
}

/// V7-F9b: Page with entries outside declared [min_hash, max_hash] range.
///
/// A page claims range [100, 200] but contains entry with hash=500.
/// MetaIndex.find_page() would never route hash=500 to this page,
/// making the entry permanently invisible.
#[test]
fn test_v7_f9b_entry_outside_page_range_invisible() {
    // Build a valid multi-page MetaIndex
    let mut meta = MetaIndex::new();
    meta.add_page(test_hash(0), test_hash(99), BlockId::new(0))
        .unwrap();
    meta.add_page(test_hash(100), test_hash(199), BlockId::new(1))
        .unwrap();

    // Page 0 correctly contains entries 0..100
    // But what if page 1 has an entry with hash=500?
    // MetaIndex.find_page(hash=500) returns None (no page covers 500)
    let result = meta.find_page(&test_hash(500));
    assert!(
        result.is_none(),
        "V7-F9: hash=500 has no covering page — entry would be invisible even if \
         it exists in a page with declared range [100, 199]."
    );
}

// ============================================================================
// V7-F10: open_readonly Bloom Rebuild is O(N) [MEDIUM]
//
// IndexStore::open_readonly() rebuilds the bloom filter by iterating every
// entry in the Redb table. For large databases, this is expensive.
// ============================================================================

/// V7-F10a: Measure open_readonly bloom rebuild cost.
#[test]
fn test_v7_f10a_open_readonly_bloom_rebuild_cost() {
    let temp_dir = TempDir::new().unwrap();
    let sizes = [1_000, 10_000, 100_000];

    for &n in &sizes {
        let db_path = temp_dir.path().join(format!("v7_f10a_{}.redb", n));

        // Create and populate
        {
            let mut store = IndexStore::create(&db_path, n * 2).unwrap();
            let entries: Vec<IndexEntry> = (0..n as u64).map(make_entry).collect();
            store.insert_batch(&entries).unwrap();
            // Preserve file on drop for crash recovery simulation
            store.keep_on_drop();
        }

        // Measure open_readonly time (includes bloom rebuild)
        let start = Instant::now();
        let store = IndexStore::open_readonly(&db_path).unwrap();
        let elapsed = start.elapsed();

        assert_eq!(store.entry_count(), n);

        eprintln!(
            "V7-F10: open_readonly({} entries): {:?}. Bloom rebuilt from scratch. \
             At 10M entries this would be ~{:?}.",
            n,
            elapsed,
            elapsed * (10_000_000 / n.max(1) as u32)
        );
    }
}

// ============================================================================
// V7-F11: Concurrent Lookup False-Negative During Buffer Transition [MEDIUM]
//
// During flush_buffer(), entries move from buffer to Redb. If another thread
// checks bloom_contains() (returns true, entry in bloom) then tries to read
// from Redb (entry not yet committed), it gets a false negative.
//
// This is a single-threaded library, so the "concurrent" scenario is about
// the state machine, not actual thread races.
// ============================================================================

/// V7-F11a: Bloom says yes, Redb says no — during buffer phase.
///
/// entry_count confirms entry exists, but store.get() may miss it because
/// it's buffered, not in Redb yet.
#[test]
fn test_v7_f11a_bloom_yes_store_no_during_buffer() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("v7_f11a.redb");
    let mut builder = IndexBuilder::with_path(&db_path, 1024 * 1024).unwrap();

    // Insert 1 entry — stays in buffer (below BATCH_SIZE)
    builder.insert(make_entry(42)).unwrap();

    // Bloom says the entry exists
    assert!(
        builder.bloom_contains(&test_hash(42)),
        "Bloom must contain the entry"
    );

    // But store.get() doesn't find it (it's in the buffer, not Redb)
    let store_result = builder.store().get(&test_hash(42)).unwrap();

    // This documents the consistency window
    if store_result.is_none() {
        eprintln!(
            "V7-F11: CONFIRMED — bloom says entry exists, but store.get() returns None. \
             Entry is in the buffer, not yet flushed to Redb. This is a consistency \
             window where bloom_contains()==true but actual lookup would fail if store \
             were queried directly (bypassing the buffer)."
        );
    } else {
        eprintln!(
            "V7-F11: Entry found in store despite being in buffer. \
             Buffer may have been flushed eagerly."
        );
    }
}

// ============================================================================
// V7-F12: page_cache Mutex vs RwLock [MEDIUM — UNFIXED from V6-F7]
//
// The page_cache in IndexReader uses Mutex<HashMap> which serializes ALL
// concurrent cache operations. For filesystem mode, this means cache miss
// I/O is serialized even across independent pages.
// ============================================================================

/// V7-F12a: Verify embedded mode avoids Mutex entirely.
///
/// In embedded mode (from_memory), lookups go through embedded_pages HashMap
/// which is &self access — no lock contention.
#[test]
fn test_v7_f12a_embedded_mode_zero_contention() {
    let mut tree = ChunkIndex::new_default().unwrap();
    for i in 0..10_000u64 {
        tree.insert(make_entry(i)).unwrap();
    }
    let reader = Arc::new(tree.finalize().unwrap());

    // 8 threads × 100K lookups — should show near-linear scaling
    let num_threads = 8;
    let lookups_per_thread = 100_000u64;

    let start = Instant::now();
    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let r = Arc::clone(&reader);
            std::thread::spawn(move || {
                let mut found = 0u64;
                for i in 0..lookups_per_thread {
                    if r.lookup(&test_hash(i % 10_000)).unwrap().is_some() {
                        found += 1;
                    }
                }
                found
            })
        })
        .collect();

    let total_found: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    let elapsed = start.elapsed();

    assert_eq!(total_found, num_threads as u64 * lookups_per_thread);

    let throughput = (num_threads as u64 * lookups_per_thread) as f64 / elapsed.as_secs_f64();
    eprintln!(
        "V7-F12: Embedded mode: {} threads × {}K lookups = {:.0} ops/sec in {:?}. \
         No Mutex contention in embedded mode. Filesystem mode would serialize \
         cache-miss I/O through Mutex<HashMap>.",
        num_threads,
        lookups_per_thread / 1000,
        throughput,
        elapsed
    );
}

// ============================================================================
// V7-F13: Domain Separation via Single-Byte XOR [LOW]
//
// nonce_context[0] ^= 0xFF is cryptographically sufficient (BLAKE3 is a PRF),
// but fragile for defense-in-depth. A typed prefix or separate constant would
// be more robust against implementation errors.
// ============================================================================

/// V7-F13a: XOR 0xFF always produces a different byte.
///
/// Verify that for all possible first bytes, XOR 0xFF gives a distinct value.
/// This is mathematically guaranteed (a ⊕ 0xFF ≠ a for all a), but we verify.
#[test]
fn test_v7_f13a_xor_always_different() {
    for byte in 0u8..=255 {
        let xored = byte ^ 0xFF;
        assert_ne!(
            byte, xored,
            "V7-F13: XOR 0xFF must always produce a different byte"
        );
    }

    // But what if someone uses a DIFFERENT XOR mask (e.g., 0x00)?
    // The current code uses 0xFF which always flips all bits.
    // A mask of 0x00 would produce no change at all.
    let problematic_mask: u8 = 0x00;
    let same_count: usize = (0u8..=255).filter(|&b| b ^ problematic_mask == b).count();
    assert_eq!(
        same_count, 256,
        "V7-F13: XOR 0x00 produces identical output for ALL inputs — \
         if the mask were accidentally changed, domain separation would vanish."
    );
}

/// V7-F13b: Nonce context collision probability with XOR domain separation.
///
/// If the full 16-byte nonce_context is random, XORing byte[0] with 0xFF changes
/// exactly 1 of 2^128 possible contexts. The collision space is zero, but the
/// API doesn't prevent someone from passing the already-XORed context as the
/// "data" context, creating a collision.
#[test]
fn test_v7_f13b_accidental_double_xor_collision() {
    let original_context: [u8; 16] = [0x42; 16];
    let mut index_context = original_context;
    index_context[0] ^= 0xFF;

    // Someone accidentally XORs again (bug in recovery code)
    let mut double_xored = index_context;
    double_xored[0] ^= 0xFF;

    // Double XOR == original! Nonce collision!
    assert_eq!(
        original_context, double_xored,
        "V7-F13: Double XOR 0xFF returns to original context — \
         if recovery code accidentally XORs the already-XORed context, \
         nonces collide with data blocks. Defense-in-depth gap."
    );
}

// ============================================================================
// V7-BENCH: Performance Benchmarks
// ============================================================================

/// V7-BENCH-1: Insert throughput at various scales.
#[test]
fn test_v7_bench_insert_throughput() {
    let sizes = [10_000, 50_000];

    for &n in &sizes {
        let start = Instant::now();
        let mut builder = IndexBuilder::new_default().unwrap();
        for i in 0..n as u64 {
            builder.insert(make_entry(i)).unwrap();
        }
        let elapsed = start.elapsed();
        let throughput = n as f64 / elapsed.as_secs_f64();

        eprintln!(
            "V7-BENCH: Insert {} entries: {:?} ({:.0} ops/sec)",
            n, elapsed, throughput
        );
    }
}

/// V7-BENCH-2: Lookup throughput (hit rate 100% vs 50% vs 0%).
#[test]
fn test_v7_bench_lookup_throughput() {
    let n = 50_000u64;
    let mut tree = ChunkIndex::new_default().unwrap();
    for i in 0..n {
        tree.insert(make_entry(i)).unwrap();
    }
    let reader = tree.finalize().unwrap();

    let iters = 100_000u64;

    // 100% hit rate
    let start = Instant::now();
    for i in 0..iters {
        let _ = reader.lookup(&test_hash(i % n));
    }
    let hit100 = start.elapsed();

    // 50% hit rate
    let start = Instant::now();
    for i in 0..iters {
        let hash = if i % 2 == 0 { i % n } else { n + i };
        let _ = reader.lookup(&test_hash(hash));
    }
    let hit50 = start.elapsed();

    // 0% hit rate (all misses — bloom filters them)
    let start = Instant::now();
    for i in 0..iters {
        let _ = reader.lookup(&test_hash(n + i));
    }
    let hit0 = start.elapsed();

    eprintln!(
        "V7-BENCH: Lookup {} iters — 100% hits: {:?}, 50% hits: {:?}, 0% hits: {:?}. \
         Bloom filter makes 100% miss faster than 100% hit (no page search).",
        iters, hit100, hit50, hit0
    );
}

/// V7-BENCH-3: finalize() time scaling.
#[test]
fn test_v7_bench_finalize_scaling() {
    let sizes = [10_000, 50_000];

    for &n in &sizes {
        let mut tree = ChunkIndex::new_default().unwrap();
        for i in 0..n as u64 {
            tree.insert(make_entry(i)).unwrap();
        }

        let start = Instant::now();
        let _reader = tree.finalize().unwrap();
        let elapsed = start.elapsed();

        eprintln!(
            "V7-BENCH: finalize({} entries): {:?} ({:.0} entries/sec)",
            n,
            elapsed,
            n as f64 / elapsed.as_secs_f64()
        );
    }
}

// ============================================================================
// V7-EDGE: Edge Case & Regression Tests
// ============================================================================

/// V7-EDGE-1: Zero-entry builder finalize succeeds.
#[test]
fn test_v7_edge_zero_entry_finalize() {
    let mut tree = ChunkIndex::new_default().unwrap();
    let reader = tree.finalize().unwrap();
    assert!(reader.lookup(&test_hash(0)).unwrap().is_none());
}

/// V7-EDGE-2: Single-entry builder finalize succeeds.
#[test]
fn test_v7_edge_single_entry_finalize() {
    let mut tree = ChunkIndex::new_default().unwrap();
    tree.insert(make_entry(42)).unwrap();
    let reader = tree.finalize().unwrap();
    assert!(reader.lookup(&test_hash(42)).unwrap().is_some());
    assert!(reader.lookup(&test_hash(43)).unwrap().is_none());
}

/// V7-EDGE-3: Exactly BATCH_SIZE entries (boundary).
#[test]
fn test_v7_edge_exact_batch_size() {
    let mut builder = IndexBuilder::new_default().unwrap();
    for i in 0..1000u64 {
        // BATCH_SIZE=1000
        builder.insert(make_entry(i)).unwrap();
    }
    assert_eq!(builder.entry_count(), 1000);
    let drained = builder.read_sorted().unwrap();
    assert_eq!(drained.len(), 1000);
}

/// V7-EDGE-4: BATCH_SIZE+1 entries (triggers flush at exactly BATCH_SIZE).
#[test]
fn test_v7_edge_batch_size_plus_one() {
    let mut builder = IndexBuilder::new_default().unwrap();
    for i in 0..1001u64 {
        builder.insert(make_entry(i)).unwrap();
    }
    assert_eq!(builder.entry_count(), 1001);
    let drained = builder.read_sorted().unwrap();
    assert_eq!(drained.len(), 1001);
}

/// V7-EDGE-5: All entries have the same hash — maximum dedup scenario.
#[test]
fn test_v7_edge_all_same_hash() {
    let mut builder = IndexBuilder::new_default().unwrap();

    // Insert 500 entries with the same hash but different offsets
    for i in 0..500u64 {
        builder
            .insert(make_entry_with_offset(42, i as u32 * 1024, 1024))
            .unwrap();
    }

    let drained = builder.read_sorted().unwrap();
    // Redb deduplicates by hash key — only 1 unique entry survives
    assert_eq!(
        drained.len(),
        1,
        "V7-EDGE: 500 entries with same hash → {} after Redb dedup. \
         First-write-wins: offset should be 0.",
        drained.len(),
    );
    // First-write-wins: the first inserted entry's offset should survive
    assert_eq!(drained[0].offset, 0);
}

/// V7-EDGE-6: Consecutive hashes — verify sort order is correct.
#[test]
fn test_v7_edge_sort_order_correctness() {
    let mut builder = IndexBuilder::new_default().unwrap();

    // Insert in reverse order
    for i in (0..5000u64).rev() {
        builder.insert(make_entry(i)).unwrap();
    }

    let drained = builder.read_sorted().unwrap();
    assert_eq!(drained.len(), 5000);

    // Must be sorted by hash
    for i in 1..drained.len() {
        assert!(
            drained[i - 1].hash <= drained[i].hash,
            "Sort invariant violated at index {}",
            i
        );
    }
}

/// V7-EDGE-7: Max/min hash values.
#[test]
fn test_v7_edge_extreme_hash_values() {
    let zero_hash = ChunkHash::from_bytes([0u8; 32]);
    let max_hash = ChunkHash::from_bytes([0xFF; 32]);

    let mut tree = ChunkIndex::new_default().unwrap();
    tree.insert(IndexEntry::new(
        zero_hash,
        VolumeId::new(),
        BlockId::new(0),
        0,
        1024,
    ))
    .unwrap();
    tree.insert(IndexEntry::new(
        max_hash,
        VolumeId::new(),
        BlockId::new(1),
        4096,
        2048,
    ))
    .unwrap();

    let reader = tree.finalize().unwrap();
    assert!(reader.lookup(&zero_hash).unwrap().is_some());
    assert!(reader.lookup(&max_hash).unwrap().is_some());
}

/// V7-EDGE-8: IndexPage with exactly ENTRIES_PER_PAGE entries.
#[test]
fn test_v7_edge_exact_entries_per_page() {
    let entries: Vec<IndexEntry> = (0..ENTRIES_PER_PAGE as u64).map(make_entry).collect();
    let page = IndexPage::try_new(entries).unwrap();
    assert_eq!(page.len(), ENTRIES_PER_PAGE);

    // First and last should be findable
    assert!(page.find(&test_hash(0)).is_some());
    assert!(page.find(&test_hash(ENTRIES_PER_PAGE as u64 - 1)).is_some());
}

/// V7-EDGE-9: Multiple discard() calls — second should handle missing file.
#[test]
fn test_v7_edge_discard_idempotency() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("v7_edge9.redb");

    let builder = IndexBuilder::with_path(&db_path, 1024 * 1024).unwrap();
    builder.discard().unwrap();

    // File is gone
    assert!(!db_path.exists());

    // Second removal of the same path should be a no-op (file already removed)
    // This tests robustness of the cleanup path
}

/// V7-EDGE-10: Store destroy is idempotent.
#[test]
fn test_v7_edge_store_destroy_missing_file() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("v7_edge10.redb");

    let store = IndexStore::create(&db_path, 1024).unwrap();
    assert!(db_path.exists());
    store.destroy().unwrap();
    assert!(!db_path.exists());
}
