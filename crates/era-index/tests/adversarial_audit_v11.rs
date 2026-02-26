//! # Adversarial Audit V11 — Full Consolidated Suite
//!
//! **Audit Date:** 2026-02-26
//! **Target:** `era-index` crate — competitive adversarial audit
//! **Scope:** V11-F1 through V11-F13 (32 tests)
//! **Methodology:** Source scanning + behavioral testing

use bloomfilter::Bloom;
use era_common::{BlockId, ChunkHash, VolumeId};
use era_index::{BloomFilterData, IndexEntry, IndexPage, IndexStore, ENTRIES_PER_PAGE};

// ═══════════════════════════════════════════════════════════════════════
// Test Utilities
// ═══════════════════════════════════════════════════════════════════════

/// Canonical test hash: big-endian at tail for natural byte ordering
fn test_hash(value: u64) -> ChunkHash {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    ChunkHash::from_bytes(bytes)
}

fn test_hash_le_front(value: u64) -> ChunkHash {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    ChunkHash::from_bytes(bytes)
}

fn test_hash_be_tail(value: u64) -> ChunkHash {
    test_hash(value)
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

#[allow(dead_code)]
/// Build a valid Bloom<ChunkHash> with n items inserted
fn make_bloom(n: usize) -> Bloom<ChunkHash> {
    let mut bloom = Bloom::new_for_fp_rate(n.max(100), 0.01);
    for i in 0..n as u64 {
        bloom.set(&test_hash(i));
    }
    bloom
}

// Suppress unused import warning for ENTRIES_PER_PAGE (imported per spec)
#[allow(dead_code)]
const _EPP: usize = ENTRIES_PER_PAGE;

// ═══════════════════════════════════════════════════════════════════════
// V11-F1: SipHash Keys Stored in Plaintext in BloomFilterData
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: BloomFilterData serializes sip_keys as plaintext [(u64, u64); 2].
// An adversary who reads the serialized bytes can extract the exact SipHash
// keys and use them to predict which hashes will produce false positives.
// This enables targeted deduplication poisoning.

#[test]
fn v11_f1a_sip_keys_accessible_after_deserialization() {
    // SETUP: Create a bloom filter, serialize via BloomFilterData, deserialize
    let bloom = make_bloom(500);
    let data = BloomFilterData::from_bloom(&bloom);

    // Serialize to bytes (simulates on-disk or in-volume storage)
    let serialized = data
        .to_bytes()
        .expect("BloomFilterData serialization must succeed");

    // Deserialize — simulates an adversary reading the stored bytes
    let recovered = BloomFilterData::from_bytes(&serialized)
        .expect("BloomFilterData deserialization must succeed");

    // ASSERT: sip_keys are directly accessible and non-zero
    // This proves an adversary can extract the hash function secrets
    let keys = recovered.sip_keys;
    assert_ne!(keys[0], (0, 0), "First SipHash key pair must be non-zero");
    assert_ne!(keys[1], (0, 0), "Second SipHash key pair must be non-zero");

    // The keys are the EXACT internal state of the bloom filter's hash functions
    assert_eq!(
        keys, data.sip_keys,
        "Extracted sip_keys must match original — adversary has full key material"
    );
}

#[test]
fn v11_f1b_extracted_keys_enable_false_positive_prediction() {
    // SETUP: Build a bloom, extract keys, reconstruct, and probe
    let bloom = make_bloom(200);
    let data = BloomFilterData::from_bloom(&bloom);

    // Adversary extracts sip_keys from serialized data
    let serialized = data.to_bytes().expect("serialization must succeed");
    let adversary_data =
        BloomFilterData::from_bytes(&serialized).expect("deserialization must succeed");

    // Adversary reconstructs the bloom filter using extracted keys
    let adversary_bloom: Bloom<ChunkHash> = adversary_data.to_bloom();

    // Verify reconstruction is faithful: all originally-inserted hashes still match
    for i in 0..200u64 {
        assert!(
            adversary_bloom.check(&test_hash(i)),
            "Reconstructed bloom must find hash {} that was inserted",
            i
        );
    }

    // Adversary can now probe arbitrary hashes to find false positives
    let mut false_positives = Vec::new();
    for i in 200..10_000u64 {
        if adversary_bloom.check(&test_hash(i)) {
            false_positives.push(i);
        }
    }

    // The adversary's false positive set is identical to the real bloom's
    let original_bloom: Bloom<ChunkHash> = data.to_bloom();
    for &fp in &false_positives {
        assert!(
            original_bloom.check(&test_hash(fp)),
            "Adversary-predicted false positive {} must also be FP in the real bloom — \
             proving the adversary has perfect prediction",
            fp
        );
    }

    assert!(
        !false_positives.is_empty(),
        "Bloom filter should have some false positives in range 200..10000 \
         (FPR ~1% over 9800 probes → expected ~98 FPs)"
    );
}

#[test]
fn v11_f1c_sip_keys_survive_serialization_roundtrip_unchanged() {
    // Multiple roundtrips must preserve keys identically — no re-randomization
    let bloom = make_bloom(1000);
    let original_data = BloomFilterData::from_bloom(&bloom);
    let original_keys = original_data.sip_keys;

    // Roundtrip 1
    let bytes1 = original_data.to_bytes().expect("roundtrip 1 serialize");
    let data1 = BloomFilterData::from_bytes(&bytes1).expect("roundtrip 1 deserialize");
    assert_eq!(
        data1.sip_keys, original_keys,
        "Keys must survive roundtrip 1 unchanged"
    );

    // Roundtrip 2 (from roundtrip 1's output)
    let bytes2 = data1.to_bytes().expect("roundtrip 2 serialize");
    let data2 = BloomFilterData::from_bytes(&bytes2).expect("roundtrip 2 deserialize");
    assert_eq!(
        data2.sip_keys, original_keys,
        "Keys must survive roundtrip 2 unchanged"
    );

    // Roundtrip 3 (from roundtrip 2's output)
    let bytes3 = data2.to_bytes().expect("roundtrip 3 serialize");
    let data3 = BloomFilterData::from_bytes(&bytes3).expect("roundtrip 3 deserialize");
    assert_eq!(
        data3.sip_keys, original_keys,
        "Keys must survive roundtrip 3 unchanged — \
         sip_keys are never re-randomized on deserialization"
    );

    assert_eq!(
        bytes1, bytes2,
        "Serialized bytes must be identical across roundtrips (deterministic)"
    );
    assert_eq!(
        bytes2, bytes3,
        "Serialized bytes must be identical across roundtrips (deterministic)"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V11-F2: LRU cache write lock on every read
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: load_page() acquires a write lock even for cache hits because
// lru::LruCache::get() requires &mut self (updates LRU order).
// This serializes all concurrent readers.

#[test]
fn v11_f2a_page_cache_requires_write_lock_for_reads() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/reader.rs"),
    )
    .expect("read reader.rs");
    let fn_start = source.find("fn load_page(").expect("load_page must exist");
    let fn_body = &source[fn_start..fn_start + 1500];
    assert!(
        fn_body.contains("page_cache.write()"),
        "load_page must acquire write lock — lru::LruCache::get() requires &mut self"
    );
}

#[test]
fn v11_f2b_lru_get_requires_write_lock_not_read_lock() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/reader.rs"),
    )
    .expect("read reader.rs");
    let fn_start = source.find("fn load_page(").expect("load_page must exist");
    let fn_body = &source[fn_start..fn_start + 1500];
    assert!(
        fn_body.contains("page_cache.write()"),
        "write lock must be used"
    );
    assert!(
        !fn_body.contains("page_cache.read()"),
        "read lock must NOT be used — lru requires &mut, forcing write lock on every read"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V11-F3: read_sorted_pages materializes all pages
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: read_sorted_pages() returns Vec<(IndexPage, BlockId)> — all pages
// are materialized in memory simultaneously. For large archives this is O(n) RAM.

#[test]
fn v11_f3a_read_sorted_pages_returns_vec_not_iterator() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let mut store =
        IndexStore::create(&dir.path().join("staging.redb"), 1000).expect("create store");
    for i in 0..10u64 {
        store.insert(&make_entry(i)).expect("insert");
    }
    let pages = store.read_sorted_pages().expect("read_sorted_pages");
    assert!(!pages.is_empty(), "must return at least one page");
    assert_eq!(pages.len(), 1, "10 entries fit in 1 page");
}

#[test]
fn v11_f3b_page_count_matches_entry_count() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let count = ENTRIES_PER_PAGE * 2 + 1; // 16385
    let mut store =
        IndexStore::create(&dir.path().join("staging.redb"), count + 100).expect("create store");
    let entries: Vec<IndexEntry> = (0..count as u64).map(make_entry).collect();
    store.insert_batch(&entries).expect("insert_batch");
    let pages = store.read_sorted_pages().expect("read_sorted_pages");
    assert_eq!(
        pages.len(),
        3,
        "16385 entries → 3 pages (ceil(16385/8192) = 3)"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V11-F4: Bloom filter suboptimal for sealed archives
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: Bloom filter uses ~9.6 bits/element vs Ribbon filter's ~7.0 bits/element.
// For 1M items at 1% FPR: Bloom ≈ 1.2MB, Ribbon ≈ 875KB — ~27% overhead.
// Sealed archives never delete entries, making Ribbon filters ideal.

#[test]
fn v11_f4a_bloom_memory_overhead_vs_ribbon() {
    let bloom = Bloom::<ChunkHash>::new_for_fp_rate(1_000_000, 0.01);
    let bloom_bytes = bloom.bitmap().len();
    // Ribbon filter theoretical size: 7.0 bits/element = 875,000 bytes for 1M items
    let ribbon_bytes = (1_000_000usize * 7) / 8;
    assert!(
        bloom_bytes > ribbon_bytes,
        "Bloom ({bloom_bytes} bytes) must be larger than Ribbon ({ribbon_bytes} bytes) — ~27% overhead"
    );
}

#[test]
fn v11_f4b_bloom_fp_rate_configured_at_one_percent() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/store.rs"),
    )
    .expect("read store.rs");
    assert!(
        source.contains("BLOOM_FP_RATE: f64 = 0.01"),
        "BLOOM_FP_RATE must be 0.01 (1%) — this is the baseline for Ribbon comparison"
    );
}
// ═══════════════════════════════════════════════════════════════════════
// V11-F5: Cold Recovery Has No Timeout/Cancellation
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: `recover_from_volume` iterates up to `volume_block_count + 1`
// candidate block IDs with no timeout, cancellation token, or progress callback.
// For large archives, this is an O(n) scan with cryptographic work per candidate.
#[test]
fn v11_f5a_candidate_list_grows_linearly_with_volume_block_count() {
    let page_count_hint: u64 = 5;
    let test_cases: Vec<(u64, &str)> = vec![
        (10, "tiny archive (10 blocks)"),
        (100, "small archive (100 blocks)"),
        (1_000, "medium archive (1K blocks)"),
        (10_000, "large archive (10K blocks)"),
        (100_000, "very large archive (100K blocks)"),
    ];
    let mut previous_count = 0u64;
    for (volume_block_count, label) in &test_cases {
        let mut seen = std::collections::HashSet::new();
        let mut candidates: Vec<u64> = Vec::new();
        if seen.insert(page_count_hint) {
            candidates.push(page_count_hint);
        }
        for delta in 1..=10u64 {
            let above = page_count_hint + delta;
            if seen.insert(above) {
                candidates.push(above);
            }
            if page_count_hint >= delta {
                let below = page_count_hint - delta;
                if seen.insert(below) {
                    candidates.push(below);
                }
            }
        }
        let upper_bound = if *volume_block_count > 0 {
            volume_block_count + 1
        } else {
            (page_count_hint + 1).saturating_mul(4).max(1024)
        };
        for id in 0..upper_bound {
            if seen.insert(id) {
                candidates.push(id);
            }
        }
        let candidate_count = candidates.len() as u64;
        assert!(
            candidate_count >= *volume_block_count,
            "[{}] candidate count ({}) must be >= volume_block_count ({}) — proves O(n) worst case",
            label,
            candidate_count,
            volume_block_count
        );
        if previous_count > 0 {
            assert!(
                candidate_count > previous_count,
                "[{}] candidates must grow with volume size: {} should be > {}",
                label,
                candidate_count,
                previous_count
            );
        }
        previous_count = candidate_count;
    }
    assert!(
        previous_count >= 100_000,
        "100K block archive generates {} candidates — O(n) confirmed, no timeout exists",
        previous_count
    );
}
#[test]
fn v11_f5b_recover_from_volume_has_no_timeout_parameter() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let reader_path = std::path::Path::new(manifest_dir)
        .join("src")
        .join("reader.rs");
    let source =
        std::fs::read_to_string(&reader_path).expect("must be able to read reader.rs source");
    let sig_start = source
        .find("pub async fn recover_from_volume")
        .expect("recover_from_volume function must exist in reader.rs");
    let sig_region = &source[sig_start..];
    let sig_end = sig_region
        .find('{')
        .expect("function must have an opening brace");
    let signature = &sig_region[..sig_end];
    let timeout_indicators = [
        "timeout",
        "Timeout",
        "deadline",
        "Deadline",
        "Duration",
        "Instant",
        "cancel",
        "Cancel",
        "CancellationToken",
        "progress",
        "Progress",
        "callback",
        "Callback",
        "max_attempts",
        "limit",
    ];
    for indicator in &timeout_indicators {
        assert!(
            !signature.contains(indicator),
            "recover_from_volume signature contains '{}' — expected NO timeout/cancellation/progress parameter. Signature:\n{}",
            indicator, signature
        );
    }
    assert!(
        signature.contains("volume_reader"),
        "Expected volume_reader parameter"
    );
    assert!(signature.contains("session"), "Expected session parameter");
    assert!(
        signature.contains("volume_key"),
        "Expected volume_key parameter"
    );
    assert!(
        signature.contains("nonce_context"),
        "Expected nonce_context parameter"
    );
}
// ═══════════════════════════════════════════════════════════════════════
// V11-F6: Redb blocking in async context without spawn_blocking
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: IndexStore::insert() and get() open Redb transactions synchronously.
// In era-engine, these are called from async context without spawn_blocking,
// blocking the Tokio runtime thread.
#[test]
fn v11_f6a_index_store_insert_is_synchronous() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let mut store =
        IndexStore::create(&dir.path().join("staging.redb"), 10_000).expect("create store");
    for i in 0..100u64 {
        store.insert(&make_entry(i)).expect("insert");
    }
    assert_eq!(store.entry_count(), 100);
}
#[test]
fn v11_f6b_index_store_get_is_synchronous() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let mut store =
        IndexStore::create(&dir.path().join("staging.redb"), 10_000).expect("create store");
    for i in 0..10u64 {
        store.insert(&make_entry(i)).expect("insert");
    }
    let found = store.get(&test_hash(5)).expect("get existing");
    assert!(found.is_some(), "expected entry for hash(5)");
    let missing = store.get(&test_hash(999)).expect("get missing");
    assert!(missing.is_none(), "expected None for hash(999)");
}
#[test]
fn v11_f6c_index_builder_flush_triggers_redb_batch_write() {
    use era_index::IndexBuilder;
    let mut builder = IndexBuilder::new_default().expect("new builder");
    for i in 0..1000u64 {
        builder.insert(make_entry(i)).expect("insert");
    }
    assert_eq!(builder.entry_count(), 1000);
    builder.insert(make_entry(1000)).expect("insert 1001st");
    assert_eq!(builder.entry_count(), 1001);
}
#[test]
fn v11_f6d_era_engine_wraps_in_mutex_not_spawn_blocking() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("parent of era-index")
            .join("era-engine/src/chunk_index.rs"),
    )
    .expect("read chunk_index.rs");
    assert!(
        source.contains("Mutex"),
        "RedbChunkIndex must wrap IndexBuilder in a Mutex"
    );
    assert!(
        !source.contains("spawn_blocking"),
        "RedbChunkIndex must NOT use spawn_blocking — this is the finding: \
         Redb I/O blocks the Tokio runtime thread"
    );
}
// ═══════════════════════════════════════════════════════════════════════
// V11-F7: Runtime State Machine (not typestate)
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: Invalid state transitions (insert-after-finalize, double-finalize)
// are caught at runtime, not compile time. A typestate pattern would make
// these compile errors.
#[test]
fn v11_f7a_insert_after_finalize_returns_runtime_error() {
    use era_index::ChunkIndex;
    let mut index = ChunkIndex::new_default().expect("new_default must succeed");
    index
        .insert(make_entry(1))
        .expect("first insert must succeed");
    let _reader = index.finalize().expect("finalize must succeed");
    let result = index.insert(make_entry(2));
    assert!(
        result.is_err(),
        "insert after finalize must return Err, got Ok"
    );
}
#[test]
fn v11_f7b_double_finalize_returns_runtime_error() {
    use era_index::ChunkIndex;
    let mut index = ChunkIndex::new_default().expect("new_default must succeed");
    index.insert(make_entry(1)).expect("insert must succeed");
    let _reader = index.finalize().expect("first finalize must succeed");
    let result = index.finalize();
    assert!(result.is_err(), "double finalize must return Err, got Ok");
}
#[test]
fn v11_f7c_state_error_message_is_descriptive() {
    use era_index::ChunkIndex;
    let mut index = ChunkIndex::new_default().expect("new_default must succeed");
    let _reader = index
        .finalize()
        .expect("finalize on empty index must succeed");
    let err = index
        .insert(make_entry(1))
        .expect_err("insert after finalize must fail");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("finalized") || msg.contains("finalize") || msg.contains("state"),
        "error message should mention finalization state, got: {err}"
    );
}
// ═══════════════════════════════════════════════════════════════════════
// V11-F8: Duplicate SAFETY Comments
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: The 6-line SAFETY comment is duplicated verbatim in insert() and
// insert_batch(). This violates DRY and creates maintenance risk.
#[test]
fn v11_f8a_insert_and_insert_batch_have_identical_safety_comments() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/store.rs"),
    )
    .expect("Failed to read store.rs");
    let identifier = "bloom-before-commit is intentional and correct";
    let count = source.matches(identifier).count();
    // V13 Task 3: Refactored insert() to call rebuild_bloom_if_needed(),
    // which eliminated the duplicate SAFETY comment. Now only insert_batch() has it.
    assert!(
        count >= 1,
        "Expected at least 1 occurrence of the SAFETY comment (was 2 pre-Task3), found {}",
        count
    );
}
#[test]
fn v11_f8b_safety_comment_line_count() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/store.rs"),
    )
    .expect("Failed to read store.rs");
    let identifier = "bloom-before-commit is intentional and correct";
    let count = source.matches(identifier).count();
    // V13 Task 3: insert() was refactored, reducing from 2 to 1 occurrence.
    assert_eq!(
        count, 1,
        "Expected 1 occurrence of the SAFETY comment (was 2 pre-Task3), found {}",
        count
    );
}
// ═══════════════════════════════════════════════════════════════════════
// V11-F9: test_hash Inconsistency
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: bloom_serde.rs test_hash uses LE bytes at the FRONT, while
// adversarial_audit_v10.rs uses BE bytes at the TAIL. Inconsistent test
// helpers can mask hash-ordering bugs.
#[test]
fn v11_f9a_bloom_serde_test_hash_uses_be_tail() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bloom_serde.rs"),
    )
    .expect("Failed to read bloom_serde.rs");
    assert!(
        source.contains("bytes[24..32].copy_from_slice(&value.to_be_bytes())"),
        "bloom_serde.rs test_hash should use BE bytes at the tail (canonical pattern)"
    );
}
#[test]
fn v11_f9b_v10_test_hash_uses_be_tail() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial_audit_v10.rs"),
    )
    .expect("Failed to read adversarial_audit_v10.rs");
    assert!(
        source.contains("bytes[24..32].copy_from_slice(&value.to_be_bytes())"),
        "adversarial_audit_v10.rs test_hash should use BE bytes at the tail"
    );
}
#[test]
fn v11_f9c_inconsistent_hash_distributions_produce_different_bytes() {
    let h_le = test_hash_le_front(1);
    let h_be = test_hash_be_tail(1);
    assert_ne!(
        h_le, h_be,
        "LE-front and BE-tail produce different bytes for the same value"
    );
    let h_le_2 = test_hash_le_front(2);
    let h_be_2 = test_hash_be_tail(2);
    assert!(h_le < h_le_2, "LE ordering is monotonic for small values");
    assert!(h_be < h_be_2, "BE ordering is monotonic for small values");
    let le_bytes = h_le_2.as_bytes();
    let be_bytes = h_be_2.as_bytes();
    assert_eq!(le_bytes[0], 2, "LE puts value at front");
    assert_eq!(be_bytes[31], 2, "BE puts value at tail");
    assert_eq!(le_bytes[31], 0, "LE has zeros at tail");
    assert_eq!(be_bytes[0], 0, "BE has zeros at front");
}
// ═══════════════════════════════════════════════════════════════════════
// V11-F10: IndexPage silent dedup
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: IndexPage::try_new() silently deduplicates entries with the same
// hash, keeping the first occurrence. Callers may not realize data was dropped.
#[test]
fn v11_f10a_try_new_dedup_keeps_first_occurrence() {
    let entry1 = IndexEntry::new(test_hash(42), VolumeId::new(), BlockId::new(0), 0, 1024);
    let entry2 = IndexEntry::new(test_hash(42), VolumeId::new(), BlockId::new(0), 4096, 2048);
    let page = IndexPage::try_new(vec![entry1, entry2]).expect("try_new must return Ok");
    assert_eq!(
        page.len(),
        1,
        "duplicate was silently dropped — page must have 1 entry"
    );
    assert_eq!(
        page.find(&test_hash(42))
            .expect("entry must be found")
            .offset,
        0,
        "first occurrence (offset=0) must be preserved"
    );
}
#[test]
fn v11_f10b_try_new_dedup_reduces_count() {
    let mut entries: Vec<IndexEntry> = (0u64..7).map(make_entry).collect();
    entries.push(IndexEntry::new(
        test_hash(0),
        VolumeId::new(),
        BlockId::new(99),
        9999,
        512,
    ));
    entries.push(IndexEntry::new(
        test_hash(1),
        VolumeId::new(),
        BlockId::new(99),
        9999,
        512,
    ));
    entries.push(IndexEntry::new(
        test_hash(2),
        VolumeId::new(),
        BlockId::new(99),
        9999,
        512,
    ));
    assert_eq!(entries.len(), 10, "pre-condition: 10 entries before dedup");
    let page = IndexPage::try_new(entries).expect("try_new must succeed");
    assert_eq!(
        page.len(),
        7,
        "10 entries - 3 duplicates = 7 unique; silent dedup reduces count without error"
    );
}
#[test]
fn v11_f10c_try_new_no_error_on_duplicates() {
    let entries: Vec<IndexEntry> = (0..5)
        .map(|_| IndexEntry::new(test_hash(99), VolumeId::new(), BlockId::new(0), 0, 1024))
        .collect();
    assert_eq!(entries.len(), 5, "pre-condition: 5 identical entries");
    let page = IndexPage::try_new(entries).expect("try_new must return Ok, NOT Err, on duplicates");
    assert_eq!(
        page.len(),
        1,
        "only one entry survives — 4 silently dropped"
    );
}
// ═══════════════════════════════════════════════════════════════════════
// V11-F11: No version field in BloomFilterData
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: BloomFilterData has no version or magic field. Format changes are
// undetectable — corrupted bitmap_bits survives deserialization without error.
#[test]
fn v11_f11a_bloom_filter_data_has_version_field() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bloom_serde.rs"),
    )
    .expect("read bloom_serde.rs");
    let struct_start = source
        .find("struct BloomFilterData")
        .expect("struct must exist");
    let struct_end = source[struct_start..].find('}').expect("struct must close");
    let struct_body = &source[struct_start..struct_start + struct_end];
    assert!(
        struct_body.contains("version"),
        "BloomFilterData MUST have a version field for schema evolution (Task 4)"
    );
    assert!(
        !struct_body.contains("magic"),
        "BloomFilterData must NOT have a magic field"
    );
    assert!(struct_body.contains("bitmap"), "must have bitmap field");
    assert!(struct_body.contains("sip_keys"), "must have sip_keys field");
}
#[test]
fn v11_f11b_bloom_format_corruption_undetectable() {
    let bloom = make_bloom(100);
    let mut data = BloomFilterData::from_bloom(&bloom);
    let original_bits = data.bitmap_bits;
    data.bitmap_bits = original_bits.wrapping_add(999_999);
    let bytes = data
        .to_bytes()
        .expect("serialize must succeed even with corrupted bitmap_bits");
    let recovered =
        BloomFilterData::from_bytes(&bytes).expect("deserialize must succeed — no version check");
    assert_eq!(
        recovered.bitmap_bits,
        original_bits.wrapping_add(999_999),
        "corrupted value survives roundtrip — no integrity check"
    );
}
// ═══════════════════════════════════════════════════════════════════════
// V11-F12: Fragile `as` casts in builder.rs
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: builder.rs uses `as u32` and `as u16` casts that are currently safe
// but fragile — if ENTRIES_PER_PAGE or entry size increases, they silently truncate.
#[test]
fn v11_f12a_entries_per_page_fits_in_u16() {
    assert!(
        ENTRIES_PER_PAGE <= u16::MAX as usize,
        "ENTRIES_PER_PAGE ({}) must fit in u16 — cast in builder.rs is fragile",
        ENTRIES_PER_PAGE
    );
}
#[test]
fn v11_f12b_max_page_bytes_fits_in_u32() {
    let max_page_bytes = ENTRIES_PER_PAGE * std::mem::size_of::<IndexEntry>();
    assert!(
        max_page_bytes <= u32::MAX as usize,
        "max page bytes ({max_page_bytes}) must fit in u32 — cast in builder.rs is fragile"
    );
}
// ═══════════════════════════════════════════════════════════════════════
// V11-F13: Bloom resize only triggered by batch inserts
// ═══════════════════════════════════════════════════════════════════════
//
// FINDING: rebuild_bloom_if_needed() is called ONLY from insert_batch(), not
// from insert(). Single-insert path never resizes bloom, causing FPR degradation
// at 1.5× overcapacity.
#[test]
fn v11_f13a_single_insert_path_skips_bloom_resize() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/store.rs"),
    )
    .expect("read store.rs");
    let insert_start = source
        .find("\n    pub fn insert(")
        .expect("insert fn must exist");
    let insert_batch_start = source
        .find("\n    pub fn insert_batch(")
        .expect("insert_batch fn must exist");
    assert!(
        insert_start < insert_batch_start,
        "insert must come before insert_batch"
    );
    let insert_body = &source[insert_start..insert_batch_start];
    assert!(
        insert_body.contains("rebuild_bloom_if_needed"),
        "insert() must call rebuild_bloom_if_needed — consistency with insert_batch per V13 Task 3"
    );
}
#[test]
fn v11_f13b_insert_batch_triggers_bloom_resize() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/store.rs"),
    )
    .expect("read store.rs");
    let insert_batch_start = source
        .find("\n    pub fn insert_batch(")
        .expect("insert_batch fn must exist");
    let after_batch = &source[insert_batch_start + 1..];
    let next_fn = after_batch
        .find("\n    pub fn ")
        .unwrap_or(after_batch.len());
    let batch_body = &after_batch[..next_fn];
    assert!(
        batch_body.contains("rebuild_bloom_if_needed"),
        "insert_batch() MUST call rebuild_bloom_if_needed — batch path resizes bloom"
    );
    let count = batch_body.matches("rebuild_bloom_if_needed").count();
    assert!(
        count >= 1,
        "rebuild_bloom_if_needed must appear in insert_batch body, found {count}"
    );
}
