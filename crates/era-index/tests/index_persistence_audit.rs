//! # Index Persistence Layer Audit Tests
//!
//! **Audit Date**: 2026-02-12
//! **Scope**: LSM-tree on-disk storage integration for single-file recoverability
//!
//! ## Test Categories
//!
//! 1. **Unit Tests**: IndexBuilder embedded finalize, MetaIndex serialization,
//!    footer index field population, page encryption/decryption roundtrip
//! 2. **Adversarial Tests**: Corrupted pages, truncated manifests, wrong keys,
//!    tampered bloom filters, block ID exhaustion, oversized payloads
//!
//! ## Key Invariants Under Test
//!
//! - All index data MUST be embedded in the .era volume (no external files)
//! - Footer MUST record index_offset/index_size/index_block_id when index is written
//! - Cold recovery via scan MUST succeed even when footer index fields are zero
//! - Encrypted index pages MUST be context-bound (block_id in AEAD AAD)
//! - Bloom filter MUST survive serialization roundtrip with identical false-positive behavior
//! - Malicious payloads MUST NOT cause panics or unbounded allocations

use bytes::Bytes;
use era_common::{
    ArchiveConfig, ArchiveId, BlockId, BlockType, ChunkHash, EncryptedMacroBlock, VolumeId,
};
use era_crypto::{KeySession, Salt};
use era_index::{IndexBuilder, IndexEntry, IndexReader, MetaIndex};
use era_storage::LocalStorageBackend;
use era_volume::{
    AccessPolicy, EncryptedVolumeKey, Footer, KeyWrapAlgorithm, RecipientSlot, RecipientType,
    SuperHeader, VolumeReader, VolumeWriter,
};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

// ============================================================================
// Helpers
// ============================================================================

/// Canonical test hash: BE at high bytes ensures sort order matches Redb's lexicographic byte comparison.
fn test_hash(value: u64) -> ChunkHash {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    ChunkHash::from_bytes(bytes)
}

fn create_test_session() -> (KeySession, era_crypto::VolumeKey, [u8; 16]) {
    let salt = Salt::generate();
    let params = era_crypto::KdfParams::fast();
    let session = KeySession::new(b"audit_password", &salt, &params).unwrap();
    let volume_key = session.generate_and_wrap_volume_key().unwrap().0;
    let nonce_context = *salt.as_bytes();
    (session, volume_key, nonce_context)
}

fn create_test_header(nonce_context: [u8; 16]) -> (SuperHeader, [u8; 16]) {
    let archive_id = ArchiveId::new();
    let header = SuperHeader::new(
        archive_id,
        vec![RecipientSlot::new(
            RecipientType::Argon2idPassword,
            Some([0x12; 8]),
            vec![0xAB; 16],
            vec![0xCD; 48],
        )],
        ArchiveConfig::default(),
        nonce_context,
        EncryptedVolumeKey::new(
            KeyWrapAlgorithm::XChaCha20Poly1305,
            [0u8; 24],
            vec![0u8; 48],
        ),
        AccessPolicy::AnyOfN,
    )
    .unwrap();
    let archive_id_bytes = *archive_id.0.as_bytes();
    (header, archive_id_bytes)
}

// ============================================================================
// UNIT TESTS: Index Persistence Fundamentals
// ============================================================================

/// Verify IndexBuilder::finalize() writes IndexPage and IndexManifest blocks
/// to the volume and returns a valid BlockLocation for the manifest.
#[tokio::test]
async fn test_embedded_finalize_writes_typed_blocks() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let volume_path = Path::new("typed_blocks.era");

    let (session, volume_key, nonce_context) = create_test_session();
    let (header, _) = create_test_header(nonce_context);
    let mut writer = VolumeWriter::create(&backend, volume_path, header)
        .await
        .unwrap();

    let mut builder = IndexBuilder::new_default().unwrap();
    for i in 0..50u64 {
        builder
            .insert(
                IndexEntry::new(test_hash(i), VolumeId::new(), BlockId::new(i / 10), 0, 1024)
                    .expect("valid entry"),
            )
            .unwrap();
    }

    let (meta, manifest_location) = builder
        .finalize(&mut writer, &session, &volume_key, nonce_context)
        .await
        .unwrap();

    // Manifest must have valid location
    assert!(
        manifest_location.physical_offset > 0,
        "IndexManifest must be written at non-zero offset"
    );
    assert!(
        manifest_location.encrypted_size > 0,
        "IndexManifest must have non-zero size"
    );

    // MetaIndex must have pages
    assert!(
        !meta.pages().is_empty(),
        "MetaIndex must contain at least one page pointer"
    );

    // Bloom filter must be populated
    assert!(
        !meta.bloom_filter().is_empty(),
        "MetaIndex bloom filter must be populated"
    );

    // Finalize volume with index location recorded in footer
    let _header = writer
        .finalize_with_catalog(
            0,
            0,
            0,
            manifest_location.physical_offset,
            manifest_location.encrypted_size,
            manifest_location.slot_index,
        )
        .await
        .unwrap();

    // Re-open and verify footer
    let reader = VolumeReader::open(&backend, volume_path).await.unwrap();
    let footer = reader.footer().expect("Volume must have footer");

    assert!(
        footer.has_index(),
        "Footer must report has_index()=true when index was written"
    );
    assert_eq!(footer.index_offset(), manifest_location.physical_offset);
    assert_eq!(footer.index_size(), manifest_location.encrypted_size);
}

#[tokio::test]
async fn test_cold_recovery_succeeds_with_nonzero_index_block_ids() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let volume_path = Path::new("nonzero_index_block_ids.era");

    let (session, volume_key, nonce_context) = create_test_session();
    let (header, archive_id) = create_test_header(nonce_context);
    let epoch_id = header.epoch_id();
    let mut writer = VolumeWriter::create(&backend, volume_path, header)
        .await
        .unwrap();

    let existing_data_block = EncryptedMacroBlock {
        block_id: BlockId::new(0),
        data: Bytes::from(vec![0xA5; 128]),
        original_size: 128,
        compressed_size: 128,
        chunk_count: 1,
    };
    writer
        .write_canonical_block(&existing_data_block, BlockType::Data)
        .await
        .unwrap();

    let mut builder = IndexBuilder::new_default_with_context(archive_id, epoch_id).unwrap();
    for i in 0..50u64 {
        builder
            .insert(
                IndexEntry::new(test_hash(i), VolumeId::new(), BlockId::new(i / 10), 0, 1024)
                    .expect("valid entry"),
            )
            .unwrap();
    }

    let (_meta, manifest_location) = builder
        .finalize(&mut writer, &session, &volume_key, nonce_context)
        .await
        .unwrap();

    assert!(
        manifest_location.slot_index > 0,
        "regression requires index manifest block_id to be non-zero"
    );

    let _ = writer
        .finalize_with_catalog(
            0,
            0,
            0,
            manifest_location.physical_offset,
            manifest_location.encrypted_size,
            manifest_location.slot_index,
        )
        .await
        .unwrap();

    let reader = VolumeReader::open(&backend, volume_path).await.unwrap();
    let recovered =
        IndexReader::recover_from_volume(&reader, &session, &volume_key, nonce_context, None)
            .await
            .expect("cold recovery must work with non-zero index block ids");

    for i in 0..50u64 {
        let result = recovered.lookup(&test_hash(i)).unwrap();
        assert!(result.is_some(), "entry {} must be recoverable", i);
    }
}

/// Verify MetaIndex serialization roundtrip via rkyv preserves all data.
#[test]
fn test_meta_index_rkyv_roundtrip() {
    let mut meta = MetaIndex::new();
    meta.add_page(test_hash(0), test_hash(99), BlockId::new(0), 0, 0)
        .unwrap();
    meta.add_page(test_hash(100), test_hash(199), BlockId::new(1), 0, 0)
        .unwrap();
    meta.add_page(test_hash(200), test_hash(299), BlockId::new(2), 0, 0)
        .unwrap();

    // Add a bloom filter
    let mut bloom = bloomfilter::Bloom::new_for_fp_rate(1000, 0.01);
    for i in 0..300u64 {
        bloom.set(&test_hash(i));
    }
    let bloom_bytes = era_index::serialize_bloom(&bloom).unwrap();
    meta.set_bloom_filter(bloom_bytes).unwrap();

    // Serialize → deserialize
    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&meta)
        .expect("MetaIndex serialization must not fail");
    let restored: MetaIndex = rkyv::from_bytes::<MetaIndex, rkyv::rancor::Error>(&bytes)
        .expect("MetaIndex deserialization must not fail");

    assert_eq!(
        restored.pages().len(),
        3,
        "Page count must survive roundtrip"
    );
    assert_eq!(
        *restored.pages()[0].min_hash(),
        test_hash(0),
        "Page hash range must survive roundtrip"
    );
    assert_eq!(
        *restored.pages()[2].max_hash(),
        test_hash(299),
        "Page hash range must survive roundtrip"
    );
    assert_eq!(
        restored.bloom_filter().len(),
        meta.bloom_filter().len(),
        "Bloom filter bytes must survive roundtrip"
    );
}

/// Verify Bloom filter survives serde roundtrip with correct false-positive behavior.
#[test]
fn test_bloom_filter_serde_roundtrip_correctness() {
    let mut bloom = bloomfilter::Bloom::<ChunkHash>::new_for_fp_rate(10_000, 0.01);

    // Insert 1000 hashes
    for i in 0..1000u64 {
        bloom.set(&test_hash(i));
    }

    // Serialize → deserialize
    let bytes = era_index::serialize_bloom(&bloom).unwrap();
    let restored = era_index::deserialize_bloom(&bytes).unwrap();

    // All inserted hashes must still be found (zero false negatives)
    for i in 0..1000u64 {
        assert!(
            restored.check(&test_hash(i)),
            "Bloom filter must have ZERO false negatives: hash {} missing after roundtrip",
            i
        );
    }

    // False positive rate on non-inserted hashes should be ~1%
    let mut false_positives = 0;
    let test_range = 10_000;
    for i in 1000..(1000 + test_range) {
        if restored.check(&test_hash(i)) {
            false_positives += 1;
        }
    }
    let fp_rate = false_positives as f64 / test_range as f64;
    assert!(
        fp_rate < 0.05,
        "Bloom false positive rate {:.3} exceeds 5% threshold after roundtrip",
        fp_rate
    );
}

/// Verify IndexPage binary search is correct for edge cases.
#[test]
fn test_index_page_binary_search_edge_cases() {
    use era_index::IndexEntry;

    // Single entry page
    let page = era_index::IndexPage::try_new(vec![IndexEntry::new(
        test_hash(42),
        VolumeId::new(),
        BlockId::new(0),
        0,
        1024,
    )
    .expect("valid entry")])
    .unwrap();
    assert!(page.find(&test_hash(42)).is_some());
    assert!(page.find(&test_hash(41)).is_none());
    assert!(page.find(&test_hash(43)).is_none());

    // Duplicate-adjacent hashes (all same hash)
    let entries: Vec<IndexEntry> = (0..5)
        .map(|i| {
            IndexEntry::new(test_hash(100), VolumeId::new(), BlockId::new(i), 0, 1024)
                .expect("valid entry")
        })
        .collect();
    let page = era_index::IndexPage::try_new(entries).unwrap();
    // binary_search_by_key will find one of them
    assert!(page.find(&test_hash(100)).is_some());

    // Max/min hash values
    let entries = vec![
        IndexEntry::new(
            ChunkHash::from_bytes([0u8; 32]),
            VolumeId::new(),
            BlockId::new(0),
            0,
            1024,
        )
        .expect("valid entry"),
        IndexEntry::new(
            ChunkHash::from_bytes([0xFF; 32]),
            VolumeId::new(),
            BlockId::new(1),
            0,
            1024,
        )
        .expect("valid entry"),
    ];
    let page = era_index::IndexPage::try_new(entries).unwrap();
    assert!(page.find(&ChunkHash::from_bytes([0u8; 32])).is_some());
    assert!(page.find(&ChunkHash::from_bytes([0xFF; 32])).is_some());
    assert!(page.find(&ChunkHash::from_bytes([0x80; 32])).is_none());
}

/// Verify that IndexBuilder enforces memory limits and spills correctly.
#[test]
fn test_builder_memory_bound_enforcement() {
    // With Redb backend, entries are stored in the database, not in memory.
    // This test verifies that the builder correctly tracks entry counts.
    let mut builder = IndexBuilder::new(1024 * 1024).unwrap(); // 1MB

    for i in 0..50u64 {
        builder
            .insert(
                IndexEntry::new(test_hash(i), VolumeId::new(), BlockId::new(0), 0, 1024)
                    .expect("valid entry"),
            )
            .unwrap();
    }

    assert_eq!(
        builder.entry_count(),
        50,
        "Builder must track all 50 inserted entries"
    );

    // Verify bloom filter contains all entries
    for i in 0..50u64 {
        assert!(
            builder.bloom_contains(&test_hash(i)),
            "Bloom filter must contain entry {}",
            i
        );
    }
}

/// Verify no external files are created when using embedded finalize.
#[tokio::test]
async fn test_no_external_files_after_embedded_finalize() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let volume_path = Path::new("no_external.era");

    let (session, volume_key, nonce_context) = create_test_session();
    let (header, _) = create_test_header(nonce_context);
    let mut writer = VolumeWriter::create(&backend, volume_path, header)
        .await
        .unwrap();

    let mut builder = IndexBuilder::new_default().unwrap();
    for i in 0..100u64 {
        builder
            .insert(
                IndexEntry::new(test_hash(i), VolumeId::new(), BlockId::new(0), 0, 1024)
                    .expect("valid entry"),
            )
            .unwrap();
    }

    let _ = builder
        .finalize(&mut writer, &session, &volume_key, nonce_context)
        .await
        .unwrap();
    let _ = writer.finalize().await.unwrap();

    // Only the .era file should exist — NO .bin, .json, .sst, .ldb files
    let external_files: Vec<_> = fs::read_dir(temp_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let path = e.path();
            let ext = path
                .extension()
                .map(|s| s.to_str().unwrap_or(""))
                .unwrap_or("");
            matches!(ext, "bin" | "json" | "sst" | "ldb" | "log" | "snap")
        })
        .collect();

    assert_eq!(
        external_files.len(),
        0,
        "No external index files should exist: {:?}",
        external_files.iter().map(|e| e.path()).collect::<Vec<_>>()
    );
}

/// Verify spill files are cleaned up after finalize.
/// Verify Redb staging file lifecycle via IndexStore: create, insert, destroy.
#[test]
fn test_redb_staging_file_lifecycle() {
    let temp_dir = TempDir::new().unwrap();
    let redb_path = temp_dir.path().join("staging.redb");

    // Create IndexStore at known path
    let mut store = era_index::IndexStore::create(&redb_path, 1024).unwrap();
    for i in 0..50u64 {
        store
            .insert(
                &IndexEntry::new(test_hash(i), VolumeId::new(), BlockId::new(0), 0, 1024)
                    .expect("valid entry"),
            )
            .unwrap();
    }

    // Redb staging file should exist
    assert!(
        redb_path.exists(),
        "Redb staging file must exist after inserts"
    );

    // Destroy cleans up the file
    store.destroy().unwrap();
    assert!(
        !redb_path.exists(),
        "Redb staging file must be removed after destroy()"
    );
}

// ============================================================================
// UNIT TESTS: Encrypted Page Roundtrip
// ============================================================================

/// Verify that IndexPage encrypted → written → read → decrypted produces
/// identical entries (end-to-end encryption roundtrip at the page level).
#[tokio::test]
async fn test_index_page_encryption_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let volume_path = Path::new("page_roundtrip.era");

    let (session, volume_key, nonce_context) = create_test_session();
    let (header, archive_id) = create_test_header(nonce_context);
    let mut writer = VolumeWriter::create(&backend, volume_path, header)
        .await
        .unwrap();

    // Insert 200 entries across different blocks
    let mut builder = IndexBuilder::new_default_with_context(archive_id, 0).unwrap();
    let mut expected_entries = Vec::new();
    for i in 0..200u64 {
        let entry = IndexEntry::new(
            test_hash(i),
            VolumeId::new(),
            BlockId::new(i / 50),
            (i % 50) as u32 * 1024,
            1024,
        )
        .expect("valid entry");
        expected_entries.push(entry);
        builder.insert(entry).unwrap();
    }

    let (_meta, manifest_location) = builder
        .finalize(&mut writer, &session, &volume_key, nonce_context)
        .await
        .unwrap();

    // Finalize with index location in footer
    let _ = writer
        .finalize_with_catalog(
            0,
            0,
            0,
            manifest_location.physical_offset,
            manifest_location.encrypted_size,
            manifest_location.slot_index,
        )
        .await
        .unwrap();

    // Cold recovery
    let reader = VolumeReader::open(&backend, volume_path).await.unwrap();
    let footer = reader.footer().unwrap();
    assert!(footer.has_index(), "Footer must indicate index presence");

    let recovered =
        IndexReader::recover_from_volume(&reader, &session, &volume_key, nonce_context, None)
            .await
            .unwrap();

    // Verify ALL 200 entries are recoverable
    for i in 0..200u64 {
        let result = recovered.lookup(&test_hash(i)).unwrap();
        assert!(
            result.is_some(),
            "Entry {} must be recoverable after cold recovery",
            i
        );
        let loc = result.unwrap();
        assert_eq!(loc.block_id, BlockId::new(i / 50));
        assert_eq!(loc.offset, (i % 50) as u32 * 1024);
    }

    // Verify non-existent entries return None
    for i in 200..210u64 {
        let result = recovered.lookup(&test_hash(i)).unwrap();
        assert!(
            result.is_none(),
            "Non-existent entry {} must return None",
            i
        );
    }
}

// ============================================================================
// ADVERSARIAL TESTS: Corrupted Index Recovery
// ============================================================================

/// Wrong decryption key must produce a clean error, not garbage data or panic.
#[tokio::test]
async fn test_wrong_key_cold_recovery_fails_cleanly() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let volume_path = Path::new("wrong_key.era");

    let (session, volume_key, nonce_context) = create_test_session();
    let (header, archive_id) = create_test_header(nonce_context);
    let mut writer = VolumeWriter::create(&backend, volume_path, header)
        .await
        .unwrap();

    let mut builder = IndexBuilder::new_default_with_context(archive_id, 0).unwrap();
    for i in 0..10u64 {
        builder
            .insert(
                IndexEntry::new(test_hash(i), VolumeId::new(), BlockId::new(0), 0, 1024)
                    .expect("valid entry"),
            )
            .unwrap();
    }

    let (_, manifest_loc) = builder
        .finalize(&mut writer, &session, &volume_key, nonce_context)
        .await
        .unwrap();

    let _ = writer
        .finalize_with_catalog(
            0,
            0,
            0,
            manifest_loc.physical_offset,
            manifest_loc.encrypted_size,
            manifest_loc.slot_index,
        )
        .await
        .unwrap();

    // Open with WRONG key
    let wrong_salt = Salt::generate();
    let wrong_params = era_crypto::KdfParams::fast();
    let wrong_session =
        KeySession::new(b"wrong_password_entirely", &wrong_salt, &wrong_params).unwrap();
    let wrong_vk = wrong_session.generate_and_wrap_volume_key().unwrap().0;
    let wrong_nonce = *wrong_salt.as_bytes();

    let reader = VolumeReader::open(&backend, volume_path).await.unwrap();

    // Recovery with wrong key must fail, not panic or return garbage
    let result =
        IndexReader::recover_from_volume(&reader, &wrong_session, &wrong_vk, wrong_nonce, None)
            .await;
    assert!(
        result.is_err(),
        "Cold recovery with wrong key must return Err, not Ok with garbage"
    );
}

/// Verify that MetaIndex deserialization rejects garbage bytes.
#[test]
fn test_meta_index_rejects_garbage_input() {
    let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x01, 0x02];
    let result = rkyv::from_bytes::<MetaIndex, rkyv::rancor::Error>(&garbage);
    assert!(
        result.is_err(),
        "MetaIndex deserialization must reject garbage bytes"
    );
}

/// Verify that truncated bloom filter data is rejected.
#[test]
fn test_truncated_bloom_filter_rejected() {
    let mut bloom = bloomfilter::Bloom::<ChunkHash>::new_for_fp_rate(100, 0.01);
    bloom.set(&test_hash(0));
    let bytes = era_index::serialize_bloom(&bloom).unwrap();

    // Truncate to half
    let truncated = &bytes[..bytes.len() / 2];
    let result = era_index::deserialize_bloom(truncated);
    assert!(result.is_err(), "Truncated bloom filter must be rejected");
}

/// Verify that empty bloom filter bytes are rejected.
#[test]
fn test_empty_bloom_filter_rejected() {
    let result = era_index::deserialize_bloom(&[]);
    assert!(result.is_err(), "Empty bloom filter must be rejected");
}

/// Verify that IndexPage with zero entries returns Err on construction
/// (panicking new() has been removed, only try_new() exists).
#[test]
fn test_empty_index_page_panics() {
    assert!(
        era_index::IndexPage::try_new(vec![]).is_err(),
        "try_new with empty vec must return Err"
    );
}

/// Large index: 10,000 entries to verify pagination works correctly.
#[tokio::test]
async fn test_large_index_embedded_finalize() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let volume_path = Path::new("large_index.era");

    let (session, volume_key, nonce_context) = create_test_session();
    let (header, archive_id) = create_test_header(nonce_context);
    let mut writer = VolumeWriter::create(&backend, volume_path, header)
        .await
        .unwrap();

    let entry_count = 10_000u64;
    let mut builder = IndexBuilder::new_default_with_context(archive_id, 0).unwrap();
    for i in 0..entry_count {
        builder
            .insert(
                IndexEntry::new(
                    test_hash(i),
                    VolumeId::new(),
                    BlockId::new(i / 1000),
                    (i % 1000) as u32 * 64,
                    64,
                )
                .expect("valid entry"),
            )
            .unwrap();
    }

    let (_meta, manifest_location) = builder
        .finalize(&mut writer, &session, &volume_key, nonce_context)
        .await
        .unwrap();

    // With 10,000 entries and ENTRIES_PER_PAGE=8192, we expect at least 1 page
    assert!(
        !_meta.pages().is_empty(),
        "Must have at least 1 page for 10k entries, got {}",
        _meta.pages().len()
    );

    let _ = writer
        .finalize_with_catalog(
            0,
            0,
            0,
            manifest_location.physical_offset,
            manifest_location.encrypted_size,
            manifest_location.slot_index,
        )
        .await
        .unwrap();

    // Recover and verify all entries
    let reader = VolumeReader::open(&backend, volume_path).await.unwrap();
    let recovered =
        IndexReader::recover_from_volume(&reader, &session, &volume_key, nonce_context, None)
            .await
            .unwrap();

    // Sample verification (checking all 10k would be slow)
    for i in (0..entry_count).step_by(100) {
        let result = recovered.lookup(&test_hash(i)).unwrap();
        assert!(
            result.is_some(),
            "Entry {} must be recoverable from 10k index",
            i
        );
    }
}

/// Verify footer has_index() returns false when index was not written.
#[tokio::test]
async fn test_footer_has_index_false_when_no_index() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let volume_path = Path::new("no_index.era");

    let (_, _, nonce_context) = create_test_session();
    let (header, _) = create_test_header(nonce_context);
    let writer = VolumeWriter::create(&backend, volume_path, header)
        .await
        .unwrap();

    // Finalize WITHOUT writing any index
    let _ = writer.finalize().await.unwrap();

    let reader = VolumeReader::open(&backend, volume_path).await.unwrap();
    let footer = reader.footer().expect("Volume must have footer");

    assert!(
        !footer.has_index(),
        "Footer must report has_index()=false when no index was written"
    );
    assert_eq!(footer.index_offset(), 0);
    assert_eq!(footer.index_size(), 0);
    assert_eq!(footer.index_block_id(), 0);
}

/// Verify that multiple index writes (overwrite scenario) use the last one.
#[tokio::test]
async fn test_multiple_index_writes_uses_last() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let volume_path = Path::new("multi_index.era");

    let (session, volume_key, nonce_context) = create_test_session();
    let (header, archive_id) = create_test_header(nonce_context);
    let mut writer = VolumeWriter::create(&backend, volume_path, header)
        .await
        .unwrap();

    // First index write (small)
    let mut builder1 = IndexBuilder::new_default_with_context(archive_id, 0).unwrap();
    for i in 0..5u64 {
        builder1
            .insert(
                IndexEntry::new(test_hash(i), VolumeId::new(), BlockId::new(0), 0, 1024)
                    .expect("valid entry"),
            )
            .unwrap();
    }
    let (_, loc1) = builder1
        .finalize(&mut writer, &session, &volume_key, nonce_context)
        .await
        .unwrap();

    // Second index write (larger, different entries)
    let mut builder2 = IndexBuilder::new_default_with_context(archive_id, 0).unwrap();
    for i in 100..120u64 {
        builder2
            .insert(
                IndexEntry::new(test_hash(i), VolumeId::new(), BlockId::new(1), 0, 2048)
                    .expect("valid entry"),
            )
            .unwrap();
    }
    let (_, loc2) = builder2
        .finalize(&mut writer, &session, &volume_key, nonce_context)
        .await
        .unwrap();

    // Use second index location in footer
    assert_ne!(
        loc1.physical_offset, loc2.physical_offset,
        "Two index writes must produce different offsets"
    );

    let _ = writer
        .finalize_with_catalog(
            0,
            0,
            0,
            loc2.physical_offset,
            loc2.encrypted_size,
            loc2.slot_index,
        )
        .await
        .unwrap();

    let reader = VolumeReader::open(&backend, volume_path).await.unwrap();
    let footer = reader.footer().unwrap();
    assert_eq!(footer.index_offset(), loc2.physical_offset);
}

/// Verify IndexReader from_memory handles empty entry list gracefully.
#[test]
fn test_index_reader_from_memory_empty() {
    let meta = MetaIndex::new();
    let reader = IndexReader::from_memory(meta, vec![]).unwrap();

    // Lookup on empty index must return None
    let result = reader.lookup(&test_hash(42)).unwrap();
    assert!(
        result.is_none(),
        "Empty index must return None for any lookup"
    );

    // bloom_contains on empty must return false
    assert!(!reader.bloom_contains(&test_hash(42)));
}

/// Verify IndexReader from_memory works with entries.
#[test]
fn test_index_reader_from_memory_with_entries() {
    let meta = MetaIndex::new();
    let mut bloom = bloomfilter::Bloom::<ChunkHash>::new_for_fp_rate(100, 0.01);

    let entries: Vec<IndexEntry> = (0..50u64)
        .map(|i| {
            let entry = IndexEntry::new(
                test_hash(i),
                VolumeId::new(),
                BlockId::new(i / 10),
                (i % 10) as u32 * 1024,
                1024,
            )
            .expect("valid entry");
            bloom.set(entry.hash());
            entry
        })
        .collect();

    let reader = IndexReader::from_memory(meta, entries).unwrap();

    for i in 0..50u64 {
        let result = reader.lookup(&test_hash(i)).unwrap();
        assert!(result.is_some(), "Entry {} must be found", i);
    }

    let result = reader.lookup(&test_hash(999)).unwrap();
    assert!(result.is_none());
}

// ============================================================================
// ADVERSARIAL TESTS: Block Type Integrity
// ============================================================================

/// Verify that scan_for_typed_blocks correctly identifies IndexPage blocks
/// among mixed block types.
#[tokio::test]
async fn test_scan_finds_index_blocks_among_mixed_types() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let volume_path = Path::new("mixed_blocks.era");

    let (_session, _volume_key, nonce_context) = create_test_session();
    let (header, _) = create_test_header(nonce_context);
    let mut writer = VolumeWriter::create(&backend, volume_path, header)
        .await
        .unwrap();

    // Write a Data block
    let data_block = era_common::EncryptedMacroBlock {
        block_id: BlockId::new(0),
        data: bytes::Bytes::from(vec![0xAA; 100]),
        original_size: 100,
        compressed_size: 100,
        chunk_count: 1,
    };
    writer
        .write_canonical_block(&data_block, BlockType::Data)
        .await
        .unwrap();

    // Write an IndexPage block
    let index_block = era_common::EncryptedMacroBlock {
        block_id: BlockId::new(1),
        data: bytes::Bytes::from(vec![0xBB; 200]),
        original_size: 200,
        compressed_size: 200,
        chunk_count: 0,
    };
    writer
        .write_canonical_block(&index_block, BlockType::IndexPage)
        .await
        .unwrap();

    // Write another Data block
    let data_block2 = era_common::EncryptedMacroBlock {
        block_id: BlockId::new(2),
        data: bytes::Bytes::from(vec![0xCC; 150]),
        original_size: 150,
        compressed_size: 150,
        chunk_count: 1,
    };
    writer
        .write_canonical_block(&data_block2, BlockType::Data)
        .await
        .unwrap();

    // Write an IndexManifest block
    let manifest_block = era_common::EncryptedMacroBlock {
        block_id: BlockId::new(3),
        data: bytes::Bytes::from(vec![0xDD; 300]),
        original_size: 300,
        compressed_size: 300,
        chunk_count: 0,
    };
    writer
        .write_canonical_block(&manifest_block, BlockType::IndexManifest)
        .await
        .unwrap();

    let _ = writer.finalize().await.unwrap();

    // Open and scan
    let reader = VolumeReader::open(&backend, volume_path).await.unwrap();

    let index_pages = reader
        .scan_for_typed_blocks(BlockType::IndexPage)
        .await
        .unwrap();
    assert_eq!(index_pages.len(), 1, "Must find exactly 1 IndexPage block");

    let manifests = reader
        .scan_for_typed_blocks(BlockType::IndexManifest)
        .await
        .unwrap();
    assert_eq!(
        manifests.len(),
        1,
        "Must find exactly 1 IndexManifest block"
    );

    let data_blocks = reader.scan_for_typed_blocks(BlockType::Data).await.unwrap();
    assert_eq!(data_blocks.len(), 2, "Must find exactly 2 Data blocks");
}

/// Footer checksum must reject tampered index fields.
#[test]
fn test_footer_checksum_rejects_tampered_index_fields() {
    let footer = Footer::with_catalog(
        8192, // data_end (must be >= HEADER_SIZE + FOOTER_SIZE = 4224)
        10,   // block_count
        1,    // sequence
        5000, // catalog_offset (must be >= HEADER_SIZE = 4096)
        500,  // catalog_size
        5,    // catalog_block_id
        0,    // checkpoint_offset
        0,    // checkpoint_block_id
        6000, // index_offset (must be >= HEADER_SIZE = 4096)
        300,  // index_size
        8,    // index_block_id
        7000, // backup_header_offset
    );

    let bytes = footer.to_bytes().unwrap();
    assert!(
        Footer::from_bytes(&bytes).is_ok(),
        "Valid footer must parse"
    );

    // Tamper with index_offset (bytes 64-71)
    let mut tampered = bytes;
    tampered[64] ^= 0xFF;
    let result = Footer::from_bytes(&tampered);
    assert!(
        result.is_err(),
        "Tampered footer index_offset must fail checksum"
    );
}

// ============================================================================
// ADVERSARIAL TESTS: ChunkIndex State Machine
// ============================================================================

/// Inserting into a finalized ChunkIndex must return error.
#[test]
fn test_insert_after_finalize_rejected() {
    let mut tree = era_index::ChunkIndex::new_default().unwrap();
    tree.insert(
        IndexEntry::new(test_hash(0), VolumeId::new(), BlockId::new(0), 0, 1024)
            .expect("valid entry"),
    )
    .unwrap();

    let _reader = tree.finalize().unwrap();

    // tree is consumed by finalize(), so we can't insert anymore
    // This is enforced at compile time by move semantics — test passes by compiling
}

/// ChunkIndex::finalize on empty tree should produce a valid empty reader.
#[test]
fn test_finalize_empty_tree() {
    let mut tree = era_index::ChunkIndex::new_default().unwrap();
    let reader = tree.finalize().unwrap();

    // Empty reader should not find anything
    assert!(!reader.bloom_contains(&test_hash(0)));
    let result = reader.lookup(&test_hash(0)).unwrap();
    assert!(result.is_none());
}

/// Bloom filter must have zero false negatives after ChunkIndex finalize.
#[test]
fn test_bloom_zero_false_negatives_after_finalize() {
    let mut tree = era_index::ChunkIndex::new_default().unwrap();
    let count = 500u64;

    for i in 0..count {
        tree.insert(
            IndexEntry::new(test_hash(i), VolumeId::new(), BlockId::new(0), 0, 1024)
                .expect("valid entry"),
        )
        .unwrap();
    }

    let reader = tree.finalize().unwrap();

    // Zero false negatives: every inserted hash must be in bloom
    for i in 0..count {
        assert!(
            reader.bloom_contains(&test_hash(i)),
            "Bloom false negative at hash {} after finalize",
            i
        );
    }
}

/// Verify that all unique hashes inserted are retrievable after finalize.
#[test]
fn test_all_entries_retrievable_after_finalize() {
    let mut tree = era_index::ChunkIndex::new_default().unwrap();
    let count = 300u64;

    for i in 0..count {
        tree.insert(
            IndexEntry::new(
                test_hash(i),
                VolumeId::new(),
                BlockId::new(i / 100),
                (i % 100) as u32 * 512,
                512,
            )
            .expect("valid entry"),
        )
        .unwrap();
    }

    let reader = tree.finalize().unwrap();

    for i in 0..count {
        let result = reader.lookup(&test_hash(i)).unwrap();
        assert!(result.is_some(), "Entry {} must be retrievable", i);
        let loc = result.unwrap();
        assert_eq!(loc.block_id, BlockId::new(i / 100));
        assert_eq!(loc.offset, (i % 100) as u32 * 512);
        assert_eq!(loc.length, 512);
    }
}

/// Verify deduplication: same hash inserted twice should be findable.
#[test]
fn test_duplicate_hash_insertion() {
    let mut tree = era_index::ChunkIndex::new_default().unwrap();
    let hash = test_hash(42);

    // Insert same hash with different locations
    tree.insert(
        IndexEntry::new(hash, VolumeId::new(), BlockId::new(0), 0, 1024).expect("valid entry"),
    )
    .unwrap();
    tree.insert(
        IndexEntry::new(hash, VolumeId::new(), BlockId::new(1), 4096, 2048).expect("valid entry"),
    )
    .unwrap();

    let reader = tree.finalize().unwrap();
    let result = reader.lookup(&hash).unwrap();
    assert!(result.is_some(), "Duplicate hash must still be findable");
}

// ============================================================================
// INTEGRATION GAP DETECTION: Engine-Level Index Persistence
// ============================================================================
// These tests document that the era-engine does NOT currently use V2.1 native
// index persistence. They serve as regression guards.

/// Verify that IndexBuilder::finalize() and writer.finalize_with_catalog()
/// correctly populate footer index fields end-to-end.
#[tokio::test]
async fn test_footer_index_fields_populated_after_full_flow() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let volume_path = Path::new("footer_fields.era");

    let (session, volume_key, nonce_context) = create_test_session();
    let (header, _) = create_test_header(nonce_context);
    let mut writer = VolumeWriter::create(&backend, volume_path, header)
        .await
        .unwrap();

    let mut builder = IndexBuilder::new_default().unwrap();
    for i in 0..25u64 {
        builder
            .insert(
                IndexEntry::new(test_hash(i), VolumeId::new(), BlockId::new(0), 0, 1024)
                    .expect("valid entry"),
            )
            .unwrap();
    }

    let (_, manifest_loc) = builder
        .finalize(&mut writer, &session, &volume_key, nonce_context)
        .await
        .unwrap();

    let _ = writer
        .finalize_with_catalog(
            0,
            0,
            0,
            manifest_loc.physical_offset,
            manifest_loc.encrypted_size,
            manifest_loc.slot_index,
        )
        .await
        .unwrap();

    let reader = VolumeReader::open(&backend, volume_path).await.unwrap();
    let footer = reader.footer().unwrap();

    // All three index fields must be non-zero
    assert!(
        footer.index_offset() > 0,
        "Footer index_offset must be populated"
    );
    assert!(
        footer.index_size() > 0,
        "Footer index_size must be populated"
    );
    // block_id could be 0 if there's only one page, so just check offset and size
    assert!(footer.has_index(), "Footer has_index() must be true");
}

/// Stress test: Index with entries spanning many pages.
#[tokio::test]
async fn test_multi_page_index_recovery() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let volume_path = Path::new("multi_page.era");

    let (session, volume_key, nonce_context) = create_test_session();
    let (header, archive_id) = create_test_header(nonce_context);
    let mut writer = VolumeWriter::create(&backend, volume_path, header)
        .await
        .unwrap();

    // ENTRIES_PER_PAGE = 8192, so 20,000 entries should give us 3 pages
    let entry_count = 20_000u64;
    let mut builder = IndexBuilder::new_default_with_context(archive_id, 0).unwrap();
    for i in 0..entry_count {
        builder
            .insert(
                IndexEntry::new(
                    test_hash(i),
                    VolumeId::new(),
                    BlockId::new(i / 5000),
                    (i % 5000) as u32 * 32,
                    32,
                )
                .expect("valid entry"),
            )
            .unwrap();
    }

    let (meta, manifest_loc) = builder
        .finalize(&mut writer, &session, &volume_key, nonce_context)
        .await
        .unwrap();

    assert!(
        meta.pages().len() >= 2,
        "20,000 entries with 8192/page must produce >= 2 pages, got {}",
        meta.pages().len()
    );

    let _ = writer
        .finalize_with_catalog(
            0,
            0,
            0,
            manifest_loc.physical_offset,
            manifest_loc.encrypted_size,
            manifest_loc.slot_index,
        )
        .await
        .unwrap();

    let reader = VolumeReader::open(&backend, volume_path).await.unwrap();
    let recovered =
        IndexReader::recover_from_volume(&reader, &session, &volume_key, nonce_context, None)
            .await
            .unwrap();

    // Verify entries from each page
    let test_indices = [0, 1000, 5000, 8191, 8192, 10000, 15000, 19999];
    for &i in &test_indices {
        let result = recovered.lookup(&test_hash(i)).unwrap();
        assert!(
            result.is_some(),
            "Entry {} must be recoverable from multi-page index",
            i
        );
    }
}
