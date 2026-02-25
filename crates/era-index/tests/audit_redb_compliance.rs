//! # Redb Compliance Audit — Hostile Technical Audit
//!
//! **Audit Date**: 2026-02-13
//! **Auditor**: Lead Systems Architect (Red Team)
//! **Spec Under Test**: `docs/RedbIndex.md` (RFC-023: "Ironclad" Indexing Protocol)
//!
//! ## Executive Finding
//!
//! The Redb migration is NOW IMPLEMENTED per RFC-023. These tests verify
//! the Redb 2.1 + rkyv architecture.
//!
//! ## Test Categories
//!
//! - **Test A**: Zero-copy proof via `rkyv::check_archived_root`
//! - **Test B**: Redb ACID crash safety
//! - **Test C**: "Zombie" recovery — garbage-appended volume
//! - **Test D**: `check_archived_root` usage audit on deserialization paths
//! - **Test E**: No `unwrap()` on I/O in production code paths
//! - **Test F**: Cargo.toml dependency audit

use era_common::{ArchiveConfig, ArchiveId, BlockId, ChunkHash, VolumeId};
use era_crypto::{KeySession, Salt};
use era_index::{
    serialize_bloom, BloomFilterData, IndexBuilder, IndexEntry, IndexPage, IndexReader, IndexStore,
    MetaIndex,
};
use era_storage::LocalStorageBackend;
use era_volume::{
    AccessPolicy, EncryptedVolumeKey, KeyWrapAlgorithm, RecipientSlot, RecipientType, SuperHeader,
    VolumeReader, VolumeWriter,
};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

// ============================================================================
// Helpers
// ============================================================================

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

fn create_test_session() -> (KeySession, era_crypto::VolumeKey, [u8; 16]) {
    let salt = Salt::generate();
    let params = era_crypto::KdfParams::fast();
    let session = KeySession::new(b"audit_password", &salt, &params).unwrap();
    let volume_key = session.generate_and_wrap_volume_key().unwrap().0;
    let nonce_context = *salt.as_bytes();
    (session, volume_key, nonce_context)
}

fn create_test_header(nonce_context: [u8; 16]) -> SuperHeader {
    SuperHeader::new(
        ArchiveId::new(),
        vec![RecipientSlot::new(
            RecipientType::ScryptPassword,
            Some([0x12; 8]),
            vec![0xAB; 16],
            vec![0xCD; 48],
        )],
        ArchiveConfig::default(),
        nonce_context,
        EncryptedVolumeKey {
            algorithm: KeyWrapAlgorithm::XChaCha20Poly1305,
            nonce: [0u8; 24],
            ciphertext: vec![0u8; 48],
        },
        AccessPolicy::AnyOfN,
    )
}

// ============================================================================
// TEST A: The Zero-Copy Proof
// ============================================================================

/// Prove IndexEntry can be accessed zero-copy via check_archived_root.
#[test]
fn test_a1_zero_copy_index_entry_access() {
    let entry = IndexEntry::new(test_hash(42), VolumeId::new(), BlockId::new(7), 8192, 4096);

    let bytes = rkyv::to_bytes::<_, 256>(&entry).expect("IndexEntry serialization must succeed");

    let archived = rkyv::check_archived_root::<IndexEntry>(&bytes)
        .expect("check_archived_root must succeed for valid IndexEntry bytes");

    assert_eq!(archived.offset, 8192, "Archived offset must match original");
    assert_eq!(archived.length, 4096, "Archived length must match original");
    assert_eq!(
        &archived.hash.0,
        entry.hash.as_bytes(),
        "Archived hash must be byte-identical to original"
    );
}

/// Prove IndexPage can be accessed zero-copy.
#[test]
fn test_a2_zero_copy_index_page_access() {
    let entries: Vec<IndexEntry> = (0..100).map(make_entry).collect();
    let page = IndexPage::try_new(entries).unwrap();

    let bytes = rkyv::to_bytes::<_, 4096>(&page).expect("IndexPage serialization must succeed");

    // Prove check_archived_root succeeds (zero-copy validation)
    let _archived = rkyv::check_archived_root::<IndexPage>(&bytes)
        .expect("check_archived_root must succeed for valid IndexPage bytes");

    // Deserialize and verify via getters (fields are private)
    let deserialized: IndexPage =
        rkyv::from_bytes(&bytes).expect("IndexPage deserialization must succeed");

    assert_eq!(
        *deserialized.min_hash(),
        test_hash(0),
        "Deserialized min_hash must match"
    );
    assert_eq!(
        *deserialized.max_hash(),
        test_hash(99),
        "Deserialized max_hash must match"
    );
    assert_eq!(
        deserialized.len(),
        100,
        "Deserialized entries count must match"
    );
    assert_eq!(
        deserialized.entries()[50].offset,
        make_entry(50).offset,
        "Deserialized entry[50].offset must match original"
    );
}

/// Prove MetaIndex can be accessed zero-copy.
#[test]
fn test_a3_zero_copy_meta_index_access() {
    let mut meta = MetaIndex::new();
    meta.add_page(test_hash(0), test_hash(999), BlockId::new(0))
        .unwrap();
    meta.add_page(test_hash(1000), test_hash(1999), BlockId::new(1))
        .unwrap();

    let bloom = bloomfilter::Bloom::<ChunkHash>::new_for_fp_rate(100, 0.01);
    let bloom_bytes = serialize_bloom(&bloom).unwrap();
    meta.set_bloom_filter(bloom_bytes.clone());

    let bytes = rkyv::to_bytes::<_, 4096>(&meta).expect("MetaIndex serialization must succeed");

    let archived = rkyv::check_archived_root::<MetaIndex>(&bytes)
        .expect("check_archived_root must succeed for valid MetaIndex bytes");

    assert_eq!(archived.pages.len(), 2, "Archived page count must match");
    assert_eq!(
        archived.bloom_filter.len(),
        bloom_bytes.len(),
        "Archived bloom filter length must match"
    );
}

/// Prove BloomFilterData survives zero-copy roundtrip.
#[test]
fn test_a4_zero_copy_bloom_filter_data() {
    let mut bloom = bloomfilter::Bloom::<ChunkHash>::new_for_fp_rate(1000, 0.01);
    for i in 0..500u64 {
        bloom.set(&test_hash(i));
    }

    let data = BloomFilterData::from_bloom(&bloom);
    let bytes =
        rkyv::to_bytes::<_, 4096>(&data).expect("BloomFilterData serialization must succeed");

    let archived = rkyv::check_archived_root::<BloomFilterData>(&bytes)
        .expect("check_archived_root must succeed for valid BloomFilterData bytes");

    assert_eq!(
        archived.bitmap_bits, data.bitmap_bits,
        "Archived bitmap_bits must match"
    );
    assert_eq!(archived.k_num, data.k_num, "Archived k_num must match");
}

// ============================================================================
// TEST B: Redb ACID Crash Safety
// ============================================================================

/// Redb committed entries survive simulated crash (drop without cleanup).
#[test]
fn test_b1_redb_crash_safety_committed_entries_survive() {
    let temp_dir = TempDir::new().unwrap();
    let redb_path = temp_dir.path().join("staging.redb");

    {
        let mut store = IndexStore::create(&redb_path, 1024).unwrap();
        for i in 0..1000u64 {
            store.insert(&make_entry(i)).unwrap();
        }
        // Simulate crash: preserve file on drop so recovery can reopen it
        store.keep_on_drop();
    }

    // Reopen — Redb auto-recovers to last valid transaction
    let store2 = IndexStore::open_readonly(&redb_path).unwrap();
    let entries = store2.read_sorted().unwrap();
    assert_eq!(
        entries.len(),
        1000,
        "All committed entries must survive crash"
    );
}

/// Redb staging file persists on disk after drop without finalize.
#[test]
fn test_b2_redb_staging_file_survives_crash() {
    let temp_dir = TempDir::new().unwrap();
    let redb_path = temp_dir.path().join("era-staging-test.redb");

    {
        let mut store = IndexStore::create(&redb_path, 1024).unwrap();
        for i in 0..100u64 {
            store.insert(&make_entry(i)).unwrap();
        }
        // Simulate crash: preserve file on drop
        store.keep_on_drop();
    }

    assert!(
        redb_path.exists(),
        "Redb staging file must persist on disk after crash"
    );

    let store = IndexStore::open_readonly(&redb_path).unwrap();
    assert_eq!(store.entry_count(), 100);
}

/// Two IndexStore instances with different paths are fully isolated.
#[test]
fn test_b3_redb_session_isolation() {
    let temp_dir = TempDir::new().unwrap();
    let path1 = temp_dir.path().join("store1.redb");
    let path2 = temp_dir.path().join("store2.redb");

    let mut store1 = IndexStore::create(&path1, 1024).unwrap();
    let mut store2 = IndexStore::create(&path2, 1024).unwrap();

    for i in 0..50u64 {
        store1.insert(&make_entry(i)).unwrap();
    }
    for i in 1000..1050u64 {
        store2.insert(&make_entry(i)).unwrap();
    }

    let entries1 = store1.read_sorted().unwrap();
    let entries2 = store2.read_sorted().unwrap();

    assert_eq!(entries1.len(), 50);
    assert_eq!(entries2.len(), 50);

    assert!(
        store1.get(&test_hash(1000)).unwrap().is_none(),
        "Store1 must NOT contain store2's entries"
    );
    assert!(
        store2.get(&test_hash(0)).unwrap().is_none(),
        "Store2 must NOT contain store1's entries"
    );
}

// ============================================================================
// TEST C: The "Zombie" Recovery
// ============================================================================

/// Write valid index to volume, append garbage bytes, verify cold recovery
/// still works for all entries.
#[tokio::test]
async fn test_c1_zombie_recovery_garbage_appended_to_volume() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let volume_path = Path::new("zombie_recovery.era");

    let (session, volume_key, nonce_context) = create_test_session();
    let header = create_test_header(nonce_context);
    let mut writer = VolumeWriter::create(&backend, volume_path, header)
        .await
        .unwrap();

    let mut builder = IndexBuilder::new_default().unwrap();
    for i in 0..500u64 {
        builder.insert(make_entry(i)).unwrap();
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

    // Append garbage bytes AFTER the footer
    let era_file_path = temp_dir.path().join(volume_path);
    {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&era_file_path)
            .unwrap();
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        file.write_all(&garbage).unwrap();
        file.sync_all().unwrap();
    }

    let reader = VolumeReader::open(&backend, volume_path).await.unwrap();
    let footer = reader
        .footer()
        .expect("Footer must be readable despite trailing garbage");
    assert!(
        footer.has_index(),
        "Footer must still report has_index()=true"
    );

    let recovered = IndexReader::recover_from_volume(&reader, &session, &volume_key, nonce_context)
        .await
        .unwrap();

    for i in 0..500u64 {
        let result = recovered.lookup(&test_hash(i)).unwrap();
        assert!(
            result.is_some(),
            "Entry {} must be recoverable after zombie recovery",
            i
        );
    }
}

/// Recovery with wrong credentials must fail cleanly.
#[tokio::test]
async fn test_c2_zombie_recovery_wrong_credentials_fails_cleanly() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let volume_path = Path::new("zombie_wrong_key.era");

    let (session, volume_key, nonce_context) = create_test_session();
    let header = create_test_header(nonce_context);
    let mut writer = VolumeWriter::create(&backend, volume_path, header)
        .await
        .unwrap();

    let mut builder = IndexBuilder::new_default().unwrap();
    for i in 0..50u64 {
        builder.insert(make_entry(i)).unwrap();
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

    let wrong_salt = Salt::generate();
    let wrong_params = era_crypto::KdfParams::fast();
    let wrong_session = KeySession::new(b"totally_wrong", &wrong_salt, &wrong_params).unwrap();
    let wrong_vk = wrong_session.generate_and_wrap_volume_key().unwrap().0;
    let wrong_nonce = *wrong_salt.as_bytes();

    let reader = VolumeReader::open(&backend, volume_path).await.unwrap();
    let result =
        IndexReader::recover_from_volume(&reader, &wrong_session, &wrong_vk, wrong_nonce).await;

    assert!(
        result.is_err(),
        "Recovery with wrong credentials must return Err, not Ok with garbage"
    );
}

// ============================================================================
// TEST D: check_archived_root Usage Audit
// ============================================================================

/// check_archived_root rejects truncated IndexEntry bytes.
#[test]
fn test_d1_check_archived_root_rejects_truncated_index_entry() {
    let entry = make_entry(42);
    let bytes = rkyv::to_bytes::<_, 256>(&entry).unwrap();

    let truncated = &bytes[..bytes.len() / 2];
    let result = rkyv::check_archived_root::<IndexEntry>(truncated);
    assert!(
        result.is_err(),
        "check_archived_root must reject truncated IndexEntry bytes"
    );
}

/// check_archived_root rejects garbage bytes for IndexPage.
#[test]
fn test_d2_check_archived_root_rejects_garbage_index_page() {
    let garbage = vec![0xFF; 1024];
    let result = rkyv::check_archived_root::<IndexPage>(&garbage);
    assert!(
        result.is_err(),
        "check_archived_root must reject garbage bytes for IndexPage"
    );
}

/// check_archived_root rejects garbage bytes for MetaIndex.
#[test]
fn test_d3_check_archived_root_rejects_garbage_meta_index() {
    let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x01, 0x02];
    let result = rkyv::check_archived_root::<MetaIndex>(&garbage);
    assert!(
        result.is_err(),
        "check_archived_root must reject garbage bytes for MetaIndex"
    );
}

/// rkyv::from_bytes also rejects garbage (validation enabled in rkyv 0.7).
#[test]
fn test_d4_from_bytes_rejects_garbage_meta_index() {
    let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x01, 0x02];
    let result = rkyv::from_bytes::<MetaIndex>(&garbage);
    assert!(
        result.is_err(),
        "rkyv::from_bytes must reject garbage bytes (validation enabled)"
    );
}

/// A single bit flip must be caught or produce structurally valid data (no panic).
#[test]
fn test_d5_check_archived_root_handles_bitflipped_vec() {
    let entries: Vec<IndexEntry> = (0..10).map(make_entry).collect();
    let mut bytes = rkyv::to_bytes::<_, 4096>(&entries).unwrap().to_vec();

    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;

    match rkyv::check_archived_root::<Vec<IndexEntry>>(&bytes) {
        Err(_) => { /* Good: validation caught the corruption */ }
        Ok(archived) => {
            let _len = archived.len();
        }
    }
}

/// Source audit: store.rs MUST use validated rkyv deserialization.
///
/// Redb value bytes may not be 8-byte aligned, so `check_archived_root`
/// can fail with alignment errors. `rkyv::from_bytes` handles alignment
/// internally while still performing full validation (rkyv 0.7 + validation
/// feature). Both approaches are spec-compliant.
#[test]
fn test_d6_store_uses_validated_deserialization() {
    let store_source = include_str!("../src/store.rs");
    let uses_from_bytes = store_source.contains("rkyv::from_bytes");
    let uses_check_archived = store_source.contains("check_archived_root");
    assert!(
        uses_from_bytes || uses_check_archived,
        "SPEC COMPLIANCE: store.rs MUST use rkyv::from_bytes or rkyv::check_archived_root \
         for validated deserialization."
    );
}

/// Source audit: reader.rs deserialization approach.
#[test]
fn test_d7_reader_deserialization_audit() {
    let reader_source = include_str!("../src/reader.rs");

    let uses_check_archived = reader_source.contains("check_archived_root");
    assert!(
        uses_check_archived,
        "reader.rs must use check_archived_root for validated deserialization"
    );
}

// ============================================================================
// TEST E: No unwrap() on I/O in Production Code
// ============================================================================

fn audit_source_for_io_unwrap(source: &str, filename: &str) {
    let mut in_test_block = false;
    let mut brace_depth: i32 = 0;

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed.contains("#[cfg(test)]") {
            in_test_block = true;
            brace_depth = 0;
        }
        if in_test_block {
            brace_depth += trimmed.matches('{').count() as i32;
            brace_depth -= trimmed.matches('}').count() as i32;
            if brace_depth < 0 {
                in_test_block = false;
            }
            continue;
        }
        if trimmed.starts_with("#[test]") || trimmed.starts_with("#[tokio::test]") {
            continue;
        }

        if trimmed.starts_with("//") || trimmed.starts_with("///") {
            continue;
        }

        if trimmed.contains(".unwrap()") || trimmed.contains(".expect(") {
            let is_io = trimmed.contains("File::")
                || trimmed.contains("fs::")
                || trimmed.contains(".read_to_end(")
                || trimmed.contains(".write_all(")
                || trimmed.contains(".open(")
                || trimmed.contains(".create(")
                || trimmed.contains(".sync_all(")
                || trimmed.contains("tempfile")
                || trimmed.contains(".tempfile()")
                || trimmed.contains(".keep()")
                || trimmed.contains("Database::")
                || trimmed.contains("IndexStore::");

            assert!(
                !is_io,
                "{} line {}: FORBIDDEN unwrap()/expect() on I/O operation: {}",
                filename,
                line_num + 1,
                trimmed
            );
        }
    }
}

#[test]
fn test_e1_builder_no_unwrap_on_io() {
    let source = include_str!("../src/builder.rs");
    audit_source_for_io_unwrap(source, "builder.rs");
}

#[test]
fn test_e2_store_no_unwrap_on_io() {
    let source = include_str!("../src/store.rs");
    audit_source_for_io_unwrap(source, "store.rs");
}

#[test]
fn test_e3_reader_no_unwrap_on_io() {
    let source = include_str!("../src/reader.rs");
    audit_source_for_io_unwrap(source, "reader.rs");
}

#[test]
fn test_e4_lsm_tree_no_unwrap_on_io() {
    let source = include_str!("../src/lsm_tree.rs");
    audit_source_for_io_unwrap(source, "lsm_tree.rs");
}

// ============================================================================
// TEST F: Cargo.toml Dependency Audit
// ============================================================================

/// Audit Cargo.toml for spec compliance — Redb MUST be present.
#[test]
fn test_f1_cargo_toml_spec_compliance() {
    let cargo_toml = include_str!("../Cargo.toml");

    // SPEC COMPLIANCE: redb IS a dependency
    let has_redb = cargo_toml.contains("redb");
    assert!(
        has_redb,
        "redb MUST be present in Cargo.toml per RFC-023 (docs/RedbIndex.md §4.1)"
    );

    // rkyv IS present
    assert!(
        cargo_toml.contains("rkyv"),
        "rkyv must be present in dependencies (spec §4.1)"
    );

    // No legacy dependencies
    assert!(
        !cargo_toml.contains("rocksdb"),
        "RocksDB must not be in dependencies"
    );
    assert!(
        !cargo_toml.contains("leveldb"),
        "LevelDB must not be in dependencies"
    );
    assert!(
        !cargo_toml.contains("bincode"),
        "bincode must not be in dependencies (spec mandates rkyv exclusively)"
    );
    assert!(
        !cargo_toml.contains("serde_json"),
        "serde_json must not be in dependencies (spec mandates rkyv exclusively)"
    );
}
