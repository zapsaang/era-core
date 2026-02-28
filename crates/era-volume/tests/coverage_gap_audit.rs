//! Iteration 11 — Test Coverage Gap Audit
//!
//! Targeted negative tests for error paths discovered during the Coverage Gap Audit.
//! These tests exercise `return Err(...)` branches that had zero prior test coverage,
//! focusing on:
//! - `header.rs` TryFrom bounds (D10-02, D10-03 fixes)
//! - `volume_pool.rs` finalization length mismatches
//! - `reader.rs` file-too-small rejection
//! - `writer.rs` setter validation

use era_common::proto;
use era_common::{ArchiveConfig, ArchiveId, EraError};
use era_volume::{
    AccessPolicy, EncryptedVolumeKey, KeyWrapAlgorithm, RecipientSlot, RecipientType, SuperHeader,
    VolumePool, VolumePoolConfig, VolumeReader, VolumeWriter, HEADER_SIZE, MAX_RECIPIENTS,
};
use prost::Message;
use std::path::Path;

// ============================================================================
// Helper constructors
// ============================================================================

fn mock_recipient() -> RecipientSlot {
    RecipientSlot::new(
        RecipientType::Argon2idPassword,
        Some([0x12; 8]),
        vec![0xAB; 16],
        vec![0xCD; 48],
    )
}

fn mock_encrypted_vk() -> EncryptedVolumeKey {
    EncryptedVolumeKey::new(KeyWrapAlgorithm::XChaCha20Poly1305, [0xAA; 24], vec![0xBB; 48])
}

fn make_header() -> SuperHeader {
    SuperHeader::new(
        ArchiveId::new(),
        vec![mock_recipient()],
        ArchiveConfig::default(),
        [0u8; 16],
        mock_encrypted_vk(),
        AccessPolicy::AnyOfN,
    )
    .unwrap()
}

/// Build a valid proto::SuperHeader from a real header, then allow mutation.
fn make_valid_proto_header() -> proto::SuperHeader {
    let header = make_header();
    // Use the From<SuperHeader> impl to get a valid proto
    header.into()
}

// ============================================================================
// Group 1: header.rs — SuperHeader::from_bytes() pre-decode limit (D10-03)
// ============================================================================

#[test]
fn test_from_bytes_rejects_oversized_input() {
    // D10-03: from_bytes() rejects data.len() > HEADER_SIZE before protobuf decode
    let oversized = vec![0u8; HEADER_SIZE + 1];
    let err = SuperHeader::from_bytes(&oversized).unwrap_err();
    match &err {
        EraError::CorruptedHeader(msg) => {
            assert!(
                msg.contains("header data too large"),
                "Expected 'header data too large', got: {msg}"
            );
        }
        other => panic!("Expected CorruptedHeader, got: {other:?}"),
    }
}

// ============================================================================
// Group 2: header.rs — TryFrom<proto::RecipientSlot> bounds (D10-02)
// ============================================================================

/// Encode a proto::SuperHeader to bytes (length-delimited, padded to HEADER_SIZE)
/// so we can feed it through SuperHeader::from_bytes() → TryFrom pipeline.
fn encode_proto_header(proto_header: &proto::SuperHeader) -> Vec<u8> {
    let mut data = Vec::new();
    proto_header.encode_length_delimited(&mut data).unwrap();
    // Pad to HEADER_SIZE so it passes the pre-decode size check
    if data.len() < HEADER_SIZE {
        data.resize(HEADER_SIZE, 0);
    }
    data
}

#[test]
fn test_tryfrom_rejects_oversized_recipient_params() {
    // D10-02: params.len() > 4096 (MAX_RECIPIENT_FIELD_SIZE)
    // Test TryFrom<proto::RecipientSlot> directly since from_bytes() has a
    // pre-decode size limit that fires first when the total proto exceeds HEADER_SIZE.
    let valid_proto = make_valid_proto_header();
    let mut slot = valid_proto.recipients[0].clone();
    slot.params = vec![0xFF; 4097];

    let result: Result<RecipientSlot, EraError> = slot.try_into();
    let err = result.unwrap_err();
    match &err {
        EraError::CorruptedHeader(msg) => {
            assert!(
                msg.contains("recipient params too large"),
                "Expected 'recipient params too large', got: {msg}"
            );
        }
        other => panic!("Expected CorruptedHeader, got: {other:?}"),
    }
}

#[test]
fn test_tryfrom_rejects_oversized_encrypted_master_key() {
    // D10-02: encrypted_master_key.len() > 4096
    // Test TryFrom<proto::RecipientSlot> directly to bypass the pre-decode size limit.
    let valid_proto = make_valid_proto_header();
    let mut slot = valid_proto.recipients[0].clone();
    slot.encrypted_master_key = vec![0xFF; 4097];

    let result: Result<RecipientSlot, EraError> = slot.try_into();
    let err = result.unwrap_err();
    match &err {
        EraError::CorruptedHeader(msg) => {
            assert!(
                msg.contains("encrypted_master_key too large"),
                "Expected 'encrypted_master_key too large', got: {msg}"
            );
        }
        other => panic!("Expected CorruptedHeader, got: {other:?}"),
    }
}

#[test]
fn test_tryfrom_rejects_short_encrypted_master_key() {
    // encrypted_master_key.len() < 24 (minimum for nonce + ciphertext)
    let mut proto_header = make_valid_proto_header();
    proto_header.recipients[0].encrypted_master_key = vec![0xFF; 23];

    let data = encode_proto_header(&proto_header);
    let err = SuperHeader::from_bytes(&data).unwrap_err();
    match &err {
        EraError::CorruptedHeader(msg) => {
            assert!(
                msg.contains("encrypted_master_key too short"),
                "Expected 'encrypted_master_key too short', got: {msg}"
            );
        }
        other => panic!("Expected CorruptedHeader, got: {other:?}"),
    }
}

// ============================================================================
// Group 3: header.rs — TryFrom<proto::EncryptedVolumeKey> bounds (D10-02)
// ============================================================================

#[test]
fn test_tryfrom_rejects_empty_evk_ciphertext() {
    // EVK with empty ciphertext should be rejected
    let mut proto_header = make_valid_proto_header();
    if let Some(ref mut evk) = proto_header.encrypted_volume_key {
        evk.ciphertext = vec![];
    }

    let data = encode_proto_header(&proto_header);
    let err = SuperHeader::from_bytes(&data).unwrap_err();
    match &err {
        EraError::CorruptedHeader(msg) => {
            assert!(
                msg.contains("Missing ciphertext"),
                "Expected 'Missing ciphertext', got: {msg}"
            );
        }
        other => panic!("Expected CorruptedHeader, got: {other:?}"),
    }
}

#[test]
fn test_tryfrom_rejects_oversized_evk_ciphertext() {
    // D10-02: ciphertext.len() > 4096 (MAX_EVK_CIPHERTEXT_SIZE)
    // Test TryFrom<proto::EncryptedVolumeKey> directly to bypass the pre-decode size limit.
    let valid_proto = make_valid_proto_header();
    let mut evk = valid_proto.encrypted_volume_key.unwrap().clone();
    evk.ciphertext = vec![0xFF; 4097];

    let result: Result<EncryptedVolumeKey, EraError> = evk.try_into();
    let err = result.unwrap_err();
    match &err {
        EraError::CorruptedHeader(msg) => {
            assert!(
                msg.contains("EVK ciphertext too large"),
                "Expected 'EVK ciphertext too large', got: {msg}"
            );
        }
        other => panic!("Expected CorruptedHeader, got: {other:?}"),
    }
}

// ============================================================================
// Group 4: header.rs — TryFrom<proto::SuperHeader> recipient bounds
// ============================================================================

#[test]
fn test_tryfrom_rejects_empty_recipients() {
    // SuperHeader with 0 recipients should fail TryFrom
    let mut proto_header = make_valid_proto_header();
    proto_header.recipients.clear();

    let data = encode_proto_header(&proto_header);
    let err = SuperHeader::from_bytes(&data).unwrap_err();
    match &err {
        EraError::CorruptedHeader(msg) => {
            assert!(
                msg.contains("at least one recipient"),
                "Expected 'at least one recipient', got: {msg}"
            );
        }
        other => panic!("Expected CorruptedHeader, got: {other:?}"),
    }
}

#[test]
fn test_tryfrom_rejects_too_many_recipients() {
    // SuperHeader with > MAX_RECIPIENTS (256) should fail TryFrom.
    // We can't encode this into HEADER_SIZE bytes (too large for 4096),
    // so we verify the constructor-level validation directly.
    let recipients: Vec<RecipientSlot> =
        (0..MAX_RECIPIENTS + 1).map(|_| mock_recipient()).collect();

    let err = SuperHeader::new(
        ArchiveId::new(),
        recipients,
        ArchiveConfig::default(),
        [0u8; 16],
        mock_encrypted_vk(),
        AccessPolicy::AnyOfN,
    )
    .unwrap_err();
    match &err {
        EraError::InvalidConfig(msg) => {
            assert!(
                msg.contains("too many recipients"),
                "Expected 'too many recipients', got: {msg}"
            );
        }
        other => panic!("Expected InvalidConfig, got: {other:?}"),
    }
}

#[test]
fn test_to_bytes_rejects_oversized_header() {
    // A header that serializes to > HEADER_SIZE bytes should fail.
    // We construct a header with the maximum allowed recipients (256) with large params
    // to exceed the 4096-byte limit after protobuf encoding.
    let big_recipients: Vec<RecipientSlot> = (0..MAX_RECIPIENTS)
        .map(|_| {
            RecipientSlot::new(
                RecipientType::Argon2idPassword,
                Some([0x12; 8]),
                vec![0xAB; 64], // 64 bytes of params per recipient
                vec![0xCD; 48],
            )
        })
        .collect();

    let header = SuperHeader::new(
        ArchiveId::new(),
        big_recipients,
        ArchiveConfig::default(),
        [0u8; 16],
        mock_encrypted_vk(),
        AccessPolicy::AnyOfN,
    )
    .unwrap();

    let err = header.to_bytes().unwrap_err();
    match &err {
        EraError::Serialization(msg) => {
            assert!(
                msg.contains("Header too large"),
                "Expected 'Header too large', got: {msg}"
            );
        }
        other => panic!("Expected Serialization error, got: {other:?}"),
    }
}

// ============================================================================
// Group 5: header.rs — TryFrom<proto::SuperHeader> threshold validation
// ============================================================================

#[test]
fn test_tryfrom_rejects_threshold_below_two() {
    // Threshold(1) is a policy downgrade — must be rejected
    let mut proto_header = make_valid_proto_header();
    proto_header.access_policy = proto::AccessPolicy::Threshold.into();
    proto_header.threshold = 1;

    let data = encode_proto_header(&proto_header);
    let err = SuperHeader::from_bytes(&data).unwrap_err();
    match &err {
        EraError::CorruptedHeader(msg) => {
            assert!(
                msg.contains("Invalid threshold") && msg.contains("minimum 2"),
                "Expected threshold < 2 rejection, got: {msg}"
            );
        }
        other => panic!("Expected CorruptedHeader, got: {other:?}"),
    }
}

// ============================================================================
// Group 6: volume_pool.rs — finalize_with_catalogs length mismatches
// ============================================================================

use era_storage::LocalStorageBackend;
use tempfile::TempDir;

fn create_test_header() -> SuperHeader {
    make_header()
}

#[tokio::test]
async fn test_finalize_with_catalogs_rejects_catalog_length_mismatch() {
    // finalize_with_catalogs requires catalog_locations.len() == writers.len()
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let base_path = temp_dir.path().join("test_archive");

    let config = VolumePoolConfig::new(&base_path, 2);
    let header = create_test_header();

    let mut pool = VolumePool::create(backend, config, header).await.unwrap();
    assert_eq!(pool.volume_count(), 2);

    // Pass 1 catalog location for 2 writers → mismatch
    let catalog_locs = [(0u64, 0u32, 0u32)];
    let err = pool
        .finalize_with_catalogs(&catalog_locs, None)
        .await
        .unwrap_err();
    match &err {
        EraError::InvalidConfig(msg) => {
            assert!(
                msg.contains("catalog_locations length")
                    && msg.contains("does not match volume count"),
                "Expected catalog length mismatch, got: {msg}"
            );
        }
        other => panic!("Expected InvalidConfig, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_finalize_with_catalogs_rejects_index_length_mismatch() {
    // finalize_with_catalogs requires index_locations.len() == writers.len() (if Some)
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let base_path = temp_dir.path().join("test_archive");

    let config = VolumePoolConfig::new(&base_path, 2);
    let header = create_test_header();

    let mut pool = VolumePool::create(backend, config, header).await.unwrap();

    // 2 catalog locations (correct), but 1 index location (mismatch)
    let catalog_locs = [(0u64, 0u32, 0u32), (0, 0, 0)];
    let index_locs = [(0u64, 0u32, 0u32)];
    let err = pool
        .finalize_with_catalogs(&catalog_locs, Some(&index_locs))
        .await
        .unwrap_err();
    match &err {
        EraError::InvalidConfig(msg) => {
            assert!(
                msg.contains("index_locations length")
                    && msg.contains("does not match volume count"),
                "Expected index length mismatch, got: {msg}"
            );
        }
        other => panic!("Expected InvalidConfig, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_needs_expansion_rejects_oversized_data() {
    // needs_expansion returns Err when required_size exceeds max per-volume capacity
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let base_path = temp_dir.path().join("test_archive");

    // Use the minimum volume size to make it easy to exceed
    let config = VolumePoolConfig::new(&base_path, 1).with_max_size(era_volume::MIN_VOLUME_SIZE);
    let header = create_test_header();

    let pool = VolumePool::create(backend, config, header).await.unwrap();

    // Request more space than any single volume can hold
    let err = pool.needs_expansion(u64::MAX).unwrap_err();
    match &err {
        EraError::InvalidConfig(msg) => {
            assert!(
                msg.contains("exceeds maximum per-volume capacity"),
                "Expected per-volume capacity error, got: {msg}"
            );
        }
        other => panic!("Expected InvalidConfig, got: {other:?}"),
    }
}

// ============================================================================
// Group 7: reader.rs — file too small for footer
// ============================================================================

#[tokio::test]
async fn test_reader_rejects_file_smaller_than_header() {
    // VolumeReader::open rejects files smaller than HEADER_SIZE
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());

    // Create a tiny file (smaller than HEADER_SIZE)
    let path = temp_dir.path().join("tiny.era");
    std::fs::write(&path, [0u8; 100]).unwrap();

    let result = VolumeReader::open(&backend, Path::new("tiny.era")).await;
    assert!(result.is_err(), "Expected an error for tiny volume");
    let err = result.err().unwrap();
    match &err {
        EraError::CorruptedHeader(msg) => {
            assert!(
                msg.contains("Volume too small"),
                "Expected 'Volume too small', got: {msg}"
            );
        }
        other => panic!("Expected CorruptedHeader, got: {other:?}"),
    }
}

// ============================================================================
// Group 8: writer.rs — setter validation
// ============================================================================

#[tokio::test]
async fn test_writer_set_catalog_info_rejects_inconsistent_offset_size() {
    // set_catalog_info rejects offset=0, size!=0 (and vice versa)
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());

    let header = create_test_header();
    let mut writer = VolumeWriter::create(&backend, Path::new("test.era"), header)
        .await
        .unwrap();

    // offset=0, size=100 → inconsistent
    let err = writer.set_catalog_info(0, 100, 0).unwrap_err();
    match &err {
        EraError::InvalidConfig(msg) => {
            assert!(
                msg.contains("both be zero or both non-zero"),
                "Expected consistency error, got: {msg}"
            );
        }
        other => panic!("Expected InvalidConfig, got: {other:?}"),
    }

    // offset=100, size=0 → inconsistent
    let err = writer.set_catalog_info(100, 0, 0).unwrap_err();
    match &err {
        EraError::InvalidConfig(msg) => {
            assert!(
                msg.contains("both be zero or both non-zero"),
                "Expected consistency error, got: {msg}"
            );
        }
        other => panic!("Expected InvalidConfig, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_writer_set_catalog_info_rejects_offset_past_position() {
    // set_catalog_info rejects offset > current write position
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());

    let header = create_test_header();
    let mut writer = VolumeWriter::create(&backend, Path::new("test.era"), header)
        .await
        .unwrap();

    // Position is DATA_REGION_START (4224). Use an offset far beyond that.
    let err = writer.set_catalog_info(u64::MAX, 100, 0).unwrap_err();
    match &err {
        EraError::InvalidConfig(msg) => {
            assert!(
                msg.contains("catalog_offset") && msg.contains("exceeds current position"),
                "Expected position bounds error, got: {msg}"
            );
        }
        other => panic!("Expected InvalidConfig, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_writer_set_index_info_rejects_inconsistent_offset_size() {
    // set_index_info has the same consistency check
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());

    let header = create_test_header();
    let mut writer = VolumeWriter::create(&backend, Path::new("test.era"), header)
        .await
        .unwrap();

    let err = writer.set_index_info(0, 100, 0).unwrap_err();
    match &err {
        EraError::InvalidConfig(msg) => {
            assert!(
                msg.contains("both be zero or both non-zero"),
                "Expected consistency error, got: {msg}"
            );
        }
        other => panic!("Expected InvalidConfig, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_writer_set_checkpoint_rejects_offset_past_position() {
    // set_last_checkpoint rejects offset > current write position
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());

    let header = create_test_header();
    let mut writer = VolumeWriter::create(&backend, Path::new("test.era"), header)
        .await
        .unwrap();

    let err = writer.set_last_checkpoint(u64::MAX).unwrap_err();
    match &err {
        EraError::InvalidConfig(msg) => {
            assert!(
                msg.contains("checkpoint_offset") && msg.contains("exceeds current position"),
                "Expected position bounds error, got: {msg}"
            );
        }
        other => panic!("Expected InvalidConfig, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_writer_set_checkpoint_with_block_id_rejects_offset_past_position() {
    // set_last_checkpoint_with_block_id rejects offset > current write position
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());

    let header = create_test_header();
    let mut writer = VolumeWriter::create(&backend, Path::new("test.era"), header)
        .await
        .unwrap();

    let err = writer
        .set_last_checkpoint_with_block_id(u64::MAX, 42)
        .unwrap_err();
    match &err {
        EraError::InvalidConfig(msg) => {
            assert!(
                msg.contains("checkpoint_offset") && msg.contains("exceeds current position"),
                "Expected position bounds error, got: {msg}"
            );
        }
        other => panic!("Expected InvalidConfig, got: {other:?}"),
    }
}

// ============================================================================
// Group 9: header.rs — version & magic validation through from_bytes()
// ============================================================================

#[test]
fn test_from_bytes_rejects_wrong_magic() {
    // Corrupt the magic bytes in an otherwise valid header
    // The magic field is inside the protobuf, so we need to manipulate the proto directly.
    // Corrupt first few bytes of the length-delimited protobuf stream.
    // The magic field is inside the protobuf, so we need to manipulate the proto directly.
    let mut proto_header = make_valid_proto_header();
    proto_header.magic = vec![0xFF; 8]; // Wrong magic
    let data = encode_proto_header(&proto_header);

    let err = SuperHeader::from_bytes(&data).unwrap_err();
    match &err {
        EraError::InvalidMagic => {} // Expected
        other => panic!("Expected InvalidMagic, got: {other:?}"),
    }
}

#[test]
fn test_from_bytes_rejects_wrong_version() {
    let mut proto_header = make_valid_proto_header();
    proto_header.version = 999; // Unsupported version

    let data = encode_proto_header(&proto_header);
    let err = SuperHeader::from_bytes(&data).unwrap_err();
    match &err {
        EraError::UnsupportedVersion { version: 999 } => {} // Expected
        other => panic!("Expected UnsupportedVersion {{ version: 999 }}, got: {other:?}"),
    }
}

// ============================================================================
// Iteration 12 — Cryptographic Context Binding Audit tests
// ============================================================================

// --- C12-01: Debug redaction tests ---

#[test]
fn test_encrypted_volume_key_debug_redacts_nonce_and_ciphertext() {
    let evk = mock_encrypted_vk();
    let debug_output = format!("{:?}", evk);
    assert!(
        debug_output.contains("[REDACTED]"),
        "Debug output must contain [REDACTED], got: {debug_output}"
    );
    // Must NOT contain raw nonce bytes (0xAA repeated)
    assert!(
        !debug_output.contains("170")
            && !debug_output.contains("0xaa")
            && !debug_output.contains("0xAA"),
        "Debug output must not contain raw nonce bytes, got: {debug_output}"
    );
    // Must NOT contain raw ciphertext bytes (0xBB repeated)
    assert!(
        !debug_output.contains("187")
            && !debug_output.contains("0xbb")
            && !debug_output.contains("0xBB"),
        "Debug output must not contain raw ciphertext bytes, got: {debug_output}"
    );
    // Must still contain the algorithm field (non-sensitive)
    assert!(
        debug_output.contains("XChaCha20Poly1305"),
        "Debug output must contain algorithm name, got: {debug_output}"
    );
}

#[test]
fn test_recipient_slot_debug_redacts_params_and_encrypted_master_key() {
    let slot = mock_recipient();
    let debug_output = format!("{:?}", slot);
    assert!(
        debug_output.contains("[REDACTED]"),
        "Debug output must contain [REDACTED], got: {debug_output}"
    );
    // Must NOT contain raw params bytes (0xAB repeated)
    assert!(
        !debug_output.contains("171")
            && !debug_output.contains("0xab")
            && !debug_output.contains("0xAB"),
        "Debug output must not contain raw params bytes, got: {debug_output}"
    );
    // Must NOT contain raw encrypted_master_key bytes (0xCD repeated)
    assert!(
        !debug_output.contains("205")
            && !debug_output.contains("0xcd")
            && !debug_output.contains("0xCD"),
        "Debug output must not contain raw encrypted_master_key bytes, got: {debug_output}"
    );
    // Must still contain the type field (non-sensitive)
    assert!(
        debug_output.contains("Argon2idPassword"),
        "Debug output must contain recipient type, got: {debug_output}"
    );
}

#[test]
fn test_super_header_debug_redacts_salt() {
    let header = make_header();
    let debug_output = format!("{:?}", header);
    // salt should be redacted
    assert!(
        debug_output.contains("salt: \"[REDACTED]\""),
        "Debug output must redact salt, got: {debug_output}"
    );
    // Non-sensitive fields should still be present
    assert!(
        debug_output.contains("magic")
            && debug_output.contains("version")
            && debug_output.contains("epoch_id"),
        "Debug output must contain non-sensitive field names, got: {debug_output}"
    );
    // Nested EncryptedVolumeKey should also be redacted (inherits custom Debug)
    assert!(
        debug_output.contains("encrypted_volume_key: EncryptedVolumeKey"),
        "Debug output must contain nested EVK struct name, got: {debug_output}"
    );
}

// --- C12-02: Minimum ciphertext length test ---

#[test]
fn test_evk_try_from_rejects_ciphertext_shorter_than_poly1305_tag() {
    // 15 bytes is less than the 16-byte Poly1305 tag minimum
    let proto_evk = proto::EncryptedVolumeKey {
        algorithm: 1, // XChaCha20Poly1305
        nonce: vec![0xAA; 24],
        ciphertext: vec![0xBB; 15], // Too short
    };
    let err = EncryptedVolumeKey::try_from(proto_evk).unwrap_err();
    match &err {
        EraError::CorruptedHeader(msg) => {
            assert!(
                msg.contains("too short"),
                "Error must mention 'too short', got: {msg}"
            );
        }
        other => panic!("Expected CorruptedHeader, got: {other:?}"),
    }
}

#[test]
fn test_evk_try_from_accepts_exactly_16_byte_ciphertext() {
    // Exactly 16 bytes (Poly1305 tag only, no plaintext) should be accepted
    let proto_evk = proto::EncryptedVolumeKey {
        algorithm: 0, // EV36-03: must use valid KeyWrapAlgorithm value
        nonce: vec![0xAA; 24],
        ciphertext: vec![0xBB; 16], // Minimum valid
    };
    let result = EncryptedVolumeKey::try_from(proto_evk);
    assert!(result.is_ok(), "16-byte ciphertext must be accepted");
}

#[test]
fn test_evk_try_from_accepts_48_byte_ciphertext() {
    // 48 bytes is the typical VK wrapping output (32B VK + 16B tag)
    let proto_evk = proto::EncryptedVolumeKey {
        algorithm: 0, // EV36-03: must use valid KeyWrapAlgorithm value
        nonce: vec![0xAA; 24],
        ciphertext: vec![0xBB; 48],
    };
    let result = EncryptedVolumeKey::try_from(proto_evk);
    assert!(result.is_ok(), "48-byte ciphertext must be accepted");
}
