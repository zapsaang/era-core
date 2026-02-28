//! Adversarial Audit V30 — era-volume
//!
//! Tests covering all V30 findings. Each test verifies that the fix
//! prevents the specific vulnerability or defect identified during audit.
//!
//! Coverage:
//! - V30-01: Pub field encapsulation — all 4 structs (SuperHeader, Footer,
//!   EncryptedVolumeKey, RecipientSlot) have private fields + accessor methods
//! - V30-05: Proto rename — Argon2idPassword variant exists and serializes correctly
//! - V30-06: Path helper — `volume_path()` is public and consistent (extract_filename
//!   is pub(crate) — tested indirectly via volume operations)
//! - V30-07: PER_VOLUME_OVERHEAD constant extracted (no more duplicated 4248 formula)

use era_common::{ArchiveConfig, ArchiveId};
use era_volume::{
    AccessPolicy, EncryptedVolumeKey, Footer, KeyWrapAlgorithm, RecipientSlot, RecipientType,
    SuperHeader, FOOTER_SIZE, HEADER_SIZE, PER_VOLUME_OVERHEAD,
};

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn make_recipients(count: usize) -> Vec<RecipientSlot> {
    (0..count)
        .map(|_| {
            RecipientSlot::new(
                RecipientType::Argon2idPassword,
                Some([0x12; 8]),
                vec![0xAB; 16],
                vec![0xCD; 48],
            )
        })
        .collect()
}

fn test_evk() -> EncryptedVolumeKey {
    EncryptedVolumeKey::new(
        KeyWrapAlgorithm::XChaCha20Poly1305,
        [0u8; 24],
        vec![0u8; 48],
    )
}

fn test_header() -> SuperHeader {
    SuperHeader::new(
        ArchiveId::new(),
        make_recipients(1),
        ArchiveConfig::default(),
        [0u8; 16],
        test_evk(),
        AccessPolicy::AnyOfN,
    )
    .unwrap()
}

// ═══════════════════════════════════════════════════════════════════════════
// V30-07: PER_VOLUME_OVERHEAD constant
// ═══════════════════════════════════════════════════════════════════════════

/// V30-07: PER_VOLUME_OVERHEAD equals the expected sum of structural components.
/// Footer (128) + HEADER_SIZE (4096) + BlockHeader (16) + ShardHeader (8) = 4248.
#[test]
fn test_v30_01_per_volume_overhead_value() {
    // BlockHeader::SIZE is 16, ShardHeader::SIZE is 8 (not publicly exported,
    // so we verify the known constant value directly)
    let expected: u64 = FOOTER_SIZE as u64 + HEADER_SIZE as u64 + 16 + 8;
    assert_eq!(
        PER_VOLUME_OVERHEAD, expected,
        "PER_VOLUME_OVERHEAD should be footer + header + block_header + shard_header = {}",
        expected
    );
}

/// V30-07: PER_VOLUME_OVERHEAD is exactly 4248.
#[test]
fn test_v30_02_per_volume_overhead_exact() {
    assert_eq!(PER_VOLUME_OVERHEAD, 4248);
}

// ═══════════════════════════════════════════════════════════════════════════
// V30-05: Proto rename — Argon2idPassword variant
// ═══════════════════════════════════════════════════════════════════════════

/// V30-05: RecipientType::Argon2idPassword variant exists and can be used
/// in a RecipientSlot that passes SuperHeader validation.
#[test]
fn test_v30_03_argon2id_password_variant_exists() {
    let slot = RecipientSlot::new(
        RecipientType::Argon2idPassword,
        Some([0xAA; 8]),
        vec![0xBB; 32],
        vec![0xCC; 48],
    );
    assert_eq!(slot.r_type(), RecipientType::Argon2idPassword);
}

/// V30-05: SuperHeader with Argon2idPassword recipient survives roundtrip.
#[test]
fn test_v30_04_argon2id_password_roundtrip() {
    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![RecipientSlot::new(
            RecipientType::Argon2idPassword,
            Some([0x11; 8]),
            vec![0x22; 32],
            vec![0x33; 48],
        )],
        ArchiveConfig::default(),
        [0xAA; 16],
        test_evk(),
        AccessPolicy::AnyOfN,
    )
    .unwrap();

    let bytes = header.to_bytes().unwrap();
    let restored = SuperHeader::from_bytes(&bytes).unwrap();
    assert_eq!(
        restored.recipients()[0].r_type(),
        RecipientType::Argon2idPassword
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// V30-01: EncryptedVolumeKey accessor API — zero-copy semantics
// ═══════════════════════════════════════════════════════════════════════════

/// V30-01: EncryptedVolumeKey accessors return correct values.
#[test]
fn test_v30_05_evk_accessors() {
    let nonce = [0x42u8; 24];
    let ciphertext = vec![0xDE; 64];
    let evk = EncryptedVolumeKey::new(
        KeyWrapAlgorithm::XChaCha20Poly1305,
        nonce,
        ciphertext.clone(),
    );

    assert_eq!(evk.algorithm(), KeyWrapAlgorithm::XChaCha20Poly1305);
    assert_eq!(*evk.nonce(), nonce);
    assert_eq!(evk.ciphertext(), ciphertext.as_slice());
}

/// V30-01: EncryptedVolumeKey nonce accessor returns a reference (zero-copy).
#[test]
fn test_v30_06_evk_nonce_zero_copy() {
    let evk = EncryptedVolumeKey::new(
        KeyWrapAlgorithm::XChaCha20Poly1305,
        [0xFF; 24],
        vec![0u8; 48],
    );
    // Verify the reference points to the original data — the nonce should
    // be a slice reference, not a copy
    let nonce_ref: &[u8; 24] = evk.nonce();
    assert_eq!(nonce_ref[0], 0xFF);
    assert_eq!(nonce_ref[23], 0xFF);
}

/// V30-01: EncryptedVolumeKey ciphertext accessor returns a slice (zero-copy).
#[test]
fn test_v30_07_evk_ciphertext_zero_copy() {
    let ct = vec![0xAB; 128];
    let evk = EncryptedVolumeKey::new(KeyWrapAlgorithm::XChaCha20Poly1305, [0u8; 24], ct.clone());
    let ct_ref: &[u8] = evk.ciphertext();
    assert_eq!(ct_ref.len(), 128);
    assert_eq!(ct_ref, ct.as_slice());
}

// ═══════════════════════════════════════════════════════════════════════════
// V30-01: RecipientSlot accessor API — zero-copy semantics
// ═══════════════════════════════════════════════════════════════════════════

/// V30-01: RecipientSlot accessors return correct values.
#[test]
fn test_v30_08_recipient_slot_accessors() {
    let slot = RecipientSlot::new(
        RecipientType::X25519PubKey,
        Some([0xDD; 8]),
        vec![0xEE; 32],
        vec![0xFF; 48],
    );

    assert_eq!(slot.r_type(), RecipientType::X25519PubKey);
    assert_eq!(slot.key_id(), Some(&[0xDD; 8]));
    assert_eq!(slot.params(), &[0xEE; 32]);
    assert_eq!(slot.encrypted_master_key(), &[0xFF; 48]);
}

/// V30-01: RecipientSlot with no key_id returns None.
#[test]
fn test_v30_09_recipient_slot_no_key_id() {
    let slot = RecipientSlot::new(
        RecipientType::Fido2Hmac,
        None,
        vec![0xAA; 16],
        vec![0xBB; 48],
    );
    assert_eq!(slot.key_id(), None);
    assert_eq!(slot.r_type(), RecipientType::Fido2Hmac);
}

/// V30-01: RecipientSlot params() returns a slice reference (zero-copy).
#[test]
fn test_v30_10_recipient_slot_params_zero_copy() {
    let params_data = vec![0x11; 64];
    let slot = RecipientSlot::new(
        RecipientType::Argon2idPassword,
        None,
        params_data.clone(),
        vec![0x22; 48],
    );
    let params_ref: &[u8] = slot.params();
    assert_eq!(params_ref.len(), 64);
    assert_eq!(params_ref, params_data.as_slice());
}

// ═══════════════════════════════════════════════════════════════════════════
// V30-01: Footer accessor API + roundtrip
// ═══════════════════════════════════════════════════════════════════════════

/// V30-01: Footer accessors return correct values after construction.
#[test]
fn test_v30_11_footer_accessors() {
    let footer = Footer::new(10000, 42, 7);

    assert_eq!(footer.magic(), &[0x45, 0x52, 0x41, 0x46]); // "ERAF"
    assert_eq!(footer.version(), 1);
    assert_eq!(footer.data_end_offset(), 10000);
    assert_eq!(footer.block_count(), 42);
    assert_eq!(footer.sequence_number(), 7);
    assert_eq!(footer.flags(), 0);
    // Default zero values for optional fields
    assert_eq!(footer.catalog_offset(), 0);
    assert_eq!(footer.catalog_size(), 0);
    assert_eq!(footer.catalog_block_id(), 0);
    assert_eq!(footer.last_checkpoint_offset(), 0);
    assert_eq!(footer.last_checkpoint_block_id(), 0);
    assert_eq!(footer.index_offset(), 0);
    assert_eq!(footer.index_size(), 0);
    assert_eq!(footer.index_block_id(), 0);
    assert_eq!(footer.backup_header_offset(), 0);
}

/// V30-01: Footer built with FooterBuilder has correct accessor values.
#[test]
fn test_v30_12_footer_builder_accessors() {
    let footer = Footer::builder(20000, 100, 3)
        .catalog(5000, 512, 10)
        .checkpoint(6000, 20)
        .index(7000, 1024, 30)
        .backup_header(8000)
        .build();

    assert_eq!(footer.data_end_offset(), 20000);
    assert_eq!(footer.block_count(), 100);
    assert_eq!(footer.sequence_number(), 3);
    assert_eq!(footer.catalog_offset(), 5000);
    assert_eq!(footer.catalog_size(), 512);
    assert_eq!(footer.catalog_block_id(), 10);
    assert_eq!(footer.last_checkpoint_offset(), 6000);
    assert_eq!(footer.last_checkpoint_block_id(), 20);
    assert_eq!(footer.index_offset(), 7000);
    assert_eq!(footer.index_size(), 1024);
    assert_eq!(footer.index_block_id(), 30);
    assert_eq!(footer.backup_header_offset(), 8000);
}

/// V30-01: Footer accessor roundtrip — serialize, deserialize, verify all accessors.
#[test]
fn test_v30_13_footer_accessor_roundtrip() {
    let footer = Footer::builder(50000, 200, 5)
        .catalog(10000, 2048, 15)
        .checkpoint(12000, 25)
        .index(14000, 4096, 35)
        .backup_header(16000)
        .build();

    let bytes = footer.to_bytes().unwrap();
    let restored = Footer::from_bytes(&bytes).unwrap();

    assert_eq!(restored.data_end_offset(), footer.data_end_offset());
    assert_eq!(restored.block_count(), footer.block_count());
    assert_eq!(restored.sequence_number(), footer.sequence_number());
    assert_eq!(restored.catalog_offset(), footer.catalog_offset());
    assert_eq!(restored.catalog_size(), footer.catalog_size());
    assert_eq!(restored.catalog_block_id(), footer.catalog_block_id());
    assert_eq!(
        restored.last_checkpoint_offset(),
        footer.last_checkpoint_offset()
    );
    assert_eq!(
        restored.last_checkpoint_block_id(),
        footer.last_checkpoint_block_id()
    );
    assert_eq!(restored.index_offset(), footer.index_offset());
    assert_eq!(restored.index_size(), footer.index_size());
    assert_eq!(restored.index_block_id(), footer.index_block_id());
    assert_eq!(
        restored.backup_header_offset(),
        footer.backup_header_offset()
    );
    assert_eq!(restored.checksum(), footer.checksum());
    assert!(restored.verify_checksum());
}

// ═══════════════════════════════════════════════════════════════════════════
// V30-01: SuperHeader accessor API + roundtrip
// ═══════════════════════════════════════════════════════════════════════════

/// V30-01: SuperHeader accessors return correct values after construction.
#[test]
fn test_v30_14_superheader_accessors() {
    let header = test_header();

    assert_eq!(
        *header.magic(),
        [0x45, 0x52, 0x41, 0x08, 0x01, 0x00, 0x00, 0x00]
    );
    assert_eq!(header.version(), era_volume::HEADER_VERSION);
    assert_eq!(header.volume_sequence(), 0);
    assert_eq!(header.total_volumes(), 0);
    assert_eq!(header.feature_flags(), 0);
    assert_eq!(header.epoch_id(), 0);
    assert_eq!(header.access_policy(), AccessPolicy::AnyOfN);
    assert_eq!(header.recipients().len(), 1);
    assert_eq!(
        header.recipients()[0].r_type(),
        RecipientType::Argon2idPassword
    );
    assert_eq!(
        header.encrypted_volume_key().algorithm(),
        KeyWrapAlgorithm::XChaCha20Poly1305
    );
}

/// V30-01: SuperHeader accessor roundtrip — serialize, deserialize, verify.
#[test]
fn test_v30_15_superheader_accessor_roundtrip() {
    let salt = [0x77u8; 16];
    let header = SuperHeader::new(
        ArchiveId::new(),
        make_recipients(3),
        ArchiveConfig::default(),
        salt,
        EncryptedVolumeKey::new(
            KeyWrapAlgorithm::XChaCha20Poly1305,
            [0xBB; 24],
            vec![0xCC; 48],
        ),
        AccessPolicy::Threshold(2),
    )
    .unwrap();

    let bytes = header.to_bytes().unwrap();
    let restored = SuperHeader::from_bytes(&bytes).unwrap();

    assert_eq!(*restored.magic(), *header.magic());
    assert_eq!(restored.version(), header.version());
    assert_eq!(restored.archive_id(), header.archive_id());
    assert_eq!(restored.volume_sequence(), header.volume_sequence());
    assert_eq!(restored.total_volumes(), header.total_volumes());
    assert_eq!(restored.feature_flags(), header.feature_flags());
    assert_eq!(restored.epoch_id(), header.epoch_id());
    assert_eq!(restored.access_policy(), AccessPolicy::Threshold(2));
    assert_eq!(*restored.salt(), salt);
    assert_eq!(restored.recipients().len(), 3);

    // EVK roundtrip
    assert_eq!(
        restored.encrypted_volume_key().algorithm(),
        header.encrypted_volume_key().algorithm()
    );
    assert_eq!(
        restored.encrypted_volume_key().nonce(),
        header.encrypted_volume_key().nonce()
    );
    assert_eq!(
        restored.encrypted_volume_key().ciphertext(),
        header.encrypted_volume_key().ciphertext()
    );
}

/// V30-01: SuperHeader config accessor returns valid ArchiveConfig reference.
#[test]
fn test_v30_16_superheader_config_accessor() {
    let config = ArchiveConfig::default();
    let header = SuperHeader::new(
        ArchiveId::new(),
        make_recipients(1),
        config.clone(),
        [0u8; 16],
        test_evk(),
        AccessPolicy::AnyOfN,
    )
    .unwrap();

    // config() returns &ArchiveConfig — we can access fields through it
    let cfg = header.config();
    assert_eq!(cfg.erasure, config.erasure);
}

// ═══════════════════════════════════════════════════════════════════════════
// V30-01: Encapsulation enforcement — private fields
// ═══════════════════════════════════════════════════════════════════════════

/// V30-01: SuperHeader fields are not directly accessible (enforced by
/// compiler — this test verifies construction MUST go through ::new()).
#[test]
fn test_v30_17_superheader_requires_constructor() {
    // Cannot construct via struct literal (fields are private).
    // This test verifies ::new() is the only construction path and
    // rejects invalid inputs.
    let result = SuperHeader::new(
        ArchiveId::new(),
        vec![], // empty recipients — should fail
        ArchiveConfig::default(),
        [0u8; 16],
        test_evk(),
        AccessPolicy::AnyOfN,
    );
    assert!(
        result.is_err(),
        "Empty recipients must be rejected by constructor"
    );
}

/// V30-01: EncryptedVolumeKey fields are not directly accessible (enforced
/// by compiler — only ::new() + accessors).
#[test]
fn test_v30_18_evk_construction_and_access() {
    let nonce = [0x99; 24];
    let ct = vec![0x88; 96];
    let evk = EncryptedVolumeKey::new(KeyWrapAlgorithm::XChaCha20Poly1305, nonce, ct.clone());

    // The only way to read fields is via accessors
    assert_eq!(evk.algorithm(), KeyWrapAlgorithm::XChaCha20Poly1305);
    assert_eq!(*evk.nonce(), nonce);
    assert_eq!(evk.ciphertext(), ct.as_slice());
}

// ═══════════════════════════════════════════════════════════════════════════
// V30-06: volume_path public helper
// ═══════════════════════════════════════════════════════════════════════════

/// V30-06: volume_path is the single canonical path generation function.
/// (Verifies the helper is public and generates correct paths.)
#[test]
fn test_v30_19_volume_path_consistency() {
    use std::path::Path;

    // Sequence 0 → base.era
    let p0 = era_volume::volume_path(Path::new("archive"), 0);
    assert_eq!(p0, Path::new("archive.era"));

    // Sequence 1 → base.era.001
    let p1 = era_volume::volume_path(Path::new("archive"), 1);
    assert_eq!(p1, Path::new("archive.era.001"));

    // Sequence 42 → base.era.042
    let p42 = era_volume::volume_path(Path::new("archive"), 42);
    assert_eq!(p42, Path::new("archive.era.042"));
}

// ═══════════════════════════════════════════════════════════════════════════
// V30-01: Footer checksum accessor
// ═══════════════════════════════════════════════════════════════════════════

/// V30-01: Footer checksum accessor returns valid non-zero Blake3 hash.
#[test]
fn test_v30_20_footer_checksum_accessor() {
    let footer = Footer::new(10000, 5, 1);
    let checksum = footer.checksum();

    // Checksum should be 32 bytes and non-zero (Blake3 output)
    assert_eq!(checksum.len(), 32);
    assert_ne!(checksum, &[0u8; 32], "Checksum should not be all zeros");
    assert!(footer.verify_checksum(), "Checksum must verify");
}

/// V30-01: Footer with different data produces different checksums.
#[test]
fn test_v30_21_footer_checksum_varies() {
    let f1 = Footer::new(10000, 5, 1);
    let f2 = Footer::new(20000, 10, 2);

    assert_ne!(
        f1.checksum(),
        f2.checksum(),
        "Different footers should have different checksums"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// V30-01: RecipientSlot all-variant coverage
// ═══════════════════════════════════════════════════════════════════════════

/// V30-05: All RecipientType variants can be used in a valid SuperHeader.
#[test]
fn test_v30_22_all_recipient_types_accepted() {
    let types = [
        RecipientType::Argon2idPassword,
        RecipientType::X25519PubKey,
        RecipientType::Fido2Hmac,
    ];

    for rt in &types {
        let slot = RecipientSlot::new(*rt, Some([0x11; 8]), vec![0x22; 32], vec![0x33; 48]);
        let result = SuperHeader::new(
            ArchiveId::new(),
            vec![slot],
            ArchiveConfig::default(),
            [0u8; 16],
            test_evk(),
            AccessPolicy::AnyOfN,
        );
        assert!(
            result.is_ok(),
            "RecipientType {:?} should be accepted in SuperHeader",
            rt
        );
    }
}

/// V30-01: SuperHeader salt accessor returns the exact salt provided at construction.
#[test]
fn test_v30_23_superheader_salt_accessor() {
    let salt = [0xAB; 16];
    let header = SuperHeader::new(
        ArchiveId::new(),
        make_recipients(1),
        ArchiveConfig::default(),
        salt,
        test_evk(),
        AccessPolicy::AnyOfN,
    )
    .unwrap();

    assert_eq!(*header.salt(), salt);
}
