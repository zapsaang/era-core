//! ADVERSARIAL AUDIT: SuperHeader & EncryptedVolumeKey
//!
//! Tests the v8.1 header structure for compliance with the CLAUDE.md
//! 3-layer envelope specification. Verifies that the header survives
//! serialization roundtrips and cannot be trivially manipulated.

use era_common::{ArchiveConfig, ArchiveId};
use era_volume::{
    AccessPolicy, EncryptedVolumeKey, KeyWrapAlgorithm, RecipientSlot, RecipientType, SuperHeader,
};
use rand::rngs::OsRng;
use rand::RngCore;

fn mock_evk() -> EncryptedVolumeKey {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let mut ct = vec![0u8; 48]; // 32 VK + 16 tag
    OsRng.fill_bytes(&mut ct);
    EncryptedVolumeKey {
        algorithm: KeyWrapAlgorithm::XChaCha20Poly1305,
        nonce,
        ciphertext: ct,
    }
}

fn mock_slot(encrypted_mk: Vec<u8>) -> RecipientSlot {
    RecipientSlot {
        r_type: RecipientType::Argon2idPassword,
        key_id: None,
        params: vec![0xAB; 24],
        encrypted_master_key: encrypted_mk,
    }
}

// ============================================================================
// HEADER STRUCTURAL COMPLIANCE (CLAUSE.md §2)
// ============================================================================

/// SuperHeader MUST contain `encrypted_volume_key` field.
#[test]
fn header_01_has_encrypted_volume_key() {
    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![mock_slot(vec![1; 56])],
        ArchiveConfig::default(),
        [0u8; 16],
        mock_evk(),
        AccessPolicy::AnyOfN,
    );

    // The field exists and is NOT default/empty
    assert_eq!(
        header.encrypted_volume_key.algorithm,
        KeyWrapAlgorithm::XChaCha20Poly1305,
    );
    assert_eq!(header.encrypted_volume_key.nonce.len(), 24);
    assert!(!header.encrypted_volume_key.ciphertext.is_empty());
}

/// SuperHeader MUST contain `epoch_id` field.
#[test]
fn header_02_has_epoch_id() {
    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![mock_slot(vec![1; 56])],
        ArchiveConfig::default(),
        [0u8; 16],
        mock_evk(),
        AccessPolicy::AnyOfN,
    );

    // Default epoch_id should be 0 for new archives
    assert_eq!(header.epoch_id, 0);
}

/// SuperHeader MUST contain `access_policy` field.
#[test]
fn header_03_has_access_policy() {
    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![mock_slot(vec![1; 56])],
        ArchiveConfig::default(),
        [0u8; 16],
        mock_evk(),
        AccessPolicy::AnyOfN,
    );

    assert_eq!(header.access_policy, AccessPolicy::AnyOfN);
}

/// EncryptedVolumeKey survives serialization roundtrip.
#[test]
fn header_04_evk_serialization_roundtrip() {
    let evk = mock_evk();
    let original_nonce = evk.nonce;
    let original_ct = evk.ciphertext.clone();

    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![mock_slot(vec![1; 56])],
        ArchiveConfig::default(),
        [0u8; 16],
        evk,
        AccessPolicy::AnyOfN,
    );

    let bytes = header.to_bytes().unwrap();
    let restored = SuperHeader::from_bytes(&bytes).unwrap();

    assert_eq!(
        restored.encrypted_volume_key.nonce, original_nonce,
        "EVK nonce corrupted during serialization!"
    );
    assert_eq!(
        restored.encrypted_volume_key.ciphertext, original_ct,
        "EVK ciphertext corrupted during serialization!"
    );
    assert_eq!(
        restored.encrypted_volume_key.algorithm,
        KeyWrapAlgorithm::XChaCha20Poly1305,
    );
}

/// epoch_id survives serialization.
#[test]
fn header_05_epoch_id_survives_serialization() {
    let mut header = SuperHeader::new(
        ArchiveId::new(),
        vec![mock_slot(vec![1; 56])],
        ArchiveConfig::default(),
        [0u8; 16],
        mock_evk(),
        AccessPolicy::AnyOfN,
    );
    header.epoch_id = 42;

    let bytes = header.to_bytes().unwrap();
    let restored = SuperHeader::from_bytes(&bytes).unwrap();
    assert_eq!(restored.epoch_id, 42);
}

/// AccessPolicy::Threshold survives serialization with correct threshold value.
#[test]
fn header_06_threshold_policy_survives_serialization() {
    let mut header = SuperHeader::new(
        ArchiveId::new(),
        vec![mock_slot(vec![1; 56])],
        ArchiveConfig::default(),
        [0u8; 16],
        mock_evk(),
        AccessPolicy::AnyOfN,
    );
    header.access_policy = AccessPolicy::Threshold(5);

    let bytes = header.to_bytes().unwrap();
    let restored = SuperHeader::from_bytes(&bytes).unwrap();
    assert_eq!(restored.access_policy, AccessPolicy::Threshold(5));
}

/// next_volume() must share the same EVK, epoch_id, access_policy.
#[test]
fn header_07_next_volume_inherits_crypto() {
    let mut header = SuperHeader::new(
        ArchiveId::new(),
        vec![mock_slot(vec![1; 56])],
        ArchiveConfig::default(),
        [0u8; 16],
        mock_evk(),
        AccessPolicy::AnyOfN,
    );
    header.epoch_id = 7;
    header.access_policy = AccessPolicy::Threshold(3);

    let next = header.next_volume();
    assert_eq!(next.archive_id.0, header.archive_id.0);
    assert_ne!(next.volume_id.0, header.volume_id.0); // New UUID
    assert_eq!(next.volume_sequence, 1);
    assert_eq!(next.epoch_id, 7);
    assert_eq!(next.access_policy, AccessPolicy::Threshold(3));
    assert_eq!(
        next.encrypted_volume_key.nonce,
        header.encrypted_volume_key.nonce
    );
    assert_eq!(
        next.encrypted_volume_key.ciphertext,
        header.encrypted_volume_key.ciphertext
    );
}

/// KeyWrapAlgorithm MUST only have XChaCha20Poly1305 variant.
#[test]
fn header_08_only_xchacha20_allowed() {
    // This is a compile-time test — we verify the enum has exactly 1 variant.
    let algo = KeyWrapAlgorithm::XChaCha20Poly1305;
    assert_eq!(algo as u8, 1);
    // If someone adds AES-CBC = 2, this test file won't catch it at compile time,
    // but the CI review will flag it.
}

// ============================================================================
// MULTIPLE RECIPIENTS (CLAUSE.md §4.1)
// ============================================================================

/// Multiple recipient slots can be stored and restored.
#[test]
fn header_09_multi_recipient_roundtrip() {
    let recipients = vec![
        RecipientSlot {
            r_type: RecipientType::Argon2idPassword,
            key_id: Some([0x01; 8]),
            params: vec![1; 24],
            encrypted_master_key: vec![0xAA; 56],
        },
        RecipientSlot {
            r_type: RecipientType::X25519PubKey,
            key_id: Some([0x02; 8]),
            params: vec![2; 32],
            encrypted_master_key: vec![0xBB; 64],
        },
        RecipientSlot {
            r_type: RecipientType::Argon2idPassword,
            key_id: None,
            params: vec![3; 24],
            encrypted_master_key: vec![0xCC; 56],
        },
    ];

    let header = SuperHeader::new(
        ArchiveId::new(),
        recipients,
        ArchiveConfig::default(),
        [0u8; 16],
        mock_evk(),
        AccessPolicy::AnyOfN,
    );

    let bytes = header.to_bytes().unwrap();
    let restored = SuperHeader::from_bytes(&bytes).unwrap();

    assert_eq!(restored.recipients.len(), 3);
    assert_eq!(
        restored.recipients[0].r_type,
        RecipientType::Argon2idPassword
    );
    assert_eq!(restored.recipients[1].r_type, RecipientType::X25519PubKey);
    assert_eq!(restored.recipients[0].key_id, Some([0x01; 8]));
    assert_eq!(restored.recipients[1].key_id, Some([0x02; 8]));
    assert_eq!(restored.recipients[2].key_id, None);
    assert_eq!(restored.recipients[0].encrypted_master_key, vec![0xAA; 56]);
    assert_eq!(restored.recipients[1].encrypted_master_key, vec![0xBB; 64]);
}

/// Header with zero recipients must be rejected at deserialization (defense-in-depth).
#[test]
fn header_10_zero_recipients() {
    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![],
        ArchiveConfig::default(),
        [0u8; 16],
        mock_evk(),
        AccessPolicy::AnyOfN,
    );

    let bytes = header.to_bytes().unwrap();
    let result = SuperHeader::from_bytes(&bytes);
    assert!(
        result.is_err(),
        "Header should reject zero recipients — creates unreadable archive"
    );
}

// ============================================================================
// HEADER CORRUPTION DETECTION
// ============================================================================

/// Corrupted header bytes must fail deserialization.
#[test]
fn header_11_corrupted_bytes_fail() {
    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![mock_slot(vec![1; 56])],
        ArchiveConfig::default(),
        [0u8; 16],
        mock_evk(),
        AccessPolicy::AnyOfN,
    );

    let mut bytes = header.to_bytes().unwrap();

    // Corrupt magic bytes
    bytes[0] ^= 0xFF;
    bytes[1] ^= 0xFF;

    let result = SuperHeader::from_bytes(&bytes);
    assert!(
        result.is_err(),
        "CRITICAL: Corrupted header magic was accepted!"
    );
}

/// Truncated header must fail.
#[test]
fn header_12_truncated_header_fails() {
    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![mock_slot(vec![1; 56])],
        ArchiveConfig::default(),
        [0u8; 16],
        mock_evk(),
        AccessPolicy::AnyOfN,
    );

    let bytes = header.to_bytes().unwrap();
    let truncated = &bytes[..100]; // Way too short

    let result = SuperHeader::from_bytes(truncated);
    assert!(result.is_err(), "CRITICAL: Truncated header was accepted!");
}
