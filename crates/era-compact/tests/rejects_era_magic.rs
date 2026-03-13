use era_common::{ArchiveConfig, ArchiveId, EraError};
use era_compact::CompactSuperHeader;
use era_volume::{
    AccessPolicy, EncryptedVolumeKey, KeyWrapAlgorithm, RecipientSlot, RecipientType, SuperHeader,
};

fn recipient() -> RecipientSlot {
    RecipientSlot::new(
        RecipientType::Argon2idPassword,
        Some([0xAA; 8]),
        vec![0xBB; 16],
        vec![0xCC; 48],
    )
}

fn evk() -> EncryptedVolumeKey {
    EncryptedVolumeKey::new(
        KeyWrapAlgorithm::XChaCha20Poly1305,
        [0xDD; 24],
        vec![0xEE; 48],
    )
}

#[test]
fn compact_header_parser_rejects_legacy_era_magic() {
    let era_header = SuperHeader::new(
        ArchiveId::new(),
        vec![recipient()],
        ArchiveConfig::default(),
        [0x99; 16],
        evk(),
        AccessPolicy::AnyOfN,
    )
    .expect("valid era header");
    let bytes = era_header.to_bytes().expect("serialize era header");

    let err = CompactSuperHeader::from_bytes(&bytes).expect_err("must reject .era header bytes");
    assert!(matches!(err, EraError::InvalidMagic));
}
