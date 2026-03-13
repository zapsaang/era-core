use era_common::{ArchiveConfig, ArchiveId};
use era_compact::CompactSuperHeader;
use era_volume::{
    AccessPolicy, EncryptedVolumeKey, KeyWrapAlgorithm, RecipientSlot, RecipientType,
};
use uuid::Uuid;

fn recipient() -> RecipientSlot {
    RecipientSlot::new(
        RecipientType::Argon2idPassword,
        Some([0x11; 8]),
        vec![0x22; 16],
        vec![0x33; 48],
    )
}

fn evk() -> EncryptedVolumeKey {
    EncryptedVolumeKey::new(
        KeyWrapAlgorithm::XChaCha20Poly1305,
        [0x44; 24],
        vec![0x55; 48],
    )
}

#[test]
fn threshold_policy_preserves_explicit_threshold_and_anyofn_requires_zero() {
    let bad_any = CompactSuperHeader::new(
        Uuid::new_v4(),
        ArchiveId::new(),
        era_common::VolumeId::new(),
        0,
        1,
        3,
        1,
        ArchiveConfig::default(),
        vec![recipient()],
        AccessPolicy::AnyOfN,
        1,
        [0x66; 16],
        9,
        evk(),
    );
    assert!(bad_any.is_err(), "AnyOfN must require threshold=0");

    let bad_threshold_mismatch = CompactSuperHeader::new(
        Uuid::new_v4(),
        ArchiveId::new(),
        era_common::VolumeId::new(),
        0,
        1,
        3,
        1,
        ArchiveConfig::default(),
        vec![recipient(), recipient(), recipient()],
        AccessPolicy::Threshold(2),
        3,
        [0x66; 16],
        9,
        evk(),
    );
    assert!(
        bad_threshold_mismatch.is_err(),
        "threshold field must remain explicit and match policy"
    );

    let ok = CompactSuperHeader::new(
        Uuid::new_v4(),
        ArchiveId::new(),
        era_common::VolumeId::new(),
        0,
        1,
        3,
        1,
        ArchiveConfig::default(),
        vec![recipient(), recipient(), recipient()],
        AccessPolicy::Threshold(2),
        2,
        [0x66; 16],
        9,
        evk(),
    )
    .expect("valid threshold config");
    assert_eq!(ok.threshold(), 2);
    assert_eq!(ok.access_policy(), AccessPolicy::Threshold(2));
}
