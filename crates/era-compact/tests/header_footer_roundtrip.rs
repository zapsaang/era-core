use era_common::{ArchiveConfig, ArchiveId, VolumeId};
use era_compact::{CompactSuperHeader, CompactVolumeFooter};
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
fn compact_header_footer_roundtrip_preserves_invariants() {
    let header = CompactSuperHeader::new(
        Uuid::new_v4(),
        ArchiveId::new(),
        VolumeId::new(),
        0,
        6,
        3,
        4,
        ArchiveConfig::default(),
        vec![recipient(), recipient(), recipient()],
        AccessPolicy::Threshold(2),
        2,
        [0x66; 16],
        7,
        evk(),
    )
    .expect("valid compact header");
    let header_bytes = header.to_bytes().expect("serialize header");
    let parsed_header = CompactSuperHeader::from_bytes(&header_bytes).expect("parse header");
    assert_eq!(parsed_header.access_policy(), AccessPolicy::Threshold(2));
    assert_eq!(parsed_header.threshold(), 2);
    assert_eq!(parsed_header.epoch_id(), 7);
    assert_eq!(parsed_header.total_compact_volumes(), 6);

    let footer = CompactVolumeFooter::new(
        1024, 2048, 4096, 512, 8, 0, 0, 0, 0, 0, 0, [0u8; 32], [0u8; 32],
    )
    .expect("valid compact footer");
    let footer_bytes = footer.to_bytes().expect("serialize footer");
    let parsed_footer = CompactVolumeFooter::from_bytes(&footer_bytes).expect("parse footer");

    assert_eq!(parsed_footer.directory_offset(), 4096);
    assert_eq!(parsed_footer.directory_size(), 512);
    assert_eq!(parsed_footer.directory_count(), 8);
}

#[test]
fn compact_footer_rejects_checksum_tampering() {
    let footer = CompactVolumeFooter::new(
        1024, 2048, 4096, 512, 8, 0, 0, 0, 0, 0, 0, [0u8; 32], [0u8; 32],
    )
    .expect("valid compact footer");
    let mut bytes = footer.to_bytes().expect("serialize footer");
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x7A;

    let err = CompactVolumeFooter::from_bytes(&bytes).expect_err("tampered footer must fail");
    assert!(format!("{err}").contains("checksum"));
}

#[test]
fn compact_footer_roundtrip_with_catalog_and_index_fields() {
    let header_hash = blake3::hash(b"test header bytes");
    let directory_hash = blake3::hash(b"test directory bytes");

    let footer = CompactVolumeFooter::new(
        4096,
        8192,
        16384,
        1024,
        12,
        8192,
        2048,
        42,
        10240,
        4096,
        99,
        *header_hash.as_bytes(),
        *directory_hash.as_bytes(),
    )
    .expect("valid footer with catalog/index");

    let bytes = footer.to_bytes().expect("serialize");
    let parsed = CompactVolumeFooter::from_bytes(&bytes).expect("parse");

    assert_eq!(parsed.data_region_end(), 4096);
    assert_eq!(parsed.meta_region_offset(), 8192);
    assert_eq!(parsed.directory_offset(), 16384);
    assert_eq!(parsed.directory_size(), 1024);
    assert_eq!(parsed.directory_count(), 12);
    assert_eq!(parsed.catalog_offset(), 8192);
    assert_eq!(parsed.catalog_size(), 2048);
    assert_eq!(parsed.catalog_block_id(), 42);
    assert_eq!(parsed.index_offset(), 10240);
    assert_eq!(parsed.index_size(), 4096);
    assert_eq!(parsed.index_block_id(), 99);
    assert_eq!(parsed.header_hash(), header_hash.as_bytes());
    assert_eq!(parsed.directory_hash(), directory_hash.as_bytes());
}
