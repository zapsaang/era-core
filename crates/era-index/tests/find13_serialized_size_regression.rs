use era_common::{ArchiveConfig, ArchiveId, BlockId, ChunkHash, VolumeId};
use era_crypto::{KeySession, Salt};
use era_index::{IndexBuilder, IndexEntry};
use era_storage::LocalStorageBackend;
use era_volume::{
    AccessPolicy, EncryptedVolumeKey, KeyWrapAlgorithm, RecipientSlot, RecipientType, SuperHeader,
    VolumeWriter,
};
use std::path::Path;
use tempfile::TempDir;

fn test_hash(value: u64) -> ChunkHash {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    ChunkHash::from_bytes(bytes)
}

fn test_session() -> (KeySession, era_crypto::VolumeKey, [u8; 16]) {
    let salt = Salt::generate();
    let session = KeySession::new(b"find13", &salt, &era_crypto::KdfParams::fast()).unwrap();
    let volume_key = session.generate_and_wrap_volume_key().unwrap().0;
    (session, volume_key, *salt.as_bytes())
}

fn test_header(nonce_context: [u8; 16]) -> (SuperHeader, [u8; 16]) {
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
    (header, *archive_id.0.as_bytes())
}

#[tokio::test]
async fn find13_estimate_equals_finalized_disk_growth_for_0_10_5000_entries() {
    for entry_count in [0u64, 10, 5000] {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let (session, volume_key, nonce_context) = test_session();
        let (header, archive_id) = test_header(nonce_context);
        let mut writer = VolumeWriter::create(&backend, Path::new("find13_exact_size.era"), header)
            .await
            .unwrap();
        let mut builder = IndexBuilder::new_default_with_context(archive_id, 0).unwrap();

        for value in 0..entry_count {
            builder
                .insert(
                    IndexEntry::new(
                        test_hash(value),
                        VolumeId::new(),
                        BlockId::new(value / 100),
                        0,
                        1024,
                    )
                    .unwrap(),
                )
                .unwrap();
        }

        let estimated = builder.estimated_finalized_disk_size().unwrap();
        let size_before = writer.current_size();
        builder
            .finalize_with_starting_block_id(&mut writer, &session, &volume_key, nonce_context, 7)
            .await
            .unwrap();
        let actual = writer.current_size() - size_before;

        assert_eq!(
            actual, estimated,
            "serialized index size mismatch for {entry_count} entries"
        );
    }
}

#[tokio::test]
async fn find09_out_of_range_manifest_writes_no_index_blocks() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let (session, volume_key, nonce_context) = test_session();
    let (header, archive_id) = test_header(nonce_context);
    let mut writer = VolumeWriter::create(&backend, Path::new("find09_range.era"), header)
        .await
        .unwrap();
    let mut builder = IndexBuilder::new_default_with_context(archive_id, 0).unwrap();
    for value in 0..10u64 {
        builder
            .insert(
                IndexEntry::new(
                    test_hash(value),
                    VolumeId::new(),
                    BlockId::new(value),
                    0,
                    1024,
                )
                .unwrap(),
            )
            .unwrap();
    }

    let size_before = writer.current_size();
    let result = builder
        .finalize_with_starting_block_id(
            &mut writer,
            &session,
            &volume_key,
            nonce_context,
            u64::from(u32::MAX),
        )
        .await;

    assert!(result.is_err(), "an out-of-range manifest ID must fail");
    assert_eq!(
        writer.current_size(),
        size_before,
        "range validation must happen before the first index write"
    );
}
