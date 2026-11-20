use super::*;
use era_codec::NoCompressor;
use era_storage::LocalStorageBackend;
use era_volume::{
    AccessPolicy, EncryptedVolumeKey, KeyWrapAlgorithm, RecipientSlot, RecipientType, SuperHeader,
    VolumeReader, VolumeWriter,
};
use std::path::Path;
use tempfile::TempDir;

struct MultiVolumeSessionFixture {
    session: KeySession,
    volume_key: VolumeKey,
    archive_id: [u8; 16],
    nonce_context: [u8; 16],
    volume_readers: Vec<VolumeReader<era_storage::LocalStorageReader>>,
    payloads: Vec<Bytes>,
    read_limits: Vec<u64>,
}

impl MultiVolumeSessionFixture {
    async fn create(temp_dir: &TempDir) -> Self {
        let session = KeySession::from_master_key(&[0x42; 32]).unwrap();
        let (volume_key, wrapped_volume_key) = session.generate_and_wrap_volume_key().unwrap();
        let archive_id = era_common::ArchiveId::new();
        let archive_id_bytes = *archive_id.0.as_bytes();
        let nonce_context = [0x5A; 16];
        let payloads = vec![
            Bytes::from_static(b"first volume committed payload"),
            Bytes::from_static(b"second volume committed payload"),
        ];
        let mut config = era_common::ArchiveConfig {
            erasure: None,
            ..Default::default()
        };
        config.compression.algorithm = era_common::CompressionAlgorithm::None;

        let mut volume_readers = Vec::with_capacity(payloads.len());
        let mut read_limits = Vec::with_capacity(payloads.len());
        for (sequence, payload) in payloads.iter().enumerate() {
            let sequence = u16::try_from(sequence).unwrap();
            let mut header = SuperHeader::new(
                archive_id,
                vec![RecipientSlot::new(
                    RecipientType::Argon2idPassword,
                    Some([0x12; 8]),
                    vec![0xAB; 16],
                    vec![0xCD; 48],
                )],
                config.clone(),
                nonce_context,
                EncryptedVolumeKey::new(
                    KeyWrapAlgorithm::XChaCha20Poly1305,
                    wrapped_volume_key.nonce,
                    wrapped_volume_key.ciphertext.clone(),
                ),
                AccessPolicy::AnyOfN,
            )
            .unwrap();
            header.set_volume_sequence(sequence);
            header.set_total_volumes(u16::try_from(payloads.len()).unwrap());

            let file_name = if sequence == 0 {
                "session-multi.era".to_string()
            } else {
                format!("session-multi.era.{sequence:03}")
            };
            let backend = LocalStorageBackend::new(temp_dir.path());
            let mut writer = VolumeWriter::create(&backend, Path::new(&file_name), header)
                .await
                .unwrap();
            let builder = era_packing::SessionBlockBuilder::new(
                &session,
                &volume_key,
                nonce_context,
                archive_id_bytes,
                0,
                0,
                Box::new(NoCompressor),
            )
            .with_starting_block_id(u64::from(sequence));

            let data_chunk =
                era_common::UniqueChunk::new(payload.clone(), era_crypto::hash(payload.as_ref()));
            let data_block = builder.pack_single(data_chunk).unwrap();
            let data_location = writer
                .write_canonical_block(&data_block, BlockType::Data)
                .await
                .unwrap();
            let committed_end = data_location.physical_offset
                + BlockHeader::SIZE as u64
                + u64::from(data_location.encrypted_size);

            let typed_payload = Bytes::from_static(b"valid typed block beyond the read limit");
            let typed_chunk = era_common::UniqueChunk::new(
                typed_payload.clone(),
                era_crypto::hash(typed_payload.as_ref()),
            );
            let typed_block = builder
                .pack_single_with_type(typed_chunk, BlockType::Checkpoint)
                .unwrap();
            writer
                .write_canonical_block(&typed_block, BlockType::Checkpoint)
                .await
                .unwrap();
            writer.finalize().await.unwrap();

            let reader = VolumeReader::open(&backend, Path::new(&file_name))
                .await
                .unwrap();
            assert!(committed_end < crate::erasure_scan::erasure_data_end(&reader));
            volume_readers.push(reader);
            read_limits.push(if sequence == 0 {
                committed_end + 1
            } else {
                committed_end
            });
        }

        Self {
            session,
            volume_key,
            archive_id: archive_id_bytes,
            nonce_context,
            volume_readers,
            payloads,
            read_limits,
        }
    }

    fn iterator(
        &self,
        committed_ends: Option<Vec<u64>>,
    ) -> MultiVolumeSessionBlockIterator<'_, era_storage::LocalStorageReader> {
        MultiVolumeSessionBlockIterator::new(
            &self.volume_readers,
            &self.session,
            &self.volume_key,
            self.nonce_context,
            self.archive_id,
            0,
            Box::new(NoCompressor),
            committed_ends,
        )
    }
}

#[tokio::test]
async fn test_multi_volume_session_iterator_skips_only_uncommitted_tails() {
    let temp_dir = TempDir::new().unwrap();
    let fixture = MultiVolumeSessionFixture::create(&temp_dir).await;
    let mut iter = fixture.iterator(Some(fixture.read_limits.clone()));

    for (expected_index, expected_payload) in fixture.payloads.iter().enumerate() {
        assert!(iter.has_more());
        let decoded = iter
            .next_block()
            .await
            .expect("later volumes must remain reachable past an earlier read limit")
            .expect("intact writer blocks must decode");
        assert_eq!(decoded.block_index, u32::try_from(expected_index).unwrap());
        assert_eq!(decoded.chunks.len(), 1);
        assert_eq!(decoded.chunks[0].1, expected_payload.clone());
    }

    assert!(
        !iter.has_more(),
        "has_more must exclude the final volume's tail beyond its read limit"
    );
    assert!(iter.next_block().await.is_none());
}

#[tokio::test]
async fn test_multi_volume_session_iterator_preserves_missing_limit_error() {
    let temp_dir = TempDir::new().unwrap();
    let fixture = MultiVolumeSessionFixture::create(&temp_dir).await;
    let mut iter = fixture.iterator(Some(vec![fixture.read_limits[0]]));
    iter.next_block()
        .await
        .expect("the first committed block must be readable")
        .expect("the first intact writer block must decode");

    match iter.next_block().await {
        Some(Err(EraError::InvalidFormat(_))) => {}
        other => panic!("expected missing committed-end InvalidFormat, got: {other:?}"),
    }
}
