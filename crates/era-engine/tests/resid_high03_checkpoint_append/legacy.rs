use super::fixtures::{block_header, checkpoint_end, PASSWORD};
use era_common::{
    compute_shard_crc, ArchiveManifest, BlockHeader, BlockId, BlockLocation, BlockType,
};
use era_crypto::{build_aad, AeadContext, XChaCha20Poly1305Context, NONCE_SIZE};
use era_engine::ArchiveReader;
use era_storage::LocalStorageBackend;
use era_volume::VolumeReader;
use std::{
    fs,
    io::{Seek, SeekFrom, Write},
    path::Path,
};

/// Rewrite only the authenticated horizon to the legacy checkpoint-inclusive form.
/// Returns the data-only end and the legacy checkpoint-inclusive end.
pub async fn rewrite_as_legacy(archive_path: &Path) -> (u64, u64) {
    let mut archive = ArchiveReader::open(archive_path, PASSWORD).await.unwrap();
    archive.preflight_metadata_recovery().await.unwrap();
    let footer = archive.primary_footer().unwrap().clone();
    let header = archive.header().clone();
    let legacy_end = checkpoint_end(archive_path, &footer);
    let retained_end = footer.last_checkpoint_offset();

    let backend = LocalStorageBackend::new(archive_path.parent().unwrap());
    let volume = VolumeReader::open(&backend, Path::new(archive_path.file_name().unwrap()))
        .await
        .unwrap();
    let block_id = BlockId::new(u64::from(footer.manifest_block_id()));
    let location = BlockLocation::single(
        header.volume_id(),
        footer.manifest_block_id(),
        footer.manifest_offset(),
        0,
    );
    let (kind, block) = volume.read_typed_block(&location).await.unwrap();
    assert_eq!(kind, BlockType::Manifest);

    let key = archive
        .session()
        .derive_block_key(archive.volume_key(), block_id.sequence(), header.salt())
        .unwrap();
    let aead = XChaCha20Poly1305Context::from_derived_key(&key.to_derived_key().unwrap()).unwrap();
    let aad = build_aad(
        header.archive_id().0.as_bytes(),
        header.epoch_id(),
        BlockType::Manifest,
        u32::from(header.volume_sequence()),
        block_id,
    );
    let nonce = block.data.first_chunk::<NONCE_SIZE>().unwrap();
    let plaintext = aead
        .decrypt(nonce, &aad, &block.data[NONCE_SIZE..])
        .unwrap();
    let (mut manifest, digest) =
        ArchiveManifest::from_bytes_with_header_digest(&plaintext).unwrap();
    manifest.committed_horizon = legacy_end;
    manifest.volume_committed_ends = vec![legacy_end];
    let legacy = manifest.to_bytes_with_header_digest(digest.unwrap());
    assert_eq!(
        legacy.len(),
        plaintext.len(),
        "legacy rewrite must not move trailing metadata"
    );

    let mut encrypted = nonce.to_vec();
    encrypted.extend(aead.encrypt(nonce, &aad, &legacy).unwrap());
    assert_eq!(encrypted.len(), block.data.len());
    let block_header = BlockHeader::new(
        BlockType::Manifest,
        u32::try_from(encrypted.len()).unwrap(),
        compute_shard_crc(&encrypted),
    );
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(archive_path)
        .unwrap();
    file.seek(SeekFrom::Start(footer.manifest_offset()))
        .unwrap();
    file.write_all(&block_header.to_bytes()).unwrap();
    file.write_all(&encrypted).unwrap();
    file.sync_all().unwrap();
    (retained_end, legacy_end)
}

/// Corrupt the checkpoint payload while keeping its frame CRC valid, forcing AEAD validation.
pub async fn corrupt_authenticated_checkpoint(archive_path: &Path) {
    let mut bytes = fs::read(archive_path).unwrap();
    let footer = {
        let backend = LocalStorageBackend::new(archive_path.parent().unwrap());
        VolumeReader::open(&backend, Path::new(archive_path.file_name().unwrap()))
            .await
            .unwrap()
            .footer()
            .unwrap()
            .clone()
    };
    let offset = footer.last_checkpoint_offset();
    let header = block_header(&bytes, offset);
    let payload_start = usize::try_from(offset).unwrap() + BlockHeader::SIZE;
    let payload_end = payload_start + usize::try_from(header.length).unwrap();
    bytes[payload_end - 1] ^= 1;
    let crc = compute_shard_crc(&bytes[payload_start..payload_end]);
    let updated = BlockHeader::new(BlockType::Checkpoint, header.length, crc);
    let header_start = usize::try_from(offset).unwrap();
    bytes[header_start..header_start + BlockHeader::SIZE].copy_from_slice(&updated.to_bytes());
    fs::write(archive_path, bytes).unwrap();
}
