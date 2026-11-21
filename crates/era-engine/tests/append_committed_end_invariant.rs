use era_common::{
    compute_shard_crc, ArchiveConfig, ArchiveManifest, BlockHeader, BlockId, BlockLocation,
    BlockType, EraError,
};
use era_crypto::{build_aad, AeadContext, Nonce, XChaCha20Poly1305Context, NONCE_SIZE};
use era_engine::{ArchiveReader, ArchiveWriter};
use era_volume::{Footer, VolumeReader, FOOTER_SIZE};
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use tempfile::TempDir;

fn write_test_file(dir: &Path, name: &str, content: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, content).unwrap();
    path
}

fn test_config() -> ArchiveConfig {
    ArchiveConfig {
        erasure: None,
        ..Default::default()
    }
}

async fn create_test_archive(archive_path: &Path, password: &str, config: ArchiveConfig) {
    let temp_dir = TempDir::new().unwrap();
    let data_path = write_test_file(temp_dir.path(), "data.txt", b"hello world");

    let mut writer = ArchiveWriter::builder(archive_path)
        .password(password)
        .config(config)
        .build()
        .await
        .unwrap();
    writer.add_file(&data_path).await.unwrap();
    writer.finalize().await.unwrap();
}

async fn read_manifest(archive_path: &Path, password: &str) -> era_common::ArchiveManifest {
    let mut reader = ArchiveReader::open(archive_path, password).await.unwrap();
    reader.preflight_metadata_recovery().await.unwrap();
    reader.manifest().unwrap().clone()
}

async fn read_footer(archive_path: &Path) -> Footer {
    let backend = era_storage::LocalStorageBackend::new(archive_path.parent().unwrap());
    let volume_name = std::path::Path::new(archive_path.file_name().unwrap());
    let reader = VolumeReader::open(&backend, volume_name).await.unwrap();
    reader.footer().unwrap().clone()
}

fn read_block_header(data: &[u8], offset: u64) -> BlockHeader {
    let header_bytes: [u8; BlockHeader::SIZE] = data
        [offset as usize..offset as usize + BlockHeader::SIZE]
        .try_into()
        .unwrap();
    BlockHeader::from_bytes(&header_bytes).unwrap()
}

#[tokio::test]
async fn test_append_committed_end_monotonic() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("append.era");
    let config = test_config();

    create_test_archive(&archive_path, "test", config.clone()).await;
    let manifest_first = read_manifest(&archive_path, "test").await;
    let ends_first = manifest_first.volume_committed_ends;

    let data_path2 = write_test_file(temp_dir.path(), "data2.txt", b"append data");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("test")
        .append_existing(true)
        .config(config)
        .build()
        .await
        .unwrap();
    writer.add_file(&data_path2).await.unwrap();
    writer.finalize().await.unwrap();

    let manifest_second = read_manifest(&archive_path, "test").await;
    let ends_second = manifest_second.volume_committed_ends;

    assert!(
        ends_second.len() >= ends_first.len(),
        "Volume count should not decrease"
    );
    for (i, (new, old)) in ends_second.iter().zip(ends_first.iter()).enumerate() {
        assert!(
            new >= old,
            "committed_end for volume {} decreased: {} -> {}",
            i,
            old,
            new
        );
    }
}

#[tokio::test]
async fn test_append_committed_end_excludes_typed_blocks() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("append.era");

    create_test_archive(&archive_path, "test", ArchiveConfig::default()).await;

    let manifest = read_manifest(&archive_path, "test").await;
    let committed_end = manifest.volume_committed_ends[0];

    let footer = read_footer(&archive_path).await;
    let data_end_offset = footer.data_end_offset();

    let file_data = fs::read(&archive_path).unwrap();
    let mut typed_blocks_total_size = 0u64;
    let mut offset = committed_end;
    while offset < data_end_offset {
        let header = read_block_header(&file_data, offset);
        typed_blocks_total_size += BlockHeader::SIZE as u64 + u64::from(header.length);
        offset += BlockHeader::SIZE as u64 + u64::from(header.length);
    }

    assert_eq!(
        data_end_offset - committed_end,
        typed_blocks_total_size,
        "data_end_offset ({}) - committed_end ({}) should equal typed_blocks_total_size ({})",
        data_end_offset,
        committed_end,
        typed_blocks_total_size
    );
}

#[tokio::test]
async fn test_append_no_data_committed_end_unchanged() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("append.era");
    let config = test_config();

    create_test_archive(&archive_path, "test", config.clone()).await;
    let manifest_first = read_manifest(&archive_path, "test").await;
    let ends_first = manifest_first.volume_committed_ends;

    let writer = ArchiveWriter::builder(&archive_path)
        .password("test")
        .append_existing(true)
        .config(config)
        .build()
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    let manifest_second = read_manifest(&archive_path, "test").await;
    let ends_second = manifest_second.volume_committed_ends;

    assert_eq!(
        ends_first, ends_second,
        "committed_ends should be unchanged when no data is appended"
    );
}

#[tokio::test]
async fn test_append_corrupt_footer_rejected() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("append.era");

    create_test_archive(&archive_path, "test", test_config()).await;

    let mut file_data = fs::read(&archive_path).unwrap();
    let file_len = file_data.len() as u64;

    let primary_footer_offset = file_len - FOOTER_SIZE as u64;
    let backup_footer_offset = era_volume::HEADER_SIZE as u64;

    file_data[primary_footer_offset as usize] = b'X';
    file_data[backup_footer_offset as usize] = b'X';

    fs::write(&archive_path, &file_data).unwrap();

    let backend = era_storage::LocalStorageBackend::new(archive_path.parent().unwrap());
    let vol_result =
        era_volume::VolumeReader::open(&backend, std::path::Path::new("append.era")).await;
    assert!(
        vol_result.is_err(),
        "VolumeReader should reject corrupted footer"
    );

    let result = ArchiveWriter::builder(&archive_path)
        .password("test")
        .append_existing(true)
        .config(test_config())
        .build()
        .await;

    assert!(
        result.is_err(),
        "Append should fail when footer is corrupted"
    );
}

#[tokio::test]
async fn test_v82_corrupt_manifest_fails_closed() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("v82.era");

    create_test_archive(&archive_path, "test", test_config()).await;

    let footer = read_footer(&archive_path).await;
    assert!(footer.has_manifest(), "Archive should have manifest");

    let mut file_data = fs::read(&archive_path).unwrap();
    let manifest_offset = footer.manifest_offset();

    let nonce_start = manifest_offset as usize + BlockHeader::SIZE;
    file_data[nonce_start] ^= 0xFF;
    file_data[nonce_start + 5] ^= 0xFF;
    file_data[nonce_start + 10] ^= 0xFF;

    fs::write(&archive_path, &file_data).unwrap();

    let result = ArchiveReader::open(&archive_path, "test").await;
    assert!(result.is_err(), "Should fail when manifest is corrupted");
    let err_string = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("Expected error"),
    };
    assert!(
        err_string.contains("IntegrityError") || err_string.contains("manifest"),
        "Error should mention integrity or manifest: {}",
        err_string
    );
}

#[test]
fn test_append_manifest_footer_integrity_check_present() {
    let source = include_str!("../src/writer.rs");
    assert!(
        source.contains("footer data_end_offset {} is less than manifest committed end"),
        "Writer append integrity check must be present"
    );
}

#[tokio::test]
async fn test_empty_volume_committed_ends_fail_closed() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("empty_ends.era");

    create_test_archive(&archive_path, "test", test_config()).await;

    let footer = read_footer(&archive_path).await;
    let mut file_data = fs::read(&archive_path).unwrap();
    let manifest_offset = footer.manifest_offset();

    let ciphertext_start = manifest_offset as usize + BlockHeader::SIZE + 24;
    file_data[ciphertext_start] ^= 0xFF;
    fs::write(&archive_path, &file_data).unwrap();

    let result = ArchiveReader::open(&archive_path, "test").await;
    assert!(
        result.is_err(),
        "Should fail when manifest cannot be loaded but is declared"
    );
}

#[tokio::test]
async fn test_append_rejects_footer_data_end_below_manifest_committed_end() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("append_mismatch.era");

    create_test_archive(&archive_path, "test", test_config()).await;

    let mut reader = ArchiveReader::open(&archive_path, "test").await.unwrap();
    reader.preflight_metadata_recovery().await.unwrap();
    let footer = reader.primary_footer().unwrap().clone();
    let header = reader.header().clone();
    assert_eq!(header.volume_sequence(), 0);
    assert_eq!(footer.sequence_number(), 1);

    let backend = era_storage::LocalStorageBackend::new(archive_path.parent().unwrap());
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

    let key = reader
        .session()
        .derive_block_key(reader.volume_key(), block_id.sequence(), header.salt())
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
    let (mut manifest, digests) =
        ArchiveManifest::from_bytes_with_header_digests(&plaintext).unwrap();

    let bumped_committed_end = footer.data_end_offset() + 1;
    manifest.committed_horizon = bumped_committed_end;
    manifest.volume_committed_ends = vec![bumped_committed_end];
    let encoded = if digests.by_sequence.is_empty() {
        manifest.to_bytes_with_header_digest(digests.local.unwrap())
    } else {
        manifest
            .to_bytes_with_header_digests(header.volume_sequence(), &digests.by_sequence)
            .unwrap()
    };
    assert_eq!(
        encoded.len(),
        plaintext.len(),
        "manifest rewrite must preserve encoded block length"
    );

    let replacement_nonce = Nonce::generate();
    let mut encrypted = replacement_nonce.as_bytes().to_vec();
    encrypted.extend(
        aead.encrypt(replacement_nonce.as_bytes(), &aad, &encoded)
            .unwrap(),
    );
    assert_eq!(encrypted.len(), block.data.len());
    let block_header = BlockHeader::new(
        BlockType::Manifest,
        u32::try_from(encrypted.len()).unwrap(),
        compute_shard_crc(&encrypted),
    );
    let mut file = OpenOptions::new().write(true).open(&archive_path).unwrap();
    file.seek(SeekFrom::Start(footer.manifest_offset()))
        .unwrap();
    file.write_all(&block_header.to_bytes()).unwrap();
    file.write_all(&encrypted).unwrap();
    file.sync_all().unwrap();
    drop(volume);
    drop(reader);

    let err = match ArchiveWriter::builder(&archive_path)
        .password("test")
        .append_existing(true)
        .config(test_config())
        .build()
        .await
    {
        Ok(_) => panic!("Expected append to fail when footer data_end_offset < committed_end"),
        Err(err) => err,
    };
    match err {
        EraError::IntegrityError(msg) => {
            assert!(
                msg.contains("Volume 0 footer data_end_offset")
                    && msg.contains("is less than manifest committed end"),
                "Unexpected IntegrityError message: {msg}"
            );
        }
        other => panic!("Expected IntegrityError, got {other:?}"),
    }
}
