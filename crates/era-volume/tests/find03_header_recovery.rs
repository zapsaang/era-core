use era_common::{ArchiveConfig, ArchiveId, EraError, ErasureCodeConfig};
use era_storage::LocalStorageBackend;
use era_volume::{
    RecipientSlot, RecipientType, SuperHeader, VolumeReader, VolumeWriter, DATA_REGION_START,
    HEADER_SIZE,
};
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use tempfile::TempDir;

fn test_header() -> SuperHeader {
    SuperHeader::new(
        ArchiveId::new(),
        vec![RecipientSlot::new(
            RecipientType::Argon2idPassword,
            Some([0x12; 8]),
            vec![0xAB; 16],
            vec![0xCD; 48],
        )],
        ArchiveConfig {
            erasure: Some(ErasureCodeConfig::default()),
            ..Default::default()
        },
        [0x42; 16],
        era_volume::EncryptedVolumeKey::new(
            era_volume::KeyWrapAlgorithm::XChaCha20Poly1305,
            [0x24; 24],
            vec![0x48; 48],
        ),
        era_volume::AccessPolicy::AnyOfN,
    )
    .unwrap()
}

async fn create_finalized_volume(backend: &LocalStorageBackend, path: &Path, payload: &[u8]) {
    let mut writer = VolumeWriter::create(backend, path, test_header())
        .await
        .unwrap();
    if !payload.is_empty() {
        writer.write_raw(payload).await.unwrap();
    }
    writer.finalize().await.unwrap();
}

fn overwrite(path: &Path, offset: u64, bytes: &[u8]) {
    let mut file = OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[tokio::test]
async fn find03_primary_header_recovers_from_footer_backup_location() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let path = Path::new("find03_recovery.era");
    create_finalized_volume(&backend, path, &[]).await;

    let expected_header = VolumeReader::open(&backend, path).await.unwrap();
    assert!(!expected_header.header_recovered_from_backup());
    let expected_bytes = expected_header.header().to_bytes().unwrap();
    let backup_offset = expected_header.footer().unwrap().backup_header_offset();
    assert!(backup_offset >= DATA_REGION_START);
    drop(expected_header);

    overwrite(&temp_dir.path().join(path), 0, &[0; 64]);

    let recovered = VolumeReader::open(&backend, path).await.unwrap();
    assert!(recovered.header_recovered_from_backup());
    assert_eq!(recovered.header().to_bytes().unwrap(), expected_bytes);
}

#[tokio::test]
async fn find03_open_fails_closed_when_primary_and_backup_headers_are_damaged() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let path = Path::new("find03_both_damaged.era");
    create_finalized_volume(&backend, path, &[]).await;

    let reader = VolumeReader::open(&backend, path).await.unwrap();
    let backup_offset = reader.footer().unwrap().backup_header_offset();
    drop(reader);

    overwrite(&temp_dir.path().join(path), 0, &[0; 64]);
    overwrite(&temp_dir.path().join(path), backup_offset, &[0; 64]);

    let error = VolumeReader::open(&backend, path)
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(error, EraError::InvalidMagic));
}

#[tokio::test]
async fn find03_header_recovers_via_reserved_footer_after_tail_truncation() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let path = Path::new("find03_reserved_footer.era");
    create_finalized_volume(&backend, path, &[0xAA; 256]).await;

    let reader = VolumeReader::open(&backend, path).await.unwrap();
    let expected_header = reader.header().to_bytes().unwrap();
    let backup_end = reader.footer().unwrap().backup_header_offset() + HEADER_SIZE as u64;
    drop(reader);

    let full_path = temp_dir.path().join(path);
    overwrite(&full_path, 0, &[0; 64]);
    let file = OpenOptions::new().write(true).open(&full_path).unwrap();
    file.set_len(backup_end).unwrap();
    file.sync_all().unwrap();

    let recovered = VolumeReader::open(&backend, path).await.unwrap();
    assert!(recovered.header_recovered_from_backup());
    assert_eq!(recovered.header().to_bytes().unwrap(), expected_header);
}

#[tokio::test]
async fn find03_truncated_volume_keeps_corrupted_footer_error() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let path = Path::new("find03_truncated.era");
    create_finalized_volume(&backend, path, &[0xAA; 256]).await;

    let full_path = temp_dir.path().join(path);
    let file = OpenOptions::new().write(true).open(&full_path).unwrap();
    file.set_len(DATA_REGION_START + 16).unwrap();
    file.sync_all().unwrap();

    let error = VolumeReader::open(&backend, path)
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(error, EraError::CorruptedFooter(_)));
}

#[tokio::test]
async fn find03_unfinalized_erasure_volume_keeps_footer_free_open_behavior() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let path = Path::new("find03_unfinalized.era");

    let writer = VolumeWriter::create(&backend, path, test_header())
        .await
        .unwrap();
    drop(writer);

    let reader = VolumeReader::open(&backend, path).await.unwrap();
    assert!(!reader.header_recovered_from_backup());
    assert!(reader.footer().is_none());
}
