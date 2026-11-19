use era_common::{ArchiveConfig, EraError, ErasureCodeConfig};
use era_engine::{repair_archive, ArchiveReader, ArchiveWriter, RepairOptions};
use era_storage::LocalStorageBackend;
use era_volume::{SuperHeader, VolumeReader, VolumeWriter, HEADER_SIZE};
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use tempfile::TempDir;

const PASSWORD: &str = "find03-test-password";

async fn create_single_volume_archive(path: &Path) {
    let mut config = ArchiveConfig::default();
    config.encryption.kdf_memory_cost = 1024;
    config.encryption.kdf_time_cost = 1;

    let mut writer = ArchiveWriter::builder(path)
        .password(PASSWORD)
        .config(config)
        .erasure_config(ErasureCodeConfig::default())
        .volume_count(1)
        .build()
        .await
        .unwrap();
    writer
        .add_bytes("payload.bin", b"FIND-03 header recovery payload")
        .await
        .unwrap();
    writer.finalize().await.unwrap();
}

fn overwrite(path: &Path, offset: u64, bytes: &[u8]) {
    let mut file = OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn corrupt_primary_header(path: &Path) -> Vec<u8> {
    let original = fs::read(path).unwrap();
    overwrite(path, 0, &[0; 64]);
    original[..HEADER_SIZE].to_vec()
}

#[tokio::test]
async fn find03_verify_reports_degraded_when_primary_header_uses_backup() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("find03_verify.era");
    create_single_volume_archive(&archive_path).await;
    corrupt_primary_header(&archive_path);

    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    let stats = reader.verify().await.unwrap();

    assert!(stats.is_ok());
    assert!(stats.is_degraded());
    assert_eq!(stats.warnings.len(), 1);
    assert!(stats.errors.is_empty());
}

#[tokio::test]
async fn find03_repair_dry_run_preserves_volume_and_skips_backup() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("find03_dry_run.era");
    create_single_volume_archive(&archive_path).await;
    corrupt_primary_header(&archive_path);
    let corrupted = fs::read(&archive_path).unwrap();
    let backup_path = archive_path.with_extension("era.bak");

    let stats = repair_archive(
        &archive_path,
        PASSWORD,
        RepairOptions {
            create_backup: true,
            dry_run: true,
            continue_on_error: true,
        },
    )
    .await
    .unwrap();

    assert!(stats.fully_repaired());
    assert_eq!(fs::read(&archive_path).unwrap(), corrupted);
    assert!(!backup_path.exists());
}

#[tokio::test]
async fn find03_repair_restores_primary_header_and_preserves_corrupted_backup() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("find03_repair.era");
    create_single_volume_archive(&archive_path).await;
    let original_header = corrupt_primary_header(&archive_path);
    let corrupted = fs::read(&archive_path).unwrap();
    let backup_path = archive_path.with_extension("era.bak");

    let stats = repair_archive(&archive_path, PASSWORD, RepairOptions::default())
        .await
        .unwrap();

    assert!(stats.fully_repaired());
    assert_eq!(stats.shards_repaired, 0);
    assert_eq!(fs::read(&backup_path).unwrap(), corrupted);
    let mut expected = corrupted;
    expected[..HEADER_SIZE].copy_from_slice(&original_header);
    assert_eq!(fs::read(&archive_path).unwrap(), expected);

    let backend = LocalStorageBackend::new(temp_dir.path());
    let volume = VolumeReader::open(&backend, Path::new("find03_repair.era"))
        .await
        .unwrap();
    assert!(!volume.header_recovered_from_backup());

    let mut repaired_reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    let verify_stats = repaired_reader.verify().await.unwrap();
    assert!(verify_stats.is_healthy());
    assert!(verify_stats.warnings.is_empty());
}

#[tokio::test]
async fn find03_recovered_header_repair_rejects_wrong_password_without_writes() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("find03_wrong_password.era");
    create_single_volume_archive(&archive_path).await;
    corrupt_primary_header(&archive_path);
    let corrupted = fs::read(&archive_path).unwrap();
    let backup_path = archive_path.with_extension("era.bak");

    let error = repair_archive(
        &archive_path,
        "find03-wrong-password",
        RepairOptions::default(),
    )
    .await
    .unwrap_err();

    assert!(matches!(error, EraError::InvalidKey(_)));
    assert_eq!(fs::read(&archive_path).unwrap(), corrupted);
    assert!(!backup_path.exists());
}

#[tokio::test]
async fn find03_metadata_repair_rejects_foreign_backup_before_writes() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("find03_target.era");
    let donor_path = temp_dir.path().join("find03_donor.era");
    create_single_volume_archive(&archive_path).await;
    create_single_volume_archive(&donor_path).await;

    let backend = LocalStorageBackend::new(temp_dir.path());
    let initial = VolumeReader::open(&backend, Path::new("find03_target.era"))
        .await
        .unwrap();
    let backup_offset = initial.footer().unwrap().backup_header_offset();
    drop(initial);

    let donor_header = fs::read(&donor_path).unwrap()[..HEADER_SIZE].to_vec();
    overwrite(&archive_path, backup_offset, &donor_header);
    corrupt_primary_header(&archive_path);
    let corrupted = fs::read(&archive_path).unwrap();
    let backup_path = archive_path.with_extension("era.bak");

    let recovered = VolumeReader::open(&backend, Path::new("find03_target.era"))
        .await
        .unwrap();
    assert_eq!(recovered.header().to_bytes().unwrap(), donor_header);
    drop(recovered);

    let result = repair_archive(&archive_path, PASSWORD, RepairOptions::default()).await;

    assert!(result.is_err());
    assert_eq!(fs::read(&archive_path).unwrap(), corrupted);
    assert!(!backup_path.exists());
}

#[tokio::test]
async fn find03_metadata_repair_requires_authenticated_on_volume_metadata() {
    let temp_dir = TempDir::new().unwrap();
    let source_path = temp_dir.path().join("source.era");
    create_single_volume_archive(&source_path).await;
    let backend = LocalStorageBackend::new(temp_dir.path());
    let source = VolumeReader::open(&backend, Path::new("source.era"))
        .await
        .unwrap();

    // A finalized volume with a valid key envelope but no authenticated manifest.
    let path = Path::new("find03_no_manifest.era");
    let writer = VolumeWriter::create(&backend, path, source.header().clone())
        .await
        .unwrap();
    writer.finalize().await.unwrap();
    let archive_path = temp_dir.path().join(path);
    corrupt_primary_header(&archive_path);
    let corrupted = fs::read(&archive_path).unwrap();

    let result = repair_archive(&archive_path, PASSWORD, RepairOptions::default()).await;

    assert!(matches!(result, Err(EraError::IntegrityError(_))));
    assert_eq!(fs::read(&archive_path).unwrap(), corrupted);
    assert!(!archive_path.with_extension("era.bak").exists());
}

#[tokio::test]
async fn find03_repair_refuses_backup_with_damaged_creation_time() {
    let temp_dir = TempDir::new().unwrap();
    let path = Path::new("find03_damaged_timestamp.era");
    let archive_path = temp_dir.path().join(path);
    create_single_volume_archive(&archive_path).await;
    let backend = LocalStorageBackend::new(temp_dir.path());
    let original = VolumeReader::open(&backend, path).await.unwrap();
    let backup_offset = original.footer().unwrap().backup_header_offset();
    let mut metadata = era_common::proto::SuperHeader::from(original.header().clone());
    metadata.creation_time ^= 1;
    let damaged_header = SuperHeader::try_from(metadata).unwrap().to_bytes().unwrap();
    drop(original);
    overwrite(&archive_path, backup_offset, &damaged_header);
    corrupt_primary_header(&archive_path);
    let damaged_archive = fs::read(&archive_path).unwrap();

    let result = repair_archive(&archive_path, PASSWORD, RepairOptions::default()).await;

    assert!(matches!(result, Err(EraError::IntegrityError(_))));
    assert_eq!(fs::read(&archive_path).unwrap(), damaged_archive);
    assert!(!archive_path.with_extension("era.bak").exists());
}
