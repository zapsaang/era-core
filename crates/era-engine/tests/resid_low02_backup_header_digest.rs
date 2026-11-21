#![allow(deprecated)]

use era_common::{ArchiveConfig, CompressionAlgorithm, EraError, ErasureCodeConfig};
use era_engine::{ArchiveReader, ArchiveWriter, ExtractOptions, GenericArchiveWriterBuilder};
use era_storage::LocalStorageBackend;
use era_volume::{volume_path, SuperHeader, VolumeReader};
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use tempfile::TempDir;

const PASSWORD: &str = "resid-low02-backup-header-digest";
const BLOCK_SIZE: usize = 512 * 1024;
const MAX_VOLUME_SIZE: u64 = 1024 * 1024;

fn fast_config(
    erasure: Option<ErasureCodeConfig>,
    compression: CompressionAlgorithm,
) -> ArchiveConfig {
    let mut config = ArchiveConfig {
        erasure,
        ..Default::default()
    };
    config.encryption.kdf_memory_cost = 1024;
    config.encryption.kdf_time_cost = 1;
    config.compression.algorithm = compression;
    config
}

fn overwrite(path: &Path, offset: u64, bytes: &[u8]) {
    let mut file = OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn corrupt_primary_header(path: &Path) {
    overwrite(path, 0, &[0; 64]);
}

async fn tamper_backup_header_and_corrupt_primary(volume_file: &Path) {
    let backend = LocalStorageBackend::new(volume_file.parent().unwrap());
    let file_name = Path::new(volume_file.file_name().unwrap());
    let reader = VolumeReader::open(&backend, file_name).await.unwrap();
    let backup_offset = reader.footer().unwrap().backup_header_offset();
    let mut proto = era_common::proto::SuperHeader::from(reader.header().clone());
    proto.creation_time ^= 1;
    let tampered_bytes = SuperHeader::try_from(proto).unwrap().to_bytes().unwrap();
    drop(reader);

    overwrite(volume_file, backup_offset, &tampered_bytes);
    corrupt_primary_header(volume_file);
}

async fn create_single_volume_archive(path: &Path, payload: &[u8]) {
    let config = fast_config(None, CompressionAlgorithm::Zstd);
    let mut writer = ArchiveWriter::builder(path)
        .password(PASSWORD)
        .config(config)
        .enable_erasure(false)
        .volume_count(1)
        .build()
        .await
        .unwrap();
    writer.add_bytes("payload.bin", payload).await.unwrap();
    writer.finalize().await.unwrap();
}

fn rotated_fixture_files() -> Vec<(String, Vec<u8>)> {
    (1..=3u8)
        .map(|value| (format!("payload-{value}.bin"), vec![value; BLOCK_SIZE]))
        .collect()
}

async fn create_rotated_ec_archive(archive_path: &Path, files: &[(String, Vec<u8>)]) -> u16 {
    let erasure = ErasureCodeConfig {
        data_shards: 2,
        parity_shards: 1,
    };
    let config = fast_config(Some(erasure), CompressionAlgorithm::None);
    let mut writer = ArchiveWriter::builder(archive_path)
        .password(PASSWORD)
        .config(config)
        .enable_erasure(true)
        .erasure_config(erasure)
        .volume_count(3)
        .max_volume_size(MAX_VOLUME_SIZE)
        .target_block_size(BLOCK_SIZE)
        .enable_cdc(false)
        .build()
        .await
        .unwrap();
    for (name, bytes) in files {
        writer.add_bytes(name, bytes).await.unwrap();
    }
    writer.finalize().await.unwrap();

    let backend = LocalStorageBackend::new(archive_path.parent().unwrap());
    let vol0 = VolumeReader::open(&backend, Path::new(archive_path.file_name().unwrap()))
        .await
        .unwrap();
    let total = vol0.header().total_volumes();
    assert!(total > 3, "size cap must trigger multi-generation rotation");
    assert!(
        !vol0.footer().unwrap().has_manifest(),
        "volume 0 must be retired without an on-volume manifest"
    );
    total
}

#[tokio::test]
async fn single_volume_open_rejects_tampered_backup_header() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("single_tampered.era");
    create_single_volume_archive(&archive_path, b"single volume payload").await;

    tamper_backup_header_and_corrupt_primary(&archive_path).await;

    let err = match ArchiveReader::open(&archive_path, PASSWORD).await {
        Ok(_) => panic!("expected tampered backup header to be rejected at open"),
        Err(err) => err,
    };
    assert!(
        matches!(err, EraError::IntegrityError(_)),
        "expected IntegrityError, got {err:?}"
    );
}

#[tokio::test]
async fn rotated_retired_volume_open_rejects_tampered_backup_header() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("rotated_tampered.era");
    let files = rotated_fixture_files();
    let total = create_rotated_ec_archive(&archive_path, &files).await;

    tamper_backup_header_and_corrupt_primary(&archive_path).await;

    for opening_path in [archive_path.clone(), volume_path(&archive_path, total - 1)] {
        let err = match ArchiveReader::open(&opening_path, PASSWORD).await {
            Ok(_) => panic!(
                "expected tampered retired backup header to be rejected when opening {}",
                opening_path.display()
            ),
            Err(err) => err,
        };
        assert!(
            matches!(err, EraError::IntegrityError(_)),
            "expected IntegrityError when opening {}, got {err:?}",
            opening_path.display()
        );
    }
}

#[tokio::test]
async fn generic_writer_open_rejects_tampered_backup_header() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let mut writer = GenericArchiveWriterBuilder::new(backend, "generic_tampered.era")
        .password(PASSWORD)
        .config(fast_config(None, CompressionAlgorithm::None))
        .build()
        .await
        .unwrap();
    writer
        .add_bytes("payload.bin", b"generic writer payload")
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    let archive_path = temp_dir.path().join("generic_tampered.era");
    tamper_backup_header_and_corrupt_primary(&archive_path).await;

    let err = match ArchiveReader::open(&archive_path, PASSWORD).await {
        Ok(_) => panic!("expected tampered generic backup header to be rejected at open"),
        Err(err) => err,
    };
    assert!(
        matches!(err, EraError::IntegrityError(_)),
        "expected IntegrityError, got {err:?}"
    );
}

#[tokio::test]
async fn intact_backup_header_still_opens_verifies_degraded_and_extracts() {
    let temp_dir = TempDir::new().unwrap();

    // Single volume positive control
    let single_path = temp_dir.path().join("single_intact.era");
    let single_payload = b"intact single backup header payload";
    create_single_volume_archive(&single_path, single_payload).await;
    corrupt_primary_header(&single_path);

    let mut single_reader = ArchiveReader::open(&single_path, PASSWORD).await.unwrap();
    let single_stats = single_reader.verify().await.unwrap();
    assert!(single_stats.is_degraded());
    assert!(single_stats.errors.is_empty());
    let single_out = temp_dir.path().join("single_out");
    single_reader
        .extract_all(&ExtractOptions::new(&single_out))
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(single_out.join("payload.bin")).unwrap(),
        single_payload
    );

    // Rotated retired volume 0 positive control
    let rotated_path = temp_dir.path().join("rotated_intact.era");
    let files = rotated_fixture_files();
    let total = create_rotated_ec_archive(&rotated_path, &files).await;
    corrupt_primary_header(&rotated_path);

    for (idx, opening_path) in [rotated_path.clone(), volume_path(&rotated_path, total - 1)]
        .into_iter()
        .enumerate()
    {
        let mut reader = ArchiveReader::open(&opening_path, PASSWORD).await.unwrap();
        let stats = reader.verify().await.unwrap();
        assert!(stats.is_degraded());
        assert!(stats.errors.is_empty());
        let out_dir = temp_dir.path().join(format!("rotated_out_{idx}"));
        reader
            .extract_all(&ExtractOptions::new(&out_dir))
            .await
            .unwrap();
        for (name, expected) in &files {
            assert_eq!(std::fs::read(out_dir.join(name)).unwrap(), *expected);
        }
    }
}
