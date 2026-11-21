use era_common::{ArchiveConfig, CompressionAlgorithm, ErasureCodeConfig};
use era_engine::{repair_archive, ArchiveReader, ArchiveWriter, ExtractOptions, RepairOptions};
use era_storage::{LocalStorageBackend, LocalStorageReader};
use era_volume::{volume_path, VolumeReader, HEADER_SIZE};
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use tempfile::TempDir;

const PASSWORD: &str = "resid-high02-test-password";
const BLOCK_SIZE: usize = 512 * 1024;
const MAX_VOLUME_SIZE: u64 = 1024 * 1024;

#[derive(Clone, Copy)]
struct ArchiveLayout {
    erasure: Option<ErasureCodeConfig>,
    volume_count: usize,
}

fn fixture_files(count: u8) -> Vec<(String, Vec<u8>)> {
    (1..=count)
        .map(|value| (format!("payload-{value}.bin"), vec![value; BLOCK_SIZE]))
        .collect()
}

async fn open_volume(archive_path: &Path, sequence: u16) -> VolumeReader<LocalStorageReader> {
    let path = volume_path(archive_path, sequence);
    let backend = LocalStorageBackend::new(path.parent().unwrap());
    VolumeReader::open(&backend, Path::new(path.file_name().unwrap()))
        .await
        .unwrap()
}

async fn create_archive(
    archive_path: &Path,
    layout: ArchiveLayout,
    files: &[(String, Vec<u8>)],
) -> u16 {
    let mut config = ArchiveConfig {
        erasure: layout.erasure,
        ..Default::default()
    };
    config.compression.algorithm = CompressionAlgorithm::None;
    config.encryption.kdf_memory_cost = 1024;
    config.encryption.kdf_time_cost = 1;

    let mut builder = ArchiveWriter::builder(archive_path)
        .password(PASSWORD)
        .config(config)
        .volume_count(layout.volume_count)
        .max_volume_size(MAX_VOLUME_SIZE)
        .target_block_size(BLOCK_SIZE)
        .enable_cdc(false);
    if let Some(erasure) = layout.erasure {
        builder = builder.erasure_config(erasure);
    }

    let mut writer = builder.build().await.unwrap();
    for (name, contents) in files {
        writer.add_bytes(name, contents).await.unwrap();
    }
    writer.finalize().await.unwrap();

    open_volume(archive_path, 0).await.header().total_volumes()
}

fn corrupt_primary_header(path: &Path) -> Vec<u8> {
    let original_header = fs::read(path).unwrap()[..HEADER_SIZE].to_vec();
    let mut file = OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(&[0; 64]).unwrap();
    file.sync_all().unwrap();
    original_header
}

fn assert_primary_header_restored(path: &Path, expected_header: &[u8]) {
    assert_eq!(
        &fs::read(path).unwrap()[..HEADER_SIZE],
        expected_header,
        "primary header bytes should match the original authenticated header"
    );
}

async fn assert_degraded_before_repair(archive_path: &Path) {
    let mut reader = ArchiveReader::open(archive_path, PASSWORD).await.unwrap();
    let stats = reader.verify().await.unwrap();
    assert!(stats.is_ok(), "payload data should remain readable");
    assert!(stats.is_degraded(), "backup-header use must be reported");
    assert!(stats.errors.is_empty());
    assert!(!stats.warnings.is_empty());
}

async fn assert_healthy_after_repair(archive_path: &Path) {
    let mut reader = ArchiveReader::open(archive_path, PASSWORD).await.unwrap();
    let stats = reader.verify().await.unwrap();
    assert!(stats.is_healthy());
    assert!(stats.warnings.is_empty());
    assert!(stats.errors.is_empty());
}

async fn assert_extracted_payloads_intact(
    archive_path: &Path,
    output_dir: &Path,
    files: &[(String, Vec<u8>)],
) {
    let mut reader = ArchiveReader::open(archive_path, PASSWORD).await.unwrap();
    let stats = reader
        .extract_all(&ExtractOptions::new(output_dir))
        .await
        .unwrap();
    assert_eq!(stats.extracted, u64::try_from(files.len()).unwrap());
    for (name, expected) in files {
        assert_eq!(fs::read(output_dir.join(name)).unwrap(), *expected);
    }
}

#[tokio::test]
async fn resid_high02_non_ec_single_volume_header_repair_restores_health_and_data() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("non-ec-single.era");
    let files = fixture_files(1);
    let total = create_archive(
        &archive_path,
        ArchiveLayout {
            erasure: None,
            volume_count: 1,
        },
        &files,
    )
    .await;
    assert_eq!(total, 1);
    let original_header = corrupt_primary_header(&archive_path);
    assert_degraded_before_repair(&archive_path).await;

    let repair = repair_archive(&archive_path, PASSWORD, RepairOptions::default())
        .await
        .unwrap();

    assert!(repair.fully_repaired());
    assert_eq!(repair.shards_repaired, 0);
    assert_primary_header_restored(&archive_path, &original_header);
    assert!(!open_volume(&archive_path, 0)
        .await
        .header_recovered_from_backup());
    assert_healthy_after_repair(&archive_path).await;
    assert_extracted_payloads_intact(&archive_path, &temp_dir.path().join("output"), &files).await;
}

#[tokio::test]
async fn resid_high02_non_ec_multi_volume_header_repair_restores_health_and_data() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("non-ec-multi.era");
    let files = fixture_files(3);
    let total = create_archive(
        &archive_path,
        ArchiveLayout {
            erasure: None,
            volume_count: 1,
        },
        &files,
    )
    .await;
    assert!(total > 1, "the size cap must force non-EC rotation");

    let damaged_sequence = total - 1;
    let active = open_volume(&archive_path, damaged_sequence).await;
    assert!(active.footer().unwrap().has_manifest());
    drop(active);
    let damaged_path = volume_path(&archive_path, damaged_sequence);
    let original_header = corrupt_primary_header(&damaged_path);
    assert_degraded_before_repair(&archive_path).await;

    let repair = repair_archive(&archive_path, PASSWORD, RepairOptions::default())
        .await
        .unwrap();

    assert!(repair.fully_repaired());
    assert_eq!(repair.shards_repaired, 0);
    assert_primary_header_restored(&damaged_path, &original_header);
    assert!(!open_volume(&archive_path, damaged_sequence)
        .await
        .header_recovered_from_backup());
    assert_healthy_after_repair(&archive_path).await;
    assert_extracted_payloads_intact(&archive_path, &temp_dir.path().join("output"), &files).await;
}

#[tokio::test]
async fn resid_high02_retired_sequence_zero_header_repair_restores_health_and_data() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("rotated-ec.era");
    let files = fixture_files(3);
    let initial_width = 3;
    let total = create_archive(
        &archive_path,
        ArchiveLayout {
            erasure: Some(ErasureCodeConfig {
                data_shards: 2,
                parity_shards: 1,
            }),
            volume_count: initial_width,
        },
        &files,
    )
    .await;
    assert!(
        total > u16::try_from(initial_width).unwrap(),
        "the EC layout must rotate beyond its initial generation"
    );

    let retired = open_volume(&archive_path, 0).await;
    assert_eq!(retired.header().volume_sequence(), 0);
    assert!(
        !retired.footer().unwrap().has_manifest(),
        "sequence 0 must be retired rather than an active manifest volume"
    );
    drop(retired);

    let original_header = corrupt_primary_header(&archive_path);
    assert_degraded_before_repair(&archive_path).await;

    let repair = repair_archive(&archive_path, PASSWORD, RepairOptions::default())
        .await
        .unwrap();

    assert!(repair.fully_repaired());
    assert_eq!(repair.shards_repaired, 0);
    assert_primary_header_restored(&archive_path, &original_header);
    assert!(!open_volume(&archive_path, 0)
        .await
        .header_recovered_from_backup());
    assert_healthy_after_repair(&archive_path).await;
    assert_extracted_payloads_intact(&archive_path, &temp_dir.path().join("output"), &files).await;
}

#[tokio::test]
async fn resid_high02_active_volume_repairs_primary_header_when_local_manifest_is_also_corrupted() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("active-double-damage.era");
    let files = fixture_files(2);
    let total = create_archive(
        &archive_path,
        ArchiveLayout {
            erasure: Some(ErasureCodeConfig {
                data_shards: 2,
                parity_shards: 1,
            }),
            volume_count: 3,
        },
        &files,
    )
    .await;
    assert_eq!(total, 3);

    let vol0 = open_volume(&archive_path, 0).await;
    let footer0 = vol0.footer().unwrap().clone();
    assert!(footer0.has_manifest());
    drop(vol0);

    // Corrupt BOTH volume 0's local manifest block AND its primary header.
    {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&archive_path)
            .unwrap();
        let corrupt_offset = footer0.manifest_offset() + era_common::BlockHeader::SIZE as u64 + 24;
        file.seek(SeekFrom::Start(corrupt_offset)).unwrap();
        let mut byte = [0u8; 1];
        std::io::Read::read_exact(&mut file, &mut byte).unwrap();
        byte[0] ^= 0xFF;
        file.seek(SeekFrom::Start(corrupt_offset)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
    }
    let original_header = corrupt_primary_header(&archive_path);
    assert_degraded_before_repair(&archive_path).await;

    let repair = repair_archive(&archive_path, PASSWORD, RepairOptions::default())
        .await
        .unwrap();

    assert!(repair.fully_repaired());
    assert_eq!(repair.shards_repaired, 0);
    assert_primary_header_restored(&archive_path, &original_header);
    assert!(!open_volume(&archive_path, 0)
        .await
        .header_recovered_from_backup());
    assert_healthy_after_repair(&archive_path).await;
    assert_extracted_payloads_intact(&archive_path, &temp_dir.path().join("output"), &files).await;
}
