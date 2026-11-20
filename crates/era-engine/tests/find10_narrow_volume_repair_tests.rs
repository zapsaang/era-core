use era_common::{ArchiveConfig, ErasureCodeConfig};
use era_engine::{
    repair_archive, ArchiveHealthStatus, ArchiveReader, ArchiveWriterBuilder, ExtractOptions,
    RepairOptions,
};
use era_volume::DATA_REGION_START;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const PASSWORD: &str = "find10-test-password";

fn test_config() -> ArchiveConfig {
    let mut config = ArchiveConfig::default();
    config.encryption.kdf_memory_cost = 1024;
    config.encryption.kdf_time_cost = 1;
    config
}

async fn create_narrow_ec_archive(
    dir: &Path,
    name: &str,
    erasure: ErasureCodeConfig,
    volume_count: usize,
) -> (PathBuf, Vec<u8>) {
    let archive_path = dir.join(name);
    let payload: Vec<u8> = (0..(128 * 1024)).map(|i| ((i * 37) % 251) as u8).collect();

    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .password(PASSWORD)
        .config(test_config())
        .enable_erasure(true)
        .erasure_config(erasure)
        .volume_count(volume_count)
        .build()
        .await
        .unwrap();

    writer.add_bytes("payload.bin", &payload).await.unwrap();
    writer.finalize().await.unwrap();
    (archive_path, payload)
}

fn flip_bytes(path: &Path, offset: u64, len: usize) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf).unwrap();
    for b in &mut buf {
        *b ^= 0xFF;
    }
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&buf).unwrap();
    file.sync_all().unwrap();
}

#[tokio::test]
async fn find10_repair_3_volumes_4_2_is_healthy_and_fully_repaired() {
    let temp_dir = TempDir::new().unwrap();
    let (archive_path, payload) = create_narrow_ec_archive(
        temp_dir.path(),
        "narrow.era",
        ErasureCodeConfig::new(4, 2),
        3,
    )
    .await;

    let vol1_path = temp_dir.path().join("narrow.era.001");
    flip_bytes(&vol1_path, DATA_REGION_START + 256, 128);

    let repair_stats = repair_archive(
        &archive_path,
        PASSWORD,
        RepairOptions {
            create_backup: false,
            dry_run: false,
            continue_on_error: true,
        },
    )
    .await
    .unwrap();

    assert!(
        repair_stats.shards_repaired > 0,
        "expected corrupted shard to be repaired"
    );
    assert_eq!(repair_stats.unrecoverable_blocks, 0);
    assert!(
        repair_stats.is_healthy(),
        "expected Healthy status after repairing all shards across 3 volumes, got {:?}",
        repair_stats.archive_health
    );
    assert!(
        repair_stats.fully_repaired(),
        "expected fully_repaired() == true, got {:?}",
        repair_stats
    );

    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    let verify_stats = reader.verify().await.unwrap();
    assert!(verify_stats.is_healthy());
    let out_dir = temp_dir.path().join("out");
    reader
        .extract_all(&ExtractOptions::new(&out_dir))
        .await
        .unwrap();
    assert_eq!(fs::read(out_dir.join("payload.bin")).unwrap(), payload);
}

#[tokio::test]
async fn find10_repair_3_volumes_4_2_with_one_missing_volume_is_degraded_not_incomplete() {
    let temp_dir = TempDir::new().unwrap();
    let (archive_path, _payload) = create_narrow_ec_archive(
        temp_dir.path(),
        "narrow_missing.era",
        ErasureCodeConfig::new(4, 2),
        3,
    )
    .await;

    // Removing 1 of 3 volumes leaves 2 volumes holding 4 shards per stripe (== data_shards).
    fs::remove_file(temp_dir.path().join("narrow_missing.era.002")).unwrap();

    let repair_stats = repair_archive(
        &archive_path,
        PASSWORD,
        RepairOptions {
            create_backup: false,
            dry_run: true,
            continue_on_error: true,
        },
    )
    .await
    .unwrap();

    assert_eq!(repair_stats.unrecoverable_blocks, 0);
    assert!(
        matches!(
            repair_stats.archive_health,
            ArchiveHealthStatus::Degraded {
                expected_volumes: 3,
                found_volumes: 2,
                ..
            }
        ),
        "expected Degraded status when 2 of 3 volumes provide 4 shards per stripe, got {:?}",
        repair_stats.archive_health
    );
}

#[tokio::test]
async fn find10_repair_3_volumes_4_2_missing_plus_corrupted_is_incomplete() {
    let temp_dir = TempDir::new().unwrap();
    let (archive_path, _payload) = create_narrow_ec_archive(
        temp_dir.path(),
        "narrow_unrec.era",
        ErasureCodeConfig::new(4, 2),
        3,
    )
    .await;

    fs::remove_file(temp_dir.path().join("narrow_unrec.era.002")).unwrap();
    flip_bytes(
        &temp_dir.path().join("narrow_unrec.era.001"),
        DATA_REGION_START + 256,
        128,
    );

    let repair_stats = repair_archive(
        &archive_path,
        PASSWORD,
        RepairOptions {
            create_backup: false,
            dry_run: true,
            continue_on_error: true,
        },
    )
    .await
    .unwrap();

    assert!(repair_stats.unrecoverable_blocks > 0);
    assert!(
        repair_stats.is_incomplete(),
        "expected Incomplete status when missing volume + corrupted shard leave < 4 shards, got {:?}",
        repair_stats.archive_health
    );
}

#[tokio::test]
async fn find10_repair_3_volumes_5_1_with_one_missing_volume_is_incomplete() {
    let temp_dir = TempDir::new().unwrap();
    let (archive_path, _payload) = create_narrow_ec_archive(
        temp_dir.path(),
        "narrow_5_1.era",
        ErasureCodeConfig::new(5, 1),
        3,
    )
    .await;

    // Removing 1 of 3 volumes leaves 2 volumes holding only 4 shards per stripe (< 5 data_shards).
    fs::remove_file(temp_dir.path().join("narrow_5_1.era.002")).unwrap();

    let repair_stats = repair_archive(
        &archive_path,
        PASSWORD,
        RepairOptions {
            create_backup: false,
            dry_run: true,
            continue_on_error: true,
        },
    )
    .await
    .unwrap();

    assert!(repair_stats.unrecoverable_blocks > 0);
    assert!(
        repair_stats.is_incomplete(),
        "expected Incomplete status for 5:1 on 3 volumes with 1 missing volume, got {:?}",
        repair_stats.archive_health
    );
}
