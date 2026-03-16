use era_common::ErasureCodeConfig;
use era_engine::{
    repair_archive_matrix, ArchiveHealthStatus, ArchiveReader, ArchiveWriterBuilder, RepairOptions,
};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

async fn create_4_plus_2_archive(temp_dir: &TempDir, name: &str, volume_count: usize) -> PathBuf {
    let archive_path = temp_dir.path().join(name);
    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .password("test_password")
        .enable_erasure(true)
        .erasure_config(ErasureCodeConfig::new(4, 2))
        .volume_count(volume_count)
        .build()
        .await
        .unwrap();

    writer
        .add_bytes("payload.bin", &vec![0x5A; 96 * 1024])
        .await
        .unwrap();
    writer.finalize().await.unwrap();
    archive_path
}

#[tokio::test]
async fn test_archive_health_healthy_when_all_expected_volumes_present() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = create_4_plus_2_archive(&temp_dir, "healthy.era", 6).await;

    let mut reader = ArchiveReader::open(&archive_path, "test_password")
        .await
        .unwrap();
    let stats = reader.verify().await.unwrap();

    assert!(stats.is_healthy());
    assert!(!stats.is_degraded());
    assert!(!stats.is_incomplete());
    assert!(matches!(stats.archive_health, ArchiveHealthStatus::Healthy));
}

#[tokio::test]
async fn test_archive_health_degraded_when_one_expected_volume_missing() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = create_4_plus_2_archive(&temp_dir, "degraded.era", 6).await;

    fs::remove_file(temp_dir.path().join("degraded.era.002")).unwrap();

    let mut reader = ArchiveReader::open(&archive_path, "test_password")
        .await
        .unwrap();
    let stats = reader.verify().await.unwrap();

    assert!(stats.is_degraded());
    assert!(!stats.is_healthy());
    assert!(!stats.is_incomplete());

    match &stats.archive_health {
        ArchiveHealthStatus::Degraded {
            expected_volumes,
            found_volumes,
            missing_indices,
        } => {
            assert_eq!(*expected_volumes, 6);
            assert_eq!(*found_volumes, 5);
            assert_eq!(missing_indices.as_slice(), &[2]);
        }
        other => panic!("expected degraded status, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_archive_health_incomplete_when_too_many_expected_volumes_missing() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = create_4_plus_2_archive(&temp_dir, "incomplete.era", 6).await;

    fs::remove_file(&archive_path).unwrap();
    fs::remove_file(temp_dir.path().join("incomplete.era.001")).unwrap();
    fs::remove_file(temp_dir.path().join("incomplete.era.002")).unwrap();

    let survivor_path = temp_dir.path().join("incomplete.era.003");
    let mut reader = ArchiveReader::open(&survivor_path, "test_password")
        .await
        .unwrap();
    let stats = reader.verify().await.unwrap();

    assert!(stats.is_incomplete());
    assert!(!stats.is_healthy());

    match &stats.archive_health {
        ArchiveHealthStatus::Incomplete {
            expected_volumes,
            found_volumes,
            missing_indices,
            reason,
        } => {
            assert_eq!(*expected_volumes, 6);
            assert_eq!(*found_volumes, 3);
            assert_eq!(missing_indices.as_slice(), &[0, 1, 2]);
            assert!(!reason.is_empty());
        }
        other => panic!("expected incomplete status, got: {other:?}"),
    }

    let repair_stats = repair_archive_matrix(
        &survivor_path,
        "test_password",
        RepairOptions {
            create_backup: false,
            dry_run: true,
            continue_on_error: true,
        },
    )
    .await
    .unwrap();

    assert!(repair_stats.is_incomplete());
    assert!(!repair_stats.is_healthy());
    match &repair_stats.archive_health {
        ArchiveHealthStatus::Incomplete {
            missing_indices, ..
        } => {
            assert_eq!(missing_indices.as_slice(), &[0, 1, 2]);
        }
        other => panic!("expected incomplete repair status, got: {other:?}"),
    }
}
