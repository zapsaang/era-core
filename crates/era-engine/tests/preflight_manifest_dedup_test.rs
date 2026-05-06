use era_common::ArchiveConfig;
use era_engine::{ArchiveReader, ArchiveWriter};
use std::fs;
use tempfile::TempDir;

#[tokio::test]
async fn preflight_metadata_recovery_skips_redundant_manifest_load() {
    let temp_dir = TempDir::new().unwrap();
    let data_path = temp_dir.path().join("data.txt");
    let archive_path = temp_dir.path().join("test.era");

    fs::write(&data_path, b"test data for dedup test").unwrap();

    let config = ArchiveConfig {
        erasure: None,
        ..Default::default()
    };

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("test")
        .config(config)
        .build()
        .await
        .unwrap();
    writer.add_file(&data_path).await.unwrap();
    writer.finalize().await.unwrap();

    let mut reader = ArchiveReader::open(&archive_path, "test").await.unwrap();

    assert!(
        reader.manifest().is_some(),
        "Manifest must be loaded after open()"
    );
    let manifest_before = reader.manifest().unwrap().clone();

    reader.preflight_metadata_recovery().await.unwrap();

    assert!(
        reader.manifest().is_some(),
        "Manifest must remain present after preflight"
    );
    let manifest_after = reader.manifest().unwrap().clone();

    assert_eq!(
        manifest_before, manifest_after,
        "Manifest must not be reloaded during preflight when already present"
    );
}
