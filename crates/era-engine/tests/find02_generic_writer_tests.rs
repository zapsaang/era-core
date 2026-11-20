#![allow(deprecated)]

use era_common::{ArchiveConfig, CompressionAlgorithm};
use era_engine::{ArchiveReader, ExtractOptions, GenericArchiveWriterBuilder};
use era_storage::{LocalStorageBackend, MemoryStorageBackend};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

const PASSWORD: &str = "find02-generic-password";

fn test_config(algorithm: CompressionAlgorithm) -> ArchiveConfig {
    let mut config = ArchiveConfig::default();
    config.encryption.kdf_memory_cost = 1024;
    config.encryption.kdf_time_cost = 1;
    config.compression.algorithm = algorithm;
    config
}

#[tokio::test]
async fn find02_memory_backend_generic_writer_roundtrip_load_verify_extract() {
    let backend = MemoryStorageBackend::new();
    let mut writer = GenericArchiveWriterBuilder::new(backend.clone(), "t7_1.era")
        .password(PASSWORD)
        .config(test_config(CompressionAlgorithm::Zstd))
        .build()
        .await
        .unwrap();

    let alpha = b"Hello from GenericArchiveWriter via MemoryStorageBackend!".to_vec();
    let beta: Vec<u8> = (0..8192).map(|i| ((i * 29) % 251) as u8).collect();
    writer.add_bytes("alpha.txt", &alpha).await.unwrap();
    writer.add_bytes("nested/beta.bin", &beta).await.unwrap();
    writer
        .add_bytes("nested/beta_dup.bin", &beta)
        .await
        .unwrap();
    let stats = writer.finalize().await.unwrap();
    assert_eq!(stats.total_files, 3);

    let archive_bytes = backend
        .get_data(Path::new("t7_1.era"))
        .unwrap()
        .expect("memory backend should store finalized archive");

    let temp_dir = TempDir::new().unwrap();
    let disk_path = temp_dir.path().join("t7_1.era");
    fs::write(&disk_path, archive_bytes).unwrap();

    let mut reader = ArchiveReader::open(&disk_path, PASSWORD).await.unwrap();
    assert_eq!(reader.header().total_volumes(), 1);
    assert!(
        reader.manifest().is_some(),
        "GenericArchiveWriter must publish a v8.2 ArchiveManifest"
    );
    let footer = reader.primary_footer().unwrap();
    assert!(
        footer.has_manifest(),
        "footer must record manifest location"
    );

    let catalog = reader.load_catalog().await.unwrap();
    assert_eq!(catalog.file_count, 3);

    let verify_stats = reader.verify().await.unwrap();
    assert!(
        verify_stats.is_healthy(),
        "expected Healthy archive, got {:?}, warnings={:?}, errors={:?}",
        verify_stats.archive_health,
        verify_stats.warnings,
        verify_stats.errors
    );

    let out_dir = temp_dir.path().join("extracted");
    let extract_stats = reader
        .extract_all(&ExtractOptions::new(&out_dir))
        .await
        .unwrap();
    assert_eq!(extract_stats.extracted, 3);
    assert_eq!(fs::read(out_dir.join("alpha.txt")).unwrap(), alpha);
    assert_eq!(fs::read(out_dir.join("nested/beta.bin")).unwrap(), beta);
    assert_eq!(fs::read(out_dir.join("nested/beta_dup.bin")).unwrap(), beta);
}

#[tokio::test]
async fn find02_local_backend_generic_writer_empty_archive_is_readable() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let writer = GenericArchiveWriterBuilder::new(backend, "empty_generic.era")
        .password(PASSWORD)
        .config(test_config(CompressionAlgorithm::None))
        .build()
        .await
        .unwrap();
    let stats = writer.finalize().await.unwrap();
    assert_eq!(stats.total_files, 0);

    let disk_path = temp_dir.path().join("empty_generic.era");
    let mut reader = ArchiveReader::open(&disk_path, PASSWORD).await.unwrap();
    assert!(reader.manifest().is_some());

    let catalog = reader.load_catalog().await.unwrap();
    assert_eq!(catalog.file_count, 0);

    let verify_stats = reader.verify().await.unwrap();
    assert!(verify_stats.is_healthy());
}
