//! Tests for cross-file deduplication via pending_hashes.
//!
//! Verifies that identical chunks are deduplicated even when still buffered
//! in the packing stage. Observable via verify (no errors) and archive size.

use era_common::ArchiveConfig;
use era_engine::{ArchiveReader, ArchiveWriter, ExtractOptions};
use era_storage::MemoryStorageBackend;
use std::fs;
use tempfile::TempDir;

fn config_no_ec() -> ArchiveConfig {
    ArchiveConfig {
        erasure: None,
        ..Default::default()
    }
}

#[tokio::test]
async fn test_cross_file_dedup_add_bytes() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("dedup.era");
    let data = vec![0xABu8; 100_000];

    let mut w = ArchiveWriter::builder(&path)
        .password("test")
        .config(config_no_ec())
        .build()
        .await
        .unwrap();
    w.add_bytes("file_a.bin", &data).await.unwrap();
    w.add_bytes("file_b.bin", &data).await.unwrap();
    w.finalize().await.unwrap();

    let mut reader = ArchiveReader::open(&path, "test").await.unwrap();
    let stats = reader.verify().await.unwrap();
    assert!(
        stats.is_ok(),
        "Verify failed with {} errors: {:?}",
        stats.errors.len(),
        &stats.errors[..stats.errors.len().min(5)]
    );
    assert_eq!(stats.files_incomplete, 0);

    let output_dir = temp_dir.path().join("output");
    let mut reader = ArchiveReader::open(&path, "test").await.unwrap();
    reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .await
        .unwrap();
    assert_eq!(fs::read(output_dir.join("file_a.bin")).unwrap(), data);
    assert_eq!(fs::read(output_dir.join("file_b.bin")).unwrap(), data);
}

#[tokio::test]
async fn test_cross_file_dedup_cdc_chunked() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    let content: Vec<u8> = (0..512 * 1024).map(|i| (i % 251) as u8).collect();
    let file_a = input_dir.join("a.bin");
    let file_b = input_dir.join("b.bin");
    fs::write(&file_a, &content).unwrap();
    fs::write(&file_b, &content).unwrap();

    let path = temp_dir.path().join("dedup_cdc.era");
    let mut w = ArchiveWriter::builder(&path)
        .password("test")
        .config(config_no_ec())
        .enable_cdc(true)
        .build()
        .await
        .unwrap();
    w.add_file(&file_a).await.unwrap();
    w.add_file(&file_b).await.unwrap();
    w.finalize().await.unwrap();

    let mut reader = ArchiveReader::open(&path, "test").await.unwrap();
    let stats = reader.verify().await.unwrap();
    assert!(
        stats.is_ok(),
        "CDC verify failed with {} errors: {:?}",
        stats.errors.len(),
        &stats.errors[..stats.errors.len().min(5)]
    );
    assert_eq!(stats.files_incomplete, 0);

    let output_dir = temp_dir.path().join("output");
    let mut reader = ArchiveReader::open(&path, "test").await.unwrap();
    reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .await
        .unwrap();
    assert_eq!(fs::read(output_dir.join("a.bin")).unwrap(), content);
    assert_eq!(fs::read(output_dir.join("b.bin")).unwrap(), content);
}

#[tokio::test]
async fn test_cross_file_dedup_single_chunk_no_cdc() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    let content = vec![0x42u8; 50_000];
    let file_a = input_dir.join("a.bin");
    let file_b = input_dir.join("b.bin");
    fs::write(&file_a, &content).unwrap();
    fs::write(&file_b, &content).unwrap();

    let path = temp_dir.path().join("dedup_single.era");
    let mut w = ArchiveWriter::builder(&path)
        .password("test")
        .config(config_no_ec())
        .build()
        .await
        .unwrap();
    w.add_file(&file_a).await.unwrap();
    w.add_file(&file_b).await.unwrap();
    w.finalize().await.unwrap();

    let mut reader = ArchiveReader::open(&path, "test").await.unwrap();
    let stats = reader.verify().await.unwrap();
    assert!(
        stats.is_ok(),
        "Single-chunk verify failed with {} errors: {:?}",
        stats.errors.len(),
        &stats.errors[..stats.errors.len().min(5)]
    );
    assert_eq!(stats.files_incomplete, 0);

    let output_dir = temp_dir.path().join("output");
    let mut reader = ArchiveReader::open(&path, "test").await.unwrap();
    reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .await
        .unwrap();
    assert_eq!(fs::read(output_dir.join("a.bin")).unwrap(), content);
    assert_eq!(fs::read(output_dir.join("b.bin")).unwrap(), content);
}

#[tokio::test]
async fn test_generic_writer_dedup_add_bytes() {
    use era_engine::GenericArchiveWriterBuilder;

    let data = vec![0xCDu8; 100_000];

    let backend_single = MemoryStorageBackend::new();
    let mut w = GenericArchiveWriterBuilder::new(backend_single.clone(), "single.era")
        .password("test")
        .build()
        .await
        .unwrap();
    w.add_bytes("file_a.bin", &data).await.unwrap();
    w.finalize().await.unwrap();
    let size_single = backend_single
        .get_data(&backend_single.list_paths().unwrap()[0])
        .unwrap()
        .unwrap()
        .len();

    let backend_double = MemoryStorageBackend::new();
    let mut w = GenericArchiveWriterBuilder::new(backend_double.clone(), "double.era")
        .password("test")
        .build()
        .await
        .unwrap();
    w.add_bytes("file_a.bin", &data).await.unwrap();
    w.add_bytes("file_b.bin", &data).await.unwrap();
    w.finalize().await.unwrap();
    let size_double = backend_double
        .get_data(&backend_double.list_paths().unwrap()[0])
        .unwrap()
        .unwrap()
        .len();

    let overhead = size_double.saturating_sub(size_single);
    assert!(
        overhead < 10_000,
        "GenericArchiveWriter dedup failed: {}B overhead (single={}, double={})",
        overhead,
        size_single,
        size_double
    );
}

/// 50 pairs of identical files (100 total) — simulates cargo build artifacts.
/// This is the scenario that triggered the original verify failure.
#[tokio::test]
async fn test_dedup_many_identical_pairs_verify() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("pairs.era");

    let mut w = ArchiveWriter::builder(&path)
        .password("test")
        .config(config_no_ec())
        .build()
        .await
        .unwrap();

    for i in 0..50 {
        let size = 10_000 + (i * 7_000);
        let data: Vec<u8> = (0..size).map(|j| ((i + j) % 251) as u8).collect();
        let name_a = format!("build-script-build-{:04x}", i);
        let name_b = format!("build_script_build-{:04x}", i);
        w.add_bytes(&name_a, &data).await.unwrap();
        w.add_bytes(&name_b, &data).await.unwrap();
    }

    w.finalize().await.unwrap();

    let mut reader = ArchiveReader::open(&path, "test").await.unwrap();
    let stats = reader.verify().await.unwrap();
    assert!(
        stats.is_ok(),
        "Verify failed with {} errors, {} incomplete files. First errors: {:?}",
        stats.errors.len(),
        stats.files_incomplete,
        &stats.errors[..stats.errors.len().min(5)]
    );
    assert_eq!(stats.files_incomplete, 0);
    assert_eq!(stats.files_verified, 100);
}

#[tokio::test]
async fn test_dedup_mixed_unique_and_duplicate() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("mixed.era");

    let shared_data = vec![0xAAu8; 100_000];
    let unique_a = vec![0xBBu8; 80_000];
    let unique_b = vec![0xCCu8; 90_000];

    let mut w = ArchiveWriter::builder(&path)
        .password("test")
        .config(config_no_ec())
        .build()
        .await
        .unwrap();
    w.add_bytes("shared_1.bin", &shared_data).await.unwrap();
    w.add_bytes("unique_a.bin", &unique_a).await.unwrap();
    w.add_bytes("shared_2.bin", &shared_data).await.unwrap();
    w.add_bytes("unique_b.bin", &unique_b).await.unwrap();
    w.add_bytes("shared_3.bin", &shared_data).await.unwrap();
    w.finalize().await.unwrap();

    let mut reader = ArchiveReader::open(&path, "test").await.unwrap();
    let stats = reader.verify().await.unwrap();
    assert!(
        stats.is_ok(),
        "Mixed verify failed with {} errors: {:?}",
        stats.errors.len(),
        &stats.errors[..stats.errors.len().min(5)]
    );

    let output_dir = temp_dir.path().join("output");
    let mut reader = ArchiveReader::open(&path, "test").await.unwrap();
    reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .await
        .unwrap();
    assert_eq!(
        fs::read(output_dir.join("shared_1.bin")).unwrap(),
        shared_data
    );
    assert_eq!(
        fs::read(output_dir.join("shared_2.bin")).unwrap(),
        shared_data
    );
    assert_eq!(
        fs::read(output_dir.join("shared_3.bin")).unwrap(),
        shared_data
    );
    assert_eq!(fs::read(output_dir.join("unique_a.bin")).unwrap(), unique_a);
    assert_eq!(fs::read(output_dir.join("unique_b.bin")).unwrap(), unique_b);
}
