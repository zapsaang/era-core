//! Tests for mandatory default configurations in ERA v2.2+
//!
//! These tests verify that the default builder configuration produces
//! correct archives with expected properties.

use era_engine::{ArchiveReader, ArchiveWriter};
use era_storage::LocalStorageBackend;
use era_volume::VolumeReader;
use tempfile::TempDir;

#[tokio::test]
async fn test_mandatory_memory_index_default() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("test_mandatory.era");

    // Create writer with absolute defaults
    // We expect:
    // 1. Memory Index to be used (no external LSM directory)
    // 2. CDC to be enabled
    // 3. No LSM manifest in footer (LSM backend removed in v2.2)
    let writer = ArchiveWriter::builder(&archive_path)
        .password("test1234")
        .build()
        .await
        .expect("Failed to build writer");

    // Close writer to flush everything
    writer.finalize().await.expect("Finalize failed");

    // Check: No index in footer (Memory backend is default)
    let backend = LocalStorageBackend::new(temp_dir.path());
    let file_name = archive_path.file_name().unwrap();
    let reader = VolumeReader::open(&backend, std::path::Path::new(file_name))
        .await
        .expect("Failed to open volume");
    let footer = reader.footer().expect("Missing footer");

    // V2.1 embedded index should now be present
    assert!(
        footer.has_index(),
        "V2.1 embedded index should be present in footer"
    );
}

/// The default builder configuration must enable content-defined chunking.
///
/// This is verified behaviourally: a large file added to the default builder is
/// stored as several chunks, while the same file under enable_cdc(false) is
/// stored as a single chunk. (Audit H-03: this test previously had an empty
/// body and therefore never verified the mandatory CDC default.)
#[tokio::test]
async fn test_mandatory_cdc_enabled() {
    let temp_dir = TempDir::new().unwrap();
    let source_path = temp_dir.path().join("large_source.bin");
    // 1 MiB of mixed content is large enough for FastCDC to emit several chunks.
    let payload: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
    std::fs::write(&source_path, &payload).unwrap();

    let default_path = temp_dir.path().join("cdc_default.era");
    let mut writer = ArchiveWriter::builder(&default_path)
        .password("test1234")
        .build()
        .await
        .expect("Failed to build writer");
    writer
        .add_file(&source_path)
        .await
        .expect("Failed to add file");
    writer.finalize().await.expect("Finalize failed");

    let mut reader = ArchiveReader::open(&default_path, "test1234")
        .await
        .expect("Failed to open default archive");
    let files = reader.list_files().await.expect("Failed to list files");
    let entry = files
        .iter()
        .find(|entry| entry.path.ends_with("large_source.bin"))
        .expect("source file missing from catalog");
    let default_chunks = entry.chunks.len();
    assert!(
        default_chunks > 1,
        "default builder must enable CDC: expected a large file to be split into \
         multiple chunks, got {default_chunks}"
    );

    let disabled_path = temp_dir.path().join("cdc_disabled.era");
    let mut writer = ArchiveWriter::builder(&disabled_path)
        .password("test1234")
        .enable_cdc(false)
        .build()
        .await
        .expect("Failed to build writer");
    writer
        .add_file(&source_path)
        .await
        .expect("Failed to add file");
    writer.finalize().await.expect("Finalize failed");

    let mut reader = ArchiveReader::open(&disabled_path, "test1234")
        .await
        .expect("Failed to open non-CDC archive");
    let files = reader.list_files().await.expect("Failed to list files");
    let entry = files
        .iter()
        .find(|entry| entry.path.ends_with("large_source.bin"))
        .expect("source file missing from catalog");
    assert_eq!(
        entry.chunks.len(),
        1,
        "explicit enable_cdc(false) must store the file as a single chunk"
    );
}
