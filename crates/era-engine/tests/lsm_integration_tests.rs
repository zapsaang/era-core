//! Integration tests for LSM-Tree based chunk index.
//!
//! These tests verify that ArchiveWriter works correctly with both
//! Memory and LSM (RocksDB) backends for chunk deduplication.

use era_common::Result;
use era_engine::chunk_index::ChunkIndexBackend;
use era_engine::{ArchiveReader, ArchiveWriter, ExtractOptions};
use std::fs;
use std::io::Write;
use tempfile::TempDir;

/// Create test files with specified content
fn create_test_file(dir: &TempDir, name: &str, content: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let mut file = fs::File::create(&path).unwrap();
    file.write_all(content).unwrap();
    path
}

/// Test basic archive creation with Memory backend (default)
#[test]
fn test_archive_with_memory_index() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let archive_path = temp_dir.path().join("test_memory.era");

    // Create test file
    let source_dir = TempDir::new()?;
    let file1 = create_test_file(&source_dir, "file1.txt", b"Hello, World!");

    // Build archive with default memory backend
    let mut writer = ArchiveWriter::builder(archive_path.clone())
        .password("test123")
        .build()?;

    writer.add_file(&file1)?;
    let stats = writer.finalize()?;

    assert_eq!(stats.total_files, 1);

    // Verify archive
    let mut reader = ArchiveReader::open(&archive_path, "test123")?;
    let verify_result = reader.verify()?;
    assert!(verify_result.is_ok());

    Ok(())
}

/// Test archive with explicit Memory backend
#[test]
fn test_archive_with_explicit_memory_index() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let archive_path = temp_dir.path().join("test_explicit_memory.era");

    let source_dir = TempDir::new()?;
    let file1 = create_test_file(&source_dir, "doc.txt", b"Document content here");

    let mut writer = ArchiveWriter::builder(archive_path.clone())
        .password("test123")
        .index_backend(ChunkIndexBackend::Memory)
        .build()?;

    writer.add_file(&file1)?;
    let stats = writer.finalize()?;

    assert_eq!(stats.total_files, 1);

    // Extract and verify
    let extract_dir = TempDir::new()?;
    let mut reader = ArchiveReader::open(&archive_path, "test123")?;
    reader.extract_all(&ExtractOptions::new(extract_dir.path()))?;

    let extracted = fs::read(extract_dir.path().join("doc.txt"))?;
    assert_eq!(extracted, b"Document content here");

    Ok(())
}

/// Test deduplication with Memory backend
#[test]
fn test_dedup_with_memory_index() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let archive_path = temp_dir.path().join("test_dedup_memory.era");

    let content = b"This is duplicate content that should be stored only once.";

    let mut writer = ArchiveWriter::builder(archive_path.clone())
        .password("test123")
        .index_backend(ChunkIndexBackend::Memory)
        .build()?;

    // Add same content multiple times with different names
    writer.add_bytes("file1.txt", content)?;
    writer.add_bytes("file2.txt", content)?;
    writer.add_bytes("file3.txt", content)?;
    let stats = writer.finalize()?;

    assert_eq!(stats.total_files, 3);
    // Deduplication should result in only one unique chunk

    // Verify all files can be extracted
    let extract_dir = TempDir::new()?;
    let mut reader = ArchiveReader::open(&archive_path, "test123")?;
    reader.extract_all(&ExtractOptions::new(extract_dir.path()))?;

    for name in ["file1.txt", "file2.txt", "file3.txt"] {
        let extracted = fs::read(extract_dir.path().join(name))?;
        assert_eq!(extracted, content);
    }

    Ok(())
}

/// Test with multiple different files
#[test]
fn test_multiple_unique_files() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let archive_path = temp_dir.path().join("test_multiple.era");

    let source_dir = TempDir::new()?;
    let a = create_test_file(&source_dir, "a.txt", b"File A content");
    let b = create_test_file(&source_dir, "b.txt", b"File B content - different");
    let c = create_test_file(&source_dir, "c.txt", b"File C content - also different!");

    let mut writer = ArchiveWriter::builder(archive_path.clone())
        .password("test123")
        .build()?;

    writer.add_files(&[&a, &b, &c])?;
    let stats = writer.finalize()?;

    assert_eq!(stats.total_files, 3);

    // Verify extraction
    let extract_dir = TempDir::new()?;
    let mut reader = ArchiveReader::open(&archive_path, "test123")?;
    reader.extract_all(&ExtractOptions::new(extract_dir.path()))?;

    assert_eq!(
        fs::read(extract_dir.path().join("a.txt"))?,
        b"File A content"
    );
    assert_eq!(
        fs::read(extract_dir.path().join("b.txt"))?,
        b"File B content - different"
    );
    assert_eq!(
        fs::read(extract_dir.path().join("c.txt"))?,
        b"File C content - also different!"
    );

    Ok(())
}

/// Test large file with CDC chunking and deduplication
#[test]
fn test_large_file_dedup_memory_index() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let archive_path = temp_dir.path().join("test_large_dedup.era");

    // Create a large file with repeating pattern (good for CDC dedup)
    let source_dir = TempDir::new()?;
    let pattern = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut large_content = Vec::new();
    for _ in 0..10000 {
        large_content.extend_from_slice(pattern);
    }
    let file1 = create_test_file(&source_dir, "large.bin", &large_content);

    let mut writer = ArchiveWriter::builder(archive_path.clone())
        .password("test123")
        .enable_cdc(true)
        .build()?;

    writer.add_file(&file1)?;
    let stats = writer.finalize()?;

    assert_eq!(stats.total_files, 1);
    assert!(stats.total_size > 0);

    // Verify
    let extract_dir = TempDir::new()?;
    let mut reader = ArchiveReader::open(&archive_path, "test123")?;
    reader.extract_all(&ExtractOptions::new(extract_dir.path()))?;

    let extracted = fs::read(extract_dir.path().join("large.bin"))?;
    assert_eq!(extracted, large_content);

    Ok(())
}

/// Test add_bytes with Memory index
#[test]
fn test_add_bytes_memory_index() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let archive_path = temp_dir.path().join("test_add_bytes.era");

    let mut writer = ArchiveWriter::builder(archive_path.clone())
        .password("test123")
        .build()?;

    writer.add_bytes("inline1.txt", b"Inline content 1")?;
    writer.add_bytes("inline2.txt", b"Inline content 2")?;
    writer.add_bytes("inline3.txt", b"Inline content 1")?; // Duplicate of inline1

    let stats = writer.finalize()?;
    assert_eq!(stats.total_files, 3);

    // Verify
    let extract_dir = TempDir::new()?;
    let mut reader = ArchiveReader::open(&archive_path, "test123")?;
    reader.extract_all(&ExtractOptions::new(extract_dir.path()))?;

    assert_eq!(
        fs::read(extract_dir.path().join("inline1.txt"))?,
        b"Inline content 1"
    );
    assert_eq!(
        fs::read(extract_dir.path().join("inline2.txt"))?,
        b"Inline content 2"
    );
    assert_eq!(
        fs::read(extract_dir.path().join("inline3.txt"))?,
        b"Inline content 1"
    );

    Ok(())
}

// === LSM Backend Tests (require 'lsm' feature) ===

#[cfg(feature = "lsm")]
mod lsm_tests {
    use super::*;
    use era_common::VolumeId;

    /// Create a test BlockLocation
    fn test_location(slot: u32) -> era_common::BlockLocation {
        era_common::BlockLocation {
            volume_id: VolumeId::new(),
            slot_index: slot,
            physical_offset: slot as u64 * 4096,
            encrypted_size: 4096,
            erasure_info: None,
            shard_offsets: None,
            shard_volumes: None,
        }
    }

    /// Test archive creation with LSM (RocksDB) backend
    #[test]
    fn test_archive_with_lsm_index() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = temp_dir.path().join("test_lsm.era");
        let index_path = temp_dir.path().join("chunk_index");

        let source_dir = TempDir::new()?;
        let file1 = create_test_file(&source_dir, "file1.txt", b"Hello from LSM!");

        let mut writer = ArchiveWriter::builder(archive_path.clone())
            .password("test123")
            .with_lsm_index(&index_path)
            .build()?;

        writer.add_file(&file1)?;
        let stats = writer.finalize()?;

        assert_eq!(stats.total_files, 1);

        // Index directory should be created
        assert!(index_path.exists());

        // Verify archive
        let mut reader = ArchiveReader::open(&archive_path, "test123")?;
        let verify_result = reader.verify()?;
        assert!(verify_result.is_ok());

        Ok(())
    }

    /// Test deduplication with LSM backend
    #[test]
    fn test_dedup_with_lsm_index() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = temp_dir.path().join("test_lsm_dedup.era");
        let index_path = temp_dir.path().join("chunk_index");

        let source_dir = TempDir::new()?;
        let content = b"Duplicate content for LSM test";
        let dup1 = create_test_file(&source_dir, "dup1.txt", content);
        let dup2 = create_test_file(&source_dir, "dup2.txt", content);
        let unique = create_test_file(&source_dir, "unique.txt", b"This is unique");

        let mut writer = ArchiveWriter::builder(archive_path.clone())
            .password("test123")
            .with_lsm_index(&index_path)
            .build()?;

        writer.add_files(&[&dup1, &dup2, &unique])?;
        let stats = writer.finalize()?;

        assert_eq!(stats.total_files, 3);

        // Verify extraction
        let extract_dir = TempDir::new()?;
        let mut reader = ArchiveReader::open(&archive_path, "test123")?;
        reader.extract_all(&ExtractOptions::new(extract_dir.path()))?;

        assert_eq!(fs::read(extract_dir.path().join("dup1.txt"))?, content);
        assert_eq!(fs::read(extract_dir.path().join("dup2.txt"))?, content);
        assert_eq!(
            fs::read(extract_dir.path().join("unique.txt"))?,
            b"This is unique"
        );

        Ok(())
    }

    /// Test LSM persistence across sessions
    #[test]
    fn test_lsm_persistence() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let index_path = temp_dir.path().join("persistent_index");

        // First session: create some entries
        {
            let backend = ChunkIndexBackend::Lsm {
                path: index_path.clone(),
            };
            let index = era_engine::chunk_index::create_chunk_index(backend)?;

            let hash1 = era_crypto::hash(b"chunk1");
            let hash2 = era_crypto::hash(b"chunk2");

            let location = test_location(0);
            index.put(hash1, location.clone())?;
            index.put(hash2, location)?;
            index.flush()?;
        }

        // Second session: verify data persists
        {
            let backend = ChunkIndexBackend::Lsm {
                path: index_path.clone(),
            };
            let index = era_engine::chunk_index::create_chunk_index(backend)?;

            let hash1 = era_crypto::hash(b"chunk1");
            let hash2 = era_crypto::hash(b"chunk2");
            let hash3 = era_crypto::hash(b"chunk3"); // Not stored

            assert!(index.contains(&hash1)?);
            assert!(index.contains(&hash2)?);
            assert!(!index.contains(&hash3)?);

            assert_eq!(index.len(), 2);
        }

        Ok(())
    }

    /// Test batch operations with LSM
    #[test]
    fn test_lsm_batch_operations() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let index_path = temp_dir.path().join("batch_index");

        let backend = ChunkIndexBackend::Lsm { path: index_path };
        let index = era_engine::chunk_index::create_chunk_index(backend)?;

        // Start batch
        index.start_batch();

        // Add many entries
        let location = test_location(0);
        for i in 0..1000 {
            let data = format!("chunk_{}", i);
            let hash = era_crypto::hash(data.as_bytes());
            index.put(hash, location.clone())?;
        }

        // Commit batch
        index.commit_batch()?;

        // Verify count
        assert_eq!(index.len(), 1000);

        Ok(())
    }

    /// Test large archive with LSM backend
    #[test]
    fn test_large_archive_with_lsm() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = temp_dir.path().join("test_large_lsm.era");
        let index_path = temp_dir.path().join("large_index");

        let source_dir = TempDir::new()?;

        // Create many small files
        let mut file_paths = Vec::new();
        for i in 0..100 {
            let content = format!("File content number {}", i);
            let path = create_test_file(
                &source_dir,
                &format!("file_{:03}.txt", i),
                content.as_bytes(),
            );
            file_paths.push(path);
        }
        let file_refs: Vec<&std::path::Path> = file_paths.iter().map(|p| p.as_path()).collect();

        let mut writer = ArchiveWriter::builder(archive_path.clone())
            .password("test123")
            .with_lsm_index(&index_path)
            .build()?;

        writer.add_files(&file_refs)?;
        let stats = writer.finalize()?;

        assert_eq!(stats.total_files, 100);

        // Verify a few files
        let extract_dir = TempDir::new()?;
        let mut reader = ArchiveReader::open(&archive_path, "test123")?;
        reader.extract_all(&ExtractOptions::new(extract_dir.path()))?;

        for i in [0, 50, 99] {
            let expected = format!("File content number {}", i);
            let actual = fs::read_to_string(extract_dir.path().join(format!("file_{:03}.txt", i)))?;
            assert_eq!(actual, expected);
        }

        Ok(())
    }

    /// Test CDC chunking with LSM backend
    #[test]
    fn test_cdc_with_lsm_index() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = temp_dir.path().join("test_cdc_lsm.era");
        let index_path = temp_dir.path().join("cdc_index");

        let source_dir = TempDir::new()?;

        // Create a file large enough for CDC to chunk
        let mut content = Vec::new();
        for i in 0..5000 {
            content.extend_from_slice(format!("Line {} of content\n", i).as_bytes());
        }
        let file1 = create_test_file(&source_dir, "large.txt", &content);

        let mut writer = ArchiveWriter::builder(archive_path.clone())
            .password("test123")
            .enable_cdc(true)
            .with_lsm_index(&index_path)
            .build()?;

        writer.add_file(&file1)?;
        let stats = writer.finalize()?;

        assert_eq!(stats.total_files, 1);

        // Verify
        let extract_dir = TempDir::new()?;
        let mut reader = ArchiveReader::open(&archive_path, "test123")?;
        reader.extract_all(&ExtractOptions::new(extract_dir.path()))?;

        let extracted = fs::read(extract_dir.path().join("large.txt"))?;
        assert_eq!(extracted, content);

        Ok(())
    }
}
