//! Tests for batch file operations

use era_engine::{ArchiveReader, ArchiveWriter, ExtractOptions};
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::TempDir;

/// Create a test file with the given content
fn create_test_file(dir: &Path, name: &str, content: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut file = fs::File::create(&path).unwrap();
    file.write_all(content).unwrap();
    path
}

#[test]
fn test_batch_add_files() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    // Create multiple test files
    let files: Vec<_> = (0..10)
        .map(|i| {
            let content = format!("File content {}", i);
            create_test_file(&input_dir, &format!("file_{}.txt", i), content.as_bytes())
        })
        .collect();

    // Create archive using batch API
    let archive_path = temp_dir.path().join("test.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("test_password")
        .build()
        .unwrap();

    // Convert to &[&Path] for batch API
    let file_refs: Vec<&Path> = files.iter().map(|p| p.as_path()).collect();
    writer.add_files(&file_refs).unwrap();
    let stats = writer.finalize().unwrap();

    assert_eq!(stats.total_files, 10);

    // Extract and verify
    let output_dir = temp_dir.path().join("output");
    let mut reader = ArchiveReader::open(&archive_path, "test_password").unwrap();
    reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .unwrap();

    // Verify all files extracted correctly
    for i in 0..10 {
        let extracted_path = output_dir.join(format!("file_{}.txt", i));
        assert!(extracted_path.exists());
        let content = fs::read_to_string(&extracted_path).unwrap();
        assert_eq!(content, format!("File content {}", i));
    }
}

#[test]
fn test_batch_vs_individual_equivalence() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    // Create test files
    let files: Vec<_> = (0..5)
        .map(|i| {
            let content = format!("Content {}", i);
            create_test_file(&input_dir, &format!("file_{}.txt", i), content.as_bytes())
        })
        .collect();

    // Create archive with batch API
    let archive_batch = temp_dir.path().join("batch.era");
    let mut writer_batch = ArchiveWriter::builder(&archive_batch)
        .password("test_password")
        .build()
        .unwrap();

    let file_refs: Vec<&Path> = files.iter().map(|p| p.as_path()).collect();
    writer_batch.add_files(&file_refs).unwrap();
    let stats_batch = writer_batch.finalize().unwrap();

    // Create archive with individual adds
    let archive_individual = temp_dir.path().join("individual.era");
    let mut writer_individual = ArchiveWriter::builder(&archive_individual)
        .password("test_password")
        .build()
        .unwrap();

    for file in &files {
        writer_individual.add_file(file).unwrap();
    }
    let stats_individual = writer_individual.finalize().unwrap();

    // Both methods should produce the same results
    assert_eq!(stats_batch.total_files, stats_individual.total_files);
    assert_eq!(stats_batch.total_size, stats_individual.total_size);
    assert_eq!(stats_batch.blocks_written, stats_individual.blocks_written);

    // Extract both and verify content is identical
    let output_batch = temp_dir.path().join("output_batch");
    let output_individual = temp_dir.path().join("output_individual");

    let mut reader_batch = ArchiveReader::open(&archive_batch, "test_password").unwrap();
    reader_batch
        .extract_all(&ExtractOptions::new(&output_batch))
        .unwrap();

    let mut reader_individual = ArchiveReader::open(&archive_individual, "test_password").unwrap();
    reader_individual
        .extract_all(&ExtractOptions::new(&output_individual))
        .unwrap();

    // Verify files are identical
    for i in 0..5 {
        let file_name = format!("file_{}.txt", i);
        let content_batch = fs::read_to_string(output_batch.join(&file_name)).unwrap();
        let content_individual = fs::read_to_string(output_individual.join(&file_name)).unwrap();
        assert_eq!(content_batch, content_individual);
    }
}

#[test]
fn test_batch_empty() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("test.era");

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("test_password")
        .build()
        .unwrap();

    // Empty batch should work without error
    writer.add_files(&[]).unwrap();
    let stats = writer.finalize().unwrap();

    assert_eq!(stats.total_files, 0);
}

#[test]
fn test_batch_large_number_of_files() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    // Create 100 small files
    let files: Vec<_> = (0..100)
        .map(|i| {
            let content = format!("File {}", i);
            create_test_file(
                &input_dir,
                &format!("file_{:03}.txt", i),
                content.as_bytes(),
            )
        })
        .collect();

    let archive_path = temp_dir.path().join("test.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("test_password")
        .build()
        .unwrap();

    let file_refs: Vec<&Path> = files.iter().map(|p| p.as_path()).collect();
    writer.add_files(&file_refs).unwrap();
    let stats = writer.finalize().unwrap();

    assert_eq!(stats.total_files, 100);

    // Quick verification
    let mut reader = ArchiveReader::open(&archive_path, "test_password").unwrap();
    let verify_stats = reader.verify().unwrap();
    assert!(verify_stats.is_ok());
    assert_eq!(verify_stats.files_verified, 100);
}

#[test]
fn test_mixed_batch_and_individual() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    // Create files
    let file1 = create_test_file(&input_dir, "file1.txt", b"Content 1");
    let file2 = create_test_file(&input_dir, "file2.txt", b"Content 2");
    let file3 = create_test_file(&input_dir, "file3.txt", b"Content 3");
    let file4 = create_test_file(&input_dir, "file4.txt", b"Content 4");

    let archive_path = temp_dir.path().join("test.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("test_password")
        .build()
        .unwrap();

    // Mix batch and individual operations
    writer.add_file(&file1).unwrap();
    writer
        .add_files(&[file2.as_path(), file3.as_path()])
        .unwrap();
    writer.add_file(&file4).unwrap();

    let stats = writer.finalize().unwrap();
    assert_eq!(stats.total_files, 4);

    // Verify extraction
    let output_dir = temp_dir.path().join("output");
    let mut reader = ArchiveReader::open(&archive_path, "test_password").unwrap();
    let extract_stats = reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .unwrap();

    assert_eq!(extract_stats.extracted, 4);
}
