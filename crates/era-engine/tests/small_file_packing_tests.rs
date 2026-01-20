//! Test small file packing functionality

use era_engine::{ArchiveReader, ArchiveWriterBuilder, ExtractOptions};
use std::fs::{self, File};
use tempfile::TempDir;

#[tokio::test]
async fn test_small_file_packing_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    fs::create_dir_all(&input_dir).unwrap();
    fs::create_dir_all(&output_dir).unwrap();

    // Create 10 small files (each < 16KB to trigger packing)
    let mut expected_files = Vec::new();
    for i in 0..10 {
        let filename = format!("file_{:02}.txt", i);
        let filepath = input_dir.join(&filename);
        let content = format!("This is file number {}\n", i).repeat(100); // ~2KB each

        fs::write(&filepath, &content).unwrap();
        expected_files.push((filename, content));
    }

    // Create archive
    let archive_path = temp_dir.path().join("packed.era");
    let password = "test_password";

    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .password(password)
        .build()
        .unwrap();

    for (filename, _) in &expected_files {
        writer.add_file(&input_dir.join(filename)).await.unwrap();
    }

    let stats = writer.finalize().unwrap();
    println!(
        "Archive stats: {} files, {} bytes",
        stats.total_files, stats.total_size
    );

    // Verify archive was created
    assert!(archive_path.exists());

    // Extract and verify
    let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
    let files = reader.list_files().unwrap();
    assert_eq!(files.len(), 10, "Should have 10 files in catalog");

    let extract_opts = ExtractOptions::new(&output_dir);
    let extract_stats = reader.extract_all(&extract_opts).unwrap();
    assert_eq!(extract_stats.extracted, 10, "Should extract 10 files");

    // Verify content
    for (filename, expected_content) in &expected_files {
        let extracted_path = output_dir.join(filename);
        assert!(extracted_path.exists(), "File {} should exist", filename);

        let actual_content = fs::read_to_string(&extracted_path).unwrap();
        assert_eq!(
            &actual_content, expected_content,
            "Content mismatch for {}",
            filename
        );
    }
}

#[tokio::test]
async fn test_mixed_small_and_large_files() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    fs::create_dir_all(&input_dir).unwrap();

    // Create 5 small files (< 16KB each)
    for i in 0..5 {
        let path = input_dir.join(format!("small_{}.txt", i));
        let content = format!("Small file {}\n", i).repeat(100); // ~1.6KB
        fs::write(&path, content).unwrap();
    }

    // Create 2 large files (> 16KB to avoid packing)
    for i in 0..2 {
        let path = input_dir.join(format!("large_{}.txt", i));
        let content = format!("Large file {}\n", i).repeat(2000); // ~32KB
        fs::write(&path, content).unwrap();
    }

    let archive_path = temp_dir.path().join("mixed.era");
    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .password("password")
        .build()
        .unwrap();

    // Add all files
    for i in 0..5 {
        writer
            .add_file(&input_dir.join(format!("small_{}.txt", i)))
            .await
            .unwrap();
    }
    for i in 0..2 {
        writer
            .add_file(&input_dir.join(format!("large_{}.txt", i)))
            .await
            .unwrap();
    }

    writer.finalize().unwrap();

    // Extract and verify
    let mut reader = ArchiveReader::open(&archive_path, "password").unwrap();
    let files = reader.list_files().unwrap();
    assert_eq!(files.len(), 7);

    let extract_stats = reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .unwrap();
    assert_eq!(extract_stats.extracted, 7);

    // Verify all files exist and have correct size
    for i in 0..5 {
        let path = output_dir.join(format!("small_{}.txt", i));
        assert!(path.exists());
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains(&format!("Small file {}", i)));
    }
    for i in 0..2 {
        let path = output_dir.join(format!("large_{}.txt", i));
        assert!(path.exists());
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains(&format!("Large file {}", i)));
    }
}

#[tokio::test]
async fn test_many_small_files() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    fs::create_dir_all(&input_dir).unwrap();

    // Create 100 small files to test batch packing
    let file_count = 100;
    for i in 0..file_count {
        let path = input_dir.join(format!("file_{:03}.dat", i));
        let content = vec![i as u8; 1024]; // 1KB each
        fs::write(&path, content).unwrap();
    }

    let archive_path = temp_dir.path().join("many.era");
    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .password("test")
        .build()
        .unwrap();

    for i in 0..file_count {
        writer
            .add_file(&input_dir.join(format!("file_{:03}.dat", i)))
            .await
            .unwrap();
    }

    let stats = writer.finalize().unwrap();
    println!(
        "Packed {} files into {} bytes",
        stats.total_files, stats.total_size
    );

    // Extract
    let mut reader = ArchiveReader::open(&archive_path, "test").unwrap();
    let extract_stats = reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .unwrap();
    assert_eq!(extract_stats.extracted as usize, file_count);

    // Spot check a few files
    for i in [0, 50, 99] {
        let path = output_dir.join(format!("file_{:03}.dat", i));
        let content = fs::read(&path).unwrap();
        assert_eq!(content.len(), 1024);
        assert_eq!(content[0], i as u8);
    }
}

#[tokio::test]
async fn test_empty_files_packed() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    fs::create_dir_all(&input_dir).unwrap();

    // Create some empty files
    for i in 0..5 {
        let path = input_dir.join(format!("empty_{}.txt", i));
        File::create(&path).unwrap();
    }

    let archive_path = temp_dir.path().join("empty.era");
    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .password("password")
        .build()
        .unwrap();

    for i in 0..5 {
        writer
            .add_file(&input_dir.join(format!("empty_{}.txt", i)))
            .await
            .unwrap();
    }

    writer.finalize().unwrap();

    // Extract and verify
    let mut reader = ArchiveReader::open(&archive_path, "password").unwrap();
    let extract_stats = reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .unwrap();
    assert_eq!(extract_stats.extracted, 5);

    for i in 0..5 {
        let path = output_dir.join(format!("empty_{}.txt", i));
        assert!(path.exists());
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
    }
}
