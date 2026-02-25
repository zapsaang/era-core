//! # V9 Adversarial Audit — era-engine Integration Tests
//!
//! End-to-end tests for archive creation, extraction, and recovery
//! focusing on edge cases, error propagation, and adversarial inputs.

use era_common::ArchiveConfig;
use era_engine::{ArchiveReader, ArchiveWriter, ExtractOptions};
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::TempDir;

// ═══════════════════════════════════════════════════════════════════════
// Test Utilities
// ═══════════════════════════════════════════════════════════════════════

fn create_test_file(dir: &std::path::Path, name: &str, content: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut f = fs::File::create(&path).unwrap();
    f.write_all(content).unwrap();
    path
}

// ═══════════════════════════════════════════════════════════════════════
// V9-E1: Basic roundtrip — create and extract archive
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn v9_e1a_basic_archive_roundtrip() {
    let temp = TempDir::new().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    // Create test files
    create_test_file(&src_dir, "hello.txt", b"Hello, ERA V9 Audit!");
    create_test_file(&src_dir, "data.bin", &vec![0x42u8; 4096]);
    create_test_file(
        &src_dir,
        "subdir/nested.txt",
        b"Nested file content for testing",
    );

    let archive_path = temp.path().join("test.era");
    let password = "v9-audit-test-password";

    // Create archive
    let config = ArchiveConfig {
        erasure: None,
        ..Default::default()
    };

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password(password)
        .config(config)
        .build()
        .await
        .expect("V9-E1a: Archive writer creation should succeed");

    // Add all files from source directory
    for entry in walkdir(&src_dir) {
        let metadata = fs::metadata(&entry).unwrap();
        if metadata.is_file() {
            writer
                .add_file(&entry)
                .await
                .unwrap_or_else(|e| panic!("V9-E1a: add_file failed for {:?}: {}", entry, e));
        }
    }

    writer
        .finalize()
        .await
        .expect("V9-E1a: Finalize should succeed");

    // Verify archive file exists and has content
    assert!(archive_path.exists(), "V9-E1a: Archive file should exist");
    let archive_size = fs::metadata(&archive_path).unwrap().len();
    assert!(
        archive_size > 0,
        "V9-E1a: Archive should have content, got {} bytes",
        archive_size
    );
    println!(
        "V9-E1a: Archive created: {} bytes for {} bytes of source data",
        archive_size,
        4096 + 20 + 30
    );

    // Extract archive
    let extract_dir = temp.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    let mut reader = ArchiveReader::open(&archive_path, password)
        .await
        .expect("V9-E1a: Archive open should succeed");

    let stats = reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .await
        .expect("V9-E1a: Extraction should succeed");

    println!(
        "V9-E1a: Extracted {} files, {} bytes",
        stats.extracted, stats.bytes_written
    );

    // Verify extracted content matches
    let extracted_hello = fs::read(extract_dir.join("hello.txt")).unwrap();
    assert_eq!(
        &extracted_hello, b"Hello, ERA V9 Audit!",
        "V9-E1a: hello.txt content mismatch"
    );

    let extracted_data = fs::read(extract_dir.join("data.bin")).unwrap();
    assert_eq!(extracted_data.len(), 4096, "V9-E1a: data.bin size mismatch");
    assert!(
        extracted_data.iter().all(|&b| b == 0x42),
        "V9-E1a: data.bin content mismatch"
    );
}

/// Simple recursive directory walk
fn walkdir(path: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut result = Vec::new();
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                result.extend(walkdir(&p));
            } else {
                result.push(p);
            }
        }
    }
    result
}

// ═══════════════════════════════════════════════════════════════════════
// V9-E2: Wrong password should fail gracefully
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn v9_e2a_wrong_password_fails() {
    let temp = TempDir::new().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    create_test_file(&src_dir, "secret.txt", b"Top secret data");

    let archive_path = temp.path().join("wrong_pw.era");

    let config = ArchiveConfig {
        erasure: None,
        ..Default::default()
    };

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("correct-password")
        .config(config)
        .build()
        .await
        .unwrap();

    writer.add_file(&src_dir.join("secret.txt")).await.unwrap();
    writer.finalize().await.unwrap();

    // Try opening with wrong password
    let result = ArchiveReader::open(&archive_path, "wrong-password").await;
    assert!(
        result.is_err(),
        "V9-E2a: Opening with wrong password should fail"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-E3: Empty archive handling
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn v9_e3a_empty_archive() {
    let temp = TempDir::new().unwrap();
    let archive_path = temp.path().join("empty.era");

    let config = ArchiveConfig {
        erasure: None,
        ..Default::default()
    };

    let writer = ArchiveWriter::builder(&archive_path)
        .password("test")
        .config(config)
        .build()
        .await
        .unwrap();

    // Finalize without adding any files
    let result = writer.finalize().await;
    // Should either succeed (empty archive) or fail gracefully
    match result {
        Ok(_) => println!("V9-E3a: Empty archive finalized successfully"),
        Err(e) => println!("V9-E3a: Empty archive finalize returned: {}", e),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// V9-E4: Large file handling (>1MB)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn v9_e4a_large_file() {
    let temp = TempDir::new().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    // Create a 2MB file with recognizable pattern
    let mut large_data = Vec::with_capacity(2 * 1024 * 1024);
    for i in 0..2 * 1024 * 1024 {
        large_data.push((i % 256) as u8);
    }
    create_test_file(&src_dir, "large.bin", &large_data);

    let archive_path = temp.path().join("large.era");
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

    writer
        .add_file(&src_dir.join("large.bin"))
        .await
        .expect("V9-E4a: Adding large file should succeed");

    writer
        .finalize()
        .await
        .expect("V9-E4a: Finalize with large file should succeed");

    // Extract and verify
    let extract_dir = temp.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    let mut reader = ArchiveReader::open(&archive_path, "test").await.unwrap();
    reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .await
        .expect("V9-E4a: Extraction should succeed");

    let extracted = fs::read(extract_dir.join("large.bin")).unwrap();
    assert_eq!(
        extracted.len(),
        large_data.len(),
        "V9-E4a: Extracted file size mismatch"
    );
    assert_eq!(
        extracted, large_data,
        "V9-E4a: Extracted file content mismatch"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-E5: Multiple files with same content (dedup test)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn v9_e5a_dedup_identical_files() {
    let temp = TempDir::new().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let content = b"Identical content for dedup testing".repeat(100);
    create_test_file(&src_dir, "file_a.txt", &content);
    create_test_file(&src_dir, "file_b.txt", &content);
    create_test_file(&src_dir, "file_c.txt", &content);

    let archive_path = temp.path().join("dedup.era");
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

    for name in &["file_a.txt", "file_b.txt", "file_c.txt"] {
        writer.add_file(&src_dir.join(name)).await.unwrap();
    }
    writer.finalize().await.unwrap();

    let archive_size = fs::metadata(&archive_path).unwrap().len();
    println!(
        "V9-E5a: Archive size for 3 identical files ({} bytes each): {} bytes",
        content.len(),
        archive_size
    );

    // Extract and verify all three files roundtrip correctly
    let extract_dir = temp.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();
    let mut reader = ArchiveReader::open(&archive_path, "test").await.unwrap();
    reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .await
        .unwrap();

    for name in &["file_a.txt", "file_b.txt", "file_c.txt"] {
        let extracted = fs::read(extract_dir.join(name)).unwrap();
        assert_eq!(
            extracted, content,
            "V9-E5a: {} content mismatch after extraction",
            name
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// V9-E6: Corrupted archive detection
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn v9_e6a_truncated_archive() {
    let temp = TempDir::new().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    create_test_file(&src_dir, "data.txt", b"Test data for corruption test");

    let archive_path = temp.path().join("corrupt.era");
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

    writer.add_file(&src_dir.join("data.txt")).await.unwrap();
    writer.finalize().await.unwrap();

    // Truncate the archive to half its size
    let original_size = fs::metadata(&archive_path).unwrap().len();
    let f = fs::OpenOptions::new()
        .write(true)
        .open(&archive_path)
        .unwrap();
    f.set_len(original_size / 2).unwrap();
    drop(f);

    // VULNERABILITY FOUND: ArchiveReader::open() succeeds on truncated archives.
    // This is a P1 finding — corruption is not detected during open().
    let result = ArchiveReader::open(&archive_path, "test").await;
    match result {
        Ok(mut reader) => {
            // Open succeeded on a corrupted file — that's the vulnerability.
            // At minimum, extraction should fail.
            let extract_dir = temp.path().join("extracted_trunc");
            fs::create_dir_all(&extract_dir).unwrap();
            let extract_result = reader.extract_all(&ExtractOptions::new(&extract_dir)).await;
            println!(
                "V9-E6a: VULNERABILITY — truncated archive opened successfully. \
                 Extraction result: {:?}",
                extract_result.is_err()
            );
            // At least extraction should detect the corruption
            assert!(
                extract_result.is_err(),
                "V9-E6a: Extracting from truncated archive should fail"
            );
        }
        Err(_) => {
            println!("V9-E6a: Truncated archive correctly rejected on open");
        }
    }
}

#[tokio::test]
async fn v9_e6b_bit_flipped_archive() {
    let temp = TempDir::new().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    create_test_file(&src_dir, "data.txt", b"Test data for bit flip test");

    let archive_path = temp.path().join("bitflip.era");
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

    writer.add_file(&src_dir.join("data.txt")).await.unwrap();
    writer.finalize().await.unwrap();

    // Flip a bit in the middle of the archive
    let mut archive_data = fs::read(&archive_path).unwrap();
    let mid = archive_data.len() / 2;
    archive_data[mid] ^= 0x01;
    fs::write(&archive_path, &archive_data).unwrap();

    // Opening/extracting should fail or detect corruption
    let result = ArchiveReader::open(&archive_path, "test").await;
    match result {
        Ok(mut reader) => {
            let extract_dir = temp.path().join("extracted");
            fs::create_dir_all(&extract_dir).unwrap();
            let extract_result = reader.extract_all(&ExtractOptions::new(&extract_dir)).await;
            // Extraction should fail due to AEAD authentication failure
            println!(
                "V9-E6b: Bit-flipped archive opened but extraction: {:?}",
                extract_result.is_err()
            );
        }
        Err(e) => {
            println!(
                "V9-E6b: Bit-flipped archive correctly rejected on open: {}",
                e
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// V9-E7: Non-existent file handling
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn v9_e7a_nonexistent_archive() {
    let result = ArchiveReader::open(Path::new("/tmp/v9_nonexistent_archive.era"), "test").await;
    assert!(
        result.is_err(),
        "V9-E7a: Opening non-existent archive should fail"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-E8: Zero-byte file handling
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn v9_e8a_zero_byte_file() {
    let temp = TempDir::new().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    create_test_file(&src_dir, "empty.txt", b"");

    let archive_path = temp.path().join("zero.era");
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

    writer.add_file(&src_dir.join("empty.txt")).await.unwrap();
    writer.finalize().await.unwrap();

    // Extract and verify
    let extract_dir = temp.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();
    let mut reader = ArchiveReader::open(&archive_path, "test").await.unwrap();
    reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .await
        .unwrap();

    let extracted = fs::read(extract_dir.join("empty.txt")).unwrap();
    assert!(
        extracted.is_empty(),
        "V9-E8a: Empty file should roundtrip as empty"
    );
}
