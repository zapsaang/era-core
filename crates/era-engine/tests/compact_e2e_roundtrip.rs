use era_common::ErasureCodeConfig;
use era_engine::{compact_archive, ArchiveWriterBuilder, CompactArchiveReader};
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::TempDir;

fn create_test_file(dir: &Path, name: &str, content: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut file = fs::File::create(&path).unwrap();
    file.write_all(content).unwrap();
    path
}

fn erasure_config() -> ErasureCodeConfig {
    ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    }
}

async fn create_erasure_archive(
    input_dir: &Path,
    archive_path: &Path,
    password: &str,
    files: &[(&str, Vec<u8>)],
) {
    for (name, content) in files {
        create_test_file(input_dir, name, content);
    }

    let mut writer = ArchiveWriterBuilder::new(archive_path)
        .password(password)
        .enable_erasure(true)
        .erasure_config(erasure_config())
        .volume_count(6)
        .build()
        .await
        .unwrap();

    for (name, _) in files {
        writer.add_file(&input_dir.join(name)).await.unwrap();
    }
    writer.finalize().await.unwrap();
}

#[tokio::test]
async fn compact_roundtrip_single_file() {
    let tmp = TempDir::new().unwrap();
    let input_dir = tmp.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    let password = "test_compact_password";
    let archive_path = tmp.path().join("source.era");
    let bundle_path = tmp.path().join("compacted.erac");
    let extract_dir = tmp.path().join("extracted");

    let content = vec![42u8; 8192];
    let files = vec![("hello.txt", content.clone())];

    create_erasure_archive(&input_dir, &archive_path, password, &files).await;

    let stats = compact_archive(&archive_path, &bundle_path, password)
        .await
        .unwrap();
    assert!(stats.total_blocks > 0);
    assert!(stats.total_stripes > 0);
    assert_eq!(stats.total_volumes, 6);
    assert!(stats.catalog_bytes > 0);

    let mut reader = CompactArchiveReader::open(&bundle_path, password).unwrap();
    let extract_stats = reader.extract_all(&extract_dir).unwrap();
    assert_eq!(extract_stats.files_extracted, 1);

    let extracted = fs::read(extract_dir.join("hello.txt")).unwrap();
    assert_eq!(extracted, content);
}

#[tokio::test]
async fn compact_roundtrip_multiple_files() {
    let tmp = TempDir::new().unwrap();
    let input_dir = tmp.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    let password = "multi_file_pass";
    let archive_path = tmp.path().join("multi.era");
    let bundle_path = tmp.path().join("multi.erac");
    let extract_dir = tmp.path().join("extracted");

    let files = vec![
        ("file_a.bin", vec![0xAAu8; 4096]),
        ("file_b.bin", vec![0xBBu8; 16384]),
        ("file_c.bin", vec![0xCCu8; 1024]),
    ];

    create_erasure_archive(&input_dir, &archive_path, password, &files).await;

    let stats = compact_archive(&archive_path, &bundle_path, password)
        .await
        .unwrap();
    assert!(stats.total_blocks > 0);

    let mut reader = CompactArchiveReader::open(&bundle_path, password).unwrap();
    let extract_stats = reader.extract_all(&extract_dir).unwrap();
    assert_eq!(extract_stats.files_extracted, 3);

    for (name, content) in &files {
        let extracted = fs::read(extract_dir.join(name)).unwrap();
        assert_eq!(extracted, *content, "content mismatch for {name}");
    }
}

#[tokio::test]
async fn compact_wrong_password_fails() {
    let tmp = TempDir::new().unwrap();
    let input_dir = tmp.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    let password = "correct_password";
    let archive_path = tmp.path().join("auth.era");
    let bundle_path = tmp.path().join("auth.erac");

    let files = vec![("secret.txt", vec![0xFFu8; 2048])];
    create_erasure_archive(&input_dir, &archive_path, password, &files).await;

    compact_archive(&archive_path, &bundle_path, password)
        .await
        .unwrap();

    let result = CompactArchiveReader::open(&bundle_path, "wrong_password");
    assert!(result.is_err());
}

#[tokio::test]
async fn compact_catalog_preserved() {
    let tmp = TempDir::new().unwrap();
    let input_dir = tmp.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    let password = "catalog_test";
    let archive_path = tmp.path().join("catalog.era");
    let bundle_path = tmp.path().join("catalog.erac");

    let files = vec![("alpha.dat", vec![1u8; 512]), ("beta.dat", vec![2u8; 1024])];
    create_erasure_archive(&input_dir, &archive_path, password, &files).await;

    compact_archive(&archive_path, &bundle_path, password)
        .await
        .unwrap();

    let reader = CompactArchiveReader::open(&bundle_path, password).unwrap();
    let catalog = reader.catalog();
    assert!(catalog.file_count >= 2);
}
