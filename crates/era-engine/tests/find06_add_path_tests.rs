use era_common::ArchiveConfig;
use era_engine::{ArchiveReader, ArchiveWriterBuilder, ExtractOptions};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[tokio::test]
async fn t7_2_add_path_accepts_absolute_single_file() {
    let temp = TempDir::new().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    let abs_file = src_dir.join("sample.bin");
    let payload = b"absolute single-file add_path payload";
    fs::write(&abs_file, payload).unwrap();
    assert!(abs_file.is_absolute());

    let archive = temp.path().join("find06_abs.era");
    let mut writer = ArchiveWriterBuilder::new(&archive)
        .password("pwd")
        .config(ArchiveConfig::default())
        .enable_erasure(false)
        .build()
        .await
        .unwrap();

    writer.add_path(&abs_file, false).await.unwrap();
    writer.finalize().await.unwrap();

    let mut reader = ArchiveReader::open(&archive, "pwd").await.unwrap();
    let files = reader.list_files().await.unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path, Path::new("sample.bin"));

    let verify = reader.verify().await.unwrap();
    assert!(verify.is_ok(), "verify failed: {:?}", verify.errors);
    assert!(verify.is_healthy());

    let out_dir = temp.path().join("out");
    let stats = reader
        .extract_all(&ExtractOptions::new(&out_dir))
        .await
        .unwrap();
    assert_eq!(stats.extracted, 1);
    assert_eq!(fs::read(out_dir.join("sample.bin")).unwrap(), payload);
}

#[tokio::test]
async fn add_path_normalizes_parent_dir_in_single_file_path() {
    let temp = TempDir::new().unwrap();
    let sub_dir = temp.path().join("nested");
    fs::create_dir_all(&sub_dir).unwrap();
    let target_file = temp.path().join("leaf.txt");
    let payload = b"normalized parent dir single file";
    fs::write(&target_file, payload).unwrap();

    let dotdot_file = sub_dir.join("..").join("leaf.txt");
    assert!(dotdot_file
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir)));

    let archive = temp.path().join("find06_dotdot.era");
    let mut writer = ArchiveWriterBuilder::new(&archive)
        .password("pwd")
        .enable_erasure(false)
        .build()
        .await
        .unwrap();

    writer.add_path(&dotdot_file, false).await.unwrap();
    writer.finalize().await.unwrap();

    let mut reader = ArchiveReader::open(&archive, "pwd").await.unwrap();
    let files = reader.list_files().await.unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path, Path::new("leaf.txt"));

    let out_dir = temp.path().join("out");
    reader
        .extract_all(&ExtractOptions::new(&out_dir))
        .await
        .unwrap();
    assert_eq!(fs::read(out_dir.join("leaf.txt")).unwrap(), payload);
}
