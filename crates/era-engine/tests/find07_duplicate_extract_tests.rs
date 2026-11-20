use era_engine::{ArchiveReader, ArchiveWriterBuilder, ExtractOptions};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[tokio::test]
async fn duplicate_catalog_entries_skip_second_without_overwrite() {
    let temp = TempDir::new().unwrap();
    let src_a = temp.path().join("src_a");
    let src_b = temp.path().join("src_b");
    fs::create_dir_all(&src_a).unwrap();
    fs::create_dir_all(&src_b).unwrap();

    let small_first = b"first small payload";
    let small_second = b"second small payload (should be skipped)";
    let large_first = vec![0x11u8; 192 * 1024];
    let large_second = vec![0x22u8; 192 * 1024];

    let small_a = src_a.join("dup_small.txt");
    let small_b = src_b.join("dup_small.txt");
    let large_a = src_a.join("dup_large.bin");
    let large_b = src_b.join("dup_large.bin");

    fs::write(&small_a, small_first).unwrap();
    fs::write(&small_b, small_second).unwrap();
    fs::write(&large_a, &large_first).unwrap();
    fs::write(&large_b, &large_second).unwrap();

    let archive = temp.path().join("dups.era");
    let mut writer = ArchiveWriterBuilder::new(&archive)
        .password("pwd")
        .enable_erasure(false)
        .build()
        .await
        .unwrap();

    writer
        .add_file_with_path(&small_a, Path::new("dup_small.txt"))
        .await
        .unwrap();
    writer
        .add_file_with_path(&small_b, Path::new("dup_small.txt"))
        .await
        .unwrap();
    writer
        .add_file_with_path(&large_a, Path::new("dup_large.bin"))
        .await
        .unwrap();
    writer
        .add_file_with_path(&large_b, Path::new("dup_large.bin"))
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    let out_dir = temp.path().join("out");
    let mut reader = ArchiveReader::open(&archive, "pwd").await.unwrap();
    let stats = reader
        .extract_all(&ExtractOptions::new(&out_dir).overwrite(false))
        .await
        .unwrap();

    assert_eq!(
        stats.extracted, 2,
        "only first occurrence of each file should extract"
    );
    assert_eq!(stats.skipped, 2, "duplicate occurrences should be skipped");
    assert_eq!(
        fs::read(out_dir.join("dup_small.txt")).unwrap(),
        small_first
    );
    assert_eq!(
        fs::read(out_dir.join("dup_large.bin")).unwrap(),
        large_first
    );
}
