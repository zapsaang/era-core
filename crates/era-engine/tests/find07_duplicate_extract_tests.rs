use era_engine::{ArchiveReader, ArchiveWriterBuilder, ExtractOptions};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
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
    #[cfg(unix)]
    {
        fs::set_permissions(&small_a, fs::Permissions::from_mode(0o640)).unwrap();
        fs::set_permissions(&small_b, fs::Permissions::from_mode(0o604)).unwrap();
    }

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
        stats.bytes_written,
        u64::try_from(small_first.len() + large_first.len()).unwrap()
    );
    assert_eq!(
        fs::read(out_dir.join("dup_small.txt")).unwrap(),
        small_first
    );
    assert_eq!(
        fs::read(out_dir.join("dup_large.bin")).unwrap(),
        large_first
    );
    #[cfg(unix)]
    {
        let mode = fs::metadata(out_dir.join("dup_small.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640, "the first occurrence's metadata must win");
    }
}

#[tokio::test]
async fn duplicate_catalog_entries_last_wins_with_overwrite() {
    let temp = TempDir::new().unwrap();
    let src_first = temp.path().join("src_first");
    let src_last = temp.path().join("src_last");
    fs::create_dir_all(&src_first).unwrap();
    fs::create_dir_all(&src_last).unwrap();

    let small_first = b"first packed payload";
    let large_last: Vec<u8> = (0..(192 * 1024)).map(|i| (i % 251) as u8).collect();
    let first_path = src_first.join("dup.bin");
    let last_path = src_last.join("dup.bin");
    fs::write(&first_path, small_first).unwrap();
    fs::write(&last_path, &large_last).unwrap();
    #[cfg(unix)]
    {
        fs::set_permissions(&first_path, fs::Permissions::from_mode(0o640)).unwrap();
        fs::set_permissions(&last_path, fs::Permissions::from_mode(0o604)).unwrap();
    }

    let archive = temp.path().join("dups_overwrite.era");
    {
        let mut writer = ArchiveWriterBuilder::new(&archive)
            .password("pwd")
            .enable_erasure(false)
            .build()
            .await
            .unwrap();
        writer
            .add_file_with_path(&first_path, Path::new("dup.bin"))
            .await
            .unwrap();
        writer.finalize().await.unwrap();
    }
    {
        let mut writer = ArchiveWriterBuilder::new(&archive)
            .password("pwd")
            .enable_erasure(false)
            .append_existing(true)
            .build()
            .await
            .unwrap();
        writer
            .add_file_with_path(&last_path, Path::new("dup.bin"))
            .await
            .unwrap();
        writer.finalize().await.unwrap();
    }

    let out_dir = temp.path().join("out_overwrite");
    let mut reader = ArchiveReader::open(&archive, "pwd").await.unwrap();
    let stats = reader
        .extract_all(&ExtractOptions::new(&out_dir).overwrite(true))
        .await
        .unwrap();

    assert_eq!(stats.extracted, 1, "only the last occurrence extracts");
    assert_eq!(stats.skipped, 1, "the superseded occurrence is skipped");
    assert_eq!(
        stats.bytes_written,
        u64::try_from(large_last.len()).unwrap()
    );
    let extracted = fs::read(out_dir.join("dup.bin")).unwrap();
    assert!(
        extracted == large_last,
        "overwrite must preserve the last occurrence's exact bytes"
    );
    #[cfg(unix)]
    {
        let mode = fs::metadata(out_dir.join("dup.bin"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o604, "the last occurrence's metadata must win");
    }
}
