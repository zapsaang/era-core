use era_engine::{ArchiveReader, ArchiveWriterBuilder, ExtractOptions};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

#[tokio::test]
async fn overwrite_readonly_small_and_large_files_succeeds() {
    let temp = TempDir::new().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let small_path = src_dir.join("ro_small.txt");
    let large_path = src_dir.join("ro_large.bin");
    let small_data = b"readonly small file payload";
    let large_data: Vec<u8> = (0..(192 * 1024)).map(|i| (i % 251) as u8).collect();

    fs::write(&small_path, small_data).unwrap();
    fs::write(&large_path, &large_data).unwrap();
    #[cfg(unix)]
    {
        fs::set_permissions(&small_path, fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(&large_path, fs::Permissions::from_mode(0o444)).unwrap();
    }

    let archive = temp.path().join("ro.era");
    let mut writer = ArchiveWriterBuilder::new(&archive)
        .password("pwd")
        .enable_erasure(false)
        .build()
        .await
        .unwrap();
    writer.add_path(&src_dir, true).await.unwrap();
    writer.finalize().await.unwrap();

    let out_dir = temp.path().join("out");
    let mut reader = ArchiveReader::open(&archive, "pwd").await.unwrap();
    let first = reader
        .extract_all(&ExtractOptions::new(&out_dir).overwrite(false))
        .await
        .unwrap();
    assert_eq!(first.extracted, 2);

    // Second extraction with overwrite(true) over existing 0444 targets
    let mut reader2 = ArchiveReader::open(&archive, "pwd").await.unwrap();
    let second = reader2
        .extract_all(&ExtractOptions::new(&out_dir).overwrite(true))
        .await
        .unwrap();
    assert_eq!(second.extracted, 2);
    assert_eq!(fs::read(out_dir.join("ro_small.txt")).unwrap(), small_data);
    assert_eq!(fs::read(out_dir.join("ro_large.bin")).unwrap(), large_data);

    #[cfg(unix)]
    {
        let mode_small = fs::metadata(out_dir.join("ro_small.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let mode_large = fs::metadata(out_dir.join("ro_large.bin"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode_small, 0o444);
        assert_eq!(mode_large, 0o444);
    }
}

#[tokio::test]
async fn failed_extraction_cleanup_preserves_untouched_existing_files() {
    let temp = TempDir::new().unwrap();
    let src_dir = temp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let small_path = src_dir.join("alpha_small.txt");
    let large_path = src_dir.join("beta_large.bin");
    fs::write(&small_path, b"new small").unwrap();
    fs::write(&large_path, vec![0x5Au8; 192 * 1024]).unwrap();

    let archive = temp.path().join("cleanup_boundary.era");
    {
        let mut writer = ArchiveWriterBuilder::new(&archive)
            .password("pwd")
            .enable_erasure(false)
            .build()
            .await
            .unwrap();
        writer.add_file(&small_path).await.unwrap();
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
        writer.add_file(&large_path).await.unwrap();
        writer.finalize().await.unwrap();
    }

    let out_dir = temp.path().join("out");
    fs::create_dir_all(&out_dir).unwrap();
    let existing_small = out_dir.join("alpha_small.txt");
    fs::write(&existing_small, b"preexisting untouched").unwrap();
    // Make beta_large.bin a directory so pre-creating it fails during planning
    fs::create_dir_all(out_dir.join("beta_large.bin")).unwrap();

    let mut reader = ArchiveReader::open(&archive, "pwd").await.unwrap();
    let res = reader
        .extract_all(&ExtractOptions::new(&out_dir).overwrite(true))
        .await;
    assert!(
        res.is_err(),
        "expected failure when target path is a directory"
    );

    assert!(
        existing_small.exists(),
        "pre-existing untouched file must NOT be deleted when extraction fails before writing it"
    );
    assert_eq!(fs::read(&existing_small).unwrap(), b"preexisting untouched");
}

#[cfg(unix)]
#[tokio::test]
async fn overwrite_unlinks_symlink_instead_of_writing_target() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("item.txt");
    fs::write(&src, b"archived item").unwrap();

    let archive = temp.path().join("symlink_safe.era");
    let mut writer = ArchiveWriterBuilder::new(&archive)
        .password("pwd")
        .enable_erasure(false)
        .build()
        .await
        .unwrap();
    writer.add_file(&src).await.unwrap();
    writer.finalize().await.unwrap();

    let out_dir = temp.path().join("out");
    fs::create_dir_all(&out_dir).unwrap();
    let outside = temp.path().join("outside_secret.txt");
    fs::write(&outside, b"do not clobber").unwrap();
    std::os::unix::fs::symlink(&outside, out_dir.join("item.txt")).unwrap();

    let mut reader = ArchiveReader::open(&archive, "pwd").await.unwrap();
    reader
        .extract_all(&ExtractOptions::new(&out_dir).overwrite(true))
        .await
        .unwrap();

    assert_eq!(fs::read(&outside).unwrap(), b"do not clobber");
    let meta = fs::symlink_metadata(out_dir.join("item.txt")).unwrap();
    assert!(!meta.file_type().is_symlink());
    assert_eq!(
        fs::read(out_dir.join("item.txt")).unwrap(),
        b"archived item"
    );
}
