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

#[tokio::test]
async fn overwrite_extraction_failure_restores_preexisting_overwritten_files() {
    use std::io::{Read, Seek, SeekFrom, Write};

    let temp = TempDir::new().unwrap();
    let archive = temp.path().join("overwrite_rollback.era");

    let mut config = era_common::ArchiveConfig {
        erasure: None,
        ..Default::default()
    };
    config.encryption.kdf_memory_cost = 1024;
    config.encryption.kdf_time_cost = 1;
    config.compression.algorithm = era_common::CompressionAlgorithm::None;
    config.block.target_size = 256;

    let mut writer = ArchiveWriterBuilder::new(&archive)
        .password("pwd")
        .config(config)
        .target_block_size(256)
        .enable_erasure(false)
        .enable_cdc(false)
        .enable_small_file_packing(false)
        .build()
        .await
        .unwrap();

    writer.add_bytes("alpha.bin", &[b'A'; 320]).await.unwrap();
    writer.add_bytes("beta_ro.bin", &[b'B'; 320]).await.unwrap();
    writer
        .add_bytes("gamma_new.bin", &[b'C'; 320])
        .await
        .unwrap();
    writer
        .add_bytes("delta_fail.bin", &[b'D'; 320])
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    // Corrupt the last data block so alpha, beta_ro, and gamma_new succeed first and then fail.
    let mut probe = ArchiveReader::open(&archive, "pwd").await.unwrap();
    let catalog = probe.load_catalog().await.unwrap().clone();
    assert!(
        catalog.block_locations.len() >= 4,
        "expected distinct data blocks before failure"
    );
    let last_loc = catalog.block_locations.last().unwrap().clone();
    drop(probe);

    {
        let mut f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&archive)
            .unwrap();
        let corrupt_offset = last_loc.physical_offset + era_common::BlockHeader::SIZE as u64 + 28;
        f.seek(SeekFrom::Start(corrupt_offset)).unwrap();
        let mut byte = [0u8; 1];
        f.read_exact(&mut byte).unwrap();
        byte[0] ^= 0xFF;
        f.seek(SeekFrom::Start(corrupt_offset)).unwrap();
        f.write_all(&byte).unwrap();
        f.sync_all().unwrap();
    }

    let out_dir = temp.path().join("out");
    fs::create_dir_all(&out_dir).unwrap();
    let alpha_path = out_dir.join("alpha.bin");
    let beta_path = out_dir.join("beta_ro.bin");
    fs::write(&alpha_path, b"original alpha content").unwrap();
    fs::write(&beta_path, b"original readonly content").unwrap();
    #[cfg(unix)]
    fs::set_permissions(&beta_path, fs::Permissions::from_mode(0o444)).unwrap();

    let mut reader = ArchiveReader::open(&archive, "pwd").await.unwrap();
    let res = reader
        .extract_all(&ExtractOptions::new(&out_dir).overwrite(true))
        .await;
    assert!(
        res.is_err(),
        "corrupted final block must fail overwrite extraction"
    );

    assert_eq!(
        fs::read(&alpha_path).unwrap(),
        b"original alpha content",
        "pre-existing overwritten file must be restored on failure"
    );
    assert_eq!(
        fs::read(&beta_path).unwrap(),
        b"original readonly content",
        "pre-existing read-only file must be restored on failure"
    );
    #[cfg(unix)]
    assert_eq!(
        fs::symlink_metadata(&beta_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o444,
        "pre-existing file permissions must be preserved on rollback"
    );
    assert!(
        !out_dir.join("gamma_new.bin").exists() && !out_dir.join("delta_fail.bin").exists(),
        "newly created partial files must be removed on failure"
    );

    let leftovers: Vec<_> = fs::read_dir(&out_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".era_overwrite_backup_")
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "rollback must clean up backup staging files: {leftovers:?}"
    );
}
