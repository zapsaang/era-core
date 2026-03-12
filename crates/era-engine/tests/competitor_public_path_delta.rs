use bytes::Bytes;
use era_common::{ArchiveConfig, ArchiveId, BlockId, EncryptedMacroBlock, ErasureCodeConfig};
use era_engine::{
    repair_archive, ArchiveReader, ArchiveWriter, ExtractOptions, RecoveryOptions, RepairOptions,
};
use era_storage::{LocalStorageBackend, StorageBackend, StorageReader};
use era_volume::{
    AccessPolicy, EncryptedVolumeKey, KeyWrapAlgorithm, RecipientSlot, RecipientType, SuperHeader,
    VolumePool, VolumePoolConfig,
};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn patterned_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[cfg(unix)]
fn install_symlink(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
}

#[path = "../src/volume_stage.rs"]
mod public_path_volume_stage;

#[tokio::test]
async fn test_public_resume_requires_durable_checkpoint_state() {
    let temp = TempDir::new().unwrap();
    let archive = temp.path().join("resume_without_checkpoint.era");

    let mut baseline = ArchiveWriter::builder(&archive)
        .password("resume-public")
        .enable_checkpoint(false)
        .enable_erasure(false)
        .build()
        .await
        .unwrap();
    baseline.add_bytes("seed.txt", b"seed").await.unwrap();
    baseline.finalize().await.unwrap();

    let result = ArchiveWriter::builder(&archive)
        .password("resume-public")
        .enable_checkpoint(true)
        .recovery_options(RecoveryOptions::resume())
        .enable_erasure(false)
        .build()
        .await;

    assert!(
        result.is_err(),
        "resume mode must fail when no durable checkpoint exists"
    );
}

#[tokio::test]
async fn test_public_finalize_persists_authoritative_checkpoint_before_catalog() {
    let temp = TempDir::new().unwrap();
    let archive = temp.path().join("finalize_checkpoint_before_catalog.era");

    let mut writer = ArchiveWriter::builder(&archive)
        .password("finalize-public")
        .enable_checkpoint(true)
        .enable_erasure(false)
        .build()
        .await
        .unwrap();

    writer
        .add_bytes("payload.txt", b"checkpoint-before-catalog")
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    let backend = LocalStorageBackend::new(temp.path());
    let volume = era_volume::VolumeReader::open(
        &backend,
        Path::new("finalize_checkpoint_before_catalog.era"),
    )
    .await
    .unwrap();
    let footer = volume.footer().unwrap();

    assert!(
        footer.last_checkpoint_offset() > 0,
        "finalize must persist durable checkpoint"
    );
    assert!(footer.catalog_offset() > 0, "catalog must be written");
    assert!(
        footer.last_checkpoint_offset() < footer.catalog_offset(),
        "durable checkpoint must be committed before catalog"
    );
}

#[tokio::test]
async fn test_public_checkpoint_commit_persists_footer_before_finalize() {
    let temp = TempDir::new().unwrap();
    let archive = temp.path().join("checkpoint_before_finalize.era");

    let mut writer = ArchiveWriter::builder(&archive)
        .password("checkpoint-public")
        .enable_checkpoint(true)
        .enable_erasure(false)
        .build()
        .await
        .unwrap();

    writer
        .add_bytes("payload.txt", b"checkpoint-live")
        .await
        .unwrap();

    let raw_reader = LocalStorageBackend::new(temp.path())
        .open_read(Path::new("checkpoint_before_finalize.era"))
        .await
        .unwrap();
    let backup_footer = raw_reader
        .read_at(era_volume::HEADER_SIZE as u64, era_volume::FOOTER_SIZE)
        .await
        .unwrap();
    assert!(
        era_volume::Footer::from_bytes(&backup_footer).is_err(),
        "before finalize, reserved footer gap should not already contain a committed checkpoint"
    );

    writer.finalize().await.unwrap();

    let raw_reader = LocalStorageBackend::new(temp.path())
        .open_read(Path::new("checkpoint_before_finalize.era"))
        .await
        .unwrap();
    let backup_footer = raw_reader
        .read_at(era_volume::HEADER_SIZE as u64, era_volume::FOOTER_SIZE)
        .await
        .unwrap();
    let footer = era_volume::Footer::from_bytes(&backup_footer).unwrap();

    assert!(
        footer.last_checkpoint_offset() > 0,
        "checkpoint commit must persist a recoverable footer into the reserved gap"
    );
}

#[tokio::test]
async fn test_public_catalog_fanout_fails_on_missing_writer_slot() {
    let temp = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp.path());
    let base = temp.path().join("missing_slot_catalog.era");

    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![RecipientSlot::new(
            RecipientType::Argon2idPassword,
            Some([0x22; 8]),
            vec![0xAB; 16],
            vec![0xCD; 48],
        )],
        ArchiveConfig::default(),
        [0x11; 16],
        EncryptedVolumeKey::new(
            KeyWrapAlgorithm::XChaCha20Poly1305,
            [0x33; 24],
            vec![0x44; 48],
        ),
        AccessPolicy::AnyOfN,
    )
    .unwrap();

    let pool = VolumePool::create(backend, VolumePoolConfig::new(&base, 2), header)
        .await
        .unwrap();
    let mut stage = public_path_volume_stage::VolumeStage::new(pool);

    let catalog_block = EncryptedMacroBlock {
        block_id: BlockId::new(7),
        data: Bytes::from(vec![0xAA; 256]),
        original_size: 256,
        compressed_size: 256,
        chunk_count: 1,
    };

    let first_locations = stage
        .write_catalog_to_all(&catalog_block, None)
        .await
        .unwrap();
    stage.finalize(&first_locations, None).await.unwrap();

    let second_attempt = stage.write_catalog_to_all(&catalog_block, None).await;
    assert!(
        second_attempt.is_err(),
        "missing catalog writer slot must hard-fail"
    );
}

#[tokio::test]
async fn test_public_catalog_copies_are_readable_via_public_paths() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("input.txt");
    fs::write(&src, b"catalog-copy-public-read").unwrap();

    let archive = temp.path().join("catalog_copies.era");
    let cfg = ArchiveConfig {
        erasure: Some(ErasureCodeConfig::new(2, 1)),
        ..Default::default()
    };

    let mut writer = ArchiveWriter::builder(&archive)
        .password("catalog-public")
        .config(cfg)
        .volume_count(3)
        .build()
        .await
        .unwrap();

    writer
        .add_file_with_path(&src, Path::new("input.txt"))
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    for volume_name in [
        "catalog_copies.era",
        "catalog_copies.era.001",
        "catalog_copies.era.002",
    ] {
        let volume_path = temp.path().join(volume_name);
        let mut reader = ArchiveReader::open(&volume_path, "catalog-public")
            .await
            .unwrap();
        let files = reader.list_files().await.unwrap();
        assert!(
            files
                .iter()
                .any(|entry| entry.path == Path::new("input.txt")),
            "catalog loaded from {} must expose input.txt",
            volume_name
        );

        let extract_root = temp
            .path()
            .join(format!("extract_{}", volume_name.replace('.', "_")));
        let stats = reader
            .extract_all(&ExtractOptions::new(&extract_root).overwrite(true))
            .await
            .unwrap();
        assert_eq!(stats.extracted, 1);
    }
}

#[tokio::test]
async fn test_public_extract_rejects_symlink_parent_swap() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("payload.txt");
    fs::write(&src, b"public-symlink-parent-swap").unwrap();

    let archive = temp.path().join("public_extract_parent_swap.era");
    let mut writer = ArchiveWriter::builder(&archive)
        .password("extract-public")
        .enable_erasure(false)
        .build()
        .await
        .unwrap();
    writer
        .add_file_with_path(&src, Path::new("dir/file.txt"))
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    let extract_root = temp.path().join("extract_root");
    fs::create_dir_all(&extract_root).unwrap();
    let outside = temp.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    install_symlink(&outside, &extract_root.join("dir"));

    let mut reader = ArchiveReader::open(&archive, "extract-public")
        .await
        .unwrap();
    let result = reader
        .extract_all(&ExtractOptions::new(&extract_root))
        .await;
    let msg = format!("{:?}", result.as_ref().err());

    assert!(result.is_err(), "symlink swap extraction must fail");
    assert!(
        msg.contains("Symlink") || msg.contains("outside output directory"),
        "expected extraction-time symlink rejection, got: {}",
        msg
    );
    assert!(
        !outside.join("file.txt").exists(),
        "extraction must not escape the requested output root"
    );
}

#[tokio::test]
async fn test_public_iterator_probe_limit_fails_closed() {
    let temp = TempDir::new().unwrap();
    let archive = temp.path().join("iterator_fail_closed.era");
    let payload = patterned_bytes(384 * 1024);
    let cfg = ArchiveConfig {
        erasure: Some(ErasureCodeConfig::new(2, 1)),
        ..Default::default()
    };

    let mut writer = ArchiveWriter::builder(&archive)
        .password("iterator-public")
        .config(cfg)
        .volume_count(3)
        .build()
        .await
        .unwrap();
    writer.add_bytes("payload.bin", &payload).await.unwrap();
    writer.finalize().await.unwrap();

    let degraded = temp.path().join("iterator_fail_closed.era.001");
    fs::OpenOptions::new()
        .write(true)
        .open(&degraded)
        .unwrap()
        .set_len(4224)
        .unwrap();
    fs::remove_file(temp.path().join("iterator_fail_closed.era.002")).unwrap();

    let output_dir = temp.path().join("iterator_out");
    let mut reader = ArchiveReader::open(&archive, "iterator-public")
        .await
        .unwrap();
    let result = reader
        .extract_all(&ExtractOptions::new(&output_dir).overwrite(true))
        .await;
    let msg = format!("{:?}", result.as_ref().err());

    assert!(
        result.is_err(),
        "iterator must fail closed on lost stripe quorum"
    );
    assert!(
        msg.contains("Not enough shards for recovery")
            || msg.contains("Unexpected EOF while reading stripe")
            || msg.contains("consecutive block failures"),
        "expected explicit iterator failure, got: {}",
        msg
    );
    assert!(
        !output_dir.join("payload.bin").exists(),
        "failed extraction must clean up partial outputs"
    );
}

#[tokio::test]
async fn test_public_repair_rejects_insufficient_shards_without_silent_success() {
    let temp = TempDir::new().unwrap();
    let archive = temp.path().join("repair_insufficient_shards.era");
    let payload = patterned_bytes(384 * 1024);
    let cfg = ArchiveConfig {
        erasure: Some(ErasureCodeConfig::new(2, 1)),
        ..Default::default()
    };

    let mut writer = ArchiveWriter::builder(&archive)
        .password("repair-public")
        .config(cfg)
        .volume_count(3)
        .build()
        .await
        .unwrap();
    writer.add_bytes("payload.bin", &payload).await.unwrap();
    writer.finalize().await.unwrap();

    let degraded = temp.path().join("repair_insufficient_shards.era.001");
    fs::OpenOptions::new()
        .write(true)
        .open(&degraded)
        .unwrap()
        .set_len(4224)
        .unwrap();
    fs::remove_file(temp.path().join("repair_insufficient_shards.era.002")).unwrap();

    let result = repair_archive(
        &archive,
        "repair-public",
        RepairOptions {
            create_backup: false,
            dry_run: true,
            continue_on_error: false,
        },
    )
    .await;

    let msg = format!("{:?}", result.as_ref().err());
    assert!(
        result.is_err(),
        "repair must reject unrecoverable shard loss instead of succeeding"
    );
    assert!(
        msg.contains("unrecoverable")
            || msg.contains("recovery")
            || msg.contains("insufficient surviving volumes")
            || msg.contains("only 1/3 shards intact"),
        "expected explicit repair failure, got: {}",
        msg
    );
}
