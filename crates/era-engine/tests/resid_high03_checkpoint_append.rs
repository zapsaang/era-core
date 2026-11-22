//! Regressions for RESID-HIGH-03 checkpoint-enabled archive append.

#[path = "resid_high03_checkpoint_append/fixtures.rs"]
mod fixtures;
#[path = "resid_high03_checkpoint_append/legacy.rs"]
mod legacy;

use era_common::{BlockType, EraError};
use era_engine::{ArchiveWriter, RecoveryOptions, RecoveryStrategy};
use fixtures::*;
use std::fs;
use tempfile::TempDir;

async fn assert_checkpointed_append_roundtrip(append_with_checkpoint: bool) {
    // Given a finalized archive whose checkpoint starts exactly at the data horizon.
    let temp = TempDir::new().unwrap();
    let archive_path = temp.path().join("append.era");
    create_original(
        &archive_path,
        Some((ORIGINAL_NAME, ORIGINAL_BYTES)),
        non_ec_config(),
    )
    .await;
    let original_end = assert_new_single_data_horizon(&archive_path).await;
    let (original_manifest, original_footer) = read_metadata(&archive_path).await;
    assert_eq!(original_manifest.finalize_sequence, 1);

    // When a new finalized generation is appended.
    let appended = vec![(APPENDED_NAME.to_owned(), APPENDED_BYTES.to_vec())];
    append_files(
        &archive_path,
        &appended,
        AppendOptions {
            checkpoint: append_with_checkpoint,
            config: non_ec_config(),
        },
    )
    .await;

    // Then the new checkpoint/catalog remains outside the committed data horizon.
    let appended_end = assert_new_single_data_horizon(&archive_path).await;
    let (appended_manifest, appended_footer) = read_metadata(&archive_path).await;
    assert_eq!(appended_manifest.finalize_sequence, 2);
    assert!(appended_end > original_end);
    if append_with_checkpoint {
        assert!(
            appended_footer.last_checkpoint_offset() > original_footer.last_checkpoint_offset()
        );
        let restored = durable_checkpoint(&archive_path).await;
        assert_eq!(restored.written_chunks().len(), 2);
        assert!(restored
            .written_chunks()
            .contains_key(&chunk_hash(ORIGINAL_BYTES)));
        assert!(restored
            .written_chunks()
            .contains_key(&chunk_hash(APPENDED_BYTES)));
    }

    let expected = vec![
        (ORIGINAL_NAME.to_owned(), ORIGINAL_BYTES.to_vec()),
        (APPENDED_NAME.to_owned(), APPENDED_BYTES.to_vec()),
    ];
    assert_extraction(&archive_path, &expected).await;
}

#[tokio::test]
async fn finalized_checkpointed_archive_appends_when_next_session_disables_checkpoints() {
    assert_checkpointed_append_roundtrip(false).await;
}

#[tokio::test]
async fn finalized_checkpointed_archive_appends_when_next_session_enables_checkpoints() {
    assert_checkpointed_append_roundtrip(true).await;
}

#[tokio::test]
async fn legacy_terminal_checkpoint_horizon_accepts_empty_append_with_or_without_data() {
    for original in [None, Some((ORIGINAL_NAME, ORIGINAL_BYTES))] {
        for checkpoint in [false, true] {
            // Given an authenticated legacy horizon ending exactly after the terminal checkpoint.
            let temp = TempDir::new().unwrap();
            let archive_path = temp.path().join("legacy.era");
            create_original(&archive_path, original, non_ec_config()).await;
            let (retained_end, legacy_end) = legacy::rewrite_as_legacy(&archive_path).await;
            let (legacy_manifest, _) = read_metadata(&archive_path).await;
            assert_eq!(legacy_manifest.committed_horizon, legacy_end);
            assert_eq!(legacy_manifest.volume_committed_ends, vec![legacy_end]);

            // When an empty append finalizes, its normalized data end may move below the legacy end.
            append_files(
                &archive_path,
                &[],
                AppendOptions {
                    checkpoint,
                    config: non_ec_config(),
                },
            )
            .await;

            // Then only the old checkpoint is trimmed; data and recovered checkpoint state remain.
            let final_end = assert_new_single_data_horizon(&archive_path).await;
            assert_eq!(final_end, retained_end);
            assert!(final_end < legacy_end);
            let (final_manifest, final_footer) = read_metadata(&archive_path).await;
            assert_eq!(final_manifest.finalize_sequence, 2);
            let expected: Vec<(String, Vec<u8>)> = if checkpoint {
                let restored = durable_checkpoint(&archive_path).await;
                original
                    .map(|(name, bytes)| {
                        assert_eq!(restored.written_chunks().len(), 1);
                        assert!(restored.written_chunks().contains_key(&chunk_hash(bytes)));
                        vec![(name.to_owned(), bytes.to_vec())]
                    })
                    .unwrap_or_else(|| {
                        assert!(restored.written_chunks().is_empty());
                        Vec::new()
                    })
            } else {
                assert_eq!(final_footer.last_checkpoint_offset(), 0);
                original
                    .map(|(name, bytes)| vec![(name.to_owned(), bytes.to_vec())])
                    .unwrap_or_default()
            };
            assert_extraction(&archive_path, &expected).await;
        }
    }
}

#[tokio::test]
async fn checkpointed_append_metadata_rotation_preserves_dense_data_only_ends() {
    let temp = TempDir::new().unwrap();
    let archive_path = temp.path().join("rotated.era");
    let mut config = non_ec_config();
    config.volume.max_size = 1024 * 1024;
    config.compression.algorithm = era_common::CompressionAlgorithm::None;
    create_original(
        &archive_path,
        Some((ORIGINAL_NAME, ORIGINAL_BYTES)),
        config.clone(),
    )
    .await;
    let original_end = assert_new_single_data_horizon(&archive_path).await;

    let mut appended = Vec::new();
    for index in 0..1100usize {
        let prefix = (0..10)
            .map(|round| {
                blake3::hash(format!("{index}:{round}").as_bytes())
                    .to_hex()
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join("/");
        let name = format!("{prefix}/{index:03}_{}.bin", "x".repeat(180));
        appended.push((name, vec![u8::try_from(index % 256).unwrap(); 96]));
    }
    append_files(
        &archive_path,
        &appended,
        AppendOptions {
            checkpoint: true,
            config,
        },
    )
    .await;

    let (manifest, footer) = read_metadata(&archive_path).await;
    assert_eq!(manifest.finalize_sequence, 2);
    assert_eq!(manifest.volume_committed_ends.len(), 2);
    let old_end = manifest.volume_committed_ends[0];
    assert!(old_end > original_end);
    assert_eq!(old_end, footer.last_checkpoint_offset());
    assert_eq!(manifest.committed_horizon, old_end);
    assert_eq!(
        manifest.volume_committed_ends[1],
        era_volume::DATA_REGION_START
    );
    let old_bytes = fs::read(&archive_path).unwrap();
    assert_eq!(
        block_header(&old_bytes, old_end).block_type,
        BlockType::Checkpoint
    );
    let rotated_bytes = fs::read(era_volume::volume_path(&archive_path, 1)).unwrap();
    assert_eq!(
        block_header(&rotated_bytes, era_volume::DATA_REGION_START).block_type,
        BlockType::Catalog
    );

    let mut expected = vec![(ORIGINAL_NAME.to_owned(), ORIGINAL_BYTES.to_vec())];
    expected.extend(appended);
    assert_extraction(&archive_path, &expected).await;
}

#[tokio::test]
async fn legacy_append_rejects_unauthenticated_checkpoint_without_mutating_archive() {
    let temp = TempDir::new().unwrap();
    let archive_path = temp.path().join("legacy-corrupt.era");
    create_original(
        &archive_path,
        Some((ORIGINAL_NAME, ORIGINAL_BYTES)),
        non_ec_config(),
    )
    .await;
    legacy::rewrite_as_legacy(&archive_path).await;
    legacy::corrupt_authenticated_checkpoint(&archive_path).await;
    let before = fs::read(&archive_path).unwrap();

    let error = match ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(non_ec_config())
        .append_existing(true)
        .enable_checkpoint(true)
        .enable_erasure(false)
        .build()
        .await
    {
        Ok(_) => panic!("unauthenticated legacy checkpoint must not be trimmed"),
        Err(error) => error,
    };
    assert!(matches!(error, EraError::Decryption(_)), "{error:?}");
    assert_eq!(fs::read(&archive_path).unwrap(), before);
}

#[tokio::test]
async fn append_abort_policy_rejects_checkpoint_without_mutating_archive() {
    let temp = TempDir::new().unwrap();
    let archive_path = temp.path().join("abort.era");
    create_original(
        &archive_path,
        Some((ORIGINAL_NAME, ORIGINAL_BYTES)),
        non_ec_config(),
    )
    .await;
    let before = fs::read(&archive_path).unwrap();

    let error = match ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(non_ec_config())
        .append_existing(true)
        .recovery_options(RecoveryOptions {
            strategy: RecoveryStrategy::Abort,
            ..Default::default()
        })
        .enable_erasure(false)
        .build()
        .await
    {
        Ok(_) => panic!("explicit Abort must reject an existing checkpoint"),
        Err(error) => error,
    };
    assert!(matches!(error, EraError::CheckpointError(_)), "{error:?}");
    assert_eq!(fs::read(&archive_path).unwrap(), before);
}

#[tokio::test]
async fn checkpoint_delete_preserves_manifest_and_does_not_corrupt_truncated_archive() {
    use era_engine::CheckpointManager;
    use era_volume::{Footer, FOOTER_SIZE, HEADER_SIZE};

    let temp = TempDir::new().unwrap();
    let archive_path = temp.path().join("delete_preserve.era");
    create_original(
        &archive_path,
        Some((ORIGINAL_NAME, ORIGINAL_BYTES)),
        non_ec_config(),
    )
    .await;

    let (_, footer_before) = read_metadata(&archive_path).await;
    assert!(footer_before.last_checkpoint_offset() > 0);
    assert!(footer_before.has_manifest());

    // Case A: deleting checkpoint on a finalized archive must preserve manifest provenance.
    let mgr = CheckpointManager::load_or_create(&archive_path).unwrap();
    mgr.delete().unwrap();

    let raw = fs::read(&archive_path).unwrap();
    let primary_after = Footer::from_bytes(&raw[raw.len() - FOOTER_SIZE..]).unwrap();
    let backup_after = Footer::from_bytes(&raw[HEADER_SIZE..HEADER_SIZE + FOOTER_SIZE]).unwrap();
    assert_eq!(primary_after.last_checkpoint_offset(), 0);
    assert_eq!(backup_after.last_checkpoint_offset(), 0);
    assert!(primary_after.has_manifest());
    assert_eq!(
        primary_after.manifest_offset(),
        footer_before.manifest_offset()
    );
    assert_eq!(
        primary_after.manifest_block_id(),
        footer_before.manifest_block_id()
    );
    assert_eq!(
        backup_after.manifest_offset(),
        footer_before.manifest_offset()
    );
    assert_eq!(
        backup_after.manifest_block_id(),
        footer_before.manifest_block_id()
    );

    let mut reader = era_engine::ArchiveReader::open(&archive_path, PASSWORD)
        .await
        .unwrap();
    reader.preflight_metadata_recovery().await.unwrap();
    assert!(reader.manifest().is_some());
    assert!(reader.verify().await.unwrap().is_healthy());

    // Case B: when primary footer is absent (truncated), delete() must only update backup footer
    // and must NOT overwrite the final 128 bytes of payload/metadata.
    let trunc_path = temp.path().join("truncated_primary_footer.era");
    create_original(
        &trunc_path,
        Some((ORIGINAL_NAME, ORIGINAL_BYTES)),
        non_ec_config(),
    )
    .await;
    let orig_len = fs::metadata(&trunc_path).unwrap().len();
    {
        let f = fs::OpenOptions::new()
            .write(true)
            .open(&trunc_path)
            .unwrap();
        f.set_len(orig_len - FOOTER_SIZE as u64).unwrap();
        f.sync_all().unwrap();
    }
    let before_trunc = fs::read(&trunc_path).unwrap();
    let tail_before = before_trunc[before_trunc.len() - FOOTER_SIZE..].to_vec();

    CheckpointManager::load_or_create(&trunc_path)
        .unwrap()
        .delete()
        .unwrap();

    let after_trunc = fs::read(&trunc_path).unwrap();
    assert_eq!(
        &after_trunc[after_trunc.len() - FOOTER_SIZE..],
        tail_before.as_slice(),
        "delete() must not overwrite trailing bytes when falling back to backup footer"
    );
    let backup_only =
        Footer::from_bytes(&after_trunc[HEADER_SIZE..HEADER_SIZE + FOOTER_SIZE]).unwrap();
    assert_eq!(backup_only.last_checkpoint_offset(), 0);
    assert!(backup_only.has_manifest());
}

#[tokio::test]
async fn append_start_fresh_failure_before_truncation_preserves_existing_archive_and_checkpoint() {
    use era_engine::CheckpointManager;

    let temp = TempDir::new().unwrap();
    let archive_path = temp.path().join("start_fresh_atomic.era");
    let mut big_cfg = non_ec_config();
    big_cfg.compression.algorithm = era_common::CompressionAlgorithm::None;
    let large_payload = vec![0x3C; 1_050_000];
    create_original(
        &archive_path,
        Some(("large.bin", &large_payload)),
        big_cfg.clone(),
    )
    .await;
    let before = fs::read(&archive_path).unwrap();

    // Force open_append_single_at to fail after builder validation by capping max_volume_size
    // to 1 MiB (< retained data size). Existing archive + checkpoint must remain untouched.
    let err = match ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(big_cfg)
        .append_existing(true)
        .enable_checkpoint(true)
        .recovery_options(RecoveryOptions::start_fresh())
        .max_volume_size(1024 * 1024)
        .enable_erasure(false)
        .build()
        .await
    {
        Ok(_) => panic!("expected append with oversized retained volume to fail"),
        Err(err) => err,
    };
    assert!(
        matches!(err, EraError::InvalidConfig(_)),
        "expected InvalidConfig from retained size check, got {err:?}"
    );
    assert_eq!(
        fs::read(&archive_path).unwrap(),
        before,
        "failed StartFresh append must not delete checkpoint or mutate archive before truncation"
    );
    assert!(
        CheckpointManager::exists(&archive_path).await.unwrap(),
        "existing durable checkpoint must still exist after failed StartFresh open"
    );

    // Positive path: successful StartFresh append clears stale backup footer after truncation
    // and finalizes cleanly.
    let small_path = temp.path().join("start_fresh_ok.era");
    create_original(
        &small_path,
        Some((ORIGINAL_NAME, ORIGINAL_BYTES)),
        non_ec_config(),
    )
    .await;
    let mut writer = ArchiveWriter::builder(&small_path)
        .password(PASSWORD)
        .config(non_ec_config())
        .append_existing(true)
        .enable_checkpoint(true)
        .recovery_options(RecoveryOptions::start_fresh())
        .enable_erasure(false)
        .build()
        .await
        .unwrap();
    assert!(
        !CheckpointManager::exists(&small_path).await.unwrap(),
        "successful StartFresh append must clear stale backup footer after truncation"
    );
    writer
        .add_bytes(APPENDED_NAME, APPENDED_BYTES)
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    assert_extraction(
        &small_path,
        &[
            (ORIGINAL_NAME.to_owned(), ORIGINAL_BYTES.to_vec()),
            (APPENDED_NAME.to_owned(), APPENDED_BYTES.to_vec()),
        ],
    )
    .await;
}

#[tokio::test]
async fn finalize_checkpoint_respects_max_volume_size_when_volume_near_full() {
    let temp = TempDir::new().unwrap();
    let archive_path = temp.path().join("ckpt_near_full.era");
    let mut cfg = non_ec_config();
    cfg.compression.algorithm = era_common::CompressionAlgorithm::None;
    cfg.volume.max_size = 1024 * 1024;

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(cfg)
        .max_volume_size(1024 * 1024)
        .enable_checkpoint(true)
        .enable_erasure(false)
        .enable_cdc(false)
        .enable_small_file_packing(false)
        .build()
        .await
        .unwrap();

    // Available data budget in 1 MiB volume = 1_048_576 - 4224 - 4248 = 1_040_104.
    // A 1_039_900-byte payload fits Volume 0 cleanly (~80B overhead), leaving < 150B before
    // PER_VOLUME_OVERHEAD so the finalized Checkpoint block must rotate to Volume 1.
    let payload = vec![0x7A; 1_039_900];
    writer.add_bytes("near_full.bin", &payload).await.unwrap();
    writer.finalize().await.unwrap();

    let vol0 = era_volume::volume_path(&archive_path, 0);
    let vol1 = era_volume::volume_path(&archive_path, 1);
    assert!(vol0.exists());
    assert!(
        vol1.exists(),
        "near-full volume must rotate before writing durable checkpoint"
    );
    assert!(
        fs::metadata(&vol0).unwrap().len() <= 1024 * 1024,
        "volume 0 size {} exceeded max_volume_size {}",
        fs::metadata(&vol0).unwrap().len(),
        1024 * 1024
    );
    assert!(
        fs::metadata(&vol1).unwrap().len() <= 1024 * 1024,
        "volume 1 size {} exceeded max_volume_size {}",
        fs::metadata(&vol1).unwrap().len(),
        1024 * 1024
    );

    let mut reader = era_engine::ArchiveReader::open(&archive_path, PASSWORD)
        .await
        .unwrap();
    let stats = reader.verify().await.unwrap();
    assert!(
        stats.is_healthy(),
        "expected Healthy archive, got {:?}, warnings={:?}, errors={:?}",
        stats.archive_health,
        stats.warnings,
        stats.errors
    );
    assert_extraction(&archive_path, &[("near_full.bin".to_owned(), payload)]).await;
}

#[tokio::test]
async fn interrupted_append_preserves_readable_archive_across_plain_resume_and_start_fresh() {
    use era_engine::ArchiveReader;

    let cases = [
        ("plain", false, None),
        ("resume", true, Some(RecoveryOptions::resume())),
        ("start_fresh", true, Some(RecoveryOptions::start_fresh())),
    ];

    for (label, checkpoint_enabled, recovery_opt) in cases {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join(format!("interrupted_{label}.era"));

        let mut config = non_ec_config();
        config.compression.algorithm = era_common::CompressionAlgorithm::None;
        config.block.target_size = 32 * 1024;

        {
            let mut writer = ArchiveWriter::builder(&archive_path)
                .password(PASSWORD)
                .config(config.clone())
                .target_block_size(32 * 1024)
                .enable_checkpoint(checkpoint_enabled)
                .enable_erasure(false)
                .build()
                .await
                .unwrap();
            writer
                .add_bytes(ORIGINAL_NAME, ORIGINAL_BYTES)
                .await
                .unwrap();
            writer.finalize().await.unwrap();
        }

        // Open for append, flush at least one data block (> target_block_size),
        // then drop without finalize() to simulate a crash mid-append.
        {
            let mut builder = ArchiveWriter::builder(&archive_path)
                .password(PASSWORD)
                .config(config.clone())
                .target_block_size(32 * 1024)
                .append_existing(true)
                .enable_checkpoint(checkpoint_enabled)
                .enable_erasure(false);
            if let Some(opts) = recovery_opt {
                builder = builder.recovery_options(opts);
            }
            let mut writer = builder.build().await.unwrap();
            writer
                .add_bytes("uncommitted.bin", &vec![0xCD; 96 * 1024])
                .await
                .unwrap();
            drop(writer);
        }

        // Committed archive must still open, verify Healthy, and extract original contents.
        let mut reader = ArchiveReader::open(&archive_path, PASSWORD)
            .await
            .unwrap_or_else(|e| panic!("[{label}] failed to open after interrupted append: {e}"));
        let stats = reader.verify().await.unwrap();
        assert!(
            stats.is_healthy(),
            "[{label}] expected Healthy archive after interrupted append, got {:?}, warnings={:?}, errors={:?}",
            stats.archive_health,
            stats.warnings,
            stats.errors
        );
        assert_extraction(
            &archive_path,
            &[(ORIGINAL_NAME.to_owned(), ORIGINAL_BYTES.to_vec())],
        )
        .await;

        // A subsequent append session must also succeed and finalize cleanly.
        append_files(
            &archive_path,
            &[(APPENDED_NAME.to_owned(), APPENDED_BYTES.to_vec())],
            AppendOptions {
                checkpoint: checkpoint_enabled,
                config,
            },
        )
        .await;
        assert_extraction(
            &archive_path,
            &[
                (ORIGINAL_NAME.to_owned(), ORIGINAL_BYTES.to_vec()),
                (APPENDED_NAME.to_owned(), APPENDED_BYTES.to_vec()),
            ],
        )
        .await;
    }
}

#[tokio::test]
async fn interrupted_start_fresh_on_legacy_checkpoint_allows_subsequent_append() {
    use era_engine::{ArchiveReader, CheckpointManager};

    let temp = TempDir::new().unwrap();
    let archive_path = temp.path().join("legacy_start_fresh_crash.era");
    create_original(
        &archive_path,
        Some((ORIGINAL_NAME, ORIGINAL_BYTES)),
        non_ec_config(),
    )
    .await;
    legacy::rewrite_as_legacy(&archive_path).await;

    {
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(PASSWORD)
            .config(non_ec_config())
            .append_existing(true)
            .enable_checkpoint(true)
            .recovery_options(RecoveryOptions::start_fresh())
            .enable_erasure(false)
            .build()
            .await
            .unwrap();
        assert!(!CheckpointManager::exists(&archive_path).await.unwrap());
        writer
            .add_bytes("uncommitted.bin", b"uncommitted")
            .await
            .unwrap();
        drop(writer);
    }

    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    let stats = reader.verify().await.unwrap();
    assert!(stats.is_healthy(), "{:?}", stats.archive_health);

    append_files(
        &archive_path,
        &[(APPENDED_NAME.to_owned(), APPENDED_BYTES.to_vec())],
        AppendOptions {
            checkpoint: true,
            config: non_ec_config(),
        },
    )
    .await;
    assert_extraction(
        &archive_path,
        &[
            (ORIGINAL_NAME.to_owned(), ORIGINAL_BYTES.to_vec()),
            (APPENDED_NAME.to_owned(), APPENDED_BYTES.to_vec()),
        ],
    )
    .await;
}

#[tokio::test]
async fn interrupted_append_after_volume_rotation_preserves_original_archive() {
    use era_engine::ArchiveReader;

    let unique_payload = |seed: u64, len: usize| -> Vec<u8> {
        let mut state = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.push((state >> 24) as u8);
        }
        out
    };

    let temp = TempDir::new().unwrap();
    let archive_path = temp.path().join("rotated_interrupted.era");
    let mut config = non_ec_config();
    config.compression.algorithm = era_common::CompressionAlgorithm::None;
    config.volume.max_size = 1024 * 1024;
    config.block.target_size = 256 * 1024;

    let original_payload = unique_payload(1, 512 * 1024);
    create_original(
        &archive_path,
        Some(("orig.bin", &original_payload)),
        config.clone(),
    )
    .await;

    {
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(PASSWORD)
            .config(config.clone())
            .max_volume_size(1024 * 1024)
            .target_block_size(256 * 1024)
            .append_existing(true)
            .enable_checkpoint(true)
            .enable_erasure(false)
            .build()
            .await
            .unwrap();
        // Exceed 1 MiB cap with incompressible non-dedup data to force rotate_volumes() before dropping.
        writer
            .add_bytes("overflow.bin", &unique_payload(2, 700 * 1024))
            .await
            .unwrap();
        drop(writer);
    }

    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    let stats = reader.verify().await.unwrap();
    assert!(
        stats.is_healthy(),
        "original single-volume archive must remain Healthy after interrupted rotated append: {:?}",
        stats.archive_health
    );
    assert_extraction(&archive_path, &[("orig.bin".to_owned(), original_payload)]).await;

    let rotated_volume = era_volume::volume_path(&archive_path, 1);
    assert!(
        !rotated_volume.exists(),
        "interrupted rotated append must clean up uncommitted orphan volume {}",
        rotated_volume.display()
    );
}
