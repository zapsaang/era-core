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
