#[path = "../src/chunk_processor.rs"]
mod v5_chunk_processor;

#[path = "../src/chunk_index.rs"]
mod v5_chunk_index;

#[path = "../src/volume_stage.rs"]
mod v5_volume_stage;

use std::fs;
use std::path::Path;

use bytes::Bytes;
use era_common::{
    ArchiveConfig, ArchiveId, BlockId, BlockLocation, ChunkHash, EncryptedMacroBlock,
    ErasureCodeConfig, VolumeId,
};
use era_crypto::{AeadContext, KdfParams, KeySession, Salt, XChaCha20Poly1305Context, NONCE_SIZE};
use era_engine::CheckpointManager;
use era_engine::{
    ArchiveReader, ArchiveWriterBuilder, ExtractOptions, RecoverableWriter, RecoveryOptions,
};
use era_storage::LocalStorageBackend;
use era_volume::{
    AccessPolicy, EncryptedVolumeKey, KeyWrapAlgorithm, RecipientSlot, RecipientType, SuperHeader,
    VolumePool, VolumePoolConfig,
};
use tempfile::TempDir;
use tokio::time::{timeout, Duration};
use v5_chunk_index::ChunkIndex;
use v5_chunk_processor::{ExtractStats, ExtractionContext, MultiChunkState};

#[tokio::test]
async fn test_v5_state_01_finalize_writes_durable_checkpoint() {
    let temp = TempDir::new().unwrap();
    let archive = temp.path().join("v5_state_01.era");

    let mut writer = ArchiveWriterBuilder::new(&archive)
        .password("v5-state-01")
        .enable_checkpoint(true)
        .enable_erasure(false)
        .build()
        .await
        .unwrap();

    writer.add_bytes("a.txt", b"checkpoint").await.unwrap();
    writer.finalize().await.unwrap();

    let backend = era_storage::LocalStorageBackend::new(temp.path());
    let volume = era_volume::VolumeReader::open(&backend, Path::new("v5_state_01.era"))
        .await
        .unwrap();
    let footer = volume.footer().unwrap();

    assert!(
        footer.last_checkpoint_offset() > 0,
        "expected non-zero durable checkpoint offset after finalize"
    );
}

#[tokio::test]
async fn test_v5_state_02_resume_requires_persisted_checkpoint() {
    let temp = TempDir::new().unwrap();
    let archive = temp.path().join("v5_state_02.era");

    let mut writer = ArchiveWriterBuilder::new(&archive)
        .password("v5-state-02")
        .enable_checkpoint(false)
        .enable_erasure(false)
        .build()
        .await
        .unwrap();

    writer.add_bytes("b.txt", b"resume").await.unwrap();
    writer.finalize().await.unwrap();

    let resumed = ArchiveWriterBuilder::new(&archive)
        .password("v5-state-02")
        .enable_checkpoint(true)
        .recovery_options(RecoveryOptions::resume())
        .enable_erasure(false)
        .build()
        .await;
    assert!(resumed.is_err());
}

#[tokio::test]
async fn test_v5_state_03_resume_rejects_corrupted_durable_checkpoint() {
    let temp = TempDir::new().unwrap();
    let archive = temp.path().join("v5_state_03.era");

    let mut writer = ArchiveWriterBuilder::new(&archive)
        .password("v5-state-03")
        .enable_checkpoint(true)
        .enable_erasure(false)
        .build()
        .await
        .unwrap();

    writer
        .add_bytes("corrupt.txt", b"durable-checkpoint")
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    let backend = LocalStorageBackend::new(temp.path());
    let volume = era_volume::VolumeReader::open(&backend, Path::new("v5_state_03.era"))
        .await
        .unwrap();
    let footer = volume.footer().unwrap();
    let checkpoint_offset = footer.last_checkpoint_offset();
    assert!(
        checkpoint_offset > 0,
        "expected durable checkpoint before corruption"
    );

    use std::io::{Seek, SeekFrom, Write};
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&archive)
        .unwrap();
    file.seek(SeekFrom::Start(checkpoint_offset)).unwrap();
    file.write_all(&[0xFF; 8]).unwrap();

    let resumed = ArchiveWriterBuilder::new(&archive)
        .password("v5-state-03")
        .enable_checkpoint(true)
        .recovery_options(RecoveryOptions::resume())
        .enable_erasure(false)
        .build()
        .await;
    assert!(
        resumed.is_err(),
        "public resume path must reject corrupted durable checkpoint provenance"
    );
}

#[tokio::test]
async fn test_v5_state_04_start_fresh_discards_prior_checkpoint_provenance() {
    let temp = TempDir::new().unwrap();
    let archive = temp.path().join("v5_state_04.era");

    let mut initial = ArchiveWriterBuilder::new(&archive)
        .password("v5-state-04")
        .enable_checkpoint(true)
        .enable_erasure(false)
        .build()
        .await
        .unwrap();

    initial.add_bytes("before.txt", b"before").await.unwrap();
    initial.finalize().await.unwrap();

    let backend = LocalStorageBackend::new(temp.path());
    let volume_before = era_volume::VolumeReader::open(&backend, Path::new("v5_state_04.era"))
        .await
        .unwrap();
    let footer_before = volume_before.footer().unwrap();
    assert!(
        footer_before.last_checkpoint_offset() > 0,
        "expected durable checkpoint before start-fresh"
    );

    let opts = RecoveryOptions::start_fresh();
    let _fresh = RecoverableWriter::new(&archive, opts).await.unwrap();

    let volume_after = era_volume::VolumeReader::open(&backend, Path::new("v5_state_04.era"))
        .await
        .unwrap();
    let footer_after = volume_after.footer().unwrap();
    assert_eq!(
        footer_after.last_checkpoint_offset(),
        0,
        "start-fresh must clear durable checkpoint provenance"
    );

    let resume_after_fresh = ArchiveWriterBuilder::new(&archive)
        .password("v5-state-04")
        .enable_checkpoint(true)
        .recovery_options(RecoveryOptions::resume())
        .enable_erasure(false)
        .build()
        .await;
    assert!(
        resume_after_fresh.is_err(),
        "public resume path should fail after start-fresh cleared checkpoint provenance"
    );
}

#[tokio::test]
async fn test_v5_state_05_checkpoint_disabled_finalize_is_clean_noop() {
    let temp = TempDir::new().unwrap();
    let archive = temp.path().join("v5_state_05.era");

    let mut writer = ArchiveWriterBuilder::new(&archive)
        .password("v5-state-05")
        .enable_checkpoint(false)
        .enable_erasure(false)
        .build()
        .await
        .unwrap();

    writer.add_bytes("noop.txt", b"noop").await.unwrap();
    writer.finalize().await.unwrap();

    let backend = LocalStorageBackend::new(temp.path());
    let volume = era_volume::VolumeReader::open(&backend, Path::new("v5_state_05.era"))
        .await
        .unwrap();
    let footer = volume.footer().unwrap();

    assert_eq!(
        footer.last_checkpoint_offset(),
        0,
        "checkpoint-disabled finalize must not write checkpoint"
    );
}

#[tokio::test]
async fn test_v5_state_06_resume_loads_durable_checkpoint_state() {
    let temp = TempDir::new().unwrap();
    let archive = temp.path().join("v5_state_06.era");

    let mut writer = ArchiveWriterBuilder::new(&archive)
        .password("v5-state-06")
        .enable_checkpoint(true)
        .enable_erasure(false)
        .build()
        .await
        .unwrap();

    writer
        .add_bytes("state.txt", b"resume-state")
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    let backend = LocalStorageBackend::new(temp.path());
    let volume = era_volume::VolumeReader::open(&backend, Path::new("v5_state_06.era"))
        .await
        .unwrap();
    let header = volume.header();

    let slot = header.recipients().first().unwrap();
    let archived = rkyv::access::<
        rkyv::Archived<era_engine::auth::PasswordSlotParams>,
        rkyv::rancor::Error,
    >(slot.params())
    .unwrap();
    let kdf = KdfParams {
        memory_cost: archived.kdf_memory_cost.into(),
        time_cost: archived.kdf_time_cost.into(),
        parallelism: archived.kdf_parallelism.into(),
    };
    let salt = Salt::from_bytes(archived.salt);
    let kek = era_crypto::derive_key(b"v5-state-06", &salt, &kdf).unwrap();
    let encrypted_mk = slot.encrypted_master_key();
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&encrypted_mk[..NONCE_SIZE]);
    let ciphertext = &encrypted_mk[NONCE_SIZE..];
    let mk = XChaCha20Poly1305Context::from_derived_key(&kek)
        .unwrap()
        .decrypt(&nonce, era_engine::auth::MK_WRAP_AAD_DOMAIN, ciphertext)
        .unwrap();

    let session = KeySession::from_master_key(
        mk.as_slice()
            .try_into()
            .expect("master key must be 32 bytes"),
    )
    .unwrap();
    let volume_key = session
        .unwrap_volume_key(
            header.encrypted_volume_key().nonce(),
            header.encrypted_volume_key().ciphertext(),
        )
        .unwrap();

    let restored = CheckpointManager::load_from_durable_checkpoint(
        &archive,
        &session,
        &volume_key,
        *header.salt(),
        *header.archive_id().0.as_bytes(),
        header.epoch_id(),
    )
    .await
    .unwrap();

    assert!(
        !restored.written_chunks().is_empty(),
        "resume path must restore persisted checkpoint chunk state"
    );
}

#[tokio::test]
async fn test_v5_advrs_01_non_session_shard_len_cap() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("blob.bin"), vec![0x41u8; 512 * 1024]).unwrap();

    let archive = temp.path().join("v5_advrs_01.era");
    let cfg = ArchiveConfig {
        erasure: Some(ErasureCodeConfig::new(2, 1)),
        ..Default::default()
    };

    let mut writer = ArchiveWriterBuilder::new(&archive)
        .password("v5-advrs-01")
        .config(cfg)
        .volume_count(3)
        .build()
        .await
        .unwrap();

    writer
        .add_file_with_path(&src.join("blob.bin"), Path::new("blob.bin"))
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&archive)
        .unwrap();
    use std::io::{Seek, SeekFrom, Write};
    // Corrupt the stripe-prefix length (now authoritative for data shards)
    // to verify the MAX_SHARD_SIZE cap still prevents unbounded allocation.
    file.seek(SeekFrom::Start(4224u64)).unwrap();
    file.write_all(&u32::MAX.to_le_bytes()).unwrap();

    let out = temp.path().join("out");
    fs::create_dir_all(&out).unwrap();
    let mut reader = ArchiveReader::open(&archive, "v5-advrs-01").await.unwrap();
    let extracted = timeout(
        Duration::from_secs(5),
        reader.extract_all(&ExtractOptions::new(&out).overwrite(true)),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "extraction timed out before surfacing shard-length cap error (pre-fix iterator/recovery behavior)"
        )
    });

    let msg = format!("{:?}", extracted.err());
    assert!(
        msg.contains("Shard size exceeds maximum"),
        "expected explicit shard-length cap error, got: {}",
        msg
    );
}

#[tokio::test]
async fn test_v5_advrs_02_extract_symlink_swap_rejected() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("file.txt"), b"content").unwrap();

    let archive = temp.path().join("v5_advrs_02.era");
    let mut writer = ArchiveWriterBuilder::new(&archive)
        .password("v5-advrs-02")
        .enable_erasure(false)
        .build()
        .await
        .unwrap();
    writer
        .add_file_with_path(&src.join("file.txt"), Path::new("dir/file.txt"))
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    let out = temp.path().join("out");
    fs::create_dir_all(&out).unwrap();
    let outside = temp.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, out.join("dir")).unwrap();

    let mut reader = ArchiveReader::open(&archive, "v5-advrs-02").await.unwrap();
    let result = reader.extract_all(&ExtractOptions::new(&out)).await;
    let msg = format!("{:?}", result.err());
    assert!(
        msg.contains("Symlink") || msg.contains("outside output directory"),
        "expected extraction-time symlink rejection, got: {}",
        msg
    );
}

#[tokio::test]
async fn test_v5_advrs_03_session_erasure_one_volume_exhausted_recovery_still_succeeds() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    let payload = vec![0x5Au8; 384 * 1024];
    fs::write(src.join("payload.bin"), &payload).unwrap();

    let archive = temp.path().join("v5_advrs_03.era");
    let cfg = ArchiveConfig {
        erasure: Some(ErasureCodeConfig::new(2, 1)),
        ..Default::default()
    };

    let mut writer = ArchiveWriterBuilder::new(&archive)
        .password("v5-advrs-03")
        .config(cfg)
        .volume_count(3)
        .build()
        .await
        .unwrap();

    writer
        .add_file_with_path(&src.join("payload.bin"), Path::new("payload.bin"))
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    let exhausted_volume = temp.path().join("v5_advrs_03.era.001");
    let exhausted = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&exhausted_volume)
        .unwrap();
    exhausted.set_len(4224).unwrap();

    let out = temp.path().join("out");
    fs::create_dir_all(&out).unwrap();
    let mut reader = ArchiveReader::open(&archive, "v5-advrs-03").await.unwrap();
    reader
        .extract_all(&ExtractOptions::new(&out).overwrite(true))
        .await
        .unwrap();

    let recovered = fs::read(out.join("payload.bin")).unwrap();
    assert_eq!(recovered, payload);
}

#[tokio::test]
async fn test_v5_depth_01_chunk_idx_bounds() {
    let mut ctx = ExtractionContext::new();
    let temp = TempDir::new().unwrap();
    let canonical_root = fs::canonicalize(temp.path()).unwrap();
    ctx.set_canonical_output_dir(canonical_root);
    let file_path = temp.path().join("chunked.bin");
    fs::write(&file_path, vec![0u8; 8]).unwrap();

    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .unwrap();

    ctx.multi_chunk_files.insert(
        1,
        MultiChunkState {
            file,
            output_path: file_path,
            expected_size: 8,
            chunks_written: vec![false],
            total_chunks: 1,
            written_count: 0,
        },
    );

    let hash = ChunkHash::from_bytes([0xAB; 32]);
    ctx.chunk_to_files.insert(hash, vec![(1, 7, 0)]);

    let mut stats = ExtractStats::default();
    let result = ctx.process_chunks(
        vec![(hash, bytes::Bytes::from_static(b"data"))].into(),
        &mut stats,
    );

    assert!(
        result.is_err(),
        "expected out-of-range chunk index to return error"
    );
    let msg = format!("{:?}", result.err());
    assert!(
        msg.contains("out of bounds") && msg.contains("chunked.bin"),
        "expected bounded chunk index error context, got: {}",
        msg
    );
}

#[tokio::test]
async fn test_v5_depth_02_secondary_chunk_write_containment() {
    let mut ctx = ExtractionContext::new();
    let temp = TempDir::new().unwrap();
    let extraction_root = temp.path().join("out");
    fs::create_dir_all(&extraction_root).unwrap();
    let canonical_root = fs::canonicalize(&extraction_root).unwrap();
    ctx.set_canonical_output_dir(canonical_root);
    let outside = temp.path().join("outside.txt");

    let hash = ChunkHash::from_bytes([0xCD; 32]);
    ctx.single_chunk_pending
        .insert(hash, vec![(0usize, outside.clone())]);

    let mut stats = ExtractStats::default();
    let result = ctx.process_chunks(
        vec![(hash, bytes::Bytes::from_static(b"escape"))].into(),
        &mut stats,
    );

    assert!(
        result.is_err(),
        "expected direct chunk write path to reject outside target"
    );
    let msg = format!("{:?}", result.err());
    assert!(
        msg.contains("outside output directory") || msg.contains("Absolute extraction target"),
        "expected containment error at write time, got: {}",
        msg
    );
    assert!(
        !outside.exists(),
        "containment rejection should prevent creating outside target"
    );
}

#[tokio::test]
async fn test_v5_trust_01_missing_catalog_writer_slot_is_error() {
    let temp = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp.path());
    let base = temp.path().join("v5_trust_01.era");

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
    let mut stage = v5_volume_stage::VolumeStage::new(pool);

    let catalog_block = EncryptedMacroBlock {
        block_id: BlockId::new(7),
        data: Bytes::from(vec![0xAA; 256]),
        original_size: 256,
        compressed_size: 256,
        chunk_count: 1,
    };

    let initial_locations = stage
        .write_catalog_to_all(&catalog_block, None)
        .await
        .unwrap();
    assert_eq!(
        initial_locations.len(),
        2,
        "happy-path fanout should write catalog to every configured volume"
    );
    assert!(
        initial_locations
            .iter()
            .all(|(_, _, logical_block_id)| *logical_block_id == 7),
        "catalog fanout must preserve logical block_id override semantics"
    );
    stage.finalize(&initial_locations, None).await.unwrap();

    let second_attempt = stage.write_catalog_to_all(&catalog_block, None).await;
    assert!(
        second_attempt.is_err(),
        "missing catalog writer slots should be a hard error, got: {:?}",
        second_attempt
    );
}

#[tokio::test]
async fn test_v5_v2_qual_16_memory_chunk_index_capacity_enforced() {
    let idx = v5_chunk_index::MemoryChunkIndex::with_capacity(1);
    let loc0 = BlockLocation::single(VolumeId::new(), 0, 0, 16);
    let loc1 = BlockLocation::single(VolumeId::new(), 1, 16, 16);

    idx.put(ChunkHash::from_bytes([1u8; 32]), loc0).unwrap();
    let second = idx.put(ChunkHash::from_bytes([2u8; 32]), loc1);

    assert!(
        second.is_err(),
        "with_capacity(1) must reject second unique insert"
    );
}
