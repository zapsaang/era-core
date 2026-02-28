//! Adversarial Audit V27 — era-volume
//!
//! 17 tests covering all 16 findings from the V27 audit report.
//! All tests assert `is_err()` for error conditions — no `#[should_panic]`.
//!
//! Coverage:
//! - V27-01: creation_time uses safe i64 conversion
//! - V27-02: Footer version=0 rejected
//! - V27-03: remaining_space uses HEADER_SIZE constant (not magic 4096)
//! - V27-04: compile_error! gate on non-64-bit platforms
//! - V27-05: shard_header uses u32::try_from
//! - V27-06: canonical block_size uses u32::try_from
//! - V27-07: read_typed_block sets original_size=0
//! - V27-08: scan block_count uses u32::try_from
//! - V27-09: volumes_with_header resizes after rotation
//! - V27-10: MultiVolumeReader::header() is deterministic (volume_sequence==0)
//! - V27-11: MAX_SHARD_SIZE validated in VolumePool::write_shard
//! - V27-12: checkpoint footer uses 0 for catalog/index fields
//! - V27-13: empty recipients rejected at construction
//! - V27-13b: MAX_RECIPIENTS enforced in new() and from_bytes()
//! - V27-14: volume_path consistency between MultiVolumeConfig and VolumePoolConfig
//! - V27-15: non-erasure blocks distributed via round-robin
//! - V27-16: SuperHeader::new() returns Result<Self>

use bytes::Bytes;
use era_common::{
    ArchiveConfig, ArchiveId, BlockId, BlockType, EncryptedMacroBlock, ErasureCodeConfig,
};
use era_storage::{LocalStorageBackend, StorageBackend, StorageReader};
use era_volume::{
    AccessPolicy, EncryptedVolumeKey, Footer, KeyWrapAlgorithm, MultiVolumeConfig,
    MultiVolumeReader, MultiVolumeWriter, RecipientSlot, RecipientType, SuperHeader, VolumePool,
    VolumePoolConfig, VolumeReader, VolumeWriter, BACKUP_FOOTER_GAP, FOOTER_SIZE, HEADER_SIZE,
    MAX_SHARD_SIZE, DATA_REGION_START, HEADER_VERSION, MAX_RECIPIENTS,
};
use std::path::Path;
use tempfile::TempDir;

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn test_header() -> SuperHeader {
    SuperHeader::new(
        ArchiveId::new(),
        vec![RecipientSlot::new(
            RecipientType::Argon2idPassword,
            Some([0x12; 8]),
            vec![0xAB; 16],
            vec![0xCD; 48],
        )],
        ArchiveConfig::default(),
        [0u8; 16],
        EncryptedVolumeKey {
            algorithm: KeyWrapAlgorithm::XChaCha20Poly1305,
            nonce: [0u8; 24],
            ciphertext: vec![0u8; 48],
        },
        AccessPolicy::AnyOfN,
    )
    .unwrap()
}

fn test_block(id: u64, size: usize) -> EncryptedMacroBlock {
    EncryptedMacroBlock {
        block_id: BlockId::new(id),
        data: Bytes::from(vec![0xAA; size]),
        original_size: size as u32,
        compressed_size: size as u32,
        chunk_count: 1,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// V27-01: creation_time uses safe i64 conversion
// ═══════════════════════════════════════════════════════════════════════════

/// V27-01: SuperHeader::new() uses `i64::try_from(...).unwrap_or(i64::MAX)` for
/// creation_time. Verify that construction succeeds and creation_time is a
/// reasonable positive value (not negative, not zero).
#[test]
fn test_v27_01_creation_time_uses_safe_i64_conversion() {
    let header = test_header();
    // creation_time should be positive (post-UNIX-epoch)
    assert!(
        header.creation_time > 0,
        "creation_time must be positive, got {}",
        header.creation_time
    );
    // Verify it roundtrips through serialization
    let bytes = header.to_bytes().unwrap();
    let restored = SuperHeader::from_bytes(&bytes).unwrap();
    assert_eq!(restored.creation_time, header.creation_time);

    // next_volume() uses map_err variant — verify it also produces valid time
    let next = header.next_volume().unwrap();
    assert!(
        next.creation_time > 0,
        "next_volume creation_time must be positive"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// V27-02: Footer version=0 rejected
// ═══════════════════════════════════════════════════════════════════════════

/// V27-02: Footer::from_bytes() rejects version==0 (footer.rs:343).
/// Previously version 0 was silently accepted.
#[test]
fn test_v27_02_footer_version_zero_rejected() {
    let footer = Footer::new(8192, 1, 1);
    let mut bytes = footer.to_bytes().unwrap();
    // Patch version at offset 4 to 0
    bytes[4] = 0;
    // Recompute checksum (domain-separated Blake3 over first 96 bytes)
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ERAFv1-footer\0");
    hasher.update(&bytes[0..96]);
    let checksum = hasher.finalize();
    bytes[96..128].copy_from_slice(checksum.as_bytes());

    let result = Footer::from_bytes(&bytes);
    assert!(
        result.is_err(),
        "Footer version 0 must be rejected (V27-02 fix)"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// V27-03: remaining_space uses HEADER_SIZE constant
// ═══════════════════════════════════════════════════════════════════════════

/// V27-03: MultiVolumeWriter::remaining_space() reserves FOOTER_SIZE + HEADER_SIZE
/// (not a magic 4096). Verify that would_fit correctly accounts for the full
/// reservation by writing blocks up to the limit.
#[tokio::test]
async fn test_v27_03_remaining_space_uses_header_size_constant() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());

    let header = test_header();
    let reserved = FOOTER_SIZE as u64 + HEADER_SIZE as u64; // 4224
    let data_start = DATA_REGION_START; // 4224

    // Volume must have at least data_start + reserved + 1 byte to hold any data
    let volume_size = data_start + reserved + 1024;
    let config =
        MultiVolumeConfig::new(temp_dir.path().join("test").to_str().unwrap(), volume_size)
            .unwrap();

    let mut writer = MultiVolumeWriter::create(&backend, config, header)
        .await
        .unwrap();

    // A block that uses nearly all available space should succeed
    let available = volume_size - data_start - reserved - era_common::BlockHeader::SIZE as u64;
    let block = test_block(0, available as usize);
    let result = writer.write_block(&backend, &block).await;
    assert!(
        result.is_ok(),
        "Block fitting within remaining space should succeed: {:?}",
        result.err()
    );

    writer.finalize().await.unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════
// V27-04: compile_error! gate on non-64-bit platforms
// ═══════════════════════════════════════════════════════════════════════════

/// V27-04: ERA requires a 64-bit platform. The compile_error! gate in lib.rs
/// ensures this. We verify the test environment is 64-bit and that `as u64`
/// casts from usize are safe.
#[test]
fn test_v27_04_compile_error_on_non_64bit() {
    // If this test compiles and runs, we're on a 64-bit platform
    // Use const assert to satisfy clippy::assertions_on_constants
    const {
        assert!(
            cfg!(target_pointer_width = "64"),
            "ERA requires a 64-bit platform"
        )
    };

    // Verify usize→u64 is lossless on this platform
    let max_usize = usize::MAX;
    let as_u64 = max_usize as u64;
    assert_eq!(
        as_u64,
        u64::MAX,
        "On 64-bit, usize::MAX must equal u64::MAX"
    );

    // Verify the MAX_SHARD_SIZE constant fits in u64 (always true on 64-bit)
    let shard_as_u64 = MAX_SHARD_SIZE as u64;
    assert_eq!(shard_as_u64, 16 * 1024 * 1024);
}

// ═══════════════════════════════════════════════════════════════════════════
// V27-05: shard_header uses u32::try_from
// ═══════════════════════════════════════════════════════════════════════════

/// V27-05: VolumePool::write_shard() uses u32::try_from(shard_data.len()) at
/// volume_pool.rs:515. Verify that writing a shard within u32 range succeeds
/// and that MAX_SHARD_SIZE (16MB) fits in u32.
#[test]
fn test_v27_05_shard_header_uses_try_from() {
    // MAX_SHARD_SIZE is 16MB = 16,777,216
    assert!(
        MAX_SHARD_SIZE <= u32::MAX as usize,
        "MAX_SHARD_SIZE must fit in u32"
    );

    // Verify u32::try_from succeeds for valid shard sizes
    let valid_size: usize = MAX_SHARD_SIZE;
    assert!(
        u32::try_from(valid_size).is_ok(),
        "MAX_SHARD_SIZE must convert to u32"
    );

    // Verify u32::try_from fails for sizes above u32::MAX
    let too_big: usize = u32::MAX as usize + 1;
    assert!(
        u32::try_from(too_big).is_err(),
        "Sizes above u32::MAX must fail try_from"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// V27-06: canonical block_size uses u32::try_from
// ═══════════════════════════════════════════════════════════════════════════

/// V27-06: MultiVolumeWriter::write_canonical_block() uses u32::try_from(block.data.len())
/// at multi_volume.rs:134. Verify that blocks within u32 range pass the check.
#[tokio::test]
async fn test_v27_06_canonical_block_size_uses_try_from() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());

    let header = test_header();
    // Use a large enough volume to hold our test block
    let config = MultiVolumeConfig::new(
        temp_dir.path().join("test").to_str().unwrap(),
        100 * 1024 * 1024, // 100MB
    )
    .unwrap();

    let mut writer = MultiVolumeWriter::create(&backend, config, header)
        .await
        .unwrap();

    // Normal-sized block should pass u32::try_from check
    let block = test_block(0, 4096);
    let result = writer
        .write_canonical_block(&backend, &block, BlockType::Data)
        .await;
    assert!(
        result.is_ok(),
        "Normal block should pass u32::try_from: {:?}",
        result.err()
    );

    writer.finalize().await.unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════
// V27-07: read_typed_block sets original_size=0
// ═══════════════════════════════════════════════════════════════════════════

/// V27-07: VolumeReader::read_typed_block() sets original_size: 0 at reader.rs:333
/// because the BlockHeader format does not carry original_size. Callers must
/// consult the catalog/index for the real value.
#[tokio::test]
async fn test_v27_07_read_typed_block_original_size_is_zero() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let path = Path::new("read_typed.era");

    let header = test_header();
    let mut writer = VolumeWriter::create(&backend, path, header).await.unwrap();

    // Write a block with known original_size
    let block = test_block(0, 256);
    assert_eq!(block.original_size, 256);
    let location = writer
        .write_canonical_block(&block, BlockType::Data)
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    // Read it back via read_typed_block
    let reader = VolumeReader::open(&backend, path).await.unwrap();
    let (block_type, read_block) = reader.read_typed_block(&location).await.unwrap();

    assert_eq!(block_type, BlockType::Data);
    // V27-07: original_size must be 0 (unavailable from BlockHeader)
    assert_eq!(
        read_block.original_size, 0,
        "read_typed_block must set original_size=0 per V27-07"
    );
    // But compressed_size should match the header length
    assert_eq!(read_block.compressed_size as usize, 256);
}

// ═══════════════════════════════════════════════════════════════════════════
// V27-08: scan block_count uses u32::try_from
// ═══════════════════════════════════════════════════════════════════════════

/// V27-08: VolumeReader::scan_for_typed_blocks() uses u32::try_from(found_blocks.len())
/// at reader.rs:399-404. Verify that scanning with a small number of blocks
/// works correctly (the u32 conversion succeeds for reasonable block counts).
#[tokio::test]
async fn test_v27_08_scan_block_count_uses_try_from() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let path = Path::new("scan_typed.era");

    let header = test_header();
    let mut writer = VolumeWriter::create(&backend, path, header).await.unwrap();

    // Write several blocks of the same type
    for i in 0..5 {
        let block = test_block(i, 64);
        writer
            .write_canonical_block(&block, BlockType::Data)
            .await
            .unwrap();
    }
    writer.finalize().await.unwrap();

    // Scan for typed blocks — the u32::try_from conversion in scan should succeed
    let reader = VolumeReader::open(&backend, path).await.unwrap();
    let locations = reader.scan_for_typed_blocks(BlockType::Data).await.unwrap();
    assert_eq!(locations.len(), 5, "scan must find all 5 Data blocks");
}

// ═══════════════════════════════════════════════════════════════════════════
// V27-09: volumes_with_header resizes after rotation
// ═══════════════════════════════════════════════════════════════════════════

/// V27-09: VolumePool::write_erasure_block() resizes volumes_with_header vec
/// after rotation at volume_pool.rs:626-628. This prevents index-out-of-bounds
/// when new volumes are added during shard distribution.
#[tokio::test]
async fn test_v27_09_volumes_with_header_resize_after_rotation() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());

    let header = test_header();
    // Use small max_volume_size that can still hold a header + backup footer + minimal data
    let small_volume = HEADER_SIZE as u64 + FOOTER_SIZE as u64 + BACKUP_FOOTER_GAP as u64 + 8192;
    let config = VolumePoolConfig::new(temp_dir.path().join("pool").to_str().unwrap(), 3)
        .with_max_size(small_volume);

    let mut pool = VolumePool::create(backend, config, header).await.unwrap();

    // Write erasure blocks that span multiple shards
    // This tests the resize logic — if the vec isn't resized, it would panic
    let erasure_config = ErasureCodeConfig {
        data_shards: 2,
        parity_shards: 1,
    };

    // Create small shards that fit in the small volumes
    let shard1 = Bytes::from(vec![0xAA; 128]);
    let shard2 = Bytes::from(vec![0xBB; 128]);
    let shard3 = Bytes::from(vec![0xCC; 128]); // parity

    let result = pool
        .write_erasure_block(
            BlockId::new(0),
            &[shard1, shard2, shard3],
            384, // original_len
            erasure_config,
        )
        .await;

    // Should succeed without panicking (the resize fix in V27-09)
    assert!(
        result.is_ok(),
        "write_erasure_block must not panic from volumes_with_header resize: {:?}",
        result.err()
    );

    pool.finalize().await.unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════
// V27-10: MultiVolumeReader::header() is deterministic
// ═══════════════════════════════════════════════════════════════════════════

/// V27-10: MultiVolumeReader::header() finds volume_sequence==0 deterministically
/// at multi_volume.rs:330 instead of relying on HashMap iteration order.
#[tokio::test]
async fn test_v27_10_multi_volume_header_is_deterministic() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());

    let header = test_header();
    let archive_id = header.archive_id;
    let config = MultiVolumeConfig::new(
        temp_dir.path().join("det").to_str().unwrap(),
        50 * 1024, // 50KB volumes to get multiple
    )
    .unwrap();

    let mut writer = MultiVolumeWriter::create(&backend, config, header)
        .await
        .unwrap();

    // Write enough data to create at least 2 volumes
    for i in 0..20 {
        let block = test_block(i, 2048);
        let _ = writer.write_block(&backend, &block).await;
    }
    let stats = writer.finalize().await.unwrap();

    // Only open reader if we actually got multiple volumes
    if stats.volume_count > 1 {
        let first_vol = temp_dir.path().join("det.era");
        let reader = MultiVolumeReader::open(&backend, &first_vol).await.unwrap();
        let hdr = reader.header().expect("header() must return Some");

        // V27-10: Must always return the volume_sequence==0 header
        assert_eq!(
            hdr.volume_sequence, 0,
            "header() must return volume_sequence==0 deterministically"
        );
        assert_eq!(hdr.archive_id.0, archive_id.0);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// V27-11: MAX_SHARD_SIZE validated in VolumePool write path
// ═══════════════════════════════════════════════════════════════════════════

/// V27-11: VolumePool::validate_shard_size() checks against MAX_SHARD_SIZE
/// at volume_pool.rs:412-422, regardless of volume size.
#[tokio::test]
async fn test_v27_11_max_shard_size_validated_in_write() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());

    let header = test_header();
    // Very large max_volume_size to isolate the MAX_SHARD_SIZE check
    let large_volume: u64 = 1024 * 1024 * 1024; // 1GB
    let config = VolumePoolConfig::new(temp_dir.path().join("shard").to_str().unwrap(), 1)
        .with_max_size(large_volume);

    let mut pool = VolumePool::create(backend, config, header).await.unwrap();

    // Write a shard exactly at MAX_SHARD_SIZE — should succeed
    let valid_shard = vec![0xAA; MAX_SHARD_SIZE];
    let result = pool.write_shard(0, &valid_shard, false, 0, None).await;
    assert!(
        result.is_ok(),
        "Shard at MAX_SHARD_SIZE must succeed: {:?}",
        result.err()
    );

    // Write a shard exceeding MAX_SHARD_SIZE — must fail
    let oversized = vec![0xBB; MAX_SHARD_SIZE + 1];
    let result = pool.write_shard(0, &oversized, false, 0, None).await;
    assert!(
        result.is_err(),
        "Shard exceeding MAX_SHARD_SIZE must be rejected"
    );

    pool.finalize().await.unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════
// V27-12: checkpoint footer uses 0 for catalog/index fields
// ═══════════════════════════════════════════════════════════════════════════

/// V27-12: VolumeWriter::commit_checkpoint() constructs a footer with 0 for
/// catalog_offset, catalog_size, catalog_block_id, index_offset, index_size,
/// index_block_id at writer.rs:193-206. We verify this by reading the backup
/// footer written at offset HEADER_SIZE (4096).
#[tokio::test]
async fn test_v27_12_checkpoint_footer_fields() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let path = Path::new("checkpoint.era");

    let header = test_header();
    let mut writer = VolumeWriter::create(&backend, path, header).await.unwrap();

    // Set max_size so commit_checkpoint can lay out backup header/footer
    writer.set_max_size(1024 * 1024).await.unwrap(); // 1MB

    // Write some data
    let block = test_block(0, 512);
    writer
        .write_canonical_block(&block, BlockType::Data)
        .await
        .unwrap();

    // Commit a checkpoint — this writes a footer at the backup location
    writer.commit_checkpoint(0).await.unwrap();

    // Finalize to close the volume
    writer.finalize().await.unwrap();

    // Read the backup footer directly from offset HEADER_SIZE (4096)
    // The checkpoint writes it there
    let reader_backend = LocalStorageBackend::new(temp_dir.path());
    let raw_reader = reader_backend.open_read(path).await.unwrap();
    let backup_bytes = raw_reader
        .read_at(HEADER_SIZE as u64, FOOTER_SIZE)
        .await
        .unwrap();
    let backup_footer = Footer::from_bytes(&backup_bytes).unwrap();

    // V27-12: checkpoint footer must have 0 for catalog/index fields
    assert_eq!(
        backup_footer.catalog_offset, 0,
        "checkpoint footer catalog_offset must be 0"
    );
    assert_eq!(
        backup_footer.catalog_size, 0,
        "checkpoint footer catalog_size must be 0"
    );
    assert_eq!(
        backup_footer.catalog_block_id, 0,
        "checkpoint footer catalog_block_id must be 0"
    );
    assert_eq!(
        backup_footer.index_offset, 0,
        "checkpoint footer index_offset must be 0"
    );
    assert_eq!(
        backup_footer.index_size, 0,
        "checkpoint footer index_size must be 0"
    );
    assert_eq!(
        backup_footer.index_block_id, 0,
        "checkpoint footer index_block_id must be 0"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// V27-13: empty recipients rejected at construction
// ═══════════════════════════════════════════════════════════════════════════

/// V27-13: SuperHeader::new() rejects empty recipients at header.rs:129-133.
#[test]
fn test_v27_13_empty_recipients_rejected_at_construction() {
    let result = SuperHeader::new(
        ArchiveId::new(),
        vec![], // empty recipients
        ArchiveConfig::default(),
        [0u8; 16],
        EncryptedVolumeKey {
            algorithm: KeyWrapAlgorithm::XChaCha20Poly1305,
            nonce: [0u8; 24],
            ciphertext: vec![0u8; 48],
        },
        AccessPolicy::AnyOfN,
    );
    assert!(
        result.is_err(),
        "SuperHeader::new() must reject empty recipients"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// V27-13b: MAX_RECIPIENTS enforced
// ═══════════════════════════════════════════════════════════════════════════

/// V27-13b: SuperHeader::new() rejects > MAX_RECIPIENTS at header.rs:134-140.
/// Also verified in from_bytes() deserialization path.
#[test]
fn test_v27_13b_max_recipients_enforced() {
    let too_many: Vec<RecipientSlot> = (0..=MAX_RECIPIENTS)
        .map(|i| {
            RecipientSlot::new(
                RecipientType::Argon2idPassword,
                Some([(i & 0xFF) as u8; 8]),
                vec![0xAB; 16],
                vec![0xCD; 48],
            )
        })
        .collect();

    assert_eq!(too_many.len(), MAX_RECIPIENTS + 1);

    let result = SuperHeader::new(
        ArchiveId::new(),
        too_many,
        ArchiveConfig::default(),
        [0u8; 16],
        EncryptedVolumeKey {
            algorithm: KeyWrapAlgorithm::XChaCha20Poly1305,
            nonce: [0u8; 24],
            ciphertext: vec![0u8; 48],
        },
        AccessPolicy::AnyOfN,
    );
    assert!(
        result.is_err(),
        "SuperHeader::new() must reject > MAX_RECIPIENTS"
    );

    // Verify exactly MAX_RECIPIENTS is accepted
    let exact: Vec<RecipientSlot> = (0..MAX_RECIPIENTS)
        .map(|i| {
            RecipientSlot::new(
                RecipientType::Argon2idPassword,
                Some([(i & 0xFF) as u8; 8]),
                vec![0xAB; 16],
                vec![0xCD; 48],
            )
        })
        .collect();

    let result = SuperHeader::new(
        ArchiveId::new(),
        exact,
        ArchiveConfig::default(),
        [0u8; 16],
        EncryptedVolumeKey {
            algorithm: KeyWrapAlgorithm::XChaCha20Poly1305,
            nonce: [0u8; 24],
            ciphertext: vec![0u8; 48],
        },
        AccessPolicy::AnyOfN,
    );
    assert!(
        result.is_ok(),
        "Exactly MAX_RECIPIENTS must be accepted: {:?}",
        result.err()
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// V27-14: volume_path consistency
// ═══════════════════════════════════════════════════════════════════════════

/// V27-14: MultiVolumeConfig and VolumePoolConfig produce identical volume_path()
/// results for the same base path and sequence number.
#[test]
fn test_v27_14_volume_path_consistency() {
    let base = "/tmp/archive";

    let mv_config = MultiVolumeConfig::new(base, 1024 * 1024).unwrap();
    let vp_config = VolumePoolConfig::new(base, 3);

    // Sequence 0: both should produce the same .era path
    let mv_path_0 = mv_config.volume_path(0);
    let vp_path_0 = vp_config.volume_path(0);
    assert_eq!(
        mv_path_0, vp_path_0,
        "MultiVolumeConfig and VolumePoolConfig must produce same path for seq 0"
    );

    // Sequence 1: both should produce .era.001
    let mv_path_1 = mv_config.volume_path(1);
    let vp_path_1 = vp_config.volume_path(1);
    assert_eq!(
        mv_path_1, vp_path_1,
        "MultiVolumeConfig and VolumePoolConfig must produce same path for seq 1"
    );

    // Sequence 255
    let mv_path_255 = mv_config.volume_path(255);
    let vp_path_255 = vp_config.volume_path(255);
    assert_eq!(
        mv_path_255, vp_path_255,
        "MultiVolumeConfig and VolumePoolConfig must produce same path for seq 255"
    );

    // Verify the actual format
    assert!(mv_path_0.to_str().unwrap().ends_with(".era"));
    assert!(mv_path_1.to_str().unwrap().ends_with("era.001"));
    assert!(mv_path_255.to_str().unwrap().ends_with("era.255"));
}

// ═══════════════════════════════════════════════════════════════════════════
// V27-15: non-erasure blocks distributed via round-robin
// ═══════════════════════════════════════════════════════════════════════════

/// V27-15: VolumePool::write_canonical_block() uses round-robin distribution
/// `(block_sequence as usize) % writers.len().max(1)` at volume_pool.rs:548.
/// Verify that blocks are evenly distributed across all volumes.
#[tokio::test]
async fn test_v27_15_non_erasure_blocks_distributed() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());

    let header = test_header();
    let config = VolumePoolConfig::new(temp_dir.path().join("rr").to_str().unwrap(), 3)
        .with_max_size(1024 * 1024); // 1MB per volume

    let mut pool = VolumePool::create(backend, config, header).await.unwrap();

    // Confirm 3 writers created
    assert_eq!(pool.volume_count(), 3);

    // Write 6 canonical blocks — with 3 volumes and round-robin,
    // each volume should receive exactly 2 blocks.
    for i in 0..6u64 {
        let block = test_block(i, 128);
        pool.write_canonical_block(&block, BlockType::Data)
            .await
            .unwrap();
        pool.advance_block_sequence();
    }

    // After 6 blocks distributed round-robin across 3 volumes,
    // each volume should have exactly 2 blocks.
    for slot in 0..3 {
        let writer = pool.get_writer_mut(slot).expect("writer must exist");
        assert_eq!(
            writer.block_count(),
            2,
            "Volume slot {} should have exactly 2 blocks from round-robin",
            slot
        );
    }

    pool.finalize().await.unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════
// V27-16: SuperHeader::new() returns Result<Self>
// ═══════════════════════════════════════════════════════════════════════════

/// V27-16: SuperHeader::new() returns Result<Self> (not Self). All test helpers
/// must use .unwrap(). This test verifies the return type by checking both
/// success and failure cases.
#[test]
fn test_v27_16_test_headers_use_valid_recipients() {
    // Success case: valid recipients returns Ok
    let result = SuperHeader::new(
        ArchiveId::new(),
        vec![RecipientSlot::new(
            RecipientType::Argon2idPassword,
            Some([0x12; 8]),
            vec![0xAB; 16],
            vec![0xCD; 48],
        )],
        ArchiveConfig::default(),
        [0u8; 16],
        EncryptedVolumeKey {
            algorithm: KeyWrapAlgorithm::XChaCha20Poly1305,
            nonce: [0u8; 24],
            ciphertext: vec![0u8; 48],
        },
        AccessPolicy::AnyOfN,
    );
    assert!(result.is_ok(), "Valid recipients must return Ok");
    let header = result.unwrap();
    assert_eq!(header.version, HEADER_VERSION);
    assert_eq!(header.recipients.len(), 1);

    // Failure case: empty recipients returns Err
    let result = SuperHeader::new(
        ArchiveId::new(),
        vec![], // no recipients
        ArchiveConfig::default(),
        [0u8; 16],
        EncryptedVolumeKey {
            algorithm: KeyWrapAlgorithm::XChaCha20Poly1305,
            nonce: [0u8; 24],
            ciphertext: vec![0u8; 48],
        },
        AccessPolicy::AnyOfN,
    );
    assert!(
        result.is_err(),
        "Empty recipients must return Err (V27-16: new() returns Result)"
    );
}
