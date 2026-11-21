use era_common::{ArchiveConfig, CompressionAlgorithm, EraError};
use era_engine::{ArchiveReader, ArchiveWriter, ExtractOptions};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use tempfile::TempDir;

const PASSWORD: &str = "bounded-fd-extraction-test";

fn fast_non_ec_config() -> ArchiveConfig {
    let mut config = ArchiveConfig {
        erasure: None,
        ..Default::default()
    };
    config.encryption.kdf_memory_cost = 1024;
    config.encryption.kdf_time_cost = 1;
    config.compression.algorithm = CompressionAlgorithm::None;
    config
}

fn payload_for(index: usize, len: usize) -> Vec<u8> {
    let seed = format!("bounded-fd-payload-{index:04}");
    let mut out = vec![0u8; len];
    let mut xof = blake3::Hasher::new();
    xof.update(seed.as_bytes());
    xof.finalize_xof().fill(&mut out);
    out
}

#[tokio::test]
async fn extract_over_1100_single_chunk_files_within_default_fd_limit() {
    const FILE_COUNT: usize = 1150;
    let temp = TempDir::new().unwrap();
    let archive_path = temp.path().join("single_chunks_1150.era");

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(fast_non_ec_config())
        .enable_erasure(false)
        .enable_cdc(false)
        .enable_small_file_packing(false)
        .build()
        .await
        .unwrap();

    let mut expected = Vec::with_capacity(FILE_COUNT);
    for idx in 0..FILE_COUNT {
        let name = format!("dir_{:02}/single_{idx:04}.bin", idx / 50);
        let data = payload_for(idx, 96);
        writer.add_bytes(&name, &data).await.unwrap();
        expected.push((name, data));
    }
    writer.finalize().await.unwrap();

    let out_dir = temp.path().join("out");
    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    let stats = reader
        .extract_all(&ExtractOptions::new(&out_dir))
        .await
        .unwrap();
    assert_eq!(stats.extracted, FILE_COUNT as u64);

    for (name, bytes) in &expected {
        assert_eq!(fs::read(out_dir.join(name)).unwrap(), *bytes);
    }
}

#[tokio::test]
async fn extract_over_1100_multi_chunk_files_within_default_fd_limit() {
    const FILE_COUNT: usize = 1150;
    let temp = TempDir::new().unwrap();
    let archive_path = temp.path().join("multi_chunks_1150.era");

    let mut config = fast_non_ec_config();
    config.block.target_size = 64;

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(config)
        .target_block_size(64)
        .enable_erasure(false)
        .enable_cdc(false)
        .enable_small_file_packing(false)
        .build()
        .await
        .unwrap();

    let mut expected = Vec::with_capacity(FILE_COUNT);
    for idx in 0..FILE_COUNT {
        let name = format!("group_{:02}/multi_{idx:04}.bin", idx / 50);
        // 160 bytes > target_block_size(64) -> split into 3 chunks per file
        let data = payload_for(idx + 10_000, 160);
        writer.add_bytes(&name, &data).await.unwrap();
        expected.push((name, data));
    }
    writer.finalize().await.unwrap();

    let out_dir = temp.path().join("out");
    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    let catalog = reader.load_catalog().await.unwrap();
    assert_eq!(catalog.entries.len(), FILE_COUNT);
    assert!(
        catalog.entries.iter().all(|entry| entry.chunks.len() == 3),
        "each file must span multiple chunks to exercise multi-chunk extraction"
    );

    let stats = reader
        .extract_all(&ExtractOptions::new(&out_dir))
        .await
        .unwrap();
    assert_eq!(stats.extracted, FILE_COUNT as u64);

    for (name, bytes) in &expected {
        assert_eq!(fs::read(out_dir.join(name)).unwrap(), *bytes);
    }
}

#[tokio::test]
async fn extract_multi_chunk_failure_cleans_up_created_files() {
    let temp = TempDir::new().unwrap();
    let archive_path = temp.path().join("partial_failure.era");

    let mut config = fast_non_ec_config();
    config.block.target_size = 64;

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(config)
        .target_block_size(64)
        .enable_erasure(false)
        .enable_cdc(false)
        .enable_small_file_packing(false)
        .build()
        .await
        .unwrap();

    // Use small flush threshold / multiple blocks so block 0 finishes and block 1 is corrupted.
    let first = payload_for(1, 160);
    let second = payload_for(2, 160);
    writer.add_bytes("first.bin", &first).await.unwrap();
    writer.add_bytes("second.bin", &second).await.unwrap();
    writer.finalize().await.unwrap();

    // Corrupt the second data block so extraction succeeds on first block then fails on second.
    let reader_probe = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    let mut archive_probe = reader_probe;
    let catalog = archive_probe.load_catalog().await.unwrap().clone();
    assert!(
        catalog.block_locations.len() >= 2,
        "need at least two data blocks to test mid-extraction cleanup"
    );
    let second_loc = catalog.block_locations.last().unwrap().clone();
    drop(archive_probe);

    {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&archive_path)
            .unwrap();
        let corrupt_offset = second_loc.physical_offset + era_common::BlockHeader::SIZE as u64 + 28;
        file.seek(SeekFrom::Start(corrupt_offset)).unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0xFF;
        file.seek(SeekFrom::Start(corrupt_offset)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
    }

    let out_dir = temp.path().join("out");
    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    let err = reader
        .extract_all(&ExtractOptions::new(&out_dir))
        .await
        .expect_err("corrupted second block must abort extraction");
    assert!(
        matches!(err, EraError::ErasureError(_) | EraError::IntegrityError(_)),
        "unexpected error variant: {err:?}"
    );
    assert!(
        !out_dir.join("first.bin").exists() && !out_dir.join("second.bin").exists(),
        "partially extracted multi-chunk files must be cleaned up on failure"
    );
}

#[cfg(unix)]
#[allow(dead_code)]
#[path = "../src/chunk_processor.rs"]
mod test_chunk_processor;

#[cfg(unix)]
#[test]
fn lazy_multi_chunk_evicted_handle_rejects_symlink_and_inode_swap() {
    use bytes::Bytes;
    use era_common::ChunkHash;
    use test_chunk_processor::{ExtractStats, ExtractionContext};

    let temp = TempDir::new().unwrap();

    // Case A: Evicted lazy handle replaced with a symlink to an external file.
    {
        let out_dir = temp.path().join("out_symlink");
        fs::create_dir_all(&out_dir).unwrap();
        let outside = temp.path().join("outside_secret.txt");
        fs::write(&outside, b"do not clobber").unwrap();

        let mut ctx = ExtractionContext::new();
        ctx.set_canonical_output_dir(fs::canonicalize(&out_dir).unwrap());
        ctx.set_overwrite(false);

        let mut first_chunks = Vec::with_capacity(65);
        let mut target_second_hash = ChunkHash::from_bytes([0u8; 32]);
        for idx in 0..65usize {
            let mut h0 = [0u8; 32];
            h0[..8].copy_from_slice(&(idx as u64).to_le_bytes());
            let mut h1 = [0u8; 32];
            h1[..8].copy_from_slice(&((idx + 1000) as u64).to_le_bytes());
            let ch0 = ChunkHash::from_bytes(h0);
            let ch1 = ChunkHash::from_bytes(h1);
            if idx == 0 {
                target_second_hash = ch1;
            }
            ctx.register_multi_chunk_file(idx, out_dir.join(format!("file_{idx:03}.bin")), 8, 2);
            ctx.chunk_to_files.insert(ch0, vec![(idx, 0, 0)]);
            ctx.chunk_to_files.insert(ch1, vec![(idx, 1, 4)]);
            first_chunks.push((ch0, Bytes::from_static(b"AAAA")));
        }

        let mut stats = ExtractStats::default();
        ctx.process_chunks(first_chunks.into(), &mut stats).unwrap();

        let swapped_path = out_dir.join("file_000.bin");
        fs::remove_file(&swapped_path).unwrap();
        std::os::unix::fs::symlink(&outside, &swapped_path).unwrap();

        let err = ctx
            .process_chunks(
                vec![(target_second_hash, Bytes::from_static(b"BBBB"))].into(),
                &mut stats,
            )
            .expect_err("reopening evicted handle replaced by symlink must fail with Security");
        assert!(
            matches!(err, EraError::Security(_)),
            "expected EraError::Security, got {err:?}"
        );
        assert_eq!(fs::read(&outside).unwrap(), b"do not clobber");
    }

    // Case B: Evicted lazy handle replaced with a different regular file inode.
    {
        let out_dir = temp.path().join("out_inode");
        fs::create_dir_all(&out_dir).unwrap();

        let mut ctx = ExtractionContext::new();
        ctx.set_canonical_output_dir(fs::canonicalize(&out_dir).unwrap());
        ctx.set_overwrite(false);

        let mut first_chunks = Vec::with_capacity(65);
        let mut target_second_hash = ChunkHash::from_bytes([0u8; 32]);
        for idx in 0..65usize {
            let mut h0 = [0u8; 32];
            h0[..8].copy_from_slice(&((idx + 2000) as u64).to_le_bytes());
            let mut h1 = [0u8; 32];
            h1[..8].copy_from_slice(&((idx + 3000) as u64).to_le_bytes());
            let ch0 = ChunkHash::from_bytes(h0);
            let ch1 = ChunkHash::from_bytes(h1);
            if idx == 0 {
                target_second_hash = ch1;
            }
            ctx.register_multi_chunk_file(idx, out_dir.join(format!("file_{idx:03}.bin")), 8, 2);
            ctx.chunk_to_files.insert(ch0, vec![(idx, 0, 0)]);
            ctx.chunk_to_files.insert(ch1, vec![(idx, 1, 4)]);
            first_chunks.push((ch0, Bytes::from_static(b"AAAA")));
        }

        let mut stats = ExtractStats::default();
        ctx.process_chunks(first_chunks.into(), &mut stats).unwrap();

        let swapped_path = out_dir.join("file_000.bin");
        fs::remove_file(&swapped_path).unwrap();
        fs::write(&swapped_path, b"decoy-inode").unwrap();

        let err = ctx
            .process_chunks(
                vec![(target_second_hash, Bytes::from_static(b"BBBB"))].into(),
                &mut stats,
            )
            .expect_err(
                "reopening evicted handle replaced by another inode must fail with Security",
            );
        assert!(
            matches!(err, EraError::Security(_)),
            "expected EraError::Security, got {err:?}"
        );
        assert_eq!(fs::read(&swapped_path).unwrap(), b"decoy-inode");
    }
}

async fn rewrite_archive_catalog(
    archive_path: &std::path::Path,
    mutator: impl FnOnce(&mut era_ingest::Catalog),
) {
    use era_common::{compute_shard_crc, BlockHeader, BlockId, BlockType, UniqueChunk};
    use era_crypto::{
        build_aad, compute_catalog_commitment, derive_nonce_with_volume_index, AeadContext,
        XChaCha20Poly1305Context, NONCE_SIZE,
    };
    use era_packing::SessionBlockBuilder;
    use era_volume::{Footer, SuperHeader, FOOTER_SIZE, HEADER_SIZE};

    let bytes = fs::read(archive_path).unwrap();
    let header_bytes = bytes[..HEADER_SIZE].to_vec();
    let header = SuperHeader::from_bytes(&header_bytes).unwrap();
    let footer = Footer::from_bytes(&bytes[bytes.len() - FOOTER_SIZE..]).unwrap();

    let mut reader = ArchiveReader::open(archive_path, PASSWORD).await.unwrap();
    let mut catalog = reader.load_catalog().await.unwrap().clone();
    let mut manifest = reader.manifest().unwrap().clone();

    mutator(&mut catalog);
    let new_catalog_bytes = catalog.to_bytes().unwrap();
    manifest.catalog_commitment = compute_catalog_commitment(&new_catalog_bytes);
    manifest.index_commitment = [0u8; 32];

    let mut framed_catalog = Vec::with_capacity(12 + new_catalog_bytes.len());
    framed_catalog.extend_from_slice(&1u32.to_le_bytes());
    framed_catalog.extend_from_slice(&(new_catalog_bytes.len() as u64).to_le_bytes());
    framed_catalog.extend_from_slice(&new_catalog_bytes);

    let cat_block = SessionBlockBuilder::new(
        reader.session(),
        reader.volume_key(),
        *header.salt(),
        *header.archive_id().0.as_bytes(),
        header.epoch_id(),
        0,
        Box::new(era_codec::NoCompressor),
    )
    .with_starting_block_id(u64::from(footer.catalog_block_id()))
    .pack_single_with_type(
        UniqueChunk::new(
            bytes::Bytes::from(framed_catalog.clone()),
            era_crypto::hash(&framed_catalog),
        ),
        BlockType::Catalog,
    )
    .unwrap();

    let cat_offset = usize::try_from(footer.catalog_offset()).unwrap();
    let cat_len = u32::try_from(cat_block.data.len()).unwrap();
    let cat_hdr = BlockHeader::new(
        BlockType::Catalog,
        cat_len,
        compute_shard_crc(&cat_block.data),
    );

    let man_offset = cat_offset + BlockHeader::SIZE + cat_block.data.len();
    let header_digest = [*blake3::hash(&header_bytes).as_bytes()];
    let man_block_id = BlockId::new(u64::from(footer.manifest_block_id()));
    let man_key = reader
        .session()
        .derive_block_key(
            reader.volume_key(),
            u64::from(footer.manifest_block_id()),
            header.salt(),
        )
        .unwrap();
    drop(reader);
    let man_aead =
        XChaCha20Poly1305Context::from_derived_key(&man_key.to_derived_key().unwrap()).unwrap();
    let man_nonce = derive_nonce_with_volume_index(header.salt(), man_block_id, 0);
    let man_aad = build_aad(
        header.archive_id().0.as_bytes(),
        header.epoch_id(),
        BlockType::Manifest,
        0,
        man_block_id,
    );

    let mut backup_offset = footer.backup_header_offset();
    let mut man_payload = Vec::new();
    for _ in 0..4 {
        manifest.volume_committed_ends = vec![backup_offset];
        manifest.committed_horizon = backup_offset;
        let manifest_bytes = manifest
            .to_bytes_with_header_digests(0, &header_digest)
            .unwrap();
        let man_cipher = man_aead
            .encrypt(&man_nonce, &man_aad, &manifest_bytes)
            .unwrap();
        man_payload.clear();
        man_payload.reserve(NONCE_SIZE + man_cipher.len());
        man_payload.extend_from_slice(&man_nonce);
        man_payload.extend_from_slice(&man_cipher);
        let computed = u64::try_from(man_offset + BlockHeader::SIZE + man_payload.len()).unwrap();
        if computed == backup_offset {
            break;
        }
        backup_offset = computed;
    }
    let man_len = u32::try_from(man_payload.len()).unwrap();
    let man_hdr = BlockHeader::new(
        BlockType::Manifest,
        man_len,
        compute_shard_crc(&man_payload),
    );
    let new_footer = Footer::with_catalog(
        backup_offset,
        footer.block_count(),
        footer.sequence_number(),
        footer.catalog_offset(),
        cat_len,
        footer.catalog_block_id(),
        footer.last_checkpoint_offset(),
        footer.last_checkpoint_block_id(),
        footer.manifest_block_id(),
        0,
        0,
        0,
        backup_offset,
        u64::try_from(man_offset).unwrap(),
    );
    let footer_bytes = new_footer.to_bytes().unwrap();

    let mut out = bytes[..cat_offset].to_vec();
    if out.len() >= HEADER_SIZE + FOOTER_SIZE && &out[HEADER_SIZE..HEADER_SIZE + 4] == b"ERAF" {
        out[HEADER_SIZE..HEADER_SIZE + FOOTER_SIZE].copy_from_slice(&footer_bytes);
    }
    out.extend_from_slice(&cat_hdr.to_bytes());
    out.extend_from_slice(&cat_block.data);
    out.extend_from_slice(&man_hdr.to_bytes());
    out.extend_from_slice(&man_payload);
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&footer_bytes);
    fs::write(archive_path, &out).unwrap();
}

#[tokio::test]
async fn malformed_file_entry_metadata_rejected_by_extract_and_verify() {
    let temp = TempDir::new().unwrap();

    // (a) Packed file whose entry.size disagrees with unpacked chunk bytes.
    {
        let src_dir = temp.path().join("packed_src");
        fs::create_dir_all(&src_dir).unwrap();
        let small_a = src_dir.join("small_a.txt");
        let small_b = src_dir.join("small_b.txt");
        fs::write(&small_a, b"hello-world").unwrap();
        fs::write(&small_b, b"second").unwrap();

        let archive_path = temp.path().join("packed_size_mismatch.era");
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(PASSWORD)
            .config(fast_non_ec_config())
            .enable_erasure(false)
            .enable_cdc(false)
            .enable_small_file_packing(true)
            .build()
            .await
            .unwrap();
        writer.add_file(&small_a).await.unwrap();
        writer.add_file(&small_b).await.unwrap();
        writer.finalize().await.unwrap();

        rewrite_archive_catalog(&archive_path, |catalog| {
            let entry = catalog
                .entries
                .iter_mut()
                .find(|e| e.path.ends_with("small_a.txt"))
                .unwrap();
            assert!(entry.chunks[0].packed_info.is_some());
            entry.size = 5; // mismatch vs actual 11 bytes
        })
        .await;

        let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
        let verify_stats = reader.verify().await.unwrap();
        assert!(
            !verify_stats.is_ok(),
            "verify must reject packed entry whose entry.size disagrees with unpacked bytes, got {verify_stats:?}"
        );
        let out_dir = temp.path().join("out_packed");
        let extract_res = reader.extract_all(&ExtractOptions::new(&out_dir)).await;
        assert!(
            extract_res.is_err(),
            "extract must reject packed entry whose entry.size disagrees with unpacked bytes"
        );
        assert!(!out_dir.join("small_a.txt").exists());
    }

    // (b1) Multi-chunk file with non-contiguous chunk offsets.
    {
        let archive_path = temp.path().join("non_contiguous.era");
        let mut config = fast_non_ec_config();
        config.block.target_size = 64;
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(PASSWORD)
            .config(config)
            .target_block_size(64)
            .enable_erasure(false)
            .enable_cdc(false)
            .enable_small_file_packing(false)
            .build()
            .await
            .unwrap();
        writer
            .add_bytes("multi.bin", &payload_for(41, 160))
            .await
            .unwrap();
        writer.finalize().await.unwrap();

        rewrite_archive_catalog(&archive_path, |catalog| {
            catalog.entries[0].chunks[1].offset += 4;
        })
        .await;

        let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
        let verify_stats = reader.verify().await.unwrap();
        assert!(
            !verify_stats.is_ok(),
            "verify must reject non-contiguous multi-chunk entry, got {verify_stats:?}"
        );
        let extract_res = reader
            .extract_all(&ExtractOptions::new(temp.path().join("out_gap")))
            .await;
        assert!(
            extract_res.is_err(),
            "extract must reject non-contiguous multi-chunk entry"
        );
    }

    // (b2) Multi-chunk file whose chunk lengths do not sum to entry.size.
    {
        let archive_path = temp.path().join("sum_mismatch.era");
        let mut config = fast_non_ec_config();
        config.block.target_size = 64;
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(PASSWORD)
            .config(config)
            .target_block_size(64)
            .enable_erasure(false)
            .enable_cdc(false)
            .enable_small_file_packing(false)
            .build()
            .await
            .unwrap();
        writer
            .add_bytes("multi.bin", &payload_for(42, 160))
            .await
            .unwrap();
        writer.finalize().await.unwrap();

        rewrite_archive_catalog(&archive_path, |catalog| {
            catalog.entries[0].size = 200; // sum of chunks is 160
        })
        .await;

        let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
        let verify_stats = reader.verify().await.unwrap();
        assert!(
            !verify_stats.is_ok(),
            "verify must reject multi-chunk entry when sum(chunk.length) != entry.size, got {verify_stats:?}"
        );
        let extract_res = reader
            .extract_all(&ExtractOptions::new(temp.path().join("out_sum")))
            .await;
        assert!(
            extract_res.is_err(),
            "extract must reject multi-chunk entry when sum(chunk.length) != entry.size"
        );
    }

    // (c) Regular FileType::File with empty chunks.
    {
        let archive_path = temp.path().join("zero_chunks.era");
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(PASSWORD)
            .config(fast_non_ec_config())
            .enable_erasure(false)
            .enable_cdc(false)
            .enable_small_file_packing(false)
            .build()
            .await
            .unwrap();
        writer.add_bytes("regular.bin", b"payload").await.unwrap();
        writer.finalize().await.unwrap();

        rewrite_archive_catalog(&archive_path, |catalog| {
            catalog.entries[0].chunks.clear();
        })
        .await;

        let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
        let verify_stats = reader.verify().await.unwrap();
        assert!(
            !verify_stats.is_ok(),
            "verify must reject regular FileType::File with empty chunks, got {verify_stats:?}"
        );
        let extract_res = reader
            .extract_all(&ExtractOptions::new(temp.path().join("out_zero")))
            .await;
        assert!(
            extract_res.is_err(),
            "extract must reject regular FileType::File with empty chunks"
        );
    }
}
