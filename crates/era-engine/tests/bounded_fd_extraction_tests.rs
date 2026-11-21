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
