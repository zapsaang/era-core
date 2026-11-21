#![allow(deprecated)]

use era_common::{ArchiveConfig, CompressionAlgorithm, EraError};
use era_engine::{ArchiveReader, ArchiveWriter, ExtractOptions, GenericArchiveWriterBuilder};
use era_storage::{LocalStorageBackend, MemoryStorageBackend};
use std::fs;
use std::io::Read;
use std::path::Path;
use tempfile::TempDir;

const PASSWORD: &str = "resid-low04-test-password";

fn fast_config(erasure: Option<era_common::ErasureCodeConfig>) -> ArchiveConfig {
    let mut config = ArchiveConfig {
        erasure,
        ..Default::default()
    };
    config.encryption.kdf_memory_cost = 1024;
    config.encryption.kdf_time_cost = 1;
    config.compression.algorithm = CompressionAlgorithm::None;
    config
}

fn pattern_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for (idx, chunk) in out.chunks_mut(8).enumerate() {
        let bytes = (idx as u64).to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    out
}

fn file_blake3(path: &Path) -> blake3::Hash {
    let mut file = fs::File::open(path).unwrap();
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = file.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    hasher.finalize()
}

#[tokio::test]
async fn archive_writer_invalid_packing_config_leaves_no_volume_files() {
    let default_ec = ArchiveConfig::default().erasure;
    for (label, erasure) in [("ec", default_ec), ("non_ec", None)] {
        for (k_factor, flush_threshold) in [(0, 95), (8, 0), (8, 101)] {
            let dir = TempDir::new().unwrap();
            let mut config = fast_config(erasure);
            config.packing.k_factor = k_factor;
            config.packing.flush_threshold = flush_threshold;

            let err = match ArchiveWriter::builder(dir.path().join("bad.era"))
                .password(PASSWORD)
                .config(config)
                .build()
                .await
            {
                Ok(_) => panic!(
                    "expected InvalidConfig for {label} k={k_factor}, flush={flush_threshold}"
                ),
                Err(err) => err,
            };
            assert!(
                matches!(err, EraError::InvalidConfig(_)),
                "expected InvalidConfig for {label} k={k_factor}, flush={flush_threshold}, got {err:?}"
            );
            assert_eq!(
                fs::read_dir(dir.path()).unwrap().count(),
                0,
                "failed build for {label} k={k_factor}, flush={flush_threshold} must leave no volume files"
            );
        }
    }
}

#[tokio::test]
async fn append_invalid_target_block_size_preserves_existing_archive() {
    let dir = TempDir::new().unwrap();
    let archive_path = dir.path().join("append_preserve.era");

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(fast_config(None))
        .build()
        .await
        .unwrap();
    writer
        .add_bytes("initial.txt", b"initial content")
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    let before = fs::read(&archive_path).unwrap();

    let err = match ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .append_existing(true)
        .target_block_size(0)
        .build()
        .await
    {
        Ok(_) => panic!("expected append with target_block_size(0) to fail"),
        Err(err) => err,
    };
    assert!(
        matches!(err, EraError::InvalidConfig(_)),
        "expected InvalidConfig, got {err:?}"
    );
    assert_eq!(
        fs::read(&archive_path).unwrap(),
        before,
        "failed append validation must not modify or truncate existing archive"
    );
}

#[tokio::test]
async fn generic_writer_invalid_packing_config_leaves_no_volume_files() {
    let cases = [
        (0, 95, 4 * 1024 * 1024),
        (8, 0, 4 * 1024 * 1024),
        (8, 101, 4 * 1024 * 1024),
        (8, 95, 0),
    ];
    for (k_factor, flush_threshold, target_size) in cases {
        let dir = TempDir::new().unwrap();
        let mut config = fast_config(None);
        config.packing.k_factor = k_factor;
        config.packing.flush_threshold = flush_threshold;
        config.block.target_size = target_size;

        let local_backend = LocalStorageBackend::new(dir.path());
        let local_err = match GenericArchiveWriterBuilder::new(local_backend, "bad_local.era")
            .password(PASSWORD)
            .config(config.clone())
            .build()
            .await
        {
            Ok(_) => panic!(
                "expected InvalidConfig on local backend for k={k_factor}, flush={flush_threshold}, target={target_size}"
            ),
            Err(err) => err,
        };
        assert!(
            matches!(local_err, EraError::InvalidConfig(_)),
            "expected InvalidConfig, got {local_err:?}"
        );
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            0,
            "failed GenericArchiveWriter build must leave no disk volume files"
        );

        let mem_backend = MemoryStorageBackend::new();
        let mem_err = match GenericArchiveWriterBuilder::new(mem_backend.clone(), "bad_mem.era")
            .password(PASSWORD)
            .config(config)
            .build()
            .await
        {
            Ok(_) => panic!(
                "expected InvalidConfig on memory backend for k={k_factor}, flush={flush_threshold}, target={target_size}"
            ),
            Err(err) => err,
        };
        assert!(
            matches!(mem_err, EraError::InvalidConfig(_)),
            "expected InvalidConfig, got {mem_err:?}"
        );
        assert!(
            mem_backend.list_paths().unwrap().is_empty(),
            "failed GenericArchiveWriter build must leave no memory backend entries"
        );
    }
}

#[tokio::test]
async fn generic_writer_splits_large_input_by_target_block_size_and_roundtrips() {
    // Subtest A: MemoryStorageBackend with 64 KiB target_block_size and 200 KiB payload -> 4 chunks
    {
        let backend = MemoryStorageBackend::new();
        let mut config = fast_config(None);
        config.block.target_size = 64 * 1024;

        let mut writer = GenericArchiveWriterBuilder::new(backend.clone(), "split_mem.era")
            .password(PASSWORD)
            .config(config)
            .build()
            .await
            .unwrap();
        let payload = pattern_bytes(200 * 1024);
        writer.add_bytes("split_mem.bin", &payload).await.unwrap();
        writer.finalize().await.unwrap();

        let archive_bytes = backend
            .get_data(Path::new("split_mem.era"))
            .unwrap()
            .unwrap();
        let dir = TempDir::new().unwrap();
        let disk_path = dir.path().join("split_mem.era");
        fs::write(&disk_path, archive_bytes).unwrap();

        let mut reader = ArchiveReader::open(&disk_path, PASSWORD).await.unwrap();
        let catalog = reader.load_catalog().await.unwrap();
        assert_eq!(catalog.entries.len(), 1);
        assert_eq!(catalog.entries[0].chunks.len(), 4);
        assert!(reader.verify().await.unwrap().is_healthy());

        let out_dir = dir.path().join("out");
        reader
            .extract_all(&ExtractOptions::new(&out_dir))
            .await
            .unwrap();
        assert_eq!(fs::read(out_dir.join("split_mem.bin")).unwrap(), payload);
    }

    // Subtest B: >64 MiB single add_bytes (65 MiB) with default 4 MiB target_block_size -> 17 chunks
    {
        let dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(dir.path());
        let config = fast_config(None);
        let mut writer = GenericArchiveWriterBuilder::new(backend, "oversized_65m.era")
            .password(PASSWORD)
            .config(config)
            .build()
            .await
            .unwrap();

        let payload = pattern_bytes(65 * 1024 * 1024);
        let expected_hash = blake3::hash(&payload);
        writer
            .add_bytes("oversized_65mib.bin", &payload)
            .await
            .unwrap();
        drop(payload);
        writer.finalize().await.unwrap();

        let archive_path = dir.path().join("oversized_65m.era");
        let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
        let catalog = reader.load_catalog().await.unwrap();
        assert_eq!(catalog.entries.len(), 1);
        assert_eq!(catalog.entries[0].chunks.len(), 17);
        let verify_stats = reader.verify().await.unwrap();
        assert!(
            verify_stats.is_healthy(),
            "expected Healthy archive, got {:?}, errors={:?}",
            verify_stats.archive_health,
            verify_stats.errors
        );

        let out_dir = dir.path().join("out");
        reader
            .extract_all(&ExtractOptions::new(&out_dir))
            .await
            .unwrap();
        let extracted_path = out_dir.join("oversized_65mib.bin");
        assert_eq!(
            fs::metadata(&extracted_path).unwrap().len(),
            65 * 1024 * 1024
        );
        assert_eq!(file_blake3(&extracted_path), expected_hash);
    }

    // Subtest C: Clamping huge config.block.target_size (128 MiB) below MAX_SHARD_SIZE (16 MiB)
    {
        let dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(dir.path());
        let mut config = fast_config(None);
        config.block.target_size = 128 * 1024 * 1024;
        let mut writer = GenericArchiveWriterBuilder::new(backend, "clamped_17m.era")
            .password(PASSWORD)
            .config(config)
            .build()
            .await
            .unwrap();

        let payload = pattern_bytes(17 * 1024 * 1024);
        let expected_hash = blake3::hash(&payload);
        writer
            .add_bytes("clamped_17mib.bin", &payload)
            .await
            .unwrap();
        drop(payload);
        writer.finalize().await.unwrap();

        let archive_path = dir.path().join("clamped_17m.era");
        let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
        let catalog = reader.load_catalog().await.unwrap();
        assert_eq!(catalog.entries.len(), 1);
        assert!(
            catalog.entries[0].chunks.len() >= 2,
            "17 MiB payload must be split below MAX_SHARD_SIZE (16 MiB), got {} chunk(s)",
            catalog.entries[0].chunks.len()
        );
        let verify_stats = reader.verify().await.unwrap();
        assert!(verify_stats.is_healthy());

        let out_dir = dir.path().join("out");
        reader
            .extract_all(&ExtractOptions::new(&out_dir))
            .await
            .unwrap();
        let extracted_path = out_dir.join("clamped_17mib.bin");
        assert_eq!(
            fs::metadata(&extracted_path).unwrap().len(),
            17 * 1024 * 1024
        );
        assert_eq!(file_blake3(&extracted_path), expected_hash);
    }
}
