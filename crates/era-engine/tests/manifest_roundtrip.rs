//! Integration test for v8.2 manifest pipeline.
//!
//! Verifies end-to-end roundtrip of the full manifest pipeline:
//! block_locations tracking, catalog, index, manifest, and footer fields.

use era_common::{
    ArchiveConfig, ArchiveManifest, BlockId, BlockLocation, BlockType, CompressionAlgorithm,
};
use era_crypto::{build_aad, AeadContext, XChaCha20Poly1305Context, NONCE_SIZE};
use era_engine::{ArchiveReader, ArchiveWriter, ExtractOptions};
use era_storage::LocalStorageBackend;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[tokio::test]
async fn test_v8p2_archive_creation_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("v8p2_roundtrip.era");
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    let files = vec![
        ("file1.txt", b"Hello from file 1".to_vec()),
        ("file2.txt", b"Hello from file 2 with more content".to_vec()),
        ("subdir/file3.txt", b"Nested file content".to_vec()),
    ];

    for (name, content) in &files {
        let path = input_dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, content).unwrap();
    }

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("test_password")
        .build()
        .await
        .unwrap();

    for (name, content) in &files {
        writer.add_bytes(name, content).await.unwrap();
    }

    let stats = writer.finalize().await.unwrap();
    assert!(stats.blocks_written > 0);

    let mut reader = ArchiveReader::open(&archive_path, "test_password")
        .await
        .unwrap();

    let footer = reader.primary_footer().expect("footer should be present");
    assert!(footer.has_manifest(), "footer should have manifest (v8.2)");
    assert!(
        footer.manifest_offset() > 0,
        "manifest_offset should be > 0"
    );
    assert!(
        footer.manifest_block_id() > 0,
        "manifest_block_id should be > 0"
    );

    let catalog = reader.load_catalog().await.unwrap();
    assert!(
        !catalog.block_locations.is_empty(),
        "catalog.block_locations should be populated"
    );

    let output_dir = temp_dir.path().join("output");
    reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .await
        .unwrap();

    for (name, expected_content) in &files {
        let extracted_path = output_dir.join(name);
        assert!(
            extracted_path.exists(),
            "extracted file should exist: {name}"
        );
        let extracted_content = fs::read(&extracted_path).unwrap();
        assert_eq!(
            extracted_content, *expected_content,
            "extracted content should match for {name}"
        );
    }
}

#[tokio::test]
async fn test_v8p2_multi_volume_manifest_redundancy() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("v8p2_multi.era");

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("test_password")
        .volume_count(2)
        .build()
        .await
        .unwrap();

    let data = vec![0u8; 64 * 1024];
    writer.add_bytes("large.bin", &data).await.unwrap();
    writer.finalize().await.unwrap();

    let backend = LocalStorageBackend::new(temp_dir.path());
    let base_name = Path::new(archive_path.file_name().unwrap());
    let volume1_name = era_volume::volume_path(base_name, 1);

    let reader0 = era_volume::VolumeReader::open(&backend, base_name)
        .await
        .unwrap();
    let reader1 = era_volume::VolumeReader::open(&backend, &volume1_name)
        .await
        .unwrap();

    let manifest_blocks0 = reader0
        .scan_for_typed_blocks(BlockType::Manifest)
        .await
        .unwrap();
    let manifest_blocks1 = reader1
        .scan_for_typed_blocks(BlockType::Manifest)
        .await
        .unwrap();

    assert_eq!(
        manifest_blocks0.len(),
        1,
        "Volume 0 should have exactly 1 manifest block"
    );
    assert_eq!(
        manifest_blocks1.len(),
        1,
        "Volume 1 should have exactly 1 manifest block"
    );

    let index_blocks0 = reader0
        .scan_for_typed_blocks(BlockType::IndexManifest)
        .await
        .unwrap();
    let index_blocks1 = reader1
        .scan_for_typed_blocks(BlockType::IndexManifest)
        .await
        .unwrap();

    assert!(
        !index_blocks0.is_empty(),
        "Volume 0 should contain index blocks"
    );
    assert!(
        !index_blocks1.is_empty(),
        "Volume 1 should contain index blocks"
    );

    let manifest0 = reader0.read_block(&manifest_blocks0[0]).await.unwrap();
    let manifest1 = reader1.read_block(&manifest_blocks1[0]).await.unwrap();

    assert!(
        manifest0.data.len() >= era_crypto::NONCE_SIZE,
        "manifest block should contain nonce"
    );
    assert!(
        manifest1.data.len() >= era_crypto::NONCE_SIZE,
        "manifest block should contain nonce"
    );

    assert_ne!(
        &manifest0.data[..era_crypto::NONCE_SIZE],
        &manifest1.data[..era_crypto::NONCE_SIZE],
        "manifest nonces should differ per volume"
    );
    assert_ne!(
        manifest0.data, manifest1.data,
        "manifest ciphertexts should differ per volume"
    );

    let footer0 = reader0.footer().unwrap();
    let footer1 = reader1.footer().unwrap();
    assert!(footer0.has_manifest());
    assert!(footer1.has_manifest());
    assert_eq!(footer0.manifest_block_id(), footer1.manifest_block_id());

    let mut reader = ArchiveReader::open(&archive_path, "test_password")
        .await
        .unwrap();
    let output_dir = temp_dir.path().join("extracted");
    reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .await
        .unwrap();

    let extracted = fs::read(output_dir.join("large.bin")).unwrap();
    assert_eq!(extracted, data, "data integrity should be preserved");
}

#[tokio::test]
async fn test_rotated_manifest_authenticates_final_header_and_keeps_dense_data_ends() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("rotated.era");
    let mut config = ArchiveConfig {
        erasure: None,
        ..Default::default()
    };
    config.compression.algorithm = CompressionAlgorithm::None;
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("test_password")
        .config(config)
        .max_volume_size(1024 * 1024)
        .target_block_size(512 * 1024)
        .enable_cdc(false)
        .build()
        .await
        .unwrap();
    for i in 1..=5u8 {
        writer
            .add_bytes(&format!("{i}.bin"), &vec![i; 512 * 1024])
            .await
            .unwrap();
    }
    writer.finalize().await.unwrap();

    let mut archive = ArchiveReader::open(&archive_path, "test_password")
        .await
        .unwrap();
    archive.preflight_metadata_recovery().await.unwrap();
    let manifest = archive.manifest().unwrap();
    let total = archive.header().total_volumes();
    assert!(total >= 3);
    assert_eq!(manifest.volume_committed_ends.len(), usize::from(total));
    let backend = LocalStorageBackend::new(temp_dir.path());
    let base = Path::new(archive_path.file_name().unwrap());
    let mut expected_ends = Vec::new();
    for sequence in 0..total {
        let reader =
            era_volume::VolumeReader::open(&backend, &era_volume::volume_path(base, sequence))
                .await
                .unwrap();
        let header = reader.header();
        let footer = reader.footer().unwrap();
        assert_eq!(footer.has_manifest(), sequence == total - 1);
        if sequence < total - 1 {
            expected_ends.push(footer.backup_header_offset());
            continue;
        }
        expected_ends.push(footer.catalog_offset());

        let block_id = BlockId::new(u64::from(footer.manifest_block_id()));
        let location = BlockLocation::single(
            header.volume_id(),
            footer.manifest_block_id(),
            footer.manifest_offset(),
            0,
        );
        let (block_type, block) = reader.read_typed_block(&location).await.unwrap();
        assert_eq!(block_type, BlockType::Manifest);
        let key = archive
            .session()
            .derive_block_key(archive.volume_key(), block_id.sequence(), header.salt())
            .unwrap();
        let aead =
            XChaCha20Poly1305Context::from_derived_key(&key.to_derived_key().unwrap()).unwrap();
        let aad = build_aad(
            header.archive_id().0.as_bytes(),
            header.epoch_id(),
            block_type,
            u32::from(sequence),
            block_id,
        );
        let plaintext = aead
            .decrypt(
                block.data.first_chunk::<NONCE_SIZE>().unwrap(),
                &aad,
                &block.data[NONCE_SIZE..],
            )
            .unwrap();
        let (replica, digest) = ArchiveManifest::from_bytes_with_header_digest(&plaintext).unwrap();
        assert_eq!(&replica, manifest);
        let backup = reader
            .read_raw(footer.backup_header_offset(), era_volume::HEADER_SIZE)
            .await
            .unwrap();
        assert_eq!(digest.unwrap(), *blake3::hash(&backup).as_bytes());
    }
    assert_eq!(manifest.volume_committed_ends, expected_ends);
}

#[tokio::test]
async fn test_non_ec_generations_roundtrip_from_first_and_last_volume() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("non-ec-generations.era");
    let mut config = ArchiveConfig {
        erasure: None,
        ..Default::default()
    };
    config.compression.algorithm = CompressionAlgorithm::None;
    let files: Vec<(String, Vec<u8>)> = (1..=5u8)
        .map(|value| (format!("{value}.bin"), vec![value; 512 * 1024]))
        .collect();
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("test_password")
        .config(config)
        .max_volume_size(1024 * 1024)
        .target_block_size(512 * 1024)
        .enable_cdc(false)
        .build()
        .await
        .unwrap();
    for (name, contents) in &files {
        writer.add_bytes(name, contents).await.unwrap();
    }
    writer.finalize().await.unwrap();

    let mut first_archive = ArchiveReader::open(&archive_path, "test_password")
        .await
        .unwrap();
    first_archive.preflight_metadata_recovery().await.unwrap();
    let total = first_archive.header().total_volumes();
    let committed_ends = first_archive
        .manifest()
        .unwrap()
        .volume_committed_ends
        .clone();
    assert!(total >= 3);
    assert_eq!(committed_ends.len(), usize::from(total));
    assert!(committed_ends
        .iter()
        .all(|end| *end > era_volume::DATA_REGION_START));

    let backend = LocalStorageBackend::new(temp_dir.path());
    let base = Path::new(archive_path.file_name().unwrap());
    for sequence in 0..total {
        let volume =
            era_volume::VolumeReader::open(&backend, &era_volume::volume_path(base, sequence))
                .await
                .unwrap();
        let footer = volume.footer().unwrap();
        let expected_end = if sequence == total - 1 {
            assert!(footer.has_manifest());
            footer.catalog_offset()
        } else {
            assert!(!footer.has_manifest());
            footer.backup_header_offset()
        };
        assert_eq!(committed_ends[usize::from(sequence)], expected_end);
    }

    let last_path = era_volume::volume_path(&archive_path, total - 1);
    for (opening_path, output_name) in [
        (archive_path.clone(), "from-first"),
        (last_path, "from-last"),
    ] {
        let mut archive = ArchiveReader::open(&opening_path, "test_password")
            .await
            .unwrap();
        assert_eq!(
            archive.manifest().unwrap().volume_committed_ends,
            committed_ends
        );
        let output_dir = temp_dir.path().join(output_name);
        archive
            .extract_all(&ExtractOptions::new(&output_dir))
            .await
            .unwrap();
        for (name, expected) in &files {
            assert_eq!(fs::read(output_dir.join(name)).unwrap(), *expected);
        }
    }
}

#[tokio::test]
async fn test_v8p2_corrupt_volume_manifest_archive_still_readable() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("v8p2_corrupt.era");

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("test_password")
        .volume_count(2)
        .build()
        .await
        .unwrap();

    let data = b"Corruption resilience test data".to_vec();
    writer.add_bytes("test.txt", &data).await.unwrap();
    writer.finalize().await.unwrap();

    let vol1_path = temp_dir.path().join(era_volume::volume_path(
        Path::new(archive_path.file_name().unwrap()),
        1,
    ));

    {
        let mut vol1_bytes = fs::read(&vol1_path).unwrap();

        let backend = LocalStorageBackend::new(temp_dir.path());
        let vol1_name = era_volume::volume_path(Path::new(archive_path.file_name().unwrap()), 1);
        let reader1 = era_volume::VolumeReader::open(&backend, &vol1_name)
            .await
            .unwrap();
        let footer = reader1.footer().unwrap();
        let manifest_offset = footer.manifest_offset() as usize;

        if manifest_offset > 0 && manifest_offset + 32 < vol1_bytes.len() {
            for i in 0..32 {
                vol1_bytes[manifest_offset + i] ^= 0xFF;
            }
        }

        fs::write(&vol1_path, vol1_bytes).unwrap();
    }

    let mut reader = ArchiveReader::open(&archive_path, "test_password")
        .await
        .unwrap();
    let output_dir = temp_dir.path().join("extracted_corrupt");
    let extract_result = reader.extract_all(&ExtractOptions::new(&output_dir)).await;

    assert!(
        extract_result.is_ok(),
        "Archive should remain readable even with one corrupted manifest: {:?}",
        extract_result.err()
    );

    let extracted = fs::read(output_dir.join("test.txt")).unwrap();
    assert_eq!(extracted, data);
}
