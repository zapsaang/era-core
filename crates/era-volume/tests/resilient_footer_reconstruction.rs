use era_common::{ArchiveConfig, ArchiveId, ErasureCodeConfig, Result};
use era_storage::LocalStorageBackend;
use era_volume::{SuperHeader, VolumeReader, VolumeWriter};
use std::path::Path;
use tempfile::TempDir;

#[tokio::test]
async fn test_resilient_footer_open_with_erasure() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let path = Path::new("test_resilient.era");

    // 1. Create a volume configuration WITH erasure coding
    let config = ArchiveConfig {
        erasure: Some(ErasureCodeConfig {
            data_shards: 4,
            parity_shards: 2,
        }),
        ..Default::default()
    };

    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![era_volume::RecipientSlot::new(
            era_volume::RecipientType::Argon2idPassword,
            Some([0x12; 8]),
            vec![0xAB; 16],
            vec![0xCD; 48],
        )],
        config,
        [0u8; 16],
        era_volume::EncryptedVolumeKey {
            algorithm: era_volume::KeyWrapAlgorithm::XChaCha20Poly1305,
            nonce: [0u8; 24],
            ciphertext: vec![0u8; 48],
        },
        era_volume::AccessPolicy::AnyOfN,
    )
    .unwrap();

    // 2. Write a valid volume first
    let writer = VolumeWriter::create(&backend, path, header.clone()).await?;
    writer.finalize().await?;

    // 3. Corrupt BOTH footers manually
    // Primary footer is at the end (last 128 bytes)
    // Backup footer is at offset 4096 (HEADER_SIZE)
    {
        use std::fs::OpenOptions;
        use std::io::Seek;
        use std::io::Write;

        let file_path = temp_dir.path().join(path);
        let mut file = OpenOptions::new().write(true).open(file_path).unwrap();

        // Corrupt primary footer (last 128 bytes)
        file.seek(std::io::SeekFrom::End(-128)).unwrap();
        file.write_all(&[0xFF; 128]).unwrap();

        // Corrupt backup footer at offset 4096
        file.seek(std::io::SeekFrom::Start(4096)).unwrap();
        file.write_all(&[0xFF; 128]).unwrap();

        // Ensure changes are on disk
        file.sync_all().unwrap();
    }

    // 4. Try to open with VolumeReader
    // This should SUCCEED now because erasure is enabled in header
    // (even though footer is corrupted, the volume can be opened for recovery)
    let reader = VolumeReader::open(&backend, path).await;
    assert!(
        reader.is_ok(),
        "Should open successfully despite corrupted footer when erasure is enabled"
    );

    let reader = reader.unwrap();

    // 5. Verify footer is None (both primary and backup are corrupted)
    assert!(
        reader.footer().is_none(),
        "Footer should be None when both footers are corrupted"
    );

    // 6. Verify we can still read parts (like header)
    assert_eq!(reader.header().archive_id.0, header.archive_id.0);

    Ok(())
}

#[tokio::test]
async fn test_fail_without_erasure() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let path = Path::new("test_fragile.era");

    // 1. Create a volume configuration WITHOUT erasure coding
    let config = ArchiveConfig {
        erasure: None, // Explicitly disable erasure coding
        ..Default::default()
    };

    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![era_volume::RecipientSlot::new(
            era_volume::RecipientType::Argon2idPassword,
            Some([0x12; 8]),
            vec![0xAB; 16],
            vec![0xCD; 48],
        )],
        config,
        [0u8; 16],
        era_volume::EncryptedVolumeKey {
            algorithm: era_volume::KeyWrapAlgorithm::XChaCha20Poly1305,
            nonce: [0u8; 24],
            ciphertext: vec![0u8; 48],
        },
        era_volume::AccessPolicy::AnyOfN,
    )
    .unwrap();

    // 2. Write
    let writer = VolumeWriter::create(&backend, path, header).await?;
    writer.finalize().await?;

    // 3. Corrupt ALL footer locations (primary, backup, and any area that might contain footer magic)
    // Layout: [Header 4096] [Backup Footer 128] [Backup Header 4096] [Primary Footer 128]
    {
        use std::fs::OpenOptions;
        use std::io::{Seek, Write};
        let file_path = temp_dir.path().join(path);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file_path)
            .unwrap();

        // Get file size
        let file_size = file.metadata().unwrap().len();

        // Corrupt primary footer (last 128 bytes)
        file.seek(std::io::SeekFrom::End(-128)).unwrap();
        file.write_all(&[0xFF; 128]).unwrap();

        // Corrupt backup footer at offset 4096
        file.seek(std::io::SeekFrom::Start(4096)).unwrap();
        file.write_all(&[0xFF; 128]).unwrap();

        // Corrupt entire data region after backup footer gap to prevent floating footer recovery
        // This corrupts the backup header area which might contain footer-like patterns
        let corrupt_start = 4096 + 128; // After backup footer gap
        let corrupt_len = file_size as usize - corrupt_start as usize - 128; // Before primary footer
        if corrupt_len > 0 {
            file.seek(std::io::SeekFrom::Start(corrupt_start as u64))
                .unwrap();
            file.write_all(&vec![0xFF; corrupt_len]).unwrap();
        }

        file.sync_all().unwrap();
    }

    // 4. Try to open - SHOULD FAIL when all footers corrupted and erasure disabled
    let reader = VolumeReader::open(&backend, path).await;
    assert!(
        reader.is_err(),
        "Should fail when all footers are corrupted and erasure is disabled"
    );

    Ok(())
}
