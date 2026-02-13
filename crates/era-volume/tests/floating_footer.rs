use era_common::{ArchiveConfig, ArchiveId};
use era_storage::memory::MemoryStorageBackend;
use era_storage::{StorageBackend, StorageWriter};
use era_volume::footer::Footer;
use era_volume::{SuperHeader, VolumeReader};

#[tokio::test]
async fn test_floating_footer_recovery() {
    // 1. Setup
    let backend = MemoryStorageBackend::new();
    let path = std::path::Path::new("vol1.era");

    // Create header
    let archive_id = ArchiveId::new();
    let config = ArchiveConfig::default();
    let header = SuperHeader::new(
        archive_id,
        vec![era_volume::RecipientSlot::new(
            era_volume::RecipientType::ScryptPassword,
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
    );
    let header_bytes = header.to_bytes().unwrap();

    // 2. Write initial data and a valid footer (Checkpoint 1)
    {
        // Use StorageBackend trait methods
        let mut writer = backend.create(path).await.unwrap();
        writer.append(&header_bytes).await.unwrap();

        // Write enough data so data_end_offset >= HEADER_SIZE + FOOTER_SIZE (4224)
        let data1 = vec![0xAA; 256];
        writer.append(&data1).await.unwrap();
        let block1_end = writer.current_size();

        // Write Valid Footer 1
        let footer1 = Footer::new(block1_end, 1, 1);
        let footer_bytes = footer1.to_bytes().unwrap();
        writer.append(&footer_bytes).await.unwrap();

        // 3. Simulate "Journaling" / Torn Write
        // Write Block 2 (Partial/Extra data)
        let data2 = vec![0xBB; 50]; // Some data
        writer.append(&data2).await.unwrap();

        // DO NOT write a final footer at the end of file (size is now Header + Data1 + Footer1 + Data2)
        // Standard reader would look at (End - 128) and find Data2 (garbage footer)
    }

    // 4. Attempt Recovery
    // This should fail with current implementation because footer is missing at EOF
    let reader = VolumeReader::open(&backend, path).await;
    // Note: VolumeReader currently errors on missing footer unless erasure is enabled.
    // If erasure is enabled, it returns valid reader but footer is None.
    // However, we WANT it to find the *valid* footer in the middle of the stream.

    // In current implementation:
    // Case A: Footer missing/invalid at EOF => Error (if no erasure) or None (if erasure).
    // We want: Footer found (the floating one).

    // Assert that we successfully opened AND found a footer
    assert!(reader.is_ok(), "Should open volume");
    let reader = reader.unwrap();

    let loaded_footer = reader.footer();
    assert!(loaded_footer.is_some(), "Should find floating footer");

    let loaded_footer = loaded_footer.unwrap();
    assert_eq!(loaded_footer.sequence_number, 1);
    assert_eq!(loaded_footer.block_count, 1);
}
