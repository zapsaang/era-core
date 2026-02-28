use bytes::Bytes;
use era_common::{ArchiveConfig, ArchiveId, BlockId, EncryptedMacroBlock};
use era_storage::LocalStorageBackend;
use era_volume::{MultiVolumeConfig, MultiVolumeWriter, SuperHeader};
use std::fs;
use tempfile::TempDir;

#[tokio::test]
async fn test_multi_volume_padding_and_atomicity() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let base_name = "atomicity_test";

    // 1. Configure for small volumes to force splitting
    // Size needs to be enough for Header + Block + Footer + Padding
    // Header ~4KB? Let's check existing code or make it generous but small enough to fill.
    // If we set 128KB max size.
    let max_volume_size = 128 * 1024; // 128 KB

    let config = MultiVolumeConfig::new(base_name, max_volume_size).unwrap();

    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![era_volume::RecipientSlot::new(
            era_volume::RecipientType::Argon2idPassword,
            Some([0x12; 8]),
            vec![0xAB; 16],
            vec![0xCD; 48],
        )],
        ArchiveConfig::default(),
        [0u8; 16],
        era_volume::EncryptedVolumeKey {
            algorithm: era_volume::KeyWrapAlgorithm::XChaCha20Poly1305,
            nonce: [0u8; 24],
            ciphertext: vec![0u8; 48],
        },
        era_volume::AccessPolicy::AnyOfN,
    )
    .unwrap();

    let mut multi_writer = MultiVolumeWriter::create(&backend, config.clone(), header)
        .await
        .unwrap();

    // 2. Write enough data to force a split
    // Each block is 32KB.
    // Volume: 128KB.
    // Header + Footer ~ 8KB (estimate).
    // Usable: 120KB.
    // We write 4 blocks of 30KB.
    // Block 1, 2, 3 = 90KB. Fits.
    // Block 4 -> 120KB. Might fit or split depending on overhead.
    // Let's write smaller blocks to be precise. 10KB blocks.

    let block_data = Bytes::from(vec![0xAAu8; 10 * 1024]); // 10KB
    let mut locations = Vec::new();

    // Write enough blocks to definitely exceed 128KB
    // 15 blocks * 10KB = 150KB + headers. Should split existing volume.
    for i in 0..20 {
        let block = EncryptedMacroBlock {
            block_id: BlockId::new(i),
            data: block_data.clone(),
            original_size: 10 * 1024,
            compressed_size: 10 * 1024,
            chunk_count: 1,
        };
        let loc = multi_writer.write_block(&backend, &block).await.unwrap();
        locations.push(loc);
    }

    // 3. Finalize
    let stats = multi_writer.finalize().await.unwrap();

    // 4. Verification

    // Check we have multiple volumes
    assert!(
        stats.volume_count > 1,
        "Should have split into multiple volumes"
    );

    // Check FIRST volume size (should be exactly max_volume_size due to Traffic Analysis Padding)
    let vol0_path = temp_dir.path().join(format!("{}.era", base_name));
    let metadata_vol0 = fs::metadata(&vol0_path).expect("Volume 0 should exist");

    assert_eq!(
        metadata_vol0.len(),
        max_volume_size,
        "Volume 0 should be padded to exactly max_volume_size for traffic analysis resistance"
    );

    // Check LAST volume size (might be smaller if not enforced, OR should also be padded?)
    // Traffic Analysis Padding usually requires ALL volumes to be the same size
    // to prevent leaking the total size of the archive via the last tail.
    // If the mandate is "pad all volumes", then the last one must also be padded.
    let last_vol_idx = stats.volume_count - 1;
    let last_vol_name = if last_vol_idx == 0 {
        format!("{}.era", base_name)
    } else {
        format!("{}.era.{:03}", base_name, last_vol_idx)
    };
    let vol_last_path = temp_dir.path().join(last_vol_name);
    let metadata_last = fs::metadata(&vol_last_path).expect("Last volume should exist");

    assert_eq!(
        metadata_last.len(),
        max_volume_size,
        "Last volume should also be padded to maximize traffic analysis resistance"
    );
}
