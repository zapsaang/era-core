use era_common::{ArchiveConfig, CompressionAlgorithm, CompressionConfig, ErasureCodeConfig};
use era_engine::{ArchiveReader, ArchiveWriterBuilder};
use std::fs;
use tempfile::TempDir;

#[test]
fn test_distributed_erasure_writing() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().join("dist_test.era");

    // Configure 2+1 erasure coding
    let erasure_config = ErasureCodeConfig {
        data_shards: 2,
        parity_shards: 1,
    };

    let config = ArchiveConfig {
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: 0,
        },
        ..Default::default()
    };

    // We want 3 volumes to distribute the 3 shards perfectly
    let volume_count = 3;

    // Build writer with multiple volumes
    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .config(config)
        .enable_erasure(true)
        .erasure_config(erasure_config)
        .volume_count(volume_count)
        // Enable CDC to split the 1MB file into multiple chunks/blocks
        // This ensures enough blocks are created to fill the stripe (2 Data + 1 Parity)
        .enable_cdc(true)
        .build()
        .unwrap();

    // Use non-repeating data to avoid CDC deduplication from reducing the size
    let size = 1024 * 1024;
    let mut data = vec![0u8; size];
    // Fill with a non-repeating pattern (counter)
    for (i, chunk) in data.chunks_mut(8).enumerate() {
        let val = i as u64;
        let bytes = val.to_le_bytes();
        let len = chunk.len();
        chunk.copy_from_slice(&bytes[..len]);
    }

    // Write to a temporary file instead of add_bytes, so we can use CDC chunking
    let input_path = temp_dir.path().join("input.bin");
    fs::write(&input_path, &data).unwrap();

    // Add using add_file_with_path to respect CDC and specify stored name
    writer
        .add_file_with_path(&input_path, std::path::Path::new("test_file.bin"))
        .unwrap();
    writer.finalize().unwrap();

    // Verify files exist and have content
    // Vol 0: dist_test.era
    // Vol 1: dist_test.era.001
    // Vol 2: dist_test.era.002

    let vol0 = &base_path;
    let vol1 = base_path.with_extension("era.001");
    let vol2 = base_path.with_extension("era.002");

    assert!(vol0.exists(), "Volume 0 missing");
    assert!(vol1.exists(), "Volume 1 missing");
    assert!(vol2.exists(), "Volume 2 missing");

    let size0 = fs::metadata(vol0).unwrap().len();
    let size1 = fs::metadata(vol1).unwrap().len();
    let size2 = fs::metadata(vol2).unwrap().len();

    println!("Sizes: {} {} {}", size0, size1, size2);

    // Each volume should have roughly 1/3 of total storage.
    assert!(size0 > 200_000);
    assert!(size1 > 200_000);
    assert!(size2 > 200_000);

    // Reading Verification
    let mut reader = ArchiveReader::open(&base_path, "").expect("Failed to open archive");

    // Check if the file entry exists
    let files = reader.list_files().expect("Failed to list files");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path.to_str().unwrap(), "test_file.bin");
    assert_eq!(files[0].size, size as u64);

    // Extract file content
    let extract_dir = temp_dir.path().join("extract");
    let options = era_engine::ExtractOptions::new(&extract_dir);
    reader
        .extract_all(&options)
        .expect("Failed to extract files");

    let extracted_path = extract_dir.join("test_file.bin");
    assert!(extracted_path.exists());
    let extracted_data = fs::read(&extracted_path).expect("Failed to read extracted file");

    assert_eq!(extracted_data.len(), size);
    assert_eq!(
        extracted_data, data,
        "Read data does not match written data"
    );
}
