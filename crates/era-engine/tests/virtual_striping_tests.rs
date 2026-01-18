use era_common::{ArchiveConfig, CompressionAlgorithm, CompressionConfig, ErasureCodeConfig};
use era_engine::{ArchiveReader, ArchiveWriter, ExtractOptions};
use std::fs;
use tempfile::TempDir;

#[test]
fn test_virtual_striping_end_to_end() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("striped.era");
    let password = "test_password";

    // Configure 2+1 erasure coding (Virtual Striping: 2 Data Blocks + 1 Parity Block)
    let erasure_config = ErasureCodeConfig {
        data_shards: 2,
        parity_shards: 1,
    };

    let config = ArchiveConfig {
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::None, // Use None to make sizes predictable
            level: 0,
        },
        ..Default::default()
    };

    // 1. Create Archive with Erasure Coding
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password(password)
        .config(config)
        .enable_erasure(true)
        .erasure_config(erasure_config)
        .target_block_size(1024) // 1KB blocks to trigger striping frequently
        .build()
        .unwrap();

    // Write 5 chunks of 800 bytes each.
    // 800 bytes < 1024, but each write might become a chunk.
    // Since we disabled CDC in builder (default), but we didn't enable CDC.
    // Actually, `add_bytes` creates a chunk.
    // `process_packed_block` will pack them.
    // Staging Pool k=8.
    // If we write 1 file of 800 bytes -> Bin Best Fit.
    // We want to force *multiple* blocks.
    // StagingPool flushes bin when > 95% of target (1KB).

    // Let's write larger files to ensure they fill blocks.
    // File 1: 1024 bytes -> Block 1.
    // File 2: 1024 bytes -> Block 2.
    // Stripe 1 (Block 1, Block 2) fits K=2. Should flush -> Writes Block 1, Block 2, Parity 1.

    // File 3: 1024 bytes -> Block 3.
    // File 4: 1024 bytes -> Block 4.
    // Stripe 2 (Block 3, Block 4) fits K=2. Should flush -> Writes Block 3, Block 4, Parity 2.

    // File 5: 1024 bytes -> Block 5.
    // Finalize -> Stripe 3 (Block 5, Padding, Parity 3).

    let mut expected_data = Vec::new();
    for i in 1..=5 {
        let content = vec![i as u8; 1024]; // 1KB
        let name = format!("file_{}.bin", i);
        writer.add_bytes(&name, &content).unwrap();
        expected_data.push(content);
    }

    let stats = writer.finalize().unwrap();

    assert_eq!(stats.total_files, 5);

    // 2. Verify physical file structure (Basic Check)
    // We expect 5 Data Blocks + 3 Parity Blocks = 8 "Physical Blocks" written to volume.
    // Each block approx 1024 + overhead.
    let file_len = fs::metadata(&archive_path).unwrap().len();
    println!("Archive size: {} bytes", file_len);
    // 8 * 1024 = 8192. Plus headers.
    assert!(
        file_len > 8000,
        "File too small, implies data missing or not written"
    );

    // 3. Read and Extract
    let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
    let files = reader.list_files().unwrap();
    assert_eq!(files.len(), 5);

    let extract_dir = temp_dir.path().join("extracted");
    let options = ExtractOptions::new(&extract_dir);

    // This expects the Reader to handle the Virtual Striping layout correctly
    // i.e., skip parity blocks and read data blocks.
    let extract_stats = reader.extract_all(&options).expect("Extraction failed");

    assert_eq!(extract_stats.extracted, 5);

    // Verify content
    for i in 1..=5 {
        let name = format!("file_{}.bin", i);
        let extracted = fs::read(extract_dir.join(name)).unwrap();
        assert_eq!(extracted, expected_data[i - 1]);
    }
}
