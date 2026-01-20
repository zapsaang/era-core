use era_common::ErasureCodeConfig;
use era_engine::ArchiveWriter;
use std::fs;
use std::io::Write;
use tempfile::TempDir;

#[tokio::test]
async fn test_reproduce_matrix_distribution_panic() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    // Create a large enough file to trigger stripe flushing
    // Default blocks are 4MB, so let's write 10MB to be safe
    let content = vec![b'a'; 10 * 1024 * 1024];
    let file_path = input_dir.join("large_file.bin");
    {
        let mut file = fs::File::create(&file_path).unwrap();
        file.write_all(&content).unwrap();
    }

    // Create archive with matrix distribution AND erasure coding
    let archive_path = temp_dir.path().join("matrix_test.era");

    // Erasure config 4:2
    let erasure_config = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    println!("Creating archive with matrix distribution...");
    match ArchiveWriter::builder(&archive_path)
        .password("test_password")
        .erasure_config(erasure_config)
        .enable_erasure(true)
        .enable_matrix_distribution(true) // This triggers the use of VolumePool
        .build()
    {
        Ok(mut writer) => {
            // This line should panic if the bug exists
            if let Err(e) = writer.add_file(&file_path).await {
                panic!("Failed to add file: {}", e);
            }
            if let Err(e) = writer.finalize() {
                panic!("Failed to finalize: {}", e);
            }
        }
        Err(e) => panic!("Failed to build writer: {}", e),
    }

    println!("Test passed (panic did not occur)");
}
