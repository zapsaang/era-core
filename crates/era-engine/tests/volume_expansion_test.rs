use era_common::{ErasureCodeConfig, Result};
use era_engine::ArchiveWriter;
use tempfile::tempdir;

#[tokio::test]
async fn test_volume_expansion_matrix_mode() -> Result<()> {
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("archive.era");

    // Low volume size to trigger expansion quickly
    // 1MB per volume * 6 volumes = 6MB total capacity before expansion needed
    let max_volume_size = 1024 * 1024; // 1MB
    let volume_count = 6;

    // Erasure config 4:2
    let erasure_config = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    let mut writer = ArchiveWriter::builder(&output_path)
        .enable_erasure(true)
        .erasure_config(erasure_config)
        .enable_matrix_distribution(true)
        .volume_count(volume_count)
        .max_volume_size(max_volume_size)
        // Disable various buffers to ensure writes happen
        .build()
        .await?;

    // Generate 10MB of data (should fill 6MB capacity and require expansion)
    let data_size = 10 * 1024 * 1024;
    // Use random data to avoid high compression
    // Simple LCG PRNG to avoid external deps if rand not available or inconvenient
    let mut data = vec![0u8; data_size];
    let mut state: u32 = 12345;
    for item in data.iter_mut() {
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        *item = (state >> 16) as u8;
    }

    // This should fail currently
    match writer.add_bytes("large_file.dat", &data).await {
        Ok(_) => println!("Successfully added data"),
        Err(e) => {
            println!("Failed as expected (or unexpected): {}", e);
            return Err(e);
        }
    }

    let _stats = writer.finalize().await?;

    // If we reach here, check we have more than 6 volumes created
    // The filenames would be archive.era, archive.era.001 ... archive.era.005 (set 1)
    // and then archive.era.006 ... (set 2)

    let entries = std::fs::read_dir(dir.path())?;
    // Filter for files starting with "era" extension or base file
    let count = entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            let path = e.path();
            if let Some(name) = path.file_name() {
                let s = name.to_string_lossy();
                s.contains("archive.era")
            } else {
                false
            }
        })
        .count();

    println!("Total volume files in output directory: {}", count);
    assert!(
        count > 6,
        "Should have created more than 6 volume files, got {}",
        count
    );

    Ok(())
}
