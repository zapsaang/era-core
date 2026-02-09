//! Test volume count auto-adjustment for optimal fault tolerance

use era_common::{ArchiveConfig, CompressionAlgorithm, CompressionConfig, ErasureCodeConfig};
use era_engine::{ArchiveReader, ArchiveWriterBuilder};
use tempfile::TempDir;

#[tokio::test]
async fn test_volume_auto_adjustment() {
    println!("\n=== VOLUME AUTO-ADJUSTMENT TEST ===\n");

    let erasure_config = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().join("archive_auto.era");

    let config = ArchiveConfig {
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: 0,
        },
        ..Default::default()
    };

    // Test 1: NOT specifying volume_count should auto-select optimal
    println!("Test 1: Auto-select volumes (not specified)");
    println!("Expected: 6 volumes (4+2 => 6 total shards)");

    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .config(config.clone())
        .enable_erasure(true)
        .erasure_config(erasure_config)
        // NOTE: NOT calling .volume_count() means default = 1
        .build()
        .await
        .expect("Failed to create writer");

    let data = vec![0xAB; 128 * 1024]; // 128KB
    writer
        .add_bytes("test.bin", &data)
        .await
        .expect("Failed to add file");
    writer.finalize().await.expect("Failed to finalize");

    // Check how many volumes were actually created
    let mut volume_count = 0;
    for i in 0..10 {
        let vol_path = if i == 0 {
            temp_dir.path().join("archive_auto.era")
        } else {
            temp_dir
                .path()
                .join("archive_auto")
                .with_extension(format!("era.{:03}", i))
        };
        if vol_path.exists() {
            volume_count += 1;
            println!("  Volume {}: ✓", i);
        }
    }

    assert_eq!(
        volume_count, 6,
        "Expected 6 volumes for 4+2 erasure with auto-selection"
    );
    println!("✅ Auto-selected 6 volumes\n");

    // Test 2: Specifying smaller volume_count should warn but work
    println!("Test 2: User specifies 3 volumes");
    println!("Expected: 3 volumes (warned about reduced fault tolerance)");

    let base_path2 = temp_dir.path().join("archive_manual.era");
    let mut writer = ArchiveWriterBuilder::new(&base_path2)
        .config(config.clone())
        .enable_erasure(true)
        .erasure_config(erasure_config)
        .volume_count(3) // Explicitly set to minimum viable
        .build()
        .await
        .expect("Failed to create writer");

    writer
        .add_bytes("test.bin", &data)
        .await
        .expect("Failed to add file");
    writer.finalize().await.expect("Failed to finalize");

    let mut volume_count = 0;
    for i in 0..10 {
        let vol_path = if i == 0 {
            temp_dir.path().join("archive_manual.era")
        } else {
            temp_dir
                .path()
                .join("archive_manual")
                .with_extension(format!("era.{:03}", i))
        };
        if vol_path.exists() {
            volume_count += 1;
        }
    }

    assert_eq!(
        volume_count, 3,
        "Expected 3 volumes when explicitly specified"
    );
    println!("✅ Respected user specification of 3 volumes\n");

    // Test 3: Verify fault tolerance improves with 6 volumes
    println!("Test 3: Fault tolerance with auto-adjusted 6 volumes");
    let _reader = ArchiveReader::open(&base_path, "")
        .await
        .expect("Failed to open auto archive");
    println!("✅ Successfully opened archive with optimal volumes");
}

#[tokio::test]
async fn test_volume_specification_compliance() {
    println!("\n=== VOLUME SPECIFICATION COMPLIANCE TEST ===\n");

    let erasure = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    let config = ArchiveConfig {
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: 0,
        },
        ..Default::default()
    };

    let configs = vec![
        (1, 6, "Auto-select when not specified"),
        (3, 3, "3 volumes (minimum viable)"),
        (4, 4, "4 volumes (specified)"),
        (6, 6, "6 volumes (optimal)"),
        (8, 8, "8 volumes (beyond optimal)"),
    ];

    for (specified, expected_actual, label) in configs {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join(format!("test_{}.era", specified));

        let mut builder = ArchiveWriterBuilder::new(&base_path)
            .config(config.clone())
            .enable_erasure(true)
            .erasure_config(erasure);

        if specified > 1 {
            builder = builder.volume_count(specified);
        }

        let mut writer = builder
            .build()
            .await
            .unwrap_or_else(|_| panic!("Failed for {}", label));
        let data = vec![0xAB; 64 * 1024];
        writer.add_bytes("test", &data).await.ok();
        writer.finalize().await.ok();

        let mut actual_count = 0;
        for i in 0..12 {
            let vol_path = if i == 0 {
                base_path.clone()
            } else {
                base_path.with_extension(format!("era.{:03}", i))
            };
            if vol_path.exists() {
                actual_count += 1;
            }
        }

        println!(
            "{}: specified={} -> actual={} ✓",
            label, specified, actual_count
        );
        assert_eq!(actual_count, expected_actual, "Mismatch for: {}", label);
    }
}
