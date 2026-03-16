use era_common::{ArchiveConfig, CompressionAlgorithm, CompressionConfig, ErasureCodeConfig};
use era_engine::ArchiveWriterBuilder;
use std::path::Path;
use tempfile::TempDir;

fn no_compression_config() -> ArchiveConfig {
    ArchiveConfig {
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: 0,
        },
        ..Default::default()
    }
}

fn count_volume_files(base_path: &Path, max_scan: usize) -> usize {
    (0..max_scan)
        .filter(|idx| {
            let path = if *idx == 0 {
                base_path.to_path_buf()
            } else {
                base_path.with_extension(format!("era.{:03}", idx))
            };
            path.exists()
        })
        .count()
}

#[tokio::test]
async fn test_omitted_volume_count_defaults_to_total_shards_for_4_plus_2() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().join("default_volumes.era");

    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .password("test_password")
        .config(no_compression_config())
        .enable_erasure(true)
        .erasure_config(ErasureCodeConfig::new(4, 2))
        .build()
        .await
        .expect("builder should succeed");

    writer
        .add_bytes("payload.bin", &vec![0xAA; 64 * 1024])
        .await
        .expect("add_bytes should succeed");
    writer.finalize().await.expect("finalize should succeed");

    let actual_count = count_volume_files(&base_path, 16);
    assert_eq!(actual_count, 6, "omitted count should default to 6");
}

#[tokio::test]
async fn test_explicit_low_volume_counts_are_respected_for_4_plus_2() {
    for requested in [1usize, 2, 3, 6] {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join(format!("explicit_{requested}.era"));

        let mut writer = ArchiveWriterBuilder::new(&base_path)
            .password("test_password")
            .config(no_compression_config())
            .enable_erasure(true)
            .erasure_config(ErasureCodeConfig::new(4, 2))
            .volume_count(requested)
            .build()
            .await
            .unwrap_or_else(|e| panic!("build should succeed for {requested}: {e}"));

        writer
            .add_bytes("payload.bin", &vec![0xBB; 48 * 1024])
            .await
            .unwrap_or_else(|e| panic!("add_bytes should succeed for {requested}: {e}"));
        writer
            .finalize()
            .await
            .unwrap_or_else(|e| panic!("finalize should succeed for {requested}: {e}"));

        let actual_count = count_volume_files(&base_path, 16);
        assert_eq!(
            actual_count, requested,
            "explicit volume count {requested} should be preserved"
        );
    }
}

#[tokio::test]
async fn test_invalid_low_volume_counts_fail_for_4_plus_2() {
    for requested in [4usize, 5] {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join(format!("invalid_{requested}.era"));

        let result = ArchiveWriterBuilder::new(&base_path)
            .password("test_password")
            .config(no_compression_config())
            .enable_erasure(true)
            .erasure_config(ErasureCodeConfig::new(4, 2))
            .volume_count(requested)
            .build()
            .await;

        assert!(
            result.is_err(),
            "build should fail for invalid requested count {requested}"
        );
        let err = result
            .err()
            .expect("invalid count should return an error")
            .to_string();
        assert!(
            err.contains("divide") || err.contains("total shards"),
            "error should mention canonical divisibility rule, got: {err}"
        );
    }
}
