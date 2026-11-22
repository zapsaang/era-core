//! End-to-end fault-tolerant recovery limits of the production write/read path.
//!
//! Round-2 finding R2-04: this file previously printed recovery outcomes without
//! asserting them and re-derived the shard distribution locally. It now creates
//! real archives, removes real volumes and asserts the recovery boundary that the
//! production distribution API implies, so a regression in the engine or in the
//! distribution turns this file red.

use era_common::{ArchiveConfig, CompressionAlgorithm, CompressionConfig, ErasureCodeConfig};
use era_engine::{ArchiveReader, ArchiveWriterBuilder, ExtractOptions};
use era_volume::{volume_path, DistributionCalculator};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// 4+2 Reed-Solomon, the workspace default.
const ERASURE: ErasureCodeConfig = ErasureCodeConfig {
    data_shards: 4,
    parity_shards: 2,
};

fn production_strategy() -> era_common::MatrixDistributionStrategy {
    use era_volume::DistributionConfigExt;
    era_common::MatrixDistributionConfig::from_erasure_config(ERASURE).strategy
}

fn removed_subsets(volume_count: usize, lost: usize) -> Vec<Vec<usize>> {
    fn recurse(
        start: usize,
        volume_count: usize,
        remaining: usize,
        current: &mut Vec<usize>,
        out: &mut Vec<Vec<usize>>,
    ) {
        if remaining == 0 {
            out.push(current.clone());
            return;
        }
        for volume in start..volume_count {
            current.push(volume);
            recurse(volume + 1, volume_count, remaining - 1, current, out);
            current.pop();
        }
    }
    let mut out = Vec::new();
    recurse(0, volume_count, lost, &mut Vec::new(), &mut out);
    out
}

/// Largest number of volume losses the production placement tolerates for every
/// block sequence (any subset of volumes still leaves >= data_shards shards).
fn production_tolerance(volume_count: usize) -> usize {
    let strategy = production_strategy();
    let data_shards = usize::from(ERASURE.data_shards);
    let mut tolerance = 0;
    'losses: for lost in 1..=volume_count {
        for removed in removed_subsets(volume_count, lost) {
            for block_sequence in 0..volume_count as u64 {
                let surviving = (0..ERASURE.total_shards())
                    .filter(|shard_idx| {
                        let volume = strategy
                            .calculate_volume(*shard_idx, block_sequence, volume_count)
                            .expect("canonical layout");
                        !removed.contains(&volume)
                    })
                    .count();
                if surviving < data_shards {
                    break 'losses;
                }
            }
        }
        tolerance = lost;
    }
    tolerance
}

async fn write_erasure_archive(base: &Path, volume_count: usize, data: &[u8]) {
    let config = ArchiveConfig {
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: 0,
        },
        ..Default::default()
    };
    let mut writer = ArchiveWriterBuilder::new(base)
        .config(config)
        .enable_erasure(true)
        .erasure_config(ERASURE)
        .volume_count(volume_count)
        .build()
        .await
        .expect("build erasure writer");
    writer
        .add_bytes("payload.bin", data)
        .await
        .expect("add payload");
    writer.finalize().await.expect("finalize archive");
}

/// Copy the archive into a scratch directory, delete the first "lost" volumes and
/// extract from the first surviving volume. Returns the extracted payload bytes.
async fn extract_after_prefix_loss(
    archive_base: &Path,
    scratch: &Path,
    volume_count: usize,
    lost: usize,
) -> Result<Vec<u8>, String> {
    let copy_base = scratch.join("copy.era");
    for sequence in 0..volume_count as u16 {
        fs::copy(
            volume_path(archive_base, sequence),
            volume_path(&copy_base, sequence),
        )
        .map_err(|error| format!("copy volume {sequence}: {error}"))?;
    }
    for sequence in 0..lost as u16 {
        fs::remove_file(volume_path(&copy_base, sequence))
            .map_err(|error| format!("delete volume {sequence}: {error}"))?;
    }

    let open_from = volume_path(&copy_base, lost as u16);
    let mut archive = ArchiveReader::open(&open_from, "")
        .await
        .map_err(|error| format!("open after losing {lost} volume(s): {error}"))?;
    let extracted_stats = archive
        .extract_all(&ExtractOptions::new(scratch.join("extract")))
        .await
        .map_err(|error| format!("extract after losing {lost} volume(s): {error}"))?;
    if extracted_stats.extracted == 0 {
        return Err("extraction reported no extracted files".to_string());
    }
    fs::read(scratch.join("extract").join("payload.bin"))
        .map_err(|error| format!("read extracted payload: {error}"))
}

#[tokio::test]
async fn test_precise_fault_tolerance_limits() {
    let payload: Vec<u8> = (0..300 * 1024)
        .map(|index: usize| (index.wrapping_mul(7).wrapping_add(13)) as u8)
        .collect();

    // Design promise for 4+2: 3 volumes tolerate 1 loss, one-shard-per-volume
    // layouts (6 or more volumes) tolerate 2 losses.
    for (volume_count, expected_tolerance) in [(3usize, 1usize), (6, 2), (8, 2)] {
        assert_eq!(
            production_tolerance(volume_count),
            expected_tolerance,
            "{volume_count}-volume layout must match the documented tolerance"
        );

        let temp = TempDir::new().expect("temp dir");
        let archive = temp.path().join("fault_tolerance.era");
        write_erasure_archive(&archive, volume_count, &payload).await;

        for lost in 1..volume_count {
            let scratch = TempDir::new().expect("scratch dir");
            let outcome =
                extract_after_prefix_loss(&archive, scratch.path(), volume_count, lost).await;
            if lost <= expected_tolerance {
                match outcome {
                    Ok(extracted) => assert_eq!(
                        extracted, payload,
                        "{volume_count} volumes, {lost} lost: recovered bytes differ"
                    ),
                    Err(error) => panic!(
                        "{volume_count} volumes, {lost} lost: expected recovery, got error: {error}"
                    ),
                }
            } else {
                match outcome {
                    Ok(_) => panic!(
                        "{volume_count} volumes, {lost} lost: expected extraction to fail beyond the tolerance of {expected_tolerance}"
                    ),
                    Err(error) => assert!(
                        error.contains("Erasure") || error.contains("Not enough shards"),
                        "{volume_count} volumes, {lost} lost: expected an erasure error, got: {error}"
                    ),
                }
            }
        }
    }
}
