//! Design promises of the matrix distribution, verified against production.
//!
//! Round-2 finding R2-04: the previous revision re-implemented the sharding and
//! tolerance math locally (total_shards.div_ceil(volumes), parity/shards_per_vol)
//! and printed end-to-end outcomes without asserting them. This version asks the
//! production distribution API for the layout and asserts the design promises on
//! real archives.

use era_common::{
    ArchiveConfig, CompressionAlgorithm, CompressionConfig, ErasureCodeConfig,
    MatrixDistributionConfig,
};
use era_engine::{ArchiveReader, ArchiveWriterBuilder, ExtractOptions};
use era_volume::{
    validate_canonical_erasure_volume_count, volume_path, DistributionCalculator,
    DistributionConfigExt,
};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// 4+2 Reed-Solomon, the workspace default.
const ERASURE: ErasureCodeConfig = ErasureCodeConfig {
    data_shards: 4,
    parity_shards: 2,
};

fn production_strategy() -> era_common::MatrixDistributionStrategy {
    MatrixDistributionConfig::from_erasure_config(ERASURE).strategy
}

/// Volume placement of every shard of one block, from the production API.
fn placement(volume_count: usize, block_sequence: u64) -> Vec<usize> {
    let strategy = production_strategy();
    (0..ERASURE.total_shards())
        .map(|shard_idx| {
            strategy
                .calculate_volume(shard_idx, block_sequence, volume_count)
                .expect("canonical layout")
        })
        .collect()
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

/// Maximum volume losses the production placement tolerates, for any subset.
fn production_tolerance(volume_count: usize) -> usize {
    let data_shards = usize::from(ERASURE.data_shards);
    let mut tolerance = 0;
    'losses: for lost in 1..=volume_count {
        for removed in removed_subsets(volume_count, lost) {
            for block_sequence in 0..volume_count as u64 {
                let surviving = placement(volume_count, block_sequence)
                    .iter()
                    .filter(|volume| !removed.contains(volume))
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

/// True when some loss set of exactly "lost" volumes leaves fewer than
/// data_shards shards for at least one block sequence.
fn marginal_loss_breaks(volume_count: usize, lost: usize) -> bool {
    if lost > volume_count {
        return false;
    }
    let data_shards = usize::from(ERASURE.data_shards);
    removed_subsets(volume_count, lost)
        .into_iter()
        .any(|removed| {
            (0..volume_count as u64).any(|block_sequence| {
                placement(volume_count, block_sequence)
                    .iter()
                    .filter(|volume| !removed.contains(volume))
                    .count()
                    < data_shards
            })
        })
}

async fn write_erasure_archive(base: &Path, volume_count: Option<usize>, data: &[u8]) {
    let config = ArchiveConfig {
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: 0,
        },
        ..Default::default()
    };
    let mut builder = ArchiveWriterBuilder::new(base)
        .config(config)
        .enable_erasure(true)
        .erasure_config(ERASURE);
    if let Some(volume_count) = volume_count {
        builder = builder.volume_count(volume_count);
    }
    let mut writer = builder.build().await.expect("build erasure writer");
    writer
        .add_bytes("payload.bin", data)
        .await
        .expect("add payload");
    writer.finalize().await.expect("finalize archive");
}

/// Copy an archive, delete the first "lost" volumes, open the first survivor and
/// return the extraction result.
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
    archive
        .extract_all(&ExtractOptions::new(scratch.join("extract")))
        .await
        .map_err(|error| format!("extract after losing {lost} volume(s): {error}"))?;
    fs::read(scratch.join("extract").join("payload.bin"))
        .map_err(|error| format!("read extracted payload: {error}"))
}

#[test]
fn test_sharding_math_verification() {
    // Divisibility/validation promises: 6 shards need canonical volume counts.
    for volume_count in [1usize, 2, 3, 6, 7, 8] {
        validate_canonical_erasure_volume_count(ERASURE.total_shards(), volume_count)
            .unwrap_or_else(|error| panic!("{volume_count} must be canonical: {error}"));
    }
    for volume_count in [4usize, 5] {
        validate_canonical_erasure_volume_count(ERASURE.total_shards(), volume_count)
            .expect_err("non-divisible volume counts must be rejected");
    }

    // Production layout: balanced partition, rotation by one volume per block.
    let total_shards = ERASURE.total_shards();
    for volume_count in [1usize, 2, 3, 6, 7, 8] {
        for block_sequence in 0..volume_count as u64 {
            let shards = placement(volume_count, block_sequence);
            assert_eq!(shards.len(), total_shards);
            let mut counts = vec![0usize; volume_count];
            for volume in &shards {
                assert!(*volume < volume_count);
                counts[*volume] += 1;
            }
            assert_eq!(counts.iter().sum::<usize>(), total_shards);
            let max = counts.iter().copied().max().unwrap_or(0);
            let min = counts.iter().copied().min().unwrap_or(0);
            assert!(
                max - min <= 1,
                "{volume_count} volumes: unbalanced {counts:?}"
            );
            let rotated = placement(volume_count, block_sequence + 1);
            for (current, next) in shards.iter().zip(rotated.iter()) {
                assert_eq!(*next, (current + 1) % volume_count);
            }
        }

        // The tolerance is the largest loss count that keeps every block
        // recoverable, and losing one more volume must break that.
        let tolerance = production_tolerance(volume_count);
        let expected = match volume_count {
            1 | 2 => 0,
            3 => 1,
            6..=8 => 2,
            other => panic!("unexpected volume count: {other}"),
        };
        assert_eq!(
            tolerance, expected,
            "{volume_count} volumes with 4+2 must tolerate {expected} volume loss(es)"
        );
        assert!(tolerance <= usize::from(ERASURE.parity_shards));
        if tolerance < volume_count {
            assert!(
                marginal_loss_breaks(volume_count, tolerance + 1),
                "{volume_count} volumes: losing {} volume(s) must break recovery",
                tolerance + 1
            );
        }
    }
}

#[tokio::test]
async fn test_design_promise_verification() {
    let payload: Vec<u8> = (0..128 * 1024)
        .map(|index: usize| (index.wrapping_mul(17).wrapping_add(3)) as u8)
        .collect();
    let temp = TempDir::new().expect("temp dir");
    let archive = temp.path().join("design_promise.era");
    write_erasure_archive(&archive, Some(6), &payload).await;

    // Promise: 4+2 across 6 volumes survives two volume losses.
    for lost in [1usize, 2] {
        let scratch = TempDir::new().expect("scratch dir");
        let recovered = extract_after_prefix_loss(&archive, scratch.path(), 6, lost)
            .await
            .unwrap_or_else(|error| panic!("losing {lost} of 6 volumes must recover: {error}"));
        assert_eq!(
            recovered, payload,
            "losing {lost} volumes changed the payload"
        );
    }

    // Promise: a third loss exceeds the parity budget and must fail cleanly.
    let scratch = TempDir::new().expect("scratch dir");
    let outcome = extract_after_prefix_loss(&archive, scratch.path(), 6, 3).await;
    match outcome {
        Ok(_) => panic!("losing 3 of 6 volumes must not extract successfully"),
        Err(error) => assert!(
            error.contains("Erasure") || error.contains("Not enough shards"),
            "expected an erasure error, got: {error}"
        ),
    }
}

#[tokio::test]
async fn test_actual_implementation_behavior() {
    let payload: Vec<u8> = (0..128 * 1024)
        .map(|index: usize| (index.wrapping_mul(19).wrapping_add(7)) as u8)
        .collect();
    let temp = TempDir::new().expect("temp dir");
    let archive = temp.path().join("auto_volumes.era");
    // Omitting volume_count: the engine promises to auto-select the optimal
    // one-shard-per-volume layout (total_shards volumes).
    write_erasure_archive(&archive, None, &payload).await;

    let mut created = 0usize;
    for sequence in 0..ERASURE.total_shards() as u16 {
        if volume_path(&archive, sequence).exists() {
            created += 1;
        }
    }
    assert_eq!(
        created,
        ERASURE.total_shards(),
        "auto-selected layout must create one volume per shard"
    );
    assert!(
        !volume_path(&archive, ERASURE.total_shards() as u16).exists(),
        "auto-selected layout must not create a spurious extra volume"
    );

    let archive_reader = ArchiveReader::open(&archive, "")
        .await
        .expect("open auto-selected archive");
    assert_eq!(
        archive_reader.expected_volume_count(),
        ERASURE.total_shards(),
        "header must advertise the auto-selected volume count"
    );
    drop(archive_reader);

    let scratch = TempDir::new().expect("scratch dir");
    let recovered = extract_after_prefix_loss(&archive, scratch.path(), ERASURE.total_shards(), 2)
        .await
        .expect("auto-selected layout must tolerate two volume losses");
    assert_eq!(recovered, payload);
}
