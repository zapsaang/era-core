//! Matrix shard distribution, asserted against the production distribution API.
//!
//! Round-2 finding R2-04: the previous revision of this file re-implemented the
//! rotating-offset formula locally (fn distribute) and asserted properties of
//! that local copy, so a regression in era-volume's distribution could not turn
//! this test red. This version calls the same public production entry point the
//! write path uses (MatrixDistributionStrategy::calculate_volume through
//! DistributionCalculator, see VolumePool::shard_volume_slot) and additionally
//! checks the real on-disk shard layout of a created archive.

use era_common::{
    ArchiveConfig, CompressionAlgorithm, CompressionConfig, ErasureCodeConfig,
    MatrixDistributionConfig, MatrixDistributionStrategy,
};
use era_engine::{ArchiveReader, ArchiveWriterBuilder};
use era_storage::LocalStorageBackend;
use era_volume::{
    validate_canonical_erasure_volume_count, volume_path, DistributionCalculator,
    DistributionConfigExt, VolumeReader,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use tempfile::TempDir;

/// 4+2 Reed-Solomon, the workspace default.
const ERASURE: ErasureCodeConfig = ErasureCodeConfig {
    data_shards: 4,
    parity_shards: 2,
};

/// Canonical volume counts accepted by the production layout validator for 4+2.
const CANONICAL_VOLUME_COUNTS: [usize; 6] = [1, 2, 3, 6, 7, 8];

/// Volume counts rejected by the production layout validator for 4+2 (6 shards).
const INVALID_VOLUME_COUNTS: [usize; 2] = [4, 5];

fn production_strategy() -> MatrixDistributionStrategy {
    MatrixDistributionConfig::from_erasure_config(ERASURE).strategy
}

/// Volume placement of every shard of one block, from the production API.
fn placement(volume_count: usize, block_sequence: u64) -> Vec<usize> {
    let strategy = production_strategy();
    (0..ERASURE.total_shards())
        .map(|shard_idx| {
            strategy
                .calculate_volume(shard_idx, block_sequence, volume_count)
                .expect("production distribution must accept a canonical volume count")
        })
        .collect()
}

/// Every way to remove exactly "lost" of the volumes.
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

/// Largest number of volume losses under which every block of the production
/// layout still exposes at least data_shards shards (any subset of volumes).
fn max_recoverable_losses(volume_count: usize) -> usize {
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

#[test]
fn test_shard_distribution_analysis() {
    // 1. The production validator accepts exactly the layouts under test.
    for volume_count in CANONICAL_VOLUME_COUNTS {
        validate_canonical_erasure_volume_count(ERASURE.total_shards(), volume_count)
            .unwrap_or_else(|error| panic!("{volume_count} volumes must be canonical: {error}"));
    }
    for volume_count in INVALID_VOLUME_COUNTS {
        assert!(
            validate_canonical_erasure_volume_count(ERASURE.total_shards(), volume_count).is_err(),
            "{volume_count} volumes cannot be canonical for 6 shards"
        );
    }
    let config = MatrixDistributionConfig::from_erasure_config(ERASURE);
    assert_eq!(config.target_volumes, ERASURE.total_shards());
    assert!(config.validate_volume_count(6).is_ok());
    assert!(config.validate_volume_count(4).is_err());

    // 2. Production placement is a balanced partition and rotates by one volume
    //    per block sequence (the property the design claims).
    let total_shards = ERASURE.total_shards();
    for volume_count in CANONICAL_VOLUME_COUNTS {
        for block_sequence in 0..volume_count as u64 {
            let shards = placement(volume_count, block_sequence);
            assert_eq!(
                shards.len(),
                total_shards,
                "{volume_count} volumes: every shard must be placed"
            );
            assert!(
                shards.iter().all(|volume| *volume < volume_count),
                "{volume_count} volumes: placement out of range: {shards:?}"
            );

            let mut counts = vec![0usize; volume_count];
            for volume in &shards {
                counts[*volume] += 1;
            }
            assert_eq!(
                counts.iter().sum::<usize>(),
                total_shards,
                "{volume_count} volumes: placement dropped shards"
            );
            let max = counts.iter().copied().max().unwrap_or(0);
            let min = counts.iter().copied().min().unwrap_or(0);
            assert!(
                max - min <= 1,
                "{volume_count} volumes, block {block_sequence}: unbalanced placement {counts:?}"
            );

            let rotated = placement(volume_count, block_sequence + 1);
            for (shard_idx, (current, next)) in shards.iter().zip(rotated.iter()).enumerate() {
                assert_eq!(
                    *next,
                    (current + 1) % volume_count,
                    "{volume_count} volumes: shard {shard_idx} must advance one volume per block"
                );
            }
        }
    }

    // 3. Recovery bound of the production layout matches the documented promise.
    for (volume_count, expected) in [(1usize, 0usize), (2, 0), (3, 1), (6, 2), (7, 2), (8, 2)] {
        assert_eq!(
            max_recoverable_losses(volume_count),
            expected,
            "{volume_count} volumes with 4+2 must tolerate {expected} volume losses"
        );
        assert!(
            max_recoverable_losses(volume_count) <= usize::from(ERASURE.parity_shards),
            "cannot tolerate more volume losses than parity shards"
        );
    }
}

#[tokio::test]
async fn test_on_disk_layout_places_one_shard_per_volume() {
    let temp = TempDir::new().expect("temp dir");
    let base = temp.path().join("shard_layout.era");
    let data: Vec<u8> = (0..300 * 1024)
        .map(|index: usize| (index.wrapping_mul(7).wrapping_add(13)) as u8)
        .collect();
    write_erasure_archive(&base, 6, &data).await;

    // Map the durable VolumeId back to the volume sequence used in the layout.
    let backend = LocalStorageBackend::new(temp.path());
    let mut sequence_by_volume_id = BTreeMap::new();
    for sequence in 0..6u16 {
        let path = volume_path(&base, sequence);
        let file_name = path.file_name().expect("volume file name").to_owned();
        let reader = VolumeReader::open(&backend, Path::new(&file_name))
            .await
            .expect("open volume header");
        sequence_by_volume_id.insert(reader.header().volume_id(), sequence);
    }

    let mut archive = ArchiveReader::open(&base, "").await.expect("open archive");
    let catalog = archive.load_catalog().await.expect("load catalog");

    let mut erasure_blocks = 0usize;
    for location in &catalog.block_locations {
        if !location.is_erasure_coded() {
            continue;
        }
        erasure_blocks += 1;
        let info = location.erasure_info().expect("erasure info");
        assert_eq!(info.data_shards, ERASURE.data_shards);
        assert_eq!(info.parity_shards, ERASURE.parity_shards);

        let mut placed = BTreeSet::new();
        let first_volume_sequence = sequence_by_volume_id
            .get(&location.volume_id)
            .copied()
            .expect("shard 0 lives on a known archive volume");
        placed.insert(first_volume_sequence);
        placed.extend(location.shard_volumes().iter().copied());
        assert_eq!(
            placed.len(),
            ERASURE.total_shards(),
            "every shard of a stripe must live on its own volume, got {placed:?}"
        );
        assert_eq!(
            placed,
            (0..6u16).collect::<BTreeSet<_>>(),
            "a 4+2 layout over 6 volumes must use every volume exactly once"
        );
    }
    assert!(
        erasure_blocks > 0,
        "catalog must expose at least one erasure-coded data block"
    );
}
