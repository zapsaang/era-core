//! Missing-volume failure modes and erasure-layout requirements, checked against
//! production APIs.
//!
//! Round-2 finding R2-04: the previous revision printed a "root cause analysis"
//! without asserting engine behaviour and re-derived the shard/tolerance
//! arithmetic locally. This version drives the real engine (create, lose volumes,
//! extract) and uses era-volume's public distribution/validation API for the
//! layout arithmetic.

use era_common::{
    ArchiveConfig, CompressionAlgorithm, CompressionConfig, EraError, ErasureCodeConfig,
    MatrixDistributionConfig,
};
use era_engine::{ArchiveReader, ArchiveWriterBuilder, ExtractOptions};
use era_volume::{
    validate_canonical_erasure_volume_count, validate_erasure_volume_count, volume_path,
    DistributionCalculator, DistributionConfigExt,
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

/// Copy an archive, drop the first "lost" volumes and open from the first
/// surviving volume. Returns the missing-volume report and extraction result.
async fn open_after_prefix_loss(
    archive_base: &Path,
    scratch: &Path,
    volume_count: usize,
    lost: usize,
) -> (Vec<usize>, Result<Vec<u8>, EraError>) {
    let copy_base = scratch.join("copy.era");
    for sequence in 0..volume_count as u16 {
        fs::copy(
            volume_path(archive_base, sequence),
            volume_path(&copy_base, sequence),
        )
        .expect("copy volume");
    }
    for sequence in 0..lost as u16 {
        fs::remove_file(volume_path(&copy_base, sequence)).expect("delete volume");
    }

    let open_from = volume_path(&copy_base, lost as u16);
    let mut archive = ArchiveReader::open(&open_from, "")
        .await
        .expect("archive must still open while enough volumes survive");
    let missing = archive.missing_volume_indices().to_vec();
    let outcome = async {
        archive
            .extract_all(&ExtractOptions::new(scratch.join("extract")))
            .await?;
        fs::read(scratch.join("extract").join("payload.bin")).map_err(EraError::Io)
    }
    .await;
    (missing, outcome)
}

/// 4+2 over 3 volumes tolerates exactly one volume loss; losing two volumes must
/// fail with a clean erasure error (the historical "root cause" was an unchecked
/// short read that panicked in the reader).
#[tokio::test]
async fn test_panic_root_cause_analysis() {
    let payload: Vec<u8> = (0..128 * 1024)
        .map(|index: usize| (index.wrapping_mul(11).wrapping_add(5)) as u8)
        .collect();
    let temp = TempDir::new().expect("temp dir");
    let archive = temp.path().join("three_volumes.era");
    write_erasure_archive(&archive, 3, &payload).await;

    let baseline_scratch = TempDir::new().expect("scratch dir");
    let (missing, baseline) = open_after_prefix_loss(&archive, baseline_scratch.path(), 3, 0).await;
    assert!(missing.is_empty(), "baseline must see every volume");
    assert_eq!(baseline.expect("baseline extraction"), payload);

    let one_lost_scratch = TempDir::new().expect("scratch dir");
    let (missing, recovered) =
        open_after_prefix_loss(&archive, one_lost_scratch.path(), 3, 1).await;
    assert_eq!(missing, vec![0], "volume 0 must be reported missing");
    assert_eq!(
        recovered.expect("one lost volume is within the 3-volume tolerance"),
        payload
    );

    let two_lost_scratch = TempDir::new().expect("scratch dir");
    let (missing, failed) = open_after_prefix_loss(&archive, two_lost_scratch.path(), 3, 2).await;
    assert_eq!(
        missing,
        vec![0, 1],
        "volumes 0 and 1 must be reported missing"
    );
    match failed {
        Ok(_) => panic!("losing 2 of 3 volumes must not extract successfully"),
        Err(EraError::ErasureError(message)) => assert!(
            message.contains("Not enough shards"),
            "expected a shard shortage error, got: {message}"
        ),
        Err(other) => panic!("expected a clean erasure error, got: {other}"),
    }
}

/// Canonical-layout validation and the recovery bound of the production
/// distribution, for both the default 4+2 and a 6+3 layout.
#[test]
fn test_volume_requirements_strict() {
    let total_shards = ERASURE.total_shards();
    for volume_count in [1usize, 2, 3, 6, 7, 8] {
        validate_canonical_erasure_volume_count(total_shards, volume_count)
            .unwrap_or_else(|error| panic!("{volume_count} volumes must be canonical: {error}"));
    }
    for volume_count in [4usize, 5] {
        validate_canonical_erasure_volume_count(total_shards, volume_count)
            .expect_err("4 and 5 volumes cannot host 6 shards canonically");
        let message = validate_erasure_volume_count(ERASURE, volume_count)
            .expect_err("production helper must reject non-canonical volume counts")
            .to_string();
        assert!(
            message.contains("total shards") || message.contains("divide"),
            "unexpected rejection message: {message}"
        );
    }

    let config = MatrixDistributionConfig::from_erasure_config(ERASURE);
    assert_eq!(config.target_volumes, total_shards);
    for volume_count in [1usize, 2, 3, 6] {
        assert!(
            config.validate_volume_count(volume_count).is_ok(),
            "{volume_count} volumes must pass MatrixDistributionConfig validation"
        );
    }

    // Design promise: 4+2 over one-shard-per-volume layouts tolerates 2 losses,
    // and it degrades to 1 loss at 3 volumes (2 shards per volume).
    for (volume_count, expected) in [(1usize, 0usize), (2, 0), (3, 1), (6, 2)] {
        assert_eq!(
            production_tolerance(volume_count),
            expected,
            "{volume_count} volumes must tolerate {expected} loss(es)"
        );
        assert!(expected <= usize::from(ERASURE.parity_shards));
    }

    let six_plus_three = ErasureCodeConfig {
        data_shards: 6,
        parity_shards: 3,
    };
    for volume_count in [1usize, 3, 9, 10] {
        validate_erasure_volume_count(six_plus_three, volume_count)
            .unwrap_or_else(|error| panic!("{volume_count} volumes must be canonical: {error}"));
    }
    for volume_count in [2usize, 4, 5, 6, 7, 8] {
        validate_erasure_volume_count(six_plus_three, volume_count)
            .expect_err("non-canonical volume count must be rejected for 6+3");
    }
}
