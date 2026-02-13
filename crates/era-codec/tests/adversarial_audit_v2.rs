//! Adversarial Audit V2 — era-codec (Erasure Coding)
//!
//! Targets:
//! - FINDING-EC-1: shard_size() can return 0 for data_len=0 (div_ceil(0,4)=0, (0+1)&!1=0)
//! - FINDING-EC-2: encode_shards silently pads missing slots with zeros — no warning
//! - FINDING-EC-3: decode with mismatched shard sizes (some shards longer than others)
//! - FINDING-EC-4: recover_data_shards with oversized shard rejects correctly

use era_codec::{ErasureCoder, ErasureConfig};

/// FINDING-EC-1: shard_size for 1-byte data with 4 shards.
/// div_ceil(1,4)=1, (1+1)&!1=2. This is correct. But verify edge cases.
#[test]
fn test_shard_size_edge_cases() {
    let config = ErasureConfig::new(4, 2).unwrap();
    assert_eq!(config.shard_size(1), 2);
    assert_eq!(config.shard_size(2), 2);
    assert_eq!(config.shard_size(3), 2);
    assert_eq!(config.shard_size(4), 2);
    assert_eq!(config.shard_size(5), 2);
    assert_eq!(config.shard_size(8), 2);
    assert_eq!(config.shard_size(9), 4); // ceil(9/4)=3, (3+1)&!1=4

    // 1 data shard: shard_size == data_len rounded up to even
    let config1 = ErasureConfig::new(1, 1).unwrap();
    assert_eq!(config1.shard_size(1), 2);
    assert_eq!(config1.shard_size(2), 2);
    assert_eq!(config1.shard_size(3), 4);
}

/// FINDING-EC-3: decode with shards of inconsistent sizes.
/// If an attacker provides shards with different lengths, the decoder
/// uses the first available shard's length as shard_size.
#[test]
fn test_decode_inconsistent_shard_sizes() {
    let config = ErasureConfig::new(4, 2).unwrap();
    let coder = ErasureCoder::new(config).unwrap();

    let original = b"Test data for inconsistent shard size attack vector";
    let shards = coder.encode(original).unwrap();
    let shard_size = shards[0].len();

    // Create shards with inconsistent sizes
    let mut shard_options: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

    // Truncate shard 1 (make it shorter)
    if let Some(ref mut s) = shard_options[1] {
        s.truncate(shard_size / 2);
    }
    // Remove shard 0 to force recovery
    shard_options[0] = None;

    // The decoder will use shard 1's truncated length as shard_size for the decoder,
    // which will cause a mismatch. This should fail, not silently corrupt.
    let result = coder.decode(&shard_options, original.len());
    // Either succeeds with correct data or fails — must not silently corrupt
    match result {
        Ok(recovered) => assert_eq!(recovered, original, "Recovery must be exact"),
        Err(_) => {} // Acceptable: inconsistent shards rejected
    }
}

/// FINDING-EC-4: recover_data_shards rejects oversized shards.
#[test]
fn test_recover_data_shards_oversized_rejected() {
    let config = ErasureConfig::new(4, 2).unwrap();
    let coder = ErasureCoder::new(config).unwrap();

    let shards = vec![vec![1u8; 10], vec![2u8; 10], vec![3u8; 10], vec![4u8; 10]];
    let all_shards = coder.encode_shards(&shards).unwrap();
    let shard_size = all_shards[0].len();

    // Make one shard oversized
    let mut shard_options: Vec<Option<Vec<u8>>> = all_shards.into_iter().map(Some).collect();
    shard_options[0] = Some(vec![0xFF; shard_size + 100]); // oversized

    let result = coder.recover_data_shards(&shard_options, shard_size);
    assert!(result.is_err(), "Oversized shard must be rejected");
}

/// FINDING-EC-5: encode then decode roundtrip for all possible single-shard losses.
#[test]
fn test_exhaustive_single_shard_loss_recovery() {
    let config = ErasureConfig::new(4, 2).unwrap();
    let coder = ErasureCoder::new(config).unwrap();

    let original: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
    let shards = coder.encode(&original).unwrap();

    // Test losing each individual shard
    for lost_idx in 0..6 {
        let mut shard_options: Vec<Option<Vec<u8>>> =
            shards.iter().map(|s| Some(s.clone())).collect();
        shard_options[lost_idx] = None;

        let recovered = coder
            .decode(&shard_options, original.len())
            .unwrap_or_else(|e| panic!("Failed to recover with shard {} lost: {}", lost_idx, e));
        assert_eq!(
            recovered, original,
            "Data mismatch after losing shard {}",
            lost_idx
        );
    }
}

/// FINDING-EC-6: encode then decode roundtrip for all possible double-shard losses.
#[test]
fn test_exhaustive_double_shard_loss_recovery() {
    let config = ErasureConfig::new(4, 2).unwrap();
    let coder = ErasureCoder::new(config).unwrap();

    let original: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
    let shards = coder.encode(&original).unwrap();

    // Test losing every pair of shards (C(6,2) = 15 combinations)
    for i in 0..6 {
        for j in (i + 1)..6 {
            let mut shard_options: Vec<Option<Vec<u8>>> =
                shards.iter().map(|s| Some(s.clone())).collect();
            shard_options[i] = None;
            shard_options[j] = None;

            let recovered = coder
                .decode(&shard_options, original.len())
                .unwrap_or_else(|e| {
                    panic!("Failed to recover with shards {},{} lost: {}", i, j, e)
                });
            assert_eq!(
                recovered, original,
                "Data mismatch after losing shards {},{}",
                i, j
            );
        }
    }
}

/// FINDING-EC-7: Triple shard loss must fail for 4+2 config.
#[test]
fn test_triple_shard_loss_must_fail() {
    let config = ErasureConfig::new(4, 2).unwrap();
    let coder = ErasureCoder::new(config).unwrap();

    let original = vec![42u8; 1024];
    let shards = coder.encode(&original).unwrap();

    let mut shard_options: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
    shard_options[0] = None;
    shard_options[2] = None;
    shard_options[4] = None;

    let result = coder.decode(&shard_options, original.len());
    assert!(
        result.is_err(),
        "Triple shard loss must fail for 4+2 config"
    );
}
