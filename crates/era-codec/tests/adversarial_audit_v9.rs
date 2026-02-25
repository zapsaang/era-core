//! # V9 Adversarial Audit — era-codec Decompression Security Tests
//!
//! Tests targeting: decompression bombs, unbounded allocations,
//! LZ4 level ignored, and erasure coding edge cases.

use era_codec::{
    Compressor, ErasureCoder, ErasureConfig, LZ4Compressor, NoCompressor, ZstdCompressor,
};

// ═══════════════════════════════════════════════════════════════════════
// V9-D1: Zstd decompression — no size limit (decompression bomb vector)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_d1a_zstd_roundtrip_basic() {
    let compressor = ZstdCompressor::default();
    let data = b"Hello, ERA! ".repeat(1000);
    let compressed = compressor.compress(&data).unwrap();
    let decompressed = compressor.decompress(&compressed).unwrap();
    assert_eq!(&decompressed[..], &data[..]);
}

#[test]
fn v9_d1b_zstd_compress_ratio_for_repetitive_data() {
    let compressor = ZstdCompressor::default();
    // Highly compressible data: 1MB of zeros
    let data = vec![0u8; 1_024_000];
    let compressed = compressor.compress(&data).unwrap();
    let ratio = data.len() as f64 / compressed.len() as f64;
    println!(
        "V9-D1b: Zstd compression ratio for 1MB zeros: {:.1}x ({} -> {} bytes)",
        ratio,
        data.len(),
        compressed.len()
    );
    // Ratio should be very high for all-zeros
    assert!(
        ratio > 100.0,
        "V9-D1b: Compression ratio for zeros should be >100x, got {:.1}x",
        ratio
    );
    // This demonstrates the decompression bomb risk: a tiny compressed payload
    // can expand to megabytes. No size limit exists in decompress().
    println!(
        "V9-D1b WARNING: A {}-byte compressed payload expands to {} bytes — \
         no decompression size limit enforced! DECOMPRESSION BOMB VECTOR.",
        compressed.len(),
        data.len()
    );
}

#[test]
fn v9_d1c_zstd_malformed_input() {
    let compressor = ZstdCompressor::default();
    let garbage = vec![0xFF, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02];
    let result = compressor.decompress(&garbage);
    assert!(result.is_err(), "V9-D1c: Decompressing garbage should fail");
}

#[test]
fn v9_d1d_zstd_empty_input() {
    let compressor = ZstdCompressor::default();
    let result = compressor.decompress(&[]);
    // Empty input should fail gracefully, not panic
    assert!(
        result.is_err(),
        "V9-D1d: Decompressing empty input should fail"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-D2: LZ4 decompression — size prefix from untrusted data
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_d2a_lz4_roundtrip_basic() {
    let compressor = LZ4Compressor::default();
    let data = b"LZ4 test data for ERA".repeat(100);
    let compressed = compressor.compress(&data).unwrap();
    let decompressed = compressor.decompress(&compressed).unwrap();
    assert_eq!(&decompressed[..], &data[..]);
}

#[test]
fn v9_d2b_lz4_crafted_size_prefix() {
    let compressor = LZ4Compressor::default();
    // Craft input with a massive size prefix (4 bytes LE)
    // Size = 256MB (0x10000000). Should be rejected by size cap.
    let mut crafted = vec![0u8; 20];
    crafted[0..4].copy_from_slice(&0x10000000u32.to_le_bytes()); // 256MB
    crafted[4..].fill(0xFF);

    let result = compressor.decompress(&crafted);
    assert!(
        result.is_err(),
        "V9-D2b: LZ4 with oversized prefix must be rejected"
    );
}

#[test]
fn v9_d2c_lz4_level_silently_ignored() {
    // The LZ4 level parameter is stored but never used
    let compressor_low = LZ4Compressor::new(1);
    let compressor_high = LZ4Compressor::new(12);
    let data = b"Test data for LZ4 level comparison".repeat(100);

    let compressed_low = compressor_low.compress(&data).unwrap();
    let compressed_high = compressor_high.compress(&data).unwrap();

    // Both produce identical output because level is silently ignored
    assert_eq!(
        compressed_low.len(),
        compressed_high.len(),
        "V9-D2c: LZ4 level parameter is silently ignored — \
         compression levels 1 and 12 produce identical output"
    );
    println!(
        "V9-D2c CONFIRMED: LZ4 level is silently ignored. \
         Level 1 ({} bytes) == Level 12 ({} bytes). \
         User's compression level preference is discarded.",
        compressed_low.len(),
        compressed_high.len()
    );
}

#[test]
fn v9_d2d_lz4_malformed_input() {
    let compressor = LZ4Compressor::default();
    let garbage = vec![0xFF; 100];
    let result = compressor.decompress(&garbage);
    // Should fail, not panic
    match result {
        Ok(_) => println!("V9-D2d: LZ4 accepted malformed input without error"),
        Err(e) => println!("V9-D2d: LZ4 properly rejected malformed input: {}", e),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// V9-D3: NoCompressor passthrough correctness
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_d3a_no_compressor_roundtrip() {
    let compressor = NoCompressor;
    let data = b"Uncompressed data";
    let compressed = compressor.compress(data).unwrap();
    assert_eq!(
        &compressed[..],
        &data[..],
        "V9-D3a: NoCompressor should passthrough"
    );
    let decompressed = compressor.decompress(&compressed).unwrap();
    assert_eq!(&decompressed[..], &data[..]);
}

// ═══════════════════════════════════════════════════════════════════════
// V9-D4: Erasure coding correctness
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_d4a_erasure_basic_roundtrip() {
    let config = ErasureConfig::new(4, 2).unwrap();
    let coder = ErasureCoder::new(config).unwrap();

    let data = b"This is test data for erasure coding in ERA v9 audit".to_vec();
    let shards = coder.encode(&data).unwrap();

    assert_eq!(
        shards.len(),
        6,
        "V9-D4a: Should produce 4 data + 2 parity shards"
    );

    // Recover with all shards present
    let shard_opts: Vec<Option<Vec<u8>>> = shards.iter().map(|s| Some(s.clone())).collect();
    let recovered = coder.decode(&shard_opts, data.len()).unwrap();
    assert_eq!(&recovered[..data.len()], &data[..]);
}

#[test]
fn v9_d4b_erasure_recovery_with_missing_shards() {
    let config = ErasureConfig::new(4, 2).unwrap();
    let coder = ErasureCoder::new(config).unwrap();

    let data = b"Erasure recovery test with missing shards".to_vec();
    let shards = coder.encode(&data).unwrap();

    // Remove 2 shards (within parity tolerance)
    let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
    shard_opts[0] = None; // Remove first data shard
    shard_opts[3] = None; // Remove last data shard

    let recovered = coder.decode(&shard_opts, data.len()).unwrap();
    assert_eq!(
        &recovered[..data.len()],
        &data[..],
        "V9-D4b: Should recover data with 2 missing shards"
    );
}

#[test]
fn v9_d4c_erasure_too_many_missing_fails() {
    let config = ErasureConfig::new(4, 2).unwrap();
    let coder = ErasureCoder::new(config).unwrap();

    let data = b"Too many missing shards test".to_vec();
    let shards = coder.encode(&data).unwrap();

    // Remove 3 shards (exceeds parity tolerance of 2)
    let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
    shard_opts[0] = None;
    shard_opts[1] = None;
    shard_opts[2] = None;

    let result = coder.decode(&shard_opts, data.len());
    assert!(
        result.is_err(),
        "V9-D4c: Should fail with too many missing shards"
    );
}

#[test]
fn v9_d4d_erasure_config_validation() {
    // Zero data shards
    let result = ErasureConfig::new(0, 2);
    assert!(result.is_err(), "V9-D4d: Zero data shards should fail");

    // Zero parity shards
    let result = ErasureConfig::new(4, 0);
    assert!(result.is_err(), "V9-D4d: Zero parity shards should fail");
}

// ═══════════════════════════════════════════════════════════════════════
// V9-D5: Compression level clamping
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_d5a_zstd_level_clamped() {
    // Extreme levels should be clamped to valid range
    let compressor = ZstdCompressor::new(100); // Way above max (22)
    let data = b"test data".repeat(100);
    let result = compressor.compress(&data);
    assert!(
        result.is_ok(),
        "V9-D5a: Extreme Zstd level should be clamped, not panic"
    );
}

#[test]
fn v9_d5b_zstd_negative_level() {
    let compressor = ZstdCompressor::new(-100);
    let data = b"test data".repeat(100);
    let result = compressor.compress(&data);
    assert!(
        result.is_ok(),
        "V9-D5b: Negative Zstd level should be clamped, not panic"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-D6: Compression with empty data
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_d6a_zstd_empty_data() {
    let compressor = ZstdCompressor::default();
    let compressed = compressor.compress(&[]).unwrap();
    let decompressed = compressor.decompress(&compressed).unwrap();
    assert!(
        decompressed.is_empty(),
        "V9-D6a: Empty data roundtrip should produce empty output"
    );
}

#[test]
fn v9_d6b_lz4_empty_data() {
    let compressor = LZ4Compressor::default();
    let compressed = compressor.compress(&[]).unwrap();
    let decompressed = compressor.decompress(&compressed).unwrap();
    assert!(
        decompressed.is_empty(),
        "V9-D6b: Empty data roundtrip should produce empty output"
    );
}
