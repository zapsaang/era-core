//! Integration tests for zero-copy streaming chunker
//!
//! These tests verify that the optimized implementation produces
//! identical results to the original while being more efficient.

use era_ingest::{ChunkerConfig, StreamingChunker, StreamingChunkerZeroCopy};
use std::io::Cursor;

/// Generate deterministic test data with patterns
fn generate_test_data(size: usize, pattern: u8) -> Vec<u8> {
    (0..size).map(|i| pattern.wrapping_add((i % 251) as u8)).collect()
}

#[tokio::test]
async fn test_identical_chunks_small_file() {
    let config = ChunkerConfig::default();
    let data = generate_test_data(100_000, 42);

    let chunks_orig = get_chunks_original(&data, config.clone()).await;
    let chunks_zero = get_chunks_zerocopy(&data, config).await;

    assert_chunks_identical(&chunks_orig, &chunks_zero);
}

#[tokio::test]
async fn test_identical_chunks_medium_file() {
    let config = ChunkerConfig::default();
    let data = generate_test_data(5_000_000, 17);

    let chunks_orig = get_chunks_original(&data, config.clone()).await;
    let chunks_zero = get_chunks_zerocopy(&data, config).await;

    assert_chunks_identical(&chunks_orig, &chunks_zero);
}

#[tokio::test]
async fn test_identical_chunks_large_file() {
    let config = ChunkerConfig::default();
    let data = generate_test_data(20_000_000, 99);

    let chunks_orig = get_chunks_original(&data, config.clone()).await;
    let chunks_zero = get_chunks_zerocopy(&data, config).await;

    assert_chunks_identical(&chunks_orig, &chunks_zero);
}

#[tokio::test]
async fn test_identical_chunks_with_small_chunk_config() {
    let config = ChunkerConfig::new(4 * 1024, 16 * 1024, 64 * 1024);
    let data = generate_test_data(1_000_000, 55);

    let chunks_orig = get_chunks_original(&data, config.clone()).await;
    let chunks_zero = get_chunks_zerocopy(&data, config).await;

    assert_chunks_identical(&chunks_orig, &chunks_zero);
}

#[tokio::test]
async fn test_identical_chunks_with_large_chunk_config() {
    let config = ChunkerConfig::new(16 * 1024, 256 * 1024, 1024 * 1024);
    let data = generate_test_data(10_000_000, 77);

    let chunks_orig = get_chunks_original(&data, config.clone()).await;
    let chunks_zero = get_chunks_zerocopy(&data, config).await;

    assert_chunks_identical(&chunks_orig, &chunks_zero);
}

#[tokio::test]
async fn test_wraparound_edge_case() {
    // This test specifically targets the buffer wraparound logic
    // by using a file size that will trigger multiple buffer fills
    let config = ChunkerConfig::default();
    // Size designed to cause head pointer to advance past 50% mark multiple times
    let data = generate_test_data(3_000_000, 123);

    let chunks_orig = get_chunks_original(&data, config.clone()).await;
    let chunks_zero = get_chunks_zerocopy(&data, config).await;

    assert_chunks_identical(&chunks_orig, &chunks_zero);
}

#[tokio::test]
async fn test_small_file_below_min_chunk() {
    let config = ChunkerConfig::default();
    let data = generate_test_data(2048, 200); // Smaller than min chunk size

    let chunks_orig = get_chunks_original(&data, config.clone()).await;
    let chunks_zero = get_chunks_zerocopy(&data, config).await;

    assert_chunks_identical(&chunks_orig, &chunks_zero);
    assert_eq!(chunks_orig.len(), 1, "Small file should produce one chunk");
}

#[tokio::test]
async fn test_exact_boundary_size() {
    let config = ChunkerConfig::default();
    // Exact multiple of average chunk size
    let data = generate_test_data(config.avg_size * 10, 88);

    let chunks_orig = get_chunks_original(&data, config.clone()).await;
    let chunks_zero = get_chunks_zerocopy(&data, config).await;

    assert_chunks_identical(&chunks_orig, &chunks_zero);
}

#[tokio::test]
async fn test_highly_compressible_data() {
    let config = ChunkerConfig::default();
    // All zeros - highly compressible
    let data = vec![0u8; 5_000_000];

    let chunks_orig = get_chunks_original(&data, config.clone()).await;
    let chunks_zero = get_chunks_zerocopy(&data, config).await;

    assert_chunks_identical(&chunks_orig, &chunks_zero);
}

#[tokio::test]
async fn test_random_like_data() {
    let config = ChunkerConfig::default();
    // Pseudo-random data (low compressibility)
    let data: Vec<u8> = (0..5_000_000u64)
        .map(|i| ((i.wrapping_mul(1103515245).wrapping_add(12345)) >> 16) as u8)
        .collect();

    let chunks_orig = get_chunks_original(&data, config.clone()).await;
    let chunks_zero = get_chunks_zerocopy(&data, config).await;

    assert_chunks_identical(&chunks_orig, &chunks_zero);
}

// Helper functions

async fn get_chunks_original(data: &[u8], config: ChunkerConfig) -> Vec<(Vec<u8>, era_common::ChunkHash)> {
    let reader = Cursor::new(data.to_vec());
    let mut chunker = StreamingChunker::new(reader, config);
    let mut chunks = Vec::new();
    
    while let Ok(Some(chunk)) = chunker.next_chunk().await {
        chunks.push((chunk.data.to_vec(), chunk.hash));
    }
    
    chunks
}

async fn get_chunks_zerocopy(data: &[u8], config: ChunkerConfig) -> Vec<(Vec<u8>, era_common::ChunkHash)> {
    let reader = Cursor::new(data.to_vec());
    let mut chunker = StreamingChunkerZeroCopy::new(reader, config);
    let mut chunks = Vec::new();
    
    while let Ok(Some(chunk)) = chunker.next_chunk().await {
        chunks.push((chunk.data.to_vec(), chunk.hash));
    }
    
    chunks
}

fn assert_chunks_identical(
    chunks_orig: &[(Vec<u8>, era_common::ChunkHash)],
    chunks_zero: &[(Vec<u8>, era_common::ChunkHash)],
) {
    assert_eq!(
        chunks_orig.len(),
        chunks_zero.len(),
        "Different number of chunks: original={}, zerocopy={}",
        chunks_orig.len(),
        chunks_zero.len()
    );

    for (i, ((data_orig, hash_orig), (data_zero, hash_zero))) in
        chunks_orig.iter().zip(chunks_zero.iter()).enumerate()
    {
        assert_eq!(
            data_orig.len(),
            data_zero.len(),
            "Chunk {} has different size: original={}, zerocopy={}",
            i,
            data_orig.len(),
            data_zero.len()
        );

        assert_eq!(
            hash_orig, hash_zero,
            "Chunk {} has different hash",
            i
        );

        assert_eq!(
            data_orig, data_zero,
            "Chunk {} has different content",
            i
        );
    }

    // Verify total data size matches
    let total_orig: usize = chunks_orig.iter().map(|(d, _)| d.len()).sum();
    let total_zero: usize = chunks_zero.iter().map(|(d, _)| d.len()).sum();
    assert_eq!(total_orig, total_zero, "Total data size mismatch");
}
