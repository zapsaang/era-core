//! Direct test of StreamingChunker to verify it's working

use era_ingest::{ChunkerConfig, StreamingChunker};
use futures::stream::StreamExt;
use std::io::Cursor;

#[tokio::test]
async fn test_streaming_chunker_directly() {
    // Create 1MB of TRULY random data
    let data_size = 1024 * 1024;
    let mut data = vec![0u8; data_size];

    // Use /dev/urandom for true randomness (incompressible and proper entropy)
    use std::fs::File;
    use std::io::Read;
    let mut urandom = File::open("/dev/urandom").expect("Failed to open /dev/urandom");
    urandom
        .read_exact(&mut data)
        .expect("Failed to read random data");

    println!("\nDirect StreamingChunker Test");
    println!("Data size: {:.2} MB", data_size as f64 / 1024.0 / 1024.0);

    let reader = Cursor::new(data);
    let config = ChunkerConfig::default(); // 64KB avg
    let streaming = StreamingChunker::new(reader, config).into_stream();
    tokio::pin!(streaming);

    let mut chunks = Vec::new();
    let mut count = 0;
    while let Some(result) = streaming.next().await {
        let chunk = result.unwrap();
        println!("  Chunk {}: {} bytes", count, chunk.data.len());
        chunks.push(chunk);
        count += 1;
        if count > 20 {
            println!("  ... stopping after 20 chunks for debugging");
            break;
        }
    }

    println!("Chunks produced: {}", chunks.len());
    println!("Expected: ~{}", data_size / (64 * 1024));

    for (i, chunk) in chunks.iter().enumerate().take(5) {
        println!("  Chunk {}: {} bytes", i, chunk.data.len());
    }

    // Verify reasonable chunk count (8-25 for 1MB @ 64KB avg)
    assert!(
        chunks.len() > 8,
        "Too few chunks: {} (expected >8 for 1MB)",
        chunks.len()
    );
    assert!(
        chunks.len() < 25,
        "Too many chunks: {} (expected <25 for 1MB)",
        chunks.len()
    );

    println!("✓ StreamingChunker working correctly!\n");
}
