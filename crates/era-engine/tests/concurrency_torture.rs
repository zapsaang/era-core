use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::time::sleep;

// Mock or Real usage? Real usage to test blocking.
// We need to construct ArchiveWriter.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_io_starvation_resistance() {
    let temp_dir = TempDir::new().unwrap();
    let root = temp_dir.path();

    // Create a large file (100MB) with random data to force CDC work
    let large_file_path = root.join("large_random.bin");
    {
        use std::io::Write;
        // Use std::fs for setup (allowed in tests)
        let mut file = std::fs::File::create(&large_file_path).unwrap();
        // 100MB
        let chunk = vec![0u8; 1024 * 1024];
        for _ in 0..100 {
            file.write_all(&chunk).unwrap();
        }
    }

    // Heartbeat Monitor
    let last_tick = Arc::new(AtomicUsize::new(0));
    let last_tick_clone = last_tick.clone();

    let monitor_handle = tokio::spawn(async move {
        let mut max_delay_ms = 0;
        let start = Instant::now();

        while start.elapsed() < Duration::from_secs(5) {
            let tick_start = Instant::now();
            sleep(Duration::from_millis(10)).await;
            let elapsed = tick_start.elapsed().as_millis() as u64;

            if elapsed > 50 {
                println!("⚠️  Heartbeat delayed by {}ms", elapsed);
            }
            if elapsed > max_delay_ms {
                max_delay_ms = elapsed;
            }

            last_tick_clone.fetch_add(1, Ordering::SeqCst);
        }
        max_delay_ms
    });

    // Ingest Task
    // We can't rely on ArchiveWriter being fully usable here without pulling all deps.
    // Instead we test the components we refactored: StreamingChunker / InputReader.

    // We will verify that reading and chunking the file via async interfaces fails the test
    // IF it blocks. Since we refactored, it SHOULD PASS.

    use era_ingest::ChunkerConfig;
    use era_ingest::StreamingChunker;
    use futures::stream::StreamExt;
    use tokio::fs::File;
    use tokio::io::BufReader;

    let ingest_handle = tokio::spawn(async move {
        let file = File::open(&large_file_path).await.unwrap();
        let reader = BufReader::new(file);
        let config = ChunkerConfig::default();
        let chunker = StreamingChunker::new(reader, config).into_stream();
        tokio::pin!(chunker);

        let mut count = 0;
        while let Some(chunk) = chunker.next().await {
            let _ = chunk.unwrap();
            count += 1;
        }
        count
    });

    let (max_delay, count) = tokio::join!(monitor_handle, ingest_handle);
    let max_delay = max_delay.unwrap();
    let count = count.unwrap();

    println!("Processed {} chunks", count);
    println!("Max heartbeat delay: {}ms", max_delay);

    assert!(
        max_delay < 50,
        "RUNTIME STARVATION DETECTED! Max delay {}ms > 50ms",
        max_delay
    );
}
