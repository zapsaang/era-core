//! Example: Using the metrics collector for performance monitoring
//!
//! Run this with:
//! `cargo run --example metrics_monitoring --release`

use era_engine::metrics_collector::{record_bytes_processed, record_operation, OperationTimer};
use std::thread;
use std::time::Duration;

fn main() {
    println!("=== ERA Performance Metrics Example ===\n");

    // Example 1: Simple operation timing
    println!("Example 1: Measuring archive creation time");
    {
        let timer = OperationTimer::new("archive_create");
        // Simulate archive creation work
        thread::sleep(Duration::from_millis(50));
        let elapsed = timer.finish();
        println!("Archive creation took: {:.2}ms\n", elapsed);
    }

    // Example 2: Measuring compression
    println!("Example 2: Measuring compression time");
    {
        let timer = OperationTimer::new("compression");
        // Simulate compression work
        thread::sleep(Duration::from_millis(30));
        let elapsed = timer.finish();
        println!("Compression took: {:.2}ms\n", elapsed);
    }

    // Example 3: Recording bytes processed
    println!("Example 3: Recording bytes processed");
    {
        let bytes_processed = 1024 * 1024; // 1MB
        record_bytes_processed("compression", bytes_processed as u64);
        println!("Recorded {} bytes processed\n", bytes_processed);
    }

    // Example 4: Recording operation counts
    println!("Example 4: Recording operation counts");
    {
        for _ in 0..5 {
            record_operation("file_encrypt");
        }
        println!("Recorded 5 encryption operations\n");
    }

    // Example 5: Multiple operations
    println!("Example 5: Multiple archive extractions with timing");
    {
        for i in 1..=3 {
            let timer = OperationTimer::new("archive_extract");
            // Simulate extraction work
            thread::sleep(Duration::from_millis(75 + (i as u64 * 10)));
            let elapsed = timer.finish();
            println!("Extraction #{} took: {:.2}ms", i, elapsed);
        }
    }

    println!("\n=== Metrics Recording Complete ===");
    println!("\nNote: In a production environment with a metrics exporter");
    println!("(e.g., prometheus-textfile), these metrics would be");
    println!("exported to Prometheus for visualization in Grafana.");
}
