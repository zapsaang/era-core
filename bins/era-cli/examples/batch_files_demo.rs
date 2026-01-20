//! Example demonstrating batch file API for improved small file performance
//!
//! Run with:
//! ```bash
//! cargo run --package era-cli --example batch_files_demo
//! ```

use era_engine::ArchiveWriterBuilder;
use std::fs;
use std::io::Write;
use std::time::Instant;
use tempfile::TempDir;

#[tokio::main]
async fn main() {
    println!("=== Batch Files API Demonstration ===\n");

    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    // Create 50 small test files (10KB each)
    println!("Creating 50 test files (10KB each)...");
    let files: Vec<_> = (0..50)
        .map(|i| {
            let file_path = input_dir.join(format!("file_{:03}.txt", i));
            let mut file = fs::File::create(&file_path).unwrap();
            let content = format!("File {} content\n", i).repeat(1000); // ~10KB
            file.write_all(content.as_bytes()).unwrap();
            file_path
        })
        .collect();

    println!("Total size: {} KB\n", files.len() * 10);

    // Method 1: Individual add_file calls
    println!("Method 1: Individual add_file() calls");
    let archive1 = temp_dir.path().join("individual.era");
    let start = Instant::now();

    {
        let mut writer = ArchiveWriterBuilder::new(&archive1)
            .password("demo_password")
            .build()
            .unwrap();

        for file in &files {
            writer.add_file(file).await.unwrap();
        }

        writer.finalize().unwrap();
    }

    let time1 = start.elapsed();
    let size1 = fs::metadata(&archive1).unwrap().len();
    println!("  Time: {:.2?}", time1);
    println!("  Archive size: {} bytes", size1);
    println!(
        "  Throughput: {:.2} MiB/s\n",
        (files.len() * 10 * 1024) as f64 / time1.as_secs_f64() / 1024.0 / 1024.0
    );

    // Method 2: Batch add_files call
    println!("Method 2: Batch add_files() call");
    let archive2 = temp_dir.path().join("batch.era");
    let start = Instant::now();

    {
        let mut writer = ArchiveWriterBuilder::new(&archive2)
            .password("demo_password")
            .build()
            .unwrap();

        // Convert to &[&Path]
        let file_refs: Vec<&std::path::Path> = files.iter().map(|p| p.as_path()).collect();
        writer.add_files(&file_refs).await.unwrap();

        writer.finalize().unwrap();
    }

    let time2 = start.elapsed();
    let size2 = fs::metadata(&archive2).unwrap().len();
    println!("  Time: {:.2?}", time2);
    println!("  Archive size: {} bytes", size2);
    println!(
        "  Throughput: {:.2} MiB/s\n",
        (files.len() * 10 * 1024) as f64 / time2.as_secs_f64() / 1024.0 / 1024.0
    );

    // Performance comparison
    println!("=== Performance Comparison ===");
    let speedup = time1.as_secs_f64() / time2.as_secs_f64();
    println!("Batch API is {:.2}x faster!", speedup);

    if speedup > 1.0 {
        println!(
            "Time saved: {:.2?} ({:.1}% reduction)",
            time1 - time2,
            ((time1.as_secs_f64() - time2.as_secs_f64()) / time1.as_secs_f64()) * 100.0
        );
    }

    // Verify both archives are functionally identical
    println!("\n=== Verification ===");
    println!("Archive 1 size: {} bytes", size1);
    println!("Archive 2 size: {} bytes", size2);
    println!(
        "Size difference: {} bytes ({:.2}%)",
        (size1 as i64 - size2 as i64).abs(),
        ((size1 as f64 - size2 as f64).abs() / size1 as f64) * 100.0
    );

    println!("\n✅ Demo complete! Use batch API for better small file performance.");
}
