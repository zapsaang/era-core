/// Diagnostic tool: Find the real performance bottleneck
///
/// Run this with: `cargo run --bin diagnostic --release`

use era_engine::*;
use std::fs;
use std::time::Instant;
use tempfile::TempDir;

fn create_test_data(size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    for i in 0..size {
        if i % 4 == 0 {
            data.push(b'A');
        } else {
            data.push((i * 7 % 256) as u8);
        }
    }
    data
}

fn main() {
    println!("=== ERA Performance Diagnostic ===\n");

    let temp_dir = TempDir::new().unwrap();
    let size_mb = 1;
    let data = create_test_data(size_mb * 1024 * 1024);

    // Create archive
    fs::create_dir_all(temp_dir.path().join("input")).unwrap();
    fs::write(temp_dir.path().join("input/file.bin"), &data).unwrap();

    let archive_path = temp_dir.path().join("test.era");

    println!("1. Creating archive...");
    let t0 = Instant::now();
    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .password("benchmark")
        .build()
        .unwrap();
    writer
        .add_file(&temp_dir.path().join("input/file.bin"))
        .unwrap();
    writer.finalize().unwrap();
    println!("   Time: {:.2}ms\n", t0.elapsed().as_secs_f64() * 1000.0);

    let extract_dir = temp_dir.path().join("output");
    fs::create_dir_all(&extract_dir).unwrap();

    // Open archive and extract - measure multiple times
    println!("2. Extracting archive (5 iterations for averaging):");
    let mut times = vec![];
    
    for i in 0..5 {
        // Clean output
        fs::remove_dir_all(&extract_dir).ok();
        fs::create_dir_all(&extract_dir).unwrap();

        let t1 = Instant::now();
        let reader = ArchiveReader::open(&archive_path, "benchmark").unwrap();
        let t_open = t1.elapsed();

        let t2 = Instant::now();
        reader
            .extract(&extract_dir, ExtractOptions::new(&extract_dir))
            .unwrap();
        let t_extract = t2.elapsed();

        let total = t_open + t_extract;
        times.push(total.as_micros() as f64);

        println!(
            "   Iteration {}: open={:.0}μs, extract={:.0}μs, total={:.0}μs ({:.0} MiB/s)",
            i + 1,
            t_open.as_micros(),
            t_extract.as_micros(),
            total.as_micros(),
            (size_mb as f64 * 1024.0 * 1024.0) / (total.as_secs_f64() * 1e6)
        );
    }

    let avg_us = times.iter().sum::<f64>() / times.len() as f64;
    println!("\nAverage: {:.0}μs ({:.0} MiB/s)", avg_us, (size_mb as f64 * 1024.0 * 1024.0) / (avg_us / 1e6) / 1e6);
    
    println!("\n=== Analysis ===");
    println!("Expected costs (theoretical):");
    println!("- Zstd decompress 1MB:  ~131 μs");
    println!("- HKDF block key derive: ~2.5 μs");
    println!("- XChaCha20-Poly1305:    ~50-100 μs");
    println!("- Disk I/O + other:      ~{:.0} μs", avg_us - 131.0 - 2.5 - 75.0);
    println!("\nIf average > 1087 μs, we're hitting system limits or I/O bottleneck");
    println!("If average < 1087 μs, optimization is working!");
}
