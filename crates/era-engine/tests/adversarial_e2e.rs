use era_common::{
    ArchiveConfig, CompressionAlgorithm, CompressionConfig, ErasureCodeConfig,
    MatrixDistributionConfig, MatrixDistributionStrategy,
};
use era_engine::{ArchiveReader, ArchiveWriter, ExtractOptions};
use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// 💀 Saboteur: Simulates disk failures, malicious tampering, and bit rot
struct Saboteur {
    file_path: PathBuf,
}

impl Saboteur {
    fn new(path: impl AsRef<Path>) -> Self {
        Self {
            file_path: path.as_ref().to_path_buf(),
        }
    }

    /// Attack Type 1: Silent Bit Rot
    /// Simulates cosmic rays or disk aging; hard to detect because file metadata looks normal.
    fn induce_bit_rot(&self, offset: u64) {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.file_path)
            .expect("Failed to open file for bit rot");
        
        // Read byte
        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();

        // Flip the 3rd bit
        byte[0] ^= 1 << 3;

        // Write back
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&byte).unwrap();
        println!("😈 [SABOTAGE] Bit flipped at offset {} in {:?}", offset, self.file_path.file_name().unwrap());
    }

    /// Attack Type 2: Large Segment Wipe (Sector Death)
    /// Simulates bad sectors or filesystem logic errors.
    fn nuke_segment(&self, offset: u64, len: usize) {
        let mut file = OpenOptions::new()
            .write(true)
            .open(&self.file_path)
            .expect("Failed to open file for nuking");
        
        file.seek(SeekFrom::Start(offset)).unwrap();
        let trash = vec![0xFFu8; len]; // Fill with 0xFF garbage
        file.write_all(&trash).unwrap();
        println!("😈 [SABOTAGE] Nuked {} bytes at offset {} in {:?}", len, offset, self.file_path.file_name().unwrap());
    }

    /// Attack Type 3: Header Corruption
    /// Destroys Magic Bytes, Version, or Salt to test the system's ability to identify bad volumes.
    fn corrupt_header(&self) {
        let mut file = OpenOptions::new()
            .write(true)
            .open(&self.file_path)
            .expect("Failed to open file for header corruption");
        
        file.seek(SeekFrom::Start(0)).unwrap();
        let garbage = [0xDEu8; 16]; // Corrupt the first 16 bytes
        file.write_all(&garbage).unwrap();
        println!("😈 [SABOTAGE] Corrupted HEADER in {:?}", self.file_path.file_name().unwrap());
    }

    /// Attack Type 4: Footer/Index Corruption
    /// Destroys floating footers or index pointers.
    fn corrupt_footer(&self) {
        let file_len = fs::metadata(&self.file_path).unwrap().len();
        let mut file = OpenOptions::new()
            .write(true)
            .open(&self.file_path)
            .expect("Failed to open file for footer corruption");
        
        // Assume Footer is within the last 4KB
        if file_len > 100 {
            file.seek(SeekFrom::Start(file_len - 100)).unwrap();
            let garbage = [0xADu8; 50]; 
            file.write_all(&garbage).unwrap();
            println!("😈 [SABOTAGE] Corrupted FOOTER in {:?}", self.file_path.file_name().unwrap());
        }
    }
}

/// Helper function: Creates a standard test archive
/// Configuration: 4 Data + 2 Parity (6 volumes total), Zstd compression, Matrix distribution
async fn create_test_archive(repo_dir: &Path, source_dir: &Path, original_data: &[u8]) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let config = ArchiveConfig {
        erasure: Some(ErasureCodeConfig {
            data_shards: 4,
            parity_shards: 2,
        }),
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level: 1,
        },
        distribution: MatrixDistributionConfig {
            strategy: MatrixDistributionStrategy::RotatingOffset,
            ..Default::default()
        },
        ..Default::default()
    };

    let archive_path = repo_dir.join("backup.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .config(config)
        .password("testpass")
        .volume_count(6) // Force generation of 6 physical files
        .enable_matrix_distribution(true)
        .build()?;

    let payload_path = source_dir.join("payload.bin");
    fs::write(&payload_path, original_data)?;
    
    writer.add_file(&payload_path).await?;
    let _stats = writer.finalize()?;
    
    Ok(archive_path)
}

#[tokio::test]
async fn test_extreme_resilience_recovery() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== TEST: Extreme Resilience (Recovering from 2/6 Volume Loss) ===");
    
    // 1. Environment preparation
    let temp_dir = TempDir::new()?;
    let repo_dir = temp_dir.path().join("repo");
    let source_dir = temp_dir.path().join("source");
    let restore_dir = temp_dir.path().join("restore");
    fs::create_dir_all(&repo_dir)?;
    fs::create_dir_all(&source_dir)?;
    fs::create_dir_all(&restore_dir)?;

    // Generate 10MB of high-entropy data
    let mut original_data = vec![0u8; 10 * 1024 * 1024];
    rand::thread_rng().fill_bytes(&mut original_data);

    // 2. Create archive
    let archive_path = create_test_archive(&repo_dir, &source_dir, &original_data).await?;
    println!("✅ Archive created.");

    // 3. 💀 Initiate attack: Simultaneously corrupt 2 volumes (Volume 2 and Volume 5)
    // A 4+2 scheme should theoretically tolerate the loss of 2 volumes. We test if this holds true.
    
    let vol2 = repo_dir.join("backup.era.002");
    let vol5 = repo_dir.join("backup.era.005");
    
    let saboteur2 = Saboteur::new(&vol2);
    let saboteur5 = Saboteur::new(&vol5);

    // Mixed attack on Vol 2: Header corruption + random bit flip
    saboteur2.corrupt_header(); 
    saboteur2.induce_bit_rot(1024 * 1024); // Flip at 1MB
    
    // Heavy damage on Vol 5: Footer corruption + large segment wipe
    saboteur5.corrupt_footer();
    saboteur5.nuke_segment(5 * 1024 * 1024, 64 * 1024); // Wipe 64KB at 5MB

    println!("🏥 Starting recovery logic...");
    
    // 4. Attempt recovery
    let mut reader = ArchiveReader::open(&archive_path, "testpass")?;
    let options = ExtractOptions::new(&restore_dir);
    
    // This step should succeed, despite massive error logs
    reader.extract_all(&options)?;
    
    // 5. Verify data integrity
    let restored_path = restore_dir.join("payload.bin");
    assert!(restored_path.exists(), "Restored file missing!");
    
    let restored_data = fs::read(restored_path)?;
    
    if original_data == restored_data {
        println!("🎉 SUCCESS: Data recovered perfectly despite losing 2 volumes!");
    } else {
        panic!("❌ FAILURE: Restore ran, but data mismatch! Silent corruption detected.");
    }

    Ok(())
}

#[tokio::test]
async fn test_impossible_recovery_rejection() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== TEST: Impossible Recovery (3/6 Volume Loss) ===");

    // 1. Environment preparation
    let temp_dir = TempDir::new()?;
    let repo_dir = temp_dir.path().join("repo");
    let source_dir = temp_dir.path().join("source");
    let restore_dir = temp_dir.path().join("restore_fail");
    fs::create_dir_all(&repo_dir)?;
    fs::create_dir_all(&source_dir)?;
    fs::create_dir_all(&restore_dir)?;

    let mut original_data = vec![0u8; 5 * 1024 * 1024]; 
    rand::thread_rng().fill_bytes(&mut original_data);

    let archive_path = create_test_archive(&repo_dir, &source_dir, &original_data).await?;

    // 2. 💀 Initiate devastating attack: Corrupt 3 volumes (exceeding Parity threshold)
    // A 4+2 scheme cannot recover from 3 bad volumes.
    
    let targets = vec![
        repo_dir.join("backup.era.001"),
        repo_dir.join("backup.era.003"),
        repo_dir.join("backup.era.004"),
    ];

    for path in targets {
        let s = Saboteur::new(path);
        s.nuke_segment(0, 200_000); // Wipe first 200KB, including Header
        s.corrupt_footer();         // Wipe Footer
    }

    println!("🏥 Attempting impossible recovery (Should Fail)...");

    let mut reader = ArchiveReader::open(&archive_path, "testpass")?;
    let options = ExtractOptions::new(&restore_dir);
    
    let result = reader.extract_all(&options);

    // 3. Verify correct error reporting
    match result {
        Ok(_) => {
            // If this succeeds, the system might have returned incorrect/padded data, which is extremely dangerous
            panic!("❌ SAFETY FAILURE: System claimed success when recovery was mathematically impossible!");
        },
        Err(e) => {
            println!("✅ SUCCESS: System correctly refused to restore corrupted data. Error caught: {}", e);
        }
    }

    Ok(())
}