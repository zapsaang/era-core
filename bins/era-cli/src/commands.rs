//! CLI command implementations

use anyhow::{Context, Result};
use era_common::ArchiveConfig;
use era_engine::{ArchiveReader, ArchiveWriter, ExtractOptions};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::Path;

/// Get password from user, either from argument or by prompting
fn get_password(password: Option<&str>, prompt: &str) -> Result<String> {
    if let Some(p) = password {
        Ok(p.to_string())
    } else {
        rpassword::prompt_password(prompt).context("Failed to read password")
    }
}

/// Create a new ERA archive
pub fn create(
    inputs: &[impl AsRef<Path>],
    output: &Path,
    password: Option<&str>,
    compression_level: i32,
) -> Result<()> {
    // If password provided via CLI, skip confirmation (for scripting)
    let password = if let Some(p) = password {
        p.to_string()
    } else {
        let pw = get_password(None, "Enter encryption password: ")?;
        // Confirm password for new archives when entering interactively
        let confirm = rpassword::prompt_password("Confirm password: ")?;
        if pw != confirm {
            anyhow::bail!("Passwords do not match");
        }
        pw
    };

    let mut config = ArchiveConfig::default();
    config.compression.level = compression_level;

    let mut writer = ArchiveWriter::builder(output)
        .password(&password)
        .config(config)
        .build()
        .context("Failed to create archive")?;

    println!("Creating archive: {}", output.display());

    let pb = ProgressBar::new(inputs.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );

    for input in inputs {
        let path = input.as_ref();
        pb.set_message(format!("{}", path.display()));
        writer
            .add_file(path)
            .with_context(|| format!("Failed to add file: {}", path.display()))?;
        pb.inc(1);
    }

    pb.finish_with_message("Packing complete");

    let stats = writer.finalize().context("Failed to finalize archive")?;

    println!();
    println!("Archive created successfully!");
    println!("  Archive ID: {}", stats.archive_id);
    println!("  Files:      {}", stats.total_files);
    println!("  Total size: {} bytes", stats.total_size);
    println!("  Blocks:     {}", stats.blocks_written);

    Ok(())
}

/// Extract files from an ERA archive
pub fn extract(input: &Path, output: &Path, password: Option<&str>, force: bool) -> Result<()> {
    let password = get_password(password, "Enter decryption password: ")?;

    println!("Opening archive: {}", input.display());

    let mut reader = ArchiveReader::open(input, &password).context("Failed to open archive")?;

    let options = ExtractOptions::new(output).overwrite(force);

    println!("Extracting to: {}", output.display());

    let stats = reader
        .extract_all(&options)
        .context("Failed to extract archive")?;

    println!();
    println!("Extraction complete!");
    println!("  Extracted: {} files", stats.extracted);
    println!("  Skipped:   {} files", stats.skipped);
    println!("  Written:   {} bytes", stats.bytes_written);

    Ok(())
}

/// List contents of an ERA archive
pub fn list(archive: &Path, password: Option<&str>, long_format: bool) -> Result<()> {
    let password = get_password(password, "Enter decryption password: ")?;

    let mut reader = ArchiveReader::open(archive, &password).context("Failed to open archive")?;

    let files = reader.list_files().context("Failed to read catalog")?;

    if long_format {
        println!("{:<12} {:<20} PATH", "SIZE", "HASH");
        println!("{}", "-".repeat(60));
        for entry in &files {
            let hash_str = entry
                .content_hash
                .map(|h| format!("{:.16}", h))
                .unwrap_or_else(|| "-".to_string());
            println!(
                "{:<12} {:<20} {}",
                entry.size,
                hash_str,
                entry.path.display()
            );
        }
    } else {
        for entry in &files {
            println!("{}", entry.path.display());
        }
    }

    println!();
    println!("Total: {} files", files.len());

    Ok(())
}

/// Show information about an ERA archive
pub fn info(archive: &Path, password: Option<&str>) -> Result<()> {
    let password = get_password(password, "Enter decryption password: ")?;

    let mut reader = ArchiveReader::open(archive, &password).context("Failed to open archive")?;

    // Clone header info before mutable borrow
    let header = reader.header().clone();
    let catalog = reader.load_catalog().context("Failed to load catalog")?;

    // ERA version is encoded in magic bytes: magic[3] = major, magic[4] = minor
    let era_version_major = header.magic[3];
    let era_version_minor = header.magic[4];

    println!("ERA Archive Information");
    println!("=======================");
    println!();
    println!("Archive ID:      {}", header.archive_id);
    println!("Volume ID:       {}", header.volume_id);
    println!("Volume Sequence: {}", header.volume_sequence);
    println!(
        "ERA Version:     {}.{}",
        era_version_major, era_version_minor
    );
    println!();
    println!("Configuration:");
    println!(
        "  Max Volume Size:    {} MB",
        header.config.volume.max_size / (1024 * 1024)
    );
    println!("  Compression Level:  {}", header.config.compression.level);
    println!(
        "  KDF Memory Cost:    {} KB",
        header.config.encryption.kdf_memory_cost
    );
    println!(
        "  KDF Time Cost:      {}",
        header.config.encryption.kdf_time_cost
    );
    println!();
    println!("Contents:");
    println!("  Total Files:  {}", catalog.file_count);
    println!("  Total Size:   {} bytes", catalog.total_size);

    Ok(())
}

/// Verify integrity of an ERA archive
pub fn verify(archive: &Path, password: Option<&str>, verbose: bool) -> Result<()> {
    let password = get_password(password, "Enter decryption password: ")?;

    println!("Verifying archive: {}", archive.display());
    println!();

    let mut reader = ArchiveReader::open(archive, &password).context("Failed to open archive")?;

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message("Scanning blocks...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let stats = reader.verify().context("Verification failed")?;

    pb.finish_and_clear();

    println!("Verification Results");
    println!("====================");
    println!();
    println!("Blocks verified:    {}", stats.blocks_verified);
    println!("Blocks failed:      {}", stats.blocks_failed);
    println!("Files verified:     {}", stats.files_verified);
    println!("Files incomplete:   {}", stats.files_incomplete);
    println!("Bytes verified:     {}", stats.bytes_verified);
    println!();

    if stats.is_ok() {
        println!("✅ Archive integrity verified successfully!");
        Ok(())
    } else {
        println!("❌ Archive integrity check FAILED!");
        println!();
        println!("Errors found: {}", stats.errors.len());

        if verbose {
            println!();
            println!("Error details:");
            for (i, error) in stats.errors.iter().enumerate() {
                println!("  {}. {}", i + 1, error);
            }
        } else if !stats.errors.is_empty() {
            println!("Use --verbose to see error details");
        }

        anyhow::bail!(
            "Archive verification failed with {} errors",
            stats.errors.len()
        )
    }
}
