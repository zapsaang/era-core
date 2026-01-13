//! CLI command implementations

use anyhow::{Context, Result};
use era_common::{ArchiveConfig, ErasureCodeConfig};
use era_engine::{
    repair_archive, ArchiveReader, ArchiveWriter, ExtractOptions, RecoveryManager, RepairOptions,
};
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

/// Parse erasure config from string format "data:parity" (e.g., "4:2")
fn parse_erasure_config(s: &str) -> Result<ErasureCodeConfig> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid erasure format. Expected 'data:parity' (e.g., '4:2')");
    }

    let data_shards: u8 = parts[0]
        .parse()
        .context("Invalid data shards value. Must be a number 1-255")?;
    let parity_shards: u8 = parts[1]
        .parse()
        .context("Invalid parity shards value. Must be a number 1-255")?;

    if data_shards == 0 {
        anyhow::bail!("Data shards must be at least 1");
    }
    if parity_shards == 0 {
        anyhow::bail!("Parity shards must be at least 1");
    }
    if data_shards as usize + parity_shards as usize > 255 {
        anyhow::bail!("Total shards (data + parity) must not exceed 255");
    }

    Ok(ErasureCodeConfig {
        data_shards,
        parity_shards,
    })
}

/// Create a new ERA archive
pub fn create(
    inputs: &[impl AsRef<Path>],
    output: &Path,
    password: Option<&str>,
    compression_level: i32,
    erasure: Option<&str>,
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

    // Parse erasure config if provided
    let erasure_config = match erasure {
        Some(s) => Some(parse_erasure_config(s)?),
        None => None,
    };

    let mut builder = ArchiveWriter::builder(output)
        .password(&password)
        .config(config);

    // Enable erasure coding if configured
    if let Some(ec) = erasure_config {
        builder = builder.erasure_config(ec);
        println!(
            "Erasure coding:   {}:{} ({}% overhead, can recover {} lost shards/block)",
            ec.data_shards,
            ec.parity_shards,
            (ec.parity_shards as f64 / ec.data_shards as f64 * 100.0) as u32,
            ec.parity_shards
        );
    }

    let mut writer = builder.build().context("Failed to create archive")?;

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

/// Repair a damaged or incomplete ERA archive
pub fn repair(archive: &Path, password: Option<&str>, force: bool, verbose: bool) -> Result<()> {
    let password = get_password(password, "Enter decryption password: ")?;

    println!("Analyzing archive: {}", archive.display());
    println!();

    // First, check recovery status
    let status = RecoveryManager::analyze(archive).context("Failed to analyze archive")?;

    println!("Recovery Analysis");
    println!("=================");
    println!();
    println!(
        "Checkpoint exists:  {}",
        if status.checkpoint_exists {
            "Yes"
        } else {
            "No"
        }
    );
    println!(
        "Archive exists:     {}",
        if status.archive_exists { "Yes" } else { "No" }
    );
    println!(
        "Recovery needed:    {}",
        if status.recovery_needed { "Yes" } else { "No" }
    );
    println!("Completed files:    {}", status.completed_files.len());
    println!(
        "In-progress file:   {}",
        status
            .in_progress_file
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "None".to_string())
    );
    println!("Chunks written:     {}", status.chunks_written);
    println!("Bytes written:      {}", status.bytes_written);
    println!();

    if !status.checkpoint_exists && !status.archive_exists {
        println!("❌ No archive or checkpoint found. Nothing to repair.");
        return Ok(());
    }

    if !status.recovery_needed {
        // Archive exists, let's verify it
        println!("Archive appears complete. Running verification...");
        println!();

        let mut reader =
            ArchiveReader::open(archive, &password).context("Failed to open archive")?;

        // Check if erasure coding is enabled
        let header = reader.header();
        let erasure_enabled = header.config.erasure.is_some();
        if erasure_enabled {
            let erasure_config = header.config.erasure.as_ref().unwrap();
            println!(
                "Erasure coding:     Enabled ({}/{} data/parity shards)",
                erasure_config.data_shards, erasure_config.parity_shards
            );
            println!(
                "                    Can recover from up to {} shard losses per block",
                erasure_config.parity_shards
            );
            println!();
        } else {
            println!("Erasure coding:     Disabled");
            println!();
        }

        let verify_stats = reader.verify().context("Verification failed")?;

        if verify_stats.is_ok() {
            println!("✅ Archive is intact. No repair needed.");
            return Ok(());
        }

        println!("❌ Archive has {} errors.", verify_stats.errors.len());

        if verbose {
            println!();
            println!("Errors found:");
            for (i, error) in verify_stats.errors.iter().enumerate() {
                println!("  {}. {}", i + 1, error);
            }
        }

        // Attempt actual repair for erasure-coded archives
        println!();
        if erasure_enabled {
            println!("Attempting repair using Reed-Solomon erasure coding...");
            println!();

            // Create repair options
            let repair_options = RepairOptions {
                create_backup: true,
                dry_run: !force, // Only actually repair if --force is specified
                continue_on_error: true,
            };

            match repair_archive(archive, &password, repair_options) {
                Ok(repair_stats) => {
                    println!();
                    println!("Repair Results:");
                    println!("===============");
                    println!("Blocks scanned:       {}", repair_stats.blocks_scanned);
                    println!(
                        "Blocks with damage:   {}",
                        repair_stats.blocks_with_corruption
                    );
                    println!(
                        "Corrupted shards:     {}",
                        repair_stats.corrupted_shards_found
                    );
                    println!("Shards repaired:      {}", repair_stats.shards_repaired);
                    println!(
                        "Unrecoverable blocks: {}",
                        repair_stats.unrecoverable_blocks
                    );
                    println!();

                    if repair_stats.fully_repaired() {
                        if force {
                            println!("✅ Archive successfully repaired!");
                        } else {
                            println!("✅ Repair is possible. Run with --force to apply repairs.");
                        }
                        return Ok(());
                    } else {
                        println!(
                            "⚠️  Partial repair: {} blocks could not be recovered.",
                            repair_stats.unrecoverable_blocks
                        );
                        if !repair_stats.errors.is_empty() && verbose {
                            println!();
                            println!("Unrecoverable errors:");
                            for (i, err) in repair_stats.errors.iter().enumerate() {
                                println!("  {}. {}", i + 1, err);
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("❌ Repair failed: {}", e);
                    println!();
                    println!("To extract recoverable data, use: era extract --force <archive>");
                }
            }
        } else {
            println!("Note: This archive was created without erasure coding.");
            println!("Consider recreating with erasure coding for better protection:");
            println!("  era create --erasure 4:2 <inputs> -o <output>.era");
            println!();
            println!("To extract what's possible, try: era extract --force <archive>");
        }

        anyhow::bail!("Archive has errors. Use 'era extract --force' to recover what's possible.");
    }

    // Recovery is needed - we have a checkpoint from interrupted creation
    println!("Recovery checkpoint found from interrupted archive creation.");
    println!();

    if !force {
        println!("To resume the interrupted creation, re-run the original 'era create' command.");
        println!("The archive writer will automatically detect and resume from the checkpoint.");
        println!();
        println!("To discard the checkpoint and start fresh, use --force flag.");
        return Ok(());
    }

    // Force flag: delete checkpoint and let user start fresh
    println!("Discarding checkpoint due to --force flag...");

    let manager = RecoveryManager::new(archive).context("Failed to load recovery state")?;
    manager.cleanup().context("Failed to clean up checkpoint")?;

    println!("✅ Checkpoint discarded. You can now create a new archive.");

    Ok(())
}
