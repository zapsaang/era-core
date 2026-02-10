//! CLI command implementations

use anyhow::{Context, Result};
use dialoguer::{theme::ColorfulTheme, Password};
use era_common::{
    ArchiveConfig, CompressionAlgorithm, ErasureCodeConfig, MatrixDistributionConfig,
    MatrixDistributionStrategy,
};
use era_engine::{
    repair_archive, repair_archive_matrix, ArchiveReader, ArchiveWriter, ExtractOptions,
    RecoveryManager, RepairOptions,
};
use indicatif::{HumanBytes, HumanDuration, ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::{error, info, warn};

/// Get password from user with a professional prompt
///
/// If password is provided via CLI argument, use it directly (for scripting).
/// Otherwise, prompt the user with a styled password input.
fn get_password(password: Option<&str>, prompt: &str) -> Result<String> {
    if let Some(p) = password {
        Ok(p.to_string())
    } else {
        Password::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .interact()
            .context("Failed to read password")
    }
}

/// Get password with confirmation for new archives
///
/// This ensures users don't accidentally mistype their password when creating
/// an archive. If password is provided via CLI, skip confirmation (for scripting).
fn get_password_with_confirmation(password: Option<&str>) -> Result<String> {
    if let Some(p) = password {
        Ok(p.to_string())
    } else {
        Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter encryption password")
            .with_confirmation("Confirm password", "Passwords do not match")
            .interact()
            .context("Failed to read password")
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

/// Parameters for creating a new ERA archive
pub struct CreateArgs<'a> {
    pub inputs: &'a [std::path::PathBuf],
    pub output: &'a Path,
    pub config_path: Option<&'a Path>,
    pub certificate_path: Option<&'a Path>,
    pub password: Option<&'a str>,
    pub compression_level: Option<i32>,
    pub no_compression: bool,
    pub erasure: Option<&'a str>,
    pub volume_count: Option<usize>,
    pub max_volume_size: Option<u64>,
    pub matrix_distribution: Option<bool>,
    pub cdc_min: Option<usize>,
    pub cdc_avg: Option<usize>,
    pub cdc_max: Option<usize>,
    pub packing_k: Option<usize>,
}

/// Create a new ERA archive
pub async fn create(args: CreateArgs<'_>) -> Result<()> {
    let CreateArgs {
        inputs,
        output,
        config_path,
        certificate_path,
        password,
        compression_level,
        no_compression,
        erasure,
        volume_count,
        max_volume_size,
        matrix_distribution,
        cdc_min,
        cdc_avg,
        cdc_max,
        packing_k,
    } = args;
    // 1. Load Configuration
    // Priority: CLI > Config File > Defaults (Secure)
    let mut config = if let Some(path) = config_path {
        info!("Loading configuration from: {}", path.display());
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?
    } else {
        // Apply "Secure Defaults" when starting from scratch
        ArchiveConfig {
            erasure: Some(ErasureCodeConfig {
                data_shards: 4,
                parity_shards: 2,
            }),
            distribution: MatrixDistributionConfig {
                strategy: MatrixDistributionStrategy::RotatingOffset,
                ..Default::default()
            },
            ..Default::default()
        }
    };

    // 2. Apply CLI Overrides

    // Compression
    if no_compression {
        config.compression.algorithm = CompressionAlgorithm::None;
        config.compression.level = 0;
        info!("Compression: disabled (Store mode)");
    } else if let Some(level) = compression_level {
        if !(0..=22).contains(&level) {
            anyhow::bail!("Compression level must be between 0 and 22");
        }
        if level == 0 {
            config.compression.algorithm = CompressionAlgorithm::None;
            config.compression.level = 0;
            info!("Compression: disabled (Store mode)");
        } else {
            config.compression.level = level;
        }
    }

    // Erasure Coding
    if let Some(erasure_str) = erasure {
        if erasure_str.eq_ignore_ascii_case("none") {
            config.erasure = None;
            info!("Erasure coding: disabled by CLI");
        } else {
            config.erasure = Some(parse_erasure_config(erasure_str)?);
        }
    }

    // Geek Parameters
    if let Some(val) = cdc_min {
        config.chunking.min_size = val;
    }
    if let Some(val) = cdc_avg {
        config.chunking.avg_size = val;
    }
    if let Some(val) = cdc_max {
        config.chunking.max_size = val;
    }
    if let Some(val) = packing_k {
        config.packing.k_factor = val;
    }

    // Volume & Distribution
    if let Some(val) = max_volume_size {
        config.volume.max_size = val;
    }
    // Always use RotatingOffset strategy
    if let Some(false) = matrix_distribution {
        eprintln!(
            "Warning: --matrix-distribution=false is deprecated. Using RotatingOffset strategy."
        );
    }
    config.distribution.strategy = MatrixDistributionStrategy::RotatingOffset;

    // Validate CDC bounds
    let min_size = config.chunking.min_size;
    let avg_size = config.chunking.avg_size;
    let max_size = config.chunking.max_size;
    if min_size == 0 || avg_size == 0 || max_size == 0 {
        anyhow::bail!("CDC sizes must be > 0");
    }
    if min_size > avg_size || avg_size > max_size {
        anyhow::bail!(
            "CDC sizes must satisfy min <= avg <= max (got {}, {}, {})",
            min_size,
            avg_size,
            max_size
        );
    }

    // Validate erasure + volume count combinations
    if let Some(ec) = &config.erasure {
        let required = (ec.data_shards + ec.parity_shards) as usize;
        if let Some(v) = volume_count {
            if v < required {
                anyhow::bail!(
                    "Volume count ({}) must be >= total shards ({}) for erasure coding",
                    v,
                    required
                );
            }
        }
    }

    // Load public certificate
    let certificate = if let Some(path) = certificate_path {
        info!("Loading certificate: {}", path.display());
        let cert = era_crypto::load_public_key_from_pem(path)
            .map_err(|e| anyhow::anyhow!("Failed to load certificate: {}", e))?;
        info!("✓ Certificate loaded successfully");
        Some(cert)
    } else {
        None
    };

    // Get password with confirmation (only if not using certificate mode)
    // Note: Hybrid mode is not yet fully supported via CLI arguments, prioritizing pure Certificate mode
    let password = if certificate.is_some() {
        password.map(|p| p.to_string()).unwrap_or_default()
    } else {
        get_password_with_confirmation(password)?
    };

    let mut builder = ArchiveWriter::builder(output)
        .password(&password)
        .config(config.clone()); // Use our resolved config

    if let Some(cert) = certificate {
        builder = builder.certificate(cert);
    }

    // Handle Volume Count Override for Matrix
    // The builder will use config.erasure and config.distribution
    // But we might need to set explicit volume count if provided
    if let Some(ec) = &config.erasure {
        info!(
            "Erasure coding:   {}:{} ({}% overhead, can recover {} lost shards/block)",
            ec.data_shards,
            ec.parity_shards,
            (ec.parity_shards as f64 / ec.data_shards as f64 * 100.0) as u32,
            ec.parity_shards
        );

        if config.distribution.strategy == MatrixDistributionStrategy::RotatingOffset {
            let volumes = volume_count.unwrap_or_else(|| {
                // Default to total_shards for optimal distribution
                (ec.data_shards + ec.parity_shards) as usize
            });
            builder = builder.volume_count(volumes);
        } else if let Some(v) = volume_count {
            builder = builder.volume_count(v);
        }
    } else if let Some(v) = volume_count {
        builder = builder.volume_count(v);
    }

    let mut writer = builder.build().await.context("Failed to create archive")?;

    info!("Creating archive: {}", output.display());

    let start_time = Instant::now();
    // Pre-scan files to update the progress bar length
    let mut files_to_process: Vec<(PathBuf, PathBuf)> = Vec::new();

    // Use ignore::WalkBuilder (implied standard, but user asked for walkdir explicitly or implies standard recursion)
    // The instructions said "Introduce walkdir crate".
    // Let's use walkdir::WalkDir
    for input in inputs {
        let path = input.as_path();
        if path.is_dir() {
            let base = path.parent().unwrap_or(path);
            for entry in walkdir::WalkDir::new(path)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() {
                    let disk_path = entry.path().to_path_buf();
                    let stored_path = entry
                        .path()
                        .strip_prefix(base)
                        .unwrap_or(entry.path())
                        .to_path_buf();
                    files_to_process.push((disk_path, stored_path));
                }
            }
        } else {
            let base = path.parent().unwrap_or(path);
            let stored_path = path.strip_prefix(base).unwrap_or(path).to_path_buf();
            files_to_process.push((path.to_path_buf(), stored_path));
        }
    }

    let pb = ProgressBar::new(files_to_process.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg} (ETA: {eta})"
            )
            .unwrap()
            .progress_chars("█▓▒░-"),
    );

    for (disk_path, stored_path) in files_to_process {
        pb.set_message(format!("{}", disk_path.display()));
        writer
            .add_file_with_path(&disk_path, &stored_path)
            .await
            .with_context(|| format!("Failed to add file: {}", disk_path.display()))?;
        pb.inc(1);
    }

    pb.finish_with_message(format!(
        "✓ Packing complete in {}",
        HumanDuration(start_time.elapsed())
    ));

    let stats = writer
        .finalize()
        .await
        .context("Failed to finalize archive")?;

    info!("");
    info!("Archive created successfully!");
    info!("  Archive ID: {}", stats.archive_id);
    info!("  Files:      {}", stats.total_files);
    info!("  Total size: {}", HumanBytes(stats.total_size));
    info!("  Blocks:     {}", stats.blocks_written);

    Ok(())
}

/// Extract files from an ERA archive
pub async fn extract(
    input: &Path,
    output: &Path,
    password: Option<&str>,
    key_path: Option<&Path>,
    force: bool,
) -> Result<()> {
    info!("Opening archive: {}", input.display());

    let mut reader = if let Some(kp_path) = key_path {
        info!("Loading private key: {}", kp_path.display());
        let keypair = era_crypto::load_private_key_from_pem(kp_path, password)
            .map_err(|e| anyhow::anyhow!("Failed to load private key: {}", e))?;
        ArchiveReader::open_with_keypair(input, &keypair)
            .await
            .context("Failed to open archive with key")?
    } else {
        let password = get_password(password, "Enter decryption password: ")?;
        ArchiveReader::open(input, &password)
            .await
            .context("Failed to open archive")?
    };

    let options = ExtractOptions::new(output).overwrite(force);

    info!("Extracting to: {}", output.display());

    let start_time = Instant::now();
    let stats = reader
        .extract_all(&options)
        .await
        .context("Failed to extract archive")?;

    info!("");
    info!(
        "✓ Extraction complete in {}!",
        HumanDuration(start_time.elapsed())
    );
    info!("  Extracted: {} files", stats.extracted);
    info!("  Skipped:   {} files", stats.skipped);
    info!("  Written:   {}", HumanBytes(stats.bytes_written));

    Ok(())
}

/// List contents of an ERA archive
pub async fn list(
    archive: &Path,
    password: Option<&str>,
    key_path: Option<&Path>,
    long_format: bool,
) -> Result<()> {
    let mut reader = if let Some(kp_path) = key_path {
        info!("Loading private key: {}", kp_path.display());
        let keypair = era_crypto::load_private_key_from_pem(kp_path, password)
            .map_err(|e| anyhow::anyhow!("Failed to load private key: {}", e))?;
        ArchiveReader::open_with_keypair(archive, &keypair)
            .await
            .context("Failed to open archive with key")?
    } else {
        let password = get_password(password, "Enter decryption password: ")?;
        ArchiveReader::open(archive, &password)
            .await
            .context("Failed to open archive")?
    };

    let files = reader
        .list_files()
        .await
        .context("Failed to read catalog")?;

    if long_format {
        info!("{:<12} {:<20} PATH", "SIZE", "HASH");
        info!("{}", "-".repeat(60));
        for entry in &files {
            let hash_str = entry
                .chunks
                .first()
                .map(|c| format!("{:.16}", c.hash))
                .unwrap_or_else(|| "-".to_string());
            info!(
                "{:<12} {:<20} {}",
                HumanBytes(entry.size),
                hash_str,
                entry.path.display()
            );
        }
    } else {
        for entry in &files {
            info!("{}", entry.path.display());
        }
    }

    info!("");
    info!(
        "Total: {} files ({} total)",
        files.len(),
        HumanBytes(files.iter().map(|e| e.size).sum())
    );

    Ok(())
}

/// Show information about an ERA archive
pub async fn info(archive: &Path, password: Option<&str>) -> Result<()> {
    let password = get_password(password, "Enter decryption password: ")?;

    let mut reader = ArchiveReader::open(archive, &password)
        .await
        .context("Failed to open archive")?;

    // Clone header info before mutable borrow
    let header = reader.header().clone();
    let catalog = reader
        .load_catalog()
        .await
        .context("Failed to load catalog")?;

    // ERA version is encoded in magic bytes: magic[3] = major, magic[4] = minor
    let era_version_major = header.magic[3];
    let era_version_minor = header.magic[4];

    info!("ERA Archive Information");
    info!("=======================");
    info!("");
    info!("Archive ID:      {}", header.archive_id);
    info!("Volume ID:       {}", header.volume_id);
    info!("Volume Sequence: {}", header.volume_sequence);
    info!(
        "ERA Version:     {}.{}",
        era_version_major, era_version_minor
    );
    info!("");
    info!("Configuration:");
    info!(
        "  Max Volume Size:    {}",
        HumanBytes(header.config.volume.max_size)
    );
    info!("  Compression Level:  {}", header.config.compression.level);
    info!(
        "  KDF Memory Cost:    {} KB",
        header.config.encryption.kdf_memory_cost
    );
    info!(
        "  KDF Time Cost:      {}",
        header.config.encryption.kdf_time_cost
    );
    info!("");
    info!("Contents:");
    info!("  Total Files:  {}", catalog.file_count);
    info!("  Total Size:   {}", HumanBytes(catalog.total_size));

    Ok(())
}

/// Verify integrity of an ERA archive
pub async fn verify(archive: &Path, password: Option<&str>, verbose: bool) -> Result<()> {
    let password = get_password(password, "Enter decryption password: ")?;

    info!("Verifying archive: {}", archive.display());
    info!("");

    let mut reader = ArchiveReader::open(archive, &password)
        .await
        .context("Failed to open archive")?;

    let start_time = Instant::now();
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap(),
    );
    pb.set_message("Scanning blocks...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let stats = reader.verify().await.context("Verification failed")?;

    pb.finish_and_clear();

    info!("Verification Results");
    info!("====================");
    info!("");
    info!("Blocks verified:    {}", stats.blocks_verified);
    info!("Blocks failed:      {}", stats.blocks_failed);
    info!("Files verified:     {}", stats.files_verified);
    info!("Files incomplete:   {}", stats.files_incomplete);
    info!("Bytes verified:     {}", HumanBytes(stats.bytes_verified));
    info!(
        "Time taken:         {}",
        HumanDuration(start_time.elapsed())
    );
    info!("");

    if stats.is_ok() {
        info!("✅ Archive integrity verified successfully!");
        Ok(())
    } else {
        error!("❌ Archive integrity check FAILED!");
        error!("");
        error!("Errors found: {}", stats.errors.len());

        if verbose {
            error!("");
            error!("Error details:");
            for (i, error) in stats.errors.iter().enumerate() {
                error!("  {}. {}", i + 1, error);
            }
        } else if !stats.errors.is_empty() {
            warn!("Use --verbose to see error details");
        }

        anyhow::bail!(
            "Archive verification failed with {} errors",
            stats.errors.len()
        )
    }
}

/// Repair a damaged or incomplete ERA archive
pub async fn repair(
    archive: &Path,
    password: Option<&str>,
    force: bool,
    verbose: bool,
) -> Result<()> {
    let password = get_password(password, "Enter decryption password: ")?;

    info!("Analyzing archive: {}", archive.display());
    info!("");

    // First, check recovery status
    let status = RecoveryManager::analyze(archive)
        .await
        .context("Failed to analyze archive")?;

    info!("Recovery Analysis");
    info!("=================");
    info!("");
    info!(
        "Checkpoint exists:  {}",
        if status.checkpoint_exists {
            "Yes"
        } else {
            "No"
        }
    );
    info!(
        "Archive exists:     {}",
        if status.archive_exists { "Yes" } else { "No" }
    );
    info!(
        "Recovery needed:    {}",
        if status.recovery_needed { "Yes" } else { "No" }
    );
    info!("Completed files:    {}", status.completed_files.len());
    info!(
        "In-progress file:   {}",
        status
            .in_progress_file
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "None".to_string())
    );
    info!("Chunks written:     {}", status.chunks_written);
    info!("Bytes written:      {}", status.bytes_written);
    info!("");

    if !status.checkpoint_exists && !status.archive_exists {
        info!("❌ No archive or checkpoint found. Nothing to repair.");
        return Ok(());
    }

    if !status.recovery_needed {
        // Archive exists, let's verify it
        info!("Archive appears complete. Running verification...");
        info!("");

        let mut reader = ArchiveReader::open(archive, &password)
            .await
            .context("Failed to open archive")?;

        // Check if erasure coding is enabled
        let header = reader.header();
        let erasure_enabled = header.config.erasure.is_some();
        if erasure_enabled {
            let erasure_config = header.config.erasure.as_ref().unwrap();
            info!(
                "Erasure coding:     Enabled ({}/{} data/parity shards)",
                erasure_config.data_shards, erasure_config.parity_shards
            );
            info!(
                "                    Can recover from up to {} shard losses per block",
                erasure_config.parity_shards
            );
            info!("");
        } else {
            info!("Erasure coding:     Disabled");
            info!("");
        }

        let verify_stats = reader.verify().await.context("Verification failed")?;

        if verify_stats.is_ok() {
            info!("✅ Archive is intact. No repair needed.");
            return Ok(());
        }

        info!("❌ Archive has {} errors.", verify_stats.errors.len());

        if verbose {
            info!("");
            info!("Errors found:");
            for (i, error) in verify_stats.errors.iter().enumerate() {
                info!("  {}. {}", i + 1, error);
            }
        }

        // Attempt actual repair for erasure-coded archives
        info!("");
        if erasure_enabled {
            info!("Attempting repair using Reed-Solomon erasure coding...");
            info!("");

            // Create repair options
            let repair_options = RepairOptions {
                create_backup: true,
                dry_run: !force, // Only actually repair if --force is specified
                continue_on_error: true,
            };

            // Check for multi-volume archive (matrix distribution)
            let base_path = archive.with_extension("");
            let vol1_path = base_path.with_extension("era.001");
            let is_multi_volume = vol1_path.exists();

            let repair_result = if is_multi_volume {
                info!("Detected multi-volume archive, using matrix-distributed repair...");
                repair_archive_matrix(archive, &password, repair_options).await
            } else {
                repair_archive(archive, &password, repair_options).await
            };

            match repair_result {
                Ok(repair_stats) => {
                    info!("");
                    info!("Repair Results:");
                    info!("===============");
                    info!("Blocks scanned:       {}", repair_stats.blocks_scanned);
                    info!(
                        "Blocks with damage:   {}",
                        repair_stats.blocks_with_corruption
                    );
                    info!(
                        "Corrupted shards:     {}",
                        repair_stats.corrupted_shards_found
                    );
                    info!("Shards repaired:      {}", repair_stats.shards_repaired);
                    info!(
                        "Unrecoverable blocks: {}",
                        repair_stats.unrecoverable_blocks
                    );
                    info!("");

                    if repair_stats.fully_repaired() {
                        if force {
                            info!("✅ Archive successfully repaired!");
                        } else {
                            info!("✅ Repair is possible. Run with --force to apply repairs.");
                        }
                        return Ok(());
                    } else {
                        info!(
                            "⚠️  Partial repair: {} blocks could not be recovered.",
                            repair_stats.unrecoverable_blocks
                        );
                        if !repair_stats.errors.is_empty() && verbose {
                            info!("");
                            info!("Unrecoverable errors:");
                            for (i, err) in repair_stats.errors.iter().enumerate() {
                                info!("  {}. {}", i + 1, err);
                            }
                        }
                    }
                }
                Err(e) => {
                    info!("❌ Repair failed: {}", e);
                    info!("");
                    info!("To extract recoverable data, use: era extract --force <archive>");
                }
            }
        } else {
            info!("Note: This archive was created without erasure coding.");
            info!("Consider recreating with erasure coding for better protection:");
            info!("  era create --erasure 4:2 <inputs> -o <output>.era");
            info!("");
            info!("To extract what's possible, try: era extract --force <archive>");
        }

        anyhow::bail!("Archive has errors. Use 'era extract --force' to recover what's possible.");
    }

    // Recovery is needed - we have a checkpoint from interrupted creation
    info!("Recovery checkpoint found from interrupted archive creation.");
    info!("");

    if !force {
        info!("To resume the interrupted creation, re-run the original 'era create' command.");
        info!("The archive writer will automatically detect and resume from the checkpoint.");
        info!("");
        info!("To discard the checkpoint and start fresh, use --force flag.");
        return Ok(());
    }

    // Force flag: delete checkpoint and let user start fresh
    info!("Discarding checkpoint due to --force flag...");

    let manager = RecoveryManager::new(archive)
        .await
        .context("Failed to load recovery state")?;
    manager.cleanup().context("Failed to clean up checkpoint")?;

    info!("✅ Checkpoint discarded. You can now create a new archive.");

    Ok(())
}
