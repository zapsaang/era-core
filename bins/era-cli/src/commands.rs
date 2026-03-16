//! CLI command implementations

use crate::progress;
use anyhow::{Context, Result};
use dialoguer::{theme::ColorfulTheme, Password};
use era_common::{
    ArchiveConfig, CompressionAlgorithm, ErasureCodeConfig, MatrixDistributionConfig,
    MatrixDistributionStrategy,
};
use era_engine::{
    repack_archive, repack_archive_with_keypair, repair_archive, repair_archive_matrix,
    ArchiveHealthStatus, ArchiveReader, ArchiveWriter, AuthMode, ExtractOptions, RecoveryManager,
    RepairOptions,
};
use indicatif::{HumanBytes, HumanDuration, ProgressStyle};
use rand::RngCore;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::{error, info, warn};
use zeroize::{Zeroize, Zeroizing};

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

struct ConfigOverrides<'a> {
    compression_level: Option<i32>,
    no_compression: bool,
    erasure: Option<&'a str>,
    cdc_min: Option<usize>,
    cdc_avg: Option<usize>,
    cdc_max: Option<usize>,
    packing_k: Option<usize>,
    flush_threshold: Option<usize>,
    block_target_size: Option<usize>,
}

fn apply_config_overrides(
    config: &mut ArchiveConfig,
    overrides: ConfigOverrides<'_>,
) -> Result<()> {
    if overrides.no_compression {
        config.compression.algorithm = CompressionAlgorithm::None;
        config.compression.level = 0;
        info!("Compression: disabled (Store mode)");
    } else if let Some(level) = overrides.compression_level {
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

    if let Some(erasure_str) = overrides.erasure {
        if erasure_str.eq_ignore_ascii_case("none") {
            config.erasure = None;
            info!("Erasure coding: disabled by CLI");
        } else {
            config.erasure = Some(parse_erasure_config(erasure_str)?);
        }
    }

    if let Some(val) = overrides.cdc_min {
        config.chunking.min_size = val;
    }
    if let Some(val) = overrides.cdc_avg {
        config.chunking.avg_size = val;
    }
    if let Some(val) = overrides.cdc_max {
        config.chunking.max_size = val;
    }
    if let Some(val) = overrides.packing_k {
        config.packing.k_factor = val;
    }
    if let Some(val) = overrides.flush_threshold {
        config.packing.flush_threshold = val;
    }
    if let Some(val) = overrides.block_target_size {
        config.block.target_size = val;
    }

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

    Ok(())
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
    pub cdc_min: Option<usize>,
    pub cdc_avg: Option<usize>,
    pub cdc_max: Option<usize>,
    pub packing_k: Option<usize>,
    pub flush_threshold: Option<usize>,
    pub block_target_size: Option<usize>,
    pub compact: bool,
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
        cdc_min,
        cdc_avg,
        cdc_max,
        packing_k,
        flush_threshold,
        block_target_size,
        compact,
    } = args;
    let mut config = if let Some(path) = config_path {
        info!("Loading configuration from: {}", path.display());
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?
    } else if compact {
        info!("Using compact preset (Zstd-19, 16MB blocks, k=32)");
        ArchiveConfig::compact_preset()
    } else {
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

    apply_config_overrides(
        &mut config,
        ConfigOverrides {
            compression_level,
            no_compression,
            erasure,
            cdc_min,
            cdc_avg,
            cdc_max,
            packing_k,
            flush_threshold,
            block_target_size,
        },
    )?;

    // Volume & Distribution
    if let Some(val) = max_volume_size {
        config.volume.max_size = val;
    }
    config.distribution.strategy = MatrixDistributionStrategy::RotatingOffset;

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

    let user_supplied_password = password.is_some();

    // Get password with confirmation (only if not using certificate mode)
    let password = if certificate.is_some() {
        if let Some(p) = password {
            info!("Hybrid mode: certificate + password");
            p.to_string()
        } else {
            let mut random_pw = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut random_pw);
            let pw = hex::encode(random_pw);
            random_pw.zeroize();
            info!("Certificate-only mode: archive will be decryptable only with the private key");
            pw
        }
    } else {
        get_password_with_confirmation(password)?
    };

    let mut builder = ArchiveWriter::builder(output).config(config.clone()); // Use our resolved config

    builder = match (certificate, user_supplied_password) {
        (Some(cert), true) => builder.auth_mode(AuthMode::Hybrid {
            password: Zeroizing::new(password),
            certificate: cert,
        }),
        (Some(cert), false) => builder.certificate(cert),
        (None, _) => builder.password(&password),
    };

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

    let mut writer = builder
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create archive: {}", e))?;

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

    let pb = progress::progress_bar(files_to_process.len() as u64);
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
        info!("{:<12} {:<20} PATH", "SIZE", "CHUNK_ID");
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
pub async fn info(archive: &Path, password: Option<&str>, key_path: Option<&Path>) -> Result<()> {
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

    let header = reader.header().clone();
    let catalog = reader
        .load_catalog()
        .await
        .context("Failed to load catalog")?;

    // ERA version is encoded in magic bytes: magic[3] = major, magic[4] = minor
    let era_version_major = header.magic()[3];
    let era_version_minor = header.magic()[4];

    info!("ERA Archive Information");
    info!("=======================");
    info!("");
    info!("Archive ID:      {}", header.archive_id());
    info!("Volume ID:       {}", header.volume_id());
    info!("Volume Sequence: {}", header.volume_sequence());
    info!(
        "ERA Version:     {}.{}",
        era_version_major, era_version_minor
    );
    info!("");
    info!("Configuration:");
    info!(
        "  Max Volume Size:    {}",
        HumanBytes(header.config().volume.max_size)
    );
    info!(
        "  Compression Level:  {}",
        header.config().compression.level
    );
    info!(
        "  KDF Memory Cost:    {} KB",
        header.config().encryption.kdf_memory_cost
    );
    info!(
        "  KDF Time Cost:      {}",
        header.config().encryption.kdf_time_cost
    );
    info!("");
    info!("Contents:");
    info!("  Total Files:  {}", catalog.file_count);
    info!("  Total Size:   {}", HumanBytes(catalog.total_size));

    Ok(())
}

/// Verify integrity of an ERA archive
pub async fn verify(
    archive: &Path,
    password: Option<&str>,
    key_path: Option<&Path>,
    verbose: bool,
) -> Result<()> {
    info!("Verifying archive: {}", archive.display());
    info!("");

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

    let start_time = Instant::now();
    let pb = progress::spinner();
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

    match &stats.archive_health {
        ArchiveHealthStatus::Healthy => {
            info!("✅ Archive integrity verified successfully!");
            Ok(())
        }
        ArchiveHealthStatus::Degraded {
            expected_volumes,
            found_volumes,
            missing_indices,
        } => {
            warn!("⚠️  Archive data is readable, but archive health is degraded.");
            if !missing_indices.is_empty() {
                warn!("Expected volumes:   {}", expected_volumes);
                warn!("Volumes found:      {}", found_volumes);
                warn!("Missing sequences:  {:?}", missing_indices);
            }
            if !stats.warnings.is_empty() {
                warn!("");
                warn!("Warnings:");
                for (i, warning) in stats.warnings.iter().enumerate() {
                    warn!("  {}. {}", i + 1, warning);
                }
            }
            anyhow::bail!(
                "Archive verification degraded: expected volumes={}, found={}, missing sequences={:?}",
                expected_volumes,
                found_volumes,
                missing_indices
            )
        }
        ArchiveHealthStatus::Incomplete {
            expected_volumes,
            found_volumes,
            missing_indices,
            reason,
        } => {
            error!("❌ Archive integrity check FAILED!");
            if !missing_indices.is_empty() {
                error!("Expected volumes:   {}", expected_volumes);
                error!("Volumes found:      {}", found_volumes);
                error!("Missing sequences:  {:?}", missing_indices);
            }
            error!("Reason:             {}", reason);
            error!("Errors found:       {}", stats.errors.len());

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
                "Archive verification incomplete: expected volumes={}, found={}, missing sequences={:?}; reason={}",
                expected_volumes,
                found_volumes,
                missing_indices,
                reason
            )
        }
    }
}

/// Repair a damaged or incomplete ERA archive
pub async fn repair(
    archive: &Path,
    password: Option<&str>,
    key_path: Option<&Path>,
    force: bool,
    verbose: bool,
) -> Result<()> {
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
        info!("Archive appears complete. Running verification...");
        info!("");

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

        // Check if erasure coding is enabled
        let header = reader.header();
        let erasure_enabled = header.config().erasure.is_some();
        if erasure_enabled {
            let erasure_config = header.config().erasure.as_ref().unwrap();
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

        if matches!(verify_stats.archive_health, ArchiveHealthStatus::Healthy)
            && !verify_stats.needs_repair()
        {
            info!("✅ Archive is intact. No repair needed.");
            return Ok(());
        }

        if matches!(verify_stats.archive_health, ArchiveHealthStatus::Healthy)
            && verify_stats.needs_repair()
        {
            info!("⚠️  Archive is readable but has recoverable shard corruption.");
            for warn in &verify_stats.warnings {
                info!("  - {}", warn);
            }
            info!("");
        }

        let mut missing_volume_sequences = Vec::new();
        let mut expected_vs_found: Option<(usize, usize)> = None;
        match &verify_stats.archive_health {
            ArchiveHealthStatus::Healthy => {}
            ArchiveHealthStatus::Degraded {
                expected_volumes,
                found_volumes,
                missing_indices,
            } => {
                missing_volume_sequences = missing_indices.clone();
                expected_vs_found = Some((*expected_volumes, *found_volumes));
                info!("⚠️  Archive data is readable but archive health is degraded:");
                if !missing_indices.is_empty() {
                    info!("  Expected volumes:  {}", expected_volumes);
                    info!("  Volumes found:     {}", found_volumes);
                    info!("  Missing sequences: {:?}", missing_indices);
                }
                for warn in &verify_stats.warnings {
                    info!("  - {}", warn);
                }
                info!("");
            }
            ArchiveHealthStatus::Incomplete {
                expected_volumes,
                found_volumes,
                missing_indices,
                reason,
            } => {
                missing_volume_sequences = missing_indices.clone();
                expected_vs_found = Some((*expected_volumes, *found_volumes));
                info!("❌ Archive is incomplete:");
                if !missing_indices.is_empty() {
                    info!("  Expected volumes:  {}", expected_volumes);
                    info!("  Volumes found:     {}", found_volumes);
                    info!("  Missing sequences: {:?}", missing_indices);
                }
                info!("  Reason:            {}", reason);

                if verbose {
                    info!("");
                    info!("Errors found:");
                    for (i, error) in verify_stats.errors.iter().enumerate() {
                        info!("  {}. {}", i + 1, error);
                    }
                }

                info!("");
            }
        }

        if !missing_volume_sequences.is_empty() {
            let (expected, found) = expected_vs_found.unwrap_or((0, 0));
            anyhow::bail!(
                "Archive is missing expected volume files: expected={}, found={}, missing sequences={:?}; current repair cannot recreate missing volume files",
                expected,
                found,
                missing_volume_sequences,
            );
        }

        if erasure_enabled {
            if key_path.is_some() {
                anyhow::bail!(
                    "Reed-Solomon repair requires password mode. Re-run with --password instead of --key."
                );
            }
            let password = get_password(password, "Enter decryption password: ")?;
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

/// Parameters for repacking an ERA archive with new settings
pub struct RepackArgs<'a> {
    pub input: &'a Path,
    pub output: &'a Path,
    pub password: Option<&'a str>,
    pub key_path: Option<&'a Path>,
    pub compact: bool,
    pub compression_level: Option<i32>,
    pub no_compression: bool,
    pub erasure: Option<&'a str>,
    pub cdc_min: Option<usize>,
    pub cdc_avg: Option<usize>,
    pub cdc_max: Option<usize>,
    pub packing_k: Option<usize>,
    pub flush_threshold: Option<usize>,
    pub block_target_size: Option<usize>,
}

/// Repack an ERA archive with new parameters
pub async fn repack(args: RepackArgs<'_>) -> Result<()> {
    let RepackArgs {
        input,
        output,
        password,
        key_path,
        compact,
        compression_level,
        no_compression,
        erasure,
        cdc_min,
        cdc_avg,
        cdc_max,
        packing_k,
        flush_threshold,
        block_target_size,
    } = args;

    // 1. Build base config
    let mut config = if compact {
        info!("Using compact preset (Zstd-19, 16MB blocks, k=32)");
        ArchiveConfig::compact_preset()
    } else {
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

    apply_config_overrides(
        &mut config,
        ConfigOverrides {
            compression_level,
            no_compression,
            erasure,
            cdc_min,
            cdc_avg,
            cdc_max,
            packing_k,
            flush_threshold,
            block_target_size,
        },
    )?;

    info!(
        "Repacking archive: {} -> {}",
        input.display(),
        output.display()
    );

    let start_time = Instant::now();

    // 3. Dispatch to engine based on auth mode
    let stats = if let Some(kp_path) = key_path {
        info!("Loading private key: {}", kp_path.display());
        let keypair = era_crypto::load_private_key_from_pem(kp_path, password)
            .map_err(|e| anyhow::anyhow!("Failed to load private key: {}", e))?;
        repack_archive_with_keypair(input, output, &keypair, config)
            .await
            .context("Failed to repack archive with keypair")?
    } else {
        let password = get_password_with_confirmation(password)?;
        repack_archive(input, output, &password, config)
            .await
            .context("Failed to repack archive")?
    };

    info!("");
    info!(
        "✓ Repack complete in {}!",
        HumanDuration(start_time.elapsed())
    );
    info!("  Files repacked: {}", stats.files_repacked);
    info!("  Extracted size:  {}", HumanBytes(stats.extracted_bytes));
    info!(
        "  Repacked size:  {}",
        HumanBytes(stats.repacked_total_size)
    );
    info!("  Blocks written: {}", stats.blocks_written);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use era_crypto::pem_support::export_private_key_as_pem;
    use era_crypto::{export_public_key_as_pem, EraKeyPair};
    use std::fs;
    use tempfile::TempDir;

    fn count_volume_files(base_path: &Path, max_scan: usize) -> usize {
        (0..max_scan)
            .filter(|idx| {
                let path = if *idx == 0 {
                    base_path.to_path_buf()
                } else {
                    base_path.with_extension(format!("era.{:03}", idx))
                };
                path.exists()
            })
            .count()
    }

    async fn create_missing_volume_archive(name: &str, missing_seq: usize) -> (TempDir, PathBuf) {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join(format!("{name}.era"));

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .config(ArchiveConfig {
                compression: era_common::CompressionConfig {
                    algorithm: CompressionAlgorithm::None,
                    level: 0,
                },
                ..Default::default()
            })
            .enable_erasure(true)
            .erasure_config(ErasureCodeConfig::new(4, 2))
            .volume_count(6)
            .build()
            .await
            .unwrap();

        writer
            .add_bytes("payload.bin", &vec![0xAB; 64 * 1024])
            .await
            .unwrap();
        writer.finalize().await.unwrap();

        let missing_path = if missing_seq == 0 {
            archive_path.clone()
        } else {
            archive_path.with_extension(format!("era.{:03}", missing_seq))
        };
        fs::remove_file(&missing_path).unwrap();

        (temp_dir, archive_path)
    }

    fn overrides<'a>(
        compression_level: Option<i32>,
        no_compression: bool,
        erasure: Option<&'a str>,
        cdc_min: Option<usize>,
        cdc_avg: Option<usize>,
        cdc_max: Option<usize>,
    ) -> ConfigOverrides<'a> {
        ConfigOverrides {
            compression_level,
            no_compression,
            erasure,
            cdc_min,
            cdc_avg,
            cdc_max,
            packing_k: None,
            flush_threshold: None,
            block_target_size: None,
        }
    }

    #[test]
    fn parse_erasure_config_valid_cases() {
        let cases = [("4:2", 4u8, 2u8), ("6:3", 6u8, 3u8), ("1:1", 1u8, 1u8)];

        for (input, expected_data, expected_parity) in cases {
            let parsed = parse_erasure_config(input)
                .unwrap_or_else(|e| panic!("expected valid erasure '{input}': {e}"));
            assert_eq!(parsed.data_shards, expected_data, "data shards mismatch");
            assert_eq!(
                parsed.parity_shards, expected_parity,
                "parity shards mismatch"
            );
        }
    }

    #[test]
    fn parse_erasure_config_invalid_cases() {
        let cases = [
            ("4", "Invalid erasure format"),
            ("4:two", "Invalid parity shards value"),
            ("zero:2", "Invalid data shards value"),
            ("0:2", "Data shards must be at least 1"),
            ("4:0", "Parity shards must be at least 1"),
            ("200:100", "Total shards"),
        ];

        for (input, expected_fragment) in cases {
            let err = parse_erasure_config(input)
                .expect_err("invalid erasure config should return an error");
            assert!(
                err.to_string().contains(expected_fragment),
                "expected '{expected_fragment}' in error for '{input}', got: {err}"
            );
        }
    }

    #[test]
    fn apply_config_overrides_store_mode_and_erasure_none() {
        let mut level_zero = ArchiveConfig::default();
        apply_config_overrides(
            &mut level_zero,
            overrides(Some(0), false, None, None, None, None),
        )
        .expect("level 0 should be accepted");
        assert_eq!(level_zero.compression.algorithm, CompressionAlgorithm::None);
        assert_eq!(level_zero.compression.level, 0);

        let mut no_compression = ArchiveConfig::default();
        apply_config_overrides(
            &mut no_compression,
            overrides(Some(12), true, None, None, None, None),
        )
        .expect("--no-compression should take precedence");
        assert_eq!(
            no_compression.compression.algorithm,
            CompressionAlgorithm::None
        );
        assert_eq!(no_compression.compression.level, 0);

        let mut erasure_none = ArchiveConfig::default();
        assert!(erasure_none.erasure.is_some());
        apply_config_overrides(
            &mut erasure_none,
            overrides(None, false, Some("none"), None, None, None),
        )
        .expect("erasure none should be accepted");
        assert!(erasure_none.erasure.is_none());

        let mut erasure_custom = ArchiveConfig::default();
        apply_config_overrides(
            &mut erasure_custom,
            overrides(None, false, Some("6:3"), None, None, None),
        )
        .expect("custom erasure should be accepted");
        let custom = erasure_custom
            .erasure
            .as_ref()
            .expect("erasure should remain enabled");
        assert_eq!(custom.data_shards, 6);
        assert_eq!(custom.parity_shards, 3);
    }

    #[test]
    fn apply_config_overrides_rejects_out_of_bounds_compression() {
        for level in [-1, 23] {
            let mut config = ArchiveConfig::default();
            let err = apply_config_overrides(
                &mut config,
                overrides(Some(level), false, None, None, None, None),
            )
            .expect_err("invalid compression level should fail");

            assert!(
                err.to_string().contains("between 0 and 22"),
                "unexpected compression error for level {level}: {err}"
            );
        }
    }

    #[test]
    fn apply_config_overrides_validates_cdc_zero_and_ordering() {
        let zero_cases = [
            (Some(0), None, None),
            (None, Some(0), None),
            (None, None, Some(0)),
        ];
        for (cdc_min, cdc_avg, cdc_max) in zero_cases {
            let mut config = ArchiveConfig::default();
            let err = apply_config_overrides(
                &mut config,
                overrides(None, false, None, cdc_min, cdc_avg, cdc_max),
            )
            .expect_err("zero CDC values should fail");
            assert!(
                err.to_string().contains("CDC sizes must be > 0"),
                "unexpected zero CDC error: {err}"
            );
        }

        let ordering_cases = [
            (Some(128 * 1024), Some(64 * 1024), Some(256 * 1024)),
            (Some(16 * 1024), Some(32 * 1024), Some(8 * 1024)),
        ];
        for (cdc_min, cdc_avg, cdc_max) in ordering_cases {
            let mut config = ArchiveConfig::default();
            let err = apply_config_overrides(
                &mut config,
                overrides(None, false, None, cdc_min, cdc_avg, cdc_max),
            )
            .expect_err("invalid CDC ordering should fail");
            assert!(
                err.to_string().contains("min <= avg <= max"),
                "unexpected CDC ordering error: {err}"
            );
        }
    }

    #[tokio::test]
    async fn create_hybrid_mode_supports_password_and_key_open_paths() {
        let temp_dir = TempDir::new().expect("temp dir should be created");
        let input = temp_dir.path().join("payload.txt");
        fs::write(&input, "hybrid auth payload").expect("hybrid input should be written");

        let archive = temp_dir.path().join("hybrid.era");
        let cert_path = temp_dir.path().join("public.pem");
        let key_path = temp_dir.path().join("private.pem");

        let keypair = EraKeyPair::generate().expect("hybrid keypair should be generated");
        let cert_pem =
            export_public_key_as_pem(&keypair.certificate()).expect("public PEM should export");
        let key_pem = export_private_key_as_pem(&keypair).expect("private PEM should export");
        fs::write(&cert_path, cert_pem).expect("public PEM should be written");
        fs::write(&key_path, key_pem).expect("private PEM should be written");

        let inputs = vec![input.clone()];
        create(CreateArgs {
            inputs: &inputs,
            output: &archive,
            config_path: None,
            certificate_path: Some(cert_path.as_path()),
            password: Some("hybrid_password"),
            compression_level: None,
            no_compression: false,
            erasure: None,
            volume_count: None,
            max_volume_size: None,
            cdc_min: None,
            cdc_avg: None,
            cdc_max: None,
            packing_k: None,
            flush_threshold: None,
            block_target_size: None,
            compact: false,
        })
        .await
        .expect("hybrid create should succeed");

        ArchiveReader::open(&archive, "hybrid_password")
            .await
            .expect("password open should succeed for hybrid archive");

        let read_keypair = era_crypto::load_private_key_from_pem(&key_path, None)
            .expect("private key should load");
        ArchiveReader::open_with_keypair(&archive, &read_keypair)
            .await
            .expect("key open should succeed for hybrid archive");
    }

    #[tokio::test]
    async fn create_accepts_canonical_low_volume_count() {
        let temp_dir = TempDir::new().unwrap();
        let input = temp_dir.path().join("payload.bin");
        fs::write(&input, vec![0xCD; 32 * 1024]).unwrap();
        let output = temp_dir.path().join("lowvol.era");
        let inputs = vec![input.clone()];

        create(CreateArgs {
            inputs: &inputs,
            output: &output,
            config_path: None,
            certificate_path: None,
            password: Some("test_password"),
            compression_level: None,
            no_compression: false,
            erasure: Some("4:2"),
            volume_count: Some(3),
            max_volume_size: None,
            cdc_min: None,
            cdc_avg: None,
            cdc_max: None,
            packing_k: None,
            flush_threshold: None,
            block_target_size: None,
            compact: false,
        })
        .await
        .unwrap();

        assert_eq!(count_volume_files(&output, 16), 3);
    }

    #[tokio::test]
    async fn create_rejects_non_divisible_low_volume_count() {
        let temp_dir = TempDir::new().unwrap();
        let input = temp_dir.path().join("payload.bin");
        fs::write(&input, vec![0xCD; 32 * 1024]).unwrap();
        let output = temp_dir.path().join("invalid.era");
        let inputs = vec![input.clone()];

        let err = create(CreateArgs {
            inputs: &inputs,
            output: &output,
            config_path: None,
            certificate_path: None,
            password: Some("test_password"),
            compression_level: None,
            no_compression: false,
            erasure: Some("4:2"),
            volume_count: Some(4),
            max_volume_size: None,
            cdc_min: None,
            cdc_avg: None,
            cdc_max: None,
            packing_k: None,
            flush_threshold: None,
            block_target_size: None,
            compact: false,
        })
        .await
        .expect_err("4 volumes for 4+2 should fail");

        assert!(
            err.to_string().contains("divide") || err.to_string().contains("total shards"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn verify_returns_error_for_missing_expected_volume() {
        let (_temp_dir, archive_path) = create_missing_volume_archive("verify_missing", 2).await;

        let err = verify(&archive_path, Some("test_password"), None, false)
            .await
            .expect_err("missing volume should degrade verify result");

        assert!(
            err.to_string().contains("Archive verification degraded")
                || err.to_string().contains("missing sequences"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn repair_returns_error_for_missing_expected_volume() {
        let (_temp_dir, archive_path) = create_missing_volume_archive("repair_missing", 1).await;

        let err = repair(&archive_path, Some("test_password"), None, false, false)
            .await
            .expect_err("missing volume should not report healthy repair status");

        assert!(
            err.to_string().contains("missing expected volume files"),
            "unexpected error: {err}"
        );
    }
}
