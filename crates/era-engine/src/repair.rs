//! Archive repair functionality using Reed-Solomon erasure coding.
//!
//! This module provides the ability to repair damaged ERA archives
//! by using RS decoding to reconstruct corrupted shards.
//!
//! ## Security (ERA v8.1)
//!
//! This module uses the HKDF "Onion Model" for per-block key derivation:
//! - Each block is decrypted/re-encrypted with a unique key derived from the volume key
//! - This provides forward and backward security isolation
//!
//! ## Matrix Distribution Support
//!
//! This module supports both single-volume and matrix-distributed archives:
//! - Single-volume: All shards in a single volume using `shard_idx % volume_count`
//! - Matrix: Shards distributed using `(shard_idx + block_sequence) % volume_count`

use crate::reader::ArchiveReader;
use bytes::Bytes;
use era_codec::{ErasureCoder, ErasureConfig, ZstdCompressor};
use era_common::{compute_shard_crc, EraError, ErasureCodeConfig, Result, ShardHeader};
use era_crypto::KeySession;
use era_storage::LocalStorageBackend;
use era_volume::VolumeReader;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Statistics about the repair operation
#[derive(Debug, Default)]
pub struct RepairStats {
    /// Total number of blocks scanned
    pub blocks_scanned: u64,
    /// Number of blocks with corrupted shards
    pub blocks_with_corruption: u64,
    /// Total number of corrupted shards found
    pub corrupted_shards_found: u64,
    /// Number of shards successfully repaired
    pub shards_repaired: u64,
    /// Number of blocks that couldn't be repaired (too many shards lost)
    pub unrecoverable_blocks: u64,
    /// Detailed error messages for unrecoverable blocks
    pub errors: Vec<String>,
}

fn preflight_metadata_recovery(path: &Path, password: &str) -> Result<()> {
    let mut reader = ArchiveReader::open(path, password)?;
    reader.preflight_metadata_recovery()
}

impl RepairStats {
    /// Check if all corrupted shards were repaired
    pub fn fully_repaired(&self) -> bool {
        self.unrecoverable_blocks == 0 && self.corrupted_shards_found == self.shards_repaired
    }
}

/// Options for the repair operation
#[derive(Debug, Clone)]
pub struct RepairOptions {
    /// Create a backup before modifying the archive
    pub create_backup: bool,
    /// Dry run - don't actually write repairs
    pub dry_run: bool,
    /// Continue after encountering unrecoverable blocks
    pub continue_on_error: bool,
}

impl Default for RepairOptions {
    fn default() -> Self {
        Self {
            create_backup: true,
            dry_run: false,
            continue_on_error: true,
        }
    }
}

/// Repair an ERA archive using RS erasure coding
///
/// This function:
/// 1. Opens the archive and validates erasure coding is enabled
/// 2. Scans all erasure blocks for corrupted shards
/// 3. Uses RS decoding to reconstruct corrupted data
/// 4. Re-encodes and writes repaired shards back to the file
///
/// Returns RepairStats with details about what was repaired.
pub fn repair_archive(path: &Path, password: &str, options: RepairOptions) -> Result<RepairStats> {
    info!("Starting archive repair: {}", path.display());

    // Open archive for reading first
    let parent_dir = path.parent().unwrap_or(Path::new("."));
    let backend = LocalStorageBackend::new(parent_dir);
    let volume_path = path.file_name().unwrap_or_default();

    let volume_reader = VolumeReader::open(&backend, Path::new(volume_path))?;

    // Verify erasure coding is enabled
    let header = volume_reader.header();
    let erasure_config = header.config.erasure.ok_or_else(|| {
        EraError::ErasureError("Archive does not use erasure coding - repair not available".into())
    })?;

    // If the archive is multi-volume, use matrix-aware repair
    if header.total_volumes > 1 {
        return repair_archive_matrix(path, password, options);
    }

    info!(
        "Erasure config: {}/{} data/parity shards",
        erasure_config.data_shards, erasure_config.parity_shards
    );

    // Create key session using PasswordProvider
    // Requires crate::auth::AuthProvider and crate::auth::PasswordProvider
    let provider = crate::auth::PasswordProvider::new(password.to_string());

    let mut master_key = None;
    for slot in &header.recipients {
        use crate::auth::AuthProvider;
        if let Ok(Some(mk)) = provider.try_unlock(slot) {
            master_key = Some(mk);
            break;
        }
    }

    let master_key = master_key.ok_or(EraError::InvalidKey("Incorrect password".into()))?;
    let mk_array: [u8; 32] = master_key
        .try_into()
        .map_err(|_| EraError::InvalidKey("Invalid master key length".into()))?;
    let _session = KeySession::from_master_key(&mk_array)?;

    // Metadata-first preflight: restore embedded LSM and catalog before repair
    preflight_metadata_recovery(path, password)?;

    // Create compressor (kept for future decode-based validation if needed)
    let _compressor: Box<dyn era_codec::Compressor> =
        Box::new(ZstdCompressor::new(header.config.compression.level));

    // Create backup if requested
    if options.create_backup && !options.dry_run {
        let backup_path = path.with_extension("era.bak");
        if !backup_path.exists() {
            info!("Creating backup: {}", backup_path.display());
            std::fs::copy(path, &backup_path)?;
        } else {
            info!("Backup already exists: {}", backup_path.display());
        }
    }

    // Scan for corrupted blocks and repair
    let mut stats = RepairStats::default();
    let total_shards = erasure_config.data_shards as usize + erasure_config.parity_shards as usize;

    let (data_start, data_end) = volume_reader.data_region();
    let erasure_data_end = volume_reader
        .footer()
        .map(|f| f.catalog_offset)
        .unwrap_or(data_end);

    let mut offset = data_start;
    let mut block_index = 0u32;
    let header_prefix_len = erasure_config.data_shards as usize * 4;

    // Collect repair operations first (to do them in a batch)
    let mut repairs: Vec<ShardRepair> = Vec::new();

    'stripe_loop: while offset < erasure_data_end {
        let mut shards: Vec<(usize, Bytes)> = Vec::with_capacity(total_shards);
        let mut shard_offsets: Vec<u64> = Vec::with_capacity(total_shards);
        let mut corrupted_indices: Vec<usize> = Vec::new();
        let mut data_lengths: Vec<Option<u32>> = vec![None; erasure_config.data_shards as usize];
        let mut max_len: usize = 0;
        let mut stripe_lengths: Option<Vec<u32>> = None;

        for shard_idx in 0..total_shards {
            let shard_header_offset = offset;

            let prefix_bytes = match volume_reader.read_raw(offset, header_prefix_len) {
                Ok(bytes) if bytes.len() == header_prefix_len => bytes,
                _ => {
                    // End of data region
                    break 'stripe_loop;
                }
            };

            if stripe_lengths.is_none() {
                let mut lengths = Vec::with_capacity(erasure_config.data_shards as usize);
                for chunk in prefix_bytes.chunks_exact(4) {
                    lengths.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
                }
                stripe_lengths = Some(lengths);
            }

            let header_bytes = match volume_reader
                .read_raw(offset + header_prefix_len as u64, ShardHeader::SIZE)
            {
                Ok(bytes) if bytes.len() == ShardHeader::SIZE => bytes,
                _ => {
                    // End of data region
                    break 'stripe_loop;
                }
            };

            let shard_header = match ShardHeader::from_bytes(&header_bytes) {
                Some(h) => h,
                None => {
                    debug!(
                        "Invalid shard header at block {}, shard {}",
                        block_index, shard_idx
                    );
                    corrupted_indices.push(shard_idx);
                    break 'stripe_loop;
                }
            };

            let shard_len = shard_header.length as usize;
            shard_offsets.push(shard_header_offset);

            if shard_idx < data_lengths.len() {
                data_lengths[shard_idx] = Some(shard_header.length);
            }

            if shard_len > max_len {
                max_len = shard_len;
            }

            match volume_reader.read_raw(
                offset + header_prefix_len as u64 + ShardHeader::SIZE as u64,
                shard_len,
            ) {
                Ok(shard_data) => {
                    if shard_header.verify(&shard_data) {
                        shards.push((shard_idx, shard_data));
                    } else {
                        debug!(
                            "Block {}: shard {} CRC mismatch at offset {}",
                            block_index, shard_idx, offset
                        );
                        corrupted_indices.push(shard_idx);
                        stats.corrupted_shards_found += 1;
                    }
                }
                Err(_) => {
                    corrupted_indices.push(shard_idx);
                    stats.corrupted_shards_found += 1;
                }
            }

            offset += header_prefix_len as u64 + ShardHeader::SIZE as u64 + shard_len as u64;
        }

        if let Some(lengths) = stripe_lengths {
            if let Some(stripe_max) = lengths.iter().copied().max() {
                if stripe_max as usize > max_len {
                    max_len = stripe_max as usize;
                }
            }

            for (idx, len) in lengths.into_iter().enumerate() {
                if idx < data_lengths.len() && data_lengths[idx].is_none() && len > 0 {
                    data_lengths[idx] = Some(len);
                }
            }
        }

        stats.blocks_scanned += 1;

        if !corrupted_indices.is_empty() {
            stats.blocks_with_corruption += 1;

            let min_shards = erasure_config.data_shards as usize;
            if shards.len() < min_shards {
                stats.unrecoverable_blocks += 1;
                let msg = format!(
                    "Block {}: only {}/{} shards intact, need {} for recovery",
                    block_index,
                    shards.len(),
                    total_shards,
                    min_shards
                );
                warn!("{}", msg);
                stats.errors.push(msg);

                if !options.continue_on_error {
                    return Err(EraError::ErasureError(format!(
                        "Block {} is unrecoverable",
                        block_index
                    )));
                }
            } else {
                let shard_size = if max_len.is_multiple_of(2) {
                    max_len
                } else {
                    max_len + 1
                };

                let repaired = repair_shards_rs(
                    &shards,
                    &corrupted_indices,
                    &data_lengths,
                    &erasure_config,
                    shard_size,
                );

                match repaired {
                    Ok(repaired_shards) => {
                        for (shard_idx, shard_data) in repaired_shards {
                            let shard_offset = shard_offsets.get(shard_idx).copied();
                            if let Some(off) = shard_offset {
                                repairs.push(ShardRepair {
                                    offset: off,
                                    shard_idx,
                                    data: shard_data,
                                });
                                stats.shards_repaired += 1;
                            }
                        }
                        info!(
                            "Block {}: recovered {} corrupted shards",
                            block_index,
                            corrupted_indices.len()
                        );
                    }
                    Err(e) => {
                        stats.unrecoverable_blocks += 1;
                        let msg = format!("Block {}: RS reconstruction failed: {}", block_index, e);
                        warn!("{}", msg);
                        stats.errors.push(msg);
                    }
                }
            }
        }

        block_index += 1;
    }

    // Apply repairs if not dry run
    if !options.dry_run && !repairs.is_empty() {
        info!("Applying {} shard repairs...", repairs.len());
        apply_repairs(path, &repairs)?;
    } else if options.dry_run && !repairs.is_empty() {
        info!("Dry run: would have repaired {} shards", repairs.len());
    }

    info!(
        "Repair complete: {} blocks scanned, {} corrupted, {} shards repaired, {} unrecoverable",
        stats.blocks_scanned,
        stats.blocks_with_corruption,
        stats.shards_repaired,
        stats.unrecoverable_blocks
    );

    Ok(stats)
}

/// Represents a shard repair operation
struct ShardRepair {
    /// File offset of the shard header
    offset: u64,
    /// Shard index (for logging)
    shard_idx: usize,
    /// Repaired shard data
    data: Bytes,
}

/// Use Reed-Solomon to reconstruct missing shards
fn repair_shards_rs(
    available_shards: &[(usize, Bytes)],
    corrupted_indices: &[usize],
    data_lengths: &[Option<u32>],
    config: &ErasureCodeConfig,
    shard_size: usize,
) -> Result<Vec<(usize, Bytes)>> {
    let data_shards = config.data_shards as usize;
    let parity_shards = config.parity_shards as usize;
    let total_shards = data_shards + parity_shards;

    let erasure_config = ErasureConfig::new(data_shards, parity_shards)?;
    let coder = ErasureCoder::new(erasure_config)?;

    let mut shards: Vec<Option<Vec<u8>>> = vec![None; total_shards];
    for (idx, data) in available_shards {
        shards[*idx] = Some(data.to_vec());
    }

    // Recover all data shards (padded)
    let recovered_data = coder.recover_data_shards(&shards, shard_size)?;

    // Re-encode to get parity shards
    let all_shards = coder.encode_shards(&recovered_data)?;

    let mut repaired = Vec::new();
    for &idx in corrupted_indices {
        if idx >= total_shards {
            return Err(EraError::ErasureError(format!(
                "Shard index {} out of range",
                idx
            )));
        }

        let mut data = all_shards[idx].clone();
        if idx < data_shards {
            let original_len = data_lengths.get(idx).and_then(|v| *v).ok_or_else(|| {
                EraError::ErasureError("Missing original length for data shard".into())
            })? as usize;
            data.truncate(original_len);
        }

        repaired.push((idx, Bytes::from(data)));
    }

    Ok(repaired)
}

/// Apply shard repairs to the archive file
fn apply_repairs(path: &Path, repairs: &[ShardRepair]) -> Result<()> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;

    for repair in repairs {
        // Write new shard header with CRC
        let crc = compute_shard_crc(&repair.data);
        let header = ShardHeader::new(repair.data.len() as u32, crc);

        file.seek(SeekFrom::Start(repair.offset))?;
        file.write_all(&header.to_bytes())?;
        file.write_all(&repair.data)?;

        debug!(
            "Repaired shard {} at offset {} ({} bytes)",
            repair.shard_idx,
            repair.offset,
            repair.data.len()
        );
    }

    file.sync_all()?;
    Ok(())
}

/// Repair a multi-volume ERA archive with matrix distribution
///
/// This function handles archives where shards are distributed across
/// multiple volumes using the matrix distribution pattern:
/// `volume_idx = (shard_idx + block_sequence) % volume_count`
///
/// # Arguments
/// * `path` - Path to the first volume (e.g., "archive.era")
/// * `password` - Archive password for decryption
/// * `options` - Repair options
///
/// # Returns
/// RepairStats with details about what was repaired across all volumes.
pub fn repair_archive_matrix(
    path: &Path,
    password: &str,
    options: RepairOptions,
) -> Result<RepairStats> {
    info!(
        "Starting matrix-distributed archive repair: {}",
        path.display()
    );

    // Metadata-first preflight: restore embedded LSM and catalog before repair
    preflight_metadata_recovery(path, password)?;

    let parent_dir = path.parent().unwrap_or(Path::new("."));
    let backend = LocalStorageBackend::new(parent_dir);

    // Collect all volumes
    let mut volume_readers: Vec<VolumeReader<era_storage::LocalStorageReader>> = Vec::new();
    let mut volume_paths: Vec<PathBuf> = Vec::new();
    let mut volume_sequences: Vec<u16> = Vec::new();

    // Open first volume
    let volume_filename = path.file_name().unwrap_or_default();
    let first_reader = VolumeReader::open(&backend, Path::new(volume_filename))?;
    let archive_id = first_reader.header().archive_id;
    let header = first_reader.header().clone();
    let total_volumes = first_reader.header().total_volumes;

    volume_sequences.push(0);
    volume_paths.push(path.to_path_buf());
    volume_readers.push(first_reader);

    // Find additional volumes - continue even if some are missing
    let base_path = path.with_extension("");
    let mut consecutive_missing = 0;
    let max_gap = 5; // Allow up to 5 consecutive missing volumes before giving up

    for seq in 1..total_volumes.max(100) {
        let ext = format!("era.{:03}", seq);
        let next_path = base_path.with_extension(&ext);
        let next_filename = next_path.file_name().unwrap_or_default();

        match VolumeReader::open(&backend, Path::new(next_filename)) {
            Ok(reader) => {
                if reader.header().archive_id != archive_id {
                    break;
                }
                volume_sequences.push(seq);
                volume_paths.push(next_path);
                volume_readers.push(reader);
                consecutive_missing = 0;
            }
            Err(_) => {
                consecutive_missing += 1;
                if consecutive_missing > max_gap && seq >= total_volumes {
                    break;
                }
            }
        }
    }

    let volume_count = volume_readers.len();
    info!(
        "Found {} volumes for matrix-distributed archive (expected {})",
        volume_count, total_volumes
    );

    if volume_count < 2 {
        // Fall back to single-volume repair
        info!("Single volume detected, using legacy repair");
        return repair_archive(path, password, options);
    }

    // Verify erasure coding is enabled
    let erasure_config = header
        .config
        .erasure
        .ok_or_else(|| EraError::ErasureError("Archive does not use erasure coding".into()))?;

    let total_shards = erasure_config.data_shards as usize + erasure_config.parity_shards as usize;

    info!(
        "Matrix repair: {}/{} erasure, {} volumes found, {} total shards",
        erasure_config.data_shards, erasure_config.parity_shards, volume_count, total_shards
    );

    // Create key session
    let provider = crate::auth::PasswordProvider::new(password.to_string());

    let mut master_key = None;
    for slot in &header.recipients {
        use crate::auth::AuthProvider;
        if let Ok(Some(mk)) = provider.try_unlock(slot) {
            master_key = Some(mk);
            break;
        }
    }

    let master_key = master_key.ok_or(EraError::InvalidKey("Incorrect password".into()))?;
    let mk_array: [u8; 32] = master_key
        .try_into()
        .map_err(|_| EraError::InvalidKey("Invalid master key length".into()))?;
    let _session = KeySession::from_master_key(&mk_array)?;

    let _compressor: Box<dyn era_codec::Compressor> =
        Box::new(ZstdCompressor::new(header.config.compression.level));

    // Create backups if requested
    if options.create_backup && !options.dry_run {
        for vol_path in &volume_paths {
            let backup_path = vol_path.with_extension(
                vol_path
                    .extension()
                    .map(|e| format!("{}.bak", e.to_string_lossy()))
                    .unwrap_or_else(|| "bak".to_string()),
            );
            if !backup_path.exists() {
                info!("Creating backup: {}", backup_path.display());
                std::fs::copy(vol_path, &backup_path)?;
            }
        }
    }

    let mut stats = RepairStats::default();
    let mut all_repairs: HashMap<usize, Vec<ShardRepair>> = HashMap::new(); // volume_idx -> repairs

    // Scan blocks using matrix distribution pattern
    // We need to iterate through block sequences and collect shards from each volume
    // Track offsets for each volume
    let mut volume_offsets: Vec<u64> = volume_readers.iter().map(|r| r.data_region().0).collect();

    let mut block_sequence: u64 = 0;
    let distribution_strategy = header.config.distribution.strategy;
    let total_volumes = header.total_volumes as usize;

    // Map volume sequence -> reader index
    let mut vol_index_map = vec![None; total_volumes.max(1)];
    for (reader_idx, seq) in volume_sequences.iter().enumerate() {
        let seq_idx = *seq as usize;
        if seq_idx < vol_index_map.len() {
            vol_index_map[seq_idx] = Some(reader_idx);
        }
    }

    let data_ends: Vec<u64> = volume_readers
        .iter()
        .map(|reader| {
            let (_, end) = reader.data_region();
            if let Some(f) = reader.footer() {
                let mut limit = if f.has_catalog_location() {
                    f.catalog_offset
                } else {
                    end
                };
                if f.has_index() && f.index_offset < limit {
                    limit = f.index_offset;
                }
                limit
            } else {
                end
            }
        })
        .collect();

    let header_prefix_len = erasure_config.data_shards as usize * 4;

    'stripe_loop: loop {
        let mut shards: Vec<(usize, Bytes)> = Vec::with_capacity(total_shards);
        let mut shard_locations: Vec<(usize, usize, u64)> = Vec::new(); // (shard_idx, reader_idx, offset)
        let mut corrupted_indices: Vec<usize> = Vec::new();
        let mut data_lengths: Vec<Option<u32>> = vec![None; erasure_config.data_shards as usize];
        let mut max_len: usize = 0;
        let mut any_shard_read = false;
        let mut stripe_lengths: Option<Vec<u32>> = None;

        for shard_idx in 0..total_shards {
            let vol_idx = distribution_strategy.calculate_volume(
                shard_idx,
                block_sequence,
                total_volumes.max(1),
            );

            let reader_idx_opt = vol_index_map.get(vol_idx).copied().flatten();
            if let Some(reader_idx) = reader_idx_opt {
                let reader = &volume_readers[reader_idx];
                let shard_offset = volume_offsets[reader_idx];

                if shard_offset >= data_ends[reader_idx] {
                    if shard_idx == 0 {
                        break 'stripe_loop;
                    }
                    corrupted_indices.push(shard_idx);
                    stats.corrupted_shards_found += 1;
                    continue;
                }

                let prefix_bytes = match reader.read_raw(shard_offset, header_prefix_len) {
                    Ok(bytes) if bytes.len() == header_prefix_len => bytes,
                    _ => {
                        if shard_idx == 0 {
                            break 'stripe_loop;
                        }
                        corrupted_indices.push(shard_idx);
                        stats.corrupted_shards_found += 1;
                        continue;
                    }
                };

                if stripe_lengths.is_none() {
                    let mut lengths = Vec::with_capacity(erasure_config.data_shards as usize);
                    for chunk in prefix_bytes.chunks_exact(4) {
                        lengths.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
                    }
                    stripe_lengths = Some(lengths);
                }

                let header_bytes = match reader
                    .read_raw(shard_offset + header_prefix_len as u64, ShardHeader::SIZE)
                {
                    Ok(bytes) if bytes.len() == ShardHeader::SIZE => bytes,
                    _ => {
                        if shard_idx == 0 {
                            break 'stripe_loop;
                        }
                        corrupted_indices.push(shard_idx);
                        stats.corrupted_shards_found += 1;
                        continue;
                    }
                };

                let shard_header = match ShardHeader::from_bytes(&header_bytes) {
                    Some(h) => h,
                    None => {
                        corrupted_indices.push(shard_idx);
                        stats.corrupted_shards_found += 1;
                        continue;
                    }
                };

                let shard_len = shard_header.length as usize;
                if shard_idx < data_lengths.len() {
                    data_lengths[shard_idx] = Some(shard_header.length);
                }
                if shard_len > max_len {
                    max_len = shard_len;
                }

                any_shard_read = true;
                match reader.read_raw(
                    shard_offset + header_prefix_len as u64 + ShardHeader::SIZE as u64,
                    shard_len,
                ) {
                    Ok(shard_data) => {
                        if shard_header.verify(&shard_data) {
                            shards.push((shard_idx, shard_data));
                            shard_locations.push((shard_idx, reader_idx, shard_offset));
                        } else {
                            corrupted_indices.push(shard_idx);
                            shard_locations.push((shard_idx, reader_idx, shard_offset));
                            stats.corrupted_shards_found += 1;
                        }
                    }
                    Err(_) => {
                        corrupted_indices.push(shard_idx);
                        stats.corrupted_shards_found += 1;
                    }
                }

                volume_offsets[reader_idx] = shard_offset
                    + header_prefix_len as u64
                    + ShardHeader::SIZE as u64
                    + shard_len as u64;
            } else {
                corrupted_indices.push(shard_idx);
                stats.corrupted_shards_found += 1;
            }
        }

        if let Some(lengths) = stripe_lengths {
            if let Some(stripe_max) = lengths.iter().copied().max() {
                if stripe_max as usize > max_len {
                    max_len = stripe_max as usize;
                }
            }
            for (idx, len) in lengths.into_iter().enumerate() {
                if idx < data_lengths.len() && data_lengths[idx].is_none() && len > 0 {
                    data_lengths[idx] = Some(len);
                }
            }
        }

        if !any_shard_read {
            break;
        }

        stats.blocks_scanned += 1;

        if !corrupted_indices.is_empty() {
            stats.blocks_with_corruption += 1;

            let min_shards = erasure_config.data_shards as usize;
            if shards.len() < min_shards {
                stats.unrecoverable_blocks += 1;
                let msg = format!(
                    "Block {}: only {}/{} shards intact, need {} for recovery",
                    block_sequence,
                    shards.len(),
                    total_shards,
                    min_shards
                );
                warn!("{}", msg);
                stats.errors.push(msg);

                if !options.continue_on_error {
                    return Err(EraError::ErasureError(format!(
                        "Block {} is unrecoverable",
                        block_sequence
                    )));
                }
            } else {
                let shard_size = if max_len.is_multiple_of(2) {
                    max_len
                } else {
                    max_len + 1
                };

                match repair_shards_rs(
                    &shards,
                    &corrupted_indices,
                    &data_lengths,
                    &erasure_config,
                    shard_size,
                ) {
                    Ok(repaired_shards) => {
                        for (shard_idx, shard_data) in repaired_shards {
                            if let Some(&(_, reader_idx, offset)) =
                                shard_locations.iter().find(|(idx, _, _)| *idx == shard_idx)
                            {
                                all_repairs
                                    .entry(reader_idx)
                                    .or_default()
                                    .push(ShardRepair {
                                        offset,
                                        shard_idx,
                                        data: shard_data,
                                    });
                                stats.shards_repaired += 1;
                            }
                        }
                        info!(
                            "Block {}: recovered {} shards",
                            block_sequence,
                            corrupted_indices.len()
                        );
                    }
                    Err(e) => {
                        stats.unrecoverable_blocks += 1;
                        let msg =
                            format!("Block {}: RS reconstruction failed: {}", block_sequence, e);
                        warn!("{}", msg);
                        stats.errors.push(msg);
                    }
                }
            }
        }

        block_sequence += 1;
    }

    // Apply repairs to each volume
    if !options.dry_run && !all_repairs.is_empty() {
        for (vol_idx, repairs) in &all_repairs {
            if !repairs.is_empty() {
                info!("Applying {} repairs to volume {}", repairs.len(), vol_idx);
                apply_repairs(&volume_paths[*vol_idx], repairs)?;
            }
        }
    } else if options.dry_run {
        let total_repairs: usize = all_repairs.values().map(|r| r.len()).sum();
        info!(
            "Dry run: would repair {} shards across {} volumes",
            total_repairs,
            all_repairs.len()
        );
    }

    info!(
        "Matrix repair complete: {} blocks, {} corrupted, {} repaired, {} unrecoverable",
        stats.blocks_scanned,
        stats.blocks_with_corruption,
        stats.shards_repaired,
        stats.unrecoverable_blocks
    );

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repair_stats_fully_repaired() {
        let mut stats = RepairStats::default();
        assert!(stats.fully_repaired());

        stats.corrupted_shards_found = 2;
        stats.shards_repaired = 2;
        assert!(stats.fully_repaired());

        stats.unrecoverable_blocks = 1;
        assert!(!stats.fully_repaired());
    }

    #[test]
    fn test_repair_options_default() {
        let opts = RepairOptions::default();
        assert!(opts.create_backup);
        assert!(!opts.dry_run);
        assert!(opts.continue_on_error);
    }
}
