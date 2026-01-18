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
//! This module supports both legacy (single-volume) and matrix-distributed archives:
//! - Legacy: All shards in a single volume using `shard_idx % volume_count`
//! - Matrix: Shards distributed using `(shard_idx + block_sequence) % volume_count`

use bytes::Bytes;
use era_codec::{ErasureCoder, ErasureConfig, ZstdCompressor};
use era_common::{
    compute_shard_crc, BlockId, EraError, ErasureBlockInfo, ErasureCodeConfig, Result, ShardHeader,
};
use era_crypto::{KdfParams, KeySession, Salt};
use era_packing::SessionErasureBlockUnpacker;
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

    info!(
        "Erasure config: {}/{} data/parity shards",
        erasure_config.data_shards, erasure_config.parity_shards
    );

    // Create key session for per-block key derivation
    let salt = Salt::from_bytes(header.crypto_anchor.salt);
    let kdf_params = KdfParams {
        memory_cost: header.crypto_anchor.kdf_memory_cost,
        time_cost: header.crypto_anchor.kdf_time_cost,
        parallelism: header.crypto_anchor.kdf_parallelism,
    };
    let session = KeySession::new(password.as_bytes(), &salt, &kdf_params)?;

    // Verify password using the session
    if !session.verify_password(&header.crypto_anchor.password_verification_tag) {
        return Err(EraError::InvalidKey("Incorrect password".to_string()));
    }

    // Derive volume key for volume 0
    let volume_key = session.derive_volume_key(0);

    // Create session-based unpacker for RS decoding with per-block key derivation
    let nonce_context = header.crypto_anchor.salt;
    let compressor: Box<dyn era_codec::Compressor> =
        Box::new(ZstdCompressor::new(header.config.compression.level));
    let erasure_unpacker =
        SessionErasureBlockUnpacker::new(&session, &volume_key, nonce_context, compressor);

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
    let erasure_data_end = volume_reader.footer().map(|f| f.catalog_offset).unwrap_or(data_end);

    let mut offset = data_start;
    let mut block_index = 0u32;

    // Collect repair operations first (to do them in a batch)
    let mut repairs: Vec<ShardRepair> = Vec::new();

    while offset < erasure_data_end {
        // Read erasure block header
        let header_bytes = match volume_reader.read_raw(offset, 4) {
            Ok(bytes) if bytes.len() == 4 => bytes,
            _ => break,
        };
        let original_len = u32::from_le_bytes([
            header_bytes[0],
            header_bytes[1],
            header_bytes[2],
            header_bytes[3],
        ]);

        let _block_header_offset = offset;
        offset += 4;

        // Track shard info for this block
        let mut shards: Vec<(usize, Bytes)> = Vec::with_capacity(total_shards);
        let mut shard_offsets: Vec<u64> = Vec::with_capacity(total_shards);
        let mut corrupted_indices: Vec<usize> = Vec::new();
        let mut first_shard_size = 0u32;

        // Read all shards
        for shard_idx in 0..total_shards {
            let shard_header_offset = offset;

            let header_bytes = match volume_reader.read_raw(offset, ShardHeader::SIZE) {
                Ok(bytes) if bytes.len() == ShardHeader::SIZE => bytes,
                _ => break,
            };

            let shard_header = match ShardHeader::from_bytes(&header_bytes) {
                Some(h) => h,
                None => {
                    debug!(
                        "Invalid shard header at block {}, shard {}",
                        block_index, shard_idx
                    );
                    corrupted_indices.push(shard_idx);
                    break;
                }
            };
            let shard_len = shard_header.length as usize;

            if first_shard_size == 0 {
                first_shard_size = shard_header.length;
            }

            shard_offsets.push(shard_header_offset);

            // Read shard data
            match volume_reader.read_raw(offset + ShardHeader::SIZE as u64, shard_len) {
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

            offset += ShardHeader::SIZE as u64 + shard_len as u64;
        }

        stats.blocks_scanned += 1;

        // If we have corrupted shards, try to repair
        if !corrupted_indices.is_empty() {
            stats.blocks_with_corruption += 1;

            let min_shards = erasure_config.data_shards as usize;
            if shards.len() < min_shards {
                // Too many shards lost
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
                // We can recover! Use RS to get the original data
                let erasure_info = ErasureBlockInfo {
                    data_shards: erasure_config.data_shards,
                    parity_shards: erasure_config.parity_shards,
                    shard_size: first_shard_size,
                    original_len,
                };

                let block_id = BlockId::new(block_index as u64);

                // Decode to get original data
                match erasure_unpacker.decode_and_extract_all(
                    shards.clone(),
                    &erasure_info,
                    block_id,
                ) {
                    Ok(_chunks) => {
                        // Successfully decoded! Now re-encode to get repaired shards
                        // Note: We need access to the packer to re-encode
                        // For now, we'll use a simpler approach: reconstruct shards from RS

                        let repaired = repair_shards_rs(
                            &shards,
                            &corrupted_indices,
                            &erasure_config,
                            first_shard_size as usize,
                            original_len,
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
                                let msg = format!(
                                    "Block {}: RS reconstruction failed: {}",
                                    block_index, e
                                );
                                warn!("{}", msg);
                                stats.errors.push(msg);
                            }
                        }
                    }
                    Err(e) => {
                        stats.unrecoverable_blocks += 1;
                        let msg = format!("Block {}: decode failed: {}", block_index, e);
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
    config: &ErasureCodeConfig,
    _shard_size: usize,
    original_len: u32,
) -> Result<Vec<(usize, Bytes)>> {
    let total_shards = config.data_shards as usize + config.parity_shards as usize;

    // Create erasure coder
    let erasure_config =
        ErasureConfig::new(config.data_shards as usize, config.parity_shards as usize)?;
    let coder = ErasureCoder::new(erasure_config)?;

    // Build shard array with None for missing shards
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; total_shards];
    for (idx, data) in available_shards {
        shards[*idx] = Some(data.to_vec());
    }

    // For reconstruction, we need to first decode the original data,
    // then re-encode to get all shards including the corrupted ones.
    // Use the exact original length from the block header for accurate reconstruction.

    // Decode to get original data using the exact original length
    let original_data = coder.decode(&shards, original_len as usize)?;

    // Re-encode to get all shards
    let mut all_shards = coder.encode(&original_data)?;

    // Collect repaired shards for corrupted indices
    let mut repaired = Vec::new();
    for &idx in corrupted_indices {
        if idx < all_shards.len() {
            repaired.push((idx, Bytes::from(std::mem::take(&mut all_shards[idx]))));
        } else {
            return Err(EraError::ErasureError(format!(
                "Shard index {} out of range",
                idx
            )));
        }
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
    let total_volumes = first_reader.header().total_volumes as u16;

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
    let salt = Salt::from_bytes(header.crypto_anchor.salt);
    let kdf_params = KdfParams {
        memory_cost: header.crypto_anchor.kdf_memory_cost,
        time_cost: header.crypto_anchor.kdf_time_cost,
        parallelism: header.crypto_anchor.kdf_parallelism,
    };
    let session = KeySession::new(password.as_bytes(), &salt, &kdf_params)?;

    if !session.verify_password(&header.crypto_anchor.password_verification_tag) {
        return Err(EraError::InvalidKey("Incorrect password".to_string()));
    }

    let volume_key = session.derive_volume_key(0);
    let nonce_context = header.crypto_anchor.salt;
    let compressor: Box<dyn era_codec::Compressor> =
        Box::new(ZstdCompressor::new(header.config.compression.level));
    let erasure_unpacker =
        SessionErasureBlockUnpacker::new(&session, &volume_key, nonce_context, compressor);

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
    let (data_start, data_end) = volume_readers[0].data_region();
    let erasure_data_end = volume_readers[0].footer()
        .map(|f| f.catalog_offset)
        .unwrap_or(data_end);

    // Track offsets for each volume
    let mut volume_offsets: Vec<u64> = volume_readers.iter().map(|r| r.data_region().0).collect();

    let mut block_sequence: u64 = 0;

    // We iterate by scanning volume 0 for block headers (original_len markers)
    let mut primary_offset = data_start;

    while primary_offset < erasure_data_end {
        // Read block header from primary volume
        let header_bytes = match volume_readers[0].read_raw(primary_offset, 4) {
            Ok(bytes) if bytes.len() == 4 => bytes,
            _ => break,
        };
        let original_len = u32::from_le_bytes([
            header_bytes[0],
            header_bytes[1],
            header_bytes[2],
            header_bytes[3],
        ]);

        // Collect shards from all volumes for this block
        let mut shards: Vec<(usize, Bytes)> = Vec::with_capacity(total_shards);
        let mut shard_locations: Vec<(usize, usize, u64)> = Vec::new(); // (shard_idx, vol_idx, offset)
        let mut corrupted_indices: Vec<usize> = Vec::new();
        let mut first_shard_size = 0u32;

        for shard_idx in 0..total_shards {
            // Calculate which volume this shard is on using matrix distribution
            let vol_idx = (shard_idx + block_sequence as usize) % volume_count;

            // For shard 0 of this volume in this block, we already read the header
            // For other shards, we need to track their positions
            let shard_offset = if shard_idx == 0 {
                primary_offset + 4 // Skip the 4-byte original_len header
            } else {
                volume_offsets[vol_idx]
            };

            let shard_header_offset = shard_offset;

            // Read shard header
            let header_bytes =
                match volume_readers[vol_idx].read_raw(shard_offset, ShardHeader::SIZE) {
                    Ok(bytes) if bytes.len() == ShardHeader::SIZE => bytes,
                    _ => {
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
            if first_shard_size == 0 {
                first_shard_size = shard_header.length;
            }

            // Read shard data
            match volume_readers[vol_idx]
                .read_raw(shard_offset + ShardHeader::SIZE as u64, shard_len)
            {
                Ok(shard_data) => {
                    if shard_header.verify(&shard_data) {
                        shards.push((shard_idx, shard_data));
                        shard_locations.push((shard_idx, vol_idx, shard_header_offset));
                    } else {
                        debug!(
                            "Block {}: shard {} CRC mismatch on volume {}",
                            block_sequence, shard_idx, vol_idx
                        );
                        corrupted_indices.push(shard_idx);
                        shard_locations.push((shard_idx, vol_idx, shard_header_offset));
                        stats.corrupted_shards_found += 1;
                    }
                }
                Err(_) => {
                    corrupted_indices.push(shard_idx);
                    stats.corrupted_shards_found += 1;
                }
            }

            // Update volume offset for next shard from this volume
            volume_offsets[vol_idx] = shard_offset + ShardHeader::SIZE as u64 + shard_len as u64;
        }

        // Update primary offset (volume 0)
        primary_offset = volume_offsets[0];

        stats.blocks_scanned += 1;

        // Attempt repair if needed
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
                // Attempt RS repair
                let erasure_info = ErasureBlockInfo {
                    data_shards: erasure_config.data_shards,
                    parity_shards: erasure_config.parity_shards,
                    shard_size: first_shard_size,
                    original_len,
                };

                let block_id = BlockId::new(block_sequence);

                match erasure_unpacker.decode_and_extract_all(
                    shards.clone(),
                    &erasure_info,
                    block_id,
                ) {
                    Ok(_) => {
                        // Decode successful, now reconstruct corrupted shards
                        match repair_shards_rs(
                            &shards,
                            &corrupted_indices,
                            &erasure_config,
                            first_shard_size as usize,
                            original_len,
                        ) {
                            Ok(repaired_shards) => {
                                for (shard_idx, shard_data) in repaired_shards {
                                    // Find the location for this shard
                                    if let Some(&(_, vol_idx, offset)) =
                                        shard_locations.iter().find(|(idx, _, _)| *idx == shard_idx)
                                    {
                                        all_repairs.entry(vol_idx).or_default().push(ShardRepair {
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
                                let msg = format!(
                                    "Block {}: RS reconstruction failed: {}",
                                    block_sequence, e
                                );
                                warn!("{}", msg);
                                stats.errors.push(msg);
                            }
                        }
                    }
                    Err(e) => {
                        stats.unrecoverable_blocks += 1;
                        let msg = format!("Block {}: decode failed: {}", block_sequence, e);
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
