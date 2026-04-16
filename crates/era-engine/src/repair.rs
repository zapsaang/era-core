//! Archive repair functionality using Reed-Solomon erasure coding.
//!
//! This module provides the ability to repair damaged ERA archives
//! by using RS decoding to reconstruct corrupted shards.
//!
//! ## Security
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

use crate::reader::{ArchiveHealthStatus, ArchiveReader};
use bytes::Bytes;
use era_codec::{ErasureCoder, ErasureConfig, ZstdCompressor};
use era_common::{compute_shard_crc, EraError, ErasureCodeConfig, Result, ShardHeader};
use era_crypto::KeySession;
use era_storage::LocalStorageBackend;
use era_volume::{DistributionCalculator, VolumeReader};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tracing::{debug, info, warn};

const MAX_SHARD_SIZE: u64 = 256 * 1024 * 1024;

fn cancellation_error(context: &str) -> EraError {
    EraError::Other(format!("Operation cancelled during {context}"))
}

fn check_cancelled(cancel_flag: &Arc<AtomicBool>, context: &str) -> Result<()> {
    if cancel_flag.load(Ordering::Relaxed) {
        return Err(cancellation_error(context));
    }
    Ok(())
}

fn classify_repair_archive_health(
    expected_volumes: usize,
    found_volumes: usize,
    missing_indices: Vec<usize>,
    unrecoverable_blocks: u64,
    minimum_required_volumes: usize,
) -> ArchiveHealthStatus {
    if found_volumes < minimum_required_volumes {
        return ArchiveHealthStatus::Incomplete {
            expected_volumes,
            found_volumes,
            missing_indices,
            reason: format!(
                "only {} volume(s) found; need at least {} for full logical verification/repair",
                found_volumes, minimum_required_volumes
            ),
        };
    }

    if unrecoverable_blocks > 0 {
        return ArchiveHealthStatus::Incomplete {
            expected_volumes,
            found_volumes,
            missing_indices,
            reason: format!(
                "{} unrecoverable block(s) prevent full logical verification/repair",
                unrecoverable_blocks
            ),
        };
    }

    if !missing_indices.is_empty() {
        return ArchiveHealthStatus::Degraded {
            expected_volumes,
            found_volumes,
            missing_indices,
        };
    }

    ArchiveHealthStatus::Healthy
}

#[cfg(test)]
mod cancel_test_hook {
    use std::sync::{mpsc, Mutex, OnceLock};

    pub(super) struct Hook {
        pub entered_tx: mpsc::Sender<()>,
        pub proceed_rx: mpsc::Receiver<()>,
    }

    static HOOK: OnceLock<Mutex<Option<Hook>>> = OnceLock::new();

    pub(super) fn install(hook: Hook) {
        let lock = HOOK.get_or_init(|| Mutex::new(None));
        *lock.lock().expect("hook mutex poisoned") = Some(hook);
    }

    pub(super) fn clear() {
        if let Some(lock) = HOOK.get() {
            *lock.lock().expect("hook mutex poisoned") = None;
        }
    }

    pub(super) fn checkpoint() {
        if let Some(lock) = HOOK.get() {
            let guard = lock.lock().expect("hook mutex poisoned");
            if let Some(hook) = guard.as_ref() {
                let _ = hook.entered_tx.send(());
                let _ = hook.proceed_rx.recv();
            }
        }
    }
}

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
    pub archive_health: ArchiveHealthStatus,
}

async fn preflight_metadata_recovery(path: &Path, password: &str) -> Result<()> {
    let mut reader = ArchiveReader::open(path, password).await?;
    reader.preflight_metadata_recovery().await
}

/// Helper to read and verify a single shard at the given offset
/// Returns (shard_data, shard_header, corrupted) or an error if I/O fails
#[allow(dead_code)]
async fn read_and_verify_shard(
    reader: &VolumeReader<era_storage::LocalStorageReader>,
    offset: u64,
    header_prefix_len: usize,
) -> Result<Option<(Bytes, ShardHeader, bool)>> {
    let _prefix_bytes = match reader.read_raw(offset, header_prefix_len).await {
        Ok(bytes) if bytes.len() == header_prefix_len => bytes,
        _ => return Ok(None),
    };

    let header_bytes = match reader
        .read_raw(offset + header_prefix_len as u64, ShardHeader::SIZE)
        .await
    {
        Ok(bytes) if bytes.len() == ShardHeader::SIZE => bytes,
        _ => return Ok(None),
    };

    let shard_header = match ShardHeader::from_bytes(&header_bytes) {
        Some(h) => h,
        None => {
            return Ok(None);
        }
    };

    if shard_header.length as u64 > MAX_SHARD_SIZE {
        return Err(EraError::ErasureError(format!(
            "Shard length {} exceeds maximum allowed size {}",
            shard_header.length, MAX_SHARD_SIZE
        )));
    }

    let shard_len = shard_header.length as usize;
    let shard_data = match reader
        .read_raw(
            offset + header_prefix_len as u64 + ShardHeader::SIZE as u64,
            shard_len,
        )
        .await
    {
        Ok(data) => data,
        Err(_) => {
            return Ok(None);
        }
    };

    let is_corrupted = !shard_header.verify(&shard_data);
    Ok(Some((shard_data, shard_header, is_corrupted)))
}

impl RepairStats {
    pub fn is_healthy(&self) -> bool {
        self.archive_health.is_healthy()
    }

    pub fn is_degraded(&self) -> bool {
        self.archive_health.is_degraded()
    }

    pub fn is_incomplete(&self) -> bool {
        self.archive_health.is_incomplete()
    }

    /// Check if all corrupted shards were repaired
    pub fn fully_repaired(&self) -> bool {
        self.is_healthy()
            && self.unrecoverable_blocks == 0
            && self.corrupted_shards_found == self.shards_repaired
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
pub async fn repair_archive(
    path: &Path,
    password: &str,
    options: RepairOptions,
) -> Result<RepairStats> {
    let cancel_flag = Arc::new(AtomicBool::new(false));
    info!("Starting archive repair: {}", path.display());

    // Open archive for reading first
    let parent_dir = path.parent().unwrap_or(Path::new("."));
    let backend = LocalStorageBackend::new(parent_dir);
    let volume_path = path.file_name().unwrap_or_default();

    let volume_reader = VolumeReader::open(&backend, Path::new(volume_path)).await?;

    // Verify erasure coding is enabled
    let header = volume_reader.header();
    let erasure_config = header.config().erasure.ok_or_else(|| {
        EraError::ErasureError("Archive does not use erasure coding - repair not available".into())
    })?;

    // If the archive is multi-volume, use matrix-aware repair
    if header.total_volumes() > 1 {
        return Box::pin(repair_archive_matrix(path, password, options)).await;
    }

    info!(
        "Erasure config: {}/{} data/parity shards",
        erasure_config.data_shards, erasure_config.parity_shards
    );

    // Create key session using PasswordProvider
    // Requires crate::auth::AuthProvider and crate::auth::PasswordProvider
    let provider = crate::auth::PasswordProvider::new(password.to_string());

    let mut master_key = None;
    for slot in header.recipients() {
        use crate::auth::AuthProvider;
        if let Ok(Some(mk)) = provider.try_unlock(slot) {
            master_key = Some(mk);
            break;
        }
    }

    let master_key = master_key.ok_or(EraError::InvalidKey("Incorrect password".into()))?;
    let mk_array: [u8; 32] = master_key.try_into().map_err(|e: Vec<u8>| {
        EraError::InvalidKey(format!(
            "Invalid master key length: expected 32, got {}",
            e.len()
        ))
    })?;
    let _session = KeySession::from_master_key(&mk_array)?;

    // Metadata-first preflight: restore embedded LSM and catalog before repair
    preflight_metadata_recovery(path, password).await?;

    // Create compressor (kept for future decode-based validation if needed)
    let _compressor: Box<dyn era_codec::Compressor> =
        Box::new(ZstdCompressor::new(header.config().compression.level));

    // Create backup if requested
    if options.create_backup && !options.dry_run {
        let backup_path = path.with_extension("era.bak");
        if !backup_path.exists() {
            info!("Creating backup: {}", backup_path.display());
            check_cancelled(&cancel_flag, "repair backup copy")?;
            // Wrap fs::copy in spawn_blocking since it's I/O-heavy (V2-QUAL-07)
            let path_clone = path.to_path_buf();
            let backup_path_clone = backup_path.clone();
            tokio::task::spawn_blocking(move || std::fs::copy(&path_clone, &backup_path_clone))
                .await
                .map_err(|e| EraError::Other(format!("Backup task failed: {e}")))??;
            check_cancelled(&cancel_flag, "repair backup copy")?;
        } else {
            info!("Backup already exists: {}", backup_path.display());
        }
    }

    // Scan for corrupted blocks and repair
    let mut stats = RepairStats::default();
    let total_shards = erasure_config.data_shards as usize + erasure_config.parity_shards as usize;

    let (data_start, _) = volume_reader.data_region();
    let erasure_data_end = crate::erasure_scan::erasure_data_end(&volume_reader);

    let mut offset = data_start;
    let mut block_index = 0u32;
    let header_prefix_len = erasure_config.data_shards as usize * 4;

    // Collect repair operations first (to do them in a batch)
    let mut repairs: Vec<ShardRepair> = Vec::new();

    'stripe_loop: while offset < erasure_data_end {
        let mut shards: Vec<(usize, Bytes)> = Vec::with_capacity(total_shards);
        let mut shard_offsets: Vec<Option<u64>> = vec![None; total_shards];
        let mut corrupted_indices: Vec<usize> = Vec::new();
        let mut data_lengths: Vec<Option<u32>> = vec![None; erasure_config.data_shards as usize];
        let mut max_len: usize = 0;

        // Pre-pass: collect all readable prefix copies for multi-copy reconciliation.
        // We use header lengths for navigation so a corrupted prefix cannot cause drift.
        let mut prefix_copies: Vec<Bytes> = Vec::with_capacity(total_shards);
        let mut temp_offset = offset;
        for _ in 0..total_shards {
            if temp_offset >= erasure_data_end {
                break;
            }
            let prefix_bytes = match volume_reader.read_raw(temp_offset, header_prefix_len).await {
                Ok(bytes) if bytes.len() == header_prefix_len => bytes,
                _ => break,
            };
            let header_bytes = match volume_reader
                .read_raw(temp_offset + header_prefix_len as u64, ShardHeader::SIZE)
                .await
            {
                Ok(bytes) if bytes.len() == ShardHeader::SIZE => bytes,
                _ => break,
            };
            let shard_header = ShardHeader::from_bytes(&header_bytes);
            let shard_len = shard_header.map_or(0, |h| h.length as usize);
            prefix_copies.push(prefix_bytes);
            temp_offset += header_prefix_len as u64 + ShardHeader::SIZE as u64 + shard_len as u64;
        }
        let stripe_lengths = crate::erasure_scan::reconcile_stripe_prefixes(
            &prefix_copies,
            erasure_config.data_shards as usize,
        );

        for shard_idx in 0..total_shards {
            let shard_header_offset = offset + header_prefix_len as u64;

            let _prefix_bytes = match volume_reader.read_raw(offset, header_prefix_len).await {
                Ok(bytes) if bytes.len() == header_prefix_len => bytes,
                _ => {
                    break 'stripe_loop;
                }
            };

            // Determine authoritative shard length from reconciled stripe prefix for data shards
            let is_data_shard = shard_idx < erasure_config.data_shards as usize;
            let authoritative_len: Option<u32> = if is_data_shard {
                stripe_lengths
                    .as_ref()
                    .and_then(|sl| sl.get(shard_idx).copied())
            } else {
                None
            };

            let header_bytes = match volume_reader
                .read_raw(offset + header_prefix_len as u64, ShardHeader::SIZE)
                .await
            {
                Ok(bytes) if bytes.len() == ShardHeader::SIZE => bytes,
                _ => {
                    break 'stripe_loop;
                }
            };

            let shard_header = ShardHeader::from_bytes(&header_bytes);

            // Compute the shard length to use for reading and offset advancement
            let shard_len: usize = if let Some(auth_len) = authoritative_len {
                // Data shard: stripe prefix is authoritative
                if auth_len as u64 > MAX_SHARD_SIZE {
                    return Err(EraError::ErasureError(format!(
                        "Stripe prefix length {} exceeds maximum allowed size {}",
                        auth_len, MAX_SHARD_SIZE
                    )));
                }
                auth_len as usize
            } else if let Some(ref h) = shard_header {
                // Parity shard: use header length, sanity-bounded by max stripe length
                if h.length as u64 > MAX_SHARD_SIZE {
                    return Err(EraError::ErasureError(format!(
                        "Shard length {} exceeds maximum allowed size {}",
                        h.length, MAX_SHARD_SIZE
                    )));
                }
                let parity_bound =
                    crate::erasure_scan::parity_bound_from_lengths(stripe_lengths.as_deref())
                        .unwrap_or(0);
                // Harden against corrupted but in-range parity length that is too small.
                // A valid parity shard should match the padded max stripe size.
                if parity_bound > 0 && h.length < parity_bound {
                    corrupted_indices.push(shard_idx);
                    stats.corrupted_shards_found += 1;
                    shard_offsets[shard_idx] = Some(shard_header_offset);
                    offset +=
                        header_prefix_len as u64 + ShardHeader::SIZE as u64 + parity_bound as u64;
                    continue;
                }
                if parity_bound > 0 && h.length > parity_bound {
                    parity_bound as usize
                } else {
                    h.length as usize
                }
            } else {
                // No header and no authoritative length (parity with corrupt header):
                // use padded max stripe length as best estimate
                let parity_estimate =
                    crate::erasure_scan::parity_bound_from_lengths(stripe_lengths.as_deref())
                        .unwrap_or(0);
                if parity_estimate == 0 {
                    break 'stripe_loop;
                }
                parity_estimate as usize
            };

            if shard_header.is_none() {
                debug!(
                    "Invalid shard header at block {}, shard {}",
                    block_index, shard_idx
                );
                corrupted_indices.push(shard_idx);
                stats.corrupted_shards_found += 1;
                // Advance offset even with corrupt header
                offset += header_prefix_len as u64 + ShardHeader::SIZE as u64 + shard_len as u64;
                continue;
            }
            let shard_header = shard_header.unwrap();

            shard_offsets[shard_idx] = Some(shard_header_offset);

            if is_data_shard {
                data_lengths[shard_idx] = authoritative_len.or(Some(shard_header.length));
            }

            if shard_len > max_len {
                max_len = shard_len;
            }

            match volume_reader
                .read_raw(
                    offset + header_prefix_len as u64 + ShardHeader::SIZE as u64,
                    shard_len,
                )
                .await
            {
                Ok(shard_data) => {
                    // When using authoritative prefix length for data shards,
                    // bypass ShardHeader.verify (which checks data.len() == header.length)
                    // since the header length field may be corrupted
                    let crc_valid = if authoritative_len.is_some() {
                        compute_shard_crc(&shard_data) == shard_header.crc
                    } else {
                        shard_header.verify(&shard_data)
                    };
                    if crc_valid {
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

        crate::erasure_scan::normalize_data_lengths(
            &mut data_lengths,
            stripe_lengths.as_deref(),
            &mut max_len,
        );

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
                let shard_size = crate::erasure_scan::even_aligned_shard_size(max_len);

                let repaired = repair_shards_rs(
                    &shards,
                    &corrupted_indices,
                    &data_lengths,
                    &erasure_config,
                    shard_size,
                    Arc::clone(&cancel_flag),
                )
                .await;

                match repaired {
                    Ok(repaired_shards) => {
                        for (shard_idx, shard_data) in repaired_shards {
                            let shard_offset = shard_offsets.get(shard_idx).and_then(|v| *v);
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

    let expected_volumes = usize::from(header.total_volumes().max(1));
    stats.archive_health = classify_repair_archive_health(
        expected_volumes,
        1,
        Vec::new(),
        stats.unrecoverable_blocks,
        1,
    );

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
async fn repair_shards_rs(
    available_shards: &[(usize, Bytes)],
    corrupted_indices: &[usize],
    data_lengths: &[Option<u32>],
    config: &ErasureCodeConfig,
    shard_size: usize,
    cancel_flag: Arc<AtomicBool>,
) -> Result<Vec<(usize, Bytes)>> {
    check_cancelled(&cancel_flag, "Reed-Solomon shard reconstruction")?;
    let data_shards = config.data_shards as usize;
    let parity_shards = config.parity_shards as usize;
    let total_shards = data_shards + parity_shards;

    let erasure_config = ErasureConfig::new(data_shards, parity_shards)?;

    // Prepare data for spawn_blocking
    let available_shards_vec: Vec<(usize, Vec<u8>)> = available_shards
        .iter()
        .map(|(idx, data)| (*idx, data.to_vec()))
        .collect();
    let corrupted_indices_vec = corrupted_indices.to_vec();
    let data_lengths_vec = data_lengths.to_vec();
    let cancel_flag_clone = Arc::clone(&cancel_flag);

    // Wrap CPU-heavy RS reconstruction in spawn_blocking (V2-PERF-02)
    let result = tokio::task::spawn_blocking(move || {
        if cancel_flag_clone.load(Ordering::Relaxed) {
            return Err(cancellation_error("Reed-Solomon shard reconstruction"));
        }

        #[cfg(test)]
        cancel_test_hook::checkpoint();

        if cancel_flag_clone.load(Ordering::Relaxed) {
            return Err(cancellation_error("Reed-Solomon shard reconstruction"));
        }

        let coder = ErasureCoder::new(erasure_config)?;

        let mut shards: Vec<Option<Vec<u8>>> = vec![None; total_shards];
        for (idx, data) in &available_shards_vec {
            if cancel_flag_clone.load(Ordering::Relaxed) {
                return Err(cancellation_error("Reed-Solomon shard reconstruction"));
            }
            shards[*idx] = Some(data.clone());
        }

        // Recover all data shards (padded)
        let recovered_data = coder.recover_data_shards(&shards, shard_size)?;

        if cancel_flag_clone.load(Ordering::Relaxed) {
            return Err(cancellation_error("Reed-Solomon shard reconstruction"));
        }

        // Re-encode to get parity shards
        let all_shards = coder.encode_shards(&recovered_data)?;

        let mut repaired = Vec::new();
        for &idx in &corrupted_indices_vec {
            if cancel_flag_clone.load(Ordering::Relaxed) {
                return Err(cancellation_error("Reed-Solomon shard reconstruction"));
            }
            if idx >= total_shards {
                return Err(EraError::ErasureError(format!(
                    "Shard index {} out of range",
                    idx
                )));
            }

            let mut data = all_shards[idx].clone();
            if idx < data_shards {
                let original_len = data_lengths_vec.get(idx).and_then(|v| *v).ok_or_else(|| {
                    EraError::ErasureError("Missing original length for data shard".into())
                })? as usize;
                data.truncate(original_len);
            }

            repaired.push((idx, Bytes::from(data)));
        }

        Ok(repaired)
    })
    .await
    .map_err(|e| EraError::AsyncError(e.to_string()))?;

    result
}

/// Apply shard repairs to the archive file
fn apply_repairs(path: &Path, repairs: &[ShardRepair]) -> Result<()> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;

    for repair in repairs {
        // Write new shard header with CRC
        let crc = compute_shard_crc(&repair.data);
        let header = ShardHeader::new(repair.data.len() as u32, crc);

        // Write shard data first, then flush, then write header
        // This ensures a crash between writes leaves the header unwritten (detectable)
        // rather than pointing to garbage data (V2-SEC-06 fix)
        let header_bytes = header.to_bytes();
        let data_offset = repair.offset + header_bytes.len() as u64;

        file.seek(SeekFrom::Start(data_offset))?;
        file.write_all(&repair.data)?;
        file.flush()?;

        // Now write the header (which points to the data we just wrote)
        file.seek(SeekFrom::Start(repair.offset))?;
        file.write_all(&header_bytes)?;

        // V2-ROB-10: Post-write CRC validation - re-read and verify written data
        file.flush()?;
        file.seek(SeekFrom::Start(data_offset))?;

        let mut read_buffer = vec![0u8; repair.data.len()];
        file.read_exact(&mut read_buffer)?;

        let read_crc = compute_shard_crc(&Bytes::from(read_buffer.clone()));
        if read_crc != crc {
            return Err(EraError::IntegrityError(format!(
                "Post-write CRC verification failed for repaired shard {} (expected {}, got {})",
                repair.shard_idx, crc, read_crc
            )));
        }

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
pub async fn repair_archive_matrix(
    path: &Path,
    password: &str,
    options: RepairOptions,
) -> Result<RepairStats> {
    let cancel_flag = Arc::new(AtomicBool::new(false));
    info!(
        "Starting matrix-distributed archive repair: {}",
        path.display()
    );

    // Metadata-first preflight: restore embedded LSM and catalog before repair
    preflight_metadata_recovery(path, password).await?;

    let parent_dir = path.parent().unwrap_or(Path::new("."));
    let backend = LocalStorageBackend::new(parent_dir);

    // Collect all volumes
    let mut volume_readers: Vec<VolumeReader<era_storage::LocalStorageReader>> = Vec::new();
    let mut volume_paths: Vec<PathBuf> = Vec::new();
    let mut volume_sequences: Vec<u16> = Vec::new();

    // Open first volume
    let volume_filename = path.file_name().unwrap_or_default();
    let first_reader = VolumeReader::open(&backend, Path::new(volume_filename)).await?;
    let archive_id = first_reader.header().archive_id();
    let header = first_reader.header().clone();
    let total_volumes = first_reader.header().total_volumes();
    let first_sequence = first_reader.header().volume_sequence();

    let base_name = {
        let base_str = volume_filename.to_string_lossy();
        if base_str.ends_with(".era") {
            base_str.to_string()
        } else {
            let owned = base_str.to_string();
            if let Some(idx) = owned.rfind(".era.") {
                owned[..idx + 4].to_string()
            } else {
                owned
            }
        }
    };

    volume_sequences.push(first_sequence);
    volume_paths.push(path.to_path_buf());
    volume_readers.push(first_reader);

    // Find additional volumes - continue even if some are missing
    let mut consecutive_missing = 0;
    let max_gap = 5; // Allow up to 5 consecutive missing volumes before giving up

    for seq in 0..usize::from(total_volumes.max(100)) {
        if seq == usize::from(first_sequence) {
            continue;
        }

        let relative_path = if seq == 0 {
            PathBuf::from(&base_name)
        } else {
            PathBuf::from(format!("{base_name}.{seq:03}"))
        };
        let next_path = parent_dir.join(&relative_path);
        let next_filename = relative_path.file_name().unwrap_or_default();

        match VolumeReader::open(&backend, Path::new(next_filename)).await {
            Ok(reader) => {
                if reader.header().archive_id() != archive_id {
                    break;
                }
                let discovered_seq = reader.header().volume_sequence();
                volume_sequences.push(discovered_seq);
                volume_paths.push(next_path);
                volume_readers.push(reader);
                consecutive_missing = 0;
            }
            Err(_) => {
                consecutive_missing += 1;
                if consecutive_missing > max_gap && seq >= usize::from(total_volumes) {
                    break;
                }
            }
        }
    }

    let volume_count = volume_readers.len();
    let expected_volumes = usize::from(total_volumes.max(1));
    let missing_volume_indices: Vec<usize> = (0..expected_volumes)
        .filter(|idx| !volume_sequences.iter().any(|seq| usize::from(*seq) == *idx))
        .collect();
    info!(
        "Found {} volumes for matrix-distributed archive (expected {})",
        volume_count, total_volumes
    );

    if !missing_volume_indices.is_empty() {
        warn!(
            "Matrix repair opened {} of {} expected volumes; missing sequences {:?}",
            volume_count, expected_volumes, missing_volume_indices
        );
    }

    if volume_count < 2 {
        return Err(EraError::ErasureError(
            "Matrix-distributed archive has insufficient surviving volumes for repair".into(),
        ));
    }

    // Verify erasure coding is enabled
    let erasure_config = header
        .config()
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
    for slot in header.recipients() {
        use crate::auth::AuthProvider;
        if let Ok(Some(mk)) = provider.try_unlock(slot) {
            master_key = Some(mk);
            break;
        }
    }

    let master_key = master_key.ok_or(EraError::InvalidKey("Incorrect password".into()))?;
    let mk_array: [u8; 32] = master_key.try_into().map_err(|e: Vec<u8>| {
        EraError::InvalidKey(format!(
            "Invalid master key length: expected 32, got {}",
            e.len()
        ))
    })?;
    let _session = KeySession::from_master_key(&mk_array)?;

    let _compressor: Box<dyn era_codec::Compressor> =
        Box::new(ZstdCompressor::new(header.config().compression.level));

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
                check_cancelled(&cancel_flag, "matrix repair backup copy")?;
                // Wrap fs::copy in spawn_blocking since it's I/O-heavy (V2-QUAL-07)
                let vol_path_clone = vol_path.to_path_buf();
                let backup_path_clone = backup_path.clone();
                tokio::task::spawn_blocking(move || {
                    std::fs::copy(&vol_path_clone, &backup_path_clone)
                })
                .await
                .map_err(|e| EraError::Other(format!("Backup task failed: {e}")))??;
                check_cancelled(&cancel_flag, "matrix repair backup copy")?;
            }
        }
    }

    let mut stats = RepairStats {
        archive_health: classify_repair_archive_health(
            expected_volumes,
            volume_count,
            missing_volume_indices.clone(),
            0,
            erasure_config.data_shards as usize,
        ),
        ..Default::default()
    };
    let mut all_repairs: HashMap<usize, Vec<ShardRepair>> = HashMap::new(); // volume_idx -> repairs

    // Scan blocks using matrix distribution pattern
    // We need to iterate through block sequences and collect shards from each volume
    // Track offsets for each volume
    let mut volume_offsets: Vec<u64> = volume_readers.iter().map(|r| r.data_region().0).collect();

    let mut block_sequence: u64 = 0;
    let distribution_strategy = header.config().distribution.strategy;
    let total_volumes = header.total_volumes() as usize;

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
        .map(crate::erasure_scan::erasure_data_end)
        .collect();

    let header_prefix_len = erasure_config.data_shards as usize * 4;

    'stripe_loop: loop {
        let mut shards: Vec<(usize, Bytes)> = Vec::with_capacity(total_shards);
        let mut shard_locations: Vec<(usize, usize, u64)> = Vec::new(); // (shard_idx, reader_idx, offset)
        let mut corrupted_indices: Vec<usize> = Vec::new();
        let mut data_lengths: Vec<Option<u32>> = vec![None; erasure_config.data_shards as usize];
        let mut max_len: usize = 0;
        let mut any_shard_read = false;

        // Pre-pass: collect all readable prefix copies for multi-copy reconciliation.
        // We use header lengths for navigation so a corrupted prefix cannot cause drift.
        let mut prefix_copies: Vec<Bytes> = Vec::with_capacity(total_shards);
        let mut temp_offsets: Vec<u64> = volume_offsets.clone();
        for shard_idx in 0..total_shards {
            let vol_idx = distribution_strategy.calculate_volume(
                shard_idx,
                block_sequence,
                total_volumes.max(1),
            )?;
            let reader_idx_opt = vol_index_map.get(vol_idx).copied().flatten();
            if let Some(reader_idx) = reader_idx_opt {
                let reader = &volume_readers[reader_idx];
                let shard_offset = temp_offsets[reader_idx];
                if shard_offset >= data_ends[reader_idx] {
                    continue;
                }
                let prefix_bytes = match reader.read_raw(shard_offset, header_prefix_len).await {
                    Ok(bytes) if bytes.len() == header_prefix_len => bytes,
                    _ => continue,
                };
                let header_bytes = match reader
                    .read_raw(shard_offset + header_prefix_len as u64, ShardHeader::SIZE)
                    .await
                {
                    Ok(bytes) if bytes.len() == ShardHeader::SIZE => bytes,
                    _ => continue,
                };
                let shard_header = ShardHeader::from_bytes(&header_bytes);
                let shard_len = shard_header.map_or(0, |h| h.length as usize);
                prefix_copies.push(prefix_bytes);
                temp_offsets[reader_idx] = shard_offset
                    + header_prefix_len as u64
                    + ShardHeader::SIZE as u64
                    + shard_len as u64;
            }
        }
        let stripe_lengths = crate::erasure_scan::reconcile_stripe_prefixes(
            &prefix_copies,
            erasure_config.data_shards as usize,
        );

        // Scan all shards across volumes using matrix distribution
        for shard_idx in 0..total_shards {
            let vol_idx = distribution_strategy.calculate_volume(
                shard_idx,
                block_sequence,
                total_volumes.max(1),
            )?;

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

                let _prefix_bytes = match reader.read_raw(shard_offset, header_prefix_len).await {
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

                // Determine authoritative shard length from reconciled stripe prefix for data shards
                let is_data_shard = shard_idx < erasure_config.data_shards as usize;
                let authoritative_len: Option<u32> = if is_data_shard {
                    stripe_lengths
                        .as_ref()
                        .and_then(|sl| sl.get(shard_idx).copied())
                } else {
                    None
                };

                let header_bytes = match reader
                    .read_raw(shard_offset + header_prefix_len as u64, ShardHeader::SIZE)
                    .await
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

                let shard_header = ShardHeader::from_bytes(&header_bytes);

                // Compute the shard length to use for reading and offset advancement
                let shard_len: usize = if let Some(auth_len) = authoritative_len {
                    // Data shard: stripe prefix is authoritative
                    if auth_len as u64 > MAX_SHARD_SIZE {
                        return Err(EraError::ErasureError(format!(
                            "Stripe prefix length {} exceeds maximum allowed size {}",
                            auth_len, MAX_SHARD_SIZE
                        )));
                    }
                    auth_len as usize
                } else if let Some(ref h) = shard_header {
                    // Parity shard: use header length, sanity-bounded by max stripe length
                    if h.length as u64 > MAX_SHARD_SIZE {
                        return Err(EraError::ErasureError(format!(
                            "Shard length {} exceeds maximum allowed size {}",
                            h.length, MAX_SHARD_SIZE
                        )));
                    }
                    let parity_bound =
                        crate::erasure_scan::parity_bound_from_lengths(stripe_lengths.as_deref())
                            .unwrap_or(0);
                    // Harden against corrupted but in-range parity length that is too small.
                    // A valid parity shard should match the padded max stripe size.
                    if parity_bound > 0 && h.length < parity_bound {
                        corrupted_indices.push(shard_idx);
                        stats.corrupted_shards_found += 1;
                        shard_locations.push((
                            shard_idx,
                            reader_idx,
                            shard_offset + header_prefix_len as u64,
                        ));
                        volume_offsets[reader_idx] = shard_offset
                            + header_prefix_len as u64
                            + ShardHeader::SIZE as u64
                            + parity_bound as u64;
                        continue;
                    }
                    if parity_bound > 0 && h.length > parity_bound {
                        parity_bound as usize
                    } else {
                        h.length as usize
                    }
                } else {
                    // No header and no authoritative length (parity with corrupt header):
                    // use padded max stripe length as best estimate
                    let parity_estimate =
                        crate::erasure_scan::parity_bound_from_lengths(stripe_lengths.as_deref())
                            .unwrap_or(0);
                    if parity_estimate == 0 {
                        // Cannot determine length — mark corrupted and skip
                        corrupted_indices.push(shard_idx);
                        stats.corrupted_shards_found += 1;
                        continue;
                    }
                    parity_estimate as usize
                };

                if shard_header.is_none() {
                    debug!(
                        "Invalid shard header at block {}, shard {}",
                        block_sequence, shard_idx
                    );
                    corrupted_indices.push(shard_idx);
                    stats.corrupted_shards_found += 1;
                    // Advance offset even with corrupt header
                    volume_offsets[reader_idx] = shard_offset
                        + header_prefix_len as u64
                        + ShardHeader::SIZE as u64
                        + shard_len as u64;
                    continue;
                }
                let shard_header = shard_header.unwrap();

                if is_data_shard {
                    if let Some(slot) = data_lengths.get_mut(shard_idx) {
                        *slot = authoritative_len.or(Some(shard_header.length));
                    }
                }
                if shard_len > max_len {
                    max_len = shard_len;
                }

                any_shard_read = true;
                match reader
                    .read_raw(
                        shard_offset + header_prefix_len as u64 + ShardHeader::SIZE as u64,
                        shard_len,
                    )
                    .await
                {
                    Ok(shard_data) => {
                        // When using authoritative prefix length for data shards,
                        // bypass ShardHeader.verify (which checks data.len() == header.length)
                        // since the header length field may be corrupted
                        let crc_valid = if authoritative_len.is_some() {
                            compute_shard_crc(&shard_data) == shard_header.crc
                        } else {
                            shard_header.verify(&shard_data)
                        };
                        if crc_valid {
                            shards.push((shard_idx, shard_data));
                            shard_locations.push((
                                shard_idx,
                                reader_idx,
                                shard_offset + header_prefix_len as u64,
                            ));
                        } else {
                            corrupted_indices.push(shard_idx);
                            shard_locations.push((
                                shard_idx,
                                reader_idx,
                                shard_offset + header_prefix_len as u64,
                            ));
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

        crate::erasure_scan::normalize_data_lengths(
            &mut data_lengths,
            stripe_lengths.as_deref(),
            &mut max_len,
        );

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
                let shard_size = crate::erasure_scan::even_aligned_shard_size(max_len);

                match repair_shards_rs(
                    &shards,
                    &corrupted_indices,
                    &data_lengths,
                    &erasure_config,
                    shard_size,
                    Arc::clone(&cancel_flag),
                )
                .await
                {
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

    stats.archive_health = classify_repair_archive_health(
        expected_volumes,
        volume_count,
        missing_volume_indices,
        stats.unrecoverable_blocks,
        erasure_config.data_shards as usize,
    );

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
    use std::sync::mpsc;

    #[tokio::test]
    async fn test_repair_shards_rs_respects_cancellation() {
        let cancel_flag = Arc::new(AtomicBool::new(true));
        let result = repair_shards_rs(
            &[],
            &[],
            &[],
            &ErasureCodeConfig::new(2, 1),
            16,
            cancel_flag,
        )
        .await;

        assert!(
            result.is_err(),
            "cancelled repair must return explicit error"
        );
        let msg = result.unwrap_err().to_string().to_lowercase();
        assert!(
            msg.contains("cancel"),
            "expected cancellation error message, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_repair_shards_rs_respects_inflight_cancellation() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (proceed_tx, proceed_rx) = mpsc::channel();
        cancel_test_hook::install(cancel_test_hook::Hook {
            entered_tx,
            proceed_rx,
        });

        let cancel_flag = Arc::new(AtomicBool::new(false));
        let cancel_for_task = Arc::clone(&cancel_flag);
        let task = tokio::spawn(async move {
            repair_shards_rs(
                &[
                    (0, Bytes::from(vec![1u8; 8])),
                    (1, Bytes::from(vec![2u8; 8])),
                ],
                &[2],
                &[Some(8), Some(8)],
                &ErasureCodeConfig::new(2, 1),
                8,
                cancel_for_task,
            )
            .await
        });

        tokio::task::spawn_blocking(move || {
            entered_rx.recv_timeout(std::time::Duration::from_secs(2))
        })
        .await
        .expect("join while waiting for blocking hook")
        .expect("spawn_blocking closure should enter before cancellation");
        cancel_flag.store(true, Ordering::Relaxed);
        proceed_tx
            .send(())
            .expect("should release blocking closure hook");

        let result = task.await.expect("join should succeed");
        cancel_test_hook::clear();

        assert!(
            result.is_err(),
            "in-flight cancelled repair must return explicit error"
        );
        let msg = result.unwrap_err().to_string().to_lowercase();
        assert!(
            msg.contains("cancel"),
            "expected cancellation error message, got: {msg}"
        );
    }

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
