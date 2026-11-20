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

use crate::erasure_scan::{read_matrix_shard_header, MatrixScanGeometry};
use crate::reader::{ArchiveHealthStatus, ArchiveReader, CatalogRepair, DiscoveredVolumes};
use bytes::Bytes;
use era_codec::{ErasureCoder, ErasureConfig, ZstdCompressor};
use era_common::{
    compute_shard_crc, ArchiveManifest, BlockId, BlockLocation, BlockType, EraError,
    ErasureCodeConfig, Result, ShardHeader,
};
use era_crypto::{build_aad, AeadContext, XChaCha20Poly1305Context, NONCE_SIZE};
use era_storage::LocalStorageBackend;
use era_volume::{VolumeReader, DATA_REGION_START, HEADER_SIZE};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tracing::{debug, info, warn};
use zeroize::Zeroize;

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

fn try_unlock_with_providers(
    header: &era_volume::SuperHeader,
    providers: &[Box<dyn crate::auth::AuthProvider>],
) -> Result<[u8; 32]> {
    match header.access_policy() {
        era_volume::AccessPolicy::AnyOfN => {
            let mut master_key = None;
            'outer: for slot in header.recipients() {
                for provider in providers {
                    if let Ok(Some(mk)) = provider.try_unlock(slot) {
                        master_key = Some(mk);
                        break 'outer;
                    }
                }
            }
            let mut mk =
                master_key.ok_or(EraError::InvalidKey("No valid credentials found".into()))?;
            let result: [u8; 32] = mk
                .as_slice()
                .try_into()
                .map_err(|_| EraError::InvalidKey("Invalid master key length".into()))?;
            mk.zeroize();
            Ok(result)
        }
        era_volume::AccessPolicy::Threshold(t) => {
            if t < 2 {
                return Err(EraError::InvalidConfig("Threshold must be >= 2".into()));
            }
            let mut shares = Vec::new();
            for slot in header.recipients() {
                for provider in providers {
                    if let Ok(Some(share)) = provider.try_unlock(slot) {
                        shares.push(share);
                        break;
                    }
                }
            }
            if (shares.len() as u32) < t {
                return Err(EraError::ThresholdNotMet {
                    required: t,
                    provided: shares.len() as u32,
                });
            }
            let result = era_crypto::reconstruct_master_key(&shares, t as u8);
            shares.iter_mut().for_each(|s| s.zeroize());
            result
        }
        _ => Err(EraError::InvalidConfig("Unsupported access policy".into())),
    }
}

#[derive(Clone, Copy)]
enum CommittedDataEnds<'a> {
    Unknown { expected_volumes: usize },
    Authenticated(&'a [u64]),
}

fn minimum_volumes_for_repair(
    erasure_config: ErasureCodeConfig,
    generation_width: usize,
    committed_ends: CommittedDataEnds<'_>,
) -> usize {
    let expected_volumes = match committed_ends {
        CommittedDataEnds::Unknown { expected_volumes } => expected_volumes,
        CommittedDataEnds::Authenticated(ends) => ends.len(),
    };
    let data_shards = usize::from(erasure_config.data_shards);
    if expected_volumes == 0 || data_shards == 0 {
        return data_shards;
    }
    let total_shards = data_shards + usize::from(erasure_config.parity_shards);
    let mut minimum_volumes = 0;
    let mut generation_start = 0;
    while generation_start < expected_volumes {
        let generation_volumes = generation_width.min(expected_volumes - generation_start);
        let generation_end = generation_start + generation_volumes;
        let data_empty = match committed_ends {
            CommittedDataEnds::Unknown { .. } => false,
            CommittedDataEnds::Authenticated(ends) => ends[generation_start..generation_end]
                .iter()
                .all(|&end| end == DATA_REGION_START),
        };
        if !data_empty {
            let max_shards_per_vol = total_shards.div_ceil(generation_volumes).max(1);
            minimum_volumes += data_shards
                .div_ceil(max_shards_per_vol)
                .min(generation_volumes);
        }
        generation_start += generation_width;
    }
    minimum_volumes
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

async fn recovered_header_bytes(
    reader: &VolumeReader<era_storage::LocalStorageReader>,
    archive: &ArchiveReader,
) -> Result<Bytes> {
    let footer = reader.footer().ok_or_else(|| {
        EraError::IntegrityError("Recovered header has no footer provenance".into())
    })?;
    let backup_offset = footer.backup_header_offset();
    if backup_offset < DATA_REGION_START || backup_offset != footer.data_end_offset() {
        return Err(EraError::IntegrityError(
            "Recovered header is outside the finalized backup-header location".into(),
        ));
    }

    let header = reader.header();
    let manifest_offset = footer.manifest_offset();
    if header.archive_id() != archive.header().archive_id()
        || header.epoch_id() != archive.epoch_id()
        || header.total_volumes() != archive.header().total_volumes()
        || header.volume_sequence() >= header.total_volumes()
    {
        return Err(EraError::IntegrityError(
            "Recovered header has no matching on-volume manifest".into(),
        ));
    }
    let backup_bytes = reader.read_raw(backup_offset, HEADER_SIZE).await?;
    let header_digest = if footer.has_manifest() {
        if !(DATA_REGION_START..backup_offset).contains(&manifest_offset) {
            return Err(EraError::IntegrityError(
                "Recovered header manifest is outside the finalized data region".into(),
            ));
        }
        local_header_digest(reader, archive).await?
    } else {
        *archive
            .manifest_header_digest(header.volume_sequence())
            .ok_or_else(|| {
                EraError::IntegrityError(
                    "Recovered header has no authenticated volume digest".into(),
                )
            })?
    };
    if blake3::hash(&backup_bytes).as_bytes() != &header_digest {
        return Err(EraError::IntegrityError(
            "Backup header bytes do not match the authenticated manifest digest".into(),
        ));
    }
    Ok(backup_bytes)
}

async fn local_header_digest(
    reader: &VolumeReader<era_storage::LocalStorageReader>,
    archive: &ArchiveReader,
) -> Result<[u8; 32]> {
    let footer = reader.footer().ok_or_else(|| {
        EraError::IntegrityError("Recovered header has no footer provenance".into())
    })?;
    let header = reader.header();
    let manifest_offset = footer.manifest_offset();
    let block_id = footer.manifest_block_id();
    let location = BlockLocation::single(header.volume_id(), block_id, manifest_offset, 0);
    let (block_type, block) = reader.read_typed_block(&location).await?;
    let manifest_end = manifest_offset
        .checked_add(u64::from(block.compressed_size))
        .and_then(|end| end.checked_add(era_common::BlockHeader::SIZE as u64));
    if block_type != BlockType::Manifest
        || !manifest_end.is_some_and(|end| end <= footer.backup_header_offset())
    {
        return Err(EraError::IntegrityError(
            "Recovered header manifest is outside the finalized data region or has the wrong type"
                .into(),
        ));
    }
    let nonce = block.data.first_chunk::<NONCE_SIZE>().ok_or_else(|| {
        EraError::IntegrityError("Recovered header manifest has a truncated nonce".into())
    })?;
    let volume_key = archive.session().unwrap_volume_key(
        header.encrypted_volume_key().nonce(),
        header.encrypted_volume_key().ciphertext(),
    )?;
    let block_id = BlockId::new(u64::from(block_id));
    let block_key =
        archive
            .session()
            .derive_block_key(&volume_key, block_id.sequence(), header.salt())?;
    let aead = XChaCha20Poly1305Context::from_derived_key(&block_key.to_derived_key()?)?;
    let aad = build_aad(
        header.archive_id().0.as_bytes(),
        header.epoch_id(),
        BlockType::Manifest,
        u32::from(header.volume_sequence()),
        block_id,
    );
    let plaintext = aead.decrypt(nonce, &aad, &block.data[NONCE_SIZE..])?;
    let (manifest, header_digest) = ArchiveManifest::from_bytes_with_header_digest(&plaintext)?;
    if archive.manifest() != Some(&manifest) || manifest.epoch_id != header.epoch_id() {
        return Err(EraError::IntegrityError(
            "Recovered header manifest does not match the authenticated archive state".into(),
        ));
    }

    header_digest.ok_or_else(|| {
        EraError::IntegrityError("Manifest has no authenticated backup header digest".into())
    })
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
    let provider = Box::new(crate::auth::PasswordProvider::new(password.to_string()));
    repair_archive_with_providers(path, vec![provider], options).await
}

pub async fn repair_archive_with_passwords(
    path: &Path,
    passwords: &[&str],
    options: RepairOptions,
) -> Result<RepairStats> {
    let providers: Vec<Box<dyn crate::auth::AuthProvider>> = passwords
        .iter()
        .map(|p| Box::new(crate::auth::PasswordProvider::new(p.to_string())) as _)
        .collect();
    repair_archive_with_providers(path, providers, options).await
}

pub async fn repair_archive_with_private_keys(
    path: &Path,
    keypairs: &[era_crypto::EitherKeyPair],
    options: RepairOptions,
) -> Result<RepairStats> {
    let mut providers: Vec<Box<dyn crate::auth::AuthProvider>> = Vec::new();
    for kp in keypairs {
        match kp {
            era_crypto::EitherKeyPair::Legacy(k) => {
                providers.push(Box::new(crate::auth::CertificateProvider::new(k.clone())) as _);
            }
            era_crypto::EitherKeyPair::Hybrid(k) => {
                providers
                    .push(Box::new(crate::auth::HybridCertificateProvider::new(*k.clone())) as _);
            }
        }
    }
    repair_archive_with_providers(path, providers, options).await
}

pub async fn repair_archive_with_providers(
    path: &Path,
    providers: Vec<Box<dyn crate::auth::AuthProvider>>,
    options: RepairOptions,
) -> Result<RepairStats> {
    let cancel_flag = Arc::new(AtomicBool::new(false));
    info!("Starting archive repair: {}", path.display());

    // Open archive for reading first
    let parent_dir = path.parent().unwrap_or(Path::new("."));
    let backend = LocalStorageBackend::new(parent_dir);
    let volume_path = path.file_name().unwrap_or_default();

    let volume_reader = VolumeReader::open(&backend, Path::new(volume_path)).await?;

    let header = volume_reader.header();
    let erasure_config = header.config().erasure;

    // If the archive is multi-volume, use matrix-aware repair
    if header.total_volumes() > 1 {
        return Box::pin(repair_archive_matrix_with_providers(
            path, providers, options,
        ))
        .await;
    }

    if erasure_config.is_none() && !volume_reader.header_recovered_from_backup() {
        return Err(EraError::ErasureError(
            "Archive does not use erasure coding - repair not available".into(),
        ));
    }

    if let Some(config) = erasure_config {
        info!(
            "Erasure config: {}/{} data/parity shards",
            config.data_shards, config.parity_shards
        );
    }

    // Verify credentials before proceeding with repair
    let needs_header = volume_reader.header_recovered_from_backup();
    let has_catalog = volume_reader
        .footer()
        .is_some_and(|footer| footer.has_catalog_location());
    let (header_repair, catalog_repairs) = if needs_header || has_catalog {
        let mut archive = ArchiveReader::open_with_providers(path, providers).await?;
        let bytes = if needs_header {
            Some(recovered_header_bytes(&volume_reader, &archive).await?)
        } else {
            None
        };
        if erasure_config.is_none() && !archive.verify().await?.is_ok() {
            return Err(EraError::IntegrityError(
                "Non-erasure archive has damage beyond its recoverable primary header".into(),
            ));
        }
        let catalogs = if erasure_config.is_some() {
            archive.plan_catalog_repairs().await?
        } else {
            Vec::new()
        };
        (bytes, catalogs)
    } else {
        let _mk_array = try_unlock_with_providers(header, &providers)?;
        (None, Vec::new())
    };

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

    if let Some(header_bytes) = header_repair {
        if options.dry_run {
            info!("Dry run: would restore the primary header from its authenticated backup");
        } else {
            check_cancelled(&cancel_flag, "primary header repair")?;
            info!("Restoring primary header from its authenticated backup");
            apply_primary_header_repair(path, header_bytes).await?;
        }
    }
    for repair in catalog_repairs {
        apply_catalog_repair(path, repair, &options, &cancel_flag).await?;
    }

    let Some(erasure_config) = erasure_config else {
        return Ok(RepairStats::default());
    };

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

            let Some(shard_header) = shard_header else {
                debug!(
                    "Invalid shard header at block {}, shard {}",
                    block_index, shard_idx
                );
                corrupted_indices.push(shard_idx);
                stats.corrupted_shards_found += 1;
                offset += header_prefix_len as u64 + ShardHeader::SIZE as u64 + shard_len as u64;
                continue;
            };

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
                    let header_len_corrupted =
                        authoritative_len.is_some_and(|auth_len| shard_header.length != auth_len);
                    if crc_valid && !header_len_corrupted {
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

async fn apply_primary_header_repair(path: &Path, header_bytes: Bytes) -> Result<()> {
    apply_metadata_repair(path, 0, header_bytes).await
}

async fn apply_catalog_repair(
    path: &Path,
    repair: CatalogRepair,
    options: &RepairOptions,
    cancel_flag: &Arc<AtomicBool>,
) -> Result<()> {
    if options.dry_run {
        info!(
            "Dry run: would restore the primary Catalog in {}",
            path.display()
        );
        return Ok(());
    }
    check_cancelled(cancel_flag, "primary Catalog repair")?;
    apply_metadata_repair(path, repair.offset, Bytes::from(repair.bytes)).await
}

async fn apply_metadata_repair(path: &Path, offset: u64, bytes: Bytes) -> Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    })
    .await
    .map_err(|e| EraError::Other(format!("Metadata repair task failed: {e}")))?
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

        let read_crc = compute_shard_crc(&read_buffer);
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
    let provider = Box::new(crate::auth::PasswordProvider::new(password.to_string()));
    repair_archive_matrix_with_providers(path, vec![provider], options).await
}

async fn repair_archive_matrix_with_providers(
    path: &Path,
    _providers: Vec<Box<dyn crate::auth::AuthProvider>>,
    options: RepairOptions,
) -> Result<RepairStats> {
    let cancel_flag = Arc::new(AtomicBool::new(false));
    info!(
        "Starting matrix-distributed archive repair: {}",
        path.display()
    );

    let DiscoveredVolumes {
        volume_readers,
        volume_paths,
        volume_indices,
        expected_volume_count,
        missing_volume_indices,
    } = ArchiveReader::discover_volumes(path).await?;
    let volume_count = volume_readers.len();
    let expected_volumes = expected_volume_count.max(1);

    if volume_count < 2 {
        return Err(EraError::ErasureError(
            "Matrix-distributed archive has insufficient surviving volumes for repair".into(),
        ));
    }

    let header = volume_readers[0].header();
    let erasure_config = header.config().erasure;
    let header_repair_needed = volume_readers
        .iter()
        .any(VolumeReader::header_recovered_from_backup);
    if erasure_config.is_none() && !header_repair_needed {
        return Err(EraError::ErasureError(
            "Archive does not use erasure coding".into(),
        ));
    }

    // Verify credentials before proceeding with repair
    let mut header_repairs = Vec::new();
    let mut catalog_repairs = Vec::new();
    let mut authenticated_committed_ends = None;
    let has_catalog = volume_readers.iter().any(|reader| {
        reader
            .footer()
            .is_some_and(|footer| footer.has_catalog_location())
    });
    let session = if header_repair_needed || has_catalog {
        let mut archive = ArchiveReader::open_with_providers(path, _providers).await?;
        authenticated_committed_ends = archive
            .manifest()
            .filter(|manifest| manifest.volume_committed_ends.len() == expected_volumes)
            .map(|manifest| manifest.volume_committed_ends.clone());
        for (reader, volume_path) in volume_readers.iter().zip(&volume_paths) {
            if reader.header_recovered_from_backup() {
                let header_bytes = recovered_header_bytes(reader, &archive).await?;
                header_repairs.push((volume_path.clone(), header_bytes));
            }
        }
        if erasure_config.is_none() && !archive.verify().await?.is_ok() {
            return Err(EraError::IntegrityError(
                "Non-erasure archive has damage beyond its recoverable primary headers".into(),
            ));
        }
        if erasure_config.is_some() {
            for repair in archive.plan_catalog_repairs().await? {
                let index = volume_indices
                    .iter()
                    .position(|&index| index == usize::from(repair.sequence))
                    .ok_or_else(|| {
                        EraError::IntegrityError("Catalog repair volume not found".into())
                    })?;
                catalog_repairs.push((index, repair));
            }
        }
        archive.session().try_clone()?
    } else {
        let mk = zeroize::Zeroizing::new(try_unlock_with_providers(header, &_providers)?);
        era_crypto::KeySession::from_master_key(&mk)?
    };
    let wrapped = header.encrypted_volume_key();
    let volume_key = session.unwrap_volume_key(wrapped.nonce(), wrapped.ciphertext())?;
    let keys = Arc::new((session, volume_key));
    let archive_id = *header.archive_id().0.as_bytes();
    let salt = *header.salt();
    let epoch = header.epoch_id();

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

    for (volume_path, header_bytes) in header_repairs {
        if options.dry_run {
            info!(
                "Dry run: would restore primary header for {}",
                volume_path.display()
            );
        } else {
            check_cancelled(&cancel_flag, "matrix primary header repair")?;
            info!("Restoring primary header for {}", volume_path.display());
            apply_primary_header_repair(&volume_path, header_bytes).await?;
        }
    }
    for (index, repair) in catalog_repairs {
        apply_catalog_repair(&volume_paths[index], repair, &options, &cancel_flag).await?;
    }

    let Some(erasure_config) = erasure_config else {
        return Ok(RepairStats {
            archive_health: classify_repair_archive_health(
                expected_volumes,
                volume_count,
                missing_volume_indices,
                0,
                expected_volumes,
            ),
            ..Default::default()
        });
    };
    let total_shards = erasure_config.data_shards as usize + erasure_config.parity_shards as usize;

    info!(
        "Matrix repair: {}/{} erasure, {} volumes found, {} total shards",
        erasure_config.data_shards, erasure_config.parity_shards, volume_count, total_shards
    );

    let mut geometry = MatrixScanGeometry::new(
        header.config(),
        expected_volume_count,
        &volume_indices,
        header.config().distribution.strategy,
    )?;
    let committed_ends = authenticated_committed_ends.as_deref().map_or(
        CommittedDataEnds::Unknown { expected_volumes },
        CommittedDataEnds::Authenticated,
    );
    let minimum_required_volumes =
        minimum_volumes_for_repair(erasure_config, geometry.generation_width(), committed_ends);
    let mut stats = RepairStats {
        archive_health: classify_repair_archive_health(
            expected_volumes,
            volume_count,
            missing_volume_indices.clone(),
            0,
            minimum_required_volumes,
        ),
        ..Default::default()
    };
    let mut all_repairs: HashMap<usize, Vec<ShardRepair>> = HashMap::new(); // volume_idx -> repairs

    // Scan blocks using matrix distribution pattern
    // We need to iterate through block sequences and collect shards from each volume
    // Track offsets for each volume
    let mut volume_offsets: Vec<u64> = volume_readers.iter().map(|r| r.data_region().0).collect();

    let mut block_sequence: u64 = 0;

    let data_ends: Vec<u64> = volume_readers
        .iter()
        .map(crate::erasure_scan::erasure_data_end)
        .collect();

    let header_prefix_len = erasure_config.data_shards as usize * 4;

    loop {
        match geometry.advance_to_data(&volume_offsets, &data_ends) {
            Ok(true) => {}
            Ok(false) => break,
            Err(e) if options.continue_on_error => {
                stats.unrecoverable_blocks += 1;
                stats.errors.push(e.to_string());
                break;
            }
            Err(e) => return Err(e),
        }
        let mut shards: Vec<(usize, Bytes)> = Vec::with_capacity(total_shards);
        let mut shard_locations: Vec<(usize, usize, u64)> = Vec::new(); // (shard_idx, reader_idx, offset)
        let mut corrupted_indices: Vec<usize> = Vec::new();
        let mut data_lengths: Vec<Option<u32>> = vec![None; erasure_config.data_shards as usize];
        let mut max_len: usize = 0;
        let mut any_frame_seen = false;

        // Pre-pass: collect all readable prefix copies for multi-copy reconciliation.
        // We use header lengths for navigation so a corrupted prefix cannot cause drift.
        let mut prefix_copies: Vec<Bytes> = Vec::with_capacity(total_shards);
        let mut temp_offsets: Vec<u64> = volume_offsets.clone();
        for shard_idx in 0..total_shards {
            let vol_idx = geometry.volume_sequence(shard_idx, block_sequence)?;
            let reader_idx_opt = geometry.reader_index(vol_idx);
            if let Some(reader_idx) = reader_idx_opt {
                let reader = &volume_readers[reader_idx];
                let shard_offset = temp_offsets[reader_idx];
                if shard_offset >= data_ends[reader_idx] {
                    continue;
                }
                let Some((prefix_bytes, shard_header)) = read_matrix_shard_header(
                    reader,
                    shard_offset,
                    data_ends[reader_idx],
                    header_prefix_len,
                )
                .await
                else {
                    temp_offsets[reader_idx] = data_ends[reader_idx];
                    continue;
                };
                if u64::from(shard_header.length) > MAX_SHARD_SIZE {
                    temp_offsets[reader_idx] = data_ends[reader_idx];
                    continue;
                }
                prefix_copies.push(prefix_bytes);
                temp_offsets[reader_idx] = shard_offset
                    + header_prefix_len as u64
                    + ShardHeader::SIZE as u64
                    + u64::from(shard_header.length);
            }
        }
        let stripe_lengths = crate::erasure_scan::reconcile_stripe_prefixes(
            &prefix_copies,
            erasure_config.data_shards as usize,
        );

        // Scan all shards across volumes using matrix distribution
        for shard_idx in 0..total_shards {
            let vol_idx = geometry.volume_sequence(shard_idx, block_sequence)?;

            let reader_idx_opt = geometry.reader_index(vol_idx);
            if let Some(reader_idx) = reader_idx_opt {
                let reader = &volume_readers[reader_idx];
                let shard_offset = volume_offsets[reader_idx];

                let Some((_, shard_header)) = read_matrix_shard_header(
                    reader,
                    shard_offset,
                    data_ends[reader_idx],
                    header_prefix_len,
                )
                .await
                else {
                    volume_offsets[reader_idx] = data_ends[reader_idx];
                    corrupted_indices.push(shard_idx);
                    stats.corrupted_shards_found += 1;
                    continue;
                };
                any_frame_seen = true;
                let header_offset = shard_offset + header_prefix_len as u64;
                let payload_offset = header_offset + ShardHeader::SIZE as u64;

                // Determine authoritative shard length from reconciled stripe prefix for data shards
                let is_data_shard = shard_idx < erasure_config.data_shards as usize;
                let authoritative_len: Option<u32> = if is_data_shard {
                    stripe_lengths
                        .as_ref()
                        .and_then(|sl| sl.get(shard_idx).copied())
                } else {
                    None
                };

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
                } else {
                    let h = &shard_header;
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
                        if u64::from(parity_bound) <= data_ends[reader_idx] - payload_offset {
                            shard_locations.push((shard_idx, reader_idx, header_offset));
                        }
                        volume_offsets[reader_idx] = payload_offset
                            .saturating_add(u64::from(parity_bound))
                            .min(data_ends[reader_idx]);
                        continue;
                    }
                    if parity_bound > 0 && h.length > parity_bound {
                        parity_bound as usize
                    } else {
                        h.length as usize
                    }
                };

                if shard_len as u64 > data_ends[reader_idx] - payload_offset {
                    corrupted_indices.push(shard_idx);
                    stats.corrupted_shards_found += 1;
                    volume_offsets[reader_idx] = data_ends[reader_idx];
                    continue;
                }

                if is_data_shard {
                    if let Some(slot) = data_lengths.get_mut(shard_idx) {
                        *slot = authoritative_len.or(Some(shard_header.length));
                    }
                }
                if shard_len > max_len {
                    max_len = shard_len;
                }

                match reader.read_raw(payload_offset, shard_len).await {
                    Ok(shard_data) if shard_data.len() == shard_len => {
                        // When using authoritative prefix length for data shards,
                        // bypass ShardHeader.verify (which checks data.len() == header.length)
                        // since the header length field may be corrupted
                        let crc_valid = if authoritative_len.is_some() {
                            compute_shard_crc(&shard_data) == shard_header.crc
                        } else {
                            shard_header.verify(&shard_data)
                        };
                        let header_len_corrupted = authoritative_len
                            .is_some_and(|auth_len| shard_header.length != auth_len);
                        if crc_valid && !header_len_corrupted {
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
                    Ok(_) | Err(_) => {
                        corrupted_indices.push(shard_idx);
                        stats.corrupted_shards_found += 1;
                    }
                }

                volume_offsets[reader_idx] = payload_offset + shard_len as u64;
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

        if !any_frame_seen {
            let error = EraError::ErasureError(format!(
                "No readable shard frames for stripe {block_sequence}"
            ));
            if !options.continue_on_error {
                return Err(error);
            }
            stats.unrecoverable_blocks += 1;
            stats.errors.push(error.to_string());
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
                        let data_blocks = (0..min_shards)
                            .map(|shard_idx| {
                                let ciphertext = shards
                                    .iter()
                                    .chain(&repaired_shards)
                                    .find_map(|(idx, data)| {
                                        (*idx == shard_idx).then_some(data.clone())
                                    })
                                    .ok_or_else(|| {
                                        EraError::ErasureError(format!(
                                            "Missing reconstructed data shard {shard_idx}"
                                        ))
                                    })?;
                                let block_id = BlockId::new(
                                    block_sequence * u64::from(erasure_config.data_shards)
                                        + shard_idx as u64,
                                );
                                let sequence =
                                    geometry.volume_sequence(shard_idx, block_sequence)?;
                                let sequence = u32::try_from(sequence).map_err(|_| {
                                    EraError::InvalidFormat("Volume sequence exceeds u32".into())
                                })?;
                                Ok((block_id, sequence, ciphertext))
                            })
                            .collect::<Result<Vec<_>>>()?;
                        let keys = Arc::clone(&keys);
                        let authentication = tokio::task::spawn_blocking(move || -> Result<()> {
                            let (session, volume_key) = &*keys;
                            for (block_id, sequence, ciphertext) in data_blocks {
                                if ciphertext.iter().all(|&byte| byte == 0) {
                                    continue;
                                }
                                let key = session
                                    .derive_block_key(volume_key, block_id.sequence(), &salt)?
                                    .to_derived_key()?;
                                era_crypto::decrypt_with_context_for_type(
                                    &key,
                                    &salt,
                                    &archive_id,
                                    epoch,
                                    sequence,
                                    BlockType::Data,
                                    block_id,
                                    &ciphertext,
                                )?;
                            }
                            Ok(())
                        })
                        .await
                        .map_err(|e| EraError::AsyncError(e.to_string()))?;
                        if let Err(error) = authentication {
                            let message = format!("Stripe {block_sequence}: reconstructed data failed authentication: {error}");
                            if !options.continue_on_error {
                                return Err(EraError::IntegrityError(message));
                            }
                            stats.unrecoverable_blocks += 1;
                            stats.errors.push(message);
                            block_sequence += 1;
                            continue;
                        }
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
        minimum_required_volumes,
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

    #[test]
    fn test_minimum_volumes_for_repair() {
        assert_eq!(
            minimum_volumes_for_repair(
                ErasureCodeConfig::new(4, 2),
                3,
                CommittedDataEnds::Unknown {
                    expected_volumes: 3,
                },
            ),
            2
        );
        assert_eq!(
            minimum_volumes_for_repair(
                ErasureCodeConfig::new(5, 1),
                3,
                CommittedDataEnds::Unknown {
                    expected_volumes: 3,
                },
            ),
            3
        );
        assert_eq!(
            minimum_volumes_for_repair(
                ErasureCodeConfig::new(4, 2),
                6,
                CommittedDataEnds::Unknown {
                    expected_volumes: 6,
                },
            ),
            4
        );
        assert_eq!(
            minimum_volumes_for_repair(
                ErasureCodeConfig::new(4, 2),
                2,
                CommittedDataEnds::Unknown {
                    expected_volumes: 2,
                },
            ),
            2
        );
        assert_eq!(
            minimum_volumes_for_repair(
                ErasureCodeConfig::new(4, 2),
                1,
                CommittedDataEnds::Unknown {
                    expected_volumes: 1,
                },
            ),
            1
        );
    }

    #[test]
    fn test_minimum_volumes_for_repair_uses_generation_width() {
        assert_eq!(
            minimum_volumes_for_repair(
                ErasureCodeConfig::new(4, 2),
                3,
                CommittedDataEnds::Unknown {
                    expected_volumes: 9,
                },
            ),
            6,
            "three narrow generations need two surviving volumes each"
        );
        assert_eq!(
            minimum_volumes_for_repair(
                ErasureCodeConfig::new(4, 2),
                3,
                CommittedDataEnds::Unknown {
                    expected_volumes: 4,
                },
            ),
            3,
            "a short final generation is capped by its actual width"
        );
    }
}
