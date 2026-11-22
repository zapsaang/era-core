//! Volume pool for matrix distribution and fixed-size volume management.
//!
//! This module provides `VolumePool`, which manages multiple volumes for
//! true matrix-distributed erasure coding with automatic volume rotation
//! when volumes reach their size limit.

use era_common::{
    compute_shard_crc, ArchiveManifest, BlockHeader, BlockLocation, BlockType, EncryptedMacroBlock,
    EraError, ErasureCodeConfig, MatrixBlockLocation, MatrixDistributionConfig, MatrixShardEntry,
    Result, ShardHeader, VolumeId,
};
use era_storage::StorageBackend;
use std::collections::HashMap;
use std::mem::size_of;
use std::path::{Path, PathBuf};

use crate::distribution::{
    validate_erasure_volume_count, DistributionCalculator, DistributionConfigExt,
};
use crate::writer::{superheader_digest, RetiredVolumeState};
use crate::{
    extract_filename, SuperHeader, VolumeReader, VolumeWriter, DEFAULT_MAX_VOLUME_SIZE,
    MIN_VOLUME_SIZE,
};

const MAX_MANIFEST_VOLUMES: usize = ArchiveManifest::MAX_VOLUMES;

fn checked_manifest_volume_count(count: usize) -> Result<u16> {
    if !(1..=MAX_MANIFEST_VOLUMES).contains(&count) {
        return Err(era_common::EraError::InvalidConfig(format!(
            "volume count {count} is outside the manifest limit (1..={MAX_MANIFEST_VOLUMES})"
        )));
    }
    u16::try_from(count)
        .map_err(|_| era_common::EraError::InvalidConfig("volume count exceeds u16".into()))
}

fn check_retained_volume_size(retained_end: u64, max_volume_size: u64) -> Result<()> {
    const FINAL_TRAILER_SIZE: u64 = (crate::HEADER_SIZE + crate::FOOTER_SIZE) as u64;
    if retained_end
        .checked_add(FINAL_TRAILER_SIZE)
        .is_none_or(|finalized_size| finalized_size > max_volume_size)
    {
        return Err(EraError::InvalidConfig(format!(
            "cannot append: retained volume ({retained_end} bytes) plus final trailer \
             ({FINAL_TRAILER_SIZE} bytes) exceeds the volume size limit ({max_volume_size} bytes)"
        )));
    }
    Ok(())
}

/// Configuration for the volume pool.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct VolumePoolConfig {
    /// Base path for volume files (without extension)
    pub base_path: PathBuf,
    /// Maximum size per volume in bytes
    pub max_volume_size: u64,
    /// Initial number of volumes to create
    pub initial_volume_count: usize,
    /// Matrix distribution configuration
    pub distribution: MatrixDistributionConfig,
}

impl VolumePoolConfig {
    /// Create a new volume pool configuration.
    pub fn new(base_path: impl Into<PathBuf>, volume_count: usize) -> Self {
        Self {
            base_path: base_path.into(),
            max_volume_size: DEFAULT_MAX_VOLUME_SIZE,
            initial_volume_count: volume_count.max(1),
            distribution: MatrixDistributionConfig::default(),
        }
    }

    /// Set maximum volume size.
    ///
    /// Values below [`MIN_VOLUME_SIZE`] are silently clamped.
    pub fn with_max_size(mut self, max_size: u64) -> Self {
        self.max_volume_size = max_size.max(MIN_VOLUME_SIZE);
        debug_assert!(self.max_volume_size >= MIN_VOLUME_SIZE);
        self
    }

    /// Set distribution configuration.
    pub fn with_distribution(mut self, distribution: MatrixDistributionConfig) -> Self {
        self.distribution = distribution;
        debug_assert!(self.initial_volume_count >= 1);
        self
    }

    /// Configure based on erasure config.
    pub fn for_erasure(mut self, erasure: ErasureCodeConfig) -> Self {
        self.distribution = MatrixDistributionConfig::from_erasure_config(erasure);
        debug_assert!(self.initial_volume_count >= 1);
        self
    }

    /// Generate volume path for a given sequence number.
    pub fn volume_path(&self, sequence: u16) -> PathBuf {
        crate::volume_path(&self.base_path, sequence)
    }
}

/// Statistics about the volume pool.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct VolumePoolStats {
    /// Total number of volumes created
    pub volume_count: usize,
    /// Total bytes written across all volumes
    pub total_bytes_written: u64,
    /// Total shards written
    pub total_shards_written: u64,
    /// Total blocks written
    pub total_blocks_written: u64,
    /// Volume sizes (volume_sequence -> size)
    pub volume_sizes: Vec<(u16, u64)>,
}

/// Volume pool manager for matrix-distributed erasure coding.
///
/// This manager handles:
/// 1. Multiple volume writers with fixed size limits
/// 2. True matrix distribution of shards across volumes
/// 3. Automatic volume rotation when size limits are reached
/// 4. Tracking of shard locations for recovery
pub struct VolumePool<B: StorageBackend> {
    /// Storage backend for creating new volumes
    backend: B,
    /// Configuration
    config: VolumePoolConfig,
    /// Template header for creating new volumes
    template_header: SuperHeader,
    /// Active volume writers indexed by their pool position
    /// Position 0..N maps to logical volume slots for distribution
    writers: Vec<VolumeWriter<B::Writer>>,
    /// Sequence numbers for each writer (for tracking across rotations)
    sequences: Vec<u16>,
    /// Retired volume metadata retained after closing handles until finalization.
    retired_volumes: Vec<(u16, RetiredVolumeState)>,
    /// Active canonical slot index for monotonic non-EC volume selection.
    active_canonical_slot: usize,
    /// Block sequence counter for rotation calculation
    block_sequence: u64,
    /// Statistics
    stats: VolumePoolStats,
    /// Initial committed ends from previous manifest (append mode only).
    initial_committed_ends: Vec<u64>,
    /// Position when each volume was opened for append, keyed by volume sequence (append mode only).
    append_start_positions: HashMap<u16, u64>,
    /// Newly created rotated volume filenames during an uncommitted append session.
    uncommitted_rotated_files: Vec<String>,
}

impl<B: StorageBackend> Drop for VolumePool<B> {
    fn drop(&mut self) {
        if self.uncommitted_rotated_files.is_empty() {
            return;
        }
        self.writers.clear();
        for filename in self.uncommitted_rotated_files.drain(..) {
            self.backend.remove_sync_on_drop(Path::new(&filename));
        }
    }
}

impl<B: StorageBackend> VolumePool<B> {
    /// Create a new volume pool.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if the count is outside the manifest's volume limit.
    /// Returns `InvalidConfig` if a volume path has no filename.
    /// Returns `Serialization` if the header cannot be encoded.
    /// Returns I/O errors from creating volumes on the storage backend.
    pub async fn create(
        backend: B,
        config: VolumePoolConfig,
        template_header: SuperHeader,
    ) -> Result<Self> {
        let volume_count = config.initial_volume_count;
        let total_volumes = checked_manifest_volume_count(volume_count)?;
        if let Some(erasure) = template_header.config().erasure {
            validate_erasure_volume_count(erasure, volume_count)?;
        }
        let mut writers = Vec::with_capacity(volume_count);
        let mut sequences = Vec::with_capacity(volume_count);

        // Create initial volumes
        for seq in 0..total_volumes {
            let mut header = template_header.clone();
            // Each volume must have a unique volume_id for identification
            header.set_volume_id(VolumeId::new());
            header.set_volume_sequence(seq);
            header.set_total_volumes(total_volumes);
            let volume_path = config.volume_path(seq);
            let volume_filename = extract_filename(&volume_path)?;

            let writer = VolumeWriter::create(&backend, Path::new(volume_filename), header).await?;
            writers.push(writer);
            sequences.push(seq);
        }

        let stats = VolumePoolStats {
            volume_count,
            ..Default::default()
        };

        let pool = Self {
            backend,
            config,
            template_header,
            writers,
            sequences,
            retired_volumes: Vec::new(),
            active_canonical_slot: 0,
            block_sequence: 0,
            stats,
            initial_committed_ends: Vec::new(),
            append_start_positions: HashMap::new(),
            uncommitted_rotated_files: Vec::new(),
        };

        Ok(pool)
    }

    /// Open an existing volume pool for appending.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if the count exceeds the manifest limit or a path has no filename.
    /// Returns `CorruptedFooter` if any volume is missing its footer.
    /// Returns `CorruptedHeader` or `CorruptedFooter` if any volume is corrupted.
    /// Returns `InvalidConfig` if a single retained volume cannot fit with its final trailer.
    /// Returns I/O errors from opening volumes on the storage backend.
    pub async fn open_append(
        backend: B,
        mut config: VolumePoolConfig,
        template_header: SuperHeader,
    ) -> Result<Self> {
        let volume_count = if template_header.total_volumes() > 0 {
            template_header.total_volumes() as usize
        } else {
            config.initial_volume_count
        };
        let total_volumes = checked_manifest_volume_count(volume_count)?;
        config.initial_volume_count = volume_count;

        // P8-02: Pre-allocate with known capacity to avoid reallocations
        let mut writers = Vec::with_capacity(config.initial_volume_count);
        let mut sequences = Vec::with_capacity(config.initial_volume_count);
        let mut max_block_count = 0u32;

        for seq in 0..total_volumes {
            let volume_path = config.volume_path(seq);
            let volume_filename = extract_filename(&volume_path)?;

            let reader = VolumeReader::open(&backend, Path::new(volume_filename)).await?;
            if reader.header().volume_sequence() != seq {
                return Err(era_common::EraError::CorruptedHeader(format!(
                    "volume at sequence {seq} has header sequence {}",
                    reader.header().volume_sequence()
                )));
            }
            let footer = reader
                .footer()
                .ok_or_else(|| era_common::EraError::CorruptedFooter("Missing footer".into()))?;

            if volume_count == 1 {
                check_retained_volume_size(footer.data_end_offset(), config.max_volume_size)?;
            }
            let writer = VolumeWriter::open_append(
                &backend,
                Path::new(volume_filename),
                reader.header().clone(),
                footer,
            )
            .await?;

            max_block_count = max_block_count.max(writer.block_count());
            writers.push(writer);
            sequences.push(seq);
        }

        let active_canonical_slot = writers
            .iter()
            .rposition(|w| w.block_count() > 0)
            .unwrap_or(0);

        let stats = VolumePoolStats {
            volume_count: writers.len(),
            ..Default::default()
        };

        Ok(Self {
            backend,
            config,
            template_header,
            writers,
            sequences,
            retired_volumes: Vec::new(),
            // Note: block_sequence is initialized from max canonical block count.
            // This doesn't account for raw writes or erasure stripe count, which may
            // cause slightly suboptimal distribution on append. This is acceptable
            // because the rotating offset strategy tolerates imprecise counters.
            active_canonical_slot,
            block_sequence: max_block_count as u64,
            stats,
            initial_committed_ends: Vec::new(),
            append_start_positions: HashMap::new(),
            uncommitted_rotated_files: Vec::new(),
        })
    }

    /// Open a single-volume archive for appending using a known footer.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if the volume path has no filename or the archive has multiple volumes.
    /// Returns `InvalidConfig` if the retained volume cannot fit with its final trailer.
    /// Returns `CorruptedFooter` if the footer's data_end_offset exceeds the file size.
    /// Returns I/O errors from opening the volume on the storage backend.
    pub async fn open_append_single(
        backend: B,
        config: VolumePoolConfig,
        header: SuperHeader,
        footer: &crate::Footer,
        initial_committed_ends: Vec<u64>,
    ) -> Result<Self> {
        Self::open_append_single_at(
            backend,
            config,
            header,
            footer,
            footer.data_end_offset(),
            footer.block_count(),
            initial_committed_ends,
        )
        .await
    }

    /// Open a single-volume archive for appending, truncating to `append_offset` and
    /// continuing canonical block numbering from `initial_block_count`.
    pub async fn open_append_single_at(
        backend: B,
        mut config: VolumePoolConfig,
        header: SuperHeader,
        footer: &crate::Footer,
        append_offset: u64,
        initial_block_count: u32,
        initial_committed_ends: Vec<u64>,
    ) -> Result<Self> {
        if header.volume_sequence() != 0
            || header.total_volumes() > 1
            || initial_committed_ends.len() > 1
        {
            return Err(era_common::EraError::InvalidConfig(
                "single-volume append requires volume sequence 0 and at most one committed end"
                    .into(),
            ));
        }
        config.initial_volume_count = 1;
        let volume_path = config.volume_path(0);
        let volume_filename = extract_filename(&volume_path)?;

        check_retained_volume_size(append_offset, config.max_volume_size)?;
        let writer = VolumeWriter::open_append_at(
            &backend,
            Path::new(volume_filename),
            header.clone(),
            footer,
            append_offset,
            initial_block_count,
        )
        .await?;
        let block_sequence = writer.block_count() as u64;

        let stats = VolumePoolStats {
            volume_count: 1,
            ..Default::default()
        };

        Ok(Self {
            backend,
            config,
            template_header: header,
            writers: vec![writer],
            sequences: vec![0],
            retired_volumes: Vec::new(),
            active_canonical_slot: 0,
            block_sequence,
            stats,
            initial_committed_ends,
            append_start_positions: {
                let mut map = HashMap::new();
                map.insert(0, append_offset);
                map
            },
            uncommitted_rotated_files: Vec::new(),
        })
    }

    /// Get the highest block count across volumes (for block_id continuation).
    #[must_use]
    pub fn current_block_count(&self) -> u32 {
        self.writers
            .iter()
            .map(|w| w.block_count())
            .max()
            .unwrap_or(0)
    }

    /// Rotate all volumes to a new set when full.
    ///
    /// # Cancellation Safety
    ///
    /// Sync existing data and create replacement writers before changing pool state.
    /// Failure or cancellation may leave uncommitted replacement files on disk,
    /// but the active writers and committed ends remain intact.
    async fn rotate_volumes(&mut self) -> Result<()> {
        let volume_count = self.writers.len();
        if volume_count == 0 {
            return Err(era_common::EraError::InvalidConfig(
                "cannot rotate an empty volume pool".into(),
            ));
        }

        let current_total = self.retired_volumes.len() + volume_count;
        let first_new_sequence = checked_manifest_volume_count(current_total)?;
        let new_total = checked_manifest_volume_count(current_total + volume_count)?;

        for writer in &mut self.writers {
            writer.sync_data().await?;
        }

        let mut new_writers = Vec::with_capacity(volume_count);
        let mut new_sequences = Vec::with_capacity(volume_count);

        let is_append_session = !self.append_start_positions.is_empty();
        for next_sequence in first_new_sequence..new_total {
            let mut header = self.template_header.clone();
            header.set_volume_id(VolumeId::new());
            header.set_volume_sequence(next_sequence);
            header.set_total_volumes(new_total);

            let volume_path = self.config.volume_path(next_sequence);
            let volume_filename = extract_filename(&volume_path)?;

            let writer =
                VolumeWriter::create(&self.backend, Path::new(volume_filename), header).await?;
            if is_append_session {
                self.uncommitted_rotated_files
                    .push(volume_filename.to_string());
            }

            new_writers.push(writer);
            new_sequences.push(next_sequence);
        }

        let old_writers = std::mem::replace(&mut self.writers, new_writers);
        let old_sequences = std::mem::replace(&mut self.sequences, new_sequences);
        for (seq, old_writer) in old_sequences.into_iter().zip(old_writers) {
            self.stats
                .volume_sizes
                .push((seq, old_writer.current_size()));
            let retired = old_writer.close_for_later_finalize().await?;
            self.retired_volumes.push((seq, retired));
        }
        self.active_canonical_slot = 0;

        self.stats.volume_count = usize::from(new_total);
        debug_assert_eq!(
            self.writers.len(),
            self.sequences.len(),
            "writers/sequences length mismatch after rotate_volumes"
        );
        Ok(())
    }

    /// Get the number of active volumes.
    #[must_use]
    pub fn volume_count(&self) -> usize {
        self.writers.len()
    }

    /// Get total size of all volumes (active + retired)
    #[must_use]
    pub fn get_total_size(&self) -> u64 {
        let active_size: u64 = self.writers.iter().map(|w| w.current_size()).sum();
        self.stats
            .volume_sizes
            .iter()
            .map(|(_, size)| size)
            .sum::<u64>()
            + active_size
    }

    /// Returns per-volume committed data boundaries.
    /// Combines rotated volumes (from `stats.volume_sizes`) with active writers.
    /// Must be called BEFORE writing typed blocks to get data-only boundaries.
    /// Returns `Vec<(volume_sequence, committed_end_offset)>` sorted by sequence.
    #[must_use]
    pub fn committed_ends(&self) -> Vec<(u16, u64)> {
        self.stats
            .volume_sizes
            .iter()
            .copied()
            .chain(
                self.sequences
                    .iter()
                    .copied()
                    .zip(self.writers.iter().map(VolumeWriter::current_size)),
            )
            .map(|(seq, current)| {
                let committed = self
                    .initial_committed_ends
                    .get(usize::from(seq))
                    .zip(self.append_start_positions.get(&seq))
                    .and_then(|(&initial, &start_pos)| {
                        current
                            .checked_sub(start_pos)
                            .and_then(|delta| initial.checked_add(delta))
                    })
                    .unwrap_or(current);
                (seq, committed)
            })
            .collect()
    }

    /// Get the current block sequence number.
    #[must_use]
    pub fn block_sequence(&self) -> u64 {
        self.block_sequence
    }

    /// Advance the block sequence after completing a full stripe.
    pub fn advance_block_sequence(&mut self) {
        self.block_sequence += 1;
        self.stats.total_blocks_written += 1;
    }

    /// Get the archive ID from the template header.
    #[must_use]
    pub fn archive_id(&self) -> era_common::ArchiveId {
        self.template_header.archive_id()
    }

    /// Calculate which volume slot a shard should go to.
    fn shard_volume_slot(&self, shard_idx: usize) -> era_common::Result<usize> {
        if self.writers.is_empty() {
            return Err(era_common::EraError::InvalidConfig(
                "no volumes available for shard distribution".into(),
            ));
        }
        self.config.distribution.strategy.calculate_volume(
            shard_idx,
            self.block_sequence,
            self.writers.len(),
        )
    }

    /// Check if a volume can fit additional data.
    fn volume_can_fit(&self, slot: usize, additional_size: u64) -> bool {
        if slot >= self.writers.len() {
            return false;
        }
        let current_size = self.writers[slot].current_size();
        let reserved = super::PER_VOLUME_OVERHEAD;
        current_size
            .saturating_add(additional_size)
            .saturating_add(reserved)
            <= self.config.max_volume_size
    }

    /// Get remaining space in a volume.
    fn volume_remaining_space(&self, slot: usize) -> u64 {
        if slot >= self.writers.len() {
            return 0;
        }
        let current_size = self.writers[slot].current_size();
        let reserved = super::PER_VOLUME_OVERHEAD;
        if current_size.saturating_add(reserved) >= self.config.max_volume_size {
            0
        } else {
            self.config.max_volume_size - current_size - reserved
        }
    }

    /// Return indices of volumes that cannot fit the given size.
    #[must_use]
    pub fn check_typed_block_space(&self, total_size_per_volume: u64) -> Vec<usize> {
        if self.writers.is_empty() {
            return vec![0];
        }
        let mut insufficient = Vec::new();
        for slot in 0..self.writers.len() {
            if !self.volume_can_fit(slot, total_size_per_volume) {
                insufficient.push(slot);
            }
        }
        insufficient
    }

    fn check_fresh_volume_space(&self, slot: usize, required: u64) -> Result<()> {
        let available = self
            .config
            .max_volume_size
            .saturating_sub(crate::DATA_REGION_START + crate::PER_VOLUME_OVERHEAD);
        if required > available {
            return Err(era_common::EraError::VolumeSpaceExhausted {
                volume: slot,
                required,
                available,
                message: "write does not fit in a fresh volume".into(),
            });
        }
        Ok(())
    }

    /// Clear stale backup footer bytes and checkpoint state on a writable volume slot.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if `slot` is out of bounds or propagates backend I/O errors.
    pub async fn clear_backup_footer_gap(&mut self, slot: usize) -> Result<()> {
        let writer = self.writers.get_mut(slot).ok_or_else(|| {
            era_common::EraError::InvalidConfig(format!(
                "volume slot {slot} is out of bounds for backup footer gap cleanup"
            ))
        })?;
        writer.clear_backup_footer_gap().await
    }

    /// Ensure a single volume slot can fit a canonical typed block of `on_disk_size` bytes,
    /// rotating volumes if needed without violating `max_volume_size`.
    ///
    /// Returns `Ok(true)` if rotation occurred, `Ok(false)` if space was already sufficient.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if `slot` is out of bounds or `on_disk_size` exceeds the
    /// maximum canonical block size, `VolumeSpaceExhausted` if it cannot fit a fresh volume,
    /// or propagates rotation errors.
    pub async fn ensure_slot_typed_block_space(
        &mut self,
        slot: usize,
        on_disk_size: u64,
    ) -> Result<bool> {
        if slot >= self.writers.len() {
            return Err(era_common::EraError::InvalidConfig(format!(
                "volume slot {slot} is out of bounds for typed-block space check"
            )));
        }
        let max_canonical_disk_size =
            (era_common::BlockHeader::SIZE as u64).saturating_add(crate::MAX_SHARD_SIZE as u64);
        if on_disk_size > max_canonical_disk_size {
            return Err(era_common::EraError::InvalidConfig(format!(
                "typed block size {on_disk_size} exceeds maximum canonical block disk size {max_canonical_disk_size}"
            )));
        }
        if self.volume_can_fit(slot, on_disk_size) {
            return Ok(false);
        }
        self.check_fresh_volume_space(slot, on_disk_size)?;
        self.rotate_volumes().await?;
        Ok(true)
    }

    /// Precheck available space for catalog + index + manifest blocks and rotate if needed.
    ///
    /// Checks whether all volumes have sufficient space for the combined on-disk
    /// size of catalog, index, and manifest blocks. Callers must include typed
    /// block headers and encryption overhead in the size arguments.
    /// If any volume lacks space, rotates only if the bundle fits a fresh volume.
    ///
    /// Returns `Ok(true)` if rotation was performed, `Ok(false)` if space was already sufficient.
    ///
    /// # Errors
    /// Returns `VolumeSpaceExhausted` if the bundle exceeds fresh volume capacity.
    pub async fn precheck_and_rotate_if_needed(
        &mut self,
        catalog_size: u64,
        index_size: u64,
        manifest_size: u64,
    ) -> Result<bool> {
        if self.writers.is_empty() {
            return Err(era_common::EraError::InvalidConfig(
                "no writable volumes available for typed-block precheck".into(),
            ));
        }
        let total_per_volume = catalog_size
            .checked_add(index_size)
            .and_then(|size| size.checked_add(manifest_size))
            .ok_or_else(|| {
                era_common::EraError::InvalidConfig("typed-block precheck size overflow".into())
            })?;

        let insufficient = self.check_typed_block_space(total_per_volume);
        let Some(&slot) = insufficient.first() else {
            return Ok(false);
        };
        self.check_fresh_volume_space(slot, total_per_volume)?;
        self.rotate_volumes().await?;
        Ok(true)
    }

    /// Check if a shard size can ever fit in a volume.
    ///
    /// Returns an error if the shard is larger than max_volume_size allows.
    fn validate_shard_size(&self, shard_size: u64) -> Result<()> {
        // V27-11: Enforce global MAX_SHARD_SIZE cap regardless of volume size
        let max_shard = crate::MAX_SHARD_SIZE as u64;
        if shard_size > max_shard {
            return Err(era_common::EraError::InvalidConfig(format!(
                "Shard size {} exceeds global MAX_SHARD_SIZE {}",
                shard_size, max_shard
            )));
        }

        // MN34-01: Use BlockHeader::SIZE (not raw `4`) to match volume_can_fit()/needs_expansion() reservation
        let reserved = super::PER_VOLUME_OVERHEAD;
        let max_volume_shard_size = self.config.max_volume_size.saturating_sub(reserved);

        if shard_size > max_volume_shard_size {
            return Err(era_common::EraError::InvalidConfig(format!(
                "Shard size {} exceeds maximum allowed {} (max_volume_size={})",
                shard_size, max_volume_shard_size, self.config.max_volume_size
            )));
        }
        Ok(())
    }

    /// Reserve a whole matrix stripe and return its absolute volume sequences in shard order.
    ///
    /// `payload_lengths` contains the exact unpadded data and aligned parity lengths.
    /// `stripe_prefix_count` is the number of `u32` lengths repeated in every frame.
    /// Write the stripe with [`Self::write_shard`] before advancing the stripe sequence.
    ///
    /// # Errors
    /// Returns a size error before rotation if any shard or slot total exceeds capacity,
    /// or propagates an error creating the next generation.
    pub async fn reserve_stripe(
        &mut self,
        payload_lengths: &[u32],
        stripe_prefix_count: usize,
    ) -> Result<Vec<u16>> {
        let mut per_slot_bytes = vec![0u64; self.writers.len()];
        let mut slots = Vec::with_capacity(payload_lengths.len());
        for (shard, &length) in payload_lengths.iter().enumerate() {
            let slot = self.shard_volume_slot(shard)?;
            let size = self.shard_disk_size(u64::from(length), stripe_prefix_count, false)?;
            per_slot_bytes[slot] = per_slot_bytes[slot].checked_add(size).ok_or_else(|| {
                EraError::InvalidConfig("stripe disk size overflow for volume slot".into())
            })?;
            slots.push(slot);
        }
        self.ensure_stripe_capacity(&per_slot_bytes).await?;
        Ok(slots.into_iter().map(|slot| self.sequences[slot]).collect())
    }

    async fn ensure_stripe_capacity(&mut self, per_slot_bytes: &[u64]) -> Result<()> {
        if per_slot_bytes
            .iter()
            .enumerate()
            .any(|(slot, &size)| size != 0 && !self.volume_can_fit(slot, size))
        {
            for (slot, &size) in per_slot_bytes.iter().enumerate() {
                self.check_fresh_volume_space(slot, size)?;
            }
            self.rotate_volumes().await?;
        }
        Ok(())
    }

    fn shard_disk_size(
        &self,
        payload_size: u64,
        stripe_prefix_count: usize,
        include_original_len: bool,
    ) -> Result<u64> {
        self.validate_shard_size(payload_size)?;
        u64::try_from(stripe_prefix_count)
            .ok()
            .and_then(|count| count.checked_add(u64::from(include_original_len)))
            .and_then(|count| count.checked_mul(size_of::<u32>() as u64))
            .and_then(|prefix| prefix.checked_add(ShardHeader::SIZE as u64))
            .and_then(|header| header.checked_add(payload_size))
            .ok_or_else(|| EraError::InvalidConfig("calculated shard write size overflow".into()))
    }

    /// Write a shard to its designated volume without spilling or rotating.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if no volumes are available, the shard size exceeds
    /// `MAX_SHARD_SIZE` or the maximum per-volume capacity, or the shard size exceeds `u32`.
    /// Returns `InvalidConfig` if the calculated write size overflows.
    /// Returns `VolumeSpaceExhausted` if the complete write cannot fit a fresh volume.
    /// Returns `InvalidConfig` if a required rotation would exceed the manifest's volume limit.
    /// Returns I/O errors from writing to the storage backend.
    ///
    /// # Arguments
    /// * `shard_idx` - The shard index (0..total_shards)
    /// * `shard_data` - The shard data to write
    /// * `include_original_len_header` - Optional 4-byte original length header (for first shard per volume per block)
    ///
    /// # Returns
    /// A `MatrixShardEntry` containing the location information.
    pub async fn write_shard(
        &mut self,
        shard_idx: usize,
        shard_data: &[u8],
        include_original_len_header: bool,
        original_len: u32,
        stripe_lengths: Option<&[u32]>,
    ) -> Result<(MatrixShardEntry, VolumeId)> {
        let slot = self.shard_volume_slot(shard_idx)?;
        let shard_len_u32 = u32::try_from(shard_data.len()).map_err(|_| {
            era_common::EraError::InvalidConfig(format!(
                "shard size {} exceeds u32",
                shard_data.len()
            ))
        })?;
        let total_size = self.shard_disk_size(
            u64::from(shard_len_u32),
            stripe_lengths.map_or(0, <[u32]>::len),
            include_original_len_header,
        )?;
        if !self.volume_can_fit(slot, total_size) {
            return Err(EraError::VolumeSpaceExhausted {
                volume: slot,
                required: total_size,
                available: self.volume_remaining_space(slot),
                message: "shard does not fit its preferred volume slot".into(),
            });
        }

        let writer = &mut self.writers[slot];
        let volume_sequence = self.sequences[slot];
        let volume_id = writer.volume_id();

        // P8-01: Coalesce metadata writes into a single buffer to reduce syscall
        // amplification. Previously N+3 separate write_raw() calls per shard (N stripe
        // lengths + original_len + shard_header + shard_data). Now 2 calls: one for
        // the coalesced header buffer, one for shard data.
        let header_capacity = stripe_lengths.map_or(0, std::mem::size_of_val)
            + if include_original_len_header {
                size_of::<u32>()
            } else {
                0
            }
            + ShardHeader::SIZE;
        let mut header_buf = Vec::with_capacity(header_capacity);

        // Append stripe data lengths
        if let Some(lengths) = stripe_lengths {
            for len in lengths {
                header_buf.extend_from_slice(&len.to_le_bytes());
            }
        }

        // Append original length header if needed
        if include_original_len_header {
            header_buf.extend_from_slice(&original_len.to_le_bytes());
        }

        // Compute CRC and append shard header
        let crc = compute_shard_crc(shard_data);
        let shard_header = ShardHeader::new(shard_len_u32, crc);
        header_buf.extend_from_slice(&shard_header.to_bytes());

        // Write coalesced header (1 syscall) then shard data (1 syscall)
        let buf_start = writer.write_raw(&header_buf).await?;
        writer.write_raw(shard_data).await?;

        // physical_offset must point to the ShardHeader within the buffer,
        // because readers expect to find ShardHeader at this offset.
        debug_assert!(
            header_buf.len() >= ShardHeader::SIZE,
            "header_buf too small for ShardHeader: {} < {}",
            header_buf.len(),
            ShardHeader::SIZE
        );
        let shard_header_offset = buf_start + (header_buf.len() - ShardHeader::SIZE) as u64;

        // Update stats
        self.stats.total_bytes_written += total_size;
        self.stats.total_shards_written += 1;

        Ok((
            MatrixShardEntry::new(volume_sequence, shard_header_offset, shard_len_u32, crc),
            volume_id,
        ))
    }

    /// Write a canonical block (BlockHeader format) to the pool.
    ///
    /// This method writes blocks using the BlockHeader format (16 bytes)
    /// instead of the ShardHeader format (8 bytes).
    ///
    /// # Errors
    /// Returns `InvalidConfig` if the block data exceeds `MAX_SHARD_SIZE` or `u32::MAX`.
    /// Returns `VolumeSpaceExhausted` if the complete write cannot fit a fresh volume.
    /// Triggers volume rotation (which may fail) if all volumes are full.
    /// Returns I/O errors from writing to the storage backend.
    ///
    /// # Arguments
    /// * `block` - The encrypted block to write
    /// * `block_type` - The type of block (Data, Catalog, etc.)
    ///
    /// # Returns
    /// A `BlockLocation` containing the location information.
    pub async fn write_canonical_block(
        &mut self,
        block: &EncryptedMacroBlock,
        block_type: BlockType,
    ) -> Result<(BlockLocation, VolumeId)> {
        let total_size = Self::canonical_block_disk_size(block.data.len())?;
        let (slot, _) = self.select_canonical_volume(total_size).await?;
        self.write_canonical_block_to_slot(slot, block, block_type)
            .await
    }

    /// Select a canonical target by exact on-disk size, rotating at most once.
    ///
    /// The size must include both the sealed payload and [`BlockHeader`]. The
    /// returned slot remains stable until the matching slot write; its actual
    /// volume sequence is returned for callers whose AEAD context binds it.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if the pool has no writers, or
    /// `VolumeSpaceExhausted` before rotation if the block cannot fit a fresh
    /// volume. Rotation and writer creation errors are also propagated.
    pub async fn select_canonical_volume(&mut self, on_disk_size: u64) -> Result<(usize, u16)> {
        if self.writers.is_empty() {
            return Err(era_common::EraError::InvalidConfig(
                "no writable volumes available for canonical block selection".into(),
            ));
        }

        let start_slot = self.active_canonical_slot.min(self.writers.len() - 1);
        let found_slot = (start_slot..self.writers.len())
            .find(|&candidate| self.volume_can_fit(candidate, on_disk_size));
        let slot = match found_slot {
            Some(slot) => slot,
            None => {
                self.check_fresh_volume_space(0, on_disk_size)?;
                self.rotate_volumes().await?;
                0
            }
        };
        self.active_canonical_slot = slot;

        let sequence = self.volume_sequence(slot).ok_or_else(|| {
            era_common::EraError::InvalidConfig(format!(
                "missing volume sequence for selected canonical slot {slot}"
            ))
        })?;
        Ok((slot, sequence))
    }

    /// Write a canonical block to a previously selected slot without reselecting.
    ///
    /// # Errors
    /// Returns `VolumeSpaceExhausted` if the exact block no longer fits the
    /// selected slot. No other slot or generation is tried. Writer validation
    /// and I/O errors are also propagated.
    pub async fn write_canonical_block_to_slot(
        &mut self,
        slot: usize,
        block: &EncryptedMacroBlock,
        block_type: BlockType,
    ) -> Result<(BlockLocation, VolumeId)> {
        let total_size = Self::canonical_block_disk_size(block.data.len())?;
        if !self.volume_can_fit(slot, total_size) {
            return Err(era_common::EraError::VolumeSpaceExhausted {
                volume: slot,
                required: total_size,
                available: self.volume_remaining_space(slot),
                message: "canonical block does not fit the selected volume slot".into(),
            });
        }

        let writer = self.writers.get_mut(slot).ok_or_else(|| {
            era_common::EraError::InvalidConfig(format!(
                "selected canonical volume slot {slot} does not exist"
            ))
        })?;
        let volume_id = writer.volume_id();
        let location = writer.write_canonical_block(block, block_type).await?;

        self.stats.total_bytes_written += total_size;
        self.stats.total_blocks_written += 1;

        Ok((location, volume_id))
    }

    fn canonical_block_disk_size(payload_len: usize) -> Result<u64> {
        let payload_size = u64::try_from(payload_len).map_err(|_| {
            era_common::EraError::InvalidConfig("canonical payload length exceeds u64".into())
        })?;
        payload_size
            .checked_add(BlockHeader::SIZE as u64)
            .ok_or_else(|| {
                era_common::EraError::InvalidConfig("canonical block disk size overflow".into())
            })
    }

    /// Write a complete erasure-coded block with matrix distribution.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if the shard size exceeds `MAX_SHARD_SIZE` or the maximum
    /// per-volume capacity.
    /// Returns errors from [`write_shard`](Self::write_shard) for each individual shard write.
    /// Returns I/O errors from the storage backend.
    ///
    /// # Arguments
    /// * `block_id` - The block ID
    /// * `shards` - Vector of shard data (indexed 0..total_shards)
    /// * `original_len` - Original data length before erasure encoding
    /// * `erasure_config` - Erasure configuration
    ///
    /// # Returns
    /// A `MatrixBlockLocation` containing all shard locations.
    pub async fn write_erasure_block(
        &mut self,
        block_id: era_common::BlockId,
        shards: &[bytes::Bytes],
        original_len: u32,
        erasure_config: ErasureCodeConfig,
    ) -> Result<MatrixBlockLocation> {
        let mut per_slot_bytes = vec![0u64; self.writers.len()];
        let mut original_len_headers = Vec::with_capacity(shards.len());
        for (shard_idx, shard_data) in shards.iter().enumerate() {
            let slot = self.shard_volume_slot(shard_idx)?;
            let need_header = per_slot_bytes[slot] == 0;
            let size = self.shard_disk_size(shard_data.len() as u64, 0, need_header)?;
            per_slot_bytes[slot] = per_slot_bytes[slot].checked_add(size).ok_or_else(|| {
                EraError::InvalidConfig("stripe disk size overflow for volume slot".into())
            })?;
            original_len_headers.push(need_header);
        }
        self.ensure_stripe_capacity(&per_slot_bytes).await?;

        let mut location = MatrixBlockLocation::new(
            block_id,
            self.block_sequence,
            erasure_config.data_shards,
            erasure_config.parity_shards,
            original_len,
        );

        for (shard_idx, (shard_data, need_header)) in
            shards.iter().zip(original_len_headers).enumerate()
        {
            let (entry, _) = self
                .write_shard(shard_idx, shard_data, need_header, original_len, None)
                .await?;
            location.add_shard(entry);
        }

        // Increment block sequence for next block (consistent with write_canonical_block path)
        self.advance_block_sequence();

        Ok(location)
    }

    fn install_final_volume_count(&mut self) -> Result<()> {
        let count = checked_manifest_volume_count(self.retired_volumes.len() + self.writers.len())?;
        for (_, retired) in &mut self.retired_volumes {
            retired.header.set_total_volumes(count);
        }
        for writer in &mut self.writers {
            writer.update_total_volumes(count);
        }
        Ok(())
    }

    /// Install the final count and digest all finalized headers in volume-sequence order.
    /// Call after the last possible rotation and before encrypting manifest replicas.
    /// Retired headers come from the same snapshots used by finalization; no files are opened.
    ///
    /// # Errors
    /// Returns an error for an invalid volume count, noncontiguous sequences, or an
    /// unencodable header.
    pub fn finalized_volume_header_digests(&mut self) -> Result<Vec<[u8; 32]>> {
        self.install_final_volume_count()?;
        self.retired_volumes
            .iter()
            .map(|(_, state)| {
                (
                    state.header.volume_sequence(),
                    superheader_digest(&state.header),
                )
            })
            .chain(self.writers.iter().map(|writer| {
                (writer.volume_sequence(), writer.finalized_header_digest())
            }))
            .enumerate()
            .map(|(expected, (sequence, digest))| {
                if expected != usize::from(sequence) {
                    return Err(EraError::InvalidConfig(format!(
                        "expected volume sequence {expected} while building header digest table, found {sequence}"
                    )));
                }
                digest
            })
            .collect()
    }

    /// Finalize all volumes.
    ///
    /// # Errors
    /// Returns `Serialization` if any volume's header or footer cannot be encoded.
    /// Returns I/O errors from finalizing volumes on the storage backend.
    pub async fn finalize(&mut self) -> Result<VolumePoolStats> {
        self.finalize_with_catalog(0, 0, 0, 0, 0, 0).await
    }

    /// Finalize all volumes with the same catalog information on active volumes.
    ///
    /// This method broadcasts the same catalog offset to all active volumes. This is appropriate
    /// when using a single catalog location shared across all volumes (the typical case).
    ///
    /// For per-volume catalog locations, use [`Self::finalize_with_catalogs`] instead.
    ///
    /// # Cancellation Safety
    ///
    /// Once finalization takes the writers, the pool is terminal, including on
    /// cancellation or I/O failure. A subsequent finalize returns `InvalidConfig`.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if catalog or index offsets exceed a volume's write position.
    /// Returns `Serialization` if any volume's header or footer cannot be encoded.
    /// Returns I/O errors from finalizing volumes on the storage backend.
    pub async fn finalize_with_catalog(
        &mut self,
        catalog_offset: u64,
        catalog_size: u32,
        catalog_block_id: u32,
        index_offset: u64,
        index_size: u32,
        index_block_id: u32,
    ) -> Result<VolumePoolStats> {
        let catalogs = vec![(catalog_offset, catalog_size, catalog_block_id); self.writers.len()];
        let indexes = vec![(index_offset, index_size, index_block_id); self.writers.len()];
        self.finalize_with_catalogs(&catalogs, Some(&indexes)).await
    }

    /// Finalize all volumes with per-volume catalog information.
    ///
    /// # Cancellation Safety
    ///
    /// Same as [`Self::finalize_with_catalog`].
    ///
    /// # Errors
    /// Returns `InvalidConfig` if `catalog_locations` or `index_locations` length does
    /// not match the number of active writers.
    /// Returns `Serialization` if any volume's header or footer cannot be encoded.
    /// Returns I/O errors from finalizing volumes on the storage backend.
    pub async fn finalize_with_catalogs(
        &mut self,
        catalog_locations: &[(u64, u32, u32)],
        index_locations: Option<&[(u64, u32, u32)]>,
    ) -> Result<VolumePoolStats> {
        self.finalize_with_catalogs_and_manifest(catalog_locations, index_locations, None)
            .await
    }

    /// Finalize all volumes with per-volume catalog, index, and manifest information.
    ///
    /// # Cancellation Safety
    ///
    /// Same as [`Self::finalize_with_catalog`]. Retired volumes are finalized
    /// before any active volume publishes the new manifest in its footer.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if `catalog_locations`, `index_locations`, or
    /// `manifest_locations` length does not match the number of active writers.
    /// Returns `Serialization` if any volume's header or footer cannot be encoded.
    /// Returns I/O errors from finalizing volumes on the storage backend.
    pub async fn finalize_with_catalogs_and_manifest(
        &mut self,
        catalog_locations: &[(u64, u32, u32)],
        index_locations: Option<&[(u64, u32, u32)]>,
        manifest_locations: Option<&[(u64, u32, u32)]>,
    ) -> Result<VolumePoolStats> {
        let volume_count = self.writers.len();
        if catalog_locations.len() != volume_count {
            return Err(era_common::EraError::InvalidConfig(format!(
                "catalog_locations length {} does not match volume count {}",
                catalog_locations.len(),
                volume_count
            )));
        }

        if let Some(idx) = index_locations {
            if idx.len() != volume_count {
                return Err(era_common::EraError::InvalidConfig(format!(
                    "index_locations length {} does not match volume count {}",
                    idx.len(),
                    volume_count
                )));
            }
        }

        if let Some(manifest) = manifest_locations {
            if manifest.len() != volume_count {
                return Err(era_common::EraError::InvalidConfig(format!(
                    "manifest_locations length {} does not match volume count {}",
                    manifest.len(),
                    volume_count
                )));
            }
            for (i, (manifest_offset, _, _)) in manifest.iter().copied().enumerate() {
                let writer_position = self.writers[i].current_size();
                if manifest_offset > writer_position {
                    return Err(era_common::EraError::InvalidConfig(format!(
                        "manifest offset {} exceeds current writer position {} for volume slot {}",
                        manifest_offset, writer_position, i
                    )));
                }
            }
        }

        self.install_final_volume_count()?;
        let mut stats = std::mem::take(&mut self.stats);

        let defer_retired_for_append = !self.append_start_positions.is_empty();
        let retired_volumes = std::mem::take(&mut self.retired_volumes);
        let old_sequences: Vec<u16> = std::mem::take(&mut self.sequences);
        let writers: Vec<_> = std::mem::take(&mut self.writers);

        if !defer_retired_for_append {
            for (seq, state) in retired_volumes {
                let volume_path = self.config.volume_path(seq);
                let volume_filename = extract_filename(&volume_path)?;
                let writer = VolumeWriter::reopen_for_finalize(
                    &self.backend,
                    Path::new(volume_filename),
                    state,
                )
                .await?;
                writer.finalize().await?;
            }

            for (i, mut writer) in writers.into_iter().enumerate() {
                let size = writer.current_size();
                let sequence = old_sequences[i];
                stats.volume_sizes.push((sequence, size));
                let (offset, size_u32, block_id) = catalog_locations[i];
                let (idx_offset, idx_size, idx_block_id) =
                    index_locations.map_or((0, 0, 0), |idx| idx[i]);
                if let Some(manifest) = manifest_locations {
                    let (manifest_offset, _manifest_size, manifest_block_id) = manifest[i];
                    writer.set_manifest_info(manifest_offset, manifest_block_id)?;
                }
                writer
                    .finalize_with_catalog(
                        offset,
                        size_u32,
                        block_id,
                        idx_offset,
                        idx_size,
                        idx_block_id,
                    )
                    .await?;
            }
        } else {
            // In append sessions that rotated, finalize the newly created volumes first so
            // any failure leaves the original retired volume(s) untouched on disk.
            for (i, mut writer) in writers.into_iter().enumerate() {
                let size = writer.current_size();
                let sequence = old_sequences[i];
                stats.volume_sizes.push((sequence, size));
                let (offset, size_u32, block_id) = catalog_locations[i];
                let (idx_offset, idx_size, idx_block_id) =
                    index_locations.map_or((0, 0, 0), |idx| idx[i]);
                if let Some(manifest) = manifest_locations {
                    let (manifest_offset, _manifest_size, manifest_block_id) = manifest[i];
                    writer.set_manifest_info(manifest_offset, manifest_block_id)?;
                }
                writer
                    .finalize_with_catalog(
                        offset,
                        size_u32,
                        block_id,
                        idx_offset,
                        idx_size,
                        idx_block_id,
                    )
                    .await?;
            }

            for (seq, state) in retired_volumes {
                let volume_path = self.config.volume_path(seq);
                let volume_filename = extract_filename(&volume_path)?;
                let mut writer = VolumeWriter::reopen_for_finalize(
                    &self.backend,
                    Path::new(volume_filename),
                    state,
                )
                .await?;
                // A retired append volume can still point at a manifest for its old header.
                writer.set_manifest_info(0, 0)?;
                writer.finalize().await?;
            }
        }

        self.uncommitted_rotated_files.clear();
        Ok(stats)
    }

    /// Get current statistics.
    #[must_use]
    pub fn stats(&self) -> &VolumePoolStats {
        &self.stats
    }

    /// Get a mutable reference to a specific volume writer.
    ///
    /// This is useful for writing non-erasure blocks (like catalog) directly.
    pub fn get_writer_mut(&mut self, slot: usize) -> Option<&mut VolumeWriter<B::Writer>> {
        self.writers.get_mut(slot)
    }

    /// Get the sequence number for a volume slot.
    #[must_use]
    pub fn volume_sequence(&self, slot: usize) -> Option<u16> {
        self.sequences.get(slot).copied()
    }

    /// Get the volume sequence for the next canonical block write target.
    #[must_use]
    pub fn next_canonical_volume_sequence(&self) -> Option<u16> {
        self.sequences.get(self.active_canonical_slot).copied()
    }

    /// Add a new volume to the pool.
    ///
    /// This is called when all existing volumes are full and more space is needed.
    /// The new volume will use the next available sequence number.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if the sequence number or total volume count exceeds `u16`,
    /// or if the volume path has no filename.
    /// Returns `Serialization` if the header cannot be encoded.
    /// Returns I/O errors from creating the volume on the storage backend.
    pub async fn add_volume(&mut self, backend: &B) -> Result<usize> {
        let new_sequence = u16::try_from(self.writers.len()).map_err(|_| {
            era_common::EraError::InvalidConfig("too many volumes for u16 sequence".into())
        })?;

        let mut header = self.template_header.clone();
        // CV32-01: Each volume must have a unique volume_id for identification in the reader's HashMap.
        // Without this, add_volume() would reuse the template's volume_id, causing collisions.
        header.set_volume_id(VolumeId::new());
        header.set_volume_sequence(new_sequence);
        header.set_total_volumes(u16::try_from(self.writers.len() + 1).map_err(|_| {
            era_common::EraError::InvalidConfig("total volumes exceeds u16".into())
        })?);

        let volume_path = self.config.volume_path(new_sequence);
        let volume_filename = extract_filename(&volume_path)?;

        let writer = VolumeWriter::create(backend, Path::new(volume_filename), header).await?;

        let slot = self.writers.len();
        self.writers.push(writer);
        self.sequences.push(new_sequence);
        self.stats.volume_count += 1;

        debug_assert_eq!(
            self.writers.len(),
            self.sequences.len(),
            "writers/sequences length mismatch after add_volume"
        );
        Ok(slot)
    }

    /// Check if the pool needs more volumes to write additional data.
    /// Returns `false` if data fits in an existing volume.
    /// Returns `true` if data needs a new volume but could fit.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if the required size exceeds the maximum per-volume capacity.
    pub fn needs_expansion(&self, required_size: u64) -> Result<bool> {
        // First check if the data is inherently too large for any single volume
        // Must match volume_can_fit() reservation: structural overhead + minimum block metadata
        let reserved = super::PER_VOLUME_OVERHEAD;
        let max_per_volume = self.config.max_volume_size.saturating_sub(reserved);
        if required_size > max_per_volume {
            return Err(era_common::EraError::InvalidConfig(format!(
                "required size {} exceeds maximum per-volume capacity {}",
                required_size, max_per_volume
            )));
        }

        // Check if any volume can fit the data
        for slot in 0..self.writers.len() {
            if self.volume_can_fit(slot, required_size) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Get total remaining space across all volumes.
    #[must_use]
    pub fn total_remaining_space(&self) -> u64 {
        (0..self.writers.len())
            .map(|slot| self.volume_remaining_space(slot))
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccessPolicy, EncryptedVolumeKey, KeyWrapAlgorithm, RecipientSlot, RecipientType};
    use bytes::Bytes;
    use era_common::{ArchiveConfig, ArchiveId, BlockId, EraError};
    use era_storage::LocalStorageBackend;
    use tempfile::TempDir;

    fn create_test_header() -> SuperHeader {
        SuperHeader::new(
            ArchiveId::new(),
            vec![RecipientSlot::new(
                RecipientType::Argon2idPassword,
                Some([0x12; 8]),
                vec![0xAB; 16],
                vec![0xCD; 48],
            )],
            ArchiveConfig::default(),
            [0u8; 16],
            EncryptedVolumeKey::new(
                KeyWrapAlgorithm::XChaCha20Poly1305,
                [0u8; 24],
                vec![0u8; 48],
            ),
            AccessPolicy::AnyOfN,
        )
        .unwrap()
    }

    impl VolumePool<LocalStorageBackend> {
        async fn write_to_current(&mut self, data: &[u8]) -> era_common::Result<()> {
            let data_len = u32::try_from(data.len()).expect("test data fits in u32");
            let block = EncryptedMacroBlock {
                block_id: BlockId::new(0),
                data: Bytes::copy_from_slice(data),
                original_size: data_len,
                compressed_size: data_len,
                chunk_count: 1,
            };

            self.write_canonical_block(&block, BlockType::Data)
                .await
                .map(|_| ())
        }
    }

    #[tokio::test]
    async fn append_rejects_cap_below_retained_volume_plus_trailer_without_truncating() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let config = VolumePoolConfig::new(temp_dir.path().join("test_archive"), 1);
        let path = config.volume_path(0);
        let mut pool = VolumePool::create(backend.clone(), config.clone(), create_test_header())
            .await
            .unwrap();
        pool.write_to_current(&vec![0x42; 32 * 1024]).await.unwrap();
        pool.finalize().await.unwrap();

        let original = tokio::fs::read(&path).await.unwrap();
        let reader = VolumeReader::open(&backend, Path::new(path.file_name().unwrap()))
            .await
            .unwrap();
        let header = reader.header().clone();
        let footer = reader.footer().unwrap();
        let retained_end = footer.data_end_offset();
        let finalized_size = u64::try_from(original.len()).unwrap();
        let config = config.with_max_size(finalized_size - 1);

        let result = VolumePool::open_append_single(
            backend.clone(),
            config.clone(),
            header.clone(),
            footer,
            vec![crate::DATA_REGION_START],
        )
        .await;
        assert!(matches!(result, Err(EraError::InvalidConfig(_))));
        assert!(tokio::fs::read(&path).await.unwrap() == original);

        let result = VolumePool::open_append(backend.clone(), config.clone(), header.clone()).await;
        assert!(matches!(result, Err(EraError::InvalidConfig(_))));
        assert!(tokio::fs::read(&path).await.unwrap() == original);

        let mut pool = VolumePool::open_append(
            backend.clone(),
            config.with_max_size(finalized_size),
            header.clone(),
        )
        .await
        .unwrap();
        pool.finalize().await.unwrap();

        let finalized = tokio::fs::read(&path).await.unwrap();
        assert_eq!(u64::try_from(finalized.len()).unwrap(), finalized_size);
        let data_start = usize::try_from(crate::DATA_REGION_START).unwrap();
        let data_end = usize::try_from(retained_end).unwrap();
        assert!(finalized[data_start..data_end] == original[data_start..data_end]);

        let footer_start = finalized.len() - crate::FOOTER_SIZE;
        let primary_footer = crate::Footer::from_bytes(&finalized[footer_start..]).unwrap();
        let backup_footer =
            crate::Footer::from_bytes(&finalized[crate::HEADER_SIZE..data_start]).unwrap();
        assert_eq!(primary_footer, backup_footer);
        assert_eq!(
            primary_footer.sequence_number(),
            footer.sequence_number() + 1
        );
        assert_eq!(primary_footer.data_end_offset(), retained_end);
        assert_eq!(primary_footer.backup_header_offset(), retained_end);
        for bytes in [
            &finalized[..crate::HEADER_SIZE],
            &finalized[data_end..footer_start],
        ] {
            let finalized_header = SuperHeader::from_bytes(bytes).unwrap();
            assert_eq!(finalized_header.volume_id(), header.volume_id());
        }
    }

    #[tokio::test]
    async fn test_committed_ends_empty_pool() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_path = temp_dir.path().join("test_archive");
        let config = VolumePoolConfig::new(&base_path, 1);
        let header = create_test_header();
        let pool = VolumePool::create(backend, config, header).await.unwrap();

        let ends = pool.committed_ends();
        assert_eq!(ends.len(), 1);
        assert_eq!(ends[0].0, 0);
        assert_eq!(ends[0].1, crate::DATA_REGION_START);
    }

    #[tokio::test]
    async fn test_committed_ends_after_writes() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_path = temp_dir.path().join("test_archive");
        let config = VolumePoolConfig::new(&base_path, 1);
        let header = create_test_header();
        let mut pool = VolumePool::create(backend, config, header).await.unwrap();

        let data = vec![0u8; 1024];
        pool.write_to_current(&data).await.unwrap();

        let ends = pool.committed_ends();
        assert_eq!(ends.len(), 1);
        assert_eq!(ends[0].0, 0);
        assert!(ends[0].1 > crate::DATA_REGION_START);
    }

    #[tokio::test]
    async fn test_committed_ends_after_rotation() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_path = temp_dir.path().join("test_archive");
        let mut config = VolumePoolConfig::new(&base_path, 1);
        config.max_volume_size = 16_000;
        let header = create_test_header();
        let mut pool = VolumePool::create(backend, config, header).await.unwrap();

        let data = vec![0u8; 4096];
        for _ in 0..2 {
            pool.write_to_current(&data).await.unwrap();
        }

        let ends = pool.committed_ends();
        assert_eq!(ends.len(), 2);
        assert_eq!(ends[0].0, 0);
        assert_eq!(ends[1].0, 1);
    }

    #[tokio::test]
    async fn finalized_digest_table_binds_retired_and_active_header_bytes() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let mut config = VolumePoolConfig::new(temp_dir.path().join("header-digests"), 1);
        config.max_volume_size = 16_000;
        let mut pool = VolumePool::create(backend.clone(), config.clone(), create_test_header())
            .await
            .unwrap();
        for _ in 0..2 {
            pool.write_to_current(&[0; 4096]).await.unwrap();
        }

        let table = pool.finalized_volume_header_digests().unwrap();
        pool.finalize_with_catalogs(&[(0, 0, 0)], None)
            .await
            .unwrap();

        assert_eq!(table.len(), 2);
        for seq in 0..2 {
            let path = config.volume_path(seq);
            let reader = VolumeReader::open(&backend, Path::new(path.file_name().unwrap()))
                .await
                .unwrap();
            assert_eq!(reader.header().total_volumes(), 2);
            assert_eq!(reader.header().volume_sequence(), seq);
            let primary = reader.read_raw(0, crate::HEADER_SIZE).await.unwrap();
            let backup = reader
                .read_raw(
                    reader.footer().unwrap().backup_header_offset(),
                    crate::HEADER_SIZE,
                )
                .await
                .unwrap();
            assert_eq!(primary, backup);
            assert_eq!(table[usize::from(seq)], *blake3::hash(&primary).as_bytes());
        }
    }

    #[tokio::test]
    async fn test_committed_ends_sorted_by_sequence() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_path = temp_dir.path().join("test_archive");
        let mut config = VolumePoolConfig::new(&base_path, 1);
        config.max_volume_size = 12_000;
        let header = create_test_header();
        let mut pool = VolumePool::create(backend, config, header).await.unwrap();

        for _ in 0..3 {
            let data = vec![0u8; 2048];
            pool.write_to_current(&data).await.unwrap();
        }

        let ends = pool.committed_ends();
        for i in 1..ends.len() {
            assert!(ends[i].0 > ends[i - 1].0, "Sequences should be sorted");
        }
    }

    #[tokio::test]
    async fn test_committed_ends_no_duplicates() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_path = temp_dir.path().join("test_archive");
        let mut config = VolumePoolConfig::new(&base_path, 1);
        config.max_volume_size = 12_000;
        let header = create_test_header();
        let mut pool = VolumePool::create(backend, config, header).await.unwrap();

        for _ in 0..2 {
            let data = vec![0u8; 2048];
            pool.write_to_current(&data).await.unwrap();
        }

        let ends = pool.committed_ends();
        let mut seen = std::collections::HashSet::new();
        for (seq, _) in &ends {
            assert!(!seen.contains(seq), "Duplicate sequence found: {seq}");
            seen.insert(*seq);
        }
    }

    #[tokio::test]
    async fn test_volume_pool_creation() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_path = temp_dir.path().join("test_archive");

        let config = VolumePoolConfig::new(&base_path, 3);
        let header = create_test_header();

        let pool = VolumePool::create(backend, config, header).await.unwrap();

        assert_eq!(pool.volume_count(), 3);
        assert_eq!(pool.block_sequence(), 0);
    }

    #[tokio::test]
    async fn test_matrix_distribution_shard_placement() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_path = temp_dir.path().join("test_archive");

        let erasure = ErasureCodeConfig::new(4, 2);
        let config = VolumePoolConfig::new(&base_path, 3).for_erasure(erasure);
        let header = create_test_header();

        let mut pool = VolumePool::create(backend, config, header).await.unwrap();

        // Create test shards
        let shards: Vec<Bytes> = (0..6).map(|i| Bytes::from(vec![i as u8; 1024])).collect();

        // Write first block
        let block_id = BlockId::new(0);
        let location = pool
            .write_erasure_block(block_id, &shards, 4096, erasure)
            .await
            .unwrap();

        assert!(location.is_complete());
        assert_eq!(location.shards.len(), 6);
    }

    #[tokio::test]
    async fn test_volume_pool_finalizes_all_three_generations() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_path = temp_dir.path().join("test_archive");

        let config = VolumePoolConfig::new(&base_path, 2).with_max_size(80_000);
        let mut pool = VolumePool::create(backend, config.clone(), create_test_header())
            .await
            .unwrap();
        let mut expected_ends = Vec::new();
        for sequence in 0..6u16 {
            let payload = vec![0; 40_000 + usize::from(sequence)];
            pool.write_to_current(&payload).await.unwrap();
            let end = crate::DATA_REGION_START
                + u64::try_from(BlockHeader::SIZE + payload.len()).unwrap();
            expected_ends.push((sequence, end));
        }
        assert_eq!(pool.committed_ends(), expected_ends);

        let stats = pool.finalize().await.unwrap();
        assert_eq!(stats.volume_count, 6);
        assert_eq!(stats.volume_sizes, expected_ends);
        for (sequence, _) in expected_ends {
            let bytes = tokio::fs::read(config.volume_path(sequence)).await.unwrap();
            let footer_start = bytes.len() - crate::FOOTER_SIZE;
            let footer = crate::Footer::from_bytes(&bytes[footer_start..]).unwrap();
            let backup = usize::try_from(footer.backup_header_offset()).unwrap();
            let front_footer = &bytes[crate::HEADER_SIZE..crate::HEADER_SIZE + crate::FOOTER_SIZE];
            assert_eq!(front_footer, &bytes[footer_start..]);
            assert_eq!(footer.block_count(), 1);
            for header_bytes in [&bytes[..crate::HEADER_SIZE], &bytes[backup..footer_start]] {
                let header = SuperHeader::from_bytes(header_bytes).unwrap();
                assert_eq!(header.volume_sequence(), sequence);
                assert_eq!(header.total_volumes(), 6, "volume {sequence}");
            }
        }
    }

    #[tokio::test]
    async fn test_canonical_selection_exact_fit_rotates_once_for_next_block() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let config = VolumePoolConfig::new(temp_dir.path().join("exact"), 1).with_max_size(25_000);
        let available =
            config.max_volume_size - crate::DATA_REGION_START - crate::PER_VOLUME_OVERHEAD;
        let exact_payload_len = usize::try_from(available)
            .unwrap()
            .checked_sub(BlockHeader::SIZE)
            .unwrap();
        let exact_block = EncryptedMacroBlock {
            block_id: BlockId::new(7),
            data: Bytes::from(vec![0x5A; exact_payload_len]),
            original_size: u32::try_from(exact_payload_len).unwrap(),
            compressed_size: u32::try_from(exact_payload_len).unwrap(),
            chunk_count: 1,
        };
        let mut pool = VolumePool::create(backend, config.clone(), create_test_header())
            .await
            .unwrap();

        let (slot, sequence) = pool.select_canonical_volume(available).await.unwrap();
        assert_eq!((slot, sequence), (0, 0));
        let (location, _) = pool
            .write_canonical_block_to_slot(slot, &exact_block, BlockType::Data)
            .await
            .unwrap();
        assert_eq!(location.physical_offset, crate::DATA_REGION_START);
        assert_eq!(
            usize::try_from(location.encrypted_size).unwrap(),
            exact_payload_len
        );

        let next_block = EncryptedMacroBlock {
            block_id: BlockId::new(8),
            data: Bytes::from(vec![0xA5; 32]),
            original_size: 32,
            compressed_size: 32,
            chunk_count: 1,
        };
        let next_size = BlockHeader::SIZE as u64 + next_block.data.len() as u64;
        let (slot, sequence) = pool.select_canonical_volume(next_size).await.unwrap();
        assert_eq!((slot, sequence), (0, 1));
        let (location, _) = pool
            .write_canonical_block_to_slot(slot, &next_block, BlockType::Data)
            .await
            .unwrap();
        assert_eq!(location.physical_offset, crate::DATA_REGION_START);

        assert_eq!(
            pool.committed_ends(),
            vec![
                (0, crate::DATA_REGION_START + available),
                (1, crate::DATA_REGION_START + next_size),
            ]
        );
        assert!(config.volume_path(1).exists());
        assert!(!config.volume_path(2).exists());
    }

    #[tokio::test]
    async fn test_canonical_selection_fresh_unfit_leaves_paths_and_generation_untouched() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let config =
            VolumePoolConfig::new(temp_dir.path().join("unfit-selection"), 1).with_max_size(25_000);
        let available =
            config.max_volume_size - crate::DATA_REGION_START - crate::PER_VOLUME_OVERHEAD;
        let mut pool = VolumePool::create(backend, config.clone(), create_test_header())
            .await
            .unwrap();
        let ends_before = pool.committed_ends();
        let paths_before: std::collections::BTreeSet<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();

        let err = pool
            .select_canonical_volume(available + 1)
            .await
            .expect_err("block must be rejected before creating a fresh generation");

        assert!(matches!(
            err,
            EraError::VolumeSpaceExhausted {
                volume: 0,
                required,
                available: actual,
                ..
            } if required == available + 1 && actual == available
        ));
        assert_eq!(pool.volume_sequence(0), Some(0));
        assert_eq!(pool.committed_ends(), ends_before);
        let paths_after: std::collections::BTreeSet<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(paths_after, paths_before);
        assert!(!config.volume_path(1).exists());
    }

    #[tokio::test]
    async fn test_typed_block_precheck_no_rotation_needed() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_path = temp_dir.path().join("typed_block_no_rotation");

        let config = VolumePoolConfig::new(&base_path, 1).with_max_size(100_000);
        let header = create_test_header();

        let mut pool = VolumePool::create(backend, config, header).await.unwrap();

        let rotated = pool
            .precheck_and_rotate_if_needed(1_024, 0, 0)
            .await
            .unwrap();

        assert!(!rotated);
        assert_eq!(pool.volume_sequence(0), Some(0));
    }

    #[tokio::test]
    async fn test_typed_block_precheck_triggers_rotation() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_path = temp_dir.path().join("typed_block_rotation");

        let config = VolumePoolConfig::new(&base_path, 1).with_max_size(100_000);
        let header = create_test_header();

        let mut pool = VolumePool::create(backend, config, header).await.unwrap();
        let total_per_volume = 50_000;

        {
            let writer = pool.get_writer_mut(0).expect("writer should exist");
            writer.write_raw(&vec![0u8; 50_000]).await.unwrap();
        }

        let rotated = pool
            .precheck_and_rotate_if_needed(50_000, 0, 0)
            .await
            .unwrap();

        assert!(rotated);
        assert_eq!(pool.volume_sequence(0), Some(1));
        assert!(pool.total_remaining_space() >= total_per_volume);
        assert!(pool.check_typed_block_space(total_per_volume).is_empty());
    }

    #[tokio::test]
    async fn test_typed_block_precheck_space_exhausted() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_path = temp_dir.path().join("typed_block_space_exhausted");

        let config = VolumePoolConfig::new(&base_path, 1).with_max_size(25_000);
        let header = create_test_header();

        let mut pool = VolumePool::create(backend, config, header).await.unwrap();
        let ends_before = pool.committed_ends();

        let err = pool
            .precheck_and_rotate_if_needed(50_000, 0, 0)
            .await
            .expect_err("request should exceed fresh volume capacity");

        match err {
            EraError::VolumeSpaceExhausted {
                volume,
                required,
                available,
                ..
            } => {
                assert_eq!(volume, 0);
                assert_eq!(required, 50_000);
                assert_eq!(available, pool.total_remaining_space());
            }
            other => panic!("expected VolumeSpaceExhausted, got {other:?}"),
        }
        assert_eq!(pool.committed_ends(), ends_before);
        assert!(!temp_dir
            .path()
            .join("typed_block_space_exhausted.era.001")
            .exists());
    }

    #[tokio::test]
    async fn test_unfit_data_writes_leave_volume_generation_intact() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let config = VolumePoolConfig::new(temp_dir.path().join("unfit"), 1).with_max_size(25_000);
        let available =
            config.max_volume_size - crate::DATA_REGION_START - crate::PER_VOLUME_OVERHEAD;
        let mut pool = VolumePool::create(backend, config.clone(), create_test_header())
            .await
            .unwrap();
        let payload = vec![0; usize::try_from(available).unwrap()];
        let ends_before = pool.committed_ends();

        let canonical = pool.write_to_current(&payload).await.unwrap_err();
        let shard = pool
            .write_shard(0, &payload, true, 0, Some(&[1, 2]))
            .await
            .unwrap_err();

        assert!(
            matches!(canonical, EraError::VolumeSpaceExhausted { available: actual, .. } if actual == available)
        );
        assert!(
            matches!(shard, EraError::VolumeSpaceExhausted { available: actual, .. } if actual == available)
        );
        assert_eq!(pool.committed_ends(), ends_before);
        assert!(!config.volume_path(1).exists());
    }

    #[tokio::test]
    async fn test_stripe_reservation_counts_colocated_frames_at_capacity_boundary() {
        let dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(dir.path());
        let frame_overhead = u32::try_from(4 * size_of::<u32>() + ShardHeader::SIZE).unwrap();
        let lengths = [10_001u32, 10_000, 10_000, 10_000, 10_002, 10_002];
        let available = u64::from(lengths[1] + lengths[4] + 2 * frame_overhead);
        let config = VolumePoolConfig::new(dir.path().join("stripe"), 3)
            .for_erasure(ErasureCodeConfig::new(4, 2))
            .with_max_size(crate::DATA_REGION_START + crate::PER_VOLUME_OVERHEAD + available);
        let mut pool = VolumePool::create(backend, config.clone(), create_test_header())
            .await
            .unwrap();

        let mut oversized = lengths;
        oversized[4] += 1;
        let original_ends = pool.committed_ends();
        assert!(matches!(
            pool.reserve_stripe(&oversized, 4).await,
            Err(EraError::VolumeSpaceExhausted { volume: 1, required, available: remaining, .. })
                if required == available + 1 && remaining == available
        ));
        assert_eq!(pool.committed_ends(), original_ends);
        assert!(!config.volume_path(3).exists());

        pool.get_writer_mut(1)
            .unwrap()
            .write_raw(&[0])
            .await
            .unwrap();
        assert_eq!(
            pool.reserve_stripe(&lengths, 4).await.unwrap(),
            [3, 4, 5, 3, 4, 5]
        );
        for (shard, length) in lengths.into_iter().enumerate() {
            let (entry, _) = pool
                .write_shard(
                    shard,
                    &vec![0; usize::try_from(length).unwrap()],
                    false,
                    0,
                    Some(&lengths[..4]),
                )
                .await
                .unwrap();
            assert_eq!(entry.volume_sequence, 3 + u16::try_from(shard % 3).unwrap());
        }
        assert_eq!(
            pool.committed_ends()[4],
            (4, crate::DATA_REGION_START + available)
        );
        assert!(matches!(
            pool.write_shard(1, &[], false, 0, Some(&lengths[..4]))
                .await,
            Err(EraError::VolumeSpaceExhausted {
                volume: 1,
                available: 0,
                ..
            })
        ));
        assert!(!config.volume_path(6).exists());
        assert_eq!(pool.stats().total_shards_written, 6);
    }

    #[tokio::test]
    async fn test_manifest_volume_bound_rejects_create_and_rotation_before_allocating() {
        let backend = era_storage::MemoryStorageBackend::new();
        let config = VolumePoolConfig::new("too_many", MAX_MANIFEST_VOLUMES + 1);
        assert!(matches!(
            VolumePool::create(backend.clone(), config.clone(), create_test_header()).await,
            Err(EraError::InvalidConfig(_))
        ));
        assert!(!backend.exists(&config.volume_path(0)).await);

        let config = VolumePoolConfig::new("bound", MAX_MANIFEST_VOLUMES / 2);
        let mut pool = VolumePool::create(backend.clone(), config.clone(), create_test_header())
            .await
            .unwrap();
        pool.rotate_volumes().await.unwrap();
        let ends = pool.committed_ends();
        assert_eq!(ends.len(), MAX_MANIFEST_VOLUMES);
        assert!(matches!(
            pool.rotate_volumes().await,
            Err(EraError::InvalidConfig(_))
        ));
        assert!(
            !backend
                .exists(&config.volume_path(u16::try_from(MAX_MANIFEST_VOLUMES).unwrap()))
                .await
        );
        assert_eq!(pool.committed_ends(), ends);
    }

    #[tokio::test]
    async fn test_retired_finalize_failure_is_terminal_before_active_footer() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let config = VolumePoolConfig::new(temp_dir.path().join("failed"), 1);
        let mut pool = VolumePool::create(backend, config.clone(), create_test_header())
            .await
            .unwrap();
        pool.get_writer_mut(0)
            .unwrap()
            .set_max_size(0)
            .await
            .unwrap();
        pool.rotate_volumes().await.unwrap();

        assert!(
            matches!(pool.finalize().await, Err(EraError::InvalidConfig(msg)) if msg.contains("backup_header_offset"))
        );
        assert!(matches!(
            pool.finalize().await,
            Err(EraError::InvalidConfig(_))
        ));
        assert_eq!(
            tokio::fs::metadata(config.volume_path(1))
                .await
                .unwrap()
                .len(),
            crate::DATA_REGION_START
        );
    }

    // ── Iteration 26: Builder Pattern & Fluent API Safety Tests ──

    #[test]
    fn bp26_01_with_distribution_preserves_explicit_count() {
        let config =
            VolumePoolConfig::new("/tmp/test", 1).with_distribution(MatrixDistributionConfig {
                strategy: era_common::MatrixDistributionStrategy::RotatingOffset,
                min_volumes: 5,
                target_volumes: 8,
            });
        assert_eq!(config.initial_volume_count, 1);
        assert_eq!(config.distribution.min_volumes, 5);
    }

    /// BP26-01: with_distribution() preserves count when it already meets min_volumes.
    #[test]
    fn bp26_01_with_distribution_preserves_sufficient_count() {
        let config =
            VolumePoolConfig::new("/tmp/test", 10).with_distribution(MatrixDistributionConfig {
                strategy: era_common::MatrixDistributionStrategy::RotatingOffset,
                min_volumes: 3,
                target_volumes: 6,
            });
        // initial_volume_count was 10, min_volumes is 3 → no change
        assert_eq!(config.initial_volume_count, 10);
    }

    #[test]
    fn bp26_02_for_erasure_then_with_distribution_preserves_count() {
        let erasure = ErasureCodeConfig::new(4, 2);
        let config = VolumePoolConfig::new("/tmp/test", 1)
            .for_erasure(erasure)
            .with_distribution(MatrixDistributionConfig {
                strategy: era_common::MatrixDistributionStrategy::RotatingOffset,
                min_volumes: 8,
                target_volumes: 10,
            });
        assert_eq!(config.initial_volume_count, 1);
    }

    #[test]
    fn bp26_02_with_distribution_then_for_erasure_preserves_count() {
        let erasure = ErasureCodeConfig::new(4, 2);
        let config = VolumePoolConfig::new("/tmp/test", 1)
            .with_distribution(MatrixDistributionConfig {
                strategy: era_common::MatrixDistributionStrategy::RotatingOffset,
                min_volumes: 2,
                target_volumes: 4,
            })
            .for_erasure(erasure);
        assert_eq!(config.initial_volume_count, 1);
    }

    #[test]
    fn test_for_erasure_preserves_explicit_low_counts_for_4_plus_2() {
        let erasure = ErasureCodeConfig::new(4, 2);

        for count in [1usize, 2, 3] {
            let config = VolumePoolConfig::new("/tmp/test", count).for_erasure(erasure);
            assert_eq!(
                config.initial_volume_count, count,
                "explicit count {count} should be preserved"
            );
        }
    }

    #[tokio::test]
    async fn test_for_erasure_invalid_low_count_fails_canonical_validation() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_path = temp_dir.path().join("invalid_low");
        let erasure = ErasureCodeConfig::new(4, 2);
        let config = VolumePoolConfig::new(&base_path, 4).for_erasure(erasure);
        let header = create_test_header();

        let result = VolumePool::create(backend, config, header).await;
        assert!(
            result.is_err(),
            "4 volumes for 4+2 should fail canonical validation"
        );
    }

    /// BP26-03: with_max_size() clamps values below MIN_VOLUME_SIZE.
    #[test]
    fn bp26_03_with_max_size_clamps_below_minimum() {
        let config = VolumePoolConfig::new("/tmp/test", 1).with_max_size(1); // way below MIN_VOLUME_SIZE
        assert!(config.max_volume_size >= MIN_VOLUME_SIZE);
    }

    /// BP26-03: with_max_size(0) is also clamped.
    #[test]
    fn bp26_03_with_max_size_zero_clamped() {
        let config = VolumePoolConfig::new("/tmp/test", 1).with_max_size(0);
        assert_eq!(config.max_volume_size, MIN_VOLUME_SIZE);
    }

    #[test]
    fn bp26_04_double_with_distribution_last_wins() {
        let config = VolumePoolConfig::new("/tmp/test", 1)
            .with_distribution(MatrixDistributionConfig {
                strategy: era_common::MatrixDistributionStrategy::RotatingOffset,
                min_volumes: 2,
                target_volumes: 4,
            })
            .with_distribution(MatrixDistributionConfig {
                strategy: era_common::MatrixDistributionStrategy::RotatingOffset,
                min_volumes: 7,
                target_volumes: 9,
            });
        assert_eq!(config.initial_volume_count, 1);
        assert_eq!(config.distribution.min_volumes, 7);
    }

    #[tokio::test]
    async fn test_canonical_selection_is_monotonic_without_backfill() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let config =
            VolumePoolConfig::new(temp_dir.path().join("monotonic"), 3).with_max_size(50_000);
        let mut pool = VolumePool::create(backend, config, create_test_header())
            .await
            .unwrap();

        let large_block = EncryptedMacroBlock {
            block_id: BlockId::new(0),
            data: Bytes::from(vec![0x11; 30_000]),
            original_size: 30_000,
            compressed_size: 30_000,
            chunk_count: 1,
        };
        let large_disk_size = BlockHeader::SIZE as u64 + large_block.data.len() as u64;

        for expected_seq in 0..2u16 {
            let (slot, seq) = pool.select_canonical_volume(large_disk_size).await.unwrap();
            assert_eq!((slot, seq), (usize::from(expected_seq), expected_seq));
            pool.write_canonical_block_to_slot(slot, &large_block, BlockType::Data)
                .await
                .unwrap();
        }
        // Fill slot 2 nearly to capacity so ~500 bytes remain there while slots 0 and 1 still have ~11.5 KiB.
        let fill_slot2 = EncryptedMacroBlock {
            block_id: BlockId::new(2),
            data: Bytes::from(vec![0x33; 41_000]),
            original_size: 41_000,
            compressed_size: 41_000,
            chunk_count: 1,
        };
        let fill_slot2_size = BlockHeader::SIZE as u64 + fill_slot2.data.len() as u64;
        let (slot, seq) = pool.select_canonical_volume(fill_slot2_size).await.unwrap();
        assert_eq!((slot, seq), (2, 2));
        pool.write_canonical_block_to_slot(slot, &fill_slot2, BlockType::Data)
            .await
            .unwrap();

        let small_block = EncryptedMacroBlock {
            block_id: BlockId::new(3),
            data: Bytes::from(vec![0x22; 1_000]),
            original_size: 1_000,
            compressed_size: 1_000,
            chunk_count: 1,
        };
        let small_disk_size = BlockHeader::SIZE as u64 + small_block.data.len() as u64;
        let (slot, seq) = pool.select_canonical_volume(small_disk_size).await.unwrap();
        assert_eq!(
            (slot, seq),
            (0, 3),
            "smaller block after filling slot 2 must rotate to gen 1 slot 0 rather than backfilling slot 0"
        );
    }

    #[tokio::test]
    async fn test_rotation_closes_retired_writers_bounding_open_handles() {
        use era_storage::{StorageBackend, StorageMetadata, StorageWriter};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct HandleTracker {
            open_writers: AtomicUsize,
            peak_open_writers: AtomicUsize,
        }

        impl HandleTracker {
            fn new() -> Arc<Self> {
                Arc::new(Self {
                    open_writers: AtomicUsize::new(0),
                    peak_open_writers: AtomicUsize::new(0),
                })
            }

            fn acquire(&self) {
                let current = self.open_writers.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak_open_writers.fetch_max(current, Ordering::SeqCst);
            }

            fn release(&self) {
                self.open_writers.fetch_sub(1, Ordering::SeqCst);
            }
        }

        struct TrackedWriter<W: StorageWriter> {
            inner: Option<W>,
            tracker: Arc<HandleTracker>,
        }

        impl<W: StorageWriter> Drop for TrackedWriter<W> {
            fn drop(&mut self) {
                if self.inner.take().is_some() {
                    self.tracker.release();
                }
            }
        }

        #[async_trait::async_trait]
        impl<W: StorageWriter> StorageWriter for TrackedWriter<W> {
            async fn append(&mut self, data: &[u8]) -> Result<u64> {
                self.inner.as_mut().unwrap().append(data).await
            }

            async fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
                self.inner.as_mut().unwrap().write_at(offset, data).await
            }

            async fn sync(&mut self) -> Result<()> {
                self.inner.as_mut().unwrap().sync().await
            }

            async fn sync_data(&mut self) -> Result<()> {
                self.inner.as_mut().unwrap().sync_data().await
            }

            fn current_size(&self) -> u64 {
                self.inner.as_ref().unwrap().current_size()
            }

            async fn truncate(&mut self, size: u64) -> Result<()> {
                self.inner.as_mut().unwrap().truncate(size).await
            }

            async fn close(mut self) -> Result<()> {
                let inner = self.inner.take().unwrap();
                let res = inner.close().await;
                self.tracker.release();
                res
            }
        }

        #[derive(Clone)]
        struct TrackedBackend {
            inner: era_storage::MemoryStorageBackend,
            tracker: Arc<HandleTracker>,
        }

        #[async_trait::async_trait]
        impl StorageBackend for TrackedBackend {
            type Writer = TrackedWriter<era_storage::MemoryStorageWriter>;
            type Reader = era_storage::MemoryStorageReader;

            async fn create(&self, path: &Path) -> Result<Self::Writer> {
                let inner = self.inner.create(path).await?;
                self.tracker.acquire();
                Ok(TrackedWriter {
                    inner: Some(inner),
                    tracker: self.tracker.clone(),
                })
            }

            async fn open_append(&self, path: &Path) -> Result<Self::Writer> {
                let inner = self.inner.open_append(path).await?;
                self.tracker.acquire();
                Ok(TrackedWriter {
                    inner: Some(inner),
                    tracker: self.tracker.clone(),
                })
            }

            async fn open_read(&self, path: &Path) -> Result<Self::Reader> {
                self.inner.open_read(path).await
            }

            async fn exists(&self, path: &Path) -> bool {
                self.inner.exists(path).await
            }

            async fn delete(&self, path: &Path) -> Result<()> {
                self.inner.delete(path).await
            }

            async fn stat(&self, path: &Path) -> Result<StorageMetadata> {
                self.inner.stat(path).await
            }
        }

        let tracker = HandleTracker::new();
        let backend = TrackedBackend {
            inner: era_storage::MemoryStorageBackend::new(),
            tracker: tracker.clone(),
        };
        let pool_width = 3usize;
        let generations = 26usize;
        let total_volumes = u16::try_from(pool_width * generations).unwrap();
        let config = VolumePoolConfig::new("retired_handles", pool_width).with_max_size(30_000);
        let mut pool = VolumePool::create(backend.clone(), config.clone(), create_test_header())
            .await
            .unwrap();

        let block_payload = vec![0x7E; 18_000];
        let block = EncryptedMacroBlock {
            block_id: BlockId::new(0),
            data: Bytes::from(block_payload),
            original_size: 18_000,
            compressed_size: 18_000,
            chunk_count: 1,
        };
        let disk_size = BlockHeader::SIZE as u64 + block.data.len() as u64;

        for _ in 0..total_volumes {
            let (slot, _) = pool.select_canonical_volume(disk_size).await.unwrap();
            pool.write_canonical_block_to_slot(slot, &block, BlockType::Data)
                .await
                .unwrap();
        }

        let stats = pool.finalize().await.unwrap();
        assert_eq!(stats.volume_count, usize::from(total_volumes));
        assert_eq!(tracker.open_writers.load(Ordering::SeqCst), 0);
        assert!(
            tracker.peak_open_writers.load(Ordering::SeqCst) <= pool_width * 2,
            "peak open writers ({}) exceeded O(W) bound ({})",
            tracker.peak_open_writers.load(Ordering::SeqCst),
            pool_width * 2
        );

        for seq in 0..total_volumes {
            let vol_path = config.volume_path(seq);
            let vol_name = extract_filename(&vol_path).unwrap();
            let reader = VolumeReader::open(&backend, Path::new(vol_name))
                .await
                .unwrap();
            assert_eq!(reader.header().volume_sequence(), seq);
            assert_eq!(reader.header().total_volumes(), total_volumes);
            assert!(!reader.header_recovered_from_backup());
            assert!(reader.footer().is_some());
        }
    }
}
