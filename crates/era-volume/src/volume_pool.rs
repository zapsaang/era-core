//! Volume pool for matrix distribution and fixed-size volume management.
//!
//! This module provides `VolumePool`, which manages multiple volumes for
//! true matrix-distributed erasure coding with automatic volume rotation
//! when volumes reach their size limit.

use era_common::{
    compute_shard_crc, BlockHeader, BlockLocation, BlockType, EncryptedMacroBlock,
    ErasureCodeConfig, MatrixBlockLocation, MatrixDistributionConfig, MatrixShardEntry, Result,
    ShardHeader, VolumeId,
};
use era_storage::StorageBackend;
use std::path::{Path, PathBuf};
use std::mem::size_of;

use crate::distribution::{DistributionCalculator, DistributionConfigExt};
use crate::footer::FOOTER_SIZE;
use crate::header::HEADER_SIZE;
use crate::{SuperHeader, VolumeReader, VolumeWriter, DEFAULT_MAX_VOLUME_SIZE, MIN_VOLUME_SIZE};

/// Space reserved for the backup copy of the SuperHeader at the end of each volume.
/// This mirrors `HEADER_SIZE` (4096 bytes) — the volume format writes a backup header
/// before the primary footer so that volumes can be recovered if the primary header is lost.
const BACKUP_HEADER_RESERVATION: u64 = HEADER_SIZE as u64;

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
    ///
    /// If the current `initial_volume_count` is below the distribution's
    /// `min_volumes`, it is automatically raised to match — the same
    /// postcondition enforced by [`for_erasure`](Self::for_erasure).
    pub fn with_distribution(mut self, distribution: MatrixDistributionConfig) -> Self {
        self.distribution = distribution;
        // BP26-01: Match for_erasure() postcondition — auto-adjust volume count
        if self.initial_volume_count < self.distribution.min_volumes {
            self.initial_volume_count = self.distribution.min_volumes;
        }
        debug_assert!(self.initial_volume_count >= self.distribution.min_volumes);
        self
    }

    /// Configure based on erasure config.
    ///
    /// Derives the matrix distribution from the erasure parameters and
    /// ensures `initial_volume_count` is at least `distribution.min_volumes`.
    pub fn for_erasure(mut self, erasure: ErasureCodeConfig) -> Self {
        self.distribution = MatrixDistributionConfig::from_erasure_config(erasure);
        // Ensure we have enough volumes
        if self.initial_volume_count < self.distribution.min_volumes {
            self.initial_volume_count = self.distribution.min_volumes;
        }
        debug_assert!(self.initial_volume_count >= self.distribution.min_volumes);
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
    /// Block sequence counter for rotation calculation
    block_sequence: u64,
    /// Statistics
    stats: VolumePoolStats,
}

impl<B: StorageBackend> VolumePool<B> {
    /// Create a new volume pool.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if the volume count or sequence exceeds `u16`.
    /// Returns `InvalidConfig` if a volume path has no filename.
    /// Returns `Serialization` if the header cannot be encoded.
    /// Returns I/O errors from creating volumes on the storage backend.
    pub async fn create(
        backend: B,
        config: VolumePoolConfig,
        template_header: SuperHeader,
    ) -> Result<Self> {
        let volume_count = config.initial_volume_count;
        let mut writers = Vec::with_capacity(volume_count);
        let mut sequences = Vec::with_capacity(volume_count);

        // Create initial volumes
        for i in 0..volume_count {
            let mut header = template_header.clone();
            // Each volume must have a unique volume_id for identification
            header.volume_id = VolumeId::new();
            header.volume_sequence = u16::try_from(i).map_err(|_| {
                era_common::EraError::InvalidConfig(format!("volume index {} exceeds u16", i))
            })?;
            header.total_volumes = u16::try_from(volume_count).map_err(|_| {
                era_common::EraError::InvalidConfig(format!(
                    "volume count {} exceeds u16",
                    volume_count
                ))
            })?;

            let seq = header.volume_sequence;
            let volume_path = config.volume_path(seq);
            let volume_filename = volume_path.file_name().ok_or_else(|| {
                era_common::EraError::InvalidConfig(format!("path has no filename: {:?}", volume_path))
            })?;

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
            block_sequence: 0,
            stats,
        };

        Ok(pool)
    }

    /// Open an existing volume pool for appending.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if a volume sequence exceeds `u16` or a path has no filename.
    /// Returns `CorruptedFooter` if any volume is missing its footer.
    /// Returns `CorruptedHeader` or `CorruptedFooter` if any volume is corrupted.
    /// Returns I/O errors from opening volumes on the storage backend.
    pub async fn open_append(
        backend: B,
        mut config: VolumePoolConfig,
        template_header: SuperHeader,
    ) -> Result<Self> {

        let volume_count = if template_header.total_volumes > 0 {
            template_header.total_volumes as usize
        } else {
            config.initial_volume_count
        };
        config.initial_volume_count = volume_count.max(1);

        // P8-02: Pre-allocate with known capacity to avoid reallocations
        let mut writers = Vec::with_capacity(config.initial_volume_count);
        let mut sequences = Vec::with_capacity(config.initial_volume_count);
        let mut max_block_count = 0u32;

        for seq in 0..config.initial_volume_count {
            let seq_u16 = u16::try_from(seq).map_err(|_| {
                era_common::EraError::InvalidConfig(format!("volume sequence {} exceeds u16", seq))
            })?;
            let volume_path = config.volume_path(seq_u16);
            let volume_filename = volume_path.file_name().ok_or_else(|| {
                era_common::EraError::InvalidConfig(format!("path has no filename: {:?}", volume_path))
            })?;

            let reader = VolumeReader::open(&backend, Path::new(volume_filename)).await?;
            let footer = reader
                .footer()
                .ok_or_else(|| era_common::EraError::CorruptedFooter("Missing footer".into()))?;

            let writer = VolumeWriter::open_append(
                &backend,
                Path::new(volume_filename),
                reader.header().clone(),
                footer,
            )
            .await?;

            max_block_count = max_block_count.max(writer.block_count());
            writers.push(writer);
            sequences.push(reader.header().volume_sequence);
        }

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
        // Note: block_sequence is initialized from max canonical block count.
        // This doesn't account for raw writes or erasure stripe count, which may
        // cause slightly suboptimal distribution on append. This is acceptable
        // because the rotating offset strategy tolerates imprecise counters.
            block_sequence: max_block_count as u64,
            stats,
        })
    }

    /// Open a single-volume archive for appending using a known footer.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if the volume path has no filename.
    /// Returns `CorruptedFooter` if the footer's data_end_offset exceeds the file size.
    /// Returns I/O errors from opening the volume on the storage backend.
    pub async fn open_append_single(
        backend: B,
        mut config: VolumePoolConfig,
        header: SuperHeader,
        footer: &crate::Footer,
    ) -> Result<Self> {
        config.initial_volume_count = 1;
        let volume_path = config.volume_path(0);
        let volume_filename = volume_path
            .file_name()
            .ok_or_else(|| era_common::EraError::InvalidConfig(format!("path has no filename: {:?}", volume_path)))?;

        let writer =
            VolumeWriter::open_append(&backend, Path::new(volume_filename), header.clone(), footer)
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
            block_sequence,
            stats,
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
    /// If cancelled during the padding/sync loop (step 1), some writers may be
    /// padded and synced while others are not — but all are still valid since
    /// padding doesn't corrupt data and partial sync is a no-op for unsynced volumes.
    /// If cancelled after `clear()` (step 2) but before new writers are created
    /// (step 3), `self.writers` and `self.sequences` are empty. The pool is in an
    /// invalid state and must not be reused — the caller should propagate the error
    /// to abandon the archive write. This is acceptable because `rotate_volumes` is
    /// private and only called within `write_shard`, which propagates errors to the
    /// engine, which handles archive-level abort.
    async fn rotate_volumes(&mut self) -> Result<()> {
        let volume_count = self.writers.len();

        // Use drain to avoid cloning — moves data into old_sequences and clears self.sequences
        let old_sequences: Vec<u16> = self.sequences.drain(..).collect();

        // 1. Pad current volumes to max size, sync data to disk, and update stats
        for (i, writer) in self.writers.iter_mut().enumerate() {
            // Force padding if max size is set
            writer.set_max_size(self.config.max_volume_size).await?;

            // RL33-01: Sync shard data to persistent storage before dropping writers.
            // Without this, rotated-out volumes' data exists only in OS page cache and
            // would be lost on power failure. Uses fdatasync (no metadata sync needed).
            writer.sync_data().await?;

            // Record size
            let size = writer.current_size();
            let sequence = old_sequences[i];
            self.stats.volume_sizes.push((sequence, size));
        }

        // 2. Drop current writers (file descriptors closed by OS on drop;
        //    data is already synced to disk by the sync_data() call above)
        self.writers.clear();

        // 3. Create new set of volumes
        let vc_u16 = u16::try_from(volume_count).map_err(|_| {
            era_common::EraError::InvalidConfig(format!(
                "volume count {} exceeds u16",
                volume_count
            ))
        })?;
        for &sequence in old_sequences.iter().take(volume_count) {
            // Next sequence: previous + volume_count
            let next_sequence = sequence.checked_add(vc_u16).ok_or_else(|| {
                era_common::EraError::InvalidConfig("volume sequence overflow".into())
            })?;

            let mut header = self.template_header.clone();
            // Each rotated volume must have a unique volume_id
            header.volume_id = VolumeId::new();
            header.volume_sequence = next_sequence;
            // total_volumes = next_sequence + 1 represents the count of volumes
            // up to and including this one. The reader takes the maximum across
            // all volumes when discovering the archive set.
            header.total_volumes = next_sequence.checked_add(1).ok_or_else(|| {
                era_common::EraError::InvalidConfig("total_volumes overflow".into())
            })?;

            let volume_path = self.config.volume_path(next_sequence);
            let volume_filename = volume_path.file_name().ok_or_else(|| {
                era_common::EraError::InvalidConfig(format!("path has no filename: {:?}", volume_path))
            })?;

            let writer =
                VolumeWriter::create(&self.backend, Path::new(volume_filename), header).await?;

            self.writers.push(writer);
            self.sequences.push(next_sequence);
        }

        self.stats.volume_count += volume_count;
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

    /// Get total size of all volumes (active + closed)
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
        self.template_header.archive_id
    }

    /// Calculate which volume slot a shard should go to.
    fn shard_volume_slot(&self, shard_idx: usize) -> era_common::Result<usize> {
        if self.writers.is_empty() {
            return Err(era_common::EraError::InvalidConfig(
                "no volumes available for shard distribution".into(),
            ));
        }
        Ok(self.config.distribution.strategy.calculate_volume(
            shard_idx,
            self.block_sequence,
            self.writers.len(),
        ))
    }

    /// Check if a volume can fit additional data.
    fn volume_can_fit(&self, slot: usize, additional_size: u64) -> bool {
        if slot >= self.writers.len() {
            return false;
        }
        let current_size = self.writers[slot].current_size();
        let reserved = FOOTER_SIZE as u64
            + BACKUP_HEADER_RESERVATION
            + BlockHeader::SIZE as u64
            + ShardHeader::SIZE as u64;
        current_size.saturating_add(additional_size).saturating_add(reserved) <= self.config.max_volume_size
    }

    /// Get remaining space in a volume.
    fn volume_remaining_space(&self, slot: usize) -> u64 {
        if slot >= self.writers.len() {
            return 0;
        }
        let current_size = self.writers[slot].current_size();
        let reserved = FOOTER_SIZE as u64 + BACKUP_HEADER_RESERVATION + BlockHeader::SIZE as u64 + ShardHeader::SIZE as u64;
        if current_size.saturating_add(reserved) >= self.config.max_volume_size {
            0
        } else {
            self.config.max_volume_size - current_size - reserved
        }
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
        let reserved =
            FOOTER_SIZE as u64 + BACKUP_HEADER_RESERVATION + BlockHeader::SIZE as u64 + ShardHeader::SIZE as u64;
        let max_volume_shard_size = self.config.max_volume_size.saturating_sub(reserved);

        if shard_size > max_volume_shard_size {
            return Err(era_common::EraError::InvalidConfig(format!(
                "Shard size {} exceeds maximum allowed {} (max_volume_size={})",
                shard_size, max_volume_shard_size, self.config.max_volume_size
            )));
        }
        Ok(())
    }

    /// Write a shard to its designated volume with matrix distribution.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if no volumes are available, the shard size exceeds
    /// `MAX_SHARD_SIZE` or the maximum per-volume capacity, or the shard size exceeds `u32`.
    /// Returns `InvalidConfig` if the calculated write size overflows.
    /// Triggers volume rotation (which may fail with `InvalidConfig` on sequence overflow)
    /// if all volumes are full.
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
        let preferred_slot = self.shard_volume_slot(shard_idx)?;

        // Validate shard size against max volume constraints
        self.validate_shard_size(shard_data.len() as u64)?;

        // Check if the volume can fit this shard
        let shard_size = shard_data.len() as u64;
        let length_prefix_size = stripe_lengths
            .map(|lens| {
                (lens.len() as u64)
                    .checked_mul(size_of::<u32>() as u64)
                    .ok_or_else(|| {
                        era_common::EraError::InvalidConfig(
                            "stripe_lengths header too large".into(),
                        )
                    })
            })
            .transpose()?
            .unwrap_or(0);
        let header_size = if include_original_len_header { size_of::<u32>() as u64 } else { 0u64 };
        let total_size = length_prefix_size
            .checked_add(header_size)
            .and_then(|v| v.checked_add(ShardHeader::SIZE as u64))
            .and_then(|v| v.checked_add(shard_size))
            .ok_or_else(|| {
                era_common::EraError::InvalidConfig(
                    "calculated shard write size overflow".into(),
                )
            })?;

        // Try preferred slot first, then find any available volume
        let slot = if self.volume_can_fit(preferred_slot, total_size) {
            preferred_slot
        } else {
            // Find any volume with enough space (overflow strategy)
            let mut found_slot = None;
            debug_assert!(!self.writers.is_empty(), "writers must be non-empty for modulo");
            for i in 0..self.writers.len() {
                // Start from preferred slot and wrap around
                let candidate = (preferred_slot + i) % self.writers.len();
                if self.volume_can_fit(candidate, total_size) {
                    found_slot = Some(candidate);
                    break;
                }
            }
            match found_slot {
                Some(s) => s,
                None => {
                    // All volumes are full - rotate volumes
                    self.rotate_volumes().await?;

                    // After rotation, write to preferred_slot which maps to new volume
                    preferred_slot
                }
            }
        };
        debug_assert!(
            slot < self.writers.len() && slot < self.sequences.len(),
            "slot {} out of bounds (writers: {}, sequences: {})",
            slot,
            self.writers.len(),
            self.sequences.len()
        );

        let writer = &mut self.writers[slot];
        let volume_sequence = self.sequences[slot];
        let volume_id = writer.volume_id();

        // V28-04: Compute shard length as u32 once and reuse
        let shard_len_u32 = u32::try_from(shard_data.len()).map_err(|_| {
            era_common::EraError::InvalidConfig(format!(
                "shard size {} exceeds u32",
                shard_data.len()
            ))
        })?;

        // P8-01: Coalesce metadata writes into a single buffer to reduce syscall
        // amplification. Previously N+3 separate write_raw() calls per shard (N stripe
        // lengths + original_len + shard_header + shard_data). Now 2 calls: one for
        // the coalesced header buffer, one for shard data.
        let header_capacity = stripe_lengths.map_or(0, std::mem::size_of_val)
            + if include_original_len_header { size_of::<u32>() } else { 0 }
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
        let shard_header = ShardHeader::new(
            shard_len_u32,
            crc,
        );
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
            MatrixShardEntry::new(
                volume_sequence,
                shard_header_offset,
                shard_len_u32,
                crc,
            ),
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
    /// Returns `VolumeFull` if a volume cannot fit the block after exhausting all slots.
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
        // V27-15: Use round-robin for canonical blocks to spread load across volumes
        let preferred_slot = (self.block_sequence as usize) % self.writers.len().max(1);

        let block_size = block.data.len() as u64;
        let total_size = BlockHeader::SIZE as u64 + block_size;

        // Try preferred slot first, then find any available volume
        let slot = if self.volume_can_fit(preferred_slot, total_size) {
            preferred_slot
        } else {
            // Find any volume with enough space
            let mut found_slot = None;
            debug_assert!(!self.writers.is_empty(), "writers must be non-empty for modulo");
            for i in 0..self.writers.len() {
                let candidate = (preferred_slot + i) % self.writers.len();
                if self.volume_can_fit(candidate, total_size) {
                    found_slot = Some(candidate);
                    break;
                }
            }
            match found_slot {
                Some(s) => s,
                None => {
                    // All volumes are full - rotate volumes
                    self.rotate_volumes().await?;
                    preferred_slot
                }
            }
        };

        let writer = &mut self.writers[slot];
        let volume_id = writer.volume_id();

        // Write using BlockHeader format
        let location = writer.write_canonical_block(block, block_type).await?;

        // Update stats
        self.stats.total_bytes_written += total_size;
        self.stats.total_blocks_written += 1;

        Ok((location, volume_id))
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
        // Validate that shards can fit in volumes
        if let Some(first_shard) = shards.first() {
            self.validate_shard_size(first_shard.len() as u64)?;
        }

        // Track which volumes we've written to for this block
        // We need to write the original_len header to the first shard on each volume
        let mut volumes_with_header: Vec<bool> = vec![false; self.writers.len()];

        let mut location = MatrixBlockLocation::new(
            block_id,
            self.block_sequence,
            erasure_config.data_shards,
            erasure_config.parity_shards,
            original_len,
        );

        for (shard_idx, shard_data) in shards.iter().enumerate() {
            let slot = self.shard_volume_slot(shard_idx)?;
            // V27-09: Ensure volumes_with_header is large enough after potential rotation
            if slot >= volumes_with_header.len() {
                volumes_with_header.resize(self.writers.len(), false);
            }
            let need_header = !volumes_with_header[slot];
            let (entry, _) = self
                .write_shard(shard_idx, shard_data, need_header, original_len, None)
                .await?;
            location.add_shard(entry);

            if need_header {
                volumes_with_header[slot] = true;
            }
        }

        // Increment block sequence for next block (consistent with write_canonical_block path)
        self.advance_block_sequence();

        Ok(location)
    }

    /// Finalize all volumes.
    ///
    /// # Errors
    /// Returns `Serialization` if any volume's header or footer cannot be encoded.
    /// Returns I/O errors from finalizing volumes on the storage backend.
    pub async fn finalize(&mut self) -> Result<VolumePoolStats> {
        self.finalize_with_catalog(0, 0, 0, 0, 0, 0).await
    }

    /// Finalize all volumes with the same catalog information.
    ///
    /// This method broadcasts the same catalog offset to all volumes. This is appropriate
    /// when using a single catalog location shared across all volumes (the typical case).
    ///
    /// For per-volume catalog locations, use [`Self::finalize_with_catalogs`] instead.
    ///
    /// # Cancellation Safety
    ///
    /// This is a terminal operation — the pool must not be reused after calling.
    /// If cancelled mid-loop, some writers may be consumed (dropped) without
    /// finalization, leaving orphaned volume files on disk. Recovery: the engine
    /// detects the incomplete archive and either retries or cleans up. Both
    /// `writers` and `sequences` are drained upfront so the pool's internal
    /// invariants remain consistent regardless of cancellation point.
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
        let mut stats = std::mem::take(&mut self.stats);

        // Drain both writers and sequences upfront so internal state is consistent
        // even if the future is cancelled mid-finalization loop.
        let old_sequences: Vec<u16> = self.sequences.drain(..).collect();
        let writers: Vec<_> = self.writers.drain(..).collect();

        for (i, writer) in writers.into_iter().enumerate() {
            let size = writer.current_size();
            let sequence = old_sequences[i];
            stats.volume_sizes.push((sequence, size));
            writer
                .finalize_with_catalog(
                    catalog_offset,
                    catalog_size,
                    catalog_block_id,
                    index_offset,
                    index_size,
                    index_block_id,
                )
                .await?;
        }

        Ok(stats)
    }

    /// Finalize all volumes with per-volume catalog information.
    ///
    /// # Cancellation Safety
    ///
    /// Same as [`Self::finalize_with_catalog`]: terminal operation, both `writers`
    /// and `sequences` are drained upfront. If cancelled mid-loop, remaining
    /// writers are dropped without finalization (orphaned files recoverable by engine).
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
        if catalog_locations.len() != self.writers.len() {
            return Err(era_common::EraError::InvalidConfig(format!(
                "catalog_locations length {} does not match volume count {}",
                catalog_locations.len(),
                self.writers.len()
            )));
        }

        if let Some(idx) = index_locations {
            if idx.len() != self.writers.len() {
                return Err(era_common::EraError::InvalidConfig(format!(
                    "index_locations length {} does not match volume count {}",
                    idx.len(),
                    self.writers.len()
                )));
            }
        }

        let mut stats = std::mem::take(&mut self.stats);

        // Drain both writers and sequences upfront so internal state is consistent
        // even if the future is cancelled mid-finalization loop.
        let old_sequences: Vec<u16> = self.sequences.drain(..).collect();
        let writers: Vec<_> = self.writers.drain(..).collect();

        for (i, writer) in writers.into_iter().enumerate() {
            let size = writer.current_size();
            let sequence = old_sequences[i];
            stats.volume_sizes.push((sequence, size));
            let (offset, size_u32, block_id) = catalog_locations[i];
            let (idx_offset, idx_size, idx_block_id) = index_locations
                .and_then(|idx| idx.get(i).copied())
                .unwrap_or((0, 0, 0));
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
        header.volume_id = VolumeId::new();
        header.volume_sequence = new_sequence;
        header.total_volumes = u16::try_from(self.writers.len() + 1)
            .map_err(|_| era_common::EraError::InvalidConfig("total volumes exceeds u16".into()))?;

        let volume_path = self.config.volume_path(new_sequence);
        let volume_filename = volume_path
            .file_name()
            .ok_or_else(|| era_common::EraError::InvalidConfig(format!("path has no filename: {:?}", volume_path)))?;

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
        let reserved = FOOTER_SIZE as u64 + BACKUP_HEADER_RESERVATION + BlockHeader::SIZE as u64 + ShardHeader::SIZE as u64;
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
    use era_common::{ArchiveConfig, ArchiveId, BlockId};
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
            EncryptedVolumeKey {
                algorithm: KeyWrapAlgorithm::XChaCha20Poly1305,
                nonce: [0u8; 24],
                ciphertext: vec![0u8; 48],
            },
            AccessPolicy::AnyOfN,
        )
        .unwrap()
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
    async fn test_volume_pool_finalization() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_path = temp_dir.path().join("test_archive");

        let config = VolumePoolConfig::new(&base_path, 2);
        let header = create_test_header();

        let mut pool = VolumePool::create(backend, config, header).await.unwrap();
        let stats = pool.finalize().await.unwrap();

        assert_eq!(stats.volume_count, 2);
        assert_eq!(stats.volume_sizes.len(), 2);
    }

    // ── Iteration 26: Builder Pattern & Fluent API Safety Tests ──

    /// BP26-01: with_distribution() auto-adjusts initial_volume_count
    /// when distribution.min_volumes exceeds the current count.
    #[test]
    fn bp26_01_with_distribution_auto_adjusts_volume_count() {
        let config = VolumePoolConfig::new("/tmp/test", 1)
            .with_distribution(MatrixDistributionConfig {
                strategy: era_common::MatrixDistributionStrategy::RotatingOffset,
                min_volumes: 5,
                target_volumes: 8,
            });
        // initial_volume_count was 1, but min_volumes is 5 → auto-raised
        assert_eq!(config.initial_volume_count, 5);
    }

    /// BP26-01: with_distribution() preserves count when it already meets min_volumes.
    #[test]
    fn bp26_01_with_distribution_preserves_sufficient_count() {
        let config = VolumePoolConfig::new("/tmp/test", 10)
            .with_distribution(MatrixDistributionConfig {
                strategy: era_common::MatrixDistributionStrategy::RotatingOffset,
                min_volumes: 3,
                target_volumes: 6,
            });
        // initial_volume_count was 10, min_volumes is 3 → no change
        assert_eq!(config.initial_volume_count, 10);
    }

    /// BP26-02: for_erasure() then with_distribution() — volume count
    /// is re-adjusted to the new distribution's min_volumes.
    #[test]
    fn bp26_02_for_erasure_then_with_distribution_adjusts() {
        let erasure = ErasureCodeConfig::new(4, 2);
        let config = VolumePoolConfig::new("/tmp/test", 1)
            .for_erasure(erasure)
            .with_distribution(MatrixDistributionConfig {
                strategy: era_common::MatrixDistributionStrategy::RotatingOffset,
                min_volumes: 8,
                target_volumes: 10,
            });
        // for_erasure set initial_volume_count to >=3 (min for 4+2),
        // then with_distribution raises it to 8
        assert!(config.initial_volume_count >= 8);
    }

    /// BP26-02: with_distribution() then for_erasure() — for_erasure
    /// also re-adjusts, so order doesn't matter for final postcondition.
    #[test]
    fn bp26_02_with_distribution_then_for_erasure_adjusts() {
        let erasure = ErasureCodeConfig::new(4, 2);
        let config = VolumePoolConfig::new("/tmp/test", 1)
            .with_distribution(MatrixDistributionConfig {
                strategy: era_common::MatrixDistributionStrategy::RotatingOffset,
                min_volumes: 2,
                target_volumes: 4,
            })
            .for_erasure(erasure);
        // with_distribution set initial_volume_count to 2,
        // then for_erasure overrides distribution and re-adjusts count to >=3
        assert!(config.initial_volume_count >= config.distribution.min_volumes);
    }

    /// BP26-03: with_max_size() clamps values below MIN_VOLUME_SIZE.
    #[test]
    fn bp26_03_with_max_size_clamps_below_minimum() {
        let config = VolumePoolConfig::new("/tmp/test", 1)
            .with_max_size(1); // way below MIN_VOLUME_SIZE
        assert!(config.max_volume_size >= MIN_VOLUME_SIZE);
    }

    /// BP26-03: with_max_size(0) is also clamped.
    #[test]
    fn bp26_03_with_max_size_zero_clamped() {
        let config = VolumePoolConfig::new("/tmp/test", 1)
            .with_max_size(0);
        assert_eq!(config.max_volume_size, MIN_VOLUME_SIZE);
    }

    /// BP26-04: Double with_distribution() — last wins, count still valid.
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
        // Second call should auto-adjust to min_volumes=7
        assert_eq!(config.initial_volume_count, 7);
        assert_eq!(config.distribution.min_volumes, 7);
    }
}
