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

use crate::distribution::{DistributionCalculator, DistributionConfigExt};
use crate::footer::FOOTER_SIZE;
use crate::{SuperHeader, VolumeReader, VolumeWriter, DEFAULT_MAX_VOLUME_SIZE, MIN_VOLUME_SIZE};

/// Configuration for the volume pool.
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
    pub fn with_max_size(mut self, max_size: u64) -> Self {
        self.max_volume_size = max_size.max(MIN_VOLUME_SIZE);
        self
    }

    /// Set distribution configuration.
    pub fn with_distribution(mut self, distribution: MatrixDistributionConfig) -> Self {
        self.distribution = distribution;
        self
    }

    /// Configure based on erasure config.
    pub fn for_erasure(mut self, erasure: ErasureCodeConfig) -> Self {
        self.distribution = MatrixDistributionConfig::from_erasure_config(erasure);
        // Ensure we have enough volumes
        if self.initial_volume_count < self.distribution.min_volumes {
            self.initial_volume_count = self.distribution.min_volumes;
        }
        self
    }

    /// Generate volume path for a given sequence number.
    pub fn volume_path(&self, sequence: u16) -> PathBuf {
        if sequence == 0 {
            self.base_path.with_extension("era")
        } else {
            let ext = format!("era.{:03}", sequence);
            self.base_path.with_extension(ext)
        }
    }
}

/// Statistics about the volume pool.
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
            header.volume_sequence = i as u16;
            header.total_volumes = volume_count as u16;

            let volume_path = config.volume_path(i as u16);
            let volume_filename = volume_path.file_name().unwrap_or_default();

            let writer = VolumeWriter::create(&backend, Path::new(volume_filename), header).await?;
            writers.push(writer);
            sequences.push(i as u16);
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
    pub async fn open_append(
        backend: B,
        mut config: VolumePoolConfig,
        template_header: SuperHeader,
    ) -> Result<Self> {
        let mut writers = Vec::new();
        let mut sequences = Vec::new();

        let volume_count = if template_header.total_volumes > 0 {
            template_header.total_volumes as usize
        } else {
            config.initial_volume_count
        };
        config.initial_volume_count = volume_count.max(1);

        let mut max_block_count = 0u32;

        for seq in 0..config.initial_volume_count {
            let volume_path = config.volume_path(seq as u16);
            let volume_filename = volume_path.file_name().unwrap_or_default();

            let reader = VolumeReader::open(&backend, Path::new(volume_filename)).await?;
            let footer = reader
                .footer()
                .ok_or_else(|| era_common::EraError::CorruptedHeader("Missing footer".into()))?;

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
            block_sequence: max_block_count as u64,
            stats,
        })
    }

    /// Open a single-volume archive for appending using a known footer.
    pub async fn open_append_single(
        backend: B,
        mut config: VolumePoolConfig,
        header: SuperHeader,
        footer: &crate::Footer,
    ) -> Result<Self> {
        config.initial_volume_count = 1;
        let volume_path = config.volume_path(0);
        let volume_filename = volume_path.file_name().unwrap_or_default();

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
    pub fn current_block_count(&self) -> u32 {
        self.writers
            .iter()
            .map(|w| w.block_count())
            .max()
            .unwrap_or(0)
    }

    /// Rotate all volumes to a new set when full.
    async fn rotate_volumes(&mut self) -> Result<()> {
        let volume_count = self.writers.len();

        let old_sequences = self.sequences.clone();

        // 1. Finalize current volumes (pad to max size and update stats)
        for (i, writer) in self.writers.iter_mut().enumerate() {
            // Force padding if max size is set
            writer.set_max_size(self.config.max_volume_size).await?;

            // Record size
            let size = writer.current_size();
            let sequence = self.sequences[i];
            self.stats.volume_sizes.push((sequence, size));
        }

        // 2. Clear current writers (closes files)
        self.writers.clear();
        self.sequences.clear();

        // 3. Create new set of volumes
        for &sequence in old_sequences.iter().take(volume_count) {
            // Next sequence: previous + volume_count
            let next_sequence = sequence + volume_count as u16;

            let mut header = self.template_header.clone();
            header.volume_sequence = next_sequence;
            header.total_volumes = next_sequence + 1;

            let volume_path = self.config.volume_path(next_sequence);
            let volume_filename = volume_path.file_name().unwrap_or_default();

            let writer =
                VolumeWriter::create(&self.backend, Path::new(volume_filename), header).await?;

            self.writers.push(writer);
            self.sequences.push(next_sequence);
        }

        self.stats.volume_count += volume_count;
        Ok(())
    }

    /// Get the number of active volumes.
    pub fn volume_count(&self) -> usize {
        self.writers.len()
    }

    /// Get total size of all volumes (active + closed)
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
    pub fn block_sequence(&self) -> u64 {
        self.block_sequence
    }

    /// Advance the block sequence after completing a full stripe.
    pub fn advance_block_sequence(&mut self) {
        self.block_sequence += 1;
        self.stats.total_blocks_written += 1;
    }

    /// Get the archive ID from the template header.
    pub fn archive_id(&self) -> era_common::ArchiveId {
        self.template_header.archive_id
    }

    /// Calculate which volume slot a shard should go to.
    fn shard_volume_slot(&self, shard_idx: usize) -> usize {
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
        let reserved = FOOTER_SIZE as u64 + 4096; // Reserve for footer + padding
        current_size + additional_size + reserved <= self.config.max_volume_size
    }

    /// Get remaining space in a volume.
    fn volume_remaining_space(&self, slot: usize) -> u64 {
        if slot >= self.writers.len() {
            return 0;
        }
        let current_size = self.writers[slot].current_size();
        let reserved = FOOTER_SIZE as u64 + 4096;
        if current_size + reserved >= self.config.max_volume_size {
            0
        } else {
            self.config.max_volume_size - current_size - reserved
        }
    }

    /// Check if a shard size can ever fit in a volume.
    ///
    /// Returns an error if the shard is larger than max_volume_size allows.
    fn validate_shard_size(&self, shard_size: u64) -> Result<()> {
        let reserved = FOOTER_SIZE as u64 + 4096 + ShardHeader::SIZE as u64 + 4; // footer + padding + header + original_len
        let max_shard_size = self.config.max_volume_size.saturating_sub(reserved);

        if shard_size > max_shard_size {
            return Err(era_common::EraError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Shard size {} exceeds maximum allowed {} (max_volume_size={})",
                    shard_size, max_shard_size, self.config.max_volume_size
                ),
            )));
        }
        Ok(())
    }

    /// Write a shard to its designated volume with matrix distribution.
    ///
    /// # Arguments
    /// * `shard_idx` - The shard index (0..total_shards)
    /// * `shard_data` - The shard data to write
    /// * `original_len_header` - Optional 4-byte original length header (for first shard per volume per block)
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
        let preferred_slot = self.shard_volume_slot(shard_idx);

        // Validate shard size against max volume constraints
        self.validate_shard_size(shard_data.len() as u64)?;

        // Check if the volume can fit this shard
        let shard_size = shard_data.len() as u64;
        let length_prefix_size = stripe_lengths
            .map(|lens| lens.len() as u64 * 4)
            .unwrap_or(0);
        let header_size = if include_original_len_header { 4 } else { 0 };
        let total_size = length_prefix_size + header_size + ShardHeader::SIZE as u64 + shard_size;

        // Try preferred slot first, then find any available volume
        let slot = if self.volume_can_fit(preferred_slot, total_size) {
            preferred_slot
        } else {
            // Find any volume with enough space (overflow strategy)
            let mut found_slot = None;
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

        let writer = &mut self.writers[slot];
        let volume_sequence = self.sequences[slot];
        let volume_id = writer.volume_id();

        // Write stripe data lengths header if provided
        if let Some(lengths) = stripe_lengths {
            for len in lengths {
                writer.write_raw(&len.to_le_bytes()).await?;
            }
        }

        // Write original length header if needed
        if include_original_len_header {
            let len_bytes = original_len.to_le_bytes();
            writer.write_raw(&len_bytes).await?;
        }

        // Compute CRC and write shard header
        let crc = compute_shard_crc(shard_data);
        let shard_header = ShardHeader::new(shard_data.len() as u32, crc);
        let offset = writer.write_raw(&shard_header.to_bytes()).await?;

        // Write shard data
        writer.write_raw(shard_data).await?;

        // Update stats
        self.stats.total_bytes_written += total_size;
        self.stats.total_shards_written += 1;

        Ok((
            MatrixShardEntry::new(volume_sequence, offset, shard_data.len() as u32, crc),
            volume_id,
        ))
    }

    /// Write a canonical block (BlockHeader format) to the pool.
    ///
    /// This method writes blocks using the BlockHeader format (16 bytes)
    /// instead of the ShardHeader format (8 bytes).
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
        let preferred_slot = 0; // For non-erasure, always use first volume

        let block_size = block.data.len() as u64;
        let total_size = BlockHeader::SIZE as u64 + block_size;

        // Try preferred slot first, then find any available volume
        let slot = if self.volume_can_fit(preferred_slot, total_size) {
            preferred_slot
        } else {
            // Find any volume with enough space
            let mut found_slot = None;
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
        let mut volumes_with_header: std::collections::HashSet<usize> =
            std::collections::HashSet::new();

        let mut location = MatrixBlockLocation::new(
            block_id,
            self.block_sequence,
            erasure_config.data_shards,
            erasure_config.parity_shards,
            original_len,
        );

        for (shard_idx, shard_data) in shards.iter().enumerate() {
            let slot = self.shard_volume_slot(shard_idx);
            let need_header = !volumes_with_header.contains(&slot);

            let (entry, _) = self
                .write_shard(shard_idx, shard_data, need_header, original_len, None)
                .await?;
            location.add_shard(entry);

            if need_header {
                volumes_with_header.insert(slot);
            }
        }

        // Increment block sequence for next block
        self.block_sequence += 1;
        self.stats.total_blocks_written += 1;

        Ok(location)
    }

    /// Finalize all volumes.
    pub async fn finalize(&mut self) -> Result<VolumePoolStats> {
        self.finalize_with_catalog(0, 0, 0, 0, 0, 0).await
    }

    /// Finalize all volumes with catalog information.
    pub async fn finalize_with_catalog(
        &mut self,
        catalog_offset: u64,
        catalog_size: u32,
        catalog_block_id: u32,
        index_offset: u64,
        index_size: u32,
        index_block_id: u32,
    ) -> Result<VolumePoolStats> {
        let mut stats = self.stats.clone();

        for (i, writer) in self.writers.drain(..).enumerate() {
            let size = writer.current_size();
            let sequence = self.sequences[i];
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

        let mut stats = self.stats.clone();

        for (i, writer) in self.writers.drain(..).enumerate() {
            let size = writer.current_size();
            let sequence = self.sequences[i];
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
    pub fn volume_sequence(&self, slot: usize) -> Option<u16> {
        self.sequences.get(slot).copied()
    }

    /// Add a new volume to the pool.
    ///
    /// This is called when all existing volumes are full and more space is needed.
    /// The new volume will use the next available sequence number.
    pub async fn add_volume(&mut self, backend: &B) -> Result<usize> {
        let new_sequence = self.writers.len() as u16;

        let mut header = self.template_header.clone();
        header.volume_sequence = new_sequence;
        header.total_volumes = (self.writers.len() + 1) as u16;

        let volume_path = self.config.volume_path(new_sequence);
        let volume_filename = volume_path.file_name().unwrap_or_default();

        let writer = VolumeWriter::create(backend, Path::new(volume_filename), header).await?;

        let slot = self.writers.len();
        self.writers.push(writer);
        self.sequences.push(new_sequence);
        self.stats.volume_count += 1;

        Ok(slot)
    }

    /// Check if the pool needs more volumes to write additional data.
    pub fn needs_expansion(&self, required_size: u64) -> bool {
        // First check if the data is inherently too large for any single volume
        let reserved = FOOTER_SIZE as u64 + 4096;
        let max_per_volume = self.config.max_volume_size.saturating_sub(reserved);
        if required_size > max_per_volume {
            return false;
        }

        // Check if any volume can fit the data
        for slot in 0..self.writers.len() {
            if self.volume_can_fit(slot, required_size) {
                return false;
            }
        }
        true
    }

    /// Get total remaining space across all volumes.
    pub fn total_remaining_space(&self) -> u64 {
        (0..self.writers.len())
            .map(|slot| self.volume_remaining_space(slot))
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use era_common::{ArchiveConfig, ArchiveId, BlockId};
    use era_storage::LocalStorageBackend;
    use tempfile::TempDir;

    fn create_test_header() -> SuperHeader {
        SuperHeader::new(
            ArchiveId::new(),
            vec![],
            ArchiveConfig::default(),
            [0u8; 16],
        )
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
}
