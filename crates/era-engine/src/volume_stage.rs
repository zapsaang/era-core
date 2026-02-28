//! Volume stage module.
//!
//! Encapsulates all volume pool interactions for writing blocks and shards.
//! This stage sits at the end of the write pipeline, handling physical storage.
//!
//! This module is part of the God Object decomposition effort (Phase 2).

use era_common::{
    BlockLocation, BlockType, EncryptedMacroBlock, MatrixShardEntry, Result, VolumeId,
};
use era_storage::StorageBackend;
use era_volume::{VolumePool, VolumePoolStats, VolumeWriter};

/// Volume stage for managing physical storage writes.
///
/// This stage sits at the end of the write pipeline:
/// ```text
/// Encryption → Erasure → [VolumeStage] → Storage
/// ```
///
/// ## Responsibilities
///
/// - Writing encrypted blocks to volumes (non-erasure path)
/// - Writing erasure shards with matrix distribution
/// - Writing catalog blocks to all volumes for redundancy
/// - Managing volume rotation when volumes fill up
/// - Tracking block sequences for matrix distribution
#[allow(dead_code)]
pub struct VolumeStage<B: StorageBackend> {
    /// The underlying volume pool
    pool: VolumePool<B>,
}

#[allow(dead_code)]
impl<B: StorageBackend> VolumeStage<B> {
    /// Create a new volume stage wrapping a volume pool.
    pub fn new(pool: VolumePool<B>) -> Self {
        Self { pool }
    }

    /// Get the number of active volumes.
    pub fn volume_count(&self) -> usize {
        self.pool.volume_count()
    }

    /// Advance the block sequence after completing a full stripe.
    ///
    /// This is called after writing all shards of an erasure-coded stripe
    /// to ensure proper matrix distribution for the next stripe.
    pub fn advance_block_sequence(&mut self) {
        self.pool.advance_block_sequence();
    }

    /// Get the current block sequence number.
    pub fn block_sequence(&self) -> u64 {
        self.pool.block_sequence()
    }

    /// Write a single canonical block (non-erasure path).
    ///
    /// This writes a block using the BlockHeader format directly to storage.
    /// Used for non-erasure-coded archives or special blocks like catalog.
    ///
    /// # Arguments
    /// * `block` - The encrypted block to write
    /// * `block_type` - The type of block (Data, Catalog, etc.)
    ///
    /// # Returns
    /// A tuple of (BlockLocation, VolumeId) indicating where the block was written.
    pub async fn write_block(
        &mut self,
        block: &EncryptedMacroBlock,
        block_type: BlockType,
    ) -> Result<(BlockLocation, VolumeId)> {
        self.pool.write_canonical_block(block, block_type).await
    }

    /// Write an erasure shard with matrix distribution.
    ///
    /// Shards are distributed across volumes according to the matrix distribution
    /// strategy configured in the volume pool.
    ///
    /// # Arguments
    /// * `shard_index` - The shard index (0..total_shards)
    /// * `data` - The shard data to write
    /// * `include_original_len` - Whether to include the original length header
    /// * `original_len` - The original data length (used if include_original_len is true)
    /// * `stripe_lengths` - Optional stripe length prefix for recovery
    ///
    /// # Returns
    /// A tuple of (MatrixShardEntry, VolumeId) with location information.
    pub async fn write_shard(
        &mut self,
        shard_index: usize,
        data: &[u8],
        include_original_len: bool,
        original_len: u32,
        stripe_lengths: Option<&[u32]>,
    ) -> Result<(MatrixShardEntry, VolumeId)> {
        self.pool
            .write_shard(
                shard_index,
                data,
                include_original_len,
                original_len,
                stripe_lengths,
            )
            .await
    }

    /// Write catalog block to all volumes for full redundancy.
    ///
    /// The catalog is written to every volume in the pool to ensure
    /// it can be recovered even if some volumes are lost.
    ///
    /// # Arguments
    /// * `block` - The encrypted catalog block
    /// * `backup_block` - Optional backup block for erasure-coded archives
    ///
    /// # Returns
    /// A vector of (offset, size, block_id) tuples for each volume.
    pub async fn write_catalog_to_all(
        &mut self,
        block: &EncryptedMacroBlock,
        backup_block: Option<&EncryptedMacroBlock>,
    ) -> Result<Vec<(u64, u32, u32)>> {
        let volume_count = self.pool.volume_count();
        let mut catalog_locations: Vec<(u64, u32, u32)> = Vec::with_capacity(volume_count);
        let block_id = block.block_id.sequence() as u32;

        for slot in 0..volume_count {
            if let Some(writer) = self.pool.get_writer_mut(slot) {
                let mut location = writer
                    .write_canonical_block(block, BlockType::Catalog)
                    .await?;
                // Override slot_index with actual block_id for correct key derivation during read
                location.slot_index = block_id;

                if let Some(backup) = backup_block {
                    let _backup_location = writer
                        .write_canonical_block(backup, BlockType::Catalog)
                        .await?;
                }

                catalog_locations.push((
                    location.physical_offset,
                    location.encrypted_size,
                    block_id,
                ));
            }
        }

        Ok(catalog_locations)
    }

    /// Finalize all volumes with catalog location information.
    ///
    /// This writes footers to all volumes and closes them.
    ///
    /// # Arguments
    /// * `catalog_locations` - Per-volume catalog locations (offset, size, block_id)
    /// * `index_locations` - Optional per-volume index locations
    ///
    /// # Returns
    /// Statistics about the finalized volume pool.
    pub async fn finalize(
        &mut self,
        catalog_locations: &[(u64, u32, u32)],
        index_locations: Option<&[(u64, u32, u32)]>,
    ) -> Result<VolumePoolStats> {
        self.pool
            .finalize_with_catalogs(catalog_locations, index_locations)
            .await
    }

    /// Get a mutable reference to a specific volume writer.
    ///
    /// This is useful for direct volume access when needed.
    pub fn get_writer_mut(&mut self, slot: usize) -> Option<&mut VolumeWriter<B::Writer>> {
        self.pool.get_writer_mut(slot)
    }

    /// Get the archive ID from the volume pool.
    pub fn archive_id(&self) -> era_common::ArchiveId {
        self.pool.archive_id()
    }

    /// Get current statistics from the volume pool.
    pub fn stats(&self) -> &VolumePoolStats {
        self.pool.stats()
    }

    /// Consume the stage and return the underlying volume pool.
    ///
    /// This is useful when you need direct access to the pool for
    /// operations not exposed by the stage interface.
    pub fn into_inner(self) -> VolumePool<B> {
        self.pool
    }

    /// Get a reference to the underlying volume pool.
    ///
    /// Prefer using the stage methods when possible.
    pub fn pool(&self) -> &VolumePool<B> {
        &self.pool
    }

    /// Get a mutable reference to the underlying volume pool.
    ///
    /// Prefer using the stage methods when possible.
    pub fn pool_mut(&mut self) -> &mut VolumePool<B> {
        &mut self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use era_common::{ArchiveConfig, ArchiveId, BlockId};
    use era_storage::LocalStorageBackend;
    use era_volume::{SuperHeader, VolumePoolConfig};
    use tempfile::TempDir;

    fn create_test_header() -> SuperHeader {
        SuperHeader::new(
            ArchiveId::new(),
            vec![era_volume::RecipientSlot::new(
                era_volume::RecipientType::Argon2idPassword,
                Some([0x12; 8]),
                vec![0xAB; 16],
                vec![0xCD; 48],
            )],
            ArchiveConfig::default(),
            [0u8; 16],
            era_volume::EncryptedVolumeKey {
                algorithm: era_volume::KeyWrapAlgorithm::XChaCha20Poly1305,
                nonce: [0u8; 24],
                ciphertext: vec![0u8; 48],
            },
            era_volume::AccessPolicy::AnyOfN,
        )
        .unwrap()
    }

    fn create_test_block(id: u64) -> EncryptedMacroBlock {
        EncryptedMacroBlock {
            block_id: BlockId::new(id),
            data: Bytes::from(vec![0u8; 1024]),
            original_size: 1024,
            compressed_size: 1024,
            chunk_count: 1,
        }
    }

    #[tokio::test]
    async fn test_volume_stage_creation() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_path = temp_dir.path().join("test_archive");

        let config = VolumePoolConfig::new(&base_path, 2);
        let header = create_test_header();

        let pool = VolumePool::create(backend, config, header).await.unwrap();
        let stage = VolumeStage::new(pool);

        assert_eq!(stage.volume_count(), 2);
        assert_eq!(stage.block_sequence(), 0);
    }

    #[tokio::test]
    async fn test_write_block() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_path = temp_dir.path().join("test_archive");

        let config = VolumePoolConfig::new(&base_path, 1);
        let header = create_test_header();

        let pool = VolumePool::create(backend, config, header).await.unwrap();
        let mut stage = VolumeStage::new(pool);

        let block = create_test_block(0);
        let (location, _volume_id) = stage.write_block(&block, BlockType::Data).await.unwrap();

        assert!(location.physical_offset > 0);
        assert_eq!(location.encrypted_size, block.data.len() as u32);
    }

    #[tokio::test]
    async fn test_advance_block_sequence() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_path = temp_dir.path().join("test_archive");

        let config = VolumePoolConfig::new(&base_path, 1);
        let header = create_test_header();

        let pool = VolumePool::create(backend, config, header).await.unwrap();
        let mut stage = VolumeStage::new(pool);

        assert_eq!(stage.block_sequence(), 0);
        stage.advance_block_sequence();
        assert_eq!(stage.block_sequence(), 1);
        stage.advance_block_sequence();
        assert_eq!(stage.block_sequence(), 2);
    }
}
