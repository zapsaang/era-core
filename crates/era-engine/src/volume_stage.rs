//! Volume stage module.
//!
//! Encapsulates all volume pool interactions for writing blocks and shards.
//! This stage sits at the end of the write pipeline, handling physical storage.
//!
//! This module is part of the God Object decomposition effort (Phase 2).

use era_common::{
    BlockId, BlockLocation, BlockType, EncryptedMacroBlock, EraError, MatrixShardEntry, Result,
    VolumeId,
};
use era_crypto::encrypt_with_context_for_type;
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

    /// Get the current sequence number for a volume slot.
    pub fn volume_sequence(&self, slot: usize) -> Option<u16> {
        self.pool.volume_sequence(slot)
    }

    /// Get the volume sequence for the next canonical block write target.
    pub fn next_canonical_volume_sequence(&self) -> Option<u16> {
        self.pool.next_canonical_volume_sequence()
    }

    /// Check whether a canonical block would force volume expansion/rotation.
    pub fn needs_expansion(&self, required_size: u64) -> Result<bool> {
        self.pool.needs_expansion(required_size)
    }

    /// Precheck typed-block fanout space and rotate volumes if needed.
    pub async fn precheck_and_rotate_if_needed(
        &mut self,
        catalog_size: u64,
        index_size: u64,
        manifest_size: u64,
    ) -> Result<bool> {
        self.pool
            .precheck_and_rotate_if_needed(catalog_size, index_size, manifest_size)
            .await
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
        if volume_count == 0 {
            return Err(EraError::Other(
                "No writable volumes available for catalog fanout".into(),
            ));
        }
        let mut catalog_locations: Vec<(u64, u32, u32)> = Vec::with_capacity(volume_count);
        let block_id = u32::try_from(block.block_id.sequence())
            .map_err(|_| EraError::Other("Block sequence ID exceeds u32::MAX".into()))?;

        for slot in 0..volume_count {
            if let Some(writer) = self.pool.get_writer_mut(slot) {
                let mut location = writer
                    .write_canonical_block(block, BlockType::Catalog)
                    .await?;
                // CRITICAL: Override the physical slot_index with the logical block_id.
                //
                // Why this mutation is necessary:
                // - VolumeWriter.write_canonical_block() returns a BlockLocation with slot_index
                //   set to the sequential write position (e.g., 1st block written = slot_index 1,
                //   2nd block written = slot_index 2, etc.)
                // - For catalog blocks, the reader must derive per-block AEAD keys using the
                //   logical block sequence number (block_id), NOT the physical write position.
                // - The AEAD decryption AAD is: archive_id ‖ epoch_id ‖ block_index, where
                //   block_index comes from the catalog's block_id metadata.
                // - Without this override, the reader would attempt decryption with an incorrect
                //   AAD (using the physical write position), causing AEAD authentication to fail
                //   even though the catalog block is intact and encrypted correctly.
                //
                // Impact: This ensures catalog blocks can be successfully decrypted during read,
                // since both encryption (here) and decryption (in reader.rs) will use the same
                // block_id for key derivation and AAD binding.
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
            } else {
                return Err(EraError::Other(format!(
                    "Missing catalog writer slot {slot} while writing catalog fanout"
                )));
            }
        }

        Ok(catalog_locations)
    }

    pub async fn write_catalog_blocks_to_all(
        &mut self,
        blocks: &[EncryptedMacroBlock],
        backup_blocks: Option<&[EncryptedMacroBlock]>,
    ) -> Result<Vec<(u64, u32, u32)>> {
        let volume_count = self.pool.volume_count();
        if volume_count == 0 {
            return Err(EraError::Other(
                "No writable volumes available for catalog fanout".into(),
            ));
        }
        if blocks.is_empty() {
            return Err(EraError::Other("No catalog blocks to write".into()));
        }

        let first_block_id = u32::try_from(blocks[0].block_id.sequence())
            .map_err(|_| EraError::Other("Block sequence ID exceeds u32::MAX".into()))?;

        let mut catalog_locations: Vec<(u64, u32, u32)> = Vec::with_capacity(volume_count);

        for slot in 0..volume_count {
            if let Some(writer) = self.pool.get_writer_mut(slot) {
                let mut first_location = None;

                for (i, block) in blocks.iter().enumerate() {
                    let mut location = writer
                        .write_canonical_block(block, BlockType::Catalog)
                        .await?;

                    let block_id = u32::try_from(block.block_id.sequence()).map_err(|_| {
                        EraError::Other("Block sequence ID exceeds u32::MAX".into())
                    })?;
                    location.slot_index = block_id;

                    if i == 0 {
                        first_location = Some(location);
                    }
                }

                if let Some(backup_blocks) = backup_blocks {
                    for backup in backup_blocks {
                        let _backup_location = writer
                            .write_canonical_block(backup, BlockType::Catalog)
                            .await?;
                    }
                }

                let loc = first_location
                    .ok_or_else(|| EraError::Other("No catalog block written".into()))?;
                catalog_locations.push((loc.physical_offset, loc.encrypted_size, first_block_id));
            } else {
                return Err(EraError::Other(format!(
                    "Missing catalog writer slot {slot} while writing catalog fanout"
                )));
            }
        }

        Ok(catalog_locations)
    }

    /// Write already re-bound catalog block sets to every volume.
    ///
    /// Each entry in `blocks_by_volume` must contain the same logical catalog
    /// block IDs encrypted with that target volume's sequence in nonce/AAD.
    pub async fn write_catalog_block_sets_to_all(
        &mut self,
        blocks_by_volume: &[Vec<EncryptedMacroBlock>],
        backup_blocks_by_volume: Option<&[Vec<EncryptedMacroBlock>]>,
    ) -> Result<Vec<(u64, u32, u32)>> {
        let volume_count = self.pool.volume_count();
        if volume_count == 0 {
            return Err(EraError::Other(
                "No writable volumes available for catalog fanout".into(),
            ));
        }
        if blocks_by_volume.len() != volume_count {
            return Err(EraError::InvalidConfig(format!(
                "catalog block-set count {} does not match volume count {}",
                blocks_by_volume.len(),
                volume_count
            )));
        }
        if let Some(backup_sets) = backup_blocks_by_volume {
            if backup_sets.len() != volume_count {
                return Err(EraError::InvalidConfig(format!(
                    "catalog backup block-set count {} does not match volume count {}",
                    backup_sets.len(),
                    volume_count
                )));
            }
        }

        let mut catalog_locations = Vec::with_capacity(volume_count);
        for slot in 0..volume_count {
            let blocks = &blocks_by_volume[slot];
            if blocks.is_empty() {
                return Err(EraError::Other(format!(
                    "No catalog blocks to write for volume slot {slot}"
                )));
            }

            let Some(writer) = self.pool.get_writer_mut(slot) else {
                return Err(EraError::Other(format!(
                    "Missing catalog writer slot {slot} while writing catalog fanout"
                )));
            };

            let first_block_id = u32::try_from(blocks[0].block_id.sequence())
                .map_err(|_| EraError::Other("Block sequence ID exceeds u32::MAX".into()))?;
            let mut first_location = None;

            for (i, block) in blocks.iter().enumerate() {
                let mut location = writer
                    .write_canonical_block(block, BlockType::Catalog)
                    .await?;
                location.slot_index = u32::try_from(block.block_id.sequence())
                    .map_err(|_| EraError::Other("Block sequence ID exceeds u32::MAX".into()))?;
                if i == 0 {
                    first_location = Some(location);
                }
            }

            if let Some(backup_sets) = backup_blocks_by_volume {
                for backup in &backup_sets[slot] {
                    let mut location = writer
                        .write_canonical_block(backup, BlockType::Catalog)
                        .await?;
                    location.slot_index =
                        u32::try_from(backup.block_id.sequence()).map_err(|_| {
                            EraError::Other("Block sequence ID exceeds u32::MAX".into())
                        })?;
                }
            }

            let loc =
                first_location.ok_or_else(|| EraError::Other("No catalog block written".into()))?;
            catalog_locations.push((loc.physical_offset, loc.encrypted_size, first_block_id));
        }

        Ok(catalog_locations)
    }

    /// Write one pre-encrypted manifest block to each volume.
    pub async fn write_manifest_to_all(
        &mut self,
        blocks: &[EncryptedMacroBlock],
    ) -> Result<Vec<(u64, u32, u32)>> {
        let volume_count = self.pool.volume_count();
        if volume_count == 0 {
            return Err(EraError::Other(
                "No writable volumes available for manifest fanout".into(),
            ));
        }
        if blocks.len() != volume_count {
            return Err(EraError::InvalidConfig(format!(
                "manifest block count {} does not match volume count {}",
                blocks.len(),
                volume_count
            )));
        }

        let mut manifest_locations = Vec::with_capacity(volume_count);
        for (slot, block) in blocks.iter().enumerate() {
            let block_id = u32::try_from(block.block_id.sequence())
                .map_err(|_| EraError::Other("Block sequence ID exceeds u32::MAX".into()))?;

            let Some(writer) = self.pool.get_writer_mut(slot) else {
                return Err(EraError::Other(format!(
                    "Missing manifest writer slot {slot} while writing manifest fanout"
                )));
            };

            let mut location = writer
                .write_canonical_block(block, BlockType::Manifest)
                .await?;
            location.slot_index = block_id;
            manifest_locations.push((location.physical_offset, location.encrypted_size, block_id));
        }

        Ok(manifest_locations)
    }

    /// Write index block fanout to volumes 1..N-1.
    ///
    /// Volume 0 is assumed to have already been written by the caller
    /// (typically via `IndexBuilder::finalize_with_starting_block_id`).
    /// This method re-encrypts the same plaintext for each remaining volume
    /// using per-volume nonces to ensure proper AEAD context binding.
    ///
    /// # Arguments
    /// * `index_plaintext` - The serialized MetaIndex plaintext bytes
    /// * `index_block_id` - The logical block ID used for key derivation
    /// * `session` - KeySession for block key derivation
    /// * `volume_key` - VolumeKey for block key derivation
    /// * `nonce_context` - 16-byte nonce context for per-volume nonce derivation
    /// * `archive_id` - 16-byte archive ID for AAD binding
    /// * `epoch_id` - Epoch ID for AAD binding
    ///
    /// # Returns
    /// Per-volume locations for slots 1..N-1 as `(offset, size, block_id)` tuples.
    #[allow(clippy::too_many_arguments)]
    pub async fn write_index_fanout(
        &mut self,
        index_plaintext: &[u8],
        index_block_id: u32,
        session: &era_crypto::KeySession,
        volume_key: &era_crypto::VolumeKey,
        nonce_context: &[u8; 16],
        archive_id: &[u8; 16],
        epoch_id: u32,
    ) -> Result<Vec<(u64, u32, u32)>> {
        let volume_count = self.pool.volume_count();
        if volume_count <= 1 {
            return Ok(Vec::new());
        }

        let block_key =
            session.derive_block_key(volume_key, u64::from(index_block_id), nonce_context)?;
        let derived_key = block_key.to_derived_key()?;
        let original_size = u32::try_from(index_plaintext.len())
            .map_err(|_| EraError::Other("MetaIndex size exceeds u32::MAX".into()))?;

        let mut locations = Vec::with_capacity(volume_count - 1);

        for slot in 1..volume_count {
            let Some(writer) = self.pool.get_writer_mut(slot) else {
                return Err(EraError::Other(format!(
                    "Missing index writer slot {slot} while writing index fanout"
                )));
            };

            let volume_index = u32::from(writer.volume_sequence());
            let encrypted_data = encrypt_with_context_for_type(
                &derived_key,
                nonce_context,
                archive_id,
                epoch_id,
                volume_index,
                BlockType::IndexManifest,
                BlockId::new(u64::from(index_block_id)),
                index_plaintext,
            )?;

            let encrypted_index_block = EncryptedMacroBlock {
                block_id: BlockId::new(u64::from(index_block_id)),
                data: encrypted_data,
                original_size,
                compressed_size: original_size,
                chunk_count: 0,
            };

            let mut location = writer
                .write_canonical_block(&encrypted_index_block, BlockType::IndexManifest)
                .await?;
            location.slot_index = index_block_id;
            locations.push((
                location.physical_offset,
                location.encrypted_size,
                index_block_id,
            ));
        }

        Ok(locations)
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

    /// Finalize all volumes with catalog, index, and manifest location information.
    pub async fn finalize_with_manifest(
        &mut self,
        catalog_locations: &[(u64, u32, u32)],
        index_locations: Option<&[(u64, u32, u32)]>,
        manifest_locations: Option<&[(u64, u32, u32)]>,
    ) -> Result<VolumePoolStats> {
        self.pool
            .finalize_with_catalogs_and_manifest(
                catalog_locations,
                index_locations,
                manifest_locations,
            )
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
            era_volume::EncryptedVolumeKey::new(
                era_volume::KeyWrapAlgorithm::XChaCha20Poly1305,
                [0u8; 24],
                vec![0u8; 48],
            ),
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
