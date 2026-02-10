//! Write pipeline module.
//!
//! Coordinates the flow between encryption, erasure coding, volume writing,
//! and index management stages. This is the core orchestration layer that
//! replaces the scattered logic in ArchiveWriter.
//!
//! This module is part of the God Object decomposition effort (Phase 2).

use era_codec::{Compressor, ErasureCoder, ErasureConfig, NoCompressor, ZstdCompressor};
use era_common::{
    BlockLocation, BlockType, ChunkHash, CompressionAlgorithm, CompressionConfig,
    EncryptedMacroBlock, ErasureBlockInfo, Result, UniqueChunk,
};
use era_packing::{BlockMeta, Stripe};
use era_storage::StorageBackend;

use crate::encryption_context::EncryptionContext;
use crate::erasure_stage::ErasureStage;
use crate::index_stage::IndexStage;
use crate::volume_stage::VolumeStage;

/// Write pipeline for coordinating the archive write path.
///
/// This pipeline orchestrates the flow:
/// ```text
/// Chunks → Encryption → Erasure Buffering → Volume Writing → Index Update
/// ```
///
/// ## Responsibilities
///
/// - Creating encrypted blocks from chunks
/// - Buffering blocks for erasure coding (when enabled)
/// - Writing blocks/shards to volumes
/// - Recording chunk locations in the index
///
/// ## Usage
///
/// ```ignore
/// let mut pipeline = WritePipeline::new(encryption, erasure, volume, index, compression);
///
/// // Process chunks (handles encryption, erasure buffering, writing, indexing)
/// pipeline.process_chunks(chunks, extra_hashes).await?;
///
/// // At finalization, flush any remaining erasure buffer
/// pipeline.flush_stripe().await?;
/// ```
pub struct WritePipeline<B: StorageBackend> {
    /// Encryption context for block encryption
    encryption: EncryptionContext,
    /// Erasure coding stage for stripe buffering
    erasure: ErasureStage,
    /// Volume stage for physical storage
    volume: VolumeStage<B>,
    /// Index stage for deduplication and recovery
    index: IndexStage,
    /// Compression configuration
    compression_config: CompressionConfig,
}

impl<B: StorageBackend> WritePipeline<B> {
    /// Create a new write pipeline.
    ///
    /// # Arguments
    /// * `encryption` - Encryption context with key session and volume key
    /// * `erasure` - Erasure coding stage (may be disabled)
    /// * `volume` - Volume stage for storage writes
    /// * `index` - Index stage for deduplication
    /// * `compression_config` - Compression settings
    pub fn new(
        encryption: EncryptionContext,
        erasure: ErasureStage,
        volume: VolumeStage<B>,
        index: IndexStage,
        compression_config: CompressionConfig,
    ) -> Self {
        Self {
            encryption,
            erasure,
            volume,
            index,
            compression_config,
        }
    }

    /// Process chunks through the full pipeline.
    ///
    /// This method:
    /// 1. Creates an encrypted block from the chunks
    /// 2. Either writes directly (non-erasure) or buffers for stripe formation (erasure)
    /// 3. Updates the index with chunk locations
    ///
    /// # Arguments
    /// * `chunks` - The chunks to process
    /// * `extra_hashes` - Additional hashes to associate with the block location
    ///   (e.g., small file hashes that map to a packed chunk)
    pub async fn process_chunks(
        &mut self,
        chunks: Vec<UniqueChunk>,
        extra_hashes: Vec<ChunkHash>,
    ) -> Result<()> {
        // Collect all hashes that need index update for this block
        let mut hashes: Vec<ChunkHash> = chunks.iter().map(|c| c.hash).collect();
        hashes.extend(extra_hashes);

        let block_meta = BlockMeta {
            chunk_hashes: hashes.clone(),
            chunk_entries: Vec::new(),
        };

        // Create encrypted block
        let compressor = self.create_compressor();
        let builder = self.encryption.create_block_builder(compressor);
        let encrypted_block = builder.pack_chunks(chunks)?;

        if self.erasure.is_enabled() {
            // Erasure Coding Path: buffer block until stripe is complete
            let maybe_stripe = self.erasure.buffer_block(encrypted_block, block_meta)?;
            if let Some(stripe) = maybe_stripe {
                self.flush_stripe_internal(stripe).await?;
            }
        } else {
            // Non-erasure path: write directly
            let (location, _volume_id) = self
                .volume
                .write_block(&encrypted_block, BlockType::Data)
                .await?;

            // Update index for all hashes
            for hash in hashes {
                self.index.record_location(hash, location.clone())?;
            }
        }

        Ok(())
    }

    /// Flush any remaining blocks in the erasure buffer.
    ///
    /// This should be called during finalization to ensure all buffered
    /// blocks are written (with padding if necessary).
    pub async fn flush_stripe(&mut self) -> Result<()> {
        if let Some(stripe) = self.erasure.flush()? {
            self.flush_stripe_internal(stripe).await?;
        }
        Ok(())
    }

    /// Flush a complete stripe to storage.
    ///
    /// This handles:
    /// 1. Writing data blocks (and padding blocks for partial stripes)
    /// 2. Computing and writing parity shards
    /// 3. Updating the index with erasure metadata
    #[allow(clippy::needless_range_loop)]
    async fn flush_stripe_internal(&mut self, stripe: Stripe) -> Result<()> {
        let volume_count = self.volume.volume_count();

        if volume_count == 0 {
            return Err(era_common::EraError::Io(std::io::Error::other(
                "No volume writers available",
            )));
        }

        let data_shards_count = stripe.config.data_shards as usize;
        let parity_shards_count = stripe.config.parity_shards as usize;

        // Prepare stripe lengths and padding blocks
        let mut stripe_lengths: Vec<u32> = vec![0; data_shards_count];
        let mut padding_blocks: Vec<Option<EncryptedMacroBlock>> = vec![None; data_shards_count];

        for i in 0..data_shards_count {
            if i < stripe.data_blocks.len() {
                stripe_lengths[i] = stripe.data_blocks[i].data.len() as u32;
            } else {
                // Create padding block for partial stripe
                let compressor = self.create_compressor();
                let builder = self.encryption.create_block_builder(compressor);
                let encrypted_block = builder.pack_chunks(vec![])?;
                stripe_lengths[i] = encrypted_block.data.len() as u32;
                padding_blocks[i] = Some(encrypted_block);
            }
        }

        // Prepare shard inputs for parity computation
        let mut shard_inputs: Vec<Vec<u8>> = Vec::with_capacity(data_shards_count);
        for i in 0..data_shards_count {
            if i < stripe.data_blocks.len() {
                shard_inputs.push(stripe.data_blocks[i].data.to_vec());
            } else {
                let padding_block = padding_blocks[i]
                    .as_ref()
                    .expect("Padding block should be prepared");
                shard_inputs.push(padding_block.data.to_vec());
            }
        }

        // Compute parity shards
        let coder = ErasureCoder::new(ErasureConfig::new(data_shards_count, parity_shards_count)?)?;
        let all_shards = coder.encode_shards(&shard_inputs)?;
        let parity_shards = all_shards[data_shards_count..].to_vec();

        // Write data blocks and collect location info
        let mut locations = Vec::new();
        let mut data_info: Vec<(u16, u64)> = Vec::with_capacity(data_shards_count);

        for i in 0..data_shards_count {
            if i < stripe.data_blocks.len() {
                let block = &stripe.data_blocks[i];
                let (entry, volume_id) = self
                    .volume
                    .write_shard(i, &block.data, false, 0, Some(&stripe_lengths))
                    .await?;

                let loc = BlockLocation::single(
                    volume_id,
                    block.block_id.0 as u32,
                    entry.physical_offset,
                    block.data.len() as u32,
                );
                locations.push(loc);
                data_info.push((entry.volume_sequence, entry.physical_offset));
            } else {
                // Write padding block
                let encrypted_block = padding_blocks[i]
                    .take()
                    .expect("Padding block should be prepared");

                let (entry, _) = self
                    .volume
                    .write_shard(i, &encrypted_block.data, false, 0, Some(&stripe_lengths))
                    .await?;
                data_info.push((entry.volume_sequence, entry.physical_offset));
            }
        }

        // Write parity shards
        let mut parity_locations: Vec<(u16, u64)> = Vec::with_capacity(parity_shards_count);
        for (i, shard) in parity_shards.iter().enumerate() {
            let (entry, _) = self
                .volume
                .write_shard(
                    data_shards_count + i,
                    shard,
                    false,
                    0,
                    Some(&stripe_lengths),
                )
                .await?;
            parity_locations.push((entry.volume_sequence, entry.physical_offset));
        }

        // Advance block sequence for matrix distribution
        self.volume.advance_block_sequence();

        // Update index for data blocks with stripe information
        for (i, meta) in stripe.block_meta.iter().enumerate() {
            let base = &locations[i];

            // Build shard_offsets and shard_volumes (excluding self)
            let mut shard_offsets = Vec::new();
            let mut shard_volumes = Vec::new();

            for (j, (sequence, offset)) in data_info.iter().enumerate() {
                if i != j {
                    shard_offsets.push(*offset);
                    shard_volumes.push(*sequence);
                }
            }

            for (sequence, offset) in &parity_locations {
                shard_offsets.push(*offset);
                shard_volumes.push(*sequence);
            }

            let loc = BlockLocation::erasure(
                base.volume_id,
                base.slot_index,
                base.physical_offset,
                base.encrypted_size,
                ErasureBlockInfo {
                    data_shards: stripe.config.data_shards,
                    parity_shards: stripe.config.parity_shards,
                    shard_size: stripe.shard_size,
                    original_len: base.encrypted_size,
                },
                shard_offsets,
                shard_volumes,
            );

            // Update index for all chunk hashes in this block
            for hash in &meta.chunk_hashes {
                self.index.record_location(*hash, loc.clone())?;
            }
        }

        Ok(())
    }

    /// Check if a chunk exists in the index (deduplication check).
    pub fn contains(&self, hash: &ChunkHash) -> Result<bool> {
        self.index.contains(hash)
    }

    /// Get a chunk location from the index.
    pub fn get_location(&self, hash: &ChunkHash) -> Result<Option<BlockLocation>> {
        self.index.get(hash)
    }

    /// Record a chunk location directly (for special cases).
    pub fn record_location(&mut self, hash: ChunkHash, location: BlockLocation) -> Result<()> {
        self.index.record_location(hash, location)
    }

    /// Create a fresh compressor based on configuration.
    ///
    /// This is called for each pack operation since compressors may have internal state.
    pub fn create_compressor(&self) -> Box<dyn Compressor> {
        match self.compression_config.algorithm {
            CompressionAlgorithm::None => Box::new(NoCompressor),
            CompressionAlgorithm::Zstd => {
                Box::new(ZstdCompressor::new(self.compression_config.level))
            }
            CompressionAlgorithm::LZ4 => {
                Box::new(era_codec::LZ4Compressor::new(self.compression_config.level))
            }
        }
    }

    /// Check if erasure coding is enabled.
    pub fn erasure_enabled(&self) -> bool {
        self.erasure.is_enabled()
    }

    /// Sync the checkpoint to stable storage.
    ///
    /// This should be called at safe points during archiving to enable
    /// crash recovery.
    pub fn sync_checkpoint(&mut self) -> Result<()> {
        self.index.sync_checkpoint()
    }

    /// Get the number of blocks written (from encryption context).
    pub fn blocks_written(&self) -> u64 {
        self.encryption.blocks_written()
    }

    /// Get a reference to the encryption context.
    pub fn encryption(&self) -> &EncryptionContext {
        &self.encryption
    }

    /// Get a reference to the erasure stage.
    #[allow(dead_code)]
    pub fn erasure(&self) -> &ErasureStage {
        &self.erasure
    }

    /// Get a mutable reference to the erasure stage.
    #[allow(dead_code)]
    pub fn erasure_mut(&mut self) -> &mut ErasureStage {
        &mut self.erasure
    }

    /// Get a reference to the volume stage.
    pub fn volume(&self) -> &VolumeStage<B> {
        &self.volume
    }

    /// Get a mutable reference to the volume stage.
    pub fn volume_mut(&mut self) -> &mut VolumeStage<B> {
        &mut self.volume
    }

    /// Get a reference to the index stage.
    pub fn index(&self) -> &IndexStage {
        &self.index
    }

    /// Get a mutable reference to the index stage.
    #[allow(dead_code)]
    pub fn index_mut(&mut self) -> &mut IndexStage {
        &mut self.index
    }

    /// Decompose the pipeline into its constituent parts.
    ///
    /// This is useful during finalization when you need direct access
    /// to individual stages.
    #[allow(dead_code)]
    pub fn into_parts(self) -> (EncryptionContext, ErasureStage, VolumeStage<B>, IndexStage) {
        (self.encryption, self.erasure, self.volume, self.index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk_index::MemoryChunkIndex;
    use bytes::Bytes;
    use era_common::{ArchiveConfig, ArchiveId, ErasureCodeConfig};
    use era_crypto::{KdfParams, KeySession, Salt};
    use era_storage::LocalStorageBackend;
    use era_volume::{SuperHeader, VolumePool, VolumePoolConfig};
    use std::sync::Arc;
    use tempfile::TempDir;

    fn create_test_encryption() -> EncryptionContext {
        let salt = Salt::generate();
        let params = KdfParams::default();
        let session = KeySession::new(b"test_password", &salt, &params).unwrap();
        let volume_key = session.derive_volume_key(0);
        let nonce_context = salt.as_bytes()[..16].try_into().unwrap();
        EncryptionContext::new(session, volume_key, nonce_context)
    }

    fn create_test_header() -> SuperHeader {
        SuperHeader::new(
            ArchiveId::new(),
            vec![],
            ArchiveConfig::default(),
            [0u8; 16],
        )
    }

    fn create_test_chunk(data: &[u8]) -> UniqueChunk {
        let hash = era_crypto::hash(data);
        UniqueChunk::new(Bytes::from(data.to_vec()), hash)
    }

    #[tokio::test]
    async fn test_pipeline_non_erasure() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_path = temp_dir.path().join("test_archive");

        let config = VolumePoolConfig::new(&base_path, 1);
        let header = create_test_header();
        let pool = VolumePool::create(backend, config, header).await.unwrap();

        let encryption = create_test_encryption();
        let erasure = ErasureStage::disabled();
        let volume = VolumeStage::new(pool);
        let index = IndexStage::without_checkpoint(Arc::new(MemoryChunkIndex::new()));
        let compression = CompressionConfig::default();

        let mut pipeline = WritePipeline::new(encryption, erasure, volume, index, compression);

        // Process a chunk
        let chunk = create_test_chunk(b"Hello, World!");
        let hash = chunk.hash;

        assert!(!pipeline.contains(&hash).unwrap());

        pipeline.process_chunks(vec![chunk], vec![]).await.unwrap();

        // Chunk should now be indexed
        assert!(pipeline.contains(&hash).unwrap());
        assert!(pipeline.get_location(&hash).unwrap().is_some());
    }

    #[tokio::test]
    async fn test_pipeline_with_extra_hashes() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_path = temp_dir.path().join("test_archive");

        let config = VolumePoolConfig::new(&base_path, 1);
        let header = create_test_header();
        let pool = VolumePool::create(backend, config, header).await.unwrap();

        let encryption = create_test_encryption();
        let erasure = ErasureStage::disabled();
        let volume = VolumeStage::new(pool);
        let index = IndexStage::without_checkpoint(Arc::new(MemoryChunkIndex::new()));
        let compression = CompressionConfig::default();

        let mut pipeline = WritePipeline::new(encryption, erasure, volume, index, compression);

        // Process a chunk with extra hashes (simulating packed small files)
        let chunk = create_test_chunk(b"Packed data");
        let extra_hash = ChunkHash::from_bytes([42u8; 32]);

        pipeline
            .process_chunks(vec![chunk], vec![extra_hash])
            .await
            .unwrap();

        // Both the chunk hash and extra hash should be indexed
        assert!(pipeline.contains(&extra_hash).unwrap());
    }

    #[tokio::test]
    async fn test_pipeline_erasure_enabled() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_path = temp_dir.path().join("test_archive");

        let erasure_config = ErasureCodeConfig::new(2, 1);
        let config = VolumePoolConfig::new(&base_path, 3).for_erasure(erasure_config);
        let header = create_test_header();
        let pool = VolumePool::create(backend, config, header).await.unwrap();

        let encryption = create_test_encryption();
        let erasure = ErasureStage::new(Some(erasure_config));
        let volume = VolumeStage::new(pool);
        let index = IndexStage::without_checkpoint(Arc::new(MemoryChunkIndex::new()));
        let compression = CompressionConfig::default();

        let mut pipeline = WritePipeline::new(encryption, erasure, volume, index, compression);

        assert!(pipeline.erasure_enabled());

        // Process two chunks to form a complete stripe (K=2)
        let chunk1 = create_test_chunk(b"Chunk 1 data");
        let chunk2 = create_test_chunk(b"Chunk 2 data");
        let hash1 = chunk1.hash;
        let hash2 = chunk2.hash;

        pipeline.process_chunks(vec![chunk1], vec![]).await.unwrap();
        // First chunk buffered, not yet indexed
        assert!(!pipeline.contains(&hash1).unwrap());

        pipeline.process_chunks(vec![chunk2], vec![]).await.unwrap();
        // Stripe complete, both chunks should be indexed
        assert!(pipeline.contains(&hash1).unwrap());
        assert!(pipeline.contains(&hash2).unwrap());
    }
}
