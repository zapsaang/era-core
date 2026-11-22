//! Write pipeline module.
//!
//! Coordinates the flow between encryption, erasure coding, volume writing,
//! and index management stages. This is the core orchestration layer that
//! replaces the scattered logic in ArchiveWriter.
//!
//! This module is part of the God Object decomposition effort (Phase 2).

use era_codec::{Compressor, ErasureCoder, ErasureConfig, NoCompressor, ZstdCompressor};
use era_common::{
    BlockHeader, BlockLocation, BlockType, ChunkHash, CompressionAlgorithm, CompressionConfig,
    EraError, ErasureBlockInfo, Result, UniqueChunk,
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
/// pipeline.process_chunks(chunks).await?;
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
    /// Cached erasure coder: (data_shards, parity_shards, coder)
    /// Reused across stripes with matching RS parameters
    cached_erasure_coder: Option<(usize, usize, ErasureCoder)>,
    /// Logical block locations written by this pipeline.
    written_blocks: Vec<BlockLocation>,
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
            cached_erasure_coder: None,
            written_blocks: Vec::new(),
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
    pub async fn process_chunks(&mut self, chunks: Vec<UniqueChunk>) -> Result<()> {
        let hashes: Vec<ChunkHash> = chunks.iter().map(|c| c.hash).collect();

        let compressor = self.create_compressor();
        let builder = self.encryption.create_block_builder(compressor)?;
        let prepared = builder.prepare_chunks(&chunks)?;

        if self.erasure.is_enabled() {
            let block_meta = BlockMeta {
                chunk_hashes: hashes,
                chunk_entries: Vec::new(),
            };
            // Erasure Coding Path: buffer block until stripe is complete
            if let Some(stripe) = self.erasure.buffer_block(prepared, block_meta)? {
                self.flush_stripe_internal(stripe).await?;
            }
        } else {
            let sealed_size = u64::try_from(prepared.sealed_len())
                .map_err(|_| EraError::InvalidConfig("sealed block length exceeds u64".into()))?;
            let total_size = sealed_size
                .checked_add(BlockHeader::SIZE as u64)
                .ok_or_else(|| EraError::InvalidConfig("canonical block size overflow".into()))?;
            let (slot, _) = self.volume.select_canonical_volume(total_size).await?;
            // Canonical non-EC Data keeps its legacy volume-0 AEAD context.
            let encrypted_block = builder.seal_prepared(&prepared, 0)?;

            let (mut location, _volume_id) = self
                .volume
                .write_block_to_slot(slot, &encrypted_block, BlockType::Data)
                .await?;
            location.slot_index = encrypted_block.block_id.sequence() as u32;
            self.written_blocks.push(location.clone());

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
        if let Some(stripe) = self.erasure.flush() {
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
    async fn flush_stripe_internal(&mut self, stripe: Stripe) -> Result<()> {
        let Stripe {
            mut data_blocks,
            block_meta,
            config,
        } = stripe;
        let data_shards_count = usize::from(config.data_shards);
        let parity_shards_count = usize::from(config.parity_shards);

        while data_blocks.len() < data_shards_count {
            let builder = self
                .encryption
                .create_block_builder(self.create_compressor())?;
            data_blocks.push(builder.prepare_chunks(&[])?);
        }
        let mut shard_lengths = data_blocks
            .iter()
            .map(|block| {
                u32::try_from(block.sealed_len())
                    .map_err(|_| EraError::InvalidConfig("sealed shard length exceeds u32".into()))
            })
            .collect::<Result<Vec<_>>>()?;
        let max_len = shard_lengths.iter().copied().max().unwrap_or(0);
        // Match encode_shards' two-byte alignment; only parity is stored padded.
        let shard_size = max_len
            .checked_add(max_len % 2)
            .ok_or_else(|| EraError::InvalidConfig("aligned parity length exceeds u32".into()))?
            .max(2);
        shard_lengths.resize(data_shards_count + parity_shards_count, shard_size);
        let volume_sequences = self
            .volume
            .reserve_stripe(&shard_lengths, data_shards_count)
            .await?;
        let stripe_lengths = &shard_lengths[..data_shards_count];

        let sealed_blocks = {
            let builder = self.encryption.create_block_builder_with_block_id(
                Box::new(NoCompressor),
                0,
                data_blocks[0].block_id().sequence(),
            )?;
            data_blocks
                .into_iter()
                .zip(volume_sequences)
                .map(|(block, sequence)| builder.seal_prepared(&block, u32::from(sequence)))
                .collect::<Result<Vec<_>>>()?
        };
        let shard_inputs: Vec<_> = sealed_blocks
            .iter()
            .map(|block| block.data.to_vec())
            .collect();

        // Compute parity shards (with cached erasure coder)
        // Check if cached coder matches current parameters
        let needs_new_coder = match &self.cached_erasure_coder {
            Some((cached_data, cached_parity, _)) => {
                *cached_data != data_shards_count || *cached_parity != parity_shards_count
            }
            None => true,
        };

        if needs_new_coder {
            let new_coder =
                ErasureCoder::new(ErasureConfig::new(data_shards_count, parity_shards_count)?)?;
            self.cached_erasure_coder = Some((data_shards_count, parity_shards_count, new_coder));
        }

        let coder = &self
            .cached_erasure_coder
            .as_ref()
            .ok_or_else(|| era_common::EraError::Other("Erasure coder not initialized".into()))?
            .2;
        let all_shards = coder.encode_shards(&shard_inputs)?;
        let parity_shards = &all_shards[data_shards_count..];

        // Write data blocks and collect location info
        let mut locations = Vec::with_capacity(block_meta.len());
        let mut data_info: Vec<(u16, u64)> = Vec::with_capacity(data_shards_count);

        for (i, block) in sealed_blocks.iter().enumerate() {
            let (entry, volume_id) = self
                .volume
                .write_shard(i, &block.data, stripe_lengths)
                .await?;
            if i < block_meta.len() {
                locations.push(BlockLocation::single(
                    volume_id,
                    block.block_id.0 as u32,
                    entry.physical_offset,
                    stripe_lengths[i],
                ));
            }
            data_info.push((entry.volume_sequence, entry.physical_offset));
        }

        // Write parity shards
        let mut parity_locations: Vec<(u16, u64)> = Vec::with_capacity(parity_shards_count);
        for (i, shard) in parity_shards.iter().enumerate() {
            let (entry, _) = self
                .volume
                .write_shard(data_shards_count + i, shard, stripe_lengths)
                .await?;
            parity_locations.push((entry.volume_sequence, entry.physical_offset));
        }

        // Advance block sequence for matrix distribution
        self.volume.advance_block_sequence();

        // Update index for data blocks with stripe information
        let mut erasure_written_blocks = Vec::with_capacity(block_meta.len());
        for (i, (meta, base)) in block_meta.iter().zip(locations).enumerate() {
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
                    data_shards: config.data_shards,
                    parity_shards: config.parity_shards,
                    shard_size,
                    original_len: base.encrypted_size,
                },
                shard_offsets,
                shard_volumes,
            )?;
            erasure_written_blocks.push(loc.clone());

            // Update index for all chunk hashes in this block
            for hash in &meta.chunk_hashes {
                self.index.record_location(*hash, loc.clone())?;
            }
        }

        self.written_blocks.extend(erasure_written_blocks);

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
    /// This should be called at safe points during archiving to enable crash recovery.
    ///
    /// For async-first checkpoint persistence with atomic volume writes, use
    /// `commit_to_volume()` instead. Both methods are valid depending on the
    /// orchestration context and whether synchronous or asynchronous flushing is needed.
    /// Ensure volume slot 0 has enough capacity for the durable checkpoint block before
    /// capturing data-only committed ends, rotating volumes if needed.
    pub async fn precheck_durable_checkpoint_space(&mut self) -> Result<bool> {
        let Some(mgr) = self.index.checkpoint_manager() else {
            return Ok(false);
        };
        let required = mgr.serialized_disk_size()?;
        self.volume.ensure_slot_typed_block_space(0, required).await
    }

    pub async fn commit_durable_checkpoint(&mut self) -> Result<()> {
        let Some(mgr) = self.index.checkpoint_manager_mut() else {
            return Ok(());
        };

        let Some(writer) = self.volume.get_writer_mut(0) else {
            return Err(EraError::InvalidConfig(
                "No primary volume writer available for checkpoint commit".into(),
            ));
        };

        let session = self.encryption.session();
        let volume_key = self.encryption.volume_key();
        let nonce_context = self.encryption.nonce_context();
        let archive_id = self.encryption.archive_id();
        let epoch_id = self.encryption.epoch_id();

        let block_id = self.encryption.next_block_id()?;
        mgr.commit_to_volume(
            writer,
            session,
            volume_key,
            nonce_context,
            archive_id,
            epoch_id,
            block_id,
        )
        .await?;

        Ok(())
    }

    /// Get the number of blocks written (from encryption context).
    pub fn blocks_written(&self) -> u64 {
        self.encryption.blocks_written()
    }

    pub fn advance_block_id(&self, n: u64) -> Result<()> {
        self.encryption.advance_block_id(n)
    }

    pub fn reserve_block_id(&self) -> Result<u64> {
        self.encryption.next_block_id()
    }

    /// Get the block locations written by this pipeline.
    #[cfg(test)]
    pub fn written_block_locations(&self) -> &[BlockLocation] {
        &self.written_blocks
    }

    /// Take the block locations written by this pipeline.
    pub fn take_written_block_locations(&mut self) -> Vec<BlockLocation> {
        std::mem::take(&mut self.written_blocks)
    }

    /// Get a reference to the encryption context.
    pub fn encryption(&self) -> &EncryptionContext {
        &self.encryption
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
    #[cfg(test)]
    pub fn index_mut(&mut self) -> &mut IndexStage {
        &mut self.index
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
        let volume_key = session.generate_and_wrap_volume_key().unwrap().0;
        let nonce_context = salt.as_bytes()[..16].try_into().unwrap();
        EncryptionContext::new(session, volume_key, nonce_context, [0xAA; 16], 1, 0)
    }

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

        pipeline.process_chunks(vec![chunk]).await.unwrap();

        // Chunk should now be indexed
        assert!(pipeline.contains(&hash).unwrap());
        assert!(pipeline.get_location(&hash).unwrap().is_some());
    }

    #[tokio::test]
    async fn test_pipeline_indexes_only_chunk_hashes() {
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

        let chunk = create_test_chunk(b"Packed data");
        let chunk_hash = chunk.hash;
        let unrelated_hash = ChunkHash::from_bytes([42u8; 32]);

        pipeline.process_chunks(vec![chunk]).await.unwrap();

        assert!(pipeline.contains(&chunk_hash).unwrap());
        assert!(!pipeline.contains(&unrelated_hash).unwrap());
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
        let erasure = ErasureStage::new(Some(erasure_config)).unwrap();
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

        pipeline.process_chunks(vec![chunk1]).await.unwrap();
        // First chunk buffered, not yet indexed
        assert!(!pipeline.contains(&hash1).unwrap());

        pipeline.process_chunks(vec![chunk2]).await.unwrap();
        // Stripe complete, both chunks should be indexed
        assert!(pipeline.contains(&hash1).unwrap());
        assert!(pipeline.contains(&hash2).unwrap());
    }

    #[tokio::test]
    async fn test_block_locations_tracking() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_path = temp_dir.path().join("test_archive");

        let config = VolumePoolConfig::new(&base_path, 1);
        let header = create_test_header();
        let pool = VolumePool::create(backend, config, header).await?;

        let encryption = create_test_encryption();
        let erasure = ErasureStage::disabled();
        let volume = VolumeStage::new(pool);
        let index = IndexStage::without_checkpoint(Arc::new(MemoryChunkIndex::new()));
        let compression = CompressionConfig::default();

        let mut pipeline = WritePipeline::new(encryption, erasure, volume, index, compression);

        assert!(pipeline.written_block_locations().is_empty());

        pipeline
            .process_chunks(vec![create_test_chunk(b"chunk-1")])
            .await?;
        pipeline
            .process_chunks(vec![create_test_chunk(b"chunk-2")])
            .await?;
        pipeline
            .process_chunks(vec![create_test_chunk(b"chunk-3")])
            .await?;

        let locations = pipeline.written_block_locations();
        assert_eq!(locations.len(), 3);
        assert!(locations
            .iter()
            .all(|location| { location.physical_offset > 0 && location.encrypted_size > 0 }));

        let taken_locations = pipeline.take_written_block_locations();
        assert_eq!(taken_locations.len(), 3);
        assert!(pipeline.written_block_locations().is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_block_locations_tracking_erasure() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_path = temp_dir.path().join("test_archive");

        let erasure_config = ErasureCodeConfig::new(2, 1);
        let config = VolumePoolConfig::new(&base_path, 3).for_erasure(erasure_config);
        let header = create_test_header();
        let pool = VolumePool::create(backend, config, header).await?;

        let encryption = create_test_encryption();
        let erasure = ErasureStage::new(Some(erasure_config))?;
        let volume = VolumeStage::new(pool);
        let index = IndexStage::without_checkpoint(Arc::new(MemoryChunkIndex::new()));
        let compression = CompressionConfig::default();

        let mut pipeline = WritePipeline::new(encryption, erasure, volume, index, compression);

        assert!(pipeline.written_block_locations().is_empty());

        pipeline
            .process_chunks(vec![create_test_chunk(b"Chunk 1 data")])
            .await?;
        pipeline
            .process_chunks(vec![create_test_chunk(b"Chunk 2 data")])
            .await?;

        assert_eq!(pipeline.written_block_locations().len(), 2);

        Ok(())
    }
}
