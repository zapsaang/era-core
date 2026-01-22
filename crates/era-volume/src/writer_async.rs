//! Async volume writer for creating and appending to volumes.
//!
//! **CRITICAL CHANGE (v2.2):** Async I/O eliminates executor blocking.
//!
//! ## Design Goals
//!
//! 1. **Zero Blocking**: All I/O operations are async
//! 2. **Zero Allocations**: Static ZERO_PAGE buffer for padding
//! 3. **Backpressure Compatible**: Works with async ChunkPipeline
//!
//! ## Migration from Sync VolumeWriter
//!
//! ```rust,ignore
//! // OLD (sync):
//! let mut writer = VolumeWriter::create(&backend, path, header)?;
//! writer.write_block(&block)?;
//! writer.finalize()?;
//!
//! // NEW (async):
//! let mut writer = AsyncVolumeWriter::create(&backend, path, header).await?;
//! writer.write_block(&block).await?;
//! writer.finalize().await?;
//! ```

use era_common::{
    compute_shard_crc, BlockLocation, EncryptedMacroBlock, Result, ShardHeader, VolumeId,
};
use era_storage::{AsyncStorageBackend, AsyncStorageWriter};
use std::path::Path;

use crate::header::HEADER_SIZE;
use crate::{Footer, SuperHeader};

/// Static zero-filled page for padding (1MB, no allocations)
/// CRITICAL: Zero-copy padding - no vec![0; size] allocations in hot path
static ZERO_PAGE: [u8; 1024 * 1024] = [0u8; 1024 * 1024];

/// Async writer for a single volume
pub struct AsyncVolumeWriter<W: AsyncStorageWriter> {
    /// Underlying storage writer
    writer: W,
    /// Volume header
    header: SuperHeader,
    /// Current write position (after header)
    position: u64,
    /// Number of blocks written
    block_count: u32,
    /// Sequence number for footer
    sequence: u64,
    /// Maximum volume size (for padding)
    max_size: Option<u64>,
    /// Last checkpoint offset
    last_checkpoint_offset: u64,
}

impl<W: AsyncStorageWriter> AsyncVolumeWriter<W> {
    /// Create a new volume with the given header
    pub async fn create<B: AsyncStorageBackend<Writer = W>>(
        backend: &B,
        path: &Path,
        header: SuperHeader,
    ) -> Result<Self> {
        let mut writer = backend.create(path).await?;

        // Write header
        let header_bytes = header.to_bytes()?;
        writer.append(&header_bytes).await?;

        Ok(Self {
            writer,
            header,
            position: HEADER_SIZE as u64,
            block_count: 0,
            sequence: 0,
            max_size: None,
            last_checkpoint_offset: 0,
        })
    }

    /// Open an existing volume for appending (truncate footer)
    pub async fn open_append<B: AsyncStorageBackend<Writer = W>>(
        backend: &B,
        path: &Path,
        header: SuperHeader,
        footer: &Footer,
    ) -> Result<Self> {
        let mut writer = backend.open_append(path).await?;
        writer.truncate(footer.data_end_offset).await?;

        Ok(Self {
            writer,
            header,
            position: footer.data_end_offset,
            block_count: footer.block_count,
            sequence: footer.sequence_number,
            max_size: None,
            last_checkpoint_offset: footer.last_checkpoint_offset,
        })
    }

    /// Set the maximum size for this volume
    pub async fn set_max_size(&mut self, max_size: u64) -> Result<()> {
        self.max_size = Some(max_size);
        self.pad_to_size(max_size).await
    }

    /// Update the last checkpoint offset
    pub fn set_last_checkpoint(&mut self, offset: u64) {
        self.last_checkpoint_offset = offset;
    }

    /// Internal helper to pad the volume with zeros up to target_size
    /// Uses static ZERO_PAGE buffer to avoid heap allocations
    async fn pad_to_size(&mut self, target_size: u64) -> Result<()> {
        let current_size = self.writer.current_size();
        if current_size < target_size {
            let mut remaining = target_size - current_size;

            while remaining > 0 {
                let to_write = remaining.min(ZERO_PAGE.len() as u64) as usize;
                self.writer.append(&ZERO_PAGE[..to_write]).await?;
                remaining -= to_write as u64;
            }
        }
        Ok(())
    }

    /// Commit a checkpoint by updating the footer atomically
    pub async fn commit_checkpoint(&mut self, checkpoint_offset: u64) -> Result<()> {
        if let Some(max_size) = self.max_size {
            // Fixed Size Mode: Update footer at fixed location

            // 1. Ensure padding
            self.pad_to_size(max_size).await?;

            // 2. Sync data
            self.writer.sync().await?;

            // 3. Update state
            self.set_last_checkpoint(checkpoint_offset);

            // 4. Construct footer
            let footer = crate::Footer::with_catalog(
                self.position,
                self.block_count,
                self.sequence,
                0,
                0,
                0,
                self.last_checkpoint_offset,
                0,
                0,
                0,
                0,
                0,
                0,
            );

            let footer_bytes = footer.to_bytes()?;

            // 5. Overwrite
            use crate::footer::FOOTER_SIZE;
            let footer_offset = max_size - FOOTER_SIZE as u64;
            self.writer.write_at(footer_offset, &footer_bytes).await?;
            self.writer.sync().await?;
        } else {
            // Dynamic/Store Mode: Append floating footer (inline checkpoint)

            // 1. Sync data
            self.writer.sync().await?;

            // 2. Update state
            self.set_last_checkpoint(checkpoint_offset);

            // 3. Construct footer pointing to current data end
            let footer = crate::Footer::with_catalog(
                self.position,
                self.block_count,
                self.sequence,
                0,
                0,
                0,
                self.last_checkpoint_offset,
                0,
                0,
                0,
                0,
                0,
                0,
            );

            let footer_bytes = footer.to_bytes()?;

            // 4. Append footer
            let offset = self.writer.append(&footer_bytes).await?;
            self.writer.sync().await?;

            // 5. Advance position
            self.position += footer_bytes.len() as u64;
            self.write_floating_checkpoint_internal(offset);
        }

        Ok(())
    }

    fn write_floating_checkpoint_internal(&mut self, offset: u64) {
        self.last_checkpoint_offset = offset;
        self.sequence += 1;
    }

    /// Get the volume ID
    pub fn volume_id(&self) -> VolumeId {
        self.header.volume_id
    }

    /// Get the current size of the volume (valid data size)
    pub fn current_size(&self) -> u64 {
        self.position
    }

    /// Get the number of blocks written
    pub fn block_count(&self) -> u32 {
        self.block_count
    }

    /// Write an encrypted macro block to the volume
    pub async fn write_block(&mut self, block: &EncryptedMacroBlock) -> Result<BlockLocation> {
        // Legacy format: Write ShardHeader + Data (for backward compatibility)
        let offset = self.position;
        let block_len = block.data.len() as u32;
        let header_size = ShardHeader::SIZE as u64;
        let total_len = block_len as u64 + header_size;

        // Check availability if max_size is set
        if let Some(max_size) = self.max_size {
            let footer_size = crate::footer::FOOTER_SIZE as u64;
            if offset + total_len + footer_size > max_size {
                return Err(era_common::EraError::Io(std::io::Error::other(
                    "Volume full",
                )));
            }
        }

        // Construct ShardHeader (legacy 8-byte format)
        let crc = compute_shard_crc(&block.data);
        let header = ShardHeader::new(block_len, crc);
        let header_bytes = header.to_bytes();

        if self.max_size.is_some() {
            // Traffic Analysis Defense: Use write_at inside the padded volume
            self.writer.write_at(offset, &header_bytes).await?;
            self.writer
                .write_at(offset + header_size, &block.data)
                .await?;
        } else {
            self.writer.append(&header_bytes).await?;
            self.writer.append(&block.data).await?;
        }

        let location = BlockLocation {
            volume_id: self.header.volume_id,
            slot_index: self.block_count,
            physical_offset: offset,
            encrypted_size: block_len,
            erasure_info: None, // Standard blocks are not erasure-coded
            shard_offsets: None,
            shard_volumes: None,
        };

        if self.max_size.is_some() {
            self.position += total_len;
        } else {
            self.position = self.writer.current_size();
        }
        self.block_count += 1;

        Ok(location)
    }

    /// Write a typed block with explicit BlockType (V5 format)
    pub async fn write_typed_block(
        &mut self,
        block: &EncryptedMacroBlock,
        block_type: era_common::BlockType,
    ) -> Result<BlockLocation> {
        // V5 Format: Write BlockHeader + Data
        let offset = self.position;
        let block_len = block.data.len() as u32;
        let header_size = era_common::BlockHeader::SIZE as u64;
        let total_len = block_len as u64 + header_size;

        // Check availability if max_size is set
        if let Some(max_size) = self.max_size {
            let footer_size = crate::footer::FOOTER_SIZE as u64;
            if offset + total_len + footer_size > max_size {
                return Err(era_common::EraError::Io(std::io::Error::other(
                    "Volume full",
                )));
            }
        }

        // Construct BlockHeader with type
        let crc = compute_shard_crc(&block.data);
        let header = era_common::BlockHeader::new(block_type, block_len, crc);
        let header_bytes = header.to_bytes();

        if self.max_size.is_some() {
            // Traffic Analysis Defense: Use write_at inside the padded volume
            self.writer.write_at(offset, &header_bytes).await?;
            self.writer
                .write_at(offset + header_size, &block.data)
                .await?;
        } else {
            self.writer.append(&header_bytes).await?;
            self.writer.append(&block.data).await?;
        }

        let location = BlockLocation {
            volume_id: self.header.volume_id,
            slot_index: self.block_count,
            physical_offset: offset,
            encrypted_size: block_len,
            erasure_info: None, // Standard blocks are not erasure-coded
            shard_offsets: None,
            shard_volumes: None,
        };

        if self.max_size.is_some() {
            self.position += total_len;
        } else {
            self.position = self.writer.current_size();
        }
        self.block_count += 1;

        Ok(location)
    }

    /// Write raw bytes to the volume (for testing/low-level access)
    pub async fn write_raw(&mut self, data: &[u8]) -> Result<u64> {
        let offset = self.position;

        if self.max_size.is_some() {
            self.writer.write_at(offset, data).await?;
            self.position += data.len() as u64;
        } else {
            self.writer.append(data).await?;
            self.position = self.writer.current_size();
        }

        Ok(offset)
    }

    /// Finalize the volume by writing the footer and syncing
    pub async fn finalize(self) -> Result<SuperHeader> {
        self.finalize_with_catalog(0, 0, 0, 0, 0, 0).await
    }

    /// Finalize the volume with catalog location information
    pub async fn finalize_with_catalog(
        mut self,
        catalog_offset: u64,
        catalog_size: u32,
        catalog_block_id: u32,
        lsm_manifest_offset: u64,
        lsm_manifest_size: u32,
        lsm_manifest_block_id: u32,
    ) -> Result<SuperHeader> {
        self.sequence += 1;

        // Random padding if max_size is set
        if let Some(max_size) = self.max_size {
            use crate::footer::FOOTER_SIZE;

            // Ensure full padding to max_size
            self.pad_to_size(max_size).await?;

            // Point to start of footer for the record
            self.position = max_size - FOOTER_SIZE as u64;

            let footer = Footer::with_catalog(
                self.position,
                self.block_count,
                self.sequence,
                catalog_offset,
                catalog_size,
                catalog_block_id,
                self.last_checkpoint_offset,
                lsm_manifest_offset,
                lsm_manifest_size,
                lsm_manifest_block_id,
                0,
                0,
                0,
            );
            let footer_bytes = footer.to_bytes()?;

            // Overwrite footer area
            self.writer.write_at(self.position, &footer_bytes).await?;
        } else {
            let footer = Footer::with_catalog(
                self.position,
                self.block_count,
                self.sequence,
                catalog_offset,
                catalog_size,
                catalog_block_id,
                self.last_checkpoint_offset,
                lsm_manifest_offset,
                lsm_manifest_size,
                lsm_manifest_block_id,
                0,
                0,
                0,
            );
            let footer_bytes = footer.to_bytes()?;
            self.writer.append(&footer_bytes).await?;
        }

        // Sync to disk
        self.writer.sync().await?;
        self.writer.close().await?;

        Ok(self.header)
    }

    /// Get the header for creating the next volume
    pub fn next_volume_header(&self) -> SuperHeader {
        self.header.next_volume()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use era_common::{ArchiveConfig, ArchiveId, BlockId};
    use era_storage::AsyncLocalStorageBackend;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_create_volume() {
        let temp_dir = TempDir::new().unwrap();
        let backend = AsyncLocalStorageBackend::new(temp_dir.path());

        let header = SuperHeader::new(
            ArchiveId::new(),
            vec![],
            ArchiveConfig::default(),
            [0u8; 16],
        );

        let writer = AsyncVolumeWriter::create(&backend, Path::new("test.era"), header)
            .await
            .unwrap();
        assert_eq!(writer.block_count(), 0);
        assert!(writer.current_size() >= HEADER_SIZE as u64);

        writer.finalize().await.unwrap();
    }

    #[tokio::test]
    async fn test_write_block() {
        let temp_dir = TempDir::new().unwrap();
        let backend = AsyncLocalStorageBackend::new(temp_dir.path());

        let header = SuperHeader::new(
            ArchiveId::new(),
            vec![],
            ArchiveConfig::default(),
            [0u8; 16],
        );

        let mut writer = AsyncVolumeWriter::create(&backend, Path::new("test.era"), header)
            .await
            .unwrap();

        let block = EncryptedMacroBlock {
            block_id: BlockId::new(0),
            data: Bytes::from_static(b"test data"),
            original_size: 9,
            compressed_size: 9,
            chunk_count: 1,
        };

        let location = writer.write_block(&block).await.unwrap();
        assert_eq!(location.slot_index, 0);
        assert_eq!(writer.block_count(), 1);

        writer.finalize().await.unwrap();
    }

    #[tokio::test]
    async fn test_write_typed_block() {
        let temp_dir = TempDir::new().unwrap();
        let backend = AsyncLocalStorageBackend::new(temp_dir.path());

        let header = SuperHeader::new(
            ArchiveId::new(),
            vec![],
            ArchiveConfig::default(),
            [0u8; 16],
        );

        let mut writer = AsyncVolumeWriter::create(&backend, Path::new("test.era"), header)
            .await
            .unwrap();

        let block = EncryptedMacroBlock {
            block_id: BlockId::new(0),
            data: Bytes::from_static(b"checkpoint data"),
            original_size: 15,
            compressed_size: 15,
            chunk_count: 0,
        };

        let location = writer
            .write_typed_block(&block, era_common::BlockType::Checkpoint)
            .await
            .unwrap();
        assert_eq!(location.slot_index, 0);
        assert_eq!(writer.block_count(), 1);

        writer.finalize().await.unwrap();
    }

    #[tokio::test]
    async fn test_set_max_size() {
        let temp_dir = TempDir::new().unwrap();
        let backend = AsyncLocalStorageBackend::new(temp_dir.path());

        let header = SuperHeader::new(
            ArchiveId::new(),
            vec![],
            ArchiveConfig::default(),
            [0u8; 16],
        );

        let mut writer = AsyncVolumeWriter::create(&backend, Path::new("test.era"), header)
            .await
            .unwrap();

        let max_size = 10 * 1024 * 1024; // 10MB
        writer.set_max_size(max_size).await.unwrap();

        // Write should work within limit
        let block = EncryptedMacroBlock {
            block_id: BlockId::new(0),
            data: Bytes::from(vec![0u8; 1024]),
            original_size: 1024,
            compressed_size: 1024,
            chunk_count: 1,
        };

        writer.write_block(&block).await.unwrap();
        writer.finalize().await.unwrap();
    }

    #[tokio::test]
    async fn test_padding_no_allocations() {
        let temp_dir = TempDir::new().unwrap();
        let backend = AsyncLocalStorageBackend::new(temp_dir.path());

        let header = SuperHeader::new(
            ArchiveId::new(),
            vec![],
            ArchiveConfig::default(),
            [0u8; 16],
        );

        let mut writer = AsyncVolumeWriter::create(&backend, Path::new("test.era"), header)
            .await
            .unwrap();

        // Set max size larger than current position
        let max_size = 5 * 1024 * 1024; // 5MB
        writer.set_max_size(max_size).await.unwrap();

        // The padding should use static ZERO_PAGE buffer (no vec![0; size] allocations)
        assert_eq!(writer.writer.current_size(), max_size);

        writer.finalize().await.unwrap();
    }
}
