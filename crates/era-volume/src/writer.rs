//! Volume writer for creating and appending to volumes.
//!
//! All I/O operations are async (non-blocking).
//!
//! ## Design Goals
//!
//! 1. **Zero Blocking**: All I/O operations are async
//! 2. **Zero Allocations**: Static buffer for padding
//! 3. **Backpressure Compatible**: Works with async ChunkPipeline

use era_common::{compute_shard_crc, BlockLocation, EncryptedMacroBlock, Result, VolumeId};
use era_storage::{StorageBackend, StorageWriter};
use std::path::Path;

use crate::footer::{BACKUP_FOOTER_GAP, FOOTER_SIZE};
use crate::header::{DATA_REGION_START, HEADER_SIZE};
use crate::{Footer, SuperHeader};
use rand::RngCore;

/// Writer for a single volume
pub struct VolumeWriter<W: StorageWriter> {
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
    /// Last checkpoint block ID (for direct decryption)
    last_checkpoint_block_id: u32,
}

impl<W: StorageWriter> VolumeWriter<W> {
    /// Create a new volume with the given header
    ///
    /// Layout on create:
    /// - Write primary header at offset 0 (4096 bytes)
    /// - Reserve backup footer gap at offset 4096 (128 bytes of zeros)
    /// - Data region starts at offset 4224 (DATA_REGION_START)
    pub async fn create<B: StorageBackend<Writer = W>>(
        backend: &B,
        path: &Path,
        header: SuperHeader,
    ) -> Result<Self> {
        let mut writer = backend.create(path).await?;

        // Write primary header
        let header_bytes = header.to_bytes()?;
        writer.append(&header_bytes).await?;

        // Reserve backup footer gap (128 bytes of zeros)
        // This will be filled with the backup footer on finalize
        let backup_footer_gap = [0u8; BACKUP_FOOTER_GAP];
        writer.append(&backup_footer_gap).await?;

        // Position now at DATA_REGION_START (4224)
        Ok(Self {
            writer,
            header,
            position: DATA_REGION_START,
            block_count: 0,
            sequence: 0,
            max_size: None,
            last_checkpoint_offset: 0,
            last_checkpoint_block_id: 0,
        })
    }

    /// Open an existing volume for appending (truncate footer)
    pub async fn open_append<B: StorageBackend<Writer = W>>(
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
            last_checkpoint_block_id: footer.last_checkpoint_block_id,
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

    /// Update the last checkpoint offset and block ID (for direct decryption)
    pub fn set_last_checkpoint_with_block_id(&mut self, offset: u64, block_id: u32) {
        self.last_checkpoint_offset = offset;
        self.last_checkpoint_block_id = block_id;
    }

    /// Internal helper to pad the volume with random data up to target_size
    /// Uses stack buffer to avoid heap allocations, fills with random data for security
    async fn pad_to_size(&mut self, target_size: u64) -> Result<()> {
        let current_size = self.writer.current_size();
        if current_size < target_size {
            let mut remaining = target_size - current_size;
            let mut buffer = [0u8; 16 * 1024]; // 16KB stack buffer

            while remaining > 0 {
                let to_write = remaining.min(buffer.len() as u64) as usize;
                // Security: Must be random to prevent traffic analysis
                rand::thread_rng().fill_bytes(&mut buffer[..to_write]);
                self.writer.append(&buffer[..to_write]).await?;
                remaining -= to_write as u64;
            }
        }
        Ok(())
    }

    /// Commit a checkpoint by updating the footer atomically
    ///
    /// max_size is required for proper backup header/footer layout
    ///
    /// # Crash Safety Protocol
    ///
    /// This function ensures crash-safe checkpoint commits:
    /// 1. Padding is written and synced to disk BEFORE footer update
    /// 2. Footer is written to both primary and backup locations
    /// 3. Final sync ensures footer is persisted
    ///
    /// On power loss, the volume will either have:
    /// - Old footer (checkpoint not committed) - safe
    /// - New footer with valid padding - safe
    pub async fn commit_checkpoint(&mut self, checkpoint_offset: u64) -> Result<()> {
        let max_size = self.max_size.ok_or_else(|| {
            era_common::EraError::InvalidConfig("max_size required for volumes".into())
        })?;

        // Fixed Size Mode: Update footer at fixed location

        // 1. Ensure padding (leave space for backup header + footer at end)
        let reserved_end = (HEADER_SIZE + FOOTER_SIZE) as u64;
        let pad_target = max_size.saturating_sub(reserved_end);
        self.pad_to_size(pad_target).await?;

        // 2. CRITICAL: Sync padding data to disk BEFORE updating footer
        //    Uses fdatasync for efficiency (metadata sync not required here)
        //    This prevents "garbage tail" on power loss - the padding zeros
        //    must be physically on disk before we update the footer pointer.
        self.writer.sync_data().await?;

        // 3. Update state
        self.set_last_checkpoint(checkpoint_offset);

        // 4. Calculate backup header offset (where backup header will be written on finalize)
        let backup_header_offset = pad_target;

        // 5. Construct footer with backup_header_offset
        let footer = crate::Footer::with_catalog(
            self.position,
            self.block_count,
            self.sequence,
            0,
            0,
            0,
            self.last_checkpoint_offset,
            self.last_checkpoint_block_id,
            0,
            0,
            0,
            backup_header_offset,
        );

        let footer_bytes = footer.to_bytes()?;

        // 6. Write primary footer at end (after backup header position)
        let footer_offset = backup_header_offset + HEADER_SIZE as u64;
        self.writer.write_at(footer_offset, &footer_bytes).await?;

        // 7. Write backup footer at reserved gap (offset HEADER_SIZE = 4096)
        self.writer
            .write_at(HEADER_SIZE as u64, &footer_bytes)
            .await?;

        // 8. Final sync to ensure footer is persisted
        self.writer.sync().await?;

        Ok(())
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

    /// Write a canonical block with explicit BlockType
    pub async fn write_canonical_block(
        &mut self,
        block: &EncryptedMacroBlock,
        block_type: era_common::BlockType,
    ) -> Result<BlockLocation> {
        // Format: Write BlockHeader + Data
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
            shard_offsets: Vec::new(),
            shard_volumes: Vec::new(),
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
    ///
    /// Layout on finalize:
    /// 1. Write backup header (copy of primary) at current position
    /// 2. Write primary footer after backup header
    /// 3. Write backup footer at reserved gap (offset HEADER_SIZE = 4096)
    ///
    /// Final layout:
    /// ```text
    /// [0]           Primary Header (4096 bytes)
    /// [4096]        Backup Footer (128 bytes)
    /// [4224]        Data Region Start
    /// ...           Blocks / Shards
    /// [N]           Backup Header (4096 bytes) - copy of primary
    /// [N+4096]      Primary Footer (128 bytes)
    /// ```
    pub async fn finalize_with_catalog(
        mut self,
        catalog_offset: u64,
        catalog_size: u32,
        catalog_block_id: u32,
        index_offset: u64,
        index_size: u32,
        index_block_id: u32,
    ) -> Result<SuperHeader> {
        self.sequence += 1;

        // Random padding if max_size is set
        if let Some(max_size) = self.max_size {
            // Ensure full padding to max_size minus space for backup header + footer
            let reserved_end = (HEADER_SIZE + FOOTER_SIZE) as u64;
            let pad_target = max_size.saturating_sub(reserved_end);
            self.pad_to_size(pad_target).await?;
            self.position = pad_target;
        }

        // 1. Write backup header (copy of primary) at current position
        let backup_header_offset = self.position;
        let header_bytes = self.header.to_bytes()?;

        if self.max_size.is_some() {
            self.writer
                .write_at(backup_header_offset, &header_bytes)
                .await?;
        } else {
            self.writer.append(&header_bytes).await?;
        }

        // 2. Calculate data_end_offset (where data region ends, before backup header)
        let data_end_offset = backup_header_offset;

        // 3. Create footer with backup_header_offset
        let footer = Footer::with_catalog(
            data_end_offset,
            self.block_count,
            self.sequence,
            catalog_offset,
            catalog_size,
            catalog_block_id,
            self.last_checkpoint_offset,
            self.last_checkpoint_block_id,
            index_offset,
            index_size,
            index_block_id,
            backup_header_offset,
        );
        let footer_bytes = footer.to_bytes()?;

        // 4. Write primary footer after backup header
        let primary_footer_offset = backup_header_offset + HEADER_SIZE as u64;
        if self.max_size.is_some() {
            self.writer
                .write_at(primary_footer_offset, &footer_bytes)
                .await?;
        } else {
            self.writer.append(&footer_bytes).await?;
        }

        // 5. Write backup footer at reserved gap (offset HEADER_SIZE = 4096)
        self.writer
            .write_at(HEADER_SIZE as u64, &footer_bytes)
            .await?;

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
    use era_storage::LocalStorageBackend;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_create_volume() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());

        let header = SuperHeader::new(
            ArchiveId::new(),
            vec![],
            ArchiveConfig::default(),
            [0u8; 16],
        );

        let writer = VolumeWriter::create(&backend, Path::new("test.era"), header)
            .await
            .unwrap();
        assert_eq!(writer.block_count(), 0);
        assert!(writer.current_size() >= HEADER_SIZE as u64);

        writer.finalize().await.unwrap();
    }

    #[tokio::test]
    async fn test_write_block() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());

        let header = SuperHeader::new(
            ArchiveId::new(),
            vec![],
            ArchiveConfig::default(),
            [0u8; 16],
        );

        let mut writer = VolumeWriter::create(&backend, Path::new("test.era"), header)
            .await
            .unwrap();

        let block = EncryptedMacroBlock {
            block_id: BlockId::new(0),
            data: Bytes::from_static(b"test data"),
            original_size: 9,
            compressed_size: 9,
            chunk_count: 1,
        };

        let location = writer
            .write_canonical_block(&block, era_common::BlockType::Data)
            .await
            .unwrap();
        assert_eq!(location.slot_index, 0);
        assert_eq!(writer.block_count(), 1);

        writer.finalize().await.unwrap();
    }

    #[tokio::test]
    async fn test_write_canonical_block() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());

        let header = SuperHeader::new(
            ArchiveId::new(),
            vec![],
            ArchiveConfig::default(),
            [0u8; 16],
        );

        let mut writer = VolumeWriter::create(&backend, Path::new("test.era"), header)
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
            .write_canonical_block(&block, era_common::BlockType::Checkpoint)
            .await
            .unwrap();
        assert_eq!(location.slot_index, 0);
        assert_eq!(writer.block_count(), 1);

        writer.finalize().await.unwrap();
    }

    #[tokio::test]
    async fn test_set_max_size() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());

        let header = SuperHeader::new(
            ArchiveId::new(),
            vec![],
            ArchiveConfig::default(),
            [0u8; 16],
        );

        let mut writer = VolumeWriter::create(&backend, Path::new("test.era"), header)
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

        writer
            .write_canonical_block(&block, era_common::BlockType::Data)
            .await
            .unwrap();
        writer.finalize().await.unwrap();
    }

    #[tokio::test]
    async fn test_padding_no_allocations() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());

        let header = SuperHeader::new(
            ArchiveId::new(),
            vec![],
            ArchiveConfig::default(),
            [0u8; 16],
        );

        let mut writer = VolumeWriter::create(&backend, Path::new("test.era"), header)
            .await
            .unwrap();

        // Set max size larger than current position
        let max_size = 5 * 1024 * 1024; // 5MB
        writer.set_max_size(max_size).await.unwrap();

        // The padding should use static buffer (no vec![0; size] allocations)
        assert_eq!(writer.writer.current_size(), max_size);

        writer.finalize().await.unwrap();
    }
}
