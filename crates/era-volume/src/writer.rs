//! Volume writer for creating and appending to volumes.

use era_common::{compute_shard_crc, BlockLocation, EncryptedMacroBlock, Result, VolumeId};
use era_storage::{StorageBackend, StorageWriter};
use std::path::Path;

use crate::header::HEADER_SIZE;
use crate::{Footer, SuperHeader};

/// Static zero-filled page for padding (1MB, no allocations)
/// CRITICAL: Zero-copy padding - no vec![0; size] allocations in hot path
static ZERO_PAGE: [u8; 1024 * 1024] = [0u8; 1024 * 1024];

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
    /// Last checkpoint block ID (V6+, for direct decryption)
    last_checkpoint_block_id: u32,
}

impl<W: StorageWriter> VolumeWriter<W> {
    /// Create a new volume with the given header
    pub fn create<B: StorageBackend<Writer = W>>(
        backend: &B,
        path: &Path,
        header: SuperHeader,
    ) -> Result<Self> {
        let mut writer = backend.create(path)?;

        // Write header
        let header_bytes = header.to_bytes()?;
        writer.append(&header_bytes)?;

        Ok(Self {
            writer,
            header,
            position: HEADER_SIZE as u64,
            block_count: 0,
            sequence: 0,
            max_size: None,
            last_checkpoint_offset: 0,
            last_checkpoint_block_id: 0,
        })
    }

    /// Open an existing volume for appending (truncate footer)
    pub fn open_append<B: StorageBackend<Writer = W>>(
        backend: &B,
        path: &Path,
        header: SuperHeader,
        footer: &Footer,
    ) -> Result<Self> {
        let mut writer = backend.open_append(path)?;
        writer.truncate(footer.data_end_offset)?;

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
    pub fn set_max_size(&mut self, max_size: u64) -> Result<()> {
        self.max_size = Some(max_size);
        self.pad_to_size(max_size)
    }

    /// Update the last checkpoint offset
    pub fn set_last_checkpoint(&mut self, offset: u64) {
        self.last_checkpoint_offset = offset;
    }

    /// Update the last checkpoint offset and block ID (V6+)
    pub fn set_last_checkpoint_with_block_id(&mut self, offset: u64, block_id: u32) {
        self.last_checkpoint_offset = offset;
        self.last_checkpoint_block_id = block_id;
    }

    /// Internal helper to pad the volume with zeros up to target_size
    /// Uses static ZERO_PAGE buffer to avoid heap allocations
    fn pad_to_size(&mut self, target_size: u64) -> Result<()> {
        let current_size = self.writer.current_size();
        if current_size < target_size {
            let mut remaining = target_size - current_size;

            while remaining > 0 {
                let to_write = remaining.min(ZERO_PAGE.len() as u64) as usize;
                self.writer.append(&ZERO_PAGE[..to_write])?;
                remaining -= to_write as u64;
            }
        }
        Ok(())
    }

    /// Commit a checkpoint by updating the footer atomically
    pub fn commit_checkpoint(&mut self, checkpoint_offset: u64) -> Result<()> {
        if let Some(max_size) = self.max_size {
            // Fixed Size Mode: Update footer at fixed location

            // 1. Ensure padding
            self.pad_to_size(max_size)?;

            // 2. Sync data
            self.writer.sync()?;

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
                self.last_checkpoint_block_id,
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
            self.writer.write_at(footer_offset, &footer_bytes)?;
            self.writer.sync()?;
        } else {
            // Dynamic/Store Mode: Append floating footer (inline checkpoint)
            // This enables "Journaling" where we have a stream of [Data...][Footer][Data...][Footer]

            // 1. Sync data
            self.writer.sync()?;

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
                self.last_checkpoint_block_id,
                0,
                0,
                0,
                0,
                0,
                0,
            );

            let footer_bytes = footer.to_bytes()?;

            // 4. Append footer
            let offset = self.writer.append(&footer_bytes)?;
            self.writer.sync()?;

            // 5. Advance position (Footer is now part of the stream)
            // Note: This means subsequent blocks will be shifted.
            // The Reader must be able to handle scanning or use the Index which we aren't persisting here yet.
            // But for "Atomic Checkpoint" of the *Stream*, this is correct.
            self.position += footer_bytes.len() as u64;

            // Update last_checkpoint to point to this footer?
            // The previous logic `self.set_last_checkpoint(checkpoint_offset)` sets the `last_checkpoint_offset` field *inside* the footer.
            // But `self.last_checkpoint_offset` struct field tracks the *location of the footer itself* for the *next* footer to reference?
            // Yes, usually a linked list.
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

    /// Write a typed block with explicit BlockType (V5 format)
    pub fn write_typed_block(
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
            self.writer.write_at(offset, &header_bytes)?;
            self.writer.write_at(offset + header_size, &block.data)?;
        } else {
            self.writer.append(&header_bytes)?;
            self.writer.append(&block.data)?;
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
    pub fn write_raw(&mut self, data: &[u8]) -> Result<u64> {
        let offset = self.position;

        if self.max_size.is_some() {
            self.writer.write_at(offset, data)?;
            self.position += data.len() as u64;
        } else {
            self.writer.append(data)?;
            self.position = self.writer.current_size();
        }

        Ok(offset)
    }

    /// Finalize the volume by writing the footer and syncing
    pub fn finalize(self) -> Result<SuperHeader> {
        self.finalize_with_catalog(0, 0, 0, 0, 0, 0)
    }

    /// Finalize the volume with catalog location information
    pub fn finalize_with_catalog(
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
            self.pad_to_size(max_size)?;

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
                self.last_checkpoint_block_id,
                lsm_manifest_offset,
                lsm_manifest_size,
                lsm_manifest_block_id,
                0,
                0,
                0,
            );
            let footer_bytes = footer.to_bytes()?;

            // Overwrite footer area
            self.writer.write_at(self.position, &footer_bytes)?;
        } else {
            let footer = Footer::with_catalog(
                self.position,
                self.block_count,
                self.sequence,
                catalog_offset,
                catalog_size,
                catalog_block_id,
                self.last_checkpoint_offset,
                self.last_checkpoint_block_id,
                lsm_manifest_offset,
                lsm_manifest_size,
                lsm_manifest_block_id,
                0,
                0,
                0,
            );
            let footer_bytes = footer.to_bytes()?;
            self.writer.append(&footer_bytes)?;
        }

        // Sync to disk
        self.writer.sync()?;
        self.writer.close()?;

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

    #[test]
    fn test_create_volume() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());

        let header = SuperHeader::new(
            ArchiveId::new(),
            vec![],
            ArchiveConfig::default(),
            [0u8; 16],
        );

        let writer = VolumeWriter::create(&backend, Path::new("test.era"), header).unwrap();
        assert_eq!(writer.block_count(), 0);
        assert!(writer.current_size() >= HEADER_SIZE as u64);

        writer.finalize().unwrap();
    }

    #[test]
    fn test_write_block() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());

        let header = SuperHeader::new(
            ArchiveId::new(),
            vec![],
            ArchiveConfig::default(),
            [0u8; 16],
        );

        let mut writer = VolumeWriter::create(&backend, Path::new("test.era"), header).unwrap();

        let block = EncryptedMacroBlock {
            block_id: BlockId::new(0),
            data: Bytes::from(vec![0u8; 1024]),
            original_size: 2048,
            compressed_size: 1024,
            chunk_count: 5,
        };

        let location = writer
            .write_typed_block(&block, era_common::BlockType::Data)
            .unwrap();
        assert_eq!(location.slot_index, 0);
        assert_eq!(location.encrypted_size, 1024);

        writer.finalize().unwrap();
    }

    #[test]
    fn test_volume_padding_and_atomic_check() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());

        let header = SuperHeader::new(
            ArchiveId::new(),
            vec![],
            ArchiveConfig::default(),
            [0u8; 16],
        );

        let mut writer = VolumeWriter::create(&backend, Path::new("padded.era"), header).unwrap();

        let header_size = crate::header::HEADER_SIZE as u64;
        let footer_size = crate::footer::FOOTER_SIZE as u64;

        // Define max size: Header + 1 Block (data + BlockHeader) + Padding (500) + Footer
        // V5 format uses BlockHeader::SIZE (16 bytes) instead of ShardHeader::SIZE (8 bytes)
        let data_len = 1008; // Adjusted for 16-byte header
        let block_header_size = era_common::BlockHeader::SIZE as u64;
        let block_disk_size = data_len as u64 + block_header_size; // 1024 total
        let padding_size = 500;

        let max_size = header_size + block_disk_size + padding_size + footer_size;
        writer.set_max_size(max_size).unwrap();

        let block = EncryptedMacroBlock {
            block_id: BlockId::new(0),
            data: Bytes::from(vec![0u8; data_len]),
            original_size: 2048,
            compressed_size: data_len as u32,
            chunk_count: 1,
        };

        // Write block 1: Success
        writer
            .write_typed_block(&block, era_common::BlockType::Data)
            .unwrap();

        // Write block 2: Should fail (needs 1024 + footer, only 500 + footer available minus footer reservation)
        assert!(writer
            .write_typed_block(&block, era_common::BlockType::Data)
            .is_err());

        // Finalize: Should fill padding
        writer.finalize().unwrap();

        // Verify file size
        let file_path = temp_dir.path().join("padded.era");
        let metadata = std::fs::metadata(file_path).unwrap();
        assert_eq!(metadata.len(), max_size);
    }
}
