//! Volume writer for creating and appending to volumes.

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
    /// V8.1 Layout on create:
    /// - Write primary header at offset 0 (4096 bytes)
    /// - Reserve backup footer gap at offset 4096 (128 bytes of zeros)
    /// - Data region starts at offset 4224 (DATA_REGION_START)
    pub fn create<B: StorageBackend<Writer = W>>(
        backend: &B,
        path: &Path,
        header: SuperHeader,
    ) -> Result<Self> {
        let mut writer = backend.create(path)?;

        // Write primary header
        let header_bytes = header.to_bytes()?;
        writer.append(&header_bytes)?;

        // Reserve backup footer gap (128 bytes of zeros)
        // This will be filled with the backup footer on finalize
        let backup_footer_gap = [0u8; BACKUP_FOOTER_GAP];
        writer.append(&backup_footer_gap)?;

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

    /// Update the last checkpoint offset and block ID (for direct decryption)
    pub fn set_last_checkpoint_with_block_id(&mut self, offset: u64, block_id: u32) {
        self.last_checkpoint_offset = offset;
        self.last_checkpoint_block_id = block_id;
    }

    /// Internal helper to pad the volume with random data up to target_size
    /// Uses stack buffer to avoid heap allocations, fills with random data for security
    fn pad_to_size(&mut self, target_size: u64) -> Result<()> {
        let current_size = self.writer.current_size();
        if current_size < target_size {
            let mut remaining = target_size - current_size;
            let mut buffer = [0u8; 16 * 1024]; // 16KB stack buffer

            while remaining > 0 {
                let to_write = remaining.min(buffer.len() as u64) as usize;
                // Security: Must be random to prevent traffic analysis
                rand::thread_rng().fill_bytes(&mut buffer[..to_write]);
                self.writer.append(&buffer[..to_write])?;
                remaining -= to_write as u64;
            }
        }
        Ok(())
    }

    /// Commit a checkpoint by updating the footer atomically
    ///
    /// v8.1: max_size is required for proper backup header/footer layout
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
    pub fn commit_checkpoint(&mut self, checkpoint_offset: u64) -> Result<()> {
        let max_size = self.max_size.ok_or_else(|| {
            era_common::EraError::InvalidConfig("max_size required for v8.1 volumes".into())
        })?;

        // Fixed Size Mode: Update footer at fixed location

        // 1. Ensure padding (leave space for backup header + footer at end)
        let reserved_end = (HEADER_SIZE + FOOTER_SIZE) as u64;
        let pad_target = max_size.saturating_sub(reserved_end);
        self.pad_to_size(pad_target)?;

        // 2. CRITICAL: Sync padding data to disk BEFORE updating footer
        //    Uses fdatasync for efficiency (metadata sync not required here)
        //    This prevents "garbage tail" on power loss - the padding zeros
        //    must be physically on disk before we update the footer pointer.
        self.writer.sync_data()?;

        // 3. Update state
        self.set_last_checkpoint(checkpoint_offset);

        // 4. Calculate backup header offset
        let backup_header_offset = pad_target;

        // 5. CRITICAL: Write backup header NOW (not just on finalize)
        //    This ensures true redundancy at every checkpoint, not just at finalization.
        //    If the primary header gets corrupted, the Reader can recover using this backup.
        let header_bytes = self.header.to_bytes()?;
        self.writer.write_at(backup_header_offset, &header_bytes)?;

        // 6. Construct footer with backup_header_offset
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

        // 7. Write primary footer at end (after backup header position)
        let footer_offset = backup_header_offset + HEADER_SIZE as u64;
        self.writer.write_at(footer_offset, &footer_bytes)?;

        // 8. Write backup footer at reserved gap (offset HEADER_SIZE = 4096)
        self.writer.write_at(HEADER_SIZE as u64, &footer_bytes)?;

        // 9. Final sync to ensure both header and footer are persisted
        self.writer.sync()?;

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

    /// Write a canonical block with explicit BlockType (v8.1 format)
    ///
    /// # Security
    ///
    /// Enforces symmetric validation with the Reader by rejecting blocks
    /// larger than `MAX_SHARD_SIZE` (16MB). This prevents creating
    /// "write-only" archives that cannot be read back.
    pub fn write_canonical_block(
        &mut self,
        block: &EncryptedMacroBlock,
        block_type: era_common::BlockType,
    ) -> Result<BlockLocation> {
        // SECURITY: Enforce symmetric bounds with Reader - reject oversized blocks
        if block.data.len() > crate::MAX_SHARD_SIZE {
            return Err(era_common::EraError::BlockTooLarge {
                size: block.data.len(),
                max_size: crate::MAX_SHARD_SIZE,
            });
        }

        // v8.1 Format: Write BlockHeader + Data
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
    ///
    /// V8.1 Layout on finalize:
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
    pub fn finalize_with_catalog(
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
            let reserved_end = (HEADER_SIZE + FOOTER_SIZE) as u64; // 4224 bytes for backup header + primary footer
            let pad_target = max_size.saturating_sub(reserved_end);
            self.pad_to_size(pad_target)?;
            self.position = pad_target;
        }

        // 1. Write backup header (copy of primary) at current position
        let backup_header_offset = self.position;
        let header_bytes = self.header.to_bytes()?;

        if self.max_size.is_some() {
            self.writer.write_at(backup_header_offset, &header_bytes)?;
        } else {
            self.writer.append(&header_bytes)?;
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
            self.writer.write_at(primary_footer_offset, &footer_bytes)?;
        } else {
            self.writer.append(&footer_bytes)?;
        }

        // 5. Write backup footer at reserved gap (offset HEADER_SIZE = 4096)
        self.writer.write_at(HEADER_SIZE as u64, &footer_bytes)?;

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
            .write_canonical_block(&block, era_common::BlockType::Data)
            .unwrap();
        assert_eq!(location.slot_index, 0);
        assert_eq!(location.encrypted_size, 1024);

        writer.finalize().unwrap();
    }

    /// Test that commit_checkpoint writes the backup header for true redundancy.
    /// Verifies that the volume can be recovered even if the primary header is corrupted.
    #[test]
    fn test_checkpoint_writes_backup_header() {
        use era_storage::LocalStorageBackend;
        use std::io::{Seek, Write};

        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let volume_path = Path::new("test_backup.era");

        let header = SuperHeader::new(
            ArchiveId::new(),
            vec![],
            ArchiveConfig::default(),
            [0u8; 16],
        );

        // Create volume and write some data
        let mut writer = VolumeWriter::create(&backend, volume_path, header).unwrap();
        let max_size = 10 * 1024 * 1024; // 10MB
        writer.set_max_size(max_size).unwrap();

        let block = EncryptedMacroBlock {
            block_id: BlockId::new(0),
            data: Bytes::from(vec![0x42; 1024]),
            original_size: 2048,
            compressed_size: 1024,
            chunk_count: 1,
        };

        writer
            .write_canonical_block(&block, era_common::BlockType::Data)
            .unwrap();

        // Commit checkpoint (should write backup header)
        let checkpoint_offset = writer.current_size();
        writer.commit_checkpoint(checkpoint_offset).unwrap();

        // DO NOT call finalize - we want to test checkpoint redundancy alone
        drop(writer);

        // Corrupt the primary header (byte 0) to simulate header failure
        let file_path = temp_dir.path().join(volume_path);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&file_path)
            .unwrap();
        file.seek(std::io::SeekFrom::Start(0)).unwrap();
        file.write_all(&[0xFF]).unwrap(); // Corrupt magic number
        drop(file);

        // Try to open the volume - should succeed using backup header
        let result = crate::VolumeReader::open(&backend, volume_path);
        assert!(
            result.is_ok(),
            "Volume should open using backup header after primary header corruption"
        );

        let reader = result.unwrap();
        assert_eq!(reader.block_count(), 1, "Should have 1 block");
    }

    /// Test that writing a block larger than MAX_SHARD_SIZE (16MB) fails.
    /// This ensures symmetric validation with the Reader.
    #[test]
    fn test_write_oversized_block_rejected() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());

        let header = SuperHeader::new(
            ArchiveId::new(),
            vec![],
            ArchiveConfig::default(),
            [0u8; 16],
        );

        let mut writer = VolumeWriter::create(&backend, Path::new("test.era"), header).unwrap();

        // Create a 17MB block (exceeds 16MB MAX_SHARD_SIZE)
        let oversized_data = vec![0u8; 17 * 1024 * 1024];
        let block = EncryptedMacroBlock {
            block_id: BlockId::new(0),
            data: Bytes::from(oversized_data),
            original_size: 17 * 1024 * 1024,
            compressed_size: 17 * 1024 * 1024,
            chunk_count: 1,
        };

        let result = writer.write_canonical_block(&block, era_common::BlockType::Data);
        assert!(result.is_err(), "Writing 17MB block should fail");

        let err = result.unwrap_err();
        assert!(
            matches!(err, era_common::EraError::BlockTooLarge { .. }),
            "Error should be BlockTooLarge, got: {:?}",
            err
        );
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
        // v8.1 format uses BlockHeader::SIZE (16 bytes) instead of ShardHeader::SIZE (8 bytes)
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
            .write_canonical_block(&block, era_common::BlockType::Data)
            .unwrap();

        // Write block 2: Should fail (needs 1024 + footer, only 500 + footer available minus footer reservation)
        assert!(writer
            .write_canonical_block(&block, era_common::BlockType::Data)
            .is_err());

        // Finalize: Should fill padding
        writer.finalize().unwrap();

        // Verify file size
        let file_path = temp_dir.path().join("padded.era");
        let metadata = std::fs::metadata(file_path).unwrap();
        assert_eq!(metadata.len(), max_size);
    }
}
