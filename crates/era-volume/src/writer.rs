//! Volume writer for creating and appending to volumes.

use era_common::{BlockLocation, EncryptedMacroBlock, Result, VolumeId};
use era_storage::{StorageBackend, StorageWriter};
use std::path::Path;

use crate::header::HEADER_SIZE;
use crate::{Footer, SuperHeader};

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
        })
    }

    /// Get the volume ID
    pub fn volume_id(&self) -> VolumeId {
        self.header.volume_id
    }

    /// Get the current size of the volume
    pub fn current_size(&self) -> u64 {
        self.writer.current_size()
    }

    /// Get the number of blocks written
    pub fn block_count(&self) -> u32 {
        self.block_count
    }

    /// Write an encrypted macro block to the volume
    pub fn write_block(&mut self, block: &EncryptedMacroBlock) -> Result<BlockLocation> {
        let offset = self.position;

        // Write block length prefix (4 bytes)
        let len_bytes = (block.data.len() as u32).to_le_bytes();
        self.writer.append(&len_bytes)?;

        // Write block data
        self.writer.append(&block.data)?;

        let location = BlockLocation {
            volume_id: self.header.volume_id,
            slot_index: self.block_count,
            physical_offset: offset,
            encrypted_size: block.data.len() as u32,
            erasure_info: None, // Standard blocks are not erasure-coded
        };

        self.position = self.writer.current_size();
        self.block_count += 1;

        Ok(location)
    }

    /// Write raw bytes to the volume (for testing/low-level access)
    pub fn write_raw(&mut self, data: &[u8]) -> Result<u64> {
        let offset = self.position;
        self.writer.append(data)?;
        self.position = self.writer.current_size();
        Ok(offset)
    }

    /// Finalize the volume by writing the footer and syncing
    pub fn finalize(self) -> Result<SuperHeader> {
        self.finalize_with_catalog(0, 0, 0)
    }

    /// Finalize the volume with catalog location information
    pub fn finalize_with_catalog(
        mut self,
        catalog_offset: u64,
        catalog_size: u32,
        catalog_block_id: u32,
    ) -> Result<SuperHeader> {
        self.sequence += 1;

        // Write footer with catalog location
        let footer = Footer::with_catalog(
            self.position,
            self.block_count,
            self.sequence,
            catalog_offset,
            catalog_size,
            catalog_block_id,
        );
        let footer_bytes = footer.to_bytes()?;
        self.writer.append(&footer_bytes)?;

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

    /// Test verification tag for unit tests
    const TEST_VERIFICATION_TAG: [u8; 16] = [0xABu8; 16];

    #[test]
    fn test_create_volume() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());

        let header = SuperHeader::new(
            ArchiveId::new(),
            [0u8; 16],
            TEST_VERIFICATION_TAG,
            ArchiveConfig::default(),
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
            [0u8; 16],
            TEST_VERIFICATION_TAG,
            ArchiveConfig::default(),
        );

        let mut writer = VolumeWriter::create(&backend, Path::new("test.era"), header).unwrap();

        let block = EncryptedMacroBlock {
            block_id: BlockId::new(0),
            data: Bytes::from(vec![0u8; 1024]),
            original_size: 2048,
            compressed_size: 1024,
            chunk_count: 5,
        };

        let location = writer.write_block(&block).unwrap();
        assert_eq!(location.slot_index, 0);
        assert_eq!(location.encrypted_size, 1024);

        writer.finalize().unwrap();
    }
}
