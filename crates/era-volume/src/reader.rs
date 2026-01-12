//! Volume reader for reading from volumes.

use bytes::Bytes;
use era_common::{BlockId, BlockLocation, EncryptedMacroBlock, EraError, Result};
use era_storage::{StorageBackend, StorageReader};
use std::path::Path;

use crate::footer::FOOTER_SIZE;
use crate::header::HEADER_SIZE;
use crate::{Footer, SuperHeader};

/// Reader for a single volume
pub struct VolumeReader<R: StorageReader> {
    /// Underlying storage reader
    reader: R,
    /// Volume header
    header: SuperHeader,
    /// Volume footer
    footer: Footer,
}

impl<R: StorageReader> VolumeReader<R> {
    /// Open an existing volume for reading
    pub fn open<B: StorageBackend<Reader = R>>(backend: &B, path: &Path) -> Result<Self> {
        let reader = backend.open_read(path)?;
        let size = reader.size();

        if size < (HEADER_SIZE + FOOTER_SIZE) as u64 {
            return Err(EraError::CorruptedHeader("Volume too small".to_string()));
        }

        // Read header
        let header_bytes = reader.read_at(0, HEADER_SIZE)?;
        let header = SuperHeader::from_bytes(&header_bytes)?;

        // Read footer (from the end of the file)
        let footer_offset = size - FOOTER_SIZE as u64;
        let footer_bytes = reader.read_at(footer_offset, FOOTER_SIZE)?;
        let footer = Footer::from_bytes(&footer_bytes)?;

        Ok(Self {
            reader,
            header,
            footer,
        })
    }

    /// Get the volume header
    pub fn header(&self) -> &SuperHeader {
        &self.header
    }

    /// Get the volume footer
    pub fn footer(&self) -> &Footer {
        &self.footer
    }

    /// Get the number of blocks in this volume
    pub fn block_count(&self) -> u32 {
        self.footer.block_count
    }

    /// Read a block at the given location
    pub fn read_block(&self, location: &BlockLocation) -> Result<EncryptedMacroBlock> {
        // Read length prefix
        let len_bytes = self.reader.read_at(location.physical_offset, 4)?;
        let len =
            u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;

        // Read block data
        let data = self.reader.read_at(location.physical_offset + 4, len)?;

        Ok(EncryptedMacroBlock {
            block_id: BlockId::new(location.slot_index as u64),
            data,
            original_size: 0, // Will be set during decryption
            compressed_size: len as u32,
            chunk_count: 0, // Will be set during unpacking
        })
    }

    /// Read raw data at the given offset
    pub fn read_raw(&self, offset: u64, len: usize) -> Result<Bytes> {
        self.reader.read_at(offset, len)
    }

    /// Get the data region (after header, before footer)
    pub fn data_region(&self) -> (u64, u64) {
        let start = HEADER_SIZE as u64;
        let end = self.footer.data_end_offset;
        (start, end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VolumeWriter;
    use era_common::{ArchiveConfig, ArchiveId};
    use era_storage::LocalStorageBackend;
    use tempfile::TempDir;

    /// Test verification tag for unit tests
    const TEST_VERIFICATION_TAG: [u8; 16] = [0xABu8; 16];

    #[test]
    fn test_open_volume() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let path = Path::new("test.era");

        // Create a volume
        let header = SuperHeader::new(
            ArchiveId::new(),
            [0u8; 16],
            TEST_VERIFICATION_TAG,
            ArchiveConfig::default(),
        );
        let archive_id = header.archive_id;

        let writer = VolumeWriter::create(&backend, path, header).unwrap();
        writer.finalize().unwrap();

        // Open and verify
        let reader = VolumeReader::open(&backend, path).unwrap();
        assert_eq!(reader.header().archive_id.0, archive_id.0);
        assert_eq!(reader.block_count(), 0);
    }

    #[test]
    fn test_read_block() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let path = Path::new("test.era");

        // Create a volume with a block
        let header = SuperHeader::new(
            ArchiveId::new(),
            [0u8; 16],
            TEST_VERIFICATION_TAG,
            ArchiveConfig::default(),
        );

        let mut writer = VolumeWriter::create(&backend, path, header).unwrap();

        let block = EncryptedMacroBlock {
            block_id: BlockId::new(0),
            data: Bytes::from(vec![42u8; 256]),
            original_size: 512,
            compressed_size: 256,
            chunk_count: 2,
        };

        let location = writer.write_block(&block).unwrap();
        writer.finalize().unwrap();

        // Read back
        let reader = VolumeReader::open(&backend, path).unwrap();
        assert_eq!(reader.block_count(), 1);

        let read_block = reader.read_block(&location).unwrap();
        assert_eq!(read_block.data.as_ref(), &[42u8; 256]);
    }
}
