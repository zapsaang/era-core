//! Volume reader for reading from volumes.

use bytes::Bytes;
use era_common::{
    BlockId, BlockLocation, EncryptedMacroBlock, EraError, ErasureBlockInfo, Result, ShardHeader,
};
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
    footer: Option<Footer>,
}

impl<R: StorageReader> VolumeReader<R> {
    /// Open an existing volume for reading
    pub fn open<B: StorageBackend<Reader = R>>(backend: &B, path: &Path) -> Result<Self> {
        let reader = backend.open_read(path)?;
        let size = reader.size();

        if size < HEADER_SIZE as u64 {
            return Err(EraError::CorruptedHeader("Volume too small".to_string()));
        }

        // Read header
        let header_bytes = reader.read_at(0, HEADER_SIZE)?;
        let header = SuperHeader::from_bytes(&header_bytes)?;

        // Check if erasure coding is likely enabled
        let erasure_enabled = header.config.erasure.is_some();

        // 1. Try to read standard footer (from the end of the file)
        let mut footer = None;
        if size >= (HEADER_SIZE + FOOTER_SIZE) as u64 {
            let footer_offset = size - FOOTER_SIZE as u64;
            if let Ok(bytes) = reader.read_at(footer_offset, FOOTER_SIZE) {
                if let Ok(f) = Footer::from_bytes(&bytes) {
                    footer = Some(f);
                }
            }
        }

        // 2. If standard footer missing, try Floating Footer Recovery (Reverse Scan)
        if footer.is_none() {
            // Scan the last 1MB (or full file if smaller) for footer magic
            // Pattern: 0x0A (Field 1) 0x04 (Len) "ERAF"
            let scan_size = 1024 * 1024; // 1MB scan window
            let start_offset = if size > scan_size {
                size - scan_size
            } else {
                HEADER_SIZE as u64
            };
            let scan_len = (size - start_offset) as usize;

            if scan_len > 6 {
                if let Ok(data) = reader.read_at(start_offset, scan_len) {
                    // Search backwards
                    // Pattern: [0x0A, 0x04, 'E', 'R', 'A', 'F']
                    let pattern = [0x0A, 0x04, 0x45, 0x52, 0x41, 0x46];

                    // We iterate backwards to find the *last* valid footer
                    for i in (0..data.len() - 5).rev() {
                        if data[i..i + 6] == pattern {
                            // Possible match found at offset `start_offset + i`
                            // This corresponds to the `magic` field in Proto.
                            // The Footer struct (with length prefix) starts 6 bytes before?
                            // No, format is [u32 len] [proto bytes].
                            // The `magic` is the first field of proto bytes.
                            // So `len` is 4 bytes before proto bytes.
                            // If `data[i]` is start of magic (0x0A), then proto starts at `i`.
                            // So Footer starts at `i - 4`.

                            if i < 4 {
                                continue;
                            } // Can't be valid if no space for length

                            let candidate_start = i - 4;
                            // Check if we have enough bytes for full footer reading (128 bytes)
                            // Even if we don't have 128 bytes in `data`, the file might have it?
                            // But we are scanning `data`.
                            // Let's rely on `read_at` from disk to be safe, or use `data` if it contains it.

                            let footer_file_offset = start_offset + candidate_start as u64;

                            // Try to read footer from this offset
                            if let Ok(bytes) = reader.read_at(footer_file_offset, FOOTER_SIZE) {
                                if let Ok(f) = Footer::from_bytes(&bytes) {
                                    tracing::warn!(
                                        "Recovered floating footer at offset {}",
                                        footer_file_offset
                                    );
                                    footer = Some(f);
                                    break; // Found the last valid footer
                                }
                            }
                        }
                    }
                }
            }
        }

        if footer.is_none() && !erasure_enabled {
            return Err(EraError::CorruptedHeader(
                "Volume too small for footer and no floating footer found".to_string(),
            ));
        }

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
    pub fn footer(&self) -> Option<&Footer> {
        self.footer.as_ref()
    }

    /// Get the number of blocks in this volume
    pub fn block_count(&self) -> u32 {
        self.footer.as_ref().map(|f| f.block_count).unwrap_or(0)
    }

    /// Read a block at the given location
    pub fn read_block(&self, location: &BlockLocation) -> Result<EncryptedMacroBlock> {
        // Unified format: [ShardHeader][Data]
        // Skip ShardHeader to get to data
        let header_size = ShardHeader::SIZE as u64;
        let header_bytes = self
            .reader
            .read_at(location.physical_offset, ShardHeader::SIZE)?;
        let header = ShardHeader::from_bytes(&header_bytes)
            .ok_or_else(|| EraError::IntegrityError("Invalid shard header".into()))?;

        if header.length != location.encrypted_size {
            return Err(EraError::IntegrityError(format!(
                "Shard length mismatch: header={} location={}",
                header.length, location.encrypted_size
            )));
        }

        let offset = location.physical_offset + header_size;
        let len = header.length as usize;

        // Read block data
        let data = self.reader.read_at(offset, len)?;

        // Read-time CRC validation for lowest-level integrity
        if !header.verify(&data) {
            return Err(EraError::IntegrityError(
                "Shard CRC verification failed".into(),
            ));
        }

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

    /// Read erasure-coded shards starting at the given offset
    ///
    /// Returns a vector of (shard_index, shard_data) pairs for all available shards.
    /// If a shard read fails, it returns None in place of the data.
    pub fn read_erasure_shards(
        &self,
        location: &BlockLocation,
        erasure_info: &ErasureBlockInfo,
    ) -> Result<Vec<(usize, Option<Bytes>)>> {
        let total_shards = erasure_info.data_shards as usize + erasure_info.parity_shards as usize;
        let mut shards = Vec::with_capacity(total_shards);
        let mut offset = location.physical_offset;

        for idx in 0..total_shards {
            // Read shard header (length + CRC)
            let header_bytes = match self.reader.read_at(offset, ShardHeader::SIZE) {
                Ok(bytes) if bytes.len() == ShardHeader::SIZE => bytes,
                _ => {
                    shards.push((idx, None));
                    offset += ShardHeader::SIZE as u64 + erasure_info.shard_size as u64;
                    continue;
                }
            };

            let header = match ShardHeader::from_bytes(&header_bytes) {
                Some(h) => h,
                None => {
                    shards.push((idx, None));
                    offset += ShardHeader::SIZE as u64 + erasure_info.shard_size as u64;
                    continue;
                }
            };

            // Read shard data
            let shard_data = match self
                .reader
                .read_at(offset + ShardHeader::SIZE as u64, header.length as usize)
            {
                Ok(data) if header.verify(&data) => Some(data),
                _ => None,
            };

            shards.push((idx, shard_data));
            offset += ShardHeader::SIZE as u64 + header.length as u64;
        }

        Ok(shards)
    }

    /// Get the data region (after header, before footer)
    pub fn data_region(&self) -> (u64, u64) {
        let start = HEADER_SIZE as u64;
        let end = self
            .footer
            .as_ref()
            .map(|f| f.data_end_offset)
            .unwrap_or(self.reader.size());
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
