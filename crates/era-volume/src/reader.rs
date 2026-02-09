//! Volume reader for reading from volumes.
//!
//! All I/O operations are async (non-blocking).

use bytes::Bytes;
use era_common::{
    BlockHeader, BlockId, BlockLocation, BlockType, EncryptedMacroBlock, EraError,
    ErasureBlockInfo, Result, ShardHeader,
};
use era_storage::{StorageBackend, StorageReader};
use std::path::Path;

use crate::footer::{FOOTER_MAGIC, FOOTER_SIZE};
use crate::header::{DATA_REGION_START, HEADER_SIZE};
use crate::{Footer, SuperHeader, MAX_SHARD_SIZE};

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
    ///
    /// Recovery Chain:
    /// 1. Try primary header at offset 0
    /// 2. If primary header fails, try to read backup footer to find backup_header_offset
    /// 3. Read backup header from backup_header_offset
    /// 4. Try primary footer at end of file
    /// 5. If primary footer fails, try backup footer at offset HEADER_SIZE (4096)
    pub async fn open<B: StorageBackend<Reader = R>>(backend: &B, path: &Path) -> Result<Self> {
        let reader = backend.open_read(path).await?;
        let size = reader.size();

        if size < HEADER_SIZE as u64 {
            return Err(EraError::CorruptedHeader("Volume too small".to_string()));
        }

        // === HEADER RECOVERY ===
        let header = match Self::try_read_header(&reader, 0).await {
            Ok(h) => h,
            Err(primary_err) => {
                tracing::warn!(
                    "Primary header corrupted: {}. Attempting backup recovery...",
                    primary_err
                );

                // Try to read backup footer first to get backup_header_offset
                let backup_result = Self::try_read_footer_at(&reader, HEADER_SIZE as u64).await;

                if let Ok(backup_footer) = backup_result {
                    if backup_footer.backup_header_offset > 0 {
                        tracing::info!(
                            "Found backup footer with backup_header_offset: {}",
                            backup_footer.backup_header_offset
                        );
                        if let Ok(h) =
                            Self::try_read_header(&reader, backup_footer.backup_header_offset).await
                        {
                            h
                        } else {
                            // Last resort: try primary footer to find backup header
                            let primary_footer = Self::try_read_footer(&reader, size).await?;
                            if primary_footer.backup_header_offset > 0 {
                                Self::try_read_header(&reader, primary_footer.backup_header_offset)
                                    .await?
                            } else {
                                return Err(EraError::CorruptedHeader(
                                    "No backup header location available".into(),
                                ));
                            }
                        }
                    } else {
                        return Err(EraError::CorruptedHeader(
                            "Backup footer has no backup_header_offset".into(),
                        ));
                    }
                } else {
                    // Last resort: try primary footer to find backup header
                    let primary_footer = Self::try_read_footer(&reader, size).await?;
                    if primary_footer.backup_header_offset > 0 {
                        Self::try_read_header(&reader, primary_footer.backup_header_offset).await?
                    } else {
                        return Err(EraError::CorruptedHeader(
                            "No backup header location available".into(),
                        ));
                    }
                }
            }
        };

        // Check if erasure coding is likely enabled
        let erasure_enabled = header.config.erasure.is_some();

        // === FOOTER RECOVERY ===
        // 1. Try primary footer (at end of file)
        let footer = match Self::try_read_footer(&reader, size).await {
            Ok(f) => Some(f),
            Err(primary_err) => {
                tracing::warn!(
                    "Primary footer corrupted: {}. Attempting backup recovery...",
                    primary_err
                );
                // 2. Try backup footer at offset HEADER_SIZE (4096)
                Self::try_read_footer_at(&reader, HEADER_SIZE as u64)
                    .await
                    .ok()
            }
        };

        // 3. If still no footer, try Floating Footer Recovery (Reverse Scan) for legacy volumes
        let footer = if footer.is_none() {
            Self::try_floating_footer_recovery(&reader, size).await?
        } else {
            footer
        };

        if footer.is_none() && !erasure_enabled {
            return Err(EraError::CorruptedHeader(
                "Volume too small for footer and no backup/floating footer found".to_string(),
            ));
        }

        Ok(Self {
            reader,
            header,
            footer,
        })
    }

    /// Try to read header at a specific offset
    async fn try_read_header(reader: &R, offset: u64) -> Result<SuperHeader> {
        let header_bytes = reader.read_at(offset, HEADER_SIZE).await?;
        SuperHeader::from_bytes(&header_bytes)
    }

    /// Try to read footer from end of file
    async fn try_read_footer(reader: &R, file_size: u64) -> Result<Footer> {
        if file_size < (HEADER_SIZE + FOOTER_SIZE) as u64 {
            return Err(EraError::CorruptedFooter(
                "File too small for footer".into(),
            ));
        }
        let footer_offset = file_size - FOOTER_SIZE as u64;
        Self::try_read_footer_at(reader, footer_offset).await
    }

    /// Try to read footer at a specific offset
    async fn try_read_footer_at(reader: &R, offset: u64) -> Result<Footer> {
        let bytes = reader.read_at(offset, FOOTER_SIZE).await?;
        Footer::from_bytes(&bytes)
    }

    /// Try floating footer recovery (reverse scan)
    async fn try_floating_footer_recovery(reader: &R, size: u64) -> Result<Option<Footer>> {
        // Scan the last 1MB (or full file if smaller) for footer magic
        // New fixed-length format: footer starts directly with "ERAF" magic
        let scan_size = 1024 * 1024; // 1MB scan window
        let start_offset = if size > scan_size {
            size - scan_size
        } else {
            HEADER_SIZE as u64
        };
        let scan_len = (size - start_offset) as usize;

        if scan_len < FOOTER_SIZE {
            return Ok(None);
        }

        let data = match reader.read_at(start_offset, scan_len).await {
            Ok(d) => d,
            Err(_) => return Ok(None),
        };

        // Search backwards for footer magic pattern "ERAF"
        let magic = FOOTER_MAGIC;

        // Iterate backwards to find the *last* valid footer
        // Footer must be aligned and have at least FOOTER_SIZE bytes after it
        for i in (0..=data.len().saturating_sub(FOOTER_SIZE)).rev() {
            if data[i..i + 4] == magic {
                // Possible match found - try to parse as footer
                let footer_file_offset = start_offset + i as u64;

                // Try to read footer from this offset
                if let Ok(bytes) = reader.read_at(footer_file_offset, FOOTER_SIZE).await {
                    if let Ok(f) = Footer::from_bytes(&bytes) {
                        tracing::warn!(
                            "Recovered floating footer at offset {}",
                            footer_file_offset
                        );
                        return Ok(Some(f));
                    }
                }
            }
        }

        Ok(None)
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

    /// Read a block at the given location (BlockHeader format)
    pub async fn read_block(&self, location: &BlockLocation) -> Result<EncryptedMacroBlock> {
        // Delegate to read_typed_block and discard the block type
        let (_block_type, block) = self.read_typed_block(location).await?;
        Ok(block)
    }

    /// Read raw data at the given offset
    pub async fn read_raw(&self, offset: u64, len: usize) -> Result<Bytes> {
        self.reader.read_at(offset, len).await
    }

    /// Read erasure-coded shards starting at the given offset
    ///
    /// Returns a vector of (shard_index, shard_data) pairs for all available shards.
    /// If a shard read fails, it returns None in place of the data.
    ///
    /// # Security
    /// All length fields are validated against MAX_SHARD_SIZE to prevent DoS attacks
    /// via malicious headers with huge length values.
    pub async fn read_erasure_shards(
        &self,
        location: &BlockLocation,
        erasure_info: &ErasureBlockInfo,
    ) -> Result<Vec<(usize, Option<Bytes>)>> {
        let total_shards = erasure_info.data_shards as usize + erasure_info.parity_shards as usize;
        let mut shards = Vec::with_capacity(total_shards);
        let mut offset = location.physical_offset;

        for idx in 0..total_shards {
            // Read shard header (length + CRC)
            let header_bytes = match self.reader.read_at(offset, ShardHeader::SIZE).await {
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

            // SECURITY: Validate length against MAX_SHARD_SIZE to prevent DoS
            if header.length as usize > MAX_SHARD_SIZE {
                tracing::warn!(
                    "Shard {} has invalid length {} (max: {}), marking as corrupted",
                    idx,
                    header.length,
                    MAX_SHARD_SIZE
                );
                shards.push((idx, None));
                offset += ShardHeader::SIZE as u64 + erasure_info.shard_size as u64;
                continue;
            }

            // Read shard data
            let shard_data = match self
                .reader
                .read_at(offset + ShardHeader::SIZE as u64, header.length as usize)
                .await
            {
                Ok(data) if header.verify(&data) => Some(data),
                _ => None,
            };

            shards.push((idx, shard_data));
            offset += ShardHeader::SIZE as u64 + header.length as u64;
        }

        Ok(shards)
    }

    /// Get the data region (after header + backup footer gap, before backup header)
    /// Layout: Data starts at DATA_REGION_START (4224)
    pub fn data_region(&self) -> (u64, u64) {
        let start = DATA_REGION_START;
        let end = self
            .footer
            .as_ref()
            .map(|f| f.data_end_offset)
            .unwrap_or(self.reader.size());
        (start, end)
    }

    /// Read a typed block (format with BlockHeader)
    ///
    /// Returns the block type and encrypted data
    ///
    /// # Security
    /// Length fields are validated against MAX_SHARD_SIZE to prevent DoS attacks.
    pub async fn read_typed_block(
        &self,
        location: &BlockLocation,
    ) -> Result<(BlockType, EncryptedMacroBlock)> {
        // Read BlockHeader (16 bytes)
        let header_bytes = self
            .reader
            .read_at(location.physical_offset, BlockHeader::SIZE)
            .await?;
        let header = BlockHeader::from_bytes(&header_bytes)
            .ok_or_else(|| EraError::InvalidFormat("Invalid BlockHeader".into()))?;

        // SECURITY: Validate length against MAX_SHARD_SIZE to prevent DoS
        if header.length as usize > MAX_SHARD_SIZE {
            return Err(EraError::IntegrityError(format!(
                "Block length {} exceeds maximum allowed size {}",
                header.length, MAX_SHARD_SIZE
            )));
        }

        // Read encrypted data
        let data_offset = location.physical_offset + BlockHeader::SIZE as u64;
        let data = self
            .reader
            .read_at(data_offset, header.length as usize)
            .await?;

        // Verify CRC
        if !header.verify(&data) {
            return Err(EraError::IntegrityError(
                "BlockHeader CRC verification failed".into(),
            ));
        }

        let block = EncryptedMacroBlock {
            block_id: BlockId::new(location.slot_index as u64),
            data,
            original_size: 0,
            compressed_size: header.length,
            chunk_count: 0,
        };

        Ok((header.block_type, block))
    }

    /// Scan the entire volume for blocks of a specific type
    ///
    /// **CRITICAL FOR COLD RECOVERY:** This performs a raw linear scan to find
    /// orphaned index blocks when the footer is lost or corrupted.
    ///
    /// # Security
    /// Length fields are validated against MAX_SHARD_SIZE to prevent DoS attacks.
    ///
    /// Returns a vector of BlockLocations for all matching blocks.
    pub async fn scan_for_typed_blocks(
        &self,
        target_type: BlockType,
    ) -> Result<Vec<BlockLocation>> {
        let (start_offset, end_offset) = self.data_region();
        let mut current_offset = start_offset;
        let mut found_blocks = Vec::new();

        tracing::info!(
            "Scanning volume for {:?} blocks (region: {} - {})",
            target_type,
            start_offset,
            end_offset
        );

        while current_offset + BlockHeader::SIZE as u64 <= end_offset {
            // Try to read BlockHeader
            match self.reader.read_at(current_offset, BlockHeader::SIZE).await {
                Ok(header_bytes) => {
                    if let Some(header) = BlockHeader::from_bytes(&header_bytes) {
                        // Check if this is a typed block (format)
                        if header.version == BlockHeader::VERSION {
                            let data_len = header.length as u64;

                            // SECURITY: Validate length against MAX_SHARD_SIZE to prevent DoS
                            if data_len > MAX_SHARD_SIZE as u64 {
                                tracing::warn!(
                                    "Block at offset {} has invalid length {}, skipping",
                                    current_offset,
                                    data_len
                                );
                                current_offset += 1;
                                continue;
                            }

                            // Verify we have enough space for the full block
                            if current_offset + BlockHeader::SIZE as u64 + data_len <= end_offset {
                                // Verify CRC by reading the data
                                if let Ok(data) = self
                                    .reader
                                    .read_at(
                                        current_offset + BlockHeader::SIZE as u64,
                                        data_len as usize,
                                    )
                                    .await
                                {
                                    if header.verify(&data) {
                                        // Valid typed block found
                                        if header.block_type == target_type {
                                            found_blocks.push(BlockLocation {
                                                volume_id: era_common::VolumeId::new(),
                                                slot_index: found_blocks.len() as u32,
                                                physical_offset: current_offset,
                                                encrypted_size: (BlockHeader::SIZE as u32
                                                    + header.length),
                                                erasure_info: None,
                                                shard_offsets: None,
                                                shard_volumes: None,
                                            });

                                            tracing::debug!(
                                                "Found {:?} block at offset {}",
                                                target_type,
                                                current_offset
                                            );
                                        }

                                        // Skip to next block
                                        current_offset += BlockHeader::SIZE as u64 + data_len;
                                        continue;
                                    }
                                }
                            }
                        }
                    }

                    // If we get here, this wasn't a valid typed block
                    // Could be legacy format (ShardHeader) - skip 8 bytes
                    if let Ok(shard_header_bytes) =
                        self.reader.read_at(current_offset, ShardHeader::SIZE).await
                    {
                        if let Some(shard_header) = ShardHeader::from_bytes(&shard_header_bytes) {
                            // SECURITY: Validate shard length too
                            if (shard_header.length as usize) <= MAX_SHARD_SIZE {
                                // Valid shard header - skip it
                                current_offset +=
                                    ShardHeader::SIZE as u64 + shard_header.length as u64;
                                continue;
                            }
                        }
                    }

                    // Unknown format or invalid length - advance 1 byte and continue scanning
                    current_offset += 1;
                }
                Err(_) => {
                    // Read error - skip forward
                    current_offset += 1;
                }
            }
        }

        tracing::info!(
            "Scan complete: found {} {:?} blocks",
            found_blocks.len(),
            target_type
        );

        Ok(found_blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VolumeWriter;
    use era_common::{ArchiveConfig, ArchiveId};
    use era_storage::LocalStorageBackend;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_open_volume() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let path = Path::new("test.era");

        // Create a volume
        let header = SuperHeader::new(
            ArchiveId::new(),
            vec![],
            ArchiveConfig::default(),
            [0u8; 16],
        );
        let archive_id = header.archive_id;

        let writer = VolumeWriter::create(&backend, path, header).await.unwrap();
        writer.finalize().await.unwrap();

        // Open and verify
        let reader = VolumeReader::open(&backend, path).await.unwrap();
        assert_eq!(reader.header().archive_id.0, archive_id.0);
        assert_eq!(reader.block_count(), 0);
    }

    #[tokio::test]
    async fn test_read_block() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let path = Path::new("test.era");

        // Create a volume with a block
        let header = SuperHeader::new(
            ArchiveId::new(),
            vec![],
            ArchiveConfig::default(),
            [0u8; 16],
        );

        let mut writer = VolumeWriter::create(&backend, path, header).await.unwrap();

        let block = EncryptedMacroBlock {
            block_id: BlockId::new(0),
            data: Bytes::from(vec![42u8; 256]),
            original_size: 512,
            compressed_size: 256,
            chunk_count: 2,
        };

        let location = writer
            .write_canonical_block(&block, era_common::BlockType::Data)
            .await
            .unwrap();
        writer.finalize().await.unwrap();

        // Read back
        let reader = VolumeReader::open(&backend, path).await.unwrap();
        assert_eq!(reader.block_count(), 1);

        let read_block = reader.read_block(&location).await.unwrap();
        assert_eq!(read_block.data.as_ref(), &[42u8; 256]);
    }
}
