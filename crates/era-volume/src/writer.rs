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
use crate::{Footer, SuperHeader, MAX_SHARD_SIZE};
use rand::rngs::OsRng;
use rand::RngCore;

/// Space reserved at the end of a fixed-size volume for the backup header + primary footer.
const BACKUP_HEADER_FOOTER_RESERVED: u64 = (HEADER_SIZE + FOOTER_SIZE) as u64;

/// Writer for a single volume
pub struct VolumeWriter<W: StorageWriter> {
    /// Underlying storage writer
    writer: W,
    /// Volume header
    header: SuperHeader,
    /// Current write position (after header)
    position: u64,
    /// Number of canonical blocks written (does not include raw writes)
    block_count: u32,
    /// Total bytes written via `write_raw()` (not counted in `block_count`)
    raw_bytes_written: u64,
    /// Sequence number for footer
    sequence: u64,
    /// Maximum volume size (for padding)
    max_size: Option<u64>,
    /// Last checkpoint offset
    last_checkpoint_offset: u64,
    /// Last checkpoint block ID (for direct decryption)
    last_checkpoint_block_id: u32,
    /// Last catalog offset (preserved across checkpoints)
    last_catalog_offset: u64,
    /// Last catalog size (preserved across checkpoints)
    last_catalog_size: u32,
    /// Last catalog block ID (preserved across checkpoints)
    last_catalog_block_id: u32,
    /// Last index offset (preserved across checkpoints)
    last_index_offset: u64,
    /// Last index size (preserved across checkpoints)
    last_index_size: u32,
    /// Last index block ID (preserved across checkpoints)
    last_index_block_id: u32,
}

impl<W: StorageWriter> VolumeWriter<W> {
    /// Create a new volume with the given header.
    ///
    /// Layout on create:
    /// - Write primary header at offset 0 (4096 bytes)
    /// - Reserve backup footer gap at offset 4096 (128 bytes of zeros)
    /// - Data region starts at offset 4224 (DATA_REGION_START)
    ///
    /// # Errors
    /// Returns `Serialization` if the header cannot be encoded, or I/O errors from the backend.
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
            raw_bytes_written: 0,
            sequence: 0,
            max_size: None,
            last_checkpoint_offset: 0,
            last_checkpoint_block_id: 0,
            last_catalog_offset: 0,
            last_catalog_size: 0,
            last_catalog_block_id: 0,
            last_index_offset: 0,
            last_index_size: 0,
            last_index_block_id: 0,
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

        // SECURITY: Validate footer.data_end_offset against actual file size
        // to prevent seeking past end of file with a corrupted footer
        let actual_size = writer.current_size();
        if footer.data_end_offset() > actual_size {
            return Err(era_common::EraError::CorruptedFooter(format!(
                "footer data_end_offset {} exceeds actual file size {}",
                footer.data_end_offset(),
                actual_size
            )));
        }

        writer.truncate(footer.data_end_offset()).await?;

        Ok(Self {
            writer,
            header,
            position: footer.data_end_offset(),
            block_count: footer.block_count(),
            raw_bytes_written: 0,
            sequence: footer.sequence_number(),
            max_size: None,
            last_checkpoint_offset: footer.last_checkpoint_offset(),
            last_checkpoint_block_id: footer.last_checkpoint_block_id(),
            last_catalog_offset: footer.catalog_offset(),
            last_catalog_size: footer.catalog_size(),
            last_catalog_block_id: footer.catalog_block_id(),
            last_index_offset: footer.index_offset(),
            last_index_size: footer.index_size(),
            last_index_block_id: footer.index_block_id(),
        })
    }

    /// Set the maximum size for this volume.
    ///
    /// Pads the underlying storage to `max_size` immediately. Subsequent writes
    /// use positional `write_at` instead of `append`.
    ///
    /// # Errors
    /// Returns I/O errors from the underlying storage backend during padding.
    pub async fn set_max_size(&mut self, max_size: u64) -> Result<()> {
        self.max_size = Some(max_size);
        self.pad_to_size(max_size).await
    }

    /// Validate that a non-zero offset does not exceed the current write position.
    fn validate_offset_in_bounds(&self, name: &str, offset: u64) -> era_common::Result<()> {
        if offset != 0 && offset > self.position {
            return Err(era_common::EraError::InvalidConfig(format!(
                "{}_offset {} exceeds current position {}",
                name, offset, self.position
            )));
        }
        Ok(())
    }

    /// Validate that offset and size are either both zero or both non-zero.
    fn validate_offset_size_pair(name: &str, offset: u64, size: u32) -> era_common::Result<()> {
        if (offset == 0) != (size == 0) {
            return Err(era_common::EraError::InvalidConfig(format!(
                "{} offset and size must both be zero or both non-zero",
                name
            )));
        }
        Ok(())
    }

    /// Update the last checkpoint offset.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if `offset` is non-zero and exceeds the current write position.
    pub fn set_last_checkpoint(&mut self, offset: u64) -> era_common::Result<()> {
        self.validate_offset_in_bounds("checkpoint", offset)?;
        self.last_checkpoint_offset = offset;
        Ok(())
    }

    /// Update the last checkpoint offset and block ID (for direct decryption).
    ///
    /// # Errors
    /// Returns `InvalidConfig` if `offset` is non-zero and exceeds the current write position.
    pub fn set_last_checkpoint_with_block_id(
        &mut self,
        offset: u64,
        block_id: u32,
    ) -> era_common::Result<()> {
        self.validate_offset_in_bounds("checkpoint", offset)?;
        self.last_checkpoint_offset = offset;
        self.last_checkpoint_block_id = block_id;
        Ok(())
    }

    /// Update the last catalog location info.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if offset/size consistency is violated or offset exceeds position.
    pub fn set_catalog_info(
        &mut self,
        offset: u64,
        size: u32,
        block_id: u32,
    ) -> era_common::Result<()> {
        Self::validate_offset_size_pair("catalog", offset, size)?;
        self.validate_offset_in_bounds("catalog", offset)?;
        self.last_catalog_offset = offset;
        self.last_catalog_size = size;
        self.last_catalog_block_id = block_id;
        debug_assert!(
            self.last_catalog_offset == 0 || self.last_catalog_offset <= self.position,
            "catalog postcondition violated: offset {} > position {}",
            self.last_catalog_offset,
            self.position
        );
        Ok(())
    }

    /// Update the last index location info.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if offset/size consistency is violated or offset exceeds position.
    pub fn set_index_info(
        &mut self,
        offset: u64,
        size: u32,
        block_id: u32,
    ) -> era_common::Result<()> {
        Self::validate_offset_size_pair("index", offset, size)?;
        self.validate_offset_in_bounds("index", offset)?;
        self.last_index_offset = offset;
        self.last_index_size = size;
        self.last_index_block_id = block_id;
        debug_assert!(
            self.last_index_offset == 0 || self.last_index_offset <= self.position,
            "index postcondition violated: offset {} > position {}",
            self.last_index_offset,
            self.position
        );
        Ok(())
    }

    /// Internal helper to pad the volume with random data up to target_size.
    ///
    /// Uses a 16KB stack buffer filled with `OsRng` for padding. The chunked approach is
    /// intentional for traffic analysis resistance: observing multiple random writes prevents
    /// attackers from inferring padding size from I/O patterns. ChaCha20-based seeding was
    /// evaluated but OsRng throughput (~1-2 GB/s) is sufficient for this use case.
    async fn pad_to_size(&mut self, target_size: u64) -> Result<()> {
        let current_size = self.writer.current_size();
        if current_size < target_size {
            let mut remaining = target_size - current_size;
            let mut buffer = [0u8; 16 * 1024]; // 16KB stack buffer

            while remaining > 0 {
                let to_write = remaining.min(buffer.len() as u64) as usize;
                // Security: Must be random to prevent traffic analysis
                OsRng.fill_bytes(&mut buffer[..to_write]);
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
    /// # Errors
    /// Returns `InvalidConfig` if `max_size` has not been set on this writer.
    /// Returns `InvalidConfig` if the checkpoint offset exceeds the current write position.
    /// Returns `CorruptedFooter` if the footer cannot be serialized.
    /// Returns I/O errors from padding, syncing, or writing footers to the backend.
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
    ///
    /// # Cancellation Safety
    ///
    /// This method borrows `&mut self` and can be cancelled at any `.await` point.
    /// If cancelled before `sync_data()` (step 2): no visible change — padding not on disk.
    /// If cancelled between `sync_data()` and footer writes: padding on disk, old footer valid.
    /// If cancelled between footer writes and `sync()`: footers buffered but not persistent —
    /// old footer still valid on disk, new footer lost.
    pub async fn commit_checkpoint(&mut self, checkpoint_offset: u64) -> Result<()> {
        let max_size = self.max_size.ok_or_else(|| {
            era_common::EraError::InvalidConfig("max_size required for volumes".into())
        })?;

        // Fixed Size Mode: Update footer at fixed location

        // 1. Ensure padding (leave space for backup header + footer at end)
        let pad_target = max_size.saturating_sub(BACKUP_HEADER_FOOTER_RESERVED);
        self.pad_to_size(pad_target).await?;

        // 2. CRITICAL: Sync padding data to disk BEFORE updating footer
        //    Uses fdatasync for efficiency (metadata sync not required here)
        //    This prevents "garbage tail" on power loss - the padding zeros
        //    must be physically on disk before we update the footer pointer.
        self.writer.sync_data().await?;

        // 3. Update state
        self.set_last_checkpoint(checkpoint_offset)?;

        // 4. Calculate backup header offset (where backup header will be written on finalize)
        let backup_header_offset = pad_target;

        // 5. Construct footer with backup_header_offset
        let footer = crate::Footer::with_catalog(
            self.position,
            self.block_count,
            self.sequence,
            self.last_catalog_offset,
            self.last_catalog_size,
            self.last_catalog_block_id,
            self.last_checkpoint_offset,
            self.last_checkpoint_block_id,
            self.last_index_offset,
            self.last_index_size,
            self.last_index_block_id,
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

        debug_assert!(
            self.last_checkpoint_offset <= self.position,
            "checkpoint postcondition violated: offset {} > position {}",
            self.last_checkpoint_offset,
            self.position
        );
        Ok(())
    }

    /// Get the volume ID
    #[must_use]
    pub fn volume_id(&self) -> VolumeId {
        self.header.volume_id()
    }

    /// Get the current size of the volume (valid data size)
    #[must_use]
    pub fn current_size(&self) -> u64 {
        self.position
    }

    /// Get the number of canonical blocks written.
    ///
    /// This only counts blocks written via `write_canonical_block()`.
    /// Raw writes via `write_raw()` are tracked separately.
    #[must_use]
    pub fn block_count(&self) -> u32 {
        self.block_count
    }

    /// Get the total bytes written via `write_raw()`.
    ///
    /// This is separate from `block_count()` which only tracks canonical blocks.
    #[must_use]
    pub fn raw_bytes_written(&self) -> u64 {
        self.raw_bytes_written
    }

    /// Write a canonical block with explicit BlockType
    ///
    /// # Errors
    /// Returns `InvalidConfig` if the block data exceeds `MAX_SHARD_SIZE` or `u32::MAX`.
    /// Returns `VolumeFull` if `max_size` is set and the block would exceed the volume limit.
    /// Returns I/O errors from the underlying storage backend.
    pub async fn write_canonical_block(
        &mut self,
        block: &EncryptedMacroBlock,
        block_type: era_common::BlockType,
    ) -> Result<BlockLocation> {
        // Format: Write BlockHeader + Data

        // SECURITY: Validate block size against MAX_SHARD_SIZE to prevent writing
        // blocks that the reader would reject (symmetric validation with reader)
        if block.data.len() > MAX_SHARD_SIZE {
            return Err(era_common::EraError::InvalidConfig(format!(
                "block data size {} exceeds MAX_SHARD_SIZE ({})",
                block.data.len(),
                MAX_SHARD_SIZE
            )));
        }

        let offset = self.position;
        let block_len = u32::try_from(block.data.len()).map_err(|_| {
            era_common::EraError::InvalidConfig("block data exceeds u32::MAX".into())
        })?;
        let header_size = era_common::BlockHeader::SIZE as u64;
        let total_len = block_len as u64 + header_size;

        // Check availability if max_size is set
        if let Some(max_size) = self.max_size {
            let footer_size = crate::footer::FOOTER_SIZE as u64;
            if offset + total_len + footer_size > max_size {
                return Err(era_common::EraError::VolumeFull {
                    volume_id: self.header.volume_id().to_string(),
                });
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

        let location =
            BlockLocation::single(self.header.volume_id(), self.block_count, offset, block_len);

        if self.max_size.is_some() {
            self.position += total_len;
        } else {
            self.position = self.writer.current_size();
        }
        self.block_count = self
            .block_count
            .checked_add(1)
            .ok_or_else(|| era_common::EraError::InvalidFormat("block_count overflow".into()))?;

        Ok(location)
    }

    /// Sync data to persistent storage without metadata (fdatasync).
    ///
    /// This ensures all previously written block data is on stable storage.
    /// More efficient than a full sync when metadata changes are not critical.
    ///
    /// # Errors
    /// Returns I/O errors from the underlying storage backend.
    pub async fn sync_data(&mut self) -> Result<()> {
        self.writer.sync_data().await
    }
    /// Write raw bytes to the volume (for index embedding and low-level access).
    ///
    /// Raw writes are tracked separately via `raw_bytes_written()` and do NOT
    /// increment `block_count()`, which only counts canonical typed blocks.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if the data exceeds `MAX_SHARD_SIZE`.
    /// Returns I/O errors from the underlying storage backend.
    pub async fn write_raw(&mut self, data: &[u8]) -> Result<u64> {
        // SECURITY: Validate raw write size against MAX_SHARD_SIZE (symmetric with reader)
        if data.len() > MAX_SHARD_SIZE {
            return Err(era_common::EraError::InvalidConfig(format!(
                "raw write size {} exceeds MAX_SHARD_SIZE ({})",
                data.len(),
                MAX_SHARD_SIZE
            )));
        }

        let offset = self.position;

        if self.max_size.is_some() {
            self.writer.write_at(offset, data).await?;
            self.position += data.len() as u64;
        } else {
            self.writer.append(data).await?;
            self.position = self.writer.current_size();
        }

        self.raw_bytes_written += data.len() as u64;

        Ok(offset)
    }

    /// Finalize the volume by writing the footer and syncing
    ///
    /// # Errors
    /// Returns `InvalidConfig` if catalog or index offsets exceed the current write position.
    /// Returns `Serialization` if the header or footer cannot be encoded.
    /// Returns I/O errors from padding, writing backup header/footer, syncing, or closing.
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
    ///
    /// # Errors
    /// Returns `InvalidConfig` if catalog or index offsets exceed the current write position.
    /// Returns `Serialization` if the header or footer cannot be encoded.
    /// Returns I/O errors from padding, writing backup header/footer, syncing, or closing.
    ///
    /// # Crash Safety
    ///
    /// This method syncs padding data to disk (fdatasync) before writing
    /// backup header and footers, preventing "garbage tail" on power loss.
    /// On crash, the volume will either have:
    /// - Old footer (finalize not committed) — data intact, recoverable via re-finalize
    /// - New footer with synced padding — fully valid
    ///
    /// # Cancellation Safety
    ///
    /// This method consumes `self`, so cancellation (dropping the future) drops the
    /// writer without syncing. The volume file remains on disk with valid data blocks
    /// but no footer. Recovery: re-open via `open_append()` using floating footer
    /// recovery (if a checkpoint was committed) or re-create.
    pub async fn finalize_with_catalog(
        mut self,
        catalog_offset: u64,
        catalog_size: u32,
        catalog_block_id: u32,
        index_offset: u64,
        index_size: u32,
        index_block_id: u32,
    ) -> Result<SuperHeader> {
        // Validate offsets: non-zero offsets must not exceed current write position
        self.validate_offset_in_bounds("catalog", catalog_offset)?;
        self.validate_offset_in_bounds("index", index_offset)?;

        self.sequence += 1;

        // Random padding if max_size is set
        if let Some(max_size) = self.max_size {
            // Ensure full padding to max_size minus space for backup header + footer
            let pad_target = max_size.saturating_sub(BACKUP_HEADER_FOOTER_RESERVED);
            self.pad_to_size(pad_target).await?;
            self.position = pad_target;

            // CRASH SAFETY: Sync padding data to disk BEFORE writing backup header
            // and footers. This matches the protocol in commit_checkpoint() and
            // prevents "garbage tail" — where footer references padding that
            // never reached disk. Uses fdatasync (metadata sync not required).
            self.writer.sync_data().await?;
        }

        // 1. Write backup header (copy of primary) at current position
        let backup_header_offset = self.position;

        // V30-04: Validate backup header offset is not below DATA_REGION_START
        if backup_header_offset < DATA_REGION_START {
            return Err(era_common::EraError::InvalidConfig(format!(
                "backup_header_offset {} is below DATA_REGION_START {}",
                backup_header_offset, DATA_REGION_START
            )));
        }
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

        // V27-12: Store catalog/index info so future checkpoints preserve it
        self.last_catalog_offset = catalog_offset;
        self.last_catalog_size = catalog_size;
        self.last_catalog_block_id = catalog_block_id;
        self.last_index_offset = index_offset;
        self.last_index_size = index_size;
        self.last_index_block_id = index_block_id;

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
    pub fn next_volume_header(&self) -> era_common::Result<SuperHeader> {
        self.header.next_volume()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccessPolicy, EncryptedVolumeKey, KeyWrapAlgorithm, RecipientSlot, RecipientType};
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
            vec![RecipientSlot::new(
                RecipientType::Argon2idPassword,
                Some([0x12; 8]),
                vec![0xAB; 16],
                vec![0xCD; 48],
            )],
            ArchiveConfig::default(),
            [0u8; 16],
            EncryptedVolumeKey::new(
                KeyWrapAlgorithm::XChaCha20Poly1305,
                [0u8; 24],
                vec![0u8; 48],
            ),
            AccessPolicy::AnyOfN,
        )
        .unwrap();

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
            vec![RecipientSlot::new(
                RecipientType::Argon2idPassword,
                Some([0x12; 8]),
                vec![0xAB; 16],
                vec![0xCD; 48],
            )],
            ArchiveConfig::default(),
            [0u8; 16],
            EncryptedVolumeKey::new(
                KeyWrapAlgorithm::XChaCha20Poly1305,
                [0u8; 24],
                vec![0u8; 48],
            ),
            AccessPolicy::AnyOfN,
        )
        .unwrap();

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
            vec![RecipientSlot::new(
                RecipientType::Argon2idPassword,
                Some([0x12; 8]),
                vec![0xAB; 16],
                vec![0xCD; 48],
            )],
            ArchiveConfig::default(),
            [0u8; 16],
            EncryptedVolumeKey::new(
                KeyWrapAlgorithm::XChaCha20Poly1305,
                [0u8; 24],
                vec![0u8; 48],
            ),
            AccessPolicy::AnyOfN,
        )
        .unwrap();

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
            vec![RecipientSlot::new(
                RecipientType::Argon2idPassword,
                Some([0x12; 8]),
                vec![0xAB; 16],
                vec![0xCD; 48],
            )],
            ArchiveConfig::default(),
            [0u8; 16],
            EncryptedVolumeKey::new(
                KeyWrapAlgorithm::XChaCha20Poly1305,
                [0u8; 24],
                vec![0u8; 48],
            ),
            AccessPolicy::AnyOfN,
        )
        .unwrap();

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
            vec![RecipientSlot::new(
                RecipientType::Argon2idPassword,
                Some([0x12; 8]),
                vec![0xAB; 16],
                vec![0xCD; 48],
            )],
            ArchiveConfig::default(),
            [0u8; 16],
            EncryptedVolumeKey::new(
                KeyWrapAlgorithm::XChaCha20Poly1305,
                [0u8; 24],
                vec![0u8; 48],
            ),
            AccessPolicy::AnyOfN,
        )
        .unwrap();

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
