//! Volume writer for creating and appending to volumes.
//!
//! All I/O operations are async (non-blocking).
//!
//! ## Design Goals
//!
//! 1. **Zero Blocking**: All I/O operations are async
//! 2. **Zero Allocations**: Static buffer for padding
//! 3. **Backpressure Compatible**: Works with async ChunkPipeline

use era_common::{
    compute_shard_crc, BlockLocation, EncryptedMacroBlock, EraError, Result, VolumeId,
};
use era_storage::{StorageBackend, StorageReader, StorageWriter};
use std::io::SeekFrom;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::footer::{BACKUP_FOOTER_GAP, FOOTER_SIZE};
use crate::header::{DATA_REGION_START, HEADER_SIZE};
use crate::{Footer, SuperHeader, MAX_SHARD_SIZE};
use rand::rngs::OsRng;
use rand::RngCore;

/// Space reserved at the end of a fixed-size volume for the backup header + primary footer.
const BACKUP_HEADER_FOOTER_RESERVED: u64 = (HEADER_SIZE + FOOTER_SIZE) as u64;
/// Streaming copy buffer size for disk-backed append spooling and rollback.
const SPOOL_CHUNK_SIZE: usize = 64 * 1024;

pub(crate) fn superheader_digest(header: &SuperHeader) -> Result<[u8; 32]> {
    Ok(*blake3::hash(&header.to_bytes()?).as_bytes())
}

struct StagedAppend {
    base_offset: u64,
    initial_block_count: u32,
    original_size: u64,
    original_footer: Footer,
    spool: tokio::fs::File,
    staged_data_offset: u64,
    staged_len: u64,
}

impl StagedAppend {
    async fn append_slices(&mut self, slices: &[&[u8]]) -> Result<()> {
        let write_offset = self
            .staged_data_offset
            .checked_add(self.staged_len)
            .ok_or_else(|| EraError::InvalidFormat("staged append spool offset overflow".into()))?;
        self.spool
            .seek(SeekFrom::Start(write_offset))
            .await
            .map_err(EraError::Io)?;
        let mut added = 0u64;
        for slice in slices {
            if !slice.is_empty() {
                self.spool.write_all(slice).await.map_err(EraError::Io)?;
                added = added.checked_add(slice.len() as u64).ok_or_else(|| {
                    EraError::InvalidFormat("staged append length overflow".into())
                })?;
            }
        }
        self.staged_len = self
            .staged_len
            .checked_add(added)
            .ok_or_else(|| EraError::InvalidFormat("staged append length overflow".into()))?;
        Ok(())
    }

    async fn overwrite_original_head_footer(&mut self, footer_bytes: &[u8]) -> Result<()> {
        self.spool
            .seek(SeekFrom::Start(HEADER_SIZE as u64))
            .await
            .map_err(EraError::Io)?;
        self.spool
            .write_all(footer_bytes)
            .await
            .map_err(EraError::Io)
    }

    async fn overwrite_original_tail_slice(
        &mut self,
        volume_offset: u64,
        bytes: &[u8],
    ) -> Result<()> {
        if volume_offset < self.base_offset {
            return Ok(());
        }
        let Some(rel) = volume_offset.checked_sub(self.base_offset) else {
            return Ok(());
        };
        let Some(end) = volume_offset.checked_add(bytes.len() as u64) else {
            return Ok(());
        };
        if end > self.original_size {
            return Ok(());
        }
        let spool_offset = DATA_REGION_START
            .checked_add(rel)
            .ok_or_else(|| EraError::InvalidFormat("staged spool tail offset overflow".into()))?;
        self.spool
            .seek(SeekFrom::Start(spool_offset))
            .await
            .map_err(EraError::Io)?;
        self.spool.write_all(bytes).await.map_err(EraError::Io)
    }
}

/// Metadata snapshot of a retired volume whose write handle was closed to bound file descriptors.
pub(crate) struct RetiredVolumeState {
    pub(crate) header: SuperHeader,
    position: u64,
    block_count: u32,
    raw_bytes_written: u64,
    sequence: u64,
    max_size: Option<u64>,
    last_checkpoint_offset: u64,
    last_checkpoint_block_id: u32,
    last_catalog_offset: u64,
    last_catalog_size: u32,
    last_catalog_block_id: u32,
    last_index_offset: u64,
    last_index_size: u32,
    last_index_block_id: u32,
    last_manifest_offset: u64,
    last_manifest_block_id: u32,
    staged_append: Option<StagedAppend>,
}

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
    /// Last manifest offset (preserved across checkpoints)
    last_manifest_offset: u64,
    /// Last manifest block ID (preserved across checkpoints)
    last_manifest_block_id: u32,
    /// Buffered append tail so an existing volume stays readable until finalization.
    staged_append: Option<StagedAppend>,
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
            last_manifest_offset: 0,
            last_manifest_block_id: 0,
            staged_append: None,
        })
    }

    /// Open an existing volume for appending (truncate footer)
    pub async fn open_append<B: StorageBackend<Writer = W>>(
        backend: &B,
        path: &Path,
        header: SuperHeader,
        footer: &Footer,
    ) -> Result<Self> {
        Self::open_append_at(
            backend,
            path,
            header,
            footer,
            footer.data_end_offset(),
            footer.block_count(),
        )
        .await
    }

    /// Open an existing volume for appending, staging new writes from `append_offset`
    /// and continuing canonical block numbering from `initial_block_count` until finalization.
    pub async fn open_append_at<B: StorageBackend<Writer = W>>(
        backend: &B,
        path: &Path,
        header: SuperHeader,
        footer: &Footer,
        append_offset: u64,
        initial_block_count: u32,
    ) -> Result<Self> {
        let writer = backend.open_append(path).await?;

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
        if append_offset < DATA_REGION_START || append_offset > footer.data_end_offset() {
            return Err(era_common::EraError::CorruptedFooter(format!(
                "append_offset {} out of bounds [{}..={}]",
                append_offset,
                DATA_REGION_START,
                footer.data_end_offset()
            )));
        }

        let reader = backend.open_read(path).await?;
        let std_spool = tempfile::tempfile().map_err(EraError::Io)?;
        let mut spool = tokio::fs::File::from_std(std_spool);
        let head = reader.read_at(0, DATA_REGION_START as usize).await?;
        if head.len() != DATA_REGION_START as usize {
            return Err(EraError::CorruptedHeader(format!(
                "short volume head read during append staging: got {} bytes, expected {}",
                head.len(),
                DATA_REGION_START
            )));
        }
        spool.write_all(&head).await.map_err(EraError::Io)?;

        let mut tail_offset = append_offset;
        while tail_offset < actual_size {
            let chunk_len =
                usize::try_from((actual_size - tail_offset).min(SPOOL_CHUNK_SIZE as u64))
                    .unwrap_or(SPOOL_CHUNK_SIZE);
            let chunk = reader.read_at(tail_offset, chunk_len).await?;
            if chunk.is_empty() {
                return Err(EraError::CorruptedFooter(format!(
                    "unexpected EOF while staging append rollback tail at offset {tail_offset}"
                )));
            }
            spool.write_all(&chunk).await.map_err(EraError::Io)?;
            tail_offset = tail_offset
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| EraError::InvalidFormat("staged tail offset overflow".into()))?;
        }
        drop(reader);

        let original_tail_len = actual_size - append_offset;
        let staged_data_offset = DATA_REGION_START
            .checked_add(original_tail_len)
            .ok_or_else(|| EraError::InvalidFormat("staged spool offset overflow".into()))?;

        let (last_checkpoint_offset, last_checkpoint_block_id) =
            if footer.last_checkpoint_offset() < append_offset {
                (
                    footer.last_checkpoint_offset(),
                    footer.last_checkpoint_block_id(),
                )
            } else {
                (0, 0)
            };
        let (last_catalog_offset, last_catalog_size, last_catalog_block_id) =
            if footer.catalog_offset() < append_offset {
                (
                    footer.catalog_offset(),
                    footer.catalog_size(),
                    footer.catalog_block_id(),
                )
            } else {
                (0, 0, 0)
            };
        let (last_index_offset, last_index_size, last_index_block_id) =
            if footer.index_offset() < append_offset {
                (
                    footer.index_offset(),
                    footer.index_size(),
                    footer.index_block_id(),
                )
            } else {
                (0, 0, 0)
            };
        let (last_manifest_offset, last_manifest_block_id) =
            if footer.manifest_offset() < append_offset {
                (footer.manifest_offset(), footer.manifest_block_id())
            } else {
                (0, 0)
            };

        Ok(Self {
            writer,
            header,
            position: append_offset,
            block_count: initial_block_count,
            raw_bytes_written: 0,
            sequence: footer.sequence_number(),
            max_size: None,
            last_checkpoint_offset,
            last_checkpoint_block_id,
            last_catalog_offset,
            last_catalog_size,
            last_catalog_block_id,
            last_index_offset,
            last_index_size,
            last_index_block_id,
            last_manifest_offset,
            last_manifest_block_id,
            staged_append: Some(StagedAppend {
                base_offset: append_offset,
                initial_block_count,
                original_size: actual_size,
                original_footer: footer.clone(),
                spool,
                staged_data_offset,
                staged_len: 0,
            }),
        })
    }

    /// Bytes currently buffered in heap memory for a staged append (always 0 because
    /// append writes spool to an anonymous temporary file).
    #[must_use]
    pub fn staged_in_memory_bytes(&self) -> usize {
        0
    }

    /// Bytes currently spooled on disk for a pending staged append session.
    #[must_use]
    pub fn staged_disk_bytes(&self) -> u64 {
        self.staged_append
            .as_ref()
            .map_or(0, |staged| staged.staged_len)
    }

    fn build_transitional_footer(staged: &StagedAppend) -> Footer {
        let base = staged.base_offset;
        let orig = &staged.original_footer;
        let mut builder = Footer::builder(base, staged.initial_block_count, orig.sequence_number());
        if orig.catalog_offset() >= DATA_REGION_START
            && orig
                .catalog_offset()
                .checked_add(u64::from(orig.catalog_size()))
                .is_some_and(|end| end <= base)
        {
            builder = builder.catalog(
                orig.catalog_offset(),
                orig.catalog_size(),
                orig.catalog_block_id(),
            );
        }
        if orig.last_checkpoint_offset() >= DATA_REGION_START
            && orig.last_checkpoint_offset() < base
        {
            builder = builder.checkpoint(
                orig.last_checkpoint_offset(),
                orig.last_checkpoint_block_id(),
            );
        }
        if orig.manifest_offset() >= DATA_REGION_START && orig.manifest_offset() < base {
            builder = builder.manifest(orig.manifest_offset(), orig.manifest_block_id());
        }
        if orig.index_offset() >= DATA_REGION_START
            && orig
                .index_offset()
                .checked_add(u64::from(orig.index_size()))
                .is_some_and(|end| end <= base)
        {
            builder = builder.index(
                orig.index_offset(),
                orig.index_size(),
                orig.index_block_id(),
            );
        }
        builder.backup_header(0).build()
    }

    async fn stream_staged_tail(writer: &mut W, staged: &mut StagedAppend) -> Result<()> {
        writer.truncate(staged.base_offset).await?;
        staged
            .spool
            .seek(SeekFrom::Start(staged.staged_data_offset))
            .await
            .map_err(EraError::Io)?;
        let mut remaining = staged.staged_len;
        let mut buf = vec![0u8; SPOOL_CHUNK_SIZE];
        while remaining > 0 {
            let to_read =
                usize::try_from(remaining.min(SPOOL_CHUNK_SIZE as u64)).unwrap_or(SPOOL_CHUNK_SIZE);
            staged
                .spool
                .read_exact(&mut buf[..to_read])
                .await
                .map_err(EraError::Io)?;
            writer.append(&buf[..to_read]).await?;
            remaining -= to_read as u64;
        }
        Ok(())
    }

    async fn restore_staged_original(writer: &mut W, staged: &mut StagedAppend) -> Result<()> {
        staged
            .spool
            .seek(SeekFrom::Start(0))
            .await
            .map_err(EraError::Io)?;
        let mut head = vec![0u8; DATA_REGION_START as usize];
        staged
            .spool
            .read_exact(&mut head)
            .await
            .map_err(EraError::Io)?;
        writer.write_at(0, &head).await?;

        let mut remaining = staged.staged_data_offset - DATA_REGION_START;
        let mut target_offset = staged.base_offset;
        let mut buf = vec![0u8; SPOOL_CHUNK_SIZE];
        while remaining > 0 {
            let to_read =
                usize::try_from(remaining.min(SPOOL_CHUNK_SIZE as u64)).unwrap_or(SPOOL_CHUNK_SIZE);
            staged
                .spool
                .read_exact(&mut buf[..to_read])
                .await
                .map_err(EraError::Io)?;
            writer.write_at(target_offset, &buf[..to_read]).await?;
            target_offset += to_read as u64;
            remaining -= to_read as u64;
        }

        writer.truncate(staged.original_size).await?;
        writer.sync().await
    }

    /// Set the maximum size for this volume.
    ///
    /// Pads the underlying storage to `max_size` immediately. Subsequent writes
    /// use positional `write_at` instead of `append`.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if called on a staged append writer.
    /// Returns I/O errors from the underlying storage backend during padding.
    pub async fn set_max_size(&mut self, max_size: u64) -> Result<()> {
        if self.staged_append.is_some() {
            return Err(EraError::InvalidConfig(
                "cannot set max_size on a staged append volume writer".into(),
            ));
        }
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

    /// Zero out stale backup footer bytes in the reserved gap after append truncation
    /// and clear in-memory checkpoint pointers so StartFresh discards prior checkpoint state.
    ///
    /// When the append tail is staged (not yet finalized), rewrite the primary and backup
    /// footers with cleared checkpoint pointers instead of blanking the backup footer, so the
    /// existing finalized archive remains readable if the append session aborts before `finalize()`.
    pub async fn clear_backup_footer_gap(&mut self) -> Result<()> {
        if let Some(ref mut staged) = self.staged_append {
            let cleared_footer = Footer::builder(
                staged.original_footer.data_end_offset(),
                staged.original_footer.block_count(),
                staged.original_footer.sequence_number(),
            )
            .catalog(
                staged.original_footer.catalog_offset(),
                staged.original_footer.catalog_size(),
                staged.original_footer.catalog_block_id(),
            )
            .checkpoint(0, 0)
            .manifest(
                staged.original_footer.manifest_offset(),
                staged.original_footer.manifest_block_id(),
            )
            .index(
                staged.original_footer.index_offset(),
                staged.original_footer.index_size(),
                staged.original_footer.index_block_id(),
            )
            .backup_header(staged.original_footer.backup_header_offset())
            .build();
            let footer_bytes = cleared_footer.to_bytes()?;
            self.writer
                .write_at(HEADER_SIZE as u64, &footer_bytes)
                .await?;
            staged.overwrite_original_head_footer(&footer_bytes).await?;
            let backup_hdr = staged.original_footer.backup_header_offset();
            if backup_hdr >= DATA_REGION_START {
                let primary_footer_offset = backup_hdr + HEADER_SIZE as u64;
                if self.writer.current_size() >= primary_footer_offset + FOOTER_SIZE as u64 {
                    self.writer
                        .write_at(primary_footer_offset, &footer_bytes)
                        .await?;
                    staged
                        .overwrite_original_tail_slice(primary_footer_offset, &footer_bytes)
                        .await?;
                }
            }
            staged.original_footer = cleared_footer;
            self.writer.sync_data().await?;
            self.last_checkpoint_offset = 0;
            self.last_checkpoint_block_id = 0;
            return Ok(());
        }
        let zeros = [0u8; BACKUP_FOOTER_GAP];
        self.writer.write_at(HEADER_SIZE as u64, &zeros).await?;
        self.writer.sync_data().await?;
        self.last_checkpoint_offset = 0;
        self.last_checkpoint_block_id = 0;
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

    /// Update the last manifest location info (v8.2).
    ///
    /// Manifest size is not stored in the footer; it is derived from the
    /// typed block's `BlockHeader` at read time.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if the offset exceeds the current write position.
    pub fn set_manifest_info(&mut self, offset: u64, block_id: u32) -> era_common::Result<()> {
        self.validate_offset_in_bounds("manifest", offset)?;
        self.last_manifest_offset = offset;
        self.last_manifest_block_id = block_id;
        debug_assert!(
            self.last_manifest_offset == 0 || self.last_manifest_offset <= self.position,
            "manifest postcondition violated: offset {} > position {}",
            self.last_manifest_offset,
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
    /// Fixed-size volumes update both footer locations. Growable volumes persist
    /// checkpoint state via the reserved backup footer gap until finalization writes
    /// the terminal primary footer.
    ///
    /// # Errors
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
        self.set_last_checkpoint(checkpoint_offset)?;

        if self.staged_append.is_some() {
            // Keep the previously finalized on-disk footers intact until finalize_with_catalog
            // flushes the staged append tail atomically.
            return Ok(());
        }

        if let Some(max_size) = self.max_size {
            let pad_target = max_size.saturating_sub(BACKUP_HEADER_FOOTER_RESERVED);
            self.pad_to_size(pad_target).await?;
            self.writer.sync_data().await?;

            let backup_header_offset = pad_target;
            let footer = crate::Footer::builder(self.position, self.block_count, self.sequence)
                .catalog(
                    self.last_catalog_offset,
                    self.last_catalog_size,
                    self.last_catalog_block_id,
                )
                .checkpoint(self.last_checkpoint_offset, self.last_checkpoint_block_id)
                .manifest(self.last_manifest_offset, self.last_manifest_block_id)
                .index(
                    self.last_index_offset,
                    self.last_index_size,
                    self.last_index_block_id,
                )
                .backup_header(backup_header_offset)
                .build();

            let footer_bytes = footer.to_bytes()?;
            let footer_offset = backup_header_offset + HEADER_SIZE as u64;
            self.writer.write_at(footer_offset, &footer_bytes).await?;
            self.writer
                .write_at(HEADER_SIZE as u64, &footer_bytes)
                .await?;
        } else {
            self.writer.sync_data().await?;

            let footer = crate::Footer::builder(self.position, self.block_count, self.sequence)
                .catalog(
                    self.last_catalog_offset,
                    self.last_catalog_size,
                    self.last_catalog_block_id,
                )
                .checkpoint(self.last_checkpoint_offset, self.last_checkpoint_block_id)
                .manifest(self.last_manifest_offset, self.last_manifest_block_id)
                .index(
                    self.last_index_offset,
                    self.last_index_size,
                    self.last_index_block_id,
                )
                .backup_header(0)
                .build();

            let footer_bytes = footer.to_bytes()?;
            self.writer
                .write_at(HEADER_SIZE as u64, &footer_bytes)
                .await?;
        }

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

    /// Get the volume sequence number (0-based position in multi-volume archive)
    #[must_use]
    pub fn volume_sequence(&self) -> u16 {
        self.header.volume_sequence()
    }

    pub fn update_total_volumes(&mut self, total: u16) {
        self.header.set_total_volumes(total);
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

        if let Some(ref mut staged) = self.staged_append {
            staged.append_slices(&[&header_bytes, &block.data]).await?;
        } else if self.max_size.is_some() {
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

        if self.staged_append.is_some() || self.max_size.is_some() {
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
        if let Some(ref staged) = self.staged_append {
            staged.spool.sync_data().await.map_err(EraError::Io)?;
        }
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

        if let Some(ref mut staged) = self.staged_append {
            staged.append_slices(&[data]).await?;
            self.position += data.len() as u64;
        } else if self.max_size.is_some() {
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

        let backup_header_offset = if let Some(max_size) = self.max_size {
            max_size.saturating_sub(BACKUP_HEADER_FOOTER_RESERVED)
        } else {
            self.position
        };
        // V30-04: Validate backup header offset is not below DATA_REGION_START
        if backup_header_offset < DATA_REGION_START {
            return Err(era_common::EraError::InvalidConfig(format!(
                "backup_header_offset {} is below DATA_REGION_START {}",
                backup_header_offset, DATA_REGION_START
            )));
        }

        self.sequence += 1;
        let header_bytes = self.header.to_bytes()?;

        // Calculate data_end_offset (where data region ends, before backup header)
        let data_end_offset = backup_header_offset;

        // V27-12: Store catalog/index info so future checkpoints preserve it
        self.last_catalog_offset = catalog_offset;
        self.last_catalog_size = catalog_size;
        self.last_catalog_block_id = catalog_block_id;
        self.last_index_offset = index_offset;
        self.last_index_size = index_size;
        self.last_index_block_id = index_block_id;

        let footer = Footer::builder(data_end_offset, self.block_count, self.sequence)
            .catalog(catalog_offset, catalog_size, catalog_block_id)
            .checkpoint(self.last_checkpoint_offset, self.last_checkpoint_block_id)
            .manifest(self.last_manifest_offset, self.last_manifest_block_id)
            .index(index_offset, index_size, index_block_id)
            .backup_header(backup_header_offset)
            .build();
        let footer_bytes = footer.to_bytes()?;

        let mut staged_opt = self.staged_append.take();
        let commit_result: Result<()> = async {
            if let Some(ref mut staged) = staged_opt {
                // Persist a valid transitional footer at offset 4096 BEFORE truncating
                // old metadata, so a hard crash right after truncate still leaves the
                // retained data region openable.
                let transitional_bytes = Self::build_transitional_footer(staged).to_bytes()?;
                self.writer
                    .write_at(HEADER_SIZE as u64, &transitional_bytes)
                    .await?;
                self.writer.sync_data().await?;
                Self::stream_staged_tail(&mut self.writer, staged).await?;
            }

            // Random padding if max_size is set
            if let Some(max_size) = self.max_size {
                // Ensure full padding to max_size minus space for backup header + footer
                let pad_target = max_size.saturating_sub(BACKUP_HEADER_FOOTER_RESERVED);
                self.pad_to_size(pad_target).await?;
                self.position = pad_target;
            }

            // CRASH SAFETY (LL-03 / RF-06): Sync data/padding to disk BEFORE writing
            // backup header and overwriting the recovery backup footer at offset 4096,
            // for both fixed-size and growable volumes.
            self.writer.sync_data().await?;

            // 1. Rewrite primary header at offset 0 so total_volumes is current,
            // and write backup header (copy of primary) at backup_header_offset.
            self.writer.write_at(0, &header_bytes).await?;

            if self.max_size.is_some() {
                self.writer
                    .write_at(backup_header_offset, &header_bytes)
                    .await?;
            } else {
                self.writer.append(&header_bytes).await?;
            }

            // 2. Write primary footer after backup header
            let primary_footer_offset = backup_header_offset + HEADER_SIZE as u64;
            if self.max_size.is_some() {
                self.writer
                    .write_at(primary_footer_offset, &footer_bytes)
                    .await?;
            } else {
                self.writer.append(&footer_bytes).await?;
            }

            // 3. Write backup footer at reserved gap (offset HEADER_SIZE = 4096)
            self.writer
                .write_at(HEADER_SIZE as u64, &footer_bytes)
                .await?;

            // Sync to disk
            self.writer.sync().await
        }
        .await;

        if let Err(err) = commit_result {
            if let Some(ref mut staged) = staged_opt {
                let _ = Self::restore_staged_original(&mut self.writer, staged).await;
            }
            return Err(err);
        }

        self.writer.close().await?;

        Ok(self.header)
    }

    /// Digest the bytes that finalization writes to both header locations.
    pub fn finalized_header_digest(&self) -> Result<[u8; 32]> {
        superheader_digest(&self.header)
    }

    /// Close the underlying writer handle while preserving state for deferred finalization.
    pub(crate) async fn close_for_later_finalize(self) -> Result<RetiredVolumeState> {
        let state = RetiredVolumeState {
            header: self.header,
            position: self.position,
            block_count: self.block_count,
            raw_bytes_written: self.raw_bytes_written,
            sequence: self.sequence,
            max_size: self.max_size,
            last_checkpoint_offset: self.last_checkpoint_offset,
            last_checkpoint_block_id: self.last_checkpoint_block_id,
            last_catalog_offset: self.last_catalog_offset,
            last_catalog_size: self.last_catalog_size,
            last_catalog_block_id: self.last_catalog_block_id,
            last_index_offset: self.last_index_offset,
            last_index_size: self.last_index_size,
            last_index_block_id: self.last_index_block_id,
            last_manifest_offset: self.last_manifest_offset,
            last_manifest_block_id: self.last_manifest_block_id,
            staged_append: self.staged_append,
        };
        self.writer.close().await?;
        Ok(state)
    }

    /// Reopen a previously retired volume to rewrite its final header and trailers.
    pub(crate) async fn reopen_for_finalize<B: StorageBackend<Writer = W>>(
        backend: &B,
        path: &Path,
        state: RetiredVolumeState,
    ) -> Result<Self> {
        let mut writer = backend.open_append(path).await?;
        let actual_size = writer.current_size();
        let min_expected_size = state
            .staged_append
            .as_ref()
            .map_or(state.position, |staged| staged.base_offset);
        if actual_size < min_expected_size {
            return Err(era_common::EraError::CorruptedHeader(format!(
                "retired volume size {} is less than expected position {}",
                actual_size, min_expected_size
            )));
        }
        if state.staged_append.is_none()
            && state.max_size.is_none()
            && actual_size != state.position
        {
            writer.truncate(state.position).await?;
        }
        Ok(Self {
            writer,
            header: state.header,
            position: state.position,
            block_count: state.block_count,
            raw_bytes_written: state.raw_bytes_written,
            sequence: state.sequence,
            max_size: state.max_size,
            last_checkpoint_offset: state.last_checkpoint_offset,
            last_checkpoint_block_id: state.last_checkpoint_block_id,
            last_catalog_offset: state.last_catalog_offset,
            last_catalog_size: state.last_catalog_size,
            last_catalog_block_id: state.last_catalog_block_id,
            last_index_offset: state.last_index_offset,
            last_index_size: state.last_index_size,
            last_index_block_id: state.last_index_block_id,
            last_manifest_offset: state.last_manifest_offset,
            last_manifest_block_id: state.last_manifest_block_id,
            staged_append: state.staged_append,
        })
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
