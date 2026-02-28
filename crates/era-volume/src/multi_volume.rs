//! Multi-volume management for large archives.
//!
//! This module provides automatic volume splitting when archives exceed a size limit.
//! All I/O operations are async (non-blocking).

use era_common::{BlockLocation, EncryptedMacroBlock, EraError, Result};
use era_storage::{StorageBackend, StorageReader, StorageWriter};
use std::path::PathBuf;

use crate::footer::FOOTER_SIZE;
use crate::header::HEADER_SIZE;
use crate::{SuperHeader, VolumeWriter};

/// Default maximum volume size (4 GB)
pub const DEFAULT_MAX_VOLUME_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Minimum volume size (must fit header + footer + at least one small block)
pub const MIN_VOLUME_SIZE: u64 = HEADER_SIZE as u64 + FOOTER_SIZE as u64 + 16 * 1024; // ~20KB minimum

/// Maximum number of volume sequences to scan when discovering multi-volume archives.
/// Scanning terminates early on the first missing sequence number.
const MAX_VOLUME_SCAN: u16 = 1000;

/// Configuration for multi-volume archives
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct MultiVolumeConfig {
    /// Maximum size per volume in bytes
    pub max_volume_size: u64,
    /// Base path for volume files (without extension)
    pub base_path: PathBuf,
}

impl MultiVolumeConfig {
    /// Create a new multi-volume configuration
    ///
    /// # Errors
    /// This method currently always succeeds but returns `Result` for forward compatibility.
    /// The `max_volume_size` is clamped to [`MIN_VOLUME_SIZE`] if the provided value is smaller.
    pub fn new(base_path: impl Into<PathBuf>, max_volume_size: u64) -> Result<Self> {
        let max_volume_size = max_volume_size.max(MIN_VOLUME_SIZE);
        Ok(Self {
            max_volume_size,
            base_path: base_path.into(),
        })
    }

    /// Generate the path for a specific volume number
    pub fn volume_path(&self, volume_num: u16) -> PathBuf {
        crate::volume_path(&self.base_path, volume_num)
    }
}

/// Statistics about a multi-volume archive
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct MultiVolumeStats {
    /// Total number of volumes created
    pub volume_count: u16,
    /// Total bytes written across all volumes
    pub total_bytes: u64,
    /// Total blocks written across all volumes
    pub total_blocks: u32,
    /// List of (volume_path, size) pairs
    pub volumes: Vec<(PathBuf, u64)>,
}

/// Manager for writing multi-volume archives
pub struct MultiVolumeWriter<W: StorageWriter> {
    /// Configuration
    config: MultiVolumeConfig,
    /// Current volume writer
    current_writer: Option<VolumeWriter<W>>,
    /// Template header for creating new volumes
    template_header: SuperHeader,
    /// Statistics
    stats: MultiVolumeStats,
    /// Storage backend reference (type-erased for flexibility)
    _phantom: std::marker::PhantomData<W>,
}

impl<W: StorageWriter> MultiVolumeWriter<W> {
    /// Create a new multi-volume writer
    ///
    /// # Errors
    /// Returns `InvalidConfig` if the volume path has no filename.
    /// Returns `Serialization` if the header cannot be encoded.
    /// Returns I/O errors from creating the volume or setting its max size.
    pub async fn create<B: StorageBackend<Writer = W>>(
        backend: &B,
        config: MultiVolumeConfig,
        header: SuperHeader,
    ) -> Result<Self> {
        let volume_path = config.volume_path(0);
        let volume_filename = volume_path.file_name().ok_or_else(|| {
            EraError::InvalidConfig(format!("path has no filename: {:?}", volume_path))
        })?;

        let mut volume_writer = VolumeWriter::create(
            backend,
            std::path::Path::new(volume_filename),
            header.clone(),
        )
        .await?;

        volume_writer.set_max_size(config.max_volume_size).await?;

        let stats = MultiVolumeStats {
            volume_count: 1,
            ..Default::default()
        };

        Ok(Self {
            config,
            current_writer: Some(volume_writer),
            template_header: header,
            stats,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Write a block, automatically switching volumes if needed
    ///
    /// # Errors
    /// Returns `InvalidConfig` if the block size exceeds `u32::MAX`.
    /// Returns `Io` if no active volume writer exists.
    /// Returns I/O errors from writing the block or switching volumes.
    pub async fn write_block<B: StorageBackend<Writer = W>>(
        &mut self,
        backend: &B,
        block: &EncryptedMacroBlock,
    ) -> Result<BlockLocation> {
        // Default to Data block type
        self.write_canonical_block(backend, block, era_common::BlockType::Data)
            .await
    }

    /// Write a canonical block, automatically switching volumes if needed
    ///
    /// # Errors
    /// Returns `InvalidConfig` if the block size exceeds `u32::MAX`.
    /// Returns `Io` if no active volume writer exists.
    /// Returns I/O errors from writing the block or switching volumes.
    pub async fn write_canonical_block<B: StorageBackend<Writer = W>>(
        &mut self,
        backend: &B,
        block: &EncryptedMacroBlock,
        block_type: era_common::BlockType,
    ) -> Result<BlockLocation> {
        let block_size = u32::try_from(block.data.len()).map_err(|_| {
            era_common::EraError::InvalidConfig(format!(
                "block size {} exceeds u32",
                block.data.len()
            ))
        })?;

        // Check if we need to switch to a new volume
        if !self.would_fit(block_size) {
            self.switch_volume(backend).await?;
        }

        // Write the block
        let writer = self.current_writer.as_mut().ok_or_else(|| {
            era_common::EraError::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "No active volume writer",
            ))
        })?;

        let location = writer.write_canonical_block(block, block_type).await?;
        self.stats.total_blocks = self.stats.total_blocks.saturating_add(1);
        // Format uses BlockHeader::SIZE (16 bytes) instead of 4 bytes
        self.stats.total_bytes += block.data.len() as u64 + era_common::BlockHeader::SIZE as u64;

        Ok(location)
    }

    /// Switch to a new volume.
    ///
    /// # Cancellation Safety
    ///
    /// If cancelled after `take()` but before re-assignment at the end,
    /// `self.current_writer` remains `None`. Subsequent writes will
    /// return `Err(InvalidConfig)` via `ok_or_else`. The old volume is
    /// finalized on disk; the new volume file may be orphaned if created
    /// but not assigned. This is recoverable: the engine re-opens or
    /// re-creates volumes on restart.
    async fn switch_volume<B: StorageBackend<Writer = W>>(&mut self, backend: &B) -> Result<()> {
        // Finalize current volume
        if let Some(writer) = self.current_writer.take() {
            let current_size = writer.current_size();
            let volume_path = self.config.volume_path(self.stats.volume_count - 1);
            writer.finalize().await?;
            self.stats.volumes.push((volume_path, current_size));
        }

        // Create next volume
        let next_header = self.template_header.next_volume()?;

        let volume_path = self.config.volume_path(self.stats.volume_count);
        let volume_filename = volume_path.file_name().ok_or_else(|| {
            EraError::InvalidConfig(format!("path has no filename: {:?}", volume_path))
        })?;

        let mut volume_writer = VolumeWriter::create(
            backend,
            std::path::Path::new(volume_filename),
            next_header.clone(),
        )
        .await?;

        volume_writer
            .set_max_size(self.config.max_volume_size)
            .await?;

        self.current_writer = Some(volume_writer);
        // Only update template header after successful creation to ensure atomicity
        self.template_header = next_header;
        self.stats.volume_count = self.stats.volume_count.saturating_add(1);

        Ok(())
    }

    /// Finalize all volumes and return statistics
    ///
    /// # Errors
    /// Returns `Serialization` if the header or footer cannot be encoded.
    /// Returns I/O errors from finalizing the current volume.
    pub async fn finalize(mut self) -> Result<MultiVolumeStats> {
        if let Some(writer) = self.current_writer.take() {
            let current_size = writer.current_size();
            let volume_path = self.config.volume_path(self.stats.volume_count - 1);
            writer.finalize().await?;
            self.stats.volumes.push((volume_path, current_size));
        }

        Ok(self.stats)
    }

    /// Remaining space in current volume.
    ///
    /// Reserves space for footer (128B) + backup header (4096B) = 4224 bytes.
    /// Callers that write blocks should use `would_fit()` which additionally
    /// accounts for BlockHeader overhead, making the effective reservation 4240 bytes.
    fn remaining_space(&self) -> u64 {
        if let Some(ref writer) = self.current_writer {
            let current_size = writer.current_size();
            let reserved = FOOTER_SIZE as u64 + HEADER_SIZE as u64; // Structural: footer (128) + backup header (4096)
            if current_size + reserved >= self.config.max_volume_size {
                0
            } else {
                self.config.max_volume_size - current_size - reserved
            }
        } else {
            0
        }
    }

    /// Check if a block of given size would fit in the current volume
    #[must_use]
    pub fn would_fit(&self, block_size: u32) -> bool {
        let needed = block_size as u64 + era_common::BlockHeader::SIZE as u64;
        self.remaining_space() >= needed
    }

    /// Get current volume number
    #[must_use]
    pub fn current_volume_num(&self) -> u16 {
        self.stats.volume_count.saturating_sub(1)
    }

    /// Get statistics about the multi-volume archive
    #[must_use]
    pub fn stats(&self) -> &MultiVolumeStats {
        &self.stats
    }
}

/// Reader for multi-volume archives
///
/// Provides unified access to blocks across multiple volumes
pub struct MultiVolumeReader<R: StorageReader> {
    /// Loaded volume readers by volume_id
    readers: std::collections::HashMap<era_common::VolumeId, crate::VolumeReader<R>>,
    /// Archive ID (shared across all volumes)
    archive_id: era_common::ArchiveId,
    /// List of volume paths in order
    volume_paths: Vec<PathBuf>,
}

impl<R: StorageReader> MultiVolumeReader<R> {
    /// Open a multi-volume archive from the first volume
    ///
    /// # Errors
    /// Returns `InvalidConfig` if the volume path has no filename.
    /// Returns `CorruptedHeader` if the first volume cannot be opened.
    /// Returns I/O errors from the storage backend during volume discovery.
    pub async fn open<B: StorageBackend<Reader = R>>(
        backend: &B,
        first_volume_path: &std::path::Path,
    ) -> Result<Self> {
        // Open the first volume
        let volume_filename = first_volume_path.file_name().ok_or_else(|| {
            EraError::InvalidConfig(format!("path has no filename: {:?}", first_volume_path))
        })?;
        let first_reader =
            crate::VolumeReader::open(backend, std::path::Path::new(volume_filename)).await?;
        let archive_id = first_reader.header().archive_id;
        let first_volume_id = first_reader.header().volume_id;

        let mut readers = std::collections::HashMap::new();
        readers.insert(first_volume_id, first_reader);

        let mut volume_paths = vec![first_volume_path.to_path_buf()];

        // Try to find additional volumes
        let base_path = first_volume_path.with_extension("");
        for seq in 1..MAX_VOLUME_SCAN {
            let next_path = crate::volume_path(&base_path, seq);
            let next_filename = next_path.file_name().ok_or_else(|| {
                EraError::InvalidConfig(format!("path has no filename: {:?}", next_path))
            })?;

            match crate::VolumeReader::open(backend, std::path::Path::new(next_filename)).await {
                Ok(reader) => {
                    // Verify it belongs to the same archive
                    if reader.header().archive_id != archive_id {
                        break;
                    }
                    let vol_id = reader.header().volume_id;
                    volume_paths.push(next_path);
                    readers.insert(vol_id, reader);
                }
                Err(_) => break,
            }
        }

        Ok(Self {
            readers,
            archive_id,
            volume_paths,
        })
    }

    /// Get the number of volumes in the archive
    #[must_use]
    pub fn volume_count(&self) -> usize {
        self.readers.len()
    }

    /// Read a block by its location
    ///
    /// # Errors
    /// Returns `VolumeNotFound` if the block's volume ID does not match any loaded volume.
    /// Returns `InvalidFormat` or `IntegrityError` if the block header or CRC is invalid.
    /// Returns I/O errors from the underlying storage backend.
    pub async fn read_block(&self, location: &BlockLocation) -> Result<EncryptedMacroBlock> {
        let reader = self.readers.get(&location.volume_id).ok_or_else(|| {
            era_common::EraError::VolumeNotFound {
                volume_id: format!("{:?}", location.volume_id),
            }
        })?;

        reader.read_block(location).await
    }

    /// Get the header from the first volume
    #[must_use]
    pub fn header(&self) -> Option<&SuperHeader> {
        // V27-10: Use ordered volume_paths to find the first volume deterministically
        // instead of non-deterministic HashMap iteration
        self.volume_paths
            .first()
            .and_then(|_| {
                // Find the reader matching the first volume by checking archive_id match
                // Since all readers share the same archive_id, we need the one with volume_sequence=0
                self.readers
                    .values()
                    .find(|r| r.header().volume_sequence == 0)
                    .or_else(|| self.readers.values().next())
            })
            .map(|r| r.header())
    }

    /// Get the archive ID
    #[must_use]
    pub fn archive_id(&self) -> era_common::ArchiveId {
        self.archive_id
    }

    /// Get list of volume paths
    #[must_use]
    pub fn volume_paths(&self) -> &[PathBuf] {
        &self.volume_paths
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

    fn create_test_header() -> SuperHeader {
        SuperHeader::new(
            ArchiveId::new(),
            vec![RecipientSlot::new(
                RecipientType::Argon2idPassword,
                Some([0x12; 8]),
                vec![0xAB; 16],
                vec![0xCD; 48],
            )],
            ArchiveConfig::default(),
            [0u8; 16],
            EncryptedVolumeKey {
                algorithm: KeyWrapAlgorithm::XChaCha20Poly1305,
                nonce: [0u8; 24],
                ciphertext: vec![0u8; 48],
            },
            AccessPolicy::AnyOfN,
        )
        .unwrap()
    }

    fn create_test_block(size: usize) -> EncryptedMacroBlock {
        EncryptedMacroBlock {
            block_id: BlockId::new(0),
            data: Bytes::from(vec![0xAAu8; size]),
            original_size: (size * 2) as u32,
            compressed_size: size as u32,
            chunk_count: 1,
        }
    }

    // ============ TDD Tests ============

    #[test]
    fn test_volume_path_generation() {
        let config = MultiVolumeConfig::new("/tmp/archive", 1024 * 1024).unwrap();

        assert_eq!(config.volume_path(0), PathBuf::from("/tmp/archive.era"));
        assert_eq!(config.volume_path(1), PathBuf::from("/tmp/archive.era.001"));
        assert_eq!(
            config.volume_path(99),
            PathBuf::from("/tmp/archive.era.099")
        );
        assert_eq!(
            config.volume_path(999),
            PathBuf::from("/tmp/archive.era.999")
        );
    }

    #[test]
    fn test_min_volume_size_enforced() {
        // Even if we request a smaller size, it should be clamped to minimum
        let config = MultiVolumeConfig::new("/tmp/archive", 1024).unwrap();
        assert!(config.max_volume_size >= MIN_VOLUME_SIZE);
    }

    #[test]
    fn test_multi_volume_stats_default() {
        let stats = MultiVolumeStats::default();
        assert_eq!(stats.volume_count, 0);
        assert_eq!(stats.total_bytes, 0);
        assert_eq!(stats.total_blocks, 0);
        assert!(stats.volumes.is_empty());
    }

    #[tokio::test]
    async fn test_create_multi_volume_writer() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("multi_archive");
        let config = MultiVolumeConfig::new(&base_path, 100 * 1024).unwrap(); // 100KB volumes

        let header = create_test_header();
        let backend = LocalStorageBackend::new(temp_dir.path());

        // TQ37-04: Use expect() to surface the actual error on failure
        // instead of assert!(is_ok()) which only says "assertion failed".
        let writer =
            MultiVolumeWriter::<era_storage::LocalStorageWriter>::create(&backend, config, header)
                .await
                .expect("MultiVolumeWriter::create should succeed");
        // Verify initial state
        assert_eq!(
            writer.current_volume_num(),
            0,
            "Writer should start on volume 0"
        );
    }

    #[tokio::test]
    async fn test_auto_volume_switch_on_size_limit() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("multi_archive");

        // Use small volume size to trigger splits: 50KB
        let config = MultiVolumeConfig::new(&base_path, 50 * 1024).unwrap();

        let header = create_test_header();
        let backend = LocalStorageBackend::new(temp_dir.path());

        let mut writer = MultiVolumeWriter::create(&backend, config, header)
            .await
            .unwrap();

        // Write multiple blocks that should trigger volume switch
        // Each block is ~10KB
        for _ in 0..10 {
            let block = create_test_block(10 * 1024);
            writer.write_block(&backend, &block).await.unwrap();
        }

        // Should have created multiple volumes
        let stats = writer.finalize().await.unwrap();
        assert!(
            stats.volume_count >= 2,
            "Expected multiple volumes, got {}",
            stats.volume_count
        );
    }

    #[tokio::test]
    async fn test_block_location_tracks_volume() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("multi_archive");

        // Small volumes
        let config = MultiVolumeConfig::new(&base_path, 50 * 1024).unwrap();
        let header = create_test_header();
        let backend = LocalStorageBackend::new(temp_dir.path());

        let mut writer = MultiVolumeWriter::create(&backend, config, header)
            .await
            .unwrap();

        let mut locations = Vec::new();
        for _ in 0..6 {
            let block = create_test_block(10 * 1024);
            let loc = writer.write_block(&backend, &block).await.unwrap();
            locations.push(loc);
        }

        writer.finalize().await.unwrap();

        // First few blocks should be in volume 0, later ones in volume 1+
        let volume_ids: Vec<_> = locations.iter().map(|l| l.volume_id).collect();
        let unique_volumes: std::collections::HashSet<_> = volume_ids.iter().collect();

        assert!(
            unique_volumes.len() >= 2,
            "Blocks should span multiple volumes"
        );
    }

    #[tokio::test]
    async fn test_would_fit_check() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("multi_archive");
        let config = MultiVolumeConfig::new(&base_path, 20 * 1024).unwrap(); // 20KB limit
        let header = create_test_header();
        let backend = LocalStorageBackend::new(temp_dir.path());

        let mut writer = MultiVolumeWriter::create(&backend, config, header)
            .await
            .unwrap();

        // Initially should have space
        assert!(writer.would_fit(1024)); // 1KB should fit

        // After writing blocks, space decreases
        let block = create_test_block(5 * 1024);
        writer.write_block(&backend, &block).await.unwrap();

        // TQ37-05: After writing 5KB into a 20KB volume (with ~8KB overhead),
        // a 15KB block should not fit. Assert the actual result instead of discarding it.
        assert!(
            !writer.would_fit(15 * 1024),
            "15KB block should not fit in 20KB volume after writing 5KB (overhead ~8KB)"
        );

        writer.finalize().await.unwrap();
    }

    // ============ MultiVolumeReader Tests ============

    #[tokio::test]
    async fn test_multi_volume_reader_open() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("multi_archive");
        let config = MultiVolumeConfig::new(&base_path, 50 * 1024).unwrap();
        let header = create_test_header();
        let backend = LocalStorageBackend::new(temp_dir.path());

        // Write some blocks to create multiple volumes
        let mut writer = MultiVolumeWriter::create(&backend, config.clone(), header)
            .await
            .unwrap();
        for _ in 0..6 {
            let block = create_test_block(10 * 1024);
            writer.write_block(&backend, &block).await.unwrap();
        }
        let stats = writer.finalize().await.unwrap();
        assert!(stats.volume_count >= 2);

        // Now open with reader
        let first_volume = config.volume_path(0);
        let reader =
            MultiVolumeReader::<era_storage::LocalStorageReader>::open(&backend, &first_volume)
                .await
                .unwrap();

        assert_eq!(reader.volume_count(), stats.volume_count as usize);
    }

    #[tokio::test]
    async fn test_multi_volume_reader_read_across_volumes() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("multi_archive");
        let config = MultiVolumeConfig::new(&base_path, 50 * 1024).unwrap();
        let header = create_test_header();
        let backend = LocalStorageBackend::new(temp_dir.path());

        // Write blocks and track their locations
        let mut writer = MultiVolumeWriter::create(&backend, config.clone(), header)
            .await
            .unwrap();
        let mut locations = Vec::new();
        for i in 0..6 {
            let block = create_test_block(10 * 1024);
            let loc = writer.write_block(&backend, &block).await.unwrap();
            locations.push((i, loc));
        }
        writer.finalize().await.unwrap();

        // Open reader
        let first_volume = config.volume_path(0);
        let reader = MultiVolumeReader::open(&backend, &first_volume)
            .await
            .unwrap();

        // Read all blocks by their locations
        for (_, loc) in &locations {
            let block = reader.read_block(loc).await;
            assert!(block.is_ok(), "Failed to read block: {:?}", block.err());
        }
    }

    #[tokio::test]
    async fn test_multi_volume_reader_single_volume() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("single_archive");
        let config = MultiVolumeConfig::new(&base_path, 1024 * 1024).unwrap(); // Large volume
        let header = create_test_header();
        let backend = LocalStorageBackend::new(temp_dir.path());

        // Write just one small block
        let mut writer = MultiVolumeWriter::create(&backend, config.clone(), header)
            .await
            .unwrap();
        let block = create_test_block(1024);
        let loc = writer.write_block(&backend, &block).await.unwrap();
        writer.finalize().await.unwrap();

        // Open reader
        let first_volume = config.volume_path(0);
        let reader = MultiVolumeReader::open(&backend, &first_volume)
            .await
            .unwrap();

        assert_eq!(reader.volume_count(), 1);

        let read_block = reader.read_block(&loc).await.unwrap();
        assert_eq!(read_block.data.len(), 1024);
    }
}
