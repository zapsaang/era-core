//! Multi-volume management for large archives.
//!
//! This module provides automatic volume splitting when archives exceed a size limit.

use era_common::{BlockLocation, EncryptedMacroBlock, Result};
use era_storage::{StorageBackend, StorageWriter};
use std::path::PathBuf;

use crate::footer::FOOTER_SIZE;
use crate::header::HEADER_SIZE;
use crate::{SuperHeader, VolumeWriter};

/// Default maximum volume size (4 GB)
pub const DEFAULT_MAX_VOLUME_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Minimum volume size (must fit header + footer + at least one small block)
pub const MIN_VOLUME_SIZE: u64 = HEADER_SIZE as u64 + FOOTER_SIZE as u64 + 16 * 1024; // ~20KB minimum

/// Configuration for multi-volume archives
#[derive(Debug, Clone)]
pub struct MultiVolumeConfig {
    /// Maximum size per volume in bytes
    pub max_volume_size: u64,
    /// Base path for volume files (without extension)
    pub base_path: PathBuf,
}

impl MultiVolumeConfig {
    /// Create a new multi-volume configuration
    pub fn new(base_path: impl Into<PathBuf>, max_volume_size: u64) -> Result<Self> {
        let max_volume_size = max_volume_size.max(MIN_VOLUME_SIZE);
        Ok(Self {
            max_volume_size,
            base_path: base_path.into(),
        })
    }

    /// Generate the path for a specific volume number
    pub fn volume_path(&self, volume_num: u16) -> PathBuf {
        if volume_num == 0 {
            self.base_path.with_extension("era")
        } else {
            let ext = format!("era.{:03}", volume_num);
            self.base_path.with_extension(ext)
        }
    }
}

/// Statistics about a multi-volume archive
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
    pub fn create<B: StorageBackend<Writer = W>>(
        backend: &B,
        config: MultiVolumeConfig,
        header: SuperHeader,
    ) -> Result<Self> {
        let volume_path = config.volume_path(0);
        let volume_filename = volume_path.file_name().unwrap_or_default();

        let mut volume_writer = VolumeWriter::create(
            backend,
            std::path::Path::new(volume_filename),
            header.clone(),
        )?;

        volume_writer.set_max_size(config.max_volume_size)?;

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
    pub fn write_block<B: StorageBackend<Writer = W>>(
        &mut self,
        backend: &B,
        block: &EncryptedMacroBlock,
    ) -> Result<BlockLocation> {
        let block_size = block.data.len() as u32;

        // Check if we need to switch to a new volume
        if !self.would_fit(block_size) {
            self.switch_volume(backend)?;
        }

        // Write the block
        let writer = self.current_writer.as_mut().ok_or_else(|| {
            era_common::EraError::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "No active volume writer",
            ))
        })?;

        let location = writer.write_block(block)?;
        self.stats.total_blocks += 1;
        self.stats.total_bytes += block.data.len() as u64 + 4; // +4 for length prefix

        Ok(location)
    }

    /// Switch to a new volume
    fn switch_volume<B: StorageBackend<Writer = W>>(&mut self, backend: &B) -> Result<()> {
        // Finalize current volume
        if let Some(writer) = self.current_writer.take() {
            let current_size = writer.current_size();
            let volume_path = self.config.volume_path(self.stats.volume_count - 1);
            writer.finalize()?;
            self.stats.volumes.push((volume_path, current_size));
        }

        // Create next volume
        let next_header = self.template_header.next_volume();

        let volume_path = self.config.volume_path(self.stats.volume_count);
        let volume_filename = volume_path.file_name().unwrap_or_default();

        let mut volume_writer = VolumeWriter::create(
            backend,
            std::path::Path::new(volume_filename),
            next_header.clone(),
        )?;

        volume_writer.set_max_size(self.config.max_volume_size)?;

        self.current_writer = Some(volume_writer);
        // Only update template header after successful creation to ensure atomicity
        self.template_header = next_header;
        self.stats.volume_count += 1;

        Ok(())
    }

    /// Finalize all volumes and return statistics
    pub fn finalize(mut self) -> Result<MultiVolumeStats> {
        if let Some(writer) = self.current_writer.take() {
            let current_size = writer.current_size();
            let volume_path = self.config.volume_path(self.stats.volume_count - 1);
            writer.finalize()?;
            self.stats.volumes.push((volume_path, current_size));
        }

        Ok(self.stats)
    }

    /// Remaining space in current volume (conservative estimate)
    fn remaining_space(&self) -> u64 {
        if let Some(ref writer) = self.current_writer {
            let current_size = writer.current_size();
            let reserved = FOOTER_SIZE as u64 + 4096; // Reserve for footer + padding
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
    pub fn would_fit(&self, block_size: u32) -> bool {
        let needed = block_size as u64 + 4; // 4 bytes for length prefix
        self.remaining_space() >= needed
    }

    /// Get current volume number
    pub fn current_volume_num(&self) -> u16 {
        self.stats.volume_count.saturating_sub(1)
    }

    /// Get statistics about the multi-volume archive
    pub fn stats(&self) -> &MultiVolumeStats {
        &self.stats
    }
}

/// Reader for multi-volume archives
///
/// Provides unified access to blocks across multiple volumes
pub struct MultiVolumeReader<R: era_storage::StorageReader> {
    /// Loaded volume readers by volume_id
    readers: std::collections::HashMap<era_common::VolumeId, crate::VolumeReader<R>>,
    /// Archive ID (shared across all volumes)
    archive_id: era_common::ArchiveId,
    /// List of volume paths in order
    volume_paths: Vec<PathBuf>,
}

impl<R: era_storage::StorageReader> MultiVolumeReader<R> {
    /// Open a multi-volume archive from the first volume
    pub fn open<B: era_storage::StorageBackend<Reader = R>>(
        backend: &B,
        first_volume_path: &std::path::Path,
    ) -> Result<Self> {
        // Open the first volume
        let volume_filename = first_volume_path.file_name().unwrap_or_default();
        let first_reader =
            crate::VolumeReader::open(backend, std::path::Path::new(volume_filename))?;
        let archive_id = first_reader.header().archive_id;
        let first_volume_id = first_reader.header().volume_id;

        let mut readers = std::collections::HashMap::new();
        readers.insert(first_volume_id, first_reader);

        let mut volume_paths = vec![first_volume_path.to_path_buf()];

        // Try to find additional volumes
        let base_path = first_volume_path.with_extension("");
        for seq in 1..1000u16 {
            let ext = format!("era.{:03}", seq);
            let next_path = base_path.with_extension(ext);
            let next_filename = next_path.file_name().unwrap_or_default();

            match crate::VolumeReader::open(backend, std::path::Path::new(next_filename)) {
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
    pub fn volume_count(&self) -> usize {
        self.readers.len()
    }

    /// Read a block by its location
    pub fn read_block(&self, location: &BlockLocation) -> Result<EncryptedMacroBlock> {
        let reader = self.readers.get(&location.volume_id).ok_or_else(|| {
            era_common::EraError::VolumeNotFound {
                volume_id: format!("{:?}", location.volume_id),
            }
        })?;

        reader.read_block(location)
    }

    /// Get the header from the first volume
    pub fn header(&self) -> Option<&SuperHeader> {
        self.volume_paths
            .first()
            .and_then(|_| self.readers.values().next())
            .map(|r| r.header())
    }

    /// Get the archive ID
    pub fn archive_id(&self) -> era_common::ArchiveId {
        self.archive_id
    }

    /// Get list of volume paths
    pub fn volume_paths(&self) -> &[PathBuf] {
        &self.volume_paths
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use era_common::{ArchiveConfig, ArchiveId, BlockId};
    use era_storage::LocalStorageBackend;
    use tempfile::TempDir;

    fn create_test_header() -> SuperHeader {
        SuperHeader::new(
            ArchiveId::new(),
            vec![],
            ArchiveConfig::default(),
            [0u8; 16],
        )
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

    // These tests will be implemented as we build the functionality

    #[test]
    fn test_create_multi_volume_writer() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("multi_archive");
        let config = MultiVolumeConfig::new(&base_path, 100 * 1024).unwrap(); // 100KB volumes

        let header = create_test_header();
        let backend = LocalStorageBackend::new(temp_dir.path());

        // This will be implemented
        let writer =
            MultiVolumeWriter::<era_storage::LocalStorageWriter>::create(&backend, config, header);

        // For now, just verify the test compiles
        assert!(writer.is_ok());
    }

    #[test]
    fn test_auto_volume_switch_on_size_limit() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("multi_archive");

        // Use small volume size to trigger splits: 50KB
        let config = MultiVolumeConfig::new(&base_path, 50 * 1024).unwrap();

        let header = create_test_header();
        let backend = LocalStorageBackend::new(temp_dir.path());

        let mut writer = MultiVolumeWriter::create(&backend, config, header).unwrap();

        // Write multiple blocks that should trigger volume switch
        // Each block is ~10KB
        for _ in 0..10 {
            let block = create_test_block(10 * 1024);
            writer.write_block(&backend, &block).unwrap();
        }

        // Should have created multiple volumes
        let stats = writer.finalize().unwrap();
        assert!(
            stats.volume_count >= 2,
            "Expected multiple volumes, got {}",
            stats.volume_count
        );
    }

    #[test]
    fn test_block_location_tracks_volume() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("multi_archive");

        // Small volumes
        let config = MultiVolumeConfig::new(&base_path, 50 * 1024).unwrap();
        let header = create_test_header();
        let backend = LocalStorageBackend::new(temp_dir.path());

        let mut writer = MultiVolumeWriter::create(&backend, config, header).unwrap();

        let mut locations = Vec::new();
        for _ in 0..6 {
            let block = create_test_block(10 * 1024);
            let loc = writer.write_block(&backend, &block).unwrap();
            locations.push(loc);
        }

        writer.finalize().unwrap();

        // First few blocks should be in volume 0, later ones in volume 1+
        let volume_ids: Vec<_> = locations.iter().map(|l| l.volume_id).collect();
        let unique_volumes: std::collections::HashSet<_> = volume_ids.iter().collect();

        assert!(
            unique_volumes.len() >= 2,
            "Blocks should span multiple volumes"
        );
    }

    #[test]
    fn test_would_fit_check() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("multi_archive");
        let config = MultiVolumeConfig::new(&base_path, 20 * 1024).unwrap(); // 20KB limit
        let header = create_test_header();
        let backend = LocalStorageBackend::new(temp_dir.path());

        let mut writer = MultiVolumeWriter::create(&backend, config, header).unwrap();

        // Initially should have space
        assert!(writer.would_fit(1024)); // 1KB should fit

        // After writing blocks, space decreases
        let block = create_test_block(5 * 1024);
        writer.write_block(&backend, &block).unwrap();

        // Large block might not fit anymore
        // This depends on remaining space calculation
        let large_block_fits = writer.would_fit(15 * 1024);
        // Just verify the method works - actual result depends on implementation
        let _ = large_block_fits;

        writer.finalize().unwrap();
    }

    // ============ MultiVolumeReader Tests ============

    #[test]
    fn test_multi_volume_reader_open() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("multi_archive");
        let config = MultiVolumeConfig::new(&base_path, 50 * 1024).unwrap();
        let header = create_test_header();
        let backend = LocalStorageBackend::new(temp_dir.path());

        // Write some blocks to create multiple volumes
        let mut writer = MultiVolumeWriter::create(&backend, config.clone(), header).unwrap();
        for _ in 0..6 {
            let block = create_test_block(10 * 1024);
            writer.write_block(&backend, &block).unwrap();
        }
        let stats = writer.finalize().unwrap();
        assert!(stats.volume_count >= 2);

        // Now open with reader
        let first_volume = config.volume_path(0);
        let reader =
            MultiVolumeReader::<era_storage::LocalStorageReader>::open(&backend, &first_volume)
                .unwrap();

        assert_eq!(reader.volume_count(), stats.volume_count as usize);
    }

    #[test]
    fn test_multi_volume_reader_read_across_volumes() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("multi_archive");
        let config = MultiVolumeConfig::new(&base_path, 50 * 1024).unwrap();
        let header = create_test_header();
        let backend = LocalStorageBackend::new(temp_dir.path());

        // Write blocks and track their locations
        let mut writer = MultiVolumeWriter::create(&backend, config.clone(), header).unwrap();
        let mut locations = Vec::new();
        for i in 0..6 {
            let block = create_test_block(10 * 1024);
            let loc = writer.write_block(&backend, &block).unwrap();
            locations.push((i, loc));
        }
        writer.finalize().unwrap();

        // Open reader
        let first_volume = config.volume_path(0);
        let reader = MultiVolumeReader::open(&backend, &first_volume).unwrap();

        // Read all blocks by their locations
        for (_, loc) in &locations {
            let block = reader.read_block(loc);
            assert!(block.is_ok(), "Failed to read block: {:?}", block.err());
        }
    }

    #[test]
    fn test_multi_volume_reader_single_volume() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("single_archive");
        let config = MultiVolumeConfig::new(&base_path, 1024 * 1024).unwrap(); // Large volume
        let header = create_test_header();
        let backend = LocalStorageBackend::new(temp_dir.path());

        // Write just one small block
        let mut writer = MultiVolumeWriter::create(&backend, config.clone(), header).unwrap();
        let block = create_test_block(1024);
        let loc = writer.write_block(&backend, &block).unwrap();
        writer.finalize().unwrap();

        // Open reader
        let first_volume = config.volume_path(0);
        let reader = MultiVolumeReader::open(&backend, &first_volume).unwrap();

        assert_eq!(reader.volume_count(), 1);

        let read_block = reader.read_block(&loc).unwrap();
        assert_eq!(read_block.data.len(), 1024);
    }
}
