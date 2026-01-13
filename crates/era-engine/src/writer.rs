//! Archive writer - creates ERA archives.

use bytes::Bytes;
use era_codec::ZstdCompressor;
use era_common::{
    ArchiveConfig, ArchiveId, BlockLocation, ChunkHash, ErasureCodeConfig, Result, UniqueChunk,
};
use era_crypto::{derive_key, DerivedKey, KdfParams, Salt};
use era_ingest::{Catalog, ChunkRef, ChunkerConfig, FileEntry, FileReader};
use era_packing::{ErasureBlockBuilder, MacroBlockBuilder};
use era_storage::LocalStorageBackend;
use era_volume::{SuperHeader, VolumeWriter};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

use crate::checkpoint::CheckpointManager;
use crate::recovery::{RecoveryOptions, RecoveryStrategy};

/// Builder for creating an ArchiveWriter
pub struct ArchiveWriterBuilder {
    output_path: PathBuf,
    password: Option<String>,
    config: ArchiveConfig,
    enable_cdc: bool,
    chunker_config: Option<ChunkerConfig>,
    /// Enable checkpoint for crash recovery
    enable_checkpoint: bool,
    /// Recovery options when checkpoint is enabled
    recovery_options: RecoveryOptions,
    /// Enable erasure coding for redundancy
    enable_erasure: bool,
    /// Erasure coding configuration
    erasure_config: ErasureCodeConfig,
}

impl ArchiveWriterBuilder {
    /// Create a new builder with the output path
    pub fn new(output_path: impl Into<PathBuf>) -> Self {
        Self {
            output_path: output_path.into(),
            password: None,
            config: ArchiveConfig::default(),
            enable_cdc: false,
            chunker_config: None,
            enable_checkpoint: false,
            recovery_options: RecoveryOptions::default(),
            enable_erasure: false,
            erasure_config: ErasureCodeConfig::default(),
        }
    }

    /// Set the encryption password
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Set the archive configuration
    pub fn config(mut self, config: ArchiveConfig) -> Self {
        self.config = config;
        self
    }

    /// Enable CDC chunking for large files
    pub fn enable_cdc(mut self, enable: bool) -> Self {
        self.enable_cdc = enable;
        self
    }

    /// Set custom CDC configuration
    pub fn chunker_config(mut self, config: ChunkerConfig) -> Self {
        self.chunker_config = Some(config);
        self.enable_cdc = true;
        self
    }

    /// Enable checkpoint for crash recovery
    ///
    /// When enabled, the writer will periodically save progress to a checkpoint file.
    /// If the process crashes, the next call to build() will automatically resume
    /// from the last checkpoint.
    pub fn enable_checkpoint(mut self, enable: bool) -> Self {
        self.enable_checkpoint = enable;
        self
    }

    /// Set recovery options for checkpoint behavior
    pub fn recovery_options(mut self, options: RecoveryOptions) -> Self {
        self.recovery_options = options;
        self.enable_checkpoint = true;
        self
    }

    /// Enable erasure coding for redundancy
    ///
    /// When enabled, blocks are encoded with Reed-Solomon erasure coding,
    /// allowing recovery from up to `parity_shards` lost shards.
    pub fn enable_erasure(mut self, enable: bool) -> Self {
        self.enable_erasure = enable;
        self
    }

    /// Set custom erasure coding configuration
    ///
    /// Default is 4+2 (4 data shards, 2 parity shards).
    /// This allows recovery from loss of any 2 shards.
    pub fn erasure_config(mut self, config: ErasureCodeConfig) -> Self {
        self.erasure_config = config;
        self.enable_erasure = true;
        self
    }

    /// Build the archive writer
    pub fn build(self) -> Result<ArchiveWriter> {
        let archive_id = ArchiveId::new();
        let salt = Salt::generate();

        // Derive encryption key
        let password = self.password.unwrap_or_default();
        let kdf_params = KdfParams {
            memory_cost: self.config.encryption.kdf_memory_cost,
            time_cost: self.config.encryption.kdf_time_cost,
            parallelism: 4,
        };
        let key = derive_key(password.as_bytes(), &salt, &kdf_params)?;

        // Generate password verification tag for early password validation
        let password_verification_tag = era_crypto::generate_password_verification_tag(&key);

        // Create storage backend
        let output_dir = self.output_path.parent().unwrap_or(Path::new("."));
        let backend = LocalStorageBackend::new(output_dir);

        // Create volume writer with password verification tag
        let header = SuperHeader::with_kdf_params(
            archive_id,
            *salt.as_bytes(),
            password_verification_tag,
            self.config.encryption.kdf_memory_cost,
            self.config.encryption.kdf_time_cost,
            self.config.clone(),
        );
        let volume_path = self.output_path.file_name().unwrap_or_default();
        let volume_writer = VolumeWriter::create(&backend, Path::new(volume_path), header)?;

        // Create block builder with salt as nonce context
        // This ensures unique nonces across different archives
        let nonce_context = *salt.as_bytes();
        let compressor = Box::new(ZstdCompressor::new(self.config.compression.level));
        let block_builder = MacroBlockBuilder::new(key.clone(), nonce_context, compressor);

        // Configure file reader with CDC if enabled
        let file_reader = if self.enable_cdc {
            let chunker_config = self.chunker_config.unwrap_or_default();
            FileReader::with_cdc().with_chunker_config(chunker_config)
        } else {
            FileReader::new()
        };

        // Set up checkpoint manager if enabled
        let checkpoint_manager = if self.enable_checkpoint {
            // Derive HMAC key from main key for checkpoint integrity
            let mut hmac_key = [0u8; 32];
            let mut hasher = blake3::Hasher::new();
            hasher.update(key.as_bytes());
            hasher.update(b"ERA-CHECKPOINT-KEY");
            let hash = hasher.finalize();
            hmac_key.copy_from_slice(&hash.as_bytes()[..32]);

            let manager = match self.recovery_options.strategy {
                RecoveryStrategy::StartFresh => {
                    // Delete any existing checkpoint
                    if CheckpointManager::exists(&self.output_path) {
                        warn!("Starting fresh, deleting existing checkpoint");
                        let old = CheckpointManager::load_or_create(&self.output_path)?;
                        old.delete()?;
                    }
                    CheckpointManager::with_hmac_key(&self.output_path, hmac_key)
                }
                RecoveryStrategy::Resume => {
                    CheckpointManager::load_or_create_with_key(&self.output_path, Some(hmac_key))?
                }
                RecoveryStrategy::Abort => {
                    if CheckpointManager::exists(&self.output_path) {
                        return Err(era_common::EraError::other(
                            "Checkpoint exists. Use Resume strategy to continue or StartFresh to discard."
                        ));
                    }
                    CheckpointManager::with_hmac_key(&self.output_path, hmac_key)
                }
            };
            Some(manager)
        } else {
            None
        };

        // Load existing chunk locations from checkpoint if resuming
        let chunk_locations = if let Some(ref mgr) = checkpoint_manager {
            if self.recovery_options.strategy == RecoveryStrategy::Resume {
                mgr.written_chunks().clone()
            } else {
                HashMap::new()
            }
        } else {
            HashMap::new()
        };

        // Create erasure builder if enabled
        let erasure_builder = if self.enable_erasure {
            let compressor = Box::new(ZstdCompressor::new(self.config.compression.level));
            Some(ErasureBlockBuilder::new(
                key.clone(),
                nonce_context,
                compressor,
                self.erasure_config,
            )?)
        } else {
            None
        };

        Ok(ArchiveWriter {
            archive_id,
            output_path: self.output_path,
            key,
            volume_writer,
            block_builder,
            erasure_builder,
            catalog: Catalog::new(),
            chunk_locations,
            file_reader,
            enable_cdc: self.enable_cdc,
            pending_chunks: Vec::new(),
            pending_size: 0,
            target_block_size: 4 * 1024 * 1024, // 4MB
            checkpoint_manager,
        })
    }
}

/// Writer for creating ERA archives
pub struct ArchiveWriter {
    archive_id: ArchiveId,
    /// Output path for the archive
    output_path: PathBuf,
    /// Key is stored for potential future re-keying operations
    #[allow(dead_code)]
    key: DerivedKey,
    volume_writer: VolumeWriter<era_storage::LocalStorageWriter>,
    /// Standard block builder
    block_builder: MacroBlockBuilder,
    /// Erasure-coded block builder (optional)
    erasure_builder: Option<ErasureBlockBuilder>,
    catalog: Catalog,
    chunk_locations: HashMap<ChunkHash, BlockLocation>,
    file_reader: FileReader,
    enable_cdc: bool,
    /// Pending chunks waiting to be packed together
    pending_chunks: Vec<UniqueChunk>,
    /// Current size of pending chunks
    pending_size: usize,
    /// Target block size for batching (default 4MB)
    target_block_size: usize,
    /// Checkpoint manager for crash recovery (optional)
    checkpoint_manager: Option<CheckpointManager>,
}

impl ArchiveWriter {
    /// Create a new builder
    pub fn builder(output_path: impl Into<PathBuf>) -> ArchiveWriterBuilder {
        ArchiveWriterBuilder::new(output_path)
    }

    /// Get the archive ID
    pub fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    /// Add a file to the archive
    ///
    /// If CDC is enabled, large files are automatically split into chunks.
    pub fn add_file(&mut self, path: &Path) -> Result<()> {
        info!("Adding file: {}", path.display());

        let relative_path = path
            .file_name()
            .map(PathBuf::from)
            .unwrap_or_else(|| path.to_path_buf());

        if self.enable_cdc {
            // Use CDC chunking for large files
            self.add_file_chunked(path, relative_path)
        } else {
            // Legacy: single chunk per file
            self.add_file_single(path, relative_path)
        }
    }

    /// Add a file as a single chunk (legacy mode)
    fn add_file_single(&mut self, path: &Path, relative_path: PathBuf) -> Result<()> {
        // Read the file as a single chunk
        let chunk = self.file_reader.read_file(path)?;
        let hash = chunk.hash;
        let size = chunk.data.len() as u64;

        debug!("File size: {} bytes, hash: {}", size, hash);

        // Check for dedup: skip if we already have this chunk
        if !self.chunk_locations.contains_key(&hash) {
            // Add to pending batch
            self.add_to_pending(chunk)?;
        }

        // Create catalog entry
        let entry = FileEntry::file(relative_path, size).with_hash(hash);
        self.catalog.add(entry);

        Ok(())
    }

    /// Add a file with CDC chunking
    fn add_file_chunked(&mut self, path: &Path, relative_path: PathBuf) -> Result<()> {
        // Read and chunk the file
        let chunks = self.file_reader.read_file_chunked(path)?;
        let total_size: u64 = chunks.iter().map(|c| c.data.len() as u64).sum();
        let chunk_count = chunks.len();

        debug!("File size: {} bytes, {} chunks", total_size, chunk_count);

        if chunk_count == 1 {
            // Single chunk: use legacy format for backward compatibility
            let chunk = chunks.into_iter().next().unwrap();
            let hash = chunk.hash;

            if !self.chunk_locations.contains_key(&hash) {
                self.add_to_pending(chunk)?;
            }

            let entry = FileEntry::file(relative_path, total_size).with_hash(hash);
            self.catalog.add(entry);
        } else {
            // Multiple chunks: use new chunk list format
            let mut chunk_refs = Vec::with_capacity(chunk_count);
            let mut offset = 0u64;

            for chunk in chunks {
                let hash = chunk.hash;
                let length = chunk.data.len() as u32;

                // Dedup check
                if !self.chunk_locations.contains_key(&hash) {
                    self.add_to_pending(chunk)?;
                }

                chunk_refs.push(ChunkRef::new(hash, offset, length));
                offset += length as u64;
            }

            let entry = FileEntry::file(relative_path, total_size).with_chunks(chunk_refs);
            self.catalog.add(entry);
        }

        Ok(())
    }

    /// Add chunk to pending buffer and flush if full
    fn add_to_pending(&mut self, chunk: UniqueChunk) -> Result<()> {
        let chunk_size = chunk.data.len();
        let hash = chunk.hash;

        // If single chunk exceeds target, pack it alone
        if chunk_size >= self.target_block_size {
            // Flush any pending chunks first
            if !self.pending_chunks.is_empty() {
                self.flush_pending()?;
            }

            // Pack the large chunk alone (with or without erasure coding)
            let location = self.pack_and_write_chunks(vec![chunk])?;
            self.chunk_locations.insert(hash, location);

            // Record in checkpoint if enabled
            if let Some(ref mut mgr) = self.checkpoint_manager {
                mgr.record_chunk(hash, location)?;
            }

            debug!(
                "Large chunk packed alone at offset {}",
                location.physical_offset
            );
            return Ok(());
        }

        // Check if adding this chunk would exceed target
        if self.pending_size + chunk_size > self.target_block_size {
            self.flush_pending()?;
        }

        // Add to pending
        self.pending_chunks.push(chunk);
        self.pending_size += chunk_size;

        Ok(())
    }

    /// Flush pending chunks to a single MacroBlock
    fn flush_pending(&mut self) -> Result<()> {
        if self.pending_chunks.is_empty() {
            return Ok(());
        }

        debug!(
            "Flushing {} pending chunks ({} bytes)",
            self.pending_chunks.len(),
            self.pending_size
        );

        // Take pending chunks
        let chunks = std::mem::take(&mut self.pending_chunks);
        let hashes: Vec<_> = chunks.iter().map(|c| c.hash).collect();
        self.pending_size = 0;

        // Pack and write chunks (with or without erasure coding)
        let location = self.pack_and_write_chunks(chunks)?;

        // Record location for all chunks
        for hash in &hashes {
            self.chunk_locations.insert(*hash, location);
        }

        // Record in checkpoint if enabled
        if let Some(ref mut mgr) = self.checkpoint_manager {
            for hash in hashes {
                mgr.record_chunk(hash, location)?;
            }
        }

        debug!(
            "Block with {} chunks written at offset {}",
            self.chunk_locations.len(),
            location.physical_offset
        );

        Ok(())
    }

    /// Pack and write chunks, using erasure coding if enabled
    fn pack_and_write_chunks(&mut self, chunks: Vec<UniqueChunk>) -> Result<BlockLocation> {
        if let Some(ref erasure_builder) = self.erasure_builder {
            // Use erasure coding
            let sharded_block = erasure_builder.pack_chunks(chunks)?;

            // Write all shards sequentially (data shards first, then parity)
            // For now, we store all shards in the same volume
            // Future: distribute across multiple volumes for better fault tolerance
            let mut first_location = None;

            for (idx, shard) in sharded_block.shards.iter().enumerate() {
                // Write each shard with a length prefix
                let len_bytes = (shard.len() as u32).to_le_bytes();
                self.volume_writer.write_raw(&len_bytes)?;
                let offset = self.volume_writer.write_raw(shard)?;

                if first_location.is_none() {
                    // Use the first shard's location as the block location
                    // The reader will know to read consecutive shards
                    first_location = Some(BlockLocation {
                        volume_id: self.volume_writer.volume_id(),
                        slot_index: self.volume_writer.block_count(),
                        physical_offset: offset - 4, // Include length prefix
                        encrypted_size: shard.len() as u32,
                    });
                }

                debug!(
                    "Wrote erasure shard {} at offset {} ({} bytes)",
                    idx,
                    offset,
                    shard.len()
                );
            }

            Ok(first_location.expect("at least one shard"))
        } else {
            // Standard non-erasure path
            let encrypted_block = self.block_builder.pack_chunks(chunks)?;
            self.volume_writer.write_block(&encrypted_block)
        }
    }

    /// Add a file from memory
    pub fn add_bytes(&mut self, name: &str, data: &[u8]) -> Result<()> {
        info!("Adding in-memory file: {} ({} bytes)", name, data.len());

        let hash = era_crypto::hash(data);

        // Dedup check
        if !self.chunk_locations.contains_key(&hash) {
            let chunk = UniqueChunk::new(Bytes::copy_from_slice(data), hash);
            self.add_to_pending(chunk)?;
        }

        // Create catalog entry
        let entry = FileEntry::file(PathBuf::from(name), data.len() as u64).with_hash(hash);
        self.catalog.add(entry);

        Ok(())
    }

    /// Finalize the archive
    pub fn finalize(mut self) -> Result<ArchiveStats> {
        info!("Finalizing archive...");

        // Flush any remaining pending chunks
        self.flush_pending()?;

        // Sync checkpoint before writing catalog (atomic point)
        if let Some(ref mut mgr) = self.checkpoint_manager {
            mgr.sync()?;
            debug!("Checkpoint synced before catalog write");
        }

        // Serialize and write catalog
        let catalog_bytes = self.catalog.to_bytes()?;
        let catalog_hash = era_crypto::hash(&catalog_bytes);
        let catalog_chunk = UniqueChunk::new(Bytes::from(catalog_bytes), catalog_hash);
        let catalog_block = self.block_builder.pack_single(catalog_chunk)?;
        let catalog_location = self.volume_writer.write_block(&catalog_block)?;

        debug!(
            "Catalog written at offset {} (size: {})",
            catalog_location.physical_offset, catalog_location.encrypted_size
        );

        // Finalize volume with catalog location for O(1) lookup
        let _header = self.volume_writer.finalize_with_catalog(
            catalog_location.physical_offset,
            catalog_location.encrypted_size,
        )?;

        // Delete checkpoint after successful completion
        if self.checkpoint_manager.is_some() {
            let checkpoint_path = self.output_path.with_extension("checkpoint");
            if checkpoint_path.exists() {
                if let Err(e) = std::fs::remove_file(&checkpoint_path) {
                    warn!("Failed to remove checkpoint file: {}", e);
                } else {
                    debug!("Checkpoint file removed after successful archive creation");
                }
            }
        }

        let stats = ArchiveStats {
            archive_id: self.archive_id,
            total_files: self.catalog.file_count,
            total_size: self.catalog.total_size,
            blocks_written: self.block_builder.blocks_created(),
        };

        info!(
            "Archive finalized: {} files, {} bytes, {} blocks",
            stats.total_files, stats.total_size, stats.blocks_written
        );

        Ok(stats)
    }
}

/// Statistics about the created archive
#[derive(Debug)]
pub struct ArchiveStats {
    /// Archive ID
    pub archive_id: ArchiveId,
    /// Total number of files
    pub total_files: u64,
    /// Total uncompressed size
    pub total_size: u64,
    /// Number of blocks written
    pub blocks_written: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    #[test]
    fn test_create_archive() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.era");

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .unwrap();

        writer.add_bytes("hello.txt", b"Hello, ERA!").unwrap();

        let stats = writer.finalize().unwrap();
        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.total_size, 11);
    }

    #[test]
    fn test_add_file() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.era");

        // Create a test file
        let mut test_file = NamedTempFile::new().unwrap();
        test_file.write_all(b"Test file content").unwrap();
        test_file.flush().unwrap();

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .unwrap();

        writer.add_file(test_file.path()).unwrap();

        let stats = writer.finalize().unwrap();
        assert_eq!(stats.total_files, 1);
        assert!(stats.blocks_written >= 2); // data + catalog
    }

    #[test]
    fn test_empty_archive() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("empty.era");

        let writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .unwrap();

        let stats = writer.finalize().unwrap();
        assert_eq!(stats.total_files, 0);
        assert_eq!(stats.total_size, 0);
    }

    #[test]
    fn test_multiple_files() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("multi.era");

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .unwrap();

        // Add multiple files
        writer.add_bytes("file1.txt", b"Content 1").unwrap();
        writer
            .add_bytes("file2.txt", b"Content 2 is longer")
            .unwrap();
        writer
            .add_bytes("dir/file3.txt", b"Nested content")
            .unwrap();

        let stats = writer.finalize().unwrap();
        assert_eq!(stats.total_files, 3);
    }

    #[test]
    fn test_large_file() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("large.era");

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .unwrap();

        // Add a larger file (1MB of compressible data)
        let large_data = vec![b'A'; 1024 * 1024];
        writer.add_bytes("large.bin", &large_data).unwrap();

        let stats = writer.finalize().unwrap();
        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.total_size, 1024 * 1024);
    }

    #[test]
    fn test_empty_file() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("empty_file.era");

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .unwrap();

        writer.add_bytes("empty.txt", b"").unwrap();

        let stats = writer.finalize().unwrap();
        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.total_size, 0);
    }

    #[test]
    fn test_unicode_filename() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("unicode.era");

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .unwrap();

        writer
            .add_bytes("中文文件名.txt", "内容".as_bytes())
            .unwrap();
        writer
            .add_bytes("日本語.txt", "コンテンツ".as_bytes())
            .unwrap();
        writer.add_bytes("emoji_📁.txt", b"emoji content").unwrap();

        let stats = writer.finalize().unwrap();
        assert_eq!(stats.total_files, 3);
    }

    #[test]
    fn test_special_characters_in_filename() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("special.era");

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .unwrap();

        writer
            .add_bytes("file with spaces.txt", b"content")
            .unwrap();
        writer
            .add_bytes("file-with-dashes.txt", b"content")
            .unwrap();
        writer
            .add_bytes("file_with_underscores.txt", b"content")
            .unwrap();

        let stats = writer.finalize().unwrap();
        assert_eq!(stats.total_files, 3);
    }

    #[test]
    fn test_binary_content() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("binary.era");

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .unwrap();

        // Add binary data with all byte values
        let binary_data: Vec<u8> = (0..=255).collect();
        writer.add_bytes("all_bytes.bin", &binary_data).unwrap();

        let stats = writer.finalize().unwrap();
        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.total_size, 256);
    }
}

/// Generic archive writer that supports any storage backend
pub mod generic {
    use super::*;
    use era_storage::{StorageBackend, StorageWriter};

    /// Builder for creating a GenericArchiveWriter with a custom backend
    pub struct GenericArchiveWriterBuilder<B: StorageBackend> {
        backend: B,
        filename: PathBuf,
        password: Option<String>,
        config: ArchiveConfig,
        enable_cdc: bool,
        chunker_config: Option<ChunkerConfig>,
    }

    impl<B: StorageBackend> GenericArchiveWriterBuilder<B> {
        /// Create a new builder with the given backend and filename
        pub fn new(backend: B, filename: impl Into<PathBuf>) -> Self {
            Self {
                backend,
                filename: filename.into(),
                password: None,
                config: ArchiveConfig::default(),
                enable_cdc: false,
                chunker_config: None,
            }
        }

        /// Set the encryption password
        pub fn password(mut self, password: impl Into<String>) -> Self {
            self.password = Some(password.into());
            self
        }

        /// Set the archive configuration
        pub fn config(mut self, config: ArchiveConfig) -> Self {
            self.config = config;
            self
        }

        /// Enable CDC chunking for large files
        pub fn enable_cdc(mut self, enable: bool) -> Self {
            self.enable_cdc = enable;
            self
        }

        /// Set custom CDC configuration
        pub fn chunker_config(mut self, config: ChunkerConfig) -> Self {
            self.chunker_config = Some(config);
            self.enable_cdc = true;
            self
        }

        /// Build the archive writer
        pub fn build(self) -> Result<GenericArchiveWriter<B::Writer>> {
            let archive_id = ArchiveId::new();
            let salt = Salt::generate();

            // Derive encryption key
            let password = self.password.unwrap_or_default();
            let kdf_params = KdfParams {
                memory_cost: self.config.encryption.kdf_memory_cost,
                time_cost: self.config.encryption.kdf_time_cost,
                parallelism: 4,
            };
            let key = derive_key(password.as_bytes(), &salt, &kdf_params)?;

            // Generate password verification tag
            let password_verification_tag = era_crypto::generate_password_verification_tag(&key);

            // Create volume writer
            let header = SuperHeader::with_kdf_params(
                archive_id,
                *salt.as_bytes(),
                password_verification_tag,
                self.config.encryption.kdf_memory_cost,
                self.config.encryption.kdf_time_cost,
                self.config.clone(),
            );
            let volume_writer =
                VolumeWriter::create(&self.backend, Path::new(&self.filename), header)?;

            // Create block builder
            let nonce_context = *salt.as_bytes();
            let compressor = Box::new(ZstdCompressor::new(self.config.compression.level));
            let block_builder = MacroBlockBuilder::new(key.clone(), nonce_context, compressor);

            // Configure file reader
            let file_reader = if self.enable_cdc {
                let chunker_config = self.chunker_config.unwrap_or_default();
                FileReader::with_cdc().with_chunker_config(chunker_config)
            } else {
                FileReader::new()
            };

            Ok(GenericArchiveWriter {
                archive_id,
                key,
                volume_writer,
                block_builder,
                catalog: Catalog::new(),
                chunk_locations: HashMap::new(),
                file_reader,
                enable_cdc: self.enable_cdc,
                pending_chunks: Vec::new(),
                pending_size: 0,
                target_block_size: 4 * 1024 * 1024,
            })
        }
    }

    /// Generic archive writer supporting any storage backend
    pub struct GenericArchiveWriter<W: StorageWriter> {
        archive_id: ArchiveId,
        #[allow(dead_code)]
        key: DerivedKey,
        volume_writer: VolumeWriter<W>,
        block_builder: MacroBlockBuilder,
        catalog: Catalog,
        chunk_locations: HashMap<ChunkHash, BlockLocation>,
        #[allow(dead_code)]
        file_reader: FileReader,
        #[allow(dead_code)]
        enable_cdc: bool,
        pending_chunks: Vec<UniqueChunk>,
        pending_size: usize,
        target_block_size: usize,
    }

    impl<W: StorageWriter> GenericArchiveWriter<W> {
        /// Get the archive ID
        pub fn archive_id(&self) -> ArchiveId {
            self.archive_id
        }

        /// Add a file from memory
        pub fn add_bytes(&mut self, name: &str, data: &[u8]) -> Result<()> {
            info!("Adding in-memory file: {} ({} bytes)", name, data.len());

            let hash = era_crypto::hash(data);

            if !self.chunk_locations.contains_key(&hash) {
                let chunk = UniqueChunk::new(Bytes::copy_from_slice(data), hash);
                self.add_to_pending(chunk)?;
            }

            let entry = FileEntry::file(PathBuf::from(name), data.len() as u64).with_hash(hash);
            self.catalog.add(entry);

            Ok(())
        }

        /// Add chunk to pending buffer and flush if full
        fn add_to_pending(&mut self, chunk: UniqueChunk) -> Result<()> {
            let chunk_size = chunk.data.len();
            let hash = chunk.hash;

            if chunk_size >= self.target_block_size {
                if !self.pending_chunks.is_empty() {
                    self.flush_pending()?;
                }
                let encrypted_block = self.block_builder.pack_single(chunk)?;
                let location = self.volume_writer.write_block(&encrypted_block)?;
                self.chunk_locations.insert(hash, location);
                return Ok(());
            }

            if self.pending_size + chunk_size > self.target_block_size {
                self.flush_pending()?;
            }

            self.pending_chunks.push(chunk);
            self.pending_size += chunk_size;

            Ok(())
        }

        /// Flush pending chunks to a single MacroBlock
        fn flush_pending(&mut self) -> Result<()> {
            if self.pending_chunks.is_empty() {
                return Ok(());
            }

            let chunks = std::mem::take(&mut self.pending_chunks);
            let hashes: Vec<_> = chunks.iter().map(|c| c.hash).collect();
            self.pending_size = 0;

            let encrypted_block = self.block_builder.pack_chunks(chunks)?;
            let location = self.volume_writer.write_block(&encrypted_block)?;

            for hash in hashes {
                self.chunk_locations.insert(hash, location);
            }

            Ok(())
        }

        /// Finalize the archive
        pub fn finalize(mut self) -> Result<ArchiveStats> {
            info!("Finalizing archive...");

            self.flush_pending()?;

            // Serialize and write catalog
            let catalog_bytes = self.catalog.to_bytes()?;
            let catalog_hash = era_crypto::hash(&catalog_bytes);
            let catalog_chunk = UniqueChunk::new(Bytes::from(catalog_bytes), catalog_hash);
            let catalog_block = self.block_builder.pack_single(catalog_chunk)?;
            let catalog_location = self.volume_writer.write_block(&catalog_block)?;

            // Finalize volume
            let _header = self.volume_writer.finalize_with_catalog(
                catalog_location.physical_offset,
                catalog_location.encrypted_size,
            )?;

            let stats = ArchiveStats {
                archive_id: self.archive_id,
                total_files: self.catalog.file_count,
                total_size: self.catalog.total_size,
                blocks_written: self.block_builder.blocks_created(),
            };

            info!(
                "Archive finalized: {} files, {} bytes, {} blocks",
                stats.total_files, stats.total_size, stats.blocks_written
            );

            Ok(stats)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use era_storage::MemoryStorageBackend;

        #[test]
        fn test_memory_backend_archive() {
            let backend = MemoryStorageBackend::new();

            let mut writer = GenericArchiveWriterBuilder::new(backend.clone(), "test.era")
                .password("test_password")
                .build()
                .unwrap();

            writer.add_bytes("hello.txt", b"Hello, Memory!").unwrap();
            writer.add_bytes("world.txt", b"World!").unwrap();

            let stats = writer.finalize().unwrap();
            assert_eq!(stats.total_files, 2);
            assert_eq!(stats.total_size, 20); // 14 + 6

            // Verify data was written to memory backend
            let paths = backend.list_paths().unwrap();
            assert_eq!(paths.len(), 1);
            assert!(paths[0].to_string_lossy().contains("test.era"));

            // Verify data is non-empty
            let data = backend.get_data(&paths[0]).unwrap().unwrap();
            assert!(!data.is_empty());
        }

        #[test]
        fn test_memory_backend_multiple_files_packed() {
            let backend = MemoryStorageBackend::new();

            let mut writer = GenericArchiveWriterBuilder::new(backend.clone(), "multi.era")
                .password("test_password")
                .build()
                .unwrap();

            // Add 10 small files
            for i in 0..10 {
                let name = format!("file_{}.txt", i);
                let content = format!("Content for file {}", i);
                writer.add_bytes(&name, content.as_bytes()).unwrap();
            }

            let stats = writer.finalize().unwrap();
            assert_eq!(stats.total_files, 10);
            // All 10 small files should fit in ~2 blocks (1 data + 1 catalog)
            assert!(
                stats.blocks_written <= 2,
                "Expected <=2 blocks, got {}",
                stats.blocks_written
            );
        }
    }
}
