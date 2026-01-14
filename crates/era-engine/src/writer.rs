//! Archive writer - creates ERA archives.
//!
//! ## Security (ERA v8.1)
//!
//! This writer implements the HKDF "Onion Model" key derivation:
//! - **Master Key (MK)**: Derived from password via Argon2id (expensive, done once)
//! - **Volume Key (VK)**: Derived from MK via HKDF (fast, per-volume)
//! - **Block Key (BK)**: Derived from VK via HKDF (fast, per-block)
//!
//! Each block is encrypted with a unique key, providing forward and backward security.

use bytes::Bytes;
use era_codec::{Compressor, NoCompressor, ZstdCompressor};
use era_common::{
    ArchiveConfig, ArchiveId, BlockLocation, ChunkHash, CompressionAlgorithm, ErasureBlockInfo,
    ErasureCodeConfig, MatrixBlockLocation, Result, UniqueChunk,
};
use era_crypto::{KdfParams, KeySession, Salt, VolumeKey};
use era_ingest::{Catalog, ChunkRef, ChunkerConfig, FileEntry, FileReader};
use era_packing::{SessionBlockBuilder, SessionErasureBlockBuilder};
use era_storage::LocalStorageBackend;
use era_volume::{SuperHeader, VolumePool, VolumePoolConfig, VolumeWriter};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// Number of storage volumes to distribute data across
    volume_count: usize,
    /// Enable true matrix distribution for erasure shards
    enable_matrix_distribution: bool,
    /// Maximum volume size for fixed-size splitting (bytes)
    max_volume_size: Option<u64>,
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
            volume_count: 1,
            enable_matrix_distribution: false,
            max_volume_size: None,
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

    /// Set the number of volumes to distribute data across
    ///
    /// This enables true distributed erasure coding where shards of the same block
    /// are stored on different volumes.
    pub fn volume_count(mut self, count: usize) -> Self {
        self.volume_count = count.max(1);
        self
    }

    /// Enable true matrix distribution for erasure shards.
    ///
    /// When enabled, each block's shards are distributed across volumes using
    /// a rotating offset pattern. This ensures that:
    /// - Consecutive blocks use different starting volumes
    /// - Loss of any `parity_shards` volumes still allows full recovery
    /// - Shards are evenly distributed across all volumes
    ///
    /// This also automatically enables erasure coding if not already enabled.
    pub fn enable_matrix_distribution(mut self, enable: bool) -> Self {
        self.enable_matrix_distribution = enable;
        if enable {
            self.enable_erasure = true;
        }
        self
    }

    /// Set maximum volume size for fixed-size splitting.
    ///
    /// When set, volumes will automatically split when reaching this size limit.
    /// Default is 4GB.
    pub fn max_volume_size(mut self, size: u64) -> Self {
        self.max_volume_size = Some(size);
        self
    }

    /// Build the archive writer
    pub fn build(self) -> Result<ArchiveWriter> {
        let archive_id = ArchiveId::new();
        let salt = Salt::generate();

        // Derive encryption key from password using Argon2id
        let password = self.password.unwrap_or_default();
        let kdf_params = KdfParams {
            memory_cost: self.config.encryption.kdf_memory_cost,
            time_cost: self.config.encryption.kdf_time_cost,
            parallelism: 4,
        };

        // Create KeySession - this derives the master key once
        let session = KeySession::new(password.as_bytes(), &salt, &kdf_params)?;

        // Derive volume key for the primary volume (volume 0)
        // In multi-volume scenarios, each volume gets its own key
        let volume_key = session.derive_volume_key(0);

        // Get password verification tag from session
        let password_verification_tag = session.password_verification_tag();

        // Create storage backend
        let output_dir = self.output_path.parent().unwrap_or(Path::new("."));
        let backend = LocalStorageBackend::new(output_dir);

        // Build config with erasure setting
        let mut config = self.config.clone();
        if self.enable_erasure {
            config.erasure = Some(self.erasure_config);
        }

        // Create volume writer with password verification tag
        let header = SuperHeader::with_kdf_params(
            archive_id,
            *salt.as_bytes(),
            password_verification_tag,
            config.encryption.kdf_memory_cost,
            config.encryption.kdf_time_cost,
            config.clone(),
        );
        let base_filename = self.output_path.file_name().unwrap_or_default();

        // Determine volume count based on erasure config if matrix distribution is enabled
        let volume_count = if self.enable_matrix_distribution && self.enable_erasure {
            let erasure = self.erasure_config;
            let total_shards = (erasure.data_shards + erasure.parity_shards) as usize;

            // For matrix distribution, recommend total_shards volumes for optimal fault tolerance
            // This allows tolerating up to parity_shards volume failures
            let recommended_volumes = total_shards;

            if self.volume_count <= 1 {
                // User didn't specify, use recommended optimal count
                info!(
                    "Matrix distribution: automatically using {} volumes \
                     for optimal fault tolerance (can tolerate {} volume failures)",
                    recommended_volumes, erasure.parity_shards
                );
                recommended_volumes
            } else if self.volume_count < recommended_volumes {
                // User specified fewer volumes than optimal
                let min_viable = (erasure.parity_shards as usize + 1).max(2);
                if self.volume_count >= min_viable {
                    warn!(
                        "Using {} volumes for matrix distribution. \
                         Note: will tolerate at most 1 volume failure \
                         (recommended: {} volumes for up to {} volume failures)",
                        self.volume_count, recommended_volumes, erasure.parity_shards
                    );
                    self.volume_count
                } else {
                    warn!(
                        "Insufficient volumes: {} specified, but {} minimum required \
                         for {},{} erasure. Adjusting to minimum.",
                        self.volume_count, min_viable, erasure.data_shards, erasure.parity_shards
                    );
                    min_viable
                }
            } else {
                // User specified at least recommended count
                info!(
                    "Using {} volumes for matrix distribution \
                     (will tolerate up to {} volume failures)",
                    self.volume_count, erasure.parity_shards
                );
                self.volume_count
            }
        } else {
            self.volume_count
        };

        // Create either VolumePool (for matrix distribution) or legacy volume_writers
        let (volume_writers, volume_pool) =
            if self.enable_matrix_distribution && self.enable_erasure {
                // Create VolumePool for matrix distribution
                let base_path = self
                    .output_path
                    .parent()
                    .map(|p| p.join(base_filename))
                    .unwrap_or_else(|| PathBuf::from(base_filename));

                let pool_config = VolumePoolConfig::new(&base_path, volume_count)
                    .for_erasure(self.erasure_config);

                let pool_config = if let Some(max_size) = self.max_volume_size {
                    pool_config.with_max_size(max_size)
                } else {
                    pool_config
                };

                let pool = VolumePool::create(&backend, pool_config, header.clone())?;

                info!(
                    "Created VolumePool with {} volumes for matrix distribution",
                    pool.volume_count()
                );

                (Vec::new(), Some(pool))
            } else {
                // Legacy mode: create individual volume writers
                let mut volume_writers = Vec::with_capacity(volume_count);
                for i in 0..volume_count {
                    let volume_path = if i == 0 {
                        PathBuf::from(base_filename)
                    } else {
                        let p = PathBuf::from(base_filename);
                        let mut file_name = p.as_os_str().to_os_string();
                        file_name.push(format!(".{:03}", i));
                        PathBuf::from(file_name)
                    };

                    let mut vol_header = header.clone();
                    vol_header.volume_sequence = i as u16;
                    vol_header.total_volumes = volume_count as u16;

                    let writer = VolumeWriter::create(&backend, &volume_path, vol_header)?;
                    volume_writers.push(writer);
                }
                (volume_writers, None)
            };

        // Store nonce context (salt) for block encryption
        let nonce_context = *salt.as_bytes();

        // Configure file reader with CDC if enabled
        let file_reader = if self.enable_cdc {
            let chunker_config = self.chunker_config.unwrap_or_default();
            FileReader::with_cdc().with_chunker_config(chunker_config)
        } else {
            FileReader::new()
        };

        // Set up checkpoint manager if enabled
        let checkpoint_manager = if self.enable_checkpoint {
            // Derive HMAC key from session for checkpoint integrity
            // Use HKDF to derive a separate key for checkpoints
            let checkpoint_vk = session.derive_volume_key(0xFFFF); // Reserved volume ID for checkpoint
            let mut hmac_key = [0u8; 32];
            hmac_key.copy_from_slice(checkpoint_vk.as_bytes());

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
                        return Err(era_common::EraError::CheckpointError(
                            "Checkpoint exists. Use Resume strategy to continue or StartFresh to discard."
                                .into(),
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

        Ok(ArchiveWriter {
            archive_id,
            output_path: self.output_path,
            session,
            volume_key,
            nonce_context,
            compression_config: self.config.compression.clone(),
            erasure_config: if self.enable_erasure {
                Some(self.erasure_config)
            } else {
                None
            },
            volume_writers,
            volume_pool,
            catalog: Catalog::new(),
            chunk_locations,
            matrix_locations: HashMap::new(),
            file_reader,
            enable_cdc: self.enable_cdc,
            pending_chunks: Vec::new(),
            pending_size: 0,
            target_block_size: 4 * 1024 * 1024, // 4MB
            checkpoint_manager,
            next_block_id: AtomicU64::new(0),
            enable_matrix_distribution: self.enable_matrix_distribution,
        })
    }
}

/// Writer for creating ERA archives
/// Archive writer - creates ERA archives with security-first design
///
/// ## Security Model (ERA v8.1)
///
/// This writer implements the HKDF "Onion Model" key derivation:
/// - **Master Key (MK)**: Derived from password via Argon2id (mlock-protected)
/// - **Volume Key (VK)**: Derived from MK via HKDF (per-volume isolation)
/// - **Block Key (BK)**: Derived from VK via HKDF (per-block forward secrecy)
///
/// Each block is encrypted with a unique key. Block keys are derived on-the-fly
/// and never stored in memory longer than necessary.
pub struct ArchiveWriter {
    archive_id: ArchiveId,
    /// Output path for the archive
    output_path: PathBuf,

    // Key Session (security-critical, mlock-protected)
    /// The KeySession holds the master key, protected by mlock
    session: KeySession,
    /// Pre-derived volume key for the primary volume (volume 0)
    volume_key: VolumeKey,
    /// Salt-based nonce context for AEAD operations (16 bytes from Salt)
    nonce_context: [u8; 16],

    // Configuration
    /// Compression settings
    compression_config: era_common::CompressionConfig,
    /// Erasure coding configuration (if enabled)
    erasure_config: Option<ErasureCodeConfig>,

    // Writers - use either legacy volume_writers or new volume_pool
    volume_writers: Vec<VolumeWriter<era_storage::LocalStorageWriter>>,
    /// Volume pool for matrix distribution (when enabled)
    volume_pool: Option<VolumePool<era_storage::LocalStorageWriter>>,

    // Catalog and deduplication
    catalog: Catalog,
    chunk_locations: HashMap<ChunkHash, BlockLocation>,
    /// Matrix block locations for erasure blocks (maps chunk hash to matrix location)
    /// Currently unused but reserved for future recovery features
    #[allow(dead_code)]
    matrix_locations: HashMap<ChunkHash, MatrixBlockLocation>,

    // File reading
    file_reader: FileReader,
    enable_cdc: bool,

    // Pending chunks waiting to be packed together
    pending_chunks: Vec<UniqueChunk>,
    pending_size: usize,
    /// Target block size for batching (default 4MB)
    target_block_size: usize,

    // Checkpoint for crash recovery
    checkpoint_manager: Option<CheckpointManager>,

    /// Block ID counter for per-block key derivation
    next_block_id: AtomicU64,

    /// Whether matrix distribution is enabled
    enable_matrix_distribution: bool,
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
            let physical_offset = location.physical_offset;

            // Record in checkpoint if enabled
            if let Some(ref mut mgr) = self.checkpoint_manager {
                mgr.record_chunk(hash, location.clone())?;
            }

            self.chunk_locations.insert(hash, location);

            debug!("Large chunk packed alone at offset {}", physical_offset);
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
            self.chunk_locations.insert(*hash, location.clone());
        }

        // Record in checkpoint if enabled
        if let Some(ref mut mgr) = self.checkpoint_manager {
            for hash in hashes {
                mgr.record_chunk(hash, location.clone())?;
            }
        }

        debug!(
            "Block with {} chunks written at offset {}",
            self.chunk_locations.len(),
            location.physical_offset
        );

        Ok(())
    }

    /// Create a fresh compressor based on configuration.
    ///
    /// This is called for each pack operation since compressors may have internal state.
    fn create_compressor(&self) -> Box<dyn Compressor> {
        match self.compression_config.algorithm {
            CompressionAlgorithm::None => Box::new(NoCompressor),
            CompressionAlgorithm::Zstd => {
                Box::new(ZstdCompressor::new(self.compression_config.level))
            }
            CompressionAlgorithm::LZ4 => {
                Box::new(era_codec::LZ4Compressor::new(self.compression_config.level))
            }
        }
    }

    /// Get the next block ID and increment the counter.
    fn next_block_id(&self) -> u64 {
        self.next_block_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Pack and write chunks, using erasure coding if enabled.
    ///
    /// ## Security
    ///
    /// Each block is encrypted with a unique per-block key derived via HKDF.
    /// This provides forward and backward security - compromising one block's
    /// key doesn't affect other blocks.
    fn pack_and_write_chunks(&mut self, chunks: Vec<UniqueChunk>) -> Result<BlockLocation> {
        if let Some(erasure_config) = self.erasure_config {
            // Use erasure coding with per-block key derivation
            let compressor = self.create_compressor();
            let block_id_start = self.next_block_id();
            let erasure_builder = SessionErasureBlockBuilder::new(
                &self.session,
                &self.volume_key,
                self.nonce_context,
                compressor,
                erasure_config,
            )?
            .with_starting_block_id(block_id_start);

            let sharded_block = erasure_builder.pack_chunks(chunks)?;

            // Check if we should use matrix distribution
            if self.enable_matrix_distribution {
                if let Some(ref mut pool) = self.volume_pool {
                    // Calculate required size per shard (approximately)
                    let shard_size = sharded_block
                        .shards
                        .first()
                        .map(|s| s.len() as u64)
                        .unwrap_or(0);
                    let per_shard_size = shard_size + era_common::ShardHeader::SIZE as u64 + 4;

                    // Expand pool if needed, with a safety limit
                    let max_volumes = 256; // Safety limit
                    while pool.needs_expansion(per_shard_size) {
                        if pool.volume_count() >= max_volumes {
                            return Err(era_common::EraError::Io(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!(
                                    "Reached maximum volume limit ({}) - shard size {} may exceed max volume size",
                                    max_volumes, per_shard_size
                                ),
                            )));
                        }
                        // Need to borrow backend from volume_writers
                        // Since we're using LocalStorageBackend, create a new one
                        let base_path = self
                            .output_path
                            .parent()
                            .unwrap_or(std::path::Path::new("."));
                        let backend = era_storage::LocalStorageBackend::new(base_path);
                        pool.add_volume(&backend)?;
                        debug!("Expanded volume pool to {} volumes", pool.volume_count());
                    }

                    // Use VolumePool for true matrix distribution
                    let matrix_location = pool.write_erasure_block(
                        sharded_block.block_id,
                        &sharded_block.shards,
                        sharded_block.original_len,
                        erasure_config,
                    )?;

                    let shard_size = sharded_block
                        .shards
                        .first()
                        .map(|s| s.len() as u32)
                        .unwrap_or(0);

                    // Convert MatrixBlockLocation to BlockLocation for compatibility
                    let first_shard = matrix_location.shards.first().ok_or_else(|| {
                        era_common::EraError::ErasureError(
                            "No shards in matrix location".to_string(),
                        )
                    })?;

                    // Build shard_offsets from matrix location (skip first shard)
                    let shard_offsets: Vec<u64> = matrix_location
                        .shards
                        .iter()
                        .skip(1)
                        .map(|s| s.physical_offset)
                        .collect();

                    // Store matrix location for potential recovery
                    // (The caller will handle storing this based on chunk hashes)

                    let location = BlockLocation {
                        volume_id: era_common::VolumeId::new(), // Placeholder, actual ID in matrix_location
                        slot_index: 0,
                        physical_offset: first_shard.physical_offset,
                        encrypted_size: shard_size,
                        erasure_info: Some(ErasureBlockInfo {
                            data_shards: erasure_config.data_shards,
                            parity_shards: erasure_config.parity_shards,
                            shard_size,
                            original_len: sharded_block.original_len,
                        }),
                        shard_offsets: Some(shard_offsets),
                        shard_volumes: Some(
                            matrix_location
                                .shards
                                .iter()
                                .map(|s| s.volume_sequence)
                                .collect(),
                        ),
                    };

                    debug!(
                        "Wrote erasure block with matrix distribution: {} shards across {} volumes",
                        matrix_location.shards.len(),
                        pool.volume_count()
                    );

                    return Ok(location);
                }
            }

            // Legacy erasure path: write shards to volume_writers
            let mut first_location = None;
            let shard_size = sharded_block
                .shards
                .first()
                .map(|s| s.len() as u32)
                .unwrap_or(0);

            // Write erasure block header (4 bytes original_len)
            // This allows the reader to know the exact original length for RS decoding
            let original_len_bytes = sharded_block.original_len.to_le_bytes();
            let mut header_offset = 0;
            // Offsets for shards 1..N (Shard 0 is at header_offset)
            let mut shard_offsets =
                Vec::with_capacity(sharded_block.shards.len().saturating_sub(1));

            let volume_count = self.volume_writers.len();

            for (idx, shard) in sharded_block.shards.iter().enumerate() {
                // Determine which volume to write this shard to
                let vol_idx = idx % volume_count;
                let writer = &mut self.volume_writers[vol_idx];

                // Write each shard with length + CRC header for integrity validation
                let crc = era_common::compute_shard_crc(shard);
                let shard_header = era_common::ShardHeader::new(shard.len() as u32, crc);

                // Write original_len header before the FIRST shard on EACH volume
                // This allows reading from any volume when some are missing
                if idx < volume_count {
                    // First shard for this volume - write the block header
                    let offset = writer.write_raw(&original_len_bytes)?;
                    if idx == 0 {
                        header_offset = offset;
                    }
                    writer.write_raw(&shard_header.to_bytes())?;
                    writer.write_raw(shard)?;
                    if idx > 0 {
                        shard_offsets.push(offset); // Record the header offset, not just shard offset
                    }
                } else {
                    let offset = writer.write_raw(&shard_header.to_bytes())?;
                    writer.write_raw(shard)?;
                    shard_offsets.push(offset);
                }
            }

            // Get Volume ID and Slot Index from the connection where Shard 0 was written
            let primary_writer_idx = 0; // Since we do idx % len, Shard 0 is always at 0
            let primary_writer = &self.volume_writers[primary_writer_idx];

            if first_location.is_none() {
                // Use the header offset as the block location
                first_location = Some(BlockLocation {
                    volume_id: primary_writer.volume_id(),
                    slot_index: primary_writer.block_count(),
                    physical_offset: header_offset, // Start at original_len header
                    encrypted_size: shard_size,
                    erasure_info: Some(ErasureBlockInfo {
                        data_shards: sharded_block.config.data_shards,
                        parity_shards: sharded_block.config.parity_shards,
                        shard_size,
                        original_len: sharded_block.original_len,
                    }),
                    shard_offsets: Some(shard_offsets),
                    shard_volumes: None, // Legacy path uses round-robin distribution
                });
            }

            Ok(first_location.expect("at least one shard"))
        } else {
            // Standard non-erasure path with per-block key derivation
            let compressor = self.create_compressor();
            let block_builder = SessionBlockBuilder::new(
                &self.session,
                &self.volume_key,
                self.nonce_context,
                compressor,
            )
            .with_starting_block_id(self.next_block_id());

            let encrypted_block = block_builder.pack_chunks(chunks)?;
            // Write standard blocks to primary volume (0)
            // In future versions, we could distribute these too
            self.volume_writers[0].write_block(&encrypted_block)
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

        // Serialize catalog
        let catalog_bytes = self.catalog.to_bytes()?;
        let catalog_hash = era_crypto::hash(&catalog_bytes);
        let catalog_chunk = UniqueChunk::new(Bytes::from(catalog_bytes), catalog_hash);

        // Create session-based builder for catalog encryption
        let compressor = self.create_compressor();
        let catalog_builder = SessionBlockBuilder::new(
            &self.session,
            &self.volume_key,
            self.nonce_context,
            compressor,
        )
        .with_starting_block_id(self.next_block_id());

        // Pack catalog ONCE to ensure same block_id (and thus same nonce) for all volumes
        // This is critical because the block_id is used to derive the encryption nonce
        let catalog_block = catalog_builder.pack_single(catalog_chunk.clone())?;
        let catalog_block_id = catalog_block.block_id.sequence() as u32;

        // Optionally create a backup block for erasure-coded archives
        let backup_block = if self.erasure_config.is_some() {
            // Create another builder for the backup block (will get next block_id)
            let compressor = self.create_compressor();
            let backup_builder = SessionBlockBuilder::new(
                &self.session,
                &self.volume_key,
                self.nonce_context,
                compressor,
            )
            .with_starting_block_id(self.next_block_id());
            Some(backup_builder.pack_single(catalog_chunk)?)
        } else {
            None
        };

        // Handle finalization based on whether we're using VolumePool or legacy writers
        if let Some(mut pool) = self.volume_pool.take() {
            // Matrix distribution mode: write catalog to each volume in the pool
            let volume_count = pool.volume_count();
            let mut catalog_locations: Vec<(u64, u32, u32)> = Vec::new();

            for slot in 0..volume_count {
                if let Some(writer) = pool.get_writer_mut(slot) {
                    let location = writer.write_block(&catalog_block)?;

                    if let Some(ref backup) = backup_block {
                        let _backup_location = writer.write_block(backup)?;
                        debug!(
                            "Volume {}: Catalog written with backup at offset {}",
                            slot, location.physical_offset
                        );
                    } else {
                        debug!(
                            "Volume {}: Catalog written at offset {}",
                            slot, location.physical_offset
                        );
                    }

                    catalog_locations.push((
                        location.physical_offset,
                        location.encrypted_size,
                        catalog_block_id,
                    ));
                }
            }

            debug!(
                "Catalog (block_id={}) written to {} volumes for full redundancy",
                catalog_block_id,
                catalog_locations.len()
            );

            // Finalize the pool
            let first_catalog = catalog_locations.first().cloned().unwrap_or((0, 0, 0));
            let pool_stats =
                pool.finalize_with_catalog(first_catalog.0, first_catalog.1, first_catalog.2)?;

            info!(
                "VolumePool finalized: {} volumes, {} total bytes, {} blocks",
                pool_stats.volume_count,
                pool_stats.total_bytes_written,
                pool_stats.total_blocks_written
            );
        } else {
            // Legacy mode: use volume_writers
            // Write catalog to EVERY volume so archive can be opened from any volume
            // This enables recovery even when some volumes (including the primary) are missing
            let mut catalog_locations: Vec<(u64, u32, u32)> = Vec::new();

            for (i, writer) in self.volume_writers.iter_mut().enumerate() {
                // Write the same catalog block to each volume
                let location = writer.write_block(&catalog_block)?;

                // Write backup copy for erasure-coded archives
                if let Some(ref backup) = backup_block {
                    let _backup_location = writer.write_block(backup)?;
                    debug!(
                        "Volume {}: Catalog written with backup at offset {}",
                        i, location.physical_offset
                    );
                } else {
                    debug!(
                        "Volume {}: Catalog written at offset {}",
                        i, location.physical_offset
                    );
                }

                catalog_locations.push((
                    location.physical_offset,
                    location.encrypted_size,
                    catalog_block_id,
                ));
            }

            debug!(
                "Catalog (block_id={}) written to {} volumes for full redundancy",
                catalog_block_id,
                catalog_locations.len()
            );

            // Finalize volumes with their respective catalog locations
            for (i, writer) in self.volume_writers.drain(..).enumerate() {
                let (offset, size, block_id) = catalog_locations[i];
                writer.finalize_with_catalog(offset, size, block_id)?;
            }
        }

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

        // Calculate total blocks written using our counter
        let blocks_written = self.next_block_id.load(Ordering::SeqCst);

        let stats = ArchiveStats {
            archive_id: self.archive_id,
            total_files: self.catalog.file_count,
            total_size: self.catalog.total_size,
            blocks_written,
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

            // Derive encryption key using KeySession for per-block key derivation
            let password = self.password.unwrap_or_default();
            let kdf_params = KdfParams {
                memory_cost: self.config.encryption.kdf_memory_cost,
                time_cost: self.config.encryption.kdf_time_cost,
                parallelism: 4,
            };

            // Create KeySession - this derives the master key once (mlock-protected)
            let session = KeySession::new(password.as_bytes(), &salt, &kdf_params)?;

            // Derive volume key for volume 0
            let volume_key = session.derive_volume_key(0);

            // Get password verification tag from session
            let password_verification_tag = session.password_verification_tag();

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

            // Store nonce context for block encryption
            let nonce_context = *salt.as_bytes();

            // Store compression config for creating compressors on demand
            let compression_config = self.config.compression.clone();

            // Configure file reader
            let file_reader = if self.enable_cdc {
                let chunker_config = self.chunker_config.unwrap_or_default();
                FileReader::with_cdc().with_chunker_config(chunker_config)
            } else {
                FileReader::new()
            };

            Ok(GenericArchiveWriter {
                archive_id,
                session,
                volume_key,
                nonce_context,
                compression_config,
                volume_writer,
                catalog: Catalog::new(),
                chunk_locations: HashMap::new(),
                file_reader,
                enable_cdc: self.enable_cdc,
                pending_chunks: Vec::new(),
                pending_size: 0,
                target_block_size: 4 * 1024 * 1024,
                next_block_id: AtomicU64::new(0),
            })
        }
    }

    /// Generic archive writer supporting any storage backend
    ///
    /// ## Security (ERA v8.1)
    ///
    /// This writer implements the HKDF "Onion Model" key derivation:
    /// - Each block is encrypted with a unique key derived via HKDF
    /// - Keys are stored in mlock-protected memory
    pub struct GenericArchiveWriter<W: StorageWriter> {
        archive_id: ArchiveId,
        /// Key session for deriving per-block keys (mlock-protected)
        session: KeySession,
        /// Pre-derived volume key for volume 0
        volume_key: VolumeKey,
        /// Salt-based nonce context for AEAD operations
        nonce_context: [u8; 16],
        /// Compression configuration
        compression_config: era_common::CompressionConfig,
        volume_writer: VolumeWriter<W>,
        catalog: Catalog,
        chunk_locations: HashMap<ChunkHash, BlockLocation>,
        #[allow(dead_code)]
        file_reader: FileReader,
        #[allow(dead_code)]
        enable_cdc: bool,
        pending_chunks: Vec<UniqueChunk>,
        pending_size: usize,
        target_block_size: usize,
        /// Block ID counter for per-block key derivation
        next_block_id: AtomicU64,
    }

    impl<W: StorageWriter> GenericArchiveWriter<W> {
        /// Get the archive ID
        pub fn archive_id(&self) -> ArchiveId {
            self.archive_id
        }

        /// Create a fresh compressor based on configuration.
        fn create_compressor(&self) -> Box<dyn Compressor> {
            match self.compression_config.algorithm {
                CompressionAlgorithm::None => Box::new(NoCompressor),
                CompressionAlgorithm::Zstd => {
                    Box::new(ZstdCompressor::new(self.compression_config.level))
                }
                CompressionAlgorithm::LZ4 => {
                    Box::new(era_codec::LZ4Compressor::new(self.compression_config.level))
                }
            }
        }

        /// Get the next block ID and increment the counter.
        fn next_block_id(&self) -> u64 {
            self.next_block_id.fetch_add(1, Ordering::SeqCst)
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
                // Create session-based builder for this block
                let compressor = self.create_compressor();
                let block_builder = SessionBlockBuilder::new(
                    &self.session,
                    &self.volume_key,
                    self.nonce_context,
                    compressor,
                )
                .with_starting_block_id(self.next_block_id());

                let encrypted_block = block_builder.pack_single(chunk)?;
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

            // Create session-based builder for this block
            let compressor = self.create_compressor();
            let block_builder = SessionBlockBuilder::new(
                &self.session,
                &self.volume_key,
                self.nonce_context,
                compressor,
            )
            .with_starting_block_id(self.next_block_id());

            let encrypted_block = block_builder.pack_chunks(chunks)?;
            let location = self.volume_writer.write_block(&encrypted_block)?;

            for hash in hashes {
                self.chunk_locations.insert(hash, location.clone());
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

            // Create session-based builder for catalog encryption
            let compressor = self.create_compressor();
            let catalog_builder = SessionBlockBuilder::new(
                &self.session,
                &self.volume_key,
                self.nonce_context,
                compressor,
            )
            .with_starting_block_id(self.next_block_id());

            let catalog_block = catalog_builder.pack_single(catalog_chunk)?;
            let catalog_block_id = catalog_block.block_id.sequence() as u32;
            let catalog_location = self.volume_writer.write_block(&catalog_block)?;

            // Finalize volume
            let _header = self.volume_writer.finalize_with_catalog(
                catalog_location.physical_offset,
                catalog_location.encrypted_size,
                catalog_block_id,
            )?;

            let blocks_written = self.next_block_id.load(Ordering::SeqCst);

            let stats = ArchiveStats {
                archive_id: self.archive_id,
                total_files: self.catalog.file_count,
                total_size: self.catalog.total_size,
                blocks_written,
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
