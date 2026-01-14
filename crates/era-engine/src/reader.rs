//! Archive reader - extracts files from ERA archives.
//!
//! ## Security (ERA v8.1)
//!
//! This reader implements the HKDF "Onion Model" key derivation:
//! - **Master Key (MK)**: Derived from password via Argon2id (mlock-protected)
//! - **Volume Key (VK)**: Derived from MK via HKDF (per-volume isolation)
//! - **Block Key (BK)**: Derived from VK via HKDF (per-block forward secrecy)
//!
//! Each block is decrypted with a unique key derived on-the-fly.

use crate::block_iter::{BlockIterator, SessionBlockIterator, SessionErasureBlockIterator};
pub use crate::chunk_processor::{ExtractStats, VerifyStats};
use crate::chunk_processor::{ExtractionContext, MultiChunkState, VerificationContext};
use bytes::Bytes;
use era_codec::ZstdCompressor;
use era_common::{BlockId, BlockLocation, ChunkVec, EraError, Result};
use era_crypto::{KdfParams, KeySession, Salt, VolumeKey};
use era_ingest::{Catalog, FileEntry};
use era_packing::{SessionBlockUnpacker, SessionErasureBlockUnpacker};
use era_storage::LocalStorageBackend;
use era_volume::{SuperHeader, VolumeReader};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Maximum allowed file size declared in catalog (100 GB) - sanity check
const MAX_DECLARED_FILE_SIZE: u64 = 100 * 1024 * 1024 * 1024;

/// Options for extraction
#[derive(Debug, Clone, Default)]
pub struct ExtractOptions {
    /// Output directory
    pub output_dir: PathBuf,
    /// Overwrite existing files
    pub overwrite: bool,
}

impl ExtractOptions {
    /// Create new options with the given output directory
    pub fn new(output_dir: impl Into<PathBuf>) -> Self {
        Self {
            output_dir: output_dir.into(),
            overwrite: false,
        }
    }

    /// Set whether to overwrite existing files
    pub fn overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite = overwrite;
        self
    }
}

/// Reader for ERA archives
///
/// ## Security (ERA v8.1)
///
/// This reader stores the KeySession and VolumeKey in mlock-protected memory.
/// Each block is decrypted with a unique per-block key derived on-the-fly via HKDF.
pub struct ArchiveReader {
    volume_readers: Vec<VolumeReader<era_storage::LocalStorageReader>>,
    /// Indices of each volume in the original multi-volume sequence
    /// e.g., [0, 2] means we have volume 0 and volume 2 (volume 1 is missing)
    volume_indices: Vec<usize>,
    /// Key session for per-block key derivation (mlock-protected)
    session: KeySession,
    /// Pre-derived volume key for volume 0
    volume_key: VolumeKey,
    /// Nonce context (archive salt)
    nonce_context: [u8; 16],
    /// Compression configuration
    compression_level: i32,
    /// Compression algorithm type
    compression_algorithm: era_common::CompressionAlgorithm,
    catalog: Option<Catalog>,
}

impl ArchiveReader {
    /// Open an archive for reading
    ///
    /// This function can open an archive starting from any available volume.
    /// It uses the volume header's `volume_sequence` and `total_volumes` fields
    /// to determine the complete volume set and handle missing volumes.
    ///
    /// This function verifies the password early using the stored verification tag,
    /// providing clear error messages for incorrect passwords.
    pub fn open(path: &Path, password: &str) -> Result<Self> {
        info!("Opening archive: {}", path.display());

        let parent_dir = path.parent().unwrap_or(Path::new("."));
        let backend = LocalStorageBackend::new(parent_dir);
        let base_filename = path.file_name().unwrap_or_default();

        // 1. Try to open the specified file first (could be any volume)
        let first_reader = VolumeReader::open(&backend, Path::new(base_filename))?;

        // Read volume metadata from header (copy values before moving reader)
        let first_vol_sequence = first_reader.header().volume_sequence as usize;
        let total_volumes = first_reader.header().total_volumes as usize;
        let erasure_config = first_reader.header().config.erasure;
        let first_archive_id = first_reader.header().archive_id;

        // 2. Determine scan tolerance based on erasure configuration
        let scan_tolerance = if let Some(config) = erasure_config {
            (config.parity_shards as usize + 1).max(2)
        } else {
            2
        };

        // 3. Determine how many volumes to scan for
        // If total_volumes is known, use it; otherwise scan up to MAX_SCAN
        const MAX_SCAN: usize = 32;
        let scan_limit = if total_volumes > 0 {
            total_volumes
        } else {
            MAX_SCAN
        };

        // 4. Build the base path for volume 0 (strip any .NNN suffix)
        let base_str = base_filename.to_string_lossy();
        let base_path = if base_str.ends_with(".era") {
            PathBuf::from(base_filename)
        } else {
            // Handle case where user opened .era.001 etc
            // Strip the .NNN suffix to get base .era path
            let s = base_str.to_string();
            if let Some(idx) = s.rfind(".era.") {
                PathBuf::from(&s[..idx + 4]) // Keep up to ".era"
            } else {
                PathBuf::from(base_filename)
            }
        };

        // 5. Scan for all available volumes
        // Store the first reader in Option to handle ownership
        let mut found_readers: Vec<(usize, VolumeReader<era_storage::LocalStorageReader>)> =
            Vec::new();
        let mut missing_count = 0;
        let mut first_reader_opt = Some(first_reader);

        for i in 0..scan_limit {
            let volume_path = if i == 0 {
                base_path.clone()
            } else {
                let mut p = base_path.as_os_str().to_os_string();
                p.push(format!(".{:03}", i));
                PathBuf::from(p)
            };

            let full_path = parent_dir.join(&volume_path);

            // Check if this corresponds to the file we already opened
            if i == first_vol_sequence {
                if let Some(reader) = first_reader_opt.take() {
                    found_readers.push((first_vol_sequence, reader));
                    missing_count = 0;
                }
                continue;
            }

            if !full_path.exists() {
                missing_count += 1;
                if total_volumes > 0 {
                    // We know the exact count, continue until we've checked all
                    continue;
                } else if missing_count >= scan_tolerance {
                    break;
                }
                continue;
            }

            missing_count = 0;

            match VolumeReader::open(&backend, &volume_path) {
                Ok(reader) => {
                    // Verify it's part of the same archive
                    if reader.header().archive_id == first_archive_id {
                        // Use the volume_sequence from header, not filename index
                        let vol_seq = reader.header().volume_sequence as usize;
                        found_readers.push((vol_seq, reader));
                    } else {
                        tracing::warn!(
                            "Volume {} has different archive_id, skipping",
                            volume_path.display()
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to open volume {}: {}", volume_path.display(), e);
                }
            }
        }

        // If first_reader wasn't used (e.g., its sequence wasn't in scan range), add it now
        if let Some(reader) = first_reader_opt {
            found_readers.push((first_vol_sequence, reader));
        }

        // 6. Sort by volume sequence and build final structures
        found_readers.sort_by_key(|(seq, _)| *seq);

        let volume_indices: Vec<usize> = found_readers.iter().map(|(seq, _)| *seq).collect();
        let volume_readers: Vec<VolumeReader<era_storage::LocalStorageReader>> =
            found_readers.into_iter().map(|(_, r)| r).collect();

        if volume_readers.is_empty() {
            return Err(EraError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No valid volumes found",
            )));
        }

        // Log discovered volumes
        info!(
            "Opened {} volumes at sequences {:?} (total expected: {}, scan tolerance: {})",
            volume_readers.len(),
            volume_indices,
            if total_volumes > 0 {
                total_volumes.to_string()
            } else {
                "unknown".to_string()
            },
            scan_tolerance
        );

        // Use first available reader for key derivation (all volumes share same crypto params)
        let volume_reader = &volume_readers[0];
        let header = volume_reader.header();
        let salt = Salt::from_bytes(header.crypto_anchor.salt);
        let kdf_params = KdfParams {
            memory_cost: header.crypto_anchor.kdf_memory_cost,
            time_cost: header.crypto_anchor.kdf_time_cost,
            parallelism: header.crypto_anchor.kdf_parallelism,
        };

        // Create KeySession for per-block key derivation (mlock-protected)
        let session = KeySession::new(password.as_bytes(), &salt, &kdf_params)?;

        // Verify password using stored verification tag
        if !session.verify_password(&header.crypto_anchor.password_verification_tag) {
            return Err(EraError::InvalidKey("Incorrect password".to_string()));
        }

        // Derive volume key for volume 0
        let volume_key = session.derive_volume_key(0);

        // Store nonce context and compression config for creating temporary unpackers
        let nonce_context = header.crypto_anchor.salt;
        let compression_level = header.config.compression.level;
        let compression_algorithm = header.config.compression.algorithm;

        Ok(Self {
            volume_readers,
            volume_indices,
            session,
            volume_key,
            nonce_context,
            compression_level,
            compression_algorithm,
            catalog: None,
        })
    }

    /// Open an archive using a pre-derived key session
    ///
    /// This is more efficient than `open()` when opening multiple archives
    /// with the same password, as it avoids repeated Argon2id derivation.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to any volume file of the archive
    /// * `session` - A pre-created KeySession containing the derived key
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Create session once (expensive)
    /// let session = KeySession::new(password.as_bytes(), &salt, &params)?;
    ///
    /// // Open multiple archives quickly
    /// let reader1 = ArchiveReader::open_with_session(&path1, &session)?;
    /// let reader2 = ArchiveReader::open_with_session(&path2, &session)?;
    /// ```
    ///
    /// Note: The session is cloned internally to ensure the reader owns its key material.
    pub fn open_with_session(path: &Path, session: &KeySession) -> Result<Self> {
        info!("Opening archive with key session: {}", path.display());

        let parent_dir = path.parent().unwrap_or(Path::new("."));
        let backend = LocalStorageBackend::new(parent_dir);
        let base_filename = path.file_name().unwrap_or_default();

        // 1. Try to open the specified file first (could be any volume)
        let first_reader = VolumeReader::open(&backend, Path::new(base_filename))?;

        // Read volume metadata from header
        let first_vol_sequence = first_reader.header().volume_sequence as usize;
        let total_volumes = first_reader.header().total_volumes as usize;
        let erasure_config = first_reader.header().config.erasure;
        let first_archive_id = first_reader.header().archive_id;

        // 2. Determine scan tolerance
        let scan_tolerance = if let Some(config) = erasure_config {
            (config.parity_shards as usize + 1).max(2)
        } else {
            2
        };

        // 3. Scan for volumes
        let max_scan = if total_volumes > 0 {
            total_volumes + scan_tolerance
        } else {
            100
        };

        let mut volume_readers = vec![first_reader];
        let mut volume_indices = vec![first_vol_sequence];

        for i in 0..max_scan {
            if i == first_vol_sequence {
                continue;
            }

            let vol_path = if i == 0 {
                PathBuf::from(base_filename)
            } else {
                let base = PathBuf::from(base_filename);
                let mut name = base.as_os_str().to_os_string();
                // Remove existing extension if present
                let base_str = name.to_string_lossy();
                let clean_base = if let Some(pos) = base_str.rfind(".era") {
                    base_str[..pos + 4].to_string()
                } else {
                    base_str.to_string()
                };
                name = std::ffi::OsString::from(format!("{}.{:03}", clean_base, i));
                PathBuf::from(name)
            };

            match VolumeReader::open(&backend, &vol_path) {
                Ok(reader) => {
                    if reader.header().archive_id == first_archive_id {
                        let seq = reader.header().volume_sequence as usize;
                        let insert_pos = volume_indices
                            .iter()
                            .position(|&idx| idx > seq)
                            .unwrap_or(volume_indices.len());
                        volume_indices.insert(insert_pos, seq);
                        volume_readers.insert(insert_pos, reader);
                    }
                }
                Err(_) => continue,
            }
        }

        // 4. Verify password using session's verification method
        let volume_reader = &volume_readers[0];
        let header = volume_reader.header();

        if !session.verify_password(&header.crypto_anchor.password_verification_tag) {
            return Err(EraError::InvalidKey("Incorrect password".to_string()));
        }

        // 5. Clone session and derive volume key
        let owned_session = session.clone();
        let volume_key = owned_session.derive_volume_key(0);

        // Store nonce context and compression config
        let nonce_context = header.crypto_anchor.salt;
        let compression_level = header.config.compression.level;
        let compression_algorithm = header.config.compression.algorithm;

        Ok(Self {
            volume_readers,
            volume_indices,
            session: owned_session,
            volume_key,
            nonce_context,
            compression_level,
            compression_algorithm,
            catalog: None,
        })
    }

    /// Create a fresh compressor based on configuration.
    fn create_compressor(&self) -> Box<dyn era_codec::Compressor> {
        match self.compression_algorithm {
            era_common::CompressionAlgorithm::None => Box::new(era_codec::NoCompressor),
            era_common::CompressionAlgorithm::Zstd => {
                Box::new(ZstdCompressor::new(self.compression_level))
            }
            era_common::CompressionAlgorithm::LZ4 => {
                Box::new(era_codec::LZ4Compressor::new(self.compression_level))
            }
        }
    }

    /// Create a temporary session-based block unpacker.
    ///
    /// The returned unpacker borrows the session and volume_key, so its lifetime
    /// is tied to the reader.
    fn create_unpacker(&self) -> SessionBlockUnpacker<'_> {
        let compressor = self.create_compressor();
        SessionBlockUnpacker::new(
            &self.session,
            &self.volume_key,
            self.nonce_context,
            compressor,
        )
    }

    /// Create a temporary session-based erasure unpacker.
    fn create_erasure_unpacker(&self) -> SessionErasureBlockUnpacker<'_> {
        let compressor = self.create_compressor();
        SessionErasureBlockUnpacker::new(
            &self.session,
            &self.volume_key,
            self.nonce_context,
            compressor,
        )
    }

    /// Get the archive header
    pub fn header(&self) -> &SuperHeader {
        self.volume_readers[0].header()
    }

    /// Load the catalog from any available volume
    /// Each volume contains a copy of the catalog, enabling recovery from any volume
    pub fn load_catalog(&mut self) -> Result<&Catalog> {
        if self.catalog.is_some() {
            return Ok(self.catalog.as_ref().unwrap());
        }

        // Find the first volume that has a valid catalog
        let mut catalog_reader_idx = None;
        for (i, reader) in self.volume_readers.iter().enumerate() {
            let footer = reader.footer();
            if footer.has_catalog_location() && reader.block_count() > 0 {
                catalog_reader_idx = Some(i);
                debug!(
                    "Found catalog in volume {} (sequence {})",
                    i,
                    reader.header().volume_sequence
                );
                break;
            }
        }

        let reader_idx = catalog_reader_idx.ok_or_else(|| {
            debug!("No volume with valid catalog found");
            EraError::EmptyArchive
        })?;

        let reader = &self.volume_readers[reader_idx];
        let footer = reader.footer();

        let catalog_location = BlockLocation {
            volume_id: reader.header().volume_id,
            slot_index: footer.catalog_block_id,
            physical_offset: footer.catalog_offset,
            encrypted_size: footer.catalog_size,
            erasure_info: None,
            shard_offsets: None,
            shard_volumes: None,
        };

        debug!(
            "Loading catalog from volume {} at offset={}, size={}, block_id={}",
            reader_idx, footer.catalog_offset, footer.catalog_size, footer.catalog_block_id
        );

        let encrypted_block = self.volume_readers[reader_idx].read_block(&catalog_location)?;

        // Create temporary session-based unpacker for decryption
        let unpacker = self.create_unpacker();
        let chunks = unpacker.unpack(&encrypted_block)?;

        // Extract chunk data from unpacked block
        if chunks.index.entries.is_empty() {
            return Err(EraError::EmptyCatalog);
        }

        let first_entry = &chunks.index.entries[0];
        let start = first_entry.offset as usize;
        let end = start + first_entry.length as usize;
        if end > chunks.data.len() {
            return Err(EraError::decompression(
                "Catalog chunk offset exceeds data size",
            ));
        }
        let catalog_data = chunks.data.slice(start..end);
        let catalog = Catalog::from_bytes(&catalog_data)?;

        info!(
            "Loaded catalog: {} files, {} bytes total",
            catalog.file_count, catalog.total_size
        );

        self.catalog = Some(catalog);
        Ok(self.catalog.as_ref().unwrap())
    }

    /// Read a block and extract all chunks, handling both erasure and non-erasure blocks
    ///
    /// This is the unified entry point for reading blocks. It automatically detects
    /// whether the block is erasure-coded based on `location.erasure_info` and uses
    /// the appropriate unpacker.
    pub fn read_and_extract_chunks(&self, location: &BlockLocation) -> Result<ChunkVec> {
        if let Some(ref erasure_info) = location.erasure_info {
            // Erasure-coded block: read shards from multiple volumes
            let num_readers = self.volume_readers.len();
            let total_shards =
                erasure_info.data_shards as usize + erasure_info.parity_shards as usize;

            let mut available_shards = Vec::with_capacity(total_shards);

            // Check shard offsets
            let shard_offsets = location.shard_offsets.as_ref().ok_or_else(|| {
                EraError::IntegrityError("Missing shard offsets for erasure block".into())
            })?;

            // Determine volume index for each shard
            // Matrix distribution: use shard_volumes if available
            // Legacy distribution: use shard_idx % num_readers
            let get_volume_idx = |shard_idx: usize| -> usize {
                if let Some(ref volumes) = location.shard_volumes {
                    // Matrix distribution: use stored volume sequence
                    if shard_idx < volumes.len() {
                        (volumes[shard_idx] as usize) % num_readers
                    } else {
                        // Fallback for safety
                        shard_idx % num_readers
                    }
                } else {
                    // Legacy round-robin distribution
                    shard_idx % num_readers
                }
            };

            // Read Shard 0 (Header + Data)
            // Note: physical_offset points to 4-byte original_len header
            let vol_idx_0 = get_volume_idx(0);
            if vol_idx_0 < num_readers {
                if let Ok(shard) = self.read_shard(
                    &self.volume_readers[vol_idx_0],
                    location.physical_offset + 4,
                ) {
                    available_shards.push((0, shard));
                }
            }

            // Read other shards (1..N)
            for (i, &offset) in shard_offsets.iter().enumerate() {
                let shard_idx = i + 1;
                let vol_idx = get_volume_idx(shard_idx);
                if vol_idx < num_readers {
                    if let Ok(shard) = self.read_shard(&self.volume_readers[vol_idx], offset) {
                        available_shards.push((shard_idx, shard));
                    }
                }
            }

            let block_id = BlockId::new(location.slot_index as u64);
            // Create temporary session-based erasure unpacker
            let erasure_unpacker = self.create_erasure_unpacker();
            erasure_unpacker.decode_and_extract_all(available_shards, erasure_info, block_id)
        } else {
            // Standard block: read and unpack directly with session-based unpacker
            let encrypted_block = self.volume_readers[0].read_block(location)?;
            let unpacker = self.create_unpacker();
            let unpacked = unpacker.unpack(&encrypted_block)?;

            // Extract all chunks from unpacked data using ChunkVec for stack allocation
            let mut chunks = ChunkVec::new();
            for entry in &unpacked.index.entries {
                let start = entry.offset as usize;
                let end = start + entry.length as usize;
                if end > unpacked.data.len() {
                    return Err(EraError::decompression("Chunk offset exceeds data size"));
                }
                chunks.push((entry.hash, unpacked.data.slice(start..end)));
            }
            Ok(chunks)
        }
    }

    fn read_shard<R: era_storage::StorageReader>(
        &self,
        reader: &VolumeReader<R>,
        offset: u64,
    ) -> Result<Bytes> {
        let header_bytes = reader.read_raw(offset, era_common::ShardHeader::SIZE)?;
        if let Some(header) = era_common::ShardHeader::from_bytes(&header_bytes) {
            let data = reader.read_raw(
                offset + era_common::ShardHeader::SIZE as u64,
                header.length as usize,
            )?;
            if header.verify(&data) {
                return Ok(data);
            }
        }
        Err(EraError::IntegrityError("Shard verification failed".into()))
    }

    /// List all files in the archive
    pub fn list_files(&mut self) -> Result<Vec<&FileEntry>> {
        let catalog = self.load_catalog()?;
        Ok(catalog.entries.iter().collect())
    }

    /// Extract using the provided block iterator
    fn extract_with_iterator(
        catalog: &Catalog,
        iter: &mut Box<dyn BlockIterator + '_>,
        options: &ExtractOptions,
    ) -> Result<ExtractStats> {
        let mut stats = ExtractStats::default();

        // Build maps for extraction
        let mut context = ExtractionContext::new();

        for (file_idx, entry) in catalog.entries.iter().enumerate() {
            let output_path = options.output_dir.join(&entry.path);

            if output_path.exists() && !options.overwrite {
                debug!("Skipping existing file: {}", output_path.display());
                stats.skipped += 1;
                continue;
            }

            if entry.size > MAX_DECLARED_FILE_SIZE {
                return Err(EraError::CorruptedHeader(format!(
                    "File '{}' declares unreasonable size: {} bytes",
                    entry.path.display(),
                    entry.size
                )));
            }

            if entry.is_chunked() {
                let chunk_count = entry.chunks.len();
                if let Some(parent) = output_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let file = File::create(&output_path)?;
                file.set_len(entry.size)?;

                context.multi_chunk_files.insert(
                    file_idx,
                    MultiChunkState {
                        file,
                        output_path,
                        expected_size: entry.size,
                        chunks_written: vec![false; chunk_count],
                        total_chunks: chunk_count,
                        written_count: 0,
                    },
                );

                for (chunk_idx, chunk_ref) in entry.chunks.iter().enumerate() {
                    context
                        .chunk_to_files
                        .entry(chunk_ref.hash)
                        .or_default()
                        .push((file_idx, chunk_idx, chunk_ref.offset));
                }
            } else if let Some(content_hash) = entry.content_hash {
                context
                    .single_chunk_pending
                    .entry(content_hash)
                    .or_default()
                    .push((file_idx, output_path));
            }
        }

        if !context.has_pending() {
            info!("No files to extract");
            return Ok(stats);
        }

        while let Some(result) = iter.next_block() {
            match result {
                Ok(decoded) => {
                    context.process_chunks(decoded.chunks, &mut stats)?;
                }
                Err(e) => {
                    return Err(e);
                }
            }
            if !context.has_pending() {
                break;
            }
        }

        context.log_incomplete_files();

        info!(
            "Extraction complete: {} files, {} bytes",
            stats.extracted, stats.bytes_written
        );

        Ok(stats)
    }

    /// Verify using the provided block iterator
    fn verify_with_iterator(
        catalog: &Catalog,
        iter: &mut Box<dyn BlockIterator + '_>,
    ) -> Result<VerifyStats> {
        let mut stats = VerifyStats::default();

        let mut context = VerificationContext::new(catalog.entries.len());

        for (file_idx, entry) in catalog.entries.iter().enumerate() {
            if entry.is_chunked() {
                context.file_chunk_counts.push(entry.chunks.len());
                for (chunk_idx, chunk_ref) in entry.chunks.iter().enumerate() {
                    context
                        .expected_chunks
                        .entry(chunk_ref.hash)
                        .or_default()
                        .push((file_idx, chunk_idx, chunk_ref.length as u64));
                }
            } else if let Some(content_hash) = entry.content_hash {
                context.file_chunk_counts.push(1);
                context
                    .expected_chunks
                    .entry(content_hash)
                    .or_default()
                    .push((file_idx, 0, entry.size));
            } else {
                context.file_chunk_counts.push(0);
            }
        }

        while let Some(result) = iter.next_block() {
            match result {
                Ok(decoded) => {
                    stats.blocks_verified += 1;
                    if decoded.corrupted_shards > 0 {
                        stats.errors.push(format!(
                            "Block {}: recovered from {} corrupted shards",
                            decoded.block_index, decoded.corrupted_shards
                        ));
                    }
                    context.process_chunks(&decoded.chunks, decoded.block_index, &mut stats);
                }
                Err(e) => {
                    stats.blocks_failed += 1;
                    stats.errors.push(format!("Block logic error: {}", e));
                }
            }
        }

        context.check_file_completeness(&mut stats, |idx| {
            catalog
                .entries
                .get(idx)
                .map(|e| e.path.display().to_string())
                .unwrap_or_default()
        });

        if stats.is_ok() {
            info!(
                "Verification passed: {} blocks, {} files, {} bytes",
                stats.blocks_verified, stats.files_verified, stats.bytes_verified
            );
        } else {
            info!(
                "Verification FAILED: {} block errors, {} incomplete files, {} total errors",
                stats.blocks_failed,
                stats.files_incomplete,
                stats.errors.len()
            );
        }

        Ok(stats)
    }

    /// Extract all files to the given directory
    ///
    /// This optimized implementation uses single-pass extraction:
    /// - Reads and decrypts each block only once
    /// - Builds hash→path mapping from catalog
    /// - Writes files directly during block scan
    /// - Supports multi-chunk files (CDC mode) with pre-created files to avoid OOM
    /// - Supports erasure-coded archives (reads shard groups and decodes)
    ///
    /// ## Security
    ///
    /// Each block is decrypted with a unique per-block key derived via HKDF.
    pub fn extract_all(&mut self, options: &ExtractOptions) -> Result<ExtractStats> {
        info!("Extracting to: {}", options.output_dir.display());

        self.load_catalog()?;
        let catalog = self.catalog.as_ref().unwrap();

        // Check if erasure coding is enabled
        let erasure_config = self.volume_readers[0].header().config.erasure;

        // Create session-based iterators with per-block key derivation
        let mut iter: Box<dyn BlockIterator> = if let Some(config) = erasure_config {
            Box::new(SessionErasureBlockIterator::new(
                &self.volume_readers,
                &self.volume_indices,
                &self.session,
                &self.volume_key,
                self.nonce_context,
                self.create_compressor(),
                config.data_shards,
                config.parity_shards,
            ))
        } else {
            Box::new(SessionBlockIterator::new(
                &self.volume_readers[0],
                &self.session,
                &self.volume_key,
                self.nonce_context,
                self.create_compressor(),
            ))
        };

        Self::extract_with_iterator(catalog, &mut iter, options)
    }

    /// Verify the integrity of the archive
    ///
    /// This method performs a comprehensive verification:
    /// - Reads and decrypts all blocks (validates AEAD authentication)
    /// - Verifies chunk hashes match their declared content
    /// - Checks that all files have their required chunks present
    /// - Reports any corrupted or missing data
    ///
    /// ## Security
    ///
    /// Each block is decrypted with a unique per-block key derived via HKDF.
    pub fn verify(&mut self) -> Result<VerifyStats> {
        info!("Verifying archive integrity...");

        self.load_catalog()?;
        let catalog = self.catalog.as_ref().unwrap();

        // Check if erasure coding is enabled
        let erasure_config = self.volume_readers[0].header().config.erasure;

        // Create session-based iterators with per-block key derivation
        let mut iter: Box<dyn BlockIterator> = if let Some(config) = erasure_config {
            Box::new(SessionErasureBlockIterator::new(
                &self.volume_readers,
                &self.volume_indices,
                &self.session,
                &self.volume_key,
                self.nonce_context,
                self.create_compressor(),
                config.data_shards,
                config.parity_shards,
            ))
        } else {
            Box::new(SessionBlockIterator::new(
                &self.volume_readers[0],
                &self.session,
                &self.volume_key,
                self.nonce_context,
                self.create_compressor(),
            ))
        };

        Self::verify_with_iterator(catalog, &mut iter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ArchiveWriter;
    use tempfile::TempDir;

    #[test]
    fn test_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.era");
        let password = "test_password";

        // Create archive
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .build()
            .unwrap();

        writer.add_bytes("hello.txt", b"Hello, World!").unwrap();
        writer.add_bytes("data.bin", &[1, 2, 3, 4, 5]).unwrap();
        writer.finalize().unwrap();

        // Read archive
        let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
        let files = reader.list_files().unwrap();
        assert_eq!(files.len(), 2);

        // Extract
        let extract_dir = temp_dir.path().join("extracted");
        let options = ExtractOptions::new(&extract_dir);
        let stats = reader.extract_all(&options).unwrap();

        assert_eq!(stats.extracted, 2);
        assert_eq!(stats.bytes_written, 18); // 13 + 5

        // Verify extracted files
        let hello_content = fs::read_to_string(extract_dir.join("hello.txt")).unwrap();
        assert_eq!(hello_content, "Hello, World!");

        let data_content = fs::read(extract_dir.join("data.bin")).unwrap();
        assert_eq!(data_content, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_wrong_password_fails() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("secure.era");

        // Create archive with password
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("correct_password")
            .build()
            .unwrap();

        writer.add_bytes("secret.txt", b"Secret data").unwrap();
        writer.finalize().unwrap();

        // Try to open with wrong password
        let result = ArchiveReader::open(&archive_path, "wrong_password");
        assert!(result.is_err(), "Wrong password should fail");
    }

    #[test]
    fn test_empty_archive_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("empty.era");
        let password = "test";

        // Create empty archive
        let writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .build()
            .unwrap();
        writer.finalize().unwrap();

        // Read empty archive
        let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
        let files = reader.list_files().unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn test_large_file_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("large.era");
        let password = "test";

        // Create archive with large file
        let large_data = vec![b'X'; 512 * 1024]; // 512KB
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .build()
            .unwrap();
        writer.add_bytes("large.bin", &large_data).unwrap();
        writer.finalize().unwrap();

        // Extract and verify
        let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
        let extract_dir = temp_dir.path().join("extracted");
        let options = ExtractOptions::new(&extract_dir);
        let stats = reader.extract_all(&options).unwrap();

        assert_eq!(stats.extracted, 1);
        assert_eq!(stats.bytes_written, 512 * 1024);

        let extracted = fs::read(extract_dir.join("large.bin")).unwrap();
        assert_eq!(extracted, large_data);
    }

    #[test]
    fn test_unicode_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("unicode.era");
        let password = "密码";

        // Create archive with unicode content
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .build()
            .unwrap();
        writer
            .add_bytes("文档.txt", "这是中文内容".as_bytes())
            .unwrap();
        writer.finalize().unwrap();

        // Extract and verify
        let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
        let extract_dir = temp_dir.path().join("extracted");
        let options = ExtractOptions::new(&extract_dir);
        reader.extract_all(&options).unwrap();

        let extracted = fs::read_to_string(extract_dir.join("文档.txt")).unwrap();
        assert_eq!(extracted, "这是中文内容");
    }

    #[test]
    fn test_overwrite_protection() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.era");
        let password = "test";

        // Create archive
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .build()
            .unwrap();
        writer.add_bytes("file.txt", b"new content").unwrap();
        writer.finalize().unwrap();

        // Create existing file
        let extract_dir = temp_dir.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();
        fs::write(extract_dir.join("file.txt"), b"original content").unwrap();

        // Extract without overwrite
        let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
        let options = ExtractOptions::new(&extract_dir);
        let stats = reader.extract_all(&options).unwrap();

        assert_eq!(stats.skipped, 1);
        assert_eq!(stats.extracted, 0);

        // Verify original content preserved
        let content = fs::read_to_string(extract_dir.join("file.txt")).unwrap();
        assert_eq!(content, "original content");
    }

    #[test]
    fn test_overwrite_enabled() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.era");
        let password = "test";

        // Create archive
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .build()
            .unwrap();
        writer.add_bytes("file.txt", b"new content").unwrap();
        writer.finalize().unwrap();

        // Create existing file
        let extract_dir = temp_dir.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();
        fs::write(extract_dir.join("file.txt"), b"original content").unwrap();

        // Extract with overwrite enabled
        let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
        let options = ExtractOptions::new(&extract_dir).overwrite(true);
        let stats = reader.extract_all(&options).unwrap();

        assert_eq!(stats.extracted, 1);

        // Verify new content
        let content = fs::read_to_string(extract_dir.join("file.txt")).unwrap();
        assert_eq!(content, "new content");
    }

    #[test]
    fn test_nested_directory_structure() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("nested.era");
        let password = "test";

        // Create archive with nested structure
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .build()
            .unwrap();
        writer.add_bytes("a/b/c/deep.txt", b"deep content").unwrap();
        writer.add_bytes("a/shallow.txt", b"shallow").unwrap();
        writer.finalize().unwrap();

        // Extract
        let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
        let extract_dir = temp_dir.path().join("extracted");
        let options = ExtractOptions::new(&extract_dir);
        reader.extract_all(&options).unwrap();

        // Verify nested file
        let deep = fs::read_to_string(extract_dir.join("a/b/c/deep.txt")).unwrap();
        assert_eq!(deep, "deep content");

        let shallow = fs::read_to_string(extract_dir.join("a/shallow.txt")).unwrap();
        assert_eq!(shallow, "shallow");
    }

    #[test]
    fn test_verify_valid_archive() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("verify.era");
        let password = "test";

        // Create archive with multiple files
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .build()
            .unwrap();

        writer.add_bytes("file1.txt", b"Hello, World!").unwrap();
        writer.add_bytes("file2.txt", b"More content here").unwrap();
        writer.add_bytes("binary.bin", &[0u8; 1024]).unwrap();
        writer.finalize().unwrap();

        // Verify the archive
        let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
        let stats = reader.verify().unwrap();

        assert!(stats.is_ok(), "Verification should pass");
        assert!(stats.blocks_verified > 0);
        assert_eq!(stats.blocks_failed, 0);
        assert_eq!(stats.files_verified, 3);
        assert_eq!(stats.files_incomplete, 0);
        assert!(stats.errors.is_empty());
    }

    #[test]
    fn test_verify_large_chunked_file() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("chunked.era");
        let password = "test";

        // Create archive with large file that gets chunked
        let large_data = vec![b'A'; 512 * 1024]; // 512KB
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .build()
            .unwrap();

        writer.add_bytes("large.bin", &large_data).unwrap();
        writer.finalize().unwrap();

        // Verify the archive
        let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
        let stats = reader.verify().unwrap();

        assert!(stats.is_ok(), "Verification should pass for chunked file");
        assert!(stats.bytes_verified > 0);
    }

    #[test]
    fn test_verify_empty_archive() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("empty.era");
        let password = "test";

        // Create empty archive
        let writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .build()
            .unwrap();
        writer.finalize().unwrap();

        // Verify empty archive
        let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
        let stats = reader.verify().unwrap();

        assert!(stats.is_ok(), "Empty archive should verify ok");
        assert_eq!(stats.files_verified, 0);
    }

    #[test]
    fn test_max_declared_file_size_constant() {
        // Verify MAX_DECLARED_FILE_SIZE is 100GB
        assert_eq!(super::MAX_DECLARED_FILE_SIZE, 100 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_erasure_simple_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("erasure.era");
        let password = "test";

        // Create archive with erasure coding
        let erasure_config = era_common::ErasureCodeConfig {
            data_shards: 4,
            parity_shards: 2,
        };

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .erasure_config(erasure_config)
            .build()
            .unwrap();

        writer
            .add_bytes("test.txt", b"Hello, Erasure World!")
            .unwrap();
        let stats = writer.finalize().unwrap();
        assert_eq!(stats.total_files, 1);

        // Extract and verify
        let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
        let extract_dir = temp_dir.path().join("extracted");
        let options = ExtractOptions::new(&extract_dir);
        let extract_stats = reader.extract_all(&options).unwrap();

        assert_eq!(extract_stats.extracted, 1);

        let content = std::fs::read_to_string(extract_dir.join("test.txt")).unwrap();
        assert_eq!(content, "Hello, Erasure World!");
    }
}
