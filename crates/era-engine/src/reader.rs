//! Archive reader - extracts files from ERA archives.
//!
//! ## Security
//!
//! This reader implements the HKDF "Onion Model" key derivation:
//! - **Master Key (MK)**: Derived from password via Argon2id (mlock-protected)
//! - **Volume Key (VK)**: Derived from MK via HKDF (per-volume isolation)
//! - **Block Key (BK)**: Derived from VK via HKDF (per-block forward secrecy)
//!
//! Each block is decrypted with a unique key derived on-the-fly.

use crate::block_iter::{
    BlockIterator, SessionBlockIterator, SessionErasureBlockIterator,
    SessionErasureBlockIteratorArgs,
};
pub use crate::chunk_processor::{ExtractStats, VerifyStats};
use crate::chunk_processor::{ExtractionContext, MultiChunkState, VerificationContext};
use bytes::Bytes;
use era_codec::ZstdCompressor;
use era_common::{BlockId, BlockLocation, ChunkHash, ChunkVec, EraError, Result, ShardLayout};
use era_crypto::certificate::EraKeyPair;
use era_crypto::{KeySession, VolumeKey};
use era_index::IndexReader;
use era_ingest::{Catalog, FileEntry};
use era_packing::{SessionBlockUnpacker, SessionErasureBlockUnpacker};
use era_storage::LocalStorageBackend;
use era_volume::{Footer, SuperHeader, VolumeReader};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use tracing::{debug, info};
use zeroize::Zeroize;

const INTERNAL_META_PREFIX: &str = ".era/meta/";

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
/// ## Security
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
    /// Restored embedded LSM directory (if present, legacy path)
    embedded_lsm_dir: Option<PathBuf>,
    /// V2.1 index reader recovered from volume (preferred fast path)
    index_reader: Option<IndexReader>,
}

#[allow(dead_code)]
fn create_embedded_lsm_restore_dir() -> PathBuf {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    let suffix = u64::from_le_bytes(bytes);

    let mut path = std::env::temp_dir();
    path.push(format!("era_lsm_restore_{:016x}", suffix));
    let _ = std::fs::create_dir_all(&path);
    path
}

/// Maximum size for a single LSM manifest entry (256 MB)
#[allow(dead_code)]
const MAX_LSM_ENTRY_SIZE: usize = 256 * 1024 * 1024;

/// Maximum number of entries in an LSM manifest
#[allow(dead_code)]
const MAX_LSM_ENTRY_COUNT: usize = 1_000_000;

#[allow(dead_code)]
fn restore_lsm_dir_from_manifest(path: &Path, data: &[u8]) -> Result<()> {
    let mut cursor = std::io::Cursor::new(data);
    let mut count_bytes = [0u8; 4];
    cursor
        .read_exact(&mut count_bytes)
        .map_err(era_common::EraError::Io)?;
    let count = u32::from_le_bytes(count_bytes) as usize;

    if count > MAX_LSM_ENTRY_COUNT {
        return Err(era_common::EraError::CorruptedHeader(format!(
            "LSM manifest entry count too large: {}",
            count
        )));
    }

    // Canonicalize the allowed base directory
    let allowed = path.canonicalize().map_err(era_common::EraError::Io)?;

    for _ in 0..count {
        let mut len_bytes = [0u8; 4];
        cursor
            .read_exact(&mut len_bytes)
            .map_err(era_common::EraError::Io)?;
        let path_len = u32::from_le_bytes(len_bytes) as usize;

        let mut path_buf = vec![0u8; path_len];
        cursor
            .read_exact(&mut path_buf)
            .map_err(era_common::EraError::Io)?;
        let rel_path = String::from_utf8(path_buf)
            .map_err(|e| era_common::EraError::Deserialization(e.to_string()))?;

        let mut size_bytes = [0u8; 8];
        cursor
            .read_exact(&mut size_bytes)
            .map_err(era_common::EraError::Io)?;
        let data_len = u64::from_le_bytes(size_bytes) as usize;

        if data_len > MAX_LSM_ENTRY_SIZE {
            return Err(era_common::EraError::CorruptedHeader(format!(
                "LSM entry too large: {} bytes",
                data_len
            )));
        }

        let mut file_data = vec![0u8; data_len];
        cursor
            .read_exact(&mut file_data)
            .map_err(era_common::EraError::Io)?;

        // Path traversal protection: validate rel_path components
        let rel = std::path::Path::new(&rel_path);
        for component in rel.components() {
            match component {
                std::path::Component::ParentDir => {
                    return Err(era_common::EraError::Security(format!(
                        "Path traversal detected in LSM manifest: {}",
                        rel_path
                    )));
                }
                std::path::Component::RootDir => {
                    return Err(era_common::EraError::Security(format!(
                        "Absolute path in LSM manifest: {}",
                        rel_path
                    )));
                }
                _ => {}
            }
        }

        let file_path = path.join(&rel_path);
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent).map_err(era_common::EraError::Io)?;
        }

        // Post-creation canonicalize check
        let canonical = if file_path.exists() {
            file_path.canonicalize().map_err(era_common::EraError::Io)?
        } else {
            let parent = file_path
                .parent()
                .ok_or_else(|| era_common::EraError::Security("Invalid path".into()))?;
            let filename = file_path
                .file_name()
                .ok_or_else(|| era_common::EraError::Security("Invalid path".into()))?;
            parent
                .canonicalize()
                .map_err(era_common::EraError::Io)?
                .join(filename)
        };

        if !canonical.starts_with(&allowed) {
            return Err(era_common::EraError::Security(format!(
                "Path traversal detected: {}",
                rel_path
            )));
        }

        std::fs::write(canonical, file_data).map_err(era_common::EraError::Io)?;
    }

    Ok(())
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
    pub async fn open(path: &Path, password: &str) -> Result<Self> {
        let provider = Box::new(crate::auth::PasswordProvider::new(password.to_string()));
        Self::open_with_providers(path, vec![provider]).await
    }

    /// Open an archive with multiple passwords (for threshold mode).
    ///
    /// Each password is tried against each recipient slot independently.
    pub async fn open_with_passwords(path: &Path, passwords: &[&str]) -> Result<Self> {
        let providers: Vec<Box<dyn crate::auth::AuthProvider>> = passwords
            .iter()
            .map(|p| {
                Box::new(crate::auth::PasswordProvider::new(p.to_string()))
                    as Box<dyn crate::auth::AuthProvider>
            })
            .collect();
        Self::open_with_providers(path, providers).await
    }

    /// Discover and open all volumes belonging to the same archive.
    async fn discover_volumes(
        path: &Path,
    ) -> Result<(
        Vec<VolumeReader<era_storage::LocalStorageReader>>,
        Vec<usize>,
    )> {
        let parent_dir = path.parent().unwrap_or(Path::new("."));
        let backend = LocalStorageBackend::new(parent_dir);
        let base_filename = path.file_name().unwrap_or_default();

        // 1. Try to open the specified file first (could be any volume)
        let first_reader = VolumeReader::open(&backend, Path::new(base_filename)).await?;

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
            let s = base_str.to_string();
            if let Some(idx) = s.rfind(".era.") {
                PathBuf::from(&s[..idx + 4])
            } else {
                PathBuf::from(base_filename)
            }
        };

        // 5. Scan for all available volumes
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
                    continue;
                } else if missing_count >= scan_tolerance {
                    break;
                }
                continue;
            }

            missing_count = 0;

            match VolumeReader::open(&backend, &volume_path).await {
                Ok(reader) => {
                    if reader.header().archive_id == first_archive_id {
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

        info!(
            "Opened {} volumes at sequences {:?} (total expected: {})",
            volume_readers.len(),
            volume_indices,
            if total_volumes > 0 {
                total_volumes.to_string()
            } else {
                "unknown".to_string()
            },
        );

        Ok((volume_readers, volume_indices))
    }

    pub async fn open_with_providers(
        path: &Path,
        providers: Vec<Box<dyn crate::auth::AuthProvider>>,
    ) -> Result<Self> {
        info!("Opening archive: {}", path.display());

        let (volume_readers, volume_indices) = Self::discover_volumes(path).await?;

        // Use first available reader for key derivation (all volumes share same crypto params)
        let volume_reader = &volume_readers[0];
        let header = volume_reader.header();

        let mk_array: [u8; 32] = match header.access_policy {
            era_volume::AccessPolicy::AnyOfN => {
                let mut master_key = None;
                'outer: for slot in &header.recipients {
                    for provider in &providers {
                        if let Ok(Some(mk)) = provider.try_unlock(slot) {
                            master_key = Some(mk);
                            break 'outer;
                        }
                    }
                }
                let mut master_key_bytes =
                    master_key.ok_or(EraError::InvalidKey("No valid credentials found".into()))?;
                let mk_array: [u8; 32] = master_key_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| EraError::InvalidKey("Invalid master key length".into()))?;
                master_key_bytes.zeroize();
                mk_array
            }
            era_volume::AccessPolicy::Threshold(t) => {
                if t < 2 {
                    return Err(EraError::InvalidConfig("Threshold must be >= 2".into()));
                }
                let mut shares = Vec::new();
                for slot in &header.recipients {
                    for provider in &providers {
                        if let Ok(Some(share)) = provider.try_unlock(slot) {
                            shares.push(share);
                            break;
                        }
                    }
                }
                if (shares.len() as u32) < t {
                    return Err(EraError::ThresholdNotMet {
                        required: t,
                        provided: shares.len() as u32,
                    });
                }
                let result = era_crypto::reconstruct_master_key(&shares, t as u8);
                shares.iter_mut().for_each(|s| s.zeroize());
                result?
            }
        };

        // Create KeySession
        let session = KeySession::from_master_key(&mk_array)?;
        let mut mk_array = mk_array;
        mk_array.zeroize();

        // Unwrap volume key from header's encrypted envelope
        let volume_key = session.unwrap_volume_key(
            &header.encrypted_volume_key.nonce,
            &header.encrypted_volume_key.ciphertext,
        )?;

        // Store nonce context
        let nonce_context = header.salt;

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
            embedded_lsm_dir: None,
            index_reader: None,
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
    pub async fn open_with_session(path: &Path, session: &KeySession) -> Result<Self> {
        info!("Opening archive with key session: {}", path.display());

        let (volume_readers, volume_indices) = Self::discover_volumes(path).await?;

        let volume_reader = &volume_readers[0];
        let header = volume_reader.header();

        if let era_volume::AccessPolicy::Threshold(t) = header.access_policy {
            return Err(EraError::InvalidConfig(
                format!("Cannot open Threshold({}) archive with session — requires multi-party authentication", t),
            ));
        }

        let owned_session = session.clone();
        let volume_key = owned_session.unwrap_volume_key(
            &header.encrypted_volume_key.nonce,
            &header.encrypted_volume_key.ciphertext,
        )?;

        let nonce_context = header.salt;
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
            embedded_lsm_dir: None,
            index_reader: None,
        })
    }

    /// Open an archive using a keypair (certificate mode)
    ///
    /// This method is ~1000x faster than password-based `open()` because it uses
    /// X25519 key exchange instead of Argon2id password derivation.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to any volume file of the archive
    /// * `keypair` - The EraKeyPair containing the private key
    ///
    /// # Example
    ///
    /// ```ignore
    /// let keypair = EraKeyPair::load_encrypted("~/.era/key.era-key", "keypass")?;
    /// let reader = ArchiveReader::open_with_keypair(&archive_path, &keypair)?;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The archive was created with password mode (not certificate mode)
    /// - The keypair doesn't match the certificate used to create the archive
    /// - The key encapsulation data is corrupted
    pub async fn open_with_keypair(path: &Path, keypair: &EraKeyPair) -> Result<Self> {
        let provider = Box::new(crate::auth::CertificateProvider::new(keypair.clone()));
        Self::open_with_providers(path, vec![provider]).await
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

    /// Metadata-first preflight: restore embedded index (if present) and load catalog.
    pub async fn preflight_metadata_recovery(&mut self) -> Result<()> {
        self.restore_embedded_index().await?;
        self.load_catalog().await?;
        Ok(())
    }

    async fn restore_embedded_index(&mut self) -> Result<()> {
        if self.embedded_lsm_dir.is_some() || self.index_reader.is_some() {
            return Ok(());
        }

        // Fast path: try V2.1 IndexReader recovery from volume footer
        for reader in &self.volume_readers {
            if let Some(footer) = reader.footer() {
                if footer.has_index() {
                    match IndexReader::recover_from_volume(
                        reader,
                        &self.session,
                        &self.volume_key,
                        self.nonce_context,
                    )
                    .await
                    {
                        Ok(index_reader) => {
                            debug!("V2.1 index recovered from volume footer");
                            self.index_reader = Some(index_reader);
                            return Ok(());
                        }
                        Err(e) => {
                            debug!(
                                "V2.1 index recovery failed, continuing without index: {}",
                                e
                            );
                            // Don't fall through to legacy path — the footer's index location
                            // points to V2.1 typed blocks which can't be unpacked as data blocks.
                            return Ok(());
                        }
                    }
                }
            }
        }

        // No footer with index found — nothing to restore
        Ok(())
    }

    /// Get the archive header
    pub fn header(&self) -> &SuperHeader {
        self.volume_readers[0].header()
    }

    /// Get the primary volume footer (if available)
    pub fn primary_footer(&self) -> Option<&Footer> {
        self.volume_readers.first().and_then(|r| r.footer())
    }

    /// Load the catalog from any available volume
    /// Each volume contains a copy of the catalog, enabling recovery from any volume
    pub async fn load_catalog(&mut self) -> Result<&Catalog> {
        if let Some(ref catalog) = self.catalog {
            return Ok(catalog);
        }

        // Find the first volume that has a valid catalog
        let mut catalog_reader_idx = None;
        for (i, reader) in self.volume_readers.iter().enumerate() {
            if let Some(footer) = reader.footer() {
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
        }

        let reader_idx = catalog_reader_idx.ok_or_else(|| {
            debug!("No volume with valid catalog found");
            EraError::EmptyArchive
        })?;

        let reader = &self.volume_readers[reader_idx];
        let footer = reader
            .footer()
            .expect("Catalog volume must have valid footer");

        let catalog_location = BlockLocation::single(
            reader.header().volume_id,
            footer.catalog_block_id,
            footer.catalog_offset,
            footer.catalog_size,
        );

        debug!(
            "Loading catalog from volume {} at offset={}, size={}, block_id={}",
            reader_idx, footer.catalog_offset, footer.catalog_size, footer.catalog_block_id
        );

        let encrypted_block = self.volume_readers[reader_idx]
            .read_block(&catalog_location)
            .await?;

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
    /// whether the block is erasure-coded based on `location.shard_layout` and uses
    /// the appropriate unpacker.
    pub async fn read_and_extract_chunks(&self, location: &BlockLocation) -> Result<ChunkVec> {
        if let ShardLayout::Erasure {
            ref info,
            ref shard_offsets,
            ref shard_volumes,
        } = location.shard_layout
        {
            let erasure_info = info;
            // Erasure-coded block: read shards from multiple volumes
            let total_shards =
                erasure_info.data_shards as usize + erasure_info.parity_shards as usize;

            let mut available_shards = Vec::with_capacity(total_shards);

            // Check shard offsets
            if shard_offsets.is_empty() {
                return Err(EraError::IntegrityError(
                    "Missing shard offsets for erasure block".into(),
                ));
            }

            // Check shard volumes - archives must be explicit about shard locations
            if shard_volumes.is_empty() {
                return Err(EraError::IntegrityError(
                    "Missing shard volumes for erasure block".into(),
                ));
            }

            // Determine volume index for each shard
            // We need to map shard_idx -> volume_reader index

            // 1. Identify which shard *this* block is (my_shard_idx)
            let my_shard_idx = (location.slot_index as usize) % (erasure_info.data_shards as usize);

            let get_reader_index = |shard_idx: usize| -> Option<usize> {
                if shard_idx == my_shard_idx {
                    // This is the current block's volume.
                    // We need to find the reader that matches location.volume_id
                    // iterating explicitly is safest because volume_readers might not be sorted/complete
                    for (i, r) in self.volume_readers.iter().enumerate() {
                        if r.header().volume_id == location.volume_id {
                            return Some(i);
                        }
                    }
                    None
                } else {
                    // It's a neighbor shard.
                    // shard_volumes contains sequences for ALL OTHER shards in order.
                    // We map shard_idx -> index in shard_volumes
                    let vec_idx = if shard_idx < my_shard_idx {
                        shard_idx
                    } else {
                        shard_idx - 1
                    };

                    if let Some(&seq) = shard_volumes.get(vec_idx) {
                        // Find reader with this sequence
                        for (i, r) in self.volume_readers.iter().enumerate() {
                            if r.header().volume_sequence as usize == seq as usize {
                                return Some(i);
                            }
                        }
                    }
                    // Fallback or legacy (not supported here fully, but...)
                    None
                }
            };

            // Read shards
            for shard_idx in 0..total_shards {
                if let Some(vol_idx) = get_reader_index(shard_idx) {
                    let offset = if shard_idx == my_shard_idx {
                        location.physical_offset
                    } else {
                        let vec_idx = if shard_idx < my_shard_idx {
                            shard_idx
                        } else {
                            shard_idx - 1
                        };
                        if let Some(&off) = shard_offsets.get(vec_idx) {
                            off
                        } else {
                            continue;
                        }
                    };

                    // Debug info
                    // println!("Reading shard {} (my={}) from vol_idx {} offset {}", shard_idx, my_shard_idx, vol_idx, offset);

                    match self.read_shard(&self.volume_readers[vol_idx], offset).await {
                        Ok(shard) => {
                            available_shards.push((shard_idx, shard));
                        }
                        Err(_e) => {
                            // println!("Failed to read shard {}: {}", shard_idx, e);
                        }
                    }
                }
            }

            let block_id = BlockId::new(location.slot_index as u64);
            // Create temporary session-based erasure unpacker
            let erasure_unpacker = self.create_erasure_unpacker();
            erasure_unpacker.decode_and_extract_all_for_shard(
                available_shards,
                erasure_info,
                block_id,
                my_shard_idx,
            )
        } else {
            // Standard block: read and unpack directly with session-based unpacker
            let encrypted_block = self.volume_readers[0].read_block(location).await?;
            let unpacker = self.create_unpacker();
            let unpacked = unpacker.unpack(&encrypted_block)?;

            // Extract all chunks using consolidated helpers
            era_packing::extract_all_chunks(&unpacked.index, &unpacked.data)
        }
    }

    async fn read_shard<R: era_storage::StorageReader>(
        &self,
        reader: &VolumeReader<R>,
        offset: u64,
    ) -> Result<Bytes> {
        let header_bytes = reader
            .read_raw(offset, era_common::ShardHeader::SIZE)
            .await?;
        if let Some(header) = era_common::ShardHeader::from_bytes(&header_bytes) {
            let data = reader
                .read_raw(
                    offset + era_common::ShardHeader::SIZE as u64,
                    header.length as usize,
                )
                .await?;
            if header.verify(&data) {
                return Ok(data);
            }
        }
        Err(EraError::IntegrityError("Shard verification failed".into()))
    }

    /// List all files in the archive
    pub async fn list_files(&mut self) -> Result<Vec<&FileEntry>> {
        let catalog = self.load_catalog().await?;
        Ok(catalog
            .entries
            .iter()
            .filter(|entry| !is_internal_entry(entry))
            .collect())
    }

    /// Extract using the provided block iterator
    async fn extract_with_iterator(
        catalog: &Catalog,
        iter: &mut Box<dyn BlockIterator + '_>,
        options: &ExtractOptions,
    ) -> Result<ExtractStats> {
        let mut stats = ExtractStats::default();

        // Build maps for extraction
        let mut context = ExtractionContext::new();

        for (file_idx, entry) in catalog.entries.iter().enumerate() {
            if is_internal_entry(entry) {
                continue;
            }
            let output_path = options.output_dir.join(&entry.path);

            // Path traversal protection: verify output_path stays within output_dir
            {
                let rel = &entry.path;
                for component in rel.components() {
                    match component {
                        std::path::Component::ParentDir => {
                            return Err(EraError::Security(format!(
                                "Path traversal detected: {}",
                                rel.display()
                            )));
                        }
                        std::path::Component::RootDir => {
                            return Err(EraError::Security(format!(
                                "Absolute path in archive entry: {}",
                                rel.display()
                            )));
                        }
                        _ => {}
                    }
                }
            }

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

                // Check if this is a packed chunk (single chunk with packed_info)
                let is_packed = chunk_count == 1 && entry.chunks[0].packed_info.is_some();

                if is_packed {
                    // Packed chunk: handle like single-chunk file
                    let chunk_ref = &entry.chunks[0];
                    let packed_info = chunk_ref.packed_info.as_ref().unwrap();

                    context
                        .packed_chunks
                        .entry(chunk_ref.hash)
                        .or_default()
                        .push((file_idx, packed_info.file_index, output_path));
                } else {
                    // Normal multi-chunk file: pre-create file
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
                }
            }
        }

        if !context.has_pending() {
            info!("No files to extract");
            return Ok(stats);
        }

        const MAX_CONSECUTIVE_FAILURES: u32 = 16;
        let mut consecutive_failures: u32 = 0;

        while let Some(result) = iter.next_block().await {
            match result {
                Ok(decoded) => {
                    consecutive_failures = 0;
                    context.process_chunks(decoded.chunks, &mut stats)?;
                }
                Err(e) => {
                    consecutive_failures += 1;
                    if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                        return Err(EraError::Security(format!(
                            "Aborting: {} consecutive block failures: {}",
                            consecutive_failures, e
                        )));
                    }
                    tracing::warn!(
                        "Block failure ({}/{}): {}",
                        consecutive_failures,
                        MAX_CONSECUTIVE_FAILURES,
                        e
                    );
                }
            }
            if !context.has_pending() {
                break;
            }
        }

        context.log_incomplete_files();

        if context.has_pending() {
            return Err(EraError::ErasureError(
                "Not enough shards for recovery: extraction incomplete due to \
                 too many missing or corrupted volumes."
                    .into(),
            ));
        }

        info!(
            "Extraction complete: {} files, {} bytes",
            stats.extracted, stats.bytes_written
        );

        Ok(stats)
    }

    /// Verify using the provided block iterator
    async fn verify_with_iterator(
        catalog: &Catalog,
        iter: &mut Box<dyn BlockIterator + '_>,
    ) -> Result<VerifyStats> {
        let mut stats = VerifyStats::default();

        let mut context = VerificationContext::new(catalog.entries.len());

        // Track packed chunks to avoid duplicate verification
        // Key: packed_chunk_hash, Value: list of file indices sharing this packed chunk
        let mut packed_chunk_files: HashMap<ChunkHash, Vec<usize>> = HashMap::new();

        for (file_idx, entry) in catalog.entries.iter().enumerate() {
            if is_internal_entry(entry) {
                context.file_chunk_counts.push(0);
                continue;
            }
            if entry.is_chunked() {
                let chunk_count = entry.chunks.len();

                // Check if this is a packed chunk (single chunk with packed_info)
                let is_packed = chunk_count == 1 && entry.chunks[0].packed_info.is_some();

                if is_packed {
                    // Packed file: track by packed chunk hash
                    // Multiple files may share the same packed chunk
                    let chunk_ref = &entry.chunks[0];
                    packed_chunk_files
                        .entry(chunk_ref.hash)
                        .or_default()
                        .push(file_idx);

                    // Only add to expected_chunks once per unique packed chunk
                    if !context.expected_chunks.contains_key(&chunk_ref.hash) {
                        context
                            .expected_chunks
                            .entry(chunk_ref.hash)
                            .or_default()
                            .push((file_idx, 0, chunk_ref.length as u64));
                    }
                    context.file_chunk_counts.push(1);
                } else {
                    // Normal multi-chunk file
                    context.file_chunk_counts.push(chunk_count);
                    for (chunk_idx, chunk_ref) in entry.chunks.iter().enumerate() {
                        context
                            .expected_chunks
                            .entry(chunk_ref.hash)
                            .or_default()
                            .push((file_idx, chunk_idx, chunk_ref.length as u64));
                    }
                }
            } else {
                context.file_chunk_counts.push(0);
            }
        }

        // For packed chunks, update expected_chunks to include all files sharing the chunk
        for (hash, file_indices) in &packed_chunk_files {
            if let Some(refs) = context.expected_chunks.get_mut(hash) {
                // The first entry was already added, add the rest
                for &file_idx in file_indices.iter().skip(1) {
                    // Get the chunk ref to get the correct length
                    if let Some(entry) = catalog.entries.get(file_idx) {
                        if !entry.chunks.is_empty() {
                            refs.push((file_idx, 0, entry.chunks[0].length as u64));
                        }
                    }
                }
            }
        }

        while let Some(result) = iter.next_block().await {
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
            for err in &stats.errors {
                println!("Verify Error: {}", err);
            }
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
    pub async fn extract_all(&mut self, options: &ExtractOptions) -> Result<ExtractStats> {
        info!("Extracting to: {}", options.output_dir.display());

        self.preflight_metadata_recovery().await?;
        let catalog = self.catalog.as_ref().unwrap();

        // Check if erasure coding is enabled
        let erasure_config = self.volume_readers[0].header().config.erasure;

        // Create session-based iterators with per-block key derivation
        let mut iter: Box<dyn BlockIterator> = if let Some(config) = erasure_config {
            // Read distribution config from header
            let dist_strategy = self.volume_readers[0].header().config.distribution.strategy;

            Box::new(SessionErasureBlockIterator::new(
                SessionErasureBlockIteratorArgs {
                    volume_readers: &self.volume_readers,
                    volume_indices: &self.volume_indices,
                    original_volume_count: self.volume_readers[0].header().total_volumes.into(),
                    session: &self.session,
                    volume_key: &self.volume_key,
                    nonce_context: self.nonce_context,
                    compressor: self.create_compressor(),
                    data_shards: config.data_shards,
                    parity_shards: config.parity_shards,
                    distribution_strategy: dist_strategy,
                },
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

        Self::extract_with_iterator(catalog, &mut iter, options).await
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
    pub async fn verify(&mut self) -> Result<VerifyStats> {
        info!("Verifying archive integrity...");

        self.preflight_metadata_recovery().await?;
        let catalog = self.catalog.as_ref().unwrap();

        // Check if erasure coding is enabled
        let erasure_config = self.volume_readers[0].header().config.erasure;

        // Create session-based iterators with per-block key derivation
        let mut iter: Box<dyn BlockIterator> = if let Some(config) = erasure_config {
            // Read distribution config from header
            let dist_strategy = self.volume_readers[0].header().config.distribution.strategy;

            Box::new(SessionErasureBlockIterator::new(
                SessionErasureBlockIteratorArgs {
                    volume_readers: &self.volume_readers,
                    volume_indices: &self.volume_indices,
                    original_volume_count: self.volume_readers[0].header().total_volumes.into(),
                    session: &self.session,
                    volume_key: &self.volume_key,
                    nonce_context: self.nonce_context,
                    compressor: self.create_compressor(),
                    data_shards: config.data_shards,
                    parity_shards: config.parity_shards,
                    distribution_strategy: dist_strategy,
                },
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

        Self::verify_with_iterator(catalog, &mut iter).await
    }
}

impl Drop for ArchiveReader {
    fn drop(&mut self) {
        if let Some(path) = &self.embedded_lsm_dir {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

fn is_internal_entry(entry: &FileEntry) -> bool {
    entry
        .path
        .to_string_lossy()
        .starts_with(INTERNAL_META_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ArchiveWriter;
    use era_common::ArchiveConfig;
    use tempfile::TempDir;

    /// Helper: Create a config with EC disabled for single-volume tests
    fn test_config_no_ec() -> ArchiveConfig {
        ArchiveConfig {
            erasure: None,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.era");
        let password = "test_password";

        // Create archive (EC disabled for single-volume test)
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .config(test_config_no_ec())
            .build()
            .await
            .unwrap();

        writer
            .add_bytes("hello.txt", b"Hello, World!")
            .await
            .unwrap();
        writer
            .add_bytes("data.bin", &[1, 2, 3, 4, 5])
            .await
            .unwrap();
        writer.finalize().await.unwrap();

        // Read archive
        let mut reader = ArchiveReader::open(&archive_path, password).await.unwrap();
        let files = reader.list_files().await.unwrap();
        assert_eq!(files.len(), 2);

        // Extract
        let extract_dir = temp_dir.path().join("extracted");
        let options = ExtractOptions::new(&extract_dir);
        let stats = reader.extract_all(&options).await.unwrap();

        assert_eq!(stats.extracted, 2);
        assert_eq!(stats.bytes_written, 18); // 13 + 5

        // Verify extracted files
        let hello_content = fs::read_to_string(extract_dir.join("hello.txt")).unwrap();
        assert_eq!(hello_content, "Hello, World!");

        let data_content = fs::read(extract_dir.join("data.bin")).unwrap();
        assert_eq!(data_content, vec![1, 2, 3, 4, 5]);
    }

    #[tokio::test]
    async fn test_wrong_password_fails() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("secure.era");

        // Create archive with password (EC disabled for single-volume test)
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("correct_password")
            .config(test_config_no_ec())
            .build()
            .await
            .unwrap();

        writer
            .add_bytes("secret.txt", b"Secret data")
            .await
            .unwrap();
        writer.finalize().await.unwrap();

        // Try to open with wrong password
        let result = ArchiveReader::open(&archive_path, "wrong_password").await;
        assert!(result.is_err(), "Wrong password should fail");
    }

    #[tokio::test]
    async fn test_empty_archive_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("empty.era");
        let password = "test";

        // Create empty archive (EC disabled for single-volume test)
        let writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .config(test_config_no_ec())
            .build()
            .await
            .unwrap();
        writer.finalize().await.unwrap();

        // Read empty archive
        let mut reader = ArchiveReader::open(&archive_path, password).await.unwrap();
        let files = reader.list_files().await.unwrap();
        assert!(files.is_empty());
    }

    #[tokio::test]
    async fn test_large_file_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("large.era");
        let password = "test";

        // Create archive with large file (EC disabled for single-volume test)
        let large_data = vec![b'X'; 512 * 1024]; // 512KB
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .config(test_config_no_ec())
            .build()
            .await
            .unwrap();
        writer.add_bytes("large.bin", &large_data).await.unwrap();
        writer.finalize().await.unwrap();

        // Extract and verify
        let mut reader = ArchiveReader::open(&archive_path, password).await.unwrap();
        let extract_dir = temp_dir.path().join("extracted");
        let options = ExtractOptions::new(&extract_dir);
        let stats = reader.extract_all(&options).await.unwrap();

        assert_eq!(stats.extracted, 1);
        assert_eq!(stats.bytes_written, 512 * 1024);

        let extracted = fs::read(extract_dir.join("large.bin")).unwrap();
        assert_eq!(extracted, large_data);
    }

    #[tokio::test]
    async fn test_unicode_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("unicode.era");
        let password = "密码";

        // Create archive with unicode content (EC disabled for single-volume test)
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .config(test_config_no_ec())
            .build()
            .await
            .unwrap();
        writer
            .add_bytes("文档.txt", "这是中文内容".as_bytes())
            .await
            .unwrap();
        writer.finalize().await.unwrap();

        // Extract and verify
        let mut reader = ArchiveReader::open(&archive_path, password).await.unwrap();
        let extract_dir = temp_dir.path().join("extracted");
        let options = ExtractOptions::new(&extract_dir);
        reader.extract_all(&options).await.unwrap();

        let extracted = fs::read_to_string(extract_dir.join("文档.txt")).unwrap();
        assert_eq!(extracted, "这是中文内容");
    }

    #[tokio::test]
    async fn test_overwrite_protection() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.era");
        let password = "test";

        // Create archive (EC disabled for single-volume test)
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .config(test_config_no_ec())
            .build()
            .await
            .unwrap();
        writer.add_bytes("file.txt", b"new content").await.unwrap();
        writer.finalize().await.unwrap();

        // Create existing file
        let extract_dir = temp_dir.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();
        fs::write(extract_dir.join("file.txt"), b"original content").unwrap();

        // Extract without overwrite
        let mut reader = ArchiveReader::open(&archive_path, password).await.unwrap();
        let options = ExtractOptions::new(&extract_dir);
        let stats = reader.extract_all(&options).await.unwrap();

        assert_eq!(stats.skipped, 1);
        assert_eq!(stats.extracted, 0);

        // Verify original content preserved
        let content = fs::read_to_string(extract_dir.join("file.txt")).unwrap();
        assert_eq!(content, "original content");
    }

    #[tokio::test]
    async fn test_overwrite_enabled() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.era");
        let password = "test";

        // Create archive (EC disabled for single-volume test)
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .config(test_config_no_ec())
            .build()
            .await
            .unwrap();
        writer.add_bytes("file.txt", b"new content").await.unwrap();
        writer.finalize().await.unwrap();

        // Create existing file
        let extract_dir = temp_dir.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();
        fs::write(extract_dir.join("file.txt"), b"original content").unwrap();

        // Extract with overwrite enabled
        let mut reader = ArchiveReader::open(&archive_path, password).await.unwrap();
        let options = ExtractOptions::new(&extract_dir).overwrite(true);
        let stats = reader.extract_all(&options).await.unwrap();

        assert_eq!(stats.extracted, 1);

        // Verify new content
        let content = fs::read_to_string(extract_dir.join("file.txt")).unwrap();
        assert_eq!(content, "new content");
    }

    #[tokio::test]
    async fn test_nested_directory_structure() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("nested.era");
        let password = "test";

        // Create archive with nested structure (EC disabled for single-volume test)
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .config(test_config_no_ec())
            .build()
            .await
            .unwrap();
        writer
            .add_bytes("a/b/c/deep.txt", b"deep content")
            .await
            .unwrap();
        writer.add_bytes("a/shallow.txt", b"shallow").await.unwrap();
        writer.finalize().await.unwrap();

        // Extract
        let mut reader = ArchiveReader::open(&archive_path, password).await.unwrap();
        let extract_dir = temp_dir.path().join("extracted");
        let options = ExtractOptions::new(&extract_dir);
        reader.extract_all(&options).await.unwrap();

        // Verify nested file
        let deep = fs::read_to_string(extract_dir.join("a/b/c/deep.txt")).unwrap();
        assert_eq!(deep, "deep content");

        let shallow = fs::read_to_string(extract_dir.join("a/shallow.txt")).unwrap();
        assert_eq!(shallow, "shallow");
    }

    #[tokio::test]
    async fn test_verify_valid_archive() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("verify.era");
        let password = "test";

        // Create archive with multiple files (EC disabled for single-volume test)
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .config(test_config_no_ec())
            .build()
            .await
            .unwrap();

        writer
            .add_bytes("file1.txt", b"Hello, World!")
            .await
            .unwrap();
        writer
            .add_bytes("file2.txt", b"More content here")
            .await
            .unwrap();
        writer.add_bytes("binary.bin", &[0u8; 1024]).await.unwrap();
        writer.finalize().await.unwrap();

        // Verify the archive
        let mut reader = ArchiveReader::open(&archive_path, password).await.unwrap();
        let stats = reader.verify().await.unwrap();

        assert!(stats.is_ok(), "Verification should pass");
        assert!(stats.blocks_verified > 0);
        assert_eq!(stats.blocks_failed, 0);
        assert_eq!(stats.files_verified, 3);
        assert_eq!(stats.files_incomplete, 0);
        assert!(stats.errors.is_empty());
    }

    #[tokio::test]
    async fn test_verify_large_chunked_file() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("chunked.era");
        let password = "test";

        // Create archive with large file that gets chunked (EC disabled for single-volume test)
        let large_data = vec![b'A'; 512 * 1024]; // 512KB
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .config(test_config_no_ec())
            .build()
            .await
            .unwrap();

        writer.add_bytes("large.bin", &large_data).await.unwrap();
        writer.finalize().await.unwrap();

        // Verify the archive
        let mut reader = ArchiveReader::open(&archive_path, password).await.unwrap();
        let stats = reader.verify().await.unwrap();

        assert!(stats.is_ok(), "Verification should pass for chunked file");
        assert!(stats.bytes_verified > 0);
    }

    #[tokio::test]
    async fn test_verify_empty_archive() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("empty.era");
        let password = "test";

        // Create empty archive (EC disabled for single-volume test)
        let writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .config(test_config_no_ec())
            .build()
            .await
            .unwrap();
        writer.finalize().await.unwrap();

        // Verify empty archive
        let mut reader = ArchiveReader::open(&archive_path, password).await.unwrap();
        let stats = reader.verify().await.unwrap();

        assert!(stats.is_ok(), "Empty archive should verify ok");
        assert_eq!(stats.files_verified, 0);
    }

    #[test]
    fn test_max_declared_file_size_constant() {
        // Verify MAX_DECLARED_FILE_SIZE is 100GB
        assert_eq!(super::MAX_DECLARED_FILE_SIZE, 100 * 1024 * 1024 * 1024);
    }

    #[tokio::test]
    async fn test_erasure_simple_roundtrip() {
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
            .await
            .unwrap();

        writer
            .add_bytes("test.txt", b"Hello, Erasure World!")
            .await
            .unwrap();
        let stats = writer.finalize().await.unwrap();
        assert_eq!(stats.total_files, 1);

        // Extract and verify
        let mut reader = ArchiveReader::open(&archive_path, password).await.unwrap();
        let extract_dir = temp_dir.path().join("extracted");
        let options = ExtractOptions::new(&extract_dir);
        let extract_stats = reader.extract_all(&options).await.unwrap();

        assert_eq!(extract_stats.extracted, 1);

        let content = std::fs::read_to_string(extract_dir.join("test.txt")).unwrap();
        assert_eq!(content, "Hello, Erasure World!");
    }
}
