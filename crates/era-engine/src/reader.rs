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
    BlockIterator, MultiVolumeSessionBlockIterator, SessionErasureBlockIterator,
    SessionErasureBlockIteratorArgs,
};
use crate::chunk_processor::{
    enforce_output_containment, open_output_for_extract, ExtractionContext, MultiChunkState,
    VerificationContext,
};
pub use crate::chunk_processor::{ArchiveHealthStatus, ExtractStats, VerifyStats};
use bytes::Bytes;
use era_codec::ZstdCompressor;
use era_common::{
    ArchiveManifest, BlockId, BlockLocation, BlockType, ChunkHash, ChunkVec, EraError, Result,
    ShardLayout,
};
use era_crypto::certificate::EraKeyPair;
use era_crypto::{
    build_aad, AeadContext, KeySession, VolumeKey, XChaCha20Poly1305Context, NONCE_SIZE,
};
use era_index::IndexReader;
use era_ingest::{Catalog, FileEntry};
use era_packing::{SessionBlockUnpacker, SessionErasureBlockUnpacker};
use era_storage::LocalStorageBackend;
use era_volume::{DistributionCalculator, Footer, SuperHeader, VolumeReader};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};
use zeroize::Zeroize;

const INTERNAL_META_PREFIX: &str = ".era/meta/";

/// Maximum allowed file size declared in catalog (100 GB) - sanity check
const MAX_DECLARED_FILE_SIZE: u64 = 100 * 1024 * 1024 * 1024;

/// Maximum total decoded bytes accepted during one extraction pass (8 GB)
const MAX_EXTRACTION_MEMORY: u64 = 8 * 1024 * 1024 * 1024;

mod catalog_repair;
pub(crate) use catalog_repair::CatalogRepair;

const MAX_SHARD_SIZE: u64 = 256 * 1024 * 1024;
pub(crate) const MAX_CATALOG_PLAINTEXT_SIZE: u64 = 1024 * 1024 * 1024;
pub(crate) const MAX_CATALOG_CHUNKS: u32 = 128;
pub(crate) const MAX_CATALOG_CHUNK_SIZE: usize = era_volume::MAX_SHARD_SIZE / 2;
const MAX_CATALOG_SCAN_CANDIDATES: usize = 256;
const CATALOG_SCAN_WINDOW: u64 = 64 * 1024;

#[derive(Clone, Copy)]
struct CatalogBlockLocator {
    reader_idx: usize,
    offset: u64,
    expected_size: Option<u32>,
    block_id: u32,
    require_manifest: bool,
}

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
    expected_volume_count: usize,
    missing_volume_indices: Vec<usize>,
    /// Key session for per-block key derivation (mlock-protected)
    session: KeySession,
    /// Pre-derived volume key for volume 0
    volume_key: VolumeKey,
    /// Nonce context (archive salt)
    nonce_context: [u8; 16],
    archive_id: [u8; 16],
    epoch_id: u32,
    /// Compression configuration
    compression_level: i32,
    /// Compression algorithm type
    compression_algorithm: era_common::CompressionAlgorithm,
    catalog: Option<Catalog>,
    catalog_recovered_from_backup: bool,
    /// Per-volume committed end offsets loaded from the highest-sequence manifest.
    /// `None` = no manifest (v8.1 or not yet loaded).
    /// `Some(vec)` = manifest loaded successfully (v8.2).
    volume_committed_ends: Option<Vec<u64>>,
    /// The full manifest loaded from volumes (v8.2 only).
    manifest: Option<ArchiveManifest>,
    manifest_header_digests: Vec<[u8; 32]>,
    /// V2.1 index reader recovered from volume
    index_reader: Option<IndexReader>,
    embedded_index_recovery_failed: bool,
}

pub(crate) struct DiscoveredVolumes {
    pub(crate) volume_readers: Vec<VolumeReader<era_storage::LocalStorageReader>>,
    pub(crate) volume_paths: Vec<PathBuf>,
    pub(crate) volume_indices: Vec<usize>,
    pub(crate) expected_volume_count: usize,
    pub(crate) missing_volume_indices: Vec<usize>,
}

impl ArchiveReader {
    fn from_discovered(
        discovered: DiscoveredVolumes,
        session: KeySession,
        volume_key: era_crypto::VolumeKey,
        header: &era_volume::SuperHeader,
    ) -> Self {
        Self {
            volume_readers: discovered.volume_readers,
            volume_indices: discovered.volume_indices,
            expected_volume_count: discovered.expected_volume_count,
            missing_volume_indices: discovered.missing_volume_indices,
            session,
            volume_key,
            nonce_context: *header.salt(),
            archive_id: *header.archive_id().0.as_bytes(),
            epoch_id: header.epoch_id(),
            compression_level: header.config().compression.level,
            compression_algorithm: header.config().compression.algorithm,
            catalog: None,
            catalog_recovered_from_backup: false,
            volume_committed_ends: None,
            manifest: None,
            manifest_header_digests: Vec::new(),
            index_reader: None,
            embedded_index_recovery_failed: false,
        }
    }

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
    pub(crate) async fn discover_volumes(path: &Path) -> Result<DiscoveredVolumes> {
        let parent_dir = path.parent().unwrap_or(Path::new("."));
        let backend = LocalStorageBackend::new(parent_dir);
        let base_filename = path.file_name().unwrap_or_default();

        // 1. Try to open the specified file first (could be any volume)
        let first_reader = VolumeReader::open(&backend, Path::new(base_filename)).await?;

        // Read volume metadata from header (copy values before moving reader)
        let first_vol_sequence = usize::from(first_reader.header().volume_sequence());
        let opening_scan_count = first_vol_sequence.saturating_add(1);
        let mut expected_volume_count = usize::from(first_reader.header().total_volumes());
        let erasure_config = first_reader.header().config().erasure;
        let first_archive_id = first_reader.header().archive_id();

        // 2. Determine scan tolerance based on erasure configuration
        let scan_tolerance = if let Some(config) = erasure_config {
            usize::from(config.parity_shards).saturating_add(1).max(2)
        } else {
            2
        };

        // 3. Scan the promised set plus a bounded probe for newer generations.
        // A larger total from a matching sibling extends both the promise and probe.
        const MAX_SCAN: usize = 32;
        let mut scan_limit = if expected_volume_count > 0 {
            expected_volume_count
                .max(opening_scan_count)
                .saturating_add(scan_tolerance)
        } else {
            MAX_SCAN.max(opening_scan_count.saturating_add(scan_tolerance))
        };

        // 4. Build the base path for volume 0 (strip any .NNN suffix)
        let is_backup = path.extension().is_some_and(|ext| ext == "bak");
        let volume_filename = if is_backup {
            path.file_stem().unwrap_or(base_filename)
        } else {
            base_filename
        };
        let base_str = volume_filename.to_string_lossy();
        let base_path = if base_str.ends_with(".era") {
            PathBuf::from(volume_filename)
        } else {
            let s = base_str.to_string();
            if let Some(idx) = s.rfind(".era.") {
                PathBuf::from(&s[..idx + 4])
            } else {
                PathBuf::from(volume_filename)
            }
        };

        // 5. Scan for all available volumes
        let mut found_readers = Vec::new();
        let mut seen_sequences = HashSet::from([first_vol_sequence]);
        let mut missing_count: usize = 0;
        let mut first_reader_opt = Some(first_reader);
        let mut i = 0;

        while i < scan_limit {
            let mut volume_filename = base_path.as_os_str().to_os_string();
            if i != 0 {
                volume_filename.push(format!(".{:03}", i));
            }
            if is_backup {
                volume_filename.push(".bak");
            }
            let volume_path = PathBuf::from(volume_filename);

            let full_path = parent_dir.join(&volume_path);

            if i == first_vol_sequence {
                if volume_path.as_os_str() != base_filename {
                    return Err(EraError::InvalidFormat(format!(
                        "Opening volume {} does not match header sequence {}",
                        path.display(),
                        first_vol_sequence
                    )));
                }
                if let Some(reader) = first_reader_opt.take() {
                    found_readers.push((first_vol_sequence, full_path, reader));
                    missing_count = 0;
                }
                i = i.saturating_add(1);
                continue;
            }

            if !tokio::fs::try_exists(&full_path).await.unwrap_or(false) {
                missing_count = missing_count.saturating_add(1);
                if expected_volume_count == 0 && missing_count >= scan_tolerance {
                    break;
                }
                i = i.saturating_add(1);
                continue;
            }

            missing_count = 0;

            match VolumeReader::open(&backend, &volume_path).await {
                Ok(reader) => {
                    if reader.header().archive_id() == first_archive_id {
                        let vol_seq = usize::from(reader.header().volume_sequence());
                        if !seen_sequences.insert(vol_seq) {
                            return Err(EraError::InvalidFormat(format!(
                                "Duplicate volume sequence {} at {}",
                                vol_seq,
                                volume_path.display()
                            )));
                        }
                        if vol_seq != i {
                            return Err(EraError::InvalidFormat(format!(
                                "Volume {} has sequence {}, expected {}",
                                volume_path.display(),
                                vol_seq,
                                i
                            )));
                        }

                        let sibling_total = usize::from(reader.header().total_volumes());
                        if sibling_total > expected_volume_count {
                            expected_volume_count = sibling_total;
                            scan_limit =
                                scan_limit.max(sibling_total.saturating_add(scan_tolerance));
                        }
                        found_readers.push((vol_seq, full_path, reader));
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

            i = i.saturating_add(1);
        }

        if let Some(reader) = first_reader_opt {
            found_readers.push((first_vol_sequence, path.to_path_buf(), reader));
        }

        // 6. Sort by volume sequence and build final structures
        found_readers.sort_by_key(|(seq, _, _)| *seq);

        let volume_indices: Vec<usize> = found_readers.iter().map(|(seq, _, _)| *seq).collect();
        let (volume_paths, volume_readers): (Vec<_>, Vec<_>) = found_readers
            .into_iter()
            .map(|(_, path, reader)| (path, reader))
            .unzip();

        if volume_readers.is_empty() {
            return Err(EraError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No valid volumes found",
            )));
        }

        if expected_volume_count > 0 {
            let highest_found_count = volume_indices
                .last()
                .map(|seq| seq.saturating_add(1))
                .unwrap_or(0);
            expected_volume_count = expected_volume_count
                .max(opening_scan_count)
                .max(highest_found_count);
        }

        info!(
            "Opened {} volumes at sequences {:?} (total expected: {})",
            volume_readers.len(),
            volume_indices,
            if expected_volume_count > 0 {
                expected_volume_count.to_string()
            } else {
                "unknown".to_string()
            },
        );

        let missing_volume_indices = if expected_volume_count > 0 {
            let present: HashSet<usize> = volume_indices.iter().copied().collect();
            (0..expected_volume_count)
                .filter(|seq| !present.contains(seq))
                .collect()
        } else {
            Vec::new()
        };

        if !missing_volume_indices.is_empty() {
            warn!(
                "Missing expected volumes at sequences {:?} (found {} of {})",
                missing_volume_indices,
                volume_readers.len(),
                expected_volume_count
            );
        }

        Ok(DiscoveredVolumes {
            volume_readers,
            volume_paths,
            volume_indices,
            expected_volume_count,
            missing_volume_indices,
        })
    }

    pub async fn open_with_providers(
        path: &Path,
        providers: Vec<Box<dyn crate::auth::AuthProvider>>,
    ) -> Result<Self> {
        info!("Opening archive: {}", path.display());

        let discovered = Self::discover_volumes(path).await?;

        // Use first available reader for key derivation (all volumes share same crypto params)
        let volume_reader = &discovered.volume_readers[0];
        let header = volume_reader.header().clone();

        let mk_array: [u8; 32] = match header.access_policy() {
            era_volume::AccessPolicy::AnyOfN => {
                let mut master_key = None;
                'outer: for slot in header.recipients() {
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
                for slot in header.recipients() {
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
            _ => {
                return Err(EraError::InvalidConfig("Unsupported access policy".into()));
            }
        };

        // Create KeySession
        let session = KeySession::from_master_key(&mk_array)?;
        let mut mk_array = mk_array;
        mk_array.zeroize();

        // Unwrap volume key from header's encrypted envelope
        let volume_key = session.unwrap_volume_key(
            header.encrypted_volume_key().nonce(),
            header.encrypted_volume_key().ciphertext(),
        )?;

        let mut reader = Self::from_discovered(discovered, session, volume_key, &header);
        reader.load_manifest().await?;
        Ok(reader)
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

        let discovered = Self::discover_volumes(path).await?;

        let volume_reader = &discovered.volume_readers[0];
        let header = volume_reader.header().clone();

        if let era_volume::AccessPolicy::Threshold(t) = header.access_policy() {
            return Err(EraError::InvalidConfig(
                format!("Cannot open Threshold({}) archive with session — requires multi-party authentication", t),
            ));
        }

        let owned_session = session.try_clone()?;
        let volume_key = owned_session.unwrap_volume_key(
            header.encrypted_volume_key().nonce(),
            header.encrypted_volume_key().ciphertext(),
        )?;

        let mut reader = Self::from_discovered(discovered, owned_session, volume_key, &header);
        reader.load_manifest().await?;
        Ok(reader)
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
    /// let keypair = era_crypto::load_private_key_from_pem("~/.era/key.pem", Some("keypass"))?;
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

    /// Open an archive using a hybrid keypair.
    ///
    /// This unlocks archives created with `--hybrid-certificate`.
    pub async fn open_with_hybrid_keypair(
        path: &Path,
        keypair: &era_crypto::HybridKeyPair,
    ) -> Result<Self> {
        let provider = Box::new(crate::auth::HybridCertificateProvider::new(keypair.clone()));
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

    fn committed_ends_for_iterators(&self) -> Option<Vec<u64>> {
        self.volume_committed_ends.clone()
    }

    /// Returns the loaded archive manifest if available (v8.2 only).
    #[must_use]
    pub fn manifest(&self) -> Option<&ArchiveManifest> {
        self.manifest.as_ref()
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
            self.archive_id,
            self.epoch_id,
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
            self.archive_id,
            self.epoch_id,
            compressor,
        )
    }

    /// Metadata-first preflight: restore embedded index (if present) and load catalog.
    pub async fn preflight_metadata_recovery(&mut self) -> Result<()> {
        let _index_recovered = self.restore_embedded_index().await?;
        // Only warn when an index was present but recovery actually failed,
        // not when no embedded index exists (normal for older archives).
        if self.embedded_index_recovery_failed {
            warn!("Embedded index recovery failed; continuing in degraded mode");
        }
        self.load_catalog().await?;
        if self.manifest.is_none() {
            self.load_manifest().await?;
        }
        Ok(())
    }

    async fn restore_embedded_index(&mut self) -> Result<bool> {
        if self.index_reader.is_some() {
            self.embedded_index_recovery_failed = false;
            return Ok(true);
        }

        self.embedded_index_recovery_failed = false;

        // Fast path: try every V2.1 index copy recorded in a volume footer.
        let mut last_error = None;
        for reader in &self.volume_readers {
            if let Some(footer) = reader.footer() {
                if footer.has_index() {
                    match IndexReader::recover_from_volume(
                        reader,
                        &self.session,
                        &self.volume_key,
                        self.nonce_context,
                        None,
                    )
                    .await
                    {
                        Ok(index_reader) => {
                            debug!(
                                "V2.1 index recovered from volume {} footer",
                                reader.header().volume_sequence()
                            );
                            self.index_reader = Some(index_reader);
                            self.embedded_index_recovery_failed = false;
                            return Ok(true);
                        }
                        Err(e) => {
                            warn!(
                                "V2.1 index recovery failed on volume {}, trying next candidate: {}",
                                reader.header().volume_sequence(),
                                e
                            );
                            last_error = Some(e);
                        }
                    }
                }
            }
        }

        if let Some(error) = last_error {
            warn!(
                "V2.1 index recovery failed, continuing without index: {}",
                error
            );
            self.embedded_index_recovery_failed = true;
            return Ok(false);
        }

        // No footer with index found — nothing to restore
        Ok(true)
    }

    pub async fn ensure_embedded_index_recovered(&mut self) -> Result<()> {
        if self.index_reader.is_some() {
            self.embedded_index_recovery_failed = false;
            return Ok(());
        }

        let mut last_err: Option<EraError> = None;
        for reader in &self.volume_readers {
            match IndexReader::recover_from_volume(
                reader,
                &self.session,
                &self.volume_key,
                self.nonce_context,
                None,
            )
            .await
            {
                Ok(index_reader) => {
                    self.index_reader = Some(index_reader);
                    self.embedded_index_recovery_failed = false;
                    return Ok(());
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        self.embedded_index_recovery_failed = true;
        Err(last_err.unwrap_or_else(|| {
            EraError::IntegrityError("embedded index unavailable after recovery attempts".into())
        }))
    }

    pub fn embedded_index_recovery_failed(&self) -> bool {
        self.embedded_index_recovery_failed
    }

    pub fn index_reader(&self) -> Option<&IndexReader> {
        self.index_reader.as_ref()
    }

    pub fn has_embedded_index(&self) -> bool {
        self.index_reader.is_some()
    }

    pub fn catalog(&self) -> Option<&Catalog> {
        self.catalog.as_ref()
    }

    pub fn live_catalog_chunk_hashes(&self) -> Result<Vec<ChunkHash>> {
        let catalog = self
            .catalog
            .as_ref()
            .ok_or_else(|| EraError::IntegrityError("catalog unavailable".into()))?;
        let mut seen: HashSet<ChunkHash> = HashSet::new();
        for entry in &catalog.entries {
            if is_internal_entry(entry) {
                continue;
            }
            for chunk in &entry.chunks {
                seen.insert(chunk.hash);
            }
        }
        Ok(seen.into_iter().collect())
    }

    pub async fn live_data_block_ids_from_hashes_via_iterator(
        &self,
        live_hashes: &[ChunkHash],
    ) -> Result<Vec<BlockId>> {
        let lookup: HashSet<ChunkHash> = live_hashes.iter().copied().collect();
        let mut out: Vec<BlockId> = Vec::new();

        let erasure_config = self.volume_readers[0].header().config().erasure;
        let mut iter: Box<dyn BlockIterator> = if let Some(config) = erasure_config {
            let dist_strategy = self.volume_readers[0]
                .header()
                .config()
                .distribution
                .strategy;
            Box::new(SessionErasureBlockIterator::new(
                SessionErasureBlockIteratorArgs {
                    volume_readers: &self.volume_readers,
                    volume_indices: &self.volume_indices,
                    original_volume_count: self.expected_volume_count,
                    session: &self.session,
                    volume_key: &self.volume_key,
                    nonce_context: self.nonce_context,
                    archive_id: self.archive_id,
                    epoch_id: self.epoch_id,
                    compressor: self.create_compressor(),
                    data_shards: config.data_shards,
                    parity_shards: config.parity_shards,
                    distribution_strategy: dist_strategy,
                    committed_ends: self.committed_ends_for_iterators(),
                },
            )?)
        } else {
            Box::new(MultiVolumeSessionBlockIterator::new(
                &self.volume_readers,
                &self.session,
                &self.volume_key,
                self.nonce_context,
                self.archive_id,
                self.epoch_id,
                self.create_compressor(),
                self.committed_ends_for_iterators(),
            ))
        };

        while let Some(result) = iter.next_block().await {
            let decoded = result?;
            if decoded.chunks.iter().any(|(h, _)| lookup.contains(h)) {
                out.push(BlockId::new(decoded.block_index as u64));
            }
        }

        out.sort_by_key(|b| b.sequence());
        out.dedup_by_key(|b| b.sequence());
        Ok(out)
    }

    /// Get the archive header
    pub fn header(&self) -> &SuperHeader {
        self.volume_readers[0].header()
    }

    /// Get the primary volume footer (if available)
    pub fn primary_footer(&self) -> Option<&Footer> {
        self.volume_readers.first().and_then(|r| r.footer())
    }

    pub fn volume_indices(&self) -> &[usize] {
        &self.volume_indices
    }

    pub fn expected_volume_count(&self) -> usize {
        self.expected_volume_count
    }

    pub fn missing_volume_indices(&self) -> &[usize] {
        &self.missing_volume_indices
    }

    pub fn nonce_context(&self) -> [u8; 16] {
        self.nonce_context
    }

    pub fn archive_id_bytes(&self) -> [u8; 16] {
        self.archive_id
    }

    pub fn epoch_id(&self) -> u32 {
        self.epoch_id
    }

    fn classify_archive_health(&self, stats: &VerifyStats) -> ArchiveHealthStatus {
        let expected_volumes = self.expected_volume_count.max(self.volume_indices.len());
        let found_volumes = self.volume_indices.len();
        let missing_indices = self.missing_volume_indices.clone();

        if !stats.is_ok() {
            return ArchiveHealthStatus::Incomplete {
                expected_volumes,
                found_volumes,
                missing_indices,
                reason: format!(
                    "verification reported {} block failures, {} incomplete files, {} errors",
                    stats.blocks_failed,
                    stats.files_incomplete,
                    stats.errors.len()
                ),
            };
        }

        if !stats.warnings.is_empty() || !self.missing_volume_indices.is_empty() {
            return ArchiveHealthStatus::Degraded {
                expected_volumes,
                found_volumes,
                missing_indices,
            };
        }

        ArchiveHealthStatus::Healthy
    }

    fn log_verify_result(&self, stats: &VerifyStats) {
        match &stats.archive_health {
            ArchiveHealthStatus::Healthy => {
                info!(
                    "Verification passed: {} blocks, {} files, {} bytes",
                    stats.blocks_verified, stats.files_verified, stats.bytes_verified
                );
            }
            ArchiveHealthStatus::Degraded {
                expected_volumes,
                found_volumes,
                missing_indices,
            } => {
                if missing_indices.is_empty() {
                    warn!(
                        "Verification degraded: {} blocks, {} files, {} bytes",
                        stats.blocks_verified, stats.files_verified, stats.bytes_verified
                    );
                } else {
                    warn!(
                        "Verification degraded: found {} of {} expected volumes; missing sequences {:?}",
                        found_volumes, expected_volumes, missing_indices
                    );
                }
            }
            ArchiveHealthStatus::Incomplete {
                expected_volumes,
                found_volumes,
                missing_indices,
                reason,
            } => {
                info!(
                    "Verification FAILED: {} block errors, {} incomplete files, {} total errors",
                    stats.blocks_failed,
                    stats.files_incomplete,
                    stats.errors.len()
                );
                if !missing_indices.is_empty() {
                    warn!(
                        "Archive incomplete: found {} of {} expected volumes; missing sequences {:?}",
                        found_volumes, expected_volumes, missing_indices
                    );
                }
                warn!("Verification status: {}", reason);
            }
        }

        for warn_msg in &stats.warnings {
            warn!("Verify Warning: {}", warn_msg);
        }
        for err in &stats.errors {
            warn!("Verify error: {}", err);
        }
    }

    pub fn session(&self) -> &KeySession {
        &self.session
    }

    pub fn volume_key(&self) -> &VolumeKey {
        &self.volume_key
    }

    pub(crate) fn volume_readers(&self) -> &[VolumeReader<era_storage::LocalStorageReader>] {
        &self.volume_readers
    }

    pub(crate) fn manifest_header_digest(&self, sequence: u16) -> Option<&[u8; 32]> {
        self.manifest_header_digests.get(usize::from(sequence))
    }

    pub fn compression_algorithm(&self) -> era_common::CompressionAlgorithm {
        self.compression_algorithm
    }

    pub fn compression_level(&self) -> i32 {
        self.compression_level
    }

    /// Load the catalog from any available volume
    /// Each volume contains a copy of the catalog, enabling recovery from any volume
    /// Primary copies across all eligible volumes are attempted before EC backups.
    pub async fn load_catalog(&mut self) -> Result<&Catalog> {
        if let Some(ref catalog) = self.catalog {
            return Ok(catalog);
        }

        let mut catalog_candidates: Vec<usize> = Vec::new();
        for (i, reader) in self.volume_readers.iter().enumerate() {
            if let Some(footer) = reader.footer() {
                if footer.has_catalog_location() && reader.block_count() > 0 {
                    catalog_candidates.push(i);
                    debug!(
                        "Found catalog candidate in volume {} (sequence {})",
                        i,
                        reader.header().volume_sequence()
                    );
                }
            }
        }

        if catalog_candidates.is_empty() {
            debug!("No volume with valid catalog found");
            return Err(EraError::EmptyArchive);
        }

        let mut last_error: Option<EraError> = None;
        let mut backup_candidates = Vec::new();

        for reader_idx in catalog_candidates {
            let reader = &self.volume_readers[reader_idx];
            let footer = match reader.footer() {
                Some(f) => f,
                None => continue,
            };
            let primary = CatalogBlockLocator {
                reader_idx,
                offset: footer.catalog_offset(),
                expected_size: Some(footer.catalog_size()),
                block_id: footer.catalog_block_id(),
                require_manifest: false,
            };
            let erasure_enabled = reader.header().config().erasure.is_some();

            debug!(
                "Attempting to load catalog from volume {} at offset={}, size={}, block_id={}",
                reader_idx,
                primary.offset,
                primary.expected_size.unwrap_or(0),
                primary.block_id
            );

            match self.try_load_catalog_from_offset(primary).await {
                Ok(catalog) => return Ok(self.catalog.insert(catalog)),
                Err(primary_error) => {
                    warn!(
                        "Failed to load primary catalog from volume {}: {}",
                        reader_idx, primary_error
                    );
                    if !erasure_enabled {
                        last_error = Some(primary_error);
                        continue;
                    }
                    backup_candidates.push((primary, primary_error));
                }
            }
        }

        for (primary, primary_error) in backup_candidates {
            let reader_idx = primary.reader_idx;
            match self.recover_ec_catalog_backup(primary).await {
                Ok((catalog, ..)) => {
                    self.catalog_recovered_from_backup = true;
                    warn!(
                        "Catalog recovered from EC backup in volume {}; primary catalog still needs repair",
                        reader_idx
                    );
                    return Ok(self.catalog.insert(catalog));
                }
                Err(backup_error) => {
                    last_error = Some(EraError::IntegrityError(format!(
                        "Catalog primary and EC backup both failed in volume {}: primary: {}; backup: {}",
                        reader_idx, primary_error, backup_error
                    )));
                }
            }
        }

        Err(last_error.unwrap_or(EraError::EmptyArchive))
    }

    async fn try_load_catalog_from_offset(&self, locator: CatalogBlockLocator) -> Result<Catalog> {
        self.read_catalog_copy(locator)
            .await
            .map(|(catalog, _)| catalog)
    }

    async fn read_catalog_copy(&self, locator: CatalogBlockLocator) -> Result<(Catalog, Vec<u32>)> {
        let reader = self.volume_readers.get(locator.reader_idx).ok_or_else(|| {
            EraError::InvalidFormat("Catalog volume index is out of bounds".into())
        })?;
        let location = BlockLocation::single(
            reader.header().volume_id(),
            locator.block_id,
            locator.offset,
            locator.expected_size.unwrap_or(0),
        );
        let (block_type, encrypted_block) = reader.read_typed_block(&location).await?;
        if block_type != BlockType::Catalog {
            return Err(EraError::InvalidFormat(
                "Catalog candidate has a different block type".into(),
            ));
        }
        if let Some(expected_size) = locator.expected_size {
            if encrypted_block.compressed_size != expected_size {
                return Err(EraError::IntegrityError(format!(
                    "Catalog first block length {} differs from footer size {}",
                    encrypted_block.compressed_size, expected_size
                )));
            }
        }

        let unpacker = self.create_unpacker();
        let volume_index = u32::from(reader.header().volume_sequence());
        let chunks =
            unpacker.unpack_with_type(&encrypted_block, volume_index, BlockType::Catalog)?;
        match chunks.index.entries.len() {
            0 => return Err(EraError::EmptyCatalog),
            1 => {}
            _ => {
                return Err(EraError::InvalidFormat(
                    "Catalog block must contain exactly one chunk".into(),
                ));
            }
        }

        let first_entry = &chunks.index.entries[0];
        let start = usize::try_from(first_entry.offset)
            .map_err(|_| EraError::InvalidFormat("Catalog chunk offset exceeds usize".into()))?;
        let length = usize::try_from(first_entry.length)
            .map_err(|_| EraError::InvalidFormat("Catalog chunk length exceeds usize".into()))?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| EraError::InvalidFormat("Catalog chunk range overflow".into()))?;
        if end > chunks.data.len() {
            return Err(EraError::decompression(
                "Catalog chunk offset exceeds data size",
            ));
        }
        let first_chunk_data = chunks.data.slice(start..end);
        let assembly_locator = CatalogBlockLocator {
            expected_size: Some(encrypted_block.compressed_size),
            ..locator
        };
        let mut lengths = vec![encrypted_block.compressed_size];
        let catalog_data = self
            .assemble_catalog_data(assembly_locator, first_chunk_data, &mut lengths)
            .await?;

        if locator.require_manifest && self.manifest.is_none() {
            return Err(EraError::IntegrityError(
                "EC backup Catalog recovery requires an authenticated manifest".into(),
            ));
        }
        if let Some(manifest) = self.manifest.as_ref() {
            era_crypto::verify_catalog_commitment(&catalog_data, &manifest.catalog_commitment)?;
        }

        Ok((Catalog::from_bytes(&catalog_data)?, lengths))
    }

    fn catalog_metadata_end(&self, reader_idx: usize, start: u64) -> Result<u64> {
        let reader = self.volume_readers.get(reader_idx).ok_or_else(|| {
            EraError::InvalidFormat("Catalog volume index is out of bounds".into())
        })?;
        let footer = reader
            .footer()
            .ok_or_else(|| EraError::InvalidFormat("Catalog volume has no footer".into()))?;
        let mut end = footer.data_end_offset();
        for boundary in [
            footer.index_offset(),
            footer.manifest_offset(),
            footer.backup_header_offset(),
        ] {
            if boundary > start {
                end = end.min(boundary);
            }
        }
        if start >= end {
            return Err(EraError::InvalidFormat(
                "Catalog metadata range is empty or inverted".into(),
            ));
        }
        Ok(end)
    }

    async fn catalog_header_chain(
        &self,
        reader_idx: usize,
        start: u64,
        end: u64,
    ) -> Result<Vec<u64>> {
        let reader = &self.volume_readers[reader_idx];
        let max_block_size = u64::try_from(era_volume::MAX_SHARD_SIZE)
            .map_err(|_| EraError::InvalidFormat("Maximum block size exceeds u64".into()))?;
        let header_size = u64::try_from(era_common::BlockHeader::SIZE)
            .map_err(|_| EraError::InvalidFormat("Block header size exceeds u64".into()))?;
        let mut offsets = Vec::new();
        let mut offset = start;

        while offsets.len() < MAX_CATALOG_SCAN_CANDIDATES
            && offset <= end.saturating_sub(header_size)
        {
            let header_bytes = reader
                .read_raw(offset, era_common::BlockHeader::SIZE)
                .await?;
            let Some(header) = era_common::BlockHeader::from_bytes(&header_bytes) else {
                break;
            };
            if header.block_type != BlockType::Catalog || u64::from(header.length) > max_block_size
            {
                break;
            }
            let Some(block_end) = offset
                .checked_add(header_size)
                .and_then(|value| value.checked_add(u64::from(header.length)))
            else {
                break;
            };
            if block_end > end {
                break;
            }
            offsets.push(offset);
            offset = block_end;
        }

        Ok(offsets)
    }

    async fn scan_catalog_candidates(
        &self,
        reader_idx: usize,
        start: u64,
        end: u64,
    ) -> Result<Vec<u64>> {
        let reader = &self.volume_readers[reader_idx];
        let max_block_size = u64::try_from(era_volume::MAX_SHARD_SIZE)
            .map_err(|_| EraError::InvalidFormat("Maximum block size exceeds u64".into()))?;
        let header_size = u64::try_from(era_common::BlockHeader::SIZE)
            .map_err(|_| EraError::InvalidFormat("Block header size exceeds u64".into()))?;
        let mut candidates = Vec::new();
        let mut window_start = start;

        while window_start <= end.saturating_sub(header_size) {
            let read_len =
                usize::try_from((end - window_start).min(CATALOG_SCAN_WINDOW + header_size - 1))
                    .map_err(|_| {
                        EraError::InvalidFormat("Catalog scan window exceeds usize".into())
                    })?;
            let bytes = reader.read_raw(window_start, read_len).await?;
            if bytes.len() < era_common::BlockHeader::SIZE {
                break;
            }

            for relative in 0..=bytes.len() - era_common::BlockHeader::SIZE {
                let relative_u64 = u64::try_from(relative).map_err(|_| {
                    EraError::InvalidFormat("Catalog scan offset exceeds u64".into())
                })?;
                let offset = window_start + relative_u64;
                if offset > end.saturating_sub(header_size) {
                    break;
                }
                let Some(header) = era_common::BlockHeader::from_bytes(
                    &bytes[relative..relative + era_common::BlockHeader::SIZE],
                ) else {
                    continue;
                };
                if header.block_type != BlockType::Catalog
                    || u64::from(header.length) > max_block_size
                    || candidates.last().is_some_and(|last| *last >= offset)
                {
                    continue;
                }
                let Some(data_offset) = offset.checked_add(header_size) else {
                    continue;
                };
                let Some(block_end) = data_offset.checked_add(u64::from(header.length)) else {
                    continue;
                };
                if block_end > end {
                    continue;
                }

                let payload = reader
                    .read_raw(
                        data_offset,
                        usize::try_from(header.length).map_err(|_| {
                            EraError::InvalidFormat("Catalog block length exceeds usize".into())
                        })?,
                    )
                    .await?;
                if header.verify(&payload) {
                    if candidates.len() >= MAX_CATALOG_SCAN_CANDIDATES {
                        return Err(EraError::IntegrityError(
                            "Catalog scan exceeded its candidate bound".into(),
                        ));
                    }
                    candidates.push(offset);
                }
            }

            window_start = window_start
                .checked_add(CATALOG_SCAN_WINDOW.min(end - window_start))
                .ok_or_else(|| EraError::InvalidFormat("Catalog scan offset overflow".into()))?;
        }

        Ok(candidates)
    }

    async fn recover_ec_catalog_backup(
        &self,
        primary: CatalogBlockLocator,
    ) -> Result<(Catalog, CatalogBlockLocator, Vec<u32>)> {
        if self.manifest.is_none() {
            return Err(EraError::IntegrityError(
                "EC backup Catalog recovery requires an authenticated manifest".into(),
            ));
        }
        let metadata_end = self.catalog_metadata_end(primary.reader_idx, primary.offset)?;
        let mut last_error =
            EraError::IntegrityError("No EC backup Catalog candidate found".into());

        let chain = self
            .catalog_header_chain(primary.reader_idx, primary.offset, metadata_end)
            .await?;
        for (ordinal, offset) in chain.iter().copied().enumerate().skip(1) {
            let chunk_count = u32::try_from(ordinal)
                .map_err(|_| EraError::InvalidFormat("Catalog chunk count exceeds u32".into()))?;
            let Some(block_id) = primary.block_id.checked_add(chunk_count) else {
                continue;
            };
            let candidate = CatalogBlockLocator {
                reader_idx: primary.reader_idx,
                offset,
                expected_size: None,
                block_id,
                require_manifest: true,
            };
            match self.read_catalog_copy(candidate).await {
                Ok((catalog, lengths)) => return Ok((catalog, candidate, lengths)),
                Err(error) => last_error = error,
            }
        }

        let candidates = self
            .scan_catalog_candidates(primary.reader_idx, primary.offset, metadata_end)
            .await?;
        let max_chunks = u32::try_from(candidates.len())
            .unwrap_or(MAX_CATALOG_CHUNKS)
            .min(MAX_CATALOG_CHUNKS);
        for chunk_count in 1..=max_chunks {
            let suffix_index = candidates.len()
                - usize::try_from(chunk_count).map_err(|_| {
                    EraError::InvalidFormat("Catalog chunk count exceeds usize".into())
                })?;
            let offset = candidates[suffix_index];
            if offset <= primary.offset {
                continue;
            }
            let Some(block_id) = primary.block_id.checked_add(chunk_count) else {
                continue;
            };
            let candidate = CatalogBlockLocator {
                reader_idx: primary.reader_idx,
                offset,
                expected_size: None,
                block_id,
                require_manifest: true,
            };
            match self.read_catalog_copy(candidate).await {
                Ok((catalog, lengths)) => return Ok((catalog, candidate, lengths)),
                Err(error) => last_error = error,
            }
        }

        Err(last_error)
    }

    async fn load_manifest(&mut self) -> Result<()> {
        let mut best_manifest: Option<ArchiveManifest> = None;
        let mut best_header_digests = Vec::new();
        let mut any_volume_has_manifest = false;

        for i in 0..self.volume_readers.len() {
            let reader = &self.volume_readers[i];
            let footer = match reader.footer() {
                Some(f) => f,
                None => continue,
            };

            if !footer.has_manifest() {
                continue;
            }
            any_volume_has_manifest = true;

            let manifest_offset = footer.manifest_offset();
            let manifest_block_id = footer.manifest_block_id();
            let volume_id = reader.header().volume_id();
            let volume_sequence = reader.header().volume_sequence();

            let manifest_location =
                BlockLocation::single(volume_id, manifest_block_id, manifest_offset, 0);

            let encrypted_block = match self.volume_readers[i].read_block(&manifest_location).await
            {
                Ok(block) => block,
                Err(e) => {
                    warn!("Failed to read manifest from volume {}: {}", i, e);
                    continue;
                }
            };

            let block_key = match self.session.derive_block_key(
                &self.volume_key,
                manifest_block_id as u64,
                &self.nonce_context,
            ) {
                Ok(bk) => bk,
                Err(e) => {
                    warn!("Failed to derive block key: {}", e);
                    continue;
                }
            };
            let derived_key = match block_key.to_derived_key() {
                Ok(dk) => dk,
                Err(e) => {
                    warn!("Failed to derive key: {}", e);
                    continue;
                }
            };
            let aead_ctx = match XChaCha20Poly1305Context::from_derived_key(&derived_key) {
                Ok(ctx) => ctx,
                Err(e) => {
                    warn!("Failed to create AEAD context: {}", e);
                    continue;
                }
            };

            let nonce_slice = match encrypted_block.data.get(..NONCE_SIZE) {
                Some(n) => n,
                None => {
                    warn!("Manifest nonce too short");
                    continue;
                }
            };
            let nonce_bytes: [u8; NONCE_SIZE] = match nonce_slice.try_into() {
                Ok(n) => n,
                Err(_) => {
                    warn!("Manifest nonce too short");
                    continue;
                }
            };
            let ciphertext = match encrypted_block.data.get(NONCE_SIZE..) {
                Some(c) => c,
                None => {
                    warn!("Manifest ciphertext missing");
                    continue;
                }
            };
            let aad = build_aad(
                &self.archive_id,
                self.epoch_id,
                BlockType::Manifest,
                u32::from(volume_sequence),
                BlockId::new(manifest_block_id as u64),
            );

            let decrypted = match aead_ctx.decrypt(&nonce_bytes, &aad, ciphertext) {
                Ok(d) => d,
                Err(e) => {
                    warn!("Failed to decrypt manifest: {}", e);
                    continue;
                }
            };

            let (manifest, digests) =
                match ArchiveManifest::from_bytes_with_header_digests(&decrypted) {
                    Ok(m) => m,
                    Err(e) => {
                        warn!("Failed to deserialize manifest from volume {}: {}", i, e);
                        continue;
                    }
                };

            if !digests.by_sequence.is_empty()
                && (manifest.epoch_id != self.epoch_id
                    || digests.by_sequence.len() != self.expected_volume_count
                    || digests.by_sequence.get(usize::from(volume_sequence))
                        != digests.local.as_ref())
            {
                return Err(EraError::IntegrityError(
                    "Manifest header digest table does not match its volume context".into(),
                ));
            }

            let dominated = best_manifest
                .as_ref()
                .is_some_and(|best| best.finalize_sequence >= manifest.finalize_sequence);
            if !dominated {
                best_manifest = Some(manifest);
                best_header_digests = digests.by_sequence;
            }
        }

        if let Some(manifest) = best_manifest {
            let ends = &manifest.volume_committed_ends;
            if !ends.is_empty() && ends.len() != self.expected_volume_count {
                return Err(EraError::InvalidFormat(format!(
                    "Manifest volume_committed_ends count ({}) != expected volume count ({})",
                    ends.len(),
                    self.expected_volume_count,
                )));
            }
            let finalize_sequence = manifest.finalize_sequence;
            let volume_committed_ends = manifest.volume_committed_ends.clone();
            self.volume_committed_ends = Some(volume_committed_ends.clone());
            self.manifest = Some(manifest);
            self.manifest_header_digests = best_header_digests;
            debug!(
                "Loaded manifest: finalize_sequence={}, volume_committed_ends={:?}",
                finalize_sequence, volume_committed_ends
            );
        } else if any_volume_has_manifest {
            return Err(EraError::IntegrityError(
                "Archive declares manifest but manifest cannot be loaded".into(),
            ));
        } else {
            debug!("No manifest found in any volume (backward compat v8.1)");
        }

        Ok(())
    }

    async fn assemble_catalog_data(
        &self,
        locator: CatalogBlockLocator,
        first_chunk_data: bytes::Bytes,
        lengths: &mut Vec<u32>,
    ) -> Result<Vec<u8>> {
        if first_chunk_data.len() < 12 {
            return Ok(first_chunk_data.to_vec());
        }

        let chunk_count = u32::from_le_bytes(
            first_chunk_data[0..4]
                .try_into()
                .map_err(|_| EraError::InvalidFormat("Catalog chunk count is invalid".into()))?,
        );
        let total_len = u64::from_le_bytes(
            first_chunk_data[4..12]
                .try_into()
                .map_err(|_| EraError::InvalidFormat("Catalog total length is invalid".into()))?,
        );

        if chunk_count <= 1 || total_len == 0 {
            let stripped = first_chunk_data.slice(12..);
            if Catalog::from_bytes(&stripped).is_ok() {
                return Ok(stripped.to_vec());
            }
            return Ok(first_chunk_data.to_vec());
        }
        if chunk_count > MAX_CATALOG_CHUNKS || total_len > MAX_CATALOG_PLAINTEXT_SIZE {
            return Err(EraError::InvalidFormat(
                "Catalog framing exceeds its chunk or plaintext bound".into(),
            ));
        }

        // The authenticated first payload gives the width used by the writer.
        // Legacy writers used the maximum width; capped writers can use less.
        let first_payload = &first_chunk_data[12..];
        if first_payload.is_empty() || first_payload.len() > MAX_CATALOG_CHUNK_SIZE {
            return Err(EraError::InvalidFormat(
                "Catalog first chunk has an invalid payload length".into(),
            ));
        }
        let capacity = usize::try_from(total_len)
            .map_err(|_| EraError::InvalidFormat("Catalog total length exceeds usize".into()))?;
        let expected_chunks = capacity.div_ceil(first_payload.len());
        let expected_chunks = u32::try_from(expected_chunks)
            .map_err(|_| EraError::InvalidFormat("Catalog chunk count exceeds u32".into()))?;
        if chunk_count != expected_chunks {
            return Err(EraError::InvalidFormat(format!(
                "Catalog chunk count {} does not match total length {}",
                chunk_count, total_len
            )));
        }

        let reader = self.volume_readers.get(locator.reader_idx).ok_or_else(|| {
            EraError::InvalidFormat("Catalog volume index is out of bounds".into())
        })?;
        let metadata_end = self.catalog_metadata_end(locator.reader_idx, locator.offset)?;
        let header_size = u64::try_from(era_common::BlockHeader::SIZE)
            .map_err(|_| EraError::InvalidFormat("Block header size exceeds u64".into()))?;
        let available_span = metadata_end - locator.offset;
        if u64::from(chunk_count) > available_span / header_size {
            return Err(EraError::InvalidFormat(
                "Catalog chunk count exceeds its metadata span".into(),
            ));
        }

        debug!(
            "Multi-block catalog: {} blocks, {} total bytes",
            chunk_count, total_len
        );
        let mut catalog_buf = Vec::with_capacity(capacity);
        catalog_buf.extend_from_slice(first_payload);

        let first_size = locator.expected_size.ok_or_else(|| {
            EraError::InvalidFormat("Catalog first block length is unavailable".into())
        })?;
        let mut next_offset = locator
            .offset
            .checked_add(header_size)
            .and_then(|value| value.checked_add(u64::from(first_size)))
            .ok_or_else(|| EraError::InvalidFormat("Catalog offset overflow".into()))?;

        for block_num in 1..chunk_count {
            if next_offset > metadata_end.saturating_sub(header_size) {
                return Err(EraError::IntegrityError(
                    "Catalog continuation exceeds its metadata range".into(),
                ));
            }
            let header_bytes = reader
                .read_raw(next_offset, era_common::BlockHeader::SIZE)
                .await?;
            let header = era_common::BlockHeader::from_bytes(&header_bytes).ok_or_else(|| {
                EraError::CorruptedHeader(format!(
                    "Invalid catalog block header at offset {} (block {}/{})",
                    next_offset, block_num, chunk_count
                ))
            })?;
            if header.block_type != BlockType::Catalog {
                return Err(EraError::IntegrityError(format!(
                    "Catalog continuation block {} has a different block type",
                    block_num
                )));
            }
            let block_end = next_offset
                .checked_add(header_size)
                .and_then(|value| value.checked_add(u64::from(header.length)))
                .ok_or_else(|| EraError::InvalidFormat("Catalog block offset overflow".into()))?;
            if block_end > metadata_end {
                return Err(EraError::IntegrityError(
                    "Catalog continuation block exceeds its metadata range".into(),
                ));
            }

            let next_block_id = locator.block_id.checked_add(block_num).ok_or_else(|| {
                EraError::InvalidFormat("Catalog continuation block ID overflow".into())
            })?;
            let block_location = BlockLocation::single(
                reader.header().volume_id(),
                next_block_id,
                next_offset,
                header.length,
            );
            let (block_type, enc_block) = reader.read_typed_block(&block_location).await?;
            if block_type != BlockType::Catalog {
                return Err(EraError::IntegrityError(
                    "Catalog continuation type changed during read".into(),
                ));
            }
            lengths.push(header.length);

            let block_unpacker = self.create_unpacker();
            let volume_index = u32::from(reader.header().volume_sequence());
            let block_chunks =
                block_unpacker.unpack_with_type(&enc_block, volume_index, BlockType::Catalog)?;
            if block_chunks.index.entries.len() != 1 {
                return Err(EraError::IntegrityError(format!(
                    "Catalog continuation block {} must contain exactly one chunk",
                    block_num
                )));
            }
            let entry = &block_chunks.index.entries[0];
            let start = usize::try_from(entry.offset).map_err(|_| {
                EraError::InvalidFormat("Catalog continuation offset exceeds usize".into())
            })?;
            let length = usize::try_from(entry.length).map_err(|_| {
                EraError::InvalidFormat("Catalog continuation length exceeds usize".into())
            })?;
            let end = start.checked_add(length).ok_or_else(|| {
                EraError::InvalidFormat("Catalog continuation chunk range overflow".into())
            })?;
            if end > block_chunks.data.len() {
                return Err(EraError::IntegrityError(format!(
                    "Catalog continuation block {} chunk bounds exceed data: {} > {}",
                    block_num,
                    end,
                    block_chunks.data.len()
                )));
            }
            let expected_len = first_payload.len().min(capacity - catalog_buf.len());
            if length != expected_len {
                return Err(EraError::IntegrityError(
                    "Catalog continuation length does not match framing".into(),
                ));
            }
            catalog_buf.extend_from_slice(&block_chunks.data[start..end]);
            next_offset = block_end;
        }

        Ok(catalog_buf)
    }

    fn check_read_bound(&self, volume_sequence: u16, offset: u64, read_len: u64) -> Result<()> {
        let committed_ends = match &self.volume_committed_ends {
            None => {
                // v8.1 archive (no manifest) - allow reads without bounds
                return Ok(());
            }
            Some(ends) if ends.is_empty() => {
                // v8.2 archive with empty committed_ends = format error (fail-closed)
                return Err(EraError::InvalidFormat(
                    "v8.2 archive with empty volume_committed_ends".into(),
                ));
            }
            Some(ends) => ends,
        };

        let committed_end = committed_ends
            .get(volume_sequence as usize)
            .ok_or_else(|| {
                EraError::InvalidFormat(format!(
                    "Missing committed end for volume sequence {}",
                    volume_sequence
                ))
            })?;
        let read_end = offset.checked_add(read_len).ok_or_else(|| {
            EraError::InvalidFormat(format!(
                "Read bound overflow for volume sequence {}",
                volume_sequence
            ))
        })?;

        if read_end > *committed_end {
            return Err(EraError::IntegrityError(format!(
                "Read beyond committed end for volume {}: range {}..{} exceeds {}",
                volume_sequence, offset, read_end, committed_end
            )));
        }

        Ok(())
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

            // 1. Identify which shard *this* block is (my_shard_idx).
            // Heuristic rationale: slot_index tracks the logical data slot. Mapping it
            // modulo data_shards identifies this block's local shard position so we can
            // align neighbor metadata (shard_offsets/shard_volumes) around it.
            if erasure_info.data_shards == 0 {
                return Err(EraError::InvalidFormat(
                    "Erasure block has zero data_shards".into(),
                ));
            }
            let my_shard_idx = (location.slot_index as usize) % (erasure_info.data_shards as usize);
            if my_shard_idx >= total_shards {
                tracing::warn!(
                    "Computed my_shard_idx={} out of range total_shards={} (slot_index={})",
                    my_shard_idx,
                    total_shards,
                    location.slot_index
                );
            }

            let get_reader_index = |shard_idx: usize| -> Option<usize> {
                if shard_idx == my_shard_idx {
                    // This is the current block's volume.
                    // We need to find the reader that matches location.volume_id
                    // iterating explicitly is safest because volume_readers might not be sorted/complete
                    for (i, r) in self.volume_readers.iter().enumerate() {
                        if r.header().volume_id() == location.volume_id {
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
                            if r.header().volume_sequence() as usize == seq as usize {
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

                    let shard_reader = &self.volume_readers[vol_idx];
                    match self
                        .read_shard(shard_reader, offset, erasure_info.shard_size)
                        .await
                    {
                        Ok(shard) => {
                            available_shards.push((shard_idx, shard));
                        }
                        Err(err) => {
                            tracing::warn!("Shard read error for shard {}: {}", shard_idx, err);
                        }
                    }
                }
            }

            let block_id = BlockId::new(location.slot_index as u64);
            // Create temporary session-based erasure unpacker
            let erasure_unpacker = self.create_erasure_unpacker();
            let volume_index = if let Some(reader) = self
                .volume_readers
                .iter()
                .find(|r| r.header().volume_id() == location.volume_id)
            {
                u32::from(reader.header().volume_sequence())
            } else {
                let config = self.header().config();
                let strategy = config.distribution.strategy;
                let geometry = crate::erasure_scan::MatrixScanGeometry::new(
                    config,
                    self.expected_volume_count,
                    &self.volume_indices,
                    strategy,
                )?;
                let configured_width = geometry.generation_width();
                let global_stripe =
                    u64::from(location.slot_index / u32::from(erasure_info.data_shards));
                let generation_for_width = |width: usize| -> Result<Option<usize>> {
                    let mut generation_start = None;
                    for sibling_shard in (0..total_shards).filter(|&idx| idx != my_shard_idx) {
                        let sibling_idx = if sibling_shard < my_shard_idx {
                            sibling_shard
                        } else {
                            sibling_shard - 1
                        };
                        let sibling_sequence =
                            usize::from(*shard_volumes.get(sibling_idx).ok_or_else(|| {
                                EraError::InvalidFormat(
                                    "Missing sibling volume for erasure geometry".into(),
                                )
                            })?);
                        let sibling_slot =
                            strategy.calculate_volume(sibling_shard, global_stripe, width)?;
                        if sibling_sequence % width != sibling_slot {
                            return Ok(None);
                        }
                        let sibling_generation = sibling_sequence - sibling_slot;
                        if generation_start.is_some_and(|start| start != sibling_generation) {
                            return Ok(None);
                        }
                        generation_start = Some(sibling_generation);
                    }
                    Ok(generation_start)
                };
                let (width, generation_start) =
                    if let Some(generation) = generation_for_width(configured_width)? {
                        (configured_width, generation)
                    } else {
                        let legacy_width = self.expected_volume_count;
                        if legacy_width <= configured_width {
                            return Err(EraError::InvalidFormat(
                                "Sibling volumes do not match configured erasure geometry".into(),
                            ));
                        }
                        let generation = generation_for_width(legacy_width)?.ok_or_else(|| {
                            EraError::InvalidFormat(
                                "Sibling volumes do not match legacy erasure geometry".into(),
                            )
                        })?;
                        (legacy_width, generation)
                    };
                let target_slot = strategy.calculate_volume(my_shard_idx, global_stripe, width)?;
                let target_sequence = generation_start
                    .checked_add(target_slot)
                    .ok_or_else(|| EraError::InvalidFormat("Volume sequence overflow".into()))?;
                if target_sequence >= self.expected_volume_count {
                    return Err(EraError::InvalidFormat(
                        "Inferred volume sequence exceeds archive volume count".into(),
                    ));
                }
                u32::try_from(target_sequence)
                    .map_err(|_| EraError::InvalidFormat("Volume sequence exceeds u32".into()))?
            };
            erasure_unpacker.decode_and_extract_all_for_shard(
                available_shards,
                erasure_info,
                block_id,
                my_shard_idx,
                volume_index,
            )
        } else {
            // Standard block: read and unpack directly with session-based unpacker
            let reader = self
                .volume_readers
                .iter()
                .find(|r| r.header().volume_id() == location.volume_id)
                .unwrap_or(&self.volume_readers[0]);
            let volume_sequence = reader.header().volume_sequence();
            self.check_read_bound(
                volume_sequence,
                location.physical_offset,
                u64::from(location.encrypted_size) + era_common::BlockHeader::SIZE as u64,
            )?;
            let encrypted_block = reader.read_block(location).await?;
            let unpacker = self.create_unpacker();
            let unpacked = unpacker.unpack(&encrypted_block, 0)?;

            // Extract all chunks using consolidated helpers
            era_packing::extract_all_chunks(&unpacked.index, &unpacked.data)
        }
    }

    async fn read_shard<R: era_storage::StorageReader>(
        &self,
        reader: &VolumeReader<R>,
        offset: u64,
        stripe_shard_size: u32,
    ) -> Result<Bytes> {
        let volume_sequence = reader.header().volume_sequence();
        self.check_read_bound(
            volume_sequence,
            offset,
            era_common::ShardHeader::SIZE as u64,
        )?;
        let header_bytes = reader
            .read_raw(offset, era_common::ShardHeader::SIZE)
            .await?;
        if let Some(header) = era_common::ShardHeader::from_bytes(&header_bytes) {
            let shard_len = usize::try_from(header.length)
                .map_err(|_| EraError::InvalidFormat("Shard length exceeds usize".into()))?;
            let shard_limit = u64::from(stripe_shard_size).min(MAX_SHARD_SIZE);
            if u64::from(header.length) > shard_limit {
                return Err(EraError::ShardTooLarge {
                    size: shard_len,
                    max_size: usize::try_from(shard_limit).map_err(|_| {
                        EraError::InvalidFormat("Shard size limit exceeds usize".into())
                    })?,
                });
            }
            self.check_read_bound(
                volume_sequence,
                offset,
                u64::from(header.length) + era_common::ShardHeader::SIZE as u64,
            )?;
            let data = reader
                .read_raw(offset + era_common::ShardHeader::SIZE as u64, shard_len)
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
        let mut tracked_output_files: Vec<PathBuf> = Vec::new();
        let mut cumulative_bytes_extracted: u64 = 0;

        let output_dir = options.output_dir.clone();
        if let Err(err) = tokio::task::spawn_blocking(move || fs::create_dir_all(output_dir))
            .await
            .map_err(|e| EraError::Other(format!("Failed to join output dir creation task: {}", e)))
            .and_then(|res| res.map_err(EraError::Io))
        {
            return Self::fail_extraction_with_cleanup(err, &tracked_output_files).await;
        }

        let output_dir = options.output_dir.clone();
        let canonical_output_dir =
            match tokio::task::spawn_blocking(move || fs::canonicalize(output_dir))
                .await
                .map_err(|e| {
                    EraError::Other(format!(
                        "Failed to join output canonicalization task: {}",
                        e
                    ))
                })
                .and_then(|res| res.map_err(EraError::Io))
            {
                Ok(path) => path,
                Err(err) => {
                    return Self::fail_extraction_with_cleanup(err, &tracked_output_files).await
                }
            };

        // Build maps for extraction
        let mut context = ExtractionContext::new();
        context.set_canonical_output_dir(canonical_output_dir.clone());
        context.set_overwrite(options.overwrite);

        let normalize_target = |path: &Path| -> PathBuf {
            path.components()
                .filter(|c| !matches!(c, std::path::Component::CurDir))
                .collect()
        };
        let mut target_winners: HashMap<PathBuf, usize> = HashMap::new();
        let mut metadata_candidates: Vec<FileEntry> = Vec::new();
        for (file_idx, entry) in catalog.entries.iter().enumerate() {
            if is_internal_entry(entry) {
                continue;
            }
            let target_key = normalize_target(&options.output_dir.join(&entry.path));
            if options.overwrite {
                target_winners.insert(target_key, file_idx);
            } else {
                target_winners.entry(target_key).or_insert(file_idx);
            }
        }

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
                            return Self::fail_extraction_with_cleanup(
                                EraError::Security(format!(
                                    "Path traversal detected: {}",
                                    rel.display()
                                )),
                                &tracked_output_files,
                            )
                            .await;
                        }
                        std::path::Component::RootDir => {
                            return Self::fail_extraction_with_cleanup(
                                EraError::Security(format!(
                                    "Absolute path in archive entry: {}",
                                    rel.display()
                                )),
                                &tracked_output_files,
                            )
                            .await;
                        }
                        _ => {}
                    }
                }
            }

            let target_key = normalize_target(&output_path);
            if target_winners.get(&target_key) != Some(&file_idx) {
                debug!("Skipping superseded file: {}", output_path.display());
                stats.skipped += 1;
                continue;
            }

            let already_exists = tokio::fs::try_exists(&output_path).await.unwrap_or(false)
                || tokio::fs::symlink_metadata(&output_path).await.is_ok();
            if already_exists && !options.overwrite {
                debug!("Skipping existing file: {}", output_path.display());
                stats.skipped += 1;
                continue;
            }

            if entry.size > MAX_DECLARED_FILE_SIZE {
                return Self::fail_extraction_with_cleanup(
                    EraError::CorruptedHeader(format!(
                        "File '{}' declares unreasonable size: {} bytes",
                        entry.path.display(),
                        entry.size
                    )),
                    &tracked_output_files,
                )
                .await;
            }

            if entry.is_chunked() {
                let chunk_count = entry.chunks.len();

                // Check if this is a packed chunk (single chunk with packed_info)
                let is_packed = chunk_count == 1 && entry.chunks[0].packed_info.is_some();

                if is_packed {
                    // Packed chunk: handle like single-chunk file
                    let chunk_ref = &entry.chunks[0];
                    let packed_info = match chunk_ref.packed_info.as_ref() {
                        Some(info) => info,
                        None => {
                            return Self::fail_extraction_with_cleanup(
                                EraError::IntegrityError(
                                    "packed_info missing for packed chunk".into(),
                                ),
                                &tracked_output_files,
                            )
                            .await;
                        }
                    };

                    context
                        .packed_chunks
                        .entry(chunk_ref.hash)
                        .or_default()
                        .push((file_idx, packed_info.file_index, output_path));
                } else {
                    // Normal multi-chunk file: pre-create file
                    let output_path_for_create = output_path.clone();
                    let expected_size = entry.size;
                    let canonical_output_dir_for_create = canonical_output_dir.clone();
                    let overwrite = options.overwrite;
                    let file =
                        match tokio::task::spawn_blocking(move || -> std::io::Result<File> {
                            enforce_output_containment(
                                &output_path_for_create,
                                &canonical_output_dir_for_create,
                            )
                            .map_err(|e| std::io::Error::other(e.to_string()))?;
                            let file = open_output_for_extract(&output_path_for_create, overwrite)?;
                            if let Err(err) = file.set_len(expected_size) {
                                drop(file);
                                let _ = std::fs::remove_file(&output_path_for_create);
                                return Err(err);
                            }
                            Ok(file)
                        })
                        .await
                        .map_err(|e| {
                            EraError::Other(format!("Failed to join file creation task: {}", e))
                        })
                        .and_then(|res| res.map_err(EraError::Io))
                        {
                            Ok(file) => {
                                tracked_output_files.push(output_path.clone());
                                file
                            }
                            Err(err) => {
                                return Self::fail_extraction_with_cleanup(
                                    err,
                                    &tracked_output_files,
                                )
                                .await;
                            }
                        };

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
            if entry.file_type == era_ingest::FileType::File {
                metadata_candidates.push(entry.clone());
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
                    let block_bytes = decoded
                        .chunks
                        .iter()
                        .try_fold(0u64, |acc, (_, chunk_data)| {
                            acc.checked_add(chunk_data.len() as u64)
                        });

                    let block_bytes = match block_bytes {
                        Some(v) => v,
                        None => {
                            return Self::fail_extraction_with_context(
                                EraError::Security(
                                    "Extraction memory budget exceeded: possible decompression bomb"
                                        .to_string(),
                                ),
                                &tracked_output_files,
                                &context,
                            )
                            .await;
                        }
                    };

                    cumulative_bytes_extracted = match cumulative_bytes_extracted
                        .checked_add(block_bytes)
                    {
                        Some(v) => v,
                        None => {
                            return Self::fail_extraction_with_context(
                                    EraError::Security(
                                        "Extraction memory budget exceeded: possible decompression bomb"
                                            .to_string(),
                                    ),
                                    &tracked_output_files,
                                    &context,
                                )
                                .await;
                        }
                    };

                    if cumulative_bytes_extracted > MAX_EXTRACTION_MEMORY {
                        return Self::fail_extraction_with_context(
                            EraError::Security(
                                "Extraction memory budget exceeded: possible decompression bomb"
                                    .to_string(),
                            ),
                            &tracked_output_files,
                            &context,
                        )
                        .await;
                    }

                    if let Err(err) = context.process_chunks(decoded.chunks, &mut stats) {
                        return Self::fail_extraction_with_context(
                            err,
                            &tracked_output_files,
                            &context,
                        )
                        .await;
                    }
                }
                Err(e) => {
                    if matches!(&e, EraError::ShardTooLarge { .. }) {
                        return Self::fail_extraction_with_context(
                            e,
                            &tracked_output_files,
                            &context,
                        )
                        .await;
                    }
                    consecutive_failures += 1;
                    if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                        return Self::fail_extraction_with_context(
                            EraError::Security(format!(
                                "Aborting: {} consecutive block failures: {}",
                                consecutive_failures, e
                            )),
                            &tracked_output_files,
                            &context,
                        )
                        .await;
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
            return Self::fail_extraction_with_context(
                EraError::ErasureError(
                    "Not enough shards for recovery: extraction incomplete due to \
                     too many missing or corrupted volumes."
                        .into(),
                ),
                &tracked_output_files,
                &context,
            )
            .await;
        }

        info!(
            "Extraction complete: {} files, {} bytes",
            stats.extracted, stats.bytes_written
        );

        Self::apply_extracted_metadata(
            metadata_candidates,
            &options.output_dir,
            &stats.extracted_paths,
        )
        .await;

        Ok(stats)
    }

    async fn apply_extracted_metadata(
        entries: Vec<FileEntry>,
        output_dir: &Path,
        extracted_paths: &[PathBuf],
    ) {
        let output_dir = output_dir.to_path_buf();
        let extracted_set: std::collections::HashSet<PathBuf> =
            extracted_paths.iter().cloned().collect();

        if let Err(e) = tokio::task::spawn_blocking(move || {
            for entry in &entries {
                let expected_path = output_dir.join(&entry.path);
                if !extracted_set.contains(&expected_path) {
                    continue;
                }
                let output_path = expected_path;

                // Restore mtime and xattrs BEFORE permissions, because a read-only
                // mode (e.g. 0444) would prevent subsequent write operations.
                if let Some(mtime_secs) = entry.mtime {
                    let target_time = std::time::SystemTime::UNIX_EPOCH
                        + std::time::Duration::from_secs(mtime_secs);
                    match std::fs::File::options().write(true).open(&output_path) {
                        Ok(file) => {
                            let times = std::fs::FileTimes::new().set_modified(target_time);
                            if let Err(e) = file.set_times(times) {
                                warn!(
                                    "Failed to restore mtime for {}: {}",
                                    output_path.display(),
                                    e
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Failed to open file for mtime restoration {}: {}",
                                output_path.display(),
                                e
                            );
                        }
                    }
                }

                #[cfg(unix)]
                {
                    for (key, value) in &entry.xattrs {
                        if let Err(e) = xattr::set(&output_path, key, value) {
                            warn!(
                                "Failed to restore xattr {} for {}: {}",
                                key,
                                output_path.display(),
                                e
                            );
                        }
                    }
                }

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = entry.permissions & 0o777;
                    if mode != 0 {
                        let perms = std::fs::Permissions::from_mode(mode);
                        if let Err(e) = std::fs::set_permissions(&output_path, perms) {
                            warn!(
                                "Failed to restore permissions for {}: {}",
                                output_path.display(),
                                e
                            );
                        }
                    }
                }
            }
        })
        .await
        {
            warn!("Metadata restoration task failed: {}", e);
        }
    }

    async fn cleanup_partial_files(paths: &[PathBuf]) -> Result<()> {
        let mut unique_paths: Vec<PathBuf> = Vec::new();
        for path in paths {
            if !unique_paths.iter().any(|p| p == path) {
                unique_paths.push(path.clone());
            }
        }

        tokio::task::spawn_blocking(move || {
            for path in unique_paths.into_iter().rev() {
                if let Err(err) = std::fs::remove_file(&path) {
                    if err.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(
                            "Failed to clean up partial extracted file {}: {}",
                            path.display(),
                            err
                        );
                    }
                }
            }
        })
        .await
        .map_err(|e| EraError::Other(format!("Failed to join extraction cleanup task: {}", e)))?;

        Ok(())
    }

    async fn fail_extraction_with_cleanup(
        err: EraError,
        paths: &[PathBuf],
    ) -> Result<ExtractStats> {
        if !paths.is_empty() {
            if let Err(cleanup_err) = Self::cleanup_partial_files(paths).await {
                tracing::warn!(
                    "Partial extraction cleanup encountered an error: {}",
                    cleanup_err
                );
            }
        }
        Err(err)
    }

    async fn fail_extraction_with_context(
        err: EraError,
        tracked_paths: &[PathBuf],
        context: &ExtractionContext,
    ) -> Result<ExtractStats> {
        let mut paths = tracked_paths.to_vec();
        paths.extend_from_slice(context.created_output_paths());
        Self::fail_extraction_with_cleanup(err, &paths).await
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
                        stats.warnings.push(format!(
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
        let catalog = self.catalog.as_ref().ok_or_else(|| {
            EraError::IntegrityError("catalog not populated after preflight".into())
        })?;

        // Check if erasure coding is enabled
        let erasure_config = self.volume_readers[0].header().config().erasure;

        // Create session-based iterators with per-block key derivation
        let mut iter: Box<dyn BlockIterator> = if let Some(config) = erasure_config {
            // Read distribution config from header
            let dist_strategy = self.volume_readers[0]
                .header()
                .config()
                .distribution
                .strategy;

            Box::new(SessionErasureBlockIterator::new(
                SessionErasureBlockIteratorArgs {
                    volume_readers: &self.volume_readers,
                    volume_indices: &self.volume_indices,
                    original_volume_count: self.expected_volume_count,
                    session: &self.session,
                    volume_key: &self.volume_key,
                    nonce_context: self.nonce_context,
                    archive_id: self.archive_id,
                    epoch_id: self.epoch_id,
                    compressor: self.create_compressor(),
                    data_shards: config.data_shards,
                    parity_shards: config.parity_shards,
                    distribution_strategy: dist_strategy,
                    committed_ends: self.committed_ends_for_iterators(),
                },
            )?)
        } else {
            Box::new(MultiVolumeSessionBlockIterator::new(
                &self.volume_readers,
                &self.session,
                &self.volume_key,
                self.nonce_context,
                self.archive_id,
                self.epoch_id,
                self.create_compressor(),
                self.committed_ends_for_iterators(),
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
        let catalog = self.catalog.as_ref().ok_or_else(|| {
            EraError::IntegrityError("catalog not populated after preflight".into())
        })?;

        // Check if erasure coding is enabled
        let erasure_config = self.volume_readers[0].header().config().erasure;

        // Create session-based iterators with per-block key derivation
        let mut iter: Box<dyn BlockIterator> = if let Some(config) = erasure_config {
            // Read distribution config from header
            let dist_strategy = self.volume_readers[0]
                .header()
                .config()
                .distribution
                .strategy;

            Box::new(SessionErasureBlockIterator::new(
                SessionErasureBlockIteratorArgs {
                    volume_readers: &self.volume_readers,
                    volume_indices: &self.volume_indices,
                    original_volume_count: self.expected_volume_count,
                    session: &self.session,
                    volume_key: &self.volume_key,
                    nonce_context: self.nonce_context,
                    archive_id: self.archive_id,
                    epoch_id: self.epoch_id,
                    compressor: self.create_compressor(),
                    data_shards: config.data_shards,
                    parity_shards: config.parity_shards,
                    distribution_strategy: dist_strategy,
                    committed_ends: self.committed_ends_for_iterators(),
                },
            )?)
        } else {
            Box::new(MultiVolumeSessionBlockIterator::new(
                &self.volume_readers,
                &self.session,
                &self.volume_key,
                self.nonce_context,
                self.archive_id,
                self.epoch_id,
                self.create_compressor(),
                self.committed_ends_for_iterators(),
            ))
        };

        let mut stats = Self::verify_with_iterator(catalog, &mut iter).await?;
        for reader in &self.volume_readers {
            if reader.header_recovered_from_backup() {
                stats.warnings.push(format!(
                    "Volume {}: using backup header; primary header still requires repair",
                    reader.header().volume_sequence()
                ));
            }
        }
        if self.catalog_recovered_from_backup {
            stats.warnings.push(
                "Catalog recovered from EC backup; primary Catalog still requires repair".into(),
            );
        }
        stats.archive_health = self.classify_archive_health(&stats);
        self.log_verify_result(&stats);
        Ok(stats)
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
    use crate::block_iter::{BlockIterStats, DecodedBlock};
    use crate::ArchiveWriter;
    use era_common::{ArchiveConfig, ArchiveId, VolumeId};
    use era_ingest::ChunkRef;
    use era_volume::{
        AccessPolicy, EncryptedVolumeKey, KeyWrapAlgorithm, RecipientSlot, RecipientType,
        VolumeWriter,
    };
    use tempfile::TempDir;

    /// Helper: Create a config with EC disabled for single-volume tests
    fn test_config_no_ec() -> ArchiveConfig {
        ArchiveConfig {
            erasure: None,
            ..Default::default()
        }
    }

    const DISCOVERY_ARCHIVE_ID: u128 = 0x4552415f444953434f56455259;
    const FOREIGN_ARCHIVE_ID: u128 = 0x4552415f464f524549474e;

    fn discovery_header(archive_id: ArchiveId, sequence: u16, total_volumes: u16) -> SuperHeader {
        let mut header = SuperHeader::new(
            archive_id,
            vec![RecipientSlot::new(
                RecipientType::Argon2idPassword,
                Some([0x12; 8]),
                vec![0xAB; 16],
                vec![0xCD; 48],
            )],
            test_config_no_ec(),
            [0u8; 16],
            EncryptedVolumeKey::new(
                KeyWrapAlgorithm::XChaCha20Poly1305,
                [0u8; 24],
                vec![0u8; 48],
            ),
            AccessPolicy::AnyOfN,
        )
        .unwrap();
        header.set_volume_sequence(sequence);
        header.set_total_volumes(total_volumes);
        header
    }

    struct DiscoveryFixture {
        temp_dir: TempDir,
        base_name: String,
        archive_id: ArchiveId,
    }

    impl DiscoveryFixture {
        fn new(base_name: &str) -> Self {
            Self {
                temp_dir: TempDir::new().unwrap(),
                base_name: base_name.to_string(),
                archive_id: ArchiveId::from_uuid(uuid::Uuid::from_u128(DISCOVERY_ARCHIVE_ID)),
            }
        }

        fn file_name(&self, sequence: u16) -> String {
            if sequence == 0 {
                self.base_name.clone()
            } else {
                format!("{}.{:03}", self.base_name, sequence)
            }
        }

        fn volume_path(&self, sequence: u16) -> PathBuf {
            self.temp_dir.path().join(self.file_name(sequence))
        }

        async fn write_volumes(&self, volumes: &[(u16, u16)]) {
            for &(sequence, total_volumes) in volumes {
                self.write_volume(sequence, total_volumes).await;
            }
        }

        async fn write_volume(&self, sequence: u16, total_volumes: u16) {
            let header = discovery_header(self.archive_id, sequence, total_volumes);
            self.write_header_at(sequence, header).await;
        }

        async fn write_foreign_volume(&self, sequence: u16, total_volumes: u16) {
            let archive_id = ArchiveId::from_uuid(uuid::Uuid::from_u128(FOREIGN_ARCHIVE_ID));
            let header = discovery_header(archive_id, sequence, total_volumes);
            self.write_header_at(sequence, header).await;
        }

        async fn write_header_at(&self, path_sequence: u16, mut header: SuperHeader) {
            header.set_volume_id(VolumeId(uuid::Uuid::from_u128(u128::from(path_sequence))));
            let backend = LocalStorageBackend::new(self.temp_dir.path());
            let file_name = self.file_name(path_sequence);
            let writer = VolumeWriter::create(&backend, Path::new(&file_name), header)
                .await
                .unwrap();
            writer.finalize().await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_discover_volumes_from_first_finds_stale_generation_chain() {
        let fixture = DiscoveryFixture::new("generations.era");
        fixture
            .write_volumes(&[(0, 2), (1, 2), (2, 4), (3, 4), (4, 7), (5, 7), (6, 7)])
            .await;

        let discovered = ArchiveReader::discover_volumes(&fixture.volume_path(0))
            .await
            .unwrap();

        assert_eq!(discovered.volume_indices, vec![0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(discovered.expected_volume_count, 7);
        assert_eq!(discovered.missing_volume_indices, Vec::<usize>::new());
    }

    #[tokio::test]
    async fn test_discover_volumes_from_last_finds_stale_generation_chain() {
        let fixture = DiscoveryFixture::new("last.era");
        fixture
            .write_volumes(&[(0, 2), (1, 2), (2, 4), (3, 4), (4, 7), (5, 7), (6, 7)])
            .await;

        let discovered = ArchiveReader::discover_volumes(&fixture.volume_path(6))
            .await
            .unwrap();

        assert_eq!(discovered.volume_indices, vec![0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(discovered.expected_volume_count, 7);
        assert_eq!(discovered.missing_volume_indices, Vec::<usize>::new());
    }

    #[tokio::test]
    async fn test_discover_volumes_reports_exact_gaps_in_extended_promise() {
        let fixture = DiscoveryFixture::new("gaps.era");
        fixture
            .write_volumes(&[(0, 2), (2, 7), (3, 7), (6, 7)])
            .await;

        let discovered = ArchiveReader::discover_volumes(&fixture.volume_path(0))
            .await
            .unwrap();

        assert_eq!(discovered.volume_indices, vec![0, 2, 3, 6]);
        assert_eq!(discovered.expected_volume_count, 7);
        assert_eq!(discovered.missing_volume_indices, vec![1, 4, 5]);
    }

    #[tokio::test]
    async fn test_discover_volumes_ignores_unrelated_archive_totals() {
        let fixture = DiscoveryFixture::new("foreign.era");
        fixture.write_volumes(&[(0, 2), (1, 2)]).await;
        fixture.write_foreign_volume(2, 7).await;
        fixture.write_foreign_volume(3, 7).await;

        let discovered = ArchiveReader::discover_volumes(&fixture.volume_path(0))
            .await
            .unwrap();

        assert_eq!(discovered.volume_indices, vec![0, 1]);
        assert_eq!(discovered.expected_volume_count, 2);
        assert_eq!(discovered.missing_volume_indices, Vec::<usize>::new());
    }

    #[tokio::test]
    async fn test_discover_volumes_forward_probe_is_bounded() {
        let fixture = DiscoveryFixture::new("bounded.era");
        fixture.write_volumes(&[(0, 2), (1, 2), (4, 9)]).await;

        let discovered = ArchiveReader::discover_volumes(&fixture.volume_path(0))
            .await
            .unwrap();

        assert_eq!(discovered.volume_indices, vec![0, 1]);
        assert_eq!(discovered.expected_volume_count, 2);
        assert_eq!(discovered.missing_volume_indices, Vec::<usize>::new());
    }

    #[tokio::test]
    async fn test_discover_volumes_rejects_duplicate_sequences() {
        let fixture = DiscoveryFixture::new("duplicate.era");
        fixture.write_volume(0, 2).await;
        let duplicate = discovery_header(fixture.archive_id, 0, 2);
        fixture.write_header_at(1, duplicate).await;

        let result = ArchiveReader::discover_volumes(&fixture.volume_path(0)).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_discover_volumes_rejects_path_sequence_mismatch() {
        let fixture = DiscoveryFixture::new("inconsistent.era");
        fixture.write_volume(0, 2).await;
        let inconsistent = discovery_header(fixture.archive_id, 2, 7);
        fixture.write_header_at(1, inconsistent).await;

        let result = ArchiveReader::discover_volumes(&fixture.volume_path(0)).await;

        assert!(result.is_err());
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
    async fn test_multivolume_non_erasure_roundtrip() {
        use rand::RngCore;

        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("multi.era");
        let password = "test";

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .config(test_config_no_ec())
            .max_volume_size(1024 * 1024)
            .target_block_size(512 * 1024)
            .build()
            .await
            .unwrap();

        // Random data to defeat compression
        let mut rng = rand::rngs::OsRng;
        let mut data_a = vec![0u8; 512 * 1024];
        rng.fill_bytes(&mut data_a);
        let mut data_b = vec![0u8; 512 * 1024];
        rng.fill_bytes(&mut data_b);
        let mut data_c = vec![0u8; 512 * 1024];
        rng.fill_bytes(&mut data_c);

        writer.add_bytes("a.bin", &data_a).await.unwrap();
        writer.add_bytes("b.bin", &data_b).await.unwrap();
        writer.add_bytes("c.bin", &data_c).await.unwrap();
        let stats = writer.finalize().await.unwrap();
        assert_eq!(stats.total_files, 3);

        // Confirm multiple volumes were created
        assert!(
            temp_dir.path().join("multi.era.001").exists(),
            "Expected at least 2 volumes but only found volume 0"
        );

        let mut reader = ArchiveReader::open(&archive_path, password).await.unwrap();
        let extract_dir = temp_dir.path().join("extracted");
        let options = ExtractOptions::new(&extract_dir);
        let extract_stats = reader.extract_all(&options).await.unwrap();

        assert_eq!(
            extract_stats.extracted, 3,
            "All 3 files should be extracted"
        );

        let extracted_a = fs::read(extract_dir.join("a.bin")).unwrap();
        assert_eq!(extracted_a, data_a, "File a.bin content mismatch");
        let extracted_b = fs::read(extract_dir.join("b.bin")).unwrap();
        assert_eq!(extracted_b, data_b, "File b.bin content mismatch");
        let extracted_c = fs::read(extract_dir.join("c.bin")).unwrap();
        assert_eq!(extracted_c, data_c, "File c.bin content mismatch");

        let mut reader2 = ArchiveReader::open(&archive_path, password).await.unwrap();
        let verify_stats = reader2.verify().await.unwrap();
        assert!(
            verify_stats.is_ok(),
            "Verification should pass for multi-volume archive"
        );
    }

    #[tokio::test]
    async fn test_large_catalog_roundtrip() {
        use rand::RngCore;

        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("bigcat.era");
        let password = "test";

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .config(test_config_no_ec())
            .build()
            .await
            .unwrap();

        // Each entry ~200 bytes in catalog. 100K entries × 200B ≈ 20MB catalog.
        // Use random hex names to defeat protobuf/zstd compression.
        let mut rng = rand::rngs::OsRng;
        let file_count = 200_000;
        for i in 0..file_count {
            let mut name_bytes = [0u8; 96];
            rng.fill_bytes(&mut name_bytes);
            let name = format!(
                "dir_{:04x}/{:04x}/{}.dat",
                i / 256,
                i % 256,
                hex::encode(name_bytes)
            );
            let mut data = [0u8; 16];
            rng.fill_bytes(&mut data);
            writer.add_bytes(&name, &data).await.unwrap();
        }

        let stats = writer.finalize().await.unwrap();
        assert_eq!(stats.total_files, file_count);

        let mut reader = ArchiveReader::open(&archive_path, password).await.unwrap();
        let files = reader.list_files().await.unwrap();
        assert_eq!(files.len() as u64, file_count);
    }

    struct InjectedBlockIterator {
        results: std::collections::VecDeque<Result<DecodedBlock>>,
        stats: BlockIterStats,
    }

    #[async_trait::async_trait(?Send)]
    impl BlockIterator for InjectedBlockIterator {
        async fn next_block(&mut self) -> Option<Result<DecodedBlock>> {
            self.results.pop_front()
        }

        fn has_more(&self) -> bool {
            !self.results.is_empty()
        }

        fn stats(&self) -> &BlockIterStats {
            &self.stats
        }
    }

    fn injected_iterator(results: Vec<Result<DecodedBlock>>) -> Box<dyn BlockIterator> {
        Box::new(InjectedBlockIterator {
            results: results.into_iter().collect(),
            stats: BlockIterStats::default(),
        })
    }

    fn decoded_block(block_index: u32, data: &Bytes) -> DecodedBlock {
        let chunks: ChunkVec = std::iter::once((era_crypto::hash(data), data.clone())).collect();
        DecodedBlock {
            block_index,
            chunks,
            corrupted_shards: 0,
        }
    }

    fn two_chunk_catalog(first: &Bytes, second: &Bytes) -> Catalog {
        let total_size = u64::try_from(first.len() + second.len()).unwrap();
        let entry = FileEntry::file(PathBuf::from("partial.txt"), total_size).with_chunks(vec![
            ChunkRef::new(
                era_crypto::hash(first),
                0,
                u32::try_from(first.len()).unwrap(),
            ),
            ChunkRef::new(
                era_crypto::hash(second),
                u64::try_from(first.len()).unwrap(),
                u32::try_from(second.len()).unwrap(),
            ),
        ]);
        let mut catalog = Catalog::new();
        catalog.add(entry);
        catalog
    }

    #[tokio::test]
    async fn test_extract_with_iterator_propagates_shard_limit_and_cleans_up() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().join("extracted");
        let output_path = output_dir.join("partial.txt");
        let first = Bytes::from_static(b"partial ");
        let second = Bytes::from_static(b"recovery");
        let catalog = two_chunk_catalog(&first, &second);
        let max_size = 256 * 1024 * 1024;
        let size = max_size + 1;
        let mut iter = injected_iterator(vec![
            Ok(decoded_block(0, &first)),
            Err(EraError::ShardTooLarge { size, max_size }),
        ]);

        let result = ArchiveReader::extract_with_iterator(
            &catalog,
            &mut iter,
            &ExtractOptions::new(&output_dir),
        )
        .await;

        match result {
            Err(EraError::ShardTooLarge {
                size: actual_size,
                max_size: actual_max,
            }) => {
                assert_eq!(actual_size, size);
                assert_eq!(actual_max, max_size);
            }
            other => panic!("expected concrete shard-limit error, got {other:?}"),
        }
        assert!(
            !output_path.exists(),
            "partial output must be removed after a shard-limit failure"
        );
    }

    #[tokio::test]
    async fn test_extract_with_iterator_recovers_after_ordinary_block_error() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().join("extracted");
        let output_path = output_dir.join("partial.txt");
        let first = Bytes::from_static(b"partial ");
        let second = Bytes::from_static(b"recovery");
        let catalog = two_chunk_catalog(&first, &second);
        let mut iter = injected_iterator(vec![
            Ok(decoded_block(0, &first)),
            Err(EraError::ErasureError(
                "injected recoverable block failure".into(),
            )),
            Ok(decoded_block(1, &second)),
        ]);

        let stats = ArchiveReader::extract_with_iterator(
            &catalog,
            &mut iter,
            &ExtractOptions::new(&output_dir),
        )
        .await
        .unwrap();

        let expected = [first.as_ref(), second.as_ref()].concat();
        assert_eq!(stats.extracted, 1);
        assert_eq!(stats.bytes_written, u64::try_from(expected.len()).unwrap());
        assert_eq!(fs::read(output_path).unwrap(), expected);
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

    #[tokio::test]
    async fn test_read_shard_enforces_stripe_and_global_size_limits() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("reader.era");
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test")
            .enable_erasure(false)
            .build()
            .await
            .unwrap();
        writer.add_bytes("a.txt", b"hello").await.unwrap();
        writer.finalize().await.unwrap();

        let archive_reader = ArchiveReader::open(&archive_path, "test").await.unwrap();

        let backend = era_storage::LocalStorageBackend::new(temp_dir.path());
        let bad_vol = "bad_shard.era";
        let mut vol_writer = VolumeWriter::create(
            &backend,
            Path::new(bad_vol),
            archive_reader.header().clone(),
        )
        .await
        .unwrap();
        let oversized_len = (MAX_SHARD_SIZE as u32) + 1;
        let shard_header = era_common::ShardHeader::new(oversized_len, 0);
        vol_writer
            .write_raw(&shard_header.to_bytes())
            .await
            .unwrap();
        vol_writer.finalize().await.unwrap();

        let vol_reader = VolumeReader::open(&backend, Path::new(bad_vol))
            .await
            .unwrap();
        let err = archive_reader
            .read_shard(&vol_reader, era_volume::DATA_REGION_START, u32::MAX)
            .await
            .expect_err("oversized shard header must return ShardTooLarge");
        match err {
            EraError::ShardTooLarge { size, max_size } => {
                assert_eq!(size, oversized_len as usize);
                assert_eq!(max_size, MAX_SHARD_SIZE as usize);
            }
            other => panic!("expected ShardTooLarge, got: {other:?}"),
        }
    }
}
