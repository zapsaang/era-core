//! Archive writer - creates ERA archives.
//!
//! ## Security Model
//!
//! This writer implements the HKDF "Onion Model" key derivation:
//! - **Master Key (MK)**: Derived from password via Argon2id, or from certificate key exchange
//! - **Volume Key (VK)**: Derived from MK via HKDF (fast, per-volume)
//! - **Block Key (BK)**: Derived from VK via HKDF (fast, per-block)
//!
//! Each block is encrypted with a unique key, providing forward and backward security.
//!
//! ## Authentication Modes
//!
//! - **Password mode**: Traditional Argon2id key derivation (~50-300ms overhead)
//! - **Certificate mode**: X25519 key exchange (~0.05ms overhead, ~1000x faster)

mod checkpoint_append;

use crate::auth::{
    AuthProvider, CertificateProvider, HybridCertificateProvider, PasswordProvider,
    PasswordSlotParams,
};
use crate::block_iter::{BlockIterator, SessionBlockIterator};
use bytes::Bytes;
use checkpoint_append::{extend_data_ends_for_rotation, scan_retained_data_region, RetainedVolume};
use era_common::{
    ArchiveConfig, ArchiveId, ArchiveManifest, BlockId, BlockLocation, ChunkHash,
    EncryptedMacroBlock, EraError, ErasureCodeConfig, MatrixDistributionStrategy, Result,
    UniqueChunk,
};
use era_crypto::certificate::{EraCertificate, EraKeyPair, KeyEncapsulation};
use era_crypto::hybrid_certificate::{HybridCertificate, HybridKeyPair};
use era_crypto::Nonce;
use era_crypto::{
    build_aad, compute_catalog_commitment, compute_index_commitment,
    derive_nonce_with_volume_index, AeadContext, KdfParams, KeySession, Salt, VolumeKey,
    XChaCha20Poly1305Context, NONCE_SIZE,
};
use era_ingest::{Catalog, ChunkRef, ChunkerConfig, FileEntry, FileReader};
use era_packing::{PackedBlock, PackedChunk};
use era_storage::LocalStorageBackend;
use era_volume::{
    validate_erasure_volume_count, Footer, RecipientSlot, RecipientType, SuperHeader, VolumePool,
    VolumePoolConfig, VolumeReader, VolumeWriter,
};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::{HashMap, HashSet};
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info, warn};
use zeroize::Zeroize;
use zeroize::Zeroizing;

const INTERNAL_META_PREFIX: &str = ".era/meta/";

type CatalogBlockSets = Vec<Vec<EncryptedMacroBlock>>;

use crate::checkpoint::CheckpointManager;
use crate::chunk_index::{create_chunk_index_with_context, ChunkIndex};
use crate::encryption_context::EncryptionContext;
use crate::erasure_stage::ErasureStage;
use crate::index_stage::IndexStage;
use crate::packing_stage::PackingStage;
use crate::reader::{
    ArchiveReader, MAX_CATALOG_CHUNKS, MAX_CATALOG_CHUNK_SIZE, MAX_CATALOG_PLAINTEXT_SIZE,
};
use crate::recovery::{RecoveryOptions, RecoveryStrategy};
use crate::sequence::{next_finalize_sequence, INITIAL_FINALIZE_SEQUENCE};
use crate::small_file_packer::{SmallFileEntry, SmallFilePacker};
use crate::volume_capacity::VolumeCapacity;
use crate::volume_stage::VolumeStage;
use crate::write_pipeline::WritePipeline;

/// Authentication mode for archive encryption
pub enum AuthMode {
    /// Password-based authentication using Argon2id
    /// This is the traditional mode with ~50-300ms key derivation overhead.
    Password(Zeroizing<String>),

    /// Certificate-based authentication using X25519 key exchange
    /// This mode is ~1000x faster than password mode (~0.05ms).
    /// The archive can be decrypted by anyone with the corresponding private key.
    Certificate(EraCertificate),

    /// Multi-recipient mode with a password slot and a legacy X25519 certificate slot.
    /// Under the default AnyOfN policy, either credential can unlock the archive.
    Hybrid {
        password: Zeroizing<String>,
        certificate: EraCertificate,
    },

    /// Post-quantum certificate authentication using X25519 + Kyber-768 hybrid KEM.
    HybridKemCertificate(HybridCertificate),

    /// Multi-recipient mode with a password slot and a hybrid certificate slot.
    /// Under the default AnyOfN policy, either credential can unlock the archive.
    HybridKemWithPassword {
        password: Zeroizing<String>,
        certificate: HybridCertificate,
    },
}

impl std::fmt::Debug for AuthMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMode::Password(_) => f.debug_tuple("Password").field(&"[REDACTED]").finish(),
            AuthMode::Certificate(cert) => f.debug_tuple("Certificate").field(cert).finish(),
            AuthMode::Hybrid { certificate, .. } => f
                .debug_struct("Hybrid")
                .field("password", &"[REDACTED]")
                .field("certificate", certificate)
                .finish(),
            AuthMode::HybridKemCertificate(_) => f
                .debug_tuple("HybridKemCertificate")
                .field(&"[REDACTED]")
                .finish(),
            AuthMode::HybridKemWithPassword { certificate, .. } => f
                .debug_struct("HybridKemWithPassword")
                .field("password", &"[REDACTED]")
                .field("certificate", certificate)
                .finish(),
        }
    }
}

impl Default for AuthMode {
    fn default() -> Self {
        AuthMode::Password(Zeroizing::new(String::new()))
    }
}

fn chunker_config_from_archive(config: &ArchiveConfig) -> Result<ChunkerConfig> {
    let chunking = &config.chunking;
    if chunking.min_size > chunking.avg_size || chunking.avg_size > chunking.max_size {
        return Err(era_common::EraError::InvalidFormat(
            "chunking sizes must satisfy min <= avg <= max".into(),
        ));
    }

    Ok(ChunkerConfig::new_with_params(
        chunking.min_size,
        chunking.avg_size,
        chunking.max_size,
        chunking.normalization_level,
        chunking.rolling_hash_seed,
    ))
}

fn bounded_small_file_batches(
    entries: Vec<SmallFileEntry>,
    max_packed_size: usize,
) -> Result<Vec<Vec<SmallFileEntry>>> {
    let mut pending = vec![entries];
    let mut batches = Vec::new();
    while let Some(mut batch) = pending.pop() {
        if batch.is_empty() {
            continue;
        }
        let entries_size = size_of::<era_packing::PackedEntry>()
            .checked_mul(batch.len())
            .ok_or_else(|| EraError::InvalidConfig("packed file index size overflow".into()))?;
        let data_size = batch.iter().try_fold(0usize, |total, entry| {
            total
                .checked_add(entry.data.len())
                .ok_or_else(|| EraError::InvalidConfig("packed file data size overflow".into()))
        })?;
        let packed_size = size_of::<era_packing::PackedHeader>()
            .checked_add(entries_size)
            .and_then(|size| size.checked_add(data_size))
            .ok_or_else(|| EraError::InvalidConfig("packed file size overflow".into()))?;
        if packed_size > max_packed_size && batch.len() > 1 {
            let second = batch.split_off(batch.len() / 2);
            pending.push(second);
            pending.push(batch);
            continue;
        }
        if packed_size > max_packed_size {
            return Err(EraError::InvalidConfig(format!(
                "one packed small file requires {packed_size} bytes, exceeding the {max_packed_size}-byte producer limit"
            )));
        }
        batches.push(batch);
    }
    Ok(batches)
}

/// Builder for creating an ArchiveWriter
pub struct ArchiveWriterBuilder {
    output_path: PathBuf,
    /// Authentication mode (password, certificate, or hybrid)
    auth_mode: AuthMode,
    config: ArchiveConfig,
    enable_cdc: bool,
    chunker_config: Option<ChunkerConfig>,
    /// Enable checkpoint for crash recovery
    enable_checkpoint: bool,
    /// Recovery options when checkpoint is enabled
    recovery_options: RecoveryOptions,
    recovery_options_explicit: bool,
    /// Enable erasure coding for redundancy (None = use config default)
    enable_erasure: Option<bool>,
    /// Erasure coding configuration
    erasure_config: ErasureCodeConfig,
    /// Number of storage volumes to distribute data across
    volume_count: Option<usize>,
    /// Maximum volume size for fixed-size splitting (bytes)
    max_volume_size: Option<u64>,
    /// Target size for encrypted blocks (default: 4MB)
    target_block_size: Option<usize>,
    /// Enable packing of multiple small files into a single chunk
    enable_small_file_packing: bool,
    /// Append to an existing archive instead of creating a new one
    append_existing: bool,
    /// Access policy for multi-party decryption
    access_policy: era_volume::AccessPolicy,
    /// Additional passwords for threshold mode
    additional_passwords: Vec<String>,
    /// Additional hybrid certificates for threshold mode
    additional_hybrid_certificates: Vec<HybridCertificate>,
    /// Private keypair for unlocking an existing legacy certificate archive in append mode
    append_keypair: Option<EraKeyPair>,
    /// Private hybrid keypair for unlocking an existing hybrid-cert archive in append mode
    append_hybrid_keypair: Option<HybridKeyPair>,
}

impl ArchiveWriterBuilder {
    /// Create a new builder with the output path
    pub fn new(output_path: impl Into<PathBuf>) -> Self {
        Self {
            output_path: output_path.into(),
            auth_mode: AuthMode::default(),
            config: ArchiveConfig::default(),
            enable_cdc: true, // MANDATORY DEFAULT: CDC enabled for k-Bounded Best-Fit
            chunker_config: None,
            enable_checkpoint: false,
            recovery_options: RecoveryOptions::default(),
            recovery_options_explicit: false,
            enable_erasure: None,
            erasure_config: ErasureCodeConfig::default(),
            volume_count: None,
            max_volume_size: None,
            target_block_size: None,
            enable_small_file_packing: true,
            append_existing: false,
            access_policy: era_volume::AccessPolicy::AnyOfN,
            additional_passwords: Vec::new(),
            additional_hybrid_certificates: Vec::new(),
            append_keypair: None,
            append_hybrid_keypair: None,
        }
    }

    /// Set the encryption password (password mode).
    ///
    /// This uses Argon2id for key derivation (~50-300ms overhead).
    /// For faster key derivation, consider using `certificate()` instead.
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.auth_mode = AuthMode::Password(Zeroizing::new(password.into()));
        self
    }

    /// Set the recipient certificate (certificate mode).
    ///
    /// This uses X25519 key exchange (~0.05ms overhead, ~1000x faster than password).
    /// The archive can only be decrypted by the holder of the corresponding private key.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let keypair = era_crypto::load_private_key_from_pem("~/.era/key.pem", Some("password"))?;
    /// let cert = keypair.certificate();
    ///
    /// let writer = ArchiveWriterBuilder::new("archive.era")
    ///     .certificate(cert)
    ///     .build()?;
    /// ```
    pub fn certificate(mut self, cert: EraCertificate) -> Self {
        self.auth_mode = AuthMode::Certificate(cert);
        self
    }

    /// Set the legacy keypair for both creating and appending to a certificate-encrypted archive.
    pub fn keypair(mut self, keypair: EraKeyPair) -> Self {
        self.auth_mode = AuthMode::Certificate(keypair.certificate());
        self.append_keypair = Some(keypair);
        self
    }

    /// Provide a legacy private keypair solely for unlocking an existing archive in append mode
    /// without altering the configured `auth_mode`.
    pub fn append_keypair(mut self, keypair: EraKeyPair) -> Self {
        self.append_keypair = Some(keypair);
        self
    }

    /// Set the recipient hybrid certificate (post-quantum certificate mode).
    ///
    /// This uses X25519 + Kyber-768 hybrid KEM for post-quantum security.
    pub fn hybrid_certificate(mut self, cert: HybridCertificate) -> Self {
        self.auth_mode = AuthMode::HybridKemCertificate(cert);
        self
    }

    /// Set the hybrid keypair for both creating and appending to a hybrid-certificate archive.
    pub fn hybrid_keypair(mut self, keypair: HybridKeyPair) -> Self {
        self.auth_mode = AuthMode::HybridKemCertificate(keypair.certificate());
        self.append_hybrid_keypair = Some(keypair);
        self
    }

    /// Provide a hybrid private keypair solely for unlocking an existing archive in append mode
    /// without altering the configured `auth_mode`.
    pub fn append_hybrid_keypair(mut self, keypair: HybridKeyPair) -> Self {
        self.append_hybrid_keypair = Some(keypair);
        self
    }

    /// Set the authentication mode directly.
    pub fn auth_mode(mut self, mode: AuthMode) -> Self {
        self.auth_mode = mode;
        self
    }

    /// Set the archive configuration
    pub fn config(mut self, config: ArchiveConfig) -> Self {
        self.config = config;
        self.chunker_config = None;
        self
    }

    /// Enable CDC chunking for large files
    pub fn enable_cdc(mut self, enable: bool) -> Self {
        self.enable_cdc = enable;
        self
    }

    /// Set custom CDC configuration
    pub fn chunker_config(mut self, config: ChunkerConfig) -> Self {
        self.config.chunking = era_common::ChunkingConfig {
            min_size: config.min_size,
            avg_size: config.avg_size,
            max_size: config.max_size,
            normalization_level: config.normalization_level,
            rolling_hash_seed: config.rolling_hash_seed,
        };
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
        self.recovery_options_explicit = true;
        self.enable_checkpoint = true;
        self
    }

    /// Enable erasure coding for redundancy
    ///
    /// When enabled, blocks are encoded with Reed-Solomon erasure coding,
    /// allowing recovery from up to `parity_shards` lost shards.
    ///
    /// Pass `false` to explicitly disable EC even if the config has it enabled.
    pub fn enable_erasure(mut self, enable: bool) -> Self {
        self.enable_erasure = Some(enable);
        self
    }

    /// Set custom erasure coding configuration
    ///
    /// Default is 4+2 (4 data shards, 2 parity shards).
    /// This allows recovery from loss of any 2 shards.
    pub fn erasure_config(mut self, config: ErasureCodeConfig) -> Self {
        self.erasure_config = config;
        self.enable_erasure = Some(true);
        self
    }

    /// Set the number of volumes to distribute data across
    ///
    /// This enables true distributed erasure coding where shards of the same block
    /// are stored on different volumes.
    pub fn volume_count(mut self, count: usize) -> Self {
        self.volume_count = Some(count.max(1));
        self
    }

    /// Set maximum volume size for fixed-size splitting.
    ///
    /// Overrides the archive configuration's volume limit (1 GiB by default).
    /// Values below [`crate::MIN_ARCHIVE_VOLUME_SIZE`] (1 MiB) are rejected during build.
    pub fn max_volume_size(mut self, size: u64) -> Self {
        self.max_volume_size = Some(size);
        self
    }

    /// Set target size for encrypted blocks.
    ///
    /// Smaller blocks increase overhead but allow finer-grained access.
    /// Default is 4MB.
    pub fn target_block_size(mut self, size: usize) -> Self {
        self.target_block_size = Some(size);
        self
    }

    /// Enable packing of multiple small files into a single chunk.
    ///
    /// Disabled by default to preserve deduplication efficiency across identical datasets.
    pub fn enable_small_file_packing(mut self, enable: bool) -> Self {
        self.enable_small_file_packing = enable;
        self
    }

    /// Append to an existing archive instead of creating a new one.
    ///
    /// This enforces chunking configuration inheritance from the existing header.
    pub fn append_existing(mut self, enable: bool) -> Self {
        self.append_existing = enable;
        self
    }

    /// Set the access policy for multi-party decryption.
    ///
    /// Use `AccessPolicy::Threshold(t)` to require `t` passwords to unlock.
    /// Each password encrypts a Shamir share of the MK, not the full MK.
    pub fn access_policy(mut self, policy: era_volume::AccessPolicy) -> Self {
        self.access_policy = policy;
        self
    }

    /// Add an additional password for threshold mode.
    ///
    /// The primary password is set via `.password()`. Additional passwords
    /// are added here. For `Threshold(t)`, you need at least `t` total passwords.
    pub fn add_password(mut self, password: impl Into<String>) -> Self {
        self.additional_passwords.push(password.into());
        self
    }

    /// Add an additional hybrid certificate for threshold mode.
    ///
    /// The primary hybrid certificate is set via `.hybrid_certificate()`.
    /// Additional hybrid certificates are added here.
    /// For `Threshold(t)`, you need at least `t` total hybrid certificates.
    pub fn add_hybrid_certificate(mut self, cert: HybridCertificate) -> Self {
        self.additional_hybrid_certificates.push(cert);
        self
    }

    /// Build the archive writer
    pub async fn build(self) -> Result<ArchiveWriter> {
        use rand::RngCore as _;
        let output_preexisted = tokio::fs::try_exists(&self.output_path).await?;
        let append_to_existing = self.append_existing && output_preexisted;
        if !append_to_existing {
            crate::volume_capacity::validate_max_volume_size(
                self.max_volume_size.unwrap_or(self.config.volume.max_size),
            )?;
        } else if let Some(size) = self.max_volume_size {
            crate::volume_capacity::validate_max_volume_size(size)?;
        }
        // Create storage backend
        let output_dir = self.output_path.parent().unwrap_or(Path::new("."));
        let backend = LocalStorageBackend::new(output_dir);

        let password_to_validate = match &self.auth_mode {
            AuthMode::Password(password) => Some(password.as_str()),
            AuthMode::Hybrid { password, .. } => Some(password.as_str()),
            AuthMode::HybridKemWithPassword { password, .. } => Some(password.as_str()),
            AuthMode::Certificate(_) | AuthMode::HybridKemCertificate(_) => None,
        };
        if let Some(password) = password_to_validate {
            if password.is_empty() {
                warn!(
                    "Building archive with empty password; this is allowed for tests but unsafe for production use"
                );
            } else if password.trim().is_empty() {
                return Err(EraError::InvalidConfig(
                    "Password must not contain only whitespace".into(),
                ));
            }
        }

        let mut archive_id = ArchiveId::new();
        // let mut salt = Salt::generate(); // Salt is per-recipient now

        // Refactor placeholders - Append mode logic restored
        let mut append_header: Option<SuperHeader> = None;
        let mut append_footer: Option<Footer> = None;
        let mut append_catalog: Option<Catalog> = None;
        let mut existing_manifest: Option<ArchiveManifest> = None;
        let mut key_encapsulation: Option<KeyEncapsulation> = None;

        // Extract Copy fields before moving config to avoid clone
        let config_erasure = self.config.erasure;
        let mut config = self.config;
        let explicit_enable_erasure = self.enable_erasure;
        let mut enable_erasure = match explicit_enable_erasure {
            Some(explicit) => explicit, // Explicit .enable_erasure(true/false) call
            None => config_erasure.is_some(), // Fall back to config default
        };
        let erasure_config = if explicit_enable_erasure == Some(true) {
            // Explicit builder setting takes precedence
            self.erasure_config
        } else if let Some(cfg) = config_erasure {
            // Use config's erasure setting (e.g., default 4+1)
            cfg
        } else {
            // Fallback (shouldn't reach here if enable_erasure is false)
            self.erasure_config
        };
        let volume_count = self.volume_count;
        let enable_cdc = self.enable_cdc;
        let chunker_override = self.chunker_config;
        let max_volume_size = self.max_volume_size;

        let mut master_key = Zeroizing::new([0u8; 32]);
        let mut archive_salt = era_crypto::Salt::generate();
        let mut recipients = Vec::new();
        let mut recovered_session: Option<(KeySession, VolumeKey)> = None;
        let mut append_retained_end = era_volume::DATA_REGION_START;
        let mut append_data_block_count = 0u32;
        let mut append_checkpoint_exists = false;
        let mut recovered_index_entries: Vec<(ChunkHash, BlockLocation)> = Vec::new();

        if append_to_existing {
            // 1. Validate volume 0 DNA before unlocking credentials
            let base_filename = self
                .output_path
                .file_name()
                .ok_or(era_common::EraError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid output path",
                )))?;
            let vol0_reader = VolumeReader::<era_storage::LocalStorageReader>::open(
                &backend,
                Path::new(base_filename),
            )
            .await
            .map_err(|e| {
                era_common::EraError::InvalidFormat(format!(
                    "Failed to open volume 0 for append (Path: {:?}): {}",
                    base_filename, e
                ))
            })?;

            let loaded_header = vol0_reader.header().clone();
            if matches!(
                loaded_header.access_policy(),
                era_volume::AccessPolicy::Threshold(_)
            ) {
                return Err(era_common::EraError::InvalidFormat(
                    "Threshold authentication not supported for append mode".into(),
                ));
            }
            if loaded_header.config().erasure.is_some() || explicit_enable_erasure == Some(true) {
                return Err(era_common::EraError::InvalidFormat(
                    "Append mode is not supported for erasure-coded archives".into(),
                ));
            }
            if loaded_header.total_volumes() > 1 {
                return Err(era_common::EraError::InvalidFormat(
                    "Append mode is only supported for single-volume archives".into(),
                ));
            }
            drop(vol0_reader);

            // 2. Inherit archive DNA
            config = loaded_header.config().clone();
            enable_erasure = false;
            archive_id = loaded_header.archive_id();
            archive_salt = Salt::from_bytes(*loaded_header.salt());
            recipients = loaded_header.recipients().to_vec();

            // 3. Unlock and recover authoritative metadata via ArchiveReader
            let providers = build_append_auth_providers(
                &self.auth_mode,
                self.append_keypair.as_ref(),
                self.append_hybrid_keypair.as_ref(),
            )?;
            let mut reader =
                ArchiveReader::open_with_providers(&self.output_path, providers).await?;
            reader.preflight_metadata_recovery().await?;

            let session = reader.session().try_clone()?;
            let volume_key = session.unwrap_volume_key(
                loaded_header.encrypted_volume_key().nonce(),
                loaded_header.encrypted_volume_key().ciphertext(),
            )?;
            recovered_session = Some((session, volume_key));

            let footer = reader
                .volume_readers()
                .first()
                .and_then(|vr| vr.footer().cloned())
                .ok_or_else(|| {
                    era_common::EraError::CorruptedHeader(
                        "Existing archive has no footer - cannot append".into(),
                    )
                })?;

            let mut manifest_opt = reader.manifest().cloned();
            if let Some(ref manifest) = manifest_opt {
                let seq = loaded_header.volume_sequence();
                if let Some(&committed_end) = manifest.volume_committed_ends.get(usize::from(seq)) {
                    if footer.data_end_offset() < committed_end {
                        return Err(EraError::IntegrityError(format!(
                            "Volume {} footer data_end_offset {} is less than manifest committed end {}. \
                             This indicates footer corruption or manifest mismatch.",
                            seq, footer.data_end_offset(), committed_end
                        )));
                    }
                }
            }

            let vol0 = reader.volume_readers().first().ok_or_else(|| {
                era_common::EraError::CorruptedHeader("Missing volume 0 reader".into())
            })?;
            let manifest_committed_end = manifest_opt
                .as_ref()
                .and_then(|m| m.volume_committed_ends.first().copied());
            append_checkpoint_exists = footer.last_checkpoint_offset() > 0;
            if self.enable_checkpoint
                && self.recovery_options_explicit
                && self.recovery_options.strategy == RecoveryStrategy::Abort
                && append_checkpoint_exists
            {
                return Err(era_common::EraError::CheckpointError(
                    "Checkpoint exists. Use Resume strategy to continue or StartFresh to discard."
                        .into(),
                ));
            }
            let retained = scan_retained_data_region(RetainedVolume {
                reader: vol0,
                footer: &footer,
                manifest_committed_end,
            })
            .await?;
            let committed_end = retained.end;
            append_retained_end = committed_end;
            append_data_block_count = retained.block_count;

            let append_resume_requested = self.enable_checkpoint
                && append_checkpoint_exists
                && (!self.recovery_options_explicit
                    || self.recovery_options.strategy == RecoveryStrategy::Resume);
            // Authenticate the old checkpoint before truncation, but never import its
            // locations or progress into a new append session.
            if retained.legacy_terminal_checkpoint || append_resume_requested {
                CheckpointManager::load_from_durable_checkpoint(
                    &self.output_path,
                    reader.session(),
                    reader.volume_key(),
                    *reader.header().salt(),
                    reader.archive_id_bytes(),
                    reader.epoch_id(),
                )
                .await?;
            }
            if retained.legacy_terminal_checkpoint {
                if let Some(manifest) = manifest_opt.as_mut() {
                    manifest.committed_horizon = committed_end;
                    if let Some(old_end) = manifest.volume_committed_ends.first_mut() {
                        *old_end = committed_end;
                    }
                }
            }

            let catalog = reader.catalog().cloned().unwrap_or_default();
            recovered_index_entries = recover_append_index_entries(
                &reader,
                &catalog,
                committed_end,
                &retained.block_spans,
                &config.compression,
            )
            .await?;

            existing_manifest = manifest_opt;
            append_catalog = Some(catalog);
            append_footer = Some(footer);
            append_header = Some(loaded_header);
        } else {
            // Generate Master Key (DEK) for new archive
            OsRng.fill_bytes(master_key.as_mut());
        }

        let (session, volume_key, encrypted_volume_key) = if let Some((session, volume_key)) =
            recovered_session
        {
            let append = append_header.as_ref().ok_or_else(|| {
                era_common::EraError::CorruptedHeader("Missing append header".into())
            })?;
            (session, volume_key, append.encrypted_volume_key().clone())
        } else {
            let session = KeySession::from_master_key(&master_key)?;
            // 1. Password Mode (adds password recipient(s))
            let has_password = matches!(
                self.auth_mode,
                AuthMode::Password(_)
                    | AuthMode::Hybrid { .. }
                    | AuthMode::HybridKemWithPassword { .. }
            );

            if has_password {
                let pwd = match &self.auth_mode {
                    AuthMode::Password(p) => p,
                    AuthMode::Hybrid { password, .. } => password,
                    AuthMode::HybridKemWithPassword { password, .. } => password,
                    _ => unreachable!(),
                };

                let kdf_params = KdfParams {
                    memory_cost: config.encryption.kdf_memory_cost,
                    time_cost: config.encryption.kdf_time_cost,
                    parallelism: 4,
                };

                match self.access_policy {
                    era_volume::AccessPolicy::Threshold(t) => {
                        // Collect all passwords
                        let mut all_passwords: Vec<zeroize::Zeroizing<String>> =
                            vec![zeroize::Zeroizing::new(pwd.as_str().to_string())];
                        all_passwords.extend(
                            self.additional_passwords
                                .iter()
                                .map(|p| zeroize::Zeroizing::new(p.clone())),
                        );
                        let n = all_passwords.len();

                        if (n as u32) < t {
                            return Err(era_common::EraError::InvalidConfig(format!(
                                "Threshold({}) requires at least {} passwords, got {}",
                                t, t, n
                            )));
                        }
                        if t < 2 {
                            return Err(era_common::EraError::InvalidConfig(
                                "Threshold must be >= 2".into(),
                            ));
                        }

                        // Reject mixed threshold families in this iteration
                        if !self.additional_hybrid_certificates.is_empty() {
                            return Err(era_common::EraError::InvalidConfig(
                                "Mixed threshold (password + hybrid certificate) is not supported"
                                    .into(),
                            ));
                        }

                        // Split MK into N shares with threshold T
                        let shares = era_crypto::split_master_key(&master_key, t as u8, n as u8)?;

                        // Create a recipient slot for each (password, share) pair
                        for (password, share) in all_passwords.iter().zip(shares.iter()) {
                            let salt = Salt::generate();
                            let kek =
                                era_crypto::derive_key(password.as_bytes(), &salt, &kdf_params)?;
                            let ctx = XChaCha20Poly1305Context::from_derived_key(&kek)?;
                            let nonce = Nonce::generate();
                            let encrypted_share = ctx.encrypt(
                                nonce.as_bytes(),
                                crate::auth::MK_WRAP_AAD_DOMAIN,
                                share,
                            )?;

                            let mut combined = Vec::new();
                            combined.extend_from_slice(nonce.as_bytes());
                            combined.extend_from_slice(&encrypted_share);

                            let p_params = PasswordSlotParams {
                                salt: *salt.as_bytes(),
                                kdf_memory_cost: kdf_params.memory_cost,
                                kdf_time_cost: kdf_params.time_cost,
                                kdf_parallelism: kdf_params.parallelism,
                            };

                            recipients.push(RecipientSlot::new(
                                RecipientType::Argon2idPassword,
                                None,
                                rkyv::to_bytes::<rkyv::rancor::Error>(&p_params)
                                    .map_err(|e| {
                                        era_common::EraError::Serialization(e.to_string())
                                    })?
                                    .to_vec(),
                                combined,
                            ));
                        }
                    }
                    era_volume::AccessPolicy::AnyOfN => {
                        // Standard: each slot encrypts the full MK
                        let salt = Salt::generate();
                        let kek = era_crypto::derive_key(pwd.as_bytes(), &salt, &kdf_params)?;

                        let ctx = XChaCha20Poly1305Context::from_derived_key(&kek)?;
                        let nonce = Nonce::generate();
                        let encrypted_mk = ctx.encrypt(
                            nonce.as_bytes(),
                            crate::auth::MK_WRAP_AAD_DOMAIN,
                            &*master_key,
                        )?;

                        let mut combined = Vec::new();
                        combined.extend_from_slice(nonce.as_bytes());
                        combined.extend_from_slice(&encrypted_mk);

                        let p_params = PasswordSlotParams {
                            salt: *salt.as_bytes(),
                            kdf_memory_cost: kdf_params.memory_cost,
                            kdf_time_cost: kdf_params.time_cost,
                            kdf_parallelism: kdf_params.parallelism,
                        };

                        recipients.push(RecipientSlot::new(
                            RecipientType::Argon2idPassword,
                            None,
                            rkyv::to_bytes::<rkyv::rancor::Error>(&p_params)
                                .map_err(|e| era_common::EraError::Serialization(e.to_string()))?
                                .to_vec(),
                            combined,
                        ));
                    }
                    _ => unreachable!(),
                }
            }

            // 2. Legacy Certificate Mode (adds a certificate recipient)
            if let AuthMode::Certificate(ref cert)
            | AuthMode::Hybrid {
                certificate: ref cert,
                ..
            } = self.auth_mode
            {
                let encapsulation = EraKeyPair::encapsulate_for(cert, &*master_key)?;
                key_encapsulation = Some(encapsulation.clone());

                let key_id_bytes: [u8; 8] = cert.key_id()[..8].try_into().map_err(|_| {
                    era_common::EraError::InvalidKey("Certificate key_id too short".into())
                })?;

                recipients.push(RecipientSlot::new(
                    RecipientType::X25519PubKey,
                    Some(key_id_bytes),
                    encapsulation.ephemeral_public.to_vec(),
                    encapsulation.encrypted_master_key,
                ));
            }

            // 3. Hybrid KEM Certificate Mode (adds a post-quantum certificate recipient)
            let maybe_hybrid_cert = match &self.auth_mode {
                AuthMode::HybridKemCertificate(c) => Some(c),
                AuthMode::HybridKemWithPassword { certificate: c, .. } => Some(c),
                _ => None,
            };

            if let Some(cert) = maybe_hybrid_cert {
                match self.access_policy {
                    era_volume::AccessPolicy::Threshold(t) => {
                        let mut all_certs = vec![cert.clone()];
                        all_certs.extend(self.additional_hybrid_certificates.iter().cloned());
                        let n = all_certs.len();

                        if (n as u32) < t {
                            return Err(era_common::EraError::InvalidConfig(format!(
                                "Threshold({}) requires at least {} hybrid certificates, got {}",
                                t, t, n
                            )));
                        }
                        if t < 2 {
                            return Err(era_common::EraError::InvalidConfig(
                                "Threshold must be >= 2".into(),
                            ));
                        }

                        // Reject mixed threshold families in this iteration
                        if !self.additional_passwords.is_empty() {
                            return Err(era_common::EraError::InvalidConfig(
                                "Mixed threshold (password + hybrid certificate) is not supported"
                                    .into(),
                            ));
                        }

                        // Split MK into N shares with threshold T
                        let shares = era_crypto::split_master_key(&master_key, t as u8, n as u8)?;

                        for (cert, share) in all_certs.iter().zip(shares.iter()) {
                            let (params, encrypted_share) =
                                HybridKeyPair::encapsulate_for(cert, share)?;
                            recipients.push(RecipientSlot::new(
                                RecipientType::HybridKem,
                                Some(cert.key_id()),
                                params,
                                encrypted_share,
                            ));
                        }
                    }
                    era_volume::AccessPolicy::AnyOfN => {
                        let (params, encrypted_mk) =
                            HybridKeyPair::encapsulate_for(cert, &*master_key)?;
                        recipients.push(RecipientSlot::new(
                            RecipientType::HybridKem,
                            Some(cert.key_id()),
                            params,
                            encrypted_mk,
                        ));
                    }
                    _ => unreachable!(),
                }
            }
            // Generate random Volume Key and wrap it with IK derived from MK
            let (volume_key, wrapped_vk) = session.generate_and_wrap_volume_key()?;
            let encrypted_volume_key = era_volume::EncryptedVolumeKey::new(
                era_volume::KeyWrapAlgorithm::XChaCha20Poly1305,
                wrapped_vk.nonce,
                wrapped_vk.ciphertext,
            );
            (session, volume_key, encrypted_volume_key)
        };

        // Zeroize master key from stack
        master_key.zeroize();

        // Store nonce context (salt) for block encryption
        let nonce_context = *archive_salt.as_bytes();

        // Build config with erasure setting
        if !append_to_existing {
            if enable_erasure {
                config.erasure = Some(erasure_config);
            } else {
                // Explicitly disable EC even if config default has it enabled
                config.erasure = None;
            }
        }

        // Set distribution strategy in config, to match VolumePool behavior
        // Always use RotatingOffset strategy for optimal fault tolerance
        config.distribution.strategy = MatrixDistributionStrategy::RotatingOffset;

        let base_filename = self.output_path.file_name().unwrap_or_default();

        // Determine volume count based on erasure config
        let resolved_volume_count = if enable_erasure {
            let total_shards = (erasure_config.data_shards + erasure_config.parity_shards) as usize;
            let requested_volume_count = volume_count.unwrap_or(total_shards);

            validate_erasure_volume_count(erasure_config, requested_volume_count)?;

            if volume_count.is_none() {
                info!(
                    "Erasure coding: using default {} volumes \
                     (up to {} independent volume failures when shards remain split one-per-volume)",
                    total_shards, erasure_config.parity_shards
                );
            } else if requested_volume_count < total_shards {
                warn!(
                    "Using {} volumes for {}/{} erasure. \
                     Layout is canonical-valid, but multiple shards can share volumes; \
                     volume-level fault tolerance is reduced versus {} volumes.",
                    requested_volume_count,
                    erasure_config.data_shards,
                    erasure_config.parity_shards,
                    total_shards
                );
            } else {
                info!(
                    "Using {} volumes \
                     (up to {} independent volume failures when shards remain split one-per-volume)",
                    requested_volume_count, erasure_config.parity_shards
                );
            }

            requested_volume_count
        } else {
            volume_count.unwrap_or(1)
        };

        if enable_erasure {
            config.distribution.min_volumes = 1;
            config.distribution.target_volumes = resolved_volume_count;
        }
        let max_volume_size = max_volume_size
            .unwrap_or(config.volume.max_size)
            .max(era_volume::MIN_VOLUME_SIZE);
        config.volume.max_size = max_volume_size;
        let capacity = VolumeCapacity::new(
            max_volume_size,
            config.compression.algorithm,
            enable_erasure.then_some(erasure_config),
            resolved_volume_count,
        )?;
        let (file_reader, chunker_max_size) = if enable_cdc {
            let mut config = match chunker_override {
                Some(cfg) => cfg,
                None => chunker_config_from_archive(&config)?,
            };
            config.max_size = config.max_size.min(capacity.max_data_chunk_size());
            config.avg_size = config.avg_size.min(config.max_size);
            config.min_size = config.min_size.min(config.avg_size);
            config.validate()?;
            let max_size = config.max_size;
            (
                FileReader::with_cdc().with_chunker_config(config),
                Some(max_size),
            )
        } else {
            (FileReader::new(), None)
        };
        let default_block_target_size = era_common::BlockConfig::default().target_size;
        let raw_target_block_size = if let Some(target) = self.target_block_size {
            target
        } else if config.block.target_size != default_block_target_size {
            config.block.target_size
        } else if enable_cdc && enable_erasure {
            chunker_max_size.unwrap_or(config.block.target_size)
        } else {
            config.block.target_size
        };
        if raw_target_block_size == 0 {
            return Err(EraError::InvalidConfig(
                "target_block_size must be > 0".into(),
            ));
        }
        let target_block_size = raw_target_block_size
            .min(capacity.max_data_chunk_size())
            .max(1);
        let packing = PackingStage::new(
            config.packing.k_factor,
            target_block_size,
            config.packing.flush_threshold,
        )?;
        let erasure = if enable_erasure {
            ErasureStage::new(Some(erasure_config))?
        } else {
            ErasureStage::disabled()
        };
        let data_chunk_limit = u64::try_from(capacity.max_data_chunk_size())
            .map_err(|_| EraError::InvalidConfig("data chunk limit exceeds u64".into()))?;
        let packed_file_overhead = u64::try_from(
            size_of::<era_packing::PackedHeader>() + size_of::<era_packing::PackedEntry>(),
        )
        .map_err(|_| EraError::InvalidConfig("packed file overhead exceeds u64".into()))?;
        let header = SuperHeader::new(
            archive_id,
            recipients,
            config.clone(),
            *archive_salt.as_bytes(),
            encrypted_volume_key,
            self.access_policy,
        )?;

        // Unified Volume Management
        let base_path = self
            .output_path
            .parent()
            .map(|p| p.join(base_filename))
            .unwrap_or_else(|| PathBuf::from(base_filename));

        let mut pool_config = VolumePoolConfig::new(&base_path, resolved_volume_count);

        if enable_erasure {
            pool_config = pool_config.for_erasure(erasure_config);
        }

        pool_config = pool_config.with_max_size(max_volume_size);

        // Initialize catalog - MUST be done before VolumePool creation (truncation)
        let catalog = append_catalog.unwrap_or_default();

        let active_header = if append_to_existing {
            append_header.clone().unwrap_or_else(|| header.clone())
        } else {
            header.clone()
        };

        let mut restore_checkpoint_state = false;
        let checkpoint_manager = if self.enable_checkpoint {
            let checkpoint_exists = if append_to_existing {
                append_checkpoint_exists
            } else {
                CheckpointManager::exists(&self.output_path).await?
            };
            let effective_strategy = if self.recovery_options_explicit {
                self.recovery_options.strategy
            } else if checkpoint_exists {
                RecoveryStrategy::Resume
            } else {
                RecoveryStrategy::StartFresh
            };
            restore_checkpoint_state =
                effective_strategy == RecoveryStrategy::Resume && checkpoint_exists;

            let manager = match effective_strategy {
                RecoveryStrategy::StartFresh => {
                    if checkpoint_exists {
                        warn!("Starting fresh, deleting existing checkpoint");
                        let old = CheckpointManager::load_or_create(&self.output_path)?;
                        old.delete()?;
                    }
                    CheckpointManager::new(&self.output_path)
                }
                RecoveryStrategy::Resume => {
                    if !checkpoint_exists {
                        if !output_preexisted {
                            CheckpointManager::new(&self.output_path)
                        } else {
                            return Err(era_common::EraError::CheckpointError(
                                "Resume requested but no prior checkpoint exists. Use StartFresh to begin a new archive."
                                    .into(),
                            ));
                        }
                    } else if append_to_existing {
                        let mut manager = CheckpointManager::new(&self.output_path);
                        for (hash, location) in &recovered_index_entries {
                            manager.record_chunk(*hash, location.clone())?;
                        }
                        manager
                    } else {
                        CheckpointManager::load_from_durable_checkpoint(
                            &self.output_path,
                            &session,
                            &volume_key,
                            *header.salt(),
                            *header.archive_id().0.as_bytes(),
                            header.epoch_id(),
                        )
                        .await?
                    }
                }
                RecoveryStrategy::Abort => {
                    if checkpoint_exists {
                        return Err(era_common::EraError::CheckpointError(
                             "Checkpoint exists. Use Resume strategy to continue or StartFresh to discard."
                                 .into(),
                         ));
                    }
                    CheckpointManager::new(&self.output_path)
                }
            };
            Some(manager)
        } else {
            None
        };

        let volume_pool = if append_to_existing {
            if enable_erasure {
                return Err(era_common::EraError::InvalidFormat(
                    "Append mode is not supported for erasure-coded archives".into(),
                ));
            }
            let footer = append_footer
                .as_ref()
                .ok_or_else(|| era_common::EraError::CorruptedHeader("Missing footer".into()))?;
            VolumePool::open_append_single_at(
                backend.clone(),
                pool_config,
                active_header.clone(),
                footer,
                append_retained_end,
                append_data_block_count,
                vec![append_retained_end],
            )
            .await?
        } else {
            VolumePool::create(backend.clone(), pool_config, active_header.clone()).await?
        };

        info!(
            "Created VolumePool with {} volumes (Strategy: RotatingOffset)",
            volume_pool.volume_count()
        );

        // Create chunk index (internal memory-based index)
        let chunk_index: Arc<dyn ChunkIndex> = create_chunk_index_with_context(
            *active_header.archive_id().0.as_bytes(),
            active_header.epoch_id(),
        )?;

        if !recovered_index_entries.is_empty() {
            chunk_index.start_batch();
            for (hash, location) in recovered_index_entries {
                chunk_index.put(hash, location)?;
            }
            chunk_index.commit_batch()?;
        }

        // Load existing chunk locations from checkpoint if resuming
        if restore_checkpoint_state && !append_to_existing {
            if let Some(ref mgr) = checkpoint_manager {
                chunk_index.start_batch();
                for (hash, location) in mgr.written_chunks() {
                    chunk_index.put(*hash, location.clone())?;
                }
                chunk_index.commit_batch()?;
                info!(
                    "Restored {} chunks from checkpoint",
                    mgr.written_chunks().len()
                );
            }
        }

        let next_block_id = if append_to_existing {
            u64::from(append_data_block_count)
        } else {
            0
        };

        // Create encryption context with all cryptographic state
        let encryption = EncryptionContext::with_starting_block_id(
            session,
            volume_key,
            nonce_context,
            *active_header.archive_id().0.as_bytes(),
            active_header.epoch_id(),
            active_header.volume_sequence() as u32,
            next_block_id,
        );

        // Create volume stage wrapping the pool
        let volume = VolumeStage::new(volume_pool);

        // Create index stage with chunk index and checkpoint
        let index = IndexStage::new(chunk_index, checkpoint_manager);

        // Create write pipeline
        let pipeline = WritePipeline::new(
            encryption,
            erasure,
            volume,
            index,
            config.compression.clone(),
        );

        Ok(ArchiveWriter {
            archive_id,
            output_path: self.output_path,
            key_encapsulation,
            catalog,
            file_reader,
            enable_cdc,
            // Initialize packing stage with k-Bounded Best-Fit
            packing,
            // Small file packing
            small_file_packer: if self.enable_small_file_packing {
                SmallFilePacker::new(
                    (16 * 1024).min(data_chunk_limit.saturating_sub(packed_file_overhead)),
                    (1024 * 1024).min(data_chunk_limit),
                    1000,
                )
            } else {
                SmallFilePacker::disabled()
            },
            pipeline,
            capacity,
            pending_hashes: HashSet::new(),
            finalize_sequence: INITIAL_FINALIZE_SEQUENCE,
            existing_manifest,
        })
    }
}

/// Writer for creating ERA archives
/// Archive writer - creates ERA archives with security-first design
///
/// ## Security Model
///
/// This writer implements the HKDF "Onion Model" key derivation:
/// - **Master Key (MK)**: Derived from password via Argon2id, or from certificate key exchange
/// - **Volume Key (VK)**: Derived from MK via HKDF (per-volume isolation)
/// - **Block Key (BK)**: Derived from VK via HKDF (per-block forward secrecy)
///
/// Each block is encrypted with a unique key. Block keys are derived on-the-fly
/// and never stored in memory longer than necessary.
///
/// ## Authentication Modes
///
/// - **Password mode**: Traditional Argon2id key derivation (~50-300ms overhead)
/// - **Certificate mode**: X25519 key exchange (~0.05ms overhead, ~1000x faster)
pub struct ArchiveWriter {
    archive_id: ArchiveId,
    /// Output path for the archive
    #[allow(dead_code)] // Kept for future use in recovery/diagnostics
    output_path: PathBuf,

    // Certificate mode: key encapsulation data
    /// Encrypted master key for certificate mode (None for password mode)
    key_encapsulation: Option<KeyEncapsulation>,

    // Catalog
    catalog: Catalog,

    // File reading
    file_reader: FileReader,
    enable_cdc: bool,

    // Packing stage for k-Bounded Best-Fit bin packing
    /// Aggregates small chunks into optimal 4MB blocks
    /// Improves space utilization from ~55% to ~95%
    packing: PackingStage,

    // Small file packing
    /// Buffers small files for efficient packing
    small_file_packer: SmallFilePacker,

    // Write pipeline (handles encryption, erasure, volume, index)
    /// Coordinates the flow: chunks → encryption → erasure → volume → index
    pipeline: WritePipeline<LocalStorageBackend>,
    capacity: VolumeCapacity,

    pending_hashes: HashSet<ChunkHash>,

    finalize_sequence: u64,

    existing_manifest: Option<ArchiveManifest>,
}

/// Recursively collect file paths using async I/O.
/// Prevents reactor blocking on large directories.
fn collect_files_async(
    dir: PathBuf,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<PathBuf>>> + Send>> {
    Box::pin(async move {
        let mut files = Vec::new();
        let mut read_dir = tokio::fs::read_dir(&dir)
            .await
            .map_err(era_common::EraError::Io)?;

        while let Some(entry) = read_dir
            .next_entry()
            .await
            .map_err(era_common::EraError::Io)?
        {
            let path = entry.path();
            let file_type = entry.file_type().await.map_err(era_common::EraError::Io)?;

            if file_type.is_file() {
                files.push(path);
            } else if file_type.is_dir() {
                let sub_files = collect_files_async(path).await?;
                files.extend(sub_files);
            }
            // Symlinks and special files are skipped
        }
        Ok(files)
    })
}

impl ArchiveWriter {
    /// Create a new builder
    pub fn builder(output_path: impl Into<PathBuf>) -> ArchiveWriterBuilder {
        ArchiveWriterBuilder::new(output_path)
    }

    fn contains_or_pending(&self, hash: &ChunkHash) -> Result<bool> {
        Ok(self.pipeline.contains(hash)? || self.pending_hashes.contains(hash))
    }

    fn build_manifest(
        &self,
        catalog_bytes: &[u8],
        index_bytes: &[u8],
        committed_horizon: u64,
        volume_committed_ends: Vec<u64>,
    ) -> Result<ArchiveManifest> {
        let catalog_commitment = compute_catalog_commitment(catalog_bytes);
        let index_commitment = compute_index_commitment(index_bytes);
        let epoch_id = self.pipeline.encryption().epoch_id();

        Ok(ArchiveManifest::new(
            epoch_id,
            self.finalize_sequence,
            committed_horizon,
            catalog_commitment,
            index_commitment,
            volume_committed_ends,
        ))
    }

    fn encrypt_manifest_for_volume(
        &self,
        manifest_bytes: &[u8],
        volume_index: u32,
        block_id: u64,
        aead_ctx: &XChaCha20Poly1305Context,
    ) -> Result<EncryptedMacroBlock> {
        encrypt_manifest_block_with_ctx(
            &self.pipeline.encryption().archive_id(),
            self.pipeline.encryption().epoch_id(),
            &self.pipeline.encryption().nonce_context(),
            manifest_bytes,
            volume_index,
            block_id,
            aead_ctx,
        )
    }

    fn block_disk_size(block: &EncryptedMacroBlock) -> Result<u64> {
        u64::try_from(block.data.len())
            .map_err(|_| EraError::Other("encrypted block length exceeds u64::MAX".into()))?
            .checked_add(era_common::BlockHeader::SIZE as u64)
            .ok_or_else(|| EraError::Other("typed block disk size overflow".into()))
    }

    fn block_set_disk_size(blocks: &[EncryptedMacroBlock]) -> Result<u64> {
        blocks.iter().try_fold(0u64, |total, block| {
            total
                .checked_add(Self::block_disk_size(block)?)
                .ok_or_else(|| EraError::Other("typed block set disk size overflow".into()))
        })
    }

    fn metadata_disk_size(catalog: u64, index: u64, manifest: u64) -> Result<u64> {
        catalog
            .checked_add(index)
            .and_then(|size| size.checked_add(manifest))
            .ok_or_else(|| EraError::InvalidConfig("metadata disk size overflow".into()))
    }

    fn typed_plaintext_disk_size(plaintext_len: usize) -> Result<u64> {
        let encrypted_len = plaintext_len
            .checked_add(NONCE_SIZE)
            .and_then(|n| n.checked_add(era_crypto::TAG_SIZE))
            .ok_or_else(|| EraError::Other("typed block size overflow".into()))?;
        u64::try_from(encrypted_len)
            .map_err(|_| EraError::Other("typed block size exceeds u64::MAX".into()))?
            .checked_add(era_common::BlockHeader::SIZE as u64)
            .ok_or_else(|| EraError::Other("typed block disk size overflow".into()))
    }

    fn current_volume_indices(&self) -> Result<Vec<u32>> {
        let volume_count = self.pipeline.volume().pool().volume_count();
        if volume_count == 0 {
            return Err(EraError::InvalidConfig(
                "No writable volumes available for archive finalization".into(),
            ));
        }

        (0..volume_count)
            .map(|slot| {
                self.pipeline
                    .volume()
                    .pool()
                    .volume_sequence(slot)
                    .map(u32::from)
                    .ok_or_else(|| {
                        EraError::InvalidConfig(format!(
                            "Missing volume sequence for slot {}",
                            slot
                        ))
                    })
            })
            .collect()
    }

    fn build_catalog_block_sets(
        &self,
        chunks: &[(Bytes, ChunkHash)],
        catalog_block_ids: &[u64],
        backup_block_ids: Option<&[u64]>,
        volume_indices: &[u32],
    ) -> Result<(CatalogBlockSets, Option<CatalogBlockSets>)> {
        if chunks.is_empty() {
            return Err(EraError::Other("No catalog chunks to encrypt".into()));
        }
        if volume_indices.is_empty() {
            return Err(EraError::InvalidConfig(
                "No target volume indices available for catalog encryption".into(),
            ));
        }
        if catalog_block_ids.len() != chunks.len() {
            return Err(EraError::InvalidConfig(format!(
                "catalog block id count {} does not match chunk count {}",
                catalog_block_ids.len(),
                chunks.len()
            )));
        }
        if let Some(ids) = backup_block_ids {
            if ids.len() != chunks.len() {
                return Err(EraError::InvalidConfig(format!(
                    "backup catalog block id count {} does not match chunk count {}",
                    ids.len(),
                    chunks.len()
                )));
            }
        }

        let mut catalog_blocks_by_volume: Vec<Vec<EncryptedMacroBlock>> = volume_indices
            .iter()
            .map(|_| Vec::with_capacity(chunks.len()))
            .collect();

        for ((chunk_data, hash), logical_block_id) in chunks.iter().zip(catalog_block_ids) {
            for (slot, volume_index) in volume_indices.iter().copied().enumerate() {
                let chunk = UniqueChunk::new(chunk_data.clone(), *hash);
                let compressor = self.pipeline.create_compressor();
                let builder = self
                    .pipeline
                    .encryption()
                    .create_block_builder_with_block_id(
                        compressor,
                        volume_index,
                        *logical_block_id,
                    )?;
                catalog_blocks_by_volume[slot]
                    .push(builder.pack_single_with_type(chunk, era_common::BlockType::Catalog)?);
            }
        }

        let backup_blocks_by_volume = if let Some(ids) = backup_block_ids {
            let mut backups_by_volume: Vec<Vec<EncryptedMacroBlock>> = volume_indices
                .iter()
                .map(|_| Vec::with_capacity(chunks.len()))
                .collect();

            for ((chunk_data, hash), logical_block_id) in chunks.iter().zip(ids) {
                for (slot, volume_index) in volume_indices.iter().copied().enumerate() {
                    let chunk = UniqueChunk::new(chunk_data.clone(), *hash);
                    let compressor = self.pipeline.create_compressor();
                    let builder = self
                        .pipeline
                        .encryption()
                        .create_block_builder_with_block_id(
                            compressor,
                            volume_index,
                            *logical_block_id,
                        )?;
                    backups_by_volume[slot].push(
                        builder.pack_single_with_type(chunk, era_common::BlockType::Catalog)?,
                    );
                }
            }
            Some(backups_by_volume)
        } else {
            None
        };

        Ok((catalog_blocks_by_volume, backup_blocks_by_volume))
    }

    /// Get the archive ID
    pub fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    /// Get the key encapsulation data (for certificate mode).
    ///
    /// Returns `Some(encapsulation)` if certificate mode was used,
    /// or `None` if password mode was used.
    ///
    /// This data should be stored in the archive header so that
    /// the recipient can decrypt the archive using their private key.
    pub fn key_encapsulation(&self) -> Option<&KeyEncapsulation> {
        self.key_encapsulation.as_ref()
    }

    /// Check if certificate mode is being used.
    pub fn is_certificate_mode(&self) -> bool {
        self.key_encapsulation.is_some()
    }

    /// Add a file to the archive
    /// Add a directory or file recursively.
    ///
    /// If `path` is a directory and `recursive` is true, all contents are added.
    /// Directory structure is preserved.
    pub async fn add_path(&mut self, path: &Path, recursive: bool) -> Result<()> {
        let metadata = tokio::fs::metadata(path)
            .await
            .map_err(era_common::EraError::Io)?;

        if metadata.is_dir() {
            if !recursive {
                return Err(era_common::EraError::Io(std::io::Error::new(
                    std::io::ErrorKind::IsADirectory,
                    format!("{} is a directory (use recursive=true)", path.display()),
                )));
            }

            let excluded = self.collect_own_volume_paths();
            let entries = collect_files_async(path.to_path_buf()).await?;
            for entry_path in entries {
                if let Ok(canonical) = entry_path.canonicalize() {
                    if excluded.contains(&canonical) {
                        debug!("Skipping self-referential file: {}", entry_path.display());
                        continue;
                    }
                }
                let relative_path = entry_path.strip_prefix(path).unwrap_or(&entry_path);
                self.add_file_with_path(&entry_path, relative_path).await?;
            }
        } else {
            let stored_path = normalize_single_file_stored_path(path)?;
            self.add_file_with_path(path, &stored_path).await?;
        }
        Ok(())
    }

    fn collect_own_volume_paths(&self) -> HashSet<PathBuf> {
        collect_archive_volume_paths(&self.output_path, None)
    }

    /// Add a file with a specific stored path
    pub async fn add_file_with_path(&mut self, disk_path: &Path, stored_path: &Path) -> Result<()> {
        // Validate stored_path against path traversal attacks
        if stored_path.is_absolute() {
            return Err(EraError::InvalidConfig(
                "stored_path must not be absolute".into(),
            ));
        }
        for component in stored_path.components() {
            if matches!(component, std::path::Component::ParentDir) {
                return Err(EraError::InvalidConfig(
                    "stored_path must not contain '..' components".into(),
                ));
            }
        }

        info!(
            "Adding file: {} as {}",
            disk_path.display(),
            stored_path.display()
        );

        let metadata = tokio::fs::metadata(disk_path)
            .await
            .map_err(era_common::EraError::Io)?;
        let file_size = metadata.len();

        #[cfg(unix)]
        let permissions = {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode()
        };
        #[cfg(not(unix))]
        let permissions = if metadata.permissions().readonly() {
            0o444
        } else {
            0o644
        };

        let mtime = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());

        #[cfg(unix)]
        let xattrs = {
            let mut map = std::collections::BTreeMap::new();
            if let Ok(names) = xattr::list(disk_path) {
                for name in names {
                    if let Ok(Some(value)) = xattr::get(disk_path, &name) {
                        map.insert(name.to_string_lossy().into_owned(), value);
                    }
                }
            }
            map
        };
        #[cfg(not(unix))]
        let xattrs = std::collections::BTreeMap::new();

        let relative_path = stored_path.to_path_buf();

        // Small file path: buffer for packing (but not empty files)
        if self.small_file_packer.should_buffer(file_size) {
            debug!(
                "Buffering small file: {} ({} bytes)",
                disk_path.display(),
                file_size
            );
            let data = tokio::fs::read(disk_path)
                .await
                .map_err(era_common::EraError::Io)?;
            let data_clone = data.clone();
            let hash = tokio::task::spawn_blocking(move || blake3::hash(&data_clone))
                .await
                .map_err(|e| EraError::AsyncError(format!("Task join failed: {}", e)))?;
            let chunk_hash = ChunkHash(*hash.as_bytes());

            if let Some(entries_to_flush) = self.small_file_packer.push(SmallFileEntry {
                path: relative_path,
                data,
                hash: chunk_hash,
                permissions,
                mtime,
                xattrs: xattrs.clone(),
            }) {
                self.flush_packed_files_batch(entries_to_flush).await?;
            }

            return Ok(());
        }

        // Large file path: process immediately
        if self.enable_cdc {
            // Use CDC chunking for large files
            self.add_file_chunked(disk_path, relative_path, permissions, mtime, xattrs)
                .await
        } else {
            // Non-CDC mode: single chunk per file
            self.add_file_single(disk_path, relative_path, permissions, mtime, xattrs)
                .await
        }
    }

    /// Add a single file (legacy compatibility: flattens path)
    ///
    /// Small files (< 16KB by default) are automatically buffered and packed together
    /// for better performance. If CDC is enabled, large files are automatically split
    /// into chunks.
    pub async fn add_file(&mut self, path: &Path) -> Result<()> {
        let relative_path = path
            .file_name()
            .map(PathBuf::from)
            .unwrap_or_else(|| path.to_path_buf());

        self.add_file_with_path(path, &relative_path).await
    }

    /// Add multiple files to the archive in a batch operation
    ///
    /// This is significantly faster than calling `add_file` repeatedly for small files,
    /// as it amortizes the fixed overhead (catalog operations, buffer management) across
    /// all files in the batch.
    ///
    /// ## Performance
    ///
    /// For small files (< 100KB), batch processing can provide 3-5x speedup compared to
    /// individual `add_file` calls by:
    /// - Batching catalog updates
    /// - Optimizing chunk buffer management
    ///
    /// ## Example
    /// ```no_run
    /// # use std::path::Path;
    /// # use era_engine::ArchiveWriterBuilder;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let mut writer = ArchiveWriterBuilder::new("archive.era")
    ///     .password("secret")
    ///     .build()
    ///     .await
    ///     .unwrap();
    ///
    /// let files = vec![
    ///     Path::new("file1.txt"),
    ///     Path::new("file2.txt"),
    ///     Path::new("file3.txt"),
    /// ];
    ///
    /// writer.add_files(&files).await.unwrap();
    /// # }
    /// ```
    pub async fn add_files(&mut self, paths: &[&Path]) -> Result<()> {
        if paths.is_empty() {
            return Ok(());
        }

        info!("Adding {} files in batch", paths.len());

        // Pre-allocate catalog entries
        self.catalog.reserve(paths.len());

        for path in paths {
            let relative_path = path
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_else(|| path.to_path_buf());

            self.add_file_with_path(path, &relative_path).await?;
        }

        debug!("Batch of {} files processed", paths.len());
        Ok(())
    }

    /// Add a file as a single chunk (legacy mode)
    async fn add_file_single(
        &mut self,
        path: &Path,
        relative_path: PathBuf,
        permissions: u32,
        mtime: Option<u64>,
        xattrs: std::collections::BTreeMap<String, Vec<u8>>,
    ) -> Result<()> {
        // Read the file as a single chunk
        let chunk = self.file_reader.read_file(path).await?;
        let hash = chunk.hash;
        let size = chunk.data.len() as u64;

        debug!("File size: {} bytes, hash: {}", size, hash);

        let target_block_size = self.packing.target_block_size();
        if chunk.data.len() > target_block_size {
            let mut chunk_refs = Vec::new();
            let mut offset = 0u64;
            for data in chunk.data.chunks(target_block_size) {
                let chunk_hash = era_crypto::hash(data);
                if !self.contains_or_pending(&chunk_hash)? {
                    self.add_to_pending(UniqueChunk::new(Bytes::copy_from_slice(data), chunk_hash))
                        .await?;
                }
                let chunk_len = u32::try_from(data.len())
                    .map_err(|_| EraError::Other("Chunk length exceeds u32::MAX".into()))?;
                chunk_refs.push(ChunkRef::new(chunk_hash, offset, chunk_len));
                offset = offset
                    .checked_add(u64::from(chunk_len))
                    .ok_or_else(|| EraError::Other("File chunk offset overflow".into()))?;
            }
            let mut entry = FileEntry::file(relative_path, size).with_chunks(chunk_refs);
            entry.permissions = permissions;
            entry.mtime = mtime;
            entry.xattrs = xattrs;
            self.catalog.add(entry);
            return Ok(());
        }

        // Check for dedup: skip if we already have this chunk
        if !self.contains_or_pending(&hash)? {
            // Add to pending batch
            self.add_to_pending(chunk).await?;
        }

        // Create catalog entry with single chunk
        let chunk_len = u32::try_from(size)
            .map_err(|_| EraError::Other("Chunk length exceeds u32::MAX".into()))?;
        let chunk_ref = era_ingest::ChunkRef::new(hash, 0, chunk_len);
        let mut entry = FileEntry::file(relative_path, size).with_chunks(vec![chunk_ref]);
        entry.permissions = permissions;
        entry.mtime = mtime;
        entry.xattrs = xattrs;
        self.catalog.add(entry);

        Ok(())
    }

    /// Add a file with CDC chunking
    async fn add_file_chunked(
        &mut self,
        path: &Path,
        relative_path: PathBuf,
        permissions: u32,
        mtime: Option<u64>,
        xattrs: std::collections::BTreeMap<String, Vec<u8>>,
    ) -> Result<()> {
        // Read and chunk the file via stream to avoid huge memory usage
        let mut stream = self.file_reader.read_file_chunked_stream(path).await?;

        let mut chunk_refs = Vec::new();
        let mut offset = 0u64;
        let mut total_size = 0u64;

        use futures::stream::StreamExt;

        while let Some(res) = stream.next().await {
            let chunk = res?;
            let hash = chunk.hash;
            let length = u32::try_from(chunk.data.len())
                .map_err(|_| EraError::Other("Chunk length exceeds u32::MAX".into()))?;

            total_size += length as u64;

            // Dedup check
            if !self.contains_or_pending(&hash)? {
                self.add_to_pending(chunk).await?;
            }

            chunk_refs.push(ChunkRef::new(hash, offset, length));
            offset += length as u64;
        }

        debug!(
            "File processed: {} bytes, {} chunks",
            total_size,
            chunk_refs.len()
        );

        let mut entry = FileEntry::file(relative_path, total_size).with_chunks(chunk_refs);
        entry.permissions = permissions;
        entry.mtime = mtime;
        entry.xattrs = xattrs;
        self.catalog.add(entry);

        Ok(())
    }

    /// Add chunk to staging pool using k-Bounded Best-Fit
    ///
    /// This method intelligently places chunks into bins for optimal packing.
    /// The staging pool will automatically flush bins when they reach 95% capacity.
    async fn add_to_pending(&mut self, chunk: UniqueChunk) -> Result<()> {
        self.pending_hashes.insert(chunk.hash);
        // Implementation Reform: k-Bounded Best-Fit is MANDATORY for all modes.
        // We use the packing stage to aggregate small CDC chunks into 4MB MacroBlocks.
        // This is critical for L3 Smart Packing.

        // Use k-Bounded Best-Fit packing stage
        // The stage will automatically handle oversized chunks and optimal bin selection
        if let Some(packed) = self.packing.push(chunk) {
            // A bin reached flush threshold - write it
            self.write_packed_block(packed).await?;
        }

        Ok(())
    }

    /// Flush all bins in the packing stage
    /// This should be called at the end of archiving to write all buffered chunks
    async fn flush_pending(&mut self) -> Result<()> {
        let packed_blocks = self.packing.flush_all();

        if packed_blocks.is_empty() {
            return Ok(());
        }

        debug!(
            "Flushing {} packed blocks from packing stage",
            packed_blocks.len()
        );

        for packed in packed_blocks {
            self.write_packed_block(packed).await?;
        }

        Ok(())
    }

    /// Write a packed block to storage
    async fn write_packed_block(&mut self, packed: PackedBlock) -> Result<()> {
        debug!(
            "Writing packed block with {} chunks ({} bytes) from bin {}",
            packed.chunks.len(),
            packed.total_size,
            if packed.bin_id == usize::MAX {
                "SINGLE".to_string()
            } else {
                packed.bin_id.to_string()
            }
        );

        // Use the pipeline to process chunks (handles encryption, erasure, volume, index)
        for chunks in self.capacity.chunk_groups(packed.chunks)? {
            self.pipeline.process_chunks(chunks, Vec::new()).await?;
        }

        Ok(())
    }

    /// Flush buffered small files by packing them together
    async fn flush_packed_files(&mut self) -> Result<()> {
        if self.small_file_packer.is_empty() {
            return Ok(());
        }
        let buffered = self.small_file_packer.take();
        self.flush_packed_files_batch(buffered).await
    }

    /// Flush a batch of small files by packing them together
    async fn flush_packed_files_batch(&mut self, buffered: Vec<SmallFileEntry>) -> Result<()> {
        for batch in bounded_small_file_batches(buffered, self.capacity.max_data_chunk_size())? {
            self.write_packed_files_batch(batch).await?;
        }
        Ok(())
    }

    async fn write_packed_files_batch(&mut self, buffered: Vec<SmallFileEntry>) -> Result<()> {
        if buffered.is_empty() {
            return Ok(());
        }

        let file_count = buffered.len();
        let total_size: u64 = buffered.iter().map(|e| e.data.len() as u64).sum();

        info!(
            "Packing {} small files ({} bytes total)",
            file_count, total_size
        );

        // Deterministic fingerprint alignment: group by hash and pack unique data in hash order
        let mut grouped: HashMap<ChunkHash, Vec<&SmallFileEntry>> = HashMap::new();
        for entry in &buffered {
            grouped.entry(entry.hash).or_default().push(entry);
        }

        let mut unique_entries: Vec<&SmallFileEntry> = grouped
            .values()
            .filter_map(|entries| entries.first().copied())
            .collect();
        unique_entries.sort_by_key(|entry| entry.hash.0);

        let mut hash_to_index: HashMap<ChunkHash, usize> = HashMap::new();
        for (idx, entry) in unique_entries.iter().enumerate() {
            hash_to_index.insert(entry.hash, idx);
        }

        // Create packed chunk with unique files only (deterministic order)
        let mut packed = PackedChunk::new();
        for entry in &unique_entries {
            packed.add_file(&entry.data)?;
        }

        // Serialize the packed chunk
        let packed_data = packed.serialize()?;
        let packed_chunk_size = u32::try_from(packed_data.len())
            .map_err(|_| EraError::InvalidFormat("Block size exceeds u32::MAX".to_string()))?;
        debug!("Packed data size: {} bytes", packed_data.len());

        let (packed_hash, packed_data) = tokio::task::spawn_blocking(move || {
            let hash = blake3::hash(&packed_data);
            (hash, packed_data)
        })
        .await
        .map_err(|e| EraError::AsyncError(format!("Task join failed: {}", e)))?;
        let chunk_hash = ChunkHash(*packed_hash.as_bytes());
        let packed_chunk = UniqueChunk {
            hash: chunk_hash,
            data: Bytes::from(packed_data),
        };

        let should_write = if self.contains_or_pending(&chunk_hash)? {
            self.pipeline.get_location(&chunk_hash)?.is_none()
        } else {
            true
        };
        if should_write {
            self.pipeline
                .process_chunks(vec![packed_chunk], Vec::new())
                .await?;
        }

        // Update catalog for each file
        let packed_file_count = unique_entries.len();
        for entry in buffered.iter() {
            // Check for dedup (file hash already exists)
            // Note: We check pre-write. If it exists, catalog points to old location.
            // If we just wrote it, we just updated the index.

            // Create chunk reference with packed info
            let file_index = *hash_to_index.get(&entry.hash).ok_or_else(|| {
                EraError::IntegrityError("packed file index missing from hash_to_index map".into())
            })?;
            let chunk_ref = ChunkRef::new_packed(
                chunk_hash,
                0, // offset within file (always 0 for single-chunk small files)
                packed_chunk_size,
                file_index,
                packed_file_count,
            );

            let mut catalog_entry = FileEntry::file(entry.path.clone(), entry.data.len() as u64)
                .with_chunks(vec![chunk_ref]);
            catalog_entry.permissions = entry.permissions;
            catalog_entry.mtime = entry.mtime;
            catalog_entry.xattrs = entry.xattrs.clone();

            self.catalog.add(catalog_entry);
        }

        info!("Packed {} files successfully", file_count);
        Ok(())
    }

    /// Add a file from memory
    pub async fn add_bytes(&mut self, name: &str, data: &[u8]) -> Result<()> {
        debug!("Adding in-memory file: {} ({} bytes)", name, data.len());

        let target_block_size = self.packing.target_block_size();

        if data.len() > target_block_size {
            let mut chunk_refs = Vec::new();
            let mut offset = 0u64;

            for chunk in data.chunks(target_block_size) {
                let hash = era_crypto::hash(chunk);

                if !self.contains_or_pending(&hash)? {
                    let chunk = UniqueChunk::new(Bytes::copy_from_slice(chunk), hash);
                    self.add_to_pending(chunk).await?;
                }

                let chunk_len = u32::try_from(chunk.len())
                    .map_err(|_| EraError::Other("Chunk length exceeds u32::MAX".into()))?;
                chunk_refs.push(ChunkRef::new(hash, offset, chunk_len));
                offset += chunk.len() as u64;
            }

            let entry =
                FileEntry::file(PathBuf::from(name), data.len() as u64).with_chunks(chunk_refs);
            self.catalog.add(entry);
            return Ok(());
        }

        let hash = era_crypto::hash(data);

        // Dedup check
        if !self.contains_or_pending(&hash)? {
            let chunk = UniqueChunk::new(Bytes::copy_from_slice(data), hash);
            self.add_to_pending(chunk).await?;
        }

        // Create catalog entry with single chunk
        let chunk_len = u32::try_from(data.len())
            .map_err(|_| EraError::Other("Chunk length exceeds u32::MAX".into()))?;
        let chunk_ref = era_ingest::ChunkRef::new(hash, 0, chunk_len);
        let entry =
            FileEntry::file(PathBuf::from(name), data.len() as u64).with_chunks(vec![chunk_ref]);
        self.catalog.add(entry);

        Ok(())
    }

    /// Finalize the archive
    pub async fn finalize(mut self) -> Result<ArchiveStats> {
        info!("Finalizing archive...");

        // Flush any buffered small files first
        self.flush_packed_files().await?;

        // Flush any remaining pending chunks
        self.flush_pending().await?;

        // Flush erasure stripe buffer if not empty
        // This ensures the last partial stripe is written (with padding)
        self.pipeline.flush_stripe().await?;

        // Embed critical metadata in-archive (self-contained recovery)
        self.write_internal_metadata().await?;

        // Flush any metadata chunks that were added
        self.flush_pending().await?;
        self.pipeline.flush_stripe().await?;

        self.catalog
            .block_locations
            .extend(self.pipeline.take_written_block_locations());

        let data_committed_ends: Vec<u64> = self
            .pipeline
            .volume()
            .pool()
            .committed_ends()
            .into_iter()
            .map(|(_, committed_end)| committed_end)
            .collect();
        self.pipeline.commit_durable_checkpoint().await?;
        debug!("Durable checkpoint committed before catalog write");

        // Serialize catalog
        let catalog_bytes = self.catalog.to_bytes()?;

        // Split catalog data so every compressed, encrypted canonical block fits a fresh volume.
        // The first chunk carries the 12-byte catalog framing in the same producer budget.
        let max_catalog_chunk = self
            .capacity
            .max_catalog_chunk_size()
            .min(MAX_CATALOG_CHUNK_SIZE);
        let chunks = frame_and_chunk_catalog(&catalog_bytes, max_catalog_chunk)?;
        let catalog_chunk_count = chunks.len();

        let catalog_block_ids: Vec<u64> = (0..chunks.len())
            .map(|_| self.pipeline.reserve_block_id())
            .collect::<Result<_>>()?;
        let backup_block_ids: Option<Vec<u64>> = if self.pipeline.erasure_enabled() {
            Some(
                (0..chunks.len())
                    .map(|_| self.pipeline.reserve_block_id())
                    .collect::<Result<_>>()?,
            )
        } else {
            None
        };
        let catalog_block_id = u32::try_from(catalog_block_ids[0])
            .map_err(|_| EraError::Other("Catalog block ID exceeds u32::MAX".into()))?;

        let mut index_builder = self.pipeline.index().take_index_builder();
        let index_total_size = if let Some(builder) = index_builder.as_mut() {
            builder.estimated_finalized_disk_size()?
        } else {
            0
        };
        if let Some(old_manifest) = &self.existing_manifest {
            self.finalize_sequence = next_finalize_sequence(old_manifest.finalize_sequence)?;
        }

        let provisional_committed_ends = data_committed_ends;
        let provisional_manifest = self.build_manifest(
            &catalog_bytes,
            &[],
            provisional_committed_ends
                .iter()
                .copied()
                .max()
                .unwrap_or(era_volume::DATA_REGION_START),
            provisional_committed_ends.clone(),
        )?;
        let current_manifest_total_size = Self::typed_plaintext_disk_size(
            provisional_manifest
                .to_bytes_with_header_digests(0, &vec![[0; 32]; provisional_committed_ends.len()])?
                .len(),
        )?;

        let mut volume_indices = self.current_volume_indices()?;
        let (mut catalog_blocks_by_volume, mut backup_blocks_by_volume) = self
            .build_catalog_block_sets(
                &chunks,
                &catalog_block_ids,
                backup_block_ids.as_deref(),
                &volume_indices,
            )?;

        let backup_catalog_size = match &backup_blocks_by_volume {
            Some(sets) => Self::block_set_disk_size(&sets[0])?,
            None => 0,
        };
        let primary_catalog_size = Self::block_set_disk_size(&catalog_blocks_by_volume[0])?;
        let catalog_total_size = primary_catalog_size
            .checked_add(backup_catalog_size)
            .ok_or_else(|| EraError::Other("catalog fanout disk size overflow".into()))?;
        let current_metadata_size = Self::metadata_disk_size(
            catalog_total_size,
            index_total_size,
            current_manifest_total_size,
        )?;
        let rotation_needed = !self
            .pipeline
            .volume()
            .pool()
            .check_typed_block_space(current_metadata_size)
            .is_empty();
        let mut rotated_committed_ends = None;
        let manifest_total_size = if rotation_needed {
            let rotated_ends = extend_data_ends_for_rotation(
                &provisional_committed_ends,
                self.pipeline.volume().volume_count(),
            )?;
            let rotated_manifest = self.build_manifest(
                &catalog_bytes,
                &[],
                rotated_ends
                    .iter()
                    .copied()
                    .max()
                    .unwrap_or(era_volume::DATA_REGION_START),
                rotated_ends.clone(),
            )?;
            rotated_committed_ends = Some(rotated_ends);
            Self::typed_plaintext_disk_size(
                rotated_manifest
                    .to_bytes_with_header_digests(
                        0,
                        &vec![[0; 32]; rotated_manifest.volume_committed_ends.len()],
                    )?
                    .len(),
            )?
        } else {
            current_manifest_total_size
        };
        let budget = FinalizeBudgetSummary {
            catalog_chunks: catalog_chunk_count,
            primary_catalog: primary_catalog_size,
            backup_catalog: backup_catalog_size,
            index: index_total_size,
            manifest: manifest_total_size,
        };
        let rotated = if rotation_needed {
            let required_without_index =
                Self::metadata_disk_size(catalog_total_size, 0, manifest_total_size)?;
            match self
                .pipeline
                .volume_mut()
                .precheck_and_rotate_if_needed(
                    catalog_total_size,
                    index_total_size,
                    manifest_total_size,
                )
                .await
            {
                Ok(rotated) => rotated,
                Err(EraError::VolumeSpaceExhausted { available, .. })
                    if backup_blocks_by_volume.is_some()
                        && index_builder.is_some()
                        && required_without_index <= available =>
                {
                    warn!(
                        catalog_bytes = catalog_total_size,
                        index_bytes = index_total_size,
                        manifest_bytes = manifest_total_size,
                        available_bytes = available,
                        "Omitting the embedded index to preserve both EC catalog copies within the volume cap"
                    );
                    index_builder = None;
                    let current_without_index = Self::metadata_disk_size(
                        catalog_total_size,
                        0,
                        current_manifest_total_size,
                    )?;
                    if self
                        .pipeline
                        .volume()
                        .pool()
                        .check_typed_block_space(current_without_index)
                        .is_empty()
                    {
                        false
                    } else {
                        self.pipeline
                            .volume_mut()
                            .precheck_and_rotate_if_needed(
                                catalog_total_size,
                                0,
                                manifest_total_size,
                            )
                            .await
                            .map_err(|err| budget.enrich_error(err, true))?
                    }
                }
                Err(error) => return Err(budget.enrich_error(error, false)),
            }
        } else {
            false
        };

        if rotated {
            volume_indices = self.current_volume_indices()?;
            (catalog_blocks_by_volume, backup_blocks_by_volume) = self.build_catalog_block_sets(
                &chunks,
                &catalog_block_ids,
                backup_block_ids.as_deref(),
                &volume_indices,
            )?;
        }

        let volume_committed_ends = if rotated {
            rotated_committed_ends.ok_or_else(|| {
                EraError::IntegrityError("rotated manifest is missing data-only ends".into())
            })?
        } else {
            provisional_committed_ends
        };
        let committed_horizon = volume_committed_ends
            .iter()
            .copied()
            .max()
            .unwrap_or(era_volume::DATA_REGION_START);

        let catalog_locations = self
            .pipeline
            .volume_mut()
            .write_catalog_block_sets_to_all(
                &catalog_blocks_by_volume,
                backup_blocks_by_volume.as_deref(),
            )
            .await?;

        debug!(
            "Catalog ({} blocks, block_id={}) written to {} volumes for full redundancy",
            catalog_blocks_by_volume[0].len(),
            catalog_block_id,
            catalog_locations.len()
        );

        // Finalize a complete V2.1 index independently on every active volume.
        let (index_locations, index_bytes) = if let Some(mut builder) = index_builder {
            let session = self.pipeline.encryption().session().try_clone()?;
            let volume_key = self.pipeline.encryption().volume_key().try_clone()?;
            let nonce_context = self.pipeline.encryption().nonce_context();
            let index_start_block_id = self.pipeline.blocks_written();

            let (meta_index, locations) = self
                .pipeline
                .volume_mut()
                .write_index_fanout(
                    &mut builder,
                    &session,
                    &volume_key,
                    nonce_context,
                    index_start_block_id,
                )
                .await?;

            let index_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&meta_index)
                .map_err(|e| EraError::Serialization(e.to_string()))?;
            let index_plaintext = index_bytes.to_vec();
            let (manifest_offset, manifest_size, index_block_id) =
                locations.first().copied().ok_or_else(|| {
                    EraError::IntegrityError("Index fanout returned no manifest locations".into())
                })?;

            let index_blocks_consumed =
                u64::from(index_block_id).saturating_sub(index_start_block_id) + 1;
            self.pipeline.advance_block_id(index_blocks_consumed)?;

            debug!(
                "V2.1 index finalized: root at offset={}, size={}, block_id={}, fanout={}",
                manifest_offset,
                manifest_size,
                index_block_id,
                locations.len(),
            );

            (Some(locations), index_plaintext)
        } else {
            (None, Vec::new())
        };

        let manifest = if let Some(ref old_manifest) = self.existing_manifest {
            if volume_committed_ends.len() < old_manifest.volume_committed_ends.len() {
                return Err(EraError::IntegrityError(format!(
                    "Volume count decreased in append mode: {} -> {}",
                    old_manifest.volume_committed_ends.len(),
                    volume_committed_ends.len()
                )));
            }

            for (seq, (&new_end, &old_end)) in volume_committed_ends
                .iter()
                .zip(old_manifest.volume_committed_ends.iter())
                .enumerate()
            {
                if new_end < old_end {
                    return Err(EraError::IntegrityError(format!(
                        "Volume {} committed_end decreased: {} -> {}",
                        seq, old_end, new_end
                    )));
                }
            }

            self.finalize_sequence = next_finalize_sequence(old_manifest.finalize_sequence)?;
            self.build_manifest(
                &catalog_bytes,
                &index_bytes,
                committed_horizon,
                volume_committed_ends,
            )?
        } else {
            self.build_manifest(
                &catalog_bytes,
                &index_bytes,
                committed_horizon,
                volume_committed_ends,
            )?
        };
        let header_digests = self
            .pipeline
            .volume_mut()
            .pool_mut()
            .finalized_volume_header_digests()?;

        let manifest_block_id = self.pipeline.reserve_block_id()?;

        let session = self.pipeline.encryption().session();
        let volume_key = self.pipeline.encryption().volume_key();
        let nonce_context = self.pipeline.encryption().nonce_context();
        let block_key = session.derive_block_key(volume_key, manifest_block_id, &nonce_context)?;
        let derived_key = block_key.to_derived_key()?;
        let aead_ctx = XChaCha20Poly1305Context::from_derived_key(&derived_key)?;

        let manifest_blocks: Vec<EncryptedMacroBlock> = volume_indices
            .into_iter()
            .map(|volume_index| {
                let sequence = u16::try_from(volume_index)
                    .map_err(|_| EraError::InvalidConfig("Volume sequence exceeds u16".into()))?;
                self.encrypt_manifest_for_volume(
                    &manifest.to_bytes_with_header_digests(sequence, &header_digests)?,
                    volume_index,
                    manifest_block_id,
                    &aead_ctx,
                )
            })
            .collect::<Result<_>>()?;

        let manifest_locations = self
            .pipeline
            .volume_mut()
            .write_manifest_to_all(&manifest_blocks)
            .await?;

        debug!(
            "Manifest (block_id={}) written to {} volumes",
            manifest_block_id,
            manifest_locations.len()
        );

        // Finalize the pool with per-volume catalog, index, and manifest locations.
        let pool_stats = self
            .pipeline
            .volume_mut()
            .finalize_with_manifest(
                &catalog_locations,
                index_locations.as_deref(),
                Some(&manifest_locations),
            )
            .await?;

        info!(
            "VolumePool finalized: {} volumes, {} total bytes, {} blocks",
            pool_stats.volume_count,
            pool_stats.total_bytes_written,
            pool_stats.total_blocks_written
        );

        // NOTE: Sidecar checkpoint files are no longer used (v2.2+).
        // Checkpoints are now stored as typed blocks inside the .era volume.

        // Calculate total blocks written using our counter
        let blocks_written = self.pipeline.blocks_written();

        let stats = ArchiveStats {
            archive_id: self.archive_id,
            total_files: self
                .catalog
                .entries
                .iter()
                .filter(|entry| !is_internal_path(&entry.path))
                .count() as u64,
            total_size: self
                .catalog
                .entries
                .iter()
                .filter(|entry| !is_internal_path(&entry.path))
                .map(|entry| entry.size)
                .sum(),
            blocks_written,
        };

        info!(
            "Archive finalized: {} files, {} bytes, {} blocks",
            stats.total_files, stats.total_size, stats.blocks_written
        );

        Ok(stats)
    }

    async fn write_internal_metadata(&mut self) -> Result<()> {
        if self.pipeline.index().checkpoint_manager().is_some() {
            debug!(
                "Skipping legacy internal checkpoint metadata file; durable checkpoint typed block is authoritative"
            );
        }

        Ok(())
    }
}

fn is_internal_path(path: &Path) -> bool {
    path.to_string_lossy().starts_with(INTERNAL_META_PREFIX)
}

/// Frame serialized catalog plaintext with its 12-byte header and split into bounded chunks.
fn frame_and_chunk_catalog(
    catalog_bytes: &[u8],
    max_catalog_chunk: usize,
) -> Result<Vec<(Bytes, ChunkHash)>> {
    let catalog_chunk_count = catalog_bytes.len().div_ceil(max_catalog_chunk).max(1);
    let catalog_chunk_count_u32 = u32::try_from(catalog_chunk_count)
        .map_err(|_| EraError::Other("Catalog chunk count exceeds u32::MAX".into()))?;

    let total_len = u64::try_from(catalog_bytes.len())
        .map_err(|_| EraError::InvalidConfig("Catalog plaintext length exceeds u64".into()))?;
    if catalog_chunk_count_u32 > MAX_CATALOG_CHUNKS || total_len > MAX_CATALOG_PLAINTEXT_SIZE {
        return Err(EraError::InvalidConfig(
            "Catalog framing exceeds its chunk or plaintext bound".into(),
        ));
    }

    let mut first_chunk_prefix = Vec::with_capacity(12);
    first_chunk_prefix.extend_from_slice(&catalog_chunk_count_u32.to_le_bytes());
    first_chunk_prefix.extend_from_slice(&total_len.to_le_bytes());

    if catalog_bytes.is_empty() {
        let chunk_data = Bytes::from(first_chunk_prefix);
        let hash = era_crypto::hash(&chunk_data);
        return Ok(vec![(chunk_data, hash)]);
    }

    Ok(catalog_bytes
        .chunks(max_catalog_chunk)
        .enumerate()
        .map(|(i, raw_chunk)| {
            let chunk_data = if i == 0 {
                let mut buf = Vec::with_capacity(first_chunk_prefix.len() + raw_chunk.len());
                buf.extend_from_slice(&first_chunk_prefix);
                buf.extend_from_slice(raw_chunk);
                Bytes::from(buf)
            } else {
                Bytes::copy_from_slice(raw_chunk)
            };
            let hash = era_crypto::hash(&chunk_data);
            (chunk_data, hash)
        })
        .collect())
}

/// Encrypt a serialized v8.2 manifest payload into a `BlockType::Manifest` macro block.
fn encrypt_manifest_block_with_ctx(
    archive_id: &[u8; 16],
    epoch_id: u32,
    nonce_context: &[u8; 16],
    manifest_bytes: &[u8],
    volume_index: u32,
    block_id: u64,
    aead_ctx: &XChaCha20Poly1305Context,
) -> Result<EncryptedMacroBlock> {
    let nonce = derive_nonce_with_volume_index(nonce_context, BlockId::new(block_id), volume_index);
    let aad = build_aad(
        archive_id,
        epoch_id,
        era_common::BlockType::Manifest,
        volume_index,
        BlockId::new(block_id),
    );
    let ciphertext = aead_ctx.encrypt(&nonce, &aad, manifest_bytes)?;
    let original_size = u32::try_from(manifest_bytes.len())
        .map_err(|_| EraError::Other("Manifest size exceeds u32::MAX".into()))?;

    let mut data = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    data.extend_from_slice(&nonce);
    data.extend_from_slice(&ciphertext);

    Ok(EncryptedMacroBlock {
        block_id: BlockId::new(block_id),
        data: Bytes::from(data),
        original_size,
        compressed_size: original_size,
        chunk_count: 1,
    })
}

fn build_append_auth_providers(
    auth_mode: &AuthMode,
    append_keypair: Option<&EraKeyPair>,
    append_hybrid_keypair: Option<&HybridKeyPair>,
) -> Result<Vec<Box<dyn AuthProvider>>> {
    let mut providers: Vec<Box<dyn AuthProvider>> = Vec::new();
    match auth_mode {
        AuthMode::Password(pwd)
        | AuthMode::Hybrid { password: pwd, .. }
        | AuthMode::HybridKemWithPassword { password: pwd, .. } => {
            providers.push(Box::new(PasswordProvider::new(pwd.as_str().to_string())));
        }
        AuthMode::Certificate(_) | AuthMode::HybridKemCertificate(_) => {}
    }
    if let Some(kp) = append_keypair {
        providers.push(Box::new(CertificateProvider::new(kp.clone())));
    }
    if let Some(kp) = append_hybrid_keypair {
        providers.push(Box::new(HybridCertificateProvider::new(kp.clone())));
    }
    if providers.is_empty() {
        return Err(EraError::InvalidKey(
            "Appending to a certificate-encrypted archive requires a private keypair (.keypair() or .hybrid_keypair())"
                .into(),
        ));
    }
    Ok(providers)
}

async fn recover_append_index_entries(
    reader: &ArchiveReader,
    catalog: &Catalog,
    committed_end: u64,
    block_spans: &[(u64, u32)],
    compression: &era_common::CompressionConfig,
) -> Result<Vec<(ChunkHash, BlockLocation)>> {
    let mut loc_by_slot: HashMap<u32, BlockLocation> =
        HashMap::with_capacity(catalog.block_locations.len());
    for loc in &catalog.block_locations {
        loc_by_slot.insert(loc.slot_index, loc.clone());
    }

    if let Some(index_reader) = reader.index_reader() {
        let physical_chunk_hashes: HashSet<ChunkHash> = catalog
            .entries
            .iter()
            .flat_map(|entry| entry.chunks.iter())
            .map(|chunk| chunk.hash)
            .collect();
        let mut entries = Vec::with_capacity(index_reader.total_entry_count());
        for entry in index_reader.iter_entries() {
            if !physical_chunk_hashes.contains(entry.hash()) {
                continue;
            }
            let slot_index = u32::try_from(entry.block_id().sequence())
                .map_err(|_| EraError::IntegrityError("Index block_id exceeds u32".into()))?;
            let location = loc_by_slot.get(&slot_index).cloned().unwrap_or_else(|| {
                let (offset, len) = block_spans
                    .get(slot_index as usize)
                    .copied()
                    .unwrap_or((0, entry.length()));
                BlockLocation::single(entry.volume_id(), slot_index, offset, len)
            });
            entries.push((*entry.hash(), location));
        }
        return Ok(entries);
    }

    if block_spans.is_empty() {
        return Ok(Vec::new());
    }

    let vol0 = reader
        .volume_readers()
        .first()
        .ok_or_else(|| era_common::EraError::CorruptedHeader("Missing volume 0 reader".into()))?;
    let compressor: Box<dyn era_codec::Compressor> = match compression.algorithm {
        era_common::CompressionAlgorithm::None => Box::new(era_codec::NoCompressor),
        era_common::CompressionAlgorithm::Zstd => {
            Box::new(era_codec::ZstdCompressor::new(compression.level))
        }
        era_common::CompressionAlgorithm::LZ4 => {
            Box::new(era_codec::LZ4Compressor::new(compression.level))
        }
    };
    let mut iter = SessionBlockIterator::new(
        vol0,
        reader.session(),
        reader.volume_key(),
        reader.nonce_context(),
        reader.archive_id_bytes(),
        reader.epoch_id(),
        compressor,
        Some(vec![committed_end]),
    );
    let vol_id = vol0.header().volume_id();
    let mut entries = Vec::new();
    while let Some(block_res) = iter.next_block().await {
        let decoded = block_res?;
        let location = loc_by_slot
            .get(&decoded.block_index)
            .cloned()
            .unwrap_or_else(|| {
                let (offset, len) = block_spans
                    .get(decoded.block_index as usize)
                    .copied()
                    .unwrap_or((0, 1));
                BlockLocation::single(vol_id, decoded.block_index, offset, len)
            });
        for (hash, _) in decoded.chunks {
            entries.push((hash, location.clone()));
        }
    }
    Ok(entries)
}

struct FinalizeBudgetSummary {
    catalog_chunks: usize,
    primary_catalog: u64,
    backup_catalog: u64,
    index: u64,
    manifest: u64,
}

impl FinalizeBudgetSummary {
    fn enrich_error(&self, error: EraError, index_omitted: bool) -> EraError {
        match error {
            EraError::VolumeSpaceExhausted {
                volume,
                required,
                available,
                message,
            } => {
                let index_bytes = if index_omitted { 0 } else { self.index };
                let catalog_budget = self
                    .primary_catalog
                    .saturating_add(self.backup_catalog)
                    .saturating_add(self.manifest);
                let detail = if self.catalog_chunks > 1 || catalog_budget > available {
                    format!(
                        "multi-block catalog metadata exceeds single-volume budget ({available} bytes); increase --max-volume-size \
                         (catalog={} bytes in {} chunks, backup catalog={} bytes, index={} bytes, manifest={} bytes)",
                        self.primary_catalog,
                        self.catalog_chunks,
                        self.backup_catalog,
                        index_bytes,
                        self.manifest
                    )
                } else {
                    format!(
                        "{message}; increase --max-volume-size (catalog={} bytes, backup catalog={} bytes, index={} bytes, manifest={} bytes)",
                        self.primary_catalog, self.backup_catalog, index_bytes, self.manifest
                    )
                };
                EraError::VolumeSpaceExhausted {
                    volume,
                    required,
                    available,
                    message: detail,
                }
            }
            other => other,
        }
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

/// Compute canonical paths of volume files associated with an archive output base path.
///
/// Canonicalizes the parent directory (so paths that do not exist yet or omit the `.era`
/// extension still resolve consistently) and derives volume paths via `era_volume::volume_path`.
pub fn collect_archive_volume_paths(
    output: &Path,
    expected_volumes: Option<usize>,
) -> HashSet<PathBuf> {
    let mut paths = HashSet::new();
    let Some(file_name) = output.file_name() else {
        return paths;
    };
    let parent = match output.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let Ok(canonical_parent) = parent.canonicalize() else {
        return paths;
    };
    let canonical_base = canonical_parent.join(file_name);

    let min_volumes = expected_volumes.unwrap_or(1).max(1);
    for seq_idx in 0..min_volumes {
        let Ok(seq) = u16::try_from(seq_idx) else {
            break;
        };
        let vol_path = era_volume::volume_path(&canonical_base, seq);
        let resolved = vol_path.canonicalize().unwrap_or(vol_path);
        paths.insert(resolved);
    }

    let start_seq = u16::try_from(min_volumes).unwrap_or(u16::MAX);
    for seq in start_seq..=u16::MAX {
        let vol_path = era_volume::volume_path(&canonical_base, seq);
        if vol_path.exists() {
            let resolved = vol_path.canonicalize().unwrap_or(vol_path);
            paths.insert(resolved);
        } else {
            break;
        }
    }

    paths
}

fn normalize_single_file_stored_path(path: &Path) -> Result<PathBuf> {
    let has_parent_dir = path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir));
    if path.is_absolute() || has_parent_dir {
        return path
            .file_name()
            .map(PathBuf::from)
            .ok_or_else(|| EraError::InvalidConfig("stored_path has no valid file name".into()));
    }
    let normalized: PathBuf = path
        .components()
        .filter(|c| !matches!(c, std::path::Component::CurDir))
        .collect();
    if normalized.as_os_str().is_empty() {
        return Err(EraError::InvalidConfig(
            "stored_path has no valid file name".into(),
        ));
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sequence::INITIAL_FINALIZE_SEQUENCE;
    use era_common::BlockType;
    use era_crypto::{compute_catalog_commitment, compute_index_commitment, NONCE_SIZE};
    use era_volume::volume_path;
    use std::io::Write;
    use std::path::Path;
    use tempfile::{NamedTempFile, TempDir};

    fn finalized_volume_paths(archive_path: &Path) -> Vec<PathBuf> {
        (0..1024u16)
            .map(|sequence| volume_path(archive_path, sequence))
            .take_while(|path| path.exists())
            .collect()
    }

    async fn read_primary_manifest(archive_path: &Path, password: &str) -> ArchiveManifest {
        let reader = ArchiveReader::open(archive_path, password).await.unwrap();
        let footer = reader.primary_footer().unwrap();
        let backend = LocalStorageBackend::new(archive_path.parent().unwrap());
        let base_name = Path::new(archive_path.file_name().unwrap());
        let volume_reader = VolumeReader::open(&backend, base_name).await.unwrap();
        let manifest_block_id = footer.manifest_block_id();
        let manifest_location = BlockLocation::single(
            reader.header().volume_id(),
            manifest_block_id,
            footer.manifest_offset(),
            0,
        );
        let encrypted_block = volume_reader.read_block(&manifest_location).await.unwrap();

        let nonce_bytes: [u8; NONCE_SIZE] = encrypted_block.data[..NONCE_SIZE].try_into().unwrap();
        let ciphertext = &encrypted_block.data[NONCE_SIZE..];
        let nonce_context = reader.nonce_context();
        let block_key = reader
            .session()
            .derive_block_key(
                reader.volume_key(),
                manifest_block_id as u64,
                &nonce_context,
            )
            .unwrap();
        let derived_key = block_key.to_derived_key().unwrap();
        let aead_ctx = XChaCha20Poly1305Context::from_derived_key(&derived_key).unwrap();
        let archive_id = reader.archive_id_bytes();
        let aad = build_aad(
            &archive_id,
            reader.epoch_id(),
            BlockType::Manifest,
            u32::from(reader.header().volume_sequence()),
            BlockId::new(manifest_block_id as u64),
        );
        let decrypted = aead_ctx.decrypt(&nonce_bytes, &aad, ciphertext).unwrap();

        ArchiveManifest::from_bytes(&decrypted).unwrap()
    }

    #[tokio::test]
    async fn test_manifest_build_and_encryption() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("manifest.era");

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .await
            .unwrap();

        let catalog_bytes = b"catalog plaintext".to_vec();
        let index_bytes = b"index plaintext".to_vec();

        let manifest: ArchiveManifest = writer
            .build_manifest(
                &catalog_bytes,
                &index_bytes,
                era_volume::DATA_REGION_START,
                vec![era_volume::DATA_REGION_START],
            )
            .unwrap();

        assert_eq!(
            manifest.catalog_commitment,
            era_crypto::compute_catalog_commitment(&catalog_bytes)
        );
        assert_eq!(
            manifest.index_commitment,
            era_crypto::compute_index_commitment(&index_bytes)
        );
        assert_eq!(manifest.epoch_id, writer.pipeline.encryption().epoch_id());
        assert_eq!(manifest.finalize_sequence, INITIAL_FINALIZE_SEQUENCE);
        assert_eq!(manifest.committed_horizon, era_volume::DATA_REGION_START);
        assert_eq!(
            manifest.volume_committed_ends,
            vec![era_volume::DATA_REGION_START]
        );

        let manifest_without_index = writer
            .build_manifest(
                &catalog_bytes,
                &[],
                era_volume::DATA_REGION_START,
                vec![era_volume::DATA_REGION_START],
            )
            .unwrap();
        assert_eq!(manifest_without_index.index_commitment, [0u8; 32]);

        writer.finalize_sequence = 7;

        writer
            .catalog
            .block_locations
            .push(era_common::BlockLocation::single(
                era_common::VolumeId::new(),
                3,
                4096,
                512,
            ));

        let manifest_with_block_location = writer
            .build_manifest(&catalog_bytes, &[], 4608, vec![4608])
            .unwrap();
        assert_eq!(manifest_with_block_location.finalize_sequence, 7);
        assert_eq!(manifest_with_block_location.committed_horizon, 4608);

        let block_id = era_common::BlockId::new(42);
        let nonce_volume_0 = era_crypto::derive_nonce_with_volume_index(
            &writer.pipeline.encryption().nonce_context(),
            block_id,
            0,
        );
        let nonce_volume_1 = era_crypto::derive_nonce_with_volume_index(
            &writer.pipeline.encryption().nonce_context(),
            block_id,
            1,
        );
        assert_ne!(nonce_volume_0, nonce_volume_1);

        let cipher = XChaCha20Poly1305Context::new(&[0x42; 32]).unwrap();
        let archive_id = writer.pipeline.encryption().archive_id();
        let epoch_id = writer.pipeline.encryption().epoch_id();
        let plaintext = b"manifest plaintext";

        let mut aad_volume_0 = [0u8; 32];
        aad_volume_0[0..16].copy_from_slice(&archive_id);
        aad_volume_0[16..20].copy_from_slice(&epoch_id.to_le_bytes());
        aad_volume_0[20..24].copy_from_slice(&0u32.to_le_bytes());
        aad_volume_0[24..32].copy_from_slice(&block_id.sequence().to_le_bytes());

        let mut aad_volume_1 = [0u8; 32];
        aad_volume_1[0..16].copy_from_slice(&archive_id);
        aad_volume_1[16..20].copy_from_slice(&epoch_id.to_le_bytes());
        aad_volume_1[20..24].copy_from_slice(&1u32.to_le_bytes());
        aad_volume_1[24..32].copy_from_slice(&block_id.sequence().to_le_bytes());

        let ciphertext_volume_0 = cipher
            .encrypt(&nonce_volume_0, &aad_volume_0, plaintext)
            .unwrap();
        let ciphertext_volume_1 = cipher
            .encrypt(&nonce_volume_1, &aad_volume_1, plaintext)
            .unwrap();

        assert_ne!(ciphertext_volume_0, ciphertext_volume_1);
    }

    #[tokio::test]
    async fn test_create_archive() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.era");

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .await
            .unwrap();

        writer.add_bytes("hello.txt", b"Hello, ERA!").await.unwrap();

        let stats = writer.finalize().await.unwrap();
        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.total_size, 11);
    }

    #[tokio::test]
    async fn test_add_file() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.era");

        // Create a test file
        let mut test_file = NamedTempFile::new().unwrap();
        test_file.write_all(b"Test file content").unwrap();
        test_file.flush().unwrap();

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .await
            .unwrap();

        writer.add_file(test_file.path()).await.unwrap();

        let stats = writer.finalize().await.unwrap();
        assert_eq!(stats.total_files, 1);
        assert!(stats.blocks_written >= 2); // data + catalog
    }

    #[tokio::test]
    async fn test_builder_uses_archive_chunking_config() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("chunk_cfg.era");

        let mut config = ArchiveConfig::default();
        config.chunking.min_size = 2 * 1024;
        config.chunking.avg_size = 8 * 1024;
        config.chunking.max_size = 16 * 1024;

        let writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .config(config)
            .enable_cdc(true)
            .build()
            .await
            .unwrap();

        let mut temp_file = NamedTempFile::new().unwrap();
        let data = vec![0xAB; 300 * 1024];
        temp_file.write_all(&data).unwrap();
        temp_file.flush().unwrap();

        let chunks = writer
            .file_reader
            .read_file_chunked(temp_file.path())
            .await
            .unwrap();

        assert!(!chunks.is_empty());
        for chunk in chunks {
            assert!(chunk.data.len() <= 16 * 1024);
        }
    }

    #[tokio::test]
    async fn test_p3_7_builder_resolves_configured_capacity_and_override() {
        for (configured_size, override_size) in
            [(1024 * 1024, None), (2 * 1024 * 1024, Some(1024 * 1024))]
        {
            let temp_dir = TempDir::new().unwrap();
            let archive_path = temp_dir.path().join("resolved_capacity.era");
            let mut config = ArchiveConfig::default();
            config.volume.max_size = configured_size;
            config.compression.algorithm = era_common::CompressionAlgorithm::None;
            config.erasure = None;

            let mut builder = ArchiveWriter::builder(&archive_path)
                .password("test_password")
                .config(config)
                .enable_erasure(false)
                .target_block_size(512 * 1024)
                .enable_cdc(false);
            if let Some(size) = override_size {
                builder = builder.max_volume_size(size);
            }
            let mut writer = builder.build().await.unwrap();
            let data: Vec<u8> = (0..3 * 512 * 1024).map(|i| (i % 251) as u8).collect();
            writer.add_bytes("payload.bin", &data).await.unwrap();
            writer.finalize().await.unwrap();

            let effective_size = override_size.unwrap_or(configured_size);
            let volumes = finalized_volume_paths(&archive_path);
            assert!(volumes.len() > 1, "expected rotation for {volumes:?}");
            for volume in volumes {
                assert!(
                    std::fs::metadata(&volume).unwrap().len() <= effective_size,
                    "{} exceeds the resolved {effective_size}-byte cap",
                    volume.display()
                );
            }
        }
    }

    #[tokio::test]
    async fn test_p3_7_small_cap_catalog_chunking_and_manifest_preflight() {
        const MAX_VOLUME_SIZE: u64 = 1024 * 1024;
        const FILE_COUNT: usize = 500;

        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("metadata_capacity.era");
        let mut config = ArchiveConfig::default();
        config.volume.max_size = MAX_VOLUME_SIZE;
        config.compression.algorithm = era_common::CompressionAlgorithm::Zstd;
        config.erasure = None;
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .config(config)
            .enable_erasure(false)
            .enable_cdc(false)
            .enable_small_file_packing(false)
            .build()
            .await
            .unwrap();

        let dir_segment = "m".repeat(220);
        let deep_prefix = (0..10)
            .map(|_| dir_segment.as_str())
            .collect::<Vec<_>>()
            .join("/");
        for i in 0..FILE_COUNT {
            let name = format!("{deep_prefix}/{i:03}_{}.bin", "x".repeat(180));
            let data = vec![u8::try_from(i % 256).unwrap(); 96];
            writer.add_bytes(&name, &data).await.unwrap();
        }
        writer.finalize().await.unwrap();

        let volumes = finalized_volume_paths(&archive_path);
        for volume in &volumes {
            assert!(
                std::fs::metadata(volume).unwrap().len() <= MAX_VOLUME_SIZE,
                "{} exceeds the metadata-test cap",
                volume.display()
            );
        }

        let last_volume = volumes.last().unwrap();
        let bytes = std::fs::read(last_volume).unwrap();
        let footer = Footer::from_bytes(&bytes[bytes.len() - era_volume::FOOTER_SIZE..]).unwrap();
        let mut offset = usize::try_from(footer.catalog_offset()).unwrap();
        let mut catalog_blocks = 0;
        while let Some(header) = era_common::BlockHeader::from_bytes(&bytes[offset..]) {
            if header.block_type != BlockType::Catalog {
                break;
            }
            catalog_blocks += 1;
            offset += era_common::BlockHeader::SIZE + usize::try_from(header.length).unwrap();
        }
        assert_eq!(
            catalog_blocks, 2,
            "fixture must write a catalog continuation"
        );

        let mut reader = ArchiveReader::open(last_volume, "test_password")
            .await
            .unwrap();
        let output_dir = temp_dir.path().join("out");
        reader
            .extract_all(&crate::ExtractOptions::new(&output_dir))
            .await
            .unwrap();
        for i in 0..FILE_COUNT {
            let name = format!("{deep_prefix}/{i:03}_{}.bin", "x".repeat(180));
            assert_eq!(
                std::fs::read(output_dir.join(name)).unwrap(),
                vec![u8::try_from(i % 256).unwrap(); 96]
            );
        }
    }

    #[tokio::test]
    async fn test_builder_uses_packing_k_factor() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("packing_k.era");

        let mut config = ArchiveConfig::default();
        config.packing.k_factor = 3;
        config.packing.flush_threshold = 90;

        let writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .config(config)
            .build()
            .await
            .unwrap();

        assert_eq!(writer.packing.bin_count(), 3);
    }

    #[tokio::test]
    async fn test_builder_uses_config_block_target_size() {
        let temp_dir = TempDir::new().unwrap();

        let mut compact = ArchiveConfig::compact_preset();
        compact.encryption.kdf_memory_cost = 1024;
        compact.encryption.kdf_time_cost = 1;
        let compact_writer = ArchiveWriter::builder(temp_dir.path().join("compact.era"))
            .password("test_password")
            .config(compact)
            .build()
            .await
            .unwrap();
        assert_eq!(
            compact_writer.packing.target_block_size(),
            (16 * 1024 * 1024).min(compact_writer.capacity.max_data_chunk_size())
        );
        assert!(compact_writer.packing.target_block_size() > 4 * 1024 * 1024);

        let mut non_ec = ArchiveConfig {
            erasure: None,
            ..Default::default()
        };
        non_ec.encryption.kdf_memory_cost = 1024;
        non_ec.encryption.kdf_time_cost = 1;
        non_ec.block.target_size = 8 * 1024 * 1024;
        let non_ec_writer = ArchiveWriter::builder(temp_dir.path().join("non_ec.era"))
            .password("test_password")
            .config(non_ec)
            .build()
            .await
            .unwrap();
        assert_eq!(non_ec_writer.packing.target_block_size(), 8 * 1024 * 1024);

        let mut overridden = ArchiveConfig::compact_preset();
        overridden.encryption.kdf_memory_cost = 1024;
        overridden.encryption.kdf_time_cost = 1;
        let overridden_writer = ArchiveWriter::builder(temp_dir.path().join("override.era"))
            .password("test_password")
            .config(overridden)
            .target_block_size(512 * 1024)
            .build()
            .await
            .unwrap();
        assert_eq!(overridden_writer.packing.target_block_size(), 512 * 1024);
    }

    #[tokio::test]
    async fn test_builder_rejects_zero_block_target_size() {
        let dir_cfg = TempDir::new().unwrap();
        let mut cfg = ArchiveConfig {
            erasure: None,
            ..Default::default()
        };
        cfg.encryption.kdf_memory_cost = 1024;
        cfg.encryption.kdf_time_cost = 1;
        cfg.block.target_size = 0;

        let err_cfg = match ArchiveWriter::builder(dir_cfg.path().join("zero_cfg.era"))
            .password("test_password")
            .config(cfg)
            .build()
            .await
        {
            Ok(_) => panic!("expected zero config.block.target_size to fail"),
            Err(err) => err,
        };
        assert!(
            matches!(err_cfg, EraError::InvalidConfig(_)),
            "expected InvalidConfig, got {err_cfg:?}"
        );
        assert_eq!(std::fs::read_dir(dir_cfg.path()).unwrap().count(), 0);

        let dir_explicit = TempDir::new().unwrap();
        let mut cfg2 = ArchiveConfig {
            erasure: None,
            ..Default::default()
        };
        cfg2.encryption.kdf_memory_cost = 1024;
        cfg2.encryption.kdf_time_cost = 1;
        let err_explicit = match ArchiveWriter::builder(dir_explicit.path().join("zero_arg.era"))
            .password("test_password")
            .config(cfg2)
            .target_block_size(0)
            .build()
            .await
        {
            Ok(_) => panic!("expected zero .target_block_size(0) to fail"),
            Err(err) => err,
        };
        assert!(
            matches!(err_explicit, EraError::InvalidConfig(_)),
            "expected InvalidConfig, got {err_explicit:?}"
        );
        assert_eq!(std::fs::read_dir(dir_explicit.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn test_builder_append_missing_target_validates_config_max_volume_size() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("missing.era");
        let mut config = ArchiveConfig {
            erasure: None,
            ..Default::default()
        };
        config.encryption.kdf_memory_cost = 1024;
        config.encryption.kdf_time_cost = 1;
        config.volume.max_size = 256 * 1024;

        let err = match ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .append_existing(true)
            .config(config)
            .build()
            .await
        {
            Ok(_) => {
                panic!("expected invalid config.volume.max_size to be rejected on new archive")
            }
            Err(err) => err,
        };
        assert!(
            matches!(err, EraError::InvalidConfig(_)),
            "expected InvalidConfig, got {err:?}"
        );
        assert_eq!(std::fs::read_dir(temp_dir.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn test_empty_archive() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("empty.era");

        let writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .await
            .unwrap();

        let stats = writer.finalize().await.unwrap();
        assert_eq!(stats.total_files, 0);
        assert_eq!(stats.total_size, 0);
    }

    #[tokio::test]
    async fn test_multiple_files() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("multi.era");

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .await
            .unwrap();

        // Add multiple files
        writer.add_bytes("file1.txt", b"Content 1").await.unwrap();
        writer
            .add_bytes("file2.txt", b"Content 2 is longer")
            .await
            .unwrap();
        writer
            .add_bytes("dir/file3.txt", b"Nested content")
            .await
            .unwrap();

        let stats = writer.finalize().await.unwrap();
        assert_eq!(stats.total_files, 3);
    }

    #[tokio::test]
    async fn test_large_file() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("large.era");

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .await
            .unwrap();

        // Add a larger file (1MB of compressible data)
        let large_data = vec![b'A'; 1024 * 1024];
        writer.add_bytes("large.bin", &large_data).await.unwrap();

        let stats = writer.finalize().await.unwrap();
        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.total_size, 1024 * 1024);
    }

    #[tokio::test]
    async fn test_empty_file() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("empty_file.era");

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .await
            .unwrap();

        writer.add_bytes("empty.txt", b"").await.unwrap();

        let stats = writer.finalize().await.unwrap();
        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.total_size, 0);
    }

    #[tokio::test]
    async fn test_unicode_filename() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("unicode.era");

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .await
            .unwrap();

        writer
            .add_bytes("中文文件名.txt", "内容".as_bytes())
            .await
            .unwrap();
        writer
            .add_bytes("日本語.txt", "コンテンツ".as_bytes())
            .await
            .unwrap();
        writer
            .add_bytes("emoji_📁.txt", b"emoji content")
            .await
            .unwrap();

        let stats = writer.finalize().await.unwrap();
        assert_eq!(stats.total_files, 3);
    }

    #[tokio::test]
    async fn test_special_characters_in_filename() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("special.era");

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .await
            .unwrap();

        writer
            .add_bytes("file with spaces.txt", b"content")
            .await
            .unwrap();
        writer
            .add_bytes("file-with-dashes.txt", b"content")
            .await
            .unwrap();
        writer
            .add_bytes("file_with_underscores.txt", b"content")
            .await
            .unwrap();

        let stats = writer.finalize().await.unwrap();
        assert_eq!(stats.total_files, 3);
    }

    #[tokio::test]
    async fn test_binary_content() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("binary.era");

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .await
            .unwrap();

        // Add binary data with all byte values
        let binary_data: Vec<u8> = (0..=255).collect();
        writer
            .add_bytes("all_bytes.bin", &binary_data)
            .await
            .unwrap();

        let stats = writer.finalize().await.unwrap();
        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.total_size, 256);
    }

    #[tokio::test]
    async fn test_build_manifest_uses_commitments_and_initial_sequence() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("manifest.era");

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .await
            .unwrap();

        let catalog_bytes = b"catalog";
        let index_bytes = b"";
        let committed_horizon = 1234;

        writer
            .catalog
            .block_locations
            .push(era_common::BlockLocation::single(
                era_common::VolumeId::new(),
                0,
                1000,
                234,
            ));

        let manifest = writer
            .build_manifest(
                catalog_bytes,
                index_bytes,
                committed_horizon,
                vec![committed_horizon],
            )
            .unwrap();

        assert_eq!(manifest.epoch_id, writer.pipeline.encryption().epoch_id());
        assert_eq!(manifest.finalize_sequence, INITIAL_FINALIZE_SEQUENCE);
        assert_eq!(manifest.committed_horizon, committed_horizon);
        assert_eq!(
            manifest.catalog_commitment,
            compute_catalog_commitment(catalog_bytes)
        );
        assert_eq!(
            manifest.index_commitment,
            compute_index_commitment(index_bytes)
        );
    }

    #[tokio::test]
    async fn test_build_manifest_preserves_volume_committed_ends() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("manifest_committed_ends.era");

        let writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .await
            .unwrap();

        let volume_committed_ends = vec![era_volume::DATA_REGION_START, 8192, 12288];
        let manifest = writer
            .build_manifest(b"catalog", b"index", 12288, volume_committed_ends.clone())
            .unwrap();

        assert_eq!(manifest.volume_committed_ends, volume_committed_ends);
    }

    #[tokio::test]
    async fn test_append_recovery_filters_legacy_packed_raw_alias() {
        let temp_dir = TempDir::new().unwrap();
        let input_dir = temp_dir.path().join("input");
        std::fs::create_dir(&input_dir).unwrap();
        let archive_path = temp_dir.path().join("legacy_packed_alias.era");
        let packed_path = input_dir.join("packed.txt");
        let raw_path = input_dir.join("raw.txt");
        let payload = b"small file bytes later written as a raw chunk";
        std::fs::write(&packed_path, payload).unwrap();
        std::fs::write(&raw_path, payload).unwrap();
        let config = ArchiveConfig {
            erasure: None,
            ..Default::default()
        };

        let mut packed_writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .config(config.clone())
            .enable_small_file_packing(true)
            .build()
            .await
            .unwrap();
        packed_writer.add_file(&packed_path).await.unwrap();
        packed_writer.flush_packed_files().await.unwrap();
        let packed_hash = packed_writer.catalog.entries[0].chunks[0].hash;
        let packed_location = packed_writer
            .pipeline
            .get_location(&packed_hash)
            .unwrap()
            .unwrap();
        let raw_hash = era_crypto::hash(payload);
        // Reproduce the historical on-disk index shape without retaining the old writer bug.
        packed_writer
            .pipeline
            .index_mut()
            .record_location(raw_hash, packed_location)
            .unwrap();
        packed_writer.finalize().await.unwrap();

        let mut legacy_reader = ArchiveReader::open(&archive_path, "test_password")
            .await
            .unwrap();
        legacy_reader.preflight_metadata_recovery().await.unwrap();
        let legacy_index = legacy_reader.index_reader().unwrap();
        assert!(
            legacy_index
                .iter_entries()
                .any(|entry| entry.hash() == &raw_hash),
            "the fixture must contain the legacy nonphysical raw alias"
        );
        assert!(legacy_index
            .iter_entries()
            .any(|entry| entry.hash() == &packed_hash));
        drop(legacy_reader);

        let mut raw_writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .config(config)
            .enable_small_file_packing(false)
            .append_existing(true)
            .build()
            .await
            .unwrap();
        raw_writer.add_file(&raw_path).await.unwrap();
        raw_writer.finalize().await.unwrap();

        let mut reader = ArchiveReader::open(&archive_path, "test_password")
            .await
            .unwrap();
        let verify_stats = reader.verify().await.unwrap();
        assert_eq!(
            verify_stats.archive_health,
            crate::ArchiveHealthStatus::Healthy,
            "legacy aliases must not suppress physical raw chunks: {:?}",
            verify_stats.errors
        );
        let extract_dir = TempDir::new().unwrap();
        reader
            .extract_all(&crate::ExtractOptions::new(extract_dir.path()))
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(extract_dir.path().join("packed.txt")).unwrap(),
            payload
        );
        assert_eq!(
            std::fs::read(extract_dir.path().join("raw.txt")).unwrap(),
            payload
        );
    }

    #[tokio::test]
    async fn test_append_manifest_sequence_and_committed_ends_are_monotonic() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("append_manifest_monotonic.era");
        let config = ArchiveConfig {
            erasure: None,
            ..Default::default()
        };

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .config(config.clone())
            .build()
            .await
            .unwrap();
        writer
            .add_bytes("first.txt", b"first payload")
            .await
            .unwrap();
        writer.finalize().await.unwrap();

        let first_manifest = read_primary_manifest(&archive_path, "test_password").await;
        assert_eq!(first_manifest.finalize_sequence, INITIAL_FINALIZE_SEQUENCE);
        assert!(!first_manifest.volume_committed_ends.is_empty());
        assert_eq!(
            first_manifest.committed_horizon,
            first_manifest
                .volume_committed_ends
                .iter()
                .copied()
                .max()
                .unwrap()
        );

        let mut append_writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .config(config)
            .append_existing(true)
            .build()
            .await
            .unwrap();
        append_writer
            .add_bytes("second.txt", b"second payload")
            .await
            .unwrap();
        append_writer.finalize().await.unwrap();

        let second_manifest = read_primary_manifest(&archive_path, "test_password").await;
        assert_eq!(
            second_manifest.finalize_sequence,
            first_manifest.finalize_sequence + 1
        );
        assert!(
            second_manifest.volume_committed_ends.len()
                >= first_manifest.volume_committed_ends.len()
        );
        assert_eq!(
            second_manifest.committed_horizon,
            second_manifest
                .volume_committed_ends
                .iter()
                .copied()
                .max()
                .unwrap()
        );
        for (&new_end, &old_end) in second_manifest
            .volume_committed_ends
            .iter()
            .zip(first_manifest.volume_committed_ends.iter())
        {
            assert!(new_end >= old_end);
        }
    }

    #[tokio::test]
    async fn test_finalize_writes_manifest_to_all_volumes_with_distinct_nonces() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("manifest_multi.era");

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .volume_count(2)
            .build()
            .await
            .unwrap();

        writer
            .add_bytes("hello.txt", b"Hello manifest")
            .await
            .unwrap();
        writer.finalize().await.unwrap();

        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_name = Path::new(archive_path.file_name().unwrap());
        let volume1_name = volume_path(base_name, 1);

        let reader0 = VolumeReader::open(&backend, base_name).await.unwrap();
        let reader1 = VolumeReader::open(&backend, &volume1_name).await.unwrap();

        let footer0 = reader0.footer().unwrap();
        let footer1 = reader1.footer().unwrap();
        assert!(footer0.has_manifest());
        assert!(footer1.has_manifest());
        assert_eq!(footer0.manifest_block_id(), footer1.manifest_block_id());

        let manifest_blocks0 = reader0
            .scan_for_typed_blocks(BlockType::Manifest)
            .await
            .unwrap();
        let manifest_blocks1 = reader1
            .scan_for_typed_blocks(BlockType::Manifest)
            .await
            .unwrap();

        assert_eq!(manifest_blocks0.len(), 1);
        assert_eq!(manifest_blocks1.len(), 1);
        assert_eq!(
            footer0.manifest_offset(),
            manifest_blocks0[0].physical_offset
        );
        assert_eq!(
            footer1.manifest_offset(),
            manifest_blocks1[0].physical_offset
        );

        let manifest0 = reader0.read_block(&manifest_blocks0[0]).await.unwrap();
        let manifest1 = reader1.read_block(&manifest_blocks1[0]).await.unwrap();

        assert!(manifest0.data.len() >= NONCE_SIZE);
        assert!(manifest1.data.len() >= NONCE_SIZE);
        assert_ne!(&manifest0.data[..NONCE_SIZE], &manifest1.data[..NONCE_SIZE]);
        assert_ne!(manifest0.data, manifest1.data);
    }

    #[tokio::test]
    async fn test_manifest_roundtrip_bytes() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("manifest_roundtrip.era");

        let writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .await
            .unwrap();

        let catalog_bytes = b"catalog plaintext for roundtrip";
        let index_bytes = b"index plaintext for roundtrip";
        let committed_horizon = 5678u64;

        let manifest = writer
            .build_manifest(
                catalog_bytes,
                index_bytes,
                committed_horizon,
                vec![committed_horizon],
            )
            .unwrap();

        let serialized = manifest.to_bytes().unwrap();
        let deserialized = era_common::ArchiveManifest::from_bytes(&serialized).unwrap();

        assert_eq!(manifest.epoch_id, deserialized.epoch_id);
        assert_eq!(manifest.finalize_sequence, deserialized.finalize_sequence);
        assert_eq!(manifest.committed_horizon, deserialized.committed_horizon);
        assert_eq!(
            manifest.volume_committed_ends,
            deserialized.volume_committed_ends
        );
        assert_eq!(manifest.catalog_commitment, deserialized.catalog_commitment);
        assert_eq!(manifest.index_commitment, deserialized.index_commitment);
    }

    #[tokio::test]
    async fn test_catalog_block_locations_populated() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("block_locations.era");

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .build()
            .await
            .unwrap();

        writer.add_bytes("file1.txt", b"content 1").await.unwrap();
        writer.add_bytes("file2.txt", b"content 2").await.unwrap();

        let stats = writer.finalize().await.unwrap();
        assert!(stats.blocks_written > 0);

        let mut reader = ArchiveReader::open(&archive_path, "test_password")
            .await
            .unwrap();
        let catalog = reader.load_catalog().await.unwrap();
        assert!(
            !catalog.block_locations.is_empty(),
            "catalog.block_locations should be populated after finalize"
        );
    }

    #[tokio::test]
    async fn test_index_written_to_all_volumes() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("index_all_volumes.era");

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .volume_count(2)
            .build()
            .await
            .unwrap();

        let data = vec![0u8; 64 * 1024];
        writer.add_bytes("large.bin", &data).await.unwrap();
        writer.finalize().await.unwrap();

        let backend = LocalStorageBackend::new(temp_dir.path());
        let base_name = Path::new(archive_path.file_name().unwrap());
        let volume1_name = volume_path(base_name, 1);

        let reader0 = era_volume::VolumeReader::open(&backend, base_name)
            .await
            .unwrap();
        let reader1 = era_volume::VolumeReader::open(&backend, &volume1_name)
            .await
            .unwrap();

        let index_blocks0 = reader0
            .scan_for_typed_blocks(BlockType::IndexManifest)
            .await
            .unwrap();
        let index_blocks1 = reader1
            .scan_for_typed_blocks(BlockType::IndexManifest)
            .await
            .unwrap();

        assert!(
            !index_blocks0.is_empty(),
            "Volume 0 should contain IndexManifest blocks"
        );
        assert!(
            !index_blocks1.is_empty(),
            "Volume 1 should contain IndexManifest blocks"
        );
    }

    #[tokio::test]
    async fn test_index_fanout_failure_aborts_finalization() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("index_fanout_failure.era");
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .volume_count(2)
            .build()
            .await
            .unwrap();
        writer
            .add_bytes("data.bin", b"fanout failure")
            .await
            .unwrap();
        let current_block_id = writer.pipeline.blocks_written();
        let target_block_id = u64::from(u32::MAX) - 6;
        writer
            .pipeline
            .advance_block_id(target_block_id - current_block_id)
            .unwrap();

        let error = writer
            .finalize()
            .await
            .expect_err("an index fanout failure must not publish a finalized archive");

        assert!(
            matches!(error, EraError::IndexError(_)),
            "unexpected finalization error: {error:?}"
        );
    }

    #[test]
    fn test_footer_without_manifest_backward_compat() {
        let footer = era_volume::Footer::new(4096, 1, 0);
        assert!(
            !footer.has_manifest(),
            "v8.1 footer without manifest should return has_manifest == false"
        );
        assert_eq!(footer.manifest_offset(), 0);
        assert_eq!(footer.manifest_block_id(), 0);
    }

    #[tokio::test]
    async fn test_finalize_multi_block_catalog_space_exhausted_mentions_max_volume_size() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("huge_catalog.era");
        let mut config = ArchiveConfig {
            erasure: None,
            ..Default::default()
        };
        config.compression.algorithm = era_common::CompressionAlgorithm::None;

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("test_password")
            .config(config)
            .enable_erasure(false)
            .enable_cdc(false)
            .enable_small_file_packing(false)
            .max_volume_size(crate::MIN_ARCHIVE_VOLUME_SIZE)
            .build()
            .await
            .unwrap();

        for i in 0..12_000usize {
            let name = format!(
                "dir_{:03}/sub_{:03}/long_entry_name_{:05}.bin",
                i / 100,
                i % 100,
                i
            );
            writer.add_bytes(&name, b"x").await.unwrap();
        }

        let err = writer
            .finalize()
            .await
            .expect_err("multi-block catalog exceeding 1 MiB single volume must fail");
        match err {
            EraError::VolumeSpaceExhausted { message, .. } => {
                assert!(
                    message.contains("--max-volume-size"),
                    "error message should suggest increasing --max-volume-size, got: {message}"
                );
                assert!(
                    message.contains("catalog"),
                    "error message should identify catalog budget failure, got: {message}"
                );
            }
            other => panic!("expected VolumeSpaceExhausted, got: {other:?}"),
        }
    }
}

/// Generic archive writer that supports any storage backend
pub mod generic {
    use super::*;
    use era_codec::{Compressor, NoCompressor, ZstdCompressor};
    use era_common::CompressionAlgorithm;
    use era_storage::{StorageBackend, StorageWriter};

    /// Builder for creating a GenericArchiveWriter with a custom backend
    pub struct GenericArchiveWriterBuilder<B: StorageBackend> {
        backend: B,
        filename: PathBuf,
        password: Option<String>,
        config: ArchiveConfig,
        access_policy: Option<era_volume::AccessPolicy>,
    }

    impl<B: StorageBackend> GenericArchiveWriterBuilder<B> {
        /// Create a new builder with the given backend and filename
        pub fn new(backend: B, filename: impl Into<PathBuf>) -> Self {
            Self {
                backend,
                filename: filename.into(),
                password: None,
                config: ArchiveConfig::default(),
                access_policy: None,
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

        /// Set the access policy
        pub fn access_policy(mut self, policy: era_volume::AccessPolicy) -> Self {
            self.access_policy = Some(policy);
            self
        }

        /// Build the archive writer
        pub async fn build(self) -> Result<GenericArchiveWriter<B::Writer>> {
            // Threshold must be rejected: t < 2 is invalid, and even valid
            // thresholds require Shamir splitting into shares via ArchiveWriter
            if let Some(era_volume::AccessPolicy::Threshold(_)) = self.access_policy {
                return Err(era_common::EraError::InvalidConfig(
                    "GenericArchiveWriter does not support Threshold policy. Use ArchiveWriter::builder()"
                        .into(),
                ));
            }

            // GenericArchiveWriter writes single-volume canonical blocks without RS shards.
            let mut config = self.config;
            if config.erasure.take().is_some() {
                debug!(
                    "GenericArchiveWriter writes canonical non-erasure blocks; clearing erasure config"
                );
            }
            if config.block.target_size == 0 {
                return Err(era_common::EraError::InvalidConfig(
                    "target_block_size must be > 0".into(),
                ));
            }
            let max_chunk = crate::volume_capacity::max_canonical_data_chunk_size(
                config.compression.algorithm,
            )?;
            let target_block_size = config.block.target_size.min(max_chunk).max(1);
            let packing = PackingStage::new(
                config.packing.k_factor,
                target_block_size,
                config.packing.flush_threshold,
            )?;

            let archive_id = ArchiveId::new();
            let archive_salt = era_crypto::Salt::generate();

            // Generate Master Key (DEK)
            let mut master_key = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(&mut *master_key);

            // Password Recipient
            let password = self.password.ok_or_else(|| {
                era_common::EraError::InvalidConfig(
                    "GenericArchiveWriter requires a password; none provided".into(),
                )
            })?;
            let pwd_salt = era_crypto::Salt::generate();
            let kdf_params = KdfParams {
                memory_cost: config.encryption.kdf_memory_cost,
                time_cost: config.encryption.kdf_time_cost,
                parallelism: 4,
            };

            let kek = era_crypto::derive_key(password.as_bytes(), &pwd_salt, &kdf_params)?;
            let ctx = XChaCha20Poly1305Context::from_derived_key(&kek)?;
            let nonce = Nonce::generate();
            let encrypted_mk = ctx.encrypt(
                nonce.as_bytes(),
                crate::auth::MK_WRAP_AAD_DOMAIN,
                &*master_key,
            )?;

            let mut combined = Vec::new();
            combined.extend_from_slice(nonce.as_bytes());
            combined.extend_from_slice(&encrypted_mk);

            let p_params = crate::auth::PasswordSlotParams {
                salt: *pwd_salt.as_bytes(),
                kdf_memory_cost: kdf_params.memory_cost,
                kdf_time_cost: kdf_params.time_cost,
                kdf_parallelism: kdf_params.parallelism,
            };

            let slot = RecipientSlot::new(
                RecipientType::Argon2idPassword,
                None,
                rkyv::to_bytes::<rkyv::rancor::Error>(&p_params)
                    .map_err(|e| era_common::EraError::Serialization(e.to_string()))?
                    .to_vec(),
                combined,
            );

            let recipients = vec![slot];

            // Create KeySession
            let session = KeySession::from_master_key(&master_key)?;
            master_key.zeroize();

            // Generate random Volume Key and wrap it with IK
            let (volume_key, wrapped_vk) = session.generate_and_wrap_volume_key()?;
            let encrypted_volume_key = era_volume::EncryptedVolumeKey::new(
                era_volume::KeyWrapAlgorithm::XChaCha20Poly1305,
                wrapped_vk.nonce,
                wrapped_vk.ciphertext,
            );

            // Create volume writer
            let mut header = SuperHeader::new(
                archive_id,
                recipients,
                config.clone(),
                *archive_salt.as_bytes(),
                encrypted_volume_key,
                self.access_policy
                    .unwrap_or(era_volume::AccessPolicy::AnyOfN),
            )?;
            header.set_total_volumes(1);
            let epoch_id = header.epoch_id();

            let volume_writer =
                VolumeWriter::create(&self.backend, Path::new(&self.filename), header).await?;

            // Store nonce context for block encryption
            let nonce_context = *archive_salt.as_bytes();

            // Store compression config for creating compressors on demand
            let compression_config = config.compression.clone();

            let chunk_index = create_chunk_index_with_context(*archive_id.0.as_bytes(), epoch_id)?;

            // Create encryption context
            let encryption = EncryptionContext::new(
                session,
                volume_key,
                nonce_context,
                *archive_id.0.as_bytes(),
                epoch_id,
                0,
            );

            Ok(GenericArchiveWriter {
                archive_id,
                encryption,
                compression_config,
                volume_writer,
                catalog: Catalog::new(),
                chunk_index,
                packing,
                written_blocks: Vec::new(),
                pending_hashes: HashSet::new(),
            })
        }
    }

    /// Generic archive writer supporting any storage backend
    ///
    /// ## Security Model
    ///
    /// This writer implements the HKDF "Onion Model" key derivation:
    /// - Each block is encrypted with a unique key derived via HKDF
    /// - Keys are stored in mlock-protected memory
    pub struct GenericArchiveWriter<W: StorageWriter> {
        archive_id: ArchiveId,
        /// Encryption context (session, volume key, nonce context, block ID counter)
        encryption: EncryptionContext,
        /// Compression configuration
        compression_config: era_common::CompressionConfig,
        volume_writer: VolumeWriter<W>,
        catalog: Catalog,
        chunk_index: Arc<dyn ChunkIndex>,
        /// Packing stage for k-Bounded Best-Fit bin packing
        packing: PackingStage,
        written_blocks: Vec<era_common::BlockLocation>,

        pending_hashes: HashSet<ChunkHash>,
    }

    impl<W: StorageWriter> GenericArchiveWriter<W> {
        /// Get the archive ID
        pub fn archive_id(&self) -> ArchiveId {
            self.archive_id
        }

        fn contains_or_pending(&self, hash: &ChunkHash) -> Result<bool> {
            Ok(self.chunk_index.contains(hash)? || self.pending_hashes.contains(hash))
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

        async fn ingest_chunk_slice(&mut self, slice: &[u8], offset: u64) -> Result<ChunkRef> {
            let hash = era_crypto::hash(slice);
            if !self.contains_or_pending(&hash)? {
                let chunk = UniqueChunk::new(Bytes::copy_from_slice(slice), hash);
                self.add_to_pending(chunk).await?;
            }
            let chunk_len = u32::try_from(slice.len())
                .map_err(|_| EraError::Other("Chunk length exceeds u32::MAX".into()))?;
            Ok(ChunkRef::new(hash, offset, chunk_len))
        }

        /// Add a file from memory
        pub async fn add_bytes(&mut self, name: &str, data: &[u8]) -> Result<()> {
            debug!("Adding in-memory file: {} ({} bytes)", name, data.len());

            let target_block_size = self.packing.target_block_size();
            let chunk_refs = if data.len() > target_block_size {
                let mut refs = Vec::with_capacity(data.len().div_ceil(target_block_size));
                let mut offset = 0u64;
                for slice in data.chunks(target_block_size) {
                    refs.push(self.ingest_chunk_slice(slice, offset).await?);
                    offset += slice.len() as u64;
                }
                refs
            } else {
                vec![self.ingest_chunk_slice(data, 0).await?]
            };

            let entry =
                FileEntry::file(PathBuf::from(name), data.len() as u64).with_chunks(chunk_refs);
            self.catalog.add(entry);

            Ok(())
        }

        /// Add chunk to packing stage using k-Bounded Best-Fit
        async fn add_to_pending(&mut self, chunk: UniqueChunk) -> Result<()> {
            self.pending_hashes.insert(chunk.hash);
            // Use k-Bounded Best-Fit packing stage for optimal packing
            // The stage automatically handles oversized chunks and bin selection
            if let Some(packed) = self.packing.push(chunk) {
                // A bin reached flush threshold - write it
                self.write_packed_block(packed).await?;
            }

            Ok(())
        }

        /// Write a packed block to storage
        async fn write_packed_block(&mut self, packed: PackedBlock) -> Result<()> {
            let hashes: Vec<_> = packed.chunks.iter().map(|c| c.hash).collect();

            // Create session-based builder for this block
            self.encryption
                .set_volume_index(self.volume_writer.volume_sequence() as u32);
            let compressor = self.create_compressor();
            let block_builder = self.encryption.create_block_builder(compressor)?;

            let encrypted_block = block_builder.pack_chunks(packed.chunks)?;
            let location = self
                .volume_writer
                .write_canonical_block(&encrypted_block, era_common::BlockType::Data)
                .await?;

            self.written_blocks.push(location.clone());

            for hash in hashes {
                self.pending_hashes.remove(&hash);
                self.chunk_index.put(hash, location.clone())?;
            }

            Ok(())
        }

        /// Flush all bins in the packing stage
        async fn flush_pending(&mut self) -> Result<()> {
            let packed_blocks = self.packing.flush_all();

            for packed in packed_blocks {
                self.write_packed_block(packed).await?;
            }

            Ok(())
        }

        /// Finalize the archive
        pub async fn finalize(mut self) -> Result<ArchiveStats> {
            info!("Finalizing archive...");

            self.flush_pending().await?;

            self.catalog.block_locations = std::mem::take(&mut self.written_blocks);
            let committed_end = self.volume_writer.current_size();
            let volume_index = u32::from(self.volume_writer.volume_sequence());
            self.encryption.set_volume_index(volume_index);

            // Serialize, frame, and write catalog with BlockType::Catalog AAD
            let catalog_bytes = self.catalog.to_bytes()?;
            let catalog_chunks = frame_and_chunk_catalog(&catalog_bytes, MAX_CATALOG_CHUNK_SIZE)?;

            let mut first_catalog_location: Option<(u64, u32, u32)> = None;
            for (chunk_data, chunk_hash) in catalog_chunks {
                let catalog_chunk = UniqueChunk::new(chunk_data, chunk_hash);
                let compressor = self.create_compressor();
                let catalog_builder = self.encryption.create_block_builder(compressor)?;

                let catalog_block = catalog_builder
                    .pack_single_with_type(catalog_chunk, era_common::BlockType::Catalog)?;
                let catalog_block_id = u32::try_from(catalog_block.block_id.sequence())
                    .map_err(|_| EraError::Other("Catalog block ID exceeds u32::MAX".into()))?;
                let catalog_location = self
                    .volume_writer
                    .write_canonical_block(&catalog_block, era_common::BlockType::Catalog)
                    .await?;
                first_catalog_location.get_or_insert((
                    catalog_location.physical_offset,
                    catalog_location.encrypted_size,
                    catalog_block_id,
                ));
            }
            let (catalog_offset, catalog_size, catalog_block_id) = first_catalog_location
                .ok_or_else(|| EraError::Other("No catalog blocks written".into()))?;

            // Build, encrypt, and write v8.2 ArchiveManifest
            let manifest = ArchiveManifest::new(
                self.encryption.epoch_id(),
                crate::sequence::INITIAL_FINALIZE_SEQUENCE,
                committed_end,
                compute_catalog_commitment(&catalog_bytes),
                compute_index_commitment(&[]),
                vec![committed_end],
            );
            let header_digest = self.volume_writer.finalized_header_digest()?;
            let manifest_bytes = manifest.to_bytes_with_header_digest(header_digest);

            let manifest_block_id = self.encryption.next_block_id()?;
            let manifest_block_id_u32 = u32::try_from(manifest_block_id)
                .map_err(|_| EraError::Other("Manifest block ID exceeds u32::MAX".into()))?;
            let nonce_context = self.encryption.nonce_context();
            let block_key = self.encryption.session().derive_block_key(
                self.encryption.volume_key(),
                manifest_block_id,
                &nonce_context,
            )?;
            let derived_key = block_key.to_derived_key()?;
            let aead_ctx = XChaCha20Poly1305Context::from_derived_key(&derived_key)?;
            let manifest_block = encrypt_manifest_block_with_ctx(
                &self.encryption.archive_id(),
                self.encryption.epoch_id(),
                &nonce_context,
                &manifest_bytes,
                volume_index,
                manifest_block_id,
                &aead_ctx,
            )?;
            let manifest_location = self
                .volume_writer
                .write_canonical_block(&manifest_block, era_common::BlockType::Manifest)
                .await?;
            self.volume_writer
                .set_manifest_info(manifest_location.physical_offset, manifest_block_id_u32)?;

            // Finalize volume
            let _header = self
                .volume_writer
                .finalize_with_catalog(catalog_offset, catalog_size, catalog_block_id, 0, 0, 0)
                .await?;

            let blocks_written = self.encryption.blocks_written();

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

        #[tokio::test]
        async fn test_memory_backend_archive() {
            let backend = MemoryStorageBackend::new();

            let mut writer = GenericArchiveWriterBuilder::new(backend.clone(), "test.era")
                .password("test_password")
                .build()
                .await
                .unwrap();

            writer
                .add_bytes("hello.txt", b"Hello, Memory!")
                .await
                .unwrap();
            writer.add_bytes("world.txt", b"World!").await.unwrap();

            let stats = writer.finalize().await.unwrap();
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

        #[tokio::test]
        async fn test_build_without_password_rejected() {
            let backend = MemoryStorageBackend::new();

            let result = GenericArchiveWriterBuilder::new(backend, "nopass.era")
                .build()
                .await;

            match result {
                Err(era_common::EraError::InvalidConfig(msg)) => {
                    assert!(msg.contains("requires a password"));
                }
                other => panic!("expected InvalidConfig error, got {:?}", other.is_ok()),
            }
        }

        #[tokio::test]
        async fn test_memory_backend_multiple_files_packed() {
            let backend = MemoryStorageBackend::new();

            let mut writer = GenericArchiveWriterBuilder::new(backend.clone(), "multi.era")
                .password("test_password")
                .build()
                .await
                .unwrap();

            // Add 10 small files
            for i in 0..10 {
                let name = format!("file_{}.txt", i);
                let content = format!("Content for file {}", i);
                writer.add_bytes(&name, content.as_bytes()).await.unwrap();
            }

            let stats = writer.finalize().await.unwrap();
            assert_eq!(stats.total_files, 10);
            // All 10 small files should fit in ~3 blocks (1 data + 1 catalog + 1 manifest)
            assert!(
                stats.blocks_written <= 3,
                "Expected <=3 blocks, got {}",
                stats.blocks_written
            );
        }
    }
}
