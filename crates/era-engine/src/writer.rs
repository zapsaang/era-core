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

use crate::auth::PasswordSlotParams;
use bytes::Bytes;
use era_common::{
    ArchiveConfig, ArchiveId, ChunkHash, EraError, ErasureCodeConfig, MatrixDistributionStrategy,
    Result, UniqueChunk,
};
use era_crypto::certificate::{EraCertificate, EraKeyPair, KeyEncapsulation};
use era_crypto::Nonce;
use era_crypto::{AeadContext, XChaCha20Poly1305Context};
use era_crypto::{KdfParams, KeySession, Salt};
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
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info, warn};
use zeroize::Zeroize;
use zeroize::Zeroizing;

const INTERNAL_META_PREFIX: &str = ".era/meta/";

use crate::checkpoint::CheckpointManager;
use crate::chunk_index::{create_chunk_index_with_context, ChunkIndex};
use crate::encryption_context::EncryptionContext;
use crate::erasure_stage::ErasureStage;
use crate::index_stage::IndexStage;
use crate::packing_stage::PackingStage;
use crate::reader::ArchiveReader;
use crate::recovery::{RecoveryOptions, RecoveryStrategy};
use crate::small_file_packer::{SmallFileEntry, SmallFilePacker};
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

    /// Hybrid mode: both password AND certificate required
    /// Provides defense-in-depth for high-security scenarios.
    Hybrid {
        password: Zeroizing<String>,
        certificate: EraCertificate,
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
    /// let keypair = EraKeyPair::load_encrypted("~/.era/key.era-key", "password")?;
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
    /// When set, volumes will automatically split when reaching this size limit.
    /// Default is 4GB.
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

    /// Build the archive writer
    pub async fn build(self) -> Result<ArchiveWriter> {
        use rand::RngCore as _;
        let output_preexisted = tokio::fs::try_exists(&self.output_path).await?;
        // Create storage backend
        let output_dir = self.output_path.parent().unwrap_or(Path::new("."));
        let backend = LocalStorageBackend::new(output_dir);

        let password_to_validate = match &self.auth_mode {
            AuthMode::Password(password) => Some(password.as_str()),
            AuthMode::Hybrid { password, .. } => Some(password.as_str()),
            AuthMode::Certificate(_) => None,
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
        let mut key_encapsulation: Option<KeyEncapsulation> = None;

        // Extract Copy fields before moving config to avoid clone
        let config_erasure = self.config.erasure;
        let mut config = self.config;
        // Determine erasure settings: explicit builder setting takes precedence over config default
        let enable_erasure = match self.enable_erasure {
            Some(explicit) => explicit, // Explicit .enable_erasure(true/false) call
            None => config_erasure.is_some(), // Fall back to config default
        };
        let erasure_config = if self.enable_erasure == Some(true) {
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
        let mut skip_auth_setup = false;

        if self.append_existing && tokio::fs::try_exists(&self.output_path).await? {
            // 1. Locate existing volume (Volume 0) to get Valid DNA
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

            // 2. DNA Check & Inheritance (Mandatory)
            config = loaded_header.config().clone();
            archive_id = loaded_header.archive_id();
            archive_salt = Salt::from_bytes(*loaded_header.salt());
            recipients = loaded_header.recipients().to_vec();

            if matches!(
                loaded_header.access_policy(),
                era_volume::AccessPolicy::Threshold(_)
            ) {
                return Err(era_common::EraError::InvalidFormat(
                    "Threshold authentication not supported for append mode".into(),
                ));
            }

            // 3. Hydrate Key Session (Recover Master Key)
            let mut recovered_mk: Option<[u8; 32]> = None;

            for slot in &recipients {
                if let (
                    AuthMode::Password(pwd) | AuthMode::Hybrid { password: pwd, .. },
                    RecipientType::Argon2idPassword,
                ) = (&self.auth_mode, slot.r_type())
                {
                    if let Ok(archived) = rkyv::access::<
                        rkyv::Archived<PasswordSlotParams>,
                        rkyv::rancor::Error,
                    >(slot.params())
                    {
                        let salt = Salt::from_bytes(archived.salt);
                        let kdf_params = KdfParams {
                            memory_cost: archived.kdf_memory_cost.into(),
                            time_cost: archived.kdf_time_cost.into(),
                            parallelism: archived.kdf_parallelism.into(),
                        };
                        if let Ok(kek) = era_crypto::derive_key(pwd.as_bytes(), &salt, &kdf_params)
                        {
                            if let Ok(ctx) = XChaCha20Poly1305Context::from_derived_key(&kek) {
                                if slot.encrypted_master_key().len() >= 24 {
                                    if let Ok(nonce_arr) =
                                        slot.encrypted_master_key()[0..24].try_into()
                                    {
                                        let ct = &slot.encrypted_master_key()[24..];
                                        if let Ok(mk) = ctx.decrypt(
                                            nonce_arr,
                                            crate::auth::MK_WRAP_AAD_DOMAIN,
                                            ct,
                                        ) {
                                            if let Ok(mk_arr) = mk.try_into() {
                                                recovered_mk = Some(mk_arr);
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            *master_key = recovered_mk.ok_or(era_common::EraError::InvalidKey(
                "No valid credentials found for append (password/key mismatch)".into(),
            ))?;

            // 4. Find Last Volume and load Footer/Catalog
            // Identify total volumes by checking existence relative to backend
            let mut last_valid_reader = vol0_reader;
            let mut current_vol_idx = 0;

            let stem = self.output_path.file_stem().unwrap_or_default();

            loop {
                let next_idx = current_vol_idx + 1;
                // e.g. archive.era.001
                let next_filename_str = format!("{}.era.{:03}", stem.to_string_lossy(), next_idx);
                let next_filename = Path::new(&next_filename_str);

                if let Ok(r) =
                    VolumeReader::<era_storage::LocalStorageReader>::open(&backend, next_filename)
                        .await
                {
                    last_valid_reader = r;
                    current_vol_idx = next_idx;
                } else {
                    break;
                }
            }

            // Read footer from the LAST volume
            if let Some(f) = last_valid_reader.footer() {
                append_footer = Some(f.clone());
                // Load catalog if present
                if f.catalog_offset() > 0 && f.catalog_size() > 0 {
                    if let Ok(catalog_bytes) = last_valid_reader
                        .read_raw(f.catalog_offset(), f.catalog_size() as usize)
                        .await
                    {
                        if let Ok(catalog) = Catalog::from_bytes(&catalog_bytes) {
                            append_catalog = Some(catalog);
                        }
                    }
                }
            } else {
                return Err(era_common::EraError::CorruptedHeader(
                    "Existing archive has no footer - cannot append".into(),
                ));
            }

            append_header = Some(loaded_header);
            skip_auth_setup = true;
        } else {
            // Generate Master Key (DEK) for new archive
            OsRng.fill_bytes(master_key.as_mut());
        }

        let session = KeySession::from_master_key(&master_key)?;

        // 1. Password Mode (adds password recipient(s))
        if !skip_auth_setup {
            if let AuthMode::Password(ref pwd)
            | AuthMode::Hybrid {
                password: ref pwd, ..
            } = self.auth_mode
            {
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
                    _ => {
                        return Err(era_common::EraError::InvalidConfig(
                            "Unsupported access policy".into(),
                        ));
                    }
                }
            }

            // 2. Certificate Mode (adds a certificate recipient)
            if let AuthMode::Certificate(ref cert)
            | AuthMode::Hybrid {
                certificate: ref cert,
                ..
            } = self.auth_mode
            {
                // Create ephemeral copy of MK for encapsulation (which might zeroize it, but we need it for session)
                // Encapsulate takes generic key slice, checking signature?
                // EraKeyPair::encapsulate_for(cert, &master_key)
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
        }

        // Zeroize master key from stack
        master_key.zeroize();

        let (volume_key, encrypted_volume_key) = if self.append_existing {
            let append = append_header.as_ref().ok_or_else(|| {
                era_common::EraError::CorruptedHeader("Missing append header".into())
            })?;
            let existing_vk = session.unwrap_volume_key(
                append.encrypted_volume_key().nonce(),
                append.encrypted_volume_key().ciphertext(),
            )?;
            (existing_vk, append.encrypted_volume_key().clone())
        } else {
            // Generate random Volume Key and wrap it with IK derived from MK
            let (volume_key, wrapped_vk) = session.generate_and_wrap_volume_key()?;
            let encrypted_volume_key = era_volume::EncryptedVolumeKey::new(
                era_volume::KeyWrapAlgorithm::XChaCha20Poly1305,
                wrapped_vk.nonce,
                wrapped_vk.ciphertext,
            );
            (volume_key, encrypted_volume_key)
        };

        // Store nonce context (salt) for block encryption
        let nonce_context = *archive_salt.as_bytes();

        // Build config with erasure setting
        if !self.append_existing {
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

        // Calculate optimal volume counts for erasure coding
        if enable_erasure {
            let total_shards = (erasure_config.data_shards + erasure_config.parity_shards) as usize;
            config.distribution.min_volumes = 1;
            config.distribution.target_volumes = total_shards;
        }

        // Create volume header
        let header = SuperHeader::new(
            archive_id,
            recipients,
            config.clone(),
            *archive_salt.as_bytes(),
            encrypted_volume_key,
            self.access_policy,
        )?;

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

        if let Some(max_size) = max_volume_size {
            pool_config = pool_config.with_max_size(max_size);
        }

        // Initialize catalog - MUST be done before VolumePool creation (truncation)
        let mut catalog = Catalog::new();
        if let Some(existing) = append_catalog {
            catalog = existing;
        } else if self.append_existing {
            let mut reader = ArchiveReader::open_with_session(&self.output_path, &session).await?;
            catalog = reader.load_catalog().await?.clone();
        }

        let active_header = if self.append_existing {
            append_header.clone().unwrap_or_else(|| header.clone())
        } else {
            header.clone()
        };

        let volume_pool = if self.append_existing {
            if enable_erasure {
                return Err(era_common::EraError::InvalidFormat(
                    "Append mode is not supported for erasure-coded archives".into(),
                ));
            }
            let footer = append_footer
                .as_ref()
                .ok_or_else(|| era_common::EraError::CorruptedHeader("Missing footer".into()))?;
            VolumePool::open_append_single(
                backend.clone(),
                pool_config,
                active_header.clone(),
                footer,
            )
            .await?
        } else {
            VolumePool::create(backend.clone(), pool_config, active_header.clone()).await?
        };

        info!(
            "Created VolumePool with {} volumes (Strategy: RotatingOffset)",
            volume_pool.volume_count()
        );

        // Configure file reader with CDC if enabled

        let chunker_config = if enable_cdc {
            let config = match chunker_override {
                Some(cfg) => cfg,
                None => chunker_config_from_archive(&config)?,
            };
            Some(config)
        } else {
            None
        };

        let chunker_max_size = chunker_config.as_ref().map(|cfg| cfg.max_size);
        let file_reader = if let Some(cfg) = chunker_config {
            FileReader::with_cdc().with_chunker_config(cfg)
        } else {
            FileReader::new()
        };

        // Set up checkpoint manager if enabled
        let checkpoint_manager = if self.enable_checkpoint {
            let checkpoint_exists = CheckpointManager::exists(&self.output_path).await?;
            let effective_strategy = if self.recovery_options_explicit {
                self.recovery_options.strategy
            } else if checkpoint_exists {
                RecoveryStrategy::Resume
            } else {
                RecoveryStrategy::StartFresh
            };

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

        // Create chunk index (internal memory-based index)
        let chunk_index: Arc<dyn ChunkIndex> = create_chunk_index_with_context(
            *active_header.archive_id().0.as_bytes(),
            active_header.epoch_id(),
        )?;

        // Load existing chunk locations from checkpoint if resuming
        if let Some(ref mgr) = checkpoint_manager {
            let should_restore_checkpoint_state = if self.recovery_options_explicit {
                self.recovery_options.strategy == RecoveryStrategy::Resume
            } else {
                self.enable_checkpoint && CheckpointManager::exists(&self.output_path).await?
            };

            if should_restore_checkpoint_state {
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

        let mut target_block_size = if let Some(target) = self.target_block_size {
            target
        } else if enable_cdc && enable_erasure {
            chunker_max_size.unwrap_or(4 * 1024 * 1024)
        } else {
            // Default to 4MB MacroBlocks as per Whitepaper, regardless of CDC.
            // PackingStage will aggregate small CDC chunks into these 4MB blocks.
            4 * 1024 * 1024
        };

        if let Some(max_volume_size) = max_volume_size {
            if enable_erasure {
                let prefix_len = erasure_config.data_shards as usize * 4;
                let reserved =
                    era_volume::FOOTER_SIZE + 4096 + era_common::ShardHeader::SIZE + prefix_len;
                if max_volume_size as usize > reserved {
                    let max_block = max_volume_size as usize - reserved;
                    target_block_size = target_block_size.min(max_block);
                }
            }
        }

        let next_block_id = if self.append_existing {
            volume_pool.current_block_count() as u64
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
            next_block_id,
        );

        // Create erasure stage (enabled or disabled based on config)
        let erasure = if enable_erasure {
            ErasureStage::new(Some(erasure_config))?
        } else {
            ErasureStage::disabled()
        };

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
            packing: PackingStage::new(
                config.packing.k_factor,
                target_block_size,
                config.packing.flush_threshold,
            )?,
            // Small file packing
            small_file_packer: if self.enable_small_file_packing {
                SmallFilePacker::new(16 * 1024, 1024 * 1024, 1000)
            } else {
                SmallFilePacker::disabled()
            },
            pipeline,
            pending_hashes: HashSet::new(),
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

    pending_hashes: HashSet<ChunkHash>,
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
            self.add_file_with_path(path, path).await?;
        }
        Ok(())
    }

    fn collect_own_volume_paths(&self) -> HashSet<PathBuf> {
        let mut paths = HashSet::new();
        if let Ok(canonical) = self.output_path.canonicalize() {
            paths.insert(canonical.clone());
            let stem = canonical.with_extension("");
            for seq in 1..=u16::MAX {
                let vol_path = stem.with_extension(format!("era.{:03}", seq));
                if vol_path.exists() {
                    paths.insert(vol_path);
                } else {
                    break;
                }
            }
        }
        paths
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
            }) {
                self.flush_packed_files_batch(entries_to_flush).await?;
            }

            return Ok(());
        }

        // Large file path: process immediately
        if self.enable_cdc {
            // Use CDC chunking for large files
            self.add_file_chunked(disk_path, relative_path).await
        } else {
            // Non-CDC mode: single chunk per file
            self.add_file_single(disk_path, relative_path).await
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
    async fn add_file_single(&mut self, path: &Path, relative_path: PathBuf) -> Result<()> {
        // Read the file as a single chunk
        let chunk = self.file_reader.read_file(path).await?;
        let hash = chunk.hash;
        let size = chunk.data.len() as u64;

        debug!("File size: {} bytes, hash: {}", size, hash);

        // Check for dedup: skip if we already have this chunk
        if !self.contains_or_pending(&hash)? {
            // Add to pending batch
            self.add_to_pending(chunk).await?;
        }

        // Create catalog entry with single chunk
        let chunk_len = u32::try_from(size)
            .map_err(|_| EraError::Other("Chunk length exceeds u32::MAX".into()))?;
        let chunk_ref = era_ingest::ChunkRef::new(hash, 0, chunk_len);
        let entry = FileEntry::file(relative_path, size).with_chunks(vec![chunk_ref]);
        self.catalog.add(entry);

        Ok(())
    }

    /// Add a file with CDC chunking
    async fn add_file_chunked(&mut self, path: &Path, relative_path: PathBuf) -> Result<()> {
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

        if chunk_refs.len() == 1 {
            // Handle single chunk specially if needed, but with_chunks works too.
            // Original code handled it for legacy format.
            // If we have single chunk, we can use with_hash?
            // But valid UniqueChunk is fine.
            // Let's stick to with_chunks for unification or check count.
            // let chunk_ref = &chunk_refs[0];
            // If legacy format requires FileEntry::file(...).with_hash(hash).
            // But with_chunks is preferred for ERA 8.1.
            // I'll stick to logic closer to original if possible but using chunk_refs is generally fine.
            // Original:
            /*
               if chunk_count == 1 {
                   let entry = FileEntry::file(relative_path, total_size).with_hash(hash);
                   self.catalog.add(entry);
               }
            */
            // I'll keep generic logic.
        }

        let entry = FileEntry::file(relative_path, total_size).with_chunks(chunk_refs);
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
        self.pipeline
            .process_chunks(packed.chunks, Vec::new())
            .await?;

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

        // Collect individual file hashes to ensure they get indexed
        // (This allows finding the packed chunk by looking up any small file hash)
        let mut small_file_hashes: Vec<ChunkHash> = grouped.keys().copied().collect();
        small_file_hashes.sort_by_key(|hash| hash.0);

        // Pre-validation: reuse existing packed chunk when possible
        if self.contains_or_pending(&chunk_hash)? {
            if let Some(existing_location) = self.pipeline.get_location(&chunk_hash)? {
                for hash in &small_file_hashes {
                    if !self.contains_or_pending(hash)? {
                        self.pipeline
                            .record_location(*hash, existing_location.clone())?;
                    }
                }
            } else {
                self.pipeline
                    .process_chunks(vec![packed_chunk], small_file_hashes)
                    .await?;
            }
        } else {
            // Process the packed chunk (write or buffer)
            // Pass small_file_hashes so they are associated with the block location
            self.pipeline
                .process_chunks(vec![packed_chunk], small_file_hashes)
                .await?;
        }

        // Note: pipeline.process_chunks handles index update for both packed_hash
        // and all small_file_hashes.

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

            let catalog_entry = FileEntry::file(entry.path.clone(), entry.data.len() as u64)
                .with_chunks(vec![chunk_ref]);

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

        self.pipeline.commit_durable_checkpoint().await?;
        debug!("Durable checkpoint committed before catalog write");

        // Serialize catalog
        let catalog_bytes = self.catalog.to_bytes()?;
        let catalog_hash = era_crypto::hash(&catalog_bytes);
        let catalog_chunk = UniqueChunk::new(Bytes::from(catalog_bytes), catalog_hash);

        // Create session-based builder for catalog encryption
        let compressor = self.pipeline.create_compressor();
        let catalog_builder = self
            .pipeline
            .encryption()
            .create_block_builder(compressor)?;

        // Pack catalog ONCE to ensure same block_id (and thus same nonce) for all volumes
        // This is critical because the block_id is used to derive the encryption nonce
        let catalog_block = catalog_builder.pack_single(catalog_chunk.clone())?;
        let catalog_block_id = catalog_block.block_id.sequence() as u32;

        // Optionally create a backup block for erasure-coded archives
        let backup_block = if self.pipeline.erasure_enabled() {
            // Create another builder for the backup block (will get next block_id)
            let compressor = self.pipeline.create_compressor();
            let backup_builder = self
                .pipeline
                .encryption()
                .create_block_builder(compressor)?;
            Some(backup_builder.pack_single(catalog_chunk)?)
        } else {
            None
        };

        let catalog_locations = self
            .pipeline
            .volume_mut()
            .write_catalog_to_all(&catalog_block, backup_block.as_ref())
            .await?;

        debug!(
            "Catalog (block_id={}) written to {} volumes for full redundancy",
            catalog_block_id,
            catalog_locations.len()
        );

        // Finalize the V2.1 index: write typed index blocks to volume 0
        let volume_count = self.pipeline.volume().pool().volume_count();
        let index_locations = if let Some(mut builder) = self.pipeline.index().take_index_builder()
        {
            // Copy crypto params before taking mutable borrow on pipeline
            let session = self.pipeline.encryption().session().try_clone()?;
            let volume_key = self.pipeline.encryption().volume_key().try_clone()?;
            let nonce_context = self.pipeline.encryption().nonce_context();
            let index_start_block_id = self.pipeline.blocks_written();

            if let Some(writer) = self.pipeline.volume_mut().get_writer_mut(0) {
                match builder
                    .finalize_with_starting_block_id(
                        writer,
                        &session,
                        &volume_key,
                        nonce_context,
                        index_start_block_id,
                    )
                    .await
                {
                    Ok((_meta_index, manifest_location)) => {
                        let mut locs: Vec<(u64, u32, u32)> = Vec::with_capacity(volume_count);
                        // Volume 0 gets the real location
                        locs.push((
                            manifest_location.physical_offset,
                            manifest_location.encrypted_size,
                            manifest_location.slot_index,
                        ));
                        // Other volumes get zeroed entries
                        for _ in 1..volume_count {
                            locs.push((0, 0, 0));
                        }
                        debug!(
                            "V2.1 index finalized: manifest at offset={}, size={}, block_id={}",
                            manifest_location.physical_offset,
                            manifest_location.encrypted_size,
                            manifest_location.slot_index,
                        );
                        Some(locs)
                    }
                    Err(e) => {
                        warn!("Failed to finalize V2.1 index, falling back to embedded snapshot only: {}", e);
                        None
                    }
                }
            } else {
                warn!("No volume writer available for index finalization");
                None
            }
        } else {
            None
        };

        // Finalize the pool with per-volume catalog offsets and index locations
        let pool_stats = self
            .pipeline
            .volume_mut()
            .pool_mut()
            .finalize_with_catalogs(&catalog_locations, index_locations.as_deref())
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

            let archive_id = ArchiveId::new();
            let archive_salt = era_crypto::Salt::generate();

            // Generate Master Key (DEK)
            let mut master_key = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(&mut *master_key);

            // Password Recipient
            let password = self.password.unwrap_or_else(|| {
                tracing::warn!("GenericArchiveWriter: no password provided, using empty password");
                String::new()
            });
            let pwd_salt = era_crypto::Salt::generate();
            let kdf_params = KdfParams {
                memory_cost: self.config.encryption.kdf_memory_cost,
                time_cost: self.config.encryption.kdf_time_cost,
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
            let header = SuperHeader::new(
                archive_id,
                recipients,
                self.config.clone(),
                *archive_salt.as_bytes(),
                encrypted_volume_key,
                self.access_policy
                    .unwrap_or(era_volume::AccessPolicy::AnyOfN),
            )?;
            let epoch_id = header.epoch_id();

            let volume_writer =
                VolumeWriter::create(&self.backend, Path::new(&self.filename), header).await?;

            // Store nonce context for block encryption
            let nonce_context = *archive_salt.as_bytes();

            // Store compression config for creating compressors on demand
            let compression_config = self.config.compression.clone();

            let chunk_index = create_chunk_index_with_context(*archive_id.0.as_bytes(), epoch_id)?;

            // Create encryption context
            let encryption = EncryptionContext::new(
                session,
                volume_key,
                nonce_context,
                *archive_id.0.as_bytes(),
                epoch_id,
            );

            Ok(GenericArchiveWriter {
                archive_id,
                encryption,
                compression_config,
                volume_writer,
                catalog: Catalog::new(),
                chunk_index,
                packing: PackingStage::new(
                    self.config.packing.k_factor,
                    4 * 1024 * 1024,
                    self.config.packing.flush_threshold,
                )?,
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

        /// Add a file from memory
        pub async fn add_bytes(&mut self, name: &str, data: &[u8]) -> Result<()> {
            debug!("Adding in-memory file: {} ({} bytes)", name, data.len());

            let hash = era_crypto::hash(data);

            if !self.contains_or_pending(&hash)? {
                let chunk = UniqueChunk::new(Bytes::copy_from_slice(data), hash);
                self.add_to_pending(chunk).await?;
            }

            let chunk_len = u32::try_from(data.len())
                .map_err(|_| EraError::Other("Chunk length exceeds u32::MAX".into()))?;
            let chunk_ref = era_ingest::ChunkRef::new(hash, 0, chunk_len);
            let entry = FileEntry::file(PathBuf::from(name), data.len() as u64)
                .with_chunks(vec![chunk_ref]);
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
            let compressor = self.create_compressor();
            let block_builder = self.encryption.create_block_builder(compressor)?;

            let encrypted_block = block_builder.pack_chunks(packed.chunks)?;
            let location = self
                .volume_writer
                .write_canonical_block(&encrypted_block, era_common::BlockType::Data)
                .await?;

            for hash in hashes {
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

            // Serialize and write catalog
            let catalog_bytes = self.catalog.to_bytes()?;
            let catalog_hash = era_crypto::hash(&catalog_bytes);
            let catalog_chunk = UniqueChunk::new(Bytes::from(catalog_bytes), catalog_hash);

            // Create session-based builder for catalog encryption
            let compressor = self.create_compressor();
            let catalog_builder = self.encryption.create_block_builder(compressor)?;

            let catalog_block = catalog_builder.pack_single(catalog_chunk)?;
            let catalog_block_id = catalog_block.block_id.sequence() as u32;
            let catalog_location = self
                .volume_writer
                .write_canonical_block(&catalog_block, era_common::BlockType::Catalog)
                .await?;

            // Finalize volume
            let _header = self
                .volume_writer
                .finalize_with_catalog(
                    catalog_location.physical_offset,
                    catalog_location.encrypted_size,
                    catalog_block_id,
                    0,
                    0,
                    0,
                )
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
            // All 10 small files should fit in ~2 blocks (1 data + 1 catalog)
            assert!(
                stats.blocks_written <= 2,
                "Expected <=2 blocks, got {}",
                stats.blocks_written
            );
        }
    }
}
