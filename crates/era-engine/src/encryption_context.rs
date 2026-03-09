//! Encryption context module.
//!
//! Encapsulates the cryptographic state needed for archive encryption,
//! including the key session, volume key, nonce context, and block ID counter.
//!
//! This module is part of the God Object decomposition effort (Phase 2).

use era_codec::Compressor;
use era_common::EraError;
use era_crypto::{KeySession, VolumeKey};
use era_packing::SessionBlockBuilder;
use std::sync::atomic::{AtomicU64, Ordering};

/// Maximum block index value — block IDs are stored as u32 in volume
/// headers and footer fields, so the counter must not exceed u32::MAX.
const MAX_BLOCK_INDEX: u64 = u32::MAX as u64;

/// Encryption context for archive operations.
///
/// Holds all cryptographic state needed to encrypt blocks:
/// - `session`: The KeySession with the master key (mlock-protected)
/// - `volume_key`: Pre-derived volume key for efficiency
/// - `nonce_context`: Salt-based context for AEAD nonce derivation
/// - `next_block_id`: Counter for per-block key derivation
///
/// ## Security Model
///
/// This context implements the HKDF "Onion Model":
/// - Master Key (MK) → Volume Key (VK) → Block Key (BK)
/// - Each block gets a unique key derived from the volume key
/// - Keys are stored in mlock-protected memory via KeySession
pub struct EncryptionContext {
    /// The KeySession holds the master key, protected by mlock
    session: KeySession,
    /// Pre-derived volume key for the primary volume (volume 0)
    volume_key: VolumeKey,
    /// Salt-based nonce context for AEAD operations (16 bytes from Salt)
    nonce_context: [u8; 16],
    archive_id: [u8; 16],
    epoch_id: u32,
    /// Block ID counter for per-block key derivation
    next_block_id: AtomicU64,
}

impl EncryptionContext {
    /// Create a new encryption context.
    ///
    /// # Arguments
    /// * `session` - The KeySession with master key
    /// * `volume_key` - Pre-derived volume key for volume 0
    /// * `nonce_context` - 16-byte salt-based context for nonce derivation
    pub fn new(
        session: KeySession,
        volume_key: VolumeKey,
        nonce_context: [u8; 16],
        archive_id: [u8; 16],
        epoch_id: u32,
    ) -> Self {
        Self {
            session,
            volume_key,
            nonce_context,
            archive_id,
            epoch_id,
            next_block_id: AtomicU64::new(0),
        }
    }

    /// Create a new encryption context with a starting block ID.
    ///
    /// Use this when resuming from a checkpoint or appending to an existing archive.
    pub fn with_starting_block_id(
        session: KeySession,
        volume_key: VolumeKey,
        nonce_context: [u8; 16],
        archive_id: [u8; 16],
        epoch_id: u32,
        block_id: u64,
    ) -> Self {
        Self {
            session,
            volume_key,
            nonce_context,
            archive_id,
            epoch_id,
            next_block_id: AtomicU64::new(block_id),
        }
    }

    /// Get the next block ID and increment the counter.
    ///
    /// This is used to ensure each block gets a unique encryption key.
    pub fn next_block_id(&self) -> u64 {
        self.next_block_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Get the current block count without incrementing.
    ///
    /// Useful for statistics and finalization.
    pub fn blocks_written(&self) -> u64 {
        self.next_block_id.load(Ordering::Relaxed)
    }

    /// Get a reference to the key session.
    #[allow(dead_code)]
    pub fn session(&self) -> &KeySession {
        &self.session
    }

    /// Get a reference to the volume key.
    #[allow(dead_code)]
    pub fn volume_key(&self) -> &VolumeKey {
        &self.volume_key
    }

    /// Get the nonce context.
    #[allow(dead_code)]
    pub fn nonce_context(&self) -> [u8; 16] {
        self.nonce_context
    }

    #[allow(dead_code)]
    pub fn archive_id(&self) -> [u8; 16] {
        self.archive_id
    }

    #[allow(dead_code)]
    pub fn epoch_id(&self) -> u32 {
        self.epoch_id
    }

    /// Create a SessionBlockBuilder configured with this context's keys.
    ///
    /// Returns an error if the block index would exceed u32::MAX,
    /// since block IDs are stored as u32 in volume headers/footers.
    pub fn create_block_builder<'a>(
        &'a self,
        compressor: Box<dyn Compressor>,
    ) -> era_common::Result<SessionBlockBuilder<'a>> {
        let block_id = self.next_block_id();
        if block_id > MAX_BLOCK_INDEX {
            return Err(EraError::IntegrityError(format!(
                "Block index {} exceeds maximum u32 capacity ({})",
                block_id, MAX_BLOCK_INDEX
            )));
        }
        Ok(SessionBlockBuilder::new(
            &self.session,
            &self.volume_key,
            self.nonce_context,
            self.archive_id,
            self.epoch_id,
            compressor,
        )
        .with_starting_block_id(block_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use era_crypto::{KdfParams, Salt};

    fn create_test_context() -> EncryptionContext {
        let salt = Salt::generate();
        let params = KdfParams::default();
        let session = KeySession::new(b"test_password", &salt, &params).unwrap();
        let volume_key = session.generate_and_wrap_volume_key().unwrap().0;
        let nonce_context = salt.as_bytes()[..16].try_into().unwrap();
        EncryptionContext::new(session, volume_key, nonce_context, [0x11; 16], 1)
    }

    #[test]
    fn test_next_block_id_increments() {
        let ctx = create_test_context();
        assert_eq!(ctx.next_block_id(), 0);
        assert_eq!(ctx.next_block_id(), 1);
        assert_eq!(ctx.next_block_id(), 2);
        assert_eq!(ctx.blocks_written(), 3);
    }

    #[test]
    fn test_with_starting_block_id() {
        let salt = Salt::generate();
        let params = KdfParams::default();
        let session = KeySession::new(b"test_password", &salt, &params).unwrap();
        let volume_key = session.generate_and_wrap_volume_key().unwrap().0;
        let nonce_context = salt.as_bytes()[..16].try_into().unwrap();

        let ctx = EncryptionContext::with_starting_block_id(
            session,
            volume_key,
            nonce_context,
            [0x22; 16],
            2,
            100,
        );
        assert_eq!(ctx.next_block_id(), 100);
        assert_eq!(ctx.next_block_id(), 101);
    }

    #[test]
    fn test_accessors() {
        let ctx = create_test_context();

        // Verify accessors don't panic
        let _ = ctx.session();
        let _ = ctx.volume_key();
        let _ = ctx.nonce_context();
        let _ = ctx.archive_id();
        let _ = ctx.epoch_id();
    }
}
