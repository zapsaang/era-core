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
/// Note: u32::MAX (4,294,967,295) is a valid block index, not a sentinel.
/// If the counter reaches this value, subsequent blocks will fail with
/// EraError::IntegrityError to prevent overflow.
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
    volume_index: u32,
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
        volume_index: u32,
    ) -> Self {
        Self {
            session,
            volume_key,
            nonce_context,
            archive_id,
            epoch_id,
            volume_index,
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
        volume_index: u32,
        block_id: u64,
    ) -> Self {
        Self {
            session,
            volume_key,
            nonce_context,
            archive_id,
            epoch_id,
            volume_index,
            next_block_id: AtomicU64::new(block_id),
        }
    }

    /// Get the next block ID and increment the counter.
    ///
    /// This is used to ensure each block gets a unique encryption key.
    pub fn next_block_id(&self) -> era_common::Result<u64> {
        self.next_block_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                if current <= MAX_BLOCK_INDEX {
                    Some(current + 1)
                } else {
                    None
                }
            })
            .map_err(|current| {
                EraError::IntegrityError(format!(
                    "Block index {} exceeds maximum u32 capacity ({})",
                    current, MAX_BLOCK_INDEX
                ))
            })
    }

    /// Get the current block count without incrementing.
    ///
    /// Useful for statistics and finalization.
    pub fn blocks_written(&self) -> u64 {
        self.next_block_id.load(Ordering::Acquire)
    }

    /// Advance the block ID counter by `n` without consuming keys.
    ///
    /// Used when typed blocks (catalog, index, manifest) are encrypted
    /// outside the normal pipeline but still consume logical block IDs.
    pub fn advance_block_id(&self, n: u64) -> era_common::Result<()> {
        self.next_block_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                let new = current.saturating_add(n);
                if new <= MAX_BLOCK_INDEX {
                    Some(new)
                } else {
                    None
                }
            })
            .map_err(|current| {
                EraError::IntegrityError(format!(
                    "Block index {} + {} exceeds maximum u32 capacity ({})",
                    current, n, MAX_BLOCK_INDEX
                ))
            })?;
        Ok(())
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

    #[allow(dead_code)]
    pub fn set_volume_index(&mut self, volume_index: u32) {
        self.volume_index = volume_index;
    }

    /// Create a SessionBlockBuilder configured with this context's keys.
    ///
    /// Returns an error if the block index would exceed u32::MAX,
    /// since block IDs are stored as u32 in volume headers/footers.
    pub fn create_block_builder<'a>(
        &'a self,
        compressor: Box<dyn Compressor>,
    ) -> era_common::Result<SessionBlockBuilder<'a>> {
        let block_id = self.next_block_id()?;
        if block_id > MAX_BLOCK_INDEX {
            return Err(EraError::IntegrityError(
                "Block index exceeds maximum u32 capacity".into(),
            ));
        }
        Ok(SessionBlockBuilder::new(
            &self.session,
            &self.volume_key,
            self.nonce_context,
            self.archive_id,
            self.epoch_id,
            self.volume_index,
            compressor,
        )
        .with_starting_block_id(block_id))
    }

    /// Create a SessionBlockBuilder for an explicit volume/block pairing.
    ///
    /// This is used when the write path must rebind a block to a rotated volume
    /// without consuming a new logical block ID.
    pub fn create_block_builder_with_block_id<'a>(
        &'a self,
        compressor: Box<dyn Compressor>,
        volume_index: u32,
        block_id: u64,
    ) -> era_common::Result<SessionBlockBuilder<'a>> {
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
            volume_index,
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
        EncryptionContext::new(session, volume_key, nonce_context, [0x11; 16], 1, 0)
    }

    #[test]
    fn test_next_block_id_increments() {
        let ctx = create_test_context();
        assert_eq!(ctx.next_block_id().unwrap(), 0);
        assert_eq!(ctx.next_block_id().unwrap(), 1);
        assert_eq!(ctx.next_block_id().unwrap(), 2);
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
            0,
            100,
        );
        assert_eq!(ctx.next_block_id().unwrap(), 100);
        assert_eq!(ctx.next_block_id().unwrap(), 101);
    }

    #[test]
    fn test_next_block_id_rejects_overflow_after_u32_max() {
        let salt = Salt::generate();
        let params = KdfParams::default();
        let session = KeySession::new(b"test_password", &salt, &params).unwrap();
        let volume_key = session.generate_and_wrap_volume_key().unwrap().0;
        let nonce_context = salt.as_bytes()[..16].try_into().unwrap();

        let ctx = EncryptionContext::with_starting_block_id(
            session,
            volume_key,
            nonce_context,
            [0x33; 16],
            3,
            0,
            MAX_BLOCK_INDEX,
        );

        assert_eq!(ctx.next_block_id().unwrap(), MAX_BLOCK_INDEX);
        assert!(ctx.next_block_id().is_err());
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
