use era_common::{EraError, Result};
use era_crypto::certificate::{EraKeyPair, KeyEncapsulation};
use era_crypto::{AeadContext, XChaCha20Poly1305Context, NONCE_SIZE};
use era_crypto::{KdfParams, Salt};
use era_volume::{RecipientSlot, RecipientType};
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use zeroize::Zeroizing;

/// Abstract identity provider for authentication.
///
/// # Security Note
/// Rate-limiting and brute-force protection are the caller's responsibility.
/// This trait performs a single unlock attempt per call without any built-in
/// throttling or lockout mechanism.
pub trait AuthProvider: Send + Sync {
    /// Attempt to unlock a recipient slot.
    /// Returns the decrypted Master Key if successful.
    fn try_unlock(&self, slot: &RecipientSlot) -> Result<Option<Vec<u8>>>;
}

#[derive(Archive, RkyvDeserialize, RkyvSerialize)]
#[archive(check_bytes)]
pub struct PasswordSlotParams {
    pub salt: [u8; 16],
    pub kdf_memory_cost: u32,
    pub kdf_time_cost: u32,
    pub kdf_parallelism: u32,
}

pub struct PasswordProvider {
    password: Zeroizing<String>,
}

impl PasswordProvider {
    pub fn new(password: String) -> Self {
        Self {
            password: Zeroizing::new(password),
        }
    }
}

impl AuthProvider for PasswordProvider {
    fn try_unlock(&self, slot: &RecipientSlot) -> Result<Option<Vec<u8>>> {
        if slot.r_type() != RecipientType::Argon2idPassword {
            return Ok(None);
        }

        // Deserialize parameters using rkyv zero-copy
        let archived = rkyv::check_archived_root::<PasswordSlotParams>(slot.params())
            .map_err(|e| EraError::Deserialization(e.to_string()))?;

        // Derive KEK (Key Encryption Key)
        let kdf_params = KdfParams {
            memory_cost: archived.kdf_memory_cost,
            time_cost: archived.kdf_time_cost,
            parallelism: archived.kdf_parallelism,
            // Output length is implicit 32
        };

        let salt = Salt::from_bytes(archived.salt);

        let derived_key = era_crypto::derive_key(self.password.as_bytes(), &salt, &kdf_params)?;

        // Decrypt the Master Key
        // Format of encrypted_master_key: [Nonce (24) | Ciphertext]

        let encrypted = slot.encrypted_master_key();
        if encrypted.len() < NONCE_SIZE + 16 {
            // Minimal size (nonce + minimal ciphertext/tag)
            return Ok(None);
        }

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&encrypted[0..NONCE_SIZE]);
        let ciphertext = &encrypted[NONCE_SIZE..];

        let ctx = XChaCha20Poly1305Context::from_derived_key(&derived_key)?;

        // decrypt returns Result<Vec<u8>>
        match ctx.decrypt(&nonce, &[], ciphertext) {
            Ok(mk) => Ok(Some(mk)),
            Err(_) => Ok(None), // Failed to decrypt (wrong password)
        }
    }
}

pub struct CertificateProvider {
    keypair: EraKeyPair,
}

impl CertificateProvider {
    pub fn new(keypair: EraKeyPair) -> Self {
        Self { keypair }
    }
}

impl AuthProvider for CertificateProvider {
    fn try_unlock(&self, slot: &RecipientSlot) -> Result<Option<Vec<u8>>> {
        if slot.r_type() != RecipientType::X25519PubKey {
            return Ok(None);
        }

        // Optional optimization: Check key_id
        if let Some(slot_kid) = slot.key_id() {
            let my_kid = self.keypair.key_id();
            if my_kid.len() >= 8 && *slot_kid != my_kid[..8] {
                return Ok(None);
            }
        }

        let ephemeral_public: [u8; 32] =
            slot.params().to_vec().try_into().map_err(|e: Vec<u8>| {
                EraError::InvalidKey(format!(
                    "Invalid ephemeral public: expected 32 bytes, got {}",
                    e.len()
                ))
            })?;

        let encapsulation = KeyEncapsulation {
            ephemeral_public,
            encrypted_master_key: slot.encrypted_master_key().to_vec(),
        };

        match self.keypair.decapsulate(&encapsulation) {
            Ok(dk) => Ok(Some(dk.as_bytes().to_vec())),
            Err(_) => Ok(None),
        }
    }
}
