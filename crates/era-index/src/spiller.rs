//! # Secure Spiller - Ephemeral Encryption for Temporary Index Files
//!
//! **Security Requirement:** All temporary spill files MUST be encrypted
//! with ephemeral keys that exist only in RAM and are never persisted.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use rand::RngCore;
use rkyv::Deserialize;
use zeroize::Zeroize;

use era_common::{EraError, Result};
use era_crypto::{AeadCipher, AeadKey, Nonce};

use super::IndexEntry;

/// Number of bytes in a nonce (24 bytes for XChaCha20)
const NONCE_SIZE: usize = 24;

/// Magic header to identify spill files (8 bytes)
const SPILL_MAGIC: &[u8; 8] = b"ERASPILL";

/// Spiller manages the secure writing and reading of temporary index segments
pub struct Spiller {
    /// Ephemeral AEAD key (exists only in RAM)
    key: AeadKey,
    /// AEAD cipher for encryption/decryption
    cipher: AeadCipher,
    /// Counter for generating unique nonces
    nonce_counter: std::sync::atomic::AtomicU64,
}

impl Spiller {
    /// Create a new Spiller with a fresh ephemeral key
    pub fn new() -> Self {
        // Generate a random 32-byte ephemeral key (never written to disk)
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        let key = AeadKey::from_bytes(&key_bytes).expect("32-byte key is valid");

        // CRITICAL: Zeroize the stack array to prevent memory forensics
        key_bytes.zeroize();

        Self {
            key,
            cipher: AeadCipher::new(),
            nonce_counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Spill sorted entries to an encrypted temporary file
    ///
    /// Returns the path to the created spill file
    pub fn spill(&self, entries: &[IndexEntry], temp_dir: &Path) -> Result<PathBuf> {
        // Create temp file
        let temp_file = tempfile::Builder::new()
            .prefix("era-spill-")
            .suffix(".enc")
            .tempfile_in(temp_dir)
            .map_err(EraError::Io)?;

        let (file, path) = temp_file.keep().map_err(|e| EraError::Io(e.error))?;

        let mut file: File = file;

        // Generate unique nonce
        let nonce = self.generate_nonce();

        // Serialize entries using rkyv (zero-copy)
        let entries_vec = entries.to_vec();
        let plaintext = rkyv::to_bytes::<_, 4096>(&entries_vec)
            .map_err(|e| EraError::Serialization(e.to_string()))?;

        // Encrypt payload
        let ciphertext = self.cipher.encrypt(&self.key, &nonce, &plaintext)?;

        // Write file format:
        // [Magic: 8 bytes] [Nonce: 24 bytes] [Ciphertext + Tag: variable]
        file.write_all(SPILL_MAGIC).map_err(EraError::Io)?;
        file.write_all(nonce.as_bytes()).map_err(EraError::Io)?;
        file.write_all(&ciphertext).map_err(EraError::Io)?;

        file.sync_all().map_err(EraError::Io)?;

        Ok(path)
    }

    /// Read and decrypt a spill file
    pub fn read_spill(&self, path: &Path) -> Result<Vec<IndexEntry>> {
        let mut file = File::open(path).map_err(EraError::Io)?;

        // Read and verify magic header
        let mut magic = [0u8; 8];
        file.read_exact(&mut magic).map_err(EraError::Io)?;

        if &magic != SPILL_MAGIC {
            return Err(EraError::InvalidFormat(
                "Invalid spill file magic header".to_string(),
            ));
        }

        // Read nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        file.read_exact(&mut nonce_bytes).map_err(EraError::Io)?;
        let nonce = Nonce::from_bytes(&nonce_bytes)?;

        // Read ciphertext
        let mut ciphertext = Vec::new();
        file.read_to_end(&mut ciphertext).map_err(EraError::Io)?;

        // Decrypt
        let plaintext = self
            .cipher
            .decrypt(&self.key, &nonce, &ciphertext)
            .map_err(|e| EraError::Decryption(format!("Failed to decrypt spill file: {}", e)))?;

        // Deserialize using rkyv (zero-copy)
        let archived = rkyv::check_archived_root::<Vec<IndexEntry>>(&plaintext)
            .map_err(|e| EraError::Deserialization(e.to_string()))?;
        let entries: Vec<IndexEntry> = archived
            .deserialize(&mut rkyv::Infallible)
            .map_err(|e| EraError::Deserialization(format!("{:?}", e)))?;

        Ok(entries)
    }

    /// Generate a unique nonce for each spill operation
    fn generate_nonce(&self) -> Nonce {
        let counter = self
            .nonce_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        // Use counter as nonce (safe for up to 2^64 spills per session)
        nonce_bytes[..8].copy_from_slice(&counter.to_le_bytes());
        Nonce::from_bytes(&nonce_bytes).expect("24-byte nonce is valid")
    }
}

impl Default for Spiller {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use era_common::{BlockId, ChunkHash, VolumeId};
    use tempfile::TempDir;

    fn test_hash(value: u64) -> ChunkHash {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        ChunkHash::from_bytes(bytes)
    }

    #[test]
    fn test_spill_and_read() {
        let temp_dir = TempDir::new().unwrap();
        let spiller = Spiller::new();

        let entries: Vec<IndexEntry> = (0..100)
            .map(|i| IndexEntry {
                hash: test_hash(i),
                volume_id: VolumeId::new(),
                block_id: BlockId::new(i / 10),
                offset: (i % 10) as u32 * 1024,
                length: 1024,
            })
            .collect();

        let path = spiller.spill(&entries, temp_dir.path()).unwrap();
        assert!(path.exists());

        let recovered = spiller.read_spill(&path).unwrap();
        assert_eq!(recovered.len(), entries.len());
        assert_eq!(recovered, entries);
    }

    #[test]
    fn test_spill_is_encrypted() {
        let temp_dir = TempDir::new().unwrap();
        let spiller = Spiller::new();

        let entries: Vec<IndexEntry> = (0..100)
            .map(|i| IndexEntry {
                hash: test_hash(i),
                volume_id: VolumeId::new(),
                block_id: BlockId::new(0),
                offset: i as u32 * 1024,
                length: 1024,
            })
            .collect();

        let path = spiller.spill(&entries, temp_dir.path()).unwrap();

        // Read raw file content
        let mut raw_content = Vec::new();
        File::open(&path)
            .unwrap()
            .read_to_end(&mut raw_content)
            .unwrap();

        // Verify magic header
        assert_eq!(&raw_content[..8], SPILL_MAGIC);

        // Verify that plaintext hashes do NOT appear in the ciphertext portion
        let ciphertext_start = 8 + NONCE_SIZE;
        let ciphertext = &raw_content[ciphertext_start..];

        for entry in &entries[..10] {
            let hash_bytes = entry.hash.as_bytes();
            assert!(
                !ciphertext.windows(32).any(|w| w == hash_bytes),
                "SECURITY VIOLATION: Plaintext hash found in encrypted spill file"
            );
        }
    }

    #[test]
    fn test_wrong_key_fails() {
        let temp_dir = TempDir::new().unwrap();
        let spiller1 = Spiller::new();
        let spiller2 = Spiller::new(); // Different ephemeral key

        let entries: Vec<IndexEntry> = (0..10)
            .map(|i| IndexEntry {
                hash: test_hash(i),
                volume_id: VolumeId::new(),
                block_id: BlockId::new(0),
                offset: i as u32 * 1024,
                length: 1024,
            })
            .collect();

        let path = spiller1.spill(&entries, temp_dir.path()).unwrap();

        // Attempting to read with different Spiller should fail authentication
        let result = spiller2.read_spill(&path);
        assert!(
            result.is_err(),
            "Spill file should not be readable with wrong key"
        );
    }
}
