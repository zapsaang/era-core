//! ArchiveManifest type definition for v8.2.
//!
//! ArchiveManifest is an AEAD-encrypted typed block that captures the
//! cryptographically authenticated global state snapshot of an archive.
//! It is stored as BlockType::Manifest in all volumes (full replica redundancy).

use serde::{Deserialize, Serialize};

/// Cryptographically authenticated global state snapshot of an archive.
///
/// Stored as an AEAD-encrypted typed block (BlockType::Manifest).
/// Uses BLOCK_KEY_DOMAIN to derive the encryption key (no dedicated key derivation domain).
///
/// Serialization format: protobuf (same as SuperHeader)
/// Encryption: XChaCha20-Poly1305, AAD = archive_id ‖ epoch_id ‖ "MANIFEST" ‖ block_id
/// Storage: typed block, written to all volumes (full replica redundancy)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveManifest {
    /// Monotonically increasing epoch ID (matches SuperHeader.epoch_id).
    /// Used for cross-archive consistency verification and version negotiation.
    pub epoch_id: u32,

    /// Authenticated generation number (monotonically increasing).
    /// Used for replay attack prevention: the Reader loads Manifest from all volumes
    /// and selects the copy with the highest finalize_sequence.
    /// Incremented after each successful finalize.
    pub finalize_sequence: u64,

    /// Logical commit boundary (absolute byte offset).
    /// Data beyond this boundary is considered uncommitted and must be ignored by the Reader.
    /// Replaces physical truncation in recovery.rs (file.set_len()).
    pub committed_horizon: u64,

    /// Domain-separated cryptographic commitment of Catalog contents.
    /// = blake3::keyed_hash("ERA-CAT-COMMIT-v1_______________", &catalog_plaintext)
    /// Computed over serialized plaintext for semantic binding.
    pub catalog_commitment: [u8; 32],

    /// Domain-separated cryptographic commitment of Index contents.
    /// = blake3::keyed_hash("ERA-IDX-COMMIT-v1_______________", &index_plaintext)
    /// If no Index exists, set to all zeros [0u8; 32].
    pub index_commitment: [u8; 32],
}

impl ArchiveManifest {
    /// Create a new ArchiveManifest with the given parameters.
    pub fn new(
        epoch_id: u32,
        finalize_sequence: u64,
        committed_horizon: u64,
        catalog_commitment: [u8; 32],
        index_commitment: [u8; 32],
    ) -> Self {
        Self {
            epoch_id,
            finalize_sequence,
            committed_horizon,
            catalog_commitment,
            index_commitment,
        }
    }

    /// Serialize the manifest to protobuf bytes.
    pub fn to_bytes(&self) -> crate::Result<Vec<u8>> {
        let proto: crate::proto::ArchiveManifest = self.into();
        Ok(prost::Message::encode_to_vec(&proto))
    }

    /// Deserialize a manifest from protobuf bytes.
    ///
    /// Enforces a maximum size limit of 16 MB to prevent DoS attacks
    /// from malicious inputs.
    pub fn from_bytes(data: &[u8]) -> crate::Result<Self> {
        let proto = crate::serde::deserialize_proto::<crate::proto::ArchiveManifest>(data)
            .map_err(|e| crate::EraError::Deserialization(format!("Failed to decode manifest: {}", e)))?;
        proto.try_into()
    }

    /// Check if this manifest has a valid index commitment (not all zeros).
    pub fn has_index(&self) -> bool {
        self.index_commitment != [0u8; 32]
    }

    /// Return the finalize_sequence for redundancy selection.
    /// This is used by load_typed_block_with_redundancy to select
    /// the highest-sequence copy (replay attack prevention).
    pub fn sequence_for_selection(&self) -> u64 {
        self.finalize_sequence
    }
}

// ── Protobuf conversions ───────────────────────────────────────────

impl From<&ArchiveManifest> for crate::proto::ArchiveManifest {
    fn from(m: &ArchiveManifest) -> Self {
        Self {
            epoch_id: m.epoch_id,
            finalize_sequence: m.finalize_sequence,
            committed_horizon: m.committed_horizon,
            catalog_commitment: m.catalog_commitment.to_vec(),
            index_commitment: m.index_commitment.to_vec(),
        }
    }
}

impl TryFrom<crate::proto::ArchiveManifest> for ArchiveManifest {
    type Error = crate::EraError;

    fn try_from(p: crate::proto::ArchiveManifest) -> crate::Result<Self> {
        let catalog_commitment: [u8; 32] = p.catalog_commitment.try_into().map_err(|_| {
            crate::EraError::Deserialization("catalog_commitment must be exactly 32 bytes".into())
        })?;
        let index_commitment: [u8; 32] = p.index_commitment.try_into().map_err(|_| {
            crate::EraError::Deserialization("index_commitment must be exactly 32 bytes".into())
        })?;

        Ok(Self {
            epoch_id: p.epoch_id,
            finalize_sequence: p.finalize_sequence,
            committed_horizon: p.committed_horizon,
            catalog_commitment,
            index_commitment,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_manifest() {
        let m = ArchiveManifest::new(1, 5, 10, [0xAA; 32], [0xBB; 32]);
        assert_eq!(m.epoch_id, 1);
        assert_eq!(m.finalize_sequence, 5);
        assert_eq!(m.committed_horizon, 10);
        assert_eq!(m.catalog_commitment, [0xAA; 32]);
        assert_eq!(m.index_commitment, [0xBB; 32]);
    }

    #[test]
    fn manifest_roundtrip_bytes() {
        let m = ArchiveManifest::new(1, 5, 10, [0xAA; 32], [0xBB; 32]);
        let bytes = m.to_bytes().unwrap();
        let m2 = ArchiveManifest::from_bytes(&bytes).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn has_index_with_nonzero_commitment() {
        let m = ArchiveManifest::new(1, 5, 10, [0xAA; 32], [0xBB; 32]);
        assert!(m.has_index());
    }

    #[test]
    fn has_index_with_zero_commitment() {
        let m = ArchiveManifest::new(1, 5, 10, [0xAA; 32], [0u8; 32]);
        assert!(!m.has_index());
    }

    #[test]
    fn sequence_for_selection() {
        let m = ArchiveManifest::new(1, 42, 10, [0; 32], [0; 32]);
        assert_eq!(m.sequence_for_selection(), 42);
    }

    #[test]
    fn proto_roundtrip() {
        let m = ArchiveManifest::new(1, 5, 10, [0xAA; 32], [0xBB; 32]);
        let proto: crate::proto::ArchiveManifest = (&m).into();
        let m2: ArchiveManifest = proto.try_into().unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn proto_rejects_wrong_catalog_commitment_length() {
        let proto = crate::proto::ArchiveManifest {
            epoch_id: 1,
            finalize_sequence: 5,
            committed_horizon: 10,
            catalog_commitment: vec![0xAA; 31],
            index_commitment: vec![0xBB; 32],
        };

        let result: crate::Result<ArchiveManifest> = proto.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn proto_rejects_wrong_index_commitment_length() {
        let proto = crate::proto::ArchiveManifest {
            epoch_id: 1,
            finalize_sequence: 5,
            committed_horizon: 10,
            catalog_commitment: vec![0xAA; 32],
            index_commitment: vec![0xBB; 33],
        };

        let result: crate::Result<ArchiveManifest> = proto.try_into();
        assert!(result.is_err());
    }
}
