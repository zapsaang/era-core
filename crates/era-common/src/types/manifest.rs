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

    /// Per-volume committed data boundaries sorted by volume sequence.
    /// Used by append mode to reject repaired/finalized state that would move
    /// any volume's committed end backward.
    pub volume_committed_ends: Vec<u64>,
}

/// Header commitments carried by an individual manifest replica.
#[derive(Debug, PartialEq, Eq)]
pub struct ManifestHeaderDigests {
    /// Legacy commitment to the replica's own volume header.
    pub local: Option<[u8; 32]>,
    /// Full table indexed by volume sequence, or empty if absent in a legacy manifest.
    pub by_sequence: Vec<[u8; 32]>,
}

impl ArchiveManifest {
    /// Maximum number of volumes represented by a manifest.
    pub const MAX_VOLUMES: usize = 1024;

    /// Create a new ArchiveManifest with the given parameters.
    pub fn new(
        epoch_id: u32,
        finalize_sequence: u64,
        committed_horizon: u64,
        catalog_commitment: [u8; 32],
        index_commitment: [u8; 32],
        volume_committed_ends: Vec<u64>,
    ) -> Self {
        Self {
            epoch_id,
            finalize_sequence,
            committed_horizon,
            catalog_commitment,
            index_commitment,
            volume_committed_ends,
        }
    }

    /// Serialize the manifest to protobuf bytes.
    pub fn to_bytes(&self) -> crate::Result<Vec<u8>> {
        Ok(self.encode_proto(None))
    }

    /// Serialize a manifest replica with its volume-local header commitment.
    pub fn to_bytes_with_header_digest(&self, digest: [u8; 32]) -> Vec<u8> {
        self.encode_proto(Some(digest))
    }

    /// Serialize a replica with the full header digest table and its legacy local digest.
    /// `digests` must be indexed by volume sequence.
    ///
    /// # Errors
    /// Returns `Serialization` if the table count is invalid, does not match the committed
    /// ends, or does not cover this replica's sequence.
    pub fn to_bytes_with_header_digests(
        &self,
        volume_sequence: u16,
        digests: &[[u8; 32]],
    ) -> crate::Result<Vec<u8>> {
        if !valid_digest_count(digests.len(), self.volume_committed_ends.len()) {
            return Err(crate::EraError::Serialization(
                "header digest table must have one entry per committed end (1..=1024)".into(),
            ));
        }
        let local = digests.get(usize::from(volume_sequence)).ok_or_else(|| {
            crate::EraError::Serialization(format!(
                "manifest replica sequence {volume_sequence} is outside the header digest table"
            ))
        })?;
        let mut proto = crate::proto::ArchiveManifest::from(self);
        proto.volume_header_digest = Some(local.to_vec());
        proto.volume_header_digests = digests.iter().map(|digest| digest.to_vec()).collect();
        Ok(prost::Message::encode_to_vec(&proto))
    }

    fn encode_proto(&self, digest: Option<[u8; 32]>) -> Vec<u8> {
        let mut proto = crate::proto::ArchiveManifest::from(self);
        proto.volume_header_digest = digest.map(|digest| digest.to_vec());
        prost::Message::encode_to_vec(&proto)
    }

    /// Deserialize a manifest from protobuf bytes.
    ///
    /// Enforces a maximum size limit of 16 MB to prevent DoS attacks
    /// from malicious inputs.
    pub fn from_bytes(data: &[u8]) -> crate::Result<Self> {
        Self::decode_proto(data)?.try_into()
    }

    /// Decode the archive-wide state and this replica's optional header commitment.
    pub fn from_bytes_with_header_digest(data: &[u8]) -> crate::Result<(Self, Option<[u8; 32]>)> {
        let (manifest, digests) = Self::from_bytes_with_header_digests(data)?;
        Ok((manifest, digests.local))
    }

    /// Decode the archive-wide state and both header commitments of this replica.
    /// The caller must authenticate the replica before trusting either commitment.
    ///
    /// # Errors
    /// Returns `Deserialization` for malformed manifests or header commitments.
    pub fn from_bytes_with_header_digests(
        data: &[u8],
    ) -> crate::Result<(Self, ManifestHeaderDigests)> {
        Self::from_proto_with_header_digests(Self::decode_proto(data)?)
    }

    fn decode_proto(data: &[u8]) -> crate::Result<crate::proto::ArchiveManifest> {
        crate::serde::deserialize_proto::<crate::proto::ArchiveManifest>(data).map_err(|e| {
            crate::EraError::Deserialization(format!("Failed to decode manifest: {}", e))
        })
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
            volume_committed_ends: m.volume_committed_ends.clone(),
            volume_header_digest: None,
            volume_header_digests: Vec::new(),
        }
    }
}

fn valid_digest_count(digest_count: usize, committed_end_count: usize) -> bool {
    (1..=ArchiveManifest::MAX_VOLUMES).contains(&digest_count)
        && digest_count == committed_end_count
}

impl TryFrom<crate::proto::ArchiveManifest> for ArchiveManifest {
    type Error = crate::EraError;

    fn try_from(p: crate::proto::ArchiveManifest) -> crate::Result<Self> {
        Self::from_proto_with_header_digests(p).map(|(manifest, _)| manifest)
    }
}

impl ArchiveManifest {
    fn from_proto_with_header_digests(
        p: crate::proto::ArchiveManifest,
    ) -> crate::Result<(Self, ManifestHeaderDigests)> {
        if p.volume_committed_ends.len() > Self::MAX_VOLUMES {
            return Err(crate::EraError::Deserialization(format!(
                "volume_committed_ends count {} exceeds maximum {}",
                p.volume_committed_ends.len(),
                Self::MAX_VOLUMES
            )));
        }
        let digest_count = p.volume_header_digests.len();
        if digest_count != 0 && !valid_digest_count(digest_count, p.volume_committed_ends.len()) {
            return Err(crate::EraError::Deserialization(format!(
                "volume_header_digests count {digest_count} must match the number of committed ends ({}) and not exceed {}",
                p.volume_committed_ends.len(),
                Self::MAX_VOLUMES,
            )));
        }

        // DATA_REGION_START = SuperHeader(4096) + BackupFooterGap(128) = 4224.
        // Canonical definition lives in era-volume/src/header.rs.
        // era-common (L0) cannot import era-volume (L2), so we replicate the value here.
        // If the header layout changes, this constant must be updated in sync.
        const DATA_REGION_START: u64 = 4224;
        for (seq, &end) in p.volume_committed_ends.iter().enumerate() {
            // end == 0 is a sentinel value meaning "volume exists but has no committed data yet".
            // This can happen for newly rotated volumes before any data is written.
            if end < DATA_REGION_START && end != 0 {
                return Err(crate::EraError::Deserialization(format!(
                    "volume {} committed_end {} is below DATA_REGION_START",
                    seq, end
                )));
            }
        }

        let catalog_commitment: [u8; 32] = p.catalog_commitment.try_into().map_err(|_| {
            crate::EraError::Deserialization("catalog_commitment must be exactly 32 bytes".into())
        })?;
        let index_commitment: [u8; 32] = p.index_commitment.try_into().map_err(|_| {
            crate::EraError::Deserialization("index_commitment must be exactly 32 bytes".into())
        })?;

        let local = p
            .volume_header_digest
            .map(|bytes| {
                bytes.try_into().map_err(|_| {
                    crate::EraError::Deserialization(
                        "volume_header_digest must be exactly 32 bytes".into(),
                    )
                })
            })
            .transpose()?;
        let by_sequence = p
            .volume_header_digests
            .into_iter()
            .enumerate()
            .map(|(sequence, bytes)| {
                bytes.try_into().map_err(|_| {
                    crate::EraError::Deserialization(format!(
                        "volume_header_digests entry {sequence} must be exactly 32 bytes"
                    ))
                })
            })
            .collect::<crate::Result<_>>()?;

        Ok((
            Self {
                epoch_id: p.epoch_id,
                finalize_sequence: p.finalize_sequence,
                committed_horizon: p.committed_horizon,
                catalog_commitment,
                index_commitment,
                volume_committed_ends: p.volume_committed_ends,
            },
            ManifestHeaderDigests { local, by_sequence },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_manifest_decodes_without_a_header_commitment() {
        let manifest = ArchiveManifest::new(1, 5, 5000, [0xAA; 32], [0xBB; 32], vec![5000]);
        let legacy = manifest.to_bytes().unwrap();

        assert_eq!(
            ArchiveManifest::from_bytes_with_header_digest(&legacy).unwrap(),
            (manifest, None)
        );
    }

    #[test]
    fn new_manifest() {
        let m = ArchiveManifest::new(1, 5, 10, [0xAA; 32], [0xBB; 32], vec![5000, 6000]);
        assert_eq!(m.epoch_id, 1);
        assert_eq!(m.finalize_sequence, 5);
        assert_eq!(m.committed_horizon, 10);
        assert_eq!(m.catalog_commitment, [0xAA; 32]);
        assert_eq!(m.index_commitment, [0xBB; 32]);
        assert_eq!(m.volume_committed_ends, vec![5000, 6000]);
    }

    #[test]
    fn manifest_roundtrip_bytes() {
        let m = ArchiveManifest::new(1, 5, 10, [0xAA; 32], [0xBB; 32], vec![5000, 6000]);
        let bytes = m.to_bytes().unwrap();
        let m2 = ArchiveManifest::from_bytes(&bytes).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn has_index_with_nonzero_commitment() {
        let m = ArchiveManifest::new(1, 5, 10, [0xAA; 32], [0xBB; 32], vec![]);
        assert!(m.has_index());
    }

    #[test]
    fn has_index_with_zero_commitment() {
        let m = ArchiveManifest::new(1, 5, 10, [0xAA; 32], [0u8; 32], vec![]);
        assert!(!m.has_index());
    }

    #[test]
    fn sequence_for_selection() {
        let m = ArchiveManifest::new(1, 42, 10, [0; 32], [0; 32], vec![]);
        assert_eq!(m.sequence_for_selection(), 42);
    }

    #[test]
    fn proto_roundtrip() {
        let m = ArchiveManifest::new(1, 5, 10, [0xAA; 32], [0xBB; 32], vec![5000, 6000]);
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
            volume_committed_ends: vec![],
            volume_header_digest: None,
            volume_header_digests: Vec::new(),
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
            volume_committed_ends: vec![],
            volume_header_digest: None,
            volume_header_digests: Vec::new(),
        };

        let result: crate::Result<ArchiveManifest> = proto.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn volume_committed_ends_uses_varint_not_fixed64_wire_encoding() {
        let proto = crate::proto::ArchiveManifest {
            epoch_id: 1,
            finalize_sequence: 1,
            committed_horizon: 100,
            catalog_commitment: vec![0; 32],
            index_commitment: vec![0; 32],
            volume_committed_ends: vec![1, 2],
            volume_header_digest: None,
            volume_header_digests: Vec::new(),
        };

        let bytes = prost::Message::encode_to_vec(&proto);

        let mut idx = 0;
        let mut field6_payload_len: Option<usize> = None;

        while idx < bytes.len() {
            let tag = bytes[idx];
            let field_num = (tag >> 3) as u32;
            let wire_type = tag & 0x07;
            idx += 1;

            if field_num == 6 {
                assert_eq!(
                    wire_type, 2,
                    "Field 6 must use packed repeated encoding (wire type 2)"
                );

                let mut length = 0u64;
                let mut shift = 0;
                while idx < bytes.len() {
                    let b = bytes[idx];
                    idx += 1;
                    length |= ((b & 0x7F) as u64) << shift;
                    if b & 0x80 == 0 {
                        break;
                    }
                    shift += 7;
                    assert!(shift <= 63, "Invalid varint length");
                }
                field6_payload_len = Some(length as usize);
                break;
            }

            match wire_type {
                0 => {
                    while idx < bytes.len() && bytes[idx] & 0x80 != 0 {
                        idx += 1;
                    }
                    idx += 1;
                }
                2 => {
                    let mut length = 0u64;
                    let mut shift = 0;
                    while idx < bytes.len() {
                        let b = bytes[idx];
                        idx += 1;
                        length |= ((b & 0x7F) as u64) << shift;
                        if b & 0x80 == 0 {
                            break;
                        }
                        shift += 7;
                    }
                    idx += length as usize;
                }
                1 => idx += 8,
                5 => idx += 4,
                _ => panic!("Unexpected wire type {} in protobuf bytes", wire_type),
            }
        }

        let payload_len = field6_payload_len
            .expect("Field 6 (volume_committed_ends) must be present in encoded bytes");

        assert_eq!(
            payload_len, 2,
            "volume_committed_ends packed payload must be 2 bytes (varint encoding). \
             If {} bytes, the field is using fixed64 which breaks v8.2 wire compatibility.",
            payload_len
        );
    }

    #[test]
    fn proto_rejects_too_many_volume_committed_ends() {
        let proto = crate::proto::ArchiveManifest {
            epoch_id: 1,
            finalize_sequence: 5,
            committed_horizon: 10,
            catalog_commitment: vec![0xAA; 32],
            index_commitment: vec![0xBB; 32],
            volume_committed_ends: vec![5000; 1025],
            volume_header_digest: None,
            volume_header_digests: Vec::new(),
        };

        let result: crate::Result<ArchiveManifest> = proto.try_into();
        assert!(result.is_err(), "Should reject >1024 volume_committed_ends");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("1024"),
            "Error should mention limit 1024: {}",
            err
        );
    }

    #[test]
    fn proto_rejects_committed_end_below_data_region_start() {
        let proto = crate::proto::ArchiveManifest {
            epoch_id: 1,
            finalize_sequence: 5,
            committed_horizon: 10,
            catalog_commitment: vec![0xAA; 32],
            index_commitment: vec![0xBB; 32],
            volume_committed_ends: vec![100, 5000],
            volume_header_digest: None,
            volume_header_digests: Vec::new(),
        };

        let result: crate::Result<ArchiveManifest> = proto.try_into();
        assert!(
            result.is_err(),
            "Should reject committed_end below DATA_REGION_START"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("DATA_REGION_START"),
            "Error should mention DATA_REGION_START: {}",
            err
        );
    }

    #[test]
    fn proto_allows_sentinel_zero_committed_end() {
        let proto = crate::proto::ArchiveManifest {
            epoch_id: 1,
            finalize_sequence: 5,
            committed_horizon: 10,
            catalog_commitment: vec![0xAA; 32],
            index_commitment: vec![0xBB; 32],
            volume_committed_ends: vec![0, 5000],
            volume_header_digest: None,
            volume_header_digests: Vec::new(),
        };

        let result: crate::Result<ArchiveManifest> = proto.try_into();
        assert!(
            result.is_ok(),
            "Should allow sentinel value 0 for committed_end: {:?}",
            result.err()
        );
    }
}
