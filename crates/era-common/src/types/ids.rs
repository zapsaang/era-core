//! Identifier types for ERA archive system.

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for an archive set
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArchiveId(pub Uuid);

impl ArchiveId {
    /// Generate a new random archive ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create from an existing UUID
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl Default for ArchiveId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ArchiveId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a volume within an archive
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VolumeId(pub Uuid);

// Manual rkyv implementation for VolumeId (Uuid doesn't implement Archive)
impl Archive for VolumeId {
    type Archived = [u8; 16];
    type Resolver = ();

    unsafe fn resolve(&self, _pos: usize, _resolver: Self::Resolver, out: *mut Self::Archived) {
        out.write(*self.0.as_bytes());
    }
}

impl<S: rkyv::ser::Serializer + ?Sized> RkyvSerialize<S> for VolumeId {
    fn serialize(&self, _serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        Ok(())
    }
}

impl<D: rkyv::Fallible + ?Sized> RkyvDeserialize<VolumeId, D> for [u8; 16] {
    fn deserialize(&self, _deserializer: &mut D) -> Result<VolumeId, D::Error> {
        Ok(VolumeId(Uuid::from_bytes(*self)))
    }
}

impl VolumeId {
    /// Generate a new random volume ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for VolumeId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for VolumeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a MacroBlock
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    Archive,
    RkyvDeserialize,
    RkyvSerialize,
)]
#[archive(check_bytes)]
pub struct BlockId(pub u64);

impl BlockId {
    /// Create a new block ID with the given sequence number
    pub fn new(seq: u64) -> Self {
        Self(seq)
    }

    /// Get the sequence number
    pub fn sequence(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for BlockId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "block:{:08x}", self.0)
    }
}

/// Hash of a chunk (32 bytes, Blake3)
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    Archive,
    RkyvDeserialize,
    RkyvSerialize,
)]
#[archive(check_bytes)]
#[archive_attr(derive(Hash, Eq, PartialEq))]
pub struct ChunkHash(pub [u8; 32]);

impl ChunkHash {
    /// Create from a byte array
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for ChunkHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChunkHash({})", hex::encode(&self.0[..8]))
    }
}

impl std::fmt::Display for ChunkHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

impl From<ChunkHash> for crate::proto::ChunkHash {
    fn from(value: ChunkHash) -> Self {
        Self {
            hash: value.0.to_vec(),
        }
    }
}

impl TryFrom<crate::proto::ChunkHash> for ChunkHash {
    type Error = crate::EraError;

    fn try_from(value: crate::proto::ChunkHash) -> Result<Self, Self::Error> {
        if value.hash.len() != 32 {
            return Err(crate::EraError::Deserialization(format!(
                "Invalid chunk hash length: expected 32, got {}",
                value.hash.len()
            )));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&value.hash);
        Ok(Self(bytes))
    }
}
