//! Typed block kind for redundancy validation and repair.
//!
//! Groups the three types of metadata blocks that are fully replicated
//! across volumes in v8.2 format.

use super::block::BlockType;

/// Typed block kind for redundancy validation and repair.
///
/// Groups the three types of metadata blocks that are fully replicated across volumes.
/// Used by `load_typed_block_with_redundancy` and `RepairManager` for generic
/// typed block operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypedBlockKind {
    /// Archive manifest (v8.2) — cryptographically authenticated global state
    Manifest,
    /// File catalog — file entries and block locations
    Catalog,
    /// Deduplication index — Bloom + L1/L2 pages
    Index,
}

impl TypedBlockKind {
    /// Returns the human-readable name of this typed block kind.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Manifest => "Manifest",
            Self::Catalog => "Catalog",
            Self::Index => "Index",
        }
    }

    /// Returns the corresponding BlockType for this typed block kind.
    pub fn block_type(&self) -> BlockType {
        match self {
            Self::Manifest => BlockType::Manifest,
            Self::Catalog => BlockType::Catalog,
            Self::Index => BlockType::IndexManifest,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TypedBlockKind;
    use crate::types::BlockType;

    #[test]
    fn typed_block_kind_maps_to_metadata_block_types() {
        assert_eq!(TypedBlockKind::Manifest.name(), "Manifest");
        assert_eq!(TypedBlockKind::Manifest.block_type(), BlockType::Manifest);
        assert_eq!(TypedBlockKind::Catalog.block_type(), BlockType::Catalog);
        assert_eq!(TypedBlockKind::Index.block_type(), BlockType::IndexManifest);
    }
}
