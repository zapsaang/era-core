//! Redb table definitions for the ERA chunk deduplication index.
//!
//! Defines the on-disk schema for the staging database used during
//! archive creation. The staging Redb is ephemeral — at finalization,
//! entries are read out and written as encrypted blocks to the volume.

use redb::TableDefinition;

/// Deduplication index: ChunkHash (32 bytes) → rkyv-serialized IndexEntry.
///
/// Key is the raw 32-byte BLAKE3 chunk fingerprint.
/// Value is rkyv-serialized IndexEntry bytes (zero-copy readable via `check_archived_root`).
pub const TABLE_CHUNKS: TableDefinition<&[u8; 32], &[u8]> =
    TableDefinition::new("chunks_v1");
