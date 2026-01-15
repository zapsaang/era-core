//! # ERA Engine
//!
//! Core engine for the ERA archive system.
//!
//! This crate orchestrates all layers (L0-L5) to provide
//! high-level archive creation and extraction APIs.
//!
//! ## Authentication Modes
//!
//! ERA supports two authentication modes:
//!
//! - **Password mode**: Traditional Argon2id key derivation (~50-300ms overhead)
//! - **Certificate mode**: X25519 key exchange (~0.05ms overhead, ~1000x faster)
//!
//! Certificate mode is recommended for automated scenarios where key management
//! is handled separately (e.g., backup servers, cloud storage).
//!
//! ## Chunk Index Backend
//!
//! ERA supports two chunk deduplication backends:
//!
//! - **Memory**: In-memory HashMap (legacy, not recommended for production)
//! - **LSM**: RocksDB-based LSM-Tree (enable with `lsm` feature)
//!
//! For production workloads with incremental backups, enable the `lsm` feature.

mod block_iter;
mod checkpoint;
pub mod chunk_index;
pub(crate) mod chunk_processor;
pub mod metrics_collector;
mod reader;
mod recovery;
mod repair;
mod writer;

pub use block_iter::{
    BlockIterStats, BlockIterator, DecodedBlock, ErasureBlockIterator, SessionBlockIterator,
    SessionErasureBlockIterator, StandardBlockIterator,
};
pub use checkpoint::{Checkpoint, CheckpointManager, InProgressFile, CHECKPOINT_VERSION};
pub use chunk_index::{ChunkIndex, ChunkIndexBackend, MemoryChunkIndex, create_chunk_index};
// Re-export KeySession for convenient access
pub use era_crypto::KeySession;
// Re-export certificate types for convenient access
pub use era_crypto::certificate::{EraCertificate, EraKeyPair, KeyEncapsulation};
pub use reader::{ArchiveReader, ExtractOptions, ExtractStats, VerifyStats};
pub use recovery::{
    RecoverableWriter, RecoveryManager, RecoveryOptions, RecoveryStatus, RecoveryStrategy,
};
pub use repair::{repair_archive, repair_archive_matrix, RepairOptions, RepairStats};
pub use writer::generic::{GenericArchiveWriter, GenericArchiveWriterBuilder};
pub use writer::{ArchiveWriter, ArchiveWriterBuilder, AuthMode};
