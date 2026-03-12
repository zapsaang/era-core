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
//! - **Password mode**: Traditional Argon2id key derivation (~50-300ms overhead).
//! - **Certificate mode**: Hybrid KEM (X25519 + Kyber-768) for post-quantum key encapsulation.
//!
//! **Caution**: While Certificate mode provides high-performance key exchange (~0.05ms overhead),
//! the current engine implementation has known trust boundary limitations for automated
//! identity verification. It is currently suitable only for scenarios where the underlying
//! transport or storage layer provides its own authentication, or where the certificate
//! trust is managed externally. Full hybrid/PQ certificate validation within the engine
//! pipeline is a planned enhancement.
//!
//! ## Chunk Index Backend
//!
//! The chunk index is internal. For production workloads with
//! incremental backups, use era_index::v2 APIs directly.

pub mod async_pipeline;
pub mod auth;
mod block_iter;
mod checkpoint;
pub(crate) mod chunk_index;
pub(crate) mod chunk_processor;
mod encryption_context;
mod erasure_stage;
mod index_stage;
pub mod metrics_collector;
mod packing_stage;
mod reader;
mod recovery;
mod repair;
mod small_file_packer;
mod volume_stage;
mod write_pipeline;
mod writer;

pub use async_pipeline::{ChunkPipeline, PipelineConfig, ProcessedChunk};
pub use block_iter::{
    BlockIterStats, BlockIterator, DecodedBlock, ErasureBlockIterator, SessionBlockIterator,
    SessionErasureBlockIterator, StandardBlockIterator,
};
pub use checkpoint::{Checkpoint, CheckpointManager, InProgressFile, CHECKPOINT_VERSION};
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
