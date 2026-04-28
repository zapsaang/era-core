//! # ERA Engine
//!
//! Core engine for the ERA archive system.
//!
//! This crate orchestrates all layers (L0-L5) to provide
//! high-level archive creation and extraction APIs.
//!
//! ## Authentication Modes
//!
//! ERA supports multiple authentication modes:
//!
//! - **Password mode**: Traditional Argon2id key derivation (~50-300ms overhead).
//! - **Legacy Certificate mode**: X25519 key exchange (~0.05ms overhead).
//! - **Hybrid KEM Certificate mode**: X25519 + Kyber-768 for post-quantum key encapsulation.
//! - **Multi-recipient (OR) mode**: Password and certificate (legacy or hybrid) as separate
//!   recipient slots under AnyOfN. Either credential can unlock the archive.
//! - **Threshold mode**: T-of-N Shamir secret sharing across passwords or hybrid certificates.
//!
//! **Caution**: Certificate modes provide high-performance key exchange, but the engine
//! does not perform automated identity verification. Certificate trust should be managed
//! externally or via the underlying transport/storage layer.
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
mod erasure_scan;
mod erasure_stage;
mod index_stage;
pub mod metrics_collector;
mod packing_stage;
mod reader;
mod recovery;
mod repack;
mod repair;
pub mod sequence;
mod small_file_packer;
mod volume_stage;
mod write_pipeline;
mod writer;

pub use async_pipeline::{ChunkPipeline, PipelineConfig, ProcessedChunk};
pub use block_iter::{
    BlockIterStats, BlockIterator, DecodedBlock, ErasureBlockIterator,
    MultiVolumeSessionBlockIterator, SessionBlockIterator, SessionErasureBlockIterator,
    StandardBlockIterator,
};
pub use checkpoint::{Checkpoint, CheckpointManager, InProgressFile, CHECKPOINT_VERSION};
// Re-export KeySession for convenient access
pub use era_crypto::KeySession;
// Re-export certificate types for convenient access
pub use era_crypto::certificate::{EraCertificate, EraKeyPair, KeyEncapsulation};
pub use era_crypto::hybrid_certificate::{HybridCertificate, HybridKeyPair};
pub use era_volume::AccessPolicy;
pub use era_volume::{RecipientSlot, RecipientType};
pub use reader::{ArchiveHealthStatus, ArchiveReader, ExtractOptions, ExtractStats, VerifyStats};
pub use recovery::{
    RecoverableWriter, RecoveryManager, RecoveryOptions, RecoveryStatus, RecoveryStrategy,
};
pub use repack::{
    repack_archive, repack_archive_with_builder, repack_archive_with_keypair,
    repack_archive_with_passwords, repack_archive_with_private_keys, RepackStats,
};
pub use repair::{
    repair_archive, repair_archive_matrix, repair_archive_with_passwords,
    repair_archive_with_private_keys, repair_archive_with_providers, RepairOptions, RepairStats,
};
#[deprecated(
    since = "0.2.0",
    note = "Use ArchiveWriter instead. GenericArchiveWriter does not support multi-volume, manifest tracking, or V8.2 format features."
)]
pub use writer::generic::{GenericArchiveWriter, GenericArchiveWriterBuilder};
pub use writer::{ArchiveWriter, ArchiveWriterBuilder, AuthMode};
