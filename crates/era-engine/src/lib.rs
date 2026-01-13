//! # ERA Engine
//!
//! Core engine for the ERA archive system.
//!
//! This crate orchestrates all layers (L0-L5) to provide
//! high-level archive creation and extraction APIs.

mod checkpoint;
mod reader;
mod recovery;
mod writer;

pub use checkpoint::{Checkpoint, CheckpointManager, InProgressFile, CHECKPOINT_VERSION};
pub use reader::{ArchiveReader, ExtractOptions, ExtractStats, VerifyStats};
pub use recovery::{
    RecoverableWriter, RecoveryManager, RecoveryOptions, RecoveryStatus, RecoveryStrategy,
};
pub use writer::generic::{GenericArchiveWriter, GenericArchiveWriterBuilder};
pub use writer::{ArchiveWriter, ArchiveWriterBuilder};
