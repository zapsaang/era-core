//! # ERA Storage
//!
//! Storage backend abstractions for the ERA archive system.
//!
//! This crate provides the L0 (Physical I/O) layer implementation.

mod local;
mod memory;
mod traits;

pub use local::{LocalStorageBackend, LocalStorageReader, LocalStorageWriter};
pub use memory::{MemoryStorageBackend, MemoryStorageReader, MemoryStorageWriter};
pub use traits::{StorageBackend, StorageMetadata, StorageReader, StorageWriter};
