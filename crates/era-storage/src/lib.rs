//! # ERA Storage
//!
//! Storage backend abstractions for the ERA archive system.
//!
//! This crate provides the L0 (Physical I/O) layer implementation.

pub mod config;
mod local;
mod local_async;
pub mod memory;
mod traits;

pub use config::{ArchiveConfig, EraConfig, KdfConfig};
pub use local::{LocalStorageBackend, LocalStorageReader, LocalStorageWriter};
pub use local_async::{AsyncLocalStorageBackend, AsyncLocalStorageReader, AsyncLocalStorageWriter};
pub use memory::{MemoryStorageBackend, MemoryStorageReader, MemoryStorageWriter};
pub use traits::{
    AsyncStorageBackend, AsyncStorageReader, AsyncStorageWriter, StorageBackend, StorageMetadata,
    StorageReader, StorageWriter,
};
