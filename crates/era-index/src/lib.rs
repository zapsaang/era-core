//! # ERA Index V2.1 - Native Log-Structured Indexing
//!
//! Native, log-structured indexing engine for the ERA archive system.
//! Replaces RocksDB with a custom, zero-trust implementation.
//!
//! ## Key Features
//!
//! - **Native Implementation**: No external database dependencies
//! - **Secure Spilling**: Ephemeral encryption for temporary files
//! - **Bloom Filters**: Fast negative lookups (>99% rejection rate)
//! - **Memory Bounded**: Fixed 64MB MemTable limit
//! - **Tiered Merging**: Prevents file descriptor exhaustion

mod config;
mod error;
#[cfg(feature = "rocksdb-backend")]
mod index; // Legacy RocksDB index - only when feature enabled
mod metrics;
pub mod v2;

pub use config::{IndexConfig, IndexConfigBuilder};
pub use error::IndexError;
#[cfg(feature = "rocksdb-backend")]
pub use index::LsmChunkIndex; // Legacy RocksDB index
pub use metrics::IndexMetrics;

// Re-export V2 types
pub use v2::{
    IndexBuilder, IndexEntry, IndexLocation, IndexPage, IndexReader, MetaIndex, Spiller,
    TieredMerger, ENTRIES_PER_PAGE,
};

// Re-export for convenience
pub use era_common::{BlockLocation, ChunkHash};
