//! # ERA Index
//!
//! LSM-Tree based chunk deduplication index for the ERA archive system.
//!
//! This crate provides persistent, high-performance chunk deduplication using
//! RocksDB as the underlying LSM-Tree implementation.
//!
//! ## Key Features
//!
//! - **Persistent Storage**: Chunk index survives process restarts, enabling incremental backups
//! - **Bloom Filters**: Reduces read amplification by ~99% for non-existent keys
//! - **Memory Bounded**: Configurable MemTable size prevents OOM on large datasets
//! - **Concurrent Access**: Multiple readers, single writer with minimal lock contention
//!
//! ## Architecture (ERA v8.1 Whitepaper)
//!
//! The index implements the L4 Chunking Layer's deduplication logic:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      LsmChunkIndex                          │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
//! │  │  MemTable   │→ │   SSTable   │→ │   SSTable   │→ ...    │
//! │  │   (RAM)     │  │  (Level 0)  │  │  (Level 1)  │         │
//! │  └─────────────┘  └─────────────┘  └─────────────┘         │
//! │         ↑                                                   │
//! │    Bloom Filter (per SSTable) - ~10 bits/key               │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Usage
//!
//! ```no_run
//! use era_index::{LsmChunkIndex, IndexConfig};
//! use era_common::{ChunkHash, BlockLocation, VolumeId};
//! use std::path::Path;
//!
//! // Create index with default configuration
//! let index = LsmChunkIndex::open(Path::new("/path/to/index"))?;
//!
//! // Store a chunk location
//! let hash = ChunkHash::from_bytes([0u8; 32]);
//! let location = BlockLocation {
//!     volume_id: VolumeId::new(),
//!     slot_index: 0,
//!     physical_offset: 4096,
//!     encrypted_size: 1024,
//!     erasure_info: None,
//!     shard_offsets: None,
//!     shard_volumes: None,
//! };
//!
//! index.put(hash, location.clone())?;
//!
//! // Lookup a chunk
//! if let Some(loc) = index.get(&hash)? {
//!     assert_eq!(loc, location);
//! }
//! # Ok::<(), era_common::EraError>(())
//! ```

mod config;
mod error;
mod index;
mod metrics;

pub use config::{IndexConfig, IndexConfigBuilder};
pub use error::IndexError;
pub use index::LsmChunkIndex;
pub use metrics::IndexMetrics;

// Re-export for convenience
pub use era_common::{BlockLocation, ChunkHash};
