//! # ERA Volume
//!
//! Volume management for the ERA archive system.
//!
//! This crate provides the L1 (Volume Management) layer implementation.

/// Maximum allowed shard/block size (16MB) - Anti-DoS protection.
/// Any length field exceeding this limit is treated as corruption.
/// This constant is enforced by BOTH the Reader AND the Writer to ensure
/// symmetric validation (archives that can be written can always be read).
pub const MAX_SHARD_SIZE: usize = 16 * 1024 * 1024;

pub mod footer;
pub mod header;
mod multi_volume;
mod reader;
mod volume_pool;
mod writer;
mod writer_async;

pub use footer::{Footer, FOOTER_MAGIC, FOOTER_SIZE};
pub use header::{RecipientSlot, RecipientType, SuperHeader, DATA_REGION_START, HEADER_SIZE};
pub use multi_volume::{
    MultiVolumeConfig, MultiVolumeReader, MultiVolumeStats, MultiVolumeWriter,
    DEFAULT_MAX_VOLUME_SIZE, MIN_VOLUME_SIZE,
};
pub use reader::VolumeReader;
pub use volume_pool::{VolumePool, VolumePoolConfig, VolumePoolStats};
pub use writer::VolumeWriter;
pub use writer_async::AsyncVolumeWriter;
