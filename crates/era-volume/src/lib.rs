//! # ERA Volume
//!
//! Volume management for the ERA archive system.
//!
//! This crate provides the L1 (Volume Management) layer implementation.
//! All I/O operations are async (non-blocking).

/// Maximum allowed shard/block size (16MB) - Anti-DoS protection.
/// Any length field exceeding this limit is treated as corruption.
/// This constant is enforced by BOTH the Reader AND the Writer to ensure
/// symmetric validation (archives that can be written can always be read).
pub const MAX_SHARD_SIZE: usize = 16 * 1024 * 1024;

mod distribution;
pub mod footer;
pub mod header;
mod multi_volume;
mod reader;
mod volume_pool;
mod writer;

pub use distribution::{DistributionCalculator, DistributionConfigExt, VolumePoolStatusExt};
pub use footer::{Footer, FOOTER_MAGIC, FOOTER_SIZE};
pub use header::{
    AccessPolicy, EncryptedVolumeKey, KeyWrapAlgorithm, RecipientSlot, RecipientType, SuperHeader,
    DATA_REGION_START, HEADER_SIZE,
};
pub use multi_volume::{
    MultiVolumeConfig, MultiVolumeReader, MultiVolumeStats, MultiVolumeWriter,
    DEFAULT_MAX_VOLUME_SIZE, MIN_VOLUME_SIZE,
};
pub use reader::VolumeReader;
pub use volume_pool::{VolumePool, VolumePoolConfig, VolumePoolStats};
pub use writer::VolumeWriter;
