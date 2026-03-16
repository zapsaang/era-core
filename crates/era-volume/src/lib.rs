//! # ERA Volume
//!
//! Volume management for the ERA archive system.
//!
//! This crate provides the L1 (Volume Management) layer implementation.
//! All I/O operations are async (non-blocking).

#![forbid(unsafe_code)]
#[cfg(not(target_pointer_width = "64"))]
compile_error!("ERA requires a 64-bit platform");

/// Maximum allowed shard/block size (16MB) - Anti-DoS protection.
/// Any length field exceeding this limit is treated as corruption.
/// This constant is enforced by BOTH the Reader AND the Writer to ensure
/// symmetric validation (archives that can be written can always be read).
pub const MAX_SHARD_SIZE: usize = 16 * 1024 * 1024;

/// Maximum consecutive scan misses before switching to coarse stepping.
/// During `scan_for_typed_blocks`, if this many consecutive 1-byte advances
/// occur without finding a valid block or shard header, the scanner switches
/// to `BlockHeader::SIZE`-step advances to prevent CPU exhaustion on volumes
/// filled with random/encrypted data. 64 KiB of consecutive misses allows
/// recovery from localized corruption while preventing O(volume_size) worst case.
pub const MAX_CONSECUTIVE_SCAN_MISSES: u64 = 64 * 1024;

/// Maximum number of block locations returned by a single volume scan.
/// Prevents unbounded memory growth when scanning volumes with many small blocks.
/// At 16 bytes minimum per block, a 64 GiB volume could theoretically contain
/// ~4 billion blocks; this cap keeps the results vector bounded.
pub const MAX_SCAN_RESULTS: usize = 1_000_000;

mod distribution;
mod footer;
mod header;
mod multi_volume;
mod reader;
mod volume_pool;
mod writer;

pub use distribution::{
    canonical_erasure_volume_count_error, validate_canonical_erasure_volume_count,
    validate_erasure_volume_count, DistributionCalculator, DistributionConfigExt,
    VolumePoolStatusExt,
};
pub use footer::{
    Footer, FooterBuilder, BACKUP_FOOTER_GAP, FOOTER_MAGIC, FOOTER_SIZE, FOOTER_VERSION,
};
pub use header::{
    AccessPolicy, EncryptedVolumeKey, KeyWrapAlgorithm, RecipientSlot, RecipientType, SuperHeader,
    DATA_REGION_START, HEADER_SIZE, HEADER_VERSION, MAGIC, MAX_RECIPIENTS,
};
pub use multi_volume::{
    MultiVolumeConfig, MultiVolumeReader, MultiVolumeStats, MultiVolumeWriter,
    DEFAULT_MAX_VOLUME_SIZE, MIN_VOLUME_SIZE,
};
pub use reader::VolumeReader;
pub use volume_pool::{VolumePool, VolumePoolConfig, VolumePoolStats};
pub use writer::VolumeWriter;

use era_common::Result;
use std::path::{Path, PathBuf};

/// Per-volume structural overhead: footer + backup header + block/shard header space.
/// Footer (128) + HEADER_SIZE (4096) + BlockHeader (16) + ShardHeader (8) = 4248 bytes
pub const PER_VOLUME_OVERHEAD: u64 = 4248;
/// Generate volume path for a given base path and sequence number.
///
/// Sequence 0 → `base_path.era`
/// Sequence N → `base_path.era.NNN`
pub fn volume_path(base_path: &Path, sequence: u16) -> PathBuf {
    if sequence == 0 {
        base_path.with_extension("era")
    } else {
        let ext = format!("era.{:03}", sequence);
        base_path.with_extension(ext)
    }
}

/// Extract filename from a path as a string slice.
///
/// # Errors
/// Returns `InvalidConfig` if the path has no filename or if the filename is not valid UTF-8.
pub(crate) fn extract_filename(path: &Path) -> Result<&str> {
    path.file_name()
        .ok_or_else(|| {
            era_common::EraError::InvalidConfig(format!("path has no filename: {:?}", path))
        })?
        .to_str()
        .ok_or_else(|| {
            era_common::EraError::InvalidConfig(format!("path is not valid UTF-8: {:?}", path))
        })
}
