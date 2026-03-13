pub mod bundle_reader;
pub mod bundle_writer;
pub mod directory;
pub mod footer;
pub mod header;
pub mod reader;
pub mod set;
pub mod stripe;
pub mod writer;

pub const COMPACT_DATA_BLOCK_CEILING: u64 = u64::MAX / 2;
pub const COMPACT_PADDING_BASE: u64 = COMPACT_DATA_BLOCK_CEILING + 1;
pub const COMPACT_CATALOG_BLOCK_ID: u64 = u64::MAX / 2 + u64::MAX / 4;
pub const COMPACT_PARITY_BASE: u64 = u64::MAX;

pub const MAX_COMPACT_FOOTER_SIZE: u64 = 1024 * 1024;
pub const MAX_COMPACT_DIRECTORY_SIZE: usize = 256 * 1024 * 1024;
pub const MAX_COMPACT_SHARD_PAYLOAD: usize = 1024 * 1024 * 1024;
pub const MAX_COMPACT_REPLICATED_BLOCK: usize = 1024 * 1024 * 1024;
pub const MAX_COMPACT_HEADER_SIZE: usize = 64 * 1024;
pub const MAX_COMPACT_RECIPIENTS: usize = 256;

pub use bundle_reader::CompactBundleReader;
pub use bundle_writer::CompactBundleWriter;
pub use directory::{CompactDirectory, CompactDirectoryEntry, CompactRegionKind};
pub use footer::{CompactVolumeFooter, COMPACT_FOOTER_MAGIC, COMPACT_FOOTER_VERSION};
pub use header::{
    CompactSuperHeader, COMPACT_HEADER_MAGIC, COMPACT_HEADER_VERSION, SOURCE_FORMAT_ERA,
};
pub use reader::{is_compact_bundle_path, reject_legacy_era_magic, CompactVolumeReader};
pub use stripe::{CompactShardInput, CompactShardRecordHeader};
pub use writer::{prepare_bundle_staging, CompactVolumeWriter};
