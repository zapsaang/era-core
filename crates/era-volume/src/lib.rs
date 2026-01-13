//! # ERA Volume
//!
//! Volume management for the ERA archive system.
//!
//! This crate provides the L1 (Volume Management) layer implementation.

mod footer;
mod header;
mod multi_volume;
mod reader;
mod writer;

pub use footer::{Footer, FOOTER_SIZE};
pub use header::{CryptoAnchor, SuperHeader, HEADER_SIZE};
pub use multi_volume::{
    MultiVolumeConfig, MultiVolumeReader, MultiVolumeStats, MultiVolumeWriter,
    DEFAULT_MAX_VOLUME_SIZE, MIN_VOLUME_SIZE,
};
pub use reader::VolumeReader;
pub use writer::VolumeWriter;
