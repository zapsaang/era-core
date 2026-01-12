//! # ERA Volume
//!
//! Volume management for the ERA archive system.
//!
//! This crate provides the L1 (Volume Management) layer implementation.

mod footer;
mod header;
mod reader;
mod writer;

pub use footer::Footer;
pub use header::{CryptoAnchor, SuperHeader};
pub use reader::VolumeReader;
pub use writer::VolumeWriter;
