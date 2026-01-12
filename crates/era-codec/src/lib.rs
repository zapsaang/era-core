//! # ERA Codec
//!
//! Compression and encoding utilities for the ERA archive system.

mod compression;

pub use compression::{compress, decompress, Compressor, ZstdCompressor};
