//! # ERA Codec
//!
//! Compression and encoding utilities for the ERA archive system.

mod compression;
mod erasure;

pub use compression::{compress, decompress, Compressor, NoCompressor, ZstdCompressor};
pub use erasure::{
    ErasureCoder, ErasureConfig, DEFAULT_DATA_SHARDS, DEFAULT_PARITY_SHARDS, MAX_TOTAL_SHARDS,
};
