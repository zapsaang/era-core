//! # ERA Packing
//!
//! MacroBlock packing for the ERA archive system.
//!
//! This crate provides the L3 (Transformation & Packing) layer implementation,
//! featuring k-Bounded Best-Fit packing via `StagingPool` for efficient MacroBlock aggregation.
//!
//! ## Session-Aware Builders
//!
//! For enhanced security with per-block key derivation, use `SessionBlockBuilder`
//! and `SessionBlockUnpacker`. These implement the HKDF "Onion Model" where each
//! block is encrypted with a unique key derived from the volume key.
//!
//! ## Session-Aware Erasure Builders
//!
//! For combined security and redundancy, use `SessionErasureBlockBuilder` which
//! provides both per-block key derivation AND Reed-Solomon erasure coding.

mod block_codec;
mod builder;
mod erasure_builder;
mod erasure_unpacker;
mod integration_performance_tests;
mod packed_chunk;
mod resilient_aead;
mod session_builder;
mod session_erasure_builder;
mod staging_pool;
mod stripe;
mod unpacker;

#[cfg(test)]
mod test_helpers;

pub use block_codec::{
    create_compressor, decrypt_and_decompress, extract_all_chunks, extract_chunk_by_hash,
};
pub use builder::MacroBlockBuilder;
pub use erasure_builder::ErasureBlockBuilder;
pub use erasure_unpacker::ErasureBlockUnpacker;
pub use packed_chunk::{pack_files, unpack_file, PackedChunk, PackedEntry, PackedHeader};
pub use resilient_aead::{AeadRecoveryResult, ResilientBlockUnpacker};
pub use session_builder::{SessionBlockBuilder, SessionBlockUnpacker};
pub use session_erasure_builder::{SessionErasureBlockBuilder, SessionErasureBlockUnpacker};
pub use staging_pool::{PackedBlock, StagingPool, StagingPoolStats};
pub use stripe::{BlockMeta, Stripe, StripeBuffer};
pub use unpacker::{MacroBlockUnpacker, UnpackedBlock};
