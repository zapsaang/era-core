//! # ERA Packing
//!
//! MacroBlock packing for the ERA archive system.
//!
//! This crate provides the L3 (Transformation & Packing) layer implementation.
//! For MVP, we use a simplified fixed-size packing strategy.
//!
//! ## Session-Aware Builders (ERA v8.1)
//!
//! For enhanced security with per-block key derivation, use `SessionBlockBuilder`
//! and `SessionBlockUnpacker`. These implement the HKDF "Onion Model" where each
//! block is encrypted with a unique key derived from the volume key.

mod builder;
mod erasure_builder;
mod erasure_unpacker;
mod session_builder;
mod unpacker;

pub use builder::MacroBlockBuilder;
pub use erasure_builder::ErasureBlockBuilder;
pub use erasure_unpacker::ErasureBlockUnpacker;
pub use session_builder::{SessionBlockBuilder, SessionBlockUnpacker};
pub use unpacker::{MacroBlockUnpacker, UnpackedBlock};
