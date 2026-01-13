//! # ERA Packing
//!
//! MacroBlock packing for the ERA archive system.
//!
//! This crate provides the L3 (Transformation & Packing) layer implementation.
//! For MVP, we use a simplified fixed-size packing strategy.

mod builder;
mod erasure_builder;
mod erasure_unpacker;
mod unpacker;

pub use builder::MacroBlockBuilder;
pub use erasure_builder::ErasureBlockBuilder;
pub use erasure_unpacker::ErasureBlockUnpacker;
pub use unpacker::MacroBlockUnpacker;
