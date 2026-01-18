//! # ERA Common
//!
//! Common types, error handling, and utilities for the ERA archive system.

pub mod config;
pub mod conversion;
pub mod error;
pub mod serde;
pub mod types;

// Include generated Protobuf modules
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/era.common.rs"));
    pub mod test {
        include!(concat!(env!("OUT_DIR"), "/era.test.rs"));
    }
}

pub use config::*;
pub use error::{EraError, Result};
pub use types::*;

// Re-export safe serialization functions
pub use crate::serde::{deserialize_proto, deserialize_proto_with_limit, serialize_proto};
