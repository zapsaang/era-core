//! # ERA Common
//!
//! Common types, error handling, and utilities for the ERA archive system.

pub mod config;
pub mod error;
pub mod serde;
pub mod types;

pub use config::*;
pub use error::{EraError, Result};
pub use types::*;

// Re-export safe serialization functions
pub use crate::serde::{deserialize, deserialize_with_limit, serialize};
