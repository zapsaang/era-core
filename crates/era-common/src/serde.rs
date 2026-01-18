//! Safe serialization utilities with size limits.
//!
//! This module provides safe wrappers around prost (Protocol Buffers).

use crate::{EraError, Result};
use prost::Message;

/// Maximum allowed size for deserialization (16 MB)
const MAX_DESERIALIZE_SIZE: usize = 16 * 1024 * 1024;

/// Serialize a Protobuf message
pub fn serialize_proto<M: Message>(msg: &M) -> Result<Vec<u8>> {
    Ok(msg.encode_to_vec())
}

/// Deserialize a Protobuf message with size limits
pub fn deserialize_proto<M: Message + Default>(data: &[u8]) -> Result<M> {
    if data.len() > MAX_DESERIALIZE_SIZE {
        return Err(EraError::Deserialization(format!(
            "Data size {} exceeds maximum allowed size {}",
            data.len(),
            MAX_DESERIALIZE_SIZE
        )));
    }

    M::decode(data).map_err(|e| EraError::Deserialization(e.to_string()))
}

/// Deserialize with a custom size limit
pub fn deserialize_proto_with_limit<M: Message + Default>(data: &[u8], max_size: u64) -> Result<M> {
    let max_size = max_size as usize;
    if data.len() > max_size {
        return Err(EraError::Deserialization(format!(
            "Data size {} exceeds maximum allowed size {}",
            data.len(),
            max_size
        )));
    }

    M::decode(data).map_err(|e| EraError::Deserialization(e.to_string()))
}
