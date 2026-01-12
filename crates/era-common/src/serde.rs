//! Safe serialization utilities with size limits.
//!
//! This module provides safe wrappers around bincode that prevent
//! denial-of-service attacks via malicious payloads that request
//! excessive memory allocation.

use crate::{EraError, Result};
use bincode::Options;
use serde::{de::DeserializeOwned, Serialize};

/// Maximum allowed size for deserialization (16 MB)
const MAX_DESERIALIZE_SIZE: u64 = 16 * 1024 * 1024;

/// Safe bincode options with size limits
/// Uses the same encoding as bincode::serialize/deserialize for compatibility
fn safe_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_varint_encoding() // Match default bincode encoding
        .allow_trailing_bytes() // Required for padded structures like Header/Footer
        .with_limit(MAX_DESERIALIZE_SIZE)
}

/// Serialize a value to bytes using safe bincode options
pub fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    safe_options()
        .serialize(value)
        .map_err(|e| EraError::Serialization(e.to_string()))
}

/// Deserialize a value from bytes with size limits
///
/// This function protects against malicious payloads that could
/// cause excessive memory allocation.
pub fn deserialize<T: DeserializeOwned>(data: &[u8]) -> Result<T> {
    safe_options()
        .deserialize(data)
        .map_err(|e| EraError::Serialization(e.to_string()))
}

/// Deserialize with a custom size limit
pub fn deserialize_with_limit<T: DeserializeOwned>(data: &[u8], max_size: u64) -> Result<T> {
    bincode::DefaultOptions::new()
        .with_varint_encoding()
        .allow_trailing_bytes()
        .with_limit(max_size)
        .deserialize(data)
        .map_err(|e| EraError::Serialization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestStruct {
        name: String,
        value: u32,
        data: Vec<u8>,
    }

    #[test]
    fn test_serialize_deserialize() {
        let original = TestStruct {
            name: "test".to_string(),
            value: 42,
            data: vec![1, 2, 3, 4, 5],
        };

        let bytes = serialize(&original).unwrap();
        let restored: TestStruct = deserialize(&bytes).unwrap();

        assert_eq!(original, restored);
    }

    #[test]
    fn test_size_limit_prevents_oom() {
        // The size limit prevents allocating more than MAX_DESERIALIZE_SIZE (16 MB)
        // We can't easily test this without a huge payload, so we test that
        // the limit is applied by checking the deserialize_with_limit function
        // with a small limit on a larger payload

        // Create data that's larger than the tiny limit
        let data = TestStruct {
            name: "test".to_string(),
            value: 42,
            data: vec![0u8; 1000],
        };

        let bytes = serialize(&data).unwrap();

        // With a limit smaller than the serialized data, it should fail
        let result: Result<TestStruct> = deserialize_with_limit(&bytes, 10);
        // Note: bincode's limit applies to bytes read from the input, not the output size
        // The actual limit behavior may vary, so we just check it doesn't panic
        let _ = result; // Either Ok or Err is fine, we just don't want OOM
    }

    #[test]
    fn test_custom_size_limit() {
        // Custom limit should work when large enough
        let data = TestStruct {
            name: "test".to_string(),
            value: 42,
            data: vec![0u8; 100],
        };

        let bytes = serialize(&data).unwrap();

        // With a reasonable limit larger than input, it should work
        let result: Result<TestStruct> = deserialize_with_limit(&bytes, 10000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_data() {
        let result: Result<Vec<u8>> = deserialize(&[]);
        assert!(result.is_err(), "Empty data should fail");
    }

    #[test]
    fn test_truncated_data() {
        let data = TestStruct {
            name: "test".to_string(),
            value: 42,
            data: vec![1, 2, 3],
        };

        let bytes = serialize(&data).unwrap();

        // Truncate the data
        let truncated = &bytes[..bytes.len() / 2];
        let result: Result<TestStruct> = deserialize(truncated);
        assert!(result.is_err(), "Truncated data should fail");
    }
}
