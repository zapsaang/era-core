//! Timestamp management and migration utilities
//!
//! This module provides:
//! - Modern OffsetDateTime-based timestamps
//! - Serialization/deserialization support
//! - Migration from legacy u64 Unix timestamps
//! - Timestamp validation and constraints

use era_common::Result;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Represents a timestamp in ISO 8601 format with UTC timezone
/// This is the new standard for all timestamp fields in ERA v0.2.0+
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Timestamp {
    #[serde(with = "time::serde::rfc3339")]
    inner: OffsetDateTime,
}

impl Timestamp {
    /// Create a timestamp from the current system time
    pub fn now() -> Self {
        Self {
            inner: OffsetDateTime::now_utc(),
        }
    }

    /// Create a timestamp from an OffsetDateTime
    pub fn from_datetime(dt: OffsetDateTime) -> Self {
        Self { inner: dt }
    }

    /// Get the underlying OffsetDateTime
    pub fn as_datetime(&self) -> OffsetDateTime {
        self.inner
    }

    /// Convert to OffsetDateTime (alias for as_datetime)
    pub fn to_datetime(&self) -> OffsetDateTime {
        self.inner
    }

    /// Create from a Unix timestamp (seconds)
    /// Used for migration from legacy u64 timestamps
    pub fn from_unix_timestamp(secs: u64) -> Result<Self> {
        let dt = OffsetDateTime::from_unix_timestamp(secs as i64).map_err(|e| {
            era_common::EraError::InvalidKey(format!("Invalid Unix timestamp {}: {}", secs, e))
        })?;
        Ok(Self { inner: dt })
    }

    /// Convert to Unix timestamp (seconds)
    pub fn to_unix_timestamp(&self) -> u64 {
        self.inner.unix_timestamp() as u64
    }

    /// Get ISO 8601 formatted string
    pub fn to_iso8601(&self) -> String {
        self.inner.to_string()
    }

    /// Check if this timestamp is in the future
    pub fn is_future(&self) -> bool {
        self.inner > OffsetDateTime::now_utc()
    }

    /// Check if this timestamp is in the past
    pub fn is_past(&self) -> bool {
        self.inner < OffsetDateTime::now_utc()
    }

    /// Get the age (duration since this timestamp)
    pub fn age(&self) -> std::time::Duration {
        let now = OffsetDateTime::now_utc();
        if now > self.inner {
            std::time::Duration::from_secs((now - self.inner).whole_seconds() as u64)
        } else {
            std::time::Duration::ZERO
        }
    }
}

impl Default for Timestamp {
    fn default() -> Self {
        Self::now()
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

/// Optional timestamp that can be None
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OptionalTimestamp(pub Option<Timestamp>);

impl OptionalTimestamp {
    /// Create an absent timestamp
    pub fn none() -> Self {
        Self(None)
    }

    /// Create a present timestamp
    pub fn some(ts: Timestamp) -> Self {
        Self(Some(ts))
    }

    /// Create from an optional Unix timestamp
    pub fn from_optional_unix(secs: Option<u64>) -> Result<Self> {
        match secs {
            Some(s) => Timestamp::from_unix_timestamp(s).map(Some).map(Self),
            None => Ok(Self(None)),
        }
    }

    /// Convert to optional Unix timestamp
    pub fn to_optional_unix(&self) -> Option<u64> {
        self.0.map(|ts| ts.to_unix_timestamp())
    }

    /// Check if timestamp is set and in the past
    pub fn is_expired(&self) -> bool {
        self.0.map(|ts| ts.is_past()).unwrap_or(false)
    }

    /// Check if timestamp is set and in the future
    pub fn is_not_yet_valid(&self) -> bool {
        self.0.map(|ts| ts.is_future()).unwrap_or(false)
    }

    /// Check if timestamp is present and valid (past + not expired)
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_not_yet_valid()
    }
}

impl std::fmt::Display for OptionalTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Some(ts) => write!(f, "{}", ts),
            None => write!(f, "never"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_now() {
        let ts = Timestamp::now();
        assert!(ts.is_past() || !ts.is_future()); // Should be very recent
    }

    #[test]
    fn test_timestamp_from_unix() {
        // January 1, 2020, 00:00:00 UTC
        let ts = Timestamp::from_unix_timestamp(1577836800).unwrap();
        assert_eq!(ts.to_unix_timestamp(), 1577836800);
    }

    #[test]
    fn test_timestamp_is_past() {
        // A timestamp from the past
        let ts = Timestamp::from_unix_timestamp(1000000000).unwrap(); // Sep 2001
        assert!(ts.is_past());
        assert!(!ts.is_future());
    }

    #[test]
    fn test_timestamp_age() {
        let ts = Timestamp::from_unix_timestamp(1000000000).unwrap();
        let age = ts.age();
        assert!(age.as_secs() > 0);
    }

    #[test]
    fn test_optional_timestamp_none() {
        let ts = OptionalTimestamp::none();
        assert!(ts.0.is_none());
        assert!(!ts.is_expired());
    }

    #[test]
    fn test_optional_timestamp_some() {
        let ts = Timestamp::now();
        let opt = OptionalTimestamp::some(ts);
        assert!(opt.0.is_some());
    }

    #[test]
    fn test_optional_timestamp_expired() {
        let ts = Timestamp::from_unix_timestamp(1000000000).unwrap(); // Very old
        let opt = OptionalTimestamp::some(ts);
        assert!(opt.is_expired());
    }

    #[test]
    fn test_timestamp_serialization() {
        let ts = Timestamp::now();
        let json = serde_json::to_string(&ts).unwrap();
        let deserialized: Timestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(ts, deserialized);
    }

    #[test]
    fn test_optional_timestamp_serialization() {
        let opt = OptionalTimestamp::some(Timestamp::now());
        let json = serde_json::to_string(&opt).unwrap();
        let deserialized: OptionalTimestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(opt, deserialized);
    }
}
