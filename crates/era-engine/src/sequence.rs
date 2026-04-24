//! Finalize sequence tracking for replay attack prevention.
//!
//! In v8.2, each successful finalize increments a monotonic sequence number
//! stored in ArchiveManifest. When loading an archive, the reader selects
//! the Manifest copy with the highest finalize_sequence across all volumes.

use era_common::ArchiveManifest;

/// Trait for types that can extract a sequence number for redundancy selection.
///
/// Implement this for ArchiveManifest (and potentially other future types)
/// to enable generic manifest loading with redundancy resolution.
pub trait SequenceSelector {
    /// Returns the sequence number for redundancy selection.
    /// Higher values indicate newer versions.
    fn selection_sequence(&self) -> u64;
}

impl SequenceSelector for ArchiveManifest {
    fn selection_sequence(&self) -> u64 {
        self.sequence_for_selection()
    }
}

/// Default starting sequence for a new archive.
pub const INITIAL_FINALIZE_SEQUENCE: u64 = 1;

/// Compute the next finalize sequence.
///
/// # Errors
/// Returns `EraError::InvalidConfig` if sequence would overflow u64.
pub fn next_finalize_sequence(current: u64) -> era_common::Result<u64> {
    current
        .checked_add(1)
        .ok_or_else(|| era_common::EraError::InvalidConfig(
            "finalize_sequence overflow: u64 exhausted".into()
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_sequence_is_one() {
        assert_eq!(INITIAL_FINALIZE_SEQUENCE, 1);
    }

    #[test]
    fn next_sequence_increments() {
        assert_eq!(next_finalize_sequence(1).unwrap(), 2);
        assert_eq!(next_finalize_sequence(100).unwrap(), 101);
        assert_eq!(next_finalize_sequence(u64::MAX - 1).unwrap(), u64::MAX);
    }

    #[test]
    fn next_sequence_overflow_returns_err() {
        let result = next_finalize_sequence(u64::MAX);
        assert!(result.is_err());
    }

    #[test]
    fn manifest_implements_sequence_selector() {
        let m = ArchiveManifest::new(1, 42, 10, [0; 32], [0; 32]);
        assert_eq!(m.selection_sequence(), 42);
    }

    #[test]
    fn sequence_selector_trait_object() {
        let m = ArchiveManifest::new(1, 99, 10, [0; 32], [0; 32]);
        let selector: &dyn SequenceSelector = &m;
        assert_eq!(selector.selection_sequence(), 99);
    }
}
