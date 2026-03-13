use era_common::{BlockId, EraError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompactRegionKind {
    StripedData,
    ReplicatedTypedBlock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactDirectoryEntry {
    pub block_id: BlockId,
    pub block_type: u16,
    pub region_kind: CompactRegionKind,
    pub offset: u64,
    pub span: u64,
    pub stripe_ordinal: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CompactDirectory {
    entries: Vec<CompactDirectoryEntry>,
}

impl CompactDirectory {
    pub fn new(entries: Vec<CompactDirectoryEntry>) -> Result<Self> {
        let mut seen = HashSet::with_capacity(entries.len());
        for entry in &entries {
            if !seen.insert(entry.block_id.sequence()) {
                return Err(EraError::InvalidFormat(format!(
                    "duplicate compact directory block_id {}",
                    entry.block_id.sequence()
                )));
            }
            if entry.span == 0 {
                return Err(EraError::InvalidFormat(
                    "compact directory span must be > 0".into(),
                ));
            }
            if entry.offset.checked_add(entry.span).is_none() {
                return Err(EraError::InvalidFormat(
                    "compact directory offset+span overflow".into(),
                ));
            }
        }

        let mut spans: Vec<(u64, u64)> = entries
            .iter()
            .map(|e| (e.offset, e.offset + e.span))
            .collect();
        spans.sort_unstable_by_key(|s| s.0);
        for window in spans.windows(2) {
            if window[0].1 > window[1].0 {
                return Err(EraError::InvalidFormat(
                    "compact directory span overlap".into(),
                ));
            }
        }

        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[CompactDirectoryEntry] {
        &self.entries
    }
}
