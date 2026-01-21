//! # Tiered Merger - K-way Merge with File Descriptor Management
//!
//! Prevents FD exhaustion by using recursive tiered merging.

use std::path::PathBuf;

use era_common::Result;

use super::{IndexEntry, Spiller};

/// Maximum fan-in for K-way merge (prevents FD exhaustion)
const MAX_FAN_IN: usize = 64;

/// A K-way merger that produces a sorted stream of IndexEntries
pub struct TieredMerger {
    /// Iterator over merged entries
    iter: Box<dyn Iterator<Item = IndexEntry>>,
}

impl TieredMerger {
    /// Create a new tiered merger from spill segments
    pub fn new(segments: Vec<PathBuf>, spiller: &Spiller) -> Result<Self> {
        let iter = recursive_merge(segments, spiller)?;
        Ok(Self { iter })
    }
}

impl Iterator for TieredMerger {
    type Item = IndexEntry;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

/// Recursively merge segments with bounded fan-in
fn recursive_merge(
    segments: Vec<PathBuf>,
    spiller: &Spiller,
) -> Result<Box<dyn Iterator<Item = IndexEntry>>> {
    if segments.is_empty() {
        return Ok(Box::new(std::iter::empty()));
    }

    if segments.len() == 1 {
        // Base case: single segment
        let entries = spiller.read_spill(&segments[0])?;
        return Ok(Box::new(entries.into_iter()));
    }

    if segments.len() <= MAX_FAN_IN {
        // Base case: direct K-way merge
        return Ok(Box::new(kway_merge(segments, spiller)?));
    }

    // Recursive case: merge in batches
    let mut next_level = Vec::new();
    for chunk in segments.chunks(MAX_FAN_IN) {
        let merged_iter = kway_merge(chunk.to_vec(), spiller)?;
        let merged_entries: Vec<IndexEntry> = merged_iter.collect();

        // For this temporary implementation, we'll just add to next level
        // In production, we'd spill to temp files
        next_level.extend(merged_entries);
    }

    // Sort the combined entries
    next_level.sort_unstable_by_key(|e| e.hash);
    Ok(Box::new(next_level.into_iter()))
}

/// K-way merge of up to MAX_FAN_IN segments
fn kway_merge(
    segments: Vec<PathBuf>,
    spiller: &Spiller,
) -> Result<impl Iterator<Item = IndexEntry>> {
    // Read all segments into memory
    let mut all_entries = Vec::new();
    for segment in segments {
        let entries = spiller.read_spill(&segment)?;
        all_entries.extend(entries);
    }

    // Sort merged entries
    all_entries.sort_unstable_by_key(|e| e.hash);
    Ok(all_entries.into_iter())
}

#[cfg(test)]
mod tests {
    use super::*;
    use era_common::{BlockId, ChunkHash, VolumeId};
    use tempfile::TempDir;

    fn test_hash(value: u64) -> ChunkHash {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        ChunkHash::from_bytes(bytes)
    }

    #[test]
    fn test_kway_merge() {
        let temp_dir = TempDir::new().unwrap();
        let spiller = Spiller::new();

        // Create 5 sorted spill files
        let mut segments = Vec::new();
        for seg_id in 0..5 {
            let entries: Vec<IndexEntry> = (0..20)
                .map(|i| {
                    let value = (seg_id * 100 + i * 5) as u64;
                    IndexEntry::new(
                        test_hash(value),
                        VolumeId::new(),
                        BlockId::new(value / 100),
                        (value % 100) as u32 * 1024,
                        1024,
                    )
                })
                .collect();

            let path = spiller.spill(&entries, temp_dir.path()).unwrap();
            segments.push(path);
        }

        // Merge
        let merger = TieredMerger::new(segments, &spiller).unwrap();
        let merged: Vec<IndexEntry> = merger.collect();

        // Verify sorted and all present
        assert_eq!(merged.len(), 100);
        for i in 1..merged.len() {
            assert!(merged[i - 1].hash <= merged[i].hash);
        }
    }
}
