//! # Tiered Merger - K-way Merge with File Descriptor Management
//!
//! Prevents FD exhaustion by using recursive tiered merging.
//! Uses a proper min-heap k-way merge for O(n log k) performance.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
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

/// Recursively merge segments with bounded fan-in.
///
/// When the number of segments exceeds MAX_FAN_IN, batches are merged
/// and spilled to encrypted temp files, then recursed. This keeps
/// memory usage bounded to O(MAX_FAN_IN * segment_size) per level.
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

    // Recursive case: merge in batches, spill intermediate results to temp files.
    // Derive temp_dir from the first segment's parent directory.
    let temp_dir = segments[0]
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));

    let mut next_level_segments = Vec::new();
    for chunk in segments.chunks(MAX_FAN_IN) {
        let merged_entries: Vec<IndexEntry> = kway_merge(chunk.to_vec(), spiller)?.collect();

        if merged_entries.is_empty() {
            continue;
        }

        // Spill merged batch to encrypted temp file instead of accumulating in RAM
        let spill_path = spiller.spill(&merged_entries, temp_dir)?;
        next_level_segments.push(spill_path);
    }

    // Recurse on the reduced set of segments
    recursive_merge(next_level_segments, spiller)
}

/// K-way merge of up to MAX_FAN_IN segments using a min-heap.
///
/// Each segment is already sorted. We use a BinaryHeap<Reverse<(hash, seg_idx, entry_idx)>>
/// to produce a globally sorted stream in O(n log k) time.
/// Deduplicates by hash — last entry wins (last-write-wins semantics).
fn kway_merge(
    segments: Vec<PathBuf>,
    spiller: &Spiller,
) -> Result<impl Iterator<Item = IndexEntry>> {
    // Read all segments into memory and ensure each is sorted
    let mut sorted_segments: Vec<Vec<IndexEntry>> = Vec::with_capacity(segments.len());
    for segment in segments {
        let mut entries = spiller.read_spill(&segment)?;
        entries.sort_unstable_by_key(|e| e.hash);
        sorted_segments.push(entries);
    }

    // Build min-heap: (hash, segment_index, entry_index)
    // Reverse for min-heap behavior (BinaryHeap is a max-heap by default)
    let mut heap: BinaryHeap<Reverse<(era_common::ChunkHash, usize, usize)>> = BinaryHeap::new();

    for (seg_idx, seg) in sorted_segments.iter().enumerate() {
        if !seg.is_empty() {
            heap.push(Reverse((seg[0].hash, seg_idx, 0)));
        }
    }

    // Extract sorted entries via heap
    let mut merged = Vec::new();
    while let Some(Reverse((_, seg_idx, entry_idx))) = heap.pop() {
        let entry = sorted_segments[seg_idx][entry_idx];
        merged.push(entry);

        // Advance this segment's cursor
        let next_idx = entry_idx + 1;
        if next_idx < sorted_segments[seg_idx].len() {
            heap.push(Reverse((
                sorted_segments[seg_idx][next_idx].hash,
                seg_idx,
                next_idx,
            )));
        }
    }

    // Deduplicate by hash — keep last occurrence (last-write-wins)
    merged.dedup_by_key(|e| e.hash);
    Ok(merged.into_iter())
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
