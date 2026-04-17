//! Small file packing module.
//!
//! Buffers small files and packs them together to improve storage efficiency.
//! This reduces overhead from block headers and improves deduplication for
//! directories with many small files.

use era_common::ChunkHash;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Entry for a small file waiting to be packed
#[derive(Debug)]
pub struct SmallFileEntry {
    /// Relative path for storage in the archive
    pub path: PathBuf,
    /// File contents
    pub data: Vec<u8>,
    /// Content hash for deduplication
    pub hash: ChunkHash,
    /// POSIX permissions
    pub permissions: u32,
    /// Modification time (Unix seconds)
    pub mtime: Option<u64>,
    /// Extended attributes
    pub xattrs: BTreeMap<String, Vec<u8>>,
}

/// Buffers small files for efficient packing.
///
/// Files smaller than `threshold` are buffered until either:
/// - Total buffered size reaches `pack_size_threshold`
/// - Number of buffered files reaches `max_buffered_files`
///
/// At that point, `push()` returns the buffered entries for flushing.
#[derive(Debug)]
pub struct SmallFilePacker {
    buffer: Vec<SmallFileEntry>,
    total_size: u64,
    threshold: u64,
    pack_size_threshold: u64,
    max_buffered_files: usize,
}

impl SmallFilePacker {
    /// Create a new SmallFilePacker.
    ///
    /// # Arguments
    /// * `threshold` - Files smaller than this are buffered (0 disables packing)
    /// * `pack_size` - Flush when total buffered size reaches this
    /// * `max_files` - Flush when this many files are buffered
    pub fn new(threshold: u64, pack_size: u64, max_files: usize) -> Self {
        Self {
            buffer: Vec::new(),
            total_size: 0,
            threshold,
            pack_size_threshold: pack_size,
            max_buffered_files: max_files,
        }
    }

    /// Create a disabled packer (no buffering).
    pub fn disabled() -> Self {
        Self::new(0, 0, 0)
    }

    /// Check if a file should be buffered based on its size.
    ///
    /// Returns true if the file is small enough to buffer and packing is enabled.
    /// Empty files (size == 0) are never buffered.
    pub fn should_buffer(&self, size: u64) -> bool {
        self.threshold > 0 && size > 0 && size < self.threshold
    }

    /// Add a small file entry to the buffer.
    ///
    /// Returns `Some(entries)` if the buffer should be flushed after this push,
    /// or `None` if more files can be buffered.
    pub fn push(&mut self, entry: SmallFileEntry) -> Option<Vec<SmallFileEntry>> {
        let file_size = entry.data.len() as u64;

        // Validate entry meets buffering criteria (V2-QUAL-12)
        if !self.should_buffer(file_size) {
            // Entry doesn't meet buffer criteria — return it for immediate processing
            // by wrapping in a single-entry flush
            self.buffer.push(entry);
            return Some(self.take());
        }

        self.buffer.push(entry);
        self.total_size += file_size;

        if self.should_flush() {
            Some(self.take())
        } else {
            None
        }
    }

    /// Check if the buffer should be flushed.
    fn should_flush(&self) -> bool {
        self.total_size >= self.pack_size_threshold || self.buffer.len() >= self.max_buffered_files
    }

    /// Take all buffered entries, resetting the buffer.
    ///
    /// Use this to flush remaining entries at finalization.
    pub fn take(&mut self) -> Vec<SmallFileEntry> {
        self.total_size = 0;
        std::mem::take(&mut self.buffer)
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Get the number of buffered files.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Get the total size of buffered data.
    #[allow(dead_code)]
    pub fn total_size(&self) -> u64 {
        self.total_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(path: &str, size: usize) -> SmallFileEntry {
        SmallFileEntry {
            path: PathBuf::from(path),
            data: vec![0u8; size],
            hash: ChunkHash([0u8; 32]),
            permissions: 0o644,
            mtime: None,
            xattrs: BTreeMap::new(),
        }
    }

    #[test]
    fn test_disabled_packer() {
        let packer = SmallFilePacker::disabled();
        assert!(!packer.should_buffer(100));
        assert!(!packer.should_buffer(0));
    }

    #[test]
    fn test_should_buffer() {
        let packer = SmallFilePacker::new(1024, 4096, 10);

        // Files under threshold should be buffered
        assert!(packer.should_buffer(100));
        assert!(packer.should_buffer(1023));

        // Files at or above threshold should not be buffered
        assert!(!packer.should_buffer(1024));
        assert!(!packer.should_buffer(2000));

        // Empty files are never buffered
        assert!(!packer.should_buffer(0));
    }

    #[test]
    fn test_push_no_flush() {
        let mut packer = SmallFilePacker::new(1024, 4096, 10);

        let result = packer.push(make_entry("file1.txt", 100));
        assert!(result.is_none());
        assert_eq!(packer.len(), 1);
        assert_eq!(packer.total_size(), 100);
    }

    #[test]
    fn test_flush_on_size_threshold() {
        let mut packer = SmallFilePacker::new(1024, 200, 10);

        // First push doesn't trigger flush
        assert!(packer.push(make_entry("file1.txt", 100)).is_none());

        // Second push triggers flush (total = 200)
        let result = packer.push(make_entry("file2.txt", 100));
        assert!(result.is_some());
        let entries = result.unwrap();
        assert_eq!(entries.len(), 2);

        // Buffer is now empty
        assert!(packer.is_empty());
        assert_eq!(packer.total_size(), 0);
    }

    #[test]
    fn test_flush_on_file_count() {
        let mut packer = SmallFilePacker::new(1024, 10000, 3);

        assert!(packer.push(make_entry("file1.txt", 10)).is_none());
        assert!(packer.push(make_entry("file2.txt", 10)).is_none());

        // Third push triggers flush
        let result = packer.push(make_entry("file3.txt", 10));
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 3);
    }

    #[test]
    fn test_take() {
        let mut packer = SmallFilePacker::new(1024, 4096, 10);

        packer.push(make_entry("file1.txt", 100));
        packer.push(make_entry("file2.txt", 200));

        let entries = packer.take();
        assert_eq!(entries.len(), 2);
        assert!(packer.is_empty());
        assert_eq!(packer.total_size(), 0);
    }
}
