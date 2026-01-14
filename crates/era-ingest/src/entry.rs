//! File entry metadata.

use era_common::ChunkHash;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Type of file entry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileType {
    /// Regular file
    File,
    /// Directory
    Directory,
    /// Symbolic link
    Symlink,
}

/// A chunk reference with offset information for multi-chunk files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRef {
    /// Hash of the chunk
    pub hash: ChunkHash,
    /// Offset within the file (for multi-chunk files)
    pub offset: u64,
    /// Length of the chunk
    pub length: u32,
    /// Packed chunk metadata (if this chunk contains multiple small files)
    #[serde(default)]
    pub packed_info: Option<PackedChunkInfo>,
}

/// Information for packed chunks (multiple small files in one chunk)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackedChunkInfo {
    /// Index of this file within the packed chunk
    pub file_index: usize,
    /// Total number of files in this packed chunk
    pub total_files: usize,
}

impl ChunkRef {
    /// Create a new chunk reference for a standalone chunk
    pub fn new(hash: ChunkHash, offset: u64, length: u32) -> Self {
        Self {
            hash,
            offset,
            length,
            packed_info: None,
        }
    }

    /// Create a new chunk reference for a file in a packed chunk
    pub fn new_packed(
        hash: ChunkHash,
        offset: u64,
        length: u32,
        file_index: usize,
        total_files: usize,
    ) -> Self {
        Self {
            hash,
            offset,
            length,
            packed_info: Some(PackedChunkInfo {
                file_index,
                total_files,
            }),
        }
    }

    /// Check if this is a packed chunk reference
    pub fn is_packed(&self) -> bool {
        self.packed_info.is_some()
    }
}

/// Metadata for a file entry in the archive
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// Relative path within the archive
    pub path: PathBuf,
    /// Type of entry
    pub file_type: FileType,
    /// Size in bytes (0 for directories)
    pub size: u64,
    /// POSIX permissions (Unix mode bits)
    #[cfg(unix)]
    pub permissions: u32,
    #[cfg(not(unix))]
    pub permissions: u32,
    /// Modification time
    pub mtime: Option<u64>,
    /// Symlink target (if applicable)
    pub symlink_target: Option<PathBuf>,
    /// Hash of the file content (for single-chunk files only)
    /// Deprecated: Use `chunks` for new archives
    pub content_hash: Option<ChunkHash>,
    /// List of chunks for multi-chunk files (CDC)
    /// Empty for single-chunk files (backward compatibility)
    #[serde(default)]
    pub chunks: Vec<ChunkRef>,
}

impl FileEntry {
    /// Create a new file entry from filesystem metadata
    pub fn from_path(
        path: &std::path::Path,
        relative_to: &std::path::Path,
    ) -> std::io::Result<Self> {
        let metadata = std::fs::metadata(path)?;
        let relative_path = path.strip_prefix(relative_to).unwrap_or(path).to_path_buf();

        let file_type = if metadata.is_file() {
            FileType::File
        } else if metadata.is_dir() {
            FileType::Directory
        } else {
            FileType::Symlink
        };

        #[cfg(unix)]
        let permissions = {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode()
        };
        #[cfg(not(unix))]
        let permissions = if metadata.permissions().readonly() {
            0o444
        } else {
            0o644
        };

        let mtime = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());

        let symlink_target = if file_type == FileType::Symlink {
            std::fs::read_link(path).ok()
        } else {
            None
        };

        Ok(Self {
            path: relative_path,
            file_type,
            size: if file_type == FileType::File {
                metadata.len()
            } else {
                0
            },
            permissions,
            mtime,
            symlink_target,
            content_hash: None,
            chunks: Vec::new(),
        })
    }

    /// Create a file entry for a regular file
    pub fn file(path: PathBuf, size: u64) -> Self {
        Self {
            path,
            file_type: FileType::File,
            size,
            permissions: 0o644,
            mtime: None,
            symlink_target: None,
            content_hash: None,
            chunks: Vec::new(),
        }
    }

    /// Set the content hash (for single-chunk files)
    pub fn with_hash(mut self, hash: ChunkHash) -> Self {
        self.content_hash = Some(hash);
        self
    }

    /// Set the chunk list (for multi-chunk files)
    pub fn with_chunks(mut self, chunks: Vec<ChunkRef>) -> Self {
        self.chunks = chunks;
        self
    }

    /// Check if this file uses multi-chunk storage
    pub fn is_chunked(&self) -> bool {
        !self.chunks.is_empty()
    }

    /// Get all chunk hashes for this file
    ///
    /// Returns content_hash for single-chunk files, or all chunk hashes for multi-chunk files.
    pub fn all_chunk_hashes(&self) -> Vec<ChunkHash> {
        if self.is_chunked() {
            self.chunks.iter().map(|c| c.hash).collect()
        } else if let Some(hash) = self.content_hash {
            vec![hash]
        } else {
            vec![]
        }
    }

    /// Check if this is a regular file
    pub fn is_file(&self) -> bool {
        self.file_type == FileType::File
    }

    /// Check if this is a directory
    pub fn is_dir(&self) -> bool {
        self.file_type == FileType::Directory
    }
}

/// Catalog of all entries in an archive
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Catalog {
    /// All file entries
    pub entries: Vec<FileEntry>,
    /// Total size of all files
    pub total_size: u64,
    /// Number of files
    pub file_count: u64,
    /// Number of directories
    pub dir_count: u64,
}

impl Catalog {
    /// Create a new empty catalog
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            total_size: 0,
            file_count: 0,
            dir_count: 0,
        }
    }

    /// Add an entry to the catalog
    pub fn add(&mut self, entry: FileEntry) {
        match entry.file_type {
            FileType::File => {
                self.total_size += entry.size;
                self.file_count += 1;
            }
            FileType::Directory => {
                self.dir_count += 1;
            }
            FileType::Symlink => {
                self.file_count += 1;
            }
        }
        self.entries.push(entry);
    }

    /// Reserve capacity for at least `additional` more entries
    ///
    /// This is useful for batch operations where the number of entries is known upfront,
    /// reducing the number of reallocations.
    pub fn reserve(&mut self, additional: usize) {
        self.entries.reserve(additional);
    }

    /// Serialize the catalog to bytes
    pub fn to_bytes(&self) -> era_common::Result<Vec<u8>> {
        era_common::serialize(self)
    }

    /// Deserialize a catalog from bytes
    ///
    /// Uses safe deserialization with size limits to prevent DoS attacks.
    pub fn from_bytes(data: &[u8]) -> era_common::Result<Self> {
        era_common::deserialize(data)
    }
}

impl Default for Catalog {
    fn default() -> Self {
        Self::new()
    }
}
