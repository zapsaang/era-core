//! File entry metadata.

use era_common::proto::{
    file_entry::FileType as ProtoFileType, Catalog as ProtoCatalog, ChunkRef as ProtoChunkRef,
    FileEntry as ProtoFileEntry, PackedChunkInfo as ProtoPackedChunkInfo,
};
use era_common::ChunkHash;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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

impl From<FileType> for ProtoFileType {
    fn from(t: FileType) -> Self {
        match t {
            FileType::File => ProtoFileType::File,
            FileType::Directory => ProtoFileType::Directory,
            FileType::Symlink => ProtoFileType::Symlink,
        }
    }
}

impl From<ProtoFileType> for FileType {
    fn from(t: ProtoFileType) -> Self {
        match t {
            ProtoFileType::File => FileType::File,
            ProtoFileType::Directory => FileType::Directory,
            ProtoFileType::Symlink => FileType::Symlink,
        }
    }
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

impl From<&ChunkRef> for ProtoChunkRef {
    fn from(c: &ChunkRef) -> Self {
        Self {
            hash: Some(c.hash.into()),
            offset: c.offset,
            length: c.length,
            packed_info: c.packed_info.as_ref().map(|p| ProtoPackedChunkInfo {
                file_index: p.file_index as u32,
                total_files: p.total_files as u32,
            }),
        }
    }
}

impl TryFrom<ProtoChunkRef> for ChunkRef {
    type Error = era_common::EraError;

    fn try_from(p: ProtoChunkRef) -> Result<Self, Self::Error> {
        Ok(Self {
            hash: p
                .hash
                .ok_or_else(|| era_common::EraError::Deserialization("Missing chunk hash".into()))?
                .try_into()?,
            offset: p.offset,
            length: p.length,
            packed_info: p.packed_info.map(|i| PackedChunkInfo {
                file_index: i.file_index as usize,
                total_files: i.total_files as usize,
            }),
        })
    }
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
    /// Owner UID (Unix)
    #[serde(default)]
    pub uid: Option<u32>,
    /// Owner GID (Unix)
    #[serde(default)]
    pub gid: Option<u32>,
    /// Extended attributes
    #[serde(default)]
    pub xattrs: BTreeMap<String, Vec<u8>>,
    /// Access Control List (Platform specific)
    #[serde(default)]
    pub acl: Option<Vec<u8>>,
    /// List of chunks for file content
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

        #[cfg(unix)]
        let (uid, gid) = {
            use std::os::unix::fs::MetadataExt;
            (Some(metadata.uid()), Some(metadata.gid()))
        };
        #[cfg(not(unix))]
        let (uid, gid) = (None, None);

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
            uid,
            gid,
            xattrs: BTreeMap::new(),
            acl: None,
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
            uid: None,
            gid: None,
            xattrs: BTreeMap::new(),
            acl: None,
            chunks: Vec::new(),
        }
    }

    /// Set the chunk list
    pub fn with_chunks(mut self, chunks: Vec<ChunkRef>) -> Self {
        self.chunks = chunks;
        self
    }

    /// Check if this file has chunks
    pub fn is_chunked(&self) -> bool {
        !self.chunks.is_empty()
    }

    /// Get all chunk hashes for this file
    pub fn all_chunk_hashes(&self) -> Vec<ChunkHash> {
        self.chunks.iter().map(|c| c.hash).collect()
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

impl From<&FileEntry> for ProtoFileEntry {
    fn from(e: &FileEntry) -> Self {
        Self {
            path: e.path.to_string_lossy().into_owned(),
            file_type: ProtoFileType::from(e.file_type) as i32,
            size: e.size,
            permissions: e.permissions,
            mtime: e.mtime,
            symlink_target: e
                .symlink_target
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            uid: e.uid,
            gid: e.gid,
            xattrs: e
                .xattrs
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            acl: e.acl.clone(),
            chunks: e.chunks.iter().map(|c| c.into()).collect(),
        }
    }
}

impl TryFrom<ProtoFileEntry> for FileEntry {
    type Error = era_common::EraError;

    fn try_from(p: ProtoFileEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            path: PathBuf::from(p.path),
            file_type: ProtoFileType::try_from(p.file_type)
                .map(FileType::from)
                .map_err(|_| era_common::EraError::Deserialization("Invalid file type".into()))?,
            size: p.size,
            permissions: p.permissions,
            mtime: p.mtime,
            symlink_target: p.symlink_target.map(PathBuf::from),
            uid: p.uid,
            gid: p.gid,
            xattrs: p.xattrs.into_iter().collect(),
            acl: p.acl,
            chunks: p
                .chunks
                .into_iter()
                .map(|c| c.try_into())
                .collect::<Result<_, _>>()?,
        })
    }
}

/// Catalog of all entries in an archive
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Catalog {
    /// All file entries
    pub entries: Vec<FileEntry>,
    /// Physical location of each block in the archive.
    /// block_locations[i] corresponds to logical block index i.
    /// For non-erasure archives: length = block_count
    /// For erasure archives: length = logical block count (= stripe_count)
    ///     BlockLocation.shard_layout::Erasure already contains all shard metadata.
    pub block_locations: Vec<era_common::BlockLocation>,
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
            block_locations: Vec::new(),
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
        let proto: ProtoCatalog = self.into();
        Ok(proto.encode_to_vec())
    }

    /// Deserialize a catalog from bytes
    ///
    /// Uses safe deserialization with size limits to prevent DoS attacks.
    pub fn from_bytes(data: &[u8]) -> era_common::Result<Self> {
        let proto = ProtoCatalog::decode(data).map_err(|e| {
            era_common::EraError::Deserialization(format!("Failed to decode catalog: {}", e))
        })?;
        proto.try_into()
    }
}

impl From<&Catalog> for ProtoCatalog {
    fn from(c: &Catalog) -> Self {
        Self {
            entries: c.entries.iter().map(|e| e.into()).collect(),
            block_locations: c.block_locations.iter().cloned().map(Into::into).collect(),
            total_size: c.total_size,
            file_count: c.file_count,
            dir_count: c.dir_count,
        }
    }
}

impl TryFrom<ProtoCatalog> for Catalog {
    type Error = era_common::EraError;

    fn try_from(p: ProtoCatalog) -> Result<Self, Self::Error> {
        let block_locations = p
            .block_locations
            .into_iter()
            .map(|loc| loc.try_into())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            entries: p
                .entries
                .into_iter()
                .map(|e| e.try_into())
                .collect::<Result<_, _>>()?,
            block_locations,
            total_size: p.total_size,
            file_count: p.file_count,
            dir_count: p.dir_count,
        })
    }
}

impl Default for Catalog {
    fn default() -> Self {
        Self::new()
    }
}
