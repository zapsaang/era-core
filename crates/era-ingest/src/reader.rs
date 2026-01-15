//! File reading utilities.

use crate::chunker::{Chunker, ChunkerConfig, StreamingChunker};
use crate::entry::FileEntry;
use bytes::Bytes;
use era_common::{ChunkHash, EraError, Result, UniqueChunk};
use glob::Pattern;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
// use tracing::{debug, warn};
use walkdir::WalkDir;

/// Threshold for using CDC chunking (files larger than this use chunking)
const CDC_THRESHOLD: u64 = 256 * 1024; // 256KB

/// Configuration for directory scanning
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Root directory to scan
    pub root: PathBuf,
    /// Glob patterns to include
    pub include_patterns: Vec<String>,
    /// Glob patterns to exclude
    pub exclude_patterns: Vec<String>,
    /// Whether to extract extended attributes
    pub extract_xattrs: bool,
    /// Whether to extract ACLs (platform specific)
    pub extract_acls: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            include_patterns: Vec::new(),
            exclude_patterns: Vec::new(),
            extract_xattrs: true,
            extract_acls: true,
        }
    }
}

/// Scanner for traversing directories and collecting metadata
pub struct DirectoryScanner {
    options: ScanOptions,
    include_globs: Vec<Pattern>,
    exclude_globs: Vec<Pattern>,
}

impl DirectoryScanner {
    /// Create a new directory scanner
    pub fn new(mut options: ScanOptions) -> Result<Self> {
        let include_globs = options
            .include_patterns
            .iter()
            .map(|p| Pattern::new(p).map_err(|e| EraError::InvalidFormat(e.to_string())))
            .collect::<Result<Vec<_>>>()?;

        let exclude_globs = options
            .exclude_patterns
            .iter()
            .map(|p| Pattern::new(p).map_err(|e| EraError::InvalidFormat(e.to_string())))
            .collect::<Result<Vec<_>>>()?;

        // Canonicalize root path if possible
        if let Ok(canon) = options.root.canonicalize() {
            options.root = canon;
        }

        Ok(Self {
            options,
            include_globs,
            exclude_globs,
        })
    }

    /// Scan the directory tree and return an iterator of file entries
    pub fn scan(&self) -> impl Iterator<Item = Result<FileEntry>> + '_ {
        WalkDir::new(&self.options.root)
            .into_iter()
            .filter_entry(move |_| {
                // We can implement early filtering of directories here if needed
                true
            })
            .filter_map(move |entry| {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => return Some(Err(EraError::Io(e.into()))),
                };

                // Skip root directory itself if desired, or include it?
                // Usually archive includes content of the root.
                if entry.path() == self.options.root {
                    // We generally don't archive the root folder as an entry unless asked.
                    // But for proper restoration of root permissions, we might want it.
                    // Let's include it.
                }

                let path = entry.path();

                // Skip if filtering rules apply
                if !self.should_include(path) {
                    return None;
                }

                // Metadata extraction
                match self.create_file_entry(path) {
                    Ok(file_entry) => Some(Ok(file_entry)),
                    Err(e) => Some(Err(e)),
                }
            })
    }

    /// Check if a path should be included based on globs
    fn should_include(&self, path: &Path) -> bool {
        // If includes are specified, path must match at least one
        if !self.include_globs.is_empty() {
            let mut matched = false;
            for pattern in &self.include_globs {
                if pattern.matches_path(path) {
                    matched = true;
                    break;
                }
            }
            if !matched {
                return false;
            }
        }

        // Must not match any excludes
        for pattern in &self.exclude_globs {
            if pattern.matches_path(path) {
                return false;
            }
        }

        true
    }

    /// Create a FileEntry with full metadata
    fn create_file_entry(&self, path: &Path) -> Result<FileEntry> {
        // Basic metadata from FileEntry::from_path
        let mut entry =
            FileEntry::from_path(path, &self.options.root).map_err(|e| EraError::Io(e))?;

        // Extract XAttrs if enabled
        if self.options.extract_xattrs {
            entry.xattrs = self.extract_xattrs(path);
        }

        // Extract ACLs if enabled
        if self.options.extract_acls {
            // Placeholder: ACL extraction is platform-specific and complex.
            // For now, we might rely on xattrs if they store ACLs (system.posix_acl_access)
            // Or use a specific crate.
            // Since we updated FileEntry to store xattrs, we can just ensure we read them.
            // On Linux "system.posix_acl_access" is an xattr.
            // So if extract_xattrs is true, we might already get it.
        }

        // Special handling for directories:
        // "Generate DirEntry structure as special small files injected into data stream"
        // If it's a directory, we can potentially add a "content block" that lists children.
        // For now, the FileEntry itself identifies it as a directory.
        // If we want to inject it as a "data stream", we would generate a chunk for it.
        // But FileEntry has `chunks`.

        Ok(entry)
    }

    fn extract_xattrs(&self, path: &Path) -> BTreeMap<String, Vec<u8>> {
        let mut xattrs = BTreeMap::new();
        if let Ok(iter) = xattr::list(path) {
            for name in iter {
                if let Some(name_str) = name.to_str() {
                    // Filter system xattrs if needed?
                    if let Ok(value) = xattr::get(path, name_str) {
                        if let Some(val) = value {
                            xattrs.insert(name_str.to_string(), val);
                        }
                    }
                }
            }
        }
        xattrs
    }
}

/// Reader for ingesting files
pub struct FileReader {
    /// Buffer size for reading
    buffer_size: usize,
    /// Whether to use CDC for large files
    use_cdc: bool,
    /// CDC configuration
    chunker_config: ChunkerConfig,
}

impl FileReader {
    /// Create a new file reader
    pub fn new() -> Self {
        Self {
            buffer_size: 64 * 1024, // 64KB default
            use_cdc: false,         // MVP compatibility: disabled by default
            chunker_config: ChunkerConfig::default(),
        }
    }

    /// Create a file reader with CDC enabled
    pub fn with_cdc() -> Self {
        Self {
            buffer_size: 64 * 1024,
            use_cdc: true,
            chunker_config: ChunkerConfig::default(),
        }
    }

    /// Set the buffer size
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// Enable or disable CDC chunking
    pub fn enable_cdc(mut self, enable: bool) -> Self {
        self.use_cdc = enable;
        self
    }

    /// Set custom CDC configuration
    pub fn with_chunker_config(mut self, config: ChunkerConfig) -> Self {
        self.chunker_config = config;
        self
    }

    /// Read an entire file as a single chunk
    ///
    /// This is the original MVP behavior, kept for backward compatibility.
    /// For large files, consider using `read_file_chunked` instead.
    pub fn read_file(&self, path: &Path) -> Result<UniqueChunk> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let size = metadata.len() as usize;

        let mut reader = BufReader::with_capacity(self.buffer_size, file);
        let mut data = Vec::with_capacity(size);
        reader.read_to_end(&mut data)?;

        let hash = era_crypto::hash(&data);

        Ok(UniqueChunk::new(Bytes::from(data), hash))
    }

    /// Read a file with automatic chunking for large files
    ///
    /// Files smaller than `CDC_THRESHOLD` are returned as a single chunk.
    /// Larger files are split using FastCDC content-defined chunking.
    pub fn read_file_chunked(&self, path: &Path) -> Result<Vec<UniqueChunk>> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let size = metadata.len();

        if !self.use_cdc || size <= CDC_THRESHOLD {
            // Small file: read as single chunk
            let chunk = self.read_file(path)?;
            return Ok(vec![chunk]);
        }

        // Large file: use streaming CDC
        let file = File::open(path)?;
        let reader = BufReader::with_capacity(self.buffer_size, file);
        let streaming = StreamingChunker::new(reader, self.chunker_config.clone());

        streaming.collect()
    }

    /// Read a file and split into chunks using FastCDC
    ///
    /// Always uses CDC chunking regardless of file size.
    pub fn read_file_cdc(&self, path: &Path) -> Result<Vec<UniqueChunk>> {
        let chunker = Chunker::new(self.chunker_config.clone());
        chunker.chunk_file(path)
    }

    /// Read a file and compute its hash without loading all data at once
    pub fn hash_file(&self, path: &Path) -> Result<ChunkHash> {
        let file = File::open(path)?;
        era_crypto::hash_reader(file).map_err(Into::into)
    }

    /// Read file contents into memory
    pub fn read_bytes(&self, path: &Path) -> Result<Bytes> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let size = metadata.len() as usize;

        let mut reader = BufReader::with_capacity(self.buffer_size, file);
        let mut data = Vec::with_capacity(size);
        reader.read_to_end(&mut data)?;

        Ok(Bytes::from(data))
    }
}

impl Default for FileReader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_file() {
        let mut temp = NamedTempFile::new().unwrap();
        let data = b"Hello, ERA file reader!";
        temp.write_all(data).unwrap();
        temp.flush().unwrap();

        let reader = FileReader::new();
        let chunk = reader.read_file(temp.path()).unwrap();

        assert_eq!(chunk.data.as_ref(), data);
        assert!(!chunk.hash.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_hash_file() {
        let mut temp = NamedTempFile::new().unwrap();
        let data = b"Test data for hashing";
        temp.write_all(data).unwrap();
        temp.flush().unwrap();

        let reader = FileReader::new();
        let hash1 = reader.hash_file(temp.path()).unwrap();
        let hash2 = era_crypto::hash(data);

        assert_eq!(hash1, hash2);
    }
}
#[cfg(test)]
mod scanner_tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_directory_scanner() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        // Create directory structure
        std::fs::create_dir(root.join("subdir")).unwrap();
        {
            let mut f = File::create(root.join("file1.txt")).unwrap();
            f.write_all(b"content").unwrap();
        }
        {
            let mut f = File::create(root.join("subdir/file2.txt")).unwrap();
            f.write_all(b"content2").unwrap();
        }
        {
            let mut f = File::create(root.join("ignored.log")).unwrap();
            f.write_all(b"log").unwrap();
        }

        let options = ScanOptions {
            root: root.to_path_buf(),
            include_patterns: vec![],
            exclude_patterns: vec!["**/*.log".to_string()],
            extract_xattrs: true,
            extract_acls: true,
        };

        let scanner = DirectoryScanner::new(options).expect("Failed to create scanner");
        let entries: Vec<FileEntry> = scanner.scan().map(|r| r.expect("Scan failed")).collect();

        // Debug output
        for e in &entries {
            println!("Found entry: {:?} ({:?})", e.path, e.file_type);
        }

        // Verify counts
        // Expect: root(.), subdir, file1.txt, subdir/file2.txt = 4
        // ignored.log is excluded.

        // Implementation check: Do I filter "."?
        // if entry.path() == root ... I had a comment but no code to return None.
        // So root is included.

        assert!(entries.iter().any(|e| e.path == PathBuf::from("file1.txt")));
        assert!(entries.iter().any(|e| e.path == PathBuf::from("subdir")));
        assert!(entries
            .iter()
            .any(|e| e.path == PathBuf::from("subdir/file2.txt")));
        assert!(!entries
            .iter()
            .any(|e| e.path.to_string_lossy().ends_with("ignored.log")));
    }
}
