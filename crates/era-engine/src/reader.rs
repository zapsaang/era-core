//! Archive reader - extracts files from ERA archives.

use era_codec::ZstdCompressor;
use era_common::{BlockLocation, ChunkHash, EraError, Result};
use era_crypto::{derive_key, KdfParams, Salt};
use era_ingest::{Catalog, FileEntry};
use era_packing::MacroBlockUnpacker;
use era_storage::LocalStorageBackend;
use era_volume::{SuperHeader, VolumeReader};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Maximum allowed block size (16 MB) - prevents malicious archives from causing OOM
const MAX_BLOCK_SIZE: u32 = 16 * 1024 * 1024;

/// Maximum allowed file size declared in catalog (100 GB) - sanity check
const MAX_DECLARED_FILE_SIZE: u64 = 100 * 1024 * 1024 * 1024;

/// Validate block size to prevent infinite loops and OOM attacks
#[inline]
fn validate_block_size(block_size: u32, offset: u64) -> Result<()> {
    if block_size == 0 {
        return Err(EraError::CorruptedHeader(format!(
            "Zero-length block at offset {}",
            offset
        )));
    }
    if block_size > MAX_BLOCK_SIZE {
        return Err(EraError::BlockTooLarge {
            size: block_size as usize,
            max_size: MAX_BLOCK_SIZE as usize,
        });
    }
    Ok(())
}

/// Options for extraction
#[derive(Debug, Clone, Default)]
pub struct ExtractOptions {
    /// Output directory
    pub output_dir: PathBuf,
    /// Overwrite existing files
    pub overwrite: bool,
}

impl ExtractOptions {
    /// Create new options with the given output directory
    pub fn new(output_dir: impl Into<PathBuf>) -> Self {
        Self {
            output_dir: output_dir.into(),
            overwrite: false,
        }
    }

    /// Set whether to overwrite existing files
    pub fn overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite = overwrite;
        self
    }
}

/// State for tracking multi-chunk file extraction
/// Uses pre-created files to avoid OOM on large files
struct MultiChunkState {
    /// Open file handle for writing chunks directly
    file: File,
    /// Output path for logging
    output_path: PathBuf,
    /// Expected file size (sum of all chunk lengths)
    expected_size: u64,
    /// Track which chunks have been written (for completion check)
    chunks_written: Vec<bool>,
    /// Total number of chunks expected
    total_chunks: usize,
    /// Number of chunks written so far
    written_count: usize,
}

/// Reader for ERA archives
pub struct ArchiveReader {
    volume_reader: VolumeReader<era_storage::LocalStorageReader>,
    unpacker: MacroBlockUnpacker,
    catalog: Option<Catalog>,
}

impl ArchiveReader {
    /// Open an archive for reading
    ///
    /// This function verifies the password early using the stored verification tag,
    /// providing clear error messages for incorrect passwords.
    pub fn open(path: &Path, password: &str) -> Result<Self> {
        info!("Opening archive: {}", path.display());

        let parent_dir = path.parent().unwrap_or(Path::new("."));
        let backend = LocalStorageBackend::new(parent_dir);
        let volume_path = path.file_name().unwrap_or_default();

        let volume_reader = VolumeReader::open(&backend, Path::new(volume_path))?;

        // Derive key from password and stored salt
        let header = volume_reader.header();
        let salt = Salt::from_bytes(header.crypto_anchor.salt);
        let kdf_params = KdfParams {
            memory_cost: header.crypto_anchor.kdf_memory_cost,
            time_cost: header.crypto_anchor.kdf_time_cost,
            parallelism: header.crypto_anchor.kdf_parallelism,
        };
        let key = derive_key(password.as_bytes(), &salt, &kdf_params)?;

        // Verify password using stored verification tag
        if !era_crypto::verify_password_tag(&key, &header.crypto_anchor.password_verification_tag) {
            return Err(EraError::InvalidKey("Incorrect password".to_string()));
        }

        // Create unpacker with salt as nonce context (must match encryption)
        let nonce_context = header.crypto_anchor.salt;
        let compressor = Box::new(ZstdCompressor::new(header.config.compression.level));
        let unpacker = MacroBlockUnpacker::new(key, nonce_context, compressor);

        Ok(Self {
            volume_reader,
            unpacker,
            catalog: None,
        })
    }

    /// Get the archive header
    pub fn header(&self) -> &SuperHeader {
        self.volume_reader.header()
    }

    /// Load the catalog (stored as the last block before footer)
    pub fn load_catalog(&mut self) -> Result<&Catalog> {
        if self.catalog.is_some() {
            return Ok(self.catalog.as_ref().unwrap());
        }

        let block_count = self.volume_reader.block_count();
        if block_count == 0 {
            return Err(EraError::other("Archive is empty"));
        }

        // Try to use catalog location from footer (O(1) lookup)
        let footer = self.volume_reader.footer();
        let catalog_location = if footer.has_catalog_location() {
            debug!(
                "Using footer catalog location: offset={}, size={}",
                footer.catalog_offset, footer.catalog_size
            );
            BlockLocation {
                volume_id: self.volume_reader.header().volume_id,
                slot_index: block_count - 1,
                physical_offset: footer.catalog_offset,
                encrypted_size: footer.catalog_size,
            }
        } else {
            // Fallback: scan for catalog (O(n) - for backwards compatibility)
            debug!("Footer lacks catalog location, scanning blocks...");
            self.scan_for_last_block()?
        };

        let encrypted_block = self.volume_reader.read_block(&catalog_location)?;
        let chunks = self.unpacker.extract_all_chunks(&encrypted_block)?;

        if chunks.is_empty() {
            return Err(EraError::other("Catalog block is empty"));
        }

        let catalog_data = &chunks[0].1;
        let catalog = Catalog::from_bytes(catalog_data)?;

        info!(
            "Loaded catalog: {} files, {} bytes total",
            catalog.file_count, catalog.total_size
        );

        self.catalog = Some(catalog);
        Ok(self.catalog.as_ref().unwrap())
    }

    /// Scan blocks to find the last one (fallback for old archives)
    fn scan_for_last_block(&self) -> Result<BlockLocation> {
        let (data_start, data_end) = self.volume_reader.data_region();
        let block_count = self.volume_reader.block_count();

        let mut offset = data_start;
        let mut last_block_offset = data_start;
        let mut last_block_size = 0u32;

        while offset < data_end {
            let len_bytes = self.volume_reader.read_raw(offset, 4)?;
            if len_bytes.len() < 4 {
                break;
            }
            let block_size =
                u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]);

            // Validate block size to prevent infinite loops
            validate_block_size(block_size, offset)?;

            last_block_offset = offset;
            last_block_size = block_size;
            offset += 4 + block_size as u64;
        }

        Ok(BlockLocation {
            volume_id: self.volume_reader.header().volume_id,
            slot_index: block_count - 1,
            physical_offset: last_block_offset,
            encrypted_size: last_block_size,
        })
    }

    /// List all files in the archive
    pub fn list_files(&mut self) -> Result<Vec<&FileEntry>> {
        let catalog = self.load_catalog()?;
        Ok(catalog.entries.iter().collect())
    }

    /// Extract all files to the given directory
    ///
    /// This optimized implementation uses single-pass extraction:
    /// - Reads and decrypts each block only once
    /// - Builds hash→path mapping from catalog
    /// - Writes files directly during block scan
    /// - Supports multi-chunk files (CDC mode) with pre-created files to avoid OOM
    pub fn extract_all(&mut self, options: &ExtractOptions) -> Result<ExtractStats> {
        info!("Extracting to: {}", options.output_dir.display());

        // Load catalog if not already loaded
        self.load_catalog()?;

        let catalog = self.catalog.as_ref().unwrap();
        let mut stats = ExtractStats::default();

        // Build maps for extraction:
        // - single_chunk_pending: hash -> (entry, output_path) for single-chunk files
        // - multi_chunk_files: file index for files that need multiple chunks
        // - chunk_to_files: hash -> list of (file_idx, chunk_idx, offset) for multi-chunk files
        let mut single_chunk_pending: HashMap<ChunkHash, Vec<(usize, PathBuf)>> = HashMap::new();
        let mut multi_chunk_files: HashMap<usize, MultiChunkState> = HashMap::new();
        let mut chunk_to_files: HashMap<ChunkHash, Vec<(usize, usize, u64)>> = HashMap::new();

        for (file_idx, entry) in catalog.entries.iter().enumerate() {
            let output_path = options.output_dir.join(&entry.path);

            // Check if file exists and should be skipped
            if output_path.exists() && !options.overwrite {
                debug!("Skipping existing file: {}", output_path.display());
                stats.skipped += 1;
                continue;
            }

            // Validate declared file size to prevent disk-filling attacks
            if entry.size > MAX_DECLARED_FILE_SIZE {
                return Err(EraError::CorruptedHeader(format!(
                    "File '{}' declares unreasonable size: {} bytes (max: {} bytes)",
                    entry.path.display(),
                    entry.size,
                    MAX_DECLARED_FILE_SIZE
                )));
            }

            if entry.is_chunked() {
                // Multi-chunk file: pre-create file to avoid OOM
                let chunk_count = entry.chunks.len();
                let expected_size = entry.size;

                // Create parent directories
                if let Some(parent) = output_path.parent() {
                    fs::create_dir_all(parent)?;
                }

                // Pre-create and pre-allocate file
                let file = File::create(&output_path)?;
                // Set file length to expected size for sparse file support
                file.set_len(expected_size)?;

                multi_chunk_files.insert(
                    file_idx,
                    MultiChunkState {
                        file,
                        output_path,
                        expected_size,
                        chunks_written: vec![false; chunk_count],
                        total_chunks: chunk_count,
                        written_count: 0,
                    },
                );

                for (chunk_idx, chunk_ref) in entry.chunks.iter().enumerate() {
                    chunk_to_files.entry(chunk_ref.hash).or_default().push((
                        file_idx,
                        chunk_idx,
                        chunk_ref.offset,
                    ));
                }
            } else if let Some(content_hash) = entry.content_hash {
                // Single-chunk file (legacy)
                single_chunk_pending
                    .entry(content_hash)
                    .or_default()
                    .push((file_idx, output_path));
            }
        }

        // If nothing to extract, return early
        if single_chunk_pending.is_empty() && multi_chunk_files.is_empty() {
            info!("No files to extract");
            return Ok(stats);
        }

        // Single-pass extraction: scan blocks and extract matching chunks
        let (data_start, data_end) = self.volume_reader.data_region();
        let mut offset = data_start;
        let mut slot_index = 0u32;

        while offset < data_end
            && (!single_chunk_pending.is_empty() || !multi_chunk_files.is_empty())
        {
            let len_bytes = self.volume_reader.read_raw(offset, 4)?;
            if len_bytes.len() < 4 {
                break;
            }
            let block_size =
                u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]);

            // Validate block size to prevent infinite loops and OOM
            validate_block_size(block_size, offset)?;

            let location = BlockLocation {
                volume_id: self.volume_reader.header().volume_id,
                slot_index,
                physical_offset: offset,
                encrypted_size: block_size,
            };

            // Read, decrypt block and extract ALL chunks in single operation
            let encrypted_block = self.volume_reader.read_block(&location)?;
            if let Ok(chunks) = self.unpacker.extract_all_chunks(&encrypted_block) {
                for (hash, data) in chunks {
                    // Handle single-chunk files
                    if let Some(entries) = single_chunk_pending.remove(&hash) {
                        for (_file_idx, output_path) in entries {
                            // Create parent directories
                            if let Some(parent) = output_path.parent() {
                                fs::create_dir_all(parent)?;
                            }

                            // Write file directly (no second decryption!)
                            let mut file = File::create(&output_path)?;
                            file.write_all(&data)?;

                            debug!("Extracted: {}", output_path.display());
                            stats.extracted += 1;
                            stats.bytes_written += data.len() as u64;
                        }
                    }

                    // Handle multi-chunk files: write directly to pre-created file
                    if let Some(file_refs) = chunk_to_files.remove(&hash) {
                        for (file_idx, chunk_idx, chunk_offset) in file_refs {
                            if let Some(state) = multi_chunk_files.get_mut(&file_idx) {
                                // Seek to correct position and write chunk
                                state.file.seek(SeekFrom::Start(chunk_offset))?;
                                state.file.write_all(&data)?;

                                state.chunks_written[chunk_idx] = true;
                                state.written_count += 1;

                                // Check if all chunks are written
                                if state.written_count == state.total_chunks {
                                    // Sync and close by dropping
                                    state.file.sync_all()?;

                                    debug!("Extracted (chunked): {}", state.output_path.display());
                                    stats.extracted += 1;
                                    stats.bytes_written += state.expected_size;

                                    // Remove completed file from tracking
                                    multi_chunk_files.remove(&file_idx);
                                }
                            }
                        }
                    }
                }
            }

            offset += 4 + block_size as u64;
            slot_index += 1;
        }

        // Sync any remaining files (shouldn't happen in normal operation)
        for (_, state) in multi_chunk_files.iter() {
            if state.written_count > 0 {
                debug!(
                    "Warning: Incomplete file: {} ({}/{})",
                    state.output_path.display(),
                    state.written_count,
                    state.total_chunks
                );
            }
        }

        info!(
            "Extraction complete: {} files, {} bytes",
            stats.extracted, stats.bytes_written
        );

        Ok(stats)
    }

    /// Verify the integrity of the archive
    ///
    /// This method performs a comprehensive verification:
    /// - Reads and decrypts all blocks (validates AEAD authentication)
    /// - Verifies chunk hashes match their declared content
    /// - Checks that all files have their required chunks present
    /// - Reports any corrupted or missing data
    pub fn verify(&mut self) -> Result<VerifyStats> {
        info!("Verifying archive integrity...");

        // Load catalog if not already loaded
        self.load_catalog()?;

        let catalog = self.catalog.as_ref().unwrap();
        let mut stats = VerifyStats::default();

        // Build a map of expected chunks for verification
        // chunk_hash -> list of (file_idx, chunk_idx, expected_len)
        let mut expected_chunks: HashMap<ChunkHash, Vec<(usize, usize, u64)>> = HashMap::new();
        let mut file_chunk_counts: Vec<usize> = Vec::with_capacity(catalog.entries.len());
        let mut file_chunks_found: Vec<usize> = vec![0; catalog.entries.len()];

        for (file_idx, entry) in catalog.entries.iter().enumerate() {
            if entry.is_chunked() {
                file_chunk_counts.push(entry.chunks.len());
                for (chunk_idx, chunk_ref) in entry.chunks.iter().enumerate() {
                    expected_chunks.entry(chunk_ref.hash).or_default().push((
                        file_idx,
                        chunk_idx,
                        chunk_ref.length as u64,
                    ));
                }
            } else if let Some(content_hash) = entry.content_hash {
                file_chunk_counts.push(1);
                expected_chunks
                    .entry(content_hash)
                    .or_default()
                    .push((file_idx, 0, entry.size));
            } else {
                file_chunk_counts.push(0);
            }
        }

        // Scan all blocks and verify each one
        let (data_start, data_end) = self.volume_reader.data_region();
        let mut offset = data_start;
        let mut slot_index = 0u32;

        while offset < data_end {
            let len_bytes = self.volume_reader.read_raw(offset, 4)?;
            if len_bytes.len() < 4 {
                break;
            }
            let block_size =
                u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]);

            // Validate block size
            if block_size == 0 {
                stats.errors.push(format!(
                    "Block {} at offset {}: zero-length block",
                    slot_index, offset
                ));
                stats.blocks_failed += 1;
                break; // Can't continue with zero-length block
            }

            if block_size > MAX_BLOCK_SIZE {
                stats.errors.push(format!(
                    "Block {} at offset {}: block too large ({} bytes, max: {} bytes)",
                    slot_index, offset, block_size, MAX_BLOCK_SIZE
                ));
                stats.blocks_failed += 1;
                break; // Can't trust further block sizes
            }

            let location = BlockLocation {
                volume_id: self.volume_reader.header().volume_id,
                slot_index,
                physical_offset: offset,
                encrypted_size: block_size,
            };

            // Read and decrypt block (AEAD verification happens here)
            let encrypted_block = match self.volume_reader.read_block(&location) {
                Ok(block) => block,
                Err(e) => {
                    stats.errors.push(format!(
                        "Block {} at offset {}: read error: {}",
                        slot_index, offset, e
                    ));
                    stats.blocks_failed += 1;
                    offset += 4 + block_size as u64;
                    slot_index += 1;
                    continue;
                }
            };

            // Try to decrypt and extract chunks
            match self.unpacker.extract_all_chunks(&encrypted_block) {
                Ok(chunks) => {
                    stats.blocks_verified += 1;

                    for (hash, data) in &chunks {
                        stats.bytes_verified += data.len() as u64;

                        // Verify chunk hash matches content
                        let computed_hash = era_crypto::hash(data);
                        if computed_hash != *hash {
                            stats.errors.push(format!(
                                "Block {}: chunk hash mismatch (expected {:?}, got {:?})",
                                slot_index, hash, computed_hash
                            ));
                        }

                        // Track which files got their chunks
                        if let Some(file_refs) = expected_chunks.get(hash) {
                            for (file_idx, _, expected_len) in file_refs {
                                if data.len() as u64 == *expected_len {
                                    file_chunks_found[*file_idx] += 1;
                                } else {
                                    stats.errors.push(format!(
                                        "Block {}: chunk length mismatch for file {} (expected {}, got {})",
                                        slot_index, file_idx, expected_len, data.len()
                                    ));
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    stats.errors.push(format!(
                        "Block {} at offset {}: decryption/decompression failed: {}",
                        slot_index, offset, e
                    ));
                    stats.blocks_failed += 1;
                }
            }

            offset += 4 + block_size as u64;
            slot_index += 1;
        }

        // Check that all files have all their chunks
        for (file_idx, entry) in catalog.entries.iter().enumerate() {
            let expected = file_chunk_counts[file_idx];
            let found = file_chunks_found[file_idx];
            if found == expected && expected > 0 {
                stats.files_verified += 1;
            } else if found < expected {
                stats.files_incomplete += 1;
                stats.errors.push(format!(
                    "File '{}': missing {} of {} chunks",
                    entry.path.display(),
                    expected - found,
                    expected
                ));
            }
        }

        if stats.is_ok() {
            info!(
                "Verification passed: {} blocks, {} files, {} bytes",
                stats.blocks_verified, stats.files_verified, stats.bytes_verified
            );
        } else {
            info!(
                "Verification FAILED: {} block errors, {} incomplete files, {} total errors",
                stats.blocks_failed,
                stats.files_incomplete,
                stats.errors.len()
            );
        }

        Ok(stats)
    }
}

/// Statistics about extraction
#[derive(Debug, Default)]
pub struct ExtractStats {
    /// Number of files extracted
    pub extracted: u64,
    /// Number of files skipped (already exist)
    pub skipped: u64,
    /// Total bytes written
    pub bytes_written: u64,
}

/// Statistics about verification
#[derive(Debug, Default)]
pub struct VerifyStats {
    /// Number of blocks verified
    pub blocks_verified: u64,
    /// Number of blocks with errors
    pub blocks_failed: u64,
    /// Number of files verified
    pub files_verified: u64,
    /// Number of files with missing chunks
    pub files_incomplete: u64,
    /// Total bytes verified
    pub bytes_verified: u64,
    /// List of errors encountered
    pub errors: Vec<String>,
}

impl VerifyStats {
    /// Check if verification passed with no errors
    pub fn is_ok(&self) -> bool {
        self.blocks_failed == 0 && self.files_incomplete == 0 && self.errors.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ArchiveWriter;
    use tempfile::TempDir;

    #[test]
    fn test_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.era");
        let password = "test_password";

        // Create archive
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .build()
            .unwrap();

        writer.add_bytes("hello.txt", b"Hello, World!").unwrap();
        writer.add_bytes("data.bin", &[1, 2, 3, 4, 5]).unwrap();
        writer.finalize().unwrap();

        // Read archive
        let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
        let files = reader.list_files().unwrap();
        assert_eq!(files.len(), 2);

        // Extract
        let extract_dir = temp_dir.path().join("extracted");
        let options = ExtractOptions::new(&extract_dir);
        let stats = reader.extract_all(&options).unwrap();

        assert_eq!(stats.extracted, 2);
        assert_eq!(stats.bytes_written, 18); // 13 + 5

        // Verify extracted files
        let hello_content = fs::read_to_string(extract_dir.join("hello.txt")).unwrap();
        assert_eq!(hello_content, "Hello, World!");

        let data_content = fs::read(extract_dir.join("data.bin")).unwrap();
        assert_eq!(data_content, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_wrong_password_fails() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("secure.era");

        // Create archive with password
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password("correct_password")
            .build()
            .unwrap();

        writer.add_bytes("secret.txt", b"Secret data").unwrap();
        writer.finalize().unwrap();

        // Try to open with wrong password
        let result = ArchiveReader::open(&archive_path, "wrong_password");
        assert!(result.is_err(), "Wrong password should fail");
    }

    #[test]
    fn test_empty_archive_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("empty.era");
        let password = "test";

        // Create empty archive
        let writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .build()
            .unwrap();
        writer.finalize().unwrap();

        // Read empty archive
        let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
        let files = reader.list_files().unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn test_large_file_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("large.era");
        let password = "test";

        // Create archive with large file
        let large_data = vec![b'X'; 512 * 1024]; // 512KB
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .build()
            .unwrap();
        writer.add_bytes("large.bin", &large_data).unwrap();
        writer.finalize().unwrap();

        // Extract and verify
        let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
        let extract_dir = temp_dir.path().join("extracted");
        let options = ExtractOptions::new(&extract_dir);
        let stats = reader.extract_all(&options).unwrap();

        assert_eq!(stats.extracted, 1);
        assert_eq!(stats.bytes_written, 512 * 1024);

        let extracted = fs::read(extract_dir.join("large.bin")).unwrap();
        assert_eq!(extracted, large_data);
    }

    #[test]
    fn test_unicode_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("unicode.era");
        let password = "密码";

        // Create archive with unicode content
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .build()
            .unwrap();
        writer
            .add_bytes("文档.txt", "这是中文内容".as_bytes())
            .unwrap();
        writer.finalize().unwrap();

        // Extract and verify
        let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
        let extract_dir = temp_dir.path().join("extracted");
        let options = ExtractOptions::new(&extract_dir);
        reader.extract_all(&options).unwrap();

        let extracted = fs::read_to_string(extract_dir.join("文档.txt")).unwrap();
        assert_eq!(extracted, "这是中文内容");
    }

    #[test]
    fn test_overwrite_protection() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.era");
        let password = "test";

        // Create archive
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .build()
            .unwrap();
        writer.add_bytes("file.txt", b"new content").unwrap();
        writer.finalize().unwrap();

        // Create existing file
        let extract_dir = temp_dir.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();
        fs::write(extract_dir.join("file.txt"), b"original content").unwrap();

        // Extract without overwrite
        let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
        let options = ExtractOptions::new(&extract_dir);
        let stats = reader.extract_all(&options).unwrap();

        assert_eq!(stats.skipped, 1);
        assert_eq!(stats.extracted, 0);

        // Verify original content preserved
        let content = fs::read_to_string(extract_dir.join("file.txt")).unwrap();
        assert_eq!(content, "original content");
    }

    #[test]
    fn test_overwrite_enabled() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.era");
        let password = "test";

        // Create archive
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .build()
            .unwrap();
        writer.add_bytes("file.txt", b"new content").unwrap();
        writer.finalize().unwrap();

        // Create existing file
        let extract_dir = temp_dir.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();
        fs::write(extract_dir.join("file.txt"), b"original content").unwrap();

        // Extract with overwrite enabled
        let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
        let options = ExtractOptions::new(&extract_dir).overwrite(true);
        let stats = reader.extract_all(&options).unwrap();

        assert_eq!(stats.extracted, 1);

        // Verify new content
        let content = fs::read_to_string(extract_dir.join("file.txt")).unwrap();
        assert_eq!(content, "new content");
    }

    #[test]
    fn test_nested_directory_structure() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("nested.era");
        let password = "test";

        // Create archive with nested structure
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .build()
            .unwrap();
        writer.add_bytes("a/b/c/deep.txt", b"deep content").unwrap();
        writer.add_bytes("a/shallow.txt", b"shallow").unwrap();
        writer.finalize().unwrap();

        // Extract
        let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
        let extract_dir = temp_dir.path().join("extracted");
        let options = ExtractOptions::new(&extract_dir);
        reader.extract_all(&options).unwrap();

        // Verify nested file
        let deep = fs::read_to_string(extract_dir.join("a/b/c/deep.txt")).unwrap();
        assert_eq!(deep, "deep content");

        let shallow = fs::read_to_string(extract_dir.join("a/shallow.txt")).unwrap();
        assert_eq!(shallow, "shallow");
    }

    #[test]
    fn test_verify_valid_archive() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("verify.era");
        let password = "test";

        // Create archive with multiple files
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .build()
            .unwrap();

        writer.add_bytes("file1.txt", b"Hello, World!").unwrap();
        writer.add_bytes("file2.txt", b"More content here").unwrap();
        writer.add_bytes("binary.bin", &[0u8; 1024]).unwrap();
        writer.finalize().unwrap();

        // Verify the archive
        let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
        let stats = reader.verify().unwrap();

        assert!(stats.is_ok(), "Verification should pass");
        assert!(stats.blocks_verified > 0);
        assert_eq!(stats.blocks_failed, 0);
        assert_eq!(stats.files_verified, 3);
        assert_eq!(stats.files_incomplete, 0);
        assert!(stats.errors.is_empty());
    }

    #[test]
    fn test_verify_large_chunked_file() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("chunked.era");
        let password = "test";

        // Create archive with large file that gets chunked
        let large_data = vec![b'A'; 512 * 1024]; // 512KB
        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .build()
            .unwrap();

        writer.add_bytes("large.bin", &large_data).unwrap();
        writer.finalize().unwrap();

        // Verify the archive
        let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
        let stats = reader.verify().unwrap();

        assert!(stats.is_ok(), "Verification should pass for chunked file");
        assert!(stats.bytes_verified > 0);
    }

    #[test]
    fn test_verify_empty_archive() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("empty.era");
        let password = "test";

        // Create empty archive
        let writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .build()
            .unwrap();
        writer.finalize().unwrap();

        // Verify empty archive
        let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
        let stats = reader.verify().unwrap();

        assert!(stats.is_ok(), "Empty archive should verify ok");
        assert_eq!(stats.files_verified, 0);
    }

    #[test]
    fn test_validate_block_size_zero() {
        // Zero-length block should be rejected
        let result = super::validate_block_size(0, 1000);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Zero-length"),
            "Error should mention zero-length: {}",
            err
        );
    }

    #[test]
    fn test_validate_block_size_too_large() {
        // Block larger than MAX_BLOCK_SIZE should be rejected
        let result = super::validate_block_size(super::MAX_BLOCK_SIZE + 1, 2000);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("too large"),
            "Error should mention too large: {}",
            err
        );
    }

    #[test]
    fn test_validate_block_size_valid() {
        // Valid block sizes should pass
        assert!(super::validate_block_size(1, 0).is_ok());
        assert!(super::validate_block_size(1024, 0).is_ok());
        assert!(super::validate_block_size(super::MAX_BLOCK_SIZE, 0).is_ok());
    }

    #[test]
    fn test_max_declared_file_size_constant() {
        // Verify MAX_DECLARED_FILE_SIZE is 100GB
        assert_eq!(super::MAX_DECLARED_FILE_SIZE, 100 * 1024 * 1024 * 1024);
    }
}
