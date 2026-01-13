//! Archive reader - extracts files from ERA archives.

use crate::block_iter::{BlockIterator, ErasureBlockIterator, StandardBlockIterator};
pub use crate::chunk_processor::{ExtractStats, VerifyStats};
use crate::chunk_processor::{ExtractionContext, MultiChunkState, VerificationContext};
use bytes::Bytes;
use era_codec::ZstdCompressor;
use era_common::{BlockId, BlockLocation, ChunkHash, EraError, Result};
use era_crypto::{derive_key, KdfParams, Salt};
use era_ingest::{Catalog, FileEntry};
use era_packing::{ErasureBlockUnpacker, MacroBlockUnpacker};
use era_storage::LocalStorageBackend;
use era_volume::{SuperHeader, VolumeReader};
use std::fs::{self, File};
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

/// Reader for ERA archives
pub struct ArchiveReader {
    volume_readers: Vec<VolumeReader<era_storage::LocalStorageReader>>,
    unpacker: MacroBlockUnpacker,
    erasure_unpacker: ErasureBlockUnpacker,
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
        let base_filename = path.file_name().unwrap_or_default();

        // 1. Open primary volume
        let mut volume_readers = Vec::new();
        let primary_reader = VolumeReader::open(&backend, Path::new(base_filename))?;
        volume_readers.push(primary_reader);

        // 2. Discover and open subsequent volumes
        // Assumes naming convention: file.era.001, file.era.002, etc.
        let mut i = 1;
        loop {
            let p = PathBuf::from(base_filename);
            let mut file_name = p.as_os_str().to_os_string();
            file_name.push(format!(".{:03}", i));
            let sub_path = PathBuf::from(file_name);

            // Check if file exists relative to backend (parent_dir)
            if !parent_dir.join(&sub_path).exists() {
                break;
            }

            match VolumeReader::open(&backend, &sub_path) {
                Ok(reader) => {
                    volume_readers.push(reader);
                    i += 1;
                }
                Err(e) => {
                    tracing::warn!("Failed to open volume {}: {}", sub_path.display(), e);
                    break;
                }
            }
        }

        info!("Opened {} volumes", volume_readers.len());

        let volume_reader = &volume_readers[0]; // Primary

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

        // Create unpackers with salt as nonce context (must match encryption)
        let nonce_context = header.crypto_anchor.salt;
        let compressor: Box<dyn era_codec::Compressor> = match header.config.compression.algorithm {
            era_common::CompressionAlgorithm::None => Box::new(era_codec::NoCompressor),
            era_common::CompressionAlgorithm::Zstd => {
                Box::new(ZstdCompressor::new(header.config.compression.level))
            }
        };
        let unpacker = MacroBlockUnpacker::new(key.clone(), nonce_context, compressor);

        // Create erasure unpacker for reading erasure-coded blocks
        let erasure_compressor: Box<dyn era_codec::Compressor> =
            match header.config.compression.algorithm {
                era_common::CompressionAlgorithm::None => Box::new(era_codec::NoCompressor),
                era_common::CompressionAlgorithm::Zstd => {
                    Box::new(ZstdCompressor::new(header.config.compression.level))
                }
            };
        let erasure_unpacker = ErasureBlockUnpacker::new(key, nonce_context, erasure_compressor);

        Ok(Self {
            volume_readers,
            unpacker,
            erasure_unpacker,
            catalog: None,
        })
    }

    /// Get the archive header
    pub fn header(&self) -> &SuperHeader {
        self.volume_readers[0].header()
    }

    /// Load the catalog (stored as the last block before footer)
    pub fn load_catalog(&mut self) -> Result<&Catalog> {
        if self.catalog.is_some() {
            return Ok(self.catalog.as_ref().unwrap());
        }

        let block_count = self.volume_readers[0].block_count();
        if block_count == 0 {
            return Err(EraError::other("Archive is empty"));
        }

        // Try to use catalog location from footer (O(1) lookup)
        let footer = self.volume_readers[0].footer();
        let catalog_location = if footer.has_catalog_location() {
            debug!(
                "Using footer catalog location: offset={}, size={}, block_id={}",
                footer.catalog_offset, footer.catalog_size, footer.catalog_block_id
            );
            BlockLocation {
                volume_id: self.volume_readers[0].header().volume_id,
                slot_index: footer.catalog_block_id,
                physical_offset: footer.catalog_offset,
                encrypted_size: footer.catalog_size,
                erasure_info: None,
                shard_offsets: None,
            }
        } else {
            // Fallback: scan for catalog (O(n) - for backwards compatibility)
            debug!("Footer lacks catalog location, scanning blocks...");
            self.scan_for_last_block()?
        };

        let encrypted_block = self.volume_readers[0].read_block(&catalog_location)?;
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
        let (data_start, data_end) = self.volume_readers[0].data_region();
        let block_count = self.volume_readers[0].block_count();

        let mut offset = data_start;
        let mut last_block_offset = data_start;
        let mut last_block_size = 0u32;

        while offset < data_end {
            let len_bytes = self.volume_readers[0].read_raw(offset, 4)?;
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
            volume_id: self.volume_readers[0].header().volume_id,
            slot_index: block_count - 1,
            physical_offset: last_block_offset,
            encrypted_size: last_block_size,
            erasure_info: None,
            shard_offsets: None,
        })
    }

    /// Read a block and extract all chunks, handling both erasure and non-erasure blocks
    ///
    /// This is the unified entry point for reading blocks. It automatically detects
    /// whether the block is erasure-coded based on `location.erasure_info` and uses
    /// the appropriate unpacker.
    pub fn read_and_extract_chunks(
        &self,
        location: &BlockLocation,
    ) -> Result<Vec<(ChunkHash, Bytes)>> {
        if let Some(ref erasure_info) = location.erasure_info {
            // Erasure-coded block: read shards from multiple volumes
            let num_readers = self.volume_readers.len();
            let total_shards =
                erasure_info.data_shards as usize + erasure_info.parity_shards as usize;

            let mut available_shards = Vec::with_capacity(total_shards);

            // Check shard offsets
            let shard_offsets = location
                .shard_offsets
                .as_ref()
                .ok_or_else(|| EraError::other("Missing shard offsets for erasure block"))?;

            // Read Shard 0 (Header + Data) on Volume 0
            // Note: physical_offset points to 4-byte original_len header
            if let Ok(shard) =
                self.read_shard(&self.volume_readers[0], location.physical_offset + 4)
            {
                available_shards.push((0, shard));
            }

            // Read other shards (1..N)
            for (i, &offset) in shard_offsets.iter().enumerate() {
                let shard_idx = i + 1;
                let vol_idx = shard_idx % num_readers;
                if let Ok(shard) = self.read_shard(&self.volume_readers[vol_idx], offset) {
                    available_shards.push((shard_idx, shard));
                }
            }

            let block_id = BlockId::new(location.slot_index as u64);
            self.erasure_unpacker
                .decode_and_extract_all(available_shards, erasure_info, block_id)
        } else {
            // Standard block: read and unpack directly
            let encrypted_block = self.volume_readers[0].read_block(location)?;
            self.unpacker.extract_all_chunks(&encrypted_block)
        }
    }

    fn read_shard<R: era_storage::StorageReader>(
        &self,
        reader: &VolumeReader<R>,
        offset: u64,
    ) -> Result<Bytes> {
        let header_bytes = reader.read_raw(offset, era_common::ShardHeader::SIZE)?;
        if let Some(header) = era_common::ShardHeader::from_bytes(&header_bytes) {
            let data = reader.read_raw(
                offset + era_common::ShardHeader::SIZE as u64,
                header.length as usize,
            )?;
            if header.verify(&data) {
                return Ok(data);
            }
        }
        Err(EraError::other("Shard verification failed"))
    }

    /// List all files in the archive
    pub fn list_files(&mut self) -> Result<Vec<&FileEntry>> {
        let catalog = self.load_catalog()?;
        Ok(catalog.entries.iter().collect())
    }

    /// Extract using the provided block iterator
    fn extract_with_iterator(
        catalog: &Catalog,
        iter: &mut Box<dyn BlockIterator + '_>,
        options: &ExtractOptions,
    ) -> Result<ExtractStats> {
        let mut stats = ExtractStats::default();

        // Build maps for extraction
        let mut context = ExtractionContext::new();

        for (file_idx, entry) in catalog.entries.iter().enumerate() {
            let output_path = options.output_dir.join(&entry.path);

            if output_path.exists() && !options.overwrite {
                debug!("Skipping existing file: {}", output_path.display());
                stats.skipped += 1;
                continue;
            }

            if entry.size > MAX_DECLARED_FILE_SIZE {
                return Err(EraError::CorruptedHeader(format!(
                    "File '{}' declares unreasonable size: {} bytes",
                    entry.path.display(),
                    entry.size
                )));
            }

            if entry.is_chunked() {
                let chunk_count = entry.chunks.len();
                if let Some(parent) = output_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let file = File::create(&output_path)?;
                file.set_len(entry.size)?;

                context.multi_chunk_files.insert(
                    file_idx,
                    MultiChunkState {
                        file,
                        output_path,
                        expected_size: entry.size,
                        chunks_written: vec![false; chunk_count],
                        total_chunks: chunk_count,
                        written_count: 0,
                    },
                );

                for (chunk_idx, chunk_ref) in entry.chunks.iter().enumerate() {
                    context
                        .chunk_to_files
                        .entry(chunk_ref.hash)
                        .or_default()
                        .push((file_idx, chunk_idx, chunk_ref.offset));
                }
            } else if let Some(content_hash) = entry.content_hash {
                context
                    .single_chunk_pending
                    .entry(content_hash)
                    .or_default()
                    .push((file_idx, output_path));
            }
        }

        if !context.has_pending() {
            info!("No files to extract");
            return Ok(stats);
        }

        while let Some(result) = iter.next_block() {
            match result {
                Ok(decoded) => {
                    context.process_chunks(decoded.chunks, &mut stats)?;
                }
                Err(e) => {
                    return Err(e);
                }
            }
            if !context.has_pending() {
                break;
            }
        }

        context.log_incomplete_files();

        info!(
            "Extraction complete: {} files, {} bytes",
            stats.extracted, stats.bytes_written
        );

        Ok(stats)
    }

    /// Verify using the provided block iterator
    fn verify_with_iterator(
        catalog: &Catalog,
        iter: &mut Box<dyn BlockIterator + '_>,
    ) -> Result<VerifyStats> {
        let mut stats = VerifyStats::default();

        let mut context = VerificationContext::new(catalog.entries.len());

        for (file_idx, entry) in catalog.entries.iter().enumerate() {
            if entry.is_chunked() {
                context.file_chunk_counts.push(entry.chunks.len());
                for (chunk_idx, chunk_ref) in entry.chunks.iter().enumerate() {
                    context
                        .expected_chunks
                        .entry(chunk_ref.hash)
                        .or_default()
                        .push((file_idx, chunk_idx, chunk_ref.length as u64));
                }
            } else if let Some(content_hash) = entry.content_hash {
                context.file_chunk_counts.push(1);
                context
                    .expected_chunks
                    .entry(content_hash)
                    .or_default()
                    .push((file_idx, 0, entry.size));
            } else {
                context.file_chunk_counts.push(0);
            }
        }

        while let Some(result) = iter.next_block() {
            match result {
                Ok(decoded) => {
                    stats.blocks_verified += 1;
                    if decoded.corrupted_shards > 0 {
                        stats.errors.push(format!(
                            "Block {}: recovered from {} corrupted shards",
                            decoded.block_index, decoded.corrupted_shards
                        ));
                    }
                    context.process_chunks(&decoded.chunks, decoded.block_index, &mut stats);
                }
                Err(e) => {
                    stats.blocks_failed += 1;
                    stats.errors.push(format!("Block logic error: {}", e));
                }
            }
        }

        context.check_file_completeness(&mut stats, |idx| {
            catalog
                .entries
                .get(idx)
                .map(|e| e.path.display().to_string())
                .unwrap_or_default()
        });

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

    /// Extract all files to the given directory
    ///
    /// This optimized implementation uses single-pass extraction:
    /// - Reads and decrypts each block only once
    /// - Builds hash→path mapping from catalog
    /// - Writes files directly during block scan
    /// - Supports multi-chunk files (CDC mode) with pre-created files to avoid OOM
    /// - Supports erasure-coded archives (reads shard groups and decodes)
    pub fn extract_all(&mut self, options: &ExtractOptions) -> Result<ExtractStats> {
        info!("Extracting to: {}", options.output_dir.display());

        self.load_catalog()?;
        let catalog = self.catalog.as_ref().unwrap();

        // Check if erasure coding is enabled
        let erasure_config = self.volume_readers[0].header().config.erasure;

        let mut iter: Box<dyn BlockIterator> = if let Some(config) = erasure_config {
            Box::new(ErasureBlockIterator::new(
                &self.volume_readers,
                &self.erasure_unpacker,
                config.data_shards,
                config.parity_shards,
            ))
        } else {
            Box::new(StandardBlockIterator::new(
                &self.volume_readers[0],
                &self.unpacker,
            ))
        };

        Self::extract_with_iterator(catalog, &mut iter, options)
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

        self.load_catalog()?;
        let catalog = self.catalog.as_ref().unwrap();

        // Check if erasure coding is enabled
        let erasure_config = self.volume_readers[0].header().config.erasure;

        let mut iter: Box<dyn BlockIterator> = if let Some(config) = erasure_config {
            Box::new(ErasureBlockIterator::new(
                &self.volume_readers,
                &self.erasure_unpacker,
                config.data_shards,
                config.parity_shards,
            ))
        } else {
            Box::new(StandardBlockIterator::new(
                &self.volume_readers[0],
                &self.unpacker,
            ))
        };

        Self::verify_with_iterator(catalog, &mut iter)
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

    #[test]
    fn test_erasure_simple_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("erasure.era");
        let password = "test";

        // Create archive with erasure coding
        let erasure_config = era_common::ErasureCodeConfig {
            data_shards: 4,
            parity_shards: 2,
        };

        let mut writer = ArchiveWriter::builder(&archive_path)
            .password(password)
            .erasure_config(erasure_config)
            .build()
            .unwrap();

        writer
            .add_bytes("test.txt", b"Hello, Erasure World!")
            .unwrap();
        let stats = writer.finalize().unwrap();
        assert_eq!(stats.total_files, 1);

        // Extract and verify
        let mut reader = ArchiveReader::open(&archive_path, password).unwrap();
        let extract_dir = temp_dir.path().join("extracted");
        let options = ExtractOptions::new(&extract_dir);
        let extract_stats = reader.extract_all(&options).unwrap();

        assert_eq!(extract_stats.extracted, 1);

        let content = std::fs::read_to_string(extract_dir.join("test.txt")).unwrap();
        assert_eq!(content, "Hello, Erasure World!");
    }
}
