//! Chunk processing utilities for extraction and verification.
//!
//! This module provides shared logic for processing chunks during extraction,
//! eliminating code duplication between standard and erasure-coded paths.
//!
//! Note: These types are currently prepared for future refactoring.
//! The reader.rs module still uses its own implementations for now.

#![allow(dead_code)]

use bytes::Bytes;
use era_common::{ChunkHash, Result};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use tracing::debug;

/// State for tracking multi-chunk file extraction
/// Uses pre-created files to avoid OOM on large files
pub struct MultiChunkState {
    /// Open file handle for writing chunks directly
    pub file: File,
    /// Output path for logging
    pub output_path: PathBuf,
    /// Expected file size (sum of all chunk lengths)
    pub expected_size: u64,
    /// Track which chunks have been written (for completion check)
    pub chunks_written: Vec<bool>,
    /// Total number of chunks expected
    pub total_chunks: usize,
    /// Number of chunks written so far
    pub written_count: usize,
}

/// Context for chunk-based extraction
/// Maintains the state needed to route chunks to their target files
pub struct ExtractionContext {
    /// Single-chunk pending: hash -> list of (file_idx, output_path)
    pub single_chunk_pending: HashMap<ChunkHash, Vec<(usize, PathBuf)>>,
    /// Multi-chunk file states: file_idx -> state
    pub multi_chunk_files: HashMap<usize, MultiChunkState>,
    /// Chunk to files mapping: hash -> list of (file_idx, chunk_idx, offset)
    pub chunk_to_files: HashMap<ChunkHash, Vec<(usize, usize, u64)>>,
}

impl ExtractionContext {
    /// Create a new empty extraction context
    pub fn new() -> Self {
        Self {
            single_chunk_pending: HashMap::new(),
            multi_chunk_files: HashMap::new(),
            chunk_to_files: HashMap::new(),
        }
    }

    /// Check if there are still files pending extraction
    pub fn has_pending(&self) -> bool {
        !self.single_chunk_pending.is_empty() || !self.multi_chunk_files.is_empty()
    }

    /// Process a batch of chunks from a decoded block
    ///
    /// This handles:
    /// - Single-chunk files: create and write file directly
    /// - Multi-chunk files: write chunk at correct offset in pre-created file
    ///
    /// Returns the number of files completed and bytes written
    pub fn process_chunks(
        &mut self,
        chunks: Vec<(ChunkHash, Bytes)>,
        stats: &mut ExtractStats,
    ) -> Result<()> {
        for (hash, data) in chunks {
            // Handle single-chunk files
            if let Some(entries) = self.single_chunk_pending.remove(&hash) {
                for (_file_idx, output_path) in entries {
                    // Create parent directories
                    if let Some(parent) = output_path.parent() {
                        fs::create_dir_all(parent)?;
                    }

                    // Write file directly
                    let mut file = File::create(&output_path)?;
                    file.write_all(&data)?;

                    debug!("Extracted: {}", output_path.display());
                    stats.extracted += 1;
                    stats.bytes_written += data.len() as u64;
                }
            }

            // Handle multi-chunk files
            if let Some(file_refs) = self.chunk_to_files.remove(&hash) {
                for (file_idx, chunk_idx, chunk_offset) in file_refs {
                    if let Some(state) = self.multi_chunk_files.get_mut(&file_idx) {
                        // Seek to correct position and write chunk
                        state.file.seek(SeekFrom::Start(chunk_offset))?;
                        state.file.write_all(&data)?;

                        state.chunks_written[chunk_idx] = true;
                        state.written_count += 1;

                        // Check if all chunks are written
                        if state.written_count == state.total_chunks {
                            state.file.sync_all()?;

                            debug!("Extracted (chunked): {}", state.output_path.display());
                            stats.extracted += 1;
                            stats.bytes_written += state.expected_size;

                            // Remove completed file from tracking
                            self.multi_chunk_files.remove(&file_idx);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Log warnings for any incomplete files
    pub fn log_incomplete_files(&self) {
        for (_, state) in self.multi_chunk_files.iter() {
            if state.written_count > 0 {
                debug!(
                    "Warning: Incomplete file: {} ({}/{})",
                    state.output_path.display(),
                    state.written_count,
                    state.total_chunks
                );
            }
        }
    }
}

impl Default for ExtractionContext {
    fn default() -> Self {
        Self::new()
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

/// Context for verification
/// Tracks expected chunks and which files have received them
pub struct VerificationContext {
    /// Expected chunks: hash -> list of (file_idx, chunk_idx, expected_len)
    pub expected_chunks: HashMap<ChunkHash, Vec<(usize, usize, u64)>>,
    /// Number of chunks expected per file
    pub file_chunk_counts: Vec<usize>,
    /// Number of chunks found per file
    pub file_chunks_found: Vec<usize>,
}

impl VerificationContext {
    /// Create a new verification context with given file count
    pub fn new(file_count: usize) -> Self {
        Self {
            expected_chunks: HashMap::new(),
            file_chunk_counts: Vec::with_capacity(file_count),
            file_chunks_found: vec![0; file_count],
        }
    }

    /// Process a batch of chunks from a decoded block for verification
    ///
    /// Returns the number of bytes verified in this batch
    pub fn process_chunks(
        &mut self,
        chunks: &[(ChunkHash, Bytes)],
        block_index: u32,
        stats: &mut VerifyStats,
    ) {
        for (hash, data) in chunks {
            stats.bytes_verified += data.len() as u64;

            // Verify chunk hash matches content
            let computed_hash = era_crypto::hash(data);
            if computed_hash != *hash {
                stats.errors.push(format!(
                    "Block {}: chunk hash mismatch (expected {:?}, got {:?})",
                    block_index, hash, computed_hash
                ));
            }

            // Track which files got their chunks
            if let Some(file_refs) = self.expected_chunks.get(hash) {
                for (file_idx, _, expected_len) in file_refs {
                    if data.len() as u64 == *expected_len {
                        self.file_chunks_found[*file_idx] += 1;
                    } else {
                        stats.errors.push(format!(
                            "Block {}: chunk length mismatch for file {} (expected {}, got {})",
                            block_index,
                            file_idx,
                            expected_len,
                            data.len()
                        ));
                    }
                }
            }
        }
    }

    /// Check file completeness and update stats
    pub fn check_file_completeness<F: Fn(usize) -> String>(
        &self,
        stats: &mut VerifyStats,
        get_file_path: F,
    ) {
        for file_idx in 0..self.file_chunk_counts.len() {
            let expected = self.file_chunk_counts[file_idx];
            let found = self.file_chunks_found[file_idx];

            if expected == 0 {
                continue;
            }

            if found == expected {
                stats.files_verified += 1;
            } else {
                stats.files_incomplete += 1;
                stats.errors.push(format!(
                    "File '{}': missing {} of {} chunks",
                    get_file_path(file_idx),
                    expected - found,
                    expected
                ));
            }
        }
    }
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

    #[test]
    fn test_extraction_context_new() {
        let ctx = ExtractionContext::new();
        assert!(ctx.single_chunk_pending.is_empty());
        assert!(ctx.multi_chunk_files.is_empty());
        assert!(ctx.chunk_to_files.is_empty());
        assert!(!ctx.has_pending());
    }

    #[test]
    fn test_verification_context_new() {
        let ctx = VerificationContext::new(10);
        assert!(ctx.expected_chunks.is_empty());
        assert_eq!(ctx.file_chunks_found.len(), 10);
    }

    #[test]
    fn test_verify_stats_is_ok() {
        let stats = VerifyStats::default();
        assert!(stats.is_ok());

        let failed_stats = VerifyStats {
            blocks_failed: 1,
            ..Default::default()
        };
        assert!(!failed_stats.is_ok());
    }
}
