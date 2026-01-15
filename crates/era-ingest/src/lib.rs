//! # ERA Ingest
//!
//! File ingestion for the ERA archive system.
//!
//! This crate provides the L5 (Ingest) and L4 (Chunking) layer implementations.
//!
//! ## L5 Ingest Layer
//! - File reading and metadata extraction
//! - Directory traversal (future)
//!
//! ## L4 Chunking Layer
//! - FastCDC content-defined chunking
//! - Streaming chunker for large files
//! - Configurable chunk sizes

mod chunker;
mod entry;
mod reader;

pub use chunker::{
    ChunkIterator, Chunker, ChunkerConfig, StreamingChunker, DEFAULT_AVG_SIZE, DEFAULT_MAX_SIZE,
    DEFAULT_MIN_SIZE,
};
pub use entry::{Catalog, ChunkRef, FileEntry, FileType, PackedChunkInfo};
pub use reader::{DirectoryScanner, FileReader, ScanOptions};
