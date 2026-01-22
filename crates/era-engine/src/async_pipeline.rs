//! # Async Chunk Processing Pipeline with Backpressure
//!
//! **Philosophy:** "Ruthless Efficiency" - CPU cycles are money, I/O is the enemy.
//!
//! ## Design Goals
//!
//! 1. **Prevent OOM**: Limit concurrent chunk processing to prevent memory exhaustion
//! 2. **Maximize Throughput**: Offload CPU-bound work to blocking threadpool
//! 3. **Minimize Latency**: Use async I/O for all storage operations
//! 4. **Backpressure**: Gracefully handle slow consumers
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────┐
//! │   Ingest    │───▶│ Hash+Compress│───▶│   Encrypt   │───▶│    Write     │
//! │   (Async)   │    │  (Blocking)  │    │  (Blocking) │    │   (Async)    │
//! └─────────────┘    └──────────────┘    └─────────────┘    └──────────────┘
//!      ▲                   │                    │                   │
//!      │                   ▼                    ▼                   ▼
//!      └─────────────── Semaphore (64) ──────────────────────────────┘
//!                     (Backpressure Control)
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! use era_engine::async_pipeline::{ChunkPipeline, PipelineConfig};
//!
//! let config = PipelineConfig {
//!     max_concurrent_chunks: 64,
//!     channel_buffer: 128,
//! };
//!
//! let pipeline = ChunkPipeline::new(config);
//!
//! // Submit chunk for processing
//! let hash = pipeline.process_chunk(chunk_data).await?;
//!
//! // Receive processed chunk
//! while let Some((hash, compressed)) = pipeline.recv().await {
//!     // Write to storage
//! }
//! ```

use bytes::Bytes;
use era_common::{ChunkHash, EraError, Result};
use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};
use tokio::task;

/// Configuration for the async chunk pipeline
#[derive(Clone, Debug)]
pub struct PipelineConfig {
    /// Maximum number of chunks being processed concurrently
    ///
    /// This prevents OOM by limiting memory usage to roughly:
    /// `max_concurrent_chunks * avg_chunk_size * 3` (raw + compressed + encrypted)
    ///
    /// Recommended: 64 for 8GB RAM, 128 for 16GB RAM, 256 for 32GB+ RAM
    pub max_concurrent_chunks: usize,

    /// Buffer size for the output channel
    ///
    /// Should be >= max_concurrent_chunks to avoid blocking producers.
    /// Recommended: 2x max_concurrent_chunks for headroom
    pub channel_buffer: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            max_concurrent_chunks: 64,
            channel_buffer: 128,
        }
    }
}

/// Async chunk processing pipeline with backpressure control
///
/// This pipeline coordinates CPU-bound (hashing, compression, encryption) and
/// I/O-bound (reading, writing) operations efficiently using Tokio's async runtime.
///
/// **Key Features:**
/// - Automatic backpressure via Semaphore
/// - CPU-bound work offloaded to blocking threadpool
/// - Non-blocking I/O for all storage operations
/// - Graceful degradation under load
pub struct ChunkPipeline {
    /// Semaphore for backpressure control
    semaphore: Arc<Semaphore>,
    /// Sender for processed chunks
    sender: mpsc::Sender<ProcessedChunk>,
    /// Receiver for processed chunks
    receiver: mpsc::Receiver<ProcessedChunk>,
    /// Pipeline configuration
    config: PipelineConfig,
}

/// A chunk that has been processed (hashed and optionally compressed)
#[derive(Debug, Clone)]
pub struct ProcessedChunk {
    /// Content hash (Blake3)
    pub hash: ChunkHash,
    /// Processed data (may be compressed)
    pub data: Bytes,
    /// Original size before compression
    pub original_size: usize,
    /// Size after compression (may equal original_size if not compressed)
    pub compressed_size: usize,
}

impl ChunkPipeline {
    /// Create a new async chunk pipeline with the given configuration
    pub fn new(config: PipelineConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_chunks));
        let (sender, receiver) = mpsc::channel(config.channel_buffer);

        Self {
            semaphore,
            sender,
            receiver,
            config,
        }
    }

    /// Submit a chunk for processing
    ///
    /// This method:
    /// 1. Acquires a semaphore permit (blocks if at concurrency limit)
    /// 2. Offloads CPU-bound work (hashing) to blocking threadpool
    /// 3. Sends result to output channel
    /// 4. Returns immediately with chunk hash
    ///
    /// **Backpressure:** If `max_concurrent_chunks` permits are in use, this will
    /// wait until a permit becomes available. This prevents memory exhaustion.
    ///
    /// ## Example
    ///
    /// ```rust,ignore
    /// let hash = pipeline.process_chunk(chunk_data).await?;
    /// ```
    pub async fn process_chunk(&self, data: Bytes) -> Result<ChunkHash> {
        // Acquire permit (blocks if at concurrency limit)
        let permit =
            self.semaphore.clone().acquire_owned().await.map_err(|e| {
                EraError::AsyncError(format!("Semaphore acquisition failed: {}", e))
            })?;

        let sender = self.sender.clone();
        let original_size = data.len();

        // Offload CPU-bound work to blocking threadpool
        let hash = task::spawn_blocking(move || {
            // Compute Blake3 hash
            let hash_result = era_crypto::hash(&data);
            let hash = ChunkHash::from_bytes(*hash_result.as_bytes());

            // TODO: Add compression here if needed
            // For now, pass through uncompressed
            let compressed_data = data;
            let compressed_size = compressed_data.len();

            let processed = ProcessedChunk {
                hash,
                data: compressed_data,
                original_size,
                compressed_size,
            };

            // Send to output channel
            // Note: This is a blocking send, which is fine in spawn_blocking
            if sender.blocking_send(processed).is_err() {
                // Receiver dropped, pipeline is shutting down
                tracing::warn!("Pipeline receiver dropped, discarding chunk");
            }

            // Release permit when done
            drop(permit);

            hash
        })
        .await
        .map_err(|e| EraError::AsyncError(format!("Task join failed: {}", e)))?;

        Ok(hash)
    }

    /// Submit a chunk for processing with compression
    ///
    /// This variant compresses the chunk data before hashing (for testing
    /// compressed vs uncompressed hashing strategies).
    ///
    /// **Note:** In production, you typically hash the original data, not the
    /// compressed data, for deduplication purposes.
    pub async fn process_chunk_with_compression(
        &self,
        data: Bytes,
        compression_level: i32,
    ) -> Result<ChunkHash> {
        let permit =
            self.semaphore.clone().acquire_owned().await.map_err(|e| {
                EraError::AsyncError(format!("Semaphore acquisition failed: {}", e))
            })?;

        let sender = self.sender.clone();
        let original_size = data.len();

        let hash = task::spawn_blocking(move || {
            // Compute hash on original data (for dedup)
            let hash_result = era_crypto::hash(&data);
            let hash = ChunkHash::from_bytes(*hash_result.as_bytes());

            // Compress data
            let compressed_data = compress_zstd(&data, compression_level);
            let compressed_size = compressed_data.len();

            let processed = ProcessedChunk {
                hash,
                data: compressed_data,
                original_size,
                compressed_size,
            };

            if sender.blocking_send(processed).is_err() {
                tracing::warn!("Pipeline receiver dropped, discarding chunk");
            }

            drop(permit);
            hash
        })
        .await
        .map_err(|e| EraError::AsyncError(format!("Task join failed: {}", e)))?;

        Ok(hash)
    }

    /// Receive a processed chunk from the pipeline
    ///
    /// This is the consumer side of the pipeline. Call this in a loop to
    /// process chunks as they become available.
    ///
    /// Returns `None` when all senders have been dropped.
    ///
    /// ## Example
    ///
    /// ```rust,ignore
    /// while let Some(processed) = pipeline.recv().await {
    ///     // Encrypt and write to storage
    ///     let location = write_chunk(&processed).await?;
    ///     index.insert(processed.hash, location)?;
    /// }
    /// ```
    pub async fn recv(&mut self) -> Option<ProcessedChunk> {
        self.receiver.recv().await
    }

    /// Try to receive a processed chunk without blocking
    ///
    /// Returns:
    /// - `Ok(Some(chunk))` if a chunk is available
    /// - `Ok(None)` if no chunks are currently available
    /// - `Err(EraError::ChannelClosed)` if all senders have been dropped
    pub fn try_recv(&mut self) -> Result<Option<ProcessedChunk>> {
        match self.receiver.try_recv() {
            Ok(chunk) => Ok(Some(chunk)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                Err(EraError::ChannelClosed("Pipeline senders dropped".into()))
            }
        }
    }

    /// Get the current number of available permits
    ///
    /// This indicates how many more chunks can be submitted without blocking.
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Get a clone of the sender for use in other tasks
    ///
    /// This allows multiple tasks to submit chunks to the same pipeline.
    pub fn sender(&self) -> mpsc::Sender<ProcessedChunk> {
        self.sender.clone()
    }

    /// Get the pipeline configuration
    pub fn config(&self) -> &PipelineConfig {
        &self.config
    }
}

/// Compress data using Zstandard
///
/// This is a helper function for CPU-bound compression work.
/// It should be called from within `spawn_blocking`.
fn compress_zstd(data: &[u8], level: i32) -> Bytes {
    use zstd::stream::encode_all;

    match encode_all(data, level) {
        Ok(compressed) => Bytes::from(compressed),
        Err(e) => {
            tracing::warn!("Compression failed: {}, using uncompressed data", e);
            Bytes::copy_from_slice(data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pipeline_basic() {
        let config = PipelineConfig {
            max_concurrent_chunks: 4,
            channel_buffer: 8,
        };

        let mut pipeline = ChunkPipeline::new(config);

        // Submit a chunk
        let data = Bytes::from_static(b"Hello, World!");
        let hash = pipeline.process_chunk(data.clone()).await.unwrap();

        // Receive processed chunk
        let processed = pipeline.recv().await.unwrap();
        assert_eq!(processed.hash, hash);
        assert_eq!(processed.data, data);
        assert_eq!(processed.original_size, data.len());
    }

    #[tokio::test]
    async fn test_pipeline_multiple_chunks() {
        let config = PipelineConfig {
            max_concurrent_chunks: 4,
            channel_buffer: 8,
        };

        let mut pipeline = ChunkPipeline::new(config);

        // Submit multiple chunks
        let chunks = vec![
            Bytes::from_static(b"Chunk 1"),
            Bytes::from_static(b"Chunk 2"),
            Bytes::from_static(b"Chunk 3"),
        ];

        let mut hashes = Vec::new();
        for chunk in &chunks {
            let hash = pipeline.process_chunk(chunk.clone()).await.unwrap();
            hashes.push(hash);
        }

        // Receive all processed chunks
        let mut received = Vec::new();
        for _ in 0..chunks.len() {
            let processed = pipeline.recv().await.unwrap();
            received.push(processed);
        }

        assert_eq!(received.len(), chunks.len());
    }

    #[tokio::test]
    async fn test_pipeline_backpressure() {
        let config = PipelineConfig {
            max_concurrent_chunks: 2,
            channel_buffer: 4,
        };

        let pipeline = ChunkPipeline::new(config);

        // Submit more chunks than the semaphore allows
        let data = Bytes::from_static(b"Test chunk");

        // These should complete without blocking (we have 2 permits)
        let _hash1 = pipeline.process_chunk(data.clone()).await.unwrap();
        let _hash2 = pipeline.process_chunk(data.clone()).await.unwrap();

        // This should still work because permits are released after processing
        let _hash3 = pipeline.process_chunk(data.clone()).await.unwrap();

        assert_eq!(pipeline.available_permits(), 2);
    }

    #[tokio::test]
    async fn test_pipeline_compression() {
        let config = PipelineConfig::default();
        let mut pipeline = ChunkPipeline::new(config);

        // Create compressible data (repeated pattern)
        let data = Bytes::from(vec![b'A'; 1024]);
        let hash = pipeline
            .process_chunk_with_compression(data.clone(), 3)
            .await
            .unwrap();

        let processed = pipeline.recv().await.unwrap();
        assert_eq!(processed.hash, hash);
        assert_eq!(processed.original_size, 1024);
        // Compressed size should be significantly smaller
        assert!(processed.compressed_size < processed.original_size);
    }

    #[tokio::test]
    async fn test_pipeline_try_recv() {
        let config = PipelineConfig::default();
        let mut pipeline = ChunkPipeline::new(config);

        // Try recv on empty pipeline
        assert!(pipeline.try_recv().unwrap().is_none());

        // Submit a chunk
        let data = Bytes::from_static(b"Test");
        let _hash = pipeline.process_chunk(data).await.unwrap();

        // Give it a moment to process
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Should now have a chunk available
        assert!(pipeline.try_recv().unwrap().is_some());
    }
}
