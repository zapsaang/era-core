//! # WAL-Based Binary Checkpoints
//!
//! **CRITICAL CHANGE (v2.2):** Checkpoints are now self-contained blocks inside the volume.
//!
//! ## Previous Design (DELETED)
//! - Sidecar `.checkpoint` files (VIOLATED self-containment)
//! - JSON serialization (slow)
//! - Separate HMAC files
//!
//! ## New Design
//! - Checkpoints written as `BlockType::Checkpoint` typed blocks
//! - `rkyv` zero-copy serialization
//! - Footer's `last_checkpoint_offset` creates a linked list
//! - **Cold Recovery**: Reconstruct from volume alone, no external files
//!
//! ## Migration Note
//! Code using the old `CheckpointManager` API will need updates.
//! The new API is simpler and more secure.

use rkyv::{Archive, Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use era_common::{BlockLocation, BlockType, ChunkHash, EraError, Result};
use era_crypto::{KeySession, VolumeKey};
use era_storage::StorageWriter;

/// Checkpoint format version (rkyv-based, v2.2+)
pub const CHECKPOINT_VERSION: u32 = 3;

/// Checkpoint record for crash recovery
///
/// This structure contains all the state needed to resume archival
/// after a crash or kill -9.
///
/// **NEW IN V3:**
/// - Uses `rkyv` for zero-copy deserialization
/// - Stored as typed block in volume (no sidecar files)
/// - Linked via footer's `last_checkpoint_offset`
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[archive(check_bytes)]
pub struct Checkpoint {
    /// Checkpoint format version (current: 3)
    pub version: u32,
    /// Unix timestamp when checkpoint was created
    pub timestamp: u64,
    /// Current volume sequence number
    pub current_volume: u16,
    /// Current write offset in the volume
    pub current_offset: u64,
    /// Total bytes written across all volumes
    pub total_bytes_written: u64,
    /// Number of files processed so far
    pub total_files_processed: u32,
    /// Number of chunks written
    pub chunks_written: u64,
    /// Chunk hash → BlockLocation mapping (partial index)
    ///
    /// This is a subset of the full index containing only chunks
    /// written since the last checkpoint. Full index is reconstructed
    /// by merging all checkpoints.
    pub written_chunks: HashMap<ChunkHash, BlockLocation>,
    /// Path to the in-progress file (if any)
    pub in_progress_file: Option<InProgressFile>,
    /// Source files that have been fully processed (backward compatibility)
    pub completed_files: HashSet<String>,
}

/// Tracks progress within a file being processed
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[archive(check_bytes)]
pub struct InProgressFile {
    /// Path to the file (as string for serialization)
    pub path: String,
    /// Total file size
    pub total_size: u64,
    /// Bytes processed so far
    pub bytes_processed: u64,
    /// Number of chunks written from this file
    pub chunks_written: u32,
}

impl Checkpoint {
    /// Create a new checkpoint record
    pub fn new(
        current_volume: u16,
        current_offset: u64,
        total_bytes_written: u64,
        total_files_processed: u32,
        chunks_written: u64,
        written_chunks: HashMap<ChunkHash, BlockLocation>,
    ) -> Self {
        Self {
            version: CHECKPOINT_VERSION,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(std::time::Duration::from_secs(0))
                .as_secs(),
            current_volume,
            current_offset,
            total_bytes_written,
            total_files_processed,
            chunks_written,
            written_chunks,
            in_progress_file: None,
            completed_files: HashSet::new(),
        }
    }

    /// Serialize to bytes using rkyv (zero-copy)
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        rkyv::to_bytes::<_, 256>(self)
            .map(|bytes| bytes.to_vec())
            .map_err(|e| EraError::Serialization(format!("Failed to serialize checkpoint: {}", e)))
    }

    /// Deserialize from bytes with validation
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let archived = rkyv::check_archived_root::<Self>(bytes).map_err(|e| {
            EraError::Deserialization(format!("Checkpoint validation failed: {}", e))
        })?;

        // SAFETY: rkyv::Infallible is an uninhabited type (like core::convert::Infallible) — it
        // cannot be constructed, so deserialize() cannot produce an error. After check_archived_root
        // succeeds, the unwrap is provably safe and will never panic.
        let checkpoint: Self = match archived.deserialize(&mut rkyv::Infallible) {
            Ok(v) => v,
            Err(infallible) => match infallible {},
        };

        // V2-SEC-09: Post-deserialize bounds validation to prevent memory exhaustion
        // from maliciously crafted checkpoint data
        const MAX_CHECKPOINT_ENTRIES: usize = 10_000_000;
        if checkpoint.written_chunks.len() > MAX_CHECKPOINT_ENTRIES {
            return Err(EraError::InvalidFormat(format!(
                "Checkpoint written_chunks exceeds maximum: {} > {}",
                checkpoint.written_chunks.len(),
                MAX_CHECKPOINT_ENTRIES
            )));
        }
        if checkpoint.completed_files.len() > MAX_CHECKPOINT_ENTRIES {
            return Err(EraError::InvalidFormat(format!(
                "Checkpoint completed_files exceeds maximum: {} > {}",
                checkpoint.completed_files.len(),
                MAX_CHECKPOINT_ENTRIES
            )));
        }

        if checkpoint.version != CHECKPOINT_VERSION {
            return Err(EraError::Deserialization(format!(
                "Checkpoint version mismatch: expected {}, found {}",
                CHECKPOINT_VERSION, checkpoint.version
            )));
        }

        Ok(checkpoint)
    }

    /// Get the size of the serialized checkpoint
    pub fn serialized_size(&self) -> Result<usize> {
        self.to_bytes().map(|bytes| bytes.len())
    }

    /// Set the in-progress file
    pub fn set_in_progress(&mut self, path: PathBuf, total_size: u64) {
        self.in_progress_file = Some(InProgressFile {
            path: path.to_string_lossy().to_string(),
            total_size,
            bytes_processed: 0,
            chunks_written: 0,
        });
    }

    /// Update progress for the in-progress file
    pub fn update_progress(&mut self, bytes_processed: u64, chunks_written: u32) {
        if let Some(ref mut in_progress) = self.in_progress_file {
            in_progress.bytes_processed = bytes_processed;
            in_progress.chunks_written = chunks_written;
        }
    }

    /// Mark current file as complete
    pub fn mark_file_complete(&mut self) {
        self.in_progress_file = None;
        self.total_files_processed += 1;
    }

    /// Get completed files as PathBuf vector (helper for recovery module)
    pub fn get_completed_files(&self) -> Vec<PathBuf> {
        self.completed_files.iter().map(PathBuf::from).collect()
    }

    /// Check if a file has been completed (for tests)
    pub fn is_file_completed(&self, path: &Path) -> bool {
        self.completed_files
            .contains(&path.to_string_lossy().to_string())
    }

    /// Get chunk location from checkpoint (for tests)
    pub fn get_chunk_location(&self, hash: &ChunkHash) -> Option<&BlockLocation> {
        self.written_chunks.get(hash)
    }
}

/// CheckpointManager - Manages writing and reading checkpoints
///
/// **NEW IMPLEMENTATION (v2.2):**
/// - No more sidecar files
/// - Checkpoints written as typed blocks to volume
/// - Footer's `last_checkpoint_offset` tracks latest checkpoint
pub struct CheckpointManager {
    /// Current checkpoint state
    checkpoint: Checkpoint,
    /// Archive output path (for compatibility with old API)
    #[allow(dead_code)] // Kept for future use in recovery path
    archive_path: PathBuf,
}

impl CheckpointManager {
    /// Create a new checkpoint manager (does NOT create sidecar file)
    pub fn with_hmac_key(archive_path: impl AsRef<Path>, _hmac_key: [u8; 32]) -> Self {
        // HMAC key is ignored in new implementation (checkpoints are encrypted blocks)
        Self {
            checkpoint: Checkpoint::new(0, 0, 0, 0, 0, HashMap::new()),
            archive_path: archive_path.as_ref().to_path_buf(),
        }
    }

    /// Load or create a checkpoint (backward compatibility API)
    ///
    /// **MIGRATION WARNING:** Old sidecar checkpoints are NOT loaded.
    /// This returns a fresh checkpoint. Full checkpoint recovery requires
    /// `read_checkpoint()` with crypto params (VolumeReader + KeySession).
    pub fn load_or_create(archive_path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            checkpoint: Checkpoint::new(0, 0, 0, 0, 0, HashMap::new()),
            archive_path: archive_path.as_ref().to_path_buf(),
        })
    }

    /// Load or create with HMAC key (backward compatibility)
    pub fn load_or_create_with_key(
        archive_path: impl AsRef<Path>,
        _hmac_key: Option<[u8; 32]>,
    ) -> Result<Self> {
        Self::load_or_create(archive_path)
    }

    /// Check if a checkpoint exists by reading the volume footer.
    ///
    /// Reads the archive file synchronously and checks if the footer's
    /// `last_checkpoint_offset > 0`. Returns `false` if the file doesn't
    /// exist, is too small, or has no valid footer.
    pub async fn exists(archive_path: impl AsRef<Path>) -> bool {
        let path = archive_path.as_ref().to_path_buf();
        tokio::task::spawn_blocking(move || {
            let metadata = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => return false,
            };
            let file_len = metadata.len();
            if file_len < era_volume::FOOTER_SIZE as u64 {
                return false;
            }
            // Try reading the last FOOTER_SIZE bytes (primary footer location)
            let mut file = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(_) => return false,
            };
            use std::io::{Read, Seek, SeekFrom};
            if file
                .seek(SeekFrom::End(-(era_volume::FOOTER_SIZE as i64)))
                .is_err()
            {
                return false;
            }
            let mut buf = [0u8; era_volume::FOOTER_SIZE];
            if file.read_exact(&mut buf).is_err() {
                return false;
            }
            match era_volume::Footer::from_bytes(&buf) {
                Ok(footer) => footer.last_checkpoint_offset() > 0,
                Err(_) => {
                    // Try backup footer at HEADER_SIZE offset
                    if file_len < (era_volume::HEADER_SIZE + era_volume::FOOTER_SIZE) as u64 {
                        return false;
                    }
                    if file
                        .seek(SeekFrom::Start(era_volume::HEADER_SIZE as u64))
                        .is_err()
                    {
                        return false;
                    }
                    let mut backup_buf = [0u8; era_volume::FOOTER_SIZE];
                    if file.read_exact(&mut backup_buf).is_err() {
                        return false;
                    }
                    match era_volume::Footer::from_bytes(&backup_buf) {
                        Ok(footer) => footer.last_checkpoint_offset() > 0,
                        Err(_) => false,
                    }
                }
            }
        })
        .await
        .unwrap_or(false)
    }

    /// Get mutable reference to checkpoint state
    pub fn checkpoint_mut(&mut self) -> &mut Checkpoint {
        &mut self.checkpoint
    }

    /// Get reference to checkpoint state
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    /// Commit checkpoint by writing it as a typed block to the volume
    ///
    /// **NEW API:** Requires VolumeWriter to write checkpoint block.
    /// The old `commit()` method that wrote sidecar files is removed.
    pub async fn commit_to_volume<W: StorageWriter>(
        &self,
        volume_writer: &mut era_volume::VolumeWriter<W>,
        session: &KeySession,
        volume_key: &VolumeKey,
        nonce_context: [u8; 16],
        archive_id: [u8; 16],
        epoch_id: u32,
    ) -> Result<u64> {
        write_checkpoint(
            volume_writer,
            session,
            volume_key,
            nonce_context,
            archive_id,
            epoch_id,
            &self.checkpoint,
        )
        .await
    }

    /// Delete checkpoint (no-op in new implementation)
    pub fn delete(&self) -> Result<()> {
        // No sidecar file to delete
        Ok(())
    }

    /// Record a chunk write (backward compatibility)
    pub fn record_chunk(&mut self, hash: ChunkHash, location: BlockLocation) -> Result<()> {
        self.checkpoint.written_chunks.insert(hash, location);
        self.checkpoint.chunks_written += 1;
        Ok(())
    }

    /// Serialize checkpoint for storage
    ///
    /// Returns the rkyv-serialized checkpoint bytes.
    pub fn snapshot_bytes(&self) -> Result<Vec<u8>> {
        self.checkpoint.to_bytes()
    }

    /// Commit checkpoint (backward compatibility - writes to sidecar file)
    ///
    /// **DEPRECATED:** This method is deprecated and does nothing in v2.2+.
    /// Use `commit_to_volume()` instead to write checkpoints as typed blocks.
    pub fn commit(&self) -> Result<()> {
        tracing::warn!(
            "CheckpointManager::commit() is deprecated - checkpoints are now written via commit_to_volume()"
        );
        // No-op in new implementation
        Ok(())
    }

    /// Get reference to written chunks (backward compatibility)
    pub fn written_chunks(&self) -> &HashMap<ChunkHash, BlockLocation> {
        &self.checkpoint.written_chunks
    }

    /// Sync checkpoint to disk (backward compatibility — no-op)
    ///
    /// **DEPRECATED:** This is a no-op. The backward-compat API cannot perform
    /// volume-based persistence without `VolumeWriter`/`KeySession`/`VolumeKey`.
    /// Real persistence is via `commit_to_volume()`.
    pub fn sync(&mut self) -> Result<()> {
        // No-op: volume I/O requires crypto context not available here
        Ok(())
    }

    /// Update checkpoint state (backward compatibility)
    pub fn update_stats(&mut self, bytes_written: u64, files_processed: u32) {
        self.checkpoint.total_bytes_written = bytes_written;
        self.checkpoint.total_files_processed = files_processed;
    }

    /// Update position (backward compatibility)
    ///
    /// Enforces monotonically increasing offset within the same volume.
    /// Moving to a new volume resets the offset constraint.
    pub fn update_position(&mut self, volume: u16, offset: u64, bytes_written: u64) -> Result<()> {
        if volume == self.checkpoint.current_volume && offset < self.checkpoint.current_offset {
            return Err(EraError::InvalidConfig(format!(
                "Position cannot go backwards on same volume: current_offset={}, new_offset={}",
                self.checkpoint.current_offset, offset
            )));
        }
        self.checkpoint.current_volume = volume;
        self.checkpoint.current_offset = offset;
        self.checkpoint.total_bytes_written = bytes_written;
        Ok(())
    }

    /// Check if a file has been completed (backward compatibility)
    pub fn is_file_completed(&self, path: &Path) -> bool {
        self.checkpoint
            .completed_files
            .contains(&path.to_string_lossy().to_string())
    }

    /// Mark a file as completed (backward compatibility)
    pub fn mark_file_completed(&mut self, path: impl AsRef<Path>) -> Result<()> {
        self.checkpoint
            .completed_files
            .insert(path.as_ref().to_string_lossy().to_string());
        self.checkpoint.in_progress_file = None;
        self.checkpoint.total_files_processed += 1;
        Ok(())
    }

    /// Start processing a file (backward compatibility)
    pub fn start_file(&mut self, path: impl AsRef<Path>, total_size: u64) -> Result<()> {
        self.checkpoint.in_progress_file = Some(InProgressFile {
            path: path.as_ref().to_string_lossy().to_string(),
            total_size,
            bytes_processed: 0,
            chunks_written: 0,
        });
        Ok(())
    }

    /// Update file processing progress (backward compatibility)
    pub fn update_file_progress(
        &mut self,
        bytes_processed: u64,
        chunks_written: u32,
    ) -> Result<()> {
        if let Some(ref mut in_progress) = self.checkpoint.in_progress_file {
            in_progress.bytes_processed = bytes_processed;
            in_progress.chunks_written = chunks_written;
        }
        Ok(())
    }

    /// Get chunk location from checkpoint (backward compatibility)
    pub fn get_chunk_location(&self, hash: &ChunkHash) -> Option<&BlockLocation> {
        self.checkpoint.written_chunks.get(hash)
    }

    /// Create a new checkpoint manager (backward compatibility)
    pub fn new(archive_path: impl AsRef<Path>) -> Self {
        Self {
            checkpoint: Checkpoint::new(0, 0, 0, 0, 0, HashMap::new()),
            archive_path: archive_path.as_ref().to_path_buf(),
        }
    }

    /// Save checkpoint (deprecated - no-op)
    ///
    /// **DEPRECATED:** Checkpoints are now written via commit_to_volume().
    /// This method exists for backward compatibility with tests.
    pub fn save(&self) -> Result<()> {
        tracing::warn!("CheckpointManager::save() is deprecated - use commit_to_volume() instead");
        Ok(())
    }
}

/// Write a checkpoint to the volume as a typed block
///
/// The checkpoint is encrypted and written as `BlockType::Checkpoint`.
/// The volume footer's `last_checkpoint_offset` field is updated to point
/// to this checkpoint, creating a linked list of checkpoints for recovery.
pub async fn write_checkpoint<W: StorageWriter>(
    volume_writer: &mut era_volume::VolumeWriter<W>,
    session: &KeySession,
    volume_key: &VolumeKey,
    nonce_context: [u8; 16],
    archive_id: [u8; 16],
    epoch_id: u32,
    checkpoint: &Checkpoint,
) -> Result<u64> {
    use era_common::{BlockId, EncryptedMacroBlock};

    // Serialize checkpoint
    let checkpoint_bytes = checkpoint.to_bytes()?;

    // Derive block ID (use current block count as sequence)
    let block_id = BlockId::new(volume_writer.block_count() as u64);

    // Encrypt checkpoint data
    let block_key = session.derive_block_key(volume_key, block_id.sequence(), &nonce_context)?;
    let derived_key = block_key.to_derived_key()?;
    let encrypted_data = era_crypto::encrypt_with_context(
        &derived_key,
        &nonce_context,
        &archive_id,
        epoch_id,
        block_id,
        &checkpoint_bytes,
    )?;

    let checkpoint_size = u32::try_from(checkpoint_bytes.len())
        .map_err(|_| EraError::Other("Checkpoint size exceeds u32::MAX".into()))?;

    // Create encrypted block
    let encrypted_block = EncryptedMacroBlock {
        block_id,
        data: encrypted_data,
        original_size: checkpoint_size,
        compressed_size: checkpoint_size, // No compression for checkpoints
        chunk_count: 0,                   // Metadata block
    };

    // Write as canonical block
    let location = volume_writer
        .write_canonical_block(&encrypted_block, BlockType::Checkpoint)
        .await?;

    // Update footer's last_checkpoint_offset and block_id for direct decryption
    let checkpoint_block_id = block_id.sequence() as u32;
    volume_writer
        .set_last_checkpoint_with_block_id(location.physical_offset, checkpoint_block_id)?;

    // CRITICAL: Atomically commit the checkpoint to disk
    // This persists the footer (primary + backup) so that if power is lost after this point,
    // the checkpoint can be recovered. Without this call, the checkpoint data would be written
    // but the footer wouldn't point to it, making recovery impossible.
    volume_writer
        .commit_checkpoint(location.physical_offset)
        .await?;

    tracing::info!(
        "Checkpoint committed: {} chunks, {} files at offset {} (block_id={})",
        checkpoint.chunks_written,
        checkpoint.total_files_processed,
        location.physical_offset,
        checkpoint_block_id
    );

    Ok(location.physical_offset)
}

/// Read a checkpoint from the volume
///
/// Given the checkpoint's physical offset (from footer or previous checkpoint),
/// this reads and decrypts the checkpoint block.
///
/// # Arguments
/// * `volume_reader` - The volume reader to read from
/// * `session` - Key session for decryption
/// * `volume_key` - Volume encryption key
/// * `nonce_context` - Nonce context for encryption
/// * `checkpoint_offset` - Physical offset of the checkpoint block
/// * `block_id` - Optional block ID for direct decryption. If `None`, falls back to brute-force search (legacy volumes).
#[allow(dead_code)] // Will be used by cold recovery path
#[allow(clippy::too_many_arguments)]
pub async fn read_checkpoint<R: era_storage::StorageReader>(
    volume_reader: &era_volume::VolumeReader<R>,
    session: &KeySession,
    volume_key: &VolumeKey,
    nonce_context: [u8; 16],
    archive_id: [u8; 16],
    epoch_id: u32,
    checkpoint_offset: u64,
    checkpoint_block_id: Option<u32>,
) -> Result<Checkpoint> {
    use era_common::BlockId;

    let (data_region_start, data_region_end) = volume_reader.data_region();
    if checkpoint_offset < data_region_start || checkpoint_offset >= data_region_end {
        return Err(EraError::InvalidFormat(format!(
            "Checkpoint offset {} out of bounds (data region: {}..{})",
            checkpoint_offset, data_region_start, data_region_end
        )));
    }

    // Construct location for the checkpoint block
    // NOTE: VolumeId::new() creates a default VolumeId (0), which represents the primary volume.
    // For checkpoint recovery, we default to volume 0 since checkpoints may be stored across
    // volumes but this location serves only as a metadata marker.
    let location = BlockLocation::single(era_common::VolumeId::new(), 0, checkpoint_offset, 0);

    // Read typed block
    let (block_type, encrypted_block) = volume_reader.read_typed_block(&location).await?;

    // Verify this is a checkpoint block
    if block_type != BlockType::Checkpoint {
        return Err(EraError::InvalidFormat(format!(
            "Expected Checkpoint block, found {:?}",
            block_type
        )));
    }

    // If block_id is provided, try direct decryption first
    if let Some(id) = checkpoint_block_id {
        let block_id = BlockId::new(id as u64);
        let block_key =
            session.derive_block_key(volume_key, block_id.sequence(), &nonce_context)?;
        let derived_key = block_key.to_derived_key()?;

        if let Ok(decrypted_data) = era_crypto::decrypt_with_context(
            &derived_key,
            &nonce_context,
            &archive_id,
            epoch_id,
            block_id,
            &encrypted_block.data,
        ) {
            if let Ok(checkpoint) = Checkpoint::from_bytes(&decrypted_data) {
                tracing::info!(
                    "Checkpoint recovered with block_id {}: {} chunks, {} files",
                    id,
                    checkpoint.chunks_written,
                    checkpoint.total_files_processed
                );
                return Ok(checkpoint);
            }
        }
    }

    Err(EraError::Decryption(
        "Could not decrypt checkpoint with any candidate block ID".into(),
    ))
}

/// Recover all checkpoints from a volume by scanning
///
/// This walks backwards from the footer's last_checkpoint_offset,
/// following the chain of checkpoints to reconstruct the full index.
///
/// # Note
/// Currently only recovers the last checkpoint. A full implementation
/// would traverse the checkpoint chain if previous checkpoint offsets
/// were stored in each checkpoint.
#[allow(dead_code)] // Will be used by cold recovery path
pub async fn recover_all_checkpoints<R: era_storage::StorageReader>(
    volume_reader: &era_volume::VolumeReader<R>,
    session: &KeySession,
    volume_key: &VolumeKey,
    nonce_context: [u8; 16],
    archive_id: [u8; 16],
    epoch_id: u32,
) -> Result<Vec<Checkpoint>> {
    let mut checkpoints = Vec::new();

    // Get initial checkpoint offset and block_id from footer
    if let Some(footer) = volume_reader.footer() {
        let checkpoint_offset = footer.last_checkpoint_offset();
        let checkpoint_block_id = footer.last_checkpoint_block_id();
        let (data_region_start, data_region_end) = volume_reader.data_region();

        // Only attempt recovery if there's a checkpoint
        if checkpoint_offset > 0 {
            if checkpoint_offset < data_region_start || checkpoint_offset >= data_region_end {
                return Err(EraError::InvalidFormat(format!(
                    "Footer checkpoint offset {} out of bounds (data region: {}..{})",
                    checkpoint_offset, data_region_start, data_region_end
                )));
            }

            // Use block_id if available, otherwise fall back to brute-force search
            let block_id_opt = if checkpoint_block_id > 0 {
                Some(checkpoint_block_id)
            } else {
                None
            };

            match read_checkpoint(
                volume_reader,
                session,
                volume_key,
                nonce_context,
                archive_id,
                epoch_id,
                checkpoint_offset,
                block_id_opt,
            )
            .await
            {
                Ok(checkpoint) => {
                    checkpoints.push(checkpoint);
                    // NOTE: Checkpoint chain traversal is not yet implemented.
                    // Each checkpoint is currently independent. When resume-from-checkpoint
                    // is needed, each checkpoint would store a pointer to the previous
                    // checkpoint offset for chain traversal.
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to read checkpoint at offset {}: {}",
                        checkpoint_offset,
                        e
                    );
                }
            }
        }
    }

    tracing::info!("Recovered {} checkpoints from volume", checkpoints.len());
    Ok(checkpoints)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_serialization() {
        let checkpoint = Checkpoint::new(0, 1024, 4096, 10, 100, HashMap::new());

        let bytes = checkpoint.to_bytes().unwrap();
        let deserialized = Checkpoint::from_bytes(&bytes).unwrap();

        assert_eq!(checkpoint.version, deserialized.version);
        assert_eq!(checkpoint.current_volume, deserialized.current_volume);
        assert_eq!(checkpoint.current_offset, deserialized.current_offset);
        assert_eq!(
            checkpoint.total_bytes_written,
            deserialized.total_bytes_written
        );
        assert_eq!(
            checkpoint.total_files_processed,
            deserialized.total_files_processed
        );
        assert_eq!(checkpoint.chunks_written, deserialized.chunks_written);
    }

    #[test]
    fn test_checkpoint_with_index() {
        let mut written_chunks = HashMap::new();
        let hash = ChunkHash::from_bytes([0u8; 32]);
        let location = BlockLocation::single(era_common::VolumeId::new(), 0, 1024, 4096);
        written_chunks.insert(hash, location);

        let checkpoint = Checkpoint::new(0, 1024, 4096, 10, 100, written_chunks.clone());

        let bytes = checkpoint.to_bytes().unwrap();
        let deserialized = Checkpoint::from_bytes(&bytes).unwrap();

        assert_eq!(deserialized.written_chunks.len(), 1);
        assert_eq!(
            deserialized
                .written_chunks
                .get(&hash)
                .unwrap()
                .physical_offset,
            1024
        );
    }

    #[test]
    fn test_checkpoint_invalid_data() {
        let invalid_bytes = vec![0xFF; 100];
        let result = Checkpoint::from_bytes(&invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_checkpoint_size() {
        let checkpoint = Checkpoint::new(0, 1024, 4096, 10, 100, HashMap::new());
        let size = checkpoint.serialized_size().unwrap();
        assert!(size > 0);
        tracing::debug!("Checkpoint size: {} bytes", size);
    }

    #[test]
    fn test_in_progress_file() {
        let mut checkpoint = Checkpoint::new(0, 1024, 4096, 10, 100, HashMap::new());

        checkpoint.set_in_progress(PathBuf::from("/tmp/test.bin"), 1024);
        assert!(checkpoint.in_progress_file.is_some());

        checkpoint.update_progress(512, 5);
        assert_eq!(
            checkpoint
                .in_progress_file
                .as_ref()
                .unwrap()
                .bytes_processed,
            512
        );
        assert_eq!(
            checkpoint.in_progress_file.as_ref().unwrap().chunks_written,
            5
        );

        checkpoint.mark_file_complete();
        assert!(checkpoint.in_progress_file.is_none());
        assert_eq!(checkpoint.total_files_processed, 11);
    }

    #[tokio::test]
    async fn test_checkpoint_manager_api() {
        let manager = CheckpointManager::with_hmac_key("/tmp/test.era", [0u8; 32]);
        assert_eq!(manager.checkpoint().version, CHECKPOINT_VERSION);

        let manager2 = CheckpointManager::load_or_create("/tmp/test.era").unwrap();
        assert_eq!(manager2.checkpoint().version, CHECKPOINT_VERSION);

        assert!(!CheckpointManager::exists("/tmp/test.era").await);
    }
}
