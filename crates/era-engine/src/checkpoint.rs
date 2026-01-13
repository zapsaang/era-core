//! Checkpoint mechanism for crash recovery.
//!
//! This module provides atomic checkpointing to enable crash recovery
//! during archive creation. The checkpoint tracks:
//! - Files that have been fully processed
//! - Chunks that have been written
//! - Current block offsets
//!
//! On restart after a crash, the checkpoint allows resuming from the
//! last known good state without data loss.
//!
//! ## Security
//!
//! Checkpoints are protected by an HMAC to prevent tampering.
//! The HMAC key is derived from the archive password.
//!
//! ## Format
//!
//! Checkpoints use bincode for efficient binary serialization.

use era_common::{BlockLocation, ChunkHash, EraError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Version of the checkpoint format
pub const CHECKPOINT_VERSION: u32 = 2;

/// Extension for checkpoint files (simplified from .era.checkpoint)
pub const CHECKPOINT_EXTENSION: &str = ".checkpoint";

/// Extension for temporary checkpoint files (during atomic write)
pub const CHECKPOINT_TMP_EXTENSION: &str = ".checkpoint.tmp";

/// HMAC size (Blake3 truncated to 32 bytes)
const HMAC_SIZE: usize = 32;

/// Domain separator for checkpoint HMAC
const CHECKPOINT_HMAC_DOMAIN: &[u8] = b"ERA-CHECKPOINT-HMAC-V2";

/// Checkpoint data structure that tracks archive creation progress
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Version of the checkpoint format
    pub version: u32,

    /// Timestamp when checkpoint was created (Unix epoch seconds)
    pub timestamp: u64,

    /// Output archive path
    pub archive_path: PathBuf,

    /// Source files that have been fully processed
    pub completed_files: HashSet<PathBuf>,

    /// Files currently being processed (partial progress)
    pub in_progress_file: Option<InProgressFile>,

    /// All chunk hashes that have been written with their locations
    pub written_chunks: HashMap<ChunkHash, BlockLocation>,

    /// Current volume number (for multi-volume archives)
    pub current_volume: u16,

    /// Current write offset within the volume
    pub current_offset: u64,

    /// Total bytes written so far
    pub total_bytes_written: u64,

    /// Total files processed (including completed)
    pub total_files_processed: u32,
}

/// Tracks progress within a file being processed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InProgressFile {
    /// Path to the file
    pub path: PathBuf,

    /// Total file size
    pub total_size: u64,

    /// Bytes processed so far
    pub bytes_processed: u64,

    /// Number of chunks written from this file
    pub chunks_written: u32,
}

impl Checkpoint {
    /// Create a new checkpoint for an archive
    pub fn new(archive_path: impl Into<PathBuf>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            version: CHECKPOINT_VERSION,
            timestamp,
            archive_path: archive_path.into(),
            completed_files: HashSet::new(),
            in_progress_file: None,
            written_chunks: HashMap::new(),
            current_volume: 0,
            current_offset: 0,
            total_bytes_written: 0,
            total_files_processed: 0,
        }
    }

    /// Mark a file as completed
    pub fn mark_file_completed(&mut self, path: impl Into<PathBuf>) {
        let path = path.into();
        self.completed_files.insert(path);
        self.in_progress_file = None;
        self.total_files_processed += 1;
        self.update_timestamp();
    }

    /// Start tracking progress on a new file
    pub fn start_file(&mut self, path: impl Into<PathBuf>, total_size: u64) {
        self.in_progress_file = Some(InProgressFile {
            path: path.into(),
            total_size,
            bytes_processed: 0,
            chunks_written: 0,
        });
    }

    /// Update progress on the current file
    pub fn update_file_progress(&mut self, bytes_added: u64, chunks_added: u32) {
        if let Some(ref mut file) = self.in_progress_file {
            file.bytes_processed += bytes_added;
            file.chunks_written += chunks_added;
        }
    }

    /// Record a chunk that has been written
    pub fn record_chunk(&mut self, hash: ChunkHash, location: BlockLocation) {
        self.written_chunks.insert(hash, location);
    }

    /// Update volume position
    pub fn update_position(&mut self, volume: u16, offset: u64, bytes_written: u64) {
        self.current_volume = volume;
        self.current_offset = offset;
        self.total_bytes_written += bytes_written;
        self.update_timestamp();
    }

    /// Check if a file has been completed
    pub fn is_file_completed(&self, path: &Path) -> bool {
        self.completed_files.contains(path)
    }

    /// Check if a chunk has been written
    pub fn get_chunk_location(&self, hash: &ChunkHash) -> Option<BlockLocation> {
        self.written_chunks.get(hash).cloned()
    }

    /// Update timestamp to current time
    fn update_timestamp(&mut self) {
        self.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Get the checkpoint file path for an archive (simplified naming)
    pub fn checkpoint_path(archive_path: &Path) -> PathBuf {
        let mut path = archive_path.to_path_buf();
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        path.set_file_name(format!("{}{}", name, CHECKPOINT_EXTENSION));
        path
    }

    /// Get the temporary checkpoint file path
    pub fn checkpoint_tmp_path(archive_path: &Path) -> PathBuf {
        let mut path = archive_path.to_path_buf();
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        path.set_file_name(format!("{}{}", name, CHECKPOINT_TMP_EXTENSION));
        path
    }
}

/// Compute HMAC for checkpoint data
fn compute_hmac(data: &[u8], key: Option<&[u8]>) -> [u8; HMAC_SIZE] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CHECKPOINT_HMAC_DOMAIN);
    if let Some(k) = key {
        hasher.update(k);
    }
    hasher.update(data);
    let hash = hasher.finalize();
    let mut hmac = [0u8; HMAC_SIZE];
    hmac.copy_from_slice(&hash.as_bytes()[..HMAC_SIZE]);
    hmac
}

/// Verify HMAC for checkpoint data
fn verify_hmac(data: &[u8], expected: &[u8; HMAC_SIZE], key: Option<&[u8]>) -> bool {
    let computed = compute_hmac(data, key);
    // Constant-time comparison
    use subtle::ConstantTimeEq;
    computed.ct_eq(expected).into()
}

/// Manager for checkpoint file operations
pub struct CheckpointManager {
    /// Path to the checkpoint file
    checkpoint_path: PathBuf,

    /// Path to the archive (for temp file path)
    archive_path: PathBuf,

    /// Current checkpoint state
    checkpoint: Checkpoint,

    /// Whether to sync to disk on every update
    sync_on_update: bool,

    /// HMAC key for integrity verification (optional)
    hmac_key: Option<Arc<[u8; 32]>>,

    /// Chunk save interval (save checkpoint every N chunks)
    chunk_save_interval: u32,

    /// Chunks since last save
    chunks_since_save: u32,
}

impl CheckpointManager {
    /// Create a new checkpoint manager for an archive
    pub fn new(archive_path: &Path) -> Self {
        let checkpoint_path = Checkpoint::checkpoint_path(archive_path);
        let checkpoint = Checkpoint::new(archive_path);

        Self {
            checkpoint_path,
            archive_path: archive_path.to_path_buf(),
            checkpoint,
            sync_on_update: true,
            hmac_key: None,
            chunk_save_interval: 100, // Save every 100 chunks by default
            chunks_since_save: 0,
        }
    }

    /// Create a new checkpoint manager with HMAC key for integrity
    pub fn with_hmac_key(archive_path: &Path, key: [u8; 32]) -> Self {
        let mut manager = Self::new(archive_path);
        manager.hmac_key = Some(Arc::new(key));
        manager
    }

    /// Load an existing checkpoint, or create new if not exists
    pub fn load_or_create(archive_path: &Path) -> Result<Self> {
        Self::load_or_create_with_key(archive_path, None)
    }

    /// Load an existing checkpoint with HMAC verification
    pub fn load_or_create_with_key(
        archive_path: &Path,
        hmac_key: Option<[u8; 32]>,
    ) -> Result<Self> {
        let checkpoint_path = Checkpoint::checkpoint_path(archive_path);

        // Clean up any orphaned temp files on startup
        Self::cleanup_temp_files(archive_path);

        let checkpoint = if checkpoint_path.exists() {
            Self::load_checkpoint(&checkpoint_path, hmac_key.as_ref())?
        } else {
            Checkpoint::new(archive_path)
        };

        Ok(Self {
            checkpoint_path,
            archive_path: archive_path.to_path_buf(),
            checkpoint,
            sync_on_update: true,
            hmac_key: hmac_key.map(Arc::new),
            chunk_save_interval: 100,
            chunks_since_save: 0,
        })
    }

    /// Clean up orphaned temporary checkpoint files
    fn cleanup_temp_files(archive_path: &Path) {
        let tmp_path = Checkpoint::checkpoint_tmp_path(archive_path);
        if tmp_path.exists() {
            let _ = fs::remove_file(&tmp_path);
        }
    }

    /// Load checkpoint from file with HMAC verification
    fn load_checkpoint(path: &Path, hmac_key: Option<&[u8; 32]>) -> Result<Checkpoint> {
        let mut file = File::open(path).map_err(EraError::Io)?;

        // Read entire file
        let mut data = Vec::new();
        file.read_to_end(&mut data).map_err(EraError::Io)?;

        if data.len() < HMAC_SIZE {
            return Err(EraError::other("Checkpoint file too small"));
        }

        // Split into HMAC and payload
        let (payload, hmac_bytes) = data.split_at(data.len() - HMAC_SIZE);
        let mut hmac = [0u8; HMAC_SIZE];
        hmac.copy_from_slice(hmac_bytes);

        // Verify HMAC
        let key_bytes = hmac_key.map(|k| k.as_slice());
        if !verify_hmac(payload, &hmac, key_bytes) {
            return Err(EraError::other(
                "Checkpoint HMAC verification failed - file may be corrupted or tampered",
            ));
        }

        // Deserialize with bincode
        let checkpoint: Checkpoint = bincode::deserialize(payload)
            .map_err(|e| EraError::other(format!("Failed to parse checkpoint: {}", e)))?;

        // Version check
        if checkpoint.version > CHECKPOINT_VERSION {
            return Err(EraError::other(format!(
                "Checkpoint version {} is newer than supported version {}",
                checkpoint.version, CHECKPOINT_VERSION
            )));
        }

        // Handle version migration if needed
        // Currently v1 -> v2 migration is automatic (bincode handles it)

        Ok(checkpoint)
    }

    /// Save checkpoint atomically with HMAC (write to temp, then rename)
    pub fn save(&mut self) -> Result<()> {
        let tmp_path = Checkpoint::checkpoint_tmp_path(&self.archive_path);

        // Serialize with bincode (much faster than JSON)
        let payload = bincode::serialize(&self.checkpoint)
            .map_err(|e| EraError::other(format!("Failed to serialize checkpoint: {}", e)))?;

        // Compute HMAC
        let key_bytes = self.hmac_key.as_ref().map(|k| k.as_slice());
        let hmac = compute_hmac(&payload, key_bytes);

        // Write to temporary file
        {
            let file = File::create(&tmp_path).map_err(EraError::Io)?;
            let mut writer = BufWriter::new(file);

            writer.write_all(&payload).map_err(EraError::Io)?;
            writer.write_all(&hmac).map_err(EraError::Io)?;
            writer.flush().map_err(EraError::Io)?;

            // Sync to disk
            writer.get_ref().sync_all().map_err(EraError::Io)?;
        }

        // Atomic rename
        fs::rename(&tmp_path, &self.checkpoint_path).map_err(EraError::Io)?;

        // Reset chunk counter
        self.chunks_since_save = 0;

        Ok(())
    }

    /// Get immutable reference to checkpoint state
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    /// Mark a file as completed and optionally save
    pub fn mark_file_completed(&mut self, path: impl Into<PathBuf>) -> Result<()> {
        self.checkpoint.mark_file_completed(path);
        if self.sync_on_update {
            self.save()?;
        }
        Ok(())
    }

    /// Start tracking a new file
    pub fn start_file(&mut self, path: impl Into<PathBuf>, total_size: u64) -> Result<()> {
        self.checkpoint.start_file(path, total_size);
        if self.sync_on_update {
            self.save()?;
        }
        Ok(())
    }

    /// Update file progress
    pub fn update_file_progress(&mut self, bytes_added: u64, chunks_added: u32) -> Result<()> {
        self.checkpoint
            .update_file_progress(bytes_added, chunks_added);
        // Don't save on every progress update to reduce I/O
        Ok(())
    }

    /// Record a written chunk with smart batching
    pub fn record_chunk(&mut self, hash: ChunkHash, location: BlockLocation) -> Result<()> {
        self.checkpoint.record_chunk(hash, location);
        self.chunks_since_save += 1;

        // Auto-save every N chunks
        if self.chunks_since_save >= self.chunk_save_interval {
            self.save()?;
        }

        Ok(())
    }

    /// Update volume position
    pub fn update_position(&mut self, volume: u16, offset: u64, bytes_written: u64) -> Result<()> {
        self.checkpoint
            .update_position(volume, offset, bytes_written);
        if self.sync_on_update {
            self.save()?;
        }
        Ok(())
    }

    /// Check if a file has been completed
    pub fn is_file_completed(&self, path: &Path) -> bool {
        self.checkpoint.is_file_completed(path)
    }

    /// Get location of a previously written chunk
    pub fn get_chunk_location(&self, hash: &ChunkHash) -> Option<BlockLocation> {
        self.checkpoint.get_chunk_location(hash)
    }

    /// Delete the checkpoint file (called after successful archive completion)
    pub fn delete(self) -> Result<()> {
        if self.checkpoint_path.exists() {
            fs::remove_file(&self.checkpoint_path).map_err(EraError::Io)?;
        }
        Ok(())
    }

    /// Check if a checkpoint exists for the given archive
    pub fn exists(archive_path: &Path) -> bool {
        Checkpoint::checkpoint_path(archive_path).exists()
    }

    /// Set whether to sync checkpoint to disk on every update
    pub fn set_sync_on_update(&mut self, sync: bool) {
        self.sync_on_update = sync;
    }

    /// Set the chunk save interval
    pub fn set_chunk_save_interval(&mut self, interval: u32) {
        self.chunk_save_interval = interval;
    }

    /// Force sync current state to disk
    pub fn sync(&mut self) -> Result<()> {
        self.save()
    }

    /// Get reference to written chunks (avoids cloning)
    pub fn written_chunks(&self) -> &HashMap<ChunkHash, BlockLocation> {
        &self.checkpoint.written_chunks
    }
}

// ============ Unit Tests (TDD) ============

#[cfg(test)]
mod tests {
    use super::*;
    use era_common::VolumeId;
    use tempfile::TempDir;

    /// Helper to create a test BlockLocation
    fn test_location(offset: u64, size: u32) -> BlockLocation {
        BlockLocation {
            volume_id: VolumeId::default(),
            slot_index: 0,
            physical_offset: offset,
            encrypted_size: size,
            erasure_info: None,
            shard_offsets: None,
        }
    }

    /// Helper to create a ChunkHash from a byte
    fn test_hash(byte: u8) -> ChunkHash {
        ChunkHash::from_bytes([byte; 32])
    }

    // ============ Checkpoint Data Tests ============

    #[test]
    fn test_checkpoint_new() {
        let checkpoint = Checkpoint::new("/tmp/test.era");

        assert_eq!(checkpoint.version, CHECKPOINT_VERSION);
        assert_eq!(checkpoint.archive_path, PathBuf::from("/tmp/test.era"));
        assert!(checkpoint.completed_files.is_empty());
        assert!(checkpoint.in_progress_file.is_none());
        assert!(checkpoint.written_chunks.is_empty());
        assert_eq!(checkpoint.current_volume, 0);
        assert_eq!(checkpoint.current_offset, 0);
    }

    #[test]
    fn test_checkpoint_mark_file_completed() {
        let mut checkpoint = Checkpoint::new("/tmp/test.era");

        checkpoint.mark_file_completed("/path/to/file1.txt");
        checkpoint.mark_file_completed("/path/to/file2.txt");

        assert!(checkpoint.is_file_completed(Path::new("/path/to/file1.txt")));
        assert!(checkpoint.is_file_completed(Path::new("/path/to/file2.txt")));
        assert!(!checkpoint.is_file_completed(Path::new("/path/to/file3.txt")));
        assert_eq!(checkpoint.total_files_processed, 2);
    }

    #[test]
    fn test_checkpoint_file_progress() {
        let mut checkpoint = Checkpoint::new("/tmp/test.era");

        checkpoint.start_file("/path/to/largefile.bin", 1_000_000);
        assert!(checkpoint.in_progress_file.is_some());

        let file = checkpoint.in_progress_file.as_ref().unwrap();
        assert_eq!(file.path, PathBuf::from("/path/to/largefile.bin"));
        assert_eq!(file.total_size, 1_000_000);
        assert_eq!(file.bytes_processed, 0);

        checkpoint.update_file_progress(100_000, 5);
        let file = checkpoint.in_progress_file.as_ref().unwrap();
        assert_eq!(file.bytes_processed, 100_000);
        assert_eq!(file.chunks_written, 5);

        checkpoint.update_file_progress(200_000, 10);
        let file = checkpoint.in_progress_file.as_ref().unwrap();
        assert_eq!(file.bytes_processed, 300_000);
        assert_eq!(file.chunks_written, 15);
    }

    #[test]
    fn test_checkpoint_record_chunk() {
        let mut checkpoint = Checkpoint::new("/tmp/test.era");

        let hash = test_hash(1);
        let location = test_location(1024, 512);

        checkpoint.record_chunk(hash, location);

        let retrieved = checkpoint.get_chunk_location(&hash);
        assert!(retrieved.is_some());
        let location = retrieved.unwrap();
        assert_eq!(location.physical_offset, 1024);
        assert_eq!(location.encrypted_size, 512);

        // Unknown hash should return None
        assert!(checkpoint.get_chunk_location(&test_hash(2)).is_none());
    }

    #[test]
    fn test_checkpoint_update_position() {
        let mut checkpoint = Checkpoint::new("/tmp/test.era");

        checkpoint.update_position(0, 1024, 1024);
        assert_eq!(checkpoint.current_volume, 0);
        assert_eq!(checkpoint.current_offset, 1024);
        assert_eq!(checkpoint.total_bytes_written, 1024);

        checkpoint.update_position(1, 512, 512);
        assert_eq!(checkpoint.current_volume, 1);
        assert_eq!(checkpoint.current_offset, 512);
        assert_eq!(checkpoint.total_bytes_written, 1536);
    }

    #[test]
    fn test_checkpoint_path_generation() {
        let archive = Path::new("/data/backups/archive.era");
        let checkpoint = Checkpoint::checkpoint_path(archive);
        // Now uses simplified .checkpoint extension
        assert_eq!(
            checkpoint,
            PathBuf::from("/data/backups/archive.era.checkpoint")
        );

        let archive2 = Path::new("test.era");
        let checkpoint2 = Checkpoint::checkpoint_path(archive2);
        assert_eq!(checkpoint2, PathBuf::from("test.era.checkpoint"));
    }

    // ============ CheckpointManager Tests ============

    #[test]
    fn test_manager_new_and_save() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("test.era");

        let mut manager = CheckpointManager::new(&archive_path);
        assert!(manager.save().is_ok());

        // Verify file was created
        let checkpoint_path = Checkpoint::checkpoint_path(&archive_path);
        assert!(checkpoint_path.exists());
    }

    #[test]
    fn test_manager_load_or_create_new() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("test.era");

        let manager = CheckpointManager::load_or_create(&archive_path).unwrap();
        assert_eq!(manager.checkpoint().archive_path, archive_path);
    }

    #[test]
    fn test_manager_load_existing() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("test.era");

        // Create and save a checkpoint
        {
            let mut manager = CheckpointManager::new(&archive_path);
            manager.mark_file_completed("/path/to/file.txt").unwrap();
            manager.save().unwrap();
        }

        // Load it back
        let manager = CheckpointManager::load_or_create(&archive_path).unwrap();
        assert!(manager.is_file_completed(Path::new("/path/to/file.txt")));
    }

    #[test]
    fn test_manager_hmac_verification() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("test.era");
        let key = [42u8; 32];

        // Create and save with HMAC
        {
            let mut manager = CheckpointManager::with_hmac_key(&archive_path, key);
            manager.mark_file_completed("/secure/file.txt").unwrap();
            manager.save().unwrap();
        }

        // Load with correct key should succeed
        {
            let manager =
                CheckpointManager::load_or_create_with_key(&archive_path, Some(key)).unwrap();
            assert!(manager.is_file_completed(Path::new("/secure/file.txt")));
        }

        // Load with wrong key should fail
        {
            let wrong_key = [99u8; 32];
            let result = CheckpointManager::load_or_create_with_key(&archive_path, Some(wrong_key));
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_manager_atomic_save() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("test.era");

        let mut manager = CheckpointManager::new(&archive_path);

        // Add some data
        let hash = test_hash(42);
        let location = test_location(2048, 1024);
        manager.record_chunk(hash, location).unwrap();
        manager.mark_file_completed("/file1.txt").unwrap();
        manager.mark_file_completed("/file2.txt").unwrap();

        // Save
        manager.save().unwrap();

        // Verify no temp file left behind
        let tmp_path = Checkpoint::checkpoint_tmp_path(&archive_path);
        assert!(!tmp_path.exists());

        // Load and verify
        let loaded = CheckpointManager::load_or_create(&archive_path).unwrap();
        assert_eq!(loaded.checkpoint().completed_files.len(), 2);
        assert!(loaded.get_chunk_location(&hash).is_some());
    }

    #[test]
    fn test_manager_temp_file_cleanup() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("test.era");

        // Create orphaned temp file
        let tmp_path = Checkpoint::checkpoint_tmp_path(&archive_path);
        fs::write(&tmp_path, b"orphaned data").unwrap();
        assert!(tmp_path.exists());

        // Loading should clean up the temp file
        let _manager = CheckpointManager::load_or_create(&archive_path).unwrap();
        assert!(!tmp_path.exists());
    }

    #[test]
    fn test_manager_delete() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("test.era");

        let mut manager = CheckpointManager::new(&archive_path);
        manager.save().unwrap();

        let checkpoint_path = Checkpoint::checkpoint_path(&archive_path);
        assert!(checkpoint_path.exists());

        manager.delete().unwrap();
        assert!(!checkpoint_path.exists());
    }

    #[test]
    fn test_manager_exists() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("test.era");

        assert!(!CheckpointManager::exists(&archive_path));

        let mut manager = CheckpointManager::new(&archive_path);
        manager.save().unwrap();

        assert!(CheckpointManager::exists(&archive_path));
    }

    #[test]
    fn test_manager_chunk_batching() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("test.era");

        let mut manager = CheckpointManager::new(&archive_path);
        manager.set_chunk_save_interval(5);
        manager.set_sync_on_update(false);

        // Add 4 chunks - should not save
        for i in 0..4 {
            manager
                .record_chunk(test_hash(i), test_location(i as u64 * 100, 50))
                .unwrap();
        }
        assert!(!Checkpoint::checkpoint_path(&archive_path).exists());

        // Add 5th chunk - should trigger save
        manager
            .record_chunk(test_hash(4), test_location(400, 50))
            .unwrap();
        assert!(Checkpoint::checkpoint_path(&archive_path).exists());
    }

    #[test]
    fn test_manager_full_workflow() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("backup.era");

        // Simulate archive creation with checkpointing
        {
            let mut manager = CheckpointManager::load_or_create(&archive_path).unwrap();

            // Process file 1
            manager.start_file("/data/file1.txt", 10000).unwrap();
            manager.update_file_progress(5000, 2).unwrap();
            manager.update_file_progress(5000, 2).unwrap();
            manager.mark_file_completed("/data/file1.txt").unwrap();

            // Process file 2
            manager.start_file("/data/file2.txt", 20000).unwrap();
            // Simulate crash after 50% progress
            manager.update_file_progress(10000, 5).unwrap();
            manager.sync().unwrap();
        }

        // Resume after "crash"
        {
            let manager = CheckpointManager::load_or_create(&archive_path).unwrap();

            assert!(manager.is_file_completed(Path::new("/data/file1.txt")));
            assert!(!manager.is_file_completed(Path::new("/data/file2.txt")));

            // File 2 should show partial progress
            let in_progress = manager.checkpoint().in_progress_file.as_ref().unwrap();
            assert_eq!(in_progress.path, PathBuf::from("/data/file2.txt"));
            assert_eq!(in_progress.bytes_processed, 10000);
            assert_eq!(in_progress.chunks_written, 5);
        }
    }

    #[test]
    fn test_checkpoint_serialization_roundtrip() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("test.era");

        let hash1 = test_hash(1);
        let hash2 = test_hash(2);

        {
            let mut manager = CheckpointManager::new(&archive_path);

            manager.record_chunk(hash1, test_location(100, 50)).unwrap();
            manager
                .record_chunk(hash2, test_location(200, 100))
                .unwrap();

            manager.mark_file_completed("/a.txt").unwrap();
            manager.mark_file_completed("/b/c.txt").unwrap();
            manager.start_file("/d/e/f.txt", 99999).unwrap();
            manager.update_file_progress(12345, 10).unwrap();
            manager.update_position(2, 8192, 8192).unwrap();

            manager.save().unwrap();
        }

        // Load and verify all data
        let loaded = CheckpointManager::load_or_create(&archive_path).unwrap();
        let cp = loaded.checkpoint();

        assert_eq!(cp.version, CHECKPOINT_VERSION);
        assert!(cp.is_file_completed(Path::new("/a.txt")));
        assert!(cp.is_file_completed(Path::new("/b/c.txt")));

        // Verify chunk locations
        let loc1 = cp.get_chunk_location(&hash1).unwrap();
        assert_eq!(loc1.physical_offset, 100);
        assert_eq!(loc1.encrypted_size, 50);

        let loc2 = cp.get_chunk_location(&hash2).unwrap();
        assert_eq!(loc2.physical_offset, 200);
        assert_eq!(loc2.encrypted_size, 100);

        let in_progress = cp.in_progress_file.as_ref().unwrap();
        assert_eq!(in_progress.path, PathBuf::from("/d/e/f.txt"));
        assert_eq!(in_progress.total_size, 99999);
        assert_eq!(in_progress.bytes_processed, 12345);
        assert_eq!(in_progress.chunks_written, 10);

        assert_eq!(cp.current_volume, 2);
        assert_eq!(cp.current_offset, 8192);
        assert_eq!(cp.total_bytes_written, 8192);
    }

    #[test]
    fn test_written_chunks_reference() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("test.era");

        let mut manager = CheckpointManager::new(&archive_path);

        for i in 0..100 {
            manager
                .record_chunk(test_hash(i), test_location(i as u64 * 100, 50))
                .unwrap();
        }

        // Access via reference (no clone)
        let chunks = manager.written_chunks();
        assert_eq!(chunks.len(), 100);
        assert!(chunks.get(&test_hash(50)).is_some());
    }
}
