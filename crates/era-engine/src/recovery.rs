//! Crash recovery module for ERA archives.
//!
//! This module provides functionality to recover from interrupted archive
//! creation. It uses the checkpoint mechanism to track progress and enables
//! resumption from the last known good state.
//!
//! ## V2.2 Changes
//!
//! Checkpoints are now stored as typed blocks inside the `.era` volume,
//! not as sidecar files. Recovery detection uses `VolumeReader` to check
//! the footer's `last_checkpoint_offset` field.

use era_common::{BlockHeader, BlockLocation, ChunkHash, EraError, Result};
use era_storage::LocalStorageBackend;
use era_volume::VolumeReader;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::task::spawn_blocking;
use tracing::{debug, info, warn};

use crate::checkpoint::{Checkpoint, CheckpointManager, InProgressFile};

#[cfg(test)]
mod cancel_test_hook {
    use std::sync::{mpsc, Mutex, OnceLock};

    pub(super) struct Hook {
        pub entered_tx: mpsc::Sender<()>,
        pub proceed_rx: mpsc::Receiver<()>,
    }

    static HOOK: OnceLock<Mutex<Option<Hook>>> = OnceLock::new();

    pub(super) fn install(hook: Hook) {
        let lock = HOOK.get_or_init(|| Mutex::new(None));
        *lock.lock().expect("hook mutex poisoned") = Some(hook);
    }

    pub(super) fn clear() {
        if let Some(lock) = HOOK.get() {
            *lock.lock().expect("hook mutex poisoned") = None;
        }
    }

    pub(super) fn checkpoint() {
        if let Some(lock) = HOOK.get() {
            let guard = lock.lock().expect("hook mutex poisoned");
            if let Some(hook) = guard.as_ref() {
                let _ = hook.entered_tx.send(());
                let _ = hook.proceed_rx.recv();
            }
        }
    }
}

/// Result of analyzing a potential recovery situation
#[derive(Debug, Clone)]
pub struct RecoveryStatus {
    /// Whether a checkpoint exists (in volume footer)
    pub checkpoint_exists: bool,

    /// Whether the archive file exists (possibly incomplete)
    pub archive_exists: bool,

    /// Whether recovery is needed
    pub recovery_needed: bool,

    /// List of completed files (from checkpoint)
    pub completed_files: Vec<PathBuf>,

    /// File that was in progress when interrupted
    pub in_progress_file: Option<PathBuf>,

    /// Number of chunks already written
    pub chunks_written: usize,

    /// Total bytes written before interruption
    pub bytes_written: u64,
}

/// Check if a volume has a checkpoint by reading its footer.
///
/// Reads only the 128-byte footer from the end of the file instead of
/// opening a full `VolumeReader` (which parses the 4096-byte header and
/// allocates reader state). This is the same lightweight pattern used by
/// `CheckpointManager::exists()`.
async fn volume_has_checkpoint(archive_path: &Path) -> Result<bool> {
    let path = archive_path.to_path_buf();
    let footer_has_checkpoint = |footer: &era_volume::Footer| footer.last_checkpoint_offset() > 0;
    tokio::task::spawn_blocking(move || -> Result<bool> {
        use std::io::{Read, Seek, SeekFrom};

        let metadata = std::fs::metadata(&path).map_err(EraError::Io)?;
        let file_len = metadata.len();
        if file_len < era_volume::FOOTER_SIZE as u64 {
            return Ok(false);
        }

        let mut file = std::fs::File::open(&path).map_err(EraError::Io)?;

        // Read primary footer (last FOOTER_SIZE bytes)
        if file
            .seek(SeekFrom::End(-(era_volume::FOOTER_SIZE as i64)))
            .is_err()
        {
            return Err(EraError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "failed to seek to primary footer",
            )));
        }
        let mut buf = [0u8; era_volume::FOOTER_SIZE];
        if file.read_exact(&mut buf).is_err() {
            return Err(EraError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "failed to read primary footer",
            )));
        }

        match era_volume::Footer::from_bytes(&buf) {
            Ok(footer) => Ok(footer_has_checkpoint(&footer)),
            Err(_) => {
                // Try backup footer at HEADER_SIZE offset
                if file_len < (era_volume::HEADER_SIZE + era_volume::FOOTER_SIZE) as u64 {
                    return Ok(false);
                }
                if file
                    .seek(SeekFrom::Start(era_volume::HEADER_SIZE as u64))
                    .is_err()
                {
                    return Err(EraError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "failed to seek to backup footer",
                    )));
                }
                let mut backup_buf = [0u8; era_volume::FOOTER_SIZE];
                if file.read_exact(&mut backup_buf).is_err() {
                    return Err(EraError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "failed to read backup footer",
                    )));
                }
                match era_volume::Footer::from_bytes(&backup_buf) {
                    Ok(footer) => Ok(footer_has_checkpoint(&footer)),
                    Err(_) => Ok(false),
                }
            }
        }
    })
    .await
    .unwrap_or_else(|e| {
        Err(EraError::AsyncError(format!(
            "volume_has_checkpoint task panicked: {}",
            e
        )))
    })
}

/// Recovery manager for handling interrupted archive creation
///
/// Note: This struct uses a reference-based design to avoid cloning
/// large chunk location maps. Use `written_chunks()` for direct access.
pub struct RecoveryManager {
    /// Archive path
    archive_path: PathBuf,

    /// Checkpoint manager (if recovery is possible)
    checkpoint_manager: Option<CheckpointManager>,
}

impl RecoveryManager {
    /// Analyze the recovery situation for an archive
    ///
    /// **V2.2 Change:** Now checks the volume footer for checkpoint presence
    /// instead of looking for sidecar files. Populates `bytes_written` from
    /// the footer's `data_end_offset` when a checkpoint exists.
    pub async fn analyze(archive_path: &Path) -> Result<RecoveryStatus> {
        let archive_exists = tokio::fs::try_exists(archive_path).await?;

        // V2.2: Check volume footer for checkpoint, not sidecar files
        let checkpoint_exists = if archive_exists {
            volume_has_checkpoint(archive_path).await?
        } else {
            false
        };

        // If no checkpoint, no recovery is possible
        if !checkpoint_exists {
            return Ok(RecoveryStatus {
                checkpoint_exists: false,
                archive_exists,
                recovery_needed: false,
                completed_files: Vec::new(),
                in_progress_file: None,
                chunks_written: 0,
                bytes_written: 0,
            });
        }

        // Load footer to populate bytes_written from data_end_offset
        let bytes_written = match Self::read_footer_data_end(archive_path).await {
            Ok(val) => val,
            Err(e) => {
                warn!(
                    "Failed to read footer data_end offset: {}. Defaulting to 0.",
                    e
                );
                0
            }
        };

        debug!(
            "Checkpoint detected in volume footer for {:?}, data_end_offset={}",
            archive_path, bytes_written
        );

        Ok(RecoveryStatus {
            checkpoint_exists: true,
            archive_exists,
            recovery_needed: true,
            completed_files: Vec::new(), // Will be populated when checkpoint is loaded
            in_progress_file: None,      // Will be populated when checkpoint is loaded
            chunks_written: 0,           // Will be populated when checkpoint is loaded
            bytes_written,
        })
    }

    /// Read the footer's data_end_offset from the archive file.
    async fn read_footer_data_end(archive_path: &Path) -> Result<u64> {
        let parent_dir = archive_path.parent().unwrap_or(Path::new("."));
        let backend = LocalStorageBackend::new(parent_dir);
        let volume_name = archive_path.file_name().unwrap_or_default();

        let reader = VolumeReader::open(&backend, Path::new(volume_name)).await?;
        if let Some(footer) = reader.footer() {
            Ok(footer.data_end_offset())
        } else {
            Ok(0)
        }
    }

    /// Create a recovery manager for an archive
    ///
    /// **V2.2 Change:** Now checks volume footer instead of sidecar files.
    pub async fn new(archive_path: &Path) -> Result<Self> {
        let checkpoint_manager = if tokio::fs::try_exists(archive_path).await?
            && volume_has_checkpoint(archive_path).await?
        {
            // Note: In V2.2, the actual checkpoint data is in the volume
            // CheckpointManager is kept for API compatibility but doesn't
            // manage sidecar files anymore
            Some(CheckpointManager::new(archive_path))
        } else {
            None
        };

        Ok(Self {
            archive_path: archive_path.to_path_buf(),
            checkpoint_manager,
        })
    }

    /// Check if recovery is available
    pub fn can_recover(&self) -> bool {
        self.checkpoint_manager.is_some()
    }

    /// Check if a file was already completed before interruption
    pub fn is_file_completed(&self, path: &Path) -> bool {
        self.checkpoint_manager
            .as_ref()
            .map(|m| m.is_file_completed(path))
            .unwrap_or(false)
    }

    /// Get the location of a chunk if it was already written
    /// Uses reference to avoid cloning the entire map
    pub fn get_chunk_location(&self, hash: &ChunkHash) -> Option<BlockLocation> {
        self.checkpoint_manager
            .as_ref()
            .and_then(|m| m.get_chunk_location(hash).cloned())
    }

    /// Get all completed files
    pub fn completed_files(&self) -> Vec<PathBuf> {
        self.checkpoint_manager
            .as_ref()
            .map(|m| m.checkpoint().get_completed_files())
            .unwrap_or_default()
    }

    /// Get the in-progress file if any
    pub fn in_progress_file(&self) -> Option<&InProgressFile> {
        self.checkpoint_manager
            .as_ref()
            .and_then(|m| m.checkpoint().in_progress_file.as_ref())
    }

    /// Get total bytes written before interruption
    pub fn bytes_written(&self) -> u64 {
        self.checkpoint_manager
            .as_ref()
            .map(|m| m.checkpoint().total_bytes_written)
            .unwrap_or(0)
    }

    /// Get the current volume number from checkpoint
    pub fn current_volume(&self) -> u16 {
        self.checkpoint_manager
            .as_ref()
            .map(|m| m.checkpoint().current_volume)
            .unwrap_or(0)
    }

    /// Get the current offset from checkpoint
    pub fn current_offset(&self) -> u64 {
        self.checkpoint_manager
            .as_ref()
            .map(|m| m.checkpoint().current_offset)
            .unwrap_or(0)
    }

    /// Clean up checkpoint after successful archive completion
    pub fn cleanup(self) -> Result<()> {
        if let Some(manager) = self.checkpoint_manager {
            info!(
                "Cleaning up checkpoint for {:?}",
                self.archive_path.display()
            );
            manager.delete()?;
        }
        Ok(())
    }

    /// Truncate the archive file to the last committed data boundary.
    ///
    /// Reads the footer's `data_end_offset` and truncates the file to that
    /// size, removing any partial writes past the last committed point.
    /// This implements CLAUDE.md §6 Step 4.
    ///
    /// Returns the new file size, or an error if the archive has no valid footer.
    pub async fn truncate_to_checkpoint(&self) -> Result<u64> {
        self.truncate_to_checkpoint_with_manifest(None).await
    }

    pub async fn truncate_to_checkpoint_with_manifest(
        &self,
        manifest: Option<&era_common::ArchiveManifest>,
    ) -> Result<u64> {
        self.truncate_to_checkpoint_with_cancel_flag_and_manifest(
            Arc::new(AtomicBool::new(false)),
            manifest,
        )
        .await
    }

    async fn truncate_to_checkpoint_with_cancel_flag_and_manifest(
        &self,
        cancel_flag: Arc<AtomicBool>,
        manifest: Option<&era_common::ArchiveManifest>,
    ) -> Result<u64> {
        if !tokio::fs::try_exists(&self.archive_path).await? {
            return Err(EraError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Archive not found: {:?}", self.archive_path),
            )));
        }

        if cancel_flag.load(Ordering::Relaxed) {
            return Err(EraError::Other(
                "Operation cancelled during truncate_to_checkpoint".into(),
            ));
        }

        // Open single VolumeReader for all operations (TOCTOU fix)
        let parent_dir = self.archive_path.parent().unwrap_or(Path::new("."));
        let backend = LocalStorageBackend::new(parent_dir);
        let volume_name = self.archive_path.file_name().unwrap_or_default();
        let reader = VolumeReader::open(&backend, Path::new(volume_name)).await?;

        let data_end = reader.footer().map(|f| f.data_end_offset()).unwrap_or(0);
        if data_end == 0 {
            return Err(EraError::InvalidConfig(
                "Cannot truncate: no valid footer with data_end_offset".into(),
            ));
        }

        // Structural integrity check: ensure truncation doesn't destroy manifest block.
        // Skip for archives without manifest (backward compat).
        if let Some(footer) = reader.footer() {
            if footer.has_manifest() {
                let manifest_offset = footer.manifest_offset();
                let header_bytes = reader.read_raw(manifest_offset, BlockHeader::SIZE).await?;
                let manifest_block_end =
                    if let Some(header) = BlockHeader::from_bytes(&header_bytes) {
                        manifest_offset + BlockHeader::SIZE as u64 + u64::from(header.length)
                    } else {
                        manifest_offset + BlockHeader::SIZE as u64
                    };
                if data_end < manifest_block_end {
                    return Err(EraError::IntegrityError(format!(
                        "data_end ({}) is below manifest block end ({}); truncation would destroy manifest",
                        data_end, manifest_block_end
                    )));
                }

                // Manifest committed_end integrity check
                if let Some(manifest) = manifest {
                    let committed_ends = &manifest.volume_committed_ends;
                    let seq = reader.header().volume_sequence();
                    if let Some(&committed_end) = committed_ends.get(usize::from(seq)) {
                        if data_end < committed_end {
                            return Err(EraError::IntegrityError(format!(
                                "Volume {} footer data_end_offset {} is less than manifest committed end {}. \
                                 This indicates footer corruption or manifest mismatch.",
                                seq, data_end, committed_end
                            )));
                        }
                    }
                }
            }
        }

        if cancel_flag.load(Ordering::Relaxed) {
            return Err(EraError::Other(
                "Operation cancelled during truncate_to_checkpoint".into(),
            ));
        }

        self.truncate_file_with_cancel_flag(data_end, cancel_flag)
            .await?;

        info!(
            "Truncated {:?} to {} bytes (data_end_offset from footer)",
            self.archive_path, data_end
        );

        Ok(data_end)
    }

    async fn truncate_file_with_cancel_flag(
        &self,
        data_end: u64,
        cancel_flag: Arc<AtomicBool>,
    ) -> Result<()> {
        let archive_path = self.archive_path.clone();
        let cancel_flag_clone = Arc::clone(&cancel_flag);
        spawn_blocking(move || {
            #[cfg(test)]
            cancel_test_hook::checkpoint();

            if cancel_flag_clone.load(Ordering::Relaxed) {
                return Err(EraError::Other(
                    "Operation cancelled during truncate_to_checkpoint".into(),
                ));
            }
            let file = std::fs::File::options().write(true).open(&archive_path)?;

            if cancel_flag_clone.load(Ordering::Relaxed) {
                return Err(EraError::Other(
                    "Operation cancelled during truncate_to_checkpoint".into(),
                ));
            }

            file.set_len(data_end)?;

            if cancel_flag_clone.load(Ordering::Relaxed) {
                return Err(EraError::Other(
                    "Operation cancelled during truncate_to_checkpoint".into(),
                ));
            }

            file.sync_all()?;
            Ok::<(), EraError>(())
        })
        .await
        .map_err(|e| EraError::Other(format!("spawn_blocking join error: {}", e)))??;
        Ok(())
    }
}

/// Strategy for handling recovery
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryStrategy {
    /// Start fresh, ignoring any checkpoint
    StartFresh,

    /// Resume from checkpoint, skipping already-processed files
    Resume,

    /// Abort - return error if checkpoint exists, requiring user decision
    Abort,
}

/// Options for recovery behavior
#[derive(Debug, Clone)]
pub struct RecoveryOptions {
    /// Strategy to use when checkpoint exists
    pub strategy: RecoveryStrategy,

    /// Whether to verify chunks before skipping them
    pub verify_existing_chunks: bool,

    /// Whether to backup the incomplete archive before recovery
    pub backup_before_recovery: bool,
}

impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            strategy: RecoveryStrategy::Resume,
            verify_existing_chunks: false, // Skip verification for speed
            backup_before_recovery: false,
        }
    }
}

impl RecoveryOptions {
    /// Create options that start fresh (no recovery)
    pub fn start_fresh() -> Self {
        Self {
            strategy: RecoveryStrategy::StartFresh,
            ..Default::default()
        }
    }

    /// Create options that resume from checkpoint
    pub fn resume() -> Self {
        Self {
            strategy: RecoveryStrategy::Resume,
            ..Default::default()
        }
    }

    /// Create options that resume with verification
    pub fn resume_with_verification() -> Self {
        Self {
            strategy: RecoveryStrategy::Resume,
            verify_existing_chunks: true,
            ..Default::default()
        }
    }
}

pub struct RecoverableWriter {
    checkpoint: CheckpointManager,
    options: RecoveryOptions,
}

impl std::fmt::Debug for RecoverableWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoverableWriter")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl RecoverableWriter {
    /// Create a recoverable writer for in-memory checkpoint tracking only.
    pub async fn new(archive_path: &Path, options: RecoveryOptions) -> Result<Self> {
        // Handle Abort strategy - return error if checkpoint exists
        if options.strategy == RecoveryStrategy::Abort
            && CheckpointManager::exists(archive_path).await?
        {
            return Err(EraError::CheckpointError(
                "Checkpoint exists and Abort strategy specified. \
                 Use Resume to continue or StartFresh to discard progress."
                    .into(),
            ));
        }

        // Determine whether to use existing checkpoint or create new
        let checkpoint = match options.strategy {
            RecoveryStrategy::StartFresh => {
                // Delete any existing checkpoint and start fresh
                if CheckpointManager::exists(archive_path).await? {
                    warn!(
                        "Starting fresh, deleting existing checkpoint for {:?}",
                        archive_path.display()
                    );
                    let old = CheckpointManager::load_or_create(archive_path)?;
                    old.delete()?;
                }
                CheckpointManager::new(archive_path)
            }
            RecoveryStrategy::Resume => {
                return Err(EraError::CheckpointError(
                    "RecoverableWriter does not support durable resume. \
                     Use ArchiveWriterBuilder with recovery_options(RecoveryOptions::resume()) \
                     to load an in-volume checkpoint."
                        .into(),
                ));
            }
            RecoveryStrategy::Abort => {
                return Err(EraError::CheckpointError(
                    "Abort strategy specified but no checkpoint exists to abort. \
                     Use StartFresh to begin a new archive."
                        .into(),
                ));
            }
        };

        Ok(Self {
            checkpoint,
            options,
        })
    }

    /// Check if a file should be skipped (already processed)
    pub fn should_skip_file(&self, path: &Path) -> bool {
        self.options.strategy == RecoveryStrategy::Resume && self.checkpoint.is_file_completed(path)
    }

    /// Check if a chunk was already written
    pub fn get_existing_chunk(&self, hash: &ChunkHash) -> Option<BlockLocation> {
        if self.options.strategy == RecoveryStrategy::Resume {
            self.checkpoint.get_chunk_location(hash).cloned()
        } else {
            None
        }
    }

    /// Record that a file has been completed
    pub fn mark_file_completed(&mut self, path: &Path) -> Result<()> {
        self.checkpoint.mark_file_completed(path)
    }

    /// Record that a chunk has been written
    pub fn record_chunk(&mut self, hash: ChunkHash, location: BlockLocation) -> Result<()> {
        self.checkpoint.record_chunk(hash, location)
    }

    /// Start tracking a new file
    pub fn start_file(&mut self, path: &Path, size: u64) -> Result<()> {
        self.checkpoint.start_file(path, size)
    }

    /// Update progress on current file
    pub fn update_progress(&mut self, bytes_added: u64, chunks_added: u32) -> Result<()> {
        self.checkpoint
            .update_file_progress(bytes_added, chunks_added)
    }

    /// Update volume position
    pub fn update_position(&mut self, volume: u16, offset: u64, bytes: u64) -> Result<()> {
        self.checkpoint.update_position(volume, offset, bytes)
    }

    #[deprecated(
        since = "2.2.0",
        note = "Use commit_to_volume() for checkpoint persistence"
    )]
    pub fn sync(&mut self) -> Result<()> {
        #[allow(deprecated)]
        self.checkpoint.sync()
    }

    /// Finalize and clean up checkpoint after successful completion
    pub fn finalize(self) -> Result<()> {
        self.checkpoint.delete()
    }

    /// Get the checkpoint (for reading state)
    pub fn checkpoint(&self) -> &Checkpoint {
        self.checkpoint.checkpoint()
    }

    /// Get the recovery options
    pub fn options(&self) -> &RecoveryOptions {
        &self.options
    }
}

// ============ Unit Tests (TDD) ============

#[cfg(test)]
mod tests {
    use super::*;
    use era_common::VolumeId;
    use std::sync::mpsc;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use tempfile::TempDir;

    fn test_hash(byte: u8) -> ChunkHash {
        ChunkHash::from_bytes([byte; 32])
    }

    fn test_location(offset: u64, size: u32) -> BlockLocation {
        BlockLocation::single(VolumeId::default(), 0, offset, size)
    }

    // ============ RecoveryStatus Tests ============

    #[tokio::test]
    async fn test_analyze_no_checkpoint() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("test.era");

        let status = RecoveryManager::analyze(&archive_path).await.unwrap();

        assert!(!status.checkpoint_exists);
        assert!(!status.archive_exists);
        assert!(!status.recovery_needed);
        assert!(status.completed_files.is_empty());
        assert!(status.in_progress_file.is_none());
    }

    // ============ RecoveryManager Tests ============

    #[tokio::test]
    async fn test_recovery_manager_no_checkpoint() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("test.era");

        let manager = RecoveryManager::new(&archive_path).await.unwrap();

        assert!(!manager.can_recover());
        assert!(!manager.is_file_completed(Path::new("/any/file.txt")));
        assert!(manager.completed_files().is_empty());
    }

    // ============ RecoveryOptions Tests ============

    #[test]
    fn test_recovery_options_default() {
        let opts = RecoveryOptions::default();
        assert_eq!(opts.strategy, RecoveryStrategy::Resume);
        assert!(!opts.verify_existing_chunks);
    }

    #[test]
    fn test_recovery_options_start_fresh() {
        let opts = RecoveryOptions::start_fresh();
        assert_eq!(opts.strategy, RecoveryStrategy::StartFresh);
    }

    // ============ RecoverableWriter Tests ============

    #[tokio::test]
    async fn test_recoverable_writer_new_fresh() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("test.era");

        let writer = RecoverableWriter::new(&archive_path, RecoveryOptions::start_fresh())
            .await
            .unwrap();

        assert!(!writer.should_skip_file(Path::new("/any/file.txt")));
        assert!(writer.get_existing_chunk(&test_hash(1)).is_none());
    }

    #[tokio::test]
    async fn test_recoverable_writer_abort_without_checkpoint() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("test.era");

        let opts = RecoveryOptions {
            strategy: RecoveryStrategy::Abort,
            ..Default::default()
        };
        // Abort strategy should return a CheckpointError, not panic
        let result = RecoverableWriter::new(&archive_path, opts).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, era_common::EraError::CheckpointError(_)),
            "Expected CheckpointError, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_recoverable_writer_resume_is_explicitly_unsupported() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("test.era");

        let err = RecoverableWriter::new(&archive_path, RecoveryOptions::resume())
            .await
            .unwrap_err();

        assert!(
            matches!(err, era_common::EraError::CheckpointError(_)),
            "Expected CheckpointError, got: {err:?}"
        );

        let msg = err.to_string();
        assert!(
            msg.contains("does not support durable resume") && msg.contains("ArchiveWriterBuilder"),
            "resume error should direct callers to the supported durable path, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_recoverable_writer_tracking() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("test.era");

        let mut writer = RecoverableWriter::new(&archive_path, RecoveryOptions::start_fresh())
            .await
            .unwrap();

        // Track progress
        writer
            .start_file(Path::new("/new_file.txt"), 10000)
            .unwrap();
        writer.update_progress(5000, 3).unwrap();
        writer
            .record_chunk(test_hash(99), test_location(500, 250))
            .unwrap();
        writer
            .mark_file_completed(Path::new("/new_file.txt"))
            .unwrap();
        writer.update_position(0, 1000, 1000).unwrap();

        // Verify state
        let cp = writer.checkpoint();
        assert!(cp.is_file_completed(Path::new("/new_file.txt")));
        assert!(cp.get_chunk_location(&test_hash(99)).is_some());
        assert_eq!(cp.total_bytes_written, 1000);

        #[allow(deprecated)]
        writer.sync().unwrap();
        writer.finalize().unwrap();

        // V2.2: Checkpoint is no longer a sidecar file, so this check is no longer valid
        // assert!(!CheckpointManager::exists(&archive_path));
    }

    #[tokio::test]
    async fn test_truncate_to_checkpoint_respects_pre_cancellation() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("cancel_truncate.era");
        std::fs::write(&archive_path, vec![0u8; 1024]).unwrap();

        let manager = RecoveryManager::new(&archive_path).await.unwrap();
        let cancelled = Arc::new(AtomicBool::new(true));

        let result = manager
            .truncate_to_checkpoint_with_cancel_flag_and_manifest(Arc::clone(&cancelled), None)
            .await;

        assert!(
            result.is_err(),
            "cancelled truncate must return explicit error"
        );
        let msg = result.unwrap_err().to_string().to_lowercase();
        assert!(
            msg.contains("cancel"),
            "expected cancellation error message, got: {msg}"
        );
        assert!(
            cancelled.load(Ordering::Relaxed),
            "test cancellation flag should remain set"
        );
    }

    #[tokio::test]
    async fn test_truncate_to_checkpoint_respects_inflight_cancellation() {
        let temp = TempDir::new().unwrap();
        let archive_path = temp.path().join("cancel_truncate_inflight.era");
        std::fs::write(&archive_path, vec![0u8; 4096]).unwrap();

        let manager = RecoveryManager::new(&archive_path).await.unwrap();

        let (entered_tx, entered_rx) = mpsc::channel();
        let (proceed_tx, proceed_rx) = mpsc::channel();
        cancel_test_hook::install(cancel_test_hook::Hook {
            entered_tx,
            proceed_rx,
        });

        let cancelled = Arc::new(AtomicBool::new(false));
        let cancel_for_task = Arc::clone(&cancelled);
        let task = tokio::spawn(async move {
            manager
                .truncate_file_with_cancel_flag(1024, cancel_for_task)
                .await
        });

        tokio::task::spawn_blocking(move || {
            entered_rx.recv_timeout(std::time::Duration::from_secs(30))
        })
        .await
        .expect("join while waiting for blocking truncate hook")
        .expect("spawn_blocking truncate closure should enter before cancellation");
        cancelled.store(true, Ordering::Relaxed);
        proceed_tx
            .send(())
            .expect("should release blocking truncate hook");

        let result = task.await.expect("join should succeed");
        cancel_test_hook::clear();

        assert!(
            result.is_err(),
            "in-flight cancelled truncate must return explicit error"
        );
        let msg = result.unwrap_err().to_string().to_lowercase();
        assert!(
            msg.contains("cancel"),
            "expected cancellation error message, got: {msg}"
        );
    }
}
