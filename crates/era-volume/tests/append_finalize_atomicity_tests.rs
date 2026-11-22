use async_trait::async_trait;
use bytes::Bytes;
use era_common::{
    ArchiveConfig, ArchiveId, BlockId, BlockType, EncryptedMacroBlock, EraError, Result,
};
use era_storage::{
    LocalStorageBackend, LocalStorageReader, LocalStorageWriter, StorageBackend, StorageMetadata,
    StorageWriter,
};
use era_volume::{
    AccessPolicy, EncryptedVolumeKey, KeyWrapAlgorithm, RecipientSlot, RecipientType, SuperHeader,
    VolumeReader, VolumeWriter, DATA_REGION_START, HEADER_SIZE,
};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

#[derive(Clone, Copy, PartialEq, Eq)]
enum FailureMode {
    None,
    /// Fail every write/sync after the first truncate (simulating process death right after truncate).
    PermanentAfterTruncate,
    /// Fail only the first append after truncate, allowing rollback writes to succeed.
    TransientOnceAfterTruncate,
}

#[derive(Default)]
struct FaultState {
    mode: Option<FailureMode>,
    truncate_seen: bool,
    transient_fired: bool,
    ops: Vec<String>,
}

#[derive(Clone)]
struct RecordingFaultBackend {
    inner: LocalStorageBackend,
    state: Arc<Mutex<FaultState>>,
}

impl RecordingFaultBackend {
    fn new(root: &Path) -> Self {
        Self {
            inner: LocalStorageBackend::new(root),
            state: Arc::new(Mutex::new(FaultState::default())),
        }
    }

    fn set_mode(&self, mode: FailureMode) {
        let mut guard = self.state.lock().unwrap();
        guard.mode = Some(mode);
        guard.truncate_seen = false;
        guard.transient_fired = false;
    }

    fn clear_ops(&self) {
        self.state.lock().unwrap().ops.clear();
    }

    fn ops(&self) -> Vec<String> {
        self.state.lock().unwrap().ops.clone()
    }
}

struct RecordingFaultWriter {
    inner: LocalStorageWriter,
    state: Arc<Mutex<FaultState>>,
}

impl RecordingFaultWriter {
    fn should_fail_after_truncate(&self, is_append: bool) -> bool {
        let mut guard = self.state.lock().unwrap();
        if !guard.truncate_seen {
            return false;
        }
        match guard.mode.unwrap_or(FailureMode::None) {
            FailureMode::None => false,
            FailureMode::PermanentAfterTruncate => true,
            FailureMode::TransientOnceAfterTruncate => {
                if is_append && !guard.transient_fired {
                    guard.transient_fired = true;
                    true
                } else {
                    false
                }
            }
        }
    }
}

#[async_trait]
impl StorageWriter for RecordingFaultWriter {
    async fn append(&mut self, data: &[u8]) -> Result<u64> {
        self.state
            .lock()
            .unwrap()
            .ops
            .push(format!("append:{}", data.len()));
        if self.should_fail_after_truncate(true) {
            return Err(EraError::Io(std::io::Error::other(
                "injected append failure after truncate",
            )));
        }
        self.inner.append(data).await
    }

    async fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        self.state
            .lock()
            .unwrap()
            .ops
            .push(format!("write_at:{offset}:{}", data.len()));
        if self.should_fail_after_truncate(false) {
            return Err(EraError::Io(std::io::Error::other(
                "injected write_at failure after truncate",
            )));
        }
        self.inner.write_at(offset, data).await
    }

    async fn sync(&mut self) -> Result<()> {
        self.state.lock().unwrap().ops.push("sync".to_string());
        if self.should_fail_after_truncate(false) {
            return Err(EraError::Io(std::io::Error::other(
                "injected sync failure after truncate",
            )));
        }
        self.inner.sync().await
    }

    async fn sync_data(&mut self) -> Result<()> {
        self.state.lock().unwrap().ops.push("sync_data".to_string());
        if self.should_fail_after_truncate(false) {
            return Err(EraError::Io(std::io::Error::other(
                "injected sync_data failure after truncate",
            )));
        }
        self.inner.sync_data().await
    }

    fn current_size(&self) -> u64 {
        self.inner.current_size()
    }

    async fn truncate(&mut self, size: u64) -> Result<()> {
        self.state
            .lock()
            .unwrap()
            .ops
            .push(format!("truncate:{size}"));
        let res = self.inner.truncate(size).await;
        if res.is_ok() {
            self.state.lock().unwrap().truncate_seen = true;
        }
        res
    }

    async fn close(self) -> Result<()> {
        self.state.lock().unwrap().ops.push("close".to_string());
        self.inner.close().await
    }
}

#[async_trait]
impl StorageBackend for RecordingFaultBackend {
    type Writer = RecordingFaultWriter;
    type Reader = LocalStorageReader;

    async fn create(&self, path: &Path) -> Result<Self::Writer> {
        let inner = self.inner.create(path).await?;
        Ok(RecordingFaultWriter {
            inner,
            state: Arc::clone(&self.state),
        })
    }

    async fn open_append(&self, path: &Path) -> Result<Self::Writer> {
        let inner = self.inner.open_append(path).await?;
        Ok(RecordingFaultWriter {
            inner,
            state: Arc::clone(&self.state),
        })
    }

    async fn open_read(&self, path: &Path) -> Result<Self::Reader> {
        self.inner.open_read(path).await
    }

    async fn exists(&self, path: &Path) -> bool {
        self.inner.exists(path).await
    }

    async fn delete(&self, path: &Path) -> Result<()> {
        self.inner.delete(path).await
    }

    async fn stat(&self, path: &Path) -> Result<StorageMetadata> {
        self.inner.stat(path).await
    }
}

fn test_header() -> SuperHeader {
    SuperHeader::new(
        ArchiveId::new(),
        vec![RecipientSlot::new(
            RecipientType::Argon2idPassword,
            Some([0x12; 8]),
            vec![0xAB; 16],
            vec![0xCD; 48],
        )],
        ArchiveConfig::default(),
        [0u8; 16],
        EncryptedVolumeKey::new(
            KeyWrapAlgorithm::XChaCha20Poly1305,
            [0u8; 24],
            vec![0u8; 48],
        ),
        AccessPolicy::AnyOfN,
    )
    .unwrap()
}

fn test_block(id: u64, byte: u8, size: usize) -> EncryptedMacroBlock {
    EncryptedMacroBlock {
        block_id: BlockId::new(id),
        data: Bytes::from(vec![byte; size]),
        original_size: size as u32,
        compressed_size: size as u32,
        chunk_count: 1,
    }
}

async fn create_initial_volume(backend: &RecordingFaultBackend, name: &str) -> (SuperHeader, u64) {
    let header = test_header();
    let mut writer = VolumeWriter::create(backend, Path::new(name), header.clone())
        .await
        .unwrap();
    let loc = writer
        .write_canonical_block(&test_block(0, 0x11, 2048), BlockType::Data)
        .await
        .unwrap();
    let retained_end = writer.current_size();
    assert!(retained_end > DATA_REGION_START);
    let catalog_loc = writer
        .write_canonical_block(&test_block(1, 0x22, 512), BlockType::Catalog)
        .await
        .unwrap();
    writer
        .finalize_with_catalog(
            catalog_loc.physical_offset,
            catalog_loc.encrypted_size,
            1,
            0,
            0,
            0,
        )
        .await
        .unwrap();
    let _ = loc;
    (header, retained_end)
}

#[tokio::test]
async fn permanent_failure_after_truncate_leaves_volume_openable_at_retained_end() {
    let temp = TempDir::new().unwrap();
    let backend = RecordingFaultBackend::new(temp.path());
    let (header, retained_end) = create_initial_volume(&backend, "perm.era").await;

    let reader = VolumeReader::open(&backend, Path::new("perm.era"))
        .await
        .unwrap();
    let footer = reader.footer().unwrap().clone();
    drop(reader);

    let mut writer = VolumeWriter::open_append_at(
        &backend,
        Path::new("perm.era"),
        header,
        &footer,
        retained_end,
        1,
    )
    .await
    .unwrap();
    writer
        .write_canonical_block(&test_block(1, 0x33, 4096), BlockType::Data)
        .await
        .unwrap();

    backend.set_mode(FailureMode::PermanentAfterTruncate);
    let err = writer.finalize().await.unwrap_err();
    assert!(
        matches!(err, EraError::Io(_)),
        "expected Io error, got {err:?}"
    );

    // Even if the process crashes permanently right after truncate, the backup footer
    // at offset 4096 was updated before truncate so the volume remains openable.
    let reopened = VolumeReader::open(&backend, Path::new("perm.era"))
        .await
        .expect("volume must remain openable when finalize fails permanently after truncate");
    let reopened_footer = reopened.footer().expect("reopened volume must have footer");
    assert_eq!(reopened_footer.data_end_offset(), retained_end);
    assert_eq!(reopened_footer.block_count(), 1);
}

#[tokio::test]
async fn transient_failure_after_truncate_rolls_back_to_byte_identical_volume() {
    let temp = TempDir::new().unwrap();
    let backend = RecordingFaultBackend::new(temp.path());
    let (header, retained_end) = create_initial_volume(&backend, "transient.era").await;
    let original_bytes = std::fs::read(temp.path().join("transient.era")).unwrap();

    let reader = VolumeReader::open(&backend, Path::new("transient.era"))
        .await
        .unwrap();
    let footer = reader.footer().unwrap().clone();
    drop(reader);

    let mut writer = VolumeWriter::open_append_at(
        &backend,
        Path::new("transient.era"),
        header,
        &footer,
        retained_end,
        1,
    )
    .await
    .unwrap();
    writer
        .write_canonical_block(&test_block(1, 0x44, 4096), BlockType::Data)
        .await
        .unwrap();

    backend.set_mode(FailureMode::TransientOnceAfterTruncate);
    let err = writer.finalize().await.unwrap_err();
    assert!(
        matches!(err, EraError::Io(_)),
        "expected Io error, got {err:?}"
    );

    let after_bytes = std::fs::read(temp.path().join("transient.era")).unwrap();
    assert_eq!(
        after_bytes, original_bytes,
        "transient finalize error after truncate must roll back to exact original bytes"
    );

    let reopened = VolumeReader::open(&backend, Path::new("transient.era"))
        .await
        .expect("rolled-back volume must reopen cleanly");
    assert!(!reopened.footer_recovered_from_backup());
    assert_eq!(
        reopened.footer().unwrap().data_end_offset(),
        footer.data_end_offset()
    );
}

#[tokio::test]
async fn growable_volume_finalize_executes_sync_data_before_header_and_backup_footer_writes() {
    let temp = TempDir::new().unwrap();
    let backend = RecordingFaultBackend::new(temp.path());
    let mut writer = VolumeWriter::create(&backend, Path::new("growable.era"), test_header())
        .await
        .unwrap();
    writer
        .write_canonical_block(&test_block(0, 0x55, 4096), BlockType::Data)
        .await
        .unwrap();
    backend.clear_ops();

    writer.finalize().await.unwrap();
    let ops = backend.ops();

    let backup_footer_write = format!("write_at:{HEADER_SIZE}:128");
    let backup_footer_pos = ops
        .iter()
        .position(|op| op == &backup_footer_write)
        .expect("backup footer write recorded");
    let primary_header_pos = ops
        .iter()
        .position(|op| op == "write_at:0:4096")
        .expect("primary header write recorded");
    let sync_data_pos = ops
        .iter()
        .position(|op| op == "sync_data")
        .expect("growable volume finalize must execute sync_data barrier");

    assert!(
        sync_data_pos < primary_header_pos && sync_data_pos < backup_footer_pos,
        "sync_data must occur before rewriting primary header and overwriting backup footer: {ops:?}"
    );
}

#[tokio::test]
async fn set_max_size_on_staged_append_writer_is_rejected_without_mutating_volume() {
    let temp = TempDir::new().unwrap();
    let backend = RecordingFaultBackend::new(temp.path());
    let (header, retained_end) = create_initial_volume(&backend, "set_max.era").await;
    let original_bytes = std::fs::read(temp.path().join("set_max.era")).unwrap();

    let reader = VolumeReader::open(&backend, Path::new("set_max.era"))
        .await
        .unwrap();
    let footer = reader.footer().unwrap().clone();
    drop(reader);

    let mut writer = VolumeWriter::open_append_at(
        &backend,
        Path::new("set_max.era"),
        header,
        &footer,
        retained_end,
        1,
    )
    .await
    .unwrap();
    writer
        .write_canonical_block(&test_block(1, 0x66, 2048), BlockType::Data)
        .await
        .unwrap();

    let err = writer.set_max_size(1024 * 1024).await.unwrap_err();
    assert!(
        matches!(err, EraError::InvalidConfig(_)),
        "expected InvalidConfig, got {err:?}"
    );
    assert_eq!(
        std::fs::read(temp.path().join("set_max.era")).unwrap(),
        original_bytes,
        "rejected set_max_size must not mutate on-disk volume"
    );
}

#[tokio::test]
async fn staged_append_uses_disk_spool_with_zero_heap_buffer_and_sync_data_persists() {
    let temp = TempDir::new().unwrap();
    let backend = RecordingFaultBackend::new(temp.path());
    let (header, retained_end) = create_initial_volume(&backend, "spool.era").await;
    let on_disk_before = std::fs::metadata(temp.path().join("spool.era"))
        .unwrap()
        .len();

    let reader = VolumeReader::open(&backend, Path::new("spool.era"))
        .await
        .unwrap();
    let footer = reader.footer().unwrap().clone();
    drop(reader);

    let mut writer = VolumeWriter::open_append_at(
        &backend,
        Path::new("spool.era"),
        header,
        &footer,
        retained_end,
        1,
    )
    .await
    .unwrap();

    // Write 4 MiB across two canonical blocks into the staged append session.
    let block_size = 2 * 1024 * 1024;
    writer
        .write_canonical_block(&test_block(1, 0x77, block_size), BlockType::Data)
        .await
        .unwrap();
    writer
        .write_canonical_block(&test_block(2, 0x88, block_size), BlockType::Data)
        .await
        .unwrap();

    assert_eq!(
        writer.staged_in_memory_bytes(),
        0,
        "staged append must not buffer appended payload in heap memory"
    );
    assert!(
        writer.staged_disk_bytes() > (2 * block_size) as u64,
        "staged append payload must be spooled to disk (got {} bytes)",
        writer.staged_disk_bytes()
    );
    assert_eq!(
        std::fs::metadata(temp.path().join("spool.era"))
            .unwrap()
            .len(),
        on_disk_before,
        "original archive on disk must stay untouched prior to finalize"
    );

    backend.clear_ops();
    writer.sync_data().await.unwrap();
    assert!(
        backend.ops().iter().any(|op| op == "sync_data"),
        "sync_data on staged writer must sync spool and propagate to underlying writer"
    );

    writer.finalize().await.unwrap();
    let reopened = VolumeReader::open(&backend, Path::new("spool.era"))
        .await
        .expect("finalized spooled append volume must open cleanly");
    assert_eq!(reopened.footer().unwrap().block_count(), 3);
}
