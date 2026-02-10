use async_trait::async_trait;
use bytes::Bytes;
use era_common::{ArchiveConfig, ArchiveId, BlockId, EncryptedMacroBlock, Result};
use era_storage::{LocalStorageBackend, StorageBackend, StorageMetadata};
use era_volume::{MultiVolumeConfig, MultiVolumeWriter, SuperHeader, VolumeReader};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

// Mock Backend to simulate failures
#[derive(Clone)]
struct FaultyBackend {
    inner: LocalStorageBackend,
    fail_on_create: Arc<Mutex<HashSet<PathBuf>>>,
}

impl FaultyBackend {
    fn new(path: &Path) -> Self {
        Self {
            inner: LocalStorageBackend::new(path),
            fail_on_create: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    fn fail_on_create(&self, filename: &str) {
        self.fail_on_create
            .lock()
            .unwrap()
            .insert(PathBuf::from(filename));
    }
}

#[async_trait]
impl StorageBackend for FaultyBackend {
    type Writer = <LocalStorageBackend as StorageBackend>::Writer;
    type Reader = <LocalStorageBackend as StorageBackend>::Reader;

    async fn create(&self, path: &Path) -> Result<Self::Writer> {
        let should_fail = {
            let guard = self.fail_on_create.lock().unwrap();
            // Check if any registered failure path ends with the requested path
            guard.iter().any(|p| path.ends_with(p))
        };

        if should_fail {
            return Err(era_common::EraError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Simulated failure on create",
            )));
        }
        self.inner.create(path).await
    }

    async fn open_append(&self, path: &Path) -> Result<Self::Writer> {
        self.inner.open_append(path).await
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

#[tokio::test]
async fn test_atomicity_failure_recovery() {
    let temp_dir = TempDir::new().unwrap();
    let backend = FaultyBackend::new(temp_dir.path());
    let base_name = "failure_test";

    // Very small volume size
    let max_volume_size = 64 * 1024; // 64 KB

    let config = MultiVolumeConfig::new(base_name, max_volume_size).unwrap();

    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![],
        ArchiveConfig::default(),
        [0u8; 16],
        era_volume::EncryptedVolumeKey {
            algorithm: era_volume::KeyWrapAlgorithm::XChaCha20Poly1305,
            nonce: [0u8; 24],
            ciphertext: vec![0u8; 48],
        },
        era_volume::AccessPolicy::AnyOfN,
    );

    let mut multi_writer = MultiVolumeWriter::create(&backend, config.clone(), header)
        .await
        .unwrap();

    let block_data = Bytes::from(vec![0xAAu8; 1024]);
    let block = EncryptedMacroBlock {
        block_id: BlockId::new(0),
        data: block_data,
        original_size: 1024,
        compressed_size: 1024,
        chunk_count: 1,
    };

    backend.fail_on_create("failure_test.era.001");

    let mut failure_caught = false;
    let mut last_successful_block = 0;

    // Write many blocks. One should trigger the split and fail.
    for i in 0..100 {
        let mut b = block.clone();
        b.block_id = BlockId::new(i);

        match multi_writer.write_block(&backend, &b).await {
            Ok(_) => {
                last_successful_block = i;
            }
            Err(_) => {
                failure_caught = true;
                break;
            }
        }
    }

    assert!(failure_caught, "Should have failed to create second volume");

    // Clear failure
    {
        let mut guard = backend.fail_on_create.lock().unwrap();
        guard.clear();
    }

    // Retry writing
    let b_retry = EncryptedMacroBlock {
        block_id: BlockId::new(last_successful_block + 1),
        data: Bytes::from(vec![0xBBu8; 1024]),
        original_size: 1024,
        compressed_size: 1024,
        chunk_count: 1,
    };

    let result = multi_writer.write_block(&backend, &b_retry).await;
    assert!(
        result.is_ok(),
        "Retry should succeed after fixing backend issue"
    );

    multi_writer.finalize().await.unwrap();

    // 3. Verify sequences
    let vol1_path = temp_dir.path().join("failure_test.era.001");
    assert!(vol1_path.exists(), "Volume 1 should exist");

    // Check Sequence Number
    // Use underlying valid backend to read
    let real_backend = LocalStorageBackend::new(temp_dir.path());

    let reader = VolumeReader::open(&real_backend, Path::new("failure_test.era.001"))
        .await
        .expect("Should open volume 1");

    // BUG CHECK: If sequence is 2, it skipped 1.
    assert_eq!(
        reader.header().volume_sequence,
        1,
        "Volume 1 should have sequence number 1. If 2, atomicity failure occurred."
    );
}
