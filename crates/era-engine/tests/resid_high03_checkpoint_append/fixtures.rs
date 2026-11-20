use era_common::{ArchiveConfig, ArchiveManifest, BlockHeader, BlockType, ChunkHash};
use era_engine::{ArchiveReader, ArchiveWriter, CheckpointManager, ExtractOptions};
use era_volume::Footer;
use std::{fs, path::Path};
use tempfile::TempDir;

pub const PASSWORD: &str = "resid-high03-checkpoint-append";
pub const ORIGINAL_NAME: &str = "original.txt";
pub const ORIGINAL_BYTES: &[u8] = b"original bytes committed before the checkpointed append";
pub const APPENDED_NAME: &str = "appended.txt";
pub const APPENDED_BYTES: &[u8] = b"new bytes committed by the checkpointed append session";

pub fn non_ec_config() -> ArchiveConfig {
    ArchiveConfig {
        erasure: None,
        ..Default::default()
    }
}

pub fn chunk_hash(data: &[u8]) -> ChunkHash {
    ChunkHash(*blake3::hash(data).as_bytes())
}

pub async fn create_original(
    archive_path: &Path,
    original: Option<(&str, &[u8])>,
    config: ArchiveConfig,
) {
    let mut writer = ArchiveWriter::builder(archive_path)
        .password(PASSWORD)
        .config(config)
        .enable_checkpoint(true)
        .enable_erasure(false)
        .build()
        .await
        .unwrap();
    if let Some((name, bytes)) = original {
        writer.add_bytes(name, bytes).await.unwrap();
    }
    writer.finalize().await.unwrap();
}

pub struct AppendOptions {
    pub checkpoint: bool,
    pub config: ArchiveConfig,
}

pub async fn append_files(
    archive_path: &Path,
    files: &[(String, Vec<u8>)],
    options: AppendOptions,
) {
    let AppendOptions { checkpoint, config } = options;
    let mut writer = ArchiveWriter::builder(archive_path)
        .password(PASSWORD)
        .config(config)
        .append_existing(true)
        .enable_checkpoint(checkpoint)
        .enable_erasure(false)
        .build()
        .await
        .unwrap();
    for (name, bytes) in files {
        writer.add_bytes(name, bytes).await.unwrap();
    }
    writer.finalize().await.unwrap();
}

pub async fn read_metadata(archive_path: &Path) -> (ArchiveManifest, Footer) {
    let mut reader = ArchiveReader::open(archive_path, PASSWORD).await.unwrap();
    reader.preflight_metadata_recovery().await.unwrap();
    (
        reader.manifest().expect("manifest").clone(),
        reader.primary_footer().expect("footer").clone(),
    )
}

pub fn block_header(bytes: &[u8], offset: u64) -> BlockHeader {
    let start = usize::try_from(offset).unwrap();
    BlockHeader::from_bytes(&bytes[start..start + BlockHeader::SIZE]).unwrap()
}

pub fn block_end(offset: u64, header: &BlockHeader) -> u64 {
    offset + BlockHeader::SIZE as u64 + u64::from(header.length)
}

pub fn checkpoint_end(archive_path: &Path, footer: &Footer) -> u64 {
    let bytes = fs::read(archive_path).unwrap();
    let offset = footer.last_checkpoint_offset();
    assert!(offset > 0, "fixture must have a checkpoint");
    let header = block_header(&bytes, offset);
    assert_eq!(header.block_type, BlockType::Checkpoint);
    block_end(offset, &header)
}

pub async fn assert_new_single_data_horizon(archive_path: &Path) -> u64 {
    let (manifest, footer) = read_metadata(archive_path).await;
    assert_eq!(manifest.volume_committed_ends.len(), 1);
    let checkpoint = footer.last_checkpoint_offset();
    let expected = if checkpoint > 0 {
        checkpoint
    } else {
        footer.catalog_offset()
    };
    assert_eq!(manifest.volume_committed_ends[0], expected);
    assert_eq!(manifest.committed_horizon, expected);

    let bytes = fs::read(archive_path).unwrap();
    let first_metadata = block_header(&bytes, expected);
    if checkpoint > 0 {
        assert_eq!(first_metadata.block_type, BlockType::Checkpoint);
        assert_eq!(
            block_end(expected, &first_metadata),
            footer.catalog_offset()
        );
    } else {
        assert_eq!(first_metadata.block_type, BlockType::Catalog);
    }
    expected
}

pub async fn assert_extraction(archive_path: &Path, expected: &[(String, Vec<u8>)]) {
    let output = TempDir::new().unwrap();
    let mut reader = ArchiveReader::open(archive_path, PASSWORD).await.unwrap();
    let stats = reader
        .extract_all(&ExtractOptions::new(output.path()))
        .await
        .unwrap();
    assert_eq!(stats.extracted, u64::try_from(expected.len()).unwrap());
    for (name, bytes) in expected {
        assert_eq!(fs::read(output.path().join(name)).unwrap(), *bytes);
    }
}

pub async fn durable_checkpoint(archive_path: &Path) -> CheckpointManager {
    let reader = ArchiveReader::open(archive_path, PASSWORD).await.unwrap();
    CheckpointManager::load_from_durable_checkpoint(
        archive_path,
        reader.session(),
        reader.volume_key(),
        *reader.header().salt(),
        reader.archive_id_bytes(),
        reader.epoch_id(),
    )
    .await
    .unwrap()
}
