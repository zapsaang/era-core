use era_common::BlockHeader;
use era_engine::{ArchiveReader, ArchiveWriter};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tempfile::TempDir;

const PASSWORD: &str = "find09-index-recovery";
const PAYLOAD: &[u8] = b"index recovery must resolve this exact chunk after a volume failure";

async fn create_two_volume_archive(archive_path: &Path) {
    let mut writer = ArchiveWriter::builder(archive_path)
        .password(PASSWORD)
        .enable_erasure(false)
        .volume_count(2)
        .build()
        .await
        .unwrap();
    writer.add_bytes("payload.bin", PAYLOAD).await.unwrap();
    writer.finalize().await.unwrap();
}

async fn assert_live_chunk_lookup(reader: &mut ArchiveReader) {
    reader.preflight_metadata_recovery().await.unwrap();
    assert!(!reader.embedded_index_recovery_failed());

    let hashes = reader.live_catalog_chunk_hashes().unwrap();
    assert_eq!(hashes.len(), 1, "fixture must contain one live chunk");
    let location = reader
        .index_reader()
        .expect("embedded index must be recovered")
        .lookup(&hashes[0])
        .unwrap()
        .expect("live chunk must resolve through the recovered index");

    let block_index = usize::try_from(location.block_id().sequence()).unwrap();
    let expected = &reader.catalog().unwrap().block_locations[block_index];
    assert_eq!(location.volume_id(), expected.volume_id);
    assert_eq!(
        u64::from(location.length()),
        u64::from(expected.encrypted_size)
    );
}

#[tokio::test]
async fn find09_index_lookup_recovers_when_volume_zero_is_missing() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("find09_missing_zero.era");
    create_two_volume_archive(&archive_path).await;

    fs::remove_file(&archive_path).unwrap();
    let volume_one = era_volume::volume_path(&archive_path, 1);
    let mut reader = ArchiveReader::open(&volume_one, PASSWORD).await.unwrap();

    assert_live_chunk_lookup(&mut reader).await;
}

#[tokio::test]
async fn find09_index_recovery_falls_back_when_first_manifest_is_unreadable() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("find09_bad_first.era");
    create_two_volume_archive(&archive_path).await;

    let backend = era_storage::LocalStorageBackend::new(temp_dir.path());
    let volume_name = Path::new(archive_path.file_name().unwrap());
    let volume = era_volume::VolumeReader::open(&backend, volume_name)
        .await
        .unwrap();
    let index_offset = volume.footer().unwrap().index_offset();
    drop(volume);

    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&archive_path)
        .unwrap();
    let payload_offset = index_offset + BlockHeader::SIZE as u64;
    file.seek(SeekFrom::Start(payload_offset)).unwrap();
    let mut original_byte = [0u8; 1];
    file.read_exact(&mut original_byte).unwrap();
    file.seek(SeekFrom::Start(payload_offset)).unwrap();
    file.write_all(&[!original_byte[0]]).unwrap();
    file.sync_all().unwrap();
    drop(file);

    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    assert_live_chunk_lookup(&mut reader).await;
}
