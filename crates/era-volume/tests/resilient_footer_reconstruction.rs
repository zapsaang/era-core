use era_common::{ArchiveConfig, ArchiveId, ErasureCodeConfig, Result};
use era_storage::{LocalStorageBackend, StorageBackend, StorageWriter};
use era_volume::{SuperHeader, VolumeReader, VolumeWriter};
use std::path::Path;
use tempfile::TempDir;

const TEST_VERIFICATION_TAG: [u8; 16] = [0xABu8; 16];

#[test]
fn test_resilient_footer_open_with_erasure() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let path = Path::new("test_resilient.era");

    // 1. Create a volume configuration WITH erasure coding
    let mut config = ArchiveConfig::default();
    config.erasure = Some(ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    });

    let header = SuperHeader::new(ArchiveId::new(), [0u8; 16], TEST_VERIFICATION_TAG, config);

    // 2. Write a valid volume first
    let writer = VolumeWriter::create(&backend, path, header.clone())?;
    writer.finalize()?;

    // 3. Corrupt the footer manually
    // The footer is at the end. We must corrupt the VALID part of the footer.
    // Footer is 128 bytes. The first 4 bytes are length.
    {
        use std::fs::OpenOptions;
        use std::io::Seek;
        use std::io::Write;

        let file_path = temp_dir.path().join(path);
        let mut file = OpenOptions::new().write(true).open(file_path).unwrap();

        // Go to start of footer (128 bytes before end)
        file.seek(std::io::SeekFrom::End(-128)).unwrap();

        // Trash the whole footer
        file.write_all(&[0xFF; 128]).unwrap();

        // Ensure changes are on disk
        file.sync_all().unwrap();
    }

    // 4. Try to open with VolumeReader
    // This should SUCCESS now because erasure is enabled in header
    let reader = VolumeReader::open(&backend, path);
    assert!(
        reader.is_ok(),
        "Should open successfully despite corrupted footer when erasure is enabled"
    );

    let reader = reader.unwrap();

    // 5. Verify footer is None
    assert!(reader.footer().is_none(), "Footer should be None");

    // 6. Verify we can still read parts (like header)
    assert_eq!(reader.header().archive_id.0, header.archive_id.0);

    Ok(())
}

#[test]
fn test_fail_without_erasure() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let path = Path::new("test_fragile.era");

    // 1. Create a volume configuration WITHOUT erasure coding
    let config = ArchiveConfig::default(); // erasure is None by default

    let header = SuperHeader::new(ArchiveId::new(), [0u8; 16], TEST_VERIFICATION_TAG, config);

    // 2. Write
    let writer = VolumeWriter::create(&backend, path, header)?;
    writer.finalize()?;

    // 3. Corrupt footer
    {
        use std::fs::OpenOptions;
        use std::io::Seek;
        use std::io::Write;
        let file_path = temp_dir.path().join(path);
        let mut file = OpenOptions::new().write(true).open(file_path).unwrap();

        file.seek(std::io::SeekFrom::End(-128)).unwrap();
        file.write_all(&[0xFF; 128]).unwrap();
        file.sync_all().unwrap();
    }

    // 4. Try to open - SHOULD FAIL
    let reader = VolumeReader::open(&backend, path);
    assert!(
        reader.is_err(),
        "Should fail when footer is corrupted and erasure is disabled"
    );

    Ok(())
}
