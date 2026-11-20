use era_common::ArchiveConfig;
use era_engine::{ArchiveHealthStatus, ArchiveReader, ArchiveWriter, ExtractOptions};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

const PASSWORD: &str = "resid-high03-packed-append";
const SHARED_PAYLOAD: &[u8] = b"same bytes must work as packed and raw chunks";
const SMALL_FILE_PACKING_LIMIT: usize = 16 * 1024;
const FORCED_FLUSH_FILLER_FILES: usize = 65;

fn non_ec_config() -> ArchiveConfig {
    ArchiveConfig {
        erasure: None,
        ..Default::default()
    }
}

async fn assert_healthy_and_extract(archive_path: &Path, expected_files: &[(String, Vec<u8>)]) {
    let mut reader = ArchiveReader::open(archive_path, PASSWORD).await.unwrap();
    let verify_stats = reader.verify().await.unwrap();
    assert_eq!(
        verify_stats.archive_health,
        ArchiveHealthStatus::Healthy,
        "raw references after packed writes must resolve; warnings={:?}; errors={:?}",
        verify_stats.warnings,
        verify_stats.errors
    );

    let extract_dir = TempDir::new().unwrap();
    let extract_stats = reader
        .extract_all(&ExtractOptions::new(extract_dir.path()))
        .await
        .unwrap();
    assert_eq!(
        extract_stats.extracted,
        u64::try_from(expected_files.len()).unwrap()
    );
    for (name, expected) in expected_files {
        let actual = fs::read(extract_dir.path().join(name)).unwrap();
        assert_eq!(
            actual.as_slice(),
            expected.as_slice(),
            "content mismatch for {name}"
        );
    }
}

#[tokio::test]
async fn raw_write_after_same_session_forced_pack_flush_verifies_and_extracts() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir(&input_dir).unwrap();
    let archive_path = temp_dir.path().join("same_session.era");

    let mut expected_files = vec![("packed.txt".to_owned(), SHARED_PAYLOAD.to_vec())];
    fs::write(input_dir.join("packed.txt"), SHARED_PAYLOAD).unwrap();
    for index in 0..FORCED_FLUSH_FILLER_FILES {
        let name = format!("flush_{index:02}.txt");
        let data = vec![u8::try_from(index).unwrap(); SMALL_FILE_PACKING_LIMIT - 1];
        fs::write(input_dir.join(&name), &data).unwrap();
        expected_files.push((name, data));
    }

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(non_ec_config())
        .enable_small_file_packing(true)
        .build()
        .await
        .unwrap();
    for (name, _) in &expected_files {
        writer.add_file(&input_dir.join(name)).await.unwrap();
    }
    // The near-limit files exceed the 1 MiB pack buffer before this write,
    // forcing the packed raw hash into the live dedup index through add_file.
    writer.add_bytes("raw.txt", SHARED_PAYLOAD).await.unwrap();
    expected_files.push(("raw.txt".to_owned(), SHARED_PAYLOAD.to_vec()));
    writer.finalize().await.unwrap();

    assert_healthy_and_extract(&archive_path, &expected_files).await;
}

#[tokio::test]
async fn raw_file_after_packed_write_in_prior_session_verifies_and_extracts() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir(&input_dir).unwrap();
    let packed_path = input_dir.join("packed.txt");
    let raw_path = input_dir.join("raw.txt");
    fs::write(&packed_path, SHARED_PAYLOAD).unwrap();
    fs::write(&raw_path, SHARED_PAYLOAD).unwrap();
    let archive_path = temp_dir.path().join("cross_session.era");

    let mut packed_writer = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(non_ec_config())
        .enable_small_file_packing(true)
        .build()
        .await
        .unwrap();
    packed_writer.add_file(&packed_path).await.unwrap();
    packed_writer.finalize().await.unwrap();

    let mut raw_writer = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(non_ec_config())
        .enable_small_file_packing(false)
        .append_existing(true)
        .build()
        .await
        .unwrap();
    raw_writer.add_file(&raw_path).await.unwrap();
    raw_writer.finalize().await.unwrap();

    let expected_files = vec![
        ("packed.txt".to_owned(), SHARED_PAYLOAD.to_vec()),
        ("raw.txt".to_owned(), SHARED_PAYLOAD.to_vec()),
    ];
    assert_healthy_and_extract(&archive_path, &expected_files).await;
}

#[tokio::test]
async fn raw_file_after_raw_write_in_prior_session_dedups_and_extracts() {
    let temp_dir = TempDir::new().unwrap();
    let input_dir = temp_dir.path().join("input");
    fs::create_dir(&input_dir).unwrap();
    let first_path = input_dir.join("first_raw.txt");
    let second_path = input_dir.join("second_raw.txt");
    fs::write(&first_path, SHARED_PAYLOAD).unwrap();
    fs::write(&second_path, SHARED_PAYLOAD).unwrap();
    let archive_path = temp_dir.path().join("raw_control.era");

    let mut first_writer = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(non_ec_config())
        .enable_small_file_packing(false)
        .build()
        .await
        .unwrap();
    first_writer.add_file(&first_path).await.unwrap();
    first_writer.finalize().await.unwrap();

    let mut second_writer = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(non_ec_config())
        .enable_small_file_packing(false)
        .append_existing(true)
        .build()
        .await
        .unwrap();
    second_writer.add_file(&second_path).await.unwrap();
    second_writer.finalize().await.unwrap();

    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    reader.preflight_metadata_recovery().await.unwrap();
    assert_eq!(
        reader.catalog().unwrap().block_locations.len(),
        1,
        "identical raw files must share their physical data block"
    );
    drop(reader);

    let expected_files = vec![
        ("first_raw.txt".to_owned(), SHARED_PAYLOAD.to_vec()),
        ("second_raw.txt".to_owned(), SHARED_PAYLOAD.to_vec()),
    ];
    assert_healthy_and_extract(&archive_path, &expected_files).await;
}
