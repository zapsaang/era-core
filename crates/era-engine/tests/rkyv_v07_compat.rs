use std::fs;
use std::path::{Path, PathBuf};

use era_common::{ArchiveConfig, CompressionAlgorithm, EraError};
use era_crypto::{AeadContext, KdfParams, KeySession, Salt, XChaCha20Poly1305Context};
use era_engine::{auth::PasswordSlotParams, ArchiveReader, ArchiveWriter, ExtractOptions};
use era_volume::{RecipientType, SuperHeader};
use tempfile::TempDir;

const FIXTURE_PASSWORD: &str = "fixture-pass";
const FIXTURE_PAYLOAD: &str = "rkyv07 fixture payload\n";

fn fixture_archive_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rkyv_v07/sample_archive.era")
}

fn copy_fixture_archive(temp_dir: &TempDir) -> PathBuf {
    let archive_path = temp_dir.path().join("sample_archive.era");
    fs::copy(fixture_archive_path(), &archive_path).unwrap();
    archive_path
}

fn fixture_config() -> ArchiveConfig {
    let mut config = ArchiveConfig::default();
    config.compression.algorithm = CompressionAlgorithm::None;
    config.compression.level = 0;
    config.erasure = None;
    config
}

fn derive_session_from_header(
    header: &SuperHeader,
    password: &str,
) -> Result<KeySession, EraError> {
    let slot = header
        .recipients()
        .iter()
        .find(|s| s.r_type() == RecipientType::Argon2idPassword)
        .ok_or(EraError::InvalidKey("No password slot found".into()))?;

    let archived =
        rkyv::access::<rkyv::Archived<PasswordSlotParams>, rkyv::rancor::Error>(slot.params())
            .map_err(|e| EraError::Serialization(e.to_string()))?;

    let salt = Salt::from_bytes(archived.salt);
    let kdf_params = KdfParams {
        memory_cost: archived.kdf_memory_cost.into(),
        time_cost: archived.kdf_time_cost.into(),
        parallelism: archived.kdf_parallelism.into(),
    };

    let kek = era_crypto::derive_key(password.as_bytes(), &salt, &kdf_params)
        .map_err(|_| EraError::InvalidKey("KDF failed".into()))?;

    let combined = slot.encrypted_master_key();
    if combined.len() < 24 {
        return Err(EraError::InvalidKey("Invalid encrypted key length".into()));
    }
    let nonce_array: &[u8; 24] = combined[0..24]
        .try_into()
        .map_err(|_| EraError::InvalidKey("Invalid nonce".into()))?;
    let ciphertext = &combined[24..];

    let ctx = XChaCha20Poly1305Context::from_derived_key(&kek)
        .map_err(|_| EraError::InvalidKey("Failed to create context".into()))?;

    let mk = ctx
        .decrypt(
            nonce_array,
            era_engine::auth::MK_WRAP_AAD_DOMAIN,
            ciphertext,
        )
        .map_err(|_| EraError::InvalidKey("Incorrect password".into()))?;

    let mk_array: [u8; 32] = mk
        .try_into()
        .map_err(|_| EraError::InvalidKey("Invalid MK length".into()))?;
    KeySession::from_master_key(&mk_array)
}

#[tokio::test]
async fn test_rkyv_v07_fixture_archive_opens_and_extracts() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = copy_fixture_archive(&temp_dir);

    let mut reader = ArchiveReader::open(&archive_path, FIXTURE_PASSWORD)
        .await
        .unwrap();
    reader.verify().await.unwrap();
    reader.load_catalog().await.unwrap();

    let extract_dir = temp_dir.path().join("extract_password");
    fs::create_dir_all(&extract_dir).unwrap();

    reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .await
        .unwrap();

    let content = fs::read_to_string(extract_dir.join("input.txt")).unwrap();
    assert_eq!(content, FIXTURE_PAYLOAD);
}

#[tokio::test]
async fn test_rkyv_v07_fixture_archive_opens_with_session() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = copy_fixture_archive(&temp_dir);

    let reader_for_header = ArchiveReader::open(&archive_path, FIXTURE_PASSWORD)
        .await
        .unwrap();
    let session = derive_session_from_header(reader_for_header.header(), FIXTURE_PASSWORD).unwrap();
    drop(reader_for_header);

    let mut reader = ArchiveReader::open_with_session(&archive_path, &session)
        .await
        .unwrap();
    reader.load_catalog().await.unwrap();

    let extract_dir = temp_dir.path().join("extract_session");
    fs::create_dir_all(&extract_dir).unwrap();

    reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .await
        .unwrap();

    let content = fs::read_to_string(extract_dir.join("input.txt")).unwrap();
    assert_eq!(content, FIXTURE_PAYLOAD);
}

#[tokio::test]
async fn test_rkyv_v07_fixture_archive_appends_existing_data() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = copy_fixture_archive(&temp_dir);

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password(FIXTURE_PASSWORD)
        .append_existing(true)
        .config(fixture_config())
        .build()
        .await
        .unwrap();

    writer
        .add_bytes("copy.txt", FIXTURE_PAYLOAD.as_bytes())
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    let mut reader = ArchiveReader::open(&archive_path, FIXTURE_PASSWORD)
        .await
        .unwrap();
    reader.verify().await.unwrap();
    reader.load_catalog().await.unwrap();

    let extract_dir = temp_dir.path().join("extract_appended");
    fs::create_dir_all(&extract_dir).unwrap();

    reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .await
        .unwrap();

    assert_eq!(
        fs::read_to_string(extract_dir.join("input.txt")).unwrap(),
        FIXTURE_PAYLOAD
    );
    assert_eq!(
        fs::read_to_string(extract_dir.join("copy.txt")).unwrap(),
        FIXTURE_PAYLOAD
    );
}
