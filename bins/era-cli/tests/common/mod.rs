//! Shared test helpers for era-cli integration tests.
//! Usage: `mod common;` then `use common::*;`

#![allow(dead_code)]

use assert_cmd::Command;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub fn era_cmd() -> Command {
    Command::cargo_bin("era").unwrap()
}

pub fn era_binary_path() -> PathBuf {
    assert_cmd::cargo::cargo_bin("era")
}

pub fn create_test_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, content).unwrap();
    path
}

/// Prime modulus (251) avoids alignment artifacts in CDC chunking.
pub fn generate_deterministic_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

pub fn create_large_test_file(dir: &Path, name: &str, size_bytes: usize) -> PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let data = generate_deterministic_data(size_bytes);
    fs::write(&path, &data).unwrap();
    path
}

/// Streaming 1 MB writes to avoid OOM on GB-scale files.
pub fn create_large_deterministic_file(path: &Path, size: u64) {
    let mut f = fs::File::create(path).unwrap();
    let chunk_size = 1024 * 1024;
    let chunk: Vec<u8> = (0..chunk_size).map(|i| (i % 251) as u8).collect();
    let mut remaining = size;
    while remaining > 0 {
        let write_size = remaining.min(chunk_size as u64) as usize;
        f.write_all(&chunk[..write_size]).unwrap();
        remaining -= write_size as u64;
    }
    f.flush().unwrap();
}

/// Each 8-byte block contains its little-endian offset for byte-level verification.
pub fn create_large_test_file_streaming(dir: &Path, name: &str, size_bytes: usize) -> PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut file = fs::File::create(&path).unwrap();
    let chunk_size = 1024 * 1024;
    let mut written = 0usize;
    while written < size_bytes {
        let to_write = (size_bytes - written).min(chunk_size);
        let mut data = vec![0u8; to_write];
        for i in (0..to_write).step_by(8) {
            let pos = (written + i) as u64;
            let bytes = pos.to_le_bytes();
            let end = (i + 8).min(to_write);
            data[i..end].copy_from_slice(&bytes[..end - i]);
        }
        file.write_all(&data).unwrap();
        written += to_write;
    }
    file.flush().unwrap();
    path
}

pub fn verify_large_deterministic_file(path: &Path, expected_size: u64) {
    let mut f = fs::File::open(path).unwrap();
    let chunk_size = 1024 * 1024;
    let expected_chunk: Vec<u8> = (0..chunk_size).map(|i| (i % 251) as u8).collect();
    let mut buf = vec![0u8; chunk_size];
    let mut total_read = 0u64;
    loop {
        let n = f.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        let expected_slice = &expected_chunk[..n];
        assert_eq!(
            &buf[..n],
            expected_slice,
            "mismatch at offset {}",
            total_read
        );
        total_read += n as u64;
    }
    assert_eq!(total_read, expected_size);
}

pub fn count_volume_files(base: &Path) -> usize {
    let mut count = 0;
    if base.exists() {
        count += 1;
    }
    let stem = base.with_extension("");
    for seq in 1..=999u16 {
        let vol = stem.with_extension(format!("era.{:03}", seq));
        if vol.exists() {
            count += 1;
        } else {
            break;
        }
    }
    count
}

pub fn get_volume_paths(base: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if base.exists() {
        paths.push(base.to_path_buf());
    }
    let stem = base.with_extension("");
    for seq in 1..=999u16 {
        let vol = stem.with_extension(format!("era.{:03}", seq));
        if vol.exists() {
            paths.push(vol);
        } else {
            break;
        }
    }
    paths
}

pub fn get_volume_size(path: &Path) -> u64 {
    fs::metadata(path).unwrap().len()
}

pub fn corrupt_archive_shard(archive: &Path, offset: u64) {
    let mut f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(archive)
        .unwrap();
    f.seek(SeekFrom::Start(offset)).unwrap();
    let mut buf = [0u8; 100];
    let n = f.read(&mut buf).unwrap();
    for b in buf[..n].iter_mut() {
        *b = !*b;
    }
    f.seek(SeekFrom::Start(offset)).unwrap();
    f.write_all(&buf[..n]).unwrap();
    f.flush().unwrap();
}

/// Offset 5000 for normal volumes, 4300 for small ones (below header+footer overhead).
pub fn corrupt_volume_data(volume_path: &Path) {
    let len = fs::metadata(volume_path).unwrap().len();
    let offset = if len > 6000 { 5000 } else { 4300 };
    corrupt_archive_shard(volume_path, offset);
}

pub fn corrupt_footer(archive: &Path) {
    let len = fs::metadata(archive).unwrap().len();
    assert!(len > 128, "archive must be larger than 128 bytes");
    corrupt_archive_shard(archive, len - 128);
}

pub fn corrupt_header_magic(archive: &Path) {
    let mut f = fs::OpenOptions::new().write(true).open(archive).unwrap();
    f.write_all(&[0u8; 8]).unwrap();
    f.flush().unwrap();
}

pub fn truncate_file(path: &Path, new_size: u64) {
    let f = fs::OpenOptions::new().write(true).open(path).unwrap();
    f.set_len(new_size).unwrap();
}

/// Returns (public_cert_path, private_key_path).
pub fn generate_test_keypair(dir: &Path) -> (PathBuf, PathBuf) {
    use era_crypto::pem_support::export_private_key_as_pem;
    use era_crypto::{export_public_key_as_pem, EraKeyPair};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);

    let keypair = EraKeyPair::generate().expect("keypair generation should succeed");
    let cert_pem =
        export_public_key_as_pem(&keypair.certificate()).expect("cert export should succeed");
    let key_pem = export_private_key_as_pem(&keypair).expect("key export should succeed");

    let pub_path = dir.join(format!("public_{}.pem", id));
    let priv_path = dir.join(format!("private_{}.pem", id));
    fs::write(&pub_path, cert_pem).expect("public pem should be written");
    fs::write(&priv_path, key_pem).expect("private pem should be written");

    (pub_path, priv_path)
}

pub fn create_archive_with_cert(input: &Path, archive: &Path, cert: &Path) {
    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--certificate",
            cert.to_str().unwrap(),
        ])
        .assert()
        .success();
}

pub fn assert_file_content_eq(path: &Path, expected: &[u8]) {
    let actual = fs::read(path).unwrap();
    assert_eq!(
        actual.len(),
        expected.len(),
        "size mismatch for {}",
        path.display()
    );
    assert_eq!(
        actual.as_slice(),
        expected,
        "content mismatch for {}",
        path.display()
    );
}

pub fn count_files_recursive(dir: &Path) -> usize {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count()
}

pub fn create_test_config(dir: &Path, content: &str) -> PathBuf {
    let path = dir.join("config.toml");
    fs::write(&path, content).unwrap();
    path
}

pub fn repo_tmp_dir() -> tempfile::TempDir {
    let repo_tmp = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tmp");
    fs::create_dir_all(&repo_tmp).unwrap();
    tempfile::tempdir_in(&repo_tmp).unwrap()
}
