//! Real-world performance test with PRODUCTION KDF settings
//!
//! This benchmark uses the actual default KDF configuration (256MB memory)
//! to measure TRUE performance that users will experience.
//!
//! Run with: cargo bench --bench real_world_perf_test

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use era_crypto::{AeadContext, KdfParams, KeySession, Salt, XChaCha20Poly1305Context};
use era_engine::{auth::PasswordSlotParams, ArchiveReader, ArchiveWriterBuilder, ExtractOptions};
use era_volume::{RecipientType, SuperHeader};
use tempfile::TempDir;

/// Helper to manually derive the Master Key Session from an archive header
fn derive_session_from_header(
    header: &SuperHeader,
    password: &str,
) -> era_common::Result<KeySession> {
    let slot = header
        .recipients()
        .iter()
        .find(|s| s.r_type() == RecipientType::Argon2idPassword)
        .ok_or(era_common::EraError::InvalidKey(
            "No password slot found".into(),
        ))?;

    let archived =
        rkyv::access::<rkyv::Archived<PasswordSlotParams>, rkyv::rancor::Error>(slot.params())
            .map_err(|e| era_common::EraError::Serialization(e.to_string()))?;

    let salt = Salt::from_bytes(archived.salt);
    let kdf_params = KdfParams {
        memory_cost: archived.kdf_memory_cost.into(),
        time_cost: archived.kdf_time_cost.into(),
        parallelism: archived.kdf_parallelism.into(),
    };

    // 1. Derive KEK
    let kek = era_crypto::derive_key(password.as_bytes(), &salt, &kdf_params)
        .map_err(|_| era_common::EraError::InvalidKey("KDF failed".into()))?;

    // 2. Decrypt MK
    let combined = slot.encrypted_master_key();
    if combined.len() < 24 {
        return Err(era_common::EraError::InvalidKey(
            "Invalid encrypted key length".into(),
        ));
    }
    let nonce_array: &[u8; 24] = combined[0..24]
        .try_into()
        .map_err(|_| era_common::EraError::InvalidKey("Invalid nonce".into()))?;
    let ciphertext = &combined[24..];

    let ctx = XChaCha20Poly1305Context::from_derived_key(&kek)
        .map_err(|_| era_common::EraError::InvalidKey("Failed to create context".into()))?;

    let mk = ctx
        .decrypt(
            nonce_array,
            era_engine::auth::MK_WRAP_AAD_DOMAIN,
            ciphertext,
        )
        .map_err(|_| era_common::EraError::InvalidKey("Incorrect password".into()))?;

    // 3. Create Session
    let mk_array: [u8; 32] = mk
        .try_into()
        .map_err(|_| era_common::EraError::InvalidKey("Invalid MK length".into()))?;
    KeySession::from_master_key(&mk_array)
}

/// Create test data with specified pattern
fn create_test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

/// Benchmark: Small file with PRODUCTION KDF (shows the KDF bottleneck)
fn bench_small_file_production_kdf(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    c.bench_function("small_file_1kb_production_kdf", |b| {
        b.iter_with_setup(
            || {
                let temp_dir = TempDir::new().unwrap();
                let archive_path = temp_dir.path().join("test.era");
                let data = create_test_data(1024);
                (temp_dir, archive_path, data)
            },
            |(temp_dir, archive_path, data)| {
                rt.block_on(async {
                    // NOTE: Using DEFAULT KDF config (256MB memory, time_cost=3)
                    let mut writer = ArchiveWriterBuilder::new(&archive_path)
                        .password("benchmark_password")
                        // NO custom config - use production defaults
                        .build()
                        .await
                        .unwrap();

                    writer.add_bytes("file.bin", &data).await.unwrap();
                    writer.finalize().await.unwrap();
                });

                black_box(temp_dir);
            },
        );
    });
}

/// Benchmark: Multiple small files to expose KDF re-derivation cost
fn bench_multiple_small_files_production_kdf(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("multiple_small_files_production");
    group.sample_size(10); // Reduce samples due to long execution time

    for file_count in [10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}files", file_count)),
            &file_count,
            |b, &count| {
                b.iter_with_setup(
                    || {
                        let temp_dir = TempDir::new().unwrap();
                        let archive_path = temp_dir.path().join("test.era");
                        (temp_dir, archive_path)
                    },
                    |(temp_dir, archive_path)| {
                        rt.block_on(async {
                            let mut writer = ArchiveWriterBuilder::new(&archive_path)
                                .password("benchmark_password")
                                .build()
                                .await
                                .unwrap();

                            for i in 0..count {
                                let data = format!("Content for file {}", i);
                                writer
                                    .add_bytes(&format!("file_{}.txt", i), data.as_bytes())
                                    .await
                                    .unwrap();
                            }
                            writer.finalize().await.unwrap();
                        });

                        black_box(temp_dir);
                    },
                );
            },
        );
    }

    group.finish();
}

/// Benchmark: Large file to show KDF overhead is amortized
fn bench_large_file_production_kdf(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    c.bench_function("large_file_10mb_production_kdf", |b| {
        b.iter_with_setup(
            || {
                let temp_dir = TempDir::new().unwrap();
                let archive_path = temp_dir.path().join("test.era");
                let data = create_test_data(10 * 1024 * 1024);
                (temp_dir, archive_path, data)
            },
            |(temp_dir, archive_path, data)| {
                rt.block_on(async {
                    let mut writer = ArchiveWriterBuilder::new(&archive_path)
                        .password("benchmark_password")
                        .build()
                        .await
                        .unwrap();

                    writer.add_bytes("large.bin", &data).await.unwrap();
                    writer.finalize().await.unwrap();
                });

                black_box(temp_dir);
            },
        );
    });
}

/// Benchmark: Extraction with PRODUCTION KDF
fn bench_extract_production_kdf(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    // Setup: Create an archive first
    let setup_dir = TempDir::new().unwrap();
    let archive_path = setup_dir.path().join("test.era");

    rt.block_on(async {
        let mut writer = ArchiveWriterBuilder::new(&archive_path)
            .password("benchmark_password")
            .build()
            .await
            .unwrap();

        let data = create_test_data(1024 * 1024); // 1MB
        writer.add_bytes("file.bin", &data).await.unwrap();
        writer.finalize().await.unwrap();
    });

    c.bench_function("extract_1mb_production_kdf", |b| {
        b.iter_with_setup(
            || TempDir::new().unwrap(),
            |extract_dir| {
                rt.block_on(async {
                    let mut reader = ArchiveReader::open(&archive_path, "benchmark_password")
                        .await
                        .unwrap();

                    let options = ExtractOptions::new(extract_dir.path());
                    reader.extract_all(&options).await.unwrap();
                });

                black_box(extract_dir);
            },
        );
    });
}

/// Benchmark: KDF-only overhead measurement
fn bench_kdf_only(c: &mut Criterion) {
    use era_crypto::{derive_key, KdfParams, Salt};

    c.bench_function("kdf_derivation_production_256mb", |b| {
        b.iter(|| {
            let salt = Salt::generate();
            let params = KdfParams {
                memory_cost: 256 * 1024, // 256MB (production default)
                time_cost: 3,
                parallelism: 4,
            };

            let _key = derive_key(b"test_password", &salt, &params).unwrap();
            black_box(_key);
        });
    });

    c.bench_function("kdf_derivation_fast_1mb", |b| {
        b.iter(|| {
            let salt = Salt::generate();
            let params = KdfParams {
                memory_cost: 1024, // 1MB (benchmark default)
                time_cost: 1,
                parallelism: 4,
            };

            let _key = derive_key(b"test_password", &salt, &params).unwrap();
            black_box(_key);
        });
    });
}

/// Benchmark: HKDF sub-key derivation (KeySession)
fn bench_hkdf_subkey_derivation(c: &mut Criterion) {
    use era_crypto::{derive_key, KdfParams, KeySession, Salt};

    // Pre-derive master key once
    let salt = Salt::generate();
    let params = KdfParams {
        memory_cost: 1024,
        time_cost: 1,
        parallelism: 4,
    };
    let key = derive_key(b"test_password", &salt, &params).unwrap();
    let session = KeySession::from_derived_key(&key).unwrap();

    c.bench_function("hkdf_volume_key_derivation", |b| {
        let mut volume_id = 0u16;
        b.iter(|| {
            let (_vk, _) = session.generate_and_wrap_volume_key().unwrap();
            volume_id = volume_id.wrapping_add(1);
            black_box(_vk);
        });
    });

    let volume_key = session.generate_and_wrap_volume_key().unwrap().0;
    c.bench_function("hkdf_block_key_derivation", |b| {
        let nonce_context = [0u8; 16];
        let mut block_id = 0u64;
        b.iter(|| {
            let _bk = session
                .derive_block_key(&volume_key, block_id, &nonce_context)
                .unwrap();
            block_id = block_id.wrapping_add(1);
            black_box(_bk);
        });
    });

    let mut artifact_group = c.benchmark_group("hkdf_block_key_artifact_validation");
    artifact_group.throughput(Throughput::Elements(100));
    artifact_group.bench_function("block_key_derivation_batched_100_normalized", |b| {
        let nonce_context = [0u8; 16];
        let mut batch_start = 0u64;
        b.iter(|| {
            for offset in 0..100u64 {
                let _bk = session
                    .derive_block_key(
                        &volume_key,
                        batch_start.wrapping_add(offset),
                        &nonce_context,
                    )
                    .unwrap();
                black_box(_bk);
            }
            batch_start = batch_start.wrapping_add(100);
        });
    });
    artifact_group.finish();

    // Compare: derive 1000 block keys vs 1000 KDF calls
    c.bench_function("hkdf_1000_block_keys", |b| {
        let nonce_context = [0u8; 16];
        b.iter(|| {
            for i in 0..1000 {
                let _bk = session
                    .derive_block_key(&volume_key, i, &nonce_context)
                    .unwrap();
                black_box(&_bk);
            }
        });
    });
}

/// Benchmark: Multiple archive reads with vs without KeySession
fn bench_key_session_reader_speedup(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    // Setup: Create test archives
    let setup_dir = TempDir::new().unwrap();
    let archive_paths: Vec<_> = (0..5)
        .map(|i| {
            let path = setup_dir.path().join(format!("test_{}.era", i));

            let mut config = era_common::ArchiveConfig::default();
            config.encryption.kdf_memory_cost = 1024;
            config.encryption.kdf_time_cost = 1;

            rt.block_on(async {
                let mut writer = ArchiveWriterBuilder::new(&path)
                    .password("benchmark_password")
                    .config(config)
                    .build()
                    .await
                    .unwrap();

                let data = create_test_data(1024);
                writer.add_bytes("file.bin", &data).await.unwrap();
                writer.finalize().await.unwrap();
            });

            path
        })
        .collect();

    let mut group = c.benchmark_group("key_session_reader_comparison");

    // Benchmark: Open multiple archives WITHOUT KeySession (each calls KDF)
    group.bench_function("open_5_archives_without_session", |b| {
        b.iter(|| {
            rt.block_on(async {
                for path in &archive_paths {
                    let reader = ArchiveReader::open(path, "benchmark_password")
                        .await
                        .unwrap();
                    black_box(reader);
                }
            });
        });
    });

    // Get session for first archive
    let first_reader = rt.block_on(async {
        ArchiveReader::open(&archive_paths[0], "benchmark_password")
            .await
            .unwrap()
    });
    let header = first_reader.header();

    let session = derive_session_from_header(header, "benchmark_password").unwrap();
    drop(first_reader);

    // Note: In this benchmark, each archive has a different Master Key, so KeySession
    // can only help with the FIRST archive.
    group.bench_function("open_1_archive_with_session", |b| {
        let session = session.try_clone().unwrap();
        b.iter(|| {
            rt.block_on(async {
                let reader = ArchiveReader::open_with_session(&archive_paths[0], &session)
                    .await
                    .unwrap();
                black_box(reader);
            });
        });
    });

    group.finish();
}

criterion_group! {
    name = real_world_benches;
    config = Criterion::default()
        .sample_size(10)  // Small sample size due to long KDF times
        .measurement_time(std::time::Duration::from_secs(30));
    targets =
        bench_small_file_production_kdf,
        bench_multiple_small_files_production_kdf,
        bench_large_file_production_kdf,
        bench_extract_production_kdf,
        bench_kdf_only,
        bench_hkdf_subkey_derivation,
        bench_key_session_reader_speedup
}

criterion_main!(real_world_benches);
