use era_common::{ArchiveConfig, BlockHeader, BlockType, EraError};
use era_crypto::certificate::EraKeyPair;
use era_crypto::hybrid_certificate::HybridKeyPair;
use era_crypto::AeadContext;
use era_engine::{
    ArchiveHealthStatus, ArchiveReader, ArchiveWriter, AuthMode, ExtractOptions,
    MIN_ARCHIVE_VOLUME_SIZE,
};
use era_volume::{Footer, VolumeReader, DATA_REGION_START};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

const PASSWORD: &str = "find05-append-secret";

fn non_ec_config() -> ArchiveConfig {
    ArchiveConfig {
        erasure: None,
        ..Default::default()
    }
}

fn prng_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed;
    let mut out = vec![0u8; len];
    for byte in &mut out {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *byte = (state >> 24) as u8;
    }
    out
}

async fn read_footer(archive_path: &Path) -> Footer {
    let backend = era_storage::LocalStorageBackend::new(archive_path.parent().unwrap());
    let name = Path::new(archive_path.file_name().unwrap());
    let reader = VolumeReader::open(&backend, name).await.unwrap();
    reader.footer().unwrap().clone()
}

async fn assert_healthy_and_extract(
    archive_path: &Path,
    password: &str,
    expected_files: &[(&str, &[u8])],
) {
    let mut reader = ArchiveReader::open(archive_path, password).await.unwrap();
    let verify_stats = reader.verify().await.unwrap();
    assert_eq!(
        verify_stats.archive_health,
        ArchiveHealthStatus::Healthy,
        "expected Healthy archive, got {:?}; warnings={:?}; errors={:?}",
        verify_stats.archive_health,
        verify_stats.warnings,
        verify_stats.errors
    );
    assert!(
        verify_stats.warnings.is_empty(),
        "unexpected warnings: {:?}",
        verify_stats.warnings
    );
    assert!(
        verify_stats.errors.is_empty(),
        "unexpected errors: {:?}",
        verify_stats.errors
    );

    let extract_dir = TempDir::new().unwrap();
    let extract_stats = reader
        .extract_all(&ExtractOptions::new(extract_dir.path()))
        .await
        .unwrap();
    assert_eq!(extract_stats.extracted, expected_files.len() as u64);

    for (name, expected) in expected_files {
        let actual = fs::read(extract_dir.path().join(name)).unwrap();
        assert_eq!(actual.as_slice(), *expected, "content mismatch for {name}");
    }
}

fn count_data_blocks_in_region(archive_path: &Path, committed_end: u64) -> u32 {
    let data = fs::read(archive_path).unwrap();
    let mut offset = DATA_REGION_START;
    let mut count = 0u32;
    while offset < committed_end {
        let hdr_bytes: [u8; BlockHeader::SIZE] = data
            [offset as usize..offset as usize + BlockHeader::SIZE]
            .try_into()
            .unwrap();
        let hdr = BlockHeader::from_bytes(&hdr_bytes).unwrap();
        assert_eq!(
            hdr.block_type,
            BlockType::Data,
            "unexpected non-Data block {:?} trapped at offset {} before committed_end {}",
            hdr.block_type,
            offset,
            committed_end
        );
        count += 1;
        offset += BlockHeader::SIZE as u64 + u64::from(hdr.length);
    }
    assert_eq!(offset, committed_end);
    count
}

fn assert_data_region_only_data_blocks(archive_path: &Path, committed_end: u64) {
    let _ = count_data_blocks_in_region(archive_path, committed_end);
}

#[tokio::test]
async fn case_a_distinct_small_files_packing_enabled() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("case_a_packed.era");
    let first_path = temp_dir.path().join("first.txt");
    let second_path = temp_dir.path().join("second.txt");
    fs::write(&first_path, b"first small payload").unwrap();
    fs::write(&second_path, b"second small payload").unwrap();

    let mut w1 = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(non_ec_config())
        .enable_small_file_packing(true)
        .build()
        .await
        .unwrap();
    w1.add_file(&first_path).await.unwrap();
    w1.finalize().await.unwrap();

    let mut w2 = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(non_ec_config())
        .enable_small_file_packing(true)
        .append_existing(true)
        .build()
        .await
        .unwrap();
    w2.add_file(&second_path).await.unwrap();
    w2.finalize().await.unwrap();

    assert_healthy_and_extract(
        &archive_path,
        PASSWORD,
        &[
            ("first.txt", b"first small payload"),
            ("second.txt", b"second small payload"),
        ],
    )
    .await;
}

#[tokio::test]
async fn case_a_distinct_small_files_packing_disabled() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("case_a_unpacked.era");

    let mut w1 = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(non_ec_config())
        .enable_small_file_packing(false)
        .build()
        .await
        .unwrap();
    w1.add_bytes("first.txt", b"first small payload")
        .await
        .unwrap();
    w1.finalize().await.unwrap();

    let mut w2 = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(non_ec_config())
        .enable_small_file_packing(false)
        .append_existing(true)
        .build()
        .await
        .unwrap();
    w2.add_bytes("second.txt", b"second small payload")
        .await
        .unwrap();
    w2.finalize().await.unwrap();

    assert_healthy_and_extract(
        &archive_path,
        PASSWORD,
        &[
            ("first.txt", b"first small payload"),
            ("second.txt", b"second small payload"),
        ],
    )
    .await;
}

#[tokio::test]
async fn case_b_distinct_64k_incompressible_files() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("case_b_64k.era");
    let first = prng_bytes(101, 64 * 1024);
    let second = prng_bytes(202, 64 * 1024);

    let mut w1 = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(non_ec_config())
        .enable_small_file_packing(false)
        .build()
        .await
        .unwrap();
    w1.add_bytes("first.bin", &first).await.unwrap();
    w1.finalize().await.unwrap();

    let mut w2 = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(non_ec_config())
        .enable_small_file_packing(false)
        .append_existing(true)
        .build()
        .await
        .unwrap();
    w2.add_bytes("second.bin", &second).await.unwrap();
    w2.finalize().await.unwrap();

    assert_healthy_and_extract(
        &archive_path,
        PASSWORD,
        &[("first.bin", &first), ("second.bin", &second)],
    )
    .await;
}

#[tokio::test]
async fn case_c_duplicate_64k_block_writes_zero_new_data_blocks() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("case_c_dup.era");
    let payload = vec![0xABu8; 64 * 1024];

    let mut w1 = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(non_ec_config())
        .enable_small_file_packing(false)
        .build()
        .await
        .unwrap();
    w1.add_bytes("first.bin", &payload).await.unwrap();
    w1.finalize().await.unwrap();

    let mut r1 = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    r1.preflight_metadata_recovery().await.unwrap();
    let end1 = r1.manifest().unwrap().volume_committed_ends[0];
    drop(r1);
    assert_eq!(count_data_blocks_in_region(&archive_path, end1), 1);

    let mut w2 = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(non_ec_config())
        .enable_small_file_packing(false)
        .append_existing(true)
        .build()
        .await
        .unwrap();
    w2.add_bytes("second.bin", &payload).await.unwrap();
    w2.finalize().await.unwrap();

    let mut r2 = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    r2.preflight_metadata_recovery().await.unwrap();
    let end2 = r2.manifest().unwrap().volume_committed_ends[0];
    drop(r2);
    assert_eq!(end2, end1, "committed_end must not advance on full dedup");
    assert_eq!(
        count_data_blocks_in_region(&archive_path, end2),
        1,
        "cross-session dedup must leave exactly 1 Data block on disk"
    );

    assert_healthy_and_extract(
        &archive_path,
        PASSWORD,
        &[("first.bin", &payload), ("second.bin", &payload)],
    )
    .await;
}

#[tokio::test]
async fn multi_round_append_keeps_data_region_clean_of_metadata() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("multi_round.era");
    let d1 = prng_bytes(1, 32 * 1024);
    let d2 = prng_bytes(2, 48 * 1024);
    let d3 = prng_bytes(3, 64 * 1024);

    let mut w1 = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(non_ec_config())
        .enable_small_file_packing(false)
        .build()
        .await
        .unwrap();
    w1.add_bytes("r1.bin", &d1).await.unwrap();
    w1.finalize().await.unwrap();

    for (name, data) in [("r2.bin", &d2), ("r3.bin", &d3)] {
        let mut w = ArchiveWriter::builder(&archive_path)
            .password(PASSWORD)
            .append_existing(true)
            .build()
            .await
            .unwrap();
        w.add_bytes(name, data).await.unwrap();
        w.finalize().await.unwrap();
    }

    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    reader.preflight_metadata_recovery().await.unwrap();
    let committed_end = reader.manifest().unwrap().volume_committed_ends[0];
    let footer = read_footer(&archive_path).await;
    assert!(footer.data_end_offset() > committed_end);
    drop(reader);

    assert_data_region_only_data_blocks(&archive_path, committed_end);
    assert_healthy_and_extract(
        &archive_path,
        PASSWORD,
        &[("r1.bin", &d1), ("r2.bin", &d2), ("r3.bin", &d3)],
    )
    .await;
}

#[tokio::test]
async fn append_public_cert_only_without_keypair_fails_clearly() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("cert_only.era");
    let keypair = EraKeyPair::generate().unwrap();

    let mut w1 = ArchiveWriter::builder(&archive_path)
        .certificate(keypair.certificate())
        .config(non_ec_config())
        .build()
        .await
        .unwrap();
    w1.add_bytes("a.txt", b"cert payload").await.unwrap();
    w1.finalize().await.unwrap();

    let res = ArchiveWriter::builder(&archive_path)
        .certificate(keypair.certificate())
        .append_existing(true)
        .build()
        .await;
    assert!(
        matches!(res, Err(EraError::InvalidKey(_))),
        "public-cert-only append must fail with InvalidKey, got: {:?}",
        res.err()
    );
}

#[tokio::test]
async fn t7_4_certificate_and_hybrid_append_modes() {
    let temp_dir = TempDir::new().unwrap();

    // 1. Legacy X25519 certificate + keypair append
    let legacy_path = temp_dir.path().join("legacy_cert.era");
    let legacy_kp = EraKeyPair::generate().unwrap();
    let mut w1 = ArchiveWriter::builder(&legacy_path)
        .certificate(legacy_kp.certificate())
        .config(non_ec_config())
        .build()
        .await
        .unwrap();
    w1.add_bytes("one.txt", b"legacy one").await.unwrap();
    w1.finalize().await.unwrap();

    let mut w2 = ArchiveWriter::builder(&legacy_path)
        .keypair(legacy_kp.clone())
        .append_existing(true)
        .build()
        .await
        .unwrap();
    w2.add_bytes("two.txt", b"legacy two").await.unwrap();
    w2.finalize().await.unwrap();

    let mut r_legacy = ArchiveReader::open_with_keypair(&legacy_path, &legacy_kp)
        .await
        .unwrap();
    assert_eq!(
        r_legacy.verify().await.unwrap().archive_health,
        ArchiveHealthStatus::Healthy
    );
    let out_legacy = temp_dir.path().join("out_legacy");
    r_legacy
        .extract_all(&ExtractOptions::new(&out_legacy))
        .await
        .unwrap();
    assert_eq!(fs::read(out_legacy.join("one.txt")).unwrap(), b"legacy one");
    assert_eq!(fs::read(out_legacy.join("two.txt")).unwrap(), b"legacy two");

    // 2. Post-quantum Hybrid KEM certificate + hybrid_keypair append
    let hybrid_path = temp_dir.path().join("hybrid_cert.era");
    let hybrid_kp = HybridKeyPair::generate();
    let mut hw1 = ArchiveWriter::builder(&hybrid_path)
        .hybrid_certificate(hybrid_kp.certificate())
        .config(non_ec_config())
        .build()
        .await
        .unwrap();
    hw1.add_bytes("hone.txt", b"hybrid one").await.unwrap();
    hw1.finalize().await.unwrap();

    let mut hw2 = ArchiveWriter::builder(&hybrid_path)
        .hybrid_keypair(hybrid_kp.clone())
        .append_existing(true)
        .build()
        .await
        .unwrap();
    hw2.add_bytes("htwo.txt", b"hybrid two").await.unwrap();
    hw2.finalize().await.unwrap();

    let mut r_hybrid = ArchiveReader::open_with_hybrid_keypair(&hybrid_path, &hybrid_kp)
        .await
        .unwrap();
    assert_eq!(
        r_hybrid.verify().await.unwrap().archive_health,
        ArchiveHealthStatus::Healthy
    );
    let out_hybrid = temp_dir.path().join("out_hybrid");
    r_hybrid
        .extract_all(&ExtractOptions::new(&out_hybrid))
        .await
        .unwrap();
    assert_eq!(
        fs::read(out_hybrid.join("hone.txt")).unwrap(),
        b"hybrid one"
    );
    assert_eq!(
        fs::read(out_hybrid.join("htwo.txt")).unwrap(),
        b"hybrid two"
    );

    // 3. HybridKemWithPassword append via password
    let hp_path = temp_dir.path().join("hybrid_pw.era");
    let mut hpw1 = ArchiveWriter::builder(&hp_path)
        .auth_mode(AuthMode::HybridKemWithPassword {
            password: zeroize::Zeroizing::new(PASSWORD.to_string()),
            certificate: hybrid_kp.certificate(),
        })
        .config(non_ec_config())
        .build()
        .await
        .unwrap();
    hpw1.add_bytes("p1.txt", b"hpw one").await.unwrap();
    hpw1.finalize().await.unwrap();

    let mut hpw2 = ArchiveWriter::builder(&hp_path)
        .auth_mode(AuthMode::HybridKemWithPassword {
            password: zeroize::Zeroizing::new(PASSWORD.to_string()),
            certificate: hybrid_kp.certificate(),
        })
        .append_existing(true)
        .build()
        .await
        .unwrap();
    hpw2.add_bytes("p2.txt", b"hpw two").await.unwrap();
    hpw2.finalize().await.unwrap();

    assert_healthy_and_extract(
        &hp_path,
        PASSWORD,
        &[("p1.txt", b"hpw one"), ("p2.txt", b"hpw two")],
    )
    .await;
}

#[tokio::test]
async fn append_triggers_volume_rotation_cleanly() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("append_rotate.era");
    let mut cfg = non_ec_config();
    cfg.compression.algorithm = era_common::CompressionAlgorithm::None;

    let d1 = prng_bytes(11, 600 * 1024);
    let d2 = prng_bytes(22, 600 * 1024);

    let mut w1 = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(cfg)
        .enable_cdc(false)
        .enable_small_file_packing(false)
        .max_volume_size(MIN_ARCHIVE_VOLUME_SIZE)
        .build()
        .await
        .unwrap();
    w1.add_bytes("d1.bin", &d1).await.unwrap();
    w1.finalize().await.unwrap();

    let mut w2 = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .enable_cdc(false)
        .enable_small_file_packing(false)
        .append_existing(true)
        .build()
        .await
        .unwrap();
    w2.add_bytes("d2.bin", &d2).await.unwrap();
    w2.finalize().await.unwrap();

    assert!(
        era_volume::volume_path(&archive_path, 1).exists(),
        "append exceeding 1 MiB cap must rotate into volume 1"
    );
    assert_healthy_and_extract(&archive_path, PASSWORD, &[("d1.bin", &d1), ("d2.bin", &d2)]).await;
}

#[tokio::test]
async fn append_explicit_max_volume_size_below_one_mib_rejected_and_legacy_cap_allowed() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("cap_contract.era");

    let mut w1 = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(non_ec_config())
        .max_volume_size(MIN_ARCHIVE_VOLUME_SIZE)
        .build()
        .await
        .unwrap();
    w1.add_bytes("base.txt", b"base").await.unwrap();
    w1.finalize().await.unwrap();

    let err = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .max_volume_size(MIN_ARCHIVE_VOLUME_SIZE - 1)
        .append_existing(true)
        .build()
        .await
        .err()
        .expect("explicit max_volume_size below 1 MiB must be rejected on append");
    assert!(matches!(err, EraError::InvalidConfig(_)));

    // Simulate a historical < 1 MiB archive header and verify append without override succeeds.
    let legacy_path = temp_dir.path().join("historical_small_cap.era");
    let mut cfg = non_ec_config();
    cfg.volume.max_size = 512 * 1024;
    let salt = era_crypto::Salt::generate();
    let kdf_params = era_crypto::KdfParams {
        memory_cost: cfg.encryption.kdf_memory_cost,
        time_cost: cfg.encryption.kdf_time_cost,
        parallelism: 4,
    };
    let mut mk = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut mk);
    let session = era_crypto::KeySession::from_master_key(&mk).unwrap();
    let kek = era_crypto::derive_key(PASSWORD.as_bytes(), &salt, &kdf_params).unwrap();
    let kek_ctx = era_crypto::XChaCha20Poly1305Context::from_derived_key(&kek).unwrap();
    let nonce = era_crypto::Nonce::generate();
    let encrypted_mk = kek_ctx
        .encrypt(nonce.as_bytes(), era_engine::auth::MK_WRAP_AAD_DOMAIN, &mk)
        .unwrap();
    let mut combined = nonce.as_bytes().to_vec();
    combined.extend_from_slice(&encrypted_mk);
    let p_params = era_engine::auth::PasswordSlotParams {
        salt: *salt.as_bytes(),
        kdf_memory_cost: kdf_params.memory_cost,
        kdf_time_cost: kdf_params.time_cost,
        kdf_parallelism: kdf_params.parallelism,
    };
    let recipient = era_volume::RecipientSlot::new(
        era_volume::RecipientType::Argon2idPassword,
        None,
        rkyv::to_bytes::<rkyv::rancor::Error>(&p_params)
            .unwrap()
            .to_vec(),
        combined,
    );
    let (vk, wrapped_vk) = session.generate_and_wrap_volume_key().unwrap();
    let evk = era_volume::EncryptedVolumeKey::new(
        era_volume::KeyWrapAlgorithm::XChaCha20Poly1305,
        wrapped_vk.nonce,
        wrapped_vk.ciphertext,
    );
    let archive_id = era_common::ArchiveId::new();
    let mut header = era_volume::SuperHeader::new(
        archive_id,
        vec![recipient],
        cfg,
        *salt.as_bytes(),
        evk,
        era_volume::AccessPolicy::AnyOfN,
    )
    .unwrap();
    header.set_volume_sequence(0);
    header.set_total_volumes(1);

    let backend = era_storage::LocalStorageBackend::new(temp_dir.path());
    let mut vw = era_volume::VolumeWriter::create(
        &backend,
        Path::new(legacy_path.file_name().unwrap()),
        header.clone(),
    )
    .await
    .unwrap();
    let catalog = era_ingest::Catalog::new();
    let cat_bytes = catalog.to_bytes().unwrap();
    let mut prefixed = Vec::with_capacity(12 + cat_bytes.len());
    prefixed.extend_from_slice(&1u32.to_le_bytes());
    prefixed.extend_from_slice(&(cat_bytes.len() as u64).to_le_bytes());
    prefixed.extend_from_slice(&cat_bytes);
    let cat_hash = era_crypto::hash(&prefixed);
    let cat_chunk = era_common::UniqueChunk::new(bytes::Bytes::from(prefixed), cat_hash);
    let cat_builder = era_packing::SessionBlockBuilder::new(
        &session,
        &vk,
        *salt.as_bytes(),
        *archive_id.0.as_bytes(),
        header.epoch_id(),
        0,
        Box::new(era_codec::ZstdCompressor::new(3)),
    );
    let cat_block = cat_builder
        .pack_single_with_type(cat_chunk, BlockType::Catalog)
        .unwrap();
    let cat_loc = vw
        .write_canonical_block(&cat_block, BlockType::Catalog)
        .await
        .unwrap();
    vw.finalize_with_catalog(cat_loc.physical_offset, cat_loc.encrypted_size, 0, 0, 0, 0)
        .await
        .unwrap();

    let mut lw = ArchiveWriter::builder(&legacy_path)
        .password(PASSWORD)
        .append_existing(true)
        .build()
        .await
        .unwrap();
    lw.add_bytes("new.txt", b"appended to historical small cap")
        .await
        .unwrap();
    lw.finalize().await.unwrap();

    assert_healthy_and_extract(
        &legacy_path,
        PASSWORD,
        &[("new.txt", b"appended to historical small cap")],
    )
    .await;
}
