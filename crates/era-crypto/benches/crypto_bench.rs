//! Benchmarks for ERA cryptographic operations.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use era_common::BlockId;
use era_crypto::{
    decrypt_with_context, derive_key, encrypt_with_context, generate_password_verification_tag,
    hash, verify_password_tag, DerivedKey, KdfParams, Salt,
};

/// Create a test key with fast KDF parameters (for benchmarking encryption, not KDF)
fn fast_test_key() -> DerivedKey {
    let salt = Salt::from_bytes([0u8; 16]);
    let params = KdfParams {
        memory_cost: 1024,
        time_cost: 1,
        parallelism: 1,
    };
    derive_key(b"benchmark_password", &salt, &params).unwrap()
}

fn bench_blake3_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_hash");

    for size in [64, 256, 1024, 4096, 16384, 65536, 262144] {
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| hash(black_box(data)))
        });
    }

    group.finish();
}

fn bench_aead_encrypt(c: &mut Criterion) {
    let key = fast_test_key();
    let nonce_context = [42u8; 16];
    let block_id = BlockId::new(1);

    let mut group = c.benchmark_group("aead_encrypt");

    for size in [64, 256, 1024, 4096, 16384, 65536, 262144] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, data| {
            b.iter(|| encrypt_with_context(black_box(&key), &nonce_context, block_id, data))
        });
    }

    group.finish();
}

fn bench_kdf_derive(c: &mut Criterion) {
    let password = b"benchmark_password";
    let salt = Salt::generate();

    let mut group = c.benchmark_group("kdf_derive");

    // Test with different memory costs
    for (name, memory_cost, time_cost) in [
        ("fast", 1024, 1),
        ("medium", 8192, 2),
        ("default", 65536, 3),
    ] {
        let params = KdfParams {
            memory_cost,
            time_cost,
            parallelism: 4,
        };

        group.bench_function(name, |b| {
            b.iter(|| derive_key(black_box(password), black_box(&salt), black_box(&params)))
        });
    }

    group.finish();
}

fn bench_password_verification(c: &mut Criterion) {
    let key = fast_test_key();
    let tag = generate_password_verification_tag(&key);

    let mut group = c.benchmark_group("password_verification");

    group.bench_function("generate_tag", |b| {
        b.iter(|| generate_password_verification_tag(black_box(&key)))
    });

    group.bench_function("verify_tag", |b| {
        b.iter(|| verify_password_tag(black_box(&key), black_box(&tag)))
    });

    group.finish();
}

fn bench_aead_decrypt(c: &mut Criterion) {
    let key = fast_test_key();
    let nonce_context = [42u8; 16];
    let block_id = BlockId::new(1);

    let mut group = c.benchmark_group("aead_decrypt");

    for size in [64, 256, 1024, 4096, 16384, 65536, 262144] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let ciphertext = encrypt_with_context(&key, &nonce_context, block_id, &plaintext).unwrap();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &ciphertext, |b, data| {
            b.iter(|| {
                decrypt_with_context(black_box(&key), &nonce_context, block_id, data).unwrap()
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_blake3_hash,
    bench_aead_encrypt,
    bench_aead_decrypt,
    bench_kdf_derive,
    bench_password_verification
);
criterion_main!(benches);
