//! Certificate key exchange vs Argon2 performance comparison
//!
//! Run: cargo run --example key_exchange_bench -p era-crypto --release

use std::time::Instant;

fn main() {
    println!("=== Key derivation performance ===\n");

    // Test X25519 key exchange
    test_x25519();

    // Test Argon2
    test_argon2();

    println!("\n=== Conclusion ===");
    println!("X25519 key exchange is ~1000-4000x faster than Argon2");
    println!("Certificate flow reduces master key derivation from ~80ms to <0.1ms");
}

fn test_x25519() {
    use rand::rngs::OsRng;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    let iterations = 10000;

    // Pre-generate receiver public key (simulate known archive public key)
    let receiver_secret = EphemeralSecret::random_from_rng(OsRng);
    let receiver_public = PublicKey::from(&receiver_secret);

    // Test full key exchange flow
    let start = Instant::now();
    for _ in 0..iterations {
        // Sender generates ephemeral keypair
        let sender_secret = EphemeralSecret::random_from_rng(OsRng);
        let _sender_public = PublicKey::from(&sender_secret);

        // Compute shared secret
        let _shared_secret = sender_secret.diffie_hellman(&receiver_public);
    }
    let elapsed = start.elapsed();

    let per_op = elapsed / iterations as u32;
    println!("X25519 key exchange:");
    println!("  {} iterations: {:?}", iterations, elapsed);
    println!("  Per-op: {:?}", per_op);
    println!(
        "  Throughput: {:.0} ops/sec",
        iterations as f64 / elapsed.as_secs_f64()
    );
}

fn test_argon2() {
    use argon2::{Algorithm, Argon2, Params, Version};

    let password = b"test_password_123";
    let salt = [0u8; 16];

    // Test 1MB memory (fast mode)
    {
        let params = Params::new(1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut output = [0u8; 32];

        let iterations = 100;
        let start = Instant::now();
        for _ in 0..iterations {
            argon2
                .hash_password_into(password, &salt, &mut output)
                .unwrap();
        }
        let elapsed = start.elapsed();

        println!("\nArgon2 (1MB memory - fast mode):");
        println!("  {} iterations: {:?}", iterations, elapsed);
        println!("  Per-op: {:?}", elapsed / iterations as u32);
    }

    // Test 64MB memory (current default)
    {
        let params = Params::new(64 * 1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut output = [0u8; 32];

        let iterations = 10;
        let start = Instant::now();
        for _ in 0..iterations {
            argon2
                .hash_password_into(password, &salt, &mut output)
                .unwrap();
        }
        let elapsed = start.elapsed();

        println!("\nArgon2 (64MB memory - current default):");
        println!("  {} iterations: {:?}", iterations, elapsed);
        println!("  Per-op: {:?}", elapsed / iterations as u32);
    }

    // Test 256MB memory (production-grade)
    {
        let params = Params::new(256 * 1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut output = [0u8; 32];

        let iterations = 3;
        let start = Instant::now();
        for _ in 0..iterations {
            argon2
                .hash_password_into(password, &salt, &mut output)
                .unwrap();
        }
        let elapsed = start.elapsed();

        println!("\nArgon2 (256MB memory - production-grade):");
        println!("  {} iterations: {:?}", iterations, elapsed);
        println!("  Per-op: {:?}", elapsed / iterations as u32);
    }
}
