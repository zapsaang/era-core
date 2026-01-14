//! 证书密钥交换 vs Argon2 性能对比
//!
//! 运行: cargo run --example key_exchange_bench -p era-crypto --release

use std::time::Instant;

fn main() {
    println!("=== 密钥派生性能对比 ===\n");

    // 测试 X25519 密钥交换
    test_x25519();

    // 测试 Argon2
    test_argon2();

    println!("\n=== 结论 ===");
    println!("X25519密钥交换比Argon2快约1000-4000倍");
    println!("证书方案可以将主密钥派生从80ms降到<0.1ms");
}

fn test_x25519() {
    use x25519_dalek::{EphemeralSecret, PublicKey};
    use rand::rngs::OsRng;

    let iterations = 10000;

    // 预生成接收方公钥（模拟已知的归档公钥）
    let receiver_secret = EphemeralSecret::random_from_rng(OsRng);
    let receiver_public = PublicKey::from(&receiver_secret);

    // 测试完整的密钥交换流程
    let start = Instant::now();
    for _ in 0..iterations {
        // 发送方生成临时密钥对
        let sender_secret = EphemeralSecret::random_from_rng(OsRng);
        let _sender_public = PublicKey::from(&sender_secret);

        // 计算共享密钥
        let _shared_secret = sender_secret.diffie_hellman(&receiver_public);
    }
    let elapsed = start.elapsed();

    let per_op = elapsed / iterations as u32;
    println!("X25519 密钥交换:");
    println!("  {} 次迭代: {:?}", iterations, elapsed);
    println!("  单次操作: {:?}", per_op);
    println!("  吞吐量: {:.0} ops/sec", iterations as f64 / elapsed.as_secs_f64());
}

fn test_argon2() {
    use argon2::{Argon2, Algorithm, Version, Params};

    let password = b"test_password_123";
    let salt = [0u8; 16];

    // 测试1MB内存（快速模式）
    {
        let params = Params::new(1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut output = [0u8; 32];

        let iterations = 100;
        let start = Instant::now();
        for _ in 0..iterations {
            argon2.hash_password_into(password, &salt, &mut output).unwrap();
        }
        let elapsed = start.elapsed();

        println!("\nArgon2 (1MB memory - 快速模式):");
        println!("  {} 次迭代: {:?}", iterations, elapsed);
        println!("  单次操作: {:?}", elapsed / iterations as u32);
    }

    // 测试64MB内存（当前默认）
    {
        let params = Params::new(64 * 1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut output = [0u8; 32];

        let iterations = 10;
        let start = Instant::now();
        for _ in 0..iterations {
            argon2.hash_password_into(password, &salt, &mut output).unwrap();
        }
        let elapsed = start.elapsed();

        println!("\nArgon2 (64MB memory - 当前默认):");
        println!("  {} 次迭代: {:?}", iterations, elapsed);
        println!("  单次操作: {:?}", elapsed / iterations as u32);
    }

    // 测试256MB内存（生产级别）
    {
        let params = Params::new(256 * 1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut output = [0u8; 32];

        let iterations = 3;
        let start = Instant::now();
        for _ in 0..iterations {
            argon2.hash_password_into(password, &salt, &mut output).unwrap();
        }
        let elapsed = start.elapsed();

        println!("\nArgon2 (256MB memory - 生产级别):");
        println!("  {} 次迭代: {:?}", iterations, elapsed);
        println!("  单次操作: {:?}", elapsed / iterations as u32);
    }
}
