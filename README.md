# ERA v8.1: **E**ncrypted **R**edundant **A**rchive

![CI Status](https://img.shields.io/badge/CI-Passing-brightgreen)
![Resilience](https://img.shields.io/badge/Resilience-Verified-blue)
![Architecture](https://img.shields.io/badge/Architecture-Async%20I%2FO-orange)
![Rust](https://img.shields.io/badge/Rust-1.70%2B-red)

**ERA v8.1** is a next-generation archival storage engine designed for **extreme data resilience**, **high-performance deduplication**, and **cryptographic agility**. It implements the "Unkillable" design philosophy with true non-blocking async I/O, ensuring data recovery even in the face of significant storage corruption, missing volumes, or partial overwrite.

## 🚀 Key Features

### Core Capabilities
*   **"Unkillable" Resilience**: Proven to survive:
    *   Single volume loss (in multi-volume setups)
    *   Partial file truncation (up to 50% with erasure coding)
    *   Random bit-rot and corruption (CRC32 + Poly1305 AEAD protected)
    *   Missing footers (via floating footer reconstruction)
    *   Header corruption (via volume header backup)
*   **True Async I/O Architecture**: Non-blocking streaming pipeline prevents runtime starvation
    *   Tokio-based async file operations
    *   Stream-based chunking with `async-stream`
    *   Verified with concurrency torture tests
*   **Advanced Deduplication**: Content-Defined Chunking (FastCDC) with k-Bounded Best-Fit packing
*   **Embedded LSM Index**: Persistent chunk index stored *inside* the archive for self-contained recovery

### Security (Onion Model)
*   **Master Key (MK)**: Argon2id password derivation or X25519 certificate-based authentication
*   **Volume Key (VK)**: HKDF-derived, unique per volume (prevents cross-volume cryptoanalysis)
*   **Block Key (BK)**: HKDF-derived, unique per block (Perfect Forward Secrecy)
*   **Encryption**: XChaCha20-Poly1305 AEAD with 256-bit keys
*   **Nonce Strategy**: Counter-based with cryptographic context separation

## 🏗 Architecture

The system is organized into decoupled crates:

| Layer | Crate | Purpose | Status |
|-------|-------|---------|--------|
| **L5** | `era-ingest` | Async file I/O, Metadata extraction, ACLs | ✅ Async |
| **L4** | `era-index` | Chunk Deduplication Index (LSM/Memory) | ✅ Complete |
| **L3** | `era-engine` | Archive orchestration, Recovery, Repair | ✅ Async |
| **L2** | `era-packing` | Block compression (Zstd/LZ4), Small file packing | ✅ Complete |
| **L2** | `era-codec` | Erasure Coding (Reed-Solomon 4:2) | ✅ Complete |
| **L1** | `era-volume` | Volume headers/footers, Physical layout | ✅ Complete |
| **L0** | `era-storage` | Physical I/O abstraction (FS/Memory) | ✅ Complete |
| **Common** | `era-crypto` | Cryptographic primitives, Key sessions | ✅ Complete |

### Async I/O Pipeline

All I/O operations are fully non-blocking, verified by runtime starvation resistance tests.

## 🛠 Installation & Usage

### Prerequisites
*   Rust 1.70+
*   Clang (for RocksDB bindings)

### Building
```bash
cargo build --release
```

### Basic Usage

**Create an archive:**
```bash
# Create encrypted archive from a directory
target/release/era create backup.era ./my_data --password "secret"
```

**Extract an archive:**
```bash
# Extract to current directory
target/release/era extract backup.era --password "secret"
```

**Verify integrity:**
```bash
# Deep verification of all blocks
target/release/era verify backup.era --password "secret"
```

## 🛡 Security Audit

### Adversarial Testing ("Evisceration Suite")

*   **Protocol Audit**: Verified strict HKDF key hierarchy with zero key reuse
*   **Truncation Tests**: Recovered from 50% volume truncation via 4:2 erasure codes
*   **Bit-Rot Detection**: 100% detection rate via CRC32 + Poly1305 AEAD tags
*   **Volume Loss Recovery**: Full dataset recovery with 1 of 3 volumes missing (2+1 erasure)
*   **Concurrency Torture**: Runtime starvation resistance under heavy I/O load

## 🧪 Testing & CI

### Continuous Integration

The project maintains strict code quality standards:
*   `cargo fmt --all -- --check`: Standard Rust formatting
*   `cargo clippy --all-targets --all-features -- -D warnings`: Zero warnings policy
*   `cargo test`: Full unit and integration test suite (150+ tests)

### Running Tests

```bash
# Full test suite
cargo test

# With LSM features
cargo test --features lsm

# Specific concurrency test
cargo test --test concurrency_torture
```

---
*Built with ❤️ in Rust | Last Updated: 2026-01-20 | Architecture: Async I/O*
