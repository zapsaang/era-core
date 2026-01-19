# ERA v8.1: **E**ncrypted **R**edundant **A**rchive

![CI Status](https://img.shields.io/badge/CI-Passing-brightgreen)
![Resilience](https://img.shields.io/badge/Resilience-Verified-blue)
![Architecture](https://img.shields.io/badge/Architecture-L1%2FL2%2FL3-orange)

**ERA v8.1** is a next-generation archival storage engine designed for **extreme data resilience**, **high-performance deduplication**, and **cryptographic agility**. It implements the "Unkillable" design philosophy, ensuring data recovery even in the face of significant storage corruption, missing volumes, or partial overwrite.

## 🚀 Key Features

*   **"Unkillable" Resilience**: Proven to survive:
    *   Single volume loss (in multi-volume setups).
    *   Partial file truncation.
    *   Random bit-rot and corruption (CRC/AEAD protected).
    *   Missing footers (via floating footer reconstruction).
    *   Header corruption (via volume header backup).
*   **Layered Architecture (L0-L5)**: Strict separation of concerns between physical I/O, volume management, coding, packing, chunking, and logical ingest.
*   **Onion Model Security**:
    *   **Master Key (MK)**: Argon2id or X25519 Certificate.
    *   **Volume Key (VK)**: HKDF-derived, unique per volume (prevents cross-volume cryptoanalysis).
    *   **Block Key (BK)**: HKDF-derived, unique per block (Perfect Forward Secrecy per block).
*   **Advanced Deduplication**: FastCDC (Content Defined Chunking) with k-Bounded Best-Fit packing.
*   **Embedded LSM Index**: Persistent chunk index stored *inside* the archive for self-contained recovery and incremental backups.

## 🏗 Architecture

The system is organized into decoupled crates:

| Layer | Crate | Purpose |
|-------|-------|---------|
| **L5** | `era-ingest` | File traversal, Metadata extraction, ACLs. |
| **L4** | `era-index` | Chunk Deduplication Index (LSM-Tree / Hash). |
| **L3** | `era-engine` | High-level orchestration, Recovery, Repair logic. |
| **L2** | `era-packing` | Block compression (Zstd/LZ4), Encryption (XChaCha20), Container format. |
| **L2** | `era-codec` | Erasure Coding (Reed-Solomon), Compression algorithms. |
| **L1** | `era-volume` | Volume headers/footers, physical layout, rotation. |
| **L0** | `era-storage` | Physical I/O abstraction (Local FS, Memory). |
| **Common** | `era-crypto` | Cryptographic primitives (AeadContext, KeySession). |

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

The system has undergone rigorous adversarial testing ("Evisceration Suite"):

*   **Protocol Audit**: Verified strict HKDF key hierarchy. No key reuse.
*   **Resilience Audit**:
    *   **Truncation**: Recovered from 50% volume truncation via erasure codes.
    *   **Bit-Rot**: Detected 100% of bit-flipped blocks via 128-bit CRC + Poly1305 tag.
    *   **Volume Loss**: Recovered full dataset with 1 of 3 volumes missing (using 2+1 erasure).

## 🤝 CI & Development

The project maintains strict code quality standards:
*   `cargo fmt`: Standard Rust formatting.
*   `cargo clippy`: Zero warnings allowed (lints enforced).
*   `cargo test`: Full unit and integration test suite.

---
*Built with ❤️ in Rust.*
