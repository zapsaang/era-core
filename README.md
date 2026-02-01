# ERA (Encrypted Redundant Archiver) Core

[![CI](https://github.com/zapsaang/era-core/actions/workflows/ci.yml/badge.svg)](https://github.com/zapsaang/era-core/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A next-generation encrypted storage engine with content-defined chunking, erasure coding, and post-quantum cryptography support.

## ✨ Features

- **🔐 Strong Encryption**: XChaCha20-Poly1305 AEAD with context-bound key derivation
- **🛡️ Post-Quantum Ready**: Hybrid KEM (X25519 + Kyber-768) for future-proof key encapsulation
- **📦 Erasure Coding**: Reed-Solomon (4+1 default) for data redundancy and corruption recovery
- **🔄 Content-Defined Chunking**: FastCDC algorithm for efficient deduplication
- **⚡ Async Runtime**: Pure async I/O with Tokio for maximum performance
- **🔧 Zero-Copy Serialization**: Rkyv for internal structures, Protobuf for wire format
- **📁 Multi-Volume Support**: Automatic volume splitting with matrix shard distribution
- **🔑 Flexible Authentication**: Password-based (Scrypt) or certificate-based (X25519/Kyber hybrid)

## 🚀 Quick Start

### Prerequisites

- Rust 1.75+ (2021 Edition)
- Linux: `libacl1-dev`, `protobuf-compiler`
- macOS: `protobuf` (via Homebrew)

### Installation

```bash
# Clone the repository
git clone https://github.com/zapsaang/era-core.git
cd era-core

# Build and install the CLI
cargo install --path bins/era-cli

# Or run directly
cargo run --release --bin era -- --help
```

### Basic Usage

```bash
# Create an encrypted archive
era create --output archive.era --password "your-secret" /path/to/files

# Extract an archive
era extract --input archive.era --output /path/to/output --password "your-secret"

# List archive contents
era list archive.era --password "your-secret"

# Verify archive integrity
era verify archive.era --password "your-secret"

# Show archive information
era info archive.era --password "your-secret"
```

### Advanced Usage

```bash
# Create with custom erasure coding (6 data + 3 parity shards)
era create --output archive.era --password "secret" --erasure "6:3" /path/to/files

# Create with custom compression level (1-22, default: 3)
era create --output archive.era --password "secret" --level 15 /path/to/files

# Create without compression (store mode)
era create --output archive.era --password "secret" --no-compression /path/to/files

# Multi-volume archive with size limit (4GB per volume)
era create --output archive.era --password "secret" \
    --max-volume-size 4294967296 /path/to/large/files

# Certificate-based encryption (post-quantum hybrid)
era create --output archive.era --certificate public.pem /path/to/files
era extract --input archive.era --output /restored --key private.pem
```

## 🏗️ Architecture

### Crate Structure

Layered architecture with strict dependency ordering:

```
┌─────────────────────────────────────────────────────────────┐
│  L5: era-cli (Command-Line Interface)                       │
├─────────────────────────────────────────────────────────────┤
│  L4: era-engine (Archive Orchestration)                      │
├─────────────────────────────────────────────────────────────┤
│  L3: era-index, era-ingest (Indexing & Ingestion)           │
├─────────────────────────────────────────────────────────────┤
│  L2: era-packing, era-volume (Chunk Packing & Volume I/O)   │
├─────────────────────────────────────────────────────────────┤
│  L1: era-codec, era-storage (Encoding & Storage Backends)   │
├─────────────────────────────────────────────────────────────┤
│  L0: era-crypto, era-common (Cryptography & Shared Types)   │
└─────────────────────────────────────────────────────────────┘
```

### Component Status

| Component | Description | Status |
|-----------|-------------|--------|
| `era-common` | Shared types, errors, configuration | ✅ Stable |
| `era-crypto` | XChaCha20, Kyber, Scrypt, secure memory | ✅ Stable |
| `era-codec` | Compression (Zstd/LZ4), erasure coding | ✅ Stable |
| `era-storage` | Async storage backend abstraction | ✅ Stable |
| `era-volume` | Volume format, header/footer, recovery | ✅ Stable |
| `era-packing` | Chunk packing, buffer management | ✅ Stable |
| `era-ingest` | Content-defined chunking (FastCDC) | ✅ Stable |
| `era-index` | LSM-tree index, bloom filters | ✅ Stable |
| `era-engine` | High-level archive API | ✅ Stable |
| `era-cli` | Command-line interface | ✅ Stable |

### Volume Format (v8.1)

```
┌──────────────────────────────────────────────────────────────┐
│  Primary Header (4096 bytes)                                  │
│  - Magic: "ERA\x08\x01"                                       │
│  - Archive ID, Config, Recipient Slots                        │
├──────────────────────────────────────────────────────────────┤
│  Backup Footer Gap (128 bytes)                                │
├──────────────────────────────────────────────────────────────┤
│  Data Region (Encrypted Blocks)                               │
│  - Packed chunks with erasure shards                          │
│  - AEAD encrypted with context-bound keys                     │
├──────────────────────────────────────────────────────────────┤
│  Backup Header (4096 bytes)                                   │
├──────────────────────────────────────────────────────────────┤
│  Primary Footer (128 bytes)                                   │
│  - Block count, Index location, Checksums                     │
└──────────────────────────────────────────────────────────────┘
```

## 🔒 Security

### Cryptographic Primitives

- **Encryption**: XChaCha20-Poly1305 (256-bit key, 192-bit nonce)
- **Key Derivation**: Scrypt (N=2^20, r=8, p=1) for passwords
- **Hybrid KEM**: X25519 + Kyber-768 for post-quantum security
- **Hashing**: BLAKE3 for content addressing
- **Key Expansion**: HKDF-SHA256 with context binding

### Security Features

- **Context-Bound Encryption**: Each block encrypted with unique context (volume ID, block ID, offset)
- **Secure Memory**: Locked memory pages (mlock), zeroization on drop
- **Core Dump Prevention**: Automatic `RLIMIT_CORE` restriction
- **Redundant Metadata**: Backup headers and footers for resilience

## 🧪 Development

### Running Tests

```bash
# Run all tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Run specific package tests
cargo test --package era-engine
```

### Code Quality

```bash
# Format check
cargo fmt --all -- --check

# Lint check
cargo clippy --all-targets --all-features -- -D warnings

# Full CI check
cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test
```

### Benchmarks

```bash
# Run benchmarks
cargo bench --package era-engine

# Run specific benchmark
cargo bench --package era-crypto -- hybrid_kem
```

## 📚 Documentation

Generate and view documentation:

```bash
cargo doc --workspace --no-deps --open
```

## 🗺️ Roadmap

- [ ] Index persistence layer (physical LSM-tree storage)
- [ ] S3/MinIO storage backend
- [ ] FUSE filesystem interface
- [ ] Incremental backup support
- [ ] Multi-recipient key management UI
- [ ] Hardware security module (HSM) integration

## 📄 License

Licensed under Apache-2.0. See [LICENSE](LICENSE) for details.

## 🤝 Contributing

Contributions are welcome! Please ensure:

1. All tests pass (`cargo test`)
2. Code is formatted (`cargo fmt`)
3. No clippy warnings (`cargo clippy -- -D warnings`)
4. Documentation is updated for new features

---

**Status**: Pre-alpha / Audit Mode - API is not stable. Breaking changes expected.
