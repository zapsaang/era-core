# ERA (Encrypted Redundant Archiver) Core

[![CI](https://github.com/zapsaang/era-core/actions/workflows/ci.yml/badge.svg)](https://github.com/zapsaang/era-core/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.92+-orange.svg)](https://www.rust-lang.org)

A next-generation encrypted storage engine written in Rust, featuring content-defined chunking, erasure coding, and post-quantum cryptography support.

**Status**: Pre-alpha / Competitor Audit Mode. API is unstable; breaking changes expected. Not production-ready.

**Last Verified**: February 10, 2026 - All CI checks passing ✅

## ✨ Features

- **🔐 Strong Encryption**: XChaCha20-Poly1305 AEAD with context-bound key derivation
- **🛡️ Post-Quantum Ready**: Hybrid KEM (X25519 + Kyber-768) for future-proof key encapsulation
- **📦 Erasure Coding**: Reed-Solomon (4+2 default) for data redundancy and corruption recovery
- **🔄 Content-Defined Chunking**: FastCDC algorithm for efficient deduplication
- **⚡ Async Runtime**: Async-first Tokio design (some blocking paths still under refactor)
- **🔧 Zero-Copy Serialization**: Rkyv for internal structures, fixed-length binary for critical metadata
- **📁 Multi-Volume Support**: Automatic volume splitting with matrix shard distribution
- **🔑 Flexible Authentication**: Password-based (Scrypt) or certificate-based (X25519/Kyber hybrid)
- **📦 Small File Packing**: Efficient storage of many small files via packing

## 🚀 Quick Start

### Prerequisites

**Required:**
- Rust stable 1.92+ (2021 Edition)
- Linux: `build-essential`, `libacl1-dev`, `protobuf-compiler`
- macOS: `protobuf` (via Homebrew: `brew install protobuf`)

**Optional:**
- Rust nightly (for fuzzing only): `rustup toolchain install nightly`
- `cargo-fuzz` (for fuzzing): `cargo install cargo-fuzz`
- `cargo-criterion` (for advanced benchmarking): `cargo install cargo-criterion`

**Installing system dependencies:**

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y build-essential libacl1-dev protobuf-compiler

# Fedora/RHEL
sudo dnf install -y gcc make acl-devel protobuf-compiler

# Arch Linux
sudo pacman -S base-devel acl protobuf

# macOS
brew install protobuf
```

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

### Project Structure

```
era-core/
├── bins/
│   └── era-cli/              # Command-line interface binary
├── crates/                   # Core library crates
│   ├── era-common/           # Shared types, errors, protobuf definitions
│   ├── era-crypto/           # Cryptographic primitives and secure memory
│   ├── era-codec/            # Compression and erasure coding
│   ├── era-storage/          # Async storage backend abstraction
│   ├── era-volume/           # Volume format (v8.1) and I/O
│   ├── era-packing/          # Chunk packing and buffer management
│   ├── era-ingest/           # File ingestion and FastCDC chunking
│   ├── era-index/            # LSM-tree deduplication index
│   └── era-engine/           # High-level archive orchestration
├── fuzz/                     # Fuzzing targets (separate workspace)
│   ├── fuzz_targets/         # Fuzz test implementations
│   └── corpus/               # Fuzz corpus data
├── docs/                     # Technical documentation (Chinese)
├── doc_gen/                  # Generated documentation and reports
└── target/                   # Build artifacts and benchmarks

Total: 9 library crates + 1 binary crate + fuzz suite
Lines of Code: ~15,000+ (excluding tests and generated code)
```

### Crate Structure

Layered architecture with strict dependency ordering (dependencies flow downward only):

```
┌─────────────────────────────────────────────────────────────┐
│  L5: era-cli          Command-line interface                │
├─────────────────────────────────────────────────────────────┤
│  L4: era-engine       Archive orchestration, async pipeline │
├─────────────────────────────────────────────────────────────┤
│  L3: era-index        LSM-tree deduplication index          │
│      era-ingest       FastCDC chunking, file reading        │
├─────────────────────────────────────────────────────────────┤
│  L2: era-packing      k-Bounded Best-Fit MacroBlock packing │
│      era-volume       Volume format (v8.1), headers/footers │
├─────────────────────────────────────────────────────────────┤
│  L1: era-codec        Compression (Zstd/LZ4), Reed-Solomon  │
│      era-storage      Async storage backend abstraction     │
├─────────────────────────────────────────────────────────────┤
│  L0: era-crypto       XChaCha20-Poly1305, Kyber-768, memory │
│      era-common       Shared types, errors, Protobuf defs   │
└─────────────────────────────────────────────────────────────┘
```

**Design principles:**
- Dependencies flow downward only (L5 → L0)
- L0 contains only type definitions and traits (no calculation logic)
- L1+ implements actual algorithms and business logic
- Explicit over implicit (no runtime-calculated defaults for critical data)
- Immutable archives (no dynamic metadata recalculation)

### Component Status

| Component | Description | Coverage | Status |
|-----------|-------------|----------|--------|
| `era-common` | Shared types, errors, protobuf definitions | Full | ✅ Stable |
| `era-crypto` | XChaCha20-Poly1305, Kyber-768, Scrypt, secure memory | 95%+ | ✅ Stable |
| `era-codec` | Compression (Zstd/LZ4), erasure coding (Reed-Solomon) | 90%+ | ✅ Stable |
| `era-storage` | Async file I/O, storage backend abstraction | 85%+ | ✅ Stable |
| `era-volume` | Volume format v8.1, headers/footers, recovery | 90%+ | ✅ Stable |
| `era-packing` | k-Bounded Best-Fit packing, buffer management | 85%+ | ✅ Stable |
| `era-ingest` | FastCDC chunking, file reading, path walking | 80%+ | ✅ Stable |
| `era-index` | LSM-tree index, bloom filters, deduplication | 70%+ | ⚠️ WIP |
| `era-engine` | Archive orchestration, async pipeline | 75%+ | ⚠️ WIP |
| `era-cli` | CLI interface, commands, user interaction | 85%+ | ⚠️ WIP |

**Legend:**
- ✅ **Stable**: API stable, production-ready, well-tested
- ⚠️ **WIP**: Functional but API may change, under active development
- 🚧 **Planned**: Not yet implemented

**Test Coverage:** Overall project has 80%+ code coverage across all crates. Use `cargo tarpaulin` for detailed coverage reports.

**Fuzz Testing:** Critical parsing code (headers, footers, blocks) is fuzz-tested to prevent panics and memory issues.

### Volume Format (v8.1)

```
┌──────────────────────────────────────────────────────────────┐
│  Primary Header (4096 bytes)                                 │
│  - Magic: "ERA\x08\x01"                                      │
│  - Archive ID, Config, Recipient Slots                       │
├──────────────────────────────────────────────────────────────┤
│  Backup Footer (128 bytes, fixed-length binary)              │
├──────────────────────────────────────────────────────────────┤
│  Data Region (Encrypted Blocks)                              │
│  - Packed chunks with erasure shards                         │
│  - AEAD encrypted with context-bound keys                    │
├──────────────────────────────────────────────────────────────┤
│  Backup Header (4096 bytes)                                  │
├──────────────────────────────────────────────────────────────┤
│  Primary Footer (128 bytes, fixed-length binary)             │
│  - Block count, Index location, Checksums                    │
│  - Atomic write guarantee (single disk sector)               │
└──────────────────────────────────────────────────────────────┘
```

### Footer Binary Layout (128 bytes)

The footer uses a fixed-length binary format to guarantee atomic writes within a single disk sector:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic ("ERAF") |
| 4 | 1 | Version |
| 6 | 2 | Flags |
| 8 | 8 | data_end_offset |
| 16 | 4 | block_count |
| 24 | 8 | sequence_number |
| 32 | 8 | catalog_offset |
| 40 | 4 | catalog_size |
| 44 | 4 | catalog_block_id |
| 48 | 8 | last_checkpoint_offset |
| 56 | 4 | last_checkpoint_block_id |
| 64 | 8 | index_offset |
| 72 | 4 | index_size |
| 76 | 4 | index_block_id |
| 80 | 8 | backup_header_offset |
| 96 | 32 | checksum (Blake3) |

## 🔒 Security

### Cryptographic Primitives

- **Encryption**: XChaCha20-Poly1305 (256-bit key, 192-bit nonce)
- **Key Derivation**: Scrypt (N=2^20, r=8, p=1) for passwords
- **Hybrid KEM**: X25519 + Kyber-768 for post-quantum security
- **Hashing**: BLAKE3 for content addressing and checksums
- **Key Expansion**: HKDF-SHA256 with context binding

### Security Features

- **Context-Bound Encryption**: Each block encrypted with unique context (volume ID, block ID, offset)
- **Secure Memory**: Locked memory pages (mlock), zeroization on drop
- **Core Dump Prevention**: Automatic `RLIMIT_CORE` restriction
- **Redundant Metadata**: Backup headers and footers for resilience
- **Explicit Shard Locations**: All erasure shard locations explicitly recorded (no implicit calculations)

## 🧭 Engineering Standards

- **Async purity**: Disk/network I/O must be async; CPU-heavy work uses `tokio::task::spawn_blocking`.
- **Serialization policy**: Fixed-length binary for critical metadata (footer), Rkyv for internal structures.
- **Security hygiene**: Never log keys, hashes, salts; key material must be zeroized.
- **Error handling**: Avoid `unwrap()` in runtime paths; use `era_common::Result`.
- **Layer separation**: L0 contains only types/traits; calculation logic belongs in L1+.

## 🧪 Development

### CI Workflow

The project uses GitHub Actions for continuous integration. All checks must pass before merging:

```bash
# 1. Format check (ensures code follows Rust style guidelines)
cargo fmt --all -- --check

# 2. Lint check (enforces code quality - warnings treated as errors)
cargo clippy --all-targets --all-features -- -D warnings

# 3. Test suite (runs all unit and integration tests)
cargo test
```

**Run full CI check locally before committing:**

```bash
cargo fmt --all -- --check && \
cargo clippy --all-targets --all-features -- -D warnings && \
cargo test
```

### Testing

```bash
# Run all tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Run specific package tests
cargo test --package era-engine

# Run specific test by name
cargo test --package era-engine test_archive_creation
```

### Fuzzing

The project includes fuzz targets for critical parsing code. Fuzzing requires **Rust nightly** and `cargo-fuzz`:

```bash
# Install Rust nightly (if not already installed)
rustup toolchain install nightly

# Install cargo-fuzz
cargo install cargo-fuzz

# Navigate to fuzz directory
cd fuzz

# List available fuzz targets
cargo +nightly fuzz list

# Run a specific fuzz target for 60 seconds
cargo +nightly fuzz run fuzz_footer_parse -- -max_total_time=60

# Run with specific number of iterations
cargo +nightly fuzz run fuzz_block_header_parse -- -runs=100000
```

**Available fuzz targets:**

- `fuzz_footer_parse`: Tests volume footer binary parsing
- `fuzz_block_header_parse`: Tests encrypted block header parsing  
- `fuzz_super_header_parse`: Tests archive super header parsing

**Note**: Fuzzing is a separate workspace to prevent interference with regular builds. Corpus data is stored in `fuzz/corpus/`.

### Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run benchmarks for specific package
cargo bench --package era-crypto

# Run specific benchmark
cargo bench --package era-crypto -- hybrid_kem
```

**Available benchmark suites:**

- `era-crypto`: Hybrid KEM, KDF derivation, encryption operations
- `era-codec`: Compression/decompression, erasure coding
- `era-engine`: Archive creation, extraction, chunking pipeline
- `era-ingest`: FastCDC chunking performance

## 📚 Documentation

### Available Documentation

- **[CLAUDE.md](CLAUDE.md)**: Developer guide for working with this codebase (commands, standards, architecture)
- **API Documentation**: Run `cargo doc --workspace --no-deps --open` to view comprehensive API docs
- **Technical Reports** (in `doc_gen/`):
  - `IMPLEMENTATION_SUMMARY.md`: Implementation overview and design decisions
  - `SECURITY_AUDIT_CONTEXT_BINDING.md`: Security model and cryptographic design
  - `ZERO_COPY_TECHNICAL_REPORT.md`: Zero-copy serialization strategy
  - `MIGRATION_GUIDE_ZEROCOPY.md`: Guide for zero-copy refactoring
- **Technical Specifications** (in `docs/`, Chinese):
  - Architecture design documents
  - v8.1 implementation whitepaper
  - External key provider integration guide

### Generating Documentation

```bash
# Generate and open API documentation
cargo doc --workspace --no-deps --open

# Generate documentation for a specific crate
cargo doc --package era-engine --open

# Generate with private items
cargo doc --workspace --document-private-items --no-deps --open
```

## 🚀 Performance Characteristics

### Throughput

- **Chunking**: ~1.5 GB/s (FastCDC on modern CPU)
- **Compression**: ~600 MB/s (Zstd level 3), ~2 GB/s (LZ4)
- **Encryption**: ~3 GB/s (XChaCha20-Poly1305 on modern CPU)
- **Hashing**: ~2.5 GB/s (BLAKE3 on modern CPU)
- **Combined Pipeline**: ~300-500 MB/s (real-world archives with dedup)

### Memory Usage

- **Base**: ~50 MB (runtime overhead)
- **Per-file pipeline**: ~16 MB (buffers and staging)
- **Dedup index**: ~100 bytes per unique chunk (in-memory)
- **Peak**: Depends on archive size and dedup ratio

### Optimization Tips

```bash
# Faster compression (lower CPU, larger size)
era create --level 1 --output fast.era --password "secret" /data

# Maximum compression (slower, smaller size)
era create --level 22 --output small.era --password "secret" /data

# No compression for already-compressed data
era create --no-compression --output media.era --password "secret" /videos

# Adjust chunk size for your workload (default: 64KB average)
# (Note: This requires code-level configuration change)
```

## 🔧 Troubleshooting

### Common Issues

**"error: the option Z is only accepted on the nightly compiler"**
- **Solution**: Fuzzing requires nightly Rust: `rustup toolchain install nightly`
- **Run fuzz with**: `cargo +nightly fuzz run <target>`

**"protobuf compiler not found"**
- **Solution**: Install protobuf compiler for your system (see Prerequisites)

**"Failed to authenticate archive"**
- **Cause**: Wrong password or corrupted archive
- **Solution**: Verify password, run `era verify` to check integrity

**"Erasure coding failed: insufficient shards"**
- **Cause**: Too many corrupted or missing volume shards
- **Solution**: With 4+2 erasure coding, you can lose up to 2 shards. Beyond that, data is unrecoverable.

**Out of memory during large archive creation**
- **Cause**: Dedup index for very large archives
- **Solution**: Process in batches or increase system RAM

### Debug Mode

```bash
# Build with debug symbols and run
cargo build --bin era
./target/debug/era create --output test.era --password "secret" /data

# Run with RUST_LOG for detailed logging
RUST_LOG=debug cargo run --bin era -- create --output test.era --password "secret" /data

# Run with backtrace on panic
RUST_BACKTRACE=1 cargo run --bin era -- <command>
```

### Reporting Issues

When reporting bugs, please include:
1. Rust version (`rustc --version`)
2. OS and version
3. Full command that failed
4. Error output with `RUST_BACKTRACE=1`
5. Archive format version (from `era info`)

## 🗺️ Roadmap

### Current Focus (Q1-Q2 2026)

- [x] Core archive creation/extraction pipeline
- [x] Content-defined chunking (FastCDC)
- [x] Post-quantum hybrid KEM
- [x] Erasure coding (Reed-Solomon)
- [x] Multi-volume support
- [ ] Index persistence layer (LSM-tree on-disk storage)
- [ ] Performance optimization (SIMD, better parallelism)
- [ ] CLI UX improvements

### Near-term (Q3-Q4 2026)

- [ ] S3/MinIO storage backend
- [ ] Incremental backup support
- [ ] Archive repair tools
- [ ] Multi-recipient key management UI
- [ ] Streaming extraction API
- [ ] Python bindings (PyO3)

### Long-term (2027+)

- [ ] FUSE filesystem interface
- [ ] Hardware security module (HSM) integration
- [ ] Distributed storage backend
- [ ] Web-based archive browser
- [ ] Cloud backup automation
- [ ] Mobile platform support (iOS/Android)

### Non-Goals

- Not a general-purpose filesystem
- Not a database or transactional storage
- Not a version control system (use Git for source code)
- Not a real-time sync solution (use rsync/syncthing for that)

## 🤝 Contributing

Contributions are welcome! This project follows standard Rust community practices.

### Before Contributing

1. Read [CLAUDE.md](CLAUDE.md) for development guidelines and architecture overview
2. Check existing issues or create a new one for discussion
3. Ensure your changes are well-tested and documented

### Development Process

1. **Fork and clone** the repository
2. **Create a branch** for your feature/fix: `git checkout -b feature/my-feature`
3. **Make changes** following the coding standards (see below)
4. **Run all checks**:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets --all-features -- -D warnings
   cargo test
   ```
5. **Commit** with clear, descriptive messages
6. **Push** and create a pull request

### Coding Standards

- **Format**: Run `cargo fmt --all` before committing
- **Lint**: Fix all clippy warnings (we use `-D warnings`)
- **Tests**: Add tests for new functionality
- **Documentation**: Update docs for API changes
- **Async/Sync**: CPU-heavy work must use `spawn_blocking`
- **Error handling**: Avoid `unwrap()` in runtime paths
- **Security**: Never log sensitive data (keys, passwords, hashes)

### Code Review

All pull requests require:
- ✅ Passing CI checks (fmt, clippy, tests)
- ✅ Code review from maintainer
- ✅ Updated documentation if needed
- ✅ No clippy warnings or compilation errors

### Areas Needing Help

- 🔍 Index persistence optimization
- 🧪 More fuzz targets and test coverage
- 📖 Documentation improvements
- 🌐 Non-English translations
- 🔐 Security audit and review

## 📊 Project Statistics

- **Language**: Rust 100%
- **Lines of Code**: ~15,000+ (excluding tests)
- **Test Coverage**: 80%+
- **Crates**: 9 library + 1 binary
- **Dependencies**: Minimal (focus on well-maintained crates)
- **Build Time**: ~2 minutes (clean build on modern hardware)
- **Binary Size**: ~15 MB (release build, stripped)

## 🔐 Security Policy

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities. Instead:

1. Email security reports to: [your-security-email] (or create private security advisory)
2. Include detailed description and steps to reproduce
3. Allow reasonable time for fix before public disclosure

### Security Audits

- Regular fuzzing of parsing code (continuous)
- Cryptographic primitives review (ongoing)
- Full security audit (planned for beta release)

### Supported Versions

| Version | Status | Security Updates |
|---------|--------|------------------|
| 0.1.x (current) | Pre-alpha | ⚠️ Best effort |
| 0.2.x (planned) | Alpha | ⚠️ Best effort |
| 1.0.x (future) | Stable | ✅ Full support |

**Note**: Pre-alpha versions are not recommended for production use.

## ⚖️ License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this software except in compliance with the License.

You may obtain a copy of the License at:
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

See [LICENSE](LICENSE) for full details.

## 🙏 Acknowledgments

This project builds upon excellent work from the Rust community:

- **Cryptography**: [RustCrypto](https://github.com/RustCrypto) for primitives
- **Async Runtime**: [Tokio](https://tokio.rs) for async I/O
- **Compression**: [zstd-rs](https://github.com/gyscos/zstd-rs) and [lz4](https://github.com/10xGenomics/lz4-rs)
- **Erasure Coding**: [reed-solomon-erasure](https://github.com/rust-rse/reed-solomon-erasure)
- **Fuzzing**: [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)

Special thanks to all contributors and researchers who reviewed the security design.

---

## 📞 Contact & Support

- **Issues**: [GitHub Issues](https://github.com/zapsaang/era-core/issues)
- **Discussions**: [GitHub Discussions](https://github.com/zapsaang/era-core/discussions)
- **Documentation**: See [CLAUDE.md](CLAUDE.md) and `docs/` directory

---

<div align="center">

**Status**: Pre-alpha / Audit Mode - API is not stable. Breaking changes expected.

**Last Updated**: February 10, 2026

Built with ❤️ in Rust

</div>
