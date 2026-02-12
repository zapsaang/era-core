# ERA (Encrypted Redundant Archiver) Core

[![CI](https://github.com/zapsaang/era-core/actions/workflows/ci.yml/badge.svg)](https://github.com/zapsaang/era-core/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.92+-orange.svg)](https://www.rust-lang.org)

A post-quantum encrypted archival storage engine written in Rust, featuring 3-layer envelope encryption, content-defined chunking, erasure coding, and multi-party access control via Shamir's Secret Sharing.

**Status**: Pre-alpha — API unstable, breaking changes expected. Not production-ready.

**Last Verified**: February 11, 2026 — 218 tests passing, 0 clippy warnings, 3 fuzz targets clean.

## Features

- **3-Layer Envelope Encryption**: Master Key (MK) → Intermediate Key (IK) → Volume Key (VK) hierarchy with randomized key wrapping (XChaCha20-Poly1305 AEAD)
- **Post-Quantum Ready**: Hybrid KEM (X25519 + Kyber-768) for future-proof key encapsulation
- **Multi-Party Access Control**: Any-of-N (OR) and T-of-N threshold (AND) policies via Shamir's Secret Sharing
- **Instant Key Rotation**: Re-wrap volume keys without rewriting data — millisecond MK rotation for petabyte archives
- **Erasure Coding**: Reed-Solomon (4+2 default) with strict shard validation for data redundancy
- **Content-Defined Chunking**: FastCDC algorithm for efficient deduplication
- **Async Pipeline**: Tokio-based async I/O with blocking offload for CPU-heavy work
- **Multi-Volume Support**: Automatic volume splitting with matrix shard distribution
- **Secure Memory**: mlock'd pages, zeroization on drop, core dump prevention
- **Small File Packing**: Efficient storage of many small files via k-Bounded Best-Fit packing
- **Context-Bound AEAD**: All encryption binds archive ID, epoch ID, and block index into the AAD to prevent cross-archive and cross-block splicing attacks
- **Bounded Allocation**: All deserialization paths enforce strict size limits to prevent memory exhaustion from malicious inputs

## Quick Start

### Prerequisites

**Required:**
- Rust stable 1.92+ (2021 Edition)
- Linux: `build-essential`, `libacl1-dev`, `protobuf-compiler`
- macOS: `protobuf` (via Homebrew: `brew install protobuf`)

**Optional:**
- Rust nightly (for fuzzing): `rustup toolchain install nightly`
- `cargo-fuzz`: `cargo install cargo-fuzz`

```bash
# Ubuntu/Debian
sudo apt-get install -y build-essential libacl1-dev protobuf-compiler

# macOS
brew install protobuf
```

### Installation

```bash
git clone https://github.com/zapsaang/era-core.git
cd era-core
cargo install --path bins/era-cli
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
```

### Advanced Usage

```bash
# Custom erasure coding (6 data + 3 parity shards)
era create --output archive.era --password "secret" --erasure "6:3" /path/to/files

# Certificate-based encryption (post-quantum hybrid)
era create --output archive.era --certificate public.pem /path/to/files
era extract --input archive.era --output /restored --key private.pem

# Multi-volume archive with size limit
era create --output archive.era --password "secret" \
    --max-volume-size 4294967296 /path/to/large/files
```

## Architecture

### Crate Hierarchy

```
era-core/
├── bins/era-cli/          CLI binary
├── crates/
│   ├── era-common/        Shared types, errors, protobuf definitions
│   ├── era-crypto/        XChaCha20-Poly1305, Kyber-768, HKDF, secure memory
│   ├── era-codec/         Compression (Zstd/LZ4), Reed-Solomon erasure coding
│   ├── era-storage/       Async storage backend abstraction
│   ├── era-volume/        Volume format v8.1, headers/footers, recovery
│   ├── era-packing/       k-Bounded Best-Fit MacroBlock packing
│   ├── era-ingest/        File ingestion, FastCDC chunking
│   ├── era-index/         LSM-tree deduplication index
│   └── era-engine/        Archive orchestration, async pipeline
└── fuzz/                  Fuzzing targets (separate workspace)
```

Layered dependency ordering (downward only):

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

### Volume Format (v8.1)

```
┌──────────────────────────────────────────────────────────────┐
│  Primary Header (4096 bytes)                                 │
│  - Magic: "ERA\x08\x01"                                     │
│  - Archive ID, Epoch ID, Encrypted Volume Key                │
│  - Recipient Slots, Access Policy, Config                    │
├──────────────────────────────────────────────────────────────┤
│  Backup Footer (128 bytes, fixed-length binary)              │
├──────────────────────────────────────────────────────────────┤
│  Data Region (Encrypted Blocks)                              │
│  - Packed chunks with erasure shards                         │
│  - AEAD encrypted with per-block derived keys                │
│  - AAD = archive_id ‖ epoch_id ‖ block_index (context-bound)│
├──────────────────────────────────────────────────────────────┤
│  Backup Header (4096 bytes)                                  │
├──────────────────────────────────────────────────────────────┤
│  Primary Footer (128 bytes, fixed-length binary)             │
│  - Block count, Index location, Blake3 checksum              │
│  - Atomic write guarantee (single disk sector)               │
└──────────────────────────────────────────────────────────────┘
```

## Security Model

### 3-Layer Envelope Encryption

ERA v8.1 uses a randomized key wrapping hierarchy that enables instant key rotation without rewriting data:

```
Layer 1: Master Key (MK)
  ├── Generated via OsRng CSPRNG, stored encrypted in RecipientSlots
  ├── Supports Any-of-N (OR) and T-of-N threshold (AND) access policies
  │
Layer 2: Intermediate Key (IK)
  ├── Derived: IK = HKDF-Expand(PRK=MK, Info="ERA_KeyWrap_v1")
  ├── Never stored on disk — memory only, zeroized on drop
  │
Layer 3: Volume Key (VK)
  ├── Randomly generated (OsRng, 32 bytes) per volume
  ├── Wrapped by IK using XChaCha20-Poly1305 AEAD
  └── Stored as EncryptedVolumeKey in SuperHeader
```

**Key Rotation**: Change MK → derive new IK → re-wrap existing VK → update header. Data untouched.

### Cryptographic Primitives

| Purpose | Algorithm | Parameters |
|---------|-----------|------------|
| Data encryption | XChaCha20-Poly1305 | 256-bit key, 192-bit nonce |
| Key wrapping (IK→VK) | XChaCha20-Poly1305 AEAD | Fresh random nonce per wrap |
| Key derivation (MK→IK) | HKDF-SHA256 | Domain-separated context |
| Password KDF | Argon2id | Configurable memory/time cost |
| Hybrid KEM | X25519 + Kyber-768 | Post-quantum security |
| Content hashing | BLAKE3 | 256-bit output |
| Secret sharing | Shamir's (sharks crate) | T-of-N threshold |
| RNG | OsRng only | No thread_rng in any code path |

### Security Guarantees

- **No nonce reuse**: Fresh 24-byte random nonce for every encryption operation
- **Strict RNG policy**: `rand::rngs::OsRng` exclusively — `thread_rng()` forbidden
- **Memory hygiene**: All key material (MK, IK, VK) zeroized on drop via `zeroize` crate
- **No key logging**: Key material never appears in any log level including TRACE
- **AEAD integrity**: Tag verification failure returns `EraError::Security("Key Tampering Detected")`
- **Context-bound AEAD**: All encryption binds `archive_id ‖ epoch_id ‖ block_index` as AAD — blocks cannot be spliced between archives or reordered within one
- **Header validation**: Corrupted magic bytes cause hard failure (no silent recovery)
- **Threshold enforcement**: Reader rejects `Threshold(T<2)` to prevent policy downgrade
- **Erasure validation**: Extraction fails explicitly when insufficient shards are available
- **Path traversal prevention**: Filenames are sanitized on extraction — absolute paths, `..`, and symlinks are rejected
- **Bounded deserialization**: All `TryFrom` conversions enforce maximum sizes to prevent allocation bombs from malicious headers

### Multi-Party Access Control

**Any-of-N (OR)**: Each recipient slot holds MK encrypted by that user's credential. Any single valid credential unlocks the archive.

**T-of-N Threshold (AND)**: MK is split via Shamir's Secret Sharing. Each recipient slot holds an encrypted share. T shares must be combined to reconstruct MK. Fewer than T shares cannot recover MK (mathematical guarantee).

### Security Audits

ERA Core has undergone five rounds of adversarial security auditing (189 test cases total):

| Audit | Tests | Focus Areas |
|-------|-------|-------------|
| `competitor_audit` | 44 | Core crypto, key management, nonce safety, AEAD correctness |
| `ruthless_audit_tests` | 14 | Edge cases, error handling, adversarial inputs |
| `second_audit` | 42 | Key wrapping, secret sharing, multi-party access control |
| `third_audit` | 43 | Memory zeroization, source-level security patterns, TryFrom bounds |
| `fourth_audit` | 46 | Context-bound AAD, path traversal, allocation limits, VK wrapping resilience |

All 189 audit tests pass. Vulnerabilities identified during audits have been fully remediated.

## Development

### CI Workflow

GitHub Actions runs on every push and PR:

```bash
# 1. Format check
cargo fmt --all -- --check

# 2. Lint (warnings = errors)
cargo clippy --all-targets --all-features -- -D warnings

# 3. Full test suite
cargo test --workspace
```

Run locally before committing:

```bash
cargo fmt --all -- --check && \
cargo clippy --all-targets --all-features -- -D warnings && \
cargo test --workspace
```

### Testing

218 tests across 9 crates covering:
- **189 adversarial audit tests** across 5 dedicated security audit suites
- Unit tests for all cryptographic operations (AEAD, KEM, KDF, secret sharing)
- Integration tests for archive create/extract roundtrips
- Threshold policy enforcement tests (T-of-N, Any-of-N)
- Erasure coding recovery and failure tests
- Memory hygiene, zeroization, and debug redaction tests
- Context-bound AEAD verification (cross-archive splicing prevention)
- Path traversal and bounded allocation tests

```bash
cargo test --workspace                        # All tests
cargo test --package era-engine               # Engine crate only
cargo test -p era-engine --test fourth_audit  # Specific audit suite
cargo test -p era-engine --test second_audit  # Second audit suite
cargo test -p era-engine --test third_audit   # Third audit suite
```

### Fuzzing

Three fuzz targets for critical parsing code (separate workspace, requires nightly):

```bash
rustup toolchain install nightly
cargo install cargo-fuzz

cd fuzz
# Run each target
cargo +nightly fuzz run fuzz_footer_parse -- -max_total_time=60
cargo +nightly fuzz run fuzz_block_header_parse -- -max_total_time=60
cargo +nightly fuzz run fuzz_super_header_parse -- -max_total_time=60
```

| Target | Tests | Last Run |
|--------|-------|----------|
| `fuzz_footer_parse` | `Footer::from_bytes()` | Millions of runs, 0 crashes |
| `fuzz_block_header_parse` | `BlockHeader::from_bytes()`, `ShardHeader::from_bytes()` | 33M+ runs, 0 crashes |
| `fuzz_super_header_parse` | `SuperHeader::from_bytes()` | 4.8M+ runs, 0 crashes |

### Benchmarks

```bash
cargo bench                          # All benchmarks
cargo bench --package era-crypto     # Crypto benchmarks
cargo bench --package era-engine     # Pipeline benchmarks
```

## Performance

- **Chunking**: ~1.5 GB/s (FastCDC)
- **Compression**: ~600 MB/s (Zstd level 3), ~2 GB/s (LZ4)
- **Encryption**: ~3 GB/s (XChaCha20-Poly1305)
- **Hashing**: ~2.5 GB/s (BLAKE3)
- **Combined Pipeline**: ~300-500 MB/s (real-world with dedup)

## Troubleshooting

**"error: the option Z is only accepted on the nightly compiler"**
Fuzzing requires nightly: `rustup toolchain install nightly`

**"protobuf compiler not found"**
Install protobuf compiler (see Prerequisites).

**"Failed to authenticate archive"**
Wrong password or corrupted archive. Run `era verify` to check integrity.

**"Not enough shards for recovery"**
Too many missing or corrupted volumes. With 4+2 erasure coding, you can lose up to 2 volumes.

## Roadmap

### Current (Q1-Q2 2026)

- [x] Core archive creation/extraction pipeline
- [x] 3-layer envelope encryption (MK/IK/VK)
- [x] Multi-party access control (Any-of-N + T-of-N threshold)
- [x] Post-quantum hybrid KEM
- [x] Erasure coding with strict shard validation
- [x] Multi-volume support
- [x] Security audit — round 1: core crypto, nonce safety (44/44 passing)
- [x] Security audit — round 2: key wrapping, secret sharing (42/42 passing)
- [x] Security audit — round 3: memory zeroization, TryFrom bounds (43/43 passing)
- [x] Security audit — round 4: context-bound AAD, path traversal, allocation limits (46/46 passing)
- [x] Security audit — adversarial edge cases (14/14 passing)
- [ ] Index persistence layer (LSM-tree on-disk storage)
- [ ] CLI UX improvements

### Near-term (Q3-Q4 2026)

- [ ] S3/MinIO storage backend
- [ ] Incremental backup support
- [ ] Archive repair tools
- [ ] Streaming extraction API
- [ ] Python bindings (PyO3)

### Long-term (2027+)

- [ ] FUSE filesystem interface
- [ ] HSM integration
- [ ] Distributed storage backend

## Contributing

1. Read [CLAUDE.md](CLAUDE.md) for architecture mandates and security constraints
2. Fork, branch, and make changes following the coding standards
3. Run all CI checks locally (`fmt`, `clippy -D warnings`, `test --workspace`)
4. Submit a PR — all checks must pass, code review required

### Coding Standards

- `cargo fmt --all` before committing
- Zero clippy warnings (`-D warnings`)
- `OsRng` only for all randomness — `thread_rng()` is forbidden
- Never log key material at any level
- Avoid `unwrap()` in runtime paths
- CPU-heavy work must use `spawn_blocking`
- All AEAD operations must bind context (archive ID, epoch ID, block index) as AAD
- All `TryFrom` deserialization must enforce bounded allocation limits

## Project Statistics

- **Language**: Rust 100%
- **Lines of Code**: ~54,300 (including tests)
- **Tests**: 218 passing (0 failures, 3 ignored)
- **Security Audit Tests**: 189 across 5 adversarial audit suites
- **Fuzz Targets**: 3 (combined 38M+ runs, 0 crashes)
- **Crates**: 9 library + 1 binary
- **Build Time**: ~2 minutes (clean build)

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

## Acknowledgments

- [RustCrypto](https://github.com/RustCrypto) — cryptographic primitives
- [Tokio](https://tokio.rs) — async runtime
- [sharks](https://github.com/c0dearm/sharks) — Shamir's Secret Sharing
- [reed-solomon-erasure](https://github.com/rust-rse/reed-solomon-erasure) — erasure coding
- [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) — fuzzing infrastructure

---

**Issues**: [GitHub Issues](https://github.com/zapsaang/era-core/issues) | **Docs**: [CLAUDE.md](CLAUDE.md), `docs/`
