# ERA (Encrypted Redundant Archiver) Core

[![CI](https://github.com/zapsaang/era-core/actions/workflows/ci.yml/badge.svg)](https://github.com/zapsaang/era-core/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.92+-orange.svg)](https://www.rust-lang.org)

An encrypted archival storage engine written in Rust, featuring 3-layer envelope encryption, content-defined chunking, Reed-Solomon erasure coding, and multi-party access control via Shamir's Secret Sharing.

**Status**: Pre-alpha — API unstable, breaking changes expected. Not production-ready.

**Last Verified**: March 2026 — workspace verification recorded 2049 passed, 0 failed, 18 ignored.

## Features

- **3-Layer Envelope Encryption**: Master Key (MK) → Intermediate Key (IK) → Volume Key (VK) hierarchy with randomized key wrapping (XChaCha20-Poly1305 AEAD)
- **Hybrid KEM Support**: Codebase supports Hybrid KEM (X25519 + Kyber-768) for post-quantum key encapsulation (Password and Threshold modes)
- **Multi-Party Access Control**: Any-of-N (OR) and T-of-N threshold (AND) policies via Shamir's Secret Sharing
- **Instant Key Rotation**: Re-wrap volume keys without rewriting data — millisecond MK rotation for petabyte archives
- **Erasure Coding**: Reed-Solomon (4+2 default) with strict shard validation for data redundancy
- **Content-Defined Chunking**: FastCDC algorithm for efficient deduplication
- **V2.1 Embedded Index**: Right-sized Bloom filter + L1 MetaIndex + L2 IndexPages written as typed blocks within volumes for cold recovery without external state
- **Async Pipeline**: Tokio-based async I/O with blocking offload for CPU-heavy work
- **Multi-Volume Support**: Automatic volume splitting with matrix shard distribution
- **Secure Memory**: mlock'd pages, zeroization on drop, core dump prevention
- **Small File Packing**: Efficient storage of many small files via k-Bounded Best-Fit packing
- **Context-Bound AEAD**: All encryption binds archive ID, epoch ID, and block index into the AAD to prevent cross-archive and cross-block splicing attacks
- **Bounded Allocation**: All deserialization paths enforce strict size limits to prevent memory exhaustion from malicious inputs
- **Archive Repair**: Reed-Solomon–based recovery of damaged archives

## Quick Start

### Prerequisites

**Required:**
- Rust stable 1.92+ (2021 Edition)
- Linux: `build-essential`, `libacl1-dev`, `protobuf-compiler`
- macOS: `protobuf` (via Homebrew)

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

# Show archive metadata
era info archive.era --password "your-secret"

# Verify archive integrity
era verify archive.era --password "your-secret"

# Repair a damaged archive
era repair archive.era --password "your-secret"

# Repack an archive with new parameters
era repack --input archive.era --output repacked.era --password "your-secret" --compact
```

### Advanced Usage

```bash
# Custom erasure coding (6 data + 3 parity shards)
era create --output archive.era --password "secret" --erasure "6:3" /path/to/files

# Custom compression level (1-22, Zstd)
era create --output archive.era --password "secret" --level 12 /path/to/files

# Disable compression
era create --output archive.era --password "secret" --no-compression /path/to/files

# Certificate-based encryption (X25519-based)
era create --output archive.era --certificate public.pem /path/to/files
era extract --input archive.era --output /restored --key private.pem

# Multi-volume archive with size limit
era create --output archive.era --password "secret" \
    --max-volume-size 4294967296 /path/to/large/files

# Custom CDC parameters and packing
era create --output archive.era --password "secret" \
    --cdc-min 16384 --cdc-avg 65536 --cdc-max 262144 \
    --packing-k 8 /path/to/files

# Configuration file
era create --output archive.era --password "secret" -C config.toml /path/to/files

# Verbose verification
era verify archive.era --password "your-secret" --verbose

# Long listing format
era list archive.era --password "your-secret" --long

# Compact mode (high compression preset: Zstd-19, 16MB blocks, k=32)
era create --output archive.era --password "secret" --compact /path/to/files

# Repack an existing archive with new parameters
era repack --input old.era --output new.era --password "secret" --compact

# Repack with custom settings
era repack --input old.era --output new.era --password "secret" \
    --level 19 --erasure "6:3" --block-target-size 16777216
```

## Architecture

### Crate Hierarchy

```
era-core/
├── bins/era-cli/          CLI binary (era)
├── crates/
│   ├── era-common/        Shared types, errors, protobuf definitions
│   ├── era-crypto/        XChaCha20-Poly1305, Kyber-768, HKDF, secure memory
│   ├── era-codec/         Compression (Zstd/LZ4), Reed-Solomon erasure coding
│   ├── era-storage/       Async storage backend abstraction
│   ├── era-volume/        Volume format v8.1, headers/footers, recovery
│   ├── era-packing/       k-Bounded Best-Fit MacroBlock packing
│   ├── era-ingest/        File ingestion, FastCDC chunking
│   ├── era-index/         V2.1 embedded deduplication index (Bloom + L1/L2)
│   └── era-engine/        Archive orchestration, async pipeline
└── fuzz/                  Fuzzing targets (separate workspace)
```

### Layered Dependency Ordering

Dependencies flow downward only — no upward or circular references:

```
┌─────────────────────────────────────────────────────────────┐
│  L5: era-cli          Command-line interface (clap)         │
├─────────────────────────────────────────────────────────────┤
│  L4: era-engine       Archive orchestration, async pipeline │
├─────────────────────────────────────────────────────────────┤
│  L3: era-packing      k-Bounded Best-Fit MacroBlock packing│
│      era-ingest       FastCDC chunking, file scanning       │
│      era-index        V2.1 embedded dedup index (Bloom+L1/L2)│
├─────────────────────────────────────────────────────────────┤
│  L2: era-codec        Compression (Zstd/LZ4), Reed-Solomon  │
│      era-volume       Volume format (v8.1), headers/footers │
├─────────────────────────────────────────────────────────────┤
│  L1: era-storage      Async storage backend abstraction     │
├─────────────────────────────────────────────────────────────┤
│  L0: era-crypto       XChaCha20-Poly1305, Kyber-768, memory │
│      era-common       Shared types, errors, Protobuf defs   │
└─────────────────────────────────────────────────────────────┘
```

### Key Data Flow

**Write path:** Files → FastCDC chunks → dedup check → k-Bounded Best-Fit packing into MacroBlocks → Zstd compress → XChaCha20-Poly1305 encrypt (per-block HKDF key) → Reed-Solomon encode → distribute shards across volumes

**Read path:** Read shards from volumes → CRC verify → RS decode (exclude CRC-failed shards) → AEAD decrypt → decompress → extract chunks → reassemble files

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
│  - AAD = archive_id ‖ epoch_id ‖ volume_index ‖ block_index │
│  - V2.1 Index Pages (Bloom + L1/L2) embedded as typed blocks │
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
| Shard integrity | CRC32 | Per-shard verification |
| RNG | OsRng only | No thread_rng in any code path |

### Security Guarantees

- **No nonce reuse**: Fresh 24-byte random nonce for every encryption operation
- **Strict RNG policy**: `rand::rngs::OsRng` exclusively — `thread_rng()` forbidden
- **Memory hygiene**: All key material (MK, IK, VK) zeroized on drop via `zeroize` crate
- **No key logging**: Key material never appears in any log level including TRACE
- **AEAD integrity**: Tag verification failure returns `EraError::Security("Key Tampering Detected")`
- **Context-bound AEAD**: All encryption binds `archive_id ‖ epoch_id ‖ volume_index ‖ block_index` as AAD — blocks cannot be spliced between archives, volumes, or reordered within one
- **Header validation**: Corrupted magic bytes cause hard failure (no silent recovery)
- **Threshold enforcement**: Reader rejects `Threshold(T<2)` to prevent policy downgrade
- **Erasure validation**: Extraction fails explicitly when insufficient shards are available
- **Path traversal prevention**: Filenames are sanitized on extraction — absolute paths, `..`, and symlinks are rejected
- **Bounded deserialization**: All `TryFrom` conversions enforce maximum sizes to prevent allocation bombs from malicious headers
- **Resilient shard pipeline**: `VerifiedShard` carries CRC status through the pipeline; `ResilientBlockUnpacker` uses 4-tier corruption detection: CRC flag → CRC re-verify → size check → all-same-byte heuristic

### Multi-Party Access Control

**Any-of-N (OR)**: Each recipient slot holds MK encrypted by that user's credential. Any single valid credential unlocks the archive.

**T-of-N Threshold (AND)**: MK is split via Shamir's Secret Sharing. Each recipient slot holds an encrypted share. T shares must be combined to reconstruct MK. Fewer than T shares cannot recover MK (mathematical guarantee).

### Security Audits

ERA Core has undergone multiple rounds of adversarial security auditing (279+ test cases across historical and V5 suites) plus a V2.1 index persistence audit (30 tests).

**Authoritative Audit Report:** [ADVERSARIAL_AUDIT_V5_REPORT.md](doc_gen/AUDIT_REPORT_era-engine/ADVERSARIAL_AUDIT_V5_REPORT.md)

| Audit | Tests | Focus Areas |
|-------|-------|-------------|
| `competitor_audit` | 44 | Core crypto, key management, nonce safety, AEAD correctness |
| `second_audit` | 42 | Key wrapping, secret sharing, multi-party access control |
| `third_audit` | 43 | Memory zeroization, source-level security patterns, TryFrom bounds |
| `fourth_audit` | 46 | Context-bound AAD, path traversal, allocation limits, VK wrapping resilience |
| `adversarial_audit_v5` | 22 | State machine integrity, resume provenance, path containment checks |
| `adversarial_audit_v3` | 20 | V3 specific adversarial coverage (all fixed) |
| `adversarial_audit_v9` | 9 | End-to-end adversarial scenarios: splicing, corruption |
| `adversarial_audit_v2` | 53 | Skeptical baseline verification (all fixed) |
| `index_persistence_audit` | 30 | V2.1 embedded index: Bloom correctness, L1/L2 pages, cold recovery |

Workspace verification recorded 2049 passed, 0 failed, 18 ignored. Vulnerabilities identified during audits have been addressed according to the Post-Fix Registry. Note: Certificate mode currently uses X25519; hybrid KEM for certificates is deferred to a future engineering slice.

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

March 2026 workspace verification recorded 2049 passed, 0 failed, 18 ignored across 10 crates, covering:

- **279+ adversarial audit tests** across multiple security audit suites (historical and V5)
- Unit tests for all cryptographic operations (AEAD, KEM, KDF, secret sharing)
- Integration tests for archive create/extract roundtrips
- V2.1 embedded index tests (Bloom filter, L1/L2 page construction, cold recovery)
- Threshold policy enforcement tests (T-of-N, Any-of-N)
- Erasure coding recovery and failure tests
- Memory hygiene, zeroization, and debug redaction tests
- Context-bound AEAD verification (cross-archive splicing prevention)
- Path traversal and bounded allocation tests
- CLI integration tests (16 tests including roundtrip create/extract)

```bash
cargo test --workspace                        # Full workspace suite
cargo test --package era-engine               # Engine crate only
cargo test -p era-engine --test fourth_audit  # Specific audit suite
cargo test -p era-engine --test second_audit  # Second audit suite
cargo test -p era-engine --test third_audit   # Third audit suite
cargo test -p era-index --test index_persistence_audit  # V2.1 index audit
cargo test -p era-cli                         # CLI integration tests
```

### Fuzzing

Three fuzz targets for critical parsing code (separate workspace, requires nightly):

```bash
rustup toolchain install nightly
cargo install cargo-fuzz

cd fuzz
# Run each target (60 seconds each)
cargo +nightly fuzz run fuzz_footer_parse -- -max_total_time=60
cargo +nightly fuzz run fuzz_block_header_parse -- -max_total_time=60
cargo +nightly fuzz run fuzz_super_header_parse -- -max_total_time=60
```

| Target | Parses | Throughput | Crashes |
|--------|--------|------------|---------|
| `fuzz_footer_parse` | `Footer::from_bytes()` | ~444K exec/s | 0 (27M+ runs) |
| `fuzz_block_header_parse` | `BlockHeader::from_bytes()`, `ShardHeader::from_bytes()` | ~1.3M exec/s | 0 (33M+ runs) |
| `fuzz_super_header_parse` | `SuperHeader::from_bytes()` | ~160K exec/s | 0 (5M+ runs) |

### Benchmarks

Criterion benchmarks are available for performance-critical paths:

```bash
cargo bench                          # All benchmarks
cargo bench --package era-crypto     # Crypto benchmarks (AEAD, KDF, KEM)
cargo bench --package era-engine     # Pipeline benchmarks (roundtrip, extraction)
cargo bench --package era-codec      # Compression and erasure coding
cargo bench --package era-index      # Index operations
cargo bench --package era-packing    # Packing operations
cargo bench --package era-ingest     # Chunking benchmarks
```

### Examples

```bash
# Batch file ingestion demo
cargo run --example batch_files_demo -p era-cli

# Guard pages security demonstration
cargo run --example guard_pages_demo -p era-cli
```

## Performance

- **Chunking**: ~1.5 GB/s (FastCDC)
- **Compression**: ~600 MB/s (Zstd level 3), ~2 GB/s (LZ4)
- **Encryption**: ~3 GB/s (XChaCha20-Poly1305)
- **Hashing**: ~2.5 GB/s (BLAKE3)
- **Combined Pipeline**: ~300–500 MB/s (real-world with dedup)

## Troubleshooting

**"error: the option Z is only accepted on the nightly compiler"**
Fuzzing requires nightly: `rustup toolchain install nightly`

**"protobuf compiler not found"**
Install protobuf compiler — see Prerequisites.

**"Failed to authenticate archive"**
Wrong password or corrupted archive. Run `era verify` to check integrity.

**"Not enough shards for recovery"**
Too many missing or corrupted volumes. With 4+2 erasure coding, you can lose up to 2 volumes. Try `era repair` first.

## Roadmap

### Current (Q1–Q2 2026)

- [x] Core archive creation/extraction pipeline
- [x] 3-layer envelope encryption (MK/IK/VK)
- [x] Multi-party access control (Any-of-N + T-of-N threshold)
- [x] Post-quantum hybrid KEM (X25519 + Kyber-768)
- [x] Erasure coding with strict shard validation
- [x] Multi-volume support with matrix distribution
- [x] Archive repair via Reed-Solomon recovery
- [x] Security audit — round 1: core crypto, nonce safety (44/44 passing)
- [x] Security audit — round 2: key wrapping, secret sharing (42/42 passing)
- [x] Security audit — round 3: memory zeroization, TryFrom bounds (43/43 passing)
- [x] Security audit — round 4: context-bound AAD, path traversal, allocation limits (46/46 passing)
- [x] Security audit — adversarial edge cases (22/22 passing)
- [x] V2.1 embedded deduplication index (Bloom + L1/L2 pages in-volume, cold recovery)
- [x] Index persistence audit (30/30 passing)
- [ ] CLI UX improvements

### Near-term (Q3–Q4 2026)

- [ ] S3/MinIO storage backend
- [ ] Incremental backup support
- [ ] Streaming extraction API
- [ ] Python bindings (PyO3)
- [ ] Bit-level volume integrity scan — detect and report every corrupted bit across all volumes (see [`doc_gen/TODO/BIT_LEVEL_VOLUME_INTEGRITY_SCAN.md`](doc_gen/TODO/BIT_LEVEL_VOLUME_INTEGRITY_SCAN.md))

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
- No `unwrap()` in runtime paths — use `Result<T, EraError>`
- CPU-heavy work must use `spawn_blocking`
- All AEAD operations must bind context (archive ID, epoch ID, block index) as AAD
- All `TryFrom` deserialization must enforce bounded allocation limits
- Zero-copy via `Bytes` and `rkyv` — avoid cloning large buffers
- Async I/O via Tokio in L0–L2

## Project Statistics

| Metric | Value |
|--------|-------|
| Language | Rust 100% |
| Lines of Code | ~56,900 (including tests) |
| Source Files | 137 `.rs` files |
| Tests | March 2026 workspace verification: 2049 passed, 0 failed, 18 ignored |
| Security Audit Tests | 279+ across multiple suites |
| Fuzz Targets | 5 (combined 65M+ runs, 0 crashes) |
| Crates | 8 library + 1 binary |
| CLI Commands | 7 (create, extract, list, info, verify, repair, repack) |
| Edition | 2021, resolver v2 |
| Build Profile | LTO + codegen-units=1 + opt-level=3 (release) |

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

## Acknowledgments

- [RustCrypto](https://github.com/RustCrypto) — cryptographic primitives
- [Tokio](https://tokio.rs) — async runtime
- [sharks](https://github.com/c0dearm/sharks) — Shamir's Secret Sharing
- [reed-solomon-simd](https://github.com/AndersTrier/reed-solomon-simd) — erasure coding
- [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) — fuzzing infrastructure
- [rkyv](https://github.com/rkyv/rkyv) — zero-copy serialization

---

**Issues**: [GitHub Issues](https://github.com/zapsaang/era-core/issues) | **Docs**: [CLAUDE.md](CLAUDE.md), `docs/`
