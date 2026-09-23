# ERA (Encrypted Redundant Archiver) Core

[![CI](https://github.com/zapsaang/era-core/actions/workflows/ci.yml/badge.svg)](https://github.com/zapsaang/era-core/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.92+-orange.svg)](https://www.rust-lang.org)

An encrypted archival storage engine written in Rust, featuring 3-layer envelope encryption, content-defined chunking, Reed-Solomon erasure coding, and multi-party access control via Shamir's Secret Sharing.

**Status**: Pre-alpha — API unstable, breaking changes expected. Not production-ready.

**Last Verified**: March 2026 — workspace verification recorded 2049 passed, 0 failed, 18 ignored.

## Features

- **3-Layer Envelope Encryption**: Master Key (MK) → Intermediate Key (IK) → Volume Key (VK) hierarchy with randomized key wrapping (XChaCha20-Poly1305 AEAD)
- **Hybrid KEM Support**: Hybrid KEM (X25519 + ML-KEM-768) for post-quantum key encapsulation, supporting standalone, password-combined, and threshold modes
- **Multi-Party Access Control**: Any-of-N (OR) recipient slots and Shamir T-of-N threshold policies
- **Instant Key Rotation**: Re-wrap volume keys without rewriting data — millisecond MK rotation for petabyte archives
- **Erasure Coding**: Reed-Solomon (4+2 default) with strict shard validation for data redundancy
- **Content-Defined Chunking**: FastCDC algorithm for efficient deduplication
- **V2.1 Embedded Index**: Right-sized Bloom filter + L1 MetaIndex + L2 IndexPages written as typed blocks within volumes for cold recovery without external state
- **Async Pipeline**: Tokio-based async I/O with blocking offload for CPU-heavy work
- **Multi-Volume Support**: Automatic volume splitting with matrix shard distribution
- **Secure Memory**: mlock'd pages, zeroization on drop, core dump prevention
- **Small File Packing**: Efficient storage of many small files via k-Bounded Best-Fit packing
- **Context-Bound Block AEAD**: Block encryption binds archive ID, epoch ID, block type, volume index, and block ID as AAD to prevent cross-archive and cross-block splicing attacks
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

# Generate a keypair for certificate-based encryption
# Default output is a hybrid (X25519 + ML-KEM-768) keypair
era keygen

# Generate a legacy X25519 keypair
era keygen -t x25519 -f ./my_x25519_key

# Generate a post-quantum hybrid keypair (default)
era keygen -t hybrid -f ./my_hybrid_key
```

### Advanced Usage

```bash
# Custom erasure coding (6 data + 3 parity shards)
era create --output archive.era --password "secret" --erasure "6:3" /path/to/files

# Custom compression level (1-22, Zstd)
era create --output archive.era --password "secret" --level 12 /path/to/files

# Disable compression
era create --output archive.era --password "secret" --no-compression /path/to/files

# Certificate-based encryption (legacy X25519)
era create --output archive.era --certificate public.pem /path/to/files

# Extract with the matching private key
era extract --input archive.era --output /restored --key private.pem

# Note: passphrase-protected private keys are not yet supported. Use unencrypted PEM keys.

# Post-quantum hybrid certificate encryption (X25519 + ML-KEM-768)
era create --output archive.era --hybrid-certificate pub.pem /path/to/files
era extract --input archive.era --output /restored --key private.pem

# Any-of-N (OR): any single credential unlocks the archive.
# Supported OR combinations are legacy certificate + password, or hybrid certificate + password.
# Both credential types are stored as separate recipient slots; each slot protects the full Master Key.
era create --output archive.era --certificate public.pem --password "secret" /path/to/files
era create --output archive.era --hybrid-certificate pub.pem --password "secret" /path/to/files

# T-of-N threshold (Shamir's Secret Sharing): the Master Key is split into N shares,
# and any T shares can reconstruct it. The scheme supports multiple distinct passwords
# or multiple distinct hybrid certificates (the --password or --hybrid-certificate
# flags are repeated to provide them). Both --threshold and --shares are required.
# Legacy certificate threshold and mixed credential threshold (password + hybrid certificate
# in the same scheme) are not supported.
# Note: threshold archives cannot be appended to existing archives.
era create --output archive.era \
    --password "share-1" --password "share-2" --password "share-3" \
    --threshold 2 --shares 3 /path/to/files

era create --output archive.era \
    --hybrid-certificate holder-a.pub --hybrid-certificate holder-b.pub --hybrid-certificate holder-c.pub \
    --threshold 2 --shares 3 /path/to/files

# Threshold extraction: provide any T of the N credentials/keys
era extract --input archive.era --output /restored \
    --password "share-1" --password "share-2"

era extract --input archive.era --output /restored \
    --key holder-a --key holder-c

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
│   ├── era-crypto/        XChaCha20-Poly1305, ML-KEM-768, HKDF, secure memory
│   ├── era-codec/         Compression (Zstd/LZ4), Reed-Solomon erasure coding
│   ├── era-storage/       Async storage backend abstraction
│   ├── era-volume/        Volume format v8.2, headers/footers, recovery
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
│  L3: era-packing      k-Bounded Best-Fit MacroBlock packing │
│      era-ingest       FastCDC chunking, file scanning       │
│      era-index        V2.1 dedup index (Bloom + L1/L2)      │
├─────────────────────────────────────────────────────────────┤
│  L2: era-codec        Compression (Zstd/LZ4), Reed-Solomon  │
│      era-volume       Volume format (v8.2), headers/footers │
├─────────────────────────────────────────────────────────────┤
│  L1: era-storage      Async storage backend abstraction     │
├─────────────────────────────────────────────────────────────┤
│  L0: era-crypto       XChaCha20-Poly1305 + ML-KEM-768       │
│      era-common       Shared types, errors, Protobuf defs   │
└─────────────────────────────────────────────────────────────┘
```

### Key Data Flow

**Write path:** Files → FastCDC chunks → dedup check → k-Bounded Best-Fit packing into MacroBlocks → Zstd compress → XChaCha20-Poly1305 encrypt (per-block HKDF key) → Reed-Solomon encode → distribute shards across volumes

**Read path:** Read shards from volumes → CRC verify → RS decode (exclude CRC-failed shards) → AEAD decrypt → decompress → extract chunks → reassemble files

### Volume Format (v8.2)

```
┌───────────────────────────────────────────────────────────────────────┐
│  SuperHeader (4096 bytes)                                             │
│  - Magic (8 bytes): 45 52 41 08 02 00 00 00                           │
│  - Archive ID, Epoch ID, Encrypted Volume Key                         │
│  - Recipient Slots, Access Policy, Config                             │
├───────────────────────────────────────────────────────────────────────┤
│  Reserved 128-byte gap (receives Footer copy at finalize)             │
├───────────────────────────────────────────────────────────────────────┤
│  Data Region (Encrypted Blocks)                                       │
│  - Packed chunks with erasure shards                                  │
│  - AEAD encrypted with per-block derived keys                         │
│  - AAD = archive_id ‖ epoch_id ‖ block_type ‖ volume_index ‖ block_id │
│  - V2.1 Index Pages (Bloom + L1/L2) as typed blocks                   │
│  - v8.2 ArchiveManifest typed block                                   │
├───────────────────────────────────────────────────────────────────────┤
│  Backup SuperHeader (4096 bytes)                                      │
├───────────────────────────────────────────────────────────────────────┤
│  Primary Footer (128 bytes, fixed-length binary)                      │
│  - Block count, Index location, Manifest block ID/offset              │
│  - Blake3 checksum                                                    │
│  - Sized to fit within a conventional disk sector                     │
└───────────────────────────────────────────────────────────────────────┘
```

## Security Model

### 3-Layer Envelope Encryption

ERA v8.2 uses a randomized key wrapping hierarchy that enables instant key rotation without rewriting data:

```
Layer 1: Master Key (MK)
  ├── Generated via OsRng CSPRNG, stored encrypted in RecipientSlots
  ├── Supports Any-of-N (OR) and T-of-N threshold access policies
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

### Certificates and External Trust

Hybrid keys use ERA-specific `ERA HYBRID PUBLIC KEY` / `ERA HYBRID PRIVATE KEY` PEM blocks. Legacy X25519 keygen emits an unencrypted PKCS#8 private PEM and an SPKI public PEM; the legacy public loader also accepts X.509 and extracts the X25519 public key. ERA does not validate PKIX chains, CA trust, validity periods, or expiration; trust is established out of band.

Password recipient slots derive their wrapping key with Argon2id and AEAD-wrap the Master Key or a Shamir share using XChaCha20-Poly1305 with a fresh random nonce. Legacy X25519 certificate recipient slots perform ephemeral ECDH, derive a wrapping key with HKDF-SHA256, and AEAD-wrap the full Master Key under XChaCha20-Poly1305 using a fixed zero nonce. Hybrid certificate recipient slots perform X25519 ECDH and ML-KEM-768 encapsulation, combine both shared secrets through HKDF-SHA256, and AEAD-wrap the full Master Key or a Shamir share under XChaCha20-Poly1305 using a fixed zero nonce. IK→VK wrapping inside the archive uses XChaCha20-Poly1305 with a fresh random nonce.

### Cryptographic Primitives

| Purpose | Algorithm | Parameters |
|---------|-----------|------------|
| Data encryption | XChaCha20-Poly1305 | 256-bit key, 192-bit nonce |
| Key wrapping (IK→VK) | XChaCha20-Poly1305 AEAD | Fresh random nonce per wrap |
| Key derivation (MK→IK) | HKDF-SHA256 | Domain-separated context |
| Password KDF | Argon2id | Configurable memory/time cost |
| Hybrid KEM | X25519 + ML-KEM-768 | Hybrid classical/PQ key establishment; ML-KEM-768 supplies the PQ component |
| Content hashing | BLAKE3 | 256-bit output |
| Secret sharing | Shamir's (sharks crate) | T-of-N threshold |
| Shard integrity | CRC32 | Per-shard verification |
| RNG | OsRng only | No thread_rng in any code path |

### Security Guarantees

- **Scoped nonce discipline**: Block nonces are deterministically derived from the nonce context, volume index, and block ID; password recipient-slot wraps and IK→VK wraps use fresh random nonces; certificate recipient-slot wraps use fresh one-time keys with a fixed zero nonce.
- **Strict RNG policy**: `rand::rngs::OsRng` exclusively — `thread_rng()` forbidden
- **Memory hygiene**: All key material (MK, IK, VK) zeroized on drop via `zeroize` crate
- **No key logging**: Key material never appears in any log level including TRACE
- **AEAD integrity**: Authentication-tag verification failures are rejected.
- **Context-bound block AEAD**: All block encryption binds `archive_id ‖ epoch_id ‖ block_type ‖ volume_index ‖ block_id` as AAD — blocks cannot be spliced between archives, volumes, or reordered within one
- **Header validation**: Corrupted magic bytes cause hard failure (no silent recovery)
- **Threshold enforcement**: Reader rejects `Threshold(T<2)` to prevent policy downgrade
- **Erasure validation**: Extraction fails explicitly when insufficient shards are available
- **Path traversal prevention**: Filenames are sanitized on extraction — absolute paths, `..`, and symlinks are rejected
- **Bounded deserialization**: All `TryFrom` conversions enforce maximum sizes to prevent allocation bombs from malicious headers
- **Resilient shard pipeline**: `VerifiedShard` carries CRC status through the pipeline; `ResilientBlockUnpacker` uses 4-tier corruption detection: CRC flag → CRC re-verify → size check → all-same-byte heuristic

### Multi-Party Access Control

**Any-of-N (OR)**: Each recipient slot holds the full Master Key encrypted by that slot's credential. Any single valid credential unlocks the archive and recovers the complete Master Key. Supported OR combinations are a legacy X25519 certificate together with one password, or a hybrid (X25519 + ML-KEM-768) certificate together with one password. Legacy certificates cannot be combined with hybrid certificates, and multiple legacy certificates are not supported in OR mode.

**T-of-N Threshold**: The Master Key is split into N shares via Shamir's Secret Sharing. The scheme can use multiple distinct passwords or multiple distinct hybrid certificates as share credentials. Each share is encrypted and stored in a separate recipient slot. Any T valid decrypted shares can reconstruct the Master Key. At the Shamir layer, fewer than T valid decrypted shares are information-theoretically insufficient to determine the Master Key. Threshold mode requires both `--threshold T` and `--shares N` with `2 <= T <= N <= 255`. A threshold scheme must be homogeneous: either all slots use distinct password credentials or all slots use distinct hybrid certificates. Legacy certificate threshold and mixed credential threshold are not supported. Threshold archives cannot be appended to existing archives.

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

Workspace verification recorded 2049 passed, 0 failed, 18 ignored. Vulnerabilities identified during audits have been addressed according to the Post-Fix Registry. Note: Both legacy X25519 certificate mode and hybrid KEM (X25519 + ML-KEM-768) certificate mode are supported via CLI.

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
- CLI integration tests (130+ tests covering auth modes, repack, repair, roundtrip, and edge cases)

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

Fuzzing is planned for the critical parsing code paths (footer, block header, super header parsing) but the `fuzz/` workspace is not yet present in this repository. Fuzz targets, a nightly `cargo-fuzz` workspace, and scheduled CI runs will be added once the workspace lands.

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
- [x] Post-quantum hybrid KEM (X25519 + ML-KEM-768)
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
- Block AEAD operations must bind context (archive ID, epoch ID, block type, volume index, block ID) as AAD
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
| Fuzz Targets | Planned (fuzz workspace not yet in repo) |
| Crates | 8 library + 1 binary |
| CLI Commands | 8 (create, extract, list, info, verify, repair, repack, keygen) |
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
