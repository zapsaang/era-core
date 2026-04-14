# ERA-CORE KNOWLEDGE BASE

**Generated:** 2026-03-31
**Commit:** 63e940b
**Branch:** feat_fly

Post-quantum encrypted archival storage engine in Rust. 3-layer envelope encryption, FastCDC chunking, Reed-Solomon erasure coding, Shamir's secret sharing.

## STRUCTURE

```
era-core/
├── bins/era-cli/          CLI (era create/extract/list/info/verify/repair/repack)
├── crates/
│   ├── era-engine/        L4: Archive orchestration, async pipeline
│   ├── era-packing/       L3: k-Bounded Best-Fit MacroBlock packing
│   ├── era-ingest/        L3: FastCDC chunking (16KB-64KB-256KB)
│   ├── era-index/         L3: V2.1 embedded dedup (Bloom + L1/L2)
│   ├── era-codec/         L2: Zstd/LZ4 compression, Reed-Solomon (4+2)
│   ├── era-volume/        L2: Volume format v8.1, SuperHeader (4096B), Footer (128B)
│   ├── era-storage/       L1: StorageBackend trait (Local/Memory)
│   ├── era-crypto/        L0: XChaCha20-Poly1305, Kyber-768, HKDF, Argon2id, SecureBuffer
│   └── era-common/        L0: EraError, Result, protobuf, config types
└── doc_gen/               Security audit reports
```

## LAYER DEPENDENCY (downward only)

```
L5: era-cli
L4: era-engine
L3: era-packing, era-ingest, era-index
L2: era-codec, era-volume
L1: era-storage
L0: era-crypto, era-common
```

## ANTI-PATTERNS (enforced by 6 audit suites + clippy)

| Rule | Alternative |
|------|-------------|
| NEVER `thread_rng` | `OsRng` only |
| NEVER log key material | Zero logging |
| NEVER `unwrap()` in runtime | `Result<T, EraError>` + `?` |
| NEVER circular deps between crates | Strict downward only |
| NEVER skip AEAD context binding | `archive_id ‖ epoch_id ‖ volume_index ‖ block_index` |
| NEVER persist IK to disk | Derive from MK at runtime |
| NEVER `as any` type suppression | Proper type conversions |
| NEVER block async runtime | `spawn_blocking` for CPU-heavy work |

## WHERE TO LOOK

| Need | Go to |
|------|-------|
| Disk format change | `era-volume/src/header.rs`, `era-volume/src/footer.rs` |
| Crypto primitives | `era-crypto/src/{aead,kdf,key_session}.rs` |
| Pipeline write path | `era-engine/src/writer.rs` (2544 lines) |
| Pipeline read path | `era-engine/src/reader.rs` (2241 lines) |
| Dedup index | `era-index/src/{builder,reader,store}.rs` |
| Chunking | `era-ingest/src/chunker*.rs` |
| Packing | `era-packing/src/macro_block.rs` |
| Compression | `era-codec/src/compression.rs` |
| Erasure coding | `era-codec/src/erasure.rs` |
| Auth (password/cert/threshold) | `era-engine/src/auth.rs` |

## LARGE FILES (>1000 lines)

| File | Lines | Purpose |
|------|-------|---------|
| `era-engine/src/writer.rs` | 2544 | Archive creation pipeline |
| `era-engine/src/reader.rs` | 2241 | Archive extraction pipeline |
| `era-engine/src/block_iter.rs` | 1657 | 4 iterator types, virtual striping |
| `era-volume/src/header.rs` | 1225 | SuperHeader, RecipientSlot, KeyWrap |
| `era-volume/src/volume_pool.rs` | 1192 | Volume rotation, matrix distribution |
| `era-engine/src/checkpoint.rs` | 927 | WAL-based binary checkpoints (v2.2+) |
| `era-engine/src/repair.rs` | 889 | RS-based shard recovery |

## TEST ORG

| Suite | Location | Tests |
|-------|----------|-------|
| 6 adversarial audit waves | `era-engine/tests/` | 279+ |
| 24+ index audit waves | `era-index/tests/` | V2.1 |
| Format/atomicity audits | `era-volume/tests/` | v30 |
| CLI integration | `bins/era-cli/tests/` | 16 |
| Property-based | `era-volume/tests/property_tests.rs` | proptest |

**March 2026 verification:** 2049 passed, 0 failed, 18 ignored.

## COMMANDS

```bash
# Full CI check
cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --workspace

# Per-crate
cargo test -p era-engine
cargo test -p era-engine --test fourth_audit
cargo bench -p era-crypto

# CLI
cargo run --manifest-path bins/era-cli/Cargo.toml -- --help

# Fuzz (nightly, separate workspace — NOT present in repo)
cd fuzz && cargo +nightly fuzz run fuzz_footer_parse -- -max_total_time=60
```

## HIERARCHY

- `crates/AGENTS.md` — crate map + dependency graph
- `crates/*/AGENTS.md` — crate boundary docs
- `crates/*/src/AGENTS.md` — source-tree maps + file inventory
- `crates/*/tests/AGENTS.md` — test surface docs (era-engine, era-index, era-volume)
- `bins/era-cli/AGENTS.md` — CLI layer

## NOTES

- Fuzz workspace (`fuzz/`) documented but NOT present in repo
- Current archive unlock uses X25519 even though hybrid KEM (X25519+Kyber-768) exists in codebase
- Volume format: v8.1, magic `ERA\x08\x01`
- Release profile: LTO, codegen-units=1, opt-level=3
