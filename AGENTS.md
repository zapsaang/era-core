# PROJECT KNOWLEDGE BASE

**Generated:** 2026-02-25
**Commit:** 6d74066
**Branch:** feat_fly

## OVERVIEW

Post-quantum encrypted archival storage engine in Rust. 3-layer envelope encryption (MK→IK→VK), FastCDC chunking, Reed-Solomon erasure coding, Shamir's Secret Sharing for T-of-N access control. Hybrid KEM (X25519 + Kyber-768) is implemented in the codebase, while current certificate archives remain X25519-based.

## STRUCTURE

```
./
├── bins/era-cli/          # L5: CLI binary (era command, clap derive)
├── crates/               # 9 library crates
│   ├── era-common/       # L0: EraError, protobuf, shared types
│   ├── era-crypto/       # L0: XChaCha20-Poly1305, Kyber-768, HKDF, SecureBuffer
│   ├── era-storage/      # L1: Async StorageBackend trait (local, memory)
│   ├── era-codec/        # L2: Zstd/LZ4 compression, Reed-Solomon erasure
│   ├── era-volume/       # L2: Volume format v8.1 (SuperHeader, Footer)
│   ├── era-packing/      # L3: k-Bounded Best-Fit, resilient AEAD
│   ├── era-ingest/       # L3: FastCDC chunking, file scanning
│   ├── era-index/        # L3: V2.1 embedded dedup index (Bloom + L1/L2)
│   └── era-engine/       # L4: Async pipeline orchestration
├── fuzz/                 # Fuzzing targets (separate workspace, nightly)
└── .github/workflows/    # CI: fmt → clippy -D warnings → test
```

## DEPENDENCY GRAPH

```
L5: era-cli → era-engine (thin UI layer, no core logic)
L4: era-engine → ALL lower layers (orchestration)
L3: era-packing, era-ingest → L0-L2
    era-index → L0-L2 + era-storage (for in-volume persistence)
L2: era-codec, era-volume → L0 + era-storage
L1: era-storage → era-common
L0: era-crypto → era-common (foundation, no internal deps)
```

Dependencies flow DOWN only. No circular refs. Enforced by architecture.

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Modify crypto | `crates/era-crypto/src/` | AEAD, KEM, HKDF, secure memory |
| Key lifecycle (MK→IK→VK) | `era-crypto/src/key_session.rs` | 662 lines, envelope encryption |
| Change volume format | `crates/era-volume/src/header.rs` | SuperHeader, RecipientSlot |
| Pipeline write path | `era-engine/src/writer.rs` | 2348 lines, main orchestration |
| Pipeline read path | `era-engine/src/reader.rs` | 1540 lines, extraction + verify |
| Block iteration | `era-engine/src/block_iter.rs` | 1174 lines, 4 iterator types |
| Archive repair | `era-engine/src/repair.rs` | RS-based shard recovery |
| Index dedup | `crates/era-index/` | Bloom + L1/L2 tiered pages |
| Chunking perf | `era-ingest/src/chunker*.rs` | FastCDC, ring buffer, zero-copy |
| CLI commands | `bins/era-cli/src/main.rs` | 6 subcommands (create/extract/list/info/verify/repair) |
| Protobuf schemas | `era-common/proto/` | Build-time codegen via build.rs |
| Fuzz targets | `fuzz/fuzz_targets/` | Footer, BlockHeader, SuperHeader |

## COMPLEXITY HOTSPOTS

| File | Lines | Why Complex |
|------|-------|-------------|
| `era-engine/src/writer.rs` | 2348 | 99 if-stmts, multi-auth modes, append vs create state machine |
| `era-engine/src/reader.rs` | 1540 | 23 match arms, multi-volume discovery, async state |
| `era-engine/src/block_iter.rs` | 1174 | 4 iterator impls, Virtual Striping (8192 length probes) |
| `era-engine/src/repair.rs` | 889 | Nested shard scanning, matrix distribution |
| `era-volume/src/volume_pool.rs` | 825 | Volume rotation state machine |
| `era-crypto/src/certificate.rs` | 816 | Hybrid KEM, PEM I/O, timestamp validation |

## CRYPTO ARCHITECTURE

3-layer envelope with per-block key derivation:
```
MK (OsRng 32B) → HKDF → IK (memory-only, never persisted)
                          IK wraps → VK (random 32B, stored encrypted in SuperHeader)
                                      VK → HKDF → BK (per-block, context-bound)
```

- **Password mode**: Argon2id → MK
- **Certificate mode**: X25519 → MK (current archive path); hybrid KEM for certificates remains deferred
- **Threshold mode**: Shamir split MK into N shares, T required to reconstruct
- **Key rotation**: Re-wrap VK with new IK. Data untouched.
- **Context binding**: All AEAD binds `archive_id ‖ epoch_id ‖ block_index` as AAD

## CONVENTIONS

- **Error handling**: `era_common::EraError` everywhere, `?` propagation, no `unwrap()` in runtime
- **Async**: Tokio runtime, `spawn_blocking` for CPU-heavy (compression, crypto)
- **Serialization**: Protobuf for wire format, rkyv for zero-copy in-memory, `TryFrom` for untrusted input
- **Memory**: `SecureBuffer<N>` with mlock + Zeroize on Drop for all key material
- **Debug**: Sensitive types print `[REDACTED]`
- **Traits**: StorageBackend (L1), Compressor (L2), AuthProvider (L4), BlockIterator (L4)
- **Re-exports**: Each crate's `lib.rs` uses `pub use` facade pattern

## ANTI-PATTERNS (THIS PROJECT)

- NEVER use `thread_rng` — always `OsRng`
- NEVER log key material at ANY level
- NEVER use `unwrap()` in runtime paths — `Result<T, EraError>` + `?`
- NEVER allow circular dependencies between crates
- NEVER skip AEAD context binding (archive_id ‖ epoch_id ‖ block_index)
- NEVER persist IK to disk — derive from MK at runtime
- NEVER use `as any` / type suppression
- NEVER block the async runtime — use `spawn_blocking`

## COMMANDS

```bash
# Full CI check (run before committing)
cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --workspace

# Specific crate
cargo test -p era-engine
cargo test -p era-engine --test fourth_audit  # specific audit suite

# CLI
cargo run --manifest-path bins/era-cli/Cargo.toml -- --help

# Benchmarks
cargo bench                    # all
cargo bench -p era-crypto      # per-crate

# Fuzz (requires nightly)
cd fuzz && cargo +nightly fuzz run fuzz_footer_parse -- -max_total_time=60
```

## NOTES

- March 2026 workspace verification: 2049 passed, 0 failed, 18 ignored; 279+ adversarial security audit tests across historical and V5 suites, plus 30 index persistence audit tests
- 3 fuzz targets: 65M+ combined runs, 0 crashes
- 12 Criterion benchmark files across 7 crates
- Edition 2021, resolver v2, MSRV 1.92+
- Release profile: LTO + codegen-units=1 + opt-level=3
- 3 unsafe blocks (mlock/munlock FFI, ring buffer ptr::copy, rkyv resolve) — all justified
- Known zeroization gaps tracked in audit tests (M1-M3, RV3-RV4) — non-exploitable
