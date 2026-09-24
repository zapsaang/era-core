# ERA-CORE KNOWLEDGE BASE

**Generated:** 2026-09-23
**Commit:** 5bf28de
**Branch:** feat_fly

Post-quantum encrypted archival storage engine in Rust. 3-layer envelope encryption, FastCDC chunking, Reed-Solomon erasure coding, Shamir's secret sharing. ~126k LOC, 234 .rs files, 10 workspace members.

## STRUCTURE

```
era-core/
├── bins/era-cli/        CLI (create/extract/list/info/verify/repair/repack/keygen) + tests/common harness
├── crates/
│   ├── era-engine/      L4: archive orchestration, async pipeline (writer.rs 3649 LOC is the god object)
│   ├── era-packing/     L3: k-Bounded Best-Fit MacroBlock packing
│   ├── era-ingest/      L3: FastCDC chunking (16KB-64KB-256KB), DirectoryScanner
│   ├── era-index/       L3: V2.1 embedded dedup (Bloom + L1/L2, redb ACID)
│   ├── era-codec/       L2: Zstd/LZ4 compression, Reed-Solomon (4+2)
│   ├── era-volume/      L2: volume format v8.2, SuperHeader (4096B), Footer (128B)
│   ├── era-storage/     L1: StorageBackend trait (Local/Memory)
│   ├── era-crypto/      L0: XChaCha20-Poly1305, ML-KEM-768, HKDF, Argon2id, SecureBuffer
│   └── era-common/      L0: EraError, Result, protobuf (proto/), config + types/
├── doc_gen/             Security audit reports + design iterations (ARCHIVAL, frozen 2026-04)
└── bench_data/          PEM fixtures for crypto benches
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

## CODE MAP

Refs = production-source reference count (tests/benches excluded).

| Symbol | File | Refs | Role |
|--------|------|-----:|------|
| `EraError` | `crates/era-common/src/error.rs` | 860 | workspace error enum (~49 variants), most cross-cut type |
| `ChunkHash` | `crates/era-common/src/types/ids.rs` | 245 | BLAKE3 content address |
| `KeySession` | `crates/era-crypto/src/key_session.rs` | 96 | MK/IK/VK envelope state |
| `SuperHeader` | `crates/era-volume/src/header.rs` | 81 | on-disk header v8.2, dynamic `recipients: Vec<RecipientSlot>` |
| `VolumeReader` | `crates/era-volume/src/reader.rs` | 69 | async volume read, MAX_SHARD_SIZE validation |
| `Catalog` | `crates/era-ingest/src/entry.rs` | 65 | file inventory + chunk refs |
| `ArchiveManifest` | `crates/era-common/src/types/manifest.rs` | 55 | v8.2 manifest: epochs, committed horizons |
| `ArchiveWriter` | `crates/era-engine/src/writer.rs` | 50 | create pipeline orchestrator |
| `VolumePool` | `crates/era-volume/src/volume_pool.rs` | 40 | volume rotation + matrix shard distribution |
| `ArchiveReader` | `crates/era-engine/src/reader.rs` | 31 | extract pipeline orchestrator |
| `StorageBackend` | `crates/era-storage/src/traits.rs` | 29 | async I/O abstraction (Local/Memory; S3 planned) |
| `IndexReader` | `crates/era-index/src/reader.rs` | 27 | Bloom + L1/L2 lookup + cold recovery |

## ANTI-PATTERNS (enforced by audit suites + clippy `-D warnings`)

| Rule | Alternative |
|------|-------------|
| NEVER `thread_rng` | `OsRng` only (audited: second_audit.rs) |
| NEVER log key material | Zero logging; Debug must redact (envelope_adversarial.rs) |
| NEVER `unwrap()`/`expect()`/`panic!` in runtime | `Result<T, EraError>` + `?` (src/ dirs are clean) |
| NEVER circular deps between crates | Strict downward only (see crates/AGENTS.md graph) |
| NEVER skip AEAD context binding | AAD = `archive_id ‖ epoch_id ‖ block_type ‖ volume_index ‖ block_id` |
| NEVER reuse `nonce_context` across archives | MUST be unique per archive — reuse breaks XChaCha20-Poly1305 (aead.rs) |
| NEVER persist IK to disk | Derive from MK at runtime; key material in `SecureBuffer<N>` + zeroize |
| NEVER silently drop failed shards | Report `EraError::ErasureCoding`; validate `data+parity ≤ 256` (era-codec) |
| NEVER validate on one side only | Symmetric validation on read AND write paths (era-volume) |
| NEVER block async runtime | `spawn_blocking` for CPU-heavy work |
| NEVER `as any` type suppression | Proper type conversions |

## WHERE TO LOOK

| Need | Go to |
|------|-------|
| Disk format change | `crates/era-volume/src/header.rs`, `crates/era-volume/src/footer.rs` |
| Crypto primitives | `crates/era-crypto/src/aead.rs`, `aead_context.rs`, `kdf.rs`, `key_session.rs` |
| Pipeline write path | `crates/era-engine/src/writer.rs` + stage files (`write_pipeline.rs`, `packing_stage.rs`, `encryption_context.rs`, `erasure_stage.rs`, `volume_stage.rs`, `index_stage.rs`) |
| Pipeline read path | `crates/era-engine/src/reader.rs`, `crates/era-engine/src/block_iter.rs` (5 iterator variants) |
| Repair / recovery / resume | `crates/era-engine/src/repair.rs`, `recovery.rs`, `checkpoint.rs` |
| Erasure scan / prefix reconciliation | `crates/era-engine/src/erasure_scan.rs` |
| Dedup index | `crates/era-index/src/builder.rs`, `reader.rs`, `store.rs` |
| Chunking | `crates/era-ingest/src/chunker.rs` (see `crates/era-ingest/src/AGENTS.md`) |
| Packing | `crates/era-packing/src/builder.rs`, `session_builder.rs`, `staging_pool.rs` |
| Compression | `crates/era-codec/src/compression.rs` |
| Erasure coding | `crates/era-codec/src/erasure.rs` |
| Auth (password/cert/threshold) | `crates/era-engine/src/auth.rs` |
| Hybrid KEM / certificates | `crates/era-crypto/src/hybrid_certificate.rs`, `hybrid_kem.rs`, `pem_support.rs` |
| Archive manifest (v8.2) | `crates/era-common/src/types/manifest.rs` |
| Typed blocks / BlockHeader | `crates/era-common/src/types/typed_block.rs`, `types/block.rs` |
| Protobuf schemas | `crates/era-common/proto/era_common.proto` (via `build.rs` prost codegen) |
| Sequence / finalize tracking | `crates/era-engine/src/sequence.rs` |
| Cryptographic commitments | `crates/era-crypto/src/commitment.rs` |
| CLI commands | `bins/era-cli/src/commands.rs` (see `bins/era-cli/src/AGENTS.md`) |
| CLI test harness | `bins/era-cli/tests/common/mod.rs` (`era_cmd()`, corruption helpers, keypair gens) |

## COMMANDS

```bash
# Full CI check (matches ci.yml exactly — lint + BOTH test jobs)
cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --release -p era-cli && cargo test --release --workspace

# Per-crate / suite
cargo test -p era-engine
cargo test -p era-engine --test fourth_audit
cargo bench -p era-crypto

# CLI
cargo run --manifest-path bins/era-cli/Cargo.toml -- --help
cargo test --release -p era-cli

# Fuzz (nightly, separate workspace — NOT present in repo; fuzz.yml is workflow_dispatch only)
cd fuzz && cargo +nightly fuzz run fuzz_footer_parse -- -max_total_time=60
```

## HIERARCHY

- `crates/AGENTS.md` — crate map + dependency graph
- `crates/*/AGENTS.md` — crate boundary docs
- `crates/*/src/AGENTS.md` — source-tree maps + file inventory
- `crates/*/tests/AGENTS.md` — test surface docs (crypto/engine/index/ingest/volume only; codec/packing/storage/common test dirs too small)
- `bins/era-cli/{,src/,tests/}AGENTS.md` — CLI layer

## NOTES

- Fuzz workspace (`fuzz/`) documented but NOT present in repo (`exclude = ["fuzz"]` in root Cargo.toml).
- Hybrid KEM (X25519 + ML-KEM-768) is the default `keygen` output; legacy X25519 via `-t x25519`.
- Volume format: v8.2, magic `ERA\x08\x02`.
- Audit numbering (`adversarial_audit_vN`) is workspace-global lineage v1–v30, not per-crate; each crate owns the waves that touched it. "6 audit suites" = era-engine's competitor/second/third/fourth + adversarial v5 + v2 baseline.
- `crates/era-storage/src/cache/` is an EMPTY placeholder dir.
- `crates/era-packing/src/{integration_performance_tests.rs,test_helpers.rs}` are test code living in src/ (cfg(test)-gated); `test_helpers.rs` is the cross-crate fixture source.
- `crates/era-engine/src/checkpoint.rs`: `commit()`/`sync()` DEPRECATED (v2.2+) → use `commit_to_volume()`.
- Only `unsafe` in workspace src: `crates/era-crypto/src/secure_memory.rs` (mlock/prctl).
- No `[workspace.lints]`, no clippy.toml/rustfmt.toml/deny.toml — enforcement is CI's `-D warnings` only. `rust-toolchain.toml` pins 1.98.1 but CI uses `stable` (drift risk).
- `doc_gen/` is archival (content frozen 2026-04-28).

## Project Review Rules

This repository uses structured multi-agent review for non-trivial code changes. Prefer evidence over advice and concrete risk over generic best practice.
### Review Objectives
Default dimensions, run independently then arbited: spec compliance, code quality, security, performance, concurrency & consistency.
### Output Rules
Each finding must: anchor to concrete `file:line`; explain why it matters; distinguish fact from inference; carry auditable evidence; skip style-only nits unless they hit correctness, maintainability, security, latency, throughput, or consistency.
### Severity
Scale: critical, high, medium, low. `informational` for non-actionable observations only.
### Performance Claims
Classify every perf claim as one of: provable regression, likely regression, benchmark-needed. No speculative concerns stated as facts.
### Security Claims
Each must include: threat scenario, trust boundary, exploit preconditions, likely impact. No vague "possible vulnerability" claims without code evidence.
### Concurrency & Consistency Claims
State the category: race condition, atomicity violation, ordering issue, idempotency gap, retry amplification, deadlock/lock contention, stale read/lost update, distributed inconsistency.
### Spec Compliance Claims
Check against, when available: PR description, issue/ticket, API contract, schema contract, tests, migration notes, docs. If spec source is missing, state that confidence is limited.
### Arbiter Rules
Must: merge duplicates, reject weak or repetitive claims, separate confirmed from plausible-but-unproven findings, preserve original review dimension labels, sort confirmed findings by severity then confidence.
### Change Safety
Raise review rigor when touching: authentication/authorization, payment or billing, data migration, cache invalidation, locking/shared mutable state, retries/queues/async workflows, distributed writes, public API contracts, feature flags/rollout/rollback paths.
### Practical Bias
Prefer catching: correctness regressions, silent behavior drift, compatibility breaks, consistency violations, operational risk — over cosmetic concerns.
