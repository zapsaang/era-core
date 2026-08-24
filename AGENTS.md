# ERA-CORE KNOWLEDGE BASE

**Generated:** 2026-08-23
**Commit:** 02a167b
**Branch:** feat_fly

Post-quantum encrypted archival storage engine in Rust. 3-layer envelope encryption, FastCDC chunking, Reed-Solomon erasure coding, Shamir's secret sharing.

## STRUCTURE

```
era-core/
├── bins/era-cli/        CLI (create/extract/list/info/verify/repair/repack/keygen)
├── crates/
│   ├── era-engine/      L4: archive orchestration, async pipeline
│   ├── era-packing/     L3: k-Bounded Best-Fit MacroBlock packing
│   ├── era-ingest/      L3: FastCDC chunking (16KB-64KB-256KB), DirectoryScanner
│   ├── era-index/       L3: V2.1 embedded dedup (Bloom + L1/L2)
│   ├── era-codec/       L2: Zstd/LZ4 compression, Reed-Solomon (4+2)
│   ├── era-volume/      L2: volume format v8.2, SuperHeader (4096B), Footer (128B)
│   ├── era-storage/     L1: StorageBackend trait (Local/Memory)
│   ├── era-crypto/      L0: XChaCha20-Poly1305, Kyber-768, HKDF, Argon2id
│   └── era-common/      L0: EraError, Result, protobuf, config types
└── doc_gen/             Security audit reports and design iterations
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

| Symbol | File | Callers | Role |
|--------|------|--------:|------|
| `ArchiveWriter` | `crates/era-engine/src/writer.rs` | 3 | create pipeline orchestrator |
| `ArchiveReader` | `crates/era-engine/src/reader.rs` | 4 | extract pipeline orchestrator |
| `KeySession` | `crates/era-crypto/src/key_session.rs` | 35 | MK/IK/VK envelope state |
| `SuperHeader` | `crates/era-volume/src/header.rs` | 42 | on-disk header type (v8.2) |

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
| Disk format change | `crates/era-volume/src/header.rs`, `crates/era-volume/src/footer.rs` |
| Crypto primitives | `crates/era-crypto/src/aead.rs`, `crates/era-crypto/src/kdf.rs`, `crates/era-crypto/src/key_session.rs` |
| Pipeline write path | `crates/era-engine/src/writer.rs` |
| Pipeline read path | `crates/era-engine/src/reader.rs` |
| Erasure scan / prefix reconciliation | `crates/era-engine/src/erasure_scan.rs` |
| Dedup index | `crates/era-index/src/builder.rs`, `crates/era-index/src/reader.rs`, `crates/era-index/src/store.rs` |
| Chunking | `crates/era-ingest/src/chunker.rs` (see `crates/era-ingest/src/AGENTS.md`) |
| Packing | `crates/era-packing/src/builder.rs` |
| Compression | `crates/era-codec/src/compression.rs` |
| Erasure coding | `crates/era-codec/src/erasure.rs` |
| Auth (password/cert/threshold) | `crates/era-engine/src/auth.rs` |
| Hybrid KEM / certificates | `crates/era-crypto/src/hybrid_certificate.rs`, `crates/era-crypto/src/hybrid_kem.rs`, `crates/era-crypto/src/pem_support.rs` |
| Archive manifest (v8.2) | `crates/era-common/src/types/manifest.rs` |
| Typed blocks / BlockHeader | `crates/era-common/src/types/typed_block.rs`, `crates/era-common/src/types/block.rs` |
| Sequence / finalize tracking | `crates/era-engine/src/sequence.rs` |
| Cryptographic commitments | `crates/era-crypto/src/commitment.rs` |
| CLI commands | `bins/era-cli/src/commands.rs` |

## COMMANDS

```bash
# Full CI check (matches ci.yml exactly)
cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --release --workspace

# Per-crate / suite
cargo test -p era-engine
cargo test -p era-engine --test fourth_audit
cargo bench -p era-crypto

# CLI
cargo run --manifest-path bins/era-cli/Cargo.toml -- --help
cargo test --release -p era-cli

# Fuzz (nightly, separate workspace — NOT present in repo)
cd fuzz && cargo +nightly fuzz run fuzz_footer_parse -- -max_total_time=60
```

## HIERARCHY

- `crates/AGENTS.md` — crate map + dependency graph
- `crates/*/AGENTS.md` — crate boundary docs
- `crates/*/src/AGENTS.md` — source-tree maps + file inventory
- `crates/*/tests/AGENTS.md` — test surface docs
- `bins/era-cli/AGENTS.md` and `bins/era-cli/tests/AGENTS.md` — CLI layer

## NOTES

- Fuzz workspace (`fuzz/`) documented but NOT present in repo.
- Current archive unlock uses X25519 although hybrid KEM (X25519+Kyber-768) exists.
- Volume format: v8.2, magic `ERA\x08\x02`.

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