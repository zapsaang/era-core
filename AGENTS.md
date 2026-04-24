# ERA-CORE KNOWLEDGE BASE

**Generated:** 2026-04-17
**Commit:** 8e59232
**Branch:** feat_fly

Post-quantum encrypted archival storage engine in Rust. 3-layer envelope encryption, FastCDC chunking, Reed-Solomon erasure coding, Shamir's secret sharing.

## STRUCTURE

```
era-core/
├── bins/era-cli/          CLI (era create/extract/list/info/verify/repair/repack/keygen)
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
| Pipeline write path | `era-engine/src/writer.rs` (2554 lines) |
| Pipeline read path | `era-engine/src/reader.rs` (2313 lines) |
| Erasure scan / prefix reconciliation | `era-engine/src/erasure_scan.rs` |
| Dedup index | `era-index/src/{builder,reader,store}.rs` |
| Chunking | `era-ingest/src/chunker*.rs` |
| Packing | `era-packing/src/builder.rs` |
| Compression | `era-codec/src/compression.rs` |
| Erasure coding | `era-codec/src/erasure.rs` |
| Auth (password/cert/threshold) | `era-engine/src/auth.rs` |
| Hybrid KEM / certificates | `era-crypto/src/{hybrid_certificate,hybrid_kem,pem_support}.rs` |

## LARGE FILES (>1000 lines)

| File | Lines | Purpose |
|------|-------|---------|
| `era-engine/src/writer.rs` | 2554 | Archive creation pipeline |
| `era-engine/src/reader.rs` | 2313 | Archive extraction pipeline |
| `era-engine/src/block_iter.rs` | 1699 | 4 iterator types, virtual striping |
| `era-engine/src/repair.rs` | 1451 | RS-based shard recovery |
| `era-index/src/reader.rs` | 1269 | Bloom + L1/L2 index lookup |
| `era-volume/src/header.rs` | 1225 | SuperHeader, RecipientSlot, KeyWrap |
| `era-volume/src/volume_pool.rs` | 1199 | Volume rotation, matrix distribution |
| `era-engine/src/checkpoint.rs` | 927 | WAL-based binary checkpoints (v2.2+) |

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
# Full CI check (matches ci.yml exactly)
cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --release --workspace

# Per-crate
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
- `bins/era-cli/AGENTS.md` — CLI layer
- `bins/era-cli/tests/AGENTS.md` — CLI integration tests

## NOTES

- Fuzz workspace (`fuzz/`) documented but NOT present in repo
- Current archive unlock uses X25519 even though hybrid KEM (X25519+Kyber-768) exists in codebase
- Volume format: v8.1, magic `ERA\x08\x01`
- Release profile: LTO, codegen-units=1, opt-level=3

# Project Review Rules

This repository uses structured multi-agent review for non-trivial code changes.

## Review Objectives

When reviewing a change, prefer evidence over advice and concrete risk over generic best practice language.

Default review dimensions:

- spec compliance
- code quality
- security
- performance
- concurrency & consistency

For substantial changes, run these dimensions independently and then perform an arbiter pass that deduplicates and validates findings.

## Output Rules

Every review finding must:

- be anchored to concrete `file:line` locations whenever possible
- explain why the issue matters
- distinguish fact from inference
- include enough evidence to be auditable by a human reviewer
- avoid style-only nitpicks unless they materially affect correctness, maintainability, security, latency, throughput, or consistency

## Severity

Use:

- critical
- high
- medium
- low

Use `informational` only for notable but non-actionable observations.

## Performance Claims

Performance claims must be classified as one of:

- provable regression
- likely regression
- benchmark-needed

Do not present speculative performance concerns as confirmed facts.

## Security Claims

Security findings must include:

- threat scenario
- trust boundary involved
- exploit preconditions
- likely impact

Do not report vague “possible vulnerability” statements without code-based evidence.

## Concurrency & Consistency Claims

Concurrency findings must state which category applies:

- race condition
- atomicity violation
- ordering issue
- idempotency gap
- retry amplification
- deadlock / lock contention
- stale read / lost update
- distributed inconsistency

## Spec Compliance Claims

Spec findings should check against, when available:

- PR description
- issue / ticket
- API contract
- schema contract
- tests
- migration notes
- docs

If the spec source is missing, explicitly state that confidence is limited.

## Arbiter Rules

The arbiter must:

- merge duplicates
- reject weak or repetitive claims
- separate confirmed findings from plausible-but-unproven findings
- preserve the original review dimension labels
- sort confirmed findings by severity, then confidence

## Change Safety

When a change touches any of the following, raise review rigor:

- authentication / authorization
- payment or billing logic
- data migration
- cache invalidation
- locking / shared mutable state
- retries / queues / async workflows
- distributed writes
- public API contracts
- feature flags / rollout logic / rollback paths

## Practical Bias

Prefer catching:

- correctness regressions
- silent behavior drift
- compatibility breaks
- consistency violations
- operational risk

over cosmetic concerns.