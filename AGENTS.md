# PROJECT KNOWLEDGE BASE

**Generated:** 2026-03-12
**Commit:** cbe6ea3
**Branch:** feat_fly

Post-quantum encrypted archival storage engine in Rust. Keep this file as the root index; push crate, source, test, and fuzz detail downward.

## HIERARCHY

- `crates/AGENTS.md` — crate map, dependency graph, cross-crate routing
- `crates/*/AGENTS.md` — crate boundary cards for `src/`, `tests/`, `benches/`, `examples/`, `proto/`, `build.rs`
- `crates/*/src/AGENTS.md` — source-tree maps and crate-internal invariants
- `crates/era-engine/tests/AGENTS.md`, `crates/era-index/tests/AGENTS.md`, `crates/era-volume/tests/AGENTS.md` — large test surfaces only
- `bins/era-cli/AGENTS.md` — CLI-only argument parsing and UX layer
- `fuzz/AGENTS.md` — separate nightly fuzz workspace

## ANTI-PATTERNS (CANONICAL)

- NEVER use `thread_rng` — always `OsRng`
- NEVER log key material at ANY level
- NEVER use `unwrap()` in runtime paths — `Result<T, EraError>` + `?`
- NEVER allow circular dependencies between crates
- NEVER skip AEAD context binding (`archive_id ‖ epoch_id ‖ block_index`)
- NEVER persist IK to disk — derive from MK at runtime
- NEVER use `as any` / type suppression
- NEVER block the async runtime — use `spawn_blocking`

## COMMANDS

```bash
# Full CI check
cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --workspace

# Focused checks
cargo test -p era-engine
cargo test -p era-engine --test fourth_audit
cargo run --manifest-path bins/era-cli/Cargo.toml -- --help
cargo bench

# Fuzz (nightly, separate workspace)
cd fuzz && cargo +nightly fuzz run fuzz_footer_parse -- -max_total_time=60
```

## NOTES

- Workspace shape: 8 library crates, 1 CLI binary, separate `fuzz/` workspace
- Dependency flow is downward only; `crates/AGENTS.md` is the authoritative crate map
- Current archive unlock path remains X25519-based even though hybrid KEM support exists in the codebase
- March 2026 verification: 2049 passed, 0 failed, 18 ignored
- 5 fuzz targets, nightly-only
