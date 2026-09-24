# Storage Source

Async storage backend abstraction. L1. Only dep: era-common.

## FILES

| File | LOC | Purpose |
|------|-----|---------|
| `lib.rs` | 16 | facade, re-exports |
| `traits.rs` | 87 | `StorageBackend`/`StorageReader`/`StorageWriter` async traits |
| `local.rs` | 306 | filesystem backend |
| `memory.rs` | 310 | in-memory backend (tests) |
| `config.rs` | 313 | backend config types |

## NOTES

- `src/cache/` exists but is an EMPTY placeholder directory — no code yet
- All I/O is async; blocking I/O in storage paths violates the contract
- New backends (S3, MinIO) implement the `StorageBackend` trait

## TEST

Single test: `tests/pwrite_test.rs` (77 LOC, write/read compliance).

```bash
cargo test -p era-storage
```

See `crates/era-storage/AGENTS.md` for crate boundary docs.
