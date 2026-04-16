# Storage Source

Async storage backend abstraction. L1.

## FILES

| File | Purpose |
|------|---------|
| `lib.rs` | Re-exports: StorageBackend, LocalStorageBackend, MemoryStorageBackend |
| `traits.rs` | `StorageBackend` trait (async read/write/pflush) |
| `local.rs` | Filesystem backend |
| `memory.rs` | In-memory backend (used in tests) |
| `config.rs` | Storage backend configuration |

## CONVENTIONS

- All I/O is async; blocking I/O in storage paths violates the async contract
- New backends (S3, MinIO) implement `StorageBackend` trait

## TEST

```bash
cargo test -p era-storage
```

See `crates/era-storage/AGENTS.md` for crate boundary docs.
