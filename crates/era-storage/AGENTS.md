# era-storage crate

Async storage backend abstraction. L1.

## SURFACES
- `src/AGENTS.md` — `StorageBackend` trait, `LocalStorageBackend`, `MemoryStorageBackend` internals
- `tests/pwrite_test.rs` — storage backend write/read compliance

## WHEN CHANGING
- New storage backends (S3, MinIO) should implement the `StorageBackend` trait.
- Async I/O is mandatory; blocking I/O in storage paths violates the async contract.

## VALIDATION
```bash
cargo test -p era-storage
```

See root `AGENTS.md` for workspace-wide rules and anti-patterns.