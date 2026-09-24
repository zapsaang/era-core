# era-storage crate

Async storage backend abstraction. L1.

## SURFACES
- `src/AGENTS.md` — `StorageBackend` trait, `LocalStorageBackend`, `MemoryStorageBackend` internals
- `tests/pwrite_test.rs` — storage backend write/read compliance

## STRUCTURE

```
era-storage/src/
├── lib.rs     # Re-exports: StorageBackend, LocalStorageBackend, MemoryStorageBackend
├── traits.rs  # StorageBackend trait (async read/write/pflush)
├── local.rs   # Filesystem backend (306 LOC)
├── memory.rs  # In-memory backend (310 LOC)
├── config.rs  # Storage backend config (313 LOC)
└── cache/     # EMPTY placeholder directory, no code yet
```

## WHEN CHANGING
- New storage backends (S3, MinIO) should implement the `StorageBackend` trait (`traits.rs`: `StorageBackend`/`StorageReader`/`StorageWriter` async traits).
- Async I/O is mandatory; blocking I/O in storage paths violates the async contract.
- `src/cache/` is an empty placeholder; treat any cache work as greenfield.

## VALIDATION
```bash
cargo test -p era-storage
```

See root `AGENTS.md` for workspace-wide rules and anti-patterns.