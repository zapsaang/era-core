# Storage Source

Async storage backend abstractions. L1 — sits between foundation (L0) and transformation (L2).

## FILES

| File | Purpose |
|------|---------|
| `lib.rs` | Re-exports |
| `traits.rs` | `StorageBackend`, `StorageReader`, `StorageWriter` traits |
| `local.rs` | Local filesystem backend (async file I/O) |
| `memory.rs` | In-memory backend (for testing) |
| `config.rs` | Storage configuration |

## TRAITS

- `StorageBackend`: Core trait — all backends implement this
- `StorageReader`: Async read (seek + read ranges)
- `StorageWriter`: Async write (append + flush)
- All traits use `async-trait` for async fn in traits

## ADDING A NEW BACKEND

1. Implement `StorageBackend` + `StorageReader` + `StorageWriter`
2. No changes needed in upper layers — trait-based dispatch
3. Future: S3/MinIO backend planned
