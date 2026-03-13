# era-storage crate

Async storage abstraction for local and in-memory backends. See root `AGENTS.md` for workspace rules and `src/AGENTS.md` for trait/module detail.

## SURFACES
- `src/AGENTS.md` — `StorageBackend`, `StorageReader`, `StorageWriter`, and backend implementations
- `tests/pwrite_test.rs` — integration coverage for write semantics
- No benches or examples today

## WHEN CHANGING
- Trait signature changes ripple into `era-volume` and `era-engine`.
- Local backend semantics must stay async-friendly; blocking filesystem behavior belongs behind Tokio or backend boundaries.
- New backends should preserve range-read, append, flush, and metadata expectations before higher layers depend on them.

## VALIDATION
```bash
cargo test -p era-storage
```
