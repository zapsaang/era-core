# era-index crate

Embedded dedup index staging, page layout, persistence, and cold recovery. See root `AGENTS.md` for workspace rules, `src/AGENTS.md` for implementation detail, and `tests/AGENTS.md` for the audit surface.

## SURFACES
- `src/AGENTS.md` — `ChunkIndex`, builder/reader/store internals, Bloom + L1/L2 layout
- `tests/AGENTS.md` — adversarial waves, Redb compliance, persistence audit, recovery/spec tests
- `benches/index_bench.rs` — lookup and persistence baseline measurements

## WHEN CHANGING
- Page layout, Bloom validation, or `ChunkIndex` state-machine changes affect `era-engine` finalization and read-path recovery.
- Keep index-specific failures in the index error domain; generic format errors belong higher or lower in the stack.
- Cold-recovery behavior is part of the crate contract, not an optional optimization.

## VALIDATION
```bash
cargo test -p era-index
cargo test -p era-index --test index_persistence_audit
cargo bench -p era-index
```
