# era-packing crate

MacroBlock packing, session builders, unpackers, and resilient AEAD recovery heuristics. See root `AGENTS.md` for workspace rules and `src/AGENTS.md` for algorithm detail.

## SURFACES
- `src/AGENTS.md` — packing internals, stripe buffering, unpackers, and in-source perf tests
- `tests/` — vulnerability and resilience coverage
- `benches/packing_bench.rs` — packing throughput / utilization checks

## WHEN CHANGING
- Packing thresholds and chunk ordering affect `era-engine` write/read paths and index offsets.
- `resilient_aead` heuristics are recovery policy, not generic crypto behavior; keep them aligned with `era-volume` shard validation.
- Session builder changes must stay compatible with `KeySession` block-key derivation and engine checkpoint/resume logic.

## VALIDATION
```bash
cargo test -p era-packing
cargo bench -p era-packing
```
