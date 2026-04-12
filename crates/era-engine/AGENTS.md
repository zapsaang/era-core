# era-engine crate

Top-level archive orchestration across ingest, packing, crypto, volume, and index layers. L4.

## SURFACES
- `src/AGENTS.md` — writer/reader/recovery/checkpoint internals and stage decomposition files
- `tests/AGENTS.md` — audit suites, resilience tests, integration flows, and repro harnesses
- `benches/` — end-to-end and small-file performance baselines

## WHEN CHANGING
- Treat this crate as the integration boundary: most changes here also need lower-layer validation.
- Writer/read-path changes must preserve checkpoint, resume, auth-mode, and block-iterator invariants.
- Stage decomposition files (`packing_stage`, `encryption_context`, `volume_stage`, etc.) exist to keep `writer.rs` manageable; do not collapse them back into another god object.

## VALIDATION
```bash
cargo test -p era-engine
cargo test -p era-engine --test fourth_audit
cargo bench -p era-engine
```

See root `AGENTS.md` for workspace-wide rules and anti-patterns.