# era-common crate

Shared errors, config types, protobuf codegen, and reusable IDs/metadata. See root `AGENTS.md` for workspace-wide rules and `src/AGENTS.md` for source-level detail.

## SURFACES
- `src/AGENTS.md` — module map for `error.rs`, `config.rs`, `serde.rs`, and `types/`
- `proto/` — `era_common.proto` and `test_evolution.proto`
- `build.rs` — prost codegen entrypoint
- No dedicated `tests/`, `benches/`, or `examples/` surface right now

## WHEN CHANGING
- `EraError` or shared config changes ripple into every crate.
- Protobuf schema updates require matching `From` / `TryFrom` conversions and compatibility checks in readers and writers.
- Serialization bounds belong here; format-specific validation belongs in `era-volume`.

## VALIDATION
```bash
cargo test -p era-common
```
