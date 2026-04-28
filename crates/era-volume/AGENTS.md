# era-volume crate

On-disk format v8.2, multi-volume coordination, footer/header validation, and volume-pool rotation. L2.

## SURFACES
- `src/AGENTS.md` — header/footer/layout, `VolumePool`, distribution helpers, and constants
- `tests/AGENTS.md` — adversarial, atomicity, property, recovery, and performance suites
- No benches or examples in this crate

## WHEN CHANGING
- Header/footer changes are format-contract changes; route them through `era-engine` writer/reader, repair, and fuzz checks.
- `VolumePool` changes must preserve rotation, matrix distribution, and finalization semantics.
- Keep validation symmetric between parse and write paths; truncation or size-limit checks do not belong in only one direction.

## VALIDATION
```bash
cargo test -p era-volume
cargo test -p era-volume --test adversarial_audit_v30
cargo test -p era-volume --test property_tests
```

See root `AGENTS.md` for workspace-wide rules and anti-patterns.
