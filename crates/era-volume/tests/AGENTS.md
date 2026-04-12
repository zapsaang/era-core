# era-volume tests

Large integration surface for format parsing, footer/header recovery, atomicity, and DoS hardening.

## Groups

- `adversarial_audit_v2.rs`, `adversarial_audit_v26.rs`, `adversarial_audit_v27.rs`, `adversarial_audit_v29.rs`, `adversarial_audit_v30.rs`, `competitor_vulnerability_audit.rs`, `coverage_gap_audit.rs` — security/regression audits
- `header_adversarial.rs`, `floating_footer.rs`, `resilient_footer_reconstruction.rs` — parser and recovery edge cases
- `atomicity_failure_full.rs`, `atomicity_stress.rs`, `property_tests.rs` — write/finalization guarantees (`property_tests.proptest-regressions` belongs with this group)
- `security_dos_tests.rs`, `traffic_analysis.rs`, `performance.rs` — stress, traffic-shape, and perf checks

## Run

```bash
cargo test -p era-volume
cargo test -p era-volume --test adversarial_audit_v30
cargo test -p era-volume --test property_tests
```

## Notes

- Keep format-level explanation in `../src/AGENTS.md`; this file only owns the test surface.
- If you add a new audit wave, extend the grouped bullet instead of enumerating every file in the crate root.
