# era-volume tests

Large integration surface for format parsing, footer/header recovery, atomicity, and DoS hardening.

## GROUPS
- `adversarial_audit_v2.rs`, `adversarial_audit_v26.rs`, `adversarial_audit_v27.rs`, `adversarial_audit_v29.rs`, `adversarial_audit_v30.rs`, `competitor_vulnerability_audit.rs`, and `coverage_gap_audit.rs` — security/regression audits
- `header_adversarial.rs`, `floating_footer.rs`, and `resilient_footer_reconstruction.rs` — parser and recovery edge cases
- `atomicity_failure_full.rs`, `atomicity_stress.rs`, and `property_tests.rs` — write/finalization guarantees (`property_tests.proptest-regressions` belongs with this group)
- `security_dos_tests.rs`, `traffic_analysis.rs`, and `performance.rs` — stress, traffic-shape, and perf checks

## RUN
```bash
cargo test -p era-volume
cargo test -p era-volume --test adversarial_audit_v30
cargo test -p era-volume --test property_tests
```

## NOTES
- Keep format-level explanation in `../src/AGENTS.md`; this file only owns the test surface.
- If you add a new audit wave, extend the grouped bullet instead of enumerating every file in the crate root.
