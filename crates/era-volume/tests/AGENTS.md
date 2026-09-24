# era-volume tests

Large integration surface for format parsing, footer/header recovery, atomicity, and DoS hardening.

## Groups

16 test files. Audit numbering is workspace-global; v28 was skipped, so there is no `adversarial_audit_v28.rs` here.

- Security/regression audits (7): `adversarial_audit_v2.rs` 288, `adversarial_audit_v26.rs` 916, `adversarial_audit_v27.rs` 782, `adversarial_audit_v29.rs` 456, `adversarial_audit_v30.rs` 682, `competitor_vulnerability_audit.rs` 584, `coverage_gap_audit.rs` 744
- Parser and recovery edge cases (3): `header_adversarial.rs` 338, `floating_footer.rs` 81, `resilient_footer_reconstruction.rs` 170
- Write/finalization guarantees (3): `atomicity_failure_full.rs` 183, `atomicity_stress.rs` 111, `property_tests.rs` 512
- Stress, traffic-shape, and perf checks (3): `security_dos_tests.rs` 333, `traffic_analysis.rs` 183, `performance.rs` 85

`property_tests.rs` is the only proptest suite in the workspace; its `property_tests.proptest-regressions` file is checked in with 2 saved seeds.

## Run

```bash
cargo test -p era-volume
cargo test -p era-volume --test adversarial_audit_v30
cargo test -p era-volume --test property_tests
```

## Notes

- Keep format-level explanation in `../src/AGENTS.md`; this file only owns the test surface.
- If you add a new audit wave, extend the grouped bullet instead of enumerating every file in the crate root.
