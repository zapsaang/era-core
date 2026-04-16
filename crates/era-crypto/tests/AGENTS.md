# Crypto Tests

Security audit surface for envelope, context binding, and key generation.

## FILES

| File | Focus |
|------|-------|
| `envelope_adversarial.rs` | Wrap/unwrap tampering, wrong-MK rejection, debug redaction |
| `context_binding_security.rs` | AEAD AAD binding: archive/epoch/volume/block identity |
| `generate_valid_keys.rs` | Key generation invariants |
| `adversarial_audit_v2.rs` | Baseline adversarial coverage |
| `adversarial_audit_v9.rs` | End-to-end adversarial scenarios |

## RUN

```bash
cargo test -p era-crypto
cargo test -p era-crypto --test envelope_adversarial
cargo test -p era-crypto --test context_binding_security
```

## Notes

- `test_helpers.rs` lives in `era-packing/src/` and provides cross-crate fixtures
- Source-file ownership lives in `../src/AGENTS.md`
