# Crypto Tests

Security audit surface for envelope, context binding, and key generation.

## FILES

| File | Lines | Focus |
|------|-------|-------|
| `envelope_adversarial.rs` | 570 | Wrap/unwrap tampering, wrong-MK rejection, debug redaction. Tampered ciphertext must fail unwrap; Debug must never contain raw key bytes. |
| `context_binding_security.rs` | 397 | AEAD AAD binding: archive/epoch/block-type/volume/block identity. Fast KDF params are test-only, DO NOT use in production. |
| `adversarial_audit_v9.rs` | 498 | End-to-end adversarial scenarios: splicing, corruption. |
| `adversarial_audit_v2.rs` | 180 | Baseline adversarial coverage. |
| `generate_valid_keys.rs` | 60 | Fixture key generator. |

## RUN

```bash
cargo test -p era-crypto
cargo test -p era-crypto --test envelope_adversarial
cargo test -p era-crypto --test context_binding_security
```

## Notes

- Cross-crate fixtures come from `crates/era-packing/src/test_helpers.rs`
- Source-file ownership lives in `../src/AGENTS.md`
