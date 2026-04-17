# era-crypto crate

Cryptographic primitives, key lifecycle, secure memory, and certificate/KEM helpers. L0.

## SURFACES
- `src/AGENTS.md` — AEAD, KDF, `KeySession`, hybrid KEM, PEM support, secure memory, and timestamp internals
- `tests/AGENTS.md` — adversarial envelope, context-binding, and key-generation coverage
- `benches/crypto_bench.rs` — throughput for AEAD/KDF/KEM hot paths
- `examples/key_exchange_bench.rs` — standalone key exchange exercise

## WHEN CHANGING
- `KeySession`, wrap/unwrap, or domain-separation changes must be checked against `era-volume` header slots and `era-engine` auth flows.
- PEM / certificate changes must preserve the current archive compatibility path; current archive unlock still routes through X25519-based certificate handling.
- Secure-memory or zeroization changes are high-risk; audit error paths as carefully as success paths.

## VALIDATION
```bash
cargo test -p era-crypto
cargo test -p era-crypto --test envelope_adversarial
cargo test -p era-crypto --test context_binding_security
cargo bench -p era-crypto
```

See root `AGENTS.md` for workspace-wide security rules and anti-patterns.
