# Crypto Source

Security primitives — all cryptographic operations and secure memory for the 3-layer envelope.

## FILES

| File | Lines | Purpose |
|------|-------|---------|
| `lib.rs` | — | Crate facade. Re-exports AEAD, KDF, certificate, secure-memory, timestamp, and key-session entrypoints. |
| `key_session.rs` | 662 | 3-layer envelope (MK→IK→VK→BK). HKDF derivation, VK wrap/unwrap, per-block key derivation, Shamir split/reconstruct. |
| `certificate.rs` | 816 | Hybrid KEM (X25519 + Kyber-768). PEM I/O, key encapsulation/decapsulation, timestamp validation. |
| `aead.rs` | — | XChaCha20-Poly1305 encrypt/decrypt. Fresh 24-byte nonce per operation via OsRng. |
| `aead_context.rs` | — | Context-bound AEAD cipher. Binds archive_id ‖ epoch_id ‖ volume_index ‖ block_index as AAD. |
| `kdf.rs` | — | Argon2id password → MK derivation. Configurable memory/time cost. |
| `secure_memory.rs` | — | `SecureBuffer<N>`: mlock + Zeroize on Drop. Core dump prevention (prctl/ptrace). |

## KEY LIFECYCLE

```
MK (32B, OsRng) → HKDF(info="ERA_KeyWrap_v1") → IK (memory-only)
                                                    IK wraps → VK (32B, OsRng, stored encrypted)
                                                                 VK → HKDF(info="ERA_BlockKey_v1") → BK (per-block)
```

## DOMAIN SEPARATION CONSTANTS

- `IK_DOMAIN = b"ERA_KeyWrap_v1"` — MK → IK derivation
- `VK_WRAP_AAD = b"ERA_VK_WRAP_v8.1"` — VK wrapping AAD
- `BLOCK_KEY_DOMAIN = b"ERA_BlockKey_v1"` — VK → BK derivation

## SECURITY RULES

- NEVER skip AEAD tag verification
- NEVER persist IK to disk — derive from MK at runtime
- All key material in `SecureBuffer<N>` with Zeroize on Drop

## TEST

```bash
cargo test -p era-crypto
cargo test -p era-crypto --test envelope_adversarial
```
