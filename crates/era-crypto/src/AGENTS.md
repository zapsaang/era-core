# Crypto Source

Security primitives — all cryptographic operations and secure memory for the 3-layer envelope.

## FILES

| File | Lines | Purpose |
|------|-------|---------|
| `lib.rs` | 67 | Crate facade. Re-exports AEAD, KDF, certificate, hybrid KEM, PEM support, secure-memory, timestamp, and key-session entrypoints. |
| `key_session.rs` | 662 | `KeySession`: MK/IK/VK envelope state. HKDF derivation, VK wrap/unwrap, per-block key derivation, Shamir split/reconstruct. IK never persisted. |
| `aead.rs` | 668 | `AeadCipher` XChaCha20-Poly1305. Fresh OsRng nonces; `nonce_context` MUST be unique per archive — hard rule. |
| `aead_context.rs` | 417 | Context-bound AEAD: AAD = archive_id ‖ epoch_id ‖ block_type ‖ volume_index ‖ block_id. |
| `certificate.rs` | 823 | Legacy X25519 certificate key exchange. PEM I/O, key encapsulation/decapsulation, timestamp validation. |
| `hybrid_kem.rs` | 406 | Hybrid KEM encapsulation/decapsulation combining X25519 and ML-KEM-768. |
| `hybrid_certificate.rs` | 171 | Post-quantum hybrid certificate (X25519 + ML-KEM-768) with PEM I/O. |
| `pem_support.rs` | 605 | PEM loading/export for X25519 and hybrid keypairs. |
| `secure_memory.rs` | 464 | `SecureBuffer<N>`: mlock + Zeroize on Drop. Core dump prevention (prctl/ptrace). ONLY unsafe site in workspace src. |
| `kdf.rs` | 234 | HKDF derivation and Argon2id password → MK. Configurable memory/time cost. |
| `key.rs` | 98 | Key type definitions and conversions. |
| `hash.rs` | 98 | BLAKE3 content hashing, 256-bit output. |
| `hkdf_utils.rs` | 95 | HKDF-SHA256 helpers shared across wrap paths. |
| `commitment.rs` | 172 | Cryptographic commitments over key material. |
| `security_check.rs` | 113 | Runtime security invariant checks. |
| `timestamp.rs` | 217 | Timestamp generation/validation for certificate paths. |

## KEY LIFECYCLE

```
MK (32B, OsRng) → HKDF(info="ERA_KeyWrap_v1") → IK (memory-only)
                                                    IK wraps → VK (32B, OsRng, stored encrypted)
                                                                 VK → HKDF(info="ERA_BlockKey_v1") → BK (per-block)
```

## DOMAIN SEPARATION CONSTANTS

HKDF domains:

- `IK_DOMAIN = b"ERA_KeyWrap_v1"` — MK → IK derivation
- `BLOCK_KEY_DOMAIN = b"ERA_BlockKey_v1"` — VK → BK derivation

AAD domains (all FROZEN — byte values are AEAD authentication inputs; changing any
byte makes every existing archive's corresponding slot fail authentication):

- `CERT_ENCAPS_AAD = b"ERA_CERT_ENCAPS_v8.1"` — legacy certificate MK encapsulation
- `MK_WRAP_AAD_DOMAIN = b"ERA_MK_WRAP_v8.1"` (era-engine `auth.rs`) — password-slot MK wrap
- `HYBRID_ENCAPS_AAD = b"ERA_HYBRID_CERT_ENCAPS_v8.1"` — hybrid certificate MK encapsulation
- `VK_WRAP_AAD_DOMAIN = b"ERA_VK_WRAP_v8.1"` — IK→VK wrap
- `HYBRID_KEY_FILE_AAD = b"ERA_HYBRID_KEY_FILE_v1"` — encrypted hybrid key file container

Governance rules for domain separators:

- Labels are versioned per *construction*, not per volume format: the same
  construction keeps its label forever; a changed construction (algorithm,
  concatenation order, or input semantics) MUST get a NEW label.
- Labels do not carry, and do not promise to carry, the volume format version.
- New constants are reviewed against these rules; each shipped constant gets a
  FROZEN comment plus a byte-exact freeze unit test in its source file.

## SECURITY RULES

- NEVER skip AEAD tag verification
- NEVER persist IK to disk — derive from MK at runtime
- All key material in `SecureBuffer<N>` with Zeroize on Drop
- OsRng only for all randomness — `thread_rng()` forbidden

## TEST

```bash
cargo test -p era-crypto
cargo test -p era-crypto --test envelope_adversarial
```
