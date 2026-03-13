# ERA CLI Rough Edges Fix — Execution Report

**Date:** 2026-03-13
**Branch:** feat_fly
**Scope:** Fix all 7 known rough edges documented in ERA_CLI_USER_GUIDE.md Section 8

## Summary

All 7 known CLI rough edges have been fixed. Changes span 5 files across 3 crates. All CI checks pass (fmt, clippy -D warnings, tests).

## Changes

### RE1: Add `--key` support to `info`, `verify`, `repair`

**Files:** `bins/era-cli/src/main.rs`, `bins/era-cli/src/commands.rs`

Added `--key` (`-k`) argument to Info, Verify, and Repair commands. Each handler now uses the same `open_with_keypair` / `open` pattern already established by extract/list/repack. For repair, `--key` supports the verification/analysis phase; Reed-Solomon repair still requires password mode (with a clear error message if `--key` is used).

### RE2: Partial TOML config support

**File:** `crates/era-common/src/config.rs`

Added `#[serde(default)]` at the struct level on `ArchiveConfig`. All fields now fall back to their `Default` impl when absent from TOML. Users can now write sparse config files like:

```toml
[compression]
level = 9
```

### RE3: Certificate-only mode generates random password

**File:** `bins/era-cli/src/commands.rs`

When `--certificate` is provided without `--password`, the CLI now generates a cryptographically random 32-byte password via `OsRng` instead of using an empty string. Hybrid mode (cert + password) is explicitly supported with an info message. Added `rand` and `hex` dependencies to era-cli.

### RE4: Removed `--matrix-distribution` flag

**Files:** `bins/era-cli/src/main.rs`, `bins/era-cli/src/commands.rs`

Removed the `--matrix-distribution` flag entirely since only `RotatingOffset` strategy exists. The strategy is still unconditionally set to `RotatingOffset` in the create path. Removed the `matrix_distribution` field from `CreateArgs` and the deprecation warning block.

### RE5: Renamed `HASH` column to `CHUNK_ID`

**File:** `bins/era-cli/src/commands.rs`

The `list --long` header now shows `CHUNK_ID` instead of `HASH`, accurately reflecting that the value is derived from the first chunk, not a whole-file digest.

### RE6: Fixed degraded-mode warning on healthy archives

**File:** `crates/era-engine/src/reader.rs`

Changed `preflight_metadata_recovery()` to check `self.embedded_index_recovery_failed` instead of `!index_recovered`. This ensures the warning only fires when an embedded index was present but recovery actually failed, not when no index exists (normal for older archives).

**File:** `crates/era-engine/tests/adversarial_audit_v3.rs`

Updated the source-level audit test `test_v3_log_02` to match the new code pattern.

### RE7: Removed `-v` short alias from verify/repair verbose

**File:** `bins/era-cli/src/main.rs`

Removed `short` from the `verbose` arg on Verify and Repair commands. This eliminates the conflict with the global `--verbose` (`-v`) flag. Users now use `--verbose` (long form) for command-specific verbose output.

## Files Modified

| File | Changes |
|------|---------|
| `crates/era-common/src/config.rs` | Added `#[serde(default)]` to ArchiveConfig struct |
| `crates/era-engine/src/reader.rs` | Fixed degraded-mode warning condition |
| `crates/era-engine/tests/adversarial_audit_v3.rs` | Updated audit test for new warning pattern |
| `bins/era-cli/Cargo.toml` | Added `rand` and `hex` workspace dependencies |
| `bins/era-cli/src/main.rs` | Added `--key` to info/verify/repair, removed `--matrix-distribution`, removed `-v` short alias |
| `bins/era-cli/src/commands.rs` | Updated info/verify/repair handlers for key support, cert-mode random password, renamed HASH→CHUNK_ID, removed matrix-distribution code |

## Validation

| Check | Result |
|-------|--------|
| `cargo fmt --all -- --check` | ✅ Pass |
| `cargo clippy --all-targets --all-features -- -D warnings` | ✅ Pass (0 warnings) |
| `cargo test -p era-cli` | ✅ 19 passed, 0 failed |
| `cargo test -p era-common` | ✅ 4 passed, 0 failed |
| `cargo test -p era-engine --test adversarial_audit_v1` | ✅ 21 passed, 0 failed |
| `cargo test -p era-engine --test adversarial_audit_v2` | ✅ 53 passed, 0 failed |
| `cargo test -p era-engine --test adversarial_audit_v3` | ✅ 22 passed, 0 failed |

## Post-Review Fixes (Oracle Feedback)

### RE3 Hardening: Zeroize random password bytes

**File:** `bins/era-cli/src/commands.rs`, `bins/era-cli/Cargo.toml`

Oracle flagged that the 32-byte random password array should be zeroized after hex-encoding to prevent key material lingering on the stack. Added `random_pw.zeroize()` after `hex::encode()` and added `zeroize` workspace dependency to era-cli. Import `use zeroize::Zeroize;` added.

### RE2 Hardening: `#[serde(default)]` on all sub-config structs

**File:** `crates/era-common/src/config.rs`

Manual QA revealed that `#[serde(default)]` on `ArchiveConfig` alone was insufficient — if a user specifies `[compression]` with only `level`, serde would fail because `CompressionConfig` itself lacked `#[serde(default)]`. Added `#[serde(default)]` to all sub-config structs: `CompressionConfig`, `EncryptionConfig`, `VolumeConfig`, `BlockConfig`, `ChunkingConfig`, `PackingConfig`. All have existing `Default` impls. Removed now-redundant field-level `#[serde(default)]` on `ChunkingConfig::normalization_level` and `rolling_hash_seed`.

## Updated Files Modified

| File | Changes |
|------|---------|
| `crates/era-common/src/config.rs` | Added `#[serde(default)]` to ArchiveConfig + all 6 sub-config structs |
| `crates/era-engine/src/reader.rs` | Fixed degraded-mode warning condition |
| `crates/era-engine/tests/adversarial_audit_v3.rs` | Updated audit test for new warning pattern |
| `bins/era-cli/Cargo.toml` | Added `rand`, `hex`, `zeroize` workspace dependencies |
| `bins/era-cli/src/main.rs` | Added `--key` to info/verify/repair, removed `--matrix-distribution`, removed `-v` short alias |
| `bins/era-cli/src/commands.rs` | Updated info/verify/repair handlers for key support, cert-mode random password with zeroize, renamed HASH→CHUNK_ID, removed matrix-distribution code |

## Updated Validation

| Check | Result |
|-------|--------|
| `cargo fmt --all -- --check` | ✅ Pass |
| `cargo clippy --all-targets --all-features -- -D warnings` | ✅ Pass (0 warnings) |
| `cargo test -p era-cli` | ✅ 19 passed, 0 failed |
| `cargo test -p era-common` | ✅ 4 passed, 0 failed |
| `cargo test -p era-engine --test adversarial_audit_v3` | ✅ 22 passed, 0 failed |
| Manual QA: `era info --help` | ✅ Shows `--key` flag |
| Manual QA: `era verify --help` | ✅ Shows `--key`, no `-v` short |
| Manual QA: `era repair --help` | ✅ Shows `--key`, no `-v` short |
| Manual QA: `era create --help` | ✅ No `--matrix-distribution` |
| Manual QA: `era list --long` | ✅ Shows `CHUNK_ID` column |
| Manual QA: partial TOML config | ✅ `[compression] level = 9` works |
| Manual QA: empty TOML config | ✅ All defaults applied |
| Manual QA: create + verify roundtrip | ✅ Archive created and verified |

## Known Limitations

1. **RE1 (repair --key):** Reed-Solomon repair functions in era-engine are password-only. Adding `repair_archive_with_keypair()` would require engine-level changes beyond CLI scope. The CLI bails with a clear message when `--key` is used and actual RS repair is needed.

2. **RE6 (warning fix):** The current `restore_embedded_index()` already returns `Ok(true)` when no index is present. The fix using `embedded_index_recovery_failed` is a defensive improvement that makes the intent explicit.
