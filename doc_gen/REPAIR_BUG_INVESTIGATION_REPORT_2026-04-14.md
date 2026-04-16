# Repair Bug Investigation Report

**Date:** 2026-04-14  
**Subject:** Audit of `doc_gen/REPAIR_BUG_ANALYSIS_REPORT.md` and `doc_gen/REPAIR_BUG_ANALYSIS_REPORT_VERIFICATION.md`  
**Verdict:** **Both reports contain material errors.** The first report is substantially incorrect about the archive topology and code path. The second report correctly rejects the `apply_repairs` theory, but still misstates key facts and overcommits on an unproven root cause.

---

## Executive Summary

After reading the two reports, tracing the relevant code paths, running targeted searches, and reproducing archive creation/verification behavior, I do **not** consider either document reliable as written.

The biggest error is in the first report:

- it claims `era create --erasure 4:2` without `--max-volume-size` produces a **single-volume** archive,
- then concludes the failing test must use `repair_archive` (single-volume path),
- and from there blames `apply_repairs`.

That chain is false at the very first step.

The CLI defaults erasure-coded archives to **RotatingOffset** distribution and defaults `--volumes` to **total shards**. For `4:2`, that means **6 volumes** by default, not 1.

The second report correctly challenges the `apply_repairs` conclusion, but it still contains unsupported or incorrect statements, especially around release/debug speculation and its confidence that the matrix scan/verify offset mismatch is the root cause.

My conclusion:

1. **The first report's root-cause analysis is invalid.**
2. **The second report is directionally better but still not correct enough to trust as the final diagnosis.**
3. The most suspicious code today is the **single-volume repair scan** in `crates/era-engine/src/repair.rs:345-438`, where the length-prefix is re-read for every shard while `offset` is advanced after every shard.
4. The safest next step is **not** to change `apply_repairs`; it is to instrument and test the single-volume scan path with a true single-volume erasure archive.

---

## Verified Facts

### 1. `era create --erasure 4:2` defaults to 6 volumes

`bins/era-cli/src/main.rs:105-107` documents:

> Number of volumes to distribute shards across (default: total shards)

`bins/era-cli/src/commands.rs:318-323` implements that default:

```rust
let volumes = volume_count.unwrap_or_else(|| {
    // Default to total_shards for optimal distribution
    (ec.data_shards + ec.parity_shards) as usize
});
builder = builder.volume_count(volumes);
```

For `4:2`, total shards = `6`.

I also reproduced this behavior directly: creating a small archive with `--erasure 4:2` produced:

- `sample.era`
- `sample.era.001`
- `sample.era.002`
- `sample.era.003`
- `sample.era.004`
- `sample.era.005`

So the default topology is **multi-volume**, not single-volume.

---

### 2. `era repair` does verification first

`bins/era-cli/src/commands.rs:751-893` shows:

1. `era repair` first opens the archive,
2. runs `reader.verify().await`,
3. only attempts Reed-Solomon repair if verification reports recoverable issues,
4. then routes to matrix repair if `.era.001` exists.

Key lines:

- `commands.rs:787` — `let verify_stats = reader.verify().await.context("Verification failed")?;`
- `commands.rs:885-893` — `.era.001` existence determines `repair_archive_matrix(...)` vs `repair_archive(...)`

This matters because a corrupt archive can fail **before any repair runs at all**.

---

### 3. Passing `.era` still opens all volumes

`crates/era-engine/src/reader.rs:137-288` (`discover_volumes`) scans sibling volume files and opens all matching volumes even when the caller passes only the primary `.era` file.

So analysis based on “user passed `archive.era`, therefore only one volume was used” is wrong.

---

### 4. `apply_repairs` ordering is intentional and should not be treated as the bug

`crates/era-engine/src/repair.rs:664-676` writes **data first, flushes, then writes the shard header**:

```rust
// Write shard data first, then flush, then write header
// This ensures a crash between writes leaves the header unwritten (detectable)
// rather than pointing to garbage data (V2-SEC-06 fix)
```

So the first report's suggestion to “fix apply_repairs ordering” is not just unproven; it directly conflicts with an explicit safety invariant in the code.

The tiny cleanup at `repair.rs:685`:

```rust
let read_crc = compute_shard_crc(&Bytes::from(read_buffer.clone()));
```

may be worth simplifying later, but it is **not** a credible root-cause fix.

---

### 5. Matrix repair scan and matrix read iterator use the same offset advancement rule

Matrix repair scan (`crates/era-engine/src/repair.rs:1063-1066`):

```rust
volume_offsets[reader_idx] = shard_offset
    + header_prefix_len as u64
    + ShardHeader::SIZE as u64
    + shard_len as u64;
```

Matrix read iterator (`crates/era-engine/src/block_iter.rs:1275-1276`):

```rust
self.current_offsets[idx] +=
    header_prefix_len as u64 + ShardHeader::SIZE as u64 + shard_len as u64;
```

That does **not** prove the layout handling is correct, but it does mean the second report's theory of a simple matrix scan vs verify offset divergence is unproven.

---

### 6. Direct small-scale corruption of byte offset 5000 in the primary `.era` file did not reproduce the claimed failure

I created a small `4:2` archive, corrupted bytes `5000..5099` in `sample.era`, then ran:

- `era repair sample.era --password pwd --force`
- `era verify sample.era --password pwd`

Both passed.

This does **not** prove the original ignored test is wrong, but it does prove the reports' simplified story (“offset 5000 corruption in `archive.era` directly reproduces the bug”) is not generally valid for default multi-volume archives.

---

## What Is Wrong in `REPAIR_BUG_ANALYSIS_REPORT.md`

### False Claim 1: “The archive is single-volume”

This is false for the default CLI path with `--erasure 4:2`.

Why it matters:

- the report analyzes the wrong archive topology,
- follows the wrong engine code path,
- and therefore reaches the wrong bug location.

### False Claim 2: “Engine uses `repair_archive`, not `repair_archive_matrix`”

Also false under the default CLI behavior above.

`commands.rs:885-893` explicitly routes to matrix repair when `.era.001` exists. Under default `4:2`, it does.

### Unsupported Claim 3: release/debug difference points to padding or optimizer behavior

There is no strong evidence for this. Safe Rust plus `Bytes::from(Vec<u8>)` does not make padding/ownership speculation a credible primary diagnosis here.

### Wrong Recommendation 4: change `apply_repairs` ordering

The existing write order is deliberate and documented as a safety fix.

---

## What Is Wrong in `REPAIR_BUG_ANALYSIS_REPORT_VERIFICATION.md`

This document is better than the first one, but still not trustworthy as a final diagnosis.

### Correct parts

- It correctly rejects the first report's blame on `apply_repairs` ordering.
- It correctly notes that the clone/`Bytes::from(...)` CRC readback is a micro-optimization, not a root-cause fix.

### Problems

#### 1. It repeats the single-volume assumption

It accepts the first report's setup too readily instead of first re-checking whether the test is actually exercising single-volume repair.

#### 2. It overstates a matrix scan/verify mismatch

The matrix repair path and matrix iterator both advance offsets with the same formula. A simple “repair scan computes different offsets than verify” claim is not established by the code that was inspected.

#### 3. It treats release/debug speculation as valid

That remains weak. There is much stronger evidence pointing toward layout/path misunderstandings than toward optimizer-sensitive safe-Rust behavior.

---

## Most Likely Real Problem Area

The strongest suspicious code is the **single-volume** scan in `crates/era-engine/src/repair.rs:345-438`:

```rust
for shard_idx in 0..total_shards {
    let shard_header_offset = offset + header_prefix_len as u64;

    let prefix_bytes = match volume_reader.read_raw(offset, header_prefix_len).await {
        ...
    };

    if stripe_lengths.is_none() {
        ... parse lengths once ...
    }

    let header_bytes = match volume_reader
        .read_raw(offset + header_prefix_len as u64, ShardHeader::SIZE)
        .await
    {
        ...
    };

    ...

    offset += header_prefix_len as u64 + ShardHeader::SIZE as u64 + shard_len as u64;
}
```

Why this is suspicious:

- `stripe_lengths` is only parsed once,
- but `prefix_bytes` is re-read from the current `offset` for every shard,
- while `offset` itself advances after every shard.

If the 16-byte prefix is a **stripe-level prefix**, then this scan is wrong.

If the 16-byte prefix is really repeated before each shard, then the code may be fine — but that needs to be proven from the actual format writer/layout, not assumed.

So the safest statement is:

> The likely bug is in the single-volume scan/layout assumptions, not in `apply_repairs` ordering and not yet proven to be a matrix scan/verify mismatch.

---

## Recommended Next Steps

### 1. Reproduce on a true single-volume erasure archive

Do **not** rely on the default CLI behavior.

Use `--volumes 1` so the test definitely exercises `repair_archive(...)` instead of `repair_archive_matrix(...)`.

This is critical. Without this, investigation keeps mixing two different code paths.

### 2. Add focused instrumentation to the single-volume scan

Specifically log, for the first few stripes:

- current `offset`
- parsed `stripe_lengths`
- `shard_header_offset`
- `shard_len`
- next `offset`

Then compare with the writer's actual serialized layout.

### 3. Keep `apply_repairs` ordering unchanged

Only inspect whether the stored `repair.offset` values are correct. Do not “fix” the data-first/header-second ordering.

### 4. Add two narrow tests

- **true single-volume repair repro** (`--volumes 1`)
- **multi-volume control case** (default `4:2`, expected to route to matrix repair)

This will separate path selection bugs from actual repair-engine bugs.

---

## Final Assessment

### `REPAIR_BUG_ANALYSIS_REPORT.md`

**Assessment:** materially incorrect; should not be used as the basis for a fix.

### `REPAIR_BUG_ANALYSIS_REPORT_VERIFICATION.md`

**Assessment:** better, but still not sufficiently accurate; acceptable only as a partial critique of the first report, not as the final diagnosis.

### Recommended project action

Treat both existing documents as superseded by this report until a true single-volume repro is run and the single-volume scan layout assumptions are validated against the writer.
