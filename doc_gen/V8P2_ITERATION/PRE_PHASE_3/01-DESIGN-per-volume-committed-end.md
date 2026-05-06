# 01-DESIGN: Per-Volume Committed End 方案

**版本**: 1.3（修订版）  
**日期**: 2026-05-06  
**状态**: 设计修订完成，已实施  
**前置条件**: Oracle 审计 PHASE3 方案，发现 committed_horizon 无法安全表达多卷物理边界  
**基于**: `doc_gen/V8P2_ITERATION/PHASE_3/01-ORACLE-AUDIT-REPORT.md`  

---

## 目录

1. [设计概述](#1-设计概述)
2. [问题分析](#2-问题分析)
3. [改动量分析](#3-改动量分析)
4. [具体实现](#4-具体实现)
   - 4.1 Protobuf Schema 变更
   - 4.2 Rust 类型变更
   - 4.3 Writer 计算逻辑变更
   - 4.4 Reader 边界检查变更
   - 4.5 Recovery / Checkpoint 边界变更
5. [性能影响](#5-性能影响)
6. [测试策略](#6-测试策略)
7. [风险与缓解](#7-风险与缓解)
8. [实施顺序](#8-实施顺序)
9. [附录：代码变更汇总](#9-附录代码变更汇总)

---

## 1. 设计概述

### 核心变更

将 `ArchiveManifest.committed_horizon: u64`（单一全局边界）替换为 `volume_committed_ends: Vec<u64>`（per-volume 边界数组）。

```
Before:  committed_horizon: u64
         试图用单一数值约束多个独立文件的偏移空间

After:   volume_committed_ends: Vec<u64>
         index = volume_sequence, value = 该 volume 文件内的最大已提交偏移
```

### 设计原则

1. **精确性**：每个 volume 的边界独立计算，不互相干扰
2. **可验证性**：per-volume 边界纳入 Manifest commitment 计算，篡改任何 volume 的边界都会导致 commitment 验证失败
3. **最小侵入性**：尽量复用现有 finalize 流程中的 per-volume 遍历逻辑

---

## 2. 问题分析

### 2.1 原始问题

Oracle 审计发现 PHASE3 方案使用单一 `u64 committed_horizon` 存在两个独立缺陷：

**缺陷 A：Writer 计算漏掉 `BlockHeader::SIZE`**

Writer 计算（`era-engine/src/writer.rs:2074-2075`）：
```rust
let committed_horizon = if let Some(last_location) = self.catalog.block_locations.last() {
    last_location.physical_offset + u64::from(last_location.encrypted_size)
} else {
    era_volume::DATA_REGION_START
};
```

但 block 在磁盘上的实际占用 = `physical_offset + BlockHeader::SIZE(16B) + encrypted_size`。

**缺陷 B：单一 u64 无法表达多卷独立 offset 空间**

各 volume 有独立的物理 offset 空间，都从 `DATA_REGION_START(4224)` 开始。用单一 `u64` 同时约束多个 volume 会导致：
- **安全绕过**：某卷未提交尾部数据可能落在全局 horizon 内而被读取
- **可用性故障**：某卷有效已提交数据可能因全局 horizon 过小而误拒

### 2.2 为什么用户的直觉部分正确但不够

在 **canonical erasure 配置**下（`volume_count >= total_shards` 或 `total_shards % volume_count == 0`），data/parity shards 确实均匀分布到各 volume，各 volume 的 data_end_offset **应该大致相同**。

但即使 offset 数值相同，也是**不同文件的无关位置**。单一 `u64` 无法表达 per-volume 语义，这是类型层面的设计缺陷，不是数值问题。

---

## 3. 改动量分析

### 影响文件清单

| # | 文件 | 当前行数 | 改动类型 | 预估改动量 |
|---|------|---------|---------|-----------|
| 1 | `era-common/proto/era_common.proto` | 325 | schema 修改 | ~8 行 |
| 2 | `era-common/src/types/manifest.rs` | 204 | 结构体 + 序列化 | ~40 行 |
| 3 | `era-common/src/serde.rs` | -- | bounded map 校验 | ~15 行 |
| 4 | `era-engine/src/writer.rs` | 3321 | build_manifest 参数 + 计算 | ~30 行 |
| 5 | `era-engine/src/reader.rs` | 2423 | open_v82 + 边界检查 | ~25 行 |
| 6 | `era-engine/src/block_iter.rs` | 1729 | Catalog 模式边界检查 | ~20 行 |
| 7 | `era-engine/src/recovery.rs` | 855 | checkpoint / recovery 边界 | ~10 行 |
| 8 | `era-volume/src/volume_pool.rs` | 1395 | 新增辅助方法 | ~5 行 |
| 9 | `PLAN.md` | 1995 | 设计文档更新 | ~50 行 |
| | **总计** | | | **~203 行** |

### 向下兼容性

- **v8.2 新 archive**：`volume_committed_ends` 长度等于 `total_volumes`，使用 field 6（`repeated uint64`）。`committed_horizon`（field 3）设为所有 volume ends 的最大值，供旧 reader 使用
- **v8.1 旧 archive**：`volume_committed_ends` 为空（`Vec::new()`），新 reader 回退到 `committed_horizon` 作为全局边界
- **protobuf 兼容性**：
  - **新 reader 读旧 archive**：`volume_committed_ends`（field 6）为空，回退到 `committed_horizon`（field 3）
  - **旧 reader 读新 archive**：读到 `committed_horizon`（field 3，设为最大值），单卷场景正确；多卷场景不够精确但不会崩溃
- **版本检测**：通过 `Footer::has_manifest()`（`manifest_offset != 0`）区分 v8.1/v8.2。v8.2 且 `volume_committed_ends.is_empty()` 视为格式错误（fail-closed）
- **显式版本标记**：`ArchiveManifest` 本身无版本字段，依赖 `epoch_id` + `finalize_sequence` 的单调性来检测回滚

---

## 4. 具体实现

### 4.1 Protobuf Schema 变更

**文件**: `era-common/proto/era_common.proto`

```protobuf
// ArchiveManifest: cryptographically authenticated global state snapshot (v8.2)
message ArchiveManifest {
  uint32 epoch_id = 1;
  uint64 finalize_sequence = 2;

  // 保留旧字段以实现向后兼容（单卷归档）
  uint64 committed_horizon = 3;

  bytes catalog_commitment = 4; // exactly 32 bytes
  bytes index_commitment = 5;   // exactly 32 bytes, or all zeros if no index

  // 新增：每卷已提交数据区域的结束偏移量
  // index = volume_sequence, value = 该 volume 的最大已提交偏移
  // 长度 = total_volumes，顺序与 volume_sequence 一一对应
  // 使用 uint64 (varint) —— Writer 在写入前测量实际序列化大小，消除自引用问题
  repeated uint64 volume_committed_ends = 6;
}
```

**设计决策**：
- **保留 field 3**：旧 reader 读取新 archive 时仍能读取 `committed_horizon`（单卷场景下正确），避免可用性灾难
- **新增 field 6**：使用新字段编号，protobuf wire format 兼容
- **使用 `uint64` (varint)**：
  1. Writer 在 finalize 前通过 `provisional_manifest.to_bytes()?.len()` 测量实际序列化大小，消除了自引用循环问题
  2. 对于典型偏移量（<2^56），varint 编码更紧凑（1-8 bytes vs 固定 8 bytes）
  3. 现有测试 `volume_committed_ends_uses_varint_not_fixed64_wire_encoding` 已锁定 varint 编码作为规范
- 使用 `repeated` 而非 `map<uint32, uint64>` —— 原因：
  1. `volume_sequence` 是连续的整数（0..N），Vec 索引天然对应 sequence
  2. 序列化顺序确定，commitment 计算稳定
  3. 内存更紧凑，无哈希表桶数组开销

---

### 4.2 Rust 类型变更

**文件**: `era-common/src/types/manifest.rs`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveManifest {
    pub epoch_id: u32,
    pub finalize_sequence: u64,

    /// Legacy global commit boundary.
    /// Kept for backward compatibility with single-volume archives.
    pub committed_horizon: u64,

    /// Per-volume committed end offsets.
    /// Index = volume_sequence (0..N), Value = maximum committed byte offset in that volume file.
    /// Data beyond this offset in the volume is considered uncommitted.
    /// Length must equal total_volumes for valid archives.
    pub volume_committed_ends: Vec<u64>,

    pub catalog_commitment: [u8; 32],
    pub index_commitment: [u8; 32],
}

impl ArchiveManifest {
    pub fn new(
        epoch_id: u32,
        finalize_sequence: u64,
        committed_horizon: u64,
        volume_committed_ends: Vec<u64>,
        catalog_commitment: [u8; 32],
        index_commitment: [u8; 32],
    ) -> Self { ... }

    /// Get the committed end for a specific volume.
    /// Returns None if volume_sequence is out of bounds.
    pub fn committed_end_for_volume(&self, volume_sequence: u16) -> Option<u64> {
        self.volume_committed_ends.get(usize::from(volume_sequence)).copied()
    }

    /// Check if the committed ends vector covers all expected volumes.
    pub fn has_all_volume_ends(&self, expected_total_volumes: u16) -> bool {
        self.volume_committed_ends.len() >= usize::from(expected_total_volumes)
    }

    pub fn to_bytes(&self) -> crate::Result<Vec<u8>> { ... }
    pub fn from_bytes(data: &[u8]) -> crate::Result<Self> { ... }
}
```

**序列化转换**：

```rust
impl From<&ArchiveManifest> for crate::proto::ArchiveManifest {
    fn from(m: &ArchiveManifest) -> Self {
        Self {
            epoch_id: m.epoch_id,
            finalize_sequence: m.finalize_sequence,
            committed_horizon: m.committed_horizon,
            volume_committed_ends: m.volume_committed_ends.clone(),
            catalog_commitment: m.catalog_commitment.to_vec(),
            index_commitment: m.index_commitment.to_vec(),
        }
    }
}

impl TryFrom<crate::proto::ArchiveManifest> for ArchiveManifest {
    type Error = crate::EraError;

    fn try_from(p: crate::proto::ArchiveManifest) -> crate::Result<Self> {
        const MAX_VOLUMES: usize = 1024;
        if p.volume_committed_ends.len() > MAX_VOLUMES {
            return Err(crate::EraError::Deserialization(
                format!(
                    "volume_committed_ends count {} exceeds maximum {}",
                    p.volume_committed_ends.len(), MAX_VOLUMES
                )
            ));
        }

        const DATA_REGION_START: u64 = 4224;
        for (seq, &end) in p.volume_committed_ends.iter().enumerate() {
            if end < DATA_REGION_START && end != 0 {
                return Err(crate::EraError::Deserialization(
                    format!(
                        "volume {} committed_end {} is below DATA_REGION_START",
                        seq, end
                    )
                ));
            }
        }

        let catalog_commitment: [u8; 32] = p.catalog_commitment.try_into().map_err(|_| {
            crate::EraError::Deserialization("catalog_commitment must be exactly 32 bytes".into())
        })?;
        let index_commitment: [u8; 32] = p.index_commitment.try_into().map_err(|_| {
            crate::EraError::Deserialization("index_commitment must be exactly 32 bytes".into())
        })?;

        Ok(Self {
            epoch_id: p.epoch_id,
            finalize_sequence: p.finalize_sequence,
            committed_horizon: p.committed_horizon,
            volume_committed_ends: p.volume_committed_ends,
            catalog_commitment,
            index_commitment,
        })
    }
}
```

---

### 4.3 Writer 计算逻辑变更

**文件**: `era-engine/src/writer.rs`

**当前代码**（`writer.rs:2074-2078`）：
```rust
let committed_horizon = if let Some(last_location) = self.catalog.block_locations.last() {
    last_location.physical_offset + u64::from(last_location.encrypted_size)
} else {
    era_volume::DATA_REGION_START
};
```

**问题**：
1. 只取 `last()`，假设所有 block 在单一 offset 空间内
2. 漏掉 `BlockHeader::SIZE`
3. 不区分 volume

**新方案**：新增 `VolumePool::committed_ends()` 方法，返回所有 volume（active + rotated）的当前大小：

```rust
// era-volume/src/volume_pool.rs
impl<B: StorageBackend> VolumePool<B> {
    /// Returns per-volume committed data boundaries.
    /// Combines rotated volumes (from stats.volume_sizes) with active writers.
    /// Must be called BEFORE writing typed blocks to get data-only boundaries.
    pub fn committed_ends(&self) -> Vec<(u16, u64)> {
        let mut ends: Vec<(u16, u64)> = self.stats.volume_sizes.clone();
        for (i, writer) in self.writers.iter().enumerate() {
            ends.push((self.sequences[i], writer.current_size()));
        }
        ends.sort_by_key(|(seq, _)| *seq);
        ends
    }
}
```

```rust
// era-engine/src/writer.rs
// 在 rotation 之后、写入 typed blocks 之前捕获 per-volume boundaries
if rotated {
    volume_indices = self.current_volume_indices()?;
    (catalog_blocks_by_volume, backup_blocks_by_volume) = self.build_catalog_block_sets(...)?;
}

// 捕获 per-volume committed ends AFTER rotation but BEFORE writing typed blocks.
let volume_committed_ends: Vec<u64> = self
    .pipeline
    .volume()
    .pool()
    .committed_ends()
    .into_iter()
    .map(|(_, size)| size)
    .collect();

// 同时保留 committed_horizon 作为 backward compat
let committed_horizon = volume_committed_ends.iter().copied().max()
    .unwrap_or(era_volume::DATA_REGION_START);

// 传给 build_manifest
let manifest = self.build_manifest(
    &catalog_bytes,
    &index_bytes,
    committed_horizon,
    volume_committed_ends,
)?;
```

**关键修正**：
- 使用 `committed_ends()` 而非 `stats().volume_sizes`：后者只包含已 rotate 的 volume，不包含 active writers
- 捕获时机：必须在 rotation **之后**、typed blocks **之前**
- `current_size()` 包含 `BlockHeader::SIZE`（16 bytes），自然修复 Defect A
- `committed_horizon` 保留并设为所有 volume ends 的最大值，用于 backward compat

**`build_manifest` 签名变更**：
```rust
// Before
fn build_manifest(
    &self,
    catalog_bytes: &[u8],
    index_bytes: &[u8],
    committed_horizon: u64,
) -> Result<ArchiveManifest> { ... }

// After
fn build_manifest(
    &self,
    catalog_bytes: &[u8],
    index_bytes: &[u8],
    committed_horizon: u64,
    volume_committed_ends: Vec<u64>,
) -> Result<ArchiveManifest> { ... }
```

**Append 模式边界单调性保证**：
当向已有 archive 追加数据时，新的 `committed_end` 必须大于等于旧的 `committed_end`：

```rust
// 在 writer.rs finalize 流程中，构建新 manifest 前
if let Some(old_manifest) = &self.existing_manifest {
    for (seq, (&new_end, &old_end)) in new_committed_ends.iter()
        .zip(old_manifest.volume_committed_ends.iter())
        .enumerate()
    {
        if new_end < old_end {
            return Err(EraError::IntegrityError(
                format!(
                    "Volume {} committed_end decreased from {} to {} (must be monotonic)",
                    seq, old_end, new_end
                )
            ));
        }
    }
}
```

---

### 4.4 Reader 边界检查变更

**文件**: `era-engine/src/reader.rs`

**新增辅助方法**（简化设计，使用 volume_sequence 直接索引）：
```rust
impl ArchiveReader {
    /// 检查指定 volume 上的读取是否超出 committed boundary
    fn check_read_bound(
        &self,
        volume_sequence: u16,
        offset: u64,
        len: u64,
    ) -> Result<()> {
        if self.volume_committed_ends.is_empty() {
            return Ok(()); // backward compat: no boundaries set
        }

        let committed_end = self.volume_committed_ends
            .get(usize::from(volume_sequence))
            .copied()
            .ok_or_else(|| EraError::InvalidFormat(
                format!("No committed end for volume {}", volume_sequence)
            ))?;

        let read_end = offset.checked_add(len)
            .ok_or_else(|| EraError::IntegrityError("Offset overflow".into()))?;

        if read_end > committed_end {
            return Err(EraError::BeyondCommitHorizon {
                offset,
                horizon: committed_end,
            });
        }

        Ok(())
    }
}
```

**设计简化**：不再使用 `HashMap<VolumeId, u16>` 映射表。Reader 的 `volume_readers` 已经可以通过 `volume_sequence` 查找（erasure shard 读取路径已有此模式）。`volume_committed_ends` 直接用 `volume_sequence` 作为 Vec 索引，避免额外的 HashMap 分配和查找开销。

**volume_sequence 获取**：
- 对于 primary shard：`BlockLocation.volume_id` → 线性搜索 `volume_readers` 获取 `volume_sequence`
- 对于 neighbor shards：直接使用 `shard_volumes` 中的 `volume_sequence`（已有）

然后检查边界时通过 `volume_id` 查表获取 `volume_sequence`：

```rust
let volume_seq = self.volume_id_to_sequence
    .get(&location.volume_id)
    .copied()
    .ok_or_else(|| EraError::InvalidFormat(
        format!("Unknown volume_id: {:?}", location.volume_id)
    ))?;
```
```

**迭代器集成**（`block_iter.rs` Catalog 模式）：
```rust
// Catalog 模式读取时
async fn next_block_catalog_mode(&mut self, catalog: &Catalog) -> Option<Result<DecodedBlock>> {
    let location = catalog.block_locations.get(self.block_index)?;
    self.block_index += 1;

    // 获取该 block 所在 volume 的 sequence（通过 volume_id 查映射表）
    let volume_seq = self.volume_id_to_sequence
        .get(&location.volume_id)
        .copied()
        .ok_or_else(|| EraError::InvalidFormat(
            format!("Unknown volume_id: {:?}", location.volume_id)
        ))?;

    // 计算 block 在该 volume 上的结束位置
    // 使用 checked_add 防止溢出（溢出意味着恶意构造的 location）
    let block_end = location.physical_offset
        .checked_add(BlockHeader::SIZE as u64)
        .and_then(|v| v.checked_add(location.encrypted_size as u64))
        .ok_or_else(|| EraError::IntegrityError(
            format!("Block location overflow: offset={}, size={}",
                    location.physical_offset, location.encrypted_size)
        ))?;

    // Per-volume 边界检查
    let read_len = block_end.checked_sub(location.physical_offset)
        .expect("block_end > physical_offset verified above");
    if let Err(e) = self.check_read_bound(volume_seq, location.physical_offset, read_len) {
        return Some(Err(e));
    }

    // ... 继续读取
}
```

**Erasure 模式 shard 读取**：
```rust
// primary shard
let primary_seq = self.volume_id_to_sequence
    .get(&location.volume_id)
    .copied()
    .ok_or_else(|| EraError::InvalidFormat(...))?;
let primary_end = location.physical_offset
    .checked_add(ShardHeader::SIZE as u64)
    .and_then(|v| v.checked_add(info.shard_size as u64))
    .ok_or_else(|| EraError::IntegrityError("Shard location overflow".into()))?;
let read_len = primary_end - location.physical_offset;
self.check_read_bound(primary_seq, location.physical_offset, read_len)?;

// remaining shards
for (&offset, &vol_seq) in shard_offsets.iter().zip(shard_volumes.iter()) {
    let shard_end = offset
        .checked_add(ShardHeader::SIZE as u64)
        .and_then(|v| v.checked_add(info.shard_size as u64))
        .ok_or_else(|| EraError::IntegrityError("Shard location overflow".into()))?;
    let read_len = shard_end - offset;
    self.check_read_bound(vol_seq, offset, read_len)?;
}
```

---

### 4.5 Recovery / Checkpoint 边界变更

**文件**: `era-engine/src/recovery.rs`

RecoveryManager 继续使用 `footer.data_end_offset()` 作为恢复边界（保留文件完整性），同时新增 Manifest 的 per-volume committed end **完整性校验**。

两者的语义区别：
- `committed_end`（Manifest）= data region 的已提交边界，**不包含** typed blocks（Catalog/Index/Manifest）
- `data_end_offset`（Footer）= backup_header_offset，**包含**所有已写入的数据（data blocks + typed blocks）

因此正常情况下 `data_end_offset >= committed_end`，且差值等于 typed blocks 的总大小。

```rust
let manifest = self.load_manifest_from_any_volume(&footers).await?;
let committed_ends = &manifest.volume_committed_ends;

for (seq, footer) in footers {
    let committed_end = committed_ends.get(usize::from(seq))
        .ok_or_else(|| EraError::InvalidFormat(
            format!("Missing committed end for volume {}", seq)
        ))?;
    let footer_end = footer.data_end_offset();

    // 验证 Footer 的 data_end_offset 不小于 Manifest 的 committed end
    // （如果 data_end_offset < committed_end，说明 Footer 被篡改或 Manifest 不匹配）
    if footer_end < *committed_end {
        return Err(EraError::IntegrityError(
            format!(
                "Volume {} footer data_end_offset {} is less than manifest committed end {}. \
                 This indicates footer corruption or manifest mismatch.",
                seq, footer_end, committed_end
            )
        ));
    }

    // 恢复时继续使用 data_end_offset 作为截断点（保留 typed blocks）
    file.set_len(footer_end)?;
}
```

**关键修正**：Recovery **继续**使用 `data_end_offset` 作为截断点（而非 `committed_end`）。截断到 `committed_end` 会删除 typed blocks（Catalog/Index/Manifest/Footer），导致 archive 无法再次打开。完整性校验通过 `footer_end >= committed_end` 检测篡改，截断操作保持不变。

---

## 5. 性能影响

### 5.1 序列化/反序列化开销

| 指标 | Before | After | 变化 |
|------|--------|-------|------|
| Manifest 大小 | ~90 bytes | ~90 + 10*N bytes | +10 bytes/volume |
| 6 volume archive | ~90 bytes | ~150 bytes | +67% |
| 100 volume archive | ~90 bytes | ~1090 bytes | +12x |

**分析**：
- protobuf `repeated uint64` 编码开销：每个元素约 10 bytes（varint tag + value）
- 典型 3-6 volume archive，Manifest 从 ~90 bytes 增长到 ~120-150 bytes
- 仍远小于 `MAX_SHARD_SIZE`（16MB），不构成 DoS 向量

### 5.2 内存开销

| 指标 | Before | After | 变化 |
|------|--------|-------|------|
| ArchiveReader 内存 | 8 bytes | ~48-200 bytes | 取决于 volume 数量 |

**分析**：
- `Vec<u64>` 内存开销可忽略（6 volume archive 约 48 bytes，100 volume 约 800 bytes）
- 连续内存，无哈希表桶数组开销，不影响大 archive 的读取性能

### 5.3 CPU 开销

| 操作 | Before | After | 变化 |
|------|--------|-------|------|
| Writer 计算 boundary | O(1) | O(1) | 从 VolumePoolStats 直接获取 |
| Reader 边界检查 | O(1) | O(1) | Vec 索引（bounds check） |
| Catalog 模式读取 | O(1) | O(1) | 无变化 |

**分析**：
- Writer 计算：利用现有 VolumePoolStats，不增加额外循环
- Reader：`Vec::get(usize)` 开销极低（约 1-2 CPU cycles），优于 HashMap

### 5.4 I/O 开销

无额外 I/O。Manifest 大小增长极小，不影响写入/读取性能。

---

## 6. 测试策略

### 6.1 单元测试

```rust
#[test]
fn test_per_volume_committed_ends_basic() {
    let ends = vec![1_000_000, 500_000, 800_000];

    let manifest = ArchiveManifest::new(1, 1, ends, [0xAA; 32], [0xBB; 32]);
    assert_eq!(manifest.committed_end_for_volume(0), Some(1_000_000));
    assert_eq!(manifest.committed_end_for_volume(1), Some(500_000));
    assert_eq!(manifest.committed_end_for_volume(2), Some(800_000));
    assert_eq!(manifest.committed_end_for_volume(99), None);
}

#[test]
fn test_committed_end_blocks_cross_volume_reads() {
    // Volume 0 的合法读取
    assert!(reader.check_read_bound(0, 500_000, 100).is_ok());
    // Volume 1 的越界读取（Volume 1 只到 500_000）
    assert!(reader.check_read_bound(1, 600_000, 100).is_err());
}

#[test]
fn test_committed_end_monotonicity() {
    // Append 模式下 committed_end 必须单调递增
    let old_ends = vec![1_000_000, 500_000];
    let new_ends = vec![1_200_000, 700_000];
    // 验证通过
    assert!(validate_monotonic(&old_ends, &new_ends).is_ok());

    // 递减应失败
    let bad_ends = vec![900_000, 700_000];
    assert!(validate_monotonic(&old_ends, &bad_ends).is_err());
}

#[test]
fn test_offset_overflow_rejected() {
    // 验证 checked_add 溢出检测
    let location = BlockLocation {
        physical_offset: u64::MAX - 5,
        encrypted_size: 100,
        ..Default::default()
    };
    // physical_offset + BlockHeader::SIZE + encrypted_size 溢出
    assert!(calculate_block_end(&location).is_err());
}
```

### 6.2 集成测试

- 多卷 archive（3-6 volumes），验证各 volume 的 committed end 正确
- 单卷 archive，验证 backward compatibility（空 Vec 回退到 data_end_offset）
- volume rotation 场景，验证新旧 volume 边界正确
- **Append 模式**：验证追加后 committed_end 单调递增，旧数据可读
- **Erasure 跨卷 shard**：验证每个 shard 在对应 volume 的边界内

### 6.3 对抗测试

- 篡改某一 volume 的 committed end，验证 commitment 检测
- 注入超大 volume_committed_ends（>1024 entries），验证 DoS 防护
- v8.2 archive 但空 volume_committed_ends，验证 fail-closed（拒绝读取）
- 构造溢出 offset（`physical_offset + encrypted_size > u64::MAX`），验证溢出拒绝
- 全卷回滚（所有 volume 替换为旧版本），验证 `finalize_sequence` 选择机制

---

## 7. 风险与缓解

| 风险 | 可能性 | 影响 | 缓解 |
|------|--------|------|------|
| Vec 索引越界 | 低 | 高 | Reader 通过 `volume_id_to_sequence` 映射表查索引，越界时返回 `InvalidFormat` |
| VolumeId -> volume_sequence 映射错误 | 中 | 高 | Reader open 时构建映射表并校验所有 volume；新增单元测试覆盖 |
| Vec 过大（DoS） | 低 | 中 | 反序列化时限制 max 1024 entries，依据见 §4.2 |
| v8.2 archive 但空 committed_ends（fail-closed 绕过） | 低 | 高 | v8.2 context 中空 Vec 视为格式错误，拒绝读取 |
| 旧版 reader 无法读取新 archive | 低 | 高 | `repeated uint64` 向后兼容：旧 reader 得到空 Vec，回退到 `data_end_offset` |
| Append 模式下 committed_end 非单调 | 中 | 高 | finalize 时校验单调性，递减返回 `IntegrityError` |
| Offset 溢出绕过边界检查 | 低 | 高 | 所有 offset 计算使用 `checked_add`，溢出返回 `IntegrityError` |

---

## 8. 实施顺序

```
Step 1: 修改 proto schema + ArchiveManifest 类型 + 序列化逻辑
        文件: era-common/proto/era_common.proto
              era-common/src/types/manifest.rs
        验证: cargo build -p era-common

Step 2: 修改 VolumePoolStats 复用 + Writer build_manifest
        文件: era-volume/src/volume_pool.rs
              era-engine/src/writer.rs
        验证: cargo test -p era-engine --lib

Step 3: 修改 Reader 边界检查 + volume_id_to_sequence 映射表 + 迭代器集成
        文件: era-engine/src/reader.rs
              era-engine/src/block_iter.rs
        验证: cargo test -p era-engine --lib

Step 4: 修改 Recovery/Checkpoint 边界（data_end_offset < committed_end 检测）
        文件: era-engine/src/recovery.rs
        验证: cargo test -p era-engine --test *audit*

Step 5: 补测试（Append 单调性、溢出检测、对抗测试）+ 性能基准
        验证: cargo test --workspace

Step 6: 更新 PLAN.md 设计文档
        文件: doc_gen/V8P2_ITERATION/PHASE_3/PLAN.md
```

**预估总工时**: ~2-3 天（单开发者）

---

## 9. 附录：代码变更汇总

### 变更前（当前代码）

```rust
// era-common/src/types/manifest.rs
pub struct ArchiveManifest {
    pub epoch_id: u32,
    pub finalize_sequence: u64,
    pub committed_horizon: u64,           // 单一全局边界
    pub catalog_commitment: [u8; 32],
    pub index_commitment: [u8; 32],
}

// era-engine/src/writer.rs:2074-2078
let committed_horizon = if let Some(last_location) = self.catalog.block_locations.last() {
    last_location.physical_offset + u64::from(last_location.encrypted_size)
} else {
    era_volume::DATA_REGION_START
};
```

### 变更后（新设计）

```rust
// era-common/proto/era_common.proto
message ArchiveManifest {
  uint32 epoch_id = 1;
  uint64 finalize_sequence = 2;
  uint64 committed_horizon = 3;              // 保留，backward compat
  bytes catalog_commitment = 4;
  bytes index_commitment = 5;
  repeated uint64 volume_committed_ends = 6; // 新增，per-volume 边界（varint 编码）
}

// era-common/src/types/manifest.rs
pub struct ArchiveManifest {
    pub epoch_id: u32,
    pub finalize_sequence: u64,
    pub committed_horizon: u64,              // 保留，backward compat
    pub volume_committed_ends: Vec<u64>,     // per-volume 边界，index = volume_sequence
    pub catalog_commitment: [u8; 32],
    pub index_commitment: [u8; 32],
}

// era-volume/src/volume_pool.rs
pub fn committed_ends(&self) -> Vec<(u16, u64)> {
    let mut ends: Vec<(u16, u64)> = self.stats.volume_sizes.clone();
    for (i, writer) in self.writers.iter().enumerate() {
        ends.push((self.sequences[i], writer.current_size()));
    }
    ends.sort_by_key(|(seq, _)| *seq);
    ends
}

// era-engine/src/writer.rs
// 在 rotation 之后、typed blocks 之前捕获 boundaries
let volume_committed_ends: Vec<u64> = self
    .pipeline
    .volume()
    .pool()
    .committed_ends()
    .into_iter()
    .map(|(_, size)| size)
    .collect();
let committed_horizon = volume_committed_ends.iter().copied().max()
    .unwrap_or(era_volume::DATA_REGION_START);

// Append 模式：完整单调性校验（包括新增 volume）
if let Some(old_manifest) = &self.existing_manifest {
    if new_committed_ends.len() < old_manifest.volume_committed_ends.len() {
        return Err(EraError::IntegrityError(
            "Volume count decreased in append mode".into()
        ));
    }
    for (seq, (&new_end, &old_end)) in new_committed_ends.iter()
        .zip(old_manifest.volume_committed_ends.iter())
        .enumerate()
    {
        if new_end < old_end {
            return Err(EraError::IntegrityError(
                format!("Volume {} committed_end decreased: {} -> {}", seq, old_end, new_end)
            ));
        }
    }
    self.finalize_sequence = old_manifest.finalize_sequence + 1;
}

let manifest = self.build_manifest(
    &catalog_bytes,
    &index_bytes,
    committed_horizon,
    volume_committed_ends,
)?;
```

---

*文档生成时间: 2026-04-30*  
*修订时间: 2026-04-30*  
*基于: Oracle 审计报告 + 代码审查 + Sisyphus 审查*  
*状态: 设计修订完成，待实施*

---

## 修订记录

| 版本 | 日期 | 修订内容 | 修订者 |
|------|------|----------|--------|
| 1.0 | 2026-04-30 | 初始设计 | - |
| 1.1 | 2026-04-30 | 修正 Critical/High/Medium 级问题 | Sisyphus |
| 1.2 | 2026-04-30 | 实施代码修复并更新设计文档 | Sisyphus |
| 1.3 | 2026-05-06 | 确认 wire format 为 uint64，更新设计文档匹配实现 | Sisyphus |

**主要修正（v1.1 → v1.2）**：
1. **Protobuf schema**：保留 field 3 `committed_horizon`，新增 field 6 `repeated fixed64 volume_committed_ends`（而非替换 field 3）
2. **使用 `fixed64` 替代 `uint64`**：避免 varint 编码大小自引用循环
3. **Writer 计算逻辑**：新增 `VolumePool::committed_ends()` 方法，替代直接读取 `stats().volume_sizes`（后者不包含 active writers）
4. **Reader 边界检查**：简化设计，直接使用 `volume_sequence` 作为 Vec 索引，避免 `HashMap<VolumeId, u16>` 映射表
5. **Recovery 截断**：继续使用 `data_end_offset` 作为截断点（保留 typed blocks），仅添加完整性校验
6. **Append 单调性**：完整检查（包括新增 volume、volume 数量不减少、`finalize_sequence` 递增）
7. **版本兼容性**：修正"旧 reader 得到空 Vec"的错误声明；旧 reader 实际读取 `committed_horizon`（field 3）
8. **实施状态**：代码已实施，所有测试通过

**主要修正（v1.2 → v1.3）**：
1. **Wire format 确认**：实施最终选择 `repeated uint64` 而非 `repeated fixed64`
2. **自引用问题消解**：Writer 通过 `provisional_manifest.to_bytes()?.len()` 测量实际序列化大小，varint 编码大小不影响 committed_end 计算
3. **规范来源**：`manifest.rs` 中的 `volume_committed_ends_uses_varint_not_fixed64_wire_encoding` 测试作为 wire format 的权威规范
4. **向后兼容**：现有 v8.2 archive 继续使用 uint64，无需版本迁移
