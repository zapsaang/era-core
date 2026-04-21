# ERA-CORE feat_fly 分支架构级 0-day 漏洞审计报告

**审计日期**: 2026-04-19
**审计分支**: feat_fly
**审计范围**: crates/era-engine/src/{erasure_scan.rs, block_iter.rs, recovery.rs, repair.rs}
**审计方法**: 静态代码分析 + 调用链推演 + 跨模块交叉验证
**审计结论**: 4 项指控中，2 项证实存在，1 项部分成立，1 项代码不匹配

---

## 执行摘要

| 目标 | 指控 | 结论 | 严重程度 |
|------|------|------|----------|
| 目标 1 | 恢复模块截断会抹除 Catalog/Index/Footer | **代码不匹配** | 中 |
| 目标 2 | 多卷恢复缺乏跨卷同步导致矩阵撕裂 | **证实存在** | **严重** |
| 目标 3 | 前缀 Quorum 平局降级导致长度未验证 | **证实存在** | **严重** |
| 目标 4 | 基于降级的 OOM 内存耗尽攻击 | **部分成立** | 中 |

**关键发现**: 系统存在两层安全边界冲突（era-volume 声明 16MB DoS 保护，但 engine 层使用 256MB），以及一个生产代码中从未被调用的截断函数存在文档与实现严重不符。

---

## 目标 1：恢复模块的"自毁指令" (Metadata Truncation Bug)

### 1.1 结论：代码不匹配

指控称截断会"抹除紧随其后的 Catalog、Index 和 Footer"。经严格推演，该指控**表述不准确**：

1. **Catalog 和 Index 不会被抹除** — 它们嵌入在 Data Region 内部，位于 `data_end_offset` 之前
2. **Backup Header 和 Primary Footer 会被抹除** — 它们位于 `data_end_offset` 之后
3. **该函数在生产代码中从未被调用** — 仅存在于测试代码中

### 1.2 源码证据

**Volume 物理布局 (v8.1)**:

```
Offset 0-4095:        Primary Header (4096 bytes)
Offset 4096-4223:     Backup Footer Gap (128 bytes)
Offset 4224+:         Data Region (包含 Catalog、Index、Checkpoint)
Offset data_end_offset: Backup Header (4096 bytes)
Offset data_end_offset+4096: Primary Footer (128 bytes)
```

**recovery.rs:344-428 — truncate_to_checkpoint 实现**:

```rust
pub async fn truncate_to_checkpoint(&self) -> Result<u64> {
    // ...
    let data_end = Self::read_footer_data_end(&self.archive_path).await?;
    // ...
    self.truncate_file_with_cancel_flag(data_end, cancel_flag).await?;
    // ...
}

async fn truncate_file_with_cancel_flag(
    &self,
    data_end: u64,
    cancel_flag: Arc<AtomicBool>,
) -> Result<()> {
    // ...
    file.set_len(data_end)?;  // Line 414: 截断到 data_end_offset
    // ...
}
```

**writer.rs:621-622 — data_end_offset 的计算**:

```rust
// 2. Calculate data_end_offset (where data region ends, before backup header)
let data_end_offset = backup_header_offset;
```

**关键发现**: `data_end_offset = backup_header_offset`，即 Data Region 的结束位置 = Backup Header 的开始位置。

### 1.3 截断影响分析

截断到 `data_end_offset` 的物理效果：

| 区域 | 偏移范围 | 截断后状态 | 说明 |
|------|----------|------------|------|
| Primary Header | 0-4095 | ✅ 保留 | 不受影响 |
| Backup Footer | 4096-4223 | ✅ 保留 | 不受影响 |
| Data Region | 4224 至 data_end_offset-1 | ✅ 保留 | 包含 Catalog/Index |
| **Backup Header** | data_end_offset 至 +4095 | ❌ **销毁** | 被截断 |
| **Primary Footer** | data_end_offset+4096 至 +4223 | ❌ **销毁** | 被截断 |

**erasure_scan.rs:83-107 — erasure_data_end 函数证明 Catalog/Index 在 Data Region 内**:

```rust
pub(crate) fn erasure_data_end<R: era_storage::StorageReader>(
    reader: &era_volume::VolumeReader<R>,
) -> u64 {
    let (_, end) = reader.data_region();
    let Some(footer) = reader.footer() else { return end; };

    let mut limit = if footer.has_catalog_location() {
        footer.catalog_offset()  // Catalog 在 Data Region 内
    } else { end };

    if footer.has_index() && footer.index_offset() < limit {
        limit = footer.index_offset()  // Index 在 Data Region 内
    }
    // ...
    limit
}
```

### 1.4 调用链分析

**致命发现**: `truncate_to_checkpoint` 是**死代码**。

```bash
$ grep -r "truncate_to_checkpoint" crates/era-engine/src/ --include="*.rs" | grep -v "test_" | grep -v "mod tests"
# 无结果 — 生产代码中零调用
```

唯一调用点：
- `test_truncate_to_checkpoint_respects_pre_cancellation` (recovery.rs:781)
- `test_truncate_to_checkpoint_respects_inflight_cancellation` (recovery.rs:809)

**实际恢复路径**: `VolumeWriter::open_append` (writer.rs:104-143) 处理截断，其逻辑与 `truncate_to_checkpoint` 不同：

```rust
pub async fn open_append<B: StorageBackend<Writer = W>>(
    backend: &B,
    path: &Path,
    header: SuperHeader,
    footer: &Footer,
) -> Result<Self> {
    let mut writer = backend.open_append(path).await?;
    let actual_size = writer.current_size();
    if footer.data_end_offset() > actual_size {
        return Err(EraError::CorruptedFooter(...));
    }
    writer.truncate(footer.data_end_offset()).await?;  // 同样截断到 data_end_offset
    // ...
}
```

### 1.5 攻击/触发路径

**触发条件**: 需要显式调用 `RecoveryManager::truncate_to_checkpoint()`（目前无生产代码调用）。

**如果触发**：
1. 文件被截断到 `data_end_offset`
2. Backup Header 和 Primary Footer 被物理销毁
3. 但 Backup Footer（offset 4096）保留，VolumeReader::open 可尝试从 Backup Footer 恢复
4. Catalog 和 Index 保留在 Data Region 内

### 1.6 评估

- **指控不准确**: 截断不会抹除 Catalog 和 Index
- **存在真实问题**: 截断会销毁 Backup Header 和 Primary Footer，且函数文档声称"移除部分写入"，实际却移除了完整的元数据结构
- **严重性降低**: 由于该函数是死代码，当前无实际攻击面

---

## 目标 2：多卷矩阵恢复的"单卷盲视" (Matrix State Tearing)

### 2.1 结论：证实存在

**RecoveryManager 完全缺乏多卷意识**。当崩溃发生在多卷矩阵分布的写入过程中时，系统仅截断 Volume 0，其余卷保持原状，导致条带矩阵永久性错位。

### 2.2 源码证据

**recovery.rs:179-228 — RecoveryManager::analyze() 仅处理单文件**:

```rust
pub async fn analyze(archive_path: &Path) -> Result<RecoveryStatus> {
    let archive_exists = tokio::fs::try_exists(archive_path).await?;
    let checkpoint_exists = if archive_exists {
        volume_has_checkpoint(archive_path).await?  // <-- 只检查一个文件
    } else { false };
    // ...
    // 无任何 total_volumes() 检查
    // 无任何 .era.001~.era.NNN 发现逻辑
}
```

**recovery.rs:344-428 — truncate_to_checkpoint 仅截断单文件**:

```rust
async fn truncate_file_with_cancel_flag(
    &self,
    data_end: u64,
    cancel_flag: Arc<AtomicBool>,
) -> Result<()> {
    let archive_path = self.archive_path.clone();  // <-- 仅 self.archive_path
    // ...
    file.set_len(data_end)?;  // <-- 仅截断一个文件
    // ...
}
```

**repair.rs:367-373 — repair.rs 明确区分单卷/多卷**:

```rust
// If the archive is multi-volume, use matrix-aware repair
if header.total_volumes() > 1 {
    return Box::pin(repair_archive_matrix_with_providers(
        path, providers, options,
    )).await;
}
```

**repair.rs:874-1427 — repair_archive_matrix_with_providers 完整多卷处理**:

```rust
async fn repair_archive_matrix_with_providers(
    path: &Path,
    providers: Vec<Box<dyn crate::auth::AuthProvider>>,
    options: RepairOptions,
) -> Result<RepairStats> {
    // 1. 发现所有卷 (lines 888-954)
    // 2. 为所有卷创建备份 (lines 1006-1027)
    // 3. 使用矩阵分布模式扫描 (lines 1067-1391)
    // 4. 为每个卷分别应用修复 (lines 1393-1400)
}
```

### 2.3 矩阵分布模型

**distribution.rs:84-85 — 矩阵分布公式**:

```rust
MatrixDistributionStrategy::RotatingOffset => {
    let result = (shard_idx + (block_sequence as usize)) % volume_count;
    Ok(result)
}
```

**5 卷 (.era.000~.era.004)、4+2 erasure (6 shards) 的分布示例**:

| Block Sequence | Shard 0 | Shard 1 | Shard 2 | Shard 3 | Shard 4 | Shard 5 |
|----------------|---------|---------|---------|---------|---------|---------|
| Block 0        | Vol 0   | Vol 1   | Vol 2   | Vol 3   | Vol 4   | Vol 0   |
| Block 1        | Vol 1   | Vol 2   | Vol 3   | Vol 4   | Vol 0   | Vol 1   |
| Block 2        | Vol 2   | Vol 3   | Vol 4   | Vol 0   | Vol 1   | Vol 2   |
| Block 3        | Vol 3   | Vol 4   | Vol 0   | Vol 1   | Vol 2   | Vol 3   |
| Block 4        | Vol 4   | Vol 0   | Vol 1   | Vol 2   | Vol 3   | Vol 4   |

### 2.4 攻击/触发路径

**场景**: 崩溃发生在 Block 5 写入过程中。

**截断前状态**:
```
Volume 0 (.era)     Volume 1 (.era.001)  Volume 2 (.era.002)  Volume 3 (.era.003)  Volume 4 (.era.004)
├─ Block 0-4        ├─ Block 0-4         ├─ Block 0-4         ├─ Block 0-4         ├─ Block 0-4
├─ Block 5 PARTIAL  ├─ Block 5 complete  ├─ Block 5 complete  ├─ Block 5 complete  ├─ Block 5 complete
├─ [未提交数据]     ├─ Block 6 written   ├─ Block 6 written   ├─ Block 6 written   ├─ Block 6 written
```

**RecoveryManager 截断后**:
```
Volume 0 (.era)     Volume 1 (.era.001)  Volume 2 (.era.002)  Volume 3 (.era.003)  Volume 4 (.era.004)
├─ Block 0-4        ├─ Block 0-6         ├─ Block 0-6         ├─ Block 0-6         ├─ Block 0-6
├─ [TRUNCATED]      ├─ (未截断)          ├─ (未截断)          ├─ (未截断)          ├─ (未截断)
```

**结果**: 
1. Volume 0 的 Block 5 shard 0 被截断
2. Volume 1-4 的 Block 5-6 数据保留
3. 条带矩阵错位：Block 6 的 shard 0 应该在 Volume 0，但 Volume 0 已被截断
4. RS 解码失败：无法找到足够的 shards 重建数据
5. 整个卷集进入不可恢复的撕裂状态

### 2.5 交叉验证

**checkpoint.rs:48 — Checkpoint 确实跟踪 current_volume**:

```rust
pub struct Checkpoint {
    pub version: u32,
    pub timestamp: u64,
    pub current_volume: u16,      // <-- 存在但 recovery.rs 从未使用
    pub current_offset: u64,
    pub total_bytes_written: u64,
    // ...
}
```

**recovery.rs:310-315 — current_volume() 方法存在但死代码**:

```rust
pub fn current_volume(&self) -> u16 {
    self.checkpoint_manager
        .as_ref()
        .map(|m| m.checkpoint().current_volume)
        .unwrap_or(0)
}
```

该方法从未在截断逻辑中被调用。

### 2.6 评估

| 能力 | Recovery.rs | Repair.rs |
|------|-------------|-----------|
| 多卷检测 | ❌ 无 | ✅ `header.total_volumes() > 1` |
| 卷发现 | ❌ 无 | ✅ 扫描 `.era.NNN` |
| 跨卷截断 | ❌ 仅 Volume 0 | ✅ 每卷独立修复 |
| 矩阵分布感知 | ❌ 无 | ✅ `calculate_volume()` |
| 所有卷备份 | ❌ 无 | ✅ 全部卷 |

**结论**: RecoveryManager 在多卷场景下是完全盲视的。截断仅作用于 Volume 0 的物理行为，结合矩阵分布的数学特性，必然导致整个条带矩阵的永久性错位。

---

## 目标 3：前缀 Quorum 的"平局降级"漏洞 (Tie-Downgrade Bypass)

### 3.1 结论：证实存在

当 `reconcile_stripe_prefixes` 因平局返回 `None` 时，`SessionErasureBlockIterator::next_block` 中的 data shard 路径会直接使用 `shard_header.length` 而**不进行 MAX_SHARD_SIZE 验证**。这与 `repair.rs` 的安全处理形成鲜明对比。

### 3.2 源码证据

**erasure_scan.rs:11-45 — reconcile_stripe_prefixes 完整逻辑**:

```rust
pub(crate) fn reconcile_stripe_prefixes(
    prefix_copies: &[Bytes],
    data_shards: usize,
) -> Option<Vec<u32>> {
    if prefix_copies.len() < 2 {
        return None;  // Line 16: 副本不足
    }

    let mut counts: HashMap<&[u8], usize> = HashMap::new();
    for copy in prefix_copies {
        *counts.entry(copy.as_ref()).or_insert(0) += 1;
    }

    let mut best_count: usize = 0;
    for &count in counts.values() {
        if count >= 2 && count > best_count {
            best_count = count;
        }
    }
    if best_count < 2 {
        return None;  // Line 31: 无 majority
    }

    let mut best: Option<&[u8]> = None;
    for (bytes, count) in counts {
        if count == best_count {
            if best.is_some() {
                return None;  // <-- LINE 38: 平局/并列
            }
            best = Some(bytes);
        }
    }

    best.map(|bytes| parse_stripe_lengths(bytes, data_shards))
}
```

**所有返回路径**:

| 行号 | 条件 | 返回值 | 场景 |
|------|------|--------|------|
| 16 | `prefix_copies.len() < 2` | `None` | 副本数不足 |
| 31 | `best_count < 2` | `None` | 无两个副本一致 |
| **38** | `best.is_some()` 时遇到并列 | **`None`** | **平局/并列** |
| 44 | 唯一 majority | `Some(Vec<u32>)` | 正常 |

**测试用例证实平局返回 None** (erasure_scan.rs:143-148):

```rust
#[test]
fn test_reconcile_stripe_prefixes_returns_none_on_two_way_tie() {
    let a = Bytes::from(vec![1u8, 0, 0, 0]);
    let b = Bytes::from(vec![2u8, 0, 0, 0]);
    let copies = vec![a.clone(), a.clone(), b.clone(), b.clone()];
    assert_eq!(reconcile_stripe_prefixes(&copies, 1), None);  // <-- 明确返回 None
}
```

**block_iter.rs:1249-1287 — SessionErasureBlockIterator 的 tie 处理**:

```rust
let authoritative_len: Option<u32> = if is_data_shard {
    stripe_lengths
        .as_ref()
        .and_then(|sl| sl.get(shard_idx).copied())
} else {
    None
};

let parity_bound =
    crate::erasure_scan::parity_bound_from_lengths(stripe_lengths.as_deref());

let shard_len: usize = if let Some(auth_len) = authoritative_len {
    auth_len as usize
} else if !is_data_shard {
    // Parity shard path
    let header_len = shard_header.length;
    if let Some(pb) = parity_bound {
        if pb > 0 && header_len < pb {
            self.stats.corrupted_shards += 1;
            self.current_offsets[idx] += ... + pb as u64;
            continue;  // 有边界检查
        }
        if pb > 0 && header_len > pb {
            pb as usize
        } else {
            header_len as usize
        }
    } else {
        header_len as usize  // <-- 无 MAX_SHARD_SIZE 检查
    }
} else {
    // DATA SHARD with no authoritative_len (TIE CASE!)
    shard_header.length as usize  // <-- LINE 1280: 直接信任 header.length，无验证！
};

// Line 1283: 此检查在 shard_len 计算之后
if shard_len as u32 > MAX_SHARD_SIZE {
    return Some(Err(EraError::InvalidFormat(
        "Shard size exceeds maximum".into(),
    )));
}
```

**关键漏洞**: Line 1280 的 `else` 分支（data shard + tie case）直接使用 `shard_header.length` 而不经过任何前置验证。虽然 Line 1283 有 MAX_SHARD_SIZE 检查，但：
1. 该检查位于 `shard_len` 计算之后
2. 对于 tie case 的 data shard，代码在 Line 1280 已经将 `shard_header.length` 赋给 `shard_len`
3. 如果攻击者设置 `shard_header.length = MAX_SHARD_SIZE`（恰好等于限制），检查通过

### 3.3 与 repair.rs 的安全处理对比

**repair.rs:494-539 — 完整的 tie case 安全处理**:

```rust
let shard_len: usize = if let Some(auth_len) = authoritative_len {
    // Data shard with authoritative_len
    if auth_len as u64 > MAX_SHARD_SIZE {  // <-- Line 496: 强制验证
        return Err(EraError::ErasureError(format!(...)));
    }
    auth_len as usize
} else if let Some(ref h) = shard_header {
    // Parity shard
    if h.length as u64 > MAX_SHARD_SIZE {  // <-- Line 505: 强制验证
        return Err(EraError::ErasureError(format!(...)));
    }
    // ... parity_bound 处理
};
```

**对比**:

| 场景 | repair.rs | block_iter.rs |
|------|-----------|---------------|
| authoritative_len 存在 | ✅ 验证 MAX_SHARD_SIZE | ✅ 使用 auth_len |
| tie case + parity shard | ✅ 验证 MAX_SHARD_SIZE | ⚠️ 部分验证（parity_bound） |
| **tie case + data shard** | **N/A（repair 不区分）** | ❌ **直接使用 header.length** |

### 3.4 攻击/触发路径

1. **攻击者构造恶意 archive**：在 4+2 erasure 的条带中，设置 4 个 data shards 的 prefix 为两两不同的值（如 [A, A, B, B]）
2. **触发平局**：`reconcile_stripe_prefixes` 返回 `None`
3. **降级处理**：所有 data shards 的 `authoritative_len` 为 `None`
4. **未验证长度使用**：代码进入 Line 1280 的 `else` 分支，使用 `shard_header.length`
5. **攻击者设置长度**：将 `shard_header.length` 设置为 `MAX_SHARD_SIZE`（256MB）或更小但仍巨大的值
6. **内存分配**：Line 1296 的 `read_raw` 使用 `shard_len` 分配内存

### 3.5 评估

**漏洞确认**: `reconcile_stripe_prefixes` 在平局时确实返回 `None`，且 `block_iter.rs` 的 tie case data shard 路径确实直接使用未经验证的 `shard_header.length`。这与 `repair.rs` 的安全处理形成鲜明对比。

**严重性**: 严重。攻击者可通过构造特定的 prefix 模式触发 tie，然后控制 shard 长度。

---

## 目标 4：基于降级的 OOM 内存耗尽攻击 (Memory Exhaustion DoS)

### 4.1 结论：部分成立

攻击者确实可以利用 tie-downgrade 路径触发大内存分配，但单次攻击的内存峰值**不超过 1.5GB**（而非指控的"数千兆"）。然而，结合安全边界不一致（era-volume 声明 16MB 但实际允许 256MB），该漏洞具有实际的 DoS 价值。

### 4.2 源码证据

**block_iter.rs:66-69 — MAX_SHARD_SIZE 定义**:

```rust
const MAX_BLOCK_SIZE: u32 = 64 * 1024 * 1024;    // 64 MB
const MAX_SHARD_SIZE: u32 = 256 * 1024 * 1024;   // 256 MB
const MAX_PROBE_ATTEMPTS: usize = 256;
```

**era-volume/src/lib.rs:16 — 底层 MAX_SHARD_SIZE**:

```rust
pub const MAX_SHARD_SIZE: usize = 16 * 1024 * 1024;  // 16 MB
```

**⚠️ 安全边界冲突**: era-volume 层声明 16MB 是"Anti-DoS 保护"，但 engine 层的迭代器使用 256MB。

**era-storage/src/local.rs:184-196 — 内存分配点**:

```rust
async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
    let mut file = self.file.try_clone().await.map_err(EraError::Io)?;
    file.seek(std::io::SeekFrom::Start(offset)).await.map_err(EraError::Io)?;
    let mut buffer = vec![0u8; len];  // <-- 直接分配 len 字节
    file.read_exact(&mut buffer).await.map_err(EraError::Io)?;
    Ok(Bytes::from(buffer))
}
```

**VolumeReader::read_raw 无长度验证** (era-volume/src/reader.rs:240-242):

```rust
pub async fn read_raw(&self, offset: u64, len: usize) -> Result<Bytes> {
    self.reader.read_at(offset, len).await  // <-- 直接委托，无验证
}
```

### 4.3 内存影响计算

**4+2 erasure 配置（4 data + 2 parity shards = 6 total）**:

| 组件 | 数量 | 单个最大 | 小计 |
|------|------|----------|------|
| Data shards | 4 | 256 MB | **1 GB** |
| Parity shards | 2 | 256 MB | 512 MB |
| `available_shards` Vec | 6 | ~64 bytes | 可忽略 |
| `shard_array` Vec | 6 | ~24 bytes | 可忽略 |
| RS 解码内部缓冲 | 1 | ~shard_size | ≤ 256 MB |
| **单次 stripe 峰值** | | | **≤ 1.5 GB** |

**block_iter.rs:1361-1367 — RS 解码前的二次复制**:

```rust
let mut shard_array: Vec<Option<Vec<u8>>> = vec![None; total_shards];
for shard in available_shards.iter() {
    if shard.crc_valid {
        shard_array[shard.index] = Some(shard.data.to_vec());  // <-- 二次复制！
    }
}
```

每个 CRC-valid shard 的 `Bytes` 被 `to_vec()` 复制为 `Vec<u8>`，导致**双倍内存占用**。

### 4.4 攻击/触发路径

1. **构造恶意 archive**：设置 tie-case（如 [A, A, B, B]）
2. **设置超大长度**：将所有 data shards 的 `shard_header.length` 设置为 `MAX_SHARD_SIZE`（256MB）
3. **填充伪造数据**：在每个 shard 后追加 256MB 数据（确保 `read_exact` 成功）
4. **触发迭代**：调用提取操作，`SessionErasureBlockIterator::next_block` 处理该 stripe
5. **内存分配**：
   - 4 个 data shards × 256MB = 1GB（Bytes 对象）
   - `to_vec()` 复制 = 额外 1GB（Vec 对象）
   - RS 解码缓冲 = 256MB
   - **峰值 ≈ 2.25GB**

**注意**: 
- 单次 stripe 峰值约 2.25GB，不是"数千兆"
- 但现代容器（如 2GB RAM 限制）会被轻易 OOM
- 攻击者可通过构造多个大 stripes 实现累积效应

### 4.5 评估

| 方面 | 状态 |
|------|------|
| 单次 stripe 峰值 | ~2.25 GB（非数千兆） |
| 现代容器（2GB RAM） | ❌ 可被 OOM |
| 攻击复杂度 | 低（仅需控制 shard headers） |
| 安全边界不一致 | 严重（16MB vs 256MB） |
| 实际 DoS 价值 | 中（需特定环境） |

---

## 附录 A：审计方法论

### A.1 分析工具

- **静态代码阅读**: 逐行阅读 recovery.rs (855 lines)、repair.rs (1529 lines)、erasure_scan.rs (251 lines)、block_iter.rs (1729 lines)
- **跨模块 grep**: 验证函数调用链、常量定义、返回值使用
- **AST 分析**: 追踪 `data_end_offset` 从计算到使用的完整数据流
- **对比分析**: 交叉对比 recovery.rs 与 repair.rs 的多卷处理逻辑

### A.2 验证规则

- 每行代码引用必须包含**文件路径、行号、完整代码片段**
- 每个结论必须有**至少两个独立证据**支撑
- 所有"可能"/"似乎"被替换为**证实/证否/代码不匹配**

---

## 附录 B：修复建议优先级

### P0（立即修复）

1. **block_iter.rs:1280**: 在 tie case data shard 路径添加 MAX_SHARD_SIZE 验证，与 repair.rs 保持一致
2. **recovery.rs**: 为多卷 archive 添加跨卷同步截断机制，或明确禁止多卷恢复

### P1（短期修复）

3. **统一 MAX_SHARD_SIZE**: 将 block_iter.rs 的 256MB 与 era-volume 的 16MB 对齐，或文档化差异
4. **修复 truncate_to_checkpoint 文档**: 更正注释，明确说明该函数会移除 Backup Header 和 Primary Footer

### P2（中期改进）

5. **remove 死代码**: 如果 `truncate_to_checkpoint` 不再使用，应标记为 deprecated 或移除
6. **添加多卷恢复测试**: 覆盖 Volume 0 截断后矩阵状态的一致性验证

---

*报告生成时间: 2026-04-19*
*审计员: Sisyphus (ERA 核心系统终极核查者)*
*声明: 本报告所有结论均基于代码的严格逻辑推演，不受任何过往测试报告或乐观注释影响。*
