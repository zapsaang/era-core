# ArchiveManifest 重构最终规范

**版本**: 1.0
**日期**: 2026-04-19
**分支**: feat_fly
**前置文档**: `docs/ArchiveManifestRefactor.md`（原始方案）、`doc_gen/ARCHIVEMANIFEST_REFACTOR_ANALYSIS_2026-04-19.md`（分析报告）、`doc_gen/ARCHIVEMANIFEST_REFACTOR_REVIEW_2026-04-19.md`（评审报告）

---

## 1. 设计原则

1. **Checkpoint 与 ArchiveManifest 职责严格分离** — Checkpoint 是 Writer 的内部状态快照，ArchiveManifest 是 Archive 的密码学认证全局状态
2. **Footer 语义不变** — Footer 保持 128 字节单扇区原子写入，作为 volume 的绝对终止标记。ArchiveManifest 不侵入 Footer 结构
3. **复用现有密码学模式** — ArchiveManifest 使用 AEAD 加密（与 Catalog/Checkpoint 相同），不引入 HMAC
4. **复用现有数据结构** — 使用已有的 `BlockLocation` 进行绝对偏移查询
5. **崩溃一致性优先** — A/B Slot 双缓冲提供原子状态转换，Footer 作为提交锚点

---

## 2. Checkpoint 与 ArchiveManifest 职责划分

### 2.1 Checkpoint — Writer 的内部状态（高频、临时）

| 职责 | 说明 |
|------|------|
| **写入进度恢复** | `current_volume`, `current_offset`, `total_bytes_written` |
| **文件级断点续传** | `in_progress_file`, `completed_files` |
| **增量去重索引** | `written_chunks: HashMap<ChunkHash, BlockLocation>` |
| **更新时机** | 周期性（如每 N 个 chunks 或每 M 秒） |
| **消费者** | Writer（崩溃后恢复写入） |
| **生命周期** | Archive 完成后理论上可丢弃 |
| **存储方式** | AEAD 加密的 typed block，Footer 的 `last_checkpoint_offset` 指向 |

Checkpoint **不负责**：
- ❌ 跨卷状态一致性
- ❌ Catalog/Index 完整性验证
- ❌ 读取路径导航
- ❌ 逻辑提交边界定义

### 2.2 ArchiveManifest — Archive 的认证全局状态（低频、权威）

| 职责 | 说明 |
|------|------|
| **逻辑提交边界** | `committed_horizon` — 超出此边界的数据视为未提交 |
| **跨卷状态同步** | `volume_states` — 每卷的精确 `tail_offset`，防止矩阵撕裂 |
| **元数据完整性** | `catalog_commitment` + `index_commitment` — 防止 Catalog/Index 篡改 |
| **读取路径导航** | 通过已验证的 Catalog 提供 O(1) 绝对偏移查询，替代预扫描 |
| **更新时机** | 仅在 `finalize()` 时（每个 archive 生命周期 1 次） |
| **消费者** | Reader（验证 + 导航）、Recovery（跨卷一致性恢复） |
| **生命周期** | 与 archive 共存亡 |
| **存储方式** | AEAD 加密，固定 A/B Slot，复制到所有 volume |

ArchiveManifest **不负责**：
- ❌ 写入进度追踪
- ❌ 文件级断点续传
- ❌ 增量去重索引
- ❌ 防回滚（需要外部单调性锚点，超出当前范围）

### 2.3 两者的交互

```
Writer 生命周期:
  1. 写入数据块 → 周期性写入 Checkpoint（Writer 内部状态）
  2. finalize() 时：
     a. 写入最终 Catalog（含 block_locations）
     b. 写入最终 Index（全副本冗余）
     c. 计算 catalog_commitment + index_commitment
     d. 构建 ArchiveManifest（committed_horizon = data_end, volume_states = 各卷 tail）
     e. AEAD 加密 manifest → 写入非活跃 A/B Slot
     f. fdatasync()
     g. 写入 Backup Header + Footer（现有 finalize 路径）
     h. fdatasync()

Reader 生命周期:
  1. 读取 Footer → 获取 backup_header_offset
  2. 计算 Manifest Slot 位置（确定性偏移）
  3. 读取 Slot A 和 Slot B → AEAD 解密 → 选择最高有效 epoch
  4. 验证 catalog_commitment（解密 Catalog 后比对）
  5. 验证 index_commitment（解密 Index 后比对，如 Index 存在）
  6. 使用 Catalog.block_locations 进行 O(1) 绝对偏移读取

Recovery 生命周期:
  1. 读取所有 volume 的 Footer
  2. 读取所有 volume 的 A/B Slot → 选择最高公共有效 epoch
  3. 使用 committed_horizon 作为逻辑掩码（不物理截断）
  4. 验证 volume_states 的 tail_offset 在矩阵意义上对齐
  5. 如需恢复写入 → 加载 Checkpoint（Writer 内部状态）
```

---

## 3. Volume 物理布局（v8.2）

### 3.1 布局变更

```
v8.1（当前）:
┌──────────────────────────────────────────────────────────────┐
│  Primary Header (4096B)                                      │
├──────────────────────────────────────────────────────────────┤
│  Backup Footer (128B)                                        │
├──────────────────────────────────────────────────────────────┤
│  Data Region（数据块、Catalog、Index、Checkpoint）             │
├──────────────────────────────────────────────────────────────┤
│  Backup Header (4096B)                                       │
├──────────────────────────────────────────────────────────────┤
│  Primary Footer (128B)                                       │
└──────────────────────────────────────────────────────────────┘

v8.2（重构后）:
┌──────────────────────────────────────────────────────────────┐
│  Primary Header (4096B)                                      │
├──────────────────────────────────────────────────────────────┤
│  Backup Footer (128B)                                        │
├──────────────────────────────────────────────────────────────┤
│  Data Region（数据块、Catalog、Index、Checkpoint）             │
├──────────────────────────────────────────────────────────────┤
│  Manifest Slot A (4096B, AEAD 加密)                          │  ← 新增
├──────────────────────────────────────────────────────────────┤
│  Manifest Slot B (4096B, AEAD 加密)                          │  ← 新增
├──────────────────────────────────────────────────────────────┤
│  Backup Header (4096B)                                       │
├──────────────────────────────────────────────────────────────┤
│  Primary Footer (128B)                                       │
└──────────────────────────────────────────────────────────────┘
```

### 3.2 关键设计决策：Manifest Slot 位于 Backup Header 之前

**为什么不放在 Footer 之后**:
- Footer 是 volume 的绝对终止标记（128B 单扇区原子写入）
- 当前 Reader 假设 Primary Footer 在文件末尾
- 在 Footer 之后追加数据会破坏这一不变量

**为什么不放在 Footer 内部**:
- Footer 仅 128 字节，无法容纳 manifest 数据
- 修改 Footer 结构会破坏 FOOTER_VERSION=1 的兼容性

**为什么放在 Backup Header 之前**:
- Footer 语义完全不变（仍是 volume 终止标记）
- FOOTER_VERSION 保持为 1，Footer 结构零修改
- Manifest Slot 位置可从 Footer 的 `backup_header_offset` 确定性计算
- 崩溃安全：manifest 在 Footer 提交之前写入，Footer 是最终提交锚点

### 3.3 确定性偏移计算

Manifest Slot 位置从 Footer 的 `backup_header_offset` 反向推导：

```rust
const MANIFEST_SLOT_SIZE: u64 = 4096;

fn manifest_slot_b_offset(backup_header_offset: u64) -> u64 {
    backup_header_offset - MANIFEST_SLOT_SIZE          // Slot B 紧邻 Backup Header
}

fn manifest_slot_a_offset(backup_header_offset: u64) -> u64 {
    backup_header_offset - 2 * MANIFEST_SLOT_SIZE      // Slot A 紧邻 Slot B
}

fn data_region_end(backup_header_offset: u64) -> u64 {
    backup_header_offset - 2 * MANIFEST_SLOT_SIZE      // Data Region 在 Slot A 之前结束
}
```

**无循环依赖**: Footer 存储 `backup_header_offset` → Reader 从中推导 Slot 位置。这是单向依赖链。

**重要变更**: v8.1 中 `backup_header_offset == data_end_offset`。v8.2 中 `data_end_offset + 8192 == backup_header_offset`。需要审计所有假设两者相等的代码。

### 3.4 空间预留常量更新

```rust
// v8.1
const BACKUP_HEADER_FOOTER_RESERVED: u64 = HEADER_SIZE + FOOTER_SIZE;  // 4224

// v8.2
const MANIFEST_SLOT_SIZE: u64 = 4096;
const MANIFEST_SLOTS_RESERVED: u64 = 2 * MANIFEST_SLOT_SIZE;           // 8192
const TRAILER_RESERVED: u64 = MANIFEST_SLOTS_RESERVED
    + HEADER_SIZE as u64
    + FOOTER_SIZE as u64;                                               // 12416

// write_canonical_block 空间检查（同时修复 v8.1 的 128B 预留 bug）
if let Some(max_size) = self.max_size {
    if offset + total_len + TRAILER_RESERVED > max_size {
        return Err(EraError::VolumeFull { ... });
    }
}
```


---

## 4. ArchiveManifest 数据结构

### 4.1 核心结构

```rust
/// Archive 的密码学认证全局状态快照。
/// 作为 AEAD 加密的固定 Slot 存储（非 typed block）。
/// 使用 HKDF 域 "ERA_MANIFEST_v8.2" 派生加密密钥。
///
/// 序列化格式：protobuf（与 SuperHeader 一致）
/// 加密方式：XChaCha20-Poly1305，AAD = archive_id ‖ epoch_id ‖ "MANIFEST"
/// 存储方式：固定 4096B A/B Slot，PKCS7 填充至 Slot 边界
pub struct ArchiveManifest {
    /// 单调递增代 ID。
    /// 用于 A/B Slot 撕裂写入选择：恢复时选择最高有效 epoch。
    /// 注意：这是崩溃恢复机制，不是防回滚机制。
    /// 防回滚需要外部单调性锚点（TPM/可信时间戳），超出当前范围。
    /// 类型为 u32，与代码库中所有 epoch_id 一致（header.rs, aead_context.rs 等）。
    pub epoch_id: u32,

    /// 逻辑提交边界（绝对字节偏移）。
    /// 超出此边界的数据视为未提交，Reader 必须忽略。
    /// 替代 recovery.rs 中的物理截断（file.set_len()），保留取证能力。
    pub committed_horizon: u64,

    /// 每卷的精确物理状态。
    /// 恢复时验证所有卷的 tail_offset 在矩阵意义上对齐，
    /// 解决当前 RecoveryManager 的单卷盲视问题。
    pub volume_states: Vec<VolumeStateEntry>,

    /// Catalog 内容的域分离密码学承诺。
    /// = blake3::keyed_hash(b"ERA-CAT-COMMIT-v1_______", &catalog_plaintext_bytes)
    /// 对解密后的规范序列化明文计算，提供语义绑定。
    pub catalog_commitment: [u8; 32],

    /// Index 内容的域分离密码学承诺。
    /// = blake3::keyed_hash(b"ERA-IDX-COMMIT-v1_______", &index_plaintext_bytes)
    /// 如 Index 不存在（旧格式 archive），则为全零 [0u8; 32]。
    pub index_commitment: [u8; 32],
}

pub struct VolumeStateEntry {
    /// Volume 序号
    pub volume_id: u32,
    /// 最后成功对齐的条带结束位置（绝对字节偏移）
    pub tail_offset: u64,
}
```

### 4.2 设计决策说明

#### 为什么使用 AEAD 而非 HMAC

| 维度 | AEAD（推荐） | HMAC |
|------|-------------|------|
| 与现有架构一致性 | ✅ Catalog/Checkpoint/Index 均使用 AEAD | ❌ 生产代码零 HMAC |
| 机密性 | ✅ manifest 内容加密（隐藏拓扑/状态） | ❌ 明文泄露 volume 拓扑和提交状态 |
| 认证 | ✅ Poly1305 tag 提供认证 | ✅ HMAC tag 提供认证 |
| 密钥派生 | 复用现有 HKDF 路径 | 需要新增 HMAC 密钥派生 |
| 代码复用 | 复用 `encrypt_with_context` | 需要新增 HMAC 计算/验证函数 |

结论：AEAD 在安全性、一致性、代码复用三个维度均优于 HMAC。

#### 为什么拆分 root_commitment 为两个独立承诺

原方案 `root_commitment = Blake3(Catalog_bytes || Index_bytes)` 存在两个问题：

1. **歧义攻击**: 简单拼接无法区分 Catalog/Index 边界。攻击者可移动边界字节产生不同组合但相同 hash。
2. **可用性耦合**: 如果 Index 丢失（Volume 0 损坏），整个 root_commitment 验证失败，即使 Catalog 完好。

拆分后：
- `catalog_commitment` 和 `index_commitment` 独立验证
- Index 丢失时仅 `index_commitment` 失败，Catalog 仍可信
- 域分离的 keyed hash 消除歧义攻击

#### 为什么对明文计算承诺（而非密文）

- 密文承诺可在解密前验证，但语义绑定弱（不同 nonce 产生不同密文 → 相同逻辑内容产生不同承诺）
- 明文承诺提供确定性语义绑定（相同逻辑内容 = 相同承诺）
- ERA 读取路径本就需要先认证（解密 MK → 派生 IK → 解包 VK），因此"解密前验证"无实际价值

### 4.3 AEAD 加密参数

```rust
// 密钥派生
// 使用专用 HKDF 域，与数据块密钥完全隔离
const MANIFEST_KEY_DOMAIN: &[u8] = b"ERA_MANIFEST_v8.2";

// Manifest 专用 nonce_context（[u8; 16]，与代码库中 nonce_context 类型一致）
// 从 MANIFEST_KEY_DOMAIN 的 blake3 hash 截取前 16 字节
fn manifest_nonce_context() -> [u8; 16] {
    let hash = blake3::hash(MANIFEST_KEY_DOMAIN);
    let mut ctx = [0u8; 16];
    ctx.copy_from_slice(&hash.as_bytes()[..16]);
    ctx
}

fn derive_manifest_key(key_session: &KeySession, volume_key: &VolumeKey) -> Result<DerivedKey> {
    // 使用固定 block_id = u32::MAX 避免与数据块密钥冲突
    // （数据块 block_id 从 0 递增，u32::MAX 不会被正常使用）
    let manifest_block_id = BlockId::from_sequence(u32::MAX as u64);
    let nonce_ctx = manifest_nonce_context();
    key_session.derive_block_key(volume_key, manifest_block_id.sequence(), &nonce_ctx)
}

// AAD 绑定
// epoch_id 为 u32（与代码库一致），占 4 字节
fn manifest_aad(archive_id: &ArchiveId, epoch_id: u32) -> [u8; 32] {
    let mut aad = [0u8; 32];
    aad[0..16].copy_from_slice(archive_id.as_bytes());
    aad[16..20].copy_from_slice(&epoch_id.to_le_bytes());  // u32 = 4 bytes
    aad[20..28].copy_from_slice(b"MANIFEST");
    aad[28..32].copy_from_slice(&[0u8; 4]);  // padding
    aad
}

// Nonce 派生（关键：防止 nonce 重用）
// 每次 manifest 写入使用 OsRng 生成随机 nonce，存储在 Slot 头部。
// 不使用确定性 nonce 派生，因为 A/B Slot 可能对同一 block_id 多次写入
// （崩溃后恢复重写），确定性 nonce 会导致 nonce 重用。
fn generate_manifest_nonce() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

// Slot 物理布局（4096 bytes）:
// [0..24]:   random nonce（明文存储，AEAD 安全性不依赖 nonce 保密）
// [24..28]:  ciphertext_len (u32 LE)
// [28..28+ciphertext_len]: AEAD ciphertext (manifest + Poly1305 tag)
// [28+ciphertext_len..4096]: zero padding
```

**Nonce 重用防护说明**:

A/B Slot 的写入模式意味着同一个 Slot 可能被多次覆写（每次 finalize 写入非活跃 Slot）。
如果使用确定性 nonce（如 `blake3(nonce_context || block_id)`），则：
- Slot A 写入 epoch=5：nonce = f(block_id=MAX)
- 下次 finalize，Slot A 写入 epoch=7：nonce = f(block_id=MAX)（相同！）
- 相同 nonce + 相同密钥 + 不同明文 = XChaCha20 安全性崩溃

因此 manifest 加密**必须使用随机 nonce**（OsRng），存储在 Slot 头部的前 24 字节。
这与数据块的确定性 nonce 不同，因为数据块的 block_id 严格单调递增（每个 block_id 只使用一次），
而 manifest Slot 的 block_id 是固定的（u32::MAX）。

---

## 5. Catalog 扩展

### 5.1 添加 block_locations

```rust
pub struct Catalog {
    pub entries: Vec<FileEntry>,
    /// 新增：每个 block 的物理位置信息。
    /// 复用已有的 BlockLocation 结构（era-common/types/block.rs:99-111）。
    /// 支持 O(1) 绝对偏移查询，替代预扫描。
    pub block_locations: Vec<BlockLocation>,
    pub total_size: u64,
    pub file_count: u64,
    pub dir_count: u64,
}
```

`BlockLocation` 已包含所需字段（无需新建结构）：
```rust
pub struct BlockLocation {
    pub volume_id: VolumeId,
    pub slot_index: u32,
    pub physical_offset: u64,    // 绝对物理偏移
    pub encrypted_size: u32,     // 加密后大小
    pub shard_layout: ShardLayout, // Single 或 Erasure
}
```

### 5.2 空间影响评估

| 场景 | Block 数量 | block_locations 大小 | 数据总量 | 占比 |
|------|-----------|---------------------|---------|------|
| 小 archive | 1,000 | ~48 KB | 4 GB | 0.001% |
| 中 archive | 100,000 | ~4.8 MB | 400 GB | 0.001% |
| 大 archive | 1,000,000 | ~48 MB | 4 TB | 0.001% |

每个 BlockLocation 约 48 字节。空间开销可忽略。

---

## 6. Index 全副本冗余

### 6.1 当前问题

Index 仅写入 Volume 0（writer.rs:1931），其他 volume 的 index 位置被零化。Volume 0 损坏 = Index 永久丢失。

### 6.2 修复方案

将 Index 写入改为全副本冗余（与 Catalog 的 `write_catalog_blocks_to_all` 相同模式）：

```rust
// 当前（仅 Volume 0）:
if let Some(writer) = self.pipeline.volume_mut().get_writer_mut(0) {
    builder.finalize_with_starting_block_id(writer, ...).await?;
}
for _ in 1..volume_count {
    locs.push((0, 0, 0));  // 零化
}

// 修改为（所有 volume）:
for vol_idx in 0..volume_count {
    if let Some(writer) = self.pipeline.volume_mut().get_writer_mut(vol_idx) {
        let loc = builder.write_index_to_volume(writer, ...).await?;
        locs.push(loc);
    }
}
```

注意：Index 构建流程（`finalize_with_starting_block_id`）需要重构为可重复写入模式，因为当前实现消耗 builder 状态。

---

## 7. 读取管线重构

### 7.1 消除预扫描

当前 `SessionErasureBlockIterator::next_block`（block_iter.rs:1096-1338）的预扫描逻辑被替换为基于 Catalog 的绝对偏移查询：

```rust
impl<'a, R: StorageReader> SessionErasureBlockIterator<'a, R> {
    async fn next_block(&mut self) -> Option<Result<DecodedBlock>> {
        // 1. O(1) 查找：从已验证的 Catalog 获取 BlockLocation
        let location = self.catalog.block_locations.get(self.block_index)?;

        // 2. 边界检查：committed_horizon 强制执行
        if location.physical_offset >= self.committed_horizon {
            return None; // 超出提交边界，停止
        }

        // 3. 安全边界：防止 OOM
        if location.encrypted_size > MAX_SHARD_SIZE as u32 {
            return Some(Err(EraError::IntegrityError(
                "Catalog block size exceeds safety bounds".into()
            )));
        }

        // 4. 直接读取：绝对偏移，无需预扫描
        match &location.shard_layout {
            ShardLayout::Single => {
                // 非纠删码：直接读取单个 block
                let data = reader.read_at(
                    location.physical_offset,
                    location.encrypted_size
                ).await?;
                // AEAD 解密 ...
            }
            ShardLayout::Erasure { info, shard_offsets, shard_volumes, shard_sizes } => {
                // 纠删码：组合 shard 0（来自 BlockLocation）+ shard 1..N（来自 ShardLayout）
                let total_shards = info.data_shards + info.parity_shards;
                let mut shards: Vec<Option<Bytes>> = Vec::with_capacity(total_shards as usize);

                // Shard 0: 来自 BlockLocation 本身
                let shard0 = reader.read_at(
                    location.physical_offset,
                    location.encrypted_size  // shard 0 的大小
                ).await?;
                shards.push(Some(shard0));

                // Shard 1..N: 来自 ShardLayout::Erasure 的 shard_offsets/shard_volumes/shard_sizes
                for i in 0..shard_offsets.len() {
                    let vol_reader = self.get_volume_reader(shard_volumes[i])?;
                    let shard = vol_reader.read_at(
                        shard_offsets[i],
                        shard_sizes[i]  // 每个 shard 的独立大小
                    ).await?;
                    shards.push(Some(shard));
                }

                // CRC 验证 + RS 恢复 ...
            }
        }

        self.block_index += 1;
        Some(Ok(decoded_block))
    }
}
```

### 7.2 ShardLayout 扩展：添加 per-shard encrypted_size

**问题**: 当前 `ShardLayout::Erasure` 不存储每个 shard 的大小。`BlockLocation.encrypted_size` 仅是 shard 0 的大小。
其他 shard 的大小在当前代码中通过预扫描 `ShardHeader.length` 获取 — 正是我们要消除的。

**解决方案**: 在 `ShardLayout::Erasure` 中新增 `shard_sizes: Vec<u32>`：

```rust
pub enum ShardLayout {
    Single,
    Erasure {
        info: ErasureBlockInfo,
        shard_offsets: Vec<u64>,    // shard 1..N 的物理偏移（已有）
        shard_volumes: Vec<u16>,    // shard 1..N 的 volume 序号（已有）
        shard_sizes: Vec<u32>,      // shard 1..N 的加密后大小（新增）
    },
}
```

**空间影响**: 每个 shard 增加 4 字节。对于 4+2 erasure（5 个额外 shard），每个 block 增加 20 字节。
100 万 blocks × 20 bytes = 20 MB，与 Catalog 中 `block_locations` 的 48 MB 相比可接受。

**替代方案评估**: 如果所有 shard 大小相同（RS 编码后通常如此），可以只存储一个 `shard_size: u32`。
但压缩后的 block 经过 RS 编码时，最后一个 data shard 可能因 padding 而大小不同。
为安全起见，存储每个 shard 的独立大小。

### 7.2 消除的漏洞链

| # | 漏洞 | 状态 |
|---|------|------|
| 1 | 预扫描平局降级（reconcile_stripe_prefixes 返回 None） | ✅ 根除：无需预扫描 |
| 2 | shard_header.length 被无条件信任 | ✅ 根除：长度来自 authenticated Catalog |
| 3 | 单卷偏移漂移（增量偏移追踪） | ✅ 根除：绝对偏移计算 |
| 4 | 256MB OOM 注入 | ✅ 根除：MAX_SHARD_SIZE 边界检查 |

### 7.3 保留 reconcile_stripe_prefixes

`reconcile_stripe_prefixes` 从读取管线移除，但保留在 `repair.rs` 中。修复场景下 Catalog 可能不可信（正在修复的 archive），仍需预扫描作为降级路径。

---

## 8. 恢复模块重写

### 8.1 RecoveryManager 改为 manifest 驱动

```rust
pub struct RecoveryManager {
    // v8.1: archive_path: PathBuf（单文件）
    // v8.2: 多卷感知
    volume_paths: Vec<PathBuf>,
}

impl RecoveryManager {
    pub async fn recover(&self) -> Result<RecoveryState> {
        // 1. 读取所有 volume 的 Footer
        let footers = self.read_all_footers().await?;

        // 2. 读取所有 volume 的 A/B Manifest Slot
        let manifests = self.read_all_manifest_slots(&footers).await?;

        // 3. 选择最高公共有效 epoch
        //    "公共" = 所有 volume 都成功解密的最高 epoch
        let target_epoch = self.select_common_epoch(&manifests)?;
        let manifest = &manifests[target_epoch];

        // 4. 验证 volume_states 矩阵对齐
        self.verify_matrix_alignment(&manifest.volume_states)?;

        // 5. 设置 committed_horizon（逻辑掩码，不物理截断）
        Ok(RecoveryState {
            committed_horizon: manifest.committed_horizon,
            volume_states: manifest.volume_states.clone(),
            epoch_id: manifest.epoch_id,
        })
    }
}
```

### 8.2 committed_horizon 执行策略

**单一执行点**: committed_horizon 在 `VolumeReader` 层强制执行，而非分散在多处：

```rust
impl VolumeReader {
    /// 所有读取操作经过此方法，强制 committed_horizon 边界
    pub async fn read_bounded(&self, offset: u64, len: u32) -> Result<Bytes> {
        if offset + len as u64 > self.committed_horizon {
            return Err(EraError::BeyondCommitHorizon { offset, horizon: self.committed_horizon });
        }
        self.read_at(offset, len).await
    }
}
```

**不自动 zero-fill**: 超出 committed_horizon 的数据保留在磁盘上（取证能力）。物理清理作为显式 `repair`/`compact` 操作。

### 8.3 删除的死代码

- `RecoveryManager::truncate_to_checkpoint()` — 当前是死代码（生产零调用），且仅操作单文件
- 读取管线中的 `reconcile_stripe_prefixes` 调用 — 移至 repair.rs


---

## 9. 写入协议（Finalize 路径）

### 9.1 完整的 finalize 写入顺序

```
步骤 1: 写入最终数据块（如有）
步骤 2: 写入 Catalog（含 block_locations）到所有 volume
步骤 3: 写入 Index 到所有 volume（全副本冗余）
步骤 4: 写入最终 Checkpoint（Writer 状态快照）
步骤 5: 构建 ArchiveManifest
         - epoch_id = previous_epoch + 1
         - committed_horizon = 当前 data_end_offset
         - volume_states = 各卷 tail_offset
         - catalog_commitment = blake3::keyed_hash("ERA-CAT-COMMIT-v1_______", &catalog_plaintext)
         - index_commitment = blake3::keyed_hash("ERA-IDX-COMMIT-v1_______", &index_plaintext)
步骤 6: AEAD 加密 manifest → 写入非活跃 A/B Slot（所有 volume）
步骤 7: fdatasync()（所有 volume）
步骤 8: 写入 Backup Header（所有 volume）
步骤 9: 写入 Primary Footer（所有 volume）
步骤 10: 写入 Backup Footer（所有 volume）
步骤 11: fdatasync()（所有 volume）
```

### 9.2 崩溃安全分析

| 崩溃点 | 状态 | 恢复策略 |
|--------|------|---------|
| 步骤 1-4 之间 | 数据/Catalog/Index 部分写入 | Checkpoint 恢复（现有机制） |
| 步骤 6（manifest 写入中） | Slot 撕裂写入 | AEAD 解密失败 → 使用另一个 Slot |
| 步骤 7 之后、步骤 9 之前 | manifest 已提交，Footer 未更新 | 旧 Footer 仍有效 → 旧 manifest Slot 仍可用。新 manifest 被忽略（Footer 未指向新的 backup_header_offset） |
| 步骤 9 之后、步骤 11 之前 | Footer 部分写入 | Backup Footer（步骤 10）或旧 Footer 恢复 |
| 步骤 11 之后 | 完全提交 | 正常读取 |

**关键不变量**: Footer 是最终提交锚点。任何在 Footer 提交之前的崩溃都不会改变 archive 的可见状态。

---

## 10. A/B Slot 恢复协议

### 10.1 单卷恢复

```rust
async fn load_manifest_from_volume(
    reader: &VolumeReader,
    key_session: &KeySession,
    volume_key: &VolumeKey,
) -> Result<Option<ArchiveManifest>> {
    let footer = reader.footer().ok_or(EraError::NoFooter)?;
    let bh_offset = footer.backup_header_offset();

    // 计算 Slot 位置
    let slot_b_offset = bh_offset - MANIFEST_SLOT_SIZE;
    let slot_a_offset = bh_offset - 2 * MANIFEST_SLOT_SIZE;

    // 读取两个 Slot
    let slot_a_bytes = reader.read_raw(slot_a_offset, MANIFEST_SLOT_SIZE as u32).await.ok();
    let slot_b_bytes = reader.read_raw(slot_b_offset, MANIFEST_SLOT_SIZE as u32).await.ok();

    // 尝试 AEAD 解密
    let manifest_key = derive_manifest_key(key_session, volume_key)?;
    let manifest_a = slot_a_bytes.and_then(|b| decrypt_manifest(&manifest_key, &b).ok());
    let manifest_b = slot_b_bytes.and_then(|b| decrypt_manifest(&manifest_key, &b).ok());

    // 选择最高有效 epoch
    match (manifest_a, manifest_b) {
        (Some(a), Some(b)) => Ok(Some(if a.epoch_id >= b.epoch_id { a } else { b })),
        (Some(a), None) => Ok(Some(a)),
        (None, Some(b)) => Ok(Some(b)),
        (None, None) => Ok(None), // 旧格式 archive，无 manifest
    }
}
```

### 10.2 多卷恢复

```rust
async fn load_manifest_multi_volume(
    readers: &[VolumeReader],
    key_session: &KeySession,
    volume_keys: &[VolumeKey],
) -> Result<Option<ArchiveManifest>> {
    let mut per_volume_manifests: Vec<Vec<ArchiveManifest>> = Vec::new();

    for (reader, vk) in readers.iter().zip(volume_keys) {
        let mut vol_manifests = Vec::new();
        if let Some(manifest) = load_manifest_from_volume(reader, key_session, vk).await? {
            vol_manifests.push(manifest);
        }
        per_volume_manifests.push(vol_manifests);
    }

    // 收集所有候选 epoch（所有 volume 的 manifest epoch 的交集）
    let total_volumes = readers.len();
    let mut epoch_counts: HashMap<u32, usize> = HashMap::new();
    for vol_manifests in &per_volume_manifests {
        for m in vol_manifests {
            *epoch_counts.entry(m.epoch_id).or_default() += 1;
        }
    }

    // 选择最高公共 epoch（所有 volume 都成功解密的最高 epoch）
    let common_epochs: Vec<u32> = epoch_counts
        .into_iter()
        .filter(|(_, count)| *count == total_volumes)
        .map(|(epoch, _)| epoch)
        .collect();

    if common_epochs.is_empty() {
        return Err(EraError::MatrixInconsistency(
            "No common manifest epoch across all volumes".into()
        ));
    }

    let target_epoch = *common_epochs.iter().max().unwrap();

    // 关键：从每个 volume 的候选中选择 target_epoch 对应的 manifest
    let selected: Vec<ArchiveManifest> = per_volume_manifests
        .iter()
        .filter_map(|vol_manifests| {
            vol_manifests.iter().find(|m| m.epoch_id == target_epoch).cloned()
        })
        .collect();

    // 内容一致性验证：所有 volume 的 manifest 内容字段必须完全一致
    // 防止 AEAD 恰好通过但内容被篡改的极端情况
    let first = &selected[0];
    for m in &selected[1..] {
        if m.committed_horizon != first.committed_horizon
            || m.catalog_commitment != first.catalog_commitment
            || m.index_commitment != first.index_commitment
        {
            return Err(EraError::ManifestInconsistency(
                "Manifest content differs across volumes for same epoch".into()
            ));
        }
        // volume_states 可以不同（每个 volume 有自己的 tail_offset）
        // 但 volume_states 的 volume_id 必须一一对应
        if m.volume_states.len() != first.volume_states.len() {
            return Err(EraError::ManifestInconsistency(
                "Volume state count differs across manifests".into()
            ));
        }
    }

    // 返回第一个（所有 volume 的 manifest 内容一致，volume_states 互补）
    Ok(Some(first.clone()))
}
```

---

## 11. 向后兼容性

### 11.1 版本检测

**问题**: 规范初稿使用 `backup_header_offset > data_end_offset + 8192` 检测 v8.2，存在边界条件风险：
- v8.1 固定大小分卷时，`pad_to_size` 可能恰好留下 8192 字节 padding
- 此时 `backup_header_offset - data_end_offset == 8192`，被误判为 v8.2

**正确检测策略**: 使用 **SuperHeader magic bytes** 升级（HEADER_VERSION 保持不变，magic 升级）：

```rust
// v8.1 magic: "ERA\x08\x01\x00\x00\x00" (header.rs:21)
// v8.2 magic: "ERA\x08\x02\x00\x00\x00" （仅第 4 字节从 0x01 变为 0x02）
pub const MAGIC: [u8; 8] = [0x45, 0x52, 0x41, 0x08, 0x02, 0x00, 0x00, 0x00];
```

| 格式 | 检测方式 | 行为 |
|------|---------|------|
| v8.1（无 manifest） | magic[4] == 0x01 | 回退到预扫描模式（兼容性代码） |
| v8.2（有 manifest） | magic[4] == 0x02 | 使用 manifest 驱动的读取路径 |

**为什么不用 FOOTER_VERSION/HEADER_VERSION**: 
- `FOOTER_VERSION` 保持 1（Footer 结构零修改）
- `HEADER_VERSION` 保持 3（SuperHeader 的 protobuf 结构不变，仅 magic bytes 升级）
- magic bytes 升级是最小、最可靠的格式版本检测方式
- 无需修改任何现有解析逻辑（magic check 已是第一验证步骤）

### 11.2 迁移路径

- **新 archive**: 自动使用 v8.2 布局（含 manifest slots）
- **旧 archive 读取**: 检测到无 manifest → 回退到预扫描模式
- **旧 archive 升级**: `repack` 命令自动升级到 v8.2 格式

---

## 12. 威胁模型声明

本重构解决的是**崩溃一致性**和**外部篡改检测**，明确声明以下边界：

| 威胁 | 能力 | 说明 |
|------|------|------|
| 意外损坏（bit rot） | ✅ 检测 | AEAD + catalog/index commitment |
| 外部攻击者篡改（无 MK） | ✅ 阻止 | AEAD 认证 + commitment 验证 |
| 崩溃后矩阵撕裂 | ✅ 恢复 | A/B Slot + volume_states 对齐 |
| 崩溃后元数据丢失 | ✅ 保留 | committed_horizon 逻辑掩码 |
| 内部攻击者（有 MK） | ❌ 无防御 | 需要 HSM/审计日志（超出范围） |
| 存储层回滚 | ❌ 无检测 | 需要外部单调性锚点（TPM/可信时间戳，超出范围） |

---

## 13. 实施路线

### Phase 1: 基础结构（第 1-2 周）

1. 定义 `ArchiveManifest`、`VolumeStateEntry` protobuf 结构
2. 在 era-crypto 添加 `derive_manifest_key()` + manifest AEAD 加密/解密
3. 在 Catalog 中添加 `block_locations: Vec<BlockLocation>`
4. 更新 `TRAILER_RESERVED` 常量（修复 v8.1 的 128B 预留 bug）
5. 更新 `volume_can_fit` 和 `write_canonical_block` 的空间检查

### Phase 2: 写入管线（第 2-3 周）

1. 实现 A/B Slot 写入逻辑（manifest 序列化 → AEAD 加密 → 写入固定 Slot）
2. 修改 `VolumeWriter::finalize_with_catalog()` 的写入顺序（manifest → backup header → footer）
3. 在 `VolumePool::finalize_with_catalogs()` 中收集 per-volume `tail_offset`
4. 计算 `catalog_commitment` + `index_commitment`
5. 实现 Index 全副本冗余写入

### Phase 3: 读取管线（第 3-4 周）

1. 实现 `load_manifest_from_volume()` + `load_manifest_multi_volume()`
2. 修改 `ArchiveReader::open()` — 加载 manifest → 验证 commitment → 设置 committed_horizon
3. 重构 `SessionErasureBlockIterator` — 删除预扫描，使用 `catalog.block_locations` 绝对偏移
4. 在 `VolumeReader` 添加 `read_bounded()` 强制 committed_horizon
5. 添加 v8.1 兼容性回退路径

### Phase 4: 恢复模块（第 4-5 周）

1. 重写 `RecoveryManager` 为多卷感知 + manifest 驱动
2. 实现公共 epoch 选择 + 矩阵对齐验证
3. 删除 `truncate_to_checkpoint()` 死代码
4. 从读取管线移除 `reconcile_stripe_prefixes`（保留在 repair.rs）

### Phase 5: 测试与审计（第 5-6 周）

1. **Manifest 完整性测试**: MAC 伪造、commitment 篡改、epoch 回退
2. **A/B Slot 测试**: 单 Slot 损坏回退、双 Slot 损坏优雅降级、撕裂写入恢复
3. **多卷一致性测试**: Volume 0 崩溃后恢复、矩阵条带对齐验证
4. **偏移雪崩测试**: 损坏中间 block 的 shard header → 验证后续 block 仍可定位
5. **向后兼容测试**: v8.1 archive 读取、v8.1 → v8.2 repack 升级
6. **空间检查测试**: 验证 TRAILER_RESERVED 修复（不再出现卷大小超标）

**预估总工时**: ~26 天（5.5 周）

---

## 附录 A: 与原方案的差异汇总

| 维度 | 原方案 | 本规范 | 原因 |
|------|--------|--------|------|
| 认证方式 | `manifest_mac` (HMAC) | AEAD 加密 | 与现有架构一致，提供机密性 |
| 完整性承诺 | `root_commitment = Blake3(Cat \|\| Idx)` | 拆分为 `catalog_commitment` + `index_commitment`（域分离 keyed hash） | 防歧义攻击，支持部分验证 |
| 存储方案 | A/B Slot（细节不足） | A/B Slot（固定 4096B，位于 Backup Header 之前） | Footer 语义不变，确定性偏移 |
| Footer 修改 | 未明确 | **零修改**（FOOTER_VERSION 保持 1） | 通过 backup_header_offset 隐式检测 |
| Manifest 位置 | 未明确 | Backup Header 之前的固定区域 | Footer 保持 volume 终止标记语义 |
| Index 冗余 | 未涉及 | 全副本冗余（与 Catalog 相同） | 消除 Volume 0 单点故障 |
| Checkpoint 关系 | 未明确 | 严格职责分离（Checkpoint=Writer 状态，Manifest=Archive 状态） | 避免职责膨胀 |
| 防回滚 | 隐含声称 | 明确声明不具备（需外部锚点） | 诚实的威胁模型 |

## 附录 B: 与分析报告的差异汇总

| 维度 | 分析报告推荐 | 本规范 | 原因 |
|------|-------------|--------|------|
| 存储方案 | Append-only Manifest Log | A/B Slot | Append-only 引入双写原子性问题和 stale tail pointer |
| Footer 修改 | 新增 manifest_tail_offset/epoch | **零修改** | 确定性偏移计算，无需 Footer 字段 |
| epoch_id 防回退 | 声称不需要 | 明确声明 epoch 仅用于撕裂选择 | 分析报告自相矛盾（Blake3 无密钥） |
| 性能提升估算 | ~2x | ~1.1-1.3x | 瓶颈是 I/O 和 AEAD，非偏移计算 |
| Compact 逻辑 | 不设计 | 不适用（A/B Slot 固定大小） | A/B Slot 无增长问题 |

---

*规范完成时间: 2026-04-19*
*验证方法: 4 路并行代码库交叉验证 + 2 轮 Oracle 密码学架构咨询*
