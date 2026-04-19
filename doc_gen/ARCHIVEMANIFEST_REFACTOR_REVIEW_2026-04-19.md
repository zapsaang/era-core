# ArchiveManifest 重构方案独立评审报告

**评审日期**: 2026-04-19
**评审对象**: `docs/ArchiveManifestRefactor.md`（重构方案）+ `doc_gen/ARCHIVEMANIFEST_REFACTOR_ANALYSIS_2026-04-19.md`（分析报告）
**评审方法**: 4 路并行代码库交叉验证 + Oracle 密码学架构咨询
**评审范围**: 方案正确性、分析报告准确性、密码学设计合理性、架构替代方案

---

## 执行摘要

两份文档整体质量较高，方向正确。重构方案识别了真实存在的架构漏洞，分析报告的代码引用经交叉验证全部准确。但两份文档均存在需要修正的设计缺陷：

| 维度 | 重构方案 | 分析报告 |
|------|---------|---------|
| **漏洞识别** | ✅ 准确 | ✅ 准确，代码引用全部验证通过 |
| **密码学设计** | ⚠️ `manifest_mac` 应改用 AEAD | ⚠️ 未质疑 HMAC 引入的必要性 |
| **存储方案** | ⚠️ A/B Slot 方向正确但细节不足 | ❌ Append-only Log 引入新的故障模式 |
| **防回滚声明** | ❌ 未明确威胁模型 | ❌ 内部自相矛盾 |
| **root_commitment** | ⚠️ 简单拼接存在歧义攻击风险 | ⚠️ 未识别此问题 |
| **Index 可用性** | 未涉及 | ✅ 正确识别 Volume 0 单点故障 |

**核心结论**: 重构方向正确，但密码学实现方案需要修正。推荐使用 AEAD 加密 manifest（而非 MAC-only），使用 A/B Slot（而非 Append-only Log），并将 root_commitment 改为域分离的组件哈希。

---

## 第一部分：代码库事实验证

以下为 4 路并行 explore agent 对分析报告中关键声明的交叉验证结果。

### 1.1 已验证为准确的声明

| # | 声明 | 验证结果 | 证据位置 |
|---|------|---------|---------|
| 1 | Catalog hash 计算后未持久化到 Footer | ✅ 准确 | writer.rs:2601 计算 hash，传入 UniqueChunk，但 Footer 仅存储 block_id/offset/size |
| 2 | Footer Blake3 仅覆盖自身 96 字节 | ✅ 准确 | footer.rs:191-203, `FOOTER_SIZE - FOOTER_CHECKSUM_SIZE = 96` |
| 3 | Footer 存储明文 catalog/index 指针 | ✅ 准确 | footer.rs:62-95, 无加密层 |
| 4 | RecoveryManager 仅操作单文件 | ✅ 准确 | recovery.rs:165-171 仅持有 `archive_path: PathBuf` |
| 5 | 预扫描 prefix_copies 存在 | ✅ 准确 | block_iter.rs:1112-1184 |
| 6 | reconcile_stripe_prefixes 平局返回 None | ✅ 准确 | erasure_scan.rs:34-42 |
| 7 | 平局时回退到未验证的 shard_header.length | ✅ 准确 | block_iter.rs:1280 |
| 8 | Index 仅写入 Volume 0 | ✅ 准确 | writer.rs:1931 `get_writer_mut(0)`，其余卷 `(0,0,0)` |
| 9 | Checkpoint 链遍历未实现 | ✅ 准确 | checkpoint.rs:808 注释明确说明 |
| 10 | write_canonical_block 仅预留 128B | ✅ 准确 | volume/writer.rs:440 `FOOTER_SIZE`，而 finalize 需要 4224B |
| 11 | BlockLocation 已存在且包含所需字段 | ✅ 准确 | era-common/types/block.rs:99-111 |
| 12 | 生产代码无 HMAC 使用 | ✅ 准确 | `derive_checkpoint_key` 仅在测试中调用 |

### 1.2 需要修正的声明

| # | 声明 | 修正 |
|---|------|------|
| 1 | "catalog_hash 计算后未存储"（分析报告 1.1） | **部分不准确**。hash 存储在 UniqueChunk 内部（随 catalog_block 写入磁盘），但确实不在 Footer 中独立可验证。应表述为"catalog_hash 未在 Footer 或任何独立可验证位置持久化" |
| 2 | "epoch_id 防回退不需要"（分析报告 6.4） | **错误**。报告自相矛盾：一方面声称 Footer Blake3 保护 manifest_tail_offset，另一方面承认攻击者可重算 Blake3。见第三部分详细分析 |

---

## 第二部分：重构方案评审

### 2.1 ArchiveManifest 结构设计

**原方案**:
```rust
pub struct ArchiveManifest {
    pub epoch_id: u64,
    pub committed_horizon: u64,
    pub volume_states: Vec<VolumeStateEntry>,
    pub root_commitment: [u8; 32],    // Blake3(Catalog_bytes || Index_bytes)
    pub manifest_mac: [u8; 32],       // HMAC(MK_derived_key, manifest_bytes)
}
```

#### 问题 1: `manifest_mac` — 应使用 AEAD 而非 HMAC

**当前代码库的密码学架构**:
- 所有元数据（Catalog、Checkpoint、Index）均使用 XChaCha20-Poly1305 AEAD 加密
- 每个 block 通过 HKDF 派生独立密钥，AAD 绑定 archive_id‖epoch_id‖volume_index‖block_id
- 生产代码中**零 HMAC 使用**（`derive_checkpoint_key` 仅存在于测试中）

**引入 HMAC 的问题**:
1. **架构不一致**: 在纯 AEAD 架构中引入 HMAC 增加认知负担，无安全收益
2. **泄露元数据**: MAC-only 意味着 manifest 明文存储，泄露 volume 拓扑、提交状态、epoch 历史
3. **多余的密钥派生**: 需要新增 HMAC 密钥派生路径，而 AEAD 已提供认证+加密

**推荐**: 将 manifest 作为 AEAD 加密的 typed block（与 Catalog/Checkpoint 相同模式），使用专用 HKDF 域 `b"ERA_MANIFEST_v8.1"`。删除 `manifest_mac` 字段，AEAD 的 Poly1305 tag 已提供认证。

```rust
// 推荐设计：manifest 作为 AEAD 加密 block
pub struct ArchiveManifest {
    pub epoch_id: u64,
    pub committed_horizon: u64,
    pub volume_states: Vec<VolumeStateEntry>,
    pub root_commitment: [u8; 32],
    // 无 manifest_mac — AEAD Poly1305 tag 提供认证
    // 加密时使用 BlockType::Manifest + 专用 HKDF 域
}
```

**唯一例外**: 如果需要在未认证状态下读取 manifest（如工具链诊断），MAC-only 有意义。但 ERA 的读取路径始终需要先认证（解密 MK → 派生 IK → 解包 VK），因此 AEAD 是正确选择。

#### 问题 2: `root_commitment` — 简单拼接存在歧义攻击

**原方案**: `root_commitment = Blake3(Catalog_bytes || Index_bytes)`

**风险**: 简单拼接无法区分边界。攻击者可以将 Catalog 末尾的字节移动到 Index 开头（或反之），产生不同的 Catalog+Index 组合但相同的 hash。

**推荐**: 使用域分离的组件哈希：

```rust
let catalog_hash = blake3::keyed_hash(b"ERA-CATALOG-COMMIT-v1___", &catalog_bytes);
let index_hash = blake3::keyed_hash(b"ERA-INDEX-COMMIT-v1_____", &index_bytes);
let root_commitment = blake3::hash(
    &[b"ERA-MANIFEST-ROOT-v1", catalog_hash.as_bytes(), index_hash.as_bytes()].concat()
);
```

**额外考虑**: 应对**明文**（解密后的规范序列化字节）计算承诺，而非密文。原因：
- 密文承诺可在解密前验证，但语义绑定弱（不同 nonce 产生不同密文）
- 明文承诺提供更强的语义绑定（相同逻辑内容 = 相同承诺）
- 代价是需要先解密再验证，但 ERA 读取路径本就需要解密

#### 问题 3: Index 绑定到 root_commitment 的可用性风险

**当前事实**: Index 仅写入 Volume 0（已验证）。

**风险**: 如果 root_commitment 覆盖 Index，而 Volume 0 损坏导致 Index 丢失，则 root_commitment 验证失败 → 整个 archive 被判定为不可信，即使数据和 Catalog 完好。

**推荐**: 两种策略（二选一）：
1. **复制 Index 到所有 volume**（与 Catalog 相同的全副本冗余），然后绑定到 root_commitment
2. **将 Index 排除出 root_commitment**，仅绑定 Catalog。Index 作为可选的性能优化结构，丢失时可从 Catalog 重建

推荐策略 1（复制 Index），因为 Index 通常 < 100MB，全副本冗余的空间开销可接受。

### 2.2 Double-Buffer Commit（A/B Slot）

原方案的 A/B Slot 方向正确，但缺少关键细节：

**需要补充的设计决策**:

1. **存储位置**: A/B Slot 应放在 volume 末尾的固定保留区域（Footer 之后），而非 SuperHeader 内（4096B 空间不足）
2. **Slot 大小**: 需要固定最大 manifest 大小（如 4KB），以支持固定偏移寻址
3. **多卷复制**: A/B Slot 必须复制到所有 volume（与 Catalog 相同），否则 manifest 本身成为单点故障
4. **恢复逻辑**: 读取所有 volume 的 A/B Slot → 验证 AEAD → 选择最高**公共** epoch_id（所有 volume 都有的最高 epoch）

---

## 第三部分：分析报告评审

### 3.1 Append-only Log vs A/B Slot — 分析报告的推荐有误

分析报告（第 6.4 节）推荐 Append-only Manifest Log 替代 A/B Slot。这个推荐存在严重问题。

**Append-only Log 引入的新故障模式**:

1. **双写原子性问题**: Append-only Log 需要两步发布：(a) 追加 ManifestEntry block，(b) 更新 Footer 的 tail 指针。如果崩溃发生在 (a) 和 (b) 之间，ManifestEntry 已写入但 Footer 不指向它。恢复时需要扫描 Data Region 寻找孤儿 entry — 这比 A/B Slot 的单步写入更复杂。

2. **Stale tail pointer**: Footer 的 `manifest_tail_offset` 是无密钥的（Blake3 checksum 无密钥）。攻击者可以：
   - 修改 `manifest_tail_offset` 指向旧的 ManifestEntry
   - 重算 Footer Blake3 checksum
   - 旧 ManifestEntry 的 AEAD/MAC 仍然有效
   - 结果：成功回滚到旧状态

3. **A/B Slot 的优势**: 不需要 Footer 中的 tail 指针。恢复时直接读取两个固定位置的 Slot，验证 AEAD，选择最高 epoch。无需信任任何无密钥指针。

**结论**: A/B Slot 是更安全的选择。Append-only Log 的"历史保留"优势在 ERA 场景下价值有限（每个 archive 通常只有 1 个 manifest entry）。

### 3.2 epoch_id 防回滚 — 分析报告自相矛盾

分析报告第 6.4 节声称"不需要 epoch_id 防回退机制"，理由是：
1. Append-only log 物理单调性
2. Footer Blake3 checksum 保护 manifest_tail_offset
3. Entry MAC 防伪造

但同一节又承认："攻击者也可以重新计算 Footer checksum（因为 Blake3 没有密钥）"。

**这是直接矛盾**: 如果 Footer checksum 无密钥，攻击者可以：
1. 截断文件到旧的 ManifestEntry
2. 重写 Footer 的 manifest_tail_offset 指向旧 entry
3. 重算 Footer Blake3 checksum
4. 旧 entry 的 MAC/AEAD 仍然有效（它是合法生成的）

**正确的威胁模型声明**: epoch_id 在 A/B Slot 中用于**撕裂写入选择**（crash 后选择完整的 slot），而非防回滚。真正的防回滚需要**外部单调性锚点**（如可信时间戳、用户维护的计数器、TPM 单调计数器）。ERA 当前不具备此能力，文档应诚实声明这一限制。

### 3.3 committed_horizon 逻辑掩码 — 基本正确但需防御加固

分析报告对 committed_horizon 替代物理截断的分析基本正确。补充评估：

**正确性**: committed_horizon 作为逻辑掩码是合理的存储引擎设计。物理截断（`file.set_len()`）是破坏性操作，逻辑掩码保留了取证能力。

**风险**: 如果 committed_horizon 的执行点分散在多处代码中，未来的 bug 可能导致读取超出边界的损坏数据。

**推荐**:
- committed_horizon 必须在**单一低层位置**强制执行（如 `VolumeReader` 或 block iteration 的入口点）
- **不应**在恢复时自动 zero-fill 超出 horizon 的区域（保留取证能力）
- 物理清理（zero-fill/truncate）应作为显式的 `repair`/`compact` 操作，而非自动恢复行为

### 3.4 性能估算 — 过于乐观

分析报告声称"理论吞吐提升约 2 倍"。这个估算过于乐观：

- 预扫描的 I/O 开销主要是**顺序读取**（读取 header prefix），而非随机 I/O
- 消除预扫描节省的是 CPU 解析时间，而非 I/O 带宽
- 实际瓶颈是磁盘 I/O 和 AEAD 解密，不是偏移计算
- 更现实的估算：**1.1-1.3 倍**（主要收益来自代码简化而非吞吐量）

### 3.5 改造成本估算 — 基本合理

分析报告估算 32 天（6.5 周）。考虑到涉及 6 个 crate 的深层改动 + 格式版本升级 + 审计测试，这个估算合理。但如果采用本评审推荐的简化方案（AEAD 替代 HMAC、A/B Slot 替代 Append-only Log），可减少约 20% 工时（约 26 天）。

---

## 第四部分：优化方案

基于以上分析，提出以下优化建议。

### 4.1 推荐的 ArchiveManifest 设计

```rust
/// Archive 的密码学认证全局状态快照
/// 作为 AEAD 加密的 typed block 存储（BlockType::Manifest）
/// 使用 HKDF 域 "ERA_MANIFEST_v8.1" 派生加密密钥
pub struct ArchiveManifest {
    /// 单调递增代 ID，用于 A/B Slot 撕裂写入选择
    pub epoch_id: u64,
    /// 逻辑提交边界（字节偏移），超出此边界的数据视为未提交
    pub committed_horizon: u64,
    /// 每卷的精确物理状态
    pub volume_states: Vec<VolumeStateEntry>,
    /// 域分离的 Catalog 内容承诺
    /// = blake3::keyed_hash("ERA-CATALOG-COMMIT-v1___", &catalog_plaintext_bytes)
    pub catalog_commitment: [u8; 32],
    /// 域分离的 Index 内容承诺（如 Index 不存在则为全零）
    /// = blake3::keyed_hash("ERA-INDEX-COMMIT-v1_____", &index_plaintext_bytes)
    pub index_commitment: [u8; 32],
    // 无 manifest_mac 字段 — AEAD Poly1305 tag 提供认证
}

pub struct VolumeStateEntry {
    pub volume_id: u32,
    /// 最后成功对齐的条带结束位置
    pub tail_offset: u64,
}
```

**与原方案的关键差异**:
1. `manifest_mac` 删除 → AEAD 提供认证
2. `root_commitment` 拆分为 `catalog_commitment` + `index_commitment` → 域分离，避免歧义攻击，支持 Index 缺失时的部分验证
3. 承诺对象为明文（解密后的规范序列化字节）→ 更强的语义绑定

### 4.2 推荐的存储方案：A/B Slot（非 Append-only Log）

```
Volume 物理布局（v8.2）:

Offset 0-4095:        Primary SuperHeader (4096 bytes)
Offset 4096-4223:     Backup Footer Gap (128 bytes)
Offset 4224+:         Data Region（数据块、Catalog、Index、Checkpoint）
Offset BH:            Backup SuperHeader (4096 bytes)
Offset BH+4096:       Primary Footer (128 bytes, FOOTER_VERSION=2)
                      - 新增: manifest_slot_a_offset: u64
                      - 新增: manifest_slot_b_offset: u64
Offset BH+4224:       Manifest Slot A (固定 4KB, AEAD 加密)
Offset BH+4224+4096:  Manifest Slot B (固定 4KB, AEAD 加密)
```

**恢复协议**:
1. 读取所有 volume 的 Slot A 和 Slot B
2. 对每个 Slot 尝试 AEAD 解密（失败 = 撕裂写入，跳过）
3. 选择所有 volume 中最高的**公共** epoch_id（所有 volume 都成功解密的最高 epoch）
4. 验证选中 epoch 的 volume_states 在矩阵意义上对齐

**写入协议**:
1. 确定当前活跃 Slot（epoch 更高的那个）
2. 将新 manifest 写入非活跃 Slot
3. `fdatasync()` 所有 volume
4. 下次读取时自动选择更高 epoch 的 Slot

### 4.3 推荐的 Catalog 扩展

复用已有的 `BlockLocation` 结构（era-common/types/block.rs:99-111）：

```rust
pub struct Catalog {
    pub entries: Vec<FileEntry>,
    /// 新增：每个 block 的物理位置，支持 O(1) 绝对偏移查询
    pub block_locations: Vec<BlockLocation>,
    pub total_size: u64,
    pub file_count: u64,
    pub dir_count: u64,
}
```

`BlockLocation` 已包含 `physical_offset`、`encrypted_size`、`shard_layout`，无需新建结构。

### 4.4 推荐的 Index 冗余策略

将 Index 从 Volume 0 单副本改为全副本冗余（与 Catalog 相同模式）：

```rust
// 当前代码（writer.rs:1931）— 仅 Volume 0
if let Some(writer) = self.pipeline.volume_mut().get_writer_mut(0) {
    builder.finalize_with_starting_block_id(writer, ...).await?;
}

// 推荐改为：写入所有 volume（类似 write_catalog_blocks_to_all）
for vol_idx in 0..volume_count {
    if let Some(writer) = self.pipeline.volume_mut().get_writer_mut(vol_idx) {
        builder.finalize_with_starting_block_id(writer, ...).await?;
    }
}
```

### 4.5 最小替代方案（如果完整重构成本过高）

如果 4-6 周的完整重构不可接受，可以考虑**最小替代方案**：扩展现有 Checkpoint 为 `ArchiveState`，携带 committed_horizon、per-volume tails 和元数据哈希。

```rust
pub struct Checkpoint {
    // ... 现有字段 ...
    // 新增：
    pub committed_horizon: u64,
    pub volume_tails: Vec<(u32, u64)>,  // (volume_id, tail_offset)
    pub catalog_commitment: [u8; 32],
    // Index commitment 可选
}
```

**优点**: 最小格式变更，复用现有 AEAD 加密路径，无需新增 A/B Slot
**缺点**: Checkpoint 职责膨胀（既是 writer 恢复状态又是 archive 完整性验证），不如独立 manifest 清晰

---

## 第五部分：威胁模型澄清

两份文档均未明确声明威胁模型，导致安全声明模糊。建议在实施前明确：

| 威胁 | 当前能力 | 重构后能力 | 需要外部锚点 |
|------|---------|-----------|-------------|
| 意外损坏（bit rot） | AEAD 检测 | AEAD + manifest 检测 | 否 |
| 外部攻击者篡改（无 MK） | AEAD 阻止 | AEAD + root_commitment 阻止 | 否 |
| 内部攻击者（有 MK） | 无防御 | 无防御 | 是（HSM/审计日志） |
| 存储层回滚 | 无检测 | **无检测**（epoch 仅用于撕裂选择） | 是（TPM/可信时间戳） |
| 崩溃后矩阵撕裂 | 无恢复 | A/B Slot + volume_states 恢复 | 否 |
| 崩溃后元数据丢失 | 物理截断销毁 | committed_horizon 逻辑掩码保留 | 否 |

**关键声明**: 重构解决的是**崩溃一致性**和**外部篡改检测**，而非**回滚抵抗**。文档应诚实反映这一边界。

---

## 第六部分：总结与建议

### 6.1 对重构方案的建议

1. ✅ 保留 ArchiveManifest 的核心设计（epoch_id、committed_horizon、volume_states）
2. ❌ 删除 `manifest_mac`，改用 AEAD 加密 manifest block
3. ❌ 将 `root_commitment` 拆分为域分离的 `catalog_commitment` + `index_commitment`
4. ✅ 保留 A/B Slot 方案，补充多卷复制和公共 epoch 选择逻辑
5. ➕ 新增 Index 全副本冗余
6. ➕ 明确威胁模型，诚实声明不具备回滚抵抗能力

### 6.2 对分析报告的建议

1. ✅ 代码引用全部准确，质量优秀
2. ❌ 撤回 Append-only Log 推荐，改为支持 A/B Slot
3. ❌ 修正 epoch_id 防回滚的自相矛盾声明
4. ⚠️ 下调性能提升估算（2x → 1.1-1.3x）
5. ⚠️ 修正 "catalog_hash 计算后未存储" 的表述精度

### 6.3 实施优先级

| 优先级 | 任务 | 预估工时 |
|--------|------|---------|
| P0 | 定义 ArchiveManifest 结构 + AEAD 加密路径 | 3 天 |
| P0 | 实现 A/B Slot 存储（含多卷复制） | 5 天 |
| P0 | Catalog 扩展（添加 block_locations） | 3 天 |
| P1 | 读取管线重构（绝对偏移替代预扫描） | 5 天 |
| P1 | 恢复模块重写（manifest 驱动） | 4 天 |
| P2 | Index 全副本冗余 | 2 天 |
| P2 | 审计测试套件 | 8 天 |
| **总计** | | **~26 天 (5.5 周)** |

---

*评审完成时间: 2026-04-19*
*评审方法: 4 路并行代码库交叉验证（explore agents）+ Oracle 密码学架构咨询*
*声明: 所有结论均有源码证据或密码学原理支撑。代码引用已通过独立 agent 交叉验证。*
