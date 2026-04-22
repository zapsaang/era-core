# PHASE 1: 已采纳修正汇总

**版本**: 1.0  
**日期**: 2026-04-21  
**来源**: Oracle 评审 + 自我反思  

---

## 修正列表

### 1. AEAD 合同修正

**问题**: DESIGN_SPEC 要求 "所有副本内容完全一致（相同 block_id、相同 ciphertext）"，但现有代码的 AAD 绑定包含 `volume_index`。如果 AAD 不同，Poly1305 tag 就不同，密文不可能完全相同。

**修正**: 放弃 "相同密文" 要求，采用**方案 B**：
- 每卷使用不同的 nonce：在 `derive_nonce_with_context` 中混入 `volume_index`
- AAD 仍绑定 `volume_index`，保持完整上下文绑定
- 各卷密文**长度相同**（`plaintext.len() + 16`），但**内容不同**

**影响文件**: `aead_context.rs`（nonce 派生）

---

### 2. 承诺验证修正

**问题**: ROADMAP §4.2 从 `catalog.to_bytes()` 重新计算承诺——如果 protobuf 解析/序列化会规范化未知/重复字段，篡改后的数据仍可能通过验证。

**修正**: 用**解密后的原始明文 bytes**（解析前）计算承诺。

```rust
// Phase 3 正确流程
let catalog_plaintext = decrypt_catalog(&encrypted)?;  // 原始 bytes
verify_catalog_commitment(&catalog_plaintext, &manifest.catalog_commitment)?;
let catalog = Catalog::from_bytes(&catalog_plaintext)?;  // 解析在后
```

**影响文件**: `era-engine/src/reader.rs`（Phase 3）

---

### 3. finalize_sequence 重放保护范围

**问题**: Oracle 指出 finalize_sequence 仅在旧副本和新副本共存时有效，无法检测"所有卷同时被替换为旧版本"的全归档回滚。

**修正**: 承认此限制，将全归档回滚检测延后到后续版本。

**当前保护范围**:
- ✅ 防止部分卷回滚（崩溃后混合世代场景）
- ✅ 防止旧 Manifest 被注入到新 archive 中
- ⏳ 全卷同时回滚检测（延后）

---

### 4. Manifest 检测逻辑

**问题**: `has_manifest()` 使用 `manifest_block_id > 0 && manifest_offset > 0`，但 `BlockId::new(0)` 是有效的，block 0 的 Manifest 会被误判为不存在。

**修正**: 使用 `manifest_offset != 0` 判断存在性。

```rust
pub fn has_manifest(&self) -> bool {
    self.manifest_offset != 0  // block_id 允许为 0
}
```

**影响文件**: `era-volume/src/footer.rs`

---

### 5. Typed-block 类型检查

**问题**: Phase 3 加载 Manifest/Catalog/Index 时应该验证 BlockType，防止类型混淆攻击。

**修正**: 使用 `read_typed_block()` 而非 `read_block()`，并显式拒绝意外类型。

```rust
let (block_type, encrypted) = reader.read_typed_block(&location).await?;
if block_type != BlockType::Manifest {
    return Err(EraError::Security("Manifest block type mismatch".into()));
}
```

**影响文件**: `era-engine/src/reader.rs`（Phase 3）

---

### 6. Index 全副本冗余工作量

**问题**: 当前索引只在 volume 0 写入（`era-index/src/builder.rs`），全副本冗余需要 API 重新设计，工作量被低估。

**修正**: 在 Phase 2 规划中标注此风险，预留额外时间。

**预估额外工作量**: ~2-3 天（IndexBuilder 需要支持多卷写入）

---

### 7. 承诺计算位置

**问题**: 原计划放在 `era-common`，但 `era-common/Cargo.toml` 没有 `blake3` 依赖。

**修正**: 放在 `era-crypto/src/commitment.rs`（已有 `blake3` 依赖）。

**导出路径**: `era_crypto::commitment::*`

---

### 8. block_locations 纠删码语义

**问题**: DESIGN_SPEC 4.2 说 "block_locations 长度 = stripe_count × data_shards"，但 `BlockLocation` 的 `shard_layout::Erasure` 已包含全部 shard 元数据。

**修正**: `block_locations` 长度为**逻辑 block 数量**（非纠删码 = block_count，纠删码 = stripe_count）。

```
block_locations[i] = BlockLocation {
    shard_layout: ShardLayout::Erasure {
        info,           // data_shards, parity_shards, shard_size
        shard_offsets,  // 所有 shard 的偏移
        shard_volumes,  // 所有 shard 的卷号
    }
}
```

---

### 9. sequence_number vs finalize_sequence 关系

**问题**: Footer 已有单调计数器 `sequence_number`，新增 `finalize_sequence` 无不变量约束会造成歧义。

**修正**: **两者独立**（选项 1）。

```
Footer.sequence_number     = volume 级别的物理写入计数（每次写入数据块递增）
Manifest.finalize_sequence = archive 级别的逻辑提交计数（每次 finalize 递增）
```

**不变量**:
- `finalize_sequence >= 1`（初始值）
- `sequence_number >= finalize_sequence`（通常 sequence 增长更快，因为非 finalize 写入也递增）

---

### 10. Protobuf 字段编号

**问题**: 原计划将 `block_locations` 作为字段 2，导致 `total_size`/`file_count`/`dir_count` 重新编号。

**修正**: `block_locations` 作为**字段 5**（新增字段），保持现有字段编号不变。

```protobuf
message Catalog {
  repeated FileEntry entries = 1;
  uint64 total_size = 2;      // 不变
  uint64 file_count = 3;      // 不变
  uint64 dir_count = 4;       // 不变
  repeated BlockLocation block_locations = 5;  // 新增
}
```

---

### 11. TypedBlockKind 枚举（补充）

**问题**: 代码库中不存在 `TypedBlockKind`，但 DESIGN_SPEC 大量使用。

**修正**: 在 Phase 1 中定义。

```rust
// era-common/src/types/typed_block.rs
pub enum TypedBlockKind {
    Manifest,
    Catalog,
    Index,
}
```

---

### 12. Footer checksum 兼容性优势（补充）

**问题**: 文档中未明确说明 Footer checksum 的前向兼容优势。

**修正**: 明确记录。

**事实**: Footer checksum 覆盖 raw 前 96 字节（包括 manifest 字段区域）。v8.1 reader 解析 v8.2 Footer 时 checksum **验证通过**，因为 checksum 计算不区分 reserved/manifest 字段——它只是哈希前 96 字节。

---

## 影响文档

| 修正 | PLAN.md | DATA_TYPE_CHANGES.md | INTERFACE_CONTRACT.md |
|------|---------|---------------------|----------------------|
| 1. AEAD 合同 | ✅ §3.2.7 | - | ✅ AEAD 章节 |
| 2. 承诺验证 | ✅ 注释 | - | ✅ Phase 3 流程 |
| 3. finalize_sequence | ✅ §3.6.2 | - | ✅ 不变量 |
| 4. Manifest 检测 | ✅ §3.4.4 | ✅ 兼容性矩阵 | ✅ 接口表 |
| 5. Typed-block 检查 | - | - | ✅ read_typed_block |
| 6. Index 全副本 | ✅ 风险 | - | ✅ 风险标注 |
| 7. 承诺位置 | ✅ §3.5.3 | ✅ 常量位置 | ✅ 概述图 |
| 8. block_locations | ✅ §3.3.4 | ✅ 语义 | ✅ 契约保证 |
| 9. sequence 关系 | ✅ §3.6.2 | - | ✅ 不变量 |
| 10. Protobuf | ✅ §3.3.4 | ✅ schema | - |
| 11. TypedBlockKind | ✅ §3.1.4 | - | ✅ 类型章节 |
| 12. Footer checksum | ✅ §3.4.5 | ✅ 兼容性矩阵 | - |

---

*文档生成时间: 2026-04-21*  
*对应: REFLECTION.md + Oracle 评审报告*
