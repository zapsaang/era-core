# PHASE 1 规划反思与修正建议

**版本**: 1.0  
**日期**: 2026-04-21  
**目的**: 审查 PLAN.md 的完整性、合理性和可执行性

---

## 执行摘要

经过对代码库的深度复查，发现 **7 处需要修正或补充**，其中 **2 处为重要修正**（承诺计算位置、BlockLocation 转换复用），其余为细节优化。整体规划方向正确，任务分解合理。

---

## 发现的问题

### 🔴 问题 1: 承诺计算位置与依赖不匹配（重要）

**现状**:
- 规划将承诺计算放在 `era-common/src/commitment.rs`
- 但 `era-common/Cargo.toml` **没有 blake3 依赖**
- `era-crypto/Cargo.toml` **已有 blake3 依赖** (`blake3 = { workspace = true }`)
- ROADMAP.md 2.5 明确标注为 "**era-crypto**: Manifest 承诺计算"

**影响**:
- 若按规划执行，Task 1.5 会因缺少 blake3 依赖而编译失败
- 需要额外修改 `era-common/Cargo.toml` 添加 blake3，但这会扩大 L0 层的依赖面

**修正建议**:
```diff
- 位置: era-common/src/commitment.rs (新增)
+ 位置: era-crypto/src/commitment.rs (新增)
```

承诺计算函数签名保持不变，但导出路径变更为 `era_crypto::commitment::*`。

```rust
// crates/era-crypto/src/commitment.rs
use blake3::Hasher;

pub const CATALOG_COMMITMENT_DOMAIN: &[u8; 32] = b"ERA-CAT-COMMIT-v1___________";
pub const INDEX_COMMITMENT_DOMAIN: &[u8; 32] = b"ERA-IDX-COMMIT-v1___________";

pub fn compute_catalog_commitment(catalog_plaintext: &[u8]) -> [u8; 32] { ... }
pub fn compute_index_commitment(index_plaintext: &[u8]) -> [u8; 32] { ... }
```

**理由**:
1. blake3 已在 era-crypto 的依赖中，无需新增依赖
2. 密码学原语（哈希、承诺）属于 era-crypto 的职责范围
3. era-ingest 已依赖 era-crypto（查看依赖图：era-ingest → era-crypto），所有使用方都能访问

**关联修改**:
- `INTERFACE_CONTRACT.md` 中更新承诺计算的导出路径
- `PLAN.md` Task 1.5 的目标 crate 从 era-common 改为 era-crypto
- `era-crypto/src/lib.rs` 新增 `pub mod commitment;`

---

### 🟡 问题 2: BlockLocation protobuf 转换已存在（工作量高估）

**现状**:
- `PLAN.md` Task 1.3 规划了新增 BlockLocation 的 `From<&BlockLocation> for ProtoBlockLocation` 和 `TryFrom<ProtoBlockLocation> for BlockLocation`
- 但 `era-common/src/conversion.rs:216-282` **已存在完整转换**

**影响**:
- Task 1.3 预估工时 1.5 天，实际可减少至 **~1 天**
- 节省的 0.5 天可用于处理其他发现的问题

**修正建议**:
```diff
Task 1.3 工作量: 1.5 天 → 1 天
```

Catalog 的转换仍需更新（`From<&Catalog> for ProtoCatalog` 和 `TryFrom<ProtoCatalog> for Catalog`），但 BlockLocation 的转换可直接复用 `conversion.rs` 中的实现。

**Catalog 转换的 import 路径**:
```rust
// era-ingest/src/entry.rs
use era_common::proto::Catalog as ProtoCatalog;
// BlockLocation 的转换由 era-common 的 conversion.rs 自动提供
```

---

### 🟡 问题 3: Catalog block_locations 的 protobuf 字段编号策略风险

**现状**:
- 规划推荐将 `block_locations` 设为 protobuf 字段 2，导致 `total_size`/`file_count`/`dir_count` 重新编号
- 但 `era-common/tests/compact_proto_schema.rs` 等测试可能包含硬编码的 protobuf 二进制 fixture

**风险**:
- 字段编号变更会破坏任何使用旧 protobuf 二进制的测试
- 虽然 DESIGN_SPEC 声明"无需向后兼容"，但测试修复工作量可能超出预期

**修正建议**:

**方案 A（推荐）**: 保持向后兼容的字段编号
```protobuf
message Catalog {
  repeated FileEntry entries = 1;
  uint64 total_size = 2;           // 不变
  uint64 file_count = 3;           // 不变
  uint64 dir_count = 4;            // 不变
  repeated BlockLocation block_locations = 5;  // 新增字段 5
}
```

**优点**:
- 现有 protobuf 二进制 fixture 仍然有效（新增字段被忽略）
- 测试修复工作量最小
- 为未来可能的向后兼容场景保留灵活性

**缺点**:
- 字段顺序与 Rust 结构不完全一致（语义上 block_locations 应在 entries 之后）

**方案 B**: 按规划重新编号（字段 2）
- 需要审计并更新所有 protobuf 相关的测试 fixture
- 额外工作量：~0.5 天

**建议采用方案 A**，在 `DATA_TYPE_CHANGES.md` 中更新 protobuf schema。

---

### 🟡 问题 4: TypedBlockKind 抽象缺失

**现状**:
- DESIGN_SPEC 大量使用 `TypedBlockKind` 枚举（Manifest, Catalog, Index）
- 代码库中**不存在**此枚举（grep 确认无匹配）
- `load_typed_block_with_redundancy`、`verify_typed_block_redundancy` 等函数依赖此抽象

**影响**:
- Phase 3 实现多副本验证时，需要临时定义此枚举，可能导致接口不一致

**修正建议**:

在 Phase 1 中定义 `TypedBlockKind`（作为基础类型），放在 `era-common`：

```rust
// crates/era-common/src/types/typed_block.rs (新增)

/// Typed block kind for redundancy validation and repair.
/// This is a higher-level abstraction than BlockType, grouping
/// the three types of metadata blocks that are fully replicated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypedBlockKind {
    Manifest,
    Catalog,
    Index,
}

impl TypedBlockKind {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Manifest => "Manifest",
            Self::Catalog => "Catalog",
            Self::Index => "Index",
        }
    }
    
    pub fn block_type(&self) -> BlockType {
        match self {
            Self::Manifest => BlockType::Manifest,
            Self::Catalog => BlockType::Catalog,
            Self::Index => BlockType::IndexManifest,
        }
    }
}
```

**新增文件**: `crates/era-common/src/types/typed_block.rs` (~50 行)
**工作量增加**: ~0.3 天（可并入 Task 1.1 或作为独立小任务）

---

### 🟡 问题 5: EraError::VolumeSpaceExhausted 命名可能造成混淆

**现状**:
- 现有错误: `VolumeFull { volume_id: String }`
- 新增错误: `VolumeSpaceExhausted { volume: usize, required: u64, available: u64, message: String }`
- 两者语义接近，但使用场景不同

**分析**:
- `VolumeFull`: 通用场景，volume 达到配置的最大大小
- `VolumeSpaceExhausted`: 特定于 typed block 预检查，需要详细的 required/available 信息

**修正建议**:

**方案 A**: 保留两个变体，但改进命名区分度
```rust
// 保留现有（不变）
VolumeFull { volume_id: String }

// 新增变体改为更具体的名称
TypedBlockSpaceExceeded {
    volume: usize,
    required: u64,
    available: u64,
    block_kind: String,  // "Catalog"/"Index"/"Manifest"
}
```

**方案 B**: 复用现有 `VolumeFull`，扩展字段
```rust
// 破坏性变更：修改现有 VolumeFull
VolumeFull {
    volume_id: String,
    required: Option<u64>,    // None = 旧语义（无详细信息）
    available: Option<u64>,
}
```

**推荐方案 A**（非破坏性，语义清晰）。

---

### 🟢 问题 6: Footer checksum 兼容性的隐藏优势（应明确说明）

**现状**:
- Footer checksum 覆盖前 96 字节（包括 offset 60-64 和 88-96 的 reserved 区域）
- 规划中没有强调这个兼容性的重要细节

**分析**:
- v8.1 Footer 中 reserved3/reserved4 为零，checksum 覆盖这些零字节
- v8.2 Footer 中这些字段非零，checksum 覆盖这些非零字节
- **关键**: v8.1 reader 读取 v8.2 Footer 时，checksum 验证**仍然通过**（因为 checksum 计算覆盖了整个 96 字节）
- v8.1 reader 只是**忽略**这些字节的内容，按原有逻辑工作
- 这是 Footer v2 设计的一个隐藏优势：无需版本号变更即可实现前向兼容

**修正建议**:
在 `PLAN.md` Task 1.4 和 `DATA_TYPE_CHANGES.md` 的兼容性矩阵中明确说明：

```
v8.2 Footer 的 checksum 计算天然覆盖 manifest 字段区域。
v8.1 reader 解析 v8.2 Footer 时：
- checksum 验证通过（覆盖全部 96 字节）
- manifest_block_id 和 manifest_offset 被读入内存但不被使用
- reader 按 v8.1 逻辑工作，无视 manifest 存在
```

---

### 🟢 问题 7: manifest_aad 和 derive_manifest_key 函数位置未明确

**现状**:
- DESIGN_SPEC 5.1-5.2 定义了 `derive_manifest_key` 和 `manifest_aad`
- 规划中未明确这些函数的放置位置

**分析**:
- `derive_manifest_key`: 复用 `key_session.derive_block_key()`，无需新增函数
- `manifest_aad`: 需要新增，因为 AAD 构造包含 "MANIFEST" 字符串（与普通 block 不同）
- 这些函数在 Phase 2（加密）和 Phase 3（解密）中都需要

**修正建议**:

在 `era-crypto/src/aead.rs` 或新建 `era-crypto/src/manifest.rs` 中定义：

```rust
/// AAD for Manifest typed block encryption/decryption.
/// Format: archive_id ‖ epoch_id ‖ "MANIFEST" ‖ block_id
pub fn manifest_aad(archive_id: &ArchiveId, epoch_id: u32, block_id: BlockId) -> [u8; 32] {
    let mut aad = [0u8; 32];
    aad[0..16].copy_from_slice(archive_id.as_bytes());
    aad[16..20].copy_from_slice(&epoch_id.to_le_bytes());
    aad[20..28].copy_from_slice(b"MANIFEST");
    aad[28..32].copy_from_slice(&block_id.sequence().to_le_bytes());
    aad
}
```

**注意**: 这不是 Phase 1 的任务（Phase 1 只做类型定义），但应在 `INTERFACE_CONTRACT.md` 中预留接口位置，或在 Phase 1 中作为常量定义。

**更轻量的方案**: 在 Phase 1 中只定义 AAD 域常量：
```rust
// era-common/src/constants.rs 或适当位置
pub const MANIFEST_AAD_DOMAIN: &[u8] = b"MANIFEST";
```

---

## 次要发现

### 8. ArchiveManifest 的 serde derive

DESIGN_SPEC 要求 `#[derive(Debug, Clone, Serialize, Deserialize)]`。`era-common` 已有 `serde` 依赖，直接添加 derive 即可，无需额外依赖。

### 9. Catalog block_locations 长度语义

DESIGN_SPEC 4.2 说 "对于纠删码 archive：block_locations 长度 = stripe_count × data_shards"。这与 `BlockLocation` 的定义有潜在不一致：

- `BlockLocation` 的 `shard_layout::Erasure` 已包含所有 shard 的信息
- `block_locations[i]` 对应逻辑 block i，其 `shard_layout` 描述该 block 的所有 shard
- **建议解释**: "block_locations 长度 = 逻辑 block 数量 = stripe_count"（对于纠删码，一个 stripe 通常对应一个逻辑 block）

应在 `INTERFACE_CONTRACT.md` 中明确：
```
block_locations.len() == 逻辑 block 数量
block_locations[i].shard_layout 描述 block i 的所有物理 shard
```

### 10. Task 1.8 构建验证的 protobuf 生成

`era-common/build.rs` 已编译 `era_common.proto`，新增 `ArchiveManifest` message 和修改 `Catalog` message 后，只需 `cargo build -p era-common` 即可自动重新生成 protobuf 代码，无需修改 `build.rs`。

---

## 修正后的任务清单

| 任务 | 原内容 | 修正 |
|------|--------|------|
| 1.1 | BlockType::Manifest | + 新增 `TypedBlockKind` 枚举（~50 行） |
| 1.2 | ArchiveManifest | 无修正 |
| 1.3 | Catalog block_locations | 工作量 1.5→1 天（BlockLocation 转换已存在） |
| 1.4 | Footer v2 | 明确 checksum 兼容性优势 |
| **1.5** | **承诺计算** | **位置: era-common → era-crypto** |
| 1.6 | finalize_sequence | 无修正 |
| 1.7 | EraError | `VolumeSpaceExhausted` → `TypedBlockSpaceExceeded` |
| 1.8 | 构建验证 | 确认 protobuf 自动生成，无需修改 build.rs |

---

## 修正后的文件变更清单

### 新增文件

| 文件 | 内容 | 大小 |
|------|------|------|
| `crates/era-common/src/types/manifest.rs` | ArchiveManifest | ~150 行 |
| `crates/era-common/src/types/typed_block.rs` | TypedBlockKind | ~50 行 |
| `crates/era-crypto/src/commitment.rs` | 承诺计算函数 | ~80 行 |

### 修改文件

| 文件 | 修改内容 |
|------|---------|
| `crates/era-common/src/types/block.rs` | BlockType::Manifest |
| `crates/era-common/src/types/mod.rs` | 导出 manifest, typed_block |
| `crates/era-common/src/error.rs` | 新增错误变体 |
| `crates/era-ingest/src/entry.rs` | Catalog 扩展 block_locations |
| `crates/era-common/proto/era_common.proto` | ArchiveManifest, Catalog 扩展 |
| `crates/era-volume/src/footer.rs` | manifest_block_id, manifest_offset |
| `crates/era-crypto/src/lib.rs` | 导出 commitment 模块 |

### 删除文件

无。

---

## 建议的后续行动

1. **立即修正** `PLAN.md` 和 `INTERFACE_CONTRACT.md` 中的承诺计算位置（era-common → era-crypto）
2. **更新** `DATA_TYPE_CHANGES.md` 的 protobuf schema（Catalog 字段编号改为向后兼容方案）
3. **补充** `TypedBlockKind` 到 Phase 1 任务清单
4. **明确** Footer checksum 兼容性在文档中的说明

---

*反思基于: 代码库实际状态（conversion.rs, Cargo.toml, error.rs 等）+ DESIGN_SPEC + ROADMAP*
