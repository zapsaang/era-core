# ERA Volume Format v8.2 — PHASE 1 实施规划

**版本**: 1.0  
**日期**: 2026-04-21  
**状态**: 规划完成，待执行  
**前置条件**: 代码未上线，无需向后兼容  

---

## 目录

1. [Phase 1 目标与范围](#1-phase-1-目标与范围)
2. [任务总览](#2-任务总览)
3. [任务详解](#3-任务详解)
   - 3.1 [Task 1.1: BlockType::Manifest 扩展](#31-task-11-blocktypemanifest-扩展)
   - 3.2 [Task 1.2: ArchiveManifest 类型定义（Rust + Protobuf）](#32-task-12-archivemanifest-类型定义rust--protobuf)
   - 3.3 [Task 1.3: Catalog 扩展 block_locations](#33-task-13-catalog-扩展-block_locations)
   - 3.4 [Task 1.4: Footer v2 字段扩展](#34-task-14-footer-v2-字段扩展)
   - 3.5 [Task 1.5: 承诺计算函数](#35-task-15-承诺计算函数)
   - 3.6 [Task 1.6: finalize_sequence 机制设计](#36-task-16-finalize_sequence-机制设计)
   - 3.7 [Task 1.7: EraError 扩展](#37-task-17-eraerror-扩展)
   - 3.8 [Task 1.8: 构建验证](#38-task-18-构建验证)
4. [跨任务依赖关系](#4-跨任务依赖关系)
5. [文件变更清单](#5-文件变更清单)
6. [验收标准](#6-验收标准)
7. [风险与缓解](#7-风险与缓解)

---

## 1. Phase 1 目标与范围

### 1.1 核心目标

Phase 1 为 v8.2 的全部上层功能（写入管线、读取管线、恢复模块）建立**类型基础与格式契约**。所有本阶段定义的数据结构、枚举值和 protobuf schema 将作为后续阶段不可变的接口契约。

### 1.2 范围边界

**包含**:
- 所有新增/修改的类型定义（Rust struct/enum + protobuf message）
- Footer 物理布局的字段扩展
- 密码学承诺计算的基础设施
- 认证世代号（finalize_sequence）的抽象设计
- 错误类型的扩展声明

**不包含**（延后到 Phase 2-4）:
- 实际的 Manifest 构建、加密、写入逻辑
- Catalog block_locations 的填充逻辑（写入时收集）
- Footer v2 的写入时机（finalize 流程）
- 多副本验证加载的实现
- committed_horizon 的强制执行

### 1.3 设计约束

1. **向后兼容**: Footer 版本保持为 `FOOTER_VERSION = 1`，新字段复用 reserved 空间
2. **零额外空间**: ArchiveManifest 作为 typed block 存储，不预留固定 slot
3. **复用密码学**: 承诺计算使用 Blake3 keyed_hash，复用现有 blake3 依赖
4. **严格向下依赖**: 所有修改遵循 L0→L4 的层级依赖，不引入循环依赖

---

## 2. 任务总览

| 任务 | 内容 | 目标 crate | 预估工时 | 风险 |
|------|------|-----------|---------|------|
| 1.1 | BlockType::Manifest + TypedBlockKind | era-common | 0.5 天 | 低 |
| 1.2 | ArchiveManifest 类型定义 | era-common | 1 天 | 低 |
| 1.3 | Catalog 扩展 block_locations | era-ingest, era-common | 1 天 | 中 |
| 1.4 | Footer v2 字段扩展 | era-volume | 1.5 天 | 中 |
| 1.5 | 承诺计算函数 | era-crypto | 0.5 天 | 低 |
| 1.6 | finalize_sequence 机制设计 | era-engine | 0.5 天 | 低 |
| 1.7 | EraError 扩展 | era-common | 0.5 天 | 低 |
| 1.8 | 构建验证 | workspace | 0.5 天 | 低 |
| **合计** | | | **~6.0 天** | |

---

## 3. 任务详解

### 3.1 Task 1.1: BlockType::Manifest 扩展

#### 3.1.1 目标

为 v8.2 新增的 ArchiveManifest typed block 分配唯一的 BlockType 标识，并定义 `TypedBlockKind` 抽象枚举（用于冗余验证和修复的通用类型标识），使其能够被 BlockHeader 自描述，并被现有的 typed block 读写基础设施识别。

#### 3.1.2 涉及文件

- `crates/era-common/src/types/block.rs`

#### 3.1.3 当前状态

```rust
// crates/era-common/src/types/block.rs:387-431
#[repr(u8)]
pub enum BlockType {
    Data = 0x01,
    IndexPage = 0x02,
    IndexManifest = 0x03,
    Catalog = 0x04,
    LsmManifest = 0x05,
    Checkpoint = 0x06,
    Reserved = 0xFF,
}
```

当前 `BlockType::from_u8()` 不支持 0x07，`is_index_block()` 仅匹配 IndexPage 和 IndexManifest。

#### 3.1.4 所需改动

**改动 1**: 在 `BlockType` 枚举中添加 `Manifest` 变体

```rust
#[repr(u8)]
pub enum BlockType {
    Data = 0x01,
    IndexPage = 0x02,
    IndexManifest = 0x03,
    Catalog = 0x04,
    LsmManifest = 0x05,
    Checkpoint = 0x06,
    Manifest = 0x07,        // ← 新增: v8.2 ArchiveManifest typed block
    Reserved = 0xFF,
}
```

**改动 2**: 更新 `from_u8()` 解析逻辑

```rust
pub fn from_u8(value: u8) -> Option<Self> {
    match value {
        0x01 => Some(Self::Data),
        0x02 => Some(Self::IndexPage),
        0x03 => Some(Self::IndexManifest),
        0x04 => Some(Self::Catalog),
        0x05 => Some(Self::LsmManifest),
        0x06 => Some(Self::Checkpoint),
        0x07 => Some(Self::Manifest),      // ← 新增
        0xFF => Some(Self::Reserved),
        _ => None,
    }
}
```

**改动 3**: 添加 Manifest 类型判断辅助方法

```rust
/// Check if this block type is a manifest block
pub fn is_manifest_block(self) -> bool {
    matches!(self, Self::Manifest)
}

/// Check if this block type is a metadata block (Catalog, Index, or Manifest)
pub fn is_metadata_block(self) -> bool {
    matches!(self, Self::Catalog | Self::IndexPage | Self::IndexManifest | Self::Manifest)
}
```

**改动 4**: 新增 `TypedBlockKind` 枚举（`crates/era-common/src/types/typed_block.rs`）

```rust
/// Typed block kind for redundancy validation and repair.
/// Groups the three types of metadata blocks that are fully replicated across volumes.
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

#### 3.1.5 关键设计决策

**为什么选择 0x07？**
- 0x01-0x06 已分配，0x07 是下一个可用值
- 0xFF 保留为未来扩展，不使用
- 与 Catalog (0x04) 和 Checkpoint (0x06) 保持距离，避免位运算混淆

#### 3.1.6 验收标准

- [ ] `BlockType::Manifest.to_u8()` 返回 0x07
- [ ] `BlockType::from_u8(0x07)` 返回 `Some(BlockType::Manifest)`
- [ ] `BlockType::from_u8(0x08)` 仍返回 `None`
- [ ] 现有 `BlockType::from_u8` 测试通过（无 regression）

---

### 3.2 Task 1.2: ArchiveManifest 类型定义（Rust + Protobuf）

#### 3.2.1 目标

定义 ArchiveManifest 的数据结构，作为 AEAD 加密的 typed block 存储的密码学认证全局状态快照。同时定义对应的 protobuf schema，确保序列化格式稳定。

#### 3.2.2 涉及文件

- `crates/era-common/src/types/mod.rs`（导出新增模块）
- `crates/era-common/src/types/manifest.rs`（新增文件）
- `crates/era-common/proto/era_common.proto`
- `crates/era-common/build.rs`（确认 protobuf 编译范围）

#### 3.2.3 数据结构定义

**Rust 结构**（新增 `crates/era-common/src/types/manifest.rs`）:

```rust
//! ArchiveManifest type definition for v8.2.
//!
//! ArchiveManifest is an AEAD-encrypted typed block that captures the
//! cryptographically authenticated global state snapshot of an archive.
//! It is stored as BlockType::Manifest in all volumes (full replica redundancy).

use serde::{Deserialize, Serialize};

/// Archive 的密码学认证全局状态快照。
///
/// 作为 AEAD 加密的 typed block 存储（BlockType::Manifest）。
/// 使用 BLOCK_KEY_DOMAIN 派生加密密钥（不引入专用密钥派生域）。
///
/// 序列化格式：protobuf（与 SuperHeader 一致）
/// 加密方式：XChaCha20-Poly1305，AAD = archive_id ‖ epoch_id ‖ volume_index ‖ block_id
/// 注：各卷使用相同的 key（从 block_id 派生），但 nonce 派生时混入 volume_index，
///     确保各卷密文不同，避免 nonce 重用。详见 §3.2.7 AEAD 合同修正。
/// 存储方式：typed block，写入所有 volume（全副本冗余）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveManifest {
    /// 单调递增代 ID（与 SuperHeader.epoch_id 一致）。
    /// 用于跨 archive 一致性验证和版本协商。
    pub epoch_id: u32,

    /// 认证世代号（单调递增）。
    /// 用于防止重放攻击：Reader 从所有 volume 加载 Manifest，
    /// 选择 finalize_sequence 最大的副本。
    /// 每次成功 finalize 后递增。
    pub finalize_sequence: u64,

    /// 逻辑提交边界（绝对字节偏移）。
    /// 超出此边界的数据视为未提交，Reader 必须忽略。
    /// 替代 recovery.rs 中的物理截断（file.set_len()）。
    pub committed_horizon: u64,

    /// Catalog 内容的域分离密码学承诺。
    /// = blake3::keyed_hash("ERA-CAT-COMMIT-v1___________", &catalog_plaintext)
    /// 对序列化后的明文计算，提供语义绑定。
    pub catalog_commitment: [u8; 32],

    /// Index 内容的域分离密码学承诺。
    /// = blake3::keyed_hash("ERA-IDX-COMMIT-v1___________", &index_plaintext)
    /// 如 Index 不存在，则为全零 [0u8; 32]。
    pub index_commitment: [u8; 32],
}

impl ArchiveManifest {
    /// Create a new ArchiveManifest with the given parameters.
    pub fn new(
        epoch_id: u32,
        finalize_sequence: u64,
        committed_horizon: u64,
        catalog_commitment: [u8; 32],
        index_commitment: [u8; 32],
    ) -> Self {
        Self {
            epoch_id,
            finalize_sequence,
            committed_horizon,
            catalog_commitment,
            index_commitment,
        }
    }

    /// Serialize the manifest to protobuf bytes.
    pub fn to_bytes(&self) -> crate::Result<Vec<u8>> {
        let proto: ProtoArchiveManifest = self.into();
        Ok(proto.encode_to_vec())
    }

    /// Deserialize a manifest from protobuf bytes.
    pub fn from_bytes(data: &[u8]) -> crate::Result<Self> {
        let proto = ProtoArchiveManifest::decode(data).map_err(|e| {
            crate::EraError::Deserialization(format!("Failed to decode manifest: {}", e))
        })?;
        proto.try_into()
    }

    /// Check if this manifest has a valid index commitment (not all zeros).
    pub fn has_index(&self) -> bool {
        self.index_commitment != [0u8; 32]
    }

    /// Return the finalize_sequence for redundancy selection.
    /// This is used by load_typed_block_with_redundancy to select
    /// the highest-sequence copy (replay attack prevention).
    pub fn sequence_for_selection(&self) -> u64 {
        self.finalize_sequence
    }
}

// ── Protobuf conversions ───────────────────────────────────────────

use crate::proto::ArchiveManifest as ProtoArchiveManifest;

impl From<&ArchiveManifest> for ProtoArchiveManifest {
    fn from(m: &ArchiveManifest) -> Self {
        Self {
            epoch_id: m.epoch_id,
            finalize_sequence: m.finalize_sequence,
            committed_horizon: m.committed_horizon,
            catalog_commitment: m.catalog_commitment.to_vec(),
            index_commitment: m.index_commitment.to_vec(),
        }
    }
}

impl TryFrom<ProtoArchiveManifest> for ArchiveManifest {
    type Error = crate::EraError;

    fn try_from(p: ProtoArchiveManifest) -> crate::Result<Self> {
        // Bounded validation: commitments must be exactly 32 bytes
        let catalog_commitment = p.catalog_commitment.try_into().map_err(|_| {
            crate::EraError::Deserialization(
                "catalog_commitment must be exactly 32 bytes".into(),
            )
        })?;
        let index_commitment = p.index_commitment.try_into().map_err(|_| {
            crate::EraError::Deserialization(
                "index_commitment must be exactly 32 bytes".into(),
            )
        })?;

        Ok(Self {
            epoch_id: p.epoch_id,
            finalize_sequence: p.finalize_sequence,
            committed_horizon: p.committed_horizon,
            catalog_commitment,
            index_commitment,
        })
    }
}
```

**Protobuf Schema**（追加到 `crates/era-common/proto/era_common.proto`）:

```protobuf
// ArchiveManifest: cryptographically authenticated global state snapshot (v8.2)
message ArchiveManifest {
    uint32 epoch_id = 1;
    uint64 finalize_sequence = 2;
    uint64 committed_horizon = 3;
    bytes catalog_commitment = 4;   // exactly 32 bytes
    bytes index_commitment = 5;     // exactly 32 bytes, or all zeros if no index
}
```

#### 3.2.4 关键设计决策

**为什么不包含 format_version？**
- 复用 `epoch_id` 进行版本协商。同一代的 archive 使用相同的格式版本。
- 减少字段冗余，降低序列化大小。

**为什么去掉 volume_states？**
- v8.2 要求 typed block 完全存放在单个 volume 内（不跨卷）。
- 同代 volume 的 tail_offset 相同，由 `committed_horizon` 隐含。
- 单写者场景下无需跟踪每个 volume 的状态。

**finalize_sequence 为什么是 u64？**
- u64 提供足够的空间（~1.8e19 次 finalize），实际上不可能溢出。
- 即使每秒 finalize 一次，也需要 5.8 亿年才溢出。
- u32（40 亿次）在极端场景下可能不够安全。

#### 3.2.7 AEAD 合同修正（重要）

**设计变更**：放弃 DESIGN_SPEC 中 "所有副本内容完全一致（相同 block_id、相同 ciphertext）" 的要求。

**原因**：
1. 现有代码的 AAD 绑定包含 `volume_index`（`aead_context.rs:38-42`）
2. 如果要求所有卷密文相同，则 AAD 必须相同 → 必须固定 `volume_index = 0`
3. 这削弱了上下文绑定安全性，且与代码库的 volume_index 绑定测试（`test_volume_index_binding_prevents_cross_volume_attack`）矛盾

**修正方案**（方案 B）：
- 每卷使用不同的 nonce：在 `derive_nonce_with_context` 中混入 `volume_index`
- AAD 仍绑定 `volume_index`，保持完整上下文绑定
- 各卷密文**长度相同**（XChaCha20 流密码 + 固定 16 字节 tag），但**内容不同**
- 放弃 "相同密文" 要求，代之以 "相同明文 + 完整 AAD 绑定 + 不同 nonce"

```rust
// aead_context.rs:69-79 修正后
fn derive_nonce_with_context(
    context: &[u8; 16],
    block_id: BlockId,
    volume_index: u32,  // ← 新增参数
) -> [u8; NONCE_SIZE] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ERA-NONCE-V2");
    hasher.update(context);
    hasher.update(&block_id.sequence().to_le_bytes());
    hasher.update(&volume_index.to_le_bytes());  // ← 新增
    let hash = hasher.finalize();
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&hash.as_bytes()[..NONCE_SIZE]);
    nonce
}
```

**影响**：
- 写入时：每卷单独加密 Manifest（相同的 plaintext，不同的 nonce）
- 读取时：每卷使用对应的 volume_index 解密
- 密文长度：所有卷相同（`plaintext.len() + 16`），仅 tag 不同

#### 3.2.5 模块导出

更新 `crates/era-common/src/types/mod.rs`:

```rust
pub mod manifest;  // ← 新增

pub use manifest::ArchiveManifest;  // ← 新增
```

更新 `crates/era-common/src/lib.rs`（如有需要，确认导出路径）:

```rust
pub use types::ArchiveManifest;  // 或保持通过 types::manifest::ArchiveManifest 访问
```

#### 3.2.6 验收标准

- [ ] `ArchiveManifest` 可序列化为 protobuf bytes 并正确反序列化
- [ ] `catalog_commitment` 长度不为 32 字节时反序列化返回错误
- [ ] `index_commitment` 全零时 `has_index()` 返回 false
- [ ] `to_bytes()` / `from_bytes()` 往返测试通过
- [ ] `cargo build -p era-common` 编译通过（protobuf 重新生成）

---

### 3.3 Task 1.3: Catalog 扩展 block_locations

#### 3.3.1 目标

在 Catalog 结构中新增 `block_locations` 字段，为每个数据块提供 O(1) 绝对偏移查询能力，根除权威路径上的预扫描需求。

#### 3.3.2 涉及文件

- `crates/era-ingest/src/entry.rs`
- `crates/era-common/proto/era_common.proto`
- `crates/era-common/src/types/block.rs`（BlockLocation 已存在，无需修改）

#### 3.3.3 当前状态

```rust
// crates/era-ingest/src/entry.rs:334-345
pub struct Catalog {
    pub entries: Vec<FileEntry>,
    pub total_size: u64,
    pub file_count: u64,
    pub dir_count: u64,
}
```

Protobuf schema（`era_common.proto:261-266`）:
```protobuf
message Catalog {
  repeated FileEntry entries = 1;
  uint64 total_size = 2;
  uint64 file_count = 3;
  uint64 dir_count = 4;
}
```

#### 3.3.4 所需改动

**改动 1**: 扩展 Rust `Catalog` 结构

```rust
// crates/era-ingest/src/entry.rs
pub struct Catalog {
    pub entries: Vec<FileEntry>,
    /// 新增：每个 block 的物理位置信息。
    /// block_locations[i] 对应逻辑 block index i。
    /// 对于非纠删码 archive：长度 = block_count
    /// 对于纠删码 archive：长度 = 逻辑 block 数量（= stripe_count）
    ///     注：BlockLocation.shard_layout::Erasure 已包含全部 shard 元数据，
    ///         无需为每个 data_shard 单独存储一个 BlockLocation
    pub block_locations: Vec<era_common::BlockLocation>,
    pub total_size: u64,
    pub file_count: u64,
    pub dir_count: u64,
}
```

**改动 2**: 更新构造函数

```rust
impl Catalog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            block_locations: Vec::new(),  // ← 新增
            total_size: 0,
            file_count: 0,
            dir_count: 0,
        }
    }
    
    // ... existing methods ...
}
```

**改动 3**: 更新 Protobuf 转换逻辑

```rust
// From<&Catalog> for ProtoCatalog
impl From<&Catalog> for ProtoCatalog {
    fn from(c: &Catalog) -> Self {
        Self {
            entries: c.entries.iter().map(|e| e.into()).collect(),
            block_locations: c.block_locations.iter().map(|loc| loc.into()).collect(),  // ← 新增
            total_size: c.total_size,
            file_count: c.file_count,
            dir_count: c.dir_count,
        }
    }
}

// TryFrom<ProtoCatalog> for Catalog
impl TryFrom<ProtoCatalog> for Catalog {
    type Error = era_common::EraError;

    fn try_from(p: ProtoCatalog) -> Result<Self, Self::Error> {
        // 新增：反序列化 block_locations，包含安全边界检查
        let block_locations = p
            .block_locations
            .into_iter()
            .map(|loc| loc.try_into())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            entries: p.entries.into_iter().map(|e| e.try_into()).collect::<Result<_, _>>()?,
            block_locations,  // ← 新增
            total_size: p.total_size,
            file_count: p.file_count,
            dir_count: p.dir_count,
        })
    }
}
```

**改动 4**: BlockLocation Protobuf 转换（复用现有代码）

`era-common/src/conversion.rs:216-282` 已存在完整的 `BlockLocation` ↔ `ProtoBlockLocation` 转换，**无需新增**。Catalog 的转换逻辑直接调用即可。

```rust
// era-ingest/src/entry.rs 中 Catalog 的转换
use era_common::proto::Catalog as ProtoCatalog;
// BlockLocation 的 From/TryFrom 由 era-common::conversion 模块自动提供
```

**改动 5**: 更新 protobuf schema（保守方案，字段 5）

```protobuf
// era-common/proto/era_common.proto
message Catalog {
  repeated FileEntry entries = 1;
  uint64 total_size = 2;           // 不变
  uint64 file_count = 3;           // 不变
  uint64 dir_count = 4;            // 不变
  repeated BlockLocation block_locations = 5;  // ← 新增字段 5
}
```

**理由**: 
- 保持现有字段编号不变，避免破坏硬编码 protobuf 测试 fixture
- block_locations 作为新增可选字段，编号 5 符合 protobuf 最佳实践
- 代码未上线，但减少测试修复工作量

#### 3.3.5 索引规则

```rust
/// block_locations 索引规则：
/// - block_locations[i] 对应逻辑 block index i
/// - 对于非纠删码 archive：block_locations 长度 = block_count
/// - 对于纠删码 archive：block_locations 长度 = 逻辑 block 数量（= stripe_count）
///     注：BlockLocation.shard_layout::Erasure 已包含全部 shard 的 offsets 和 volumes
/// 
/// 读取时：
/// let location = catalog.block_locations.get(block_index)?;
/// let data = reader.read_at(location.physical_offset, location.encrypted_size).await?;
```

#### 3.3.6 验收标准

- [ ] Catalog 序列化/反序列化包含 block_locations
- [ ] block_locations 为空时序列化/反序列化正常（向后兼容测试场景）
- [ ] BlockLocation 的 Erasure 布局正确序列化/反序列化
- [ ] 现有 Catalog 相关测试通过（entries, total_size, file_count, dir_count 无 regression）
- [ ] protobuf 编译通过（`cargo build -p era-common`）

---

### 3.4 Task 1.4: Footer v2 字段扩展

#### 3.4.1 目标

复用 Footer 的 reserved 空间（12 字节），添加 manifest_block_id（4 字节）和 manifest_offset（8 字节）字段，使 Reader 能够 O(1) 定位 Manifest typed block，无需预扫描。

#### 3.4.2 涉及文件

- `crates/era-volume/src/footer.rs`

#### 3.4.3 当前状态

Footer 当前布局（128 字节）:

```
| Offset | Size | Field                    | Current Value |
|--------|------|--------------------------|---------------|
| 0      | 4    | magic                    | "ERAF"        |
| 4      | 1    | version                  | 1             |
| 5      | 1    | reserved1                | 0             |
| 6      | 2    | flags                    | 0             |
| 8      | 8    | data_end_offset          | ✓             |
| 16     | 4    | block_count              | ✓             |
| 20     | 4    | reserved2                | 0             |
| 24     | 8    | sequence_number          | ✓             |
| 32     | 8    | catalog_offset           | ✓             |
| 40     | 4    | catalog_size             | ✓             |
| 44     | 4    | catalog_block_id         | ✓             |
| 48     | 8    | last_checkpoint_offset   | ✓             |
| 56     | 4    | last_checkpoint_block_id | ✓             |
| **60** | **4**| **reserved3**            | **0**         |
| 64     | 8    | index_offset             | ✓             |
| 72     | 4    | index_size               | ✓             |
| 76     | 4    | index_block_id           | ✓             |
| 80     | 8    | backup_header_offset     | ✓             |
| **88** | **8**| **reserved4**            | **0**         |
| 96     | 32   | checksum                 | Blake3        |
| **128**|      | **Total**                |               |
```

当前 `write_fields_to()` 和 `read_fields_from()` 对 reserved3/reserved4 的处理：
- 写入: `buf[60..64].copy_from_slice(&0u32.to_le_bytes())` (reserved3)
- 写入: `buf[88..96].copy_from_slice(&0u64.to_le_bytes())` (reserved4)
- 读取: 直接解析为 u32/u64 但不存储到任何字段（被忽略）

#### 3.4.4 所需改动

**改动 1**: 扩展 `Footer` 结构体字段

```rust
// crates/era-volume/src/footer.rs:62-95
pub struct Footer {
    // ... existing fields up to last_checkpoint_block_id ...
    
    /// Block ID of the manifest (for AEAD decryption)
    /// v8.2: 复用 reserved3 (offset 60, 4 bytes)
    manifest_block_id: u32,
    
    // ... existing fields: index_offset, index_size, index_block_id ...
    
    /// Offset of the manifest block
    /// v8.2: 复用 reserved4 (offset 88, 8 bytes)
    manifest_offset: u64,
    
    // ... existing fields: backup_header_offset, checksum ...
}
```

**改动 2**: 更新 `Footer::with_catalog` → `Footer::with_typed_blocks`

由于参数过多（超过 clippy 的 too_many_arguments 阈值），考虑重命名并扩展参数：

```rust
#[allow(clippy::too_many_arguments)]
pub fn with_typed_blocks(
    data_end_offset: u64,
    block_count: u32,
    sequence_number: u64,
    catalog_offset: u64,
    catalog_size: u32,
    catalog_block_id: u32,
    last_checkpoint_offset: u64,
    last_checkpoint_block_id: u32,
    manifest_offset: u64,            // ← 新增
    manifest_block_id: u32,          // ← 新增
    index_offset: u64,
    index_size: u32,
    index_block_id: u32,
    backup_header_offset: u64,
) -> Self {
    let mut footer = Self {
        // ... existing fields ...
        manifest_block_id,           // ← 新增
        // ... existing fields ...
        manifest_offset,             // ← 新增
        // ... existing fields ...
        checksum: [0u8; 32],
    };
    footer.update_checksum();
    footer
}
```

**或者**（推荐）：保持 `with_catalog` 不变，添加新的 builder 方法，因为 DESIGN_SPEC 要求向后兼容：

```rust
// 保持现有 with_catalog 不变（用于 v8.1 兼容路径测试）
// 新增 builder 方法支持 manifest
pub fn builder(data_end_offset: u64, block_count: u32, sequence_number: u64) -> FooterBuilder {
    FooterBuilder {
        // ... existing fields ...
        manifest_offset: 0,           // ← 新增，默认 0
        manifest_block_id: 0,         // ← 新增，默认 0
    }
}
```

**改动 3**: 扩展 `FooterBuilder`

```rust
pub struct FooterBuilder {
    // ... existing fields ...
    manifest_offset: u64,            // ← 新增
    manifest_block_id: u32,          // ← 新增
}

impl FooterBuilder {
    // ... existing methods ...
    
    /// Sets the manifest location (offset and block ID).
    pub fn manifest(mut self, offset: u64, block_id: u32) -> Self {
        self.manifest_offset = offset;
        self.manifest_block_id = block_id;
        self
    }
    
    pub fn build(self) -> Footer {
        Footer::with_typed_blocks(
            self.data_end_offset,
            self.block_count,
            self.sequence_number,
            self.catalog_offset,
            self.catalog_size,
            self.catalog_block_id,
            self.last_checkpoint_offset,
            self.last_checkpoint_block_id,
            self.manifest_offset,         // ← 新增
            self.manifest_block_id,       // ← 新增
            self.index_offset,
            self.index_size,
            self.index_block_id,
            self.backup_header_offset,
        )
    }
}
```

**改动 4**: 更新序列化/反序列化逻辑

```rust
fn write_fields_to(&self, buf: &mut [u8; FOOTER_SIZE - FOOTER_CHECKSUM_SIZE]) {
    // ... existing fields up to offset 60 ...
    
    // Offset 60: manifest_block_id (4 bytes) — 复用 reserved3
    buf[60..64].copy_from_slice(&self.manifest_block_id.to_le_bytes());
    
    // ... existing fields: index_offset, index_size, index_block_id ...
    
    // Offset 88: manifest_offset (8 bytes) — 复用 reserved4
    buf[88..96].copy_from_slice(&self.manifest_offset.to_le_bytes());
}

fn read_fields_from(buf: &[u8; FOOTER_SIZE - FOOTER_CHECKSUM_SIZE]) -> Result<Self> {
    Ok(Self {
        // ... existing fields ...
        
        // Offset 60: manifest_block_id (4 bytes)
        manifest_block_id: u32::from_le_bytes(buf[60..64].try_into().map_err(|_| {
            EraError::CorruptedFooter("invalid footer manifest_block_id slice".into())
        })?),
        
        // ... existing fields: index_offset, index_size, index_block_id ...
        
        // Offset 88: manifest_offset (8 bytes)
        manifest_offset: u64::from_le_bytes(buf[88..96].try_into().map_err(|_| {
            EraError::CorruptedFooter("invalid footer manifest_offset slice".into())
        })?),
        
        // ... existing fields: backup_header_offset ...
        checksum: [0u8; 32],
    })
}
```

**改动 5**: 添加 accessor 和验证方法

```rust
impl Footer {
    /// Offset of the manifest block
    #[must_use]
    pub fn manifest_offset(&self) -> u64 {
        self.manifest_offset
    }

    /// Block ID of the manifest
    #[must_use]
    pub fn manifest_block_id(&self) -> u32 {
        self.manifest_block_id
    }

    /// Check if manifest location is available (v8.2 indicator)
    /// 
    /// **注意**: 使用 `manifest_offset != 0` 判断，而不是 `manifest_block_id > 0`。
    /// `BlockId::new(0)` 是有效的，block_id 可以为 0。
    #[must_use]
    pub fn has_manifest(&self) -> bool {
        self.manifest_offset != 0
    }
    
    /// Returns the manifest location as a tuple (offset, block_id)
    #[must_use]
    pub fn manifest_location(&self) -> Option<(u64, u32)> {
        if self.has_manifest() {
            Some((self.manifest_offset, self.manifest_block_id))
        } else {
            None
        }
    }
}
```

**改动 6**: 更新区域边界验证

在 `Footer::from_bytes()` 中，添加 manifest 区域的交叉验证：

```rust
// 在 existing validate_region_bounds 调用之后添加：
Self::validate_region_bounds(
    "manifest",
    footer.manifest_offset,
    // manifest_size 不直接存储在 footer 中，需要从 BlockHeader 读取
    // 这里使用一个安全的上界估计（如 MAX_BLOCK_SIZE）
    // 或者在验证时跳过 size 检查，仅检查 offset
    // 注：manifest 的大小通常在 finalize 时已知，但 footer 不直接存储
    // 方案 A：在 footer 中添加 manifest_size 字段（需要更多空间，不推荐）
    // 方案 B：验证时仅检查 offset 非零且小于 data_end_offset
    // 方案 C：读取时通过 BlockHeader 获取实际大小
    // 推荐方案 C：from_bytes 阶段仅验证 offset 非零且在合理范围
)?;
```

由于 manifest_size 不在 footer 中存储（reserved 空间不足以容纳另一个 4 字节字段），`validate_region_bounds` 对 manifest 的处理需要调整：

```rust
// 选项：仅验证 offset 非零且在 data_end_offset 内
if footer.manifest_offset != 0 && footer.manifest_offset >= footer.data_end_offset {
    return Err(EraError::CorruptedFooter(format!(
        "manifest_offset {} exceeds data_end_offset {}",
        footer.manifest_offset, footer.data_end_offset
    )));
}
```

**改动 7**: 更新测试

- `test_footer_size_is_exactly_128_bytes`: 确保仍通过
- `test_footer_roundtrip`: 添加 manifest 字段的测试
- `test_footer_with_all_fields`: 添加 manifest 最大值测试
- 新增 `test_footer_manifest_location` 和 `test_footer_has_manifest`

#### 3.4.5 兼容性策略

**隐藏优势**: Footer checksum 覆盖 raw 前 96 字节（包括 reserved 区域）。v8.2 将 reserved3/reserved4 改为 manifest 字段后，checksum 仍覆盖这些字节，因此：

| 场景 | 行为 |
|------|------|
| v8.1 writer 创建，v8.2 reader 读取 | manifest_block_id = 0, manifest_offset = 0，`has_manifest()` 返回 false |
| v8.2 writer 创建，v8.1 reader 读取 | **checksum 验证通过**（覆盖全部 96 字节），v8.1 reader 忽略 reserved 字段，按 v8.1 逻辑工作 |
| v8.2 writer 创建，v8.2 reader 读取 | 正常读取 manifest 字段 |

**关键**: 无需修改 FOOTER_VERSION（保持为 1），因为 checksum 的覆盖范围天然保证了前向兼容。

#### 3.4.6 验收标准

- [ ] Footer 仍序列化为 128 字节
- [ ] manifest_block_id/manifest_offset 正确读写
- [ ] v8.1 Footer（manifest 字段为零）解析正常，`has_manifest()` 返回 false
- [ ] `test_footer_size_is_exactly_128_bytes` 通过
- [ ] `FooterBuilder::manifest(offset, block_id)` 链式调用可用

---

### 3.5 Task 1.5: 承诺计算函数

#### 3.5.1 目标

定义 Catalog 和 Index 内容的密码学承诺计算函数，使用 Blake3 keyed_hash 提供域分离的语义绑定。

#### 3.5.2 涉及文件

- `crates/era-crypto/src/lib.rs`（导出新增模块）
- `crates/era-crypto/src/commitment.rs`（新增文件）

#### 3.5.3 放置位置决策

**放在 `era-crypto/src/commitment.rs`**:
- `era-crypto/Cargo.toml` 已有 `blake3` 依赖
- `era-common/Cargo.toml` **没有** `blake3` 依赖
- 密码学原语（哈希、承诺）属于 `era-crypto` 的职责范围
- `era-ingest` 已依赖 `era-crypto`（L3 → L0），所有使用方可访问

#### 3.5.4 实现

```rust
//! Cryptographic commitment functions for v8.2.
//!
//! Commitments provide domain-separated semantic binding of catalog and index
//! contents. They are stored in ArchiveManifest and verified during archive open.

use blake3::Hasher;

/// Domain separation key for catalog commitment.
/// 32 bytes, padded with underscores for alignment.
pub const CATALOG_COMMITMENT_DOMAIN: &[u8; 32] = b"ERA-CAT-COMMIT-v1___________";

/// Domain separation key for index commitment.
pub const INDEX_COMMITMENT_DOMAIN: &[u8; 32] = b"ERA-IDX-COMMIT-v1___________";

/// Compute the cryptographic commitment of catalog plaintext.
///
/// Uses Blake3 keyed_hash with domain separation to prevent cross-protocol
/// collisions and provide semantic binding.
///
/// # Arguments
/// * `catalog_plaintext` - The serialized catalog bytes (protobuf encoding)
///
/// # Returns
/// 32-byte commitment value
pub fn compute_catalog_commitment(catalog_plaintext: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_keyed(CATALOG_COMMITMENT_DOMAIN);
    hasher.update(catalog_plaintext);
    *hasher.finalize().as_bytes()
}

/// Compute the cryptographic commitment of index plaintext.
///
/// Uses Blake3 keyed_hash with domain separation.
///
/// # Arguments
/// * `index_plaintext` - The serialized index bytes
///
/// # Returns
/// 32-byte commitment value, or all zeros if index_plaintext is empty
pub fn compute_index_commitment(index_plaintext: &[u8]) -> [u8; 32] {
    if index_plaintext.is_empty() {
        return [0u8; 32];
    }
    let mut hasher = Hasher::new_keyed(INDEX_COMMITMENT_DOMAIN);
    hasher.update(index_plaintext);
    *hasher.finalize().as_bytes()
}

/// Verify a catalog commitment against expected value.
///
/// # Errors
/// Returns `CatalogCommitmentMismatch` if commitment does not match.
pub fn verify_catalog_commitment(
    catalog_plaintext: &[u8],
    expected: &[u8; 32],
) -> crate::Result<()> {
    let computed = compute_catalog_commitment(catalog_plaintext);
    if computed != *expected {
        return Err(crate::EraError::CatalogCommitmentMismatch);
    }
    Ok(())
}

/// Verify an index commitment against expected value.
///
/// # Errors
/// Returns `IndexCommitmentMismatch` if commitment does not match.
/// Pass `expected = [0u8; 32]` to verify that no index exists.
pub fn verify_index_commitment(
    index_plaintext: &[u8],
    expected: &[u8; 32],
) -> crate::Result<()> {
    let computed = compute_index_commitment(index_plaintext);
    if computed != *expected {
        return Err(crate::EraError::IndexCommitmentMismatch);
    }
    Ok(())
}
```

#### 3.5.5 模块导出

```rust
// era-crypto/src/lib.rs
pub mod commitment;

pub use commitment::{
    compute_catalog_commitment,
    compute_index_commitment,
    verify_catalog_commitment,
    verify_index_commitment,
    CATALOG_COMMITMENT_DOMAIN,
    INDEX_COMMITMENT_DOMAIN,
};
```

使用方通过 `era_crypto::commitment::*` 访问。

#### 3.5.6 为什么使用 `Hasher::new_keyed` 而非 `keyed_hash`

- `blake3` crate 的 `keyed_hash` 函数在较新版本中可能不存在或 API 不同
- `Hasher::new_keyed(key)` 是标准 API，接受 32 字节 key
- 这与 `blake3` 文档中的 keyed hashing 模式一致

#### 3.5.7 验收标准

- [ ] 相同输入产生相同 32 字节输出
- [ ] 不同输入产生不同输出（碰撞测试）
- [ ] 空 index_plaintext 返回 `[0u8; 32]`
- [ ] `verify_catalog_commitment` 正确返回 Ok/Err
- [ ] `verify_index_commitment` 正确返回 Ok/Err

---

### 3.6 Task 1.6: finalize_sequence 机制设计

#### 3.6.1 目标

设计并定义 `finalize_sequence` 的抽象接口，使其能够在 Phase 2 被 ArchiveWriter 使用，在 Phase 3 被 ArchiveReader 使用。

#### 3.6.2 设计决策

`finalize_sequence` 是 ArchiveManifest 的字段（已在 Task 1.2 中定义），但需要在 engine 层定义其管理和递增机制。

**关键问题 1**: `finalize_sequence` 存储在哪里？

**方案 A**: 存储在 Footer 中（每个 volume 独立）
- 优点：无需读取 Manifest 即可知道版本
- 缺点：Footer 无额外空间，且不同 volume 可能不同步

**方案 B**: 存储在 Manifest 中（已在 Task 1.2 中实现）
- 优点：与 Manifest 一起认证，防止单独篡改
- 缺点：读取 Manifest 前无法知道版本
- **推荐**：这正是 DESIGN_SPEC 选择的方案

**方案 C**: 存储在 SuperHeader 中
- 优点：Header 有较大空间
- 缺点：Header 在 archive 创建后不应修改（除了 epoch_id 旋转）

**关键问题 2**: `finalize_sequence` 与 `Footer.sequence_number` 的关系？

```
Footer.sequence_number    = volume 级别的物理写入计数（每次写入数据块递增）
Manifest.finalize_sequence = archive 级别的逻辑提交计数（每次 finalize 递增）
```

**不变量（选项 1 - 推荐）**: **两者独立**
- `Footer.sequence_number` 由 VolumeWriter 管理，每次写入递增
- `Manifest.finalize_sequence` 由 ArchiveWriter 管理，每次 finalize 递增
- 关系：`finalize_sequence >= 1`（初始值），`sequence_number >= finalize_sequence`（通常 sequence 增长更快）
- 验证：Reader 加载 Manifest 后，可检查 `manifest.finalize_sequence > 0`，但无需与 Footer.sequence_number 比较

**不变量（选项 2）**: **强制相等**
- 每次 finalize 时：`Footer.sequence_number = Manifest.finalize_sequence`
- 优点：简单，Footer 可做基础验证
- 缺点：非 finalize 写入（checkpoint）也会递增 sequence_number，导致不等
- **不推荐**

#### 3.6.3 抽象接口设计

在 `era-engine` 中定义 `FinalizeSequenceTracker`（Phase 2 实现）：

```rust
//! Finalize sequence tracking for replay attack prevention.
//!
//! In v8.2, each successful finalize increments a monotonic sequence number
//! stored in ArchiveManifest. When loading an archive, the reader selects
//! the Manifest copy with the highest finalize_sequence across all volumes.

/// Trait for types that can extract a sequence number for redundancy selection.
///
/// Implement this for ArchiveManifest (and potentially other future types)
/// to enable generic `load_typed_block_with_redundancy`.
pub trait SequenceSelector {
    /// Returns the sequence number for redundancy selection.
    /// Higher values indicate newer versions.
    fn selection_sequence(&self) -> u64;
}

impl SequenceSelector for era_common::ArchiveManifest {
    fn selection_sequence(&self) -> u64 {
        self.finalize_sequence
    }
}

/// Default starting sequence for a new archive.
pub const INITIAL_FINALIZE_SEQUENCE: u64 = 1;

/// Compute the next finalize sequence.
///
/// # Panics
/// Panics if sequence would overflow u64 (practically impossible).
pub fn next_finalize_sequence(current: u64) -> u64 {
    current.checked_add(1).expect("finalize_sequence overflow")
}
```

#### 3.6.4 读取时的选择逻辑（Phase 3 参考）

```rust
/// 从所有 volume 中加载指定类型的 typed block，支持多副本冗余验证。
/// 
/// 策略：
/// 1. 从所有 volume 尝试加载候选副本
/// 2. 对每个成功解密的副本，提取其 selection_sequence
/// 3. 选择 selection_sequence 最大的认证副本（防止重放攻击）
/// 4. 如果全部副本失败，返回错误（不静默回退）
/// 5. 返回所有失败/跳过的警告
async fn load_typed_block_with_redundancy<T: SequenceSelector>(
    volume_readers: &[VolumeReader],
    kind: TypedBlockKind,
    location_extractor: impl Fn(&Footer) -> Option<BlockLocation>,
    validator: impl Fn(EncryptedMacroBlock) -> Result<T>,
) -> Result<(T, Vec<String>)> {
    let mut warnings = Vec::new();
    let mut candidates: Vec<(u64, T, usize)> = Vec::new();
    
    for (vol_idx, reader) in volume_readers.iter().enumerate() {
        match location_extractor(reader.footer()?) {
            Some(location) => {
                match reader.read_block(&location).await {
                    Ok(encrypted) => {
                        match validator(encrypted) {
                            Ok(result) => {
                                let seq = result.selection_sequence();
                                candidates.push((seq, result, vol_idx));
                            }
                            Err(e) => warnings.push(format!("Volume {}: {} validation failed: {}", 
                                vol_idx, kind.name(), e)),
                        }
                    }
                    Err(e) => warnings.push(format!("Volume {}: {} read failed: {}", 
                        vol_idx, kind.name(), e)),
                }
            }
            None => warnings.push(format!("Volume {}: no {} location in footer", 
                vol_idx, kind.name())),
        }
    }
    
    if candidates.is_empty() {
        return Err(EraError::AllTypedBlockCopiesCorrupted {
            kind: kind.name().to_string(),
            volume_count: volume_readers.len(),
            warnings,
        });
    }
    
    // 选择 selection_sequence 最大的（防止重放）
    candidates.sort_by_key(|(seq, _, _)| *seq);
    let (_, result, vol_idx) = candidates.pop().unwrap();
    
    if !candidates.is_empty() {
        warnings.push(format!(
            "Selected {} from volume {} with highest sequence (skipped {} older copies)",
            kind.name(), vol_idx, candidates.len()
        ));
    }
    
    Ok((result, warnings))
}
```

#### 3.6.5 验收标准

- [ ] `SequenceSelector` trait 定义完成
- [ ] `ArchiveManifest` 实现 `SequenceSelector`
- [ ] `INITIAL_FINALIZE_SEQUENCE` 和 `next_finalize_sequence` 定义完成
- [ ] 选择逻辑伪代码通过设计评审

---

### 3.7 Task 1.7: EraError 扩展

#### 3.7.1 目标

为 v8.2 新增的错误场景定义错误类型，确保所有 Phase 2-4 的错误路径有明确的错误变体。

#### 3.7.2 涉及文件

- `crates/era-common/src/error.rs`

#### 3.7.3 新增错误变体

```rust
// crates/era-common/src/error.rs

pub enum EraError {
    // ... existing variants ...

    /// 读取超出提交边界（committed_horizon）
    #[error("Read beyond commit horizon: offset={offset}, horizon={horizon}")]
    BeyondCommitHorizon { offset: u64, horizon: u64 },

    /// Catalog 承诺验证失败
    #[error("Catalog commitment mismatch: computed commitment does not match manifest")]
    CatalogCommitmentMismatch,

    /// Index 承诺验证失败
    #[error("Index commitment mismatch: computed commitment does not match manifest")]
    IndexCommitmentMismatch,

    /// Volume 空间不足（typed block 预检查失败）
    #[error("Volume {volume} full: required={required}, available={available}: {message}")]
    VolumeSpaceExhausted {
        volume: usize,
        required: u64,
        available: u64,
        message: String,
    },

    /// Manifest 加载失败
    #[error("Manifest load error: {0}")]
    ManifestLoadError(String),

    /// Footer 一致性验证失败（多卷场景）
    #[error("Footer inconsistency: field={field}, expected={expected}, actual={actual}")]
    FooterInconsistency {
        field: String,
        expected: String,
        actual: String,
    },

    /// 指定类型的 typed block 在所有 volume 上均无法读取
    #[error("All {kind} copies corrupted across {volume_count} volumes")]
    AllTypedBlockCopiesCorrupted {
        kind: String,
        volume_count: usize,
        warnings: Vec<String>,
    },

    /// Typed block 在指定 volume 上不存在或位置无效
    #[error("Typed block not found: {0}")]
    TypedBlockNotFound(String),

    /// Repair 后的副本验证失败（写入后读取不一致）
    #[error("Repair verification failed for {kind} on volume {volume_idx}: expected_crc={expected_crc}, actual_crc={actual_crc}")]
    RepairVerificationFailed {
        kind: String,
        volume_idx: usize,
        expected_crc: u32,
        actual_crc: u32,
    },

    /// 不支持的历史格式（v8.1 archive 在 fail-closed 模式下）
    #[error("Unsupported archive format: {0}")]
    UnsupportedFormat(String),
}
```

#### 3.7.4 添加构造辅助方法

```rust
impl EraError {
    // ... existing helpers ...

    /// Create a new beyond commit horizon error
    pub fn beyond_commit_horizon(offset: u64, horizon: u64) -> Self {
        Self::BeyondCommitHorizon { offset, horizon }
    }

    /// Create a new manifest load error
    pub fn manifest_load_error(msg: impl Into<String>) -> Self {
        Self::ManifestLoadError(msg.into())
    }

    /// Create a new footer inconsistency error
    pub fn footer_inconsistency(field: impl Into<String>, expected: impl Into<String>, actual: impl Into<String>) -> Self {
        Self::FooterInconsistency {
            field: field.into(),
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    /// Create a new all copies corrupted error
    pub fn all_typed_block_copies_corrupted(kind: impl Into<String>, volume_count: usize, warnings: Vec<String>) -> Self {
        Self::AllTypedBlockCopiesCorrupted {
            kind: kind.into(),
            volume_count,
            warnings,
        }
    }

    /// Create a new typed block not found error
    pub fn typed_block_not_found(msg: impl Into<String>) -> Self {
        Self::TypedBlockNotFound(msg.into())
    }

    /// Create a new unsupported format error
    pub fn unsupported_format(msg: impl Into<String>) -> Self {
        Self::UnsupportedFormat(msg.into())
    }
}
```

#### 3.7.5 命名说明

- `VolumeSpaceExhausted` vs `VolumeFull`: 
  - 现有 `VolumeFull` 用于 generic "volume full" 场景
  - 新增 `VolumeSpaceExhausted` 专指 typed block 预检查失败，包含 required/available 信息
  - 或者复用现有的 `VolumeFull`，扩展其字段（但这会破坏现有 API）
  - **推荐**: 保留现有 `VolumeFull`，新增 `VolumeSpaceExhausted` 用于预检查场景

- `UnsupportedFormat` vs `UnsupportedVersion`:
  - `UnsupportedVersion` 用于 header/footer 版本号不匹配
  - `UnsupportedFormat` 用于 archive 格式不兼容（如 v8.1 archive 在 v8.2 fail-closed 模式下）

#### 3.7.6 验收标准

- [ ] 所有新增错误变体有 `#[error(...)]` 属性
- [ ] 所有新增错误变体有对应的构造辅助方法
- [ ] `cargo build -p era-common` 编译通过
- [ ] 现有使用 `EraError` 的代码无 regression

---

### 3.8 Task 1.8: 构建验证

#### 3.8.1 目标

确保所有 Phase 1 的修改在 workspace 级别编译通过，不影响现有功能。

#### 3.8.2 构建步骤

```bash
# 1. 格式化检查
cargo fmt --all -- --check

# 2. 编译 era-common（protobuf 重新生成）
cargo build -p era-common

# 3. 编译 era-ingest（Catalog 扩展）
cargo build -p era-ingest

# 4. 编译 era-volume（Footer 扩展）
cargo build -p era-volume

# 5. 编译整个 workspace
cargo build --workspace

# 6. Lint 检查
cargo clippy --all-targets --all-features -- -D warnings

# 7. 运行测试
cargo test --workspace
```

#### 3.8.3 预期问题与解决

| 问题 | 原因 | 解决 |
|------|------|------|
| Footer::with_catalog 调用点编译失败 | 签名变更 | 更新所有调用点，或保留旧签名并标记 deprecated |
| Protobuf 字段编号变更导致测试失败 | Catalog 字段重新编号 | 更新测试中的 protobuf 二进制 fixture |
| EraError 新增变体导致 match 不穷尽 | Rust 要求穷尽匹配 | 在需要的地方添加 `_ =>` 或显式处理新变体 |

#### 3.8.4 验收标准

- [ ] `cargo fmt --all -- --check` 通过
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` 通过
- [ ] `cargo test --workspace` 通过（或仅存在与变更无关的 pre-existing 失败）

---

## 4. 跨任务依赖关系

```
Task 1.1 (BlockType::Manifest)
    │
    ▼
Task 1.2 (ArchiveManifest) ───────┐
    │                              │
    ▼                              ▼
Task 1.3 (Catalog block_locations) Task 1.5 (承诺计算)
    │                              │
    ▼                              ▼
Task 1.4 (Footer v2) ◄───────────┘
    │
    ▼
Task 1.6 (finalize_sequence)
    │
    ▼
Task 1.7 (EraError 扩展)
    │
    ▼
Task 1.8 (构建验证)
```

**可并行开发**:
- Task 1.1 和 Task 1.5 可并行（独立）
- Task 1.6 和 Task 1.7 可并行（独立）

**关键路径**:
- Task 1.2 → Task 1.3 → Task 1.4 → Task 1.8
- 任何延迟直接影响 Phase 2 的开始

---

## 5. 文件变更清单

### 5.1 新增文件

| 文件 | 内容 | 大小（预估） |
|------|------|------------|
| `crates/era-common/src/types/manifest.rs` | ArchiveManifest 结构定义 + Protobuf 转换 | ~150 行 |
| `crates/era-common/src/commitment.rs` | 承诺计算函数 | ~80 行 |

### 5.2 修改文件

| 文件 | 修改内容 | 影响范围 |
|------|---------|---------|
| `crates/era-common/src/types/block.rs` | BlockType::Manifest 添加 | 全 workspace（BlockType 广泛使用） |
| `crates/era-common/src/types/mod.rs` | 导出 manifest 模块 | era-common |
| `crates/era-common/src/lib.rs` | 导出 commitment 模块 | era-common |
| `crates/era-common/src/error.rs` | 新增错误变体 | 全 workspace |
| `crates/era-ingest/src/entry.rs` | Catalog 扩展 block_locations | era-ingest, era-engine |
| `crates/era-common/proto/era_common.proto` | ArchiveManifest message, Catalog 扩展 | 全 workspace（protobuf 生成） |
| `crates/era-volume/src/footer.rs` | manifest_block_id/manifest_offset 字段 | era-volume, era-engine |

### 5.3 删除文件

无。

---

## 6. 验收标准

### 6.1 功能验收

- [ ] `BlockType::Manifest` 定义完成，to_u8/from_u8 正确
- [ ] `ArchiveManifest` 可 protobuf 序列化/反序列化
- [ ] `Catalog.block_locations` 定义完成，protobuf 字段正确
- [ ] `Footer` 正确读写 manifest_block_id 和 manifest_offset
- [ ] 承诺计算函数正确（相同输入 → 相同输出，不同输入 → 不同输出）
- [ ] `finalize_sequence` 抽象接口定义完成
- [ ] 新增 EraError 变体有完整 display 和构造方法

### 6.2 构建验收

- [ ] `cargo fmt --all -- --check` 通过
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` 通过
- [ ] `cargo test --workspace` 通过（允许 pre-existing 失败）
- [ ] `cargo build --workspace` 通过

### 6.3 设计验收

- [ ] 所有新增类型不破坏现有接口（向后兼容或明确声明不兼容）
- [ ] Footer 仍保持 128 字节原子写入
- [ ] 无循环依赖引入
- [ ] 所有新增错误变体遵循现有命名和分类约定

---

## 7. 风险与缓解

| 风险 | 可能性 | 影响 | 缓解 |
|------|--------|------|------|
| Footer 字段扩展引入 regression | 中 | 高 | 全面的 Footer 测试；验证所有现有 Footer 调用点 |
| Catalog protobuf 字段编号变更破坏测试 | 中 | 中 | 更新测试 fixture；声明不兼容 |
| BlockType 新增变体导致 match 不穷尽 | 高 | 低 | 编译器强制检查；修复所有 match 语句 |
| Blake3 keyed_hash API 不匹配 | 低 | 中 | 查阅 blake3 文档；使用 `Hasher::new_keyed` |
| EraError 新增变体影响下游 crate | 中 | 低 | 编译器强制检查；逐步修复 |

---

## 附录 A: 常量汇总

```rust
// BlockType
pub const MANIFEST_BLOCK_TYPE: BlockType = BlockType::Manifest;
pub const MANIFEST_BLOCK_TYPE_U8: u8 = 0x07;

// Footer（保持 FOOTER_VERSION = 1）
pub const FOOTER_VERSION: u8 = 1;

// Commitment domains
pub const CATALOG_COMMITMENT_DOMAIN: &[u8; 32] = b"ERA-CAT-COMMIT-v1___________";
pub const INDEX_COMMITMENT_DOMAIN: &[u8; 32] = b"ERA-IDX-COMMIT-v1___________";

// Initial sequence
pub const INITIAL_FINALIZE_SEQUENCE: u64 = 1;

// Volume layout（保持不变）
pub const HEADER_SIZE: usize = 4096;
pub const FOOTER_SIZE: usize = 128;
pub const BACKUP_FOOTER_GAP: usize = 128;
pub const DATA_REGION_START: u64 = (HEADER_SIZE + BACKUP_FOOTER_GAP) as u64;
```

## 附录 B: 与 DESIGN_SPEC 的对应关系

| DESIGN_SPEC 章节 | 本规划任务 | 状态 |
|-----------------|-----------|------|
| 4.1 ArchiveManifest | Task 1.2 | 已规划 |
| 4.2 Catalog 扩展 | Task 1.3 | 已规划 |
| 5.3 承诺计算 | Task 1.5 | 已规划 |
| 6.3 全副本冗余写入 | —（Phase 2）| 延后 |
| 7.1 多副本验证 | —（Phase 3）| 延后 |
| 9.1 新增错误类型 | Task 1.7 | 已规划 |
| 10 常量定义 | 附录 A | 已汇总 |

---

*文档生成时间: 2026-04-21*  
*基于: DESIGN_SPEC.md v1.0 + ROADMAP.md v1.0 + 代码库现状分析*  
*状态: 规划完成，待执行*
