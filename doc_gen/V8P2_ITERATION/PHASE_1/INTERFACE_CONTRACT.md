# PHASE 1: 接口契约文档

**版本**: 1.0  
**日期**: 2026-04-21  
**作用**: 定义 Phase 1 完成后，各 crate 之间的新接口边界，作为 Phase 2-4 的开发契约。

---

## 1. 接口契约概述

Phase 1 完成后，以下接口将被定义并稳定化。Phase 2-4 的开发必须遵循这些契约，不得修改（除非经过设计变更流程）。

```
┌─────────────────────────────────────────────────────────────────────┐
│ L4: era-engine                                                      │
│   ├── 使用: ArchiveManifest, Catalog (含 block_locations)          │
│   ├── 使用: Footer::has_manifest(), manifest_location()            │
│   ├── 使用: compute_catalog_commitment(), compute_index_commitment()│
│   └── 使用: EraError::CatalogCommitmentMismatch 等                 │
├─────────────────────────────────────────────────────────────────────┤
│ L3: era-ingest                                                      │
│   ├── 提供: Catalog (含 block_locations)                           │
│   └── 提供: Catalog::to_bytes(), Catalog::from_bytes()             │
├─────────────────────────────────────────────────────────────────────┤
│ L2: era-volume                                                      │
│   ├── 提供: Footer (含 manifest_block_id, manifest_offset)         │
│   └── 提供: Footer::has_manifest(), manifest_location()            │
├─────────────────────────────────────────────────────────────────────┤
│ L0: era-common                                                      │
│   ├── 提供: ArchiveManifest 类型 + Protobuf 序列化                 │
│   ├── 提供: BlockType::Manifest + TypedBlockKind                   │
│   └── 提供: EraError 扩展                                          │
│ L0: era-crypto                                                      │
│   └── 提供: compute_catalog_commitment(), compute_index_commitment()│
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. era-common → 所有上层 crate

### 2.1 ArchiveManifest 类型

**定义位置**: `era-common/src/types/manifest.rs`  
**导出路径**: `era_common::ArchiveManifest`

```rust
pub struct ArchiveManifest {
    pub epoch_id: u32,
    pub finalize_sequence: u64,
    pub committed_horizon: u64,
    pub catalog_commitment: [u8; 32],
    pub index_commitment: [u8; 32],
}
```

**接口方法**:

| 方法 | 签名 | 用途 | 使用者 |
|------|------|------|--------|
| `new` | `fn new(epoch_id, finalize_sequence, committed_horizon, catalog_commitment, index_commitment) -> Self` | 构造 | era-engine (Phase 2) |
| `to_bytes` | `fn to_bytes(&self) -> Result<Vec<u8>>` | Protobuf 序列化 | era-engine (Phase 2) |
| `from_bytes` | `fn from_bytes(data: &[u8]) -> Result<Self>` | Protobuf 反序列化 | era-engine (Phase 3) |
| `has_index` | `fn has_index(&self) -> bool` | 检查是否有 index | era-engine (Phase 3) |
| `sequence_for_selection` | `fn sequence_for_selection(&self) -> u64` | 冗余选择 | era-engine (Phase 3) |

**契约保证**:
- `to_bytes()` / `from_bytes()` 往返一致性
- `catalog_commitment` 和 `index_commitment` 始终为 32 字节
- 空 index 时 `index_commitment` 为 `[0u8; 32]`

### 2.2 BlockType 扩展

**定义位置**: `era-common/src/types/block.rs`  
**导出路径**: `era_common::BlockType`

```rust
pub enum BlockType {
    // ... existing variants ...
    Manifest = 0x07,
}
```

**新增方法**:

| 方法 | 签名 | 用途 |
|------|------|------|
| `is_manifest_block` | `fn is_manifest_block(self) -> bool` | 检查是否为 Manifest |
| `is_metadata_block` | `fn is_metadata_block(self) -> bool` | 检查是否为元数据块 |

**契约保证**:
- `Manifest.to_u8()` 始终返回 `0x07`
- `from_u8(0x07)` 始终返回 `Some(Manifest)`
- 现有变体的值不变

## 3. era-crypto → 所有上层 crate

### 3.1 承诺计算函数

**定义位置**: `era-crypto/src/commitment.rs`  
**导出路径**: `era_crypto::commitment::*`

```rust
pub fn compute_catalog_commitment(catalog_plaintext: &[u8]) -> [u8; 32];
pub fn compute_index_commitment(index_plaintext: &[u8]) -> [u8; 32];
pub fn verify_catalog_commitment(catalog_plaintext: &[u8], expected: &[u8; 32]) -> Result<()>;
pub fn verify_index_commitment(index_plaintext: &[u8], expected: &[u8; 32]) -> Result<()>;
```

**契约保证**:
- 相同输入 → 相同 32 字节输出（确定性）
- 不同输入 → 不同输出（抗碰撞）
- `compute_index_commitment(&[])` 返回 `[0u8; 32]`
- 使用 Blake3 `Hasher::new_keyed()` 进行域分离

### 2.3 TypedBlockKind 枚举

**定义位置**: `era-common/src/types/typed_block.rs`  
**导出路径**: `era_common::TypedBlockKind`

```rust
pub enum TypedBlockKind {
    Manifest,
    Catalog,
    Index,
}
```

**用途**: 冗余验证、修复、日志中的类型标识。

### 2.4 EraError 扩展

**定义位置**: `era-common/src/error.rs`  
**导出路径**: `era_common::EraError`

**新增变体**:

```rust
BeyondCommitHorizon { offset: u64, horizon: u64 }
CatalogCommitmentMismatch
IndexCommitmentMismatch
VolumeSpaceExhausted { volume: usize, required: u64, available: u64, message: String }
ManifestLoadError(String)
FooterInconsistency { field: String, expected: String, actual: String }
AllTypedBlockCopiesCorrupted { kind: String, volume_count: usize, warnings: Vec<String> }
TypedBlockNotFound(String)
RepairVerificationFailed { kind: String, volume_idx: usize, expected_crc: u32, actual_crc: u32 }
UnsupportedFormat(String)
```

**契约保证**:
- 所有变体实现 `std::fmt::Display`（通过 `thiserror`）
- 所有变体有对应的构造辅助方法

---

## 3. era-ingest → era-engine

### 3.1 Catalog 扩展

**定义位置**: `era-ingest/src/entry.rs`  
**导出路径**: `era_ingest::Catalog`（或 `era_common::Catalog`，取决于实际导出）

```rust
pub struct Catalog {
    pub entries: Vec<FileEntry>,
    pub block_locations: Vec<BlockLocation>,  // ← Phase 1 新增
    pub total_size: u64,
    pub file_count: u64,
    pub dir_count: u64,
}
```

**接口方法**:

| 方法 | 签名 | 用途 | 使用者 |
|------|------|------|--------|
| `to_bytes` | `fn to_bytes(&self) -> Result<Vec<u8>>` | Protobuf 序列化 | era-engine (Phase 2: 构建 Manifest 承诺) |
| `from_bytes` | `fn from_bytes(data: &[u8]) -> Result<Self>` | Protobuf 反序列化 | era-engine (Phase 3: 加载 Catalog) |

**契约保证**:
- `block_locations[i]` 对应逻辑 block index `i`
- 非纠删码: `block_locations.len() == block_count`
- 纠删码: `block_locations.len() == stripe_count`（BlockLocation.shard_layout::Erasure 已含全部 shard 元数据）
- `to_bytes()` 产生的明文用于 `compute_catalog_commitment()`

**Phase 2 使用模式**:

```rust
// era-engine/src/writer.rs (Phase 2)
let catalog = self.build_catalog();  // 包含 block_locations
let catalog_plaintext = catalog.to_bytes()?;
let catalog_commitment = compute_catalog_commitment(&catalog_plaintext);

let manifest = ArchiveManifest::new(
    self.epoch_id,
    self.next_finalize_sequence(),
    self.data_end_offset,
    catalog_commitment,
    index_commitment,
);
```

**Phase 3 使用模式**:

```rust
// era-engine/src/reader.rs (Phase 3)
let catalog = Catalog::from_bytes(&catalog_plaintext)?;
verify_catalog_commitment(&catalog_plaintext, &manifest.catalog_commitment)?;

// 使用 block_locations 进行 O(1) 查找
let location = catalog.block_locations.get(block_index)
    .ok_or_else(|| EraError::BlockNotFound { block_id: block_index.to_string() })?;
```

---

## 4. era-volume → era-engine

### 4.1 Footer v2 扩展

**定义位置**: `era-volume/src/footer.rs`  
**导出路径**: `era_volume::Footer`

**新增字段**（内部，通过 accessor 暴露）:

```rust
manifest_block_id: u32,   // offset 60, 4 bytes (复用 reserved3)
manifest_offset: u64,     // offset 88, 8 bytes (复用 reserved4)
```

**新增方法**:

| 方法 | 签名 | 用途 | 使用者 |
|------|------|------|--------|
| `manifest_offset` | `fn manifest_offset(&self) -> u64` | 获取 Manifest 偏移 | era-engine (Phase 3) |
| `manifest_block_id` | `fn manifest_block_id(&self) -> u32` | 获取 Manifest block ID | era-engine (Phase 3) |
| `has_manifest` | `fn has_manifest(&self) -> bool` | 检测 v8.2 Footer（`manifest_offset != 0`） | era-engine (Phase 3) |
| `manifest_location` | `fn manifest_location(&self) -> Option<(u64, u32)>` | 获取 Manifest 位置 | era-engine (Phase 3) |

**FooterBuilder 新增方法**:

| 方法 | 签名 | 用途 |
|------|------|------|
| `manifest` | `fn manifest(self, offset: u64, block_id: u32) -> Self` | 设置 Manifest 位置 |

**契约保证**:
- Footer 始终序列化为 128 字节
- `has_manifest()` 为 true 当且仅当 `manifest_block_id > 0 && manifest_offset > 0`
- v8.1 Footer（manifest 字段为零）解析正常，`has_manifest()` 返回 false
- `manifest_location()` 返回 `Some((offset, block_id))` 当且仅当 `has_manifest()` 为 true

**Phase 2 使用模式**（写入）:

```rust
// era-volume/src/volume_pool.rs 或 era-engine (Phase 2)
let footer = Footer::builder(data_end_offset, block_count, sequence_number)
    .catalog(catalog_offset, catalog_size, catalog_block_id)
    .manifest(manifest_offset, manifest_block_id)  // ← Phase 1 新增接口
    .index(index_offset, index_size, index_block_id)
    .backup_header(backup_header_offset)
    .build();
```

**Phase 3 使用模式**（读取）:

```rust
// era-engine/src/reader.rs (Phase 3)
let footer = volume_reader.footer()?;

if footer.has_manifest() {
    // v8.2 路径
    let (manifest_offset, manifest_block_id) = footer.manifest_location().unwrap();
    // 加载 Manifest...
} else {
    // v8.2 fail-closed: 无 manifest 时报错
    return Err(EraError::unsupported_format(
        "Archive requires v8.2+ reader. Use --legacy-mode for v8.1 archives."
    ));
}
```

---

## 5. 跨层调用关系

### 5.1 Phase 2 调用链（写入管线）

```
era-engine::ArchiveWriter::finalize()
    ├── era-ingest::Catalog::to_bytes()          → catalog_plaintext
    ├── era-common::compute_catalog_commitment() → catalog_commitment
    ├── era-common::ArchiveManifest::new()       → manifest
    ├── era-common::ArchiveManifest::to_bytes()  → manifest_plaintext
    ├── era-crypto::encrypt()                    → manifest_encrypted
    ├── era-volume::VolumePool::write_canonical_block(BlockType::Manifest)
    └── era-volume::Footer::builder().manifest(offset, block_id).build()
```

### 5.2 Phase 3 调用链（读取管线）

```
era-engine::ArchiveReader::open()
    ├── era-volume::VolumeReader::footer()
    ├── Footer::has_manifest()                    → v8.2 检测
    ├── Footer::manifest_location()
    ├── era-volume::VolumeReader::read_typed_block()
    ├── era-crypto::decrypt()                     → manifest_plaintext
    ├── era-common::ArchiveManifest::from_bytes()
    ├── era-volume::VolumeReader::read_typed_block() → catalog_encrypted
    ├── era-crypto::decrypt()                     → catalog_plaintext
    ├── era-ingest::Catalog::from_bytes()
    └── era-common::verify_catalog_commitment()   → 承诺验证
```

### 5.3 Phase 4 调用链（恢复模块）

```
era-engine::RecoveryManager::recover()
    ├── era-volume::VolumeReader::footer()        → 所有 volume
    ├── Footer::manifest_location()
    ├── era-volume::VolumeReader::read_typed_block()
    ├── era-crypto::decrypt()
    ├── era-common::ArchiveManifest::from_bytes()
    └── 返回 RecoveryState { committed_horizon, epoch_id }
```

---

## 6. 不变量（Invariants）

以下不变量在所有阶段必须保持：

### 6.1 数据不变量

1. **Footer 大小**: `Footer::to_bytes().len() == 128`
2. **BlockType 值**: `BlockType::Manifest as u8 == 0x07`
3. **承诺大小**: `compute_catalog_commitment(..).len() == 32`
4. **Manifest 承诺空值**: 无 index 时 `index_commitment == [0u8; 32]`
5. **Catalog 索引一致性**: `block_locations.len()` 与 archive 的 block 数量一致

### 6.2 接口不变量

1. **向后兼容读取**: v8.1 Footer（manifest 字段为零）可被 v8.2 Footer::from_bytes() 正确解析
2. **向前兼容读取**: v8.2 Footer 可被 v8.1 Footer::from_bytes() 解析（忽略 reserved 字段）
3. **错误构造**: 所有 EraError 变体可通过辅助方法构造
4. **序列化确定性**: 相同内容的 Catalog/ArchiveManifest 产生相同的字节序列

### 6.3 安全不变量

1. **承诺确定性**: 相同 plaintext 始终产生相同 commitment
2. **承诺域分离**: `compute_catalog_commitment` 和 `compute_index_commitment` 使用不同 key
3. **Footer 校验和**: 修改任何字段（包括 manifest 字段）会破坏 checksum

---

## 7. 变更控制

Phase 1 完成后，以下接口的变更需要经过设计评审：

| 接口 | 变更类型 | 审批要求 |
|------|---------|---------|
| `ArchiveManifest` 字段 | 添加/删除/修改 | 需要更新 DESIGN_SPEC 和本契约 |
| `Footer` 字段 | 添加/删除/修改 | 需要验证 128 字节约束 |
| `BlockType` 变体 | 添加 | 需确认不冲突 |
| `EraError` 变体 | 添加 | 需确认命名一致性 |
| `compute_*_commitment` | 修改算法 | **严格禁止**（破坏已有 archive）|

---

*文档生成时间: 2026-04-21*  
*对应主规划: PLAN.md*
