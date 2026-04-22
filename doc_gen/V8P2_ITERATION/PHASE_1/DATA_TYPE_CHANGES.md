# PHASE 1: 数据类型变更详细对照表

**版本**: 1.0  
**日期**: 2026-04-21  

---

## 1. BlockType 枚举变更

### 变更前（v8.1）

```rust
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

### 变更后（v8.2）

```rust
#[repr(u8)]
pub enum BlockType {
    Data = 0x01,
    IndexPage = 0x02,
    IndexManifest = 0x03,
    Catalog = 0x04,
    LsmManifest = 0x05,
    Checkpoint = 0x06,
    Manifest = 0x07,        // ← 新增
    Reserved = 0xFF,
}
```

### 影响分析

| 影响点 | 说明 |
|--------|------|
| `BlockType::from_u8(0x07)` | 新增支持，返回 `Some(Manifest)` |
| `BlockType::from_u8(0x08..=0xFE)` | 仍返回 `None` |
| block_iter.rs 跳过逻辑 | Manifest 块应被跳过（与 IndexPage/Checkpoint 一致） |
| read_typed_block | 可返回 `BlockType::Manifest`，需 caller 处理 |

---

## 2. ArchiveManifest 新增类型

### Rust 结构

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveManifest {
    pub epoch_id: u32,
    pub finalize_sequence: u64,
    pub committed_horizon: u64,
    pub catalog_commitment: [u8; 32],
    pub index_commitment: [u8; 32],
}
```

### Protobuf Schema

```protobuf
message ArchiveManifest {
    uint32 epoch_id = 1;
    uint64 finalize_sequence = 2;
    uint64 committed_horizon = 3;
    bytes catalog_commitment = 4;
    bytes index_commitment = 5;
}
```

### 序列化大小估算

| 字段 | 类型 | 大小（protobuf） |
|------|------|----------------|
| epoch_id | uint32 | 1-5 bytes (varint) |
| finalize_sequence | uint64 | 1-10 bytes (varint) |
| committed_horizon | uint64 | 1-10 bytes (varint) |
| catalog_commitment | bytes(32) | 2-5 (length) + 32 = 34-37 bytes |
| index_commitment | bytes(32) | 2-5 (length) + 32 = 34-37 bytes |
| **总计** | | **~71-99 bytes** |

**典型大小**: ~80 bytes（加上 protobuf 消息包装开销）。加密后（XChaCha20-Poly1305 tag = 16 bytes）约为 **~96 bytes**。加上 BlockHeader（16 bytes），总存储约 **~112 bytes**。

---

## 3. Catalog 结构变更

### 变更前（v8.1）

```rust
pub struct Catalog {
    pub entries: Vec<FileEntry>,
    pub total_size: u64,
    pub file_count: u64,
    pub dir_count: u64,
}
```

```protobuf
message Catalog {
  repeated FileEntry entries = 1;
  uint64 total_size = 2;
  uint64 file_count = 3;
  uint64 dir_count = 4;
}
```

### 变更后（v8.2）

```rust
pub struct Catalog {
    pub entries: Vec<FileEntry>,
    pub block_locations: Vec<BlockLocation>,    // ← 新增
    pub total_size: u64,
    pub file_count: u64,
    pub dir_count: u64,
}
```

```protobuf
message Catalog {
  repeated FileEntry entries = 1;
  uint64 total_size = 2;           // 不变
  uint64 file_count = 3;           // 不变
  uint64 dir_count = 4;            // 不变
  repeated BlockLocation block_locations = 5;  // ← 新增字段 5（保持向后兼容）
}
```

### block_locations 大小估算

对于包含 N 个 block 的 archive：

| 场景 | block_locations 大小 |
|------|---------------------|
| 非纠删码，10K blocks | 10K × ~50 bytes = ~500 KB |
| 非纠删码，100K blocks | 100K × ~50 bytes = ~5 MB |
| 纠删码(4+2)，10K stripes | 10K × 4 × ~70 bytes = ~2.8 MB |

**BlockLocation protobuf 大小**:
- volume_id: 16 bytes (UUID) + 2-3 bytes overhead = ~19 bytes
- slot_index: 1-5 bytes
- physical_offset: 1-10 bytes
- encrypted_size: 1-5 bytes
- erasure_info (optional): ~15 bytes (if present)
- shard_offsets: 8 bytes each
- shard_volumes: 4 bytes each
- **典型 Single 布局**: ~40-50 bytes
- **典型 Erasure 布局**: ~70-90 bytes

**Catalog 总大小 overhead**:
- block_locations 占 archive 总大小的比例通常 < 1%
- 对于 1TB archive（~16K blocks @ 64MB），block_locations ≈ 800KB，占比 0.0008%

**纠删码语义澄清**:
- `block_locations[i]` 对应**逻辑 block index i**
- `BlockLocation.shard_layout::Erasure` 已包含该 block 的所有 shard 信息（`shard_offsets` + `shard_volumes`）
- 因此 block_locations 长度 = 逻辑 block 数量，**不是** `stripe_count × data_shards`

---

## 4. Footer 结构变更

### 变更前（v8.1）

```rust
pub struct Footer {
    magic: [u8; 4],
    version: u8,
    flags: u16,
    data_end_offset: u64,
    block_count: u32,
    sequence_number: u64,
    catalog_offset: u64,
    catalog_size: u32,
    catalog_block_id: u32,
    last_checkpoint_offset: u64,
    last_checkpoint_block_id: u32,
    // reserved3: u32 (implicitly zero)
    index_offset: u64,
    index_size: u32,
    index_block_id: u32,
    backup_header_offset: u64,
    // reserved4: u64 (implicitly zero)
    checksum: [u8; 32],
}
```

### 变更后（v8.2）

```rust
pub struct Footer {
    magic: [u8; 4],
    version: u8,
    flags: u16,
    data_end_offset: u64,
    block_count: u32,
    sequence_number: u64,
    catalog_offset: u64,
    catalog_size: u32,
    catalog_block_id: u32,
    last_checkpoint_offset: u64,
    last_checkpoint_block_id: u32,
    manifest_block_id: u32,          // ← 新增（复用 reserved3）
    index_offset: u64,
    index_size: u32,
    index_block_id: u32,
    backup_header_offset: u64,
    manifest_offset: u64,            // ← 新增（复用 reserved4）
    checksum: [u8; 32],
}
```

### 二进制布局对比

| Offset | Size | v8.1 Field | v8.2 Field | 说明 |
|--------|------|-----------|-----------|------|
| 0 | 4 | magic | magic | 不变 |
| 4 | 1 | version | version | 不变（仍为 1） |
| 5 | 1 | reserved1 | reserved1 | 不变 |
| 6 | 2 | flags | flags | 不变 |
| 8 | 8 | data_end_offset | data_end_offset | 不变 |
| 16 | 4 | block_count | block_count | 不变 |
| 20 | 4 | reserved2 | reserved2 | 不变 |
| 24 | 8 | sequence_number | sequence_number | 不变 |
| 32 | 8 | catalog_offset | catalog_offset | 不变 |
| 40 | 4 | catalog_size | catalog_size | 不变 |
| 44 | 4 | catalog_block_id | catalog_block_id | 不变 |
| 48 | 8 | last_checkpoint_offset | last_checkpoint_offset | 不变 |
| 56 | 4 | last_checkpoint_block_id | last_checkpoint_block_id | 不变 |
| **60** | **4** | **reserved3 (=0)** | **manifest_block_id** | **复用** |
| 64 | 8 | index_offset | index_offset | 不变 |
| 72 | 4 | index_size | index_size | 不变 |
| 76 | 4 | index_block_id | index_block_id | 不变 |
| 80 | 8 | backup_header_offset | backup_header_offset | 不变 |
| **88** | **8** | **reserved4 (=0)** | **manifest_offset** | **复用** |
| 96 | 32 | checksum | checksum | 不变 |
| **128** | | **Total** | **Total** | **仍为 128 字节** |

### 兼容性矩阵

| Writer | Reader | manifest_block_id | manifest_offset | 行为 |
|--------|--------|------------------|-----------------|------|
| v8.1 | v8.1 | N/A | N/A | 正常 |
| v8.1 | v8.2 | 0 | 0 | `has_manifest()` → false，按 v8.1 路径处理 |
| v8.2 | v8.1 | 非零 | 非零 | **checksum 验证通过**（覆盖全部 96 字节），忽略 reserved 字段，按 v8.1 路径处理 |
| v8.2 | v8.2 | 非零 | 非零 | `has_manifest()` → true，按 v8.2 路径处理 |

**关键**: Footer checksum 覆盖 raw 前 96 字节（包括 manifest 字段区域）。v8.1 reader 解析 v8.2 Footer 时 checksum 仍能通过，因为 checksum 计算不区分 reserved/manifest 字段——它只是哈希前 96 字节。

---

## 5. EraError 变更对照

### 新增变体

| 变体 | 使用场景 | 阶段 |
|------|---------|------|
| `BeyondCommitHorizon { offset, horizon }` | Reader 尝试读取超出 committed_horizon 的数据 | Phase 3 |
| `CatalogCommitmentMismatch` | Catalog 承诺与 Manifest 中存储的不匹配 | Phase 3 |
| `IndexCommitmentMismatch` | Index 承诺与 Manifest 中存储的不匹配 | Phase 3 |
| `VolumeSpaceExhausted { volume, required, available, message }` | typed block 预检查时发现空间不足 | Phase 2 |
| `ManifestLoadError(String)` | Manifest 加载/解密失败 | Phase 3 |
| `FooterInconsistency { field, expected, actual }` | 多卷 Footer 字段不一致 | Phase 4 |
| `AllTypedBlockCopiesCorrupted { kind, volume_count, warnings }` | 所有 volume 的某类型 typed block 均损坏 | Phase 3 |
| `TypedBlockNotFound(String)` | Footer 中无指定 typed block 的位置信息 | Phase 3 |
| `RepairVerificationFailed { kind, volume_idx, expected_crc, actual_crc }` | Repair 后副本验证失败 | Phase 4 |
| `UnsupportedFormat(String)` | 不支持的历史格式（v8.1 在 fail-closed 模式下） | Phase 3 |

---

## 6. 常量定义汇总

| 常量 | 值 | 定义位置 | 用途 |
|------|-----|---------|------|
| `MANIFEST_BLOCK_TYPE` | `BlockType::Manifest` | `era-common/src/types/block.rs` | Manifest typed block 类型标识 |
| `MANIFEST_BLOCK_TYPE_U8` | `0x07` | `era-common/src/types/block.rs` | Manifest 的原始字节值 |
| `FOOTER_VERSION` | `1` | `era-volume/src/footer.rs` | Footer 版本（保持不变） |
| `CATALOG_COMMITMENT_DOMAIN` | `b"ERA-CAT-COMMIT-v1___________"` | `era-common/src/commitment.rs` | Catalog 承诺域分离 key |
| `INDEX_COMMITMENT_DOMAIN` | `b"ERA-IDX-COMMIT-v1___________"` | `era-common/src/commitment.rs` | Index 承诺域分离 key |
| `INITIAL_FINALIZE_SEQUENCE` | `1` | `era-engine/src/sequence.rs`（新增） | 新 archive 的初始认证世代 |

---

*文档生成时间: 2026-04-21*  
*对应主规划: PLAN.md*
