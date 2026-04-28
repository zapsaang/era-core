# ERA Volume Format v8.2 — PHASE 2 实施规划

**版本**: 1.0  
**日期**: 2026-04-25  
**状态**: 规划完成，待执行  
**前置条件**: PHASE 1 基础结构已完成（类型定义、schema、承诺计算、Footer 扩展）  
**目标**: 完成 v8.2 写入管线的全部功能，使 ArchiveWriter 能够创建含 Manifest 的 v8.2 archive  

---

## 目录

1. [Phase 2 目标与范围](#1-phase-2-目标与范围)
2. [任务总览](#2-任务总览)
3. [任务详解](#3-任务详解)
   - 3.1 [Task 2.1: Catalog block_locations 填充](#31-task-21-catalog-block_locations-填充)
   - 3.2 [Task 2.2: Typed block 空间预检查与预先 rotation](#32-task-22-typed-block-空间预检查与预先-rotation)
   - 3.3 [Task 2.3: Manifest 构建 + AEAD 加密](#33-task-23-manifest-构建--aead-加密)
   - 3.4 [Task 2.4: 全副本冗余写入（Index + Manifest）](#34-task-24-全副本冗余写入index--manifest)
   - 3.5 [Task 2.5: Footer v2 写入（manifest 字段）](#35-task-25-footer-v2-写入manifest-字段)
   - 3.6 [Task 2.6: 构建验证](#36-task-26-构建验证)
4. [跨任务依赖关系](#4-跨任务依赖关系)
5. [文件变更清单](#5-文件变更清单)
6. [验收标准](#6-验收标准)
7. [风险与缓解](#7-风险与缓解)

---

## 1. Phase 2 目标与范围

### 1.1 核心目标

Phase 2 实现 v8.2 的**完整写入管线**，使 `ArchiveWriter::finalize()` 能够：

1. 填充 `Catalog.block_locations` 以支持 O(1) 块定位
2. 预检查 typed block 空间并在需要时预先 rotation
3. 构建、加密并写入 `ArchiveManifest` 到所有 volume
4. 将 Index 从单卷写入改为全副本冗余写入
5. 在 Footer 中正确写入 manifest 位置字段
6. 保持向后兼容的 Footer 版本（FOOTER_VERSION = 1）

### 1.2 范围边界

**包含**:
- Catalog block_locations 的收集与填充逻辑
- Typed block 空间预检查与预先 rotation 机制
- ArchiveManifest 的构建、承诺计算、AEAD 加密
- Manifest 和 Index 的全副本冗余写入
- Footer v2 的 manifest 字段写入
- 写入管线的集成测试

**不包含**（延后到 Phase 3-4）:
- Manifest 的加载与验证（读取管线）
- 多副本验证加载逻辑
- committed_horizon 的强制执行
- RecoveryManager 的 manifest 驱动重写
- Repair 的 typed block 副本修复

### 1.3 设计约束

1. **Typed block 不触发 rotation**: 写入前预检查，空间不足时预先 rotation
2. **全副本冗余**: Catalog、Index、Manifest 写入所有 volume，各副本内容一致（相同 plaintext，不同 nonce）
3. **复用现有密码学模式**: Manifest 加密复用 BLOCK_KEY_DOMAIN，每卷使用不同 nonce
4. **Footer 语义不变**: FOOTER_VERSION 保持为 1，manifest 字段复用 reserved 空间
5. **data_end_offset 物理语义不变**: 仍等于 backup_header_offset，包含 typed block 区域
   - **注意**: ROADMAP.md §3.2 声称 `data_end_offset = backup_header_offset - TRAILER_RESERVED` 是"修复"，这是**错误**的。该变更会破坏 `scan_for_typed_blocks()` 和 Reader 的读取能力。`data_end_offset` 必须保持等于 `backup_header_offset`（包含 typed block 区域），`committed_horizon` 作为逻辑边界记录在 Manifest 中。
   - 详见附录 A.1.1

---

## 2. 任务总览

| 任务 | 内容 | 目标 crate | 预估工时 | 风险 |
|------|------|-----------|---------|------|
| 2.1 | Catalog block_locations 填充 | era-engine | 2 天 | 中 |
| 2.2 | Typed block 空间预检查与预先 rotation | era-volume | 1 天 | 中 |
| 2.3 | Manifest 构建 + AEAD 加密 | era-engine | 2 天 | 高 |
| 2.4 | 全副本冗余写入（Index + Manifest） | era-engine, era-volume | 2 天 | 高 |
| 2.5 | Footer v2 写入（manifest 字段） | era-volume | 1 天 | 中 |
| 2.6 | 构建验证 | workspace | 1 天 | 低 |
| **合计** | | | **~9 天** | |

---

## 3. 任务详解

### 3.1 Task 2.1: Catalog block_locations 填充

#### 3.1.1 目标

在写入阶段收集每个 block 的 `BlockLocation`，在 finalize 时按 `block_index` 顺序填充到 `Catalog.block_locations`，使 Reader 能够通过 `catalog.block_locations[i]` 进行 O(1) 定位。

#### 3.1.2 涉及文件

- `crates/era-engine/src/write_pipeline.rs`
- `crates/era-engine/src/writer.rs`
- `crates/era-engine/src/index_stage.rs`
- `crates/era-ingest/src/entry.rs`（确认 Catalog 结构）

#### 3.1.3 当前状态

```rust
// era-ingest/src/entry.rs:336-352
pub struct Catalog {
    pub entries: Vec<FileEntry>,
    pub block_locations: Vec<era_common::BlockLocation>,  // ← 已定义，但未填充
    pub total_size: u64,
    pub file_count: u64,
    pub dir_count: u64,
}
```

当前代码中，`block_locations` 字段在 `Catalog::new()` 中初始化为空 Vec，且**没有任何代码**在写入过程中填充它。`ChunkIndex`（`HashMap<ChunkHash, BlockLocation>`）确实跟踪了 chunk→location 映射，但这些信息从未被复制到 Catalog。

#### 3.1.4 所需改动

**改动 1**: 在 `WritePipeline` 中增加 `written_blocks` 列表，按写入顺序跟踪 BlockLocation

```rust
// crates/era-engine/src/write_pipeline.rs
pub struct WritePipeline {
    // ... 现有字段 ...
    
    /// 按写入顺序记录每个 block 的 BlockLocation。
    /// 用于在 finalize 时填充 Catalog.block_locations。
    /// 
    /// 索引规则：written_blocks[i] 对应逻辑 block index i。
    /// 非纠删码：每个 EncryptedMacroBlock 对应一个 BlockLocation
    /// 纠删码：每个 stripe 对应一个 BlockLocation（包含所有 shard 元数据）
    written_blocks: Vec<era_common::BlockLocation>,
}

impl WritePipeline {
    pub fn new(...) -> Self {
        Self {
            // ... 现有字段 ...
            written_blocks: Vec::new(),
        }
    }
    
    /// 获取已写入 block 的数量（即下一个 block 的索引）。
    pub fn blocks_written(&self) -> usize {
        self.written_blocks.len()
    }
    
    /// 获取所有已写入 block 的 BlockLocation（按 block_index 顺序）。
    pub fn written_block_locations(&self) -> &[era_common::BlockLocation] {
        &self.written_blocks
    }
}
```

**改动 2**: 在非纠删码路径中记录 BlockLocation

```rust
// crates/era-engine/src/write_pipeline.rs
// 在 process_chunks() 的非纠删码路径中（当前代码约 171-181 行）

// 非纠删码路径：直接写入
let (location, _volume_id) = self.volume.write_block(&encrypted_block, BlockType::Data).await?;

// 记录此 block 的 BlockLocation（按写入顺序）
self.written_blocks.push(location.clone());

// Update index for all hashes（现有逻辑不变）
for hash in hashes {
    self.index.record_location(hash, location.clone())?;
}
```

**改动 3**: 在纠删码路径中记录 BlockLocation

```rust
// crates/era-engine/src/write_pipeline.rs
// 在 flush_stripe_internal() 的纠删码路径中（当前代码约 336-374 行）

// 构建 erasure BlockLocation，包含所有 shard 信息
let loc = BlockLocation::erasure(
    volume_0_id,
    block_id,
    first_shard_offset,
    total_encrypted_len as u32,
    erasure_info,
    shard_offsets,
    shard_volumes,
)?;

// 记录此 stripe 的 BlockLocation（按写入顺序）
self.written_blocks.push(loc.clone());

// Update index for all chunk hashes（现有逻辑不变）
for hash in &meta.chunk_hashes {
    self.index.record_location(*hash, loc.clone())?;
}
```

**改动 4**: 在 `ArchiveWriter::finalize()` 中填充 `catalog.block_locations`

```rust
// crates/era-engine/src/writer.rs
// 在 ArchiveWriter::finalize() 中，serialize catalog 之前

pub async fn finalize(mut self) -> Result<ArchiveStats> {
    // ... 现有 flush 逻辑 ...
    
    // === 新增：填充 catalog.block_locations ===
    // 从 pipeline 提取按顺序记录的 BlockLocation
    let block_locations = self.pipeline.take_written_block_locations();
    
    // 验证长度一致性
    let expected_blocks = self.pipeline.blocks_written();
    if block_locations.len() != expected_blocks {
        return Err(EraError::IntegrityError(format!(
            "Block location count mismatch: expected {}, got {}",
            expected_blocks, block_locations.len()
        )));
    }
    
    // 填充到 catalog
    self.catalog.block_locations = block_locations;
    
    // === 现有逻辑：序列化 catalog ===
    let catalog_bytes = self.catalog.to_bytes()?;
    
    // ... 后续 catalog 分块、写入、finalize ...
}
```

**改动 5**: 在 `GenericArchiveWriter` 中同样填充 block_locations

```rust
// crates/era-engine/src/writer.rs
// 在 GenericArchiveWriter::finalize() 中（约 2594 行）
// 采用相同的模式：在 serialize catalog 前填充 block_locations
```

**改动 6**: 在 `ArchiveWriter` 中新增字段

```rust
// crates/era-engine/src/writer.rs

pub struct ArchiveWriter {
    // ... 现有字段 ...
    
    /// 当前认证世代号。
    /// 新 archive：`None`（使用 `INITIAL_FINALIZE_SEQUENCE = 1`）
    /// 追加模式：`Some(n)`（从现有 Manifest 读取，Phase 4 实现）
    finalize_sequence: Option<u64>,
    
    /// 已分配的 typed block 数量（用于 block_id 分配）。
    /// 跟踪 Catalog、Index、Manifest 已占用的 block_id，防止冲突。
    typed_blocks_allocated: u64,
}

impl ArchiveWriter {
    pub fn new(...) -> Self {
        Self {
            // ... 现有字段初始化 ...
            finalize_sequence: None,
            typed_blocks_allocated: 0,
        }
    }
}
```

#### 3.1.5 索引规则与边界情况

**索引规则**:
- `block_locations[i]` 对应逻辑 block index `i`
- 非纠删码 archive：`block_locations.len() == block_count`（每个 encrypted macro block 一个 location）
- 纠删码 archive：`block_locations.len() == stripe_count`（每个 stripe 一个 location，`BlockLocation.shard_layout::Erasure` 包含所有 shards 的元数据）

**边界情况处理**:
- **空 archive**（无数据块）：`block_locations` 为空 Vec，序列化正常
- **Catalog 本身作为 typed block**：不计入 `block_locations`（`block_locations` 只记录数据块）
- **Checkpoint blocks**：是否计入？→ **不计入**，`block_locations` 只记录用户数据块，checkpoint 是内部元数据
- **内部元数据块**（如 internal metadata）：不计入

**验证**: 在 finalize 时检查 `block_locations.len() == blocks_written`（用户数据块计数）。

#### 3.1.6 关键设计决策

**为什么不用 ChunkIndex 来重建 block_locations？**
- ChunkIndex 是 `HashMap<ChunkHash, BlockLocation>`，按 chunk hash 索引，不是按 block_index 顺序
- 同一个 block 包含多个 chunks，ChunkIndex 中有多个条目指向同一个 BlockLocation
- 从 ChunkIndex 重建 block_locations 需要去重和排序，复杂且容易出错
- 直接在写入时按顺序记录更简单、更高效

**written_blocks 的内存开销**:
- 每个 `BlockLocation` 约 64-128 bytes（取决于 shard_layout）
- 100K blocks → ~10-15 MB 内存，可接受
- 如需优化，可在 finalize 后释放（`take_written_block_locations()` 移动所有权）

#### 3.1.7 验收标准

- [ ] 非纠删码 archive 的 `catalog.block_locations` 长度等于数据块数量
- [ ] 纠删码 archive 的 `catalog.block_locations` 长度等于 stripe 数量
- [ ] `block_locations[i]` 的 `physical_offset` 和 `encrypted_size` 与实际写入位置一致
- [ ] 纠删码 archive 的 `block_locations[i].shard_layout` 为 `Erasure`，且包含正确的 `shard_offsets` 和 `shard_volumes`
- [ ] 空 archive 的 `block_locations` 为空 Vec，序列化/反序列化正常
- [ ] 现有测试通过（无 regression）

---

### 3.2 Task 2.2: Typed block 空间预检查与预先 rotation

#### 3.2.1 目标

在 finalize 阶段写入 typed blocks（Catalog/Index/Manifest）之前，预检查所有 volume 是否有足够空间。空间不足时**预先 rotation**（创建新 volume），确保 typed block 的写入操作本身**不触发 rotation**。

#### 3.2.2 涉及文件

- `crates/era-volume/src/volume_pool.rs`
- `crates/era-volume/src/volume_pool.rs`（VolumePool 的 `needs_expansion` 和 `rotate_volumes`）
- `crates/era-engine/src/volume_stage.rs`
- `crates/era-engine/src/writer.rs`

#### 3.2.3 当前状态

当前代码中，typed blocks（Catalog）的写入通过 `VolumeStage::write_catalog_blocks_to_all()` 直接调用 `VolumeWriter::write_canonical_block()`。如果空间不足，`write_canonical_block()` 内部会触发 rotation（通过 `VolumePool::write_canonical_block()` 中的 `volume_can_fit` 检查）。这违反了 v8.2 的"typed block 不触发 rotation"约束。

#### 3.2.4 所需改动

**改动 1**: 在 `VolumePool` 中新增 `typed_block_space_check` 方法

```rust
// crates/era-volume/src/volume_pool.rs

impl<B: StorageBackend> VolumePool<B> {
    /// 检查所有 volume 是否有足够空间写入指定大小的 typed blocks。
    /// 
    /// 返回需要 rotation 的 volume 列表。如果返回空，表示所有 volume 空间充足。
    /// 
    /// # Arguments
    /// * `total_size_per_volume` - 每个 volume 需要写入的 typed blocks 总大小
    ///   （包括 Catalog + Index + Manifest + 3 * BlockHeader::SIZE）
    pub fn check_typed_block_space(&self, total_size_per_volume: u64) -> Vec<usize> {
        let mut need_rotation = Vec::new();
        for slot in 0..self.writers.len() {
            let remaining = self.volume_remaining_space(slot);
            if remaining < total_size_per_volume {
                need_rotation.push(slot);
            }
        }
        need_rotation
    }
    
    /// 获取指定 volume 的剩余可用空间（字节）。
    pub fn volume_remaining_space(&self, slot: usize) -> u64 {
        let writer = match self.writers.get(slot) {
            Some(w) => w,
            None => return 0,
        };
        let current_size = writer.current_size();
        self.config.max_volume_size.saturating_sub(current_size).saturating_sub(super::PER_VOLUME_OVERHEAD)
    }
}
```

**改动 2**: 在 `VolumePool` 中新增 `precheck_and_rotate_if_needed` 方法

```rust
// crates/era-volume/src/volume_pool.rs

impl<B: StorageBackend> VolumePool<B> {
    /// 在写入 typed blocks 之前预检查空间，不足时预先 rotation。
    /// 
    /// **约束**：typed block 的写入操作本身不触发 rotation。
    /// 空间不足时，此方法会创建新 volume 并将旧 volume 的 writers 替换掉。
    /// 
    /// # Arguments
    /// * `catalog_size` - Catalog 加密后的大小（每卷）
    /// * `index_size` - Index 加密后的大小（每卷，0 表示无 index）
    /// * `manifest_size` - Manifest 加密后的大小（每卷）
    /// 
    /// # Returns
    /// `true` 如果发生了 rotation，`false` 如果空间充足无需 rotation。
    pub async fn precheck_and_rotate_if_needed(
        &mut self,
        catalog_size: u64,
        index_size: u64,
        manifest_size: u64,
    ) -> Result<bool> {
        // 计算每卷需要的总空间
        // 每个 typed block 需要额外的 BlockHeader（16 bytes）
        let header_size = BlockHeader::SIZE as u64;
        let total_per_volume = catalog_size + index_size + manifest_size
            + 3 * header_size; // 3 个 typed blocks 的 header
        
        // 检查是否有 volume 空间不足
        let need_rotation = self.check_typed_block_space(total_per_volume);
        
        if need_rotation.is_empty() {
            // 所有 volume 空间充足
            return Ok(false);
        }
        
        // 空间不足：预先 rotation
        // 注意：rotation 会创建新 volume，所有旧 volume 会被 finalize
        // 这可能会改变 volume 的数量和 writers 列表
        warn!(
            "Volume space insufficient for typed blocks (need {} bytes per volume). \
             Pre-rotating volumes before typed block write.",
            total_per_volume
        );
        
        self.rotate_volumes().await?;
        
        // rotation 后，验证新 volume 的空间是否充足
        // 新 volume 是空的，通常空间充足，但为安全起见再检查一次
        let still_insufficient = self.check_typed_block_space(total_per_volume);
        if !still_insufficient.is_empty() {
            return Err(era_common::EraError::VolumeSpaceExhausted {
                volume: still_insufficient[0],
                required: total_per_volume,
                available: self.volume_remaining_space(still_insufficient[0]),
                message: "Insufficient space even after rotation".into(),
            });
        }
        
        Ok(true)
    }
}
```

**改动 3**: 在 `VolumeStage` 中暴露预检查方法

```rust
// crates/era-engine/src/volume_stage.rs

impl<B: StorageBackend> VolumeStage<B> {
    /// 预检查 typed block 空间，不足时预先 rotation。
    /// 
    /// 代理到 VolumePool::precheck_and_rotate_if_needed。
    pub async fn precheck_and_rotate_if_needed(
        &mut self,
        catalog_size: u64,
        index_size: u64,
        manifest_size: u64,
    ) -> Result<bool> {
        self.pool.precheck_and_rotate_if_needed(catalog_size, index_size, manifest_size).await
    }
}
```

**改动 4**: 在 `ArchiveWriter::finalize()` 中调用预检查

```rust
// crates/era-engine/src/writer.rs
// 在 ArchiveWriter::finalize() 中，写入 typed blocks 之前

pub async fn finalize(mut self) -> Result<ArchiveStats> {
    // ... 现有 flush 逻辑 ...
    
    // === 新增：预检查 typed block 空间 ===
    // 估算 Catalog、Index、Manifest 的大小
    let catalog_plaintext_size = self.catalog.to_bytes()?.len() as u64;
    // Catalog 加密后大小 ≈ plaintext + AEAD tag (16 bytes)
    let catalog_encrypted_size = catalog_plaintext_size + 16;
    
    // Index 大小（如果有）
    let index_encrypted_size = if self.pipeline.index().has_index() {
        // 从 index builder 获取估算大小，或使用默认值
        // 实际大小在 finalize 时确定
        estimate_index_size(&self.pipeline).unwrap_or(0)
    } else {
        0
    };
    
    // Manifest 大小（固定较小）
    let manifest_plaintext_size = estimate_manifest_size(&self.pipeline);
    let manifest_encrypted_size = manifest_plaintext_size + 16;
    
    // 预检查并预先 rotation（如需要）
    let did_rotate = self.pipeline
        .volume_mut()
        .precheck_and_rotate_if_needed(
            catalog_encrypted_size,
            index_encrypted_size,
            manifest_encrypted_size,
        )
        .await?;
    
    if did_rotate {
        info!("Volumes pre-rotated before typed block write");
    }
    
    // === 继续：序列化并写入 typed blocks ===
    // ... 现有逻辑 ...
}
```

**注意**: 预检查需要在 catalog 序列化之后、写入之前进行。如果预检查触发了 rotation，旧 volume 会被 finalize（写入 Footer），新 volume 会被创建。然后 typed blocks 写入新 volume。

#### 3.2.5 关键设计决策

**为什么不在写入中触发 rotation？**
- Typed blocks（Catalog/Index/Manifest）必须在同一代 volume 中全副本冗余
- 如果在写入 Catalog 后、写入 Manifest 前触发 rotation，会导致不同 typed block 分布在不同代的 volume 中
- 这会破坏全副本冗余的假设，使 Reader 难以定位所有 typed blocks

**预检查的时机**:
- 在 catalog 序列化之后（知道确切大小）
- 在写入任何 typed block 之前
- 如果触发 rotation，旧 volume 被 finalize，新 volume 接收所有 typed blocks

**空间估算**:
- Catalog 大小 = plaintext + AEAD tag（16 bytes）+ BlockHeader（16 bytes）
- Index 大小需要从 index builder 获取估算
- Manifest 大小固定较小（~80 bytes plaintext）
- 保守估算可加上 10% 余量

#### 3.2.6 验收标准

- [ ] 空间充足时，typed blocks 正常写入，不触发 rotation
- [ ] 空间不足时，预先 rotation 成功，typed blocks 写入新 volume
- [ ] rotation 后所有 volume 的 typed blocks 在同一代中
- [ ] 空间严重不足（超过单卷容量）时返回明确的错误
- [ ] 现有 volume rotation 测试通过（无 regression）

---

### 3.3 Task 2.3: Manifest 构建 + AEAD 加密

#### 3.3.1 目标

在 `ArchiveWriter::finalize()` 中构建 `ArchiveManifest`，计算 Catalog 和 Index 的承诺值，使用 AEAD 加密（复用 block key 派生，每卷不同 nonce），生成可写入的 `EncryptedMacroBlock`。

#### 3.3.2 涉及文件

- `crates/era-engine/src/writer.rs`
- `crates/era-crypto/src/aead_context.rs`（确认 AAD 绑定和 nonce 派生）
- `crates/era-crypto/src/key_session.rs`（确认 block key 派生接口）
- `crates/era-common/src/types/manifest.rs`

#### 3.3.3 当前状态

`ArchiveManifest` 类型和承诺计算函数已实现，但 `ArchiveWriter::finalize()` 中没有任何 Manifest 构建/加密的逻辑。

#### 3.3.4 所需改动

**改动 1**: 在 `ArchiveWriter` 中新增 Manifest 构建方法

```rust
// crates/era-engine/src/writer.rs

impl ArchiveWriter {
    /// 构建 ArchiveManifest，包含 Catalog 和 Index 的承诺。
    /// 
    /// 在 finalize 阶段调用，在 Catalog 序列化之后、写入之前。
    fn build_manifest(
        &self,
        catalog_plaintext: &[u8],
        index_plaintext: Option<&[u8]>,
    ) -> Result<ArchiveManifest> {
        // 计算 Catalog 承诺
        let catalog_commitment = era_crypto::compute_catalog_commitment(catalog_plaintext);
        
        // 计算 Index 承诺（如存在）
        let index_commitment = index_plaintext
            .map(|p| era_crypto::compute_index_commitment(p))
            .unwrap_or([0u8; 32]);
        
        // 获取当前的 finalize_sequence
        // 新 archive：INITIAL_FINALIZE_SEQUENCE（= 1）
        // 追加模式：从现有 Manifest 读取并递增（Phase 4 实现）
        let finalize_sequence = self.finalize_sequence.unwrap_or(INITIAL_FINALIZE_SEQUENCE);
        
        // committed_horizon = 最后一个数据块的结束位置
        // 即数据区域的逻辑边界，不包含 typed blocks（Catalog/Index/Manifest）
        let committed_horizon = if !self.catalog.block_locations.is_empty() {
            let last_loc = self.catalog.block_locations.last().unwrap();
            last_loc.physical_offset + last_loc.encrypted_size as u64
        } else {
            // 空 archive：使用数据区域起始位置
            era_volume::DATA_REGION_START as u64
        };
        
        Ok(ArchiveManifest::new(
            self.epoch_id,
            finalize_sequence,
            committed_horizon,
            catalog_commitment,
            index_commitment,
        ))
    }
}
```

**改动 2**: 在 `era-common` 中新增 `ManifestBlock` 类型（供 Phase 2-4 共享）

```rust
// crates/era-common/src/types/manifest.rs

/// 待加密的 Manifest 块（明文）。
/// 
/// 与 `EncryptedMacroBlock` 的区别：此类型存储明文，需要在写入前加密。
/// 放在 era-common 中，使 Phase 3 的 Reader 和 Phase 4 的 Repair 可以复用相同的
/// 加密/解密逻辑。
#[derive(Debug, Clone)]
pub struct ManifestBlock {
    pub block_id: BlockId,
    pub plaintext: Vec<u8>,
    pub original_size: u32,
    pub chunk_count: u32,
}

impl ManifestBlock {
    /// 将 ManifestBlock 加密为 EncryptedMacroBlock（针对特定 volume）。
    /// 
    /// 每卷使用不同的 nonce（混入 volume_index），但使用相同的 block key。
    /// AAD 包含类型标识 "MANIFEST"，防止跨类型重放攻击。
    pub fn encrypt_for_volume(
        &self,
        session: &era_crypto::KeySession,
        volume_key: &era_crypto::VolumeKey,
        nonce_context: &[u8; 16],
        archive_id: &era_common::ArchiveId,
        epoch_id: u32,
        volume_index: u32,
    ) -> Result<EncryptedMacroBlock> {
        // 派生 block key（key 与 volume_index 无关）
        let block_key = session.derive_block_key(
            volume_key,
            self.block_id.sequence(),
            nonce_context,
        )?;
        
        // 派生 nonce（混入 volume_index）
        let nonce = derive_nonce_with_volume_index(nonce_context, self.block_id, volume_index);
        
        // 构建 AAD
        let aad = build_manifest_aad(archive_id, epoch_id, volume_index, self.block_id);
        
        // AEAD 加密
        let ciphertext = era_crypto::aead_encrypt(
            &block_key,
            &nonce,
            &self.plaintext,
            &aad,
        )?;
        
        Ok(EncryptedMacroBlock {
            block_id: self.block_id,
            data: Bytes::from(ciphertext),
            original_size: self.original_size,
            compressed_size: self.original_size,
            chunk_count: self.chunk_count,
        })
    }
}

impl ArchiveWriter {
    /// 将 Manifest 序列化为 ManifestBlock（明文，尚未加密）。
    /// 
    /// 加密操作由 VolumeStage::write_manifest_to_all 在每卷分别执行。
    fn build_manifest_block(
        &self,
        manifest: &ArchiveManifest,
        block_id: BlockId,
    ) -> Result<ManifestBlock> {
        let plaintext = manifest.to_bytes()?;
        Ok(ManifestBlock {
            block_id,
            plaintext,
            original_size: plaintext.len() as u32,
            chunk_count: 1,
        })
    }
}
```

**改动 3**: 在 `VolumeStage` 中新增 `write_manifest_to_all` 方法

```rust
// crates/era-engine/src/volume_stage.rs

impl<B: StorageBackend> VolumeStage<B> {
    /// 将 Manifest 写入所有 volume（全副本冗余）。
    /// 
    /// 每卷使用不同的 nonce（AAD 绑定 volume_index），但使用相同的 block key
    ///（从 block_id 派生）。各卷密文长度相同，内容不同。
    /// 
    /// # Arguments
    /// * `manifest_plaintext` - Manifest 的序列化明文
    /// * `block_id` - Manifest 的 block ID
    /// * `session` - KeySession 用于派生 block key
    /// * `volume_key` - VolumeKey 用于派生 block key
    /// * `nonce_context` - Nonce 上下文
    /// * `archive_id` - Archive ID 用于 AAD
    /// * `epoch_id` - Epoch ID 用于 AAD
    /// 
    /// # Returns
    /// 每卷的 Manifest 位置 `(offset, size, block_id)`。
    pub async fn write_manifest_to_all(
        &mut self,
        manifest_plaintext: &[u8],
        block_id: BlockId,
        session: &era_crypto::KeySession,
        volume_key: &era_crypto::VolumeKey,
        nonce_context: &[u8; 16],
        archive_id: &era_common::ArchiveId,
        epoch_id: u32,
    ) -> Result<Vec<(u64, u32, u32)>> {
        let volume_count = self.pool.volume_count();
        let mut manifest_locations = Vec::with_capacity(volume_count);
        
        // 派生 block key（key 与 volume_index 无关）
        let block_key = session.derive_block_key(
            volume_key,
            block_id.sequence(),
            nonce_context,
        )?;
        
        for slot in 0..volume_count {
            if let Some(writer) = self.pool.get_writer_mut(slot) {
                // 为此卷派生 nonce（混入 volume_index）
                let nonce = derive_nonce_with_volume_index(
                    nonce_context,
                    block_id,
                    slot as u32,
                );
                
                // 构建 AAD：archive_id ‖ epoch_id ‖ volume_index ‖ block_id
                let aad = build_manifest_aad(archive_id, epoch_id, slot as u32, block_id);
                
                // AEAD 加密
                let ciphertext = era_crypto::aead_encrypt(
                    &block_key,
                    &nonce,
                    manifest_plaintext,
                    &aad,
                )?;
                
                // 构建 EncryptedMacroBlock
                let encrypted_block = EncryptedMacroBlock {
                    block_id,
                    data: Bytes::from(ciphertext),
                    original_size: manifest_plaintext.len() as u32,
                    compressed_size: manifest_plaintext.len() as u32,
                    chunk_count: 1,
                };
                
                // 写入此卷
                let location = writer
                    .write_canonical_block(&encrypted_block, BlockType::Manifest)
                    .await?;
                
                manifest_locations.push((
                    location.physical_offset,
                    location.encrypted_size,
                    block_id.sequence() as u32,
                ));
            } else {
                return Err(EraError::Other(format!(
                    "Missing writer for slot {} while writing manifest",
                    slot
                )));
            }
        }
        
        Ok(manifest_locations)
    }
}
```

**改动 4**: 添加 nonce 派生辅助函数

```rust
// crates/era-crypto/src/aead_context.rs 或 era-engine/src/writer.rs

/// 派生 Manifest 的 nonce，混入 volume_index 确保各卷密文不同。
/// 
/// 复用现有的 nonce 派生逻辑，但额外混入 volume_index。
fn derive_nonce_with_volume_index(
    nonce_context: &[u8; 16],
    block_id: BlockId,
    volume_index: u32,
) -> [u8; 24] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ERA-NONCE-V2");
    hasher.update(nonce_context);
    hasher.update(&block_id.sequence().to_le_bytes());
    hasher.update(&volume_index.to_le_bytes());
    let hash = hasher.finalize();
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&hash.as_bytes()[..24]);
    nonce
}

/// 构建 Manifest 的 AAD。
/// AAD = archive_id ‖ epoch_id ‖ "MANIFEST" ‖ block_id
fn build_manifest_aad(
    archive_id: &era_common::ArchiveId,
    epoch_id: u32,
    volume_index: u32,
    block_id: BlockId,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32);
    aad.extend_from_slice(archive_id.as_bytes());
    aad.extend_from_slice(&epoch_id.to_le_bytes());
    aad.extend_from_slice(b"MANIFEST");
    aad.extend_from_slice(&volume_index.to_le_bytes());
    aad.extend_from_slice(&block_id.sequence().to_le_bytes());
    aad
}
```

**注意**: 实际的 nonce 派生和 AAD 构建需要与现有代码库中的 `aead_context.rs` 保持一致。上述伪代码是概念性的，实际实现应复用或扩展现有的 `AeadContext`。

#### 3.3.5 关键设计决策

**为什么每卷使用不同的 nonce？**
- 现有代码的 AAD 绑定包含 `volume_index`（`aead_context.rs:38-42`）
- 如果所有卷使用相同的 nonce 和 AAD，则 AAD 必须相同 → 必须固定 `volume_index = 0`
- 这会削弱上下文绑定安全性，且与现有测试（`test_volume_index_binding_prevents_cross_volume_attack`）矛盾
- 方案：每卷使用不同的 nonce（混入 volume_index），AAD 保持完整绑定

**为什么复用 BLOCK_KEY_DOMAIN？**
- Manifest 本质上是特殊的 typed block
- 使用与普通数据块相同的密钥派生逻辑，不引入额外的密码学复杂度
- 各卷使用相同的 block key（从 block_id 派生），只有 nonce 不同

**Manifest block_id 的分配**:
- 使用 `pipeline.blocks_written()` 作为下一个可用的 block_id
- 或者使用一个专门的 block_id 范围（如从某个偏移开始）
- 推荐：使用 `pipeline.blocks_written()`，因为 Manifest 是在所有数据块之后写入的

#### 3.3.6 验收标准

- [ ] Manifest 正确序列化为 protobuf bytes
- [ ] `catalog_commitment` 与 `compute_catalog_commitment()` 结果一致
- [ ] `index_commitment` 与 `compute_index_commitment()` 结果一致（或无 index 时为全零）
- [ ] `epoch_id` 与 SuperHeader.epoch_id 一致
- [ ] `finalize_sequence` 正确递增
- [ ] `committed_horizon` 等于当前 data_end_offset
- [ ] 每卷的 Manifest 密文不同（nonce 不同），但均可正确解密
- [ ] AEAD tag 验证通过

---

### 3.4 Task 2.4: 全副本冗余写入（Index + Manifest）

#### 3.4.1 目标

将 Index 从仅写入 volume 0 改为写入所有 volume（全副本冗余），并实现 Manifest 的全副本冗余写入。

#### 3.4.2 涉及文件

- `crates/era-engine/src/writer.rs`
- `crates/era-engine/src/volume_stage.rs`
- `crates/era-index/src/builder.rs`（确认 IndexBuilder::finalize 接口）

#### 3.4.3 当前状态

当前代码中，Index 仅写入 volume 0（`writer.rs:1931-1940`）：
```rust
if let Some(writer) = self.pipeline.volume_mut().get_writer_mut(0) {
    match builder.finalize_with_starting_block_id(writer, ...).await {
        Ok((_meta_index, manifest_location)) => {
            // Volume 0 gets the real location
            locs.push((...));
            // Other volumes get zeroed entries
            for _ in 1..volume_count {
                locs.push((0, 0, 0));
            }
        }
    }
}
```

#### 3.4.4 所需改动

**改动 1**: 在 `VolumeStage` 中新增 `write_index_to_all` 方法

```rust
// crates/era-engine/src/volume_stage.rs

impl<B: StorageBackend> VolumeStage<B> {
    /// 将 Index 写入所有 volume（全副本冗余）。
    /// 
    /// 与 write_catalog_to_all 类似，但针对 Index typed blocks。
    /// 各卷使用相同的 block_id，但不同的 nonce（AAD 绑定 volume_index）。
    /// 
    /// # Arguments
    /// * `blocks` - Index 的加密块列表（通常只有一个块）
    /// * `session`, `volume_key`, `nonce_context` - 加密参数
    /// * `archive_id`, `epoch_id` - AAD 参数
    /// 
    /// # Returns
    /// 每卷的 Index 位置 `(offset, size, block_id)`。
    pub async fn write_index_to_all(
        &mut self,
        blocks: &[EncryptedMacroBlock],
        session: &era_crypto::KeySession,
        volume_key: &era_crypto::VolumeKey,
        nonce_context: &[u8; 16],
        archive_id: &era_common::ArchiveId,
        epoch_id: u32,
    ) -> Result<Vec<(u64, u32, u32)>> {
        let volume_count = self.pool.volume_count();
        let mut index_locations = Vec::with_capacity(volume_count);
        
        let first_block_id = u32::try_from(blocks[0].block_id.sequence())
            .map_err(|_| EraError::Other("Block sequence ID exceeds u32::MAX".into()))?;
        
        for slot in 0..volume_count {
            if let Some(writer) = self.pool.get_writer_mut(slot) {
                let mut first_location = None;
                
                for (i, block) in blocks.iter().enumerate() {
                    // 每卷重新加密（不同的 nonce）
                    let nonce = derive_nonce_with_volume_index(
                        nonce_context,
                        block.block_id,
                        slot as u32,
                    );
                    
                    let aad = build_manifest_aad(archive_id, epoch_id, slot as u32, block.block_id);
                    // ... AEAD 加密 ...
                    
                    let encrypted_block = // ... 重新加密后的块 ...
                    
                    let location = writer
                        .write_canonical_block(&encrypted_block, BlockType::IndexManifest)
                        .await?;
                    
                    if i == 0 {
                        location.slot_index = first_block_id;
                        first_location = Some(location);
                    }
                }
                
                let loc = first_location
                    .ok_or_else(|| EraError::Other("No index block written".into()))?;
                index_locations.push((loc.physical_offset, loc.encrypted_size, first_block_id));
            } else {
                return Err(EraError::Other(format!(
                    "Missing index writer slot {slot}"
                )));
            }
        }
        
        Ok(index_locations)
    }
}
```

**改动 2**: 修改 `ArchiveWriter::finalize()` 中的 Index 写入逻辑

```rust
// crates/era-engine/src/writer.rs
// 替换现有的 Index 仅写入 volume 0 的逻辑

// Finalize the V2.1 index: write typed index blocks to ALL volumes
let volume_count = self.pipeline.volume().pool().volume_count();
let index_locations = if let Some(mut builder) = self.pipeline.index().take_index_builder() {
    let session = self.pipeline.encryption().session().try_clone()?;
    let volume_key = self.pipeline.encryption().volume_key().try_clone()?;
    let nonce_context = self.pipeline.encryption().nonce_context();
    let index_start_block_id = self.pipeline.blocks_written();
    
    // 获取 Index 的 plaintext blocks（需要 IndexBuilder 支持输出 plaintext）
    let index_plaintext = builder.serialize()?;
    
    // 加密 Index blocks（与 Manifest 类似，每卷不同 nonce）
    let index_blocks = self.encrypt_index_blocks(
        &index_plaintext,
        BlockId::new(index_start_block_id),
        &session,
        &volume_key,
        nonce_context,
    ).await?;
    
    // 写入所有 volume
    let locations = self.pipeline
        .volume_mut()
        .write_index_to_all(&index_blocks, ...)
        .await?;
    
    Some(locations)
} else {
    None
};
```

**改动 3**: 修改 `ArchiveWriter::finalize()` 中的 Manifest 写入逻辑

```rust
// crates/era-engine/src/writer.rs
// 在 catalog 写入之后、Footer 写入之前

// 构建 Manifest
let manifest = self.build_manifest(&catalog_plaintext, index_plaintext.as_deref())?;
let manifest_plaintext = manifest.to_bytes()?;

// 获取 Manifest 的 block_id（使用下一个可用 ID）
let manifest_block_id = BlockId::new(self.pipeline.blocks_written() as u64);

// 加密并写入 Manifest 到所有 volume
let session = self.pipeline.encryption().session().try_clone()?;
let volume_key = self.pipeline.encryption().volume_key().try_clone()?;
let nonce_context = self.pipeline.encryption().nonce_context();
let archive_id = self.archive_id;
let epoch_id = self.epoch_id;

let manifest_locations = self.pipeline
    .volume_mut()
    .write_manifest_to_all(
        &manifest_plaintext,
        manifest_block_id,
        &session,
        &volume_key,
        nonce_context,
        &archive_id,
        epoch_id,
    )
    .await?;

debug!(
    "Manifest (block_id={}) written to {} volumes",
    manifest_block_id.sequence(),
    manifest_locations.len()
);
```

#### 3.4.5 关键设计决策

**Index 全副本冗余的实现方式**:

当前 `IndexBuilder::finalize_with_starting_block_id()` 的签名是：
```rust
async fn finalize_with_starting_block_id(
    &mut self,
    writer: &mut VolumeWriter,      // ← 直接写入 volume 0
    session: &KeySession,
    volume_key: &VolumeKey,
    nonce_context: &[u8; 16],
    starting_block_id: u64,
) -> Result<(MetaIndex, BlockLocation)>
```

该函数**在内部完成加密并写入 volume 0**，没有暴露 `serialize()` 方法。

**方案 A**: 修改 `IndexBuilder` 接口，添加 `serialize_to_bytes()` 方法：
```rust
impl IndexBuilder {
    /// 序列化 Index 为明文 bytes，但不加密或写入。
    /// 返回 (plaintext, MetaIndex)，由 caller 负责加密和写入。
    pub fn serialize_to_bytes(&self) -> Result<(Vec<u8>, MetaIndex)> { ... }
}
```
**缺点**: 需要暴露 IndexBuilder 内部状态，破坏封装；序列化逻辑可能与压缩/加密深度耦合。

**方案 B（推荐）**: 让 `IndexBuilder` 写入 `MemoryStorageBackend`，提取 ciphertext 后复制到所有 volume：
```rust
// 使用内存 backend 让 IndexBuilder 完成 finalize
let mem_backend = MemoryStorageBackend::new();
let mut mem_writer = VolumeWriter::create(&mem_backend, ...).await?;
let (meta_index, _) = builder.finalize_with_starting_block_id(
    &mut mem_writer, ...).await?;

// 从内存 backend 读取 ciphertext
let ciphertext = mem_backend.read_all().await?;

// 将相同的 ciphertext 写入所有 volume
// 注意：所有卷使用相同的 AAD（volume_index = 0），
// 这在安全上可接受，因为 Index 的 block_id 与 Manifest 不同
```
**优点**: 零侵入，不需要修改 IndexBuilder 接口；内存开销小（Index 通常 < 10MB）。

**方案 C（妥协）**: 如果方案 B 不可行，保持 Index 单卷写入，在文档中明确记录为"已知限制"，延后到 v8.3+ 解决。

**决策**: **优先采用方案 B**。如果 MemoryStorageBackend 提取 ciphertext 有困难，则回退到方案 C。
**理由**: Oracle 审查认为方案 B 是架构上最干净的实现，避免了破坏 IndexBuilder 的封装。

**Index 加密的注意事项**:
- 当前 Index 使用 `BlockType::IndexManifest`（不是 `BlockType::Manifest`）
- Index 的 AAD 必须包含类型标识 `"INDEX"`（而非 `"MANIFEST"`），防止跨类型重放攻击
- AAD 格式: `archive_id ‖ epoch_id ‖ "INDEX" ‖ volume_index ‖ block_id`
- 即使 block_id 不同，类型标识提供了额外的安全边界
- 如果使用方案 B（MemoryStorageBackend），所有卷使用相同的 AAD（`volume_index = 0`），这是可接受的，因为 Index 的 block_id 与 Manifest 不同

#### 3.4.6 验收标准

- [ ] Index 写入所有 volume，每个 volume 都有有效的位置信息
- [ ] 各卷 Index 副本内容一致（相同 plaintext，不同 nonce）
- [ ] Manifest 写入所有 volume，每个 volume 都有有效的位置信息
- [ ] 各卷 Manifest 副本均可独立解密
- [ ] `volume_stage.rs` 的 `write_catalog_to_all` 仍然正常工作（Catalog 已是全副本）

---

### 3.5 Task 2.5: Footer v2 写入（manifest 字段）

#### 3.5.1 目标

在 `VolumeWriter::finalize_with_catalog()` 中正确写入 manifest_offset 和 manifest_block_id 字段，使 Reader 能够通过 Footer 直接定位 Manifest typed block。

#### 3.5.2 涉及文件

- `crates/era-volume/src/writer.rs`
- `crates/era-volume/src/volume_pool.rs`
- `crates/era-engine/src/volume_stage.rs`

#### 3.5.3 当前状态

当前代码中，`VolumeWriter` 已经有 `last_manifest_offset` 和 `last_manifest_block_id` 字段，以及 `set_manifest_location()` 方法（`writer.rs:264-270`）。`finalize_with_catalog()` 已经会在 FooterBuilder 中调用 `.manifest(self.last_manifest_offset, self.last_manifest_block_id)`（`writer.rs:666`）。

但当前 `ArchiveWriter::finalize()` 中**没有调用** `set_manifest_location()`，所以 `last_manifest_offset` 和 `last_manifest_block_id` 始终为 0，Footer 中的 manifest 字段无效。

#### 3.5.4 所需改动

**改动 1**: 在 `VolumeWriter` 中确保 `set_manifest_location` 被正确调用

当前代码中已经有：
```rust
// era-volume/src/writer.rs:264-270
pub fn set_manifest_location(&mut self, offset: u64, block_id: u32) {
    self.last_manifest_offset = offset;
    self.last_manifest_block_id = block_id;
}
```

**改动 2**: 在 `VolumePool::finalize_with_catalogs()` 中设置 manifest 位置（**不修改签名**）

```rust
// crates/era-volume/src/volume_pool.rs
// 保持 finalize_with_catalogs 签名不变！

pub async fn finalize_with_catalogs(
    &mut self,
    catalog_locations: &[(u64, u32, u32)],
    index_locations: Option<&[(u64, u32, u32)]>,
) -> Result<VolumePoolStats> {
    // ... 现有验证逻辑 ...
    
    for (i, mut writer) in writers.into_iter().enumerate() {
        // ... 现有 catalog/index 处理 ...
        
        writer.finalize_with_catalog(...).await?;
    }
    
    Ok(stats)
}
```

**改动 3**: 在 `VolumePool` 中新增 `finalize_with_catalogs_and_manifest` 方法

```rust
// crates/era-volume/src/volume_pool.rs
// 新增方法，不破坏现有 finalize_with_catalogs 的签名

pub async fn finalize_with_catalogs_and_manifest(
    &mut self,
    catalog_locations: &[(u64, u32, u32)],
    index_locations: Option<&[(u64, u32, u32)]>,
    manifest_locations: Option<&[(u64, u32, u32)]>,
) -> Result<VolumePoolStats> {
    if catalog_locations.len() != self.writers.len() {
        return Err(era_common::EraError::InvalidConfig(format!(
            "catalog_locations length {} does not match volume count {}",
            catalog_locations.len(),
            self.writers.len()
        )));
    }
    
    if let Some(idx) = index_locations {
        if idx.len() != self.writers.len() {
            return Err(era_common::EraError::InvalidConfig(format!(
                "index_locations length {} does not match volume count {}",
                idx.len(), self.writers.len()
            )));
        }
    }
    
    if let Some(manifest_locs) = manifest_locations {
        if manifest_locs.len() != self.writers.len() {
            return Err(era_common::EraError::InvalidConfig(format!(
                "manifest_locations length {} does not match volume count {}",
                manifest_locs.len(), self.writers.len()
            )));
        }
    }
    
    let mut stats = std::mem::take(&mut self.stats);
    let old_sequences: Vec<u16> = self.sequences.drain(..).collect();
    let writers: Vec<_> = self.writers.drain(..).collect();
    
    for (i, mut writer) in writers.into_iter().enumerate() {
        let size = writer.current_size();
        let sequence = old_sequences[i];
        stats.volume_sizes.push((sequence, size));
        
        let (offset, size_u32, block_id) = catalog_locations[i];
        let (idx_offset, idx_size, idx_block_id) = index_locations
            .and_then(|idx| idx.get(i).copied())
            .unwrap_or((0, 0, 0));
        
        // 设置 manifest 位置（如提供）
        if let Some(manifest_locs) = manifest_locations {
            if let Some((manifest_offset, _manifest_size, manifest_block_id)) = manifest_locs.get(i) {
                writer.set_manifest_location(*manifest_offset, *manifest_block_id);
            }
        }
        
        writer
            .finalize_with_catalog(
                offset,
                size_u32,
                block_id,
                idx_offset,
                idx_size,
                idx_block_id,
            )
            .await?;
    }
    
    Ok(stats)
}
```

**改动 4**: 在 `VolumeStage::finalize()` 中提供两个版本

```rust
// crates/era-engine/src/volume_stage.rs

impl<B: StorageBackend> VolumeStage<B> {
    /// 原有方法，保持不变（向后兼容）
    pub async fn finalize(
        &mut self,
        catalog_locations: &[(u64, u32, u32)],
        index_locations: Option<&[(u64, u32, u32)]>,
    ) -> Result<VolumePoolStats> {
        self.pool
            .finalize_with_catalogs(catalog_locations, index_locations)
            .await
    }
    
    /// 新增方法，支持 manifest 位置（v8.2）
    pub async fn finalize_with_manifest(
        &mut self,
        catalog_locations: &[(u64, u32, u32)],
        index_locations: Option<&[(u64, u32, u32)]>,
        manifest_locations: Option<&[(u64, u32, u32)]>,
    ) -> Result<VolumePoolStats> {
        self.pool
            .finalize_with_catalogs_and_manifest(
                catalog_locations,
                index_locations,
                manifest_locations,
            )
            .await
    }
}
```

**改动 5**: 在 `ArchiveWriter::finalize()` 中调用新的 finalize 方法

```rust
// crates/era-engine/src/writer.rs

// 在写入 Manifest 之后、调用 finalize 之前
let manifest_locations: Vec<(u64, u32, u32)> = manifest_locations; // 从 write_manifest_to_all 获取

// Finalize the pool with catalog, index, and manifest locations
let pool_stats = self
    .pipeline
    .volume_mut()
    .finalize_with_manifest(
        &catalog_locations,
        index_locations.as_deref(),
        Some(&manifest_locations),
    )
    .await?;
```

#### 3.5.5 关键设计决策

**manifest_locations 的格式**:
- 与 catalog_locations 和 index_locations 一致：`(offset, size, block_id)`
- 即使 manifest 很小（< 1KB），也统一使用三元组格式

**向后兼容性**:
- `manifest_locations = None` 时，`last_manifest_offset` 和 `last_manifest_block_id` 保持为 0
- Footer 的 `has_manifest()` 返回 false，v8.2 reader 会 fail-closed（Phase 3 实现）
- 这与 v8.1 archive 的行为一致

#### 3.5.6 验收标准

- [ ] Footer 正确包含 manifest_offset 和 manifest_block_id
- [ ] `Footer::has_manifest()` 返回 true（当 manifest_offset != 0）
- [ ] `Footer::manifest_location()` 返回正确的 `(offset, block_id)`
- [ ] Footer 仍序列化为 128 字节
- [ ] 无 manifest 时（manifest_offset = 0），Footer 其他字段不受影响

---

### 3.6 Task 2.6: 构建验证

#### 3.6.1 目标

确保所有 Phase 2 的修改在 workspace 级别编译通过，不影响现有功能。

#### 3.6.2 构建步骤

```bash
# 1. 格式化检查
cargo fmt --all -- --check

# 2. 编译 era-ingest（Catalog 扩展）
cargo build -p era-ingest

# 3. 编译 era-volume（Footer 扩展、预检查机制）
cargo build -p era-volume

# 4. 编译 era-crypto（承诺计算）
cargo build -p era-crypto

# 5. 编译 era-engine（Manifest 构建、全副本写入）
cargo build -p era-engine

# 6. 编译整个 workspace
cargo build --workspace

# 7. Lint 检查
cargo clippy --all-targets --all-features -- -D warnings

# 8. 运行测试
cargo test --workspace
```

#### 3.6.3 预期问题与解决

| 问题 | 原因 | 解决 |
|------|------|------|
| `WritePipeline` 新增字段导致构造失败 | `written_blocks` 字段 | 更新 `new()` 方法 |
| `next_finalize_sequence` 未使用 | 新引入的函数 | 在 writer.rs 中集成使用 |
| `IndexBuilder` 不支持 `serialize_to_bytes()` | 接口限制 | 采用 fallback 方案（内存 backend 或妥协方案） |

#### 3.6.4 验收标准

- [ ] `cargo fmt --all -- --check` 通过
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` 通过
- [ ] `cargo test --workspace` 通过（或仅存在与变更无关的 pre-existing 失败）
- [ ] `cargo build --workspace` 通过

---

## 4. 跨任务依赖关系

```
Task 2.1 (block_locations 填充)
    │
    ▼
Task 2.2 (预检查/预先 rotation)
    │
    ▼
Task 2.3 (Manifest 构建 + 加密)
    │
    ▼
Task 2.4 (全副本冗余写入)
    │
    ▼
Task 2.5 (Footer v2 写入)
    │
    ▼
Task 2.6 (构建验证)
```

**可并行开发**:
- Task 2.1 和 Task 2.2 可部分并行（block_locations 收集和预检查机制独立）
- Task 2.3 的 Manifest 构建逻辑可在 Task 2.1 完成后独立开发

**关键路径**:
- Task 2.1 → Task 2.3 → Task 2.4 → Task 2.5 → Task 2.6
- 任何延迟直接影响总工期

---

## 5. 文件变更清单

### 5.1 新增文件

| 文件 | 内容 | 原因 |
|------|------|------|
| `crates/era-engine/src/manifest_block.rs`（或内联在 `writer.rs`） | `ManifestBlock` 中间类型 | 区分明文块和密文块，防止语义混淆 |

### 5.2 修改文件

| 文件 | 修改内容 | 影响范围 |
|------|---------|---------|
| `crates/era-engine/src/write_pipeline.rs` | 新增 `written_blocks`、`typed_blocks_allocated`、 `next_available_block_id()` | era-engine |
| `crates/era-engine/src/writer.rs` | 填充 block_locations、构建 Manifest、调用全副本写入、新增字段 | era-engine |
| `crates/era-engine/src/volume_stage.rs` | 新增 `write_manifest_to_all`、`write_index_to_all`、 `finalize_with_manifest`（签名不变） | era-engine |
| `crates/era-volume/src/volume_pool.rs` | 新增 `precheck_and_rotate_if_needed`、 `check_typed_block_space`、 `finalize_with_catalogs_and_manifest`（签名不变） | era-volume |
| `crates/era-volume/src/writer.rs` | **签名不变**，使用 `set_manifest_location()` 设置位置 | era-volume |
| `crates/era-index/src/builder.rs` | 新增 `serialize_to_bytes()` 方法（如采用方案 A） | era-index |
| `crates/era-crypto/src/aead_context.rs` | 新增 nonce 派生辅助函数（如需要） | era-crypto |

### 5.3 测试文件

| 文件 | 测试内容 |
|------|---------|
| `crates/era-engine/tests/` | 新增 v8.2 创建/读取集成测试 |
| `crates/era-volume/tests/` | 新增 Footer v2 测试、预检查测试 |

---

## 6. 验收标准

### 6.1 功能验收

- [ ] 可创建 v8.2 archive（含 Manifest、Catalog block_locations、Footer v2）
- [ ] Catalog.block_locations 正确填充，长度等于数据块数量
- [ ] typed block 不触发 rotation（预检查+预先 rotation 机制工作正常）
- [ ] Manifest 写入所有 volume，各副本可独立解密
- [ ] Index 写入所有 volume（全副本冗余）
- [ ] Footer 正确包含 manifest_offset 和 manifest_block_id
- [ ] 无 manifest 时 Footer 其他字段不受影响

### 6.2 构建验收

- [ ] `cargo fmt --all -- --check` 通过
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` 通过
- [ ] `cargo test --workspace` 通过（允许 pre-existing 失败）
- [ ] `cargo build --workspace` 通过

### 6.3 安全验收

- [ ] Manifest AEAD 加密正确，tag 验证通过
- [ ] 每卷 Manifest 密文不同（nonce 不同）
- [ ] Catalog 承诺计算正确（相同输入 → 相同输出）
- [ ] 空 index 时 index_commitment 为全零

---

## 7. 风险与缓解

| 风险 | 可能性 | 影响 | 缓解 |
|------|--------|------|------|
| **block_locations 收集引入内存开销** | 低 | 中 | 基准测试；100K blocks → ~10MB，可接受 |
| **预检查触发 rotation 导致数据分散** | 低 | 高 | 确保 rotation 在写入任何 typed block 之前完成；测试验证 |
| **Manifest 加密参数错误** | 中 | 高 | 与现有 AEAD 测试对比；单独测试 Manifest 加解密往返 |
| **Index 全副本冗余破坏现有索引** | 中 | 高 | 保留 IndexBuilder 接口兼容性；逐步迁移到全副本 |
| **ROADMAP.md 误导性 data_end_offset "修复"** | 低 | 高 | 明确记录 design intent；拒绝破坏性变更 |
| **Manifest 明文误用 EncryptedMacroBlock** | 中 | 高 | 引入 ManifestBlock 中间类型；编译期区分 |
| **IndexBuilder 接口不支持全副本** | 中 | 高 | 预分析接口限制；准备 fallback 方案 |
| **Footer 字段变更引入 regression** | 中 | 高 | 全面的 Footer 测试；验证 v8.1 Footer 解析 |

---

## 附录 A: 设计审查与修正

**审查日期**: 2026-04-25  
**审查方法**: 竞争对手视角 / 红队审计  
**审查结果**: 发现 9 个问题，其中 3 个严重、3 个不合理、3 个需要补充说明

---

### A.1 严重问题（必须修正）

#### A.1.1 ROADMAP.md 的 `data_end_offset` "bug 修复" 是误导性的

**问题**: ROADMAP.md §3.2 声称：
```rust
// v8.1 BUG:
// let data_end_offset = backup_header_offset;
// v8.2 FIX:
let data_end_offset = backup_header_offset - TRAILER_RESERVED;
```

**分析**: 这是**错误**的。如果 `data_end_offset = backup_header_offset - TRAILER_RESERVED`，则 `data_end_offset` 将位于 backup header 之前、typed blocks 之后。这会导致：
1. `scan_for_typed_blocks()` 无法扫描到 typed blocks（因为它们超出了 `data_end_offset`）
2. Reader 会拒绝读取 typed blocks（认为它们在未提交区域之外）
3. 破坏冷恢复能力

**结论**: `data_end_offset = backup_header_offset` **不是 bug**，而是 v8.2 的**设计意图**。
- `data_end_offset` 保持物理语义不变（包含 typed block 区域）
- `committed_horizon` 作为**逻辑边界**记录在 Manifest 中，Reader 使用 `committed_horizon` 而非 `data_end_offset` 作为读取边界

**决策**: **拒绝** ROADMAP.md 的这个变更。在 PHASE 2 实施中保持 `data_end_offset = backup_header_offset`。

---

#### A.1.2 `EncryptedMacroBlock` 语义被滥用（Task 2.3）

**问题**: 在 Task 2.3 的伪代码中：
```rust
// 错误：返回 EncryptedMacroBlock 但 data 是明文！
Ok(EncryptedMacroBlock {
    block_id,
    data: Bytes::from(manifest_plaintext),  // ← 明文！
    // ...
})
```

**风险**: `EncryptedMacroBlock` 的语义是"已加密的宏块"。如果某个调用者误以为 `data` 是密文而直接写入 volume，会导致明文泄露。

**修正**: 引入中间类型 `ManifestBlock`：

```rust
/// 待加密的 Manifest 块（明文）。
/// 与 EncryptedMacroBlock 的区别：data 字段存储的是明文，需要在写入前加密。
pub struct ManifestBlock {
    pub block_id: BlockId,
    pub plaintext: Vec<u8>,
    pub original_size: u32,
    pub chunk_count: u32,
}

impl ManifestBlock {
    pub fn encrypt_for_volume(
        &self,
        session: &KeySession,
        volume_key: &VolumeKey,
        nonce_context: &[u8; 16],
        archive_id: &ArchiveId,
        epoch_id: u32,
        volume_index: u32,
    ) -> Result<EncryptedMacroBlock> {
        // 派生 block key
        let block_key = session.derive_block_key(volume_key, self.block_id.sequence(), nonce_context)?;
        
        // 派生 nonce（混入 volume_index）
        let nonce = derive_nonce_with_volume_index(nonce_context, self.block_id, volume_index);
        
        // 构建 AAD
        let aad = build_manifest_aad(archive_id, epoch_id, volume_index, self.block_id);
        
        // AEAD 加密
        let ciphertext = era_crypto::aead_encrypt(&block_key, &nonce, &self.plaintext, &aad)?;
        
        Ok(EncryptedMacroBlock {
            block_id: self.block_id,
            data: Bytes::from(ciphertext),
            original_size: self.original_size,
            compressed_size: self.original_size,
            chunk_count: self.chunk_count,
        })
    }
}
```

**影响文件**: `crates/era-engine/src/writer.rs`

---

#### A.1.3 `IndexBuilder` 接口可能不支持全副本冗余（Task 2.4）

**问题**: 当前 `IndexBuilder::finalize_with_starting_block_id()` 的签名是：
```rust
async fn finalize_with_starting_block_id(
    &mut self,
    writer: &mut VolumeWriter,      // ← 直接写入 volume 0
    session: &KeySession,
    volume_key: &VolumeKey,
    nonce_context: &[u8; 16],
    starting_block_id: u64,
) -> Result<(MetaIndex, BlockLocation)>
```

该函数**在内部完成加密并写入 volume 0**，没有暴露 `serialize()` 方法。

**风险**: Task 2.4 提出的"选项 B"（输出 plaintext 后由 VolumeStage 加密并写入所有 volume）可能不可行，因为 `IndexBuilder` 不支持分离序列化和加密。

**修正方案**（按优先级排序）：

**方案 A（推荐）**: 修改 `IndexBuilder` 接口，添加 `serialize_to_bytes()` 方法：
```rust
impl IndexBuilder {
    /// 序列化 Index 为明文 bytes，但不加密或写入。
    /// 返回 (plaintext, MetaIndex)，由 caller 负责加密和写入。
    pub fn serialize_to_bytes(&self) -> Result<(Vec<u8>, MetaIndex)> { ... }
}
```

**方案 B（fallback）**: 让 `IndexBuilder` 写入 `MemoryStorageBackend`，提取 ciphertext 后复制到所有 volume：
```rust
// 使用内存 backend 让 IndexBuilder 完成 finalize
let mem_backend = MemoryStorageBackend::new();
let mut mem_writer = VolumeWriter::create(&mem_backend, ...).await?;
let (meta_index, _) = builder.finalize_with_starting_block_id(&mut mem_writer, ...).await?;

// 从内存 backend 读取 ciphertext
let ciphertext = mem_backend.read_all().await?;

// 将相同的 ciphertext 写入所有 volume（注意：这需要所有卷使用相同的 AAD）
```

**方案 C（妥协）**: 如果方案 A 和 B 都不可行，保持 Index 单卷写入，在文档中明确记录为"已知限制"，延后到 v8.3+ 解决。

**决策**: **优先尝试方案 A**。如果 `IndexBuilder` 的序列化逻辑与加密逻辑耦合过深，则回退到方案 B。

---

### A.2 不合理的设计（建议修正）

#### A.2.1 `finalize_with_catalogs` 签名不应修改

**问题**: Task 2.5 提出修改 `finalize_with_catalogs` 签名：
```rust
pub async fn finalize_with_catalogs(
    &mut self,
    catalog_locations: &[(u64, u32, u32)],
    index_locations: Option<&[(u64, u32, u32)]>,
    manifest_locations: Option<&[(u64, u32, u32)]>,  // ← 新增
) -> Result<VolumePoolStats>
```

**分析**: `VolumeWriter` 已经有 `set_manifest_location()` 方法（`writer.rs:264-270`），`finalize_with_catalog()` 已经通过 `self.last_manifest_offset` 自动写入 Footer。

**更简洁的方案**:
```rust
// VolumePool::finalize_with_catalogs() 循环中：
for (i, mut writer) in writers.into_iter().enumerate() {
    // 设置 manifest 位置（如提供）
    if let Some(manifest_locs) = manifest_locations {
        if let Some((offset, _size, block_id)) = manifest_locs.get(i) {
            writer.set_manifest_location(*offset, *block_id);
        }
    }
    
    // 调用现有的 finalize_with_catalog（签名不变！）
    writer.finalize_with_catalog(...).await?;
}
```

**优点**:
- 不修改 `finalize_with_catalog` 和 `finalize_with_catalogs` 的签名
- 减少编译失败范围
- 降低回归风险

**修正**: 在 Task 2.5 中采用此方案，**不修改任何 finalize 方法的签名**。

---

#### A.2.2 Manifest block_id 分配需要统一接口

**问题**: Task 2.3 使用 `self.pipeline.blocks_written()` 作为 Manifest 的 block_id，但 Catalog 和 Index 也占用 block_id。

**风险**: block_id 冲突。如果：
- 数据块：0..99（100 个）
- Catalog 分块：100..101（2 个块）
- Index：102..103
- Manifest：假设用 `blocks_written()` 返回 100，与 Catalog 的 block_id 100 冲突

**修正**: `WritePipeline` 应暴露 `next_available_block_id()` 方法：
```rust
impl WritePipeline {
    /// 返回下一个可用的 block_id。
    /// 该方法会考虑数据块、Catalog、Index 和 Manifest 已占用的 block_id。
    pub fn next_available_block_id(&self) -> BlockId {
        // blocks_written 只统计数据块
        // 需要加上已分配的 typed block block_id
        let next_id = self.blocks_written() as u64 + self.typed_blocks_allocated;
        BlockId::new(next_id)
    }
    
    /// 预留一个 block_id 用于 typed block。
    pub fn allocate_block_id(&mut self) -> BlockId {
        let id = self.next_available_block_id();
        self.typed_blocks_allocated += 1;
        id
    }
}
```

**影响**: 需要跟踪 `typed_blocks_allocated` 计数器，确保 Catalog、Index、Manifest 的 block_id 不冲突。

---

#### A.2.3 `ArchiveWriter` 新增字段未定义

**问题**: Task 2.3 的伪代码引用了 `self.finalize_sequence`，但从未明确需要在 `ArchiveWriter` 结构中添加此字段。

**修正**: 在 `ArchiveWriter` 结构中添加：
```rust
pub struct ArchiveWriter {
    // ... 现有字段 ...
    
    /// 当前认证世代号。
    /// 新 archive：INITIAL_FINALIZE_SEQUENCE（= 1）
    /// 追加模式：从现有 Manifest 读取并递增（Phase 4 实现）
    finalize_sequence: Option<u64>,
    
    /// 已分配的 typed block 数量（用于 block_id 分配）
    typed_blocks_allocated: u64,
}
```

---

### A.3 需要补充的安全说明

#### A.3.1 Reader 必须验证 volume_id 匹配

**问题**: 攻击者可能交换 volume 文件的物理顺序（如把 volume_1.era 重命名为 volume_0.era）。

**防御**: Reader 必须验证 `block_locations[i].volume_id` 与打开的实际 volume 的 `volume_id` 匹配。

**注意**: 这是 Phase 3（读取管线）的要求，但需要在 PHASE 2 文档中记录，以确保 Phase 2 的实现为 Phase 3 提供足够的信息。

#### A.3.2 承诺验证是安全关键

**问题**: 如果 Phase 3 的 Reader 跳过承诺验证，攻击者可以：
1. 修改 Catalog 密文（不修改 tag）
2. 保持 Manifest 中的旧承诺值
3. Reader 接受被篡改的 Catalog

**要求**: 在 Phase 3 中，Catalog 和 Index 的**承诺验证必须强制执行**，不可作为可选检查。

#### A.3.3 `committed_horizon` 与 `data_end_offset` 的语义区分

**澄清**:
- `data_end_offset`（Footer 字段）= 物理写入位置 = backup_header_offset，**包含** typed blocks
- `committed_horizon`（Manifest 字段）= 逻辑提交边界，**排除**未提交的数据

**Reader 行为**:
- 使用 `committed_horizon` 作为读取边界（而非 `data_end_offset`）
- 超出 `committed_horizon` 但在 `data_end_offset` 内的数据保留在磁盘上（取证能力），但对 Reader 不可见

---

### A.4 修正后的文件变更清单

#### A.4.1 新增文件

| 文件 | 内容 | 原因 |
|------|------|------|
| `crates/era-common/src/types/manifest.rs` | 新增 `ManifestBlock` 类型 | 放在 era-common 供 Phase 2-4 共享；区分明文块和密文块 |

#### A.4.2 修改文件（修正后）

| 文件 | 修改内容 | 影响范围 |
|------|---------|---------|
| `crates/era-engine/src/write_pipeline.rs` | 新增 `written_blocks`、`typed_blocks_allocated`、`next_available_block_id()` | era-engine |
| `crates/era-engine/src/writer.rs` | 填充 block_locations、构建 Manifest、调用全副本写入、新增字段 | era-engine |
| `crates/era-engine/src/volume_stage.rs` | 新增 `write_manifest_to_all`、`write_index_to_all`、**finalize 签名不变** | era-engine |
| `crates/era-volume/src/volume_pool.rs` | 新增 `precheck_and_rotate_if_needed`、`check_typed_block_space`、**finalize 签名不变** | era-volume |
| `crates/era-volume/src/writer.rs` | **签名不变**，使用 `set_manifest_location()` 设置位置 | era-volume |
| `crates/era-index/src/builder.rs` | 可能无需修改（采用方案 B：MemoryStorageBackend） | era-index |

---

### A.5 Oracle 审查补充发现

**审查日期**: 2026-04-25  
**审查方法**: Oracle 咨询（高可信度架构/安全审查）  

#### A.5.1 ManifestBlock 位置优化

**Oracle 建议**: `ManifestBlock` 应放在 `era-common/src/types/manifest.rs`（与 `ArchiveManifest` 同文件），而非 `era-engine/src/writer.rs`。

**理由**:
- `ManifestBlock::encrypt_for_volume()` 是密码学操作
- Phase 3 的 Reader 和 Phase 4 的 Repair 也需要解密 Manifest
- 放在 `era-common` 使所有层可以复用相同的加密/解密逻辑，避免代码重复

**已采纳**: 将 `ManifestBlock` 定义移到 `era-common/src/types/manifest.rs`。

#### A.5.2 `committed_horizon` 精确计算

**Oracle 发现**: 原方案使用 `self.pipeline.volume().pool().data_end_offset()`，但 `VolumePool` 没有此方法。

**修正**: `committed_horizon` 应基于最后一个数据块的位置计算：
```rust
let committed_horizon = if !self.catalog.block_locations.is_empty() {
    let last_loc = self.catalog.block_locations.last().unwrap();
    last_loc.physical_offset + last_loc.encrypted_size as u64
} else {
    era_volume::DATA_REGION_START as u64
};
```

**理由**:
- `committed_horizon` 是**数据区域**的逻辑边界，不包含 typed blocks
- Typed blocks（Catalog/Index/Manifest）是元数据，不属于用户数据
- Reader 使用 `committed_horizon` 作为读取边界，不应读取 typed blocks 作为数据

#### A.5.3 AAD 类型标识

**Oracle 建议**: AAD 中应明确包含类型标识（`"MANIFEST"` 或 `"INDEX"`），防止跨类型重放攻击。

**已采纳**: 
- Manifest AAD: `archive_id ‖ epoch_id ‖ "MANIFEST" ‖ volume_index ‖ block_id`
- Index AAD: `archive_id ‖ epoch_id ‖ "INDEX" ‖ volume_index ‖ block_id`

即使 block_id 不同，类型标识提供了额外的安全边界。

#### A.5.4 Index 全副本方案选择

**Oracle 建议**: **优先采用方案 B（MemoryStorageBackend）** 而非方案 A（`serialize_to_bytes()`）。

**理由**:
- `IndexBuilder` 的序列化逻辑可能与压缩/加密深度耦合
- `serialize_to_bytes()` 需要暴露内部状态，破坏封装
- MemoryStorageBackend 是零侵入方案：IndexBuilder 行为不变，只是后端换成内存
- 内存开销小（Index 通常 < 10MB）

**安全影响**: 方案 B 要求所有卷使用相同的 AAD（`volume_index = 0`），这在安全上可接受，因为 Index 的 block_id 与 Manifest 不同。

**已采纳**: 将方案 B 设为首选，方案 A 和 C 作为备选。

#### A.5.5 预检查 + 预先 rotation 的崩溃一致性

**Oracle 分析**: 如果在 `rotate_volumes()` 和 typed block 写入之间崩溃：
- 旧 volume 已 finalize（有 Footer），但无 typed blocks
- 新 volume 可能有 Footer 但无 typed blocks
- Reader 打开时：`manifest_offset = 0` → `has_manifest() = false` → **fail-closed**

**结论**: 这是**正确行为**。fail-closed 防止读取不一致状态，下次 append 可以从旧 volume 的 Footer 恢复。

**要求**: 确保 `rotate_volumes()` 的 finalize 是尽力原子的（当前 VolumeWriter::finalize 已写入 backup header + primary footer + backup footer + sync）。

#### A.5.6 `finalize_sequence` 在 append 模式下的预留

**Oracle 建议**: Phase 2 不需要处理 append 模式，但应在 `ArchiveWriter` 中预留接口：
```rust
pub struct ArchiveWriter {
    // ...
    finalize_sequence: Option<u64>, // None = new archive, Some(n) = append mode (Phase 4)
}
```

**已采纳**: 在 Task 2.1 的 `ArchiveWriter` 新增字段中定义 `finalize_sequence`。

#### A.5.7 Oracle 最终评估

| 维度 | 评分 | 说明 |
|------|------|------|
| 安全正确性 | 8/10 | ManifestBlock 设计正确，AAD 类型标识已补充 |
| 架构清晰度 | 7/10 | 层次边界清晰，ManifestBlock 位置已优化 |
| 崩溃一致性 | 8/10 | fail-closed 行为正确，预检查+rotation 顺序合理 |
| 可实施性 | 7/10 | Index 全副本是主要风险点，已提供 fallback |
| 文档完整性 | 6/10 → 8/10 | committed_horizon 计算、ArchiveWriter 字段已补充 |

**已实施的修正**:
1. ✅ `committed_horizon` 精确计算（基于最后一个数据块位置）
2. ✅ `ManifestBlock` 移到 `era-common`（供 Phase 2-4 共享）
3. ✅ AAD 类型标识（`"MANIFEST"` / `"INDEX"`）
4. ✅ Index 全副本推荐方案 B（MemoryStorageBackend）
5. ✅ `finalize_sequence` 字段预留
6. ✅ 预检查+rotation 崩溃一致性说明

---

*附录生成时间: 2026-04-25*  
*审查视角: 竞争对手 / 红队审计 + Oracle 架构/安全审查*
