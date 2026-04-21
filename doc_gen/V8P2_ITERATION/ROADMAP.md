# ERA Volume Format v8.2 实施路线图

**版本**: 1.0
**日期**: 2026-04-21
**状态**: 设计完成，待实施
**前置条件**: 代码未上线，无需向后兼容

---

## 目录

1. [实施阶段概览](#1-实施阶段概览)
2. [Phase 1: 基础结构](#2-phase-1-基础结构)
3. [Phase 2: 写入管线](#3-phase-2-写入管线)
4. [Phase 3: 读取管线](#4-phase-3-读取管线)
5. [Phase 4: 恢复模块](#5-phase-4-恢复模块)
6. [Phase 5: 测试与审计](#6-phase-5-测试与审计)
7. [工作量估算](#7-工作量估算)
8. [关键路径](#8-关键路径)
9. [风险与缓解](#9-风险与缓解)
10. [验收标准](#10-验收标准)

---

## 1. 实施阶段概览

```
Phase 1 (基础结构) ───────────────────────────────────────┐
├── era-common: ArchiveManifest protobuf + types          │
├── era-common: Catalog.block_locations 扩展              │
├── era-common: Footer v2 reserved 字段定义               │
└── era-crypto: Manifest 承诺计算 (Blake3 keyed_hash)     │
                                                          │
Phase 2 (写入管线) ───────────────────────────────────────┤
├── era-ingest: Catalog 构建（含 block_locations）        │
├── era-volume: data_end_offset bug 修复                  │
├── era-volume: typed block 预检查机制                    │
├── era-engine: Manifest 构建 + AEAD 加密                 │
├── era-engine: 全副本冗余写入（Catalog/Index/Manifest）  │
└── era-engine: Footer v2 写入                            │
                                                          │
Phase 3 (读取管线 + 验证增强) ────────────────────────────┤
├── era-engine: Manifest 加载 + 验证                      │
├── era-engine: Catalog 加载 + 承诺验证                   │
├── era-engine: 【修改1】多副本验证加载（Catalog/Index/Manifest） │
├── era-engine: 【修改2】Verify 额外检查 typed block 副本   │
├── era-engine: 迭代器重构（双模式）                      │
├── era-volume: committed_horizon 强制执行                │
└── era-engine: v8.1 兼容性路径保留                       │
                                                          │
Phase 4 (恢复模块 + Repair 增强) ─────────────────────────┤
├── era-engine: RecoveryManager 重写                      │
├── era-engine: 物理截断移除                              │
├── era-engine: 【修改3】Repair typed block 副本覆盖修复    │
├── era-engine: 【修改3】Repair Catalog 扫描重建（Level B） │
└── era-engine: 死代码删除                                │
                                                          │
Phase 5 (测试与审计) ─────────────────────────────────────┘
└── All crates: 单元测试 + 集成测试 + 对抗性审计
```

---

## 2. Phase 1: 基础结构（第 1 周）

### 2.1 era-common: ArchiveManifest 类型定义

**任务**: 在 `era-common/src/types/` 新增 `manifest.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveManifest {
    pub epoch_id: u32,
    pub committed_horizon: u64,
    pub catalog_commitment: [u8; 32],
    pub index_commitment: [u8; 32],
}
```

**工作量**: ~1 天
**风险**: 低（纯类型定义）
**验收**: 编译通过，与现有类型无冲突

### 2.2 era-common: Catalog 扩展 block_locations

**任务**: 修改 `era-ingest/src/entry.rs` 的 `Catalog` 结构

```rust
pub struct Catalog {
    pub entries: Vec<FileEntry>,
    pub block_locations: Vec<BlockLocation>,  // ← 新增
    pub total_size: u64,
    pub file_count: u64,
    pub dir_count: u64,
}
```

**工作量**: ~1 天
**风险**: 低
**验收**: 
- Catalog 序列化/反序列化正常
- 现有测试通过

### 2.3 era-common: Footer v2 reserved 字段定义

**任务**: 修改 `era-volume/src/footer.rs`

```rust
// 新增 accessor
pub fn manifest_block_id(&self) -> u32 { ... }
pub fn manifest_offset(&self) -> u64 { ... }

// 新增 setter（builder 模式）
pub fn manifest(mut self, offset: u64, block_id: u32) -> Self { ... }
```

**工作量**: ~1 天
**风险**: 低
**验收**:
- Footer 仍序列化为 128 字节
- reserved 字段正确映射到新字段
- 向后兼容：v8.1 Footer 解析正常

### 2.4 era-common: protobuf schema 更新

**任务**: 更新 `era-common/proto/era_common.proto`

```protobuf
message ArchiveManifest {
    uint32 epoch_id = 1;
    uint64 committed_horizon = 2;
    bytes catalog_commitment = 3;
    bytes index_commitment = 4;
}

// Catalog 扩展
message Catalog {
    repeated FileEntry entries = 1;
    repeated BlockLocation block_locations = 2;  // ← 新增
    uint64 total_size = 3;
    uint64 file_count = 4;
    uint64 dir_count = 5;
}
```

**工作量**: ~1 天
**风险**: 低
**验收**: protobuf 编译通过

### 2.5 era-crypto: Manifest 承诺计算

**任务**: 在 `era-crypto/src/` 或 `era-common/src/` 添加承诺计算函数

```rust
pub fn compute_catalog_commitment(catalog_plaintext: &[u8]) -> [u8; 32] {
    blake3::keyed_hash(b"ERA-CAT-COMMIT-v1___________", catalog_plaintext).into()
}

pub fn compute_index_commitment(index_plaintext: &[u8]) -> [u8; 32] {
    blake3::keyed_hash(b"ERA-IDX-COMMIT-v1___________", index_plaintext).into()
}
```

**工作量**: ~0.5 天
**风险**: 低
**验收**:
- 相同输入产生相同输出
- 不同输入产生不同输出（碰撞测试）

**Phase 1 里程碑**: 所有类型定义和 schema 更新完成，编译通过

---

## 3. Phase 2: 写入管线（第 1-2 周）

### 3.1 era-ingest: Catalog 构建（含 block_locations）

**任务**: 修改 `ArchiveWriter::build_catalog()` 或等效函数

```rust
fn build_catalog(&self) -> Result<Catalog> {
    let mut catalog = Catalog {
        entries: self.completed_files.iter().map(|f| f.to_entry()).collect(),
        block_locations: self.written_blocks.iter()
            .map(|b| b.location.clone())
            .collect(),
        total_size: self.total_size,
        file_count: self.file_count,
        dir_count: self.dir_count,
    };
    Ok(catalog)
}
```

**工作量**: ~2 天
**风险**: 中（影响 Catalog 构建逻辑）
**验收**:
- Catalog 正确包含所有 block 的 BlockLocation
- block_locations 索引与 block_index 一一对应

### 3.2 era-volume: data_end_offset bug 修复

**任务**: 修复 `era-volume/src/writer.rs`

```rust
// v8.1 BUG:
// let data_end_offset = backup_header_offset;

// v8.2 FIX:
let data_end_offset = backup_header_offset - TRAILER_RESERVED;
```

**工作量**: ~0.5 天
**风险**: 高（影响 volume 布局）
**验收**:
- data_end_offset 正确排除 trailer 空间
- 现有 volume 布局测试通过

### 3.3 era-volume: typed block 预检查机制

**任务**: 在 `VolumePool` 新增预检查 + 预先 rotation 方法

```rust
pub async fn precheck_and_rotate_if_needed(&mut self, total_size: u64) -> Result<()> {
    let need_rotation = (0..self.volume_count()).any(|slot| {
        self.volume_remaining_space(slot) < total_size
    });
    if need_rotation {
        self.rotate_volumes().await?;
    }
    Ok(())
}
```

**工作量**: ~1 天
**风险**: 中
**验收**:
- 空间充足时继续写入
- 空间不足时预先 rotation（不在写入中触发）
- rotation 后所有 volume 有足够空间

### 3.4 era-engine: Manifest 构建 + AEAD 加密

**任务**: 在 finalize 阶段构建 Manifest

```rust
async fn build_and_encrypt_manifest(
    &self,
    catalog_plaintext: &[u8],
    index_plaintext: Option<&[u8]>,
) -> Result<EncryptedMacroBlock> {
    let manifest = ArchiveManifest {
        epoch_id: self.epoch_id,
        finalize_sequence: self.last_finalize_sequence + 1,
        committed_horizon: self.data_end_offset,
        catalog_commitment: compute_catalog_commitment(catalog_plaintext),
        index_commitment: index_plaintext
            .map(|p| compute_index_commitment(p))
            .unwrap_or([0u8; 32]),
    };
    
    // 序列化
    let manifest_bytes = manifest.to_bytes()?;
    
    // AEAD 加密（复用 block key 派生）
    let block_id = BlockId::new(self.next_manifest_block_id);
    let block_key = self.session.derive_block_key(&self.volume_key, block_id.sequence(), &self.nonce_context)?;
    let encrypted = encrypt_with_context(
        &block_key,
        &self.nonce_context,
        &self.archive_id,
        self.epoch_id,
        0, // volume_index
        block_id,
        &manifest_bytes,
    )?;
    
    Ok(EncryptedMacroBlock {
        block_id,
        data: Bytes::from(encrypted),
        original_size: manifest_bytes.len() as u32,
        compressed_size: manifest_bytes.len() as u32,
        chunk_count: 1,
    })
}
```

**工作量**: ~2 天
**风险**: 高（密码学关键路径）
**验收**:
- Manifest 正确序列化/加密
- AEAD tag 验证通过
- AAD 绑定正确

### 3.5 era-engine: 全副本冗余写入

**任务**: 修改 `VolumeStage::write_catalog_to_all` 和新增 `write_manifest_to_all`

```rust
// Catalog 全副本（已存在，需确认 Index 也全副本）
pub async fn write_catalog_to_all(...) -> Result<Vec<(u64, u32, u32)>> { ... }

// Index 全副本（新增）
pub async fn write_index_to_all(...) -> Result<Vec<(u64, u32, u32)>> { ... }

// Manifest 全副本（新增）
pub async fn write_manifest_to_all(...) -> Result<Vec<(u64, u32, u32)>> { ... }
```

**工作量**: ~2 天
**风险**: 中
**验收**:
- 所有 volume 都有 Catalog/Index/Manifest 副本
- 各副本内容完全一致

### 3.6 era-engine: Footer v2 写入

**任务**: 修改 `VolumePool::finalize_with_catalogs()`

```rust
// 新增 manifest 位置到 footer
footer_builder
    .manifest(manifest_offset, manifest_block_id)
    .catalog(catalog_offset, catalog_size, catalog_block_id)
    .index(index_offset, index_size, index_block_id)
    .build();
```

**工作量**: ~1 天
**风险**: 中
**验收**:
- Footer v2 正确序列化
- manifest_offset/block_id 正确写入

**Phase 2 里程碑**: 写入管线完整，可创建含 Manifest 的 v8.2 archive

---

## 4. Phase 3: 读取管线 + 验证增强（第 2-3 周）

### 4.1 era-engine: Manifest 加载与验证

**任务**: 实现 `load_manifest_from_volume()`

```rust
async fn load_manifest_from_volume(
    reader: &VolumeReader,
    key_session: &KeySession,
    footer: &Footer,
) -> Result<ArchiveManifest> {
    let offset = footer.manifest_offset();
    let block_id = footer.manifest_block_id();
    
    let location = BlockLocation::single(
        reader.header().volume_id(),
        block_id,
        offset,
        // size 需要从 volume 读取 BlockHeader 获取
        0,
    );
    
    let encrypted_block = reader.read_block(&location).await?;
    
    // AEAD 解密
    let block_key = key_session.derive_block_key(
        &volume_key,
        block_id as u64,
        &nonce_context,
    )?;
    let manifest_plaintext = decrypt_with_context(...)?;
    
    let manifest = ArchiveManifest::from_bytes(&manifest_plaintext)?;
    Ok(manifest)
}
```

**工作量**: ~2 天
**风险**: 高（恢复逻辑关键路径）
**验收**:
- Manifest 正确加载
- AEAD 解密成功
- Footer 无 manifest 字段时优雅回退

### 4.2 era-engine: Catalog 加载 + 承诺验证

**任务**: 修改 `ArchiveReader::load_catalog()`

```rust
pub async fn load_catalog(&mut self) -> Result<&Catalog> {
    // 1. 从 Volume 0 加载 Catalog（权威副本）
    let catalog = self.load_catalog_from_volume_0().await?;
    
    // 2. 验证 Catalog 承诺（如有 Manifest）
    if let Some(ref manifest) = self.manifest {
        let catalog_plaintext = catalog.to_bytes()?;
        let expected = compute_catalog_commitment(&catalog_plaintext);
        if expected != manifest.catalog_commitment {
            return Err(EraError::CatalogCommitmentMismatch);
        }
    }
    
    self.catalog = Some(catalog);
    Ok(self.catalog.as_ref().unwrap())
}
```

**工作量**: ~1 天
**风险**: 中
**验收**:
- Catalog 正确加载
- 承诺验证通过
- 承诺不匹配时返回错误（不静默回退）

### 4.3 【修改1】era-engine: 多副本验证加载

**任务**: 为 Catalog/Index/Manifest 实现最高认证世代选择机制

```rust
async fn load_typed_block_with_redundancy<T>(
    volume_readers: &[VolumeReader],
    kind: TypedBlockKind,
    location_extractor: impl Fn(&Footer) -> Option<BlockLocation>,
    validator: impl Fn(EncryptedMacroBlock) -> Result<T>,
    sequence_extractor: impl Fn(&T) -> u64,
) -> Result<(T, Vec<String>)> {
    // 1. 从所有 volume 尝试加载候选副本
    // 2. 对每个成功解密的副本，提取 finalize_sequence
    // 3. 选择 finalize_sequence 最大的认证副本（防止重放）
    // 4. 全部失败返回 AllTypedBlockCopiesCorrupted
}
```

**工作量**: ~2 天
**风险**: 中（影响读取关键路径）
**验收**:
- 崩溃后混合世代时选择最新版本
- 防止旧版有效副本的重放攻击
- 全部副本损坏时返回错误（不静默回退）
- 部分副本损坏时发出警告

### 4.4 【修改2】era-engine: Verify 额外检查 typed block 副本

**任务**: 在 verify 流程中增加 typed block 副本可读性检查

```rust
async fn verify_typed_block_redundancy(&self) -> Result<TypedBlockHealthReport> {
    // 1. 遍历所有 volume
    // 2. 从每个 volume 读取 Catalog/Index/Manifest 副本
    // 3. 验证可读性（AEAD 解密 + CRC + 格式验证）
    // 4. 返回每 volume 的健康状态 + 警告列表
}
```

**工作量**: ~1.5 天
**风险**: 低
**验收**:
- 正常 archive 无警告
- 单副本损坏时发出警告但 verify 通过
- 全部副本损坏时 verify 失败
- 性能开销 < verify 总时间的 5%

### 4.5 era-engine: 迭代器重构（双模式）

**任务**: 重构 `SessionErasureBlockIterator::next_block()`

```rust
pub struct SessionErasureBlockIterator<'a, R> {
    // ... 现有字段 ...
    catalog: Option<&'a Catalog>,
    committed_horizon: u64,
    block_index: usize,
}

impl<'a, R: StorageReader> SessionErasureBlockIterator<'a, R> {
    async fn next_block(&mut self) -> Option<Result<DecodedBlock>> {
        match self.catalog {
            Some(c) => self.next_block_catalog_mode(c).await,
            None => self.next_block_salvage_mode().await,
        }
    }
}
```

**工作量**: ~3 天
**风险**: 高（核心读取路径）
**验收**:
- Catalog 模式：O(1) 查找，无预扫描
- Salvage 模式：保留现有预扫描逻辑
- 两种模式输出结果一致（对比测试）

### 4.6 era-volume: committed_horizon 强制执行

**任务**: 在 `VolumeReader` 添加边界检查

```rust
impl VolumeReader {
    pub async fn read_bounded(&self, offset: u64, len: u32) -> Result<Bytes> {
        if offset + len as u64 > self.committed_horizon {
            return Err(EraError::BeyondCommitHorizon { offset, horizon: self.committed_horizon });
        }
        self.read_at(offset, len).await
    }
}
```

**工作量**: ~0.5 天
**风险**: 低
**验收**:
- 边界内读取正常
- 超出边界返回错误

### 4.7 era-engine: v8.1 兼容性路径

**任务**: fail-closed（移除自动回退）

```rust
impl ArchiveReader {
    async fn open(...) -> Result<Self> {
        let has_manifest = footer.manifest_block_id() > 0;
        
        if has_manifest {
            // v8.2 路径：加载 Manifest，选择最高认证世代
            self.open_v82().await
        } else {
            // fail-closed：无 manifest 时报错
            return Err(EraError::UnsupportedFormat(
                "Archive requires v8.2+ reader. Use --legacy-mode for v8.1 archives.".into()
            ));
        }
    }
}
```

**工作量**: ~0.5 天
**风险**: 低
**验收**:
- v8.2 archive 使用新路径
- 无 manifest 时直接报错

**Phase 3 里程碑**: 读取管线完整，可读取 v8.2 archive，支持多副本验证和 verify 增强

---

## 5. Phase 4: 恢复模块 + Repair 增强（第 3-4 周）

### 5.1 era-engine: RecoveryManager 重写

**任务**: 将 RecoveryManager 改为 manifest 驱动

```rust
pub struct RecoveryManager {
    volume_paths: Vec<PathBuf>,
}

impl RecoveryManager {
    pub async fn recover(&self) -> Result<RecoveryState> {
        // 1. 读取所有 volume 的 Footer
        let footers = self.read_all_footers().await?;
        
        // 2. 从 Volume 0 加载 Manifest（权威副本）
        let manifest = self.load_manifest_from_volume_0(&footers[0]).await?;
        
        // 3. 验证所有 volume 的 Footer 一致性
        self.verify_footer_consistency(&footers)?;
        
        // 4. 返回 RecoveryState（逻辑掩码，不物理截断）
        Ok(RecoveryState {
            committed_horizon: manifest.committed_horizon,
            epoch_id: manifest.epoch_id,
        })
    }
}
```

**工作量**: ~2 天
**风险**: 高（恢复逻辑关键路径）
**验收**:
- 正确读取 Manifest
- 正确验证 Footer 一致性
- 返回正确的 committed_horizon

### 5.2 物理截断移除

**任务**:
- 删除 `RecoveryManager::truncate_to_checkpoint()`（死代码）
- 修改 `VolumeWriter::open_append()`：不截断，记录 committed_horizon

```rust
pub async fn open_append(...) -> Result<Self> {
    let footer = reader.read_footer().await?;
    // 移除：writer.truncate(footer.data_end_offset()).await?;
    
    Ok(Self {
        committed_horizon: footer.data_end_offset(),  // 新增：逻辑边界
        position: footer.data_end_offset(),
    })
}
```

**工作量**: ~1 天
**风险**: 中
**验收**:
- file.set_len() 不再被调用
- append 操作不破坏已有数据

### 5.3 【修改3】era-engine: Repair typed block 副本覆盖修复（Level A）

**任务**: 实现 typed block 损坏副本的覆盖修复

```rust
async fn repair_typed_block_copies(
    &self,
    volume_paths: &[PathBuf],
    key_session: &KeySession,
) -> Result<TypedBlockRepairReport> {
    // 1. 检查每种 typed block 在所有 volume 上的副本
    // 2. 找出健康副本作为权威来源
    // 3. 用权威副本覆盖所有损坏副本
    // 4. 更新 Footer（如需要）
}
```

**工作量**: ~2 天
**风险**: 中（涉及直接文件写入）
**验收**:
- 单副本损坏时成功修复
- 多副本损坏时尝试修复所有可修复的
- 修复后验证可读
- 不破坏未损坏的数据

### 5.4 【修改3】era-engine: Repair Catalog 扫描重建（Level B，延后到 v8.3+）

> **状态**：不在 v8.2 首个版本中实现。

Level B（Catalog 扫描重建）和 Level C（Index 重建）需要额外的元数据冗余设计。当前方案中 Level B 重建的 catalog `entries` 为空，导致 Level C 重建空索引。作为独立项目延后。

### 5.5 死代码删除

**任务**:
- 从读取管线移除 `reconcile_stripe_prefixes` 调用（保留在 repair.rs）
- 删除预扫描 fallback 路径（权威路径中）

**工作量**: ~0.5 天
**风险**: 低
**验收**:
- 编译通过
- Salvage 模式仍保留预扫描（repair.rs 使用）

**Phase 4 里程碑**: 恢复模块完整，支持 v8.2 崩溃恢复 + typed block 修复能力

---

## 6. Phase 5: 测试与审计（第 3-4 周）

### 6.1 单元测试

| 测试模块 | 覆盖内容 | 预估用例 | 优先级 |
|---------|---------|---------|--------|
| ArchiveManifest 序列化 | Protobuf 编码正确性 | 5 | P0 |
| Manifest AEAD 加解密 | AAD 绑定、tag 验证 | 10 | P0 |
| Catalog block_locations | 索引正确性、O(1) 查找 | 8 | P0 |
| Footer v2 字段 | manifest_offset/block_id 读写 | 5 | P0 |
| Catalog 承诺计算 | Blake3 keyed_hash 正确性 | 5 | P0 |
| committed_horizon 边界 | 越界读取拒绝 | 5 | P0 |
| **【修改1】多副本验证加载** | volume_0 失败后尝试其他 volume | 5 | P0 |
| **【修改2】Verify typed block 检查** | 副本可读性验证逻辑 | 5 | P0 |
| **【修改3】Repair 副本覆盖** | 损坏副本的覆盖修复 | 5 | P0 |

### 6.2 集成测试

| 测试场景 | 描述 | 预估用例 | 优先级 |
|---------|------|---------|--------|
| 正常创建/读取 v8.2 | 完整写入读取循环 | 5 | P0 |
| v8.1 兼容性 | 读取旧格式 archive | 3 | P1 |
| 崩溃恢复 | 模拟 finalize 各阶段崩溃 | 8 | P0 |
| 空间不足 | typed block 预检查失败 | 3 | P0 |
| 多卷一致性 | Volume 0 损坏后从其他 volume 恢复 | 5 | P0 |
| 承诺验证失败 | 篡改 Catalog/Index 后检测 | 5 | P0 |
| 偏移雪崩 | 损坏中间 block 后验证 | 3 | P1 |
| **【修改1】Catalog 单副本损坏** | Volume 0 catalog 损坏，从 Volume 1 恢复 | 3 | P0 |
| **【修改1】全部副本损坏** | 所有 volume 的 catalog 损坏，加载失败 | 2 | P0 |
| **【修改2】Verify 发现损坏副本** | 单 volume 的 typed block 副本损坏，verify 发出警告 | 3 | P0 |
| **【修改3】Repair 覆盖 typed block** | 损坏 catalog 副本通过其他 volume 修复 | 3 | P0 |
| **【修改3】Repair 重建 catalog** | 全部 catalog 副本损坏，扫描 data region 重建 | 2 | P1 |

### 6.3 对抗性审计

| 审计方向 | 描述 | 预估用例 | 优先级 |
|---------|------|---------|--------|
| Manifest 篡改 | 修改 manifest ciphertext/tag | 3 | P0 |
| Catalog 承诺绕过 | 修改 catalog 但不更新 commitment | 3 | P0 |
| Epoch 回退 | 注入旧 epoch manifest | 3 | P0 |
| committed_horizon 绕过 | 尝试读取超出边界的数据 | 3 | P0 |
| Footer 字段篡改 | 修改 manifest_offset/block_id | 3 | P0 |
| OOM 攻击 | 尝试用恶意 header 触发大分配 | 3 | P0 |
| **【修改1】多副本验证绕过** | 损坏 volume_0 后注入恶意 volume_1 副本 | 3 | P0 |
| **【修改2】Verify 警告抑制** | 尝试阻止 verify 报告 typed block 损坏 | 2 | P0 |
| **【修改3】Repair 后验证绕过** | 修复后尝试读取损坏数据 | 2 | P0 |

### 6.4 性能基准

| 基准 | 目标 | 方法 |
|------|------|------|
| 读取吞吐 | 1.1-1.3x 提升 | 消除预扫描 overhead |
| Catalog 大小 overhead | < 5% | block_locations 占 archive 总大小比例 |
| 写入延迟 | < 5% 增加 | Manifest 加密 + 承诺计算 overhead |
| 恢复速度 | 2x 提升 | 无需扫描，直接 O(1) 定位 |
| **【修改2】Verify 额外开销** | < 5% 增加 | Typed block 副本验证时间 |
| **【修改3】Repair 覆盖速度** | < 2x 单卷修复时间 | Typed block 副本复制时间 |

**Phase 5 里程碑**: 所有测试通过，对抗性审计无漏洞

---

## 7. 工作量估算

| Phase | 内容 | 天数 | 风险 |
|-------|------|------|------|
| 1 | 基础结构（类型 + schema + 承诺计算 + finalize_sequence） | 5 | 低 |
| 2 | 写入管线（Catalog 构建 + 预检查/预先 rotation + Manifest 加密 + 全副本写入 + Footer v2） | 8 | 高 |
| 3 | 读取管线（Manifest 加载 + 最高世代选择 + Catalog 验证 + Verify 增强 + 迭代器重构 + committed_horizon + fail-closed） | 10 | 高 |
| 4 | 恢复模块（RecoveryManager 重写 + 截断移除 + Repair Level A/D + 非 O_APPEND 存储模式） | 8 | 高 |
| 5 | 测试与审计 | 10 | 中 |
| **总计** | | **~41 天** | |

**预估总工时**: **~5-6 周**（考虑并行开发和部分任务重叠）

> 注：相比 DESIGN_SPEC_v2.0 的 12 周，精简方案节省 **50%+** 工期。Level B/C 延后到 v8.3+ 作为独立项目。
>
> **v8.2 核心功能工时**：
> - 认证世代 + 最高世代选择：~3 天
> - Verify 增强：~2 天
> - Repair Level A + D：~3 天
> - 非 O_APPEND 存储模式：~2 天
> - **合计**：~10 天（含对应测试）

---

## 8. 关键路径

```
Phase 1.1 (Manifest 类型) ──→ Phase 2.4 (Manifest 加密) ──→ Phase 2.5 (全副本写入)
      │                            │                            │
      ↓                            ↓                            ↓
Phase 1.2 (Catalog 扩展) ──→ Phase 2.1 (Catalog 构建) ──→ Phase 3.5 (迭代器重构)
      │                            │                            │
      ↓                            ↓                            ↓
Phase 1.3 (Footer v2) ─────→ Phase 3.1 (Manifest 加载) ──→ Phase 3.2 (Catalog 验证)
                                                              │
                                                              ↓
                                                    Phase 3.3/4.3 (多副本验证 + Repair)
```

**关键路径**（任何延迟直接影响总工期）：
1. Catalog block_locations 扩展 → 迭代器重构
2. Manifest 类型 → Manifest 加密 → Manifest 加载
3. 全副本冗余写入 → 多副本验证加载 → Repair 副本覆盖

**可并行开发**（独立任务）：
- data_end_offset bug 修复
- Footer v2 字段定义
- 承诺计算函数
- committed_horizon 强制执行
- 物理截断移除
- Verify 额外检查（依赖 preflight 加载抽象）
- Catalog 扫描重建（独立复杂任务，可延后）

---

## 9. 风险与缓解

| 风险 | 可能性 | 影响 | 缓解 |
|------|--------|------|------|
| **迭代器重构引入读取错误** | 中 | 高 | 保留 Salvage 模式作为对比基准；编写对比测试确保两种模式输出一致 |
| **data_end_offset 修复引入 regression** | 中 | 高 | 全面的 volume 布局测试；验证现有 archive 的读取 |
| **Catalog block_locations 过大** | 低 | 中 | 基准测试；如过大可考虑分页或压缩 |
| **v8.1 兼容性路径遗漏** | 低 | 高 | 显式的 v8.1 archive 集成测试 |
| **承诺验证性能瓶颈** | 低 | 低 | 基准测试；Blake3 足够快，通常 < 1ms 每 archive |
| **5-6 周工期超期** | 中 | 中 | Phase 3-4 可并行开发；Level B/C 已延后到 v8.3+ |
| **【修改1】多副本验证绕过** | 低 | 高 | 增加对抗性审计：损坏 volume_0 后注入恶意 volume_1 副本的场景 |
| **【修改3】Repair 写入破坏数据** | 低 | 高 | 修复前创建 backup；写入后验证可读性；非原子更新分两步进行 |
| **【修改3】Level B/C 延后** | 低 | 中 | v8.2 仅实现 Level A + D；Level B/C 作为 v8.3+ 独立项目 |

---

## 10. 验收标准

### 10.1 功能验收

- [ ] 可创建 v8.2 archive（含 Manifest、Catalog block_locations、Footer v2）
- [ ] 可读取 v8.2 archive（Catalog 模式，O(1) 查找）
- [ ] fail-closed：无 manifest 时直接报错（不自动回退）
- [ ] Manifest AEAD 加密/解密正确
- [ ] Catalog/Index 承诺验证正确
- [ ] committed_horizon 边界强制执行
- [ ] RecoveryManager 不使用 file.set_len()
- [ ] typed block 不触发 rotation
- [ ] **【修改1】选择最高认证世代的 Manifest（防止重放攻击）**
- [ ] **【修改1】全部 catalog 副本损坏时返回错误（不静默回退）**
- [ ] **【修改1】部分副本损坏时发出警告**
- [ ] **【修改2】verify 检查所有 volume 的 typed block 副本可读性**
- [ ] **【修改2】verify 发现损坏副本时发出警告**
- [ ] **【修改3】repair Level A：可修复损坏的 typed block 副本（从其他 volume 复制）**
- [ ] **【修改3】repair Level D：可重建 Manifest（纯计算）**

### 10.2 安全验收

- [ ] 对抗性审计：无 OOM 向量（Catalog 模式）
- [ ] 对抗性审计：无 Footer 篡改绕过（承诺验证）
- [ ] 对抗性审计：无 Manifest 伪造（AEAD tag 验证）
- [ ] 对抗性审计：无 committed_horizon 绕过（边界检查）
- [ ] 对抗性审计：无 epoch 回退（epoch_id 验证）
- [ ] **【修改1】对抗性审计：无重放攻击（旧版 Manifest 替换新版）**
- [ ] **【修改3】对抗性审计：无 repair 后数据破坏**

### 10.3 性能验收

- [ ] 读取吞吐 ≥ 1.1x v8.1 基线（Catalog 模式）
- [ ] 写入延迟 ≤ 1.05x v8.1 基线
- [ ] Catalog 大小 overhead ≤ 5%
- [ ] 恢复速度 ≥ 2x v8.1 基线
- [ ] **【修改2】verify 额外开销 ≤ 5%**
- [ ] **【修改3】repair 副本覆盖速度 ≤ 2x 单卷修复时间**

---

## 附录：与 DESIGN_SPEC_v2.0 Roadmap 的差异

| 维度 | DESIGN_SPEC_v2.0 (12 周) | 本路线图 (5-6 周) | 原因 |
|------|-------------------------|------------------|------|
| **A/B Slot 实现** | 2 周（Slot 写入 + 切换逻辑） | **0 周**（typed block 替代） | 零额外实现 |
| **多数派共识** | 1 周（Epoch 选择逻辑） | **0 周**（单卷权威副本） | 无需分布式共识 |
| **volume_states** | 0.5 周（HashMap 序列化） | **0 周**（去掉此字段） | 由 committed_horizon 隐含 |
| **专用密钥派生** | 0.5 周（HKDF 域实现） | **0 周**（复用 BLOCK_KEY_DOMAIN） | 减少密码学复杂度 |
| **Index 全副本** | 0.5 周（写入管线修改） | **0.5 周**（统一全副本机制） | 与 Catalog/Manifest 共享代码 |
| **TRAILER_RESERVED** | 1 周（volume 布局重构） | **0.5 周**（仅修复 data_end_offset） | 无 8192B 预留 |
| **测试** | 3 周 | **2 周** | 精简设计减少测试面 |

---

*文档生成时间: 2026-04-21*
*状态: 设计完成，待实施*
