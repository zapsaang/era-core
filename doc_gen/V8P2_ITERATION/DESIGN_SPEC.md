# ERA Volume Format v8.2 设计规范

**版本**: 1.0
**日期**: 2026-04-21
**状态**: 设计完成，待实施
**前置条件**: 代码未上线，无需向后兼容

---

## 目录

1. [设计原则](#1-设计原则)
2. [变更摘要](#2-变更摘要)
3. [Volume 物理布局](#3-volume-物理布局)
4. [数据类型规范](#4-数据类型规范)
5. [密码学规范](#5-密码学规范)
6. [写入协议](#6-写入协议)
7. [读取协议](#7-读取协议)
8. [恢复协议](#8-恢复协议)
9. [错误处理](#9-错误处理)
10. [常量定义](#10-常量定义)
11. [附录：与 DESIGN_SPEC_v2.0 的差异](#11-附录与-design_spec_v20-的差异)

---

## 1. 设计原则

### 1.1 核心目标

1. **根除 OOM 攻击向量**：Catalog.block_locations 提供认证过的 O(1) 绝对偏移查询
2. **消除物理截断**：committed_horizon 逻辑掩码替代 file.set_len()，保留取证能力
3. **外部篡改检测**：AEAD 加密的 Manifest + Catalog/Index 承诺验证
4. **简化恢复逻辑**：typed block 单卷约束 + 全副本冗余

### 1.2 关键架构约束

1. **typed block 不触发 rotation**
   - 写入前预检查目标 volume 空间
   - 空间不足时**预先 rotation**（在写入 typed blocks 之前创建新 volume），不允许写入中 rotation

2. **全副本冗余**
   - Catalog、Index、Manifest 写入**所有 volume**
   - 所有副本内容完全一致（相同 block_id、相同 ciphertext）

3. **Footer 语义不变 + 字段复用**
   - Footer 保持 128 字节单扇区原子写入
   - 利用 reserved 空间（12 字节）增加 manifest 定位字段
   - 不破坏 FOOTER_VERSION=1 的结构兼容性（新增字段在 reserved 区域）

4. **复用现有密码学模式**
   - Manifest 加密复用 BLOCK_KEY_DOMAIN（不引入专用密钥派生）
   - 承诺计算使用 Blake3 keyed_hash

---

## 2. 变更摘要

### 2.1 新增组件

| 组件 | 用途 | 存储位置 |
|------|------|---------|
| `ArchiveManifest` | 认证全局状态 | Typed block (BlockType::Manifest) |
| `Catalog.block_locations` | 块物理位置索引 | Catalog typed block |
| Footer v2 `manifest_offset/block_id` | Manifest 定位 | Footer reserved 字段 |
| `TypedBlockRedundancyValidator` | 多副本验证与修复协调 | 运行时结构（无持久化状态） |

### 2.2 修改组件

| 组件 | 修改内容 |
|------|---------|
| `Catalog` | 新增 `block_locations: Vec<BlockLocation>` |
| `Footer` | reserved3 → manifest_block_id; reserved4 → manifest_offset |
| `SessionErasureBlockIterator` | 双模式：Catalog 模式 / Salvage 模式 |
| `RecoveryManager` | 移除 file.set_len()，改用 committed_horizon |
| `data_end_offset` | 保持物理语义不变（= backup_header_offset），兼容现有 footer/scan 逻辑 |
| `ArchiveReader::load_catalog()` | 多副本验证：volume_0 失败时依次尝试其他 volume |
| `ArchiveReader::verify()` | 额外检查所有 typed block 副本的可读性 |
| `RepairManager` (新增) | Typed block 副本覆盖修复 + 扫描重建能力 |

### 2.3 删除组件

| 组件 | 删除理由 |
|------|---------|
| `file.set_len()` | 破坏性物理截断，改用逻辑掩码 |
| 预扫描 fallback（权威路径） | Catalog 模式提供认证偏移，无需 fallback |

---

## 3. Volume 物理布局

### 3.1 v8.2 布局

```
v8.2:
┌──────────────────────────────────────────────────────────────┐
│  Primary Header (4096B)                                      │
├──────────────────────────────────────────────────────────────┤
│  Backup Footer (128B)                                        │
├──────────────────────────────────────────────────────────────┤
│  Data Region（数据块、Checkpoint）                            │
├──────────────────────────────────────────────────────────────┤
│  Typed Blocks（Catalog、Index、Manifest）← 全副本冗余        │
├──────────────────────────────────────────────────────────────┤
│  Backup Header (4096B)                                       │
├──────────────────────────────────────────────────────────────┤
│  Primary Footer (128B)                                       │
└──────────────────────────────────────────────────────────────┘
```

**关键设计**：
- Typed Blocks 位于 Data Region 内（和 v8.1 一致），在 Data Blocks 之后、Backup Header 之前
- 所有 typed block 完全存放在**单个 volume**内（不跨卷）
- 同一代 volume 的 typed block 位置完全相同（全副本冗余）
- `data_end_offset` 保持物理语义（= backup_header_offset），包含 typed block 区域，确保 `scan_for_typed_blocks` 能扫描到所有 typed blocks

### 3.2 确定性偏移计算

```rust
// v8.2 保持物理语义不变
data_end_offset = backup_header_offset;  // 保持与 v8.1 一致，包含 typed block 区域
```

**committed_horizon 作为逻辑边界**：
```rust
// v8.2 新增：逻辑提交边界，记录在 Manifest 中
let committed_horizon = manifest.committed_horizon;

// Reader 读取数据块时以此为界
// 超出 committed_horizon 但在 data_end_offset 内的数据：
// - 物理存在于磁盘上（取证能力）
// - 对 Reader 不可见（未提交）
```

### 3.3 Footer v2 布局（128 字节）

| Offset | Size | Field | v8.1 | v8.2 |
|--------|------|-------|------|------|
| 0 | 4 | magic | "ERAF" | 不变 |
| 4 | 1 | version | 1 | 1 |
| 5 | 1 | reserved1 | 0 | 0 |
| 6 | 2 | flags | 0 | 0 |
| 8 | 8 | data_end_offset | ✓ | ✓（修复计算） |
| 16 | 4 | block_count | ✓ | ✓ |
| 20 | 4 | reserved2 | 0 | 0 |
| 24 | 8 | sequence_number | ✓ | ✓ |
| 32 | 8 | catalog_offset | ✓ | ✓ |
| 40 | 4 | catalog_size | ✓ | ✓ |
| 44 | 4 | catalog_block_id | ✓ | ✓ |
| 48 | 8 | last_checkpoint_offset | ✓ | ✓ |
| 56 | 4 | last_checkpoint_block_id | ✓ | ✓ |
| **60** | **4** | **reserved3** | **0** | **manifest_block_id** |
| 64 | 8 | index_offset | ✓ | ✓ |
| 72 | 4 | index_size | ✓ | ✓ |
| 76 | 4 | index_block_id | ✓ | ✓ |
| 80 | 8 | backup_header_offset | ✓ | ✓ |
| **88** | **8** | **reserved4** | **0** | **manifest_offset** |
| 96 | 32 | checksum | Blake3 | Blake3 |

**兼容性说明**：
- v8.1 reader 忽略 manifest_block_id/manifest_offset（reserved 字段），按原有逻辑工作
- v8.2 reader **fail-closed**：footer 无 manifest 字段时直接报错，不自动回退到预扫描模式
- 如需读取 v8.1 archive，使用显式 `--legacy-mode` CLI 参数

---

## 4. 数据类型规范

### 4.1 ArchiveManifest（简化版）

```rust
/// Archive 的密码学认证全局状态快照。
/// 作为 AEAD 加密的 typed block 存储（BlockType::Manifest）。
/// 使用 BLOCK_KEY_DOMAIN 派生加密密钥（不复用专用域）。
///
/// 序列化格式：protobuf（与 SuperHeader 一致）
/// 加密方式：XChaCha20-Poly1305，AAD = archive_id ‖ epoch_id ‖ "MANIFEST" ‖ block_id
/// 存储方式：typed block，写入所有 volume（全副本冗余）
#[derive(Debug, Clone)]
pub struct ArchiveManifest {
    /// 单调递增代 ID（与 SuperHeader.epoch_id 一致）。
    /// 用于跨 archive 一致性验证和版本协商。
    pub epoch_id: u32,

    /// 认证世代号（单调递增）。
    /// 用于防止重放攻击：Reader 从所有 volume 加载 Manifest，选择 finalize_sequence 最大的副本。
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
```

**简化说明**：
- 去掉 `manifest_sequence`（复用 `epoch_id` 即可）
- 去掉 `volume_states`（同代 volume tail_offset 相同，由 committed_horizon 隐含）
- 去掉 `index_root_locations`（Index 位置由 Footer.index_offset 指向，或通过扫描获取）
- 去掉 `format_version`（复用 `epoch_id` 协商）

### 4.2 Catalog 扩展

```rust
pub struct Catalog {
    pub entries: Vec<FileEntry>,
    /// 新增：每个 block 的物理位置信息。
    /// 复用已有的 BlockLocation 结构。
    /// 支持 O(1) 绝对偏移查询，替代预扫描。
    pub block_locations: Vec<BlockLocation>,
    pub total_size: u64,
    pub file_count: u64,
    pub dir_count: u64,
}
```

**block_locations 索引规则**：
- `block_locations[i]` 对应逻辑 block index `i`
- 对于非纠删码 archive：`block_locations` 长度 = block_count
- 对于纠删码 archive：`block_locations` 长度 = stripe_count × data_shards

### 4.3 ShardLayout（保持不变）

```rust
pub enum ShardLayout {
    Single,
    Erasure {
        info: ErasureBlockInfo,
        shard_offsets: Vec<u64>,
        shard_volumes: Vec<u16>,
    },
}
```

**说明**：当前代码已包含 `shard_offsets` 和 `shard_volumes`，`ErasureBlockInfo.shard_size` 已提供统一 shard 大小。无需新增 `shard_sizes` 字段（v8.2 不扩展 ShardLayout）。

---

## 5. 密码学规范

### 5.1 Manifest 密钥派生

**不复用专用 HKDF 域**，直接使用现有 block key 派生：

```rust
fn derive_manifest_key(
    key_session: &KeySession,
    volume_key: &VolumeKey,
    block_id: u64,
) -> Result<BlockKey> {
    // 复用现有的 block key 派生，域 = BLOCK_KEY_DOMAIN
    key_session.derive_block_key(volume_key, block_id, nonce_context)
}
```

**理由**：Manifest 本质上是特殊的 typed block，使用与普通数据块相同的密钥派生逻辑。不引入额外的密码学复杂度。

### 5.2 AEAD 加密参数

```rust
// AAD 绑定（32 bytes）
fn manifest_aad(archive_id: &ArchiveId, epoch_id: u32, block_id: BlockId) -> [u8; 32] {
    let mut aad = [0u8; 32];
    aad[0..16].copy_from_slice(archive_id.as_bytes());
    aad[16..20].copy_from_slice(&epoch_id.to_le_bytes());
    aad[20..28].copy_from_slice(b"MANIFEST");
    aad[28..32].copy_from_slice(&block_id.sequence().to_le_bytes());
    aad
}

// Nonce 生成（复用 block nonce 派生）
fn derive_manifest_nonce(nonce_context: &[u8; 16], block_id: u64) -> [u8; 24] {
    // 复用现有的 nonce 派生逻辑
    derive_nonce(nonce_context, block_id)
}
```

### 5.3 承诺计算

```rust
fn compute_catalog_commitment(catalog_plaintext: &[u8]) -> [u8; 32] {
    blake3::keyed_hash(
        b"ERA-CAT-COMMIT-v1___________",  // 32 字节 key
        catalog_plaintext
    ).into()
}

fn compute_index_commitment(index_plaintext: &[u8]) -> [u8; 32] {
    blake3::keyed_hash(
        b"ERA-IDX-COMMIT-v1___________",  // 32 字节 key
        index_plaintext
    ).into()
}
```

**承诺对象**：序列化后的明文 bytes（不是密文）。
- 原因：明文承诺提供确定性语义绑定（相同逻辑内容 = 相同承诺）
- 要求：序列化必须是确定性的（protobuf 字段顺序稳定，BTreeMap 已保证）

---

## 6. 写入协议

### 6.1 完整的 finalize 写入顺序

```
步骤 1: 写入最终数据块（如有）
步骤 2: 预检查 typed block 空间
         - 计算 Catalog + Index + Manifest 总大小
         - 检查每个 volume 是否有足够空间
         - 空间不足 → 预先 rotation（创建新 volume），然后继续
步骤 3: 写入 Catalog 到所有 volume（全副本冗余）
步骤 4: 写入 Index 到所有 volume（全副本冗余）
步骤 5: 构建 ArchiveManifest
         - epoch_id = header.epoch_id
         - finalize_sequence = 上次值 + 1
         - committed_horizon = data_end_offset
         - catalog_commitment = blake3::keyed_hash(domain, &catalog_plaintext)
         - index_commitment = blake3::keyed_hash(domain, &index_plaintext)
步骤 6: AEAD 加密 Manifest → 写入所有 volume（全副本冗余）
步骤 7: 更新 Footer v2
         - manifest_offset = Manifest typed block 的偏移
         - manifest_block_id = Manifest typed block 的 block_id
步骤 8: 写入 Backup Header（所有 volume）
步骤 9: 写入 Primary Footer（所有 volume）
步骤 10: 写入 Backup Footer（所有 volume）
步骤 11: fdatasync()（所有 volume）
```

### 6.2 typed block 空间预检查与预先 rotation

```rust
/// 在 finalize 阶段预检查 typed block 空间
/// 空间不足时预先 rotation（不在写入中触发 rotation）
pub async fn precheck_and_rotate_if_needed(&mut self, catalog_size: u64, index_size: u64) -> Result<()> {
    let manifest_size = estimate_manifest_size();  // 通常 < 1KB
    let total_per_volume = catalog_size + index_size + manifest_size + 3 * BlockHeader::SIZE as u64;
    
    let need_rotation = (0..self.volume_count()).any(|slot| {
        self.volume_remaining_space(slot) < total_per_volume
    });
    
    if need_rotation {
        // 预先 rotation：创建新 volume，确保有足够空间
        self.rotate_volumes().await?;
    }
    
    Ok(())
}
```

**关键约束**：
- 预检查在写入 typed blocks **之前**完成
- 空间不足时**主动 rotation**，不返回错误
- typed block 的写入操作本身**不触发 rotation**

### 6.3 全副本冗余写入

```rust
/// 写入 typed block 到所有 volume（全副本冗余）
/// 约束：每个副本内容完全一致（相同 block_id、相同 ciphertext）
pub async fn write_typed_block_to_all(
    &mut self,
    block: &EncryptedMacroBlock,
    block_type: BlockType,
) -> Result<Vec<BlockLocation>> {
    let mut locations = Vec::with_capacity(self.volume_count());
    
    for slot in 0..self.volume_count() {
        // 直接写入指定 slot（不检查 rotation）
        let writer = self.get_writer_mut(slot)
            .ok_or_else(|| EraError::Other(format!("Missing writer for slot {}", slot)))?;
        
        let location = writer.write_canonical_block(block, block_type).await?;
        locations.push(location);
    }
    
    Ok(locations)
}
```

---

## 7. 读取协议

### 7.1 ArchiveReader::open 流程（含多副本验证）

```rust
impl ArchiveReader {
    async fn open(volume_paths: &[PathBuf], key_session: &KeySession) -> Result<Self> {
        // 1. 打开所有 volume，读取 Footer
        let mut volume_readers = Vec::new();
        for path in volume_paths {
            let reader = VolumeReader::open(path).await?;
            volume_readers.push(reader);
        }
        
        // 2. 检测版本（Footer.magic + 检查 manifest 字段）
        let footer = volume_readers[0].footer()
            .ok_or(EraError::NoFooter)?;
        let has_manifest = footer.manifest_block_id() > 0 && footer.manifest_offset() > 0;
        
        if has_manifest {
            // === v8.2 路径：manifest 驱动 ===
            
            // 3. 加载 Manifest（多副本验证）
            // 优先 volume_0，失败时依次尝试后续 volume 的副本
            let (manifest, manifest_warnings) = load_typed_block_with_redundancy(
                &volume_readers,
                TypedBlockKind::Manifest,
                |footer| footer.manifest_location(),
                |encrypted| decrypt_and_verify_manifest(encrypted, key_session),
            ).await?;
            
            // 4. 加载 Catalog（多副本验证 + 承诺验证）
            let (catalog, catalog_warnings) = load_typed_block_with_redundancy(
                &volume_readers,
                TypedBlockKind::Catalog,
                |footer| footer.catalog_location(),
                |encrypted| decrypt_and_verify_catalog(encrypted, key_session),
            ).await?;
            verify_catalog_commitment(&catalog, &manifest.catalog_commitment)?;
            
            // 5. 加载 Index（多副本验证 + 承诺验证，如存在）
            let (index, index_warnings) = load_typed_block_with_redundancy(
                &volume_readers,
                TypedBlockKind::Index,
                |footer| footer.index_location(),
                |encrypted| decrypt_and_verify_index(encrypted, key_session),
            ).await.ok();
            if let Some(ref idx) = index {
                verify_index_commitment(idx, &manifest.index_commitment)?;
            }
            
            // 6. 合并并发出所有警告（任何 volume 的副本损坏都需报告）
            for w in manifest_warnings.into_iter().chain(catalog_warnings).chain(index_warnings.unwrap_or_default()) {
                warn!("Typed block redundancy warning: {}", w);
            }
            
            // 7. 设置 committed_horizon（读取边界）
            let committed_horizon = manifest.committed_horizon;
            
            Ok(ArchiveReader {
                volume_readers,
                catalog,
                index,
                committed_horizon,
                manifest: Some(manifest),
            })
        } else {
            // === v8.2 fail-closed：无 manifest 时直接报错 ===
            return Err(EraError::UnsupportedFormat(
                "Archive requires v8.2+ reader. Use --legacy-mode for v8.1 archives.".into()
            ));
        }
    }
}
```

**多副本验证核心逻辑**：

```rust
/// 从所有 volume 中加载指定类型的 typed block，支持多副本冗余验证。
/// 
/// 策略：
/// 1. 从所有 volume 尝试加载候选副本
/// 2. 对每个成功解密的副本，提取其 finalize_sequence
/// 3. 选择 finalize_sequence 最大的认证副本（防止重放攻击）
/// 4. 如果全部副本失败，返回错误（不静默回退）
/// 5. 返回所有失败/跳过的警告
async fn load_typed_block_with_redundancy<T>(
    volume_readers: &[VolumeReader],
    kind: TypedBlockKind,
    location_extractor: impl Fn(&Footer) -> Option<BlockLocation>,
    validator: impl Fn(EncryptedMacroBlock) -> Result<T>,
    sequence_extractor: impl Fn(&T) -> u64,  // 提取 finalize_sequence
) -> Result<(T, Vec<String>)> {
    let mut warnings = Vec::new();
    let mut candidates: Vec<(u64, T, usize)> = Vec::new();  // (finalize_sequence, result, vol_idx)
    
    // 尝试从所有 volume 加载
    for (vol_idx, reader) in volume_readers.iter().enumerate() {
        match reader.footer().and_then(|f| location_extractor(f)) {
            Some(location) => {
                match reader.read_block(&location).await {
                    Ok(encrypted) => {
                        match validator(encrypted) {
                            Ok(result) => {
                                let seq = sequence_extractor(&result);
                                candidates.push((seq, result, vol_idx));
                            }
                            Err(e) => {
                                warnings.push(format!(
                                    "Volume {}: {} validation failed: {}",
                                    vol_idx, kind.name(), e
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        warnings.push(format!(
                            "Volume {}: {} read failed: {}",
                            vol_idx, kind.name(), e
                        ));
                    }
                }
            }
            None => {
                warnings.push(format!(
                    "Volume {}: no {} location in footer",
                    vol_idx, kind.name()
                ));
            }
        }
    }
    
    if candidates.is_empty() {
        return Err(EraError::AllTypedBlockCopiesCorrupted {
            kind: kind.name().to_string(),
            volume_count: volume_readers.len(),
            warnings,
        });
    }
    
    // 选择 finalize_sequence 最大的（防止重放）
    candidates.sort_by_key(|(seq, _, _)| *seq);
    let (_, result, vol_idx) = candidates.pop().unwrap();
    
    if !candidates.is_empty() {
        warnings.push(format!(
            "Volume {}: selected {} with highest finalize_sequence (skipped {} older copies)",
            vol_idx, kind.name(), candidates.len()
        ));
    }
    
    Ok((result, warnings))
}
```

### 7.2 双模式迭代器

**设计原则**：当 Catalog（含 block_locations）可用时，完全跳过预扫描；当 Catalog 不可用时（如 repair 场景），保留预扫描作为 salvage 路径。

```rust
pub struct SessionErasureBlockIterator<'a, R> {
    // ... 现有字段 ...
    catalog: Option<&'a Catalog>,  // None = salvage 模式
    committed_horizon: u64,
    block_index: usize,
}

impl<'a, R: StorageReader> SessionErasureBlockIterator<'a, R> {
    pub fn new(args: Args, catalog: Option<&'a Catalog>, committed_horizon: u64) -> Result<Self> {
        match catalog {
            Some(c) => Self::new_catalog_mode(args, c, committed_horizon),
            None => Self::new_salvage_mode(args),
        }
    }
    
    /// CATALOG 模式：O(1) 查找，无预扫描，无 fallback
    async fn next_block_catalog_mode(&mut self) -> Option<Result<DecodedBlock>> {
        // 1. 从已验证的 Catalog 获取 BlockLocation
        let location = self.catalog?.block_locations.get(self.block_index)?;

        // 2. committed_horizon 边界检查
        if location.physical_offset >= self.committed_horizon {
            return None;
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
                let data = self.reader.read_at(
                    location.physical_offset,
                    location.encrypted_size
                ).await?;
                // AEAD 解密 ...
            }
            ShardLayout::Erasure { info, shard_offsets, shard_volumes } => {
                // 纠删码：组合 shard 0 + shard 1..N
                // ...
            }
        }

        self.block_index += 1;
        Some(Ok(decoded_block))
    }
    
    /// SALVAGE 模式：保留现有预扫描（仅 repair 使用）
    async fn next_block_salvage_mode(&mut self) -> Option<Result<DecodedBlock>> {
        // 现有逻辑：预扫描 + reconcile_stripe_prefixes + fallback
        // 此模式仅在 Catalog 不可用时激活（repair.rs 调用）
    }
}
```

**调用点**：
```rust
// ArchiveReader::open() — 权威路径，有 Catalog
let iter = SessionErasureBlockIterator::new(args, Some(&catalog), committed_horizon);

// repair.rs — 修复路径，无 Catalog
let iter = SessionErasureBlockIterator::new(args, None, u64::MAX);  // salvage 模式
```

### 7.3 committed_horizon 强制执行

```rust
impl VolumeReader {
    /// 所有读取操作经过此方法，强制 committed_horizon 边界
    pub async fn read_bounded(&self, offset: u64, len: u32) -> Result<Bytes> {
        if offset + len as u64 > self.committed_horizon {
            return Err(EraError::BeyondCommitHorizon { 
                offset, 
                horizon: self.committed_horizon 
            });
        }
        self.read_at(offset, len).await
    }
}
```

**不自动 zero-fill**: 超出 committed_horizon 的数据保留在磁盘上（取证能力）。

---

### 7.4 Verify 指令增强：Typed Block 副本可读性检查

**设计目标**：在 verify 归档时，额外验证所有 typed block（Catalog/Index/Manifest）在每个 volume 上的副本是否可读。任一副本不可读即发出警告，但不导致 verify 失败（只要至少一个副本可读）。

**验证流程**：

```rust
impl ArchiveReader {
    pub async fn verify(&mut self) -> Result<VerifyStats> {
        info!("Verifying archive integrity...");
        
        self.preflight_metadata_recovery().await?;
        let catalog = self.catalog.as_ref().ok_or_else(|| {
            EraError::IntegrityError("catalog not populated after preflight".into())
        })?;
        
        // === 新增：Typed Block 副本可读性检查 ===
        let typed_block_health = self.verify_typed_block_redundancy().await?;
        
        // 原有 data block 验证逻辑...
        let mut stats = Self::verify_with_iterator(catalog, &mut iter).await?;
        
        // 合并 typed block 健康状态到 stats
        stats.typed_block_warnings = typed_block_health.warnings;
        stats.typed_block_copy_health = typed_block_health.per_volume_status;
        
        stats.archive_health = self.classify_archive_health(&stats);
        self.log_verify_result(&stats);
        Ok(stats)
    }
    
    /// 验证所有 typed block 在所有 volume 上的副本可读性
    async fn verify_typed_block_redundancy(&self) -> Result<TypedBlockHealthReport> {
        let mut report = TypedBlockHealthReport::default();
        
        for (vol_idx, reader) in self.volume_readers.iter().enumerate() {
            let mut volume_status = VolumeTypedBlockStatus::new(vol_idx);
            
            // 验证 Catalog 副本
            if let Some(footer) = reader.footer() {
                if footer.has_catalog_location() {
                    match self.try_read_catalog_from_volume(vol_idx, footer).await {
                        Ok(_) => volume_status.catalog = CopyHealth::Healthy,
                        Err(e) => {
                            volume_status.catalog = CopyHealth::Corrupted(e.to_string());
                            report.warnings.push(format!(
                                "Volume {}: Catalog copy unreadable: {}", vol_idx, e
                            ));
                        }
                    }
                }
                
                // 验证 Index 副本
                if footer.has_index() {
                    match self.try_read_index_from_volume(vol_idx, footer).await {
                        Ok(_) => volume_status.index = CopyHealth::Healthy,
                        Err(e) => {
                            volume_status.index = CopyHealth::Corrupted(e.to_string());
                            report.warnings.push(format!(
                                "Volume {}: Index copy unreadable: {}", vol_idx, e
                            ));
                        }
                    }
                }
                
                // 验证 Manifest 副本（v8.2）
                if footer.manifest_block_id() > 0 {
                    match self.try_read_manifest_from_volume(vol_idx, footer).await {
                        Ok(_) => volume_status.manifest = CopyHealth::Healthy,
                        Err(e) => {
                            volume_status.manifest = CopyHealth::Corrupted(e.to_string());
                            report.warnings.push(format!(
                                "Volume {}: Manifest copy unreadable: {}", vol_idx, e
                            ));
                        }
                    }
                }
            }
            
            report.per_volume_status.push(volume_status);
        }
        
        Ok(report)
    }
}
```

**性能考虑**：
- Typed block 通常很小（Catalog < 1MB，Index < 10MB，Manifest < 1KB）
- 从所有 volume 读取并解密的开销 < verify 总时间的 5%
- 已加载的 volume（preflight 中成功加载的）可复用缓存结果，避免重复解密

**VerifyStats 扩展**：

```rust
pub struct VerifyStats {
    // ... 原有字段 ...
    
    /// 新增：typed block 冗余警告
    pub typed_block_warnings: Vec<String>,
    
    /// 新增：每个 typed block 在各 volume 的健康状态
    /// Key: "catalog"/"index"/"manifest", Value: 每 volume 的健康状态列表
    pub typed_block_copy_health: HashMap<String, Vec<CopyHealth>>,
}
```

---

## 8. 恢复协议

### 8.1 RecoveryManager 改为 manifest 驱动

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
        //    - 相同的 archive_id
        //    - 相同的 epoch_id
        //    - 相同的 data_end_offset（同代 volume 相同）
        self.verify_footer_consistency(&footers, &manifest)?;
        
        // 4. 设置 committed_horizon（逻辑掩码，不物理截断）
        //    关键：RecoveryManager 不再调用 file.set_len() 或任何物理截断操作
        Ok(RecoveryState {
            committed_horizon: manifest.committed_horizon,
            epoch_id: manifest.epoch_id,
        })
    }
}
```

### 8.2 物理截断移除

**移除的截断点**：

| 位置 | 旧行为 | 新行为 |
|------|--------|--------|
| `VolumeWriter::open_append()` | `writer.truncate(footer.data_end_offset())` | 不截断，记录 `committed_horizon = footer.data_end_offset()` |
| `RecoveryManager::truncate_to_checkpoint()` | `file.set_len(data_end)` | **完全删除此函数** |

**Append 写入策略**：

```
Before append:
[Header][Data...old][Footer]  ← committed_horizon = footer.data_end_offset

After append:
[Header][Data...old][NewData][NewFooter]
                       ↑
                committed_horizon（updated after finalize）
```

**崩溃场景处理**：
- 如果在写入 NewData 后、写入 NewFooter 前崩溃：
  - 旧 Footer 仍然存在（没有被截断）
  - Reader 使用旧 Footer → 旧 committed_horizon
  - NewData 对 Reader 不可见（超出 committed_horizon）
  - 下次 append 可以从旧 committed_horizon 继续

---

### 8.3 Repair 增强：Typed Block 副本修复与重建

**设计目标**：repair 时不仅修复 data shards，还需处理 typed block（Catalog/Index/Manifest）的损坏。策略分层：

1. **Level A - 副本覆盖**（v8.2 保留）：从正常 volume 读取副本，覆盖损坏的副本
2. **Level B - Catalog 重建**（延后到 v8.3+）：从 data region 扫描重建 catalog（丢失文件路径等元数据）
3. **Level C - Index 重建**（延后到 v8.3+）：重新运行 IndexBuilder 流程
4. **Level D - Manifest 重建**（v8.2 保留）：重新计算承诺值

**v8.2 首个版本范围**：仅实现 Level A + Level D。Level B/C 需要额外的元数据冗余设计，作为独立项目延后。

#### 8.3.1 Level A：副本覆盖修复

```rust
pub struct RepairManager;

impl RepairManager {
    /// 修复所有 typed block 的损坏副本
    async fn repair_typed_block_copies(
        &self,
        volume_paths: &[PathBuf],
        key_session: &KeySession,
    ) -> Result<TypedBlockRepairReport> {
        let mut report = TypedBlockRepairReport::default();
        
        // 1. 打开所有 volume
        let mut volumes = Vec::new();
        for path in volume_paths {
            volumes.push(VolumeReaderWriter::open(path).await?);
        }
        
        // 2. 对每种 typed block，检查所有 volume 的副本
        for kind in [TypedBlockKind::Manifest, TypedBlockKind::Catalog, TypedBlockKind::Index] {
            let copies = self.collect_typed_block_copies(&volumes, kind).await?;
            
            // 3. 找出健康的权威副本
            let healthy_copies: Vec<_> = copies.iter()
                .filter(|c| c.validation_result.is_ok())
                .collect();
            
            if healthy_copies.is_empty() {
                report.level_a_failed.push(kind);
                warn!("All {} copies corrupted, falling back to Level B/C reconstruction", kind.name());
                continue;
            }
            
            // 4. 使用第一个健康副本作为权威来源
            let authoritative = &healthy_copies[0];
            
            // 5. 修复所有损坏的副本
            for copy in copies.iter().filter(|c| c.validation_result.is_err()) {
                match self.overwrite_typed_block_copy(
                    &mut volumes[copy.volume_idx],
                    kind,
                    &authoritative.raw_bytes,
                ).await {
                    Ok(_) => {
                        report.repairs.push(TypedBlockRepair {
                            kind,
                            volume_idx: copy.volume_idx,
                            repair_type: RepairType::CopyOverwrite,
                        });
                        info!("Repaired {} copy on volume {} by overwrite", kind.name(), copy.volume_idx);
                    }
                    Err(e) => {
                        report.level_a_partial_failures.push((kind, copy.volume_idx, e.to_string()));
                        warn!("Failed to repair {} on volume {}: {}", kind.name(), copy.volume_idx, e);
                    }
                }
            }
        }
        
        Ok(report)
    }
    
    /// 覆盖写入 typed block 副本到指定 volume
    async fn overwrite_typed_block_copy(
        &self,
        volume: &mut VolumeReaderWriter,
        kind: TypedBlockKind,
        data: &[u8],
    ) -> Result<()> {
        // 1. 确定写入位置（使用与原副本相同的 block_id，但可能需要新偏移）
        let footer = volume.footer()
            .ok_or_else(|| EraError::NoFooter)?;
        let location = kind.extract_location(footer)
            .ok_or_else(|| EraError::TypedBlockNotFound(kind.name().to_string()))?;
        
        // 2. 写入数据（保持相同的 block_id 和加密参数）
        volume.write_at(location.physical_offset, data).await?;
        
        // 3. 更新 Footer（如果需要新偏移，同步更新 footer 中的位置指针）
        // 注意：如果覆盖到原位置，Footer 无需更新
        // 如果写入到新位置（原位置损坏无法覆盖），需更新 Footer 并原子写入
        
        // 4. 验证写入后的副本可读
        let verify_result = volume.read_block(&location).await;
        if verify_result.is_err() {
            return Err(EraError::IntegrityError("Repaired copy verification failed".into()));
        }
        
        Ok(())
    }
}
```

#### 8.3.2 Level B：Catalog 扫描重建（v8.3+ 规划）

> **状态**：不在 v8.2 首个版本中实现。

当全部 Catalog 副本损坏时，扫描 data region 重建 catalog。但这只能恢复 raw chunks，**无法恢复文件路径、目录结构、权限等元数据**。

此外，Level B 重建的 catalog `entries` 为空，导致 Level C 重建的 Index 也为空。需要额外的元数据冗余设计才能解决。

#### 8.3.3 Level C：Index 重建（v8.3+ 规划）

> **状态**：不在 v8.2 首个版本中实现。

当全部 Index 副本损坏时，重新运行 IndexBuilder。依赖于 Level B 的 catalog 重建，但 Level B 的 catalog entries 为空，导致 Level C 重建空索引。

#### 8.3.4 Level D：Manifest 重建

Manifest 是纯派生结构，重建简单：

```rust
fn rebuild_manifest(
    epoch_id: u32,
    committed_horizon: u64,
    catalog: &Catalog,
    index: Option<&IndexReader>,
) -> ArchiveManifest {
    let catalog_plaintext = catalog.to_bytes();
    let catalog_commitment = compute_catalog_commitment(&catalog_plaintext);
    
    let index_commitment = index.map(|idx| {
        let index_plaintext = idx.to_bytes();
        compute_index_commitment(&index_plaintext)
    }).unwrap_or([0u8; 32]);
    
    ArchiveManifest {
        epoch_id,
        committed_horizon,
        catalog_commitment,
        index_commitment,
    }
}
```

---

## 9. 错误处理

### 9.1 新增错误类型

```rust
pub enum EraError {
    // ... 现有错误 ...
    
    /// 读取超出提交边界
    BeyondCommitHorizon { offset: u64, horizon: u64 },
    
    /// Catalog 承诺验证失败
    CatalogCommitmentMismatch,
    
    /// Index 承诺验证失败
    IndexCommitmentMismatch,
    
    /// Volume 空间不足（typed block 预检查失败）
    VolumeFull {
        volume: usize,
        required: u64,
        available: u64,
        message: String,
    },
    
    /// Manifest 加载失败
    ManifestLoadError(String),
    
    /// Footer 一致性验证失败（多卷场景）
    FooterInconsistency {
        field: String,
        expected: String,
        actual: String,
    },
    
    /// 【修改1】指定类型的 typed block 在所有 volume 上均无法读取
    AllTypedBlockCopiesCorrupted {
        kind: String,
        volume_count: usize,
        warnings: Vec<String>,
    },
    
    /// 【修改1/3】Typed block 在指定 volume 上不存在或位置无效
    TypedBlockNotFound(String),
    
    /// 【修改3】Catalog 重建失败（data region 扫描无法恢复足够信息）
    CatalogReconstructionFailed {
        reason: String,
        blocks_scanned: u64,
        chunks_recovered: u64,
    },
    
    /// 【修改3】Repair 后的副本验证失败（写入后读取不一致）
    RepairVerificationFailed {
        kind: String,
        volume_idx: usize,
        expected_crc: u32,
        actual_crc: u32,
    },
}
```

---

## 10. 常量定义

```rust
// Footer v2
pub const FOOTER_VERSION: u8 = 1;  // 保持为 1（字段利用 reserved 空间）

// Manifest
pub const MANIFEST_BLOCK_TYPE: BlockType = BlockType::Manifest;  // 新增 block type
pub const CATALOG_COMMITMENT_DOMAIN: &[u8] = b"ERA-CAT-COMMIT-v1___________";
pub const INDEX_COMMITMENT_DOMAIN: &[u8] = b"ERA-IDX-COMMIT-v1___________";

// Volume 布局
pub const TRAILER_RESERVED: u64 = HEADER_SIZE as u64 + FOOTER_SIZE as u64; // 4224

// 安全边界
pub const MAX_SHARD_SIZE: u64 = 256 * 1024 * 1024;  // 256MB（保持不变）
pub const MAX_BLOCK_SIZE: u32 = 64 * 1024 * 1024;   // 64MB（保持不变）
```

---

## 11. 附录：与 DESIGN_SPEC_v2.0 的差异

| 维度 | DESIGN_SPEC_v2.0 (完整方案) | 本规范 (v8.2 精简方案) | 原因 |
|------|---------------------------|----------------------|------|
| **ArchiveManifest 结构** | 6 个字段（+ manifest_sequence + format_version + index_root_locations） | 5 个字段（epoch_id + **finalize_sequence** + committed_horizon + catalog_commitment + index_commitment） | 增加认证世代防止重放攻击；单写者场景简化 |
| **Manifest 存储** | A/B Slot（Backup Header 前预留 8192B） | **Typed block**（Data Region 内，不预留空间） | 零额外空间开销；利用现有 typed block 机制 |
| **Manifest Slot 大小** | 4096B per slot | **无固定 slot**（大小由内容决定） | typed block 自然适配内容大小 |
| **volume_states** | `HashMap<VolumeId, u64>` | **去掉** | 单卷约束 + 同代 volume tail_offset 相同，由 committed_horizon 隐含 |
| **密钥派生** | 专用 HKDF 域 "ERA_MANIFEST_KEY_v1______" | **复用 BLOCK_KEY_DOMAIN** | Manifest 本质是特殊 typed block |
| **AAD** | archive_id ‖ epoch_id ‖ "MANIFEST" ‖ slot_id | archive_id ‖ epoch_id ‖ "MANIFEST" ‖ block_id | 无 slot 概念，用 block_id 防重放 |
| **物理截断** | recovery.rs / open_append() 截断文件 | **逻辑 committed_horizon 掩码 + 非 O_APPEND 存储模式** | 保留取证能力；需要新存储 API |
| **预扫描** | 权威路径使用预扫描 + fallback | **双模式迭代器**（Catalog 模式无预扫描 / Salvage 模式保留） + **fail-closed（无自动回退）** | 根除权威路径的 fallback 漏洞；防止降级攻击 |
| **Index 冗余** | 只写 Volume 0 | **全副本冗余**（所有 volume） | 提高可用性 |
| **typed block rotation** | 隐式 rotation（写入中可能触发） | **预检查 + 预先 rotation**（不在写入中触发） | 空间不足时预先 rotation；写入中不触发 |
| **Footer 变更** | 零修改（保持 128B） | **复用 reserved 字段**（manifest_block_id + manifest_offset） | 向后兼容；v8.1 reader 忽略新字段 |
| **多副本验证加载** | 未明确（单卷权威副本） | **最高认证世代选择**：加载所有副本，选择 finalize_sequence 最大的 | 防止重放攻击；崩溃后正确选择最新版本 |
| **Verify 增强** | 仅验证 data blocks | **额外检查 typed block 副本可读性**：每 volume 验证，损坏即警告 | 增强可观测性；提前发现潜在故障 |
| **Repair 增强** | 仅修复 data shards（RS 解码） | **v8.2 保留 Level A + D**；Level B/C 延后到 v8.3+ | Level B/C 需要额外元数据冗余设计 |
| **工期** | 12 周 | **5-6 周** | 精简设计 + 三个增强功能；复用现有机制 |
| **Catalog xattrs** | BTreeMap 替代 HashMap | **无需改动**（代码库已是 BTreeMap） | 代码库已满足 |

---

*文档生成时间: 2026-04-21*
*审计方法: 代码库深度分析 + 架构权衡评估*
*状态: 设计完成，待实施*
