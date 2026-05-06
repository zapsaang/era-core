# Phase 3: 读取管线 + 验证增强 — 详细实施规划

**版本**: 1.0  
**日期**: 2026-04-29  
**状态**: 规划完成，待实施  
**前置条件**: Phase 1（基础结构）、Phase 2（写入管线）已完成

---

## 目录

1. [Phase 3 概述](#1-phase-3-概述)
2. [任务清单与依赖图](#2-任务清单与依赖图)
3. [任务 1: Manifest 加载与验证](#3-任务-1-manifest-加载与验证)
4. [任务 2: Catalog 加载 + 承诺验证](#4-任务-2-catalog-加载--承诺验证)
5. [任务 3: 多副本验证加载（修改1）](#5-任务-3-多副本验证加载修改1)
6. [任务 4: Verify 增强（修改2）](#6-任务-4-verify-增强修改2)
7. [任务 5: 迭代器重构（双模式）](#7-任务-5-迭代器重构双模式)
8. [任务 6: committed_horizon 强制执行](#8-任务-6-committed_horizon-强制执行)
9. [任务 7: v8.1 兼容性路径](#9-任务-7-v81-兼容性路径)
10. [新增错误类型](#10-新增错误类型)
11. [关键设计决策](#11-关键设计决策)
12. [测试策略](#12-测试策略)
13. [工作量与排期](#13-工作量与排期)
14. [风险与缓解](#14-风险与缓解)
15. [验收标准](#15-验收标准)

---

## 1. Phase 3 概述

### 1.1 目标

Phase 3 的核心目标是完成 **v8.2 读取管线** 和 **验证增强**，确保：

1. **Manifest 驱动读取**：ArchiveReader 从 Footer 定位 Manifest，验证 Catalog/Index 承诺，建立 committed_horizon 边界
2. **多副本冗余**：任意 volume 的 typed block（Catalog/Index/Manifest）副本损坏时，可自动从其他 volume 恢复
3. **O(1) 块查找**：Catalog.block_locations 提供认证过的绝对偏移，消除权威路径的预扫描
4. **验证增强**：verify 指令额外检查所有 typed block 副本的可读性，提前发现潜在故障
5. **安全边界**：committed_horizon 强制执行，防止读取未提交数据

### 1.2 设计约束

| 约束 | 说明 |
|------|------|
| typed block 不跨卷 | 每个 typed block 完全存放在单个 volume 内 |
| 全副本冗余 | Catalog/Index/Manifest 在所有 volume 上内容完全一致 |
| fail-closed | v8.2 reader 遇到无 manifest 的 archive 直接报错，不自动回退到预扫描 |
| 防止重放 | 多副本加载时选择 `finalize_sequence` 最大的认证副本 |
| 保留取证能力 | 超出 committed_horizon 的数据保留在磁盘上，对 Reader 不可见 |

### 1.3 输入 / 输出

**输入**（Phase 2 已完成）：
- 含 Manifest 的 v8.2 archive（Footer v2 含 manifest_offset/block_id）
- Catalog 含 block_locations
- Index 全副本冗余

**输出**（Phase 3 交付）：
- 可读取 v8.2 archive 的 ArchiveReader
- 支持多副本验证加载的读取管线
- 增强版 verify 指令
- 双模式迭代器（Catalog 模式 / Salvage 模式）
- committed_horizon 边界强制执行

---

## 2. 任务清单与依赖图

### 2.1 任务清单

| # | 任务 | 风险 | 工作量 | 前置任务 |
|---|------|------|--------|---------|
| 3.1 | Manifest 加载与验证 | 高 | ~2 天 | Phase 2 完成 |
| 3.2 | Catalog 加载 + 承诺验证 | 中 | ~1 天 | 3.1 |
| 3.3 | 【修改1】多副本验证加载 | 中 | ~2 天 | 3.1, 3.2 |
| 3.4 | 【修改2】Verify 增强 | 低 | ~1.5 天 | 3.1, 3.2 |
| 3.5 | 迭代器重构（双模式） | 高 | ~3 天 | 3.2 |
| 3.6 | committed_horizon 强制执行 | 低 | ~0.5 天 | 3.1 |
| 3.7 | v8.1 兼容性路径 | 低 | ~0.5 天 | 3.1 |

### 2.2 依赖图

```
Phase 2 完成 ─────────────────────────────────────────────┐
                                                          │
    ┌──────────────────┬──────────────────┐               │
    ↓                  ↓                  ↓               │
  3.1 (Manifest      3.6 (committed    3.7 (兼容性       │
      加载)              horizon)           路径)        │
    │                  │                  │               │
    ↓                  │                  │               │
  3.2 (Catalog       │                  │               │
      验证)          │                  │               │
    │                  │                  │               │
    ├──┬───────────────┤                  │               │
    ↓  ↓               ↓                  │               │
  3.3  3.4          3.5                 │               │
(多副本) (Verify)  (迭代器)             │               │
    │                  │                  │               │
    └────────┬─────────┘                  │               │
             ↓                            │               │
       Phase 3 里程碑                    │               │
                                          │               │
```

### 2.3 关键路径

**关键路径**（任何延迟直接影响总工期）：
1. `3.1` Manifest 加载 → `3.2` Catalog 验证 → `3.5` 迭代器重构
2. `3.1` Manifest 加载 → `3.3` 多副本验证

**可并行开发**（独立任务）：
- `3.6` committed_horizon 强制执行（与 3.1 并行）
- `3.7` v8.1 兼容性路径（与 3.1 并行）
- `3.4` Verify 增强（依赖 3.2，但可与 3.5 并行）

---

## 3. 任务 1: Manifest 加载与验证

### 3.1 目标

实现从单个 volume 加载 Manifest 的完整流程：定位 → 读取 → AEAD 解密 → 反序列化 → 验证。

### 3.2 修改文件

- `era-engine/src/reader.rs` — 新增 `load_manifest_from_volume()`
- `era-common/src/types/manifest.rs` — `ArchiveManifest::from_bytes()`
- `era-crypto/src/commitment.rs` — 已有承诺计算函数

### 3.3 详细方案

#### 3.3.1 Manifest 定位

Manifest 的位置通过 Footer v2 的 `manifest_offset` 和 `manifest_block_id` 字段确定。
**注意**：Footer 不存储 Manifest 大小，需先从 `manifest_offset` 读取 `BlockHeader` 获取 `length` 字段。

```rust
/// 从 Footer 提取 Manifest 位置信息
///
/// 步骤：
/// 1. 检查 footer.has_manifest()（manifest_offset != 0）
/// 2. 从 manifest_offset 读取 BlockHeader（16 bytes）
/// 3. 从 BlockHeader.length 获取 ciphertext 大小（含 nonce 前缀）
/// 4. 构造 BlockLocation
async fn manifest_location(
    reader: &VolumeReader,
    footer: &Footer,
) -> Result<BlockLocation> {
    if !footer.has_manifest() {
        return Err(EraError::InvalidFormat(
            "Footer missing manifest".into()
        ));
    }
    let offset = footer.manifest_offset();
    let block_id = footer.manifest_block_id();
    let volume_index = u32::from(reader.header().volume_sequence());

    // 读取 BlockHeader 获取长度
    let header_bytes = reader.read_raw(offset, BlockHeader::SIZE as u32).await?;
    let header = BlockHeader::from_bytes(&header_bytes)
        .ok_or_else(|| EraError::CorruptedHeader(
            "Invalid manifest BlockHeader".into()
        ))?;

    Ok(BlockLocation::single(
        reader.header().volume_id(),
        block_id,
        offset,
        header.length,
    ))
}
```

#### 3.3.2 读取与解密

**关键约束**：Writer 将 `nonce || ciphertext` 写入 `EncryptedMacroBlock.data`。Reader 必须先剥离 nonce 前缀，并用前缀 nonce 进行 AEAD 解密。

```rust
/// 从指定 volume 加载并验证 Manifest
///
/// 流程：
/// 1. 定位 Manifest（从 Footer + BlockHeader）
/// 2. 读取完整 EncryptedMacroBlock
/// 3. 从 data 前缀提取实际 nonce，并验证其等于派生 nonce
/// 4. 派生 block key（使用 ArchiveReader 已持有的 volume_key 和 nonce_context）
/// 5. 使用 build_aad() 构建 AAD（复用现有实现）
/// 6. AEAD 解密（验证 tag）
/// 7. protobuf 反序列化
/// 8. 基础验证（epoch_id 非零）
async fn load_manifest_from_volume(
    reader: &VolumeReader,
    key_session: &KeySession,
    footer: &Footer,
) -> Result<ArchiveManifest> {
    // 1. 定位（读取 BlockHeader 获取长度）
    let location = manifest_location(reader, footer).await?;
    let block_id = footer.manifest_block_id();
    let volume_index = u32::from(reader.header().volume_sequence());

    // 2. 读取完整 EncryptedMacroBlock
    let encrypted_block = reader.read_block(&location).await?;

    // 3. 从 data 前缀提取 nonce
    let (stored_nonce, ciphertext) = extract_nonce_prefix(&encrypted_block.data)
        .ok_or_else(|| EraError::Security(
            "Manifest block too short to contain nonce prefix".into()
        ))?;

    // 4. 派生 nonce 并与存储值比对（防 nonce 替换）
    let derived_nonce = derive_nonce_with_volume_index(
        &key_session.nonce_context(),
        BlockId::new(block_id as u64),
        volume_index,
    );
    if stored_nonce != derived_nonce {
        return Err(EraError::Security(
            "Manifest nonce mismatch: possible tampering or wrong volume".into()
        ));
    }

    // 5. 派生 block key（使用 ArchiveReader 已持有的 volume_key）
    let block_key = key_session.derive_block_key(
        &key_session.volume_key(),
        BlockId::new(block_id as u64),
        &key_session.nonce_context(),
    )?;

    // 6. 使用 build_aad() 构建 AAD（复用现有实现）
    let aad = build_aad(
        &key_session.archive_id(),
        key_session.epoch_id(),
        BlockType::Manifest,
        volume_index,
        BlockId::new(block_id as u64),
    );

    // 7. AEAD 解密
    let aead_ctx = XChaCha20Poly1305Context::new(&block_key)?;
    let plaintext = aead_ctx.decrypt(&derived_nonce, &aad, ciphertext)
        .map_err(|e| EraError::Security(format!("Manifest AEAD tag verification failed: {}", e)))?;

    // 8. 反序列化 + 基础验证
    let manifest = ArchiveManifest::from_bytes(&plaintext)?;

    if manifest.epoch_id == 0 {
        return Err(EraError::IntegrityError(
            "Manifest epoch_id cannot be zero".into()
        ));
    }

    Ok(manifest)
}

/// 从 EncryptedMacroBlock.data 前缀提取 nonce
///
/// Writer 将 nonce(24 bytes) || ciphertext 写入 data。
/// 返回 (nonce_bytes, ciphertext_bytes)。
fn extract_nonce_prefix(data: &[u8]) -> Option<([u8; NONCE_SIZE], &[u8])> {
    if data.len() < NONCE_SIZE {
        return None;
    }
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&data[..NONCE_SIZE]);
    Some((nonce, &data[NONCE_SIZE..]))
}
```

#### 3.3.3 ArchiveManifest::from_bytes()

```rust
impl ArchiveManifest {
    /// 从 protobuf bytes 反序列化
    ///
    /// 安全约束：
    /// - 所有字段必须存在
    /// - epoch_id ≠ 0
    /// - committed_horizon ≤ MAX_ARCHIVE_SIZE
    /// - catalog_commitment 和 index_commitment 长度 = 32
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let proto = era_common_proto::ArchiveManifest::decode(bytes)
            .map_err(|e| EraError::Deserialization(e.to_string()))?;

        let epoch_id = proto.epoch_id;
        if epoch_id == 0 {
            return Err(EraError::IntegrityError("epoch_id is zero".into()));
        }

        let committed_horizon = proto.committed_horizon;
        if committed_horizon > MAX_ARCHIVE_SIZE {
            return Err(EraError::IntegrityError(
                format!("committed_horizon {} exceeds max", committed_horizon)
            ));
        }

        let catalog_commitment = proto.catalog_commitment
            .try_into()
            .map_err(|_| EraError::IntegrityError("catalog_commitment length != 32".into()))?;

        let index_commitment = proto.index_commitment
            .try_into()
            .map_err(|_| EraError::IntegrityError("index_commitment length != 32".into()))?;

        Ok(ArchiveManifest {
            epoch_id,
            finalize_sequence: proto.finalize_sequence,
            committed_horizon,
            catalog_commitment,
            index_commitment,
        })
    }
}
```

### 3.4 错误处理

| 错误场景 | 错误类型 | 处理 |
|---------|---------|------|
| Footer 无 manifest | `EraError::InvalidFormat` | 向上传播（由调用者决定是否 fail-closed） |
| Block 读取失败 | `EraError::Io` | 向上传播 |
| nonce 前缀缺失 | `EraError::Security` | 向上传播（tampering detected） |
| nonce 不匹配（派生 vs 存储） | `EraError::Security` | 向上传播（tampering detected） |
| AEAD tag 验证失败 | `EraError::Security` | 向上传播（tampering detected） |
| Protobuf 解析失败 | `EraError::Deserialization` | 向上传播 |
| epoch_id = 0 | `EraError::IntegrityError` | 向上传播 |

### 3.5 验收标准

- [ ] 正确加载含有效 Manifest 的 v8.2 archive
- [ ] nonce 前缀缺失/不匹配时返回 `Security` 错误
- [ ] AEAD tag 验证失败时返回 `Security` 错误
- [ ] Footer 缺少 manifest 时返回 `InvalidFormat` 错误
- [ ] Protobuf 解析失败时返回 `Deserialization` 错误

---

## 4. 任务 2: Catalog 加载 + 承诺验证

### 4.1 目标

加载 Catalog 并验证其密码学承诺，确保 Catalog 内容未被篡改。

### 4.2 修改文件

- `era-engine/src/reader.rs` — 修改 `load_catalog()` 和 `assemble_catalog_data()`
- `era-crypto/src/commitment.rs` — `compute_catalog_commitment()`（已存在）

### 4.3 详细方案

#### 4.3.1 Catalog 加载流程（v8.2 路径）

**关键约束**：Catalog 在写入时经过 **pack → compress → encrypt**。读取时必须走完整的 **decrypt → decompress → unpack → 重组 bytes** 流程，然后对重组后的原始 bytes 验证承诺。

```rust
impl ArchiveReader {
    /// 加载 Catalog（v8.2 路径：先解包重组 bytes，再验证承诺，最后反序列化）
    ///
    /// 流程：
    /// 1. 从 volume 读取 EncryptedMacroBlock（含 BlockHeader）
    /// 2. 使用 unpacker 解包（decrypt + decompress + unpack chunks）
    /// 3. 从 chunks 重组完整的 catalog_data bytes（处理多 block catalog）
    /// 4. 如有 Manifest，对重组后的 bytes 验证 Catalog 承诺
    /// 5. 承诺通过后 protobuf 反序列化
    async fn load_catalog_v82(
        &mut self,
        reader_idx: usize,
    ) -> Result<Catalog> {
        let reader = &self.volume_readers[reader_idx];
        let footer = reader.footer()
            .ok_or_else(|| EraError::CorruptedFooter(
                "Missing footer".into()
            ))?;

        if !footer.has_catalog_location() {
            return Err(EraError::EmptyArchive);
        }

        let catalog_offset = footer.catalog_offset();
        let catalog_size = footer.catalog_size();
        let catalog_block_id = footer.catalog_block_id();
        let volume_index = u32::from(reader.header().volume_sequence());

        // 1. 读取 EncryptedMacroBlock（从 footer 已知 offset 和 size）
        let catalog_location = BlockLocation::single(
            reader.header().volume_id(),
            catalog_block_id,
            catalog_offset,
            catalog_size,
        );
        let encrypted_block = reader.read_block(&catalog_location).await?;

        // 2. 解包（decrypt + decompress + unpack chunks）
        let unpacker = self.create_unpacker();
        let chunks = unpacker.unpack_with_type(
            &encrypted_block,
            volume_index,
            BlockType::Catalog,
        )?;

        if chunks.index.entries.is_empty() {
            return Err(EraError::EmptyCatalog);
        }

        let first_entry = &chunks.index.entries[0];
        let start = first_entry.offset as usize;
        let end = start + first_entry.length as usize;
        if end > chunks.data.len() {
            return Err(EraError::IntegrityError(
                "Catalog chunk bounds exceed data".into()
            ));
        }
        let first_chunk_data = chunks.data.slice(start..end);

        // 3. 重组完整的 catalog_data bytes（处理多 block catalog）
        let catalog_data = self.assemble_catalog_data(
            reader_idx,
            catalog_offset,
            catalog_size,
            catalog_block_id,
            first_chunk_data,
        ).await?;

        // 4. 验证 Catalog 承诺（必须在反序列化之前，使用原始重组 bytes）
        if let Some(ref manifest) = self.manifest {
            let computed = compute_catalog_commitment(&catalog_data);
            if computed != manifest.catalog_commitment {
                return Err(EraError::CatalogCommitmentMismatch);
            }
            info!("Catalog commitment verified against manifest");
        }

        // 5. 承诺通过后反序列化
        let catalog = Catalog::from_bytes(&catalog_data)?;
        Ok(catalog)
    }
}
```

#### 4.3.2 Catalog 承诺验证

```rust
/// 验证 Catalog 承诺
///
/// 承诺对象：**重组后的原始 Catalog bytes**（经过完整解包流程后的 bytes）。
/// 注意：不是 EncryptedMacroBlock 的密文，也不是 protobuf decode+encode 的结果。
/// Writer 在 finalize 阶段对 catalog_data 计算承诺，因此 Reader 必须在
/// 完整解包重组后、反序列化前验证。
fn verify_catalog_commitment(
    catalog_data: &[u8],
    expected_commitment: &[u8; 32],
) -> Result<()> {
    let computed = compute_catalog_commitment(catalog_data);
    if computed != *expected_commitment {
        return Err(EraError::CatalogCommitmentMismatch);
    }
    Ok(())
}

/// Catalog 承诺计算（已存在于 era-crypto）
///
/// 使用 Blake3 keyed_hash，key 为域分离常量
/// key 必须恰好 32 字节
pub fn compute_catalog_commitment(catalog_data: &[u8]) -> [u8; 32] {
    blake3::keyed_hash(
        b"ERA-CAT-COMMIT-v1_____________",  // 32 字节 key
        catalog_data
    ).into()
}
```

### 4.4 错误处理

| 错误场景 | 错误类型 | 处理 |
|---------|---------|------|
| Footer 无 catalog 位置 | `EraError::TypedBlockNotFound` | 向上传播 |
| AEAD 解密失败 | `EraError::Security` | 向上传播 |
| 承诺不匹配 | `EraError::CatalogCommitmentMismatch` | **不静默回退，直接报错** |

### 4.5 验收标准

- [ ] 正确加载含有效 Catalog 的 archive
- [ ] 承诺验证通过时正常返回
- [ ] 承诺不匹配时返回 `CatalogCommitmentMismatch` 错误（不静默回退）
- [ ] 无 Manifest 时跳过承诺验证（向后兼容场景）

---

## 5. 任务 3: 多副本验证加载（修改1）

### 5.1 目标

为 Catalog/Index/Manifest 实现多副本冗余加载机制：从所有 volume 尝试加载，选择 `finalize_sequence` 最大的认证副本，防止重放攻击。

### 5.2 修改文件

- `era-engine/src/reader.rs` — 新增 `load_typed_block_with_redundancy()`
- `era-engine/src/reader.rs` — 修改 `ArchiveReader::open()`

### 5.3 详细方案

#### 5.3.1 核心设计

**策略**：
1. 从所有 volume 尝试加载候选副本
2. 对每个成功解密的副本，提取其 `finalize_sequence`
3. 选择 `finalize_sequence` 最大的认证副本（防止重放攻击）
4. 如果全部副本失败，返回错误（不静默回退）
5. 返回所有失败/跳过的警告

#### 5.3.2 实现

**注意**：`TypedBlockKind` 已存在于 `era-common/src/types/typed_block.rs`，直接复用。`BlockLocation` 使用现有字段 `volume_id`/`slot_index`/`physical_offset`/`encrypted_size`/`shard_layout`。

**设计变更**：去掉不可编译的泛型 async 闭包，改为三个具体的 loader 函数。

```rust
/// 多副本加载的候选结果
struct ManifestCandidate {
    manifest: ArchiveManifest,
    raw_bytes: Vec<u8>,
    volume_idx: usize,
}

/// 从所有 volume 加载 Manifest，选择 finalize_sequence 最大的副本
///
/// 策略：
/// 1. 从所有 volume 并行尝试加载
/// 2. 选择 finalize_sequence 最大的副本
/// 3. 若多个副本有相同最高 sequence，要求原始 bytes 完全一致（blake3 hash）
/// 4. 不一致直接返回 IntegrityError
async fn load_manifest_with_redundancy(
    volume_readers: &[VolumeReader],
    key_session: &KeySession,
) -> Result<(ArchiveManifest, Vec<String>)> {
    let mut warnings = Vec::new();
    let mut candidates: Vec<ManifestCandidate> = Vec::new();

    // 并行加载所有 volume
    let mut futures = Vec::new();
    for (vol_idx, reader) in volume_readers.iter().enumerate() {
        let fut = async move {
            match try_load_manifest_from_volume(reader, key_session, vol_idx).await {
                Ok((manifest, raw_bytes)) => Ok(ManifestCandidate {
                    manifest, raw_bytes, volume_idx: vol_idx,
                }),
                Err(e) => Err((vol_idx, e)),
            }
        };
        futures.push(fut);
    }

    let results = futures::future::join_all(futures).await;
    for result in results {
        match result {
            Ok(candidate) => candidates.push(candidate),
            Err((vol_idx, e)) => warnings.push(format!(
                "Volume {}: Manifest load failed: {}", vol_idx, e
            )),
        }
    }

    if candidates.is_empty() {
        return Err(EraError::IntegrityError(format!(
            "All Manifest copies corrupted: {:?}", warnings
        )));
    }

    // 按 finalize_sequence 排序，取最大值
    candidates.sort_by_key(|c| c.manifest.finalize_sequence);
    let max_seq = candidates.last().unwrap().manifest.finalize_sequence;
    let max_candidates: Vec<_> = candidates.iter()
        .filter(|c| c.manifest.finalize_sequence == max_seq)
        .collect();

    // Tie-breaking：比较原始 bytes 的 blake3 hash
    if max_candidates.len() > 1 {
        let first_hash = blake3::hash(&max_candidates[0].raw_bytes);
        for cand in &max_candidates[1..] {
            let cand_hash = blake3::hash(&cand.raw_bytes);
            if first_hash != cand_hash {
                return Err(EraError::IntegrityError(format!(
                    "Manifest tie-break failed: {} copies with seq={} have different content",
                    max_candidates.len(), max_seq
                )));
            }
        }
    }

    let selected = max_candidates.last().unwrap();
    let skipped = candidates.len() - max_candidates.len();
    if skipped > 0 {
        warnings.push(format!(
            "Selected Manifest from volume {} with seq={} (skipped {} older)",
            selected.volume_idx, max_seq, skipped
        ));
    }

    Ok((selected.manifest.clone(), warnings))
}

/// 尝试从单个 volume 加载 Manifest
async fn try_load_manifest_from_volume(
    reader: &VolumeReader,
    key_session: &KeySession,
    vol_idx: usize,
) -> Result<(ArchiveManifest, Vec<u8>)> {
    let footer = reader.footer()
        .ok_or_else(|| EraError::CorruptedFooter(
            format!("Volume {}: no footer", vol_idx)
        ))?;

    if !footer.has_manifest() {
        return Err(EraError::InvalidFormat(
            format!("Volume {}: footer missing manifest", vol_idx)
        ));
    }

    // 读取 BlockHeader 获取长度，然后读取完整 block
    let manifest = load_manifest_from_volume(reader, key_session, footer).await?;
    // 返回 manifest 和原始 plaintext bytes（用于 tie-breaking）
    let raw_bytes = manifest.to_bytes()?;
    Ok((manifest, raw_bytes))
}

/// Catalog 多副本加载（类似 Manifest，但用承诺验证过滤候选）
async fn load_catalog_with_redundancy(
    volume_readers: &[VolumeReader],
    key_session: &KeySession,
    expected_commitment: &[u8; 32],
) -> Result<(Catalog, Vec<String>)> {
    let mut warnings = Vec::new();
    let mut candidates: Vec<(Catalog, usize)> = Vec::new();

    let mut futures = Vec::new();
    for (vol_idx, reader) in volume_readers.iter().enumerate() {
        let fut = async move {
            match try_load_catalog_with_commitment(
                reader, key_session, vol_idx, expected_commitment
            ).await {
                Ok(catalog) => Ok((catalog, vol_idx)),
                Err(e) => Err((vol_idx, e)),
            }
        };
        futures.push(fut);
    }

    let results = futures::future::join_all(futures).await;
    for result in results {
        match result {
            Ok((catalog, vol_idx)) => candidates.push((catalog, vol_idx)),
            Err((vol_idx, e)) => warnings.push(format!(
                "Volume {}: Catalog load failed: {}", vol_idx, e
            )),
        }
    }

    if candidates.is_empty() {
        return Err(EraError::CatalogCommitmentMismatch);
    }

    // Catalog 多副本不需要 sequence 选择（承诺已绑定到 Manifest）
    // 任选一个成功验证的即可（所有成功验证的 Catalog 内容相同）
    let (catalog, vol_idx) = candidates.remove(0);
    if candidates.len() > 0 {
        warnings.push(format!(
            "Catalog loaded from volume {} ({} additional valid copies)",
            vol_idx, candidates.len()
        ));
    }
    Ok((catalog, warnings))
}

/// Index 多副本加载（类似 Catalog）
async fn load_index_with_redundancy(
    volume_readers: &[VolumeReader],
    key_session: &KeySession,
    expected_commitment: &[u8; 32],
) -> Result<(IndexReader, Vec<String>)> {
    let mut warnings = Vec::new();
    let mut candidates: Vec<(IndexReader, usize)> = Vec::new();

    let mut futures = Vec::new();
    for (vol_idx, reader) in volume_readers.iter().enumerate() {
        let fut = async move {
            match try_load_index_with_commitment(
                reader, key_session, vol_idx, expected_commitment
            ).await {
                Ok(index) => Ok((index, vol_idx)),
                Err(e) => Err((vol_idx, e)),
            }
        };
        futures.push(fut);
    }

    let results = futures::future::join_all(futures).await;
    for result in results {
        match result {
            Ok((index, vol_idx)) => candidates.push((index, vol_idx)),
            Err((vol_idx, e)) => warnings.push(format!(
                "Volume {}: Index load failed: {}", vol_idx, e
            )),
        }
    }

    if candidates.is_empty() {
        return Err(EraError::IndexCommitmentMismatch);
    }

    let (index, vol_idx) = candidates.remove(0);
    if candidates.len() > 0 {
        warnings.push(format!(
            "Index loaded from volume {} ({} additional valid copies)",
            vol_idx, candidates.len()
        ));
    }
    Ok((index, warnings))
}
```

#### 5.3.3 ArchiveReader::open() 集成

```rust
impl ArchiveReader {
    /// 向后兼容的 open：默认使用 v8.2 路径，v8.1 archive 需显式指定 legacy_mode
    pub async fn open(
        path: &Path,
        password: &str,
    ) -> Result<Self> {
        Self::open_with_options(path, password, OpenOptions::default()).await
    }

    /// 带选项的 open
    pub async fn open_with_options(
        path: &Path,
        password: &str,
        options: OpenOptions,
    ) -> Result<Self> {
        // 1. 使用现有 volume discovery 打开所有 volume
        let discovered = Self::discover_volumes(path).await?;
        let volume_readers = discovered.volume_readers;

        if volume_readers.is_empty() {
            return Err(EraError::InvalidFormat("No volumes found".into()));
        }

        // 2. 检测版本：扫描所有 volume，只要任一有 manifest 就走 v8.2
        let any_has_manifest = volume_readers.iter().any(|r| {
            r.footer().map_or(false, |f| f.has_manifest())
        });

        if any_has_manifest {
            // === v8.2 路径：manifest 驱动 ===
            Self::open_v82(volume_readers, discovered, password, options).await
        } else if options.legacy_mode {
            // === v8.1 兼容路径（显式启用） ===
            warn!("Opening archive in legacy v8.1 mode");
            Self::open_v81(volume_readers, discovered, password).await
        } else {
            // === fail-closed ===
            Err(EraError::UnsupportedFormat(
                "Archive requires v8.2+ reader. Use --legacy-mode for v8.1 archives.".into()
            ))
        }
    }

    /// v8.2 打开路径
    async fn open_v82(
        volume_readers: Vec<VolumeReader>,
        discovered: DiscoveredVolumes,
        password: &str,
        _options: OpenOptions,
    ) -> Result<Self> {
        // 认证并创建 key_session（复用现有逻辑）
        let (session, volume_key, nonce_context, archive_id, epoch_id) =
            Self::authenticate_and_create_session(&volume_readers, password).await?;

        // 3. 加载 Manifest（多副本验证 + tie-breaking）
        let (manifest, manifest_warnings) =
            load_manifest_with_redundancy(&volume_readers, &session).await?;

        // 4. 加载 Catalog（多副本验证 + 承诺验证）
        let (catalog, catalog_warnings) =
            load_catalog_with_redundancy(
                &volume_readers, &session, &manifest.catalog_commitment
            ).await?;

        // 5. 加载 Index（以 manifest.index_commitment 为准）
        let has_index_commitment = !manifest.index_commitment.iter().all(|b| *b == 0);
        let (index, index_warnings) = if has_index_commitment {
            let (idx, warnings) = load_index_with_redundancy(
                &volume_readers, &session, &manifest.index_commitment
            ).await?;
            (Some(idx), warnings)
        } else {
            // manifest 声明无 Index：若 footer 有 stray index 则警告但不失败
            let stray_count = volume_readers.iter().filter(|r| {
                r.footer().map_or(false, |f| f.has_index())
            }).count();
            if stray_count > 0 {
                warn!("Manifest has no index commitment but {} volume(s) have stray index", stray_count);
            }
            (None, Vec::new())
        };

        // 6. 合并并发出所有警告
        for w in manifest_warnings.into_iter()
            .chain(catalog_warnings)
            .chain(index_warnings) {
            warn!("Typed block redundancy warning: {}", w);
        }

        // 7. 设置 committed_horizon
        let committed_horizon = manifest.committed_horizon;

        // 从 header 获取 compression 配置（ArchiveManifest 不含这些字段）
        let (compression_level, compression_algorithm) = if let Some(reader) = volume_readers.first() {
            let header = reader.header();
            (header.compression_level, header.compression_algorithm)
        } else {
            (3, CompressionAlgorithm::Zstd) // 默认值
        };

        Ok(ArchiveReader {
            volume_readers,
            volume_indices: discovered.volume_indices,
            expected_volume_count: discovered.expected_volume_count,
            missing_volume_indices: discovered.missing_volume_indices,
            session,
            volume_key,
            nonce_context,
            archive_id,
            epoch_id,
            compression_level,
            compression_algorithm,
            catalog: Some(catalog),
            index_reader: index,
            embedded_index_recovery_failed: false,
        })
    }
}
```

#### 5.3.4 辅助加载函数

```rust
/// 从 volume 加载 Manifest（复用任务 3.1 的实现）
///
/// 注意：此函数处理 nonce 前缀剥离、AAD 绑定、反序列化。
async fn load_manifest_from_volume(
    reader: &VolumeReader,
    key_session: &KeySession,
    footer: &Footer,
) -> Result<ArchiveManifest> {
    // ... 见任务 3.1 的完整实现 ...
}

/// 从 volume 加载 Catalog 并验证承诺
///
/// 流程：读取 → 解包 → 重组 bytes → 验证承诺 → 反序列化
async fn load_catalog_from_volume_with_commitment_check(
    reader: &VolumeReader,
    key_session: &KeySession,
    footer: &Footer,
    expected_commitment: &[u8; 32],
) -> Result<Catalog> {
    // 1. 读取 EncryptedMacroBlock
    let location = BlockLocation::single(
        reader.header().volume_id(),
        footer.catalog_block_id(),
        footer.catalog_offset(),
        footer.catalog_size(),
    );
    let encrypted_block = reader.read_block(&location).await?;

    // 2. 解包（decrypt + decompress）
    let unpacker = create_unpacker(key_session, reader.header().volume_sequence());
    let volume_index = u32::from(reader.header().volume_sequence());
    let chunks = unpacker.unpack_with_type(&encrypted_block, volume_index, BlockType::Catalog)?;

    if chunks.index.entries.is_empty() {
        return Err(EraError::EmptyCatalog);
    }

    // 3. 重组 catalog_data bytes
    let first_entry = &chunks.index.entries[0];
    let start = first_entry.offset as usize;
    let end = start + first_entry.length as usize;
    let first_chunk_data = chunks.data.slice(start..end);
    let catalog_data = assemble_catalog_data_from_chunks(&chunks, first_chunk_data)?;

    // 4. 验证承诺（必须在反序列化之前）
    let computed = compute_catalog_commitment(&catalog_data);
    if computed != *expected_commitment {
        return Err(EraError::CatalogCommitmentMismatch);
    }

    // 5. 反序列化
    Catalog::from_bytes(&catalog_data)
}

/// 从 volume 加载 Index 并验证承诺
async fn load_index_from_volume_with_commitment_check(
    reader: &VolumeReader,
    key_session: &KeySession,
    footer: &Footer,
    expected_commitment: &[u8; 32],
) -> Result<IndexReader> {
    // 类似 Catalog 流程：读取 → 解包 → 重组 → 验证承诺 → 反序列化
    let location = BlockLocation::single(
        reader.header().volume_id(),
        footer.index_block_id(),
        footer.index_offset(),
        footer.index_size(),
    );
    let encrypted_block = reader.read_block(&location).await?;

    let unpacker = create_unpacker(key_session, reader.header().volume_sequence());
    let volume_index = u32::from(reader.header().volume_sequence());
    let chunks = unpacker.unpack_with_type(&encrypted_block, volume_index, BlockType::IndexManifest)?;

    let index_data = assemble_index_data_from_chunks(&chunks)?;

    let computed = compute_index_commitment(&index_data);
    if computed != *expected_commitment {
        return Err(EraError::IndexCommitmentMismatch);
    }

    IndexReader::from_bytes(&index_data)
}
```

#### 5.3.5 错误处理

| 错误场景 | 错误类型 | 处理 |
|---------|---------|------|
| 全部副本损坏 | `EraError::IntegrityError` | 包含所有 volume 的警告信息 |
| 部分副本损坏 | 警告日志 | 继续选择最佳副本 |
| 存在旧版本副本 | 警告日志 | 选择 finalize_sequence 最大的 |
| 相同最高 sequence 的多副本不一致 | `EraError::IntegrityError` | 直接报错（validator 保证一致性） |

#### 5.3.6 验收标准

- [ ] 崩溃后混合世代时选择最新版本（finalize_sequence 最大）
- [ ] 相同最高 sequence 的多副本不一致时直接报错
- [ ] 全部副本损坏时返回错误（不静默回退）
- [ ] 部分副本损坏时发出警告，但加载成功
- [ ] Volume 0 损坏时可从其他 volume 恢复

### 5.4 错误处理

| 错误场景 | 错误类型 | 处理 |
|---------|---------|------|
| 全部副本损坏 | `EraError::AllTypedBlockCopiesCorrupted` | 包含所有 volume 的警告信息 |
| 部分副本损坏 | 警告日志 | 继续选择最佳副本 |
| 存在旧版本副本 | 警告日志 | 选择 finalize_sequence 最大的 |

### 5.5 验收标准

- [ ] 崩溃后混合世代时选择最新版本（finalize_sequence 最大）
- [ ] 防止旧版有效副本的重放攻击
- [ ] 全部副本损坏时返回 `AllTypedBlockCopiesCorrupted` 错误（不静默回退）
- [ ] 部分副本损坏时发出警告，但加载成功
- [ ] Volume 0 损坏时可从其他 volume 恢复

---

## 6. 任务 4: Verify 增强（修改2）

### 6.1 目标

在 verify 流程中额外检查所有 typed block（Catalog/Index/Manifest）在每个 volume 上的副本是否可读。任一副本不可读即发出警告，但不导致 verify 失败（只要至少一个副本可读）。

### 6.2 修改文件

- `era-engine/src/reader.rs` — 修改 `ArchiveReader::verify()`
- `era-common/src/types/verify.rs` — 扩展 `VerifyStats`

### 6.3 详细方案

#### 6.3.1 VerifyStats 扩展

```rust
pub struct VerifyStats {
    // ... 原有字段 ...
    
    /// 新增：typed block 冗余警告
    pub typed_block_warnings: Vec<String>,
    
    /// 新增：每个 typed block 在各 volume 的健康状态
    /// Key: "catalog"/"index"/"manifest", Value: 每 volume 的健康状态列表
    pub typed_block_copy_health: HashMap<String, Vec<CopyHealth>>,
}

#[derive(Debug, Clone)]
pub enum CopyHealth {
    /// 副本可读且与选中的当前世代一致
    HealthyCurrent,
    /// 副本可读但属于旧世代（finalize_sequence 不匹配）
    Stale { expected_seq: u64, actual_seq: u64 },
    /// 副本损坏（AEAD 失败、承诺不匹配、格式错误等）
    Corrupted(String),
    /// Footer 中无此 typed block 的位置信息
    Missing,
}

/// 每 volume 的 typed block 健康状态
#[derive(Debug, Clone)]
pub struct VolumeTypedBlockStatus {
    pub volume_idx: usize,
    pub catalog: CopyHealth,
    pub index: CopyHealth,
    pub manifest: CopyHealth,
}

impl VolumeTypedBlockStatus {
    pub fn new(volume_idx: usize) -> Self {
        Self {
            volume_idx,
            catalog: CopyHealth::Missing,
            index: CopyHealth::Missing,
            manifest: CopyHealth::Missing,
        }
    }
    
    /// 判断当前 volume 的所有 typed block 是否健康
    /// 
    /// 注意：Missing 对 Index 是允许的（archive 可能不含 index），
    /// 但 Catalog 和 Manifest 在 v8.2 中必须存在。
    pub fn all_healthy(&self) -> bool {
        let catalog_ok = matches!(self.catalog, CopyHealth::Healthy);
        let manifest_ok = matches!(self.manifest, CopyHealth::Healthy);
        let index_ok = matches!(self.index, CopyHealth::Healthy | CopyHealth::Missing);
        catalog_ok && manifest_ok && index_ok
    }
}

/// Typed block 健康报告
#[derive(Debug, Default)]
pub struct TypedBlockHealthReport {
    pub warnings: Vec<String>,
    pub per_volume_status: Vec<VolumeTypedBlockStatus>,
}
```

#### 6.3.2 verify() 主流程修改

```rust
impl ArchiveReader {
    pub async fn verify(&mut self) -> Result<VerifyStats> {
        info!("Verifying archive integrity...");

        // 1. 预检：确保 Catalog 已加载（v8.2 路径已在 open 时加载）
        let catalog = match self.catalog {
            Some(ref c) => c,
            None => return Err(EraError::IntegrityError("catalog not loaded".into())),
        };

        // 2. 新增：Typed Block 副本健康检查
        let typed_block_health = self.verify_typed_block_redundancy().await?;

        // 3. 原有 data block 验证逻辑
        let iter = self.block_iterator();
        let mut stats = Self::verify_with_iterator(catalog, &mut iter).await?;

        // 4. 合并 typed block 健康状态到 stats
        stats.warnings.extend(typed_block_health.warnings);
        stats.archive_health = self.classify_health_from_typed_blocks(
            &stats,
            &typed_block_health.per_volume_status
        );

        Ok(stats)
    }
}
```

#### 6.3.3 副本可读性验证

```rust
impl ArchiveReader {
    /// 验证所有 typed block 在所有 volume 上的副本可读性
    /// 
    /// 策略：
    /// 1. 遍历所有 volume
    /// 2. 从每个 volume 读取 Catalog/Index/Manifest 副本
    /// 3. 验证可读性（AEAD 解密 + 格式验证）
    /// 4. 返回每 volume 的健康状态 + 警告列表
    async fn verify_typed_block_redundancy(&self) -> Result<TypedBlockHealthReport> {
        let mut report = TypedBlockHealthReport::default();
        
        for (vol_idx, reader) in self.volume_readers.iter().enumerate() {
            let mut volume_status = VolumeTypedBlockStatus::new(vol_idx);
            
            if let Some(footer) = reader.footer() {
                // 验证 Catalog 副本
                if footer.has_catalog_location() {
                    match self.try_read_catalog_from_volume(vol_idx, footer).await {
                        Ok(_) => volume_status.catalog = CopyHealth::HealthyCurrent,
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
                        Ok(_) => volume_status.index = CopyHealth::HealthyCurrent,
                        Err(e) => {
                            volume_status.index = CopyHealth::Corrupted(e.to_string());
                            report.warnings.push(format!(
                                "Volume {}: Index copy unreadable: {}", vol_idx, e
                            ));
                        }
                    }
                }

                // 验证 Manifest 副本（v8.2）
                if footer.has_manifest() {
                    match self.try_read_manifest_from_volume(vol_idx, footer).await {
                        Ok(manifest) => {
                            // 检查 finalize_sequence 是否与 open 时选中的 Manifest 一致
                            if let Some(ref open_manifest) = self.manifest {
                                if manifest.finalize_sequence != open_manifest.finalize_sequence {
                                    volume_status.manifest = CopyHealth::Stale {
                                        expected_seq: open_manifest.finalize_sequence,
                                        actual_seq: manifest.finalize_sequence,
                                    };
                                    report.warnings.push(format!(
                                        "Volume {}: Manifest is stale (seq {} != selected seq {})",
                                        vol_idx, manifest.finalize_sequence,
                                        open_manifest.finalize_sequence
                                    ));
                                } else {
                                    volume_status.manifest = CopyHealth::HealthyCurrent;
                                }
                            } else {
                                volume_status.manifest = CopyHealth::HealthyCurrent;
                            }
                        }
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

    /// 尝试从指定 volume 读取 Catalog（用于 verify）
    ///
    /// 完整流程：读取 → 解包 → 重组 bytes → 验证承诺
    async fn try_read_catalog_from_volume(
        &self,
        vol_idx: usize,
        footer: &Footer,
    ) -> Result<Catalog> {
        let reader = &self.volume_readers[vol_idx];
        let location = BlockLocation::single(
            reader.header().volume_id(),
            footer.catalog_block_id(),
            footer.catalog_offset(),
            footer.catalog_size(),
        );
        let encrypted = reader.read_block(&location).await?;

        // 使用与 open() 相同的完整解包+承诺验证流程
        let catalog = load_catalog_from_volume_with_commitment_check(
            reader, &self.session, footer,
            &self.selected_manifest.as_ref().unwrap().catalog_commitment
        ).await?;
        Ok(catalog)
    }

    /// 尝试从指定 volume 读取 Index（用于 verify）
    async fn try_read_index_from_volume(
        &self,
        vol_idx: usize,
        footer: &Footer,
    ) -> Result<IndexReader> {
        let reader = &self.volume_readers[vol_idx];
        let location = BlockLocation::single(
            reader.header().volume_id(),
            footer.index_block_id(),
            footer.index_offset(),
            footer.index_size(),
        );
        let encrypted = reader.read_block(&location).await?;

        let index = load_index_from_volume_with_commitment_check(
            reader, &self.session, footer,
            &self.selected_manifest.as_ref().unwrap().index_commitment
        ).await?;
        Ok(index)
    }

    /// 尝试从指定 volume 读取 Manifest（用于 verify）
    async fn try_read_manifest_from_volume(
        &self,
        vol_idx: usize,
        footer: &Footer,
    ) -> Result<ArchiveManifest> {
        let reader = &self.volume_readers[vol_idx];
        load_manifest_from_volume(reader, &self.session, footer).await
    }
}
```

### 6.4 性能考虑

- **benchmark-needed**：Catalog 大小取决于 block_locations 数量。对于 1000 万 block 的 archive，Catalog 可达 1GB+。
- **benchmark-needed**：Verify 额外开销（从所有 volume 并行读取 typed block、解包、验证承诺）与 volume 数量和 Catalog 大小成正比。声明 `< 5%` 需基准证明。
- 已加载的 volume（preflight 中成功加载的）可复用缓存结果
- 多 volume typed-block 检查使用 bounded parallelism（限制并发读取量）

### 6.5 验收标准

- [ ] 正常 archive 无警告
- [ ] 单副本损坏时发出警告但 verify 通过
- [ ] 全部副本损坏时 verify 失败
- [ ] **benchmark-needed**：性能开销目标 < verify 总时间的 5%（需用真实 workload 验证）

---

## 7. 任务 5: 迭代器重构（双模式）

### 7.1 目标

重构 `SessionErasureBlockIterator` 为双模式：
- **Catalog 模式**：当 Catalog（含 block_locations）可用时，O(1) 查找，无预扫描
- **Salvage 模式**：当 Catalog 不可用时（如 repair 场景），保留现有预扫描逻辑

### 7.2 修改文件

- `era-engine/src/block_iter.rs` — 重构 `SessionErasureBlockIterator`
- `era-engine/src/reader.rs` — 修改迭代器构造

### 7.3 详细方案

#### 7.3.1 迭代器结构

```rust
pub struct SessionErasureBlockIterator<'a, R> {
    // 原有字段
    reader: R,
    volume_pool: VolumePool,
    // ... 其他现有字段 ...
    
    // 新增：模式选择
    mode: IteratorMode<'a>,
    
    // 新增： committed_horizon 边界
    committed_horizon: u64,
    
    // Catalog 模式专用
    block_index: usize,
}

enum IteratorMode<'a> {
    /// Catalog 模式：O(1) 查找
    Catalog { catalog: &'a Catalog },
    /// Salvage 模式：保留现有预扫描
    Salvage { /* 原有预扫描状态 */ },
}
```

#### 7.3.2 构造器

```rust
impl<'a, R: StorageReader> SessionErasureBlockIterator<'a, R> {
    pub fn new(
        args: IteratorArgs,
        catalog: Option<&'a Catalog>,
        committed_horizon: u64,
    ) -> Result<Self> {
        match catalog {
            Some(c) => Self::new_catalog_mode(args, c, committed_horizon),
            None => Self::new_salvage_mode(args),
        }
    }
    
    fn new_catalog_mode(
        args: IteratorArgs,
        catalog: &'a Catalog,
        committed_horizon: u64,
    ) -> Result<Self> {
        Ok(Self {
            reader: args.reader,
            volume_pool: args.volume_pool,
            mode: IteratorMode::Catalog { catalog },
            committed_horizon,
            block_index: 0,
            // ... 其他字段 ...
        })
    }
    
    fn new_salvage_mode(args: IteratorArgs) -> Result<Self> {
        Ok(Self {
            reader: args.reader,
            volume_pool: args.volume_pool,
            mode: IteratorMode::Salvage { /* 初始化预扫描状态 */ },
            committed_horizon: u64::MAX, // salvage 模式不设边界
            block_index: 0,
            // ... 其他字段 ...
        })
    }
}
```

#### 7.3.3 Catalog 模式：next_block

```rust
impl<'a, R: StorageReader> SessionErasureBlockIterator<'a, R> {
    pub async fn next_block(&mut self) -> Option<Result<DecodedBlock>> {
        match &self.mode {
            IteratorMode::Catalog { catalog } => {
                self.next_block_catalog_mode(catalog).await
            }
            IteratorMode::Salvage { .. } => {
                self.next_block_salvage_mode().await
            }
        }
    }
    
    /// CATALOG 模式：O(1) 查找，无预扫描，无 fallback
    ///
    /// 流程：
    /// 1. 从已验证的 Catalog 获取 BlockLocation
    /// 2. committed_horizon 边界检查（含 BlockHeader + payload）
    /// 3. 安全边界：防止 OOM
    /// 4. 直接读取：绝对偏移，无需预扫描
    ///
    /// 注意：所有错误路径在返回前已推进 block_index，防止无限循环。
    async fn next_block_catalog_mode(
        &mut self,
        catalog: &Catalog,
    ) -> Option<Result<DecodedBlock>> {
        // 1. 获取 BlockLocation
        let location = match catalog.block_locations.get(self.block_index) {
            Some(loc) => loc,
            None => return None,
        };
        self.block_index += 1; // 立即推进，防止后续错误导致重复

        // 2. committed_horizon 边界检查
        // 真实磁盘读取范围 = physical_offset + BlockHeader::SIZE + payload
        let disk_end = location.physical_offset
            .saturating_add(BlockHeader::SIZE as u64)
            .saturating_add(location.encrypted_size as u64);
        if disk_end > self.committed_horizon {
            return Some(Err(EraError::BeyondCommitHorizon {
                offset: location.physical_offset,
                horizon: self.committed_horizon,
            }));
        }

        // 3. 安全边界：防止 OOM
        if location.encrypted_size > MAX_SAFE_BLOCK_SIZE {
            return Some(Err(EraError::IntegrityError(
                "Catalog block size exceeds safety bounds".into()
            )));
        }

        // 4. 根据 shard_layout 读取
        let result = match &location.shard_layout {
            ShardLayout::Single => {
                // 单块：读取 BlockHeader + payload
                let data = self.reader.read_at(
                    location.physical_offset,
                    BlockHeader::SIZE as u32 + location.encrypted_size
                ).await;
                match data {
                    Ok(bytes) => self.decode_block(bytes, location.block_id).await,
                    Err(e) => Err(e),
                }
            }
            ShardLayout::Erasure { info, shard_offsets, shard_volumes } => {
                // 纠删码：复用现有 erasure 解码组件
                self.read_erasure_block_catalog_mode(location, info, shard_offsets, shard_volumes).await
            }
        };

        Some(result)
    }

    /// SALVAGE 模式：保留现有预扫描（仅 repair 使用）
    ///
    /// 此模式仅在 Catalog 不可用时激活：
    /// - repair.rs 调用时 catalog = None
    /// - 保留现有逻辑：预扫描 + reconcile_stripe_prefixes + fallback
    async fn next_block_salvage_mode(&mut self) -> Option<Result<DecodedBlock>> {
        // 现有逻辑：预扫描 + reconcile_stripe_prefixes + fallback
        // 此模式仅在 Catalog 不可用时激活（repair.rs 调用）
        // ... 保留现有实现 ...
    }
}
```

#### 7.3.4 纠删码块读取（Catalog 模式）

```rust
impl<'a, R: StorageReader> SessionErasureBlockIterator<'a, R> {
    /// 读取纠删码块（Catalog 模式）
    ///
    /// 关键设计：不重新实现 erasure 解码，而是复用现有组件。
    /// 只把"定位"从预扫描换成 Catalog 的 block_locations。
    ///
    /// 现有 ShardLayout::Erasure 约定：
    /// - primary shard 在 BlockLocation 的 volume_id/physical_offset 上
    /// - shard_offsets/shard_volumes 只包含剩余 shards（不含 primary）
    /// - 每个 shard 读取范围 = offset + ShardHeader::SIZE + shard_payload
    async fn read_erasure_block_catalog_mode(
        &mut self,
        location: &BlockLocation,
        info: &ErasureBlockInfo,
        shard_offsets: &[u64],
        shard_volumes: &[u16],
    ) -> Result<DecodedBlock> {
        // 1. committed_horizon 边界检查
        // primary shard（在 BlockLocation 上）
        let primary_shard_end = location.physical_offset
            .saturating_add(ShardHeader::SIZE as u64)
            .saturating_add(info.shard_size as u64);
        if primary_shard_end > self.committed_horizon {
            return Err(EraError::BeyondCommitHorizon {
                offset: location.physical_offset,
                horizon: self.committed_horizon,
            });
        }
        // remaining shards
        for (&offset, &_vol_idx) in shard_offsets.iter().zip(shard_volumes.iter()) {
            let shard_end = offset
                .saturating_add(ShardHeader::SIZE as u64)
                .saturating_add(info.shard_size as u64);
            if shard_end > self.committed_horizon {
                return Err(EraError::BeyondCommitHorizon {
                    offset,
                    horizon: self.committed_horizon,
                });
            }
        }

        // 2. 构建 available_shards 列表
        // 复用现有 SessionErasureBlockUnpacker 或 read_and_extract_chunks 路径
        let mut available_shards = Vec::new();

        // primary shard
        let primary_reader = self.volume_pool.reader(location.volume_id as usize)
            .ok_or_else(|| EraError::VolumeNotFound {
                volume_id: location.volume_id.to_string()
            })?;
        let primary_shard_data = primary_reader.read_at(
            location.physical_offset,
            ShardHeader::SIZE as u32 + info.shard_size
        ).await?;
        available_shards.push(VerifiedShard {
            data: primary_shard_data,
            volume_idx: location.volume_id as usize,
            is_primary: true,
        });

        // remaining shards
        for (&offset, &vol_idx) in shard_offsets.iter().zip(shard_volumes.iter()) {
            let reader = self.volume_pool.reader(vol_idx as usize)
                .ok_or_else(|| EraError::VolumeNotFound {
                    volume_id: vol_idx.to_string()
                })?;
            let shard_data = reader.read_at(
                offset,
                ShardHeader::SIZE as u32 + info.shard_size
            ).await?;
            available_shards.push(VerifiedShard {
                data: shard_data,
                volume_idx: vol_idx as usize,
                is_primary: false,
            });
        }

        // 3. 复用现有 erasure 解码
        let decoded_bytes = self.erasure_decoder.decode_shards(
            &available_shards,
            info.data_shard_count,
            info.parity_shard_count,
        )?;

        // 4. AEAD 解密（复用现有 decode_block）
        self.decode_block(decoded_bytes, BlockId::new(location.slot_index as u64)).await
    }
}
```

#### 7.3.5 调用点更新

```rust
// ArchiveReader::open() — 权威路径，有 Catalog
let iter = SessionErasureBlockIterator::new(
    args,
    Some(&catalog),
    manifest.committed_horizon,
);

// repair.rs — 修复路径，无 Catalog
let iter = SessionErasureBlockIterator::new(
    args,
    None,
    u64::MAX, // salvage 模式不设边界
);
```

### 7.4 关键约束

| 约束 | 说明 |
|------|------|
| Catalog 模式不 fallback | 一旦进入 Catalog 模式，永远不回到预扫描 |
| Salvage 模式保留 | repair.rs 等场景仍需预扫描 |
| 边界检查 | Catalog 模式严格执行 committed_horizon |
| 安全边界 | 所有读取前检查大小，防止 OOM |

### 7.5 验收标准

- [ ] Catalog 模式：O(1) 查找，无预扫描开销
- [ ] Salvage 模式：保留现有预扫描逻辑
- [ ] 两种模式输出结果一致（对比测试）
- [ ] committed_horizon 边界正确执行

---

## 8. 任务 6: committed_horizon 强制执行

### 8.1 目标

在 `ArchiveReader` / `SessionErasureBlockIterator` 层强制执行 committed_horizon 边界，防止读取未提交数据。**不在 VolumeReader 层实现**，以保持层级隔离（committed_horizon 是 archive 级语义，不应污染 L2 的 VolumeReader）。

### 8.2 修改文件

- `era-engine/src/reader.rs` — `ArchiveReader` 携带 `committed_horizon`
- `era-engine/src/block_iter.rs` — `SessionErasureBlockIterator` 在 Catalog 模式中执行边界检查

### 8.3 详细方案

#### 8.3.1 ArchiveReader 边界检查

```rust
pub struct ArchiveReader {
    volume_readers: Vec<VolumeReader>,
    catalog: Catalog,
    index: Option<IndexReader>,
    manifest: Option<ArchiveManifest>,
    /// 从 Manifest 加载的已提交边界
    committed_horizon: u64,
}

impl ArchiveReader {
    /// 读取边界检查辅助函数
    /// 
    /// 规则：
    /// - offset + len <= committed_horizon：允许读取
    /// - offset + len > committed_horizon：返回 BeyondCommitHorizon 错误
    /// 
    /// 注意：
    /// - 不自动 zero-fill
    /// - 超出边界的数据保留在磁盘上（取证能力）
    fn check_read_bound(&self, offset: u64, len: u64) -> Result<()> {
        let end = offset.saturating_add(len);
        if end > self.committed_horizon {
            return Err(EraError::BeyondCommitHorizon { 
                offset, 
                horizon: self.committed_horizon 
            });
        }
        Ok(())
    }
}
```

#### 8.3.2 迭代器集成（Catalog 模式）

迭代器在 Catalog 模式下自行执行边界检查，不依赖 VolumeReader：

```rust
// 在 next_block_catalog_mode 中
// 1. 先检查块是否完全在 committed_horizon 内
let block_end = location.physical_offset.saturating_add(location.encrypted_size as u64);
if block_end > self.committed_horizon {
    return Some(Err(EraError::BeyondCommitHorizon {
        offset: location.physical_offset,
        horizon: self.committed_horizon,
    }));
}

// 2. 安全边界：防止 OOM
if location.encrypted_size > MAX_SAFE_BLOCK_SIZE {
    return Some(Err(EraError::IntegrityError(
        "Catalog block size exceeds safety bounds".into()
    )));
}

// 3. 读取（此时已知在边界内）
let data = self.reader.read_at(
    location.physical_offset,
    location.encrypted_size
).await;
```

### 8.4 错误处理

| 错误场景 | 错误类型 | 处理 |
|---------|---------|------|
| 读取超出 committed_horizon | `EraError::BeyondCommitHorizon` | 向上传播 |

### 8.5 验收标准

- [ ] 边界内读取正常
- [ ] 超出边界返回 `BeyondCommitHorizon` 错误
- [ ] 不自动 zero-fill（保留取证能力）

---

## 9. 任务 7: v8.1 兼容性路径

### 9.1 目标

v8.2 reader 对无 manifest 的 archive 采取 fail-closed 策略：直接报错，不自动回退到预扫描模式。

### 9.2 修改文件

- `era-engine/src/reader.rs` — 修改 `ArchiveReader::open()`
- `bins/era-cli/src/commands.rs` — 新增 `--legacy-mode` CLI 参数（如需）

### 9.3 详细方案

#### 9.3.1 fail-closed 实现

**注意**：完整的 `ArchiveReader::open()` 和 `open_v82()` 实现已在 **任务 3.3** 中详细定义（第 5.3.3 节）。本节仅描述兼容性策略的差异点。

```rust
impl ArchiveReader {
    /// 向后兼容的 open：默认使用 v8.2 路径，v8.1 archive 需显式指定 legacy_mode
    pub async fn open(path: &Path, password: &str) -> Result<Self> {
        Self::open_with_options(path, password, OpenOptions::default()).await
    }

    /// 带选项的 open
    pub async fn open_with_options(
        path: &Path,
        password: &str,
        options: OpenOptions,
    ) -> Result<Self> {
        // 1. 使用现有 discover_volumes 打开所有 volume
        let discovered = Self::discover_volumes(path).await?;
        let volume_readers = discovered.volume_readers;

        if volume_readers.is_empty() {
            return Err(EraError::InvalidFormat("No volumes found".into()));
        }

        // 2. 检测版本：扫描所有 volume，任一有 manifest 即走 v8.2
        let any_has_manifest = volume_readers.iter().any(|r| {
            r.footer().map_or(false, |f| f.has_manifest())
        });

        if any_has_manifest {
            Self::open_v82(volume_readers, discovered, password, options).await
        } else if options.legacy_mode {
            warn!("Opening archive in legacy v8.1 mode");
            Self::open_v81(volume_readers, discovered, password).await
        } else {
            Err(EraError::UnsupportedFormat(
                "Archive requires v8.2+ reader. Use --legacy-mode for v8.1 archives.".into()
            ))
        }
    }
}
```

#### 9.3.2 OpenOptions

```rust
pub struct OpenOptions {
    /// 启用 v8.1 兼容模式
    pub legacy_mode: bool,
    // ... 其他选项 ...
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            legacy_mode: false,
        }
    }
}
```

### 9.4 兼容性说明

| 场景 | 行为 |
|------|------|
| v8.2 archive + v8.2 reader | 正常读取，使用新路径 |
| v8.1 archive + v8.2 reader | 默认报错，提示使用 `--legacy-mode` |
| v8.1 archive + v8.2 reader + `--legacy-mode` | 使用 v8.1 预扫描路径读取 |
| v8.2 archive + v8.1 reader | v8.1 reader 忽略 manifest 字段，按原有逻辑工作（但可能无法验证承诺） |

### 9.5 验收标准

- [ ] v8.2 archive 使用新路径
- [ ] 无 manifest 时默认报错（fail-closed）
- [ ] `--legacy-mode` 可读取 v8.1 archive

---

## 10. 新增错误类型

### 10.1 EraError 扩展

```rust
pub enum EraError {
    // ... 现有错误 ...
    
    /// 【修改3/通用】读取超出提交边界
    BeyondCommitHorizon { 
        offset: u64, 
        horizon: u64 
    },
    
    /// 【修改2】Catalog 承诺验证失败
    CatalogCommitmentMismatch,
    
    /// 【修改2】Index 承诺验证失败
    IndexCommitmentMismatch,
    
    /// 【修改1】指定类型的 typed block 在所有 volume 上均无法读取
    AllTypedBlockCopiesCorrupted {
        kind: String,
        volume_count: usize,
        warnings: Vec<String>,
    },
    
    /// 【修改1/3】Typed block 在指定 volume 上不存在或位置无效
    TypedBlockNotFound(String),
    
    /// 【修改1】Manifest 加载失败
    ManifestLoadError(String),
}
```

### 10.2 错误使用场景

| 错误 | 触发场景 | 处理策略 |
|------|---------|---------|
| `BeyondCommitHorizon` | 读取超出 committed_horizon | 向上传播，Reader 不可见 |
| `CatalogCommitmentMismatch` | Catalog 承诺验证失败 | **不静默回退，直接报错** |
| `IndexCommitmentMismatch` | Index 承诺验证失败 | **不静默回退，直接报错** |
| `AllTypedBlockCopiesCorrupted` | 全部副本损坏 | 包含所有 volume 的警告信息 |
| `TypedBlockNotFound` | Footer 中无指定 typed block 位置 | 向上传播 |
| `ManifestLoadError` | Manifest 定位/读取/解密失败 | 向上传播 |


---

## 11. 关键设计决策

### 11.1 决策 1：多副本加载选择 finalize_sequence 最大的副本

**问题**：崩溃后不同 volume 可能包含不同世代的 Manifest，如何选择？

**方案**：选择 `finalize_sequence` 最大的认证副本。

**理由**：
- `finalize_sequence` 单调递增，每次成功 finalize 后递增
- 最大 finalize_sequence 对应最新成功提交的 archive 状态
- 防止旧版有效副本的重放攻击

**替代方案**：多数派共识（v2.0 设计）。**未采用原因**：单写者场景无需分布式共识，增加复杂度。

### 11.2 决策 2：fail-closed 而非自动回退

**问题**：v8.2 reader 遇到无 manifest 的 archive 时如何处理？

**方案**：直接报错，提示使用 `--legacy-mode`。

**理由**：
- 防止降级攻击：攻击者删除 manifest 迫使 reader 回退到不安全的预扫描模式
- 明确性：用户显式选择兼容模式，了解安全风险
- 向后兼容：v8.1 reader 仍可读取旧 archive

### 11.3 决策 3：Catalog 模式不 fallback 到预扫描

**问题**：Catalog 模式下读取失败时（如 block_locations 指向损坏区域）是否回退到预扫描？

**方案**：不回退，直接报错。

**理由**：
- Catalog 已通过承诺验证，block_locations 是可信的
- 回退会引入预扫描的 OOM 攻击向量
- 损坏应由 repair 流程处理，而非读取时静默修复

### 11.4 决策 4：承诺计算使用明文而非密文

**问题**：承诺对象是序列化后的明文 bytes 还是密文？

**方案**：明文。

**理由**：
- 明文承诺提供确定性语义绑定（相同逻辑内容 = 相同承诺）
- 密文承诺依赖于加密参数（nonce、key），相同内容可能产生不同密文

**风险与缓解**：
- **protobuf 重新序列化非确定性风险**：读取时 `decode` 后再 `encode` 可能与原始 bytes 不同（未知字段、默认值处理、Map 遍历顺序）
- **缓解**：承诺验证**不基于重新序列化**。读取时保留原始 plaintext bytes，承诺直接对这些原始 bytes 验证。`Catalog::from_bytes()` 和 `to_bytes()` 仅用于逻辑操作，不参与承诺验证。
- **额外保障**：Catalog/Index 多副本加载时，validator 先返回原始 plaintext，承诺验证通过后，再进行 protobuf 反序列化。

---

## 12. 测试策略

### 12.1 单元测试

| 测试模块 | 覆盖内容 | 预估用例 | 优先级 |
|---------|---------|---------|--------|
| Manifest 序列化 | Protobuf 编码正确性 | 5 | P0 |
| Manifest AEAD 加解密 | AAD 绑定、tag 验证 | 10 | P0 |
| Catalog 承诺计算 | Blake3 keyed_hash 正确性 | 5 | P0 |
| Index 承诺计算 | Blake3 keyed_hash 正确性 | 5 | P0 |
| Footer v2 字段 | manifest_offset/block_id 读写 | 5 | P0 |
| committed_horizon 边界 | 越界读取拒绝 | 5 | P0 |
| **多副本验证加载** | volume_0 失败后尝试其他 volume | 5 | P0 |
| **多副本验证加载** | 混合世代时选择最大 finalize_sequence | 3 | P0 |
| **承诺验证：原始 bytes** | decode+encode 后承诺不匹配（验证原始 bytes 策略） | 3 | P0 |
| **AAD 完整性** | 验证 AAD 包含 volume_index（防止跨 volume 拼接） | 3 | P0 |
| **Verify typed block 检查** | 副本可读性验证逻辑 | 5 | P0 |

### 12.2 集成测试

| 测试场景 | 描述 | 预估用例 | 优先级 |
|---------|------|---------|--------|
| 正常读取 v8.2 | 完整写入读取循环 | 5 | P0 |
| v8.1 兼容性 | `--legacy-mode` 读取旧格式 | 3 | P1 |
| 崩溃恢复 | 模拟 finalize 各阶段崩溃 | 8 | P0 |
| 多卷一致性 | Volume 0 损坏后从其他 volume 恢复 | 5 | P0 |
| 承诺验证失败 | 篡改 Catalog/Index 后检测 | 5 | P0 |
| **Catalog 单副本损坏** | Volume 0 catalog 损坏，从 Volume 1 恢复 | 3 | P0 |
| **全部副本损坏** | 所有 volume 的 catalog 损坏，加载失败 | 2 | P0 |
| **Verify 发现损坏副本** | 单 volume 的 typed block 副本损坏，verify 发出警告 | 3 | P0 |
| **重放攻击防护** | 注入旧版 Manifest，验证选择最新版本 | 3 | P0 |
| **Catalog 内容替换** | 注入内容不同但承诺不匹配的 Catalog，验证被拒绝 | 3 | P0 |

### 12.3 对抗性审计

| 审计方向 | 描述 | 预估用例 | 优先级 |
|---------|------|---------|--------|
| Manifest 篡改 | 修改 manifest ciphertext/tag | 3 | P0 |
| Catalog 承诺绕过 | 修改 catalog 但不更新 commitment | 3 | P0 |
| Epoch 回退 | 注入旧 epoch manifest | 3 | P0 |
| committed_horizon 绕过 | 尝试读取超出边界的数据 | 3 | P0 |
| Footer 字段篡改 | 修改 manifest_offset/block_id | 3 | P0 |
| OOM 攻击 | 尝试用恶意 header 触发大分配 | 3 | P0 |
| **多副本验证绕过** | 损坏 volume_0 后注入恶意 volume_1 副本 | 3 | P0 |
| **跨 volume AAD 拼接** | 将 volume_0 的 block 密文移到 volume_1 尝试解密 | 3 | P0 |
| **Verify 警告抑制** | 尝试阻止 verify 报告 typed block 损坏 | 2 | P0 |

### 12.4 性能基准

| 基准 | 目标 | 方法 |
|------|------|------|
| 读取吞吐 | 1.1-1.3x 提升 | 消除预扫描 overhead |
| Catalog 大小 overhead | < 5% | block_locations 占 archive 总大小比例 |
| **Verify 额外开销** | < 5% 增加 | Typed block 副本验证时间 |

---

## 13. 工作量与排期

### 13.1 任务拆分

| 任务 | 工作量 | 风险 | 建议排期 |
|------|--------|------|---------|
| 3.1 Manifest 加载与验证 | ~2 天 | 高 | 第 1 周 |
| 3.2 Catalog 加载 + 承诺验证 | ~1 天 | 中 | 第 1 周 |
| 3.3 多副本验证加载 | ~2 天 | 中 | 第 1-2 周 |
| 3.4 Verify 增强 | ~1.5 天 | 低 | 第 2 周 |
| 3.5 迭代器重构 | ~3 天 | 高 | 第 1-2 周 |
| 3.6 committed_horizon 强制执行 | ~0.5 天 | 低 | 第 2 周 |
| 3.7 v8.1 兼容性路径 | ~0.5 天 | 低 | 第 2 周 |
| **合计** | **~10.5 天** | | **第 1-2 周** |

### 13.2 并行开发建议

**第 1 周（并行）**：
- 开发者 A：3.1 Manifest 加载 + 3.2 Catalog 验证
- 开发者 B：3.5 迭代器重构（Catalog 模式部分）
- 开发者 C：3.6 committed_horizon + 3.7 兼容性路径

**第 2 周（并行）**：
- 开发者 A：3.3 多副本验证加载
- 开发者 B：3.5 迭代器重构（Salvage 模式 + 集成）
- 开发者 C：3.4 Verify 增强 + 测试

### 13.3 关键里程碑

| 里程碑 | 时间 | 标准 |
|--------|------|------|
| Manifest/Catalog 加载完成 | 第 1 周末 | 可加载并验证 v8.2 archive 的 Manifest 和 Catalog |
| 迭代器重构完成 | 第 2 周中 | Catalog 模式 O(1) 查找通过测试 |
| Phase 3 完成 | 第 2 周末 | 所有任务完成，读取管线完整 |

---

## 14. 风险与缓解

| 风险 | 可能性 | 影响 | 缓解 |
|------|--------|------|------|
| **迭代器重构引入读取错误** | 中 | 高 | 保留 Salvage 模式作为对比基准；编写对比测试确保两种模式输出一致 |
| **多副本验证性能问题** | 低 | 中 | 从所有 volume 并行读取；Catalog 大小取决于 block 数量（benchmark-needed） |
| **承诺验证性能瓶颈** | 低 | 低 | Blake3 足够快，但大 Catalog（1GB+）仍需时间；可缓存承诺值（benchmark-needed） |
| **v8.1 兼容性路径遗漏** | 低 | 高 | 显式的 v8.1 archive 集成测试；`--legacy-mode` CLI 测试 |
| **Catalog block_locations 过大** | 低 | 中 | 基准测试；如过大可考虑分页或压缩（v8.3+） |
| **多副本验证绕过** | 低 | 高 | 增加对抗性审计：损坏 volume_0 后注入恶意 volume_1 副本的场景 |

---

## 15. 验收标准

### 15.1 功能验收

- [ ] 可读取 v8.2 archive（Catalog 模式，O(1) 查找）
- [ ] fail-closed：无 manifest 时直接报错（不自动回退）
- [ ] Manifest AEAD 加密/解密正确
- [ ] Catalog/Index 承诺验证正确
- [ ] committed_horizon 边界强制执行
- [ ] **多副本验证：选择最高认证世代的 Manifest（防止重放攻击）**
- [ ] **多副本验证：全部 catalog 副本损坏时返回错误（不静默回退）**
- [ ] **多副本验证：部分副本损坏时发出警告**
- [ ] **Verify 增强：检查所有 volume 的 typed block 副本可读性**
- [ ] **Verify 增强：发现损坏副本时发出警告**

### 15.2 安全验收

- [ ] 对抗性审计：无 OOM 向量（Catalog 模式）
- [ ] 对抗性审计：无 Footer 篡改绕过（承诺验证）
- [ ] 对抗性审计：无 Manifest 伪造（AEAD tag 验证）
- [ ] 对抗性审计：无 committed_horizon 绕过（边界检查）
- [ ] 对抗性审计：无 epoch 回退（epoch_id 验证）
- [ ] **对抗性审计：无重放攻击（旧版 Manifest 替换新版）**

### 15.3 性能验收

- [ ] **benchmark-needed**：读取吞吐 ≥ 1.1x v8.1 基线（Catalog 模式）
- [ ] **benchmark-needed**：Catalog 大小 overhead ≤ 5%（取决于 block 数量和文件数）
- [ ] **benchmark-needed**：恢复速度 ≥ 2x v8.1 基线
- [ ] **benchmark-needed**：Verify 额外开销 ≤ 5%（需用真实 workload 验证）

---

## 附录 A：与 ROADMAP.md Phase 3 的差异

| 维度 | ROADMAP.md | 本规划 | 原因 |
|------|-----------|--------|------|
| **任务 3.3 多副本验证** | 泛型函数 `load_typed_block_with_redundancy` | **复用现有 `TypedBlockKind`** | 避免重复定义；对齐现有代码 |
| **任务 3.4 Verify 增强** | 基础实现 | **增加 `CopyHealth` 枚举（含 Stale/HealthyCurrent）** | 区分旧世代副本和当前副本 |
| **任务 3.5 迭代器重构** | 直接修改 `next_block` | **引入 `IteratorMode` 枚举；复用现有 erasure 解码** | 清晰分离模式；避免重写 erasure 逻辑 |
| **任务 3.7 兼容性** | 基础 fail-closed | **增加 `OpenOptions`；保留默认 `open()`** | 向后兼容；扫描所有 volume 检测 v8.2 |
| **伪代码覆盖** | 仅关键函数 | **所有任务均含完整伪代码** | 明确改动，降低实现歧义 |
| **测试策略** | 列表形式 | **按单元/集成/对抗性/性能分类** | 明确测试责任，便于排期 |

## 附录 B：Oracle 审计后修订摘要（2026-04-29）

| 审计发现 | 原始方案 | 修订后 |
|---------|---------|--------|
| AAD 与现有 writer 不兼容 | 自定义 `manifest_aad()` 48 字节 | **复用 `build_aad()` + `derive_nonce_with_volume_index()`** |
| Manifest nonce 前缀未处理 | 直接用派生 nonce 解密整个 data | **先剥离 `nonce \|\| ciphertext` 前缀，验证 nonce 匹配** |
| Catalog 承诺验证对象错误 | 对 AEAD 明文验证 | **解包重组后、反序列化前对原始 catalog_data 验证** |
| Index 可选逻辑 | 以 footer 为准 | **以 `manifest.index_commitment` 为准** |
| committed_horizon 未覆盖 shard | 只查主块 | **Catalog 模式覆盖主块 + 每个 shard + ShardHeader** |
| v8.2 检测只看 volume 0 | `volume_readers[0]` | **扫描所有 volume，任一有 manifest 即走 v8.2** |
| verify 不验证承诺 | 只检查 AEAD 可解密 | **复用 open 的完整 validator（承诺 + 世代一致性）** |
| finalize_sequence tie | 任意选择 | **相同最高 sequence 要求内容一致（validator 保证）** |
| API 不兼容 | 自定义 Footer/BlockLocation 方法 | **对齐现有 API：`has_manifest()`、`BlockLocation::single` 等** |
| 性能假设过强 | 声明 `< 5%` 为既定事实 | **改为 `benchmark-needed`，要求实测证明** |

---

*文档生成时间: 2026-04-29*  
*基于: DESIGN_SPEC.md v1.0 + ROADMAP.md v1.0*  
*状态: 规划完成，待实施*
