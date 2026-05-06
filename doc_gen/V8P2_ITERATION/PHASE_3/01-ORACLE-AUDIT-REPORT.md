# Oracle 审计报告：ERA Core v8.2 Phase 3 读取管线 + 验证增强方案

**审计日期**: 2026-04-29  
**审计对象**: `doc_gen/V8P2_ITERATION/PHASE_3/PLAN.md`（1995 行）  
**参考文档**: `doc_gen/V8P2_ITERATION/ROADMAP.md`（842 行）  
**代码基线**: `feat_fly` 分支，`reader.rs`（2423 行）、`writer.rs`（3321 行）、`block_iter.rs`（1729 行）、`era-index/src/reader.rs`（1282 行）等  
**审计维度**: 安全性、正确性、现有代码兼容性、性能风险、实现可行性、测试覆盖缺口  

---

## 执行摘要

**结论：当前 PLAN 不可直接实施。**

Phase 3 的核心方向（Manifest 驱动读取、Catalog 承诺验证、fail-closed、多副本冗余加载）是正确的，但 PLAN 中存在 **1 个 critical、6 个 high** 级别的阻塞问题，主要集中在：

1. **数据边界契约缺陷**：单一 `committed_horizon` 无法安全表达多卷物理边界
2. **格式兼容冲突**：Index 加载方案与现有 `era-index` 的 rkyv + `IDX\x01` nonce context 不兼容
3. **安全顺序被破坏**：Catalog 承诺验证前可能被现有代码触发 protobuf 反序列化
4. **威胁模型过度承诺**：最大 `finalize_sequence` 不能防全卷回滚
5. **实现不可编译**：多处伪代码依赖不存在的 API（`KeySession` getter、iterator 组件）
6. **路径覆盖不全**：non-erasure 迭代器未进入 Catalog 模式

**建议**：按下方"前置条件"修订 PLAN 后，再进行实现与二次审计。

---

## 关键发现（按严重级别排序）

---

### Critical

#### C1. 单一 `committed_horizon` 不能安全表达多卷边界，且当前 writer 计算会使最后一块被误判越界

| 属性 | 内容 |
|------|------|
| **位置** | `PLAN.md:49-50`（设计约束）、`PLAN.md:813-815`（open_v82 设置）、`PLAN.md:1356-1365`（Catalog 模式边界检查）、`PLAN.md:1430-1451`（shard 边界检查）、`PLAN.md:1555-1613`（committed_horizon 强制执行）；`ROADMAP.md:831-833`；`writer.rs:2074-2078`（horizon 计算）；`writer.rs:444-496` |
| **问题描述** | PLAN 使用单个 `u64 committed_horizon` 约束所有 volume 的读取边界。但每个 volume 有独立的物理 offset 空间：一个全局边界既可能允许读取某卷未提交的尾部数据（安全绕过），也可能拒绝另一卷的有效已提交数据（可用性故障）。<br><br>更严重的是，现有 writer 用 `last_location.physical_offset + encrypted_size` 计算 horizon（**漏掉 `BlockHeader::SIZE`**），而读侧计划按 `physical_offset + BlockHeader::SIZE + encrypted_size` 检查。这意味着最后一个 block 的读取会被错误拒绝。 |
| **威胁场景** | 1. **可用性故障**：v8.2 archive 在读取最后一个 block 时因 horizon 计算不一致而被拒<br>2. **安全绕过**：多卷 archive 中，某卷的尾部未提交数据可能落在全局 horizon 之内而被读取 |
| **影响评估** | 直接影响 v8.2 archive 的读取可用性；多卷场景下存在 committed boundary bypass 风险 |
| **修复建议** | 1. **Manifest 存储 per-volume 边界**：`volume_sequence -> committed_end`，而非单个 `u64`<br>2. 或从已验证的 `Catalog.block_locations` 计算每卷最大 committed end，并与 Manifest commitment 绑定<br>3. 所有加法使用 `checked_add`，防止溢出<br>4. 按对应 shard 所在 volume 的 horizon 检查，而非全局 horizon |

---

### High

#### H1. Index 加载方案与现有 `era-index` 格式和 nonce 域不兼容

| 属性 | 内容 |
|------|------|
| **位置** | `PLAN.md:674-930`（Index 多副本加载）；`era-index/src/reader.rs:365-420`；`era-index/src/builder.rs:430-472`；`era-engine/src/volume_stage.rs:421-452` |
| **问题描述** | PLAN 将 Index 当作 pack -> compress -> encrypt 的 block 处理，引用不存在的 `IndexReader::from_bytes()` 和 `unpack_with_type(BlockType::IndexManifest)`。<br><br>实际情况：<br>- 现有 `IndexManifest` 是 rkyv `MetaIndex`，直接 AEAD 加密，**不走 `SessionBlockUnpacker`**<br>- `era-index` 读写使用独立的 nonce context：`nonce_context[0..4] = b"IDX\x01"`<br>- `IndexReader` 通过 `era_index::reader::Reader::open()` 从明文 rkyv bytes 构建，不是从 protobuf |
| **威胁场景** | 按 PLAN 实现的 Index 多副本加载会解密失败（错误的 nonce context）或无法编译（不存在的 API）；Index commitment 可能对错对象计算（对 unpack 后的 bytes 而非 rkyv 明文） |
| **影响评估** | Index 加载完全不可用；可能破坏现有 V2.1 索引冷恢复能力 |
| **修复建议** | 1. 给 `era-index` 新增 API：`read_index_manifest_plaintext()` -> 返回 AEAD 解密后的原始 rkyv bytes<br>2. 承诺验证对 rkyv MetaIndex 原始明文做 `blake3::keyed_hash(b"ERA-IDX-COMMIT-v1", &rkyv_bytes)`<br>3. 严格复用 `IDX\x01` nonce context 进行 AEAD 解密<br>4. 明文验证通过后，再用 `IndexReader::from_bytes()` 构建读取器 |

#### H2. Catalog 承诺验证顺序仍可能被现有代码破坏，并存在 OOM 向量

| 属性 | 内容 |
|------|------|
| **位置** | `PLAN.md:353-365`（Catalog 加载流程）、`PLAN.md:424-434`（承诺验证）；`reader.rs:986-998`、`reader.rs:1068-1070`（现有 `assemble_catalog_data`）；`entry.rs:405-416` |
| **问题描述** | PLAN 明确要求"重组 bytes -> 验证承诺 -> 反序列化"的安全顺序。但现有 `assemble_catalog_data()` 在单块路径中会**先调用 `Catalog::from_bytes()` 探测**是否需要 strip 12 字节前缀（见 `reader.rs:1068-1070`）。<br><br>此外，重组过程中 `total_len` 来自未认证的 chunk 元数据，当前代码直接执行 `Vec::with_capacity(total_len as usize)`，无上限检查。 |
| **威胁场景** | 1. **承诺验证顺序被破坏**：攻击者构造恶意 Catalog block，在承诺验证前触发 protobuf 解析（现有代码路径）<br>2. **OOM 攻击**：恶意 header 中的 `total_len` 可触发超大内存分配 |
| **影响评估** | 违背 PLAN 的核心安全设计；对抗性审计中的 OOM 向量可能复现 |
| **修复建议** | 1. **Catalog framing 显式化**：按 writer 合同（`write_catalog_to_all`）明确处理 12 字节前缀，**不要靠 `Catalog::from_bytes()` 探测**<br>2. 验证前严格限制：`total_len <= MAX_CATALOG_SIZE`（如 2GB）、`chunk_count <= MAX_CHUNK_COUNT`、每块大小有上限<br>3. 优先**流式计算 BLAKE3 commitment**（`blake3::Hasher::update()`），避免完整物化后再 hash<br>4. 承诺验证通过后，再进行 protobuf 反序列化 |

#### H3. "选择最大 finalize_sequence"不能防全卷回滚，tie-breaking 也没有真正比较原始明文

| 属性 | 内容 |
|------|------|
| **位置** | `PLAN.md:493-531`（多副本加载核心设计）、`PLAN.md:576-590`（tie-breaking）；`PLAN.md:619-623`（`try_load_manifest_from_volume`）；`PLAN.md:1773-1784`（设计决策 1）；`sequence.rs:1-5` |
| **问题描述** | 1. **全卷回滚**：最大 `finalize_sequence` 只能防"部分 volume 包含旧副本"的场景。如果攻击者把所有 volumes 一起回滚到旧的、认证有效的 archive 状态，所有副本的 `finalize_sequence` 都相同且合法，选择机制无法检测。<br>2. **tie-breaking 缺陷**：`try_load_manifest_from_volume()` 返回的是 `manifest.to_bytes()`（protobuf 重新编码结果），而非实际解密出的原始 plaintext bytes。protobuf 的重新编码可能因未知字段、默认值、Map 遍历顺序等与原始 bytes 不同，导致 tie-break 比较的是不稳定的对象。 |
| **威胁场景** | 1. 攻击者拥有所有 volume 的写权限，将全卷替换为旧版本 archive -> reader 加载旧版本而不报错<br>2. 两个不同内容的 Manifest 有相同 `finalize_sequence` 时，tie-break 可能因 protobuf 重新编码差异而漏报 |
| **影响评估** | 文档对"防止重放攻击"的表述过度承诺；实际只能防护 partial stale-copy replay |
| **修复建议** | 1. **威胁模型修正**：将表述改为"partial stale-copy replay 防护"，明确说明不能防全卷回滚<br>2. 若要防全卷回滚，需要外部可信最小 sequence/epoch 锚点（如用户显式指定最小 epoch）<br>3. **tie-break 必须比较解密得到的原始 plaintext digest**（`blake3::hash(&decrypted_plaintext)`），而非 `manifest.to_bytes()` |

#### H4. Iterator 重构伪代码与现有实现不匹配，且未覆盖 non-erasure 路径

| 属性 | 内容 |
|------|------|
| **位置** | `PLAN.md:1253-1276`（迭代器结构）、`PLAN.md:1410-1499`（纠删码块读取）、`PLAN.md:1503-1518`（调用点）；`block_iter.rs:927-956`、`block_iter.rs:1094-1603`（现有 `SessionErasureBlockIterator`）；`reader.rs:1813-1909`；`block.rs:331-340` |
| **问题描述** | PLAN 使用了大量不存在/不匹配的字段和组件：<br>- `volume_pool`：现有代码中 iterator 没有 `VolumePool` 字段<br>- `erasure_decoder`：不存在这个组件，现有 erasure 解码通过 `SessionErasureBlockUnpacker`<br>- `decode_block`：方法签名不匹配<br>- `VerifiedShard { volume_idx, is_primary }`：现有 `VerifiedShard` 需要 `index/expected_crc/crc_valid`<br><br>更严重的是，reader 的 **non-erasure 路径**仍走 `MultiVolumeSessionBlockIterator`（`reader.rs:1813-1909`），PLAN 只重构了 `SessionErasureBlockIterator`。这意味着 non-erasure archive 不会执行 Catalog O(1) 查找和 committed_horizon 检查。 |
| **影响评估** | 方案不可编译；non-erasure archive（大量现有用户场景）无法获得 Phase 3 的任何收益 |
| **修复建议** | 1. **新建或重构一个统一 iterator**，同时覆盖 Single 和 Erasure `BlockLocation`<br>2. 输入为：**已验证 Catalog** + **per-volume committed horizon map**<br>3. 内部根据 `location.shard_layout` 分发到 single-read 或 erasure-decode 路径<br>4. 复用现有的 `SessionErasureBlockUnpacker` 和 shard 读取逻辑，不要引入不存在的组件 |

#### H5. Manifest loader 伪代码依赖不存在的 `KeySession` getter，且 Manifest 校验不足

| 属性 | 内容 |
|------|------|
| **位置** | `PLAN.md:192-253`（`load_manifest_from_volume`）、`PLAN.md:281-304`（`ArchiveManifest::from_bytes`）；`key_session.rs:354-359`；`manifest.rs:111-125`；`volume-reader.rs:383-430` |
| **问题描述** | 1. **不存在的 API**：`key_session.volume_key()`、`key_session.nonce_context()`、`key_session.archive_id()`、`key_session.epoch_id()` 在 `KeySession` 上不存在。这些值目前在 `ArchiveReader` 的独立字段中。<br>2. **校验缺失**：当前 `ArchiveManifest::from_bytes()` 没有验证 `epoch_id != 0`、`committed_horizon` 范围、`catalog_commitment` 长度等 PLAN 声称的约束。<br>3. **未定义常量**：`MAX_ARCHIVE_SIZE` 在代码中未定义。 |
| **影响评估** | 伪代码不可编译；Manifest 结构约束只存在于文档，不在代码中 |
| **修复建议** | 1. 显式传入 `ManifestLoadContext { volume_key, nonce_context, archive_id, epoch_id }`，不要依赖不存在的 getter<br>2. 读取 Manifest 时使用 `read_typed_block()` 并确认 `BlockType::Manifest`，返回原始 plaintext bytes<br>3. `ArchiveManifest::try_from`（或 `from_bytes`）内实现所有边界校验：`epoch_id != 0`、`committed_horizon <= MAX_ARCHIVE_SIZE`、`commitment.len() == 32`<br>4. 额外比对 `manifest.epoch_id == header.epoch_id()`，防止跨 archive 的 epoch 注入 |

#### H6. `OpenOptions` 设计只覆盖 password path，破坏现有认证与 repair 调用面

| 属性 | 内容 |
|------|------|
| **位置** | `PLAN.md:721-840`（`open_v82`）、`PLAN.md:1647-1703`（fail-closed）；`reader.rs:291-490`（现有 `open_with_providers`）；`repair.rs:142-147` |
| **问题描述** | 现有实际入口是 `open_with_providers()`，被 password、threshold、certificate、hybrid、repair 等多种模式复用。PLAN 只给 `open(path, password)` 和 `open_with_options(path, password, options)` 两个入口。<br><br>这意味着 `--legacy-mode`、v8.2 fail-closed、manifest 路径可能**只对密码模式生效**；certificate、threshold、repair 等模式的行为可能与密码模式不一致。 |
| **影响评估** | 多认证模式行为不一致；repair 流程可能无法读取 v8.1 archive（因为 fail-closed 而缺少 legacy 路径） |
| **修复建议** | 1. 增加 `open_with_providers_and_options(providers, options)` 作为**唯一核心入口**<br>2. 所有其它 open 方法（`open`、`open_with_password`、`open_with_keypair`、`open_for_repair` 等）全部委托它<br>3. `OpenOptions` 必须传播到所有认证路径，包括 repair 的 preflight 阶段 |

---

### Medium

#### M1. Verify 增强伪代码内部不一致，当前形态不可编译且语义不清

| 属性 | 内容 |
|------|------|
| **位置** | `PLAN.md:972-973`（VerifyStats 扩展）、`PLAN.md:995-1005`（CopyHealth）、`PLAN.md:1031-1033`（all_healthy）、`PLAN.md:1127-1143`（Manifest stale 检查）、`PLAN.md:1181-1203`（try_read_index_from_volume）、`PLAN.md:1231`（性能声明）；`chunk_processor.rs:397-415` |
| **问题描述** | 1. `CopyHealth` 定义的是 `HealthyCurrent`，但 `all_healthy()` 匹配 `Healthy`（不存在该变体）<br>2. 伪代码同时使用 `self.manifest` 和 `self.selected_manifest`，但 `open_v82()` 构造 `ArchiveReader` 时没有设置这些字段<br>3. "单副本损坏只警告、全部损坏才失败"的语义没有明确规则：selected Manifest/Catalog 本身损坏时应 fail 还是 warn？ |
| **影响评估** | 不可编译；verify 语义不清晰可能导致误报或漏报 |
| **修复建议** | 1. 统一 `CopyHealth` 变体命名：`HealthyCurrent` / `Stale` / `Corrupted` / `Missing`<br>2. 在 `ArchiveReader` 中持久保存 `selected_manifest` 和 `selected_catalog`<br>3. 明确 verify 规则：**selected Manifest/Catalog 必须 healthy**（否则 fail）；**其它副本损坏降级为 warning/degraded** |

#### M2. 多副本并行加载与大 Catalog/Index 组合会造成资源峰值

| 属性 | 内容 |
|------|------|
| **位置** | `PLAN.md:539-553`（Manifest join_all）、`PLAN.md:635-648`（Catalog join_all）、`PLAN.md:683-697`（Index join_all）、`PLAN.md:1222-1225`（性能说明） |
| **问题描述** | 文档提到 bounded parallelism，但伪代码使用 `futures::future::join_all` 同时加载所有 volume。对 1GB+ Catalog，N 个 volume 会产生 N 倍内存和反序列化成本。<br><br>`<5%` verify 开销声明被标记为 `benchmark-needed`，但验收标准仍将其作为目标，存在过度承诺。 |
| **影响评估** | Verify/open 可能在大 archive 上 OOM；性能目标缺乏实证 |
| **修复建议** | 1. **open 路径**：只需找到一个承诺通过的 Catalog 即可（顺序或 limited concurrency），不需要加载所有副本<br>2. **verify 路径**：用 bounded concurrency（如 `stream::iter(volumes).buffer_unordered(4)`）和流式 commitment 计算<br>3. 将 `<5%` 从验收目标改为 `benchmark-needed`，实测后再设定目标 |

---

### Low

#### L1. v8.2 Catalog loader 中"无 Manifest 跳过承诺验证"与 fail-closed 目标冲突

| 属性 | 内容 |
|------|------|
| **位置** | `PLAN.md:425-431`、`PLAN.md:485`（向后兼容场景）、`PLAN.md:752-764`（fail-closed） |
| **问题描述** | v8.2 路径理论上必须有 Manifest（这是 fail-closed 的前提），但 `load_catalog_v82()` 仍允许 `self.manifest == None` 时跳过承诺验证（"向后兼容场景"）。 |
| **影响评估** | 如果调用路径集成错误，可能产生未认证 Catalog 读取，削弱 fail-closed 保证 |
| **修复建议** | v8.2 loader 接口直接要求 `&ArchiveManifest`（非 `Option`）；legacy v8.1 使用单独的 `load_catalog_v81()` 函数 |

---

### Informational

#### I1. 附录 B 已修正一部分 Oracle 问题，但仍遗漏关键修订点

附录 B（`PLAN.md:1976-1990`）覆盖了以下修订：
- AAD 复用 `build_aad()`
- Manifest nonce 前缀剥离与验证
- Catalog 原始 bytes 承诺
- Index 可选逻辑以 `manifest.index_commitment` 为准
- committed_horizon 覆盖 shard
- v8.2 检测扫描所有 volume
- verify 复用完整 validator
- finalize_sequence tie-breaking
- API 对齐现有方法
- `benchmark-needed` 标注

**仍遗漏的关键修订点**：
1. **per-volume committed horizon**，而非单个 `u64`
2. **writer 当前 horizon 漏 `BlockHeader::SIZE`**
3. **Index rkyv + `IDX\x01` nonce context 契约**
4. **Manifest tie-break 必须比较实际解密 plaintext**，非 `to_bytes()`
5. **non-erasure iterator 也必须进入 Catalog mode**
6. **`OpenOptions` 必须覆盖所有 auth/repair 入口**
7. **bounded concurrency 需要落到伪代码**，不只是性能说明
8. **全卷 rollback 不在最大 sequence 选择的防护范围内**

---

## 整体评估

| 评估维度 | 结论 |
|---------|------|
| **安全性** | 核心 crypto 设计方向正确（AAD 绑定、nonce 前缀防替换、明文承诺），但 per-volume horizon 缺失和 Index 格式兼容是阻塞问题 |
| **正确性** | 边界检查覆盖不全，writer/reader horizon 计算不一致，可能导致可用性故障 |
| **现有代码兼容性** | 多处 API 冲突（`KeySession` getter 不存在、`OpenOptions` 覆盖不全），non-erasure 路径未纳入重构 |
| **性能** | 多副本并行加载的资源峰值需 bounded concurrency 和流式处理；`<5%` 目标缺乏实证 |
| **实现可行性** | 伪代码在当前代码基上不可直接编译；需要先对齐现有 API 再编写 |

### 前置条件（实施前必须完成）

1. **修订 `committed_horizon` 为 per-volume 边界契约**
   - 选项 A：Manifest 存储 `HashMap<u16, u64>`（`volume_sequence -> committed_end`）
   - 选项 B：从已验证 Catalog 的 `block_locations` 计算每卷最大 offset，与 Manifest commitment 绑定

2. **明确 Index 加载路径**
   - 调研 `era-index` 的 rkyv MetaIndex 格式和 `IDX\x01` nonce context
   - 设计"读取 IndexManifest 明文 bytes -> 承诺验证 -> 构建 IndexReader"的完整流程

3. **重写 Catalog 重组逻辑**
   - 承诺验证前不得 protobuf 反序列化
   - 限制 `total_len`、`chunk_count`、每块大小
   - 流式计算 BLAKE3 commitment

4. **统一 open API**
   - `open_with_providers_and_options()` 作为唯一核心入口
   - `OpenOptions` 传播到所有认证模式和 repair preflight

5. **重写可编译的 Catalog-mode iterator**
   - 覆盖 Single 和 Erasure `BlockLocation`
   - 复用现有 `SessionErasureBlockUnpacker`，不引入虚构组件
   - 输入：已验证 Catalog + per-volume horizon map

6. **修正威胁模型表述**
   - 将"防止重放攻击"改为"partial stale-copy replay 防护"
   - 明确说明全卷回滚不在防护范围内（除非有外部锚点）

7. **补充 P0 对抗测试**
   - 多卷 horizon 边界
   - Index `IDX\x01` nonce 注入
   - 全卷回滚检测
   - same-seq 不同 Manifest 内容
   - 1GB+ Catalog OOM 防护
   - non-erasure 越界读取

---

## 工作量估算

| 活动 | 预估工作量 | 风险 |
|------|-----------|------|
| 修订 PLAN.md（上述 7 项前置条件） | ~2 天 | 中 |
| 对齐现有代码 API（调研 + 文档） | ~1 天 | 低 |
| 实现（按修订后 PLAN） | ~8-10 天 | 高 |
| 单元/集成/对抗测试 | ~5-7 天 | 中 |
| **二次 Oracle 审计** | ~0.5 天 | 低 |
| **总计** | **~16-20 天** | |

> 注：此估算基于单开发者全职投入；若并行开发（3 人），可压缩至 ~2-3 周。

---

*审计完成时间: 2026-04-29*  
*审计代理: Oracle (OhMyOpenCode)*  
*下次行动: 按前置条件修订 PLAN.md，完成后进行二次审计*
