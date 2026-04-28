# 非纠删码 archive 路径删除调研报告

**调研日期**: 2026-04-26
**调研范围**: era-core 全代码库
**背景**: 评估删除非纠删码 (non-erasure-coded) archive 支持后，可降低的复杂度与维护成本。

---

## 核心结论

如果删除非纠删码 archive 支持，**可删除约 500-700 行运行时条件分支代码 + 数百行测试代码**，并将 `Option<ErasureCodeConfig>` 模式从 6 个核心类型中移除。最显著的收益在 **写入流水线、迭代器体系、修复逻辑** 三个模块。

---

## 一、类型系统可简化（6 处 `Option<T>` → `T`）

| 当前类型 | 文件 | 删除后 |
|---------|------|--------|
| `ArchiveConfig.erasure: Option<ErasureCodeConfig>` | `era-common/src/config.rs:25` | `ErasureCodeConfig` |
| `ErasureStage.config: Option<ErasureCodeConfig>` | `era-engine/src/erasure_stage.rs:33` | `ErasureCodeConfig` |
| `ErasureStage.stripe_buffer: Option<StripeBuffer>` | `era-engine/src/erasure_stage.rs:31` | `StripeBuffer` |
| `WritePipeline.cached_erasure_coder: Option<(usize,usize,ErasureCoder)>` | `era-engine/src/write_pipeline.rs:66` | 直接持有 |
| `erasure_info: Option<ErasureBlockInfo>` (protobuf) | `era-common/src/conversion.rs` | 非 optional |
| CLI `--erasure` 解析支持 `"none"` | `era-cli/src/commands.rs:267` | 仅解析 `data:parity` |

**收益**: 消除 `is_some()` / `is_none()` 检查、`ok_or_else()` 转换、`match` 分支等 boilerplate。

---

## 二、运行时条件分支可删除（按模块）

### era-engine/src — 共 358 处 erasure 引用

| 文件 | 引用数 | 可删除的核心分支 |
|------|--------|----------------|
| `write_pipeline.rs` | 66 | `erasure.is_enabled()` 分支 × 4、`!erasure.is_enabled() && volume_count == 1` 捷径 × 2 |
| `writer.rs` | 63 | `match self.enable_erasure` 决策树、`if enable_erasure` 配置设置 × 6、`backup_blocks` 条件创建 |
| `block_iter.rs` | 62 | **`MultiVolumeSessionBlockIterator` 可完全删除**（仅非纠删码使用）；`SessionErasureBlockIterator` 成为唯一迭代器 |
| `repair.rs` | 62 | 非纠删码错误处理分支可删除（`"Archive does not use erasure coding"` 等） |
| `reader.rs` | 49 | `if let Some(config) = erasure_config` 分支 × 2、迭代器选择逻辑 |
| `erasure_stage.rs` | 37 | `disabled()`、`is_enabled()`、`config()` 方法可删除；`match &mut self.stripe_buffer` 中的 `None` 分支可删除 |
| `volume_stage.rs` | 8 | 少量 footer 缺失时的容错分支 |

### CLI 层 — 共 75 处 erasure 引用

| 文件 | 引用数 | 可删除内容 |
|------|--------|-----------|
| `commands.rs` | 60 | `--erasure none` 解析、`info` 中 `Disabled` 显示分支、`repair` 非纠删码提示、单卷/多卷差异处理 |
| `main.rs` | 15 | `--erasure` flag 的 `none` 文档说明 |

### 其他

| 文件 | 引用数 | 说明 |
|------|--------|------|
| `era-common/src/conversion.rs` | 19 | protobuf 序列化中 `erasure_info` 的 `None` → `Single` 分支可删除 |
| `era-volume/src/reader.rs` | ~5 | footer 缺失时的非纠删码报错分支 |

---

## 三、关键代码路径变化

### 1. 写入流水线（`write_pipeline.rs`）— 最显著简化

当前 `process_chunks()` 方法中，**非纠删码路径与纠删码路径完全平行**：

```rust
// 当前：两个并行路径
if self.erasure.is_enabled() {
    // 路径 A：buffer block → stripe → flush
    let maybe_stripe = self.erasure.buffer_block(encrypted_block, block_meta)?;
    // ...
} else {
    // 路径 B：直接写入
    let (location, _) = self.volume.write_block(&encrypted_block, BlockType::Data).await?;
    // ...
}
```

删除后：只保留路径 A，但 `stripe_buffer` 永远有值，`buffer_block` 永远成功。

同时删除：
- `retry_chunks` 备份逻辑（仅非纠删码单卷需要）
- Volume rebinding 逻辑（`needs_expansion` 检查）
- `active_volume_sequence` 的 `0u32` 回退（永远走 distribution strategy）

### 2. Block 迭代器（`block_iter.rs`）— 可删除一个完整迭代器

当前存在 **4 个迭代器变体**：
- `StandardBlockIterator` / `SessionBlockIterator`（非纠删码）
- `ErasureBlockIterator` / `SessionErasureBlockIterator`（纠删码）

删除后：**2 个变体足够**（纠删码版本可直接用于非分片场景，只是每卷只有 1 个 shard）。

### 3. 修复逻辑（`repair.rs`）— 大量错误处理代码可删除

当前 repair 命令在非纠删码 archive 上有 **专门的用户提示和错误处理**：

```rust
// 当前
let erasure_config = header.config().erasure.ok_or_else(|| {
    EraError::ErasureError("Archive does not use erasure coding - repair not available".into())
})?;
```

删除后：永远有 `erasure_config`，这段变成直接解包。

CLI 层同样：
```rust
// 当前 CLI repair 输出
} else {
    info!("Note: This archive was created without erasure coding.");
    info!("Consider recreating with erasure coding for better protection:");
    info!("  era create --erasure 4:2 <inputs> -o <output>.era");
}
```
→ 整段可删除。

### 4. `ErasureStage` — 从条件状态机变为纯缓冲器

当前 `ErasureStage` 有双重人格：
- **enabled**: 持有 `StripeBuffer`，`buffer_block()` 工作
- **disabled**: `stripe_buffer: None`，`buffer_block()` 返回 `Err`

删除后：`StripeBuffer` 永远存在，`buffer_block()` 永远返回 `Ok(Some/None)`，`is_enabled()` / `disabled()` / `config()` 全部删除。

---

## 四、测试可删除/简化

### 明确可删除的测试（~25 个）

| 测试名 | 文件 | 删除原因 |
|--------|------|---------|
| `test_pipeline_non_erasure` | `write_pipeline.rs` | 非纠删码 pipeline 不再存在 |
| `test_multivolume_non_erasure_roundtrip` | `reader.rs` | 非纠删码多卷路径删除 |
| `test_single_volume_no_erasure` | `multi_volume_tests.rs` | 同上 |
| `test_repair_single_shard_corruption_no_erasure` | `aead_resilience_tests.rs` | 非纠删码 repair 拒绝场景消失 |
| `test_repair_non_erasure_archive` | `integration_tests.rs` | 同上 |
| `test_repair_non_erasure_archive_no_op` | `cli_integration_tests.rs` | 同上 |
| `test_repair_non_erasure_no_op` | `cli_integration_tests_comprehensive.rs` | 同上 |
| `test_repair_no_erasure_after_corruption` | `cli_e2e_tests.rs` | 同上 |
| `test_info_no_erasure_archive` | `cli_integration_tests.rs` | info 不再显示 "Disabled" |
| `test_fail_without_erasure` | `resilient_footer_reconstruction.rs` | footer 缺失时行为统一 |
| `test_v27_15_non_erasure_blocks_distributed` | `adversarial_audit_v27.rs` | 非纠删码分布测试 |
| `test_erasure_none` | `cli_integration_tests_comprehensive.rs` | `--erasure none` 选项删除 |
| `test_disabled_stage` | `erasure_stage.rs` | `disabled()` 删除 |
| `test_buffer_block_disabled` | `erasure_stage.rs` | 禁用状态报错测试删除 |

### 可大幅简化的测试文件（5 个纯非纠删码测试文件）

| 文件 | 行数 | 简化方式 |
|------|------|---------|
| `dedup_pending_tests.rs` | 276 | 全部使用 `config_no_ec()` → 改为默认 `ArchiveConfig` |
| `batch_api_tests.rs` | 255 | 同上 |
| `certificate_auth_tests.rs` | 633 | 同上 |
| `cold_recovery_bulletproof.rs` | 322 | 注释明确说 "disable EC to test single-volume" → 无需禁用 |
| `competitor_public_path_delta.rs` | 403 | 全部 `enable_erasure(false)` → 删除该调用 |

### 辅助函数删除（7 个）

| 函数名 | 出现次数 | 说明 |
|--------|---------|------|
| `config_no_ec()` / `test_config_no_ec()` | 7 处 | 创建 `erasure: None` 的 fixture，全部改为默认配置 |

---

## 五、量化估算

| 维度 | 当前 | 删除后 | 减少 |
|------|------|--------|------|
| **era-engine/src 中 erasure 条件分支** | ~103 处显式条件 | ~15 处（仅保留 stripe 计算、shard 分布等核心逻辑） | **~85%** |
| **Block 迭代器变体** | 4 个 | 2 个 | **50%** |
| **可删除的 CLI 输出分支** | ~20 处 | 0 | **100%** |
| **可删除的测试函数** | ~25 个 | 0 | **100%** |
| **可简化的测试文件** | 5 个 | 0（改为默认配置） | **配置行数减少 ~30 行/文件** |
| **ErasureStage API 方法** | 8 个 | 3 个（`new`, `buffer_block`, `flush`） | **62%** |
| **protobuf 字段 optional** | 2 处 (`erasure_info`) | 0（改为 required） | **序列化分支简化** |

**估算可删除的代码行数**：
- 运行时条件分支：~300-400 行（if/else/match 块体）
- `ErasureStage` / `WritePipeline` 简化：~100 行
- `block_iter.rs` 中 `MultiVolumeSessionBlockIterator`：~80 行
- CLI 错误处理和提示：~80 行
- 测试代码：~200-300 行（含 fixture）
- **总计：约 600-900 行可删除**

---

## 六、架构层面的简化

### 1. Builder 模式简化

当前 `ArchiveWriterBuilder` 有两个独立控制纠删码的旋钮：
```rust
.enable_erasure(bool)      // 显式开关
.erasure_config(ErasureCodeConfig)  // 配置参数
```

删除后：只剩 `.erasure_config(ErasureCodeConfig)`，不再需要 boolean 开关。

### 2. Volume 读取 Footer 容错逻辑

当前 `VolumeReader` 对 footer 缺失的处理有双重标准：
- 纠删码：允许 footer 缺失（可从其他卷恢复）
- 非纠删码：footer 缺失直接报错

删除后：**统一为允许 footer 缺失**（因为总有纠删码冗余可以恢复）。

### 3. ArchiveConfig Default

当前：
```rust
erasure: Some(ErasureCodeConfig { data_shards: 4, parity_shards: 2 })
```

删除后：
```rust
erasure: ErasureCodeConfig { data_shards: 4, parity_shards: 2 }
```

不再需要在 serde 反序列化时处理 `null` 值。

### 4. 读取路径统一

当前读取必须 **先检测是否启用了纠删码**，再选择迭代器类型。删除后：
- 永远使用纠删码迭代器
- 单卷 archive 就是 `data_shards=1, parity_shards=0` 的特例（或保持 `4+2` 但只写 1 个卷）

---

## 七、风险与需要注意的点

### 1. 单卷 archive 的场景

当前大量测试使用非纠删码 + 单卷组合来测试「最小配置」。删除后需要确保：
- 单卷 archive 仍然能正确创建/读取
- 纠删码的 shard 分布逻辑在单卷时退化为「所有 shard 在同一卷」

**风险等级**: 低 — `MatrixDistributionStrategy` 已支持单卷。

### 2. 测试覆盖率

约 **71 处测试代码**使用非纠删码配置，覆盖 dedup、batch API、certificate auth、cold recovery 等场景。删除后这些测试需要改为使用默认（纠删码启用）配置，但测试逻辑本身不变。

**风险等级**: 低 — 只需修改 fixture。

### 3. 向后兼容性

如果已有用户创建了非纠删码 archive，删除支持后这些 archive 将无法读取。需要决定：
- 是否提供 migration 工具（`repack` 已存在，可扩展）
- 是否在文档中明确声明 breaking change

**风险等级**: 中 — 需要沟通策略。

### 4. `Option<ErasureCodeConfig>` 的广泛使用

`erasure: Option<ErasureCodeConfig>` 出现在：
- `ArchiveConfig`
- `ErasureStage`
- `VolumeHeader` / `SuperHeader` 配置
- Protobuf 消息
- CLI 解析结果

改为非 optional 需要 **全栈改动**，但 Rust 的类型系统会让所有遗漏点在编译期暴露。

**风险等级**: 低 — 机械性重构。

---

## 结论

删除非纠删码支持可以带来 **实质性的复杂度降低**：

1. **最划算**: `block_iter.rs`（删除一个完整迭代器）、`write_pipeline.rs`（删除并行路径）、`repair.rs`（删除错误处理）
2. **中等收益**: `ErasureStage` 简化、`ArchiveConfig` 去 Option、CLI 去分支
3. **测试维护**: 5 个纯非纠删码测试文件 + 7 个辅助函数可删除/简化

**建议**: 如果产品定位明确为「always-on erasure coding」，这个重构值得做。它会让核心路径更短、错误状态更少、测试更聚焦。
