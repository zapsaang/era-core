# PHASE 2: 写入管线实施规划

**对应**: ROADMAP.md 第 3 节 "Phase 2: 写入管线（第 1-2 周）"  
**前置条件**: PHASE 1 基础结构已完成（类型定义、schema、承诺计算、Footer 扩展）  
**目标**: 完成 v8.2 写入管线的全部功能，使 ArchiveWriter 能够创建含 Manifest 的 v8.2 archive  
**预估工时**: ~8-10 天  
**风险等级**: 高（涉及密码学关键路径、volume 布局、多卷一致性）

---

## 目录结构

```
PHASE_2/
├── README.md                 # 本文件：目录导航与快速参考
└── PLAN.md                   # 主规划文档：6 个任务的详细方案与伪代码
```

---

## 任务总览

| 任务 | 内容 | 目标文件 | 预估工时 | 风险 |
|------|------|---------|---------|------|
| 2.1 | Catalog block_locations 填充 | `era-engine/src/write_pipeline.rs`, `era-engine/src/writer.rs` | 2 天 | 中 |
| 2.2 | Typed block 空间预检查与预先 rotation | `era-volume/src/volume_pool.rs` | 1 天 | 中 |
| 2.3 | Manifest 构建 + AEAD 加密 | `era-engine/src/writer.rs` | 2 天 | 高 |
| 2.4 | 全副本冗余写入（Index + Manifest） | `era-engine/src/volume_stage.rs`, `era-engine/src/writer.rs` | 2 天 | 高 |
| 2.5 | Footer v2 写入（manifest 字段） | `era-volume/src/writer.rs` | 1 天 | 中 |
| 2.6 | 构建验证 | workspace | 1 天 | 低 |

---

## 关键设计决策

1. **block_locations 在 finalize 时填充**: 写入阶段通过 ChunkIndex 跟踪 chunk→location 映射，finalize 阶段按 block_index 顺序提取并填充到 Catalog
2. **Typed block 不触发 rotation**: 写入前预检查空间，不足时预先 rotation，不在写入中触发
3. **Manifest 每卷使用不同 nonce**: AAD 绑定 volume_index，各卷密文不同但长度相同，保持完整上下文绑定安全性
4. **Index 全副本冗余**: 与 Catalog/Manifest 一致，写入所有 volume
5. **data_end_offset 保持物理语义不变**: 仍等于 backup_header_offset，包含 typed block 区域；committed_horizon 作为逻辑边界记录在 Manifest 中

---

## 与 DESIGN_SPEC 的对应

| DESIGN_SPEC 章节 | 本阶段实现 | 状态 |
|-----------------|-----------|------|
| 4.1 ArchiveManifest | Task 2.3 | 类型已定义，需实现构建+加密 |
| 4.2 Catalog 扩展 | Task 2.1 | 字段已定义，需实现填充逻辑 |
| 5.1 Manifest 密钥派生 | Task 2.3 | 复用 BLOCK_KEY_DOMAIN |
| 5.2 AEAD 加密参数 | Task 2.3 | 每卷不同 nonce，AAD 绑定 volume_index |
| 5.3 承诺计算 | Task 2.3 | 函数已实现，需集成到 finalize |
| 6.1 finalize 写入顺序 | Task 2.3-2.5 | 完整 finalize 流程 |
| 6.2 typed block 预检查 | Task 2.2 | 新增预检查+预先 rotation |
| 6.3 全副本冗余写入 | Task 2.4 | Index 从单卷改为全副本 |

---

## 执行建议

1. **按依赖顺序执行**: Task 2.1 → 2.2 → 2.3 → 2.4 → 2.5 → 2.6
2. **可并行**: Task 2.1（block_locations 收集）和 Task 2.2（预检查）可部分并行开发
3. **每完成一个任务**: 运行 `cargo test -p <crate>` 确保无 regression
4. **Task 2.6 前**: 运行完整 CI：`cargo fmt --check && cargo clippy -D warnings && cargo test --workspace`

---

## 代码库现状（Phase 2 开始前）

### 已完成的 PHASE 1 工作

| 组件 | 文件 | 状态 |
|------|------|------|
| `ArchiveManifest` 类型 | `era-common/src/types/manifest.rs` | ✅ 已完成 |
| `BlockType::Manifest` | `era-common/src/types/block.rs` | ✅ 已完成 |
| `Catalog.block_locations` | `era-ingest/src/entry.rs` | ✅ 字段已定义 |
| `Footer.manifest_offset/block_id` | `era-volume/src/footer.rs` | ✅ 字段已定义 |
| 承诺计算函数 | `era-crypto/src/commitment.rs` | ✅ 已实现 |
| `finalize_sequence` 机制 | `era-engine/src/sequence.rs` | ✅ 已定义 |
| `TypedBlockKind` | `era-common/src/types/typed_block.rs` | ✅ 已定义 |

### 当前缺失（Phase 2 需实现）

| 缺失项 | 影响 | 解决任务 |
|--------|------|---------|
| `Catalog.block_locations` 未填充 | Catalog 序列化时 block_locations 为空 | Task 2.1 |
| 无 typed block 空间预检查 | 写入中可能触发 rotation | Task 2.2 |
| 无 Manifest 构建/加密/写入 | v8.2 核心功能缺失 | Task 2.3 |
| Index 仅写入 volume 0 | 非全副本冗余 | Task 2.4 |
| Footer 未写入 manifest 字段 | Reader 无法定位 Manifest | Task 2.5 |

---

*文档生成时间: 2026-04-25*  
*基于: DESIGN_SPEC.md v1.0 + ROADMAP.md v1.0 + PHASE_1 接口契约*
