# PHASE 1: 基础结构实施规划

**对应**: ROADMAP.md 第 2 节 "Phase 1: 基础结构（第 1 周）"  
**目标**: 为 v8.2 的全部上层功能建立类型基础与格式契约  
**预估工时**: ~6.5 天  
**风险等级**: 低（纯类型定义，无运行时逻辑）

---

## 目录结构

```
PHASE_1/
├── README.md                 # 本文件：目录导航与快速参考
├── PLAN.md                   # 主规划文档：8 个任务的详细方案与伪代码
├── DATA_TYPE_CHANGES.md      # 数据类型变更对照表：前后对比、大小估算
├── INTERFACE_CONTRACT.md     # 接口契约：Phase 2-4 的开发边界
├── REFLECTION.md             # 自我反思：规划审查与问题发现
└── ADOPTED_CORRECTIONS.md    # 已采纳修正：Oracle 评审后的最终方案
```

---

## 快速导航

| 你想了解 | 去读 |
|---------|------|
| Phase 1 要做什么、怎么做、验收标准 | [PLAN.md](PLAN.md) |
| 具体某个数据结构怎么改、改了什么 | [DATA_TYPE_CHANGES.md](DATA_TYPE_CHANGES.md) |
| Phase 2-4 能用什么接口、不能改什么 | [INTERFACE_CONTRACT.md](INTERFACE_CONTRACT.md) |
| Oracle 评审后改了什么 | [ADOPTED_CORRECTIONS.md](ADOPTED_CORRECTIONS.md) |

---

## 任务总览

| 任务 | 内容 | 文件 | 预估工时 |
|------|------|------|---------|
| 1.1 | BlockType::Manifest 扩展 | `era-common/src/types/block.rs` | 0.5 天 |
| 1.2 | ArchiveManifest 类型定义 | `era-common/src/types/manifest.rs` (新增) | 1 天 |
| 1.3 | Catalog 扩展 block_locations | `era-ingest/src/entry.rs` | 1.5 天 |
| 1.4 | Footer v2 字段扩展 | `era-volume/src/footer.rs` | 1.5 天 |
| 1.5 | 承诺计算函数 | `era-common/src/commitment.rs` (新增) | 0.5 天 |
| 1.6 | finalize_sequence 机制设计 | `era-engine/src/sequence.rs` (新增) | 0.5 天 |
| 1.7 | EraError 扩展 | `era-common/src/error.rs` | 0.5 天 |
| 1.8 | 构建验证 | workspace | 0.5 天 |

---

## 关键设计决策

1. **Footer 版本保持为 1**: 新字段复用 reserved 空间（12 字节），不破坏 128 字节原子写入
2. **Manifest 作为 typed block**: 不预留固定 slot，复用现有 `write_canonical_block` 机制
3. **承诺使用 Blake3 keyed_hash**: 不复用专用 HKDF 域，减少密码学复杂度
4. **protobuf 字段重新编号**: 代码未上线，无需向后兼容
5. **finalize_sequence 存储在 Manifest 中**: 与 Manifest 一起认证，防止单独篡改

---

## 与 DESIGN_SPEC 的对应

| DESIGN_SPEC 章节 | 本阶段实现 | 状态 |
|-----------------|-----------|------|
| 4.1 ArchiveManifest | Task 1.2 | ✅ 已规划 |
| 4.2 Catalog 扩展 | Task 1.3 | ✅ 已规划 |
| 5.1 Manifest 密钥派生 | —（Phase 2）| ⏳ 延后 |
| 5.3 承诺计算 | Task 1.5 | ✅ 已规划 |
| 6.2 typed block 预检查 | —（Phase 2）| ⏳ 延后 |
| 7.1 多副本验证 | —（Phase 3）| ⏳ 延后 |
| 9.1 新增错误类型 | Task 1.7 | ✅ 已规划 |
| 10 常量定义 | DATA_TYPE_CHANGES.md 附录 | ✅ 已汇总 |

---

## 执行建议

1. **按依赖顺序执行**: Task 1.1 → 1.2 → 1.3 → 1.4 → 1.5 → 1.6 → 1.7 → 1.8
2. **可并行**: Task 1.5（承诺计算）可与 Task 1.3 并行；Task 1.6 和 1.7 可并行
3. **每完成一个任务**: 运行 `cargo test -p <crate>` 确保无 regression
4. **Task 1.8 前**: 运行完整 CI：`cargo fmt --check && cargo clippy -D warnings && cargo test --workspace`

---

*文档生成时间: 2026-04-21*
