# ERA-CORE 全仓复审计与遗留问题报告

> **整改闭环记录（2026-11-22，已全部清零并通过验收）**：
> - 基于基线 `ee39fae`，本报告 §4.1–§4.10 与 §5.1–§5.4 所列全部问题已按 TDD（RED → GREEN → Refactor）与原子化提交闭环修复：
>   - `8c42a4c`：§4.1 中断 append 后原归档保持完整可读（`StagedAppend` + legacy checkpoint `StartFresh` 清理）
>   - `31d358f`：§4.2 备份头校验与修复、§4.4 非纠删归档认证头/目录优先写回与 CLI 文案修正、§4.9 `verify` 目录去重校验
>   - `5ff825e`：§4.3 覆盖提取失败原子备份回滚、§4.5 落盘 `sync_all()` 统一、§4.6 `O_NOFOLLOW` + `(dev, ino)` 惰性句柄防掉包、§4.7 死代码与 `#![allow(dead_code)]` 清理、§4.8 解包与校验阶段 `FileEntry` 分片完整性校验、§4.10 解除源码行号强耦合测试
>   - 工程收口提交：§5.1–§5.4 取消 `pwrite_test.rs` 过期 `#[ignore]`、强化 `resilience_tests.rs` 实测恢复、对齐 `rust-toolchain.toml` 为 `stable`、`fuzz.yml` 缺失容错、纳入 `Cargo.lock` 与 4 份 11 月审计报告跟踪、同步 `README.md` / `AGENTS.md` / `docs/` 统计与归因，并通过 `ulimit -n 1024` 下全量门禁与测试。

- **复审计日期**: 2026-11-21（整改验收同步：2026-11-22）
- **原审计基线**: 分支 `feat_fly`，`ee39fae`（父提交 `780a26a`）
- **审计依据**:
  - [`docs/post-fix-audit-and-residual-findings-2026-11-21.md`](./post-fix-audit-and-residual-findings-2026-11-21.md)（已同步过时 `780a26a` 状态与 `RESID-LOW-02` 结论）
  - [`docs/post-fix-audit-and-residual-findings-2026-11-20.md`](./post-fix-audit-and-residual-findings-2026-11-20.md)（`RESID-*` 12 项）
  - [`docs/code-and-practical-test-findings-2026-11-18.md`](./code-and-practical-test-findings-2026-11-18.md)（已同步修正闭环归因 `ee39fae` 与后续提交）
- **审计范围**: 逐项核验工程师“已全部修复”的声明；对 10 个 workspace 成员 + `era-cli` 做全仓复核；复跑格式/Clippy/全量 release 测试（含 CI 默认 `ulimit -n = 1024` 仿真）；对新增路径做定向故障注入与临时探针复现。
- **审计方法**: 4 个独立审计线程（整改核验 / 解包路径 / 核心 crate 与 CLI / 全仓卫生）+ 主审计员独立复核与复现；所有结论区分 **已确认（复现/测试/代码必然性）** 与 **推断（需 benchmark 或需进一步构造）**。
- **证据链说明（已整改）**: 原仓库 `.gitignore` 忽略 `*.md` 与 `Cargo.lock`，且环境全局 gitignore 忽略 `docs/`；本次工程收口已通过 `.gitignore` 放行与强制追踪将 `Cargo.lock` 与 4 份 11 月审计报告全部纳入 `git` 版本管理。

---

## 1. 总体结论

1. **工程师“9 项审计问题已全部修复”成立**：`AUDIT-HIGH-01/02`、`AUDIT-MED-01/02`、`AUDIT-LOW-01` ~ `05` 在 HEAD `ee39fae` 上均可核实为已修复，并有可在 `ulimit -n = 1024` 下稳定通过的新增/更新回归测试。
2. **但“零技术债、无遗留问题”不成立**：本轮重新审计发现 **1 项 High、3 项 Medium、6 项 Low** 的实质问题，以及一组工程/流程债。其中 4 项（§4.1–§4.4）在审计基线 `780a26a` 及更早已存在，属前两轮审计的**漏检**，并非 `ee39fae` 引入；§4.8 亦属既有防御缺口；另有 5 项（§4.5、§4.6、§4.7、§4.9、§4.10）与 `ee39fae` 的新增改动或整改不彻底直接相关。
3. **门禁全绿**（`fmt`、`clippy -D warnings`、CI 等价 `ulimit -n 1024; cargo test --release --workspace` 均 `exit 0`），但门禁绿不能证明无遗留：本轮 High/Medium 问题恰好落在测试未覆盖（append 中断、备份头冗余）或被测试“固化”的失败语义（`--force` 解包失败、非 EC 头修复）上。
4. **放行建议（2026-11-22 更新）**：在完成 `8c42a4c`、`31d358f`、`5ff825e` 与工程收口提交后，§4.1–§4.10 与 §5.1–§5.4 所列 P0/P1/P2 问题**均已闭环清零并通过全量验收**，现已达到结项放行标准。

### 1.1 与前序报告的差异（需更正的结论）

| 前序结论 | 本轮核实 | 依据 |
|---|---|---|
| `RESID-LOW-02` 在 `780a26a` “未修复” | **误判**：读端备份头摘要校验在基线前已由 `7b35b3c`/`257cde5` 落地并存在于 `git show 780a26a:...reader.rs`；真正遗留的是 repair 侧的全局摘要回退，已由 `ee39fae` 修复 | 基线源码含 `from_bytes_with_header_digests` 与 `verify_recovered_backup_headers`；`resid_low02_backup_header_digest` 4/4 通过 |
| `AUDIT-LOW-05` 文档已同步 | **仅工作区同步**：`docs/` 被双重 ignore，更新未进入 `ee39fae`；且 11-18 文档把闭环归因于 `780a26a`，实际闭环提交是 `ee39fae` | `git ls-files docs` 为空；`git check-ignore` 指向 `~/.config/git/ignore:29` |
| 11-21 报告标记“不建议结项” | **已过期**：其 9 项在 `ee39fae` 已闭环，但报告未更新；同时报告未覆盖本文件发现的 §4 问题 | 见 §3 |

### 1.2 遗留问题汇总（本文件 §4/§5）

| 编号 | 严重度 | 问题 | 与 `ee39fae` 的关系 | 整改优先级 |
|---|---|---|---|---|
| §4.1 | **High** | 中断 append 后归档不可再打开（含 StartFresh/Resume/普通归档） | 基线 `780a26a` 已存在，前序审计漏检 | **P0** |
| §4.2 | Medium | `verify` 不校验仍可解析的备份头，冗余静默丢失 | 基线已存在，前序审计漏检 | P1 |
| §4.3 | Medium | `extract --force` 失败删除已覆盖的用户原文件 | 基线已存在；`ee39fae` 新测试将其固化 | P1 |
| §4.4 | Medium | 非 EC 归档有数据损坏时连认证主头也不修，文案矛盾 | 基线已存在 | P1 |
| §4.5 | Low | 单块文件解包不再 `fsync`（持久化语义回归） | `ee39fae` 引入 | P2 |
| §4.6 | Low | 懒句柄重开 TOCTOU（新增攻击面，低可达性） | `ee39fae` 引入 | P2 |
| §4.7 | Low | 旧多块路径死代码、`tracked_output_files` 死参数、大面积 `allow` | 整改不彻底 | P2 |
| §4.8 | Low | 多块/packed 尺寸校验不完整；零 chunk 条目静默跳过 | 基线已存在 | P2 |
| §4.9 | Low | `verify` 新增每卷完整 Catalog 读取（likely regression） | `ee39fae` 引入 | P2（benchmark） |
| §4.10 | Low | 审计测试直接断言源码字符串 | `ee39fae` 修改 | P2 |
| §5.1–5.5 | 工程/流程债 | docs 未跟踪、Cargo.lock/工具链漂移、README 统计、测试质量、fuzz workflow | 长期存在 | P2 |

---

## 2. 实测环境与门禁证据

### 2.1 环境

- 工具链：Nix store `rustc 1.99.1` / `cargo 1.99.0` / `clippy 0.1.99` / `rustfmt 1.10.0`（与 11-20/11-21 审计一致）。
- 系统默认 `ulimit -n = 524288`；CI/标准环境为 `1024`，所有关键测试均显式在 `bash -c 'ulimit -n 1024; ...'` 中复跑。
- `protoc 3.21.12`、`nproc = 6`。

### 2.2 门禁与全量测试

| 命令 | 结果 |
|---|---|
| `cargo fmt --all -- --check` | **exit 0**，无输出 |
| `cargo clippy --all-targets --all-features -- -D warnings` | **exit 0**，无告警 |
| `bash -c 'ulimit -n 1024; cargo test --release --workspace'` | **exit 0**，全部 target 与 doc-tests 通过（含最终 `era_volume` 集成套件与 doc-tests） |
| `cargo test --release --workspace`（默认 ulimit） | **exit 0** |

### 2.3 9 项整改的定向回归（关键项均在 `ulimit 1024` 下）

| 套件 | 结果 |
|---|---|
| `resid_high03_checkpoint_append` | 9 passed / 0 failed（含原 1100 文件场景） |
| `bounded_fd_extraction_tests` | 3 passed / 0 failed（1150 单块 + 1150 多块） |
| `resid_high01_catalog_repair`（engine） | 5 passed / 0 failed |
| `resid_high02_header_repair`（engine） | 4 passed / 0 failed |
| `resid_low04_packing_and_generic_writer` | 6 passed / 0 failed |
| `resid_high01_cli_catalog_repair` / `resid_high02_cli_repair` / `resid_low04_cli_packing_validation` | 1 + 2 + 1 passed / 0 failed |
| `resid_low02_backup_header_digest` | 4 passed / 0 failed |
| `adversarial_audit_v3`（LOW-01 源码不变量） | 22 passed / 0 failed |
| `cli_boundary_tests::extract_command_tests` | 2 passed / 0 failed |

---

## 3. 前序 9 项 `AUDIT-*` 逐项核验

结论：**9/9 已修复**（其中 `LOW-02` 为原报告误判，见 §1.1）。

| 编号 | 结论 | 代码锚点 | 测试/证据 |
|---|---|---|---|
| **AUDIT-HIGH-01**<br>新增 FD 测试在 `ulimit 1024` 必崩 | **已修复** | [`chunk_processor.rs:21`](../crates/era-engine/src/chunk_processor.rs#L21) `MAX_OPEN_EXTRACTION_FILES = 64`；[`:166-231`](../crates/era-engine/src/chunk_processor.rs#L166-L231) 懒打开 + LRU；[`:241-246`](../crates/era-engine/src/chunk_processor.rs#L241-L246) 纳入 `has_pending`；[`reader.rs:2222-2249`](../crates/era-engine/src/reader.rs#L2222-L2249) 不再在规划期预开全部文件 | 原 1100 文件场景 9/9 通过；1150 文件双用例通过；在 `ulimit -n 48/64/128` 下同样通过（实测 FD 峰值 13–15）。**不是靠缩小测试规模规避** |
| **AUDIT-HIGH-02**<br>多卷卷 0 主 Catalog 损坏时 verify 误报 Healthy、repair 拒修 | **已修复** | [`reader.rs:2793-2827`](../crates/era-engine/src/reader.rs#L2793-L2827) 逐卷读主 Catalog，任一失败即 `Degraded` 并给出卷号警告；[`reader/catalog_repair.rs`](../crates/era-engine/src/reader/catalog_repair.rs) + [`repair.rs:533-550`](../crates/era-engine/src/repair.rs#L533-L550)、[`:1216-1218`](../crates/era-engine/src/repair.rs#L1216-L1218) 计划并原位写回 | `resid_high01_catalog_repair` 覆盖卷 0/卷 1 独立损坏（含 split catalog 字节级还原）；CLI 端到端测试断言 `repair --force` 后卷 0 与原文件**逐字节相同**，re-verify 通过 |
| **AUDIT-MED-01**<br>GenericArchiveWriter 多 chunk 合箱超 16 MiB | **已修复** | [`volume_capacity.rs:111-167`](../crates/era-engine/src/volume_capacity.rs#L111-L167) `canonical_unbounded` + `chunk_groups`；[`writer.rs:4341`](../crates/era-engine/src/writer.rs#L4341) 打包前按容量拆组；catalog 块预算同步收敛 | `resid_low04_packing_and_generic_writer`：4×4 MiB（无压缩）与 500×~33 KiB（Zstd，索引+AEAD 超限）两用例均 verify + extract 哈希一致 |
| **AUDIT-MED-02**<br>Checkpoint 写入早于容量判定 / StartFresh 截断前删检查点 | **已修复** | [`writer.rs:2152-2161`](../crates/era-engine/src/writer.rs#L2152-L2161) 先 `precheck_durable_checkpoint_space()` 再取 committed ends、再提交 checkpoint；[`checkpoint.rs:402-483`](../crates/era-engine/src/checkpoint.rs#L402-L483) 精确尺寸估算 + 删除时保留 manifest 指针 + 兼容截断主 footer；[`writer.rs:1111`](../crates/era-engine/src/writer.rs#L1111)、[`:1178`](../crates/era-engine/src/writer.rs#L1178) StartFresh 延迟到截断后清理 | `resid_high03_checkpoint_append` 9/9：近满 1 MiB 卷先轮转再写 checkpoint、两卷均不超限、verify Healthy；delete 保留 manifest 指针；StartFresh 失败在截断前不破坏原归档与 checkpoint |
| **AUDIT-LOW-01**<br>相邻两行重复 `try_exists` | **已修复** | [`writer.rs:466-467`](../crates/era-engine/src/writer.rs#L466-L467) 单次异步探测后派生 `append_to_existing` | `adversarial_audit_v3` 更新为断言单次调用形状；22/22 通过 |
| **AUDIT-LOW-02**<br>主头回退未校验 `volume_header_digest` | **已修复（原报告误判读端未修）** | [`reader.rs:1521-1580`](../crates/era-engine/src/reader.rs#L1521-L1580) `verify_recovered_backup_headers`；[`repair.rs:360-374`](../crates/era-engine/src/repair.rs#L360-L374) repair 侧优先全局已认证摘要表 | `resid_high02_active_volume_repairs_primary_header_when_local_manifest_is_also_corrupted` + `resid_low02_backup_header_digest`（4/4）通过 |
| **AUDIT-LOW-03**<br>无用 `finalized_header_digests`/`extra_hashes`；GenericWriter 旧单摘要 Manifest | **已修复（有名项）** | `finalized_header_digests`、`extra_hashes` 全仓 0 引用；[volume_pool.rs:1060-1083](../crates/era-volume/src/volume_pool.rs#L1060-L1083) `finalized_volume_header_digests` 被 [writer.rs:2459-2463](../crates/era-engine/src/writer.rs#L2459-L2463) 使用；[writer.rs:4430](../crates/era-engine/src/writer.rs#L4430) GenericWriter 写全量摘要表 | `generic_writer_finalize_encodes_full_volume_header_digests_table` 通过；但旧多块解包路径成为新死代码（见 §4.7） |
| **AUDIT-LOW-04**<br>未在帮助中体现的 `archive` 位置参数 | **已修复** | [`main.rs:169-190`](../bins/era-cli/src/main.rs#L169-L190) 帮助文案 + 示例 + 参数说明 | 实测 `era extract --help` 输出 `[ARCHIVE]` / “positional alternative to --input” / 示例；`cli_boundary_tests.rs:912-983` 2/2 通过 |
| **AUDIT-LOW-05**<br>前置文档状态标记/ulimit 假设 | **仅工作区修复** | [`docs/code-and-practical-test-findings-2026-11-18.md:520-528`](./code-and-practical-test-findings-2026-11-18.md) 已改为 `ulimit -n = 1024` 且数字可复现（CLI 499 passed/16 suites） | 但该文件被 ignore，未进入 `ee39fae`；且把闭环归因于 `780a26a`（实际为 `ee39fae`）；11-21 报告本身未更新 |

---

## 4. 本轮新发现/遗留缺陷

> 等级说明：critical > high > medium > low > informational。每条均标注 **与 `ee39fae` 的关系** 及 **确认程度**。

### 4.1 【HIGH】中断 append 后归档不可再打开（数据可用性；已复现）

- **类别**: 并发与一致性 / 崩溃安全 / 数据可用性
- **代码锚点**:
  - [`writer/checkpoint_append.rs:34-118`](../crates/era-engine/src/writer/checkpoint_append.rs#L34-L118)：append 的保留边界取 `manifest.volume_committed_ends`（**仅数据区**，早于 catalog/index/manifest/footer）；
  - [`writer.rs:646-653`](../crates/era-engine/src/writer.rs#L646-L653)：以此作为 `append_retained_end`；
  - [`volume/writer.rs:183`](../crates/era-volume/src/writer.rs#L183)：`open_append_at` 立即 `truncate(append_offset)`，主 footer 与备份 header 被裁掉；
  - [`volume/writer.rs:288-295`](../crates/era-volume/src/writer.rs#L288-L295) + [`writer.rs:1111,1178`](../crates/era-engine/src/writer.rs#L1111)：仅“存在 checkpoint 且 StartFresh”时把备份 footer 清零；
  - [`volume/writer.rs:699-792`](../crates/era-volume/src/writer.rs#L699-L792)：footer 的 `data_end_offset` 是“全部元数据之后”的位置（含 catalog/index/manifest），**大于**数据-only committed end；
  - [`volume/reader.rs:119-127`](../crates/era-volume/src/reader.rs#L119-L127)：footer 的 `data_end_offset > file_size` 直接拒绝打开。
- **机理**: append 一旦进入（truncate 已完成）而尚未 `finalize()`（footer 由 `finalize_with_catalog` 最后写入），磁盘上不存在与截断后文件尺寸一致的 footer：
  - StartFresh 分支：备份 footer 被清零 → 完全无 footer；
  - Resume/默认/无 checkpoint 分支：备份 footer 仍声明截断前的更大 `data_end_offset` → 被 `ArchiveAreTruncated` 校验拒绝。
  两条路径都无法通过 `VolumeReader::open`，因此 `verify`/`repair`/再次 `build(append)` 全部失败。
- **复现证据（主审计员临时探针，已删除）**:
  ```text
  PROBE_PLAIN   file_len=8397  open=err Corrupted footer: footer claims data_end_offset=10403 but file size is 8397
  PROBE_RESUME  file_len=8397  open=err Corrupted footer: footer claims data_end_offset=10859 but file size is 8397
  PROBE_START_FRESH file_len=8397 open_err=Some("Corrupted header: Volume too small for footer and no backup/floating footer found")
  ```
  探针流程：创建完整归档（分别 enable_checkpoint=false/true）→ `append_existing(true)` 成功打开（已完成 truncate）→ 写入一个新块 → **不调用 finalize 直接 drop**（等价于进程被 kill）→ 重新 `ArchiveReader::open` 均失败。Resume 与 StartFresh 两种策略、以及无 checkpoint 的普通归档都复现。
- **影响**: append 会话在任意时刻失败/崩溃（OOM、断电、错误返回提前结束、用户 Ctrl-C）都会让**原有已提交数据不可访问**，与 [`writer.rs:353-357`](../crates/era-engine/src/writer.rs#L353-L357) “crash 后下一次 build() 自动从 checkpoint 恢复”的文档承诺矛盾。CLI 未暴露 append，故 CLI 用户不受直接影响；影响的是公开的引擎 API（`ArchiveWriterBuilder::append_existing`）。
- **与基线关系**: **`780a26a` 已存在**（`scan_retained_data_region`、`writer.truncate(append_offset)` 均在基线源码中），由 11-20 整改系列 `7bfcfdc`/`28bd374` 引入“截断到数据-only committed end”语义；前两轮审计（11-20/11-21）均未覆盖。**不是 `ee39fae` 引入**，但属于“全部修复”声明下的遗留。
- **建议修复（P0）**: truncate 后立即写回一份合法备份 footer（`data_end=append_retained_end`、checkpoint=0、保留/重写 manifest 指针），或在 append 全过程中保留可恢复的旧 footer；并新增“truncate 后 finalize 前中断仍可 open”的负例测试。
- **确认程度**: **已确认**（可复现；代码路径必然）。

### 4.2 【MEDIUM】`verify` 不校验仍可解析的备份头：冗余静默丢失仍报“verified”（已复现）

- **类别**: 规格符合性 / 安全性（完整性验证覆盖不足）
- **代码锚点**:
  - [`reader.rs:1521-1529`](../crates/era-engine/src/reader.rs#L1521-L1529)：`verify_recovered_backup_headers` 对“主头可解析”的卷直接 `continue`；
  - [`reader.rs:2785-2792`](../crates/era-engine/src/reader.rs#L2785-L2792)：`verify()` 只对“已经从备份头恢复”的卷追加警告；
  - 已有能力：v8.2 `volume_header_digests` 全量表（[`manifest.rs:98-117`](../crates/era-common/src/types/manifest.rs#L98-L117)，由 [`volume_pool.rs:1060-1083`](../crates/era-volume/src/volume_pool.rs#L1060-L1083) 生成、[`writer.rs:2459-2486`](../crates/era-engine/src/writer.rs#L2459-L2486) 写入）本可用于校验未损坏路径的备份头。
- **复现证据（`era` 实测，单卷 `--erasure none`）**:
  ```text
  # 将 file_size-4224 处的 4096B 备份头清零后：
  era verify  -> ✅ Archive integrity verified successfully!   (exit 0)
  era repair  -> Archive is intact. No repair needed.          (exit 0)
  # 再清零主头（offset 0, 64B）后：
  era verify  -> Error: Failed to open archive / Invalid magic number (exit 1)
  ```
- **影响**: 备份头遭遇 bitrot/部分覆写无法被 `verify` 发现；当主头随后损坏（备份头存在的唯一目的）时归档不可打开且 `repair` 无法自愈，形成“先静默降级、后彻底失效”的路径。与 v8.2 头冗余契约及“对称校验”原则不符。
- **与基线关系**: **`780a26a` 已存在**（摘要表来自 `257cde5`；`verify` 从未校验完好路径的备份头）。前两轮审计漏检。
- **建议修复（P1）**: 在 `verify()` 中对每个卷读取 `backup_header_offset` 的 4096B，与 manifest 摘要表比对；不一致则标 `Degraded` 并纳入 `repair`（写回认证备份头）。成本为每卷一次 4 KiB 读。
- **确认程度**: **已确认**（CLI 复现）。

### 4.3 【MEDIUM】`extract --force` 失败会删除已覆盖的用户原文件（已复现；既有行为被新测试固化）

- **类别**: 数据安全 / 失败原子性
- **代码锚点**:
  - [`chunk_processor.rs:450-473`](../crates/era-engine/src/chunk_processor.rs#L450-L473)：`overwrite=true` 时先 unlink 既有文件，再 `create_new`；
  - [`chunk_processor.rs:208,267,295`](../crates/era-engine/src/chunk_processor.rs#L208)：新文件路径记入 `created_output_paths`；
  - [`reader.rs:2502-2553`](../crates/era-engine/src/reader.rs#L2502-L2553)：任一后续失败都会删除 `created_output_paths` 中的**全部**路径（包括已完整解出的文件与被覆盖的原文件）；
  - [`bounded_fd_extraction_tests.rs:117-184`](../crates/era-engine/tests/bounded_fd_extraction_tests.rs#L117-L184)：新测试显式断言失败后 `first.bin`/`second.bin` 都不存在（把该行为固化为预期）。
- **复现证据（审计线程探针，已删除）**: 预置 `first.bin`/`second.bin` 用户内容 → `extract_all(overwrite=true)` → 第二个数据块损坏 → 返回 `Err("...extraction incomplete...")` → 两个预置文件均 `NotFound`。
- **影响**: 用户按帮助文案（`--force` 仅表示 overwrite）在已有目录上解包损坏归档时，可能丢失原有数据；已完成文件的回滚也超出“清理 partial 文件”的常规语义。
- **与基线关系**: **`780a26a` 已存在**（基线同样在规划期 unlink/预建并统一清理），非 `ee39fae` 引入；但 `ee39fae` 的“clean up partial files”改动与新增测试使其成为显式语义。
- **建议修复（P1）**: 解包到同目录临时文件，全部成功后再 `rename` 原子替换；失败时仅删除临时文件并保留用户原文件；或至少在 `--force` 覆盖场景保留失败回滚备份并对用户告警。
- **确认程度**: **已确认**（复现）。

### 4.4 【MEDIUM】非 EC 归档只要存在任一数据损坏，连已认证主头也不修复（部分恢复能力被拒绝 + 文案矛盾）

- **类别**: 规格符合性 / 容灾恢复
- **代码锚点**:
  - [`repair.rs:529-544`](../crates/era-engine/src/repair.rs#L529-L544)：先认证备份头，随后因 `erasure_config.is_none() && !archive.verify().is_ok()` 直接返回 `IntegrityError("Non-erasure archive has damage beyond its recoverable primary header")`，**早于** [`:578-586`](../crates/era-engine/src/repair.rs#L578-L586) 的主头写回；
  - 多卷路径同样在 [`repair.rs:1151-1155`](../crates/era-engine/src/repair.rs#L1151-L1155) 提前返回；
  - CLI 文案 [`commands.rs:1327-1355`](../bins/era-cli/src/commands.rs#L1327-L1355)：声称“Only an authenticated primary header can be restored without erasure coding”，与实际行为相反；
  - CLI 测试 [`bins/era-cli/tests/resid_high02_cli_repair.rs`](../bins/era-cli/tests/resid_high02_cli_repair.rs) 把“头+数据双损坏必须失败”固化为预期。
- **影响**: 主头损坏 + 任一数据块损坏的非 EC 归档，即使主头可完整认证回写、且其余完好块本可被解出，也整体拒绝修复，用户失去部分恢复机会；同时输出文案与实际行为不一致，误导排障。
- **与基线关系**: **`780a26a` 已存在**（不在 `ee39fae` 的 repair.rs hunk 内）；`ee39fae` 更新了 CLI 文案但未解开该限制。
- **建议修复（P1）**: 将“主头修复”与“数据块修复”解耦：头可认证即写回，然后单独报告数据不可修；或明确文档化为限制并修正文案。
- **确认程度**: **已确认**（代码路径 + CLI 测试行为）。

### 4.5 【LOW，新回归】单块文件解包不再 `fsync`

- **代码锚点**: [`chunk_processor.rs:277-303`](../crates/era-engine/src/chunk_processor.rs#L277-L303)（single-chunk 直写后立即 drop，无 `sync_all`）；对照多块完成路径 [`:400-403`](../crates/era-engine/src/chunk_processor.rs#L400-L403) 与 packed 路径 [`:261-273`](../crates/era-engine/src/chunk_processor.rs#L261-L273)。
- **与基线关系**: **`ee39fae` 引入**。基线所有非 packed 文件都经 `MultiChunkState` 完成分支并 `sync_all`；新 fast path 改变了持久化语义（进程崩溃安全，掉电不保证），且与多块路径不一致。
- **影响**: `extract` 返回成功后 1-chunk 文件（最常见形态）未落盘；掉电可能留下空/截断输出。当前无测试断言持久化。
- **建议**: 在 single-chunk/packed 完成后（或批量解包收尾）统一 `fsync`，或明确“不保证掉电持久性”的 API 文档。
- **确认程度**: **已确认代码差异**；实际掉电影响为推断。

### 4.6 【LOW，新增攻击面】懒句柄重开存在 TOCTOU（检查→按路径 open）

- **代码锚点**: [`chunk_processor.rs:199-221`](../crates/era-engine/src/chunk_processor.rs#L199-L221)：先 `ensure_contained_output_target`（canonicalize 父目录）→ `symlink_metadata` 判定普通文件 → `OpenOptions::new().write(true).open(&output_path)`（跟随符号链接）。
- **与基线关系**: **`ee39fae` 引入**（基线全程持有打开句柄，不存在重开窗口）。
- **触发条件**: 仅当同时存在的未完成多块文件超过 64、触发 LRU 驱逐并重开；正常 writer 产物实测 FD 峰值 13–15，因此实际可达性低。攻击者需在输出目录内可写并赢得竞态。
- **影响**: 竞态成功时块数据可按 catalog 控制的偏移写入攻击者指向的文件（无 truncate），若解包以特权身份运行可形成任意文件写。
- **建议**: 重开使用 `O_NOFOLLOW`/`openat2(RESOLVE_BENEATH)`，或保留 `dup` 的句柄并校验 `dev/ino`；至少增加 `File::sync_all` 语义一致性测试与 eviction/reopen 单测（当前该分支完全未被测试覆盖）。
- **确认程度**: 代码路径已确认；可利用性为推断（低）。

### 4.7 【LOW】整改遗留死代码 / 死参数 / 大面积 `allow`

- [`chunk_processor.rs:9`](../crates/era-engine/src/chunk_processor.rs#L9) 模块级 `#![allow(dead_code)]`；[`:34-58`](../crates/era-engine/src/chunk_processor.rs#L34-L58) `MultiChunkState`/`multi_chunk_files` 已无生产写入方；[`:306-348`](../crates/era-engine/src/chunk_processor.rs#L306-L348) 分支与 [`:420-431`](../crates/era-engine/src/chunk_processor.rs#L420-L431) 日志不可达（仅测试构造器 `adversarial_audit_v5.rs:469` 使用）。
- [`reader.rs:2076`](../crates/era-engine/src/reader.rs#L2076) `tracked_output_files` 恒为空 `Vec`，仍传入 15 处 failure/cleanup 调用；实际清理只依赖 `context.created_output_paths()`。
- 全仓生产代码 66 个 `allow`（42 个 `dead_code`、13 个 `too_many_arguments` 等）；8 个零引用 `pub fn`（如 `reader.rs:689/731`、`era-volume/header.rs:114/223/229`、`volume_pool.rs:387/465`、`writer.rs:862`）；`era_index::ChunkIndex` 仅测试使用。`clippy -D warnings` 全绿依赖这些抑制。
- **建议**: 删除不可达旧路径与空参数；把模块级 `allow(dead_code)` 收窄到具体项或删除；对保留的 `dead_code` 逐项注明原因。

### 4.8 【LOW】解包尺寸校验不完整 / 零 chunk 条目静默跳过

- 仅 single-chunk fast path 校验 `data.len() == entry.size`（[`chunk_processor.rs:280-290`](../crates/era-engine/src/chunk_processor.rs#L280-L290)）；多块仅校验单块 `offset+len ≤ size`（[`:369-379`](../crates/era-engine/src/chunk_processor.rs#L369-L379)），不校验 `sum(chunk lengths) == size` 或区间无缝覆盖；packed 文件完全不校验 `unpack_file` 结果长度（[`:261-268`](../crates/era-engine/src/chunk_processor.rs#L261-L268)）。
- 零 chunk 的 `FileType::File` 条目被 `entry.is_chunked()` 跳过（[`reader.rs:2194`](../crates/era-engine/src/reader.rs#L2194)），不计入 `skipped`；当归档仅含此类条目时在 [`:2256-2259`](../crates/era-engine/src/reader.rs#L2256-L2259) 返回成功但未创建文件（`verify` 同样存在盲区）。
- 当前 writer 不会产生这两类 catalog（每文件至少一个 chunk；空文件有 0 长度 chunk 走 single-chunk 路径），故属外来/修复 catalog 的防御性缺口；但 `ee39fae` 的“validate extracted chunk sizes”提交信息过度概括。
- **建议**: 统一在 `verify`/`extract` 规划期校验 `sum(lengths)==size` 与 packed 解包长度；零 chunk 的 File 条目在 extract/verify 中显式报错或计入 skipped 并告警。

### 4.9 【LOW，likely regression / benchmark-needed】`verify()` 新增每卷一次完整 Catalog 读取

- 代码锚点: [`reader.rs:2793-2811`](../crates/era-engine/src/reader.rs#L2793-L2811)（AUDIT-HIGH-02 修复引入）。
- 影响: `verify`/`repair` 预检在原有全块扫描之外增加 `O(卷数 × catalog 明文大小)` 的读取、解密与解析；百万文件级目录 + 多卷时可能显著变慢（例如 100 卷 × 100 MiB catalog ≈ 10 GiB 额外 I/O）。正确性无问题，属 **likely regression**，需 benchmark 量化。
- **建议**: 评测后决定是否改为抽样/摘要校验，或在 verify 增加“仅主副本”选项。

### 4.10 【LOW】源码字符串耦合测试

- [`tests/adversarial_audit_v3.rs:276-297`](../crates/era-engine/tests/adversarial_audit_v3.rs#L276-L297) 直接断言 `writer.rs` 中精确源码行（LOW-01 的修复形状）。不变量仍有意义，但任何无害重命名/格式调整都会误报。
- **建议**: 改为行为测试（例如统计 I/O 调用或 memoized probe），或至少使用更宽松的语义断言。

---

## 5. 工程 / 流程 / 文档债

### 5.1 审计证据链未纳入仓库（工程风险：中）

- `git ls-files docs` 为空；`git check-ignore -v docs/...` → `~/.config/git/ignore:29:docs/`；仓库 [`.gitignore:22-25`](../.gitignore#L22-L25) 忽略 `*.md`，仅放行 `README.md`/`AGENTS.md`/`CLAUDE.md`/`doc_gen/**/*.md`。
- 后果：11-18/11-20/11-21 审计报告与本文件均只存在于本机；验收声明无法与提交对应、无法在 CI/新克隆中复核。11-21 报告仍停留在“暂不建议结项放行”的旧结论，且包含一处误判（`RESID-LOW-02`）。
- **建议**: 将“整改状态/验收结论”以可跟踪形式（`doc_gen/` 或跟踪的 `docs/*.md`，必要时改 `.gitignore`）纳入版本库；或在 `README`/release note 记录验收基线。

### 5.2 依赖与工具链可复现性（LOW ~ MEDIUM）

- `Cargo.lock` 存在但未跟踪（`.gitignore` 第 12 行），CLI 二进制工作区依赖解析不可复现；`flake.nix`/`flake.lock` 同样未跟踪。
- 工具链三方漂移：[rust-toolchain.toml:2](../rust-toolchain.toml#L2) 固定 `1.98.1`；CI [`.github/workflows/ci.yml:36,74,107`](../.github/workflows/ci.yml#L36) 使用 `dtolnay/rust-toolchain@stable`；`README` 声称“Rust 1.92+”；本地审计使用 `1.99.1`。
- `fuzz/` 目录不存在（根 `Cargo.toml` `exclude = ["fuzz"]`），但 [`.github/workflows/fuzz.yml`](../.github/workflows/fuzz.yml) 存在且为 `workflow_dispatch`，触发必然失败；`README` 对 fuzz 的描述自相矛盾。

### 5.3 统计与文档漂移（LOW）

- `README`/根 `AGENTS.md` 多处统计过期：文件数（实际 265 个 `.rs`）、LOC（src 52.6k + tests 84.5k）、`writer.rs` 行数（4561）、测试数/忽略数（`#[ignore]` 实际 4 处，而非 18 个套件级忽略）、fuzz 目录等。
- 生产 `src/` 中内联 `#[cfg(test)]` 约 15.1k 行（占 src 约 30%），`AGENTS.md` 仅记录了 3 个独立 test-only 文件；测试代码与源码比约 1.6:1，15 个 CLI 测试二进制约 23k 行高度重叠。

### 5.4 测试质量（LOW）

- [`crates/era-storage/tests/pwrite_test.rs:16`](../crates/era-storage/tests/pwrite_test.rs#L16) 自述“Invalid test: pwrite with O_APPEND is undefined behavior”，却以 `#[ignore]` 保留，宜删除或重写。
- 存在无断言/仅打印的测试（如 [`era-packing/tests/resilience_tests.rs:41-47`](../crates/era-packing/tests/resilience_tests.rs#L41-L47)），以及 5 s 忙等（`concurrency_torture.rs:36`）等墙钟依赖。
- 解包 FD 相关测试现已在 `ulimit 1024`（甚至 48）稳定；但 append 崩溃、备份头损坏、`--force` 失败语义、LRU 驱逐/重开均无负例测试覆盖（本轮 High/Medium 问题正源于此）。

### 5.5 其他 Informational

- `ee39fae` 提交信息正文含字面量 `\n`（“lazy LRU-backed multi-chunk writes\n- Validate ...”），属提交信息格式瑕疵。
- 审计线程曾临时引入 `crates/era-engine/tests/zz_*.rs` 探针文件，均已在结束前删除；最终工作区 `git status` 为空（HEAD `ee39fae`）。
- 未发现循环 crate 依赖；`cargo build` 全仓通过。
- 生产运行时代码清洁度经复核属实：可执行路径 **0 个 `unwrap/expect/panic!/todo!/unimplemented!`、0 `thread_rng`**；`unsafe` 仅存在于 [`era-crypto/src/secure_memory.rs`](../crates/era-crypto/src/secure_memory.rs)（mlock/prctl 等）；Rust 代码无 TODO/FIXME/XXX/HACK。AGENTS.md “src/ 干净”与“仅 crypto 有 unsafe”论断成立（仅 rustdoc 示例含 `unwrap`）。

---

## 6. 维度归集（按仓库 Review Rules）

| 维度 | 本轮发现 |
|---|---|
| 规格符合性 | §4.4 非 EC 头修复被拒/文案矛盾；§4.2 verify 未覆盖备份头冗余；§4.8 尺寸校验不完整；§5.2 工具链/CI 规格漂移 |
| 安全 | §4.6 懒重开 TOCTOU（新增攻击面，低可达性）；备份头冗余失效不可检测（§4.2） |
| 性能 | §4.9 verify 每卷 catalog I/O（likely regression）；非 EC repair 双重全量 verify（§4.4） |
| 并发与一致性 | §4.1 append 中断后不可恢复（崩溃安全，High）；§4.3 --force 失败删除既有文件（失败原子性） |
| 代码质量 | §4.5 fsync 语义回归；§4.7 死代码/死参数/allow 面；§4.10 源码字符串耦合测试；§5.3/5.4 文档与测试债 |

---

## 7. 结项门槛与整改建议

1. **P0（阻塞结项）**
   - 修复 §4.1：append 截断后在 finalize 前必须存在可恢复的合法 footer（推荐 truncate 后立即写回 `data_end=append_retained_end` 的备份 footer），并补充“截断后崩溃可恢复”的负例测试；在此之前修正 [`writer.rs:353-357`](../crates/era-engine/src/writer.rs#L353-L357) 的 resume 承诺文档。
2. **P1（建议结项前完成）**
   - §4.2 `verify` 校验所有卷的备份头（复用 manifest 摘要表，每卷 4 KiB）。
   - §4.3 `--force` 解包改为临时文件 + 原子 rename，失败保留用户原文件；若维持现语义，必须在 CLI 帮助与文档中明确“失败会删除已覆盖文件”。
   - §4.4 解耦非 EC 主头修复与数据修复，按“头可认证即写回”处理，并修正文案；更新对应 CLI 测试预期。
3. **P2（技术债清理）**
   - §4.5 统一 fsync 语义；§4.6 修复 TOCTOU 并补 eviction/reopen 单测；§4.7 清除死路径/死参数并收窄 `allow`；§4.8 统一尺寸/零 chunk 校验；§4.9 benchmark 后决定 verify 策略；§4.10 改行为测试。
   - §5.1 把审计/验收结论纳入跟踪文档；§5.2 跟踪 `Cargo.lock`、统一工具链、更新/移除 fuzz workflow；§5.3/5.4 更新 README/AGENTS 统计、清理无效 `#[ignore]` 测试、补充 §4 各项的负例回归。
4. **后续放行状态**：在完成 `8c42a4c`、`31d358f`、`5ff825e` 及工程收口提交后，§4.1–§4.10 与 §5.1–§5.4 **均已闭环清零**并通过全量门禁，可满足结项放行标准。

---

## 8. 附录：复现与证据摘要

### 8.1 中断 append（§4.1）

临时探针（`crates/era-engine/tests/zz_lead_crash_probe.rs`，运行后已删除）：

```text
running 3 tests
PROBE_PLAIN file_len=8397  open=err Corrupted footer: footer claims data_end_offset=10403 but file size is 8397
PROBE_RESUME file_len=8397 open=err Corrupted footer: footer claims data_end_offset=10859 but file size is 8397
PROBE_START_FRESH file_len=8397 open_err=Some("Corrupted header: Volume too small for footer and no backup/floating footer found")
test result: ok. 3 passed
```

实现要点：`enable_checkpoint(false/true)` 创建归档 → `append_existing(true).build()` 成功后写入新块 → 不 `finalize` 直接 drop → 重新 `ArchiveReader::open`。

### 8.2 备份头 bitrot 未被 verify 发现（§4.2）

```text
# create 200000B 文件，--erasure none --volumes 1
# dd 清零 file_size-4224 处的 4096B 备份头
era verify <archive> --password pwd
  INFO ✅ Archive integrity verified successfully!       (exit 0)
era repair <archive> --password pwd
  INFO ✅ Archive is intact. No repair needed.           (exit 0)
# 再清零主头前 64B
era verify <archive> --password pwd
  Error: Failed to open archive / Invalid magic number   (exit 1)
```

### 8.3 解包 `--force` 失败删除既有文件（§4.3）

审计线程探针（已删除）：预置 `first.bin`/`second.bin` → 损坏第二个数据块 → `extract_all(overwrite=true)` 返回 `Err("...extraction incomplete...")` → 两文件均 `NotFound`。

### 8.4 门禁

```text
cargo fmt --all -- --check                                  -> exit 0
cargo clippy --all-targets --all-features -- -D warnings    -> exit 0
bash -c 'ulimit -n 1024; cargo test --release --workspace'  -> exit 0（全部 target + doc-tests）
```

### 8.5 审计线程分工

| 线程 | 范围 | 结论摘要 |
|---|---|---|
| fix-verifier | 9 项 `AUDIT-*` 逐项核验、1024 FD 复跑 | 9/9 FIXED；发现 `LOW-02` 原报告误判；提出 NEW-01~07 |
| extraction-auditor | `chunk_processor.rs` + 解包规划/执行 | FD 修复属实（峰值 13–15）；确认 TOCTOU、fsync 回归、`--force` 数据丢失、尺寸校验缺口 |
| core-auditor | era-volume/crypto/index/common/ingest/packing + CLI | 确认备份头未校验、append 截断危害、非 EC 头修复被拒；manifest 摘要表实现本身正确 |
| hygiene-auditor | 全仓卫生、门禁、死代码/allow、文档/CI | fmt/clippy/1024 测试全绿；生产代码无 unwrap/panic/thread_rng；发现 docs 未跟踪、Cargo.lock/工具链漂移、测试债 |

---

*本文件由 2026-11-21 全仓复审计生成（原始基线：`feat_fly` @ `ee39fae`），并在 2026-11-22 完成 §4/§5 全部整改后纳入仓库版本跟踪。*
