# ERA-CORE 全仓复审与两轮修订报告（2026-11-22）

- **仓库**: `/home/ricardom/code/github.com/zapsaang/era-core`，分支 `feat_fly`
- **初始复核对象**: `b22a07e` → `c4d6e02` → `c7d2666`（工程师自称“已修复全部问题、零技术债、无遗留”）
- **最终冻结代码提交**: `c12c976`（两轮 5 个原子代码提交 `4549d85` → `ebb915d` → `933807c` → `83a0e55` → `c12c976` 之终点；本报告及文档更新随第 6 个原子提交入库）
- **工具链**: Nix store `cargo 1.99.1` / `rustc 1.99.1` / `clippy` / `rustfmt`（本地 `~/.nix-profile/bin/cargo` shim 损坏，验证显式使用 nix store PATH；CI 使用 `stable` + `--locked`）
- **证据附件**: `docs/audit/round0-baseline.md`、`docs/audit/round1-*.md`（5 份）、`docs/audit/round2-*.md`（3 份）、`docs/audit/round1-consolidated.md`、`docs/issue-list-2026-11-22.md`

---

## 一、最终结论

1. **工程师“已修复仓库全部问题、零技术债、无遗留”的声明经实证核查不成立。**
   - 在 `c7d2666` 上复核可见，`c4d6e02` 虽收敛了前序部分问题，但仍遗留 `RF-01`（append finalize 非原子崩溃窗口）、`RF-03`（staged append 全量堆内存 `Vec<u8>`）、`RF-06`（可增长卷缺 `fdatasync` 屏障）、`EW-05`（轮转未提交卷无回收清理）、`EW-07`（staged append 期间允许 `set_max_size`）、`RF-15/16/18`（解包目录未 fsync、元数据重开 TOCTOU、verify/extract 100 GiB 上限不一致）、`RF-23`（protobuf `TryFrom` 缺跨字段校验）、`LL-11`（`check_mlock_available` 探测未 `munlock`）、`EW-08`（`read_checkpoint(..., None)` 恒失败）、`EW-10`（`apply_repairs` 在 async 上下文同步阻塞文件 I/O）、`R2-07`（footer 修复重复读盘）、`RF-09/R2-06`（生产 `src/` 存在 43 处 `allow(dead_code|unused_mut|unused_imports)`）、`RF-10`（6 份历史 `docs/*.md` 被 `.gitignore` 屏蔽）及 `R2-CI-01`（`README.md`/`AGENTS.md` 命令漏掉 `ulimit -n 1024` 与行数漂移）。
2. **两轮 TDD 审计与原子化修订已全部闭环前述代码与工程缺陷。**
   - 每项修复均遵循“先写失败回归测试验证 RED → 实现修复 → 验证 GREEN → 原子提交”。
   - 冻结代码树 `c12c976` 上 `cargo fmt --all -- --check` 0 问题，`cargo clippy --locked --all-targets --all-features -- -D warnings` 0 警告，`ulimit -n 1024` 下 `era-cli` 与 `--workspace` 全量测试 **3,507 passed / 0 failed / 20 ignored（190 suites/doc-tests）**。
   - 生产 `crates/*/src` 与 `bins/*/src` 中 `allow(dead_code)`、`allow(unused_mut)`、`allow(unused_imports)` 已清零（0 处），并由 `hygiene_guards_test::meta_gates::production_sources_have_zero_dead_code_or_unused_allows` 永久门禁守护。
3. **剩余已知边界与低风险工程限制（必须如实记录，不称“零遗留”）：**
   - 架构/规格边界与结构性工程债务：`RF-11`（读路径不支持 Directory/Symlink 条目提取）、`RF-17`（verify 逐卷读 Catalog / 非 EC repair 重复 verify，benchmark-needed）、`RF-19/25/26/28`（既有源码字符串断言、`#[path]` 集成测试复用、墙钟并发测试、内联 `#[cfg(test)]` 模块）以及 `fuzz/` 未入库、`flake.nix/flake.lock` 缺失（`RF-24` 残留）。这些均为明确界定的独立规格项或长期工程债务，不再构成正确性、崩溃安全性或技术债隐藏漏洞。

---

## 二、基线与最终门禁实测

### 2.1 初始基线 `b22a07e` 复跑记录

在 `b22a07e` 上复跑 CLI 500 passed / 0 failed / 3 ignored（16 suites）、workspace 2916 passed / 0 failed / 17 ignored（164 suites），合计 **3,416 passed / 0 failed / 20 ignored**。基线门禁呈绿，说明上述缺陷属于此前门禁未覆盖的崩溃安全性、TOCTOU 竞态、格式校验与卫生抑制漏洞。

### 2.2 最终冻结代码树（`feat_fly @ c12c976`）全量门禁实测

```bash
cargo fmt --all -- --check && \
cargo clippy --locked --all-targets --all-features -- -D warnings && \
bash -c 'ulimit -n 1024 && cargo test --release --locked -p era-cli -- --test-threads=2 && cargo test --release --locked --workspace -- --test-threads=2'
```

| 阶段 | suites / doc-tests | passed | failed | ignored |
|---|---:|---:|---:|---:|
| `cargo fmt --all -- --check` | — | — | 0 | — |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | — | — | 0 | — |
| `era-cli`（`ulimit -n 1024`） | 18 | 518 | 0 | 3 |
| `--workspace`（`ulimit -n 1024`） | 172 | 2989 | 0 | 17 |
| **合计** | **190** | **3507** | **0** | **20** |

注：17 个 `--workspace` 忽略项包含 3 个超大数据体积手跑测试（4GB 边界与 5GB 往返）及 14 个仅作示例/编译文档的 `ignore` doctest；`era-cli` 中 3 个忽略项与前者中的 4GB/5GB 边界重用对应。文档刷新提交后再跑 `cargo fmt --all -- --check` 与 `hygiene_guards_test`（7/7 通过），确保单源统计与零抑制门禁均绿。

代码规模实测（`c12c976`）：`find crates bins -name '*.rs' | wc -l` = **273** 个 `.rs` 文件，总计 **147,587 LOC**（`src` 55,425 + `tests` 89,289 + benches/examples 2,873）。

---

## 三、两轮审计与原子化修订明细（在 `c7d2666` 之上）

### 3.1 提交链总览

| 顺序 | 提交哈希 | 主题 | 涵盖问题 ID | 关键验证结果 |
|---|---|---|---|---|
| Commit 1 | `4549d85` | `fix(volume,engine): make append finalize crash-safe with disk spooling and sync barriers` | `RF-01`, `RF-03`, `RF-06`, `EW-05`, `EW-07` | `era-storage` 27 passed；`era-volume` 82 unit + 5 `append_finalize_atomicity_tests` + 全集成通过；`resid_high03_checkpoint_append` 12 passed |
| Commit 2 | `ebb915d` | `fix(engine): unify verify/extract size bounds and harden metadata and directory sync` | `RF-15`, `RF-16`, `RF-18` | `era-engine --lib` 174 passed；`adversarial_audit_v1` 21；`bounded_fd_extraction_tests` 12；`find11` 4；`round1_reader_fixes` 4；`round2_engine_fixes` 8 全部通过 |
| Commit 3 | `933807c` | `fix(common,crypto): validate protobuf cross-field bounds and unlock mlock probe` | `RF-23`, `RF-30` (`LL-11`) | `era-common` 26+5+3；`era-crypto` 104；`era-packing` 64+3+4；`fourth_audit` 46 全部通过 |
| Commit 4 | `83a0e55` | `fix(engine): offload shard repair I/O to spawn_blocking and scan legacy checkpoint block IDs` | `EW-08`, `EW-10`, `R2-07` | `checkpoint::tests` 7；`repair::tests` 7；`adversarial_audit_v1` 21；`adversarial_audit_v2` 53；`round2_engine_fixes` 8 全部通过 |
| Commit 5 | `c12c976` | `refactor(workspace): eliminate all allow(dead_code) suppressions from production sources` | `RF-09` (`H-01`, `R2-06`) | 全工作区 `clippy --all-targets --all-features -- -D warnings` 0 警告；`hygiene_guards_test` 7/7；`adversarial_audit_v5` 26/26；`competitor_public_path_delta` 11/11 |
| Commit 6 | 本次提交 | `docs(audit): finalize two-round audit reports, track historical docs, and refresh verified stats` | `RF-10`, `R2-CI-01`, 文档统计同步 | 6 份历史 `docs/*.md` 纳管；`README`/`AGENTS`/crate `AGENTS` 与冻结树实测完全一致；`hygiene_guards_test` 7/7 通过 |

### 3.2 第一轮：崩溃安全、存储与提取一致性修复（`4549d85`、`ebb915d`）

1. **`RF-01 (LL-01/EW-02)` — Append `finalize()` 崩溃安全与回滚（`4549d85`）**
   - `crates/era-volume/src/writer.rs`：staged append 不再先 truncate 再裸写；改为先保存原文件头/尾回滚镜像，并在 offset `HEADER_SIZE`（4096）持久化过渡备份 footer + `sync_data()` 屏障后再 `truncate(staged.base_offset)`；一旦提交阶段任何写盘/刷新失败，通过 `restore_staged_original` 自动恢复原始头/尾字节，确保原归档可打开。
   - 新增故障注入测试：`crates/era-volume/tests/append_finalize_atomicity_tests.rs::interrupted_finalize_restores_original_archive`。
2. **`RF-03 (LL-02/EW-01)` — Staged append 匿名磁盘临时卷替代堆内存（`4549d85`）**
   - `crates/era-volume/src/writer.rs`：`StagedAppend` 移除 `Vec<u8>` 缓冲，改用 `tempfile::tempfile()` 创建已 unlink 的匿名磁盘 spool（`tokio::fs::File`），以 64 KiB 块流式回放至卷文件；暴露 `staged_in_memory_bytes()`（恒为 `0`）与 `staged_disk_bytes()`。
   - 回归测试：`append_finalize_atomicity_tests::staged_append_spools_to_disk_without_full_memory_buffer`。
3. **`RF-06 (LL-03)` — 可增长卷（Growable）finalize `sync_data` 屏障（`4549d85`）**
   - `crates/era-volume/src/writer.rs`：为固定上限卷与无 `max_size` 可增长卷统一在写入 backup/primary headers/footers 前补齐 `sync_data()` 持久化屏障。
   - 回归测试：`append_finalize_atomicity_tests::growable_volume_finalize_syncs_data_before_footer`。
4. **`EW-05` & `EW-07` — 卷池轮转未提交清理与阶段性 `set_max_size` 禁止（`4549d85`）**
   - `crates/era-storage/src/{traits.rs,local.rs,memory.rs}` 新增 `remove_sync_on_drop`；`crates/era-volume/src/volume_pool.rs` 在 append 模式记录 `uncommitted_rotated_files`，严格先完成新卷再提交退出的原卷，若未正常完成则在 `Drop` 时清理孤立 `.era.NNN` 文件；`VolumeWriter::set_max_size` 对活跃 staged append 返回 `EraError::InvalidConfig`。
   - 回归测试：`append_finalize_atomicity_tests::{uncommitted_rotated_volume_cleaned_up_on_drop, set_max_size_rejected_while_staged_append_is_active}` 及更新后的 `resid_high03_checkpoint_append::interrupted_append_after_volume_rotation_preserves_original_archive`。
5. **`RF-18 (ENG-RC-11)` / `RF-16 (ENG-RC-09)` / `RF-15 (ENG-RC-08)` — Read 路径对称上限、fd 级元数据与目录 fsync（`ebb915d`）**
   - `crates/era-engine/src/reader.rs`：将 `entry.size > MAX_DECLARED_FILE_SIZE`（100 GiB）检查下沉至共享的 `validate_regular_file_chunks`，令 `verify` 与 `extract` 判定一致；`apply_extracted_metadata` 改为单次 `O_NOFOLLOW` 打开目标文件并校验非常规文件后直接经 fd 设置时间、`xattr::FileExt` 扩展属性与权限，防止符号链接替换攻击；`extract_with_iterator` 完成时执行 `sync_extracted_directories` 持久化已提取目录项。
   - 新增 3 项单元回归测试：`verify_and_extract_symmetrically_reject_file_exceeding_max_declared_size`、`apply_extracted_metadata_refuses_symlink_swap_and_protects_victim_permissions`、`extract_all_syncs_output_directories_on_completion`。

### 3.3 第二轮：低层边界、Engine 遗留路径、技术债清零与文档对齐（`933807c`、`83a0e55`、`c12c976`）

1. **`RF-23 (LL-08)` & `RF-30 / LL-11` — Protobuf 跨字段校验与 `mlock` 探测释放（`933807c`）**
   - `crates/era-common/src/conversion.rs`：`TryFrom<proto::ErasureBlockInfo>` 校验 `data_shards >= 1`、`parity_shards >= 1`、`data_shards + parity_shards <= 255`、`0 < shard_size <= 16 MiB` 及 `original_len <= shard_size * data_shards`；`TryFrom<proto::BlockChunkIndex>` 校验 `usize::from(count) == entries.len()`。
   - `crates/era-crypto/src/secure_memory.rs`：`check_mlock_available()` 在探针 `mlock` 成功后调用 `munlock(test_buf.as_ptr(), 16)` 归还锁定配额。
   - 新增 TDD 测试：`block_chunk_index_rejects_count_entry_length_mismatch`、`erasure_block_info_rejects_zero_shards_excess_total_or_invalid_lengths`、`check_mlock_available_unlocks_probe_buffer_when_supported`。
2. **`EW-08`、`EW-10`、`R2-07` — Checkpoint 历史卷扫描、`apply_repairs` 异步阻塞卸载与 footer 读去重（`83a0e55`）**
   - `crates/era-engine/src/checkpoint.rs`：当 `read_checkpoint(..., None)` 处理 `last_checkpoint_block_id == 0` 的历史卷时，保留 `if let Some(id)` 直查主路径（满足 `adversarial_audit_v1`），在 `None` 分支从 `data_region_start` 顺序扫描规范 `BlockHeader` 至 `checkpoint_offset` 计算前置块序号，并辅以受物理空间上限约束的 `0..=block_count()` 候选校验；保留 `block_iter`/A1 全部契约。
   - `crates/era-engine/src/repair.rs`：移除重复读盘的 `volume_needs_footer_repair`，在单卷与矩阵修复路径统一先调用一次 `plan_volume_footer_repairs`；将 `apply_repairs` 改造为 `async fn apply_repairs(path: &Path, repairs: Vec<ShardRepair>) -> Result<()>` 并在 `tokio::task::spawn_blocking` 中执行同步文件写入、`sync_all` 与写后 CRC 回读（完整保留 `// V2-ROB-10` 校验逻辑与注释）。
   - 新增 TDD 测试：`read_checkpoint_and_recover_all_checkpoints_succeed_when_block_id_is_none`、`test_apply_repairs_writes_verifies_on_blocking_pool`。
3. **`RF-09 (H-01 / R2-06)` — 彻底消除生产 `src/` 全部 43 处警告抑制与死代码（`c12c976`）**
   - 清零 13 个源文件中所有 `#[allow(dead_code)]`（41 处）、`#[allow(unused_mut)]`（`era-storage/src/local.rs:42`，1 处）、`#[allow(unused_imports)]`（`era-index/src/reader.rs:11`，1 处）：
     - 将真实公用 API 正确导出（`era_crypto::SecureBytes`、`era_engine::{read_checkpoint, recover_all_checkpoints}`、`CheckpointManager::archive_path()`），为集成测试夹具使用内部类型提供 `#[doc(hidden)] pub use`（`ChunkIndex`、`MemoryChunkIndex`、`VolumeStage`）并补全 `ChunkIndex::is_empty()` / `impl Default for MemoryChunkIndex`。
     - 将仅单测使用的 helper 规范标注 `#[cfg(test)]`（含 `read_and_verify_shard` 并补 `test_read_and_verify_shard_checks_crc`），移除 9 个既无生产调用亦无测试调用的真实死方法（含依赖废弃 `CheckpointManager::sync()` 的 `sync_checkpoint` 封装，顺带消除了 `index_stage.rs` 的 `#[allow(deprecated)]`）。
   - 在 `crates/era-engine/tests/hygiene_guards_test.rs` 新增永久门禁 `production_sources_have_zero_dead_code_or_unused_allows`（RED 43 处 → GREEN 0 处）。
4. **`RF-10` & `R2-CI-01` — 仓库忽略规则与文档一致性收敛（Commit 6）**
   - `.gitignore` 将 `!docs/*-2026-11-*.md` 放宽为 `!docs/*.md` 与 `!docs/**/*.md`，使 6 份历史设计与审计文档正式纳管入库；`README.md` 与 `AGENTS.md` CI 命令补齐 `ulimit -n 1024`，统计数字与引用计数按 `c12c976` 实测刷新，`crates/era-engine/src/AGENTS.md` 与 `crates/era-volume/src/AGENTS.md` 行数同步更新。

---

## 四、仍在观察的独立规格/结构限制（非本轮阻断项）

| 编号 | 类别 | 说明 | 后续建议 |
|---|---|---|---|
| `RF-11` (`ENG-RC-04`) | 独立功能边界 | 读路径不提取 Directory/Symlink 条目（当前 writer 不生成目录/软链数据条目，`create` 对软链已显式硬失败或 `--skip-symlinks`） | 若后续支持软链归档单独立项 |
| `RF-17` (`ENG-RC-10`) | 性能待测（benchmark-needed） | `verify` 逐卷全量读 Catalog、非 EC `repair` 在头部修复场景重跑 `verify`；无功能错误 | 引入端到端基准评估后再决定是否优化 |
| `RF-19` / `RF-25` / `RF-26` / `RF-28` | 测试组织债务 | 既有源码字符串断言、`#[path = "../src/..."]` 集成测试重复编译、墙钟并发睡眠断言、`src/` 内联 `#[cfg(test)]` | 随模块演进逐步迁为公共行为测试与 `tests/` |
| `RF-24`（局部） | 工程完善项 | `Cargo.lock`/`ci.yml`/`--locked`/`ulimit -n 1024` 均已落位，但 `fuzz/` 工作区尚未建立、`flake.nix/flake.lock` 未跟踪 | 后续纳入 Nix flake 与 nightly fuzz 工程 |

---

*本报告基于 2026-11-22 分支 `feat_fly` 冻结代码提交 `c12c976` 实测生成；全部数字、提交哈希与测试计数均来自本轮实跑工具输出，未依赖工程师口头陈述。*
