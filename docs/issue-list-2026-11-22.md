# ERA-CORE 问题清单（2026-11-22，两轮 TDD 审计与原子化修订全闭环）

- **初始基线**: `b22a07e` → `c4d6e02` → `c7d2666`
- **最终冻结代码提交**: `feat_fly @ c12c976`（两轮 5 个原子代码提交：`4549d85`、`ebb915d`、`933807c`、`83a0e55`、`c12c976`，加文档提交 Commit 6）
- **状态图例**: ✅已修复（含 TDD RED→GREEN 回归验证与原子提交） / 📌已知边界或工程结构债（独立功能/测试组织项，非正确性缺陷） / ℹ️观察项
- **主报告**: `docs/final-audit-and-remediation-2026-11-22.md`；历史证据：`docs/audit/round0-baseline.md`、`round1-*.md`、`round2-*.md`

## 一、High / Medium（全部可修复缺陷已清零）

| 编号 | 严重度 | 维度 | 标题 | 基线状态 (`b22a07e`/`c7d2666`) | 最终状态 | 修复提交与锚点/证据 |
|---|---|---|---|---|---|---|
| `RF-01` (`LL-01`/`EW-02`) | **High** | 崩溃安全与一致性 | append `finalize()` 先 `truncate` 旧元数据后写 footer，窗口内崩溃毁坏原归档 | 存在 | ✅已修复 | `4549d85`：`era-volume/src/writer.rs` 先保存 head+tail 回滚镜像并于 offset 4096 写过渡 footer+`sync_data()`，失败由 `restore_staged_original` 恢复；`interrupted_finalize_restores_original_archive` |
| `RF-02` (`ENG-RC-01`) | **High** | 规格/数据可用性 | 解包全局累计 8 GiB 隐式上限使 >8 GiB 合法归档必败 | `c4d6e02` 后已修 | ✅已修复 | `era-engine/src/reader.rs` `ExtractOptions.max_total_output_bytes: Option<u64>`（opt-in）且按真实 `bytes_written` 计费 |
| `RF-03` (`LL-02`/`EW-01`) | **Medium~High** | 资源/OOM 风险 | staged append 全量驻留堆内存（`StagedAppend.buf` ≈ `max_volume_size`） | 修订引入 | ✅已修复 | `4549d85`：`era-volume/src/writer.rs` 改用 `tempfile::tempfile()` 匿名磁盘 spool 并 64 KiB 流式回放（`staged_in_memory_bytes() == 0`）；`staged_append_spools_to_disk_without_full_memory_buffer` |
| `EW-05` | **High/Medium** | 崩溃安全/资源 | append 期间卷轮转在崩溃/Drop 时遗留孤立 `.era.NNN` 卷并错序提交 | 存在 | ✅已修复 | `4549d85`：`era-volume/src/volume_pool.rs` 追踪 `uncommitted_rotated_files`，先提交新卷后提交原卷并在 `Drop` 通过 `remove_sync_on_drop` 清理；`uncommitted_rotated_volume_cleaned_up_on_drop`、`interrupted_append_after_volume_rotation_preserves_original_archive` |
| `EW-07` | **Medium** | 状态不变量 | 活跃 staged append 会话允许调用 `set_max_size` 破坏阶段不变量 | 存在 | ✅已修复 | `4549d85`：`VolumeWriter::set_max_size` 在存在 `staged_append` 时返回 `EraError::InvalidConfig`；`set_max_size_rejected_while_staged_append_is_active` |
| `RF-04` (`ENG-RC-02`/`EW-03`) | Medium | 规格/完整性 | `verify`/`repair` 不覆盖主备 footer 冗余 | `c4d6e02` 后已修 | ✅已修复 | `era-volume/src/reader.rs`、`era-engine/src/{reader,repair}.rs` 双侧校验与修复 |
| `RF-05` (`ENG-RC-03`) | Medium | 规格/数据可用性 | `era create` 静默丢弃 symlink/空目录/不可读子树 | `c4d6e02` 后已修 | ✅已修复 | `bins/era-cli/src/commands.rs` 硬失败 + `--skip-symlinks` 显式逃生口 |
| `RF-06` (`LL-03`) | Medium | 持久化 | 可增长卷（无 `max_size`）finalize 写备份 footer 前缺 `sync_data` 屏障 | 存在 | ✅已修复 | `4549d85`：`era-volume/src/writer.rs` 固定与可增长两条 finalize 分支均先 `sync_data()`；`growable_volume_finalize_syncs_data_before_footer` |
| `RF-07` (`LL-04`) | Medium | 安全/完整性 | 打开归档未认证活跃 `SuperHeader` 摘要 | `c4d6e02` 后已修 | ✅已修复 | `era-engine/src/reader.rs` 摘要校验 + 备份头采纳 + AAD 重试 |
| `RF-08` (`H-03`) | Medium | 测试质量 | 空体/恒过测试计入验收统计 | `c4d6e02` 后已修 | ✅已修复 | 7 项测试重写 + `hygiene_guards_test` 扫描门禁 |
| `RF-09` (`H-01`/`R2-06`) | Medium | 代码质量 | 生产 `src/` 存在 43 处 `allow(dead_code|unused_mut|unused_imports)` | 存在 | ✅已修复 | `c12c976`：13 个源文件 43 处抑制全部清零（导出公共 API、`#[cfg(test)]` 隔离、删除 9 个真死方法）；新增永久门禁 `production_sources_have_zero_dead_code_or_unused_allows` |
| `RF-10` (`H-02`) | Medium | 工程/证据链 | `.gitignore` 屏蔽历史 6 份 `docs/*.md` 未入库 | 部分存在 | ✅已修复 | Commit 6：`.gitignore` 改 `!docs/*.md` 与 `!docs/**/*.md`，6 份历史 `docs/*.md` 全部入库 |
| `R2-01` | **High（阻塞）** | 回归 | R1 header digest 校验阻塞既有单头损坏 repair | 修订期已修 | ✅已修复 | 备份头摘要认证后降级采纳并可修复，双头损坏 fail-closed |
| `R2-02` | Medium | 修复假成功 | floating footer 恢复卷 repair 零写回永不收敛 | 修订期已修 | ✅已修复 | 重建规范双 footer 并截断垃圾尾部，否则显式 `IntegrityError` |
| `R2-03`/`R2-04` | Medium | 资源/测试 | 输出预算按解码字节计费、矩阵/容错自证式测试 | 修订期已修 | ✅已修复 | 按 `stats.bytes_written` 计费；矩阵测试直调生产分布实现 |
| `R2-STOR-01`/`CLI-02`/`ING-01` | Medium | 持久化/契约 | 相对裸路径 fsync、`--skip-symlinks`、`Chunker::new -> Result` | 修订期已修 | ✅已修复 | 归一化 `.`、CLI help/README 文档化、`Chunker::new` 返回 `Result` |
| `EW-08` | Medium | 可恢复性 | `read_checkpoint(..., None)` 缺失扫描分支，历史 `block_id=0` 卷不可恢复 | 存在 | ✅已修复 | `83a0e55`：`checkpoint.rs` 增加 `data_region_start..checkpoint_offset` `BlockHeader` 扫描与受限候选遍历；`read_checkpoint_and_recover_all_checkpoints_succeed_when_block_id_is_none` |
| `EW-10` | Medium | 异步并发 | `repair.rs::apply_repairs` 在 `async fn` 中执行同步阻塞文件 I/O | 存在 | ✅已修复 | `83a0e55`：改为 `async fn apply_repairs` 并下沉至 `tokio::task::spawn_blocking`，保留 `V2-ROB-10` 校验；`test_apply_repairs_writes_verifies_on_blocking_pool` |

## 二、Low / Info 与其余发现

| 编号 | 维度 | 标题 | 最终状态 | 锚点/说明 |
|---|---|---|---|---|
| `RF-11` (`ENG-RC-04`) | 规格边界 | 读路径不提取 Directory/Symlink 条目 | 📌已知功能边界 | `writer` 不产出；`create` 对软链显式拒收或 `--skip-symlinks`；读支持为独立新需求 |
| `RF-12` (`ENG-RC-05`) | 规格/运维 | `repair` 对不存在路径返回 exit 0 | ✅已修复（R1） | 改为非零退出 |
| `RF-13` (`ENG-RC-06`) | 可运维性 | `verify` Degraded 文案一律报"卷缺失" | ✅已修复（R1+R2） | 按 `missing_indices` 准确区分并去重 |
| `RF-14` (`ENG-RC-07`) | 代码质量 | `repair` 死分支 `Healthy && needs_repair()` | ✅已修复（R1+R2） | 布尔不可满足，改穷尽 `match` |
| `RF-15` (`ENG-RC-08`) | 崩溃安全 | 解包未 `fsync` 目标父目录 | ✅已修复 | `ebb915d`：`reader.rs` `sync_extracted_directories`；`extract_all_syncs_output_directories_on_completion` |
| `RF-16` (`ENG-RC-09`) | 安全/TOCTOU | `apply_extracted_metadata` 按路径重开可能跟随恶意符号链接 | ✅已修复 | `ebb915d`：`reader.rs` 改为单次 `O_NOFOLLOW` 打开并在 fd 上应用时间戳/`xattr::FileExt`/权限；`apply_extracted_metadata_refuses_symlink_swap_and_protects_victim_permissions` |
| `RF-17` (`ENG-RC-10`) | 性能 | `verify` 每卷完整读 Catalog；非 EC `repair` 重复 `verify` | 📌benchmark-needed | 正确性无误；缺乏端到端基准前暂保留全量校验证 |
| `RF-18` (`ENG-RC-11`) | 规格一致性 | `verify` 不校验 `entry.size > 100 GiB`（仅 `extract` 校验） | ✅已修复 | `ebb915d`：上限校验下沉 `validate_regular_file_chunks` 实现双向对称；`verify_and_extract_symmetrically_reject_file_exceeding_max_declared_size` |
| `RF-19` (`ENG-RC-12`/`H-04`) | 测试结构 | 139+ 处 `include_str!("../src...")` 源码字符串耦合测试 | 📌结构性工程债 | 历史审计套件固守；已新增不破坏既有审计的协同约束记录 |
| `RF-20`/`21`/`22` (`LL-05`/`06`/`07`) | 健壮/存储 | `Chunker` 校验、`LocalStorageBackend::create` `O_NOFOLLOW`、`read_all_from` 下溢 | ✅已修复（R1+R2） | `era-ingest`、`era-storage` 全绿通过 |
| `RF-23` (`LL-08`) | 防御纵深 | protobuf `TryFrom` 缺跨字段不变量校验（`BlockChunkIndex.count` 等） | ✅已修复 | `933807c`：`era-common/src/conversion.rs` 校验证据见单测 `block_chunk_index_rejects_count_entry_length_mismatch` 等 |
| `RF-24` (`H-05`) | 工程 | CI `--locked`/`ulimit`/`timeout`、`README`/`AGENTS`、`flake.nix`/`fuzz` | ✅核心已修复 / 📌两项缺席项 | `ci.yml` 与 README/AGENTS 全配齐 `ulimit -n 1024`（`R2-CI-01`）；`flake.nix` 与 `fuzz/` 仍待独立工程建设 |
| `RF-25`/`26`/`28` | 测试组织 | `#[path]` 复用生产文件、墙钟并发睡眠测试、内联 `#[cfg(test)]` 模块 | 📌结构性工程债 | 不影响运行正确性，随长期架构拆分逐步迁移 |
| `RF-27` (`H-08`) | 文档/统计 | README/AGENTS 统计、`AGENTS` 引用计数、crate `AGENTS.md` 行数 | ✅已修复 | Commit 6 全量按 `c12c976` 实测刷新，且有 `hygiene_guards_test` 单源校验 |
| `RF-30` (`LL-11` 等) | 纵深/卫生 | `check_mlock_available()` 成功分支未 `munlock` 探针页 | ✅已修复 | `933807c`：`secure_memory.rs` `let _ = munlock(test_buf.as_ptr(), 16)`；`check_mlock_available_unlocks_probe_buffer_when_supported` |
| `R2-07` | 性能/读放大 | `repair` 重复调用 `volume_needs_footer_repair` 与 `plan_volume_footer_repairs` | ✅已修复 | `83a0e55`：`repair.rs` 移除 `volume_needs_footer_repair`，单卷/矩阵路径统一仅调用一次 `plan_volume_footer_repairs` |
| `R2-CI-01` | 文档/可复现性 | `README.md` 与 `AGENTS.md` 本地验证命令漏写 `ulimit -n 1024` | ✅已修复 | Commit 6 补齐 `ulimit -n 1024` 并与 CI 完全一致 |
| `R2-08`/`R2-09`/`R2-VERIFY-01` | 安全/文档 | manifest backup AAD 重试、`ExtractOptions` 破坏性字段、CLI 去重 | ✅已修复 | 已合并并在全套审计回归中持续验证 |

## 三、最终冻结门禁结果（`feat_fly @ c12c976` + Commit 6）

- **`cargo fmt --all -- --check`**：exit 0
- **`cargo clippy --locked --all-targets --all-features -- -D warnings`**：exit 0（全工作区 0 警告）
- **`ulimit -n 1024 && cargo test --release --locked -p era-cli -- --test-threads=2`**：**18 suites，518 passed，0 failed，3 ignored**
- **`ulimit -n 1024 && cargo test --release --locked --workspace -- --test-threads=2`**：**172 suites/doc-tests，2989 passed，0 failed，17 ignored**
- **双阶段合计**：**190 suites/doc-tests，3507 passed，0 failed，20 ignored**
- **`crates/*/src` 与 `bins/*/src` 警告抑制计数**：**0**（`allow(dead_code)` / `allow(unused_mut)` / `allow(unused_imports)` 已由 `hygiene_guards_test::meta_gates::production_sources_have_zero_dead_code_or_unused_allows` 永久锁死）
