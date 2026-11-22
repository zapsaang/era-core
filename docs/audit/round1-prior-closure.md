# Round 1：前序遗留 14 项整改闭环核验（re-audit §4.1–§4.10 / §5.1–§5.4）

> **角色**：独立整改核验（prior-closure 审计线程）  
> **仓库**：`/home/ricardom/code/github.com/zapsaang/era-core`，分支 `feat_fly`  
> **审计 HEAD**：`b22a07e`（整改提交链：`8c42a4c` / `31d358f` / `5ff825e` / `b22a07e`；复审计基线 `ee39fae`）  
> **被核验声明**：工程师声称“已修复仓库全部问题、零技术债、无遗留”，且 re-audit 文档头部记录“§4.1–§4.10 与 §5.1–§5.4 已全部闭环清零并通过验收”。  
> **前序文档**：`docs/re-audit-and-residual-findings-2026-11-21.md`（14 项来源）、`docs/post-fix-audit-and-residual-findings-2026-11-21.md`（9 项 AUDIT-* / 12 项 RESID-* 上下文）  
> **方法**：逐提交 `git show` diff 阅读 → HEAD 代码路径推导 → 定向 release 测试实跑 → 独立临时探针（fault-injection）复现 → 结束前删除探针  
> **工具链**：nix store `cargo 1.99.1` / `rustc 1.99.1`（会话内 rustup stable shim 损坏，所有 cargo 命令显式 PATH）；未运行全量 workspace 测试（由团队负责人后台运行，日志 `/tmp/era_ci_baseline2.log`）  
> **约束遵守**：未修改任何源码/测试/既有文档，未 commit；仅新增本 findings 文件。

---

## 0. 14 项对账表（结论一览）

| # | 前序问题（re-audit 严重度） | HEAD 结论 | 关键代码锚点（HEAD） | 关键证据 | 整改性质 |
|---|---|---|---|---|---|
| §4.1 | 中断 append 后归档不可再打开（High） | **PARTIAL** | `crates/era-volume/src/writer.rs:28-33,248-265,661-673,721-730,832-877`；`crates/era-engine/src/writer/checkpoint_append.rs:14-20,113-119` | 新负例测试 `resid_high03_checkpoint_append` 12/12 通过（含 3 个新增中断用例）；独立探针：finalize 前中断可读=true，finalize 中 truncate 后中断归档损坏 | 真修复“finalize 前”窗口；finalize 窗口未闭环 + 内存回归 |
| §4.2 | `verify` 不校验可解析的备份头（Medium） | **FIXED** | `crates/era-engine/src/reader.rs:2767,2818-2882`；`repair.rs:341-560,684-762` | 新增引擎测试 6/6、CLI 备份头损坏/修复端到端 3/3 通过 | 真修复 |
| §4.3 | `extract --force` 失败删除已覆盖原文件（Medium） | **FIXED** | `chunk_processor.rs:561-613`；`reader.rs:2403,2515-2531` | `find11_extract_overwrite_tests` 4/4（新用例断言原内容、0444 权限保留、无残留备份） | 真修复（rename-aside + 失败回滚）；崩溃场景见 R4 |
| §4.4 | 非 EC 主头在数据损坏时也被拒修 + 文案矛盾（Medium） | **FIXED** | `repair.rs:750-762,1257-1400`；`bins/era-cli/src/commands.rs:1345-1354` | 引擎用例断言“报数据错误但主头已按字节写回”通过；CLI 用例断言主头恢复 | 真修复（解耦头修复与数据修复） |
| §4.5 | 单块解包路径丢失 `sync_all`（Low） | **FIXED** | `chunk_processor.rs:412,444,523` | 代码路径：packed / single / multi-complete 三路径均有 `file.sync_all()` | 真修复 |
| §4.6 | 懒句柄重开 TOCTOU（Low） | **FIXED** | `chunk_processor.rs:239-362`（`O_NOFOLLOW` + `(dev,ino)` 校验） | `bounded_fd_extraction_tests::lazy_multi_chunk_evicted_handle_rejects_symlink_and_inode_swap` 通过（12/12） | 真修复 |
| §4.7 | 死代码/死参数/大面积 `allow`（Low） | **PARTIAL** | `chunk_processor.rs`（模块级 allow 已删、`MultiChunkState`/`tracked_output_files` 已删）；全仓 `src` 仍有 64 个 allow（其中 `dead_code` 41） | `grep` 计数；模块级 `#![allow(dead_code)]` 已不存在 | 症状性清理：主路径已清，残留面仍大 |
| §4.8 | 尺寸校验不完整 / 零 chunk 静默跳过（Low） | **FIXED** | `reader.rs:2885-2934`（`validate_regular_file_chunks`，extract/verify 双端调用 `:2197,:2547`）；`chunk_processor.rs:388-401,767-800` | `bounded_fd_extraction_tests::malformed_file_entry_metadata_rejected_by_extract_and_verify` 通过 | 真修复（行为更严格，见 R10） |
| §4.9 | `verify` 每卷完整 Catalog 读取（Low，likely regression） | **PARTIAL** | `reader.rs:2767-2796`（仅跳过 `catalog_loaded_from_primary` 的 1 卷） | `git show ee39fae:.../reader.rs` 对比：基线无跳过；HEAD 仅减少 1 卷 | 缓解 1/N，未做 benchmark |
| §4.10 | 审计测试直接断言源码字符串（Low） | **PARTIAL** | `tests/adversarial_audit_v3.rs:276-315`；`tests/adversarial_audit_v2.rs:41-50` | 仍 `include_str!` + `contains(...)`；仅放宽匹配范围并追加行为用例 | 症状性放宽 |
| §5.1 | docs 未纳入版本库（工程债） | **FIXED** | `.gitignore:27`；`git ls-files docs` | 4 份 11 月审计报告已跟踪；本文件因全局 ignore 仍不可跟踪（见 R8） | 真修复（残留 ignore 脆弱性） |
| §5.2 | Cargo.lock / 工具链 / fuzz 漂移（Low–Medium） | **PARTIAL** | `Cargo.lock`（已跟踪）；`rust-toolchain.toml:2`；`.github/workflows/fuzz.yml:38-47` | Cargo.lock 已跟踪；toolchain=stable 对齐 CI；fuzz.yml 缺失时跳过；`flake.nix/flake.lock` 仍未跟踪 | 大部分修复，flake 未闭环 |
| §5.3 | 统计与文档漂移（Low） | **PARTIAL** | `README.md:503-512`；`AGENTS.md:3-4,15`；`crates/era-engine/src/AGENTS.md:10-18` | README/根 AGENTS 数字经实测核对正确（2916/17/164、265 文件、141.7k LOC、writer.rs 4586）；但 crate 级 AGENTS 行数表与根 AGENTS `Commit: 5bf28de` 仍过期 | 部分修复 |
| §5.4 | 测试质量债（Low） | **PARTIAL** | `crates/era-storage/tests/pwrite_test.rs:7-9`；`crates/era-packing/tests/resilience_tests.rs:41-155`；`crates/era-engine/tests/concurrency_torture.rs:36,88-92` | pwrite 测试取消 ignore 且实跑通过；resilience 测试已实测断言；`concurrency_torture` 仍为 5s 墙钟断言 | 大部分修复，残留墙钟/大磁盘 ignore |

**合计**：FIXED **7** / PARTIAL **7** / NOT FIXED **0** / REGRESSED **0**（按 14 项口径）；另有 **12 项**残留/整改引入发现：confirmed **high 1 / medium 1 / low 8 / informational 2**（见 §3）。

**“已修复全部问题、零技术债、无遗留”不成立**。14 项中没有一项仍是完全未动，但 7 项只做到部分闭环；其中 §4.1 的“P0 崩溃安全”承诺仅覆盖 finalize 之前，且整改本身引入可证明的 append 内存回归（R2）。

---

## 1. 证据环境与实测清单

### 1.1 环境

- 仓库：`feat_fly @ b22a07e`，`git status --porcelain` 在被核验主体上干净（仅两位 peer 审计员的未跟踪临时探针，见 §6）。
- 工具链：nix store `cargo 1.99.1` / `rustc 1.99.1`；本会话 rustup stable shim 不可用，所有 cargo 命令前置：

```bash
export PATH="/nix/store/c2ii5nkzv440xj9igxsd49i8f5y2vr6f-cargo-1.99.1/bin:/nix/store/mslcwkiyh6wayx8gpzlq53wvr3a5pp44-rustc-1.99.1/bin:$PATH"
export RUSTC=/nix/store/mslcwkiyh6wayx8gpzlq53wvr3a5pp44-rustc-1.99.1/bin/rustc
```

### 1.2 定向测试实跑（我自己执行，release，`--test-threads=1/2`）

| 套件 | 命令（节选） | 结果 |
|---|---|---|
| `resid_high03_checkpoint_append` | `cargo test --release -p era-engine --test resid_high03_checkpoint_append -- --test-threads=2` | **12 passed / 0 failed**（含 3 个新增中断 append 用例） |
| `resid_high02_header_repair` | `cargo test --release -p era-engine --test resid_high02_header_repair -- --test-threads=2` | **6 passed / 0 failed**（含备份头损坏检测/修复、非 EC 头+数据双损坏用例） |
| `resid_high02_cli_repair` | `cargo test --release -p era-cli --test resid_high02_cli_repair -- --test-threads=1` | **3 passed / 0 failed** |
| `find11_extract_overwrite_tests` | `cargo test --release -p era-engine --test find11_extract_overwrite_tests -- --test-threads=2` | **4 passed / 0 failed**（含 `--force` 失败回滚用例） |
| `bounded_fd_extraction_tests` | `cargo test --release -p era-engine --test bounded_fd_extraction_tests -- --test-threads=1` | **12 passed / 0 failed**（含 LRU 驱逐/重开防掉包、畸形 catalog 用例） |
| `adversarial_audit_v3` | `cargo test --release -p era-engine --test adversarial_audit_v3 -- --test-threads=2` | **22 passed / 0 failed** |
| `era-storage`（含 pwrite） | `cargo test --release -p era-storage -- --test-threads=1` | **20 passed + pwrite 1 passed / 0 failed** |
| 临时探针（finalize 原子性） | `cargo test --release -p era-volume --test zz_prior_closure_probe -- --test-threads=1 --nocapture` | **3 passed**；输出见 R1/R2 证据段 |

### 1.3 全量门禁（引用团队负责人后台实测，非我重复运行）

- 日志 `/tmp/era_ci_baseline2.log`：`fmt_rc=0`、`clippy_rc=0`；两段 cargo 运行（`-p era-cli` 与 `--workspace`）；
- 分段求和：era-cli **16 suites / 500 passed / 3 ignored**；workspace **164 suites / 2916 passed / 0 failed / 17 ignored**；`ws_rc=0`。
- 该结果与 `README.md:508` 声称的 “2916 passed, 0 failed, 17 ignored (164 suites/doc-tests)” **完全一致**（17 ignored = 3 个源码 `#[ignore]` + 14 个 rustdoc 忽略代码块）。

---

## 2. 逐项核验

### §4.1 【High】中断 append 后归档不可再打开 — **PARTIAL**

- **结论**：原先“build()/open_append 即 truncate，finalize 前崩溃导致无合法 footer”的路径已被消除，但只在 **finalize 之前** 成立；finalize 内部仍有“truncate 后、footer 落盘前”的崩溃窗口（窗口≈整段 staged 数据写盘时长），且整改以“把整段 append 数据放内存”实现，引入新的资源回归。
- **代码锚点（HEAD）**：
  - `crates/era-volume/src/writer.rs:28-33`：`StagedAppend { base_offset, buf: Vec<u8>, original_footer }`；
  - `crates/era-volume/src/writer.rs:245-253`：`open_append_at` 不再 `truncate(append_offset)`，改为登记 staged；
  - `crates/era-volume/src/writer.rs:256-265`：`flush_staged_append()` = `truncate(base)` → `append(buf)`（finalize 时才执行）；
  - `crates/era-volume/src/writer.rs:661-673,721-730`：数据块/raw 写入追加到 `buf`（内存）；
  - `crates/era-volume/src/writer.rs:832-877`：`finalize_with_catalog` 先 `flush_staged_append()`，再 pad/sync、写主头（`:850`）、备份头、主 footer（`:861-868`）、备份 footer（`:872`）；`truncate` 与 footer 之间没有中间合法 footer；
  - `crates/era-volume/src/writer.rs:504-513`：staged 期间 `commit_checkpoint` 直接 `return Ok(())`（footer 不更新；checkpoint 块本身也只在 staged 缓冲中）；
  - `crates/era-engine/src/writer/checkpoint_append.rs:14-20,95-119`：`legacy_terminal_checkpoint_offset`（含 `last_checkpoint_offset()==0` 的 StartFresh 崩溃残留识别）；
  - `crates/era-engine/src/writer.rs:660-706`：append 前对 legacy checkpoint 的认证分支；`:350-360`：删除了“crash 后自动从 checkpoint 恢复”的错误文档承诺。
- **机理**：
  - finalize 前中断：磁盘文件完全未被改写（或 StartFresh 仅重写了两处“清 checkpoint 指针但保留 data_end/block_count”的 footer），归档仍可 `VolumeReader::open`；
  - finalize 中中断：`flush_staged_append` 已把旧 catalog/index/manifest/footer 从 `base_offset` 之后截掉，若进程在 `:850-872` 的 footer 落盘前崩溃/IO 失败，则文件长度只剩 retained data 区（+部分 staged 数据），磁盘上不存在与文件尺寸一致的 footer → 归档不可打开；非 EC 单卷归档的 catalog 无法重建 → 数据永久不可用。
- **证据（实测）**：

```text
# 1) 新负例测试（git show 8c42a4c 新增，HEAD 实跑）
running 12 tests
test interrupted_append_preserves_readable_archive_across_plain_resume_and_start_fresh ... ok
test interrupted_start_fresh_on_legacy_checkpoint_allows_subsequent_append ... ok
test interrupted_append_after_volume_rotation_preserves_original_archive ... ok
test result: ok. 12 passed; 0 failed; 0 ignored

# 2) 独立 fault-injection 探针（临时文件 zz_prior_closure_probe.rs，运行后已删除）
PROBE_A crash-before-finalize: file unchanged=true len=13568
PROBE_A reopen_ok=true
PROBE_B finalize_err=Some("I/O error: injected crash/IO failure immediately after truncate, before the new footer is written")
PROBE_B before_len=13568 after_len=8320 reopen_err=Some("Corrupted footer: Archive appears truncated: footer claims data_end_offset=9344 but file size is 8320")
PROBE_C on_disk_before=13568 on_disk_after=13568 writer_position=8396928 staged_bytes=8383360
```

  探针 A = 写入 staged 后直接 drop（等价 kill），文件字节不变且可重开；探针 B = 在 `truncate` 之后注入 append IO 失败（等价 finalize 中崩溃），文件被截到 8320B、重开报 `Archive appears truncated`；探针 C = 8 MiB append 全在内存（磁盘未增长，`writer_position` 已增长 8,383,360B）。
- **确认程度**：finalize 前可恢复 = **confirmed（实测）**；finalize 中不可恢复 = **confirmed（实测 + 代码路径）**；崩溃场景的“永久数据不可用”以非 EC 单卷为前提（实探针即该场景）。
- **整改性质**：症状性规避（延迟 truncate 到 finalize），未实现 re-audit P0 建议的“truncate 后立即写回合法备份 footer”或“原子 finalize”；同时引入 R2 内存回归。
- **建议修复**：
  1. finalize 原子化：写入新卷文件（或新数据区段）后原子 `rename`/双 footer 协议；或
  2. 保留旧 footer 不被 truncate（在旧 data_end 之后追加再切换），确保任意时刻磁盘上存在一个合法可打开视图；或
  3. 至少实现 P0 原建议：truncate 后立刻写回 `data_end=append_retained_end`、checkpoint=0 的合法 footer，再写新数据，最后写最终 footer；
  4. 为 staged 数据设置上限/落盘 spool（另见 R2）。
- **应补 TDD 回归测试**：
  - 负例：fault-injection backend 在 `truncate` 后、footer 写入前返回 IO 错误（或注入 `kill -9` 子进程），断言旧归档仍可 `VolumeReader::open`/`ArchiveReader::open` 且能 extract 原有内容；
  - 负例：finalize 过程中每个关键写点（truncate 后 / 数据写完 / header 写完 / footer 写完）崩溃的矩阵测试；
  - 负例：append 数据量 > 阈值时 staged 内存占用有界（或明确返回错误）。

### §4.2 【Medium】verify 不校验仍可解析的备份头 — **FIXED**

- **结论**：已逐卷校验备份头。`verify()` 在块扫描前调用 `verify_backup_headers`；对每个“未从备份头恢复”的卷：校验 backup offset 合法性（≥`DATA_REGION_START` 且 == footer.data_end_offset）、读取主头与备份头各 4096B、校验长度、用 manifest 全局签名摘要（`manifest_header_digest`）或本卷 local manifest 摘要（`manifest_local_header_digest`）做 BLAKE3 认证比较、要求备份头可解析且与主头逐字节一致；任一不满足 push warning，`classify_archive_health` 把 warning 归为 `Degraded`，CLI `verify` 对 Degraded 退出失败。repair 侧可计划并写回备份头。
- **锚点**：`crates/era-engine/src/reader.rs:2767`（调用）、`:2818-2882`（`verify_backup_headers`）、`:853-881`（warning→Degraded）、`:1021`（`catalog_loaded_from_primary`）；`crates/era-engine/src/repair.rs:341-560`（provenance/摘要认证/计划）、`:684-762`（应用顺序）；`bins/era-cli/src/commands.rs:1048-1077`（Degraded→bail）。
- **证据（实测）**：

```text
== era-engine resid_high02_header_repair（6/6）==
test resid_high02_corrupted_backup_header_is_detected_by_verify_and_restored_by_repair ... ok
test resid_high02_non_ec_header_plus_data_damage_restores_primary_header_before_reporting_data_error ... ok
test result: ok. 6 passed; 0 failed

== era-cli resid_high02_cli_repair（3/3）==
test resid_high02_cli_detects_and_repairs_corrupted_backup_header ... ok
test result: ok. 3 passed; 0 failed
```

  测试内容（`resid_high02_header_repair.rs:293`、`bins/era-cli/tests/resid_high02_cli_repair.rs:132`）：清零备份头 → verify 必须 Degraded/失败（旧行为是 exit 0）→ dry-run repair 不改文件且提示 `--force` → `repair --force` 后文件与原文件**逐字节相等** → verify 通过 → 再破坏主头，仍可 extract 出原 payload（证明修复后的备份头真实可用）。多卷 EC 归档同断言。
- **确认程度**：**confirmed（实测）**。
- **残留说明**：对既无 manifest 全局摘要、也无本卷 local manifest 摘要的旧格式，退化为“备份头与主头逐字节比较 + 可解析性”，不具备密码学认证强度（仍能发现 bitrot/覆写）；这是降级路径，不是缺口。
- **建议/测试**：保持现状；建议补一条“备份头与主头不同但两者都可解析且无摘要表”用例，锁定降级语义。

### §4.3 【Medium】extract --force 失败删除已覆盖的用户原文件 — **FIXED**

- **结论**：覆盖改为“rename-aside”：写入目标前把既有普通文件/符号链接 rename 到同目录唯一备份 `.era_overwrite_backup_<pid>_<seq>`，再 `create_new` 打开新文件；失败清理只删除本次新建的 `created_output_paths`，随后 `restore_overwritten_backups()` 把备份 rename 回原路径（保留 inode/权限/内容）；成功则在元数据恢复之后 `commit_overwritten_backups()` 删除备份。
- **锚点**：`crates/era-engine/src/chunk_processor.rs:561-613`（`open_output_for_extract`，含类型检查、备份命名、失败回滚）、`:94-150`（take/commit/restore）；`crates/era-engine/src/reader.rs:2403`（成功后提交/删除备份）、`:2515-2531`（`fail_extraction_with_context`：删新建文件→恢复备份→返回原错误）。
- **证据（实测）**：

```text
running 4 tests
test overwrite_extraction_failure_restores_preexisting_overwritten_files ... ok
test failed_extraction_cleanup_preserves_untouched_existing_files ... ok
test overwrite_readonly_small_and_large_files_succeeds ... ok
test overwrite_unlinks_symlink_instead_of_writing_target ... ok
test result: ok. 4 passed; 0 failed
```

  测试（`find11_extract_overwrite_tests.rs:167`）真实断言：预置 `alpha.bin` 用户内容 + 0444 只读 `beta_ro.bin` → 损坏最后一个数据块使解包失败 → 断言两文件内容与失败前**完全一致**、`beta_ro.bin` 权限仍为 0444、新建的 `gamma_new.bin`/`delta_fail.bin` 被删除、输出目录无 `.era_overwrite_backup_*` 残留。
- **确认程度**：**confirmed（实测）**。
- **整改引入的残留**：进程崩溃（SIGKILL/断电）而非可捕获错误时，原文件会被留在隐藏备份名下、原路径消失，且下次运行没有自动恢复逻辑（数据未丢，但偏离“用户原文件保留在原路径”的直觉）。见 R4。
- **建议/测试**：保留现有行为；建议启动时扫描输出目录的 `.era_overwrite_backup_*` 并在明确确认下恢复/清理，或改为“临时文件 + 原子 rename 替换”以彻底消除 backup 依赖；补“模拟崩溃后备份文件存在且原路径缺失”恢复语义测试。

### §4.4 【Medium】非 EC 归档数据损坏时连已认证主头也不修复 — **FIXED**

- **结论**：头修复与数据错误已解耦：单卷路径先规划/应用 header repairs（+用于非 EC 的 catalog repairs），之后才用修复前采集的 `verify_stats` 判断“数据是否超出可修复范围”并返回 IntegrityError；多卷矩阵路径同构。CLI 文案改为“Only authenticated headers and sibling catalogs can be restored without erasure coding”。
- **锚点**：`crates/era-engine/src/repair.rs:687-762`（needs_header → verify_stats 采集 → `apply_header_repairs` 在 `:750`，错误判定在 `:755-762`）、`:1257-1400`（matrix 同构：头修复先于数据错误）；`bins/era-cli/src/commands.rs:1345-1354`。
- **证据（实测）**：引擎用例 `resid_high02_non_ec_header_plus_data_damage_restores_primary_header_before_reporting_data_error` 通过（`resid_high02_header_repair.rs:391`）：dry-run 不修改文件；非 dry-run 返回 IntegrityError 但断言主头已按原认证字节写回、不再从备份恢复；CLI 用例（`resid_high02_cli_repair.rs:73`）断言失败退出时主头已恢复且不输出误导性 erasure-parity 文案。
- **确认程度**：**confirmed（实测）**。
- **残留说明**：非 EC 数据块仍不可修复（设计限制，已正确文档化/文案化）。
- **建议/测试**：保持；已有测试足够。

### §4.5 【Low】单块文件解包不再 fsync — **FIXED**

- **结论**：三条完成路径都恢复 `sync_all`：packed 文件（`chunk_processor.rs:412`）、single-chunk fast path（`:444`）、multi-chunk 完成（`:523`）。
- **机理**：基线（`ee39fae` 前）所有非 packed 文件经 `MultiChunkState` 完成分支落盘并 `sync_all`；`ee39fae` 的 single-chunk fast path 曾遗漏；HEAD 已补齐。
- **确认程度**：**confirmed（代码路径）**；掉电持久性无测试断言（目录 fsync 仍缺失，属既有语义，非本项回归）。
- **建议/测试**：如需“extract 返回即持久”语义，补 `sync_all` 之后对父目录 `sync` 并加掉电模拟（较难）或文档化；至少加一条“解包完成后文件已 fsync”的实现断言（如通过 mock backend 记录 sync 调用）。

### §4.6 【Low】懒句柄重开 TOCTOU — **FIXED**

- **结论**：重开路径不再“检查→按路径 open”：`open_or_get_lazy_handle` 在重新打开时使用 `custom_flags(libc::O_NOFOLLOW)`（`chunk_processor.rs:318-324`），打开后校验 `metadata.file_type().is_file()` 且 `(dev, ino)` 与首次创建时记录一致（`:335-351`），不一致返回 `Security`；重开前仍做 output containment 复检（`:287`）。首次创建使用 `create_new(true)` + 先 `symlink_metadata` 判型/rename-aside，不跟随符号链接。
- **证据（实测）**：`bounded_fd_extraction_tests.rs:193` 的两个场景（驱逐后用符号链接替换目标 → 必须 Security 失败；驱逐后用另一 inode 替换 → 必须 Security 失败）在 12/12 套件中通过。
- **确认程度**：**confirmed（实测 + 代码）**；威胁模型：输出目录可写 + 触发 LRU 驱逐（>64 个未完成多块文件）+ 赢得竞态；修复后即使赢得竞态也无法写到攻击者指定文件（O_NOFOLLOW + inode 校验）。
- **建议/测试**：已有；如需进一步收紧可用 `openat2(RESOLVE_BENEATH)`（可选，非必须）。

### §4.7 【Low】整改遗留死代码 / 死参数 / 大面积 allow — **PARTIAL**

- **结论**：re-audit 点名的主项已清：`chunk_processor.rs` 模块级 `#![allow(dead_code)]` 已删除；`MultiChunkState`/`multi_chunk_files`/`tracked_output_files` 已删除（全仓 grep 0 命中；测试构造改为 `register_multi_chunk_file`/`set_overwrite`，见 `adversarial_audit_v5.rs` 适配）。但“大面积 allow”整体未收敛：生产 `src` 仍有 **64** 个 allow 属性，其中 `dead_code` **41** 个（`write_pipeline.rs` 8、`encryption_context.rs` 6、`chunk_index.rs` 6、`packing_stage.rs` 4、`index_stage.rs` 4、`checkpoint.rs` 3……），且部分确为生产不可达（如 `index_stage.rs:53,92,118` 的“Used in tests and scenarios” API 未 `cfg(test)` 门控）。
- **证据**：

```text
$ grep -rn "allow(dead_code)" crates/*/src bins/*/src | wc -l
41
$ grep -rhn "^\s*#\[allow" crates/*/src bins/*/src | sort | uniq -c
     41 dead_code / 18 clippy / 3 deprecated / 1 unused_imports / 1 unreachable_patterns
$ grep -rn "MultiChunkState\|multi_chunk_files\|tracked_output_files" crates/ | wc -l
0
```

- **确认程度**：**confirmed（命令/代码）**。
- **整改性质**：症状性清理（清掉最刺眼的模块级 allow 与不可达分支，未逐项处理 41 个 `dead_code`）。
- **建议/测试**：对 41 个 `dead_code` 逐项判定（删除 / `cfg(test)` / 注明保留原因）；为保留项加 clippy 白名单注释。回归测试：在 CI 加 `#![deny(dead_code)]` 的 crate 级试验或审计脚本对 allow 数量设上限，避免继续增长。

### §4.8 【Low】解包尺寸校验不完整 / 零 chunk 静默跳过 — **FIXED**

- **结论**：新增 `validate_regular_file_chunks`（`reader.rs:2885-2934`），在 extract 规划（`:2197`）与 verify（`:2547`）双端执行：普通文件 chunks 为空 → `InvalidFormat`（不再静默跳过）；混用 `packed_info` 与多 chunk → 错误；chunk 偏移必须从 0 开始连续无空洞/重叠；`sum(length) == entry.size`（带 overflow 检查）。packed 文件在 verify 侧校验外层长度与每个 packed entry 解包长度（`chunk_processor.rs:767-800`），extract 侧校验解包长度==entry.size（`:392-401`）。
- **证据（实测）**：`bounded_fd_extraction_tests::malformed_file_entry_metadata_rejected_by_extract_and_verify`（`:439`）覆盖 packed size 不一致、多块非连续偏移、多块长度和 != size 三类，断言 verify 不 ok 且 extract 报错、无输出文件；12/12 套件通过。
- **确认程度**：**confirmed（实测）**。
- **行为变化**：对“外部/修复产生的异常 catalog”，HEAD 由“静默跳过/部分成功”变为“extract 与 verify 均报错”。这是更安全的语义，但对 v8.x 旧数据/第三方工具产物是 accept→reject 变化（见 R10，informational）。
- **建议/测试**：已有；建议为“零 chunk File 条目”单独加一条正反例（当前由 `entry.chunks.is_empty()` 分支覆盖，但无专门测试名）。

### §4.9 【Low，likely regression / benchmark-needed】verify 每卷完整 Catalog 读取 — **PARTIAL**

- **结论**：verify 依旧对每个“有 catalog 位置且 block_count>0”的卷执行主 Catalog 读取+解密+解析+承诺校验（`reader.rs:2769-2796`；manifest 存在时用 `read_and_verify_catalog_bytes`），HEAD 仅新增“跳过 open 时已用主 Catalog 装载的那 1 个卷”（`:2770`，`catalog_loaded_from_primary` 于 `:1021` 设置）。基线 `ee39fae` 没有该跳过（`git show ee39fae:crates/era-engine/src/reader.rs` 的 `damaged_primary_catalogs` 循环无 `catalog_loaded_from_primary`），所以相对基线只减少 1 卷 I/O，N 卷归档仍是 O(N × catalog 明文) 的额外读取/解密。
- **证据**：

```text
$ git show ee39fae:crates/era-engine/src/reader.rs | grep -n catalog_loaded_from_primary
(no output; baseline 无跳过逻辑)
$ grep -n catalog_loaded_from_primary crates/era-engine/src/reader.rs
121
164
1021
2770
```

  另：§4.2 修复新增每卷 2×4096B 的备份头校验读（`reader.rs:2839-2853`），成本固定且较小，属预期成本。
- **确认程度**：代码路径 **confirmed**；性能影响量级 **inference（benchmark-needed）**：未提供 benchmark/测量；正确性无问题。
- **分类**：**likely regression（相对 `ee39fae` 之前的 verify），未达 provable**；需 benchmark 量化（例如 100 卷 × 每卷 catalog 大小）。
- **建议/测试**：与团队约定——若 catalog 有冗余副本，改为抽样/摘要校验或加 `--verify-catalogs minimal` 选项；补 benchmark（多卷大 catalog verify 对比 create 时已知 catalog 数量）。

### §4.10 【Low】源码字符串耦合测试 — **PARTIAL**

- **结论**：`adversarial_audit_v3::test_v3_perf_03_writer_uses_async_path_exists` 仍 `include_str!("../src/writer.rs")` 并 `source.find("pub async fn build(...)")`、`slice.contains("tokio::fs::try_exists(")`、`!slice.contains(".exists()")`；只是从“精确行/精确语句”放宽为“函数体片段 + 子串”，并**追加**了一个行为用例（对非法已存在文件 `append_existing(true).build()` 必须干净失败）。`adversarial_audit_v2.rs:41-50` 同类测试从 1 种写法放宽为接受 3 种写法（仍基于源码文本）。
- **证据**：`tests/adversarial_audit_v3.rs:276-315`（HEAD 原文）；`git show 5ff825e -- crates/era-engine/tests/adversarial_audit_v3.rs`；实跑 22/22 通过。
- **确认程度**：**confirmed（代码）**。
- **整改性质**：症状性放宽（降低误报概率，但未消除源码文本耦合；任何把 `try_exists` 封装进 helper 或改 doc 注释边界的重构仍会误报，`find("\n/// Writer for creating ERA archives")` 依赖 doc 文本尤其脆弱）。
- **建议/测试**：改为纯行为测试（例如 mock backend 统计 `exists`/`try_exists` 调用次数，或用 trait 注入 probe），删除 `include_str!` 断言；至少用编译期 API/特征而非源码文本。

### §5.1 【工程债】审计证据链未纳入仓库 — **FIXED（残留 R8）**

- **结论**：4 份 2026-11 审计报告已纳入 `git` 跟踪（`git ls-files docs` 输出 4 个文件）；`.gitignore` 增加 `!docs/*-2026-11-*.md` 放行；re-audit 文档头部已写“整改闭环记录”。
- **证据**：

```text
$ git ls-files docs
docs/code-and-practical-test-findings-2026-11-18.md
docs/post-fix-audit-and-residual-findings-2026-11-20.md
docs/post-fix-audit-and-residual-findings-2026-11-21.md
docs/re-audit-and-residual-findings-2026-11-21.md
$ git check-ignore -v docs/audit/round1-prior-closure.md
/home/ricardom/.config/git/ignore:29:docs/  docs/audit/round1-prior-closure.md
```

- **确认程度**：**confirmed**。残留：本机用户级 global ignore 仍整体忽略 `docs/`，仓库白名单只匹配 `*-2026-11-*.md`；因此本轮及后续 `docs/audit/*.md` 默认不可跟踪（见 R8）。

### §5.2 【Low–Medium】依赖与工具链可复现性 — **PARTIAL**

- **结论**：`Cargo.lock` 已跟踪（`b22a07e` 新增 3412 行，`.gitignore:10` 注释改为“Keep Cargo.lock tracked”）；`rust-toolchain.toml:2` 改为 `channel = "stable"`，与 CI `dtolnay/rust-toolchain@stable` 对齐；`fuzz.yml:38-47` 增加 `fuzz/Cargo.toml` 缺失时跳过（不再必然失败）。**残留**：`flake.nix`/`flake.lock` 仍未被跟踪（本地存在，被用户 global ignore 匹配）；fuzz 工作区仍不存在，workflow 只是静默跳过（无 fuzz 覆盖）。
- **证据**：

```text
$ git ls-files Cargo.lock flake.nix flake.lock rust-toolchain.toml
Cargo.lock
rust-toolchain.toml
$ git check-ignore -v flake.nix flake.lock
~/.config/git/ignore:31:flake.nix     flake.nix
~/.config/git/ignore:30:flake.lock    flake.lock
```

- **确认程度**：**confirmed**。flake 未跟踪部分依赖用户全局 ignore（仓库侧无 `.gitignore` 条目），属于“可复现性仍不完整”的工程残留。
- **建议**：显式 `git add -f` 跟踪 flake 文件（或加仓库级 `!flake.nix`/`!flake.lock` 放行）；fuzz 目标要么真正入库，要么在 CI 中明确标记 skipped 而非“成功”。

### §5.3 【Low】统计与文档漂移 — **PARTIAL**

- **结论（实测核对）**：README/根 AGENTS 的核心数字已更新且**正确**：
  - `README.md:506-508`：141,700 LOC（53,200 src + 85,650 tests）；265 `.rs`；2916 passed / 0 failed / 17 ignored（164 suites/doc-tests）。我独立核对：`git ls-files "*.rs"` 共 **265**；`cat $(git ls-files "*.rs") | wc -l` = **141,721**；tests 路径 = **85,651**；`writer.rs` = **4586**（与 `AGENTS.md:15` 一致）；全量日志分段 = **164 suites / 2916 passed / 0 failed / 17 ignored**。17 ignored = 3 个源码 `#[ignore]` + 14 个 rustdoc 忽略代码块（`git grep -n "#\[ignore" -- "*.rs"` = 3；cargo 日志 doctest 段 3+8+3 ignored）。
  - **残留**：`AGENTS.md:3-4` 头部仍为 `Generated: 2026-09-23 / Commit: 5bf28de`（落后于 b22a07e）；crate 级 AGENTS 行数表普遍过期：`crates/era-engine/src/AGENTS.md:10-18` 称 writer.rs 3649 / reader.rs 2633 / repair.rs 1507 / chunk_processor.rs 595，实际 4586 / 3802 / 2000 / 1070；`crates/era-volume/src/AGENTS.md:13` 称 writer.rs 918，实际 1182。
- **确认程度**：**confirmed（命令 + 数字对比）**。
- **整改性质**：部分修复（只同步了 README/根 AGENTS 的统计，crate 级地图与生成元数据未同步）。
- **建议**：把行数/文件数统计改为脚本生成（如 CI 校验 `wc -l` 快照），或至少同步 crate 级 AGENTS 与根头部 commit。

### §5.4 【Low】测试质量债 — **PARTIAL**

- **结论**：
  - `pwrite_test` 已取消过期 `#[ignore]`，且**测试本身现在是有效的**：底层问题已在 `0d05fcd fix(storage): honor positional writes on reopened files`（`ee39fae` 的祖先）修复——`crates/era-storage/src/local.rs:59-67` 的 `open_append` 不再使用 `.append(true)`（O_APPEND 会让 `pwrite` 追加到 EOF），改为 `.write(true)` + 显式 seek；实跑 `test_storage_pwrite_concurrency ... ok`。
  - `resilience_tests.rs` 已从“仅编译/仅打印”改为真实断言（`unpack_resilient` 用零化 shard 恢复、`unpack_resilient_verified` 用 CRC 失败 bitflip 恢复，断言 corrupted 索引与恢复内容哈希/字节）。
  - re-audit 要求的负例覆盖已补：append 中断（3 个新用例）、备份头损坏/修复、`--force` 失败回滚、LRU 驱逐/重开防掉包（均在上述实跑中通过）。
  - **残留**：`crates/era-engine/tests/concurrency_torture.rs:36,88-92` 仍为 5s 墙钟 + `max_delay < 50ms` 断言（共享 CI 负载下可能 flaky）；仍有 3 个 `#[ignore]`（2×“requires ~10GB disk space” + 1×“5GB test requires >10GB free disk”），属合理的大磁盘豁免但意味着相应边界无 CI 覆盖。
- **确认程度**：**confirmed（实跑 + 代码）**。
- **建议/测试**：把 concurrency torture 的墙钟阈值改为“相对基线/可注入时钟”，或在 CI 标记为非阻塞；大磁盘用例移到 nightly/自托管 runner 并在文档标注。

---

## 3. 整改引入的回归 / 新发现（R1–R12）

> 编号独立于前序；维度按仓库 Review Rules；性能断言标注分类；安全断言含威胁场景/信任边界/前置/影响。

### R1【High｜并发与一致性/崩溃安全】finalize 中断仍可摧毁原归档（§4.1 残留窗口）

- **锚点**：`crates/era-volume/src/writer.rs:832-877`（`flush_staged_append` → pad/sync → 主头 → footer）、`:256-265`（truncate+append）。
- **机理**：见 §4.1；窗口长度 ≈ staged 整体写盘 + 可选 pad/fdatasync + header/footer 写入。对 GB 级 append，窗口不是瞬时。
- **证据**：探针 B（`PROBE_B before_len=13568 after_len=8320 reopen_err=...Archive appears truncated...`）。
- **确认**：confirmed（fault-injection 实测 + 代码必然性）。
- **影响**：非 EC 单卷归档在 finalize 期间崩溃后 catalog 无法重建，原已提交数据不可访问（data availability 永久损失）。
- **建议**：见 §4.1；负例测试见 §4.1。

### R2【Medium｜性能/资源；provable regression】staged append 把整段追加数据放内存（§4.1 整改引入）

- **锚点**：`crates/era-volume/src/writer.rs:28-33`（`buf: Vec<u8>`）、`:661-673`、`:721-730`；`flush_staged_append` 仅在 `finalize_with_catalog`（`:832`）与 `set_max_size`（`:275`）执行；engine 以 `with_max_size(max_volume_size)` 建池（`crates/era-engine/src/writer.rs:1104`），默认 `DEFAULT_MAX_VOLUME_SIZE = 4 GiB`（`crates/era-volume/src/multi_volume.rs`）。
- **机理**：append 期间所有数据块、raw 字节、catalog/index/manifest/checkpoint 块都进 `Vec<u8>`，峰值内存 = O(追加字节数)，上限受用户的 `max_volume_size` 影响；基线（`ee39fae`）是流式写盘、内存 O(1)。
- **证据**：探针 C：`on_disk_before=13568 on_disk_after=13568 writer_position=8396928 staged_bytes=8383360`（8 MiB 追加 0 字节落盘，全部驻留内存）；代码路径必达。
- **确认**：内存增长 **confirmed（实测 + 代码）**；OOM 触发为 inference（取决于数据量与配置），但增长率是确定的。
- **分类**：**provable regression**（峰值内存相对基线由 O(1) 变 O(appended)，非推测）。
- **影响**：公开引擎 API（`ArchiveWriterBuilder::append_existing`）在大追加时可能 OOM/被 OOM killer 终止；虽然原归档因 staging 而保持完整（这是 §4.1 修复的收益），但 append 功能在“归档大小 ≈ 内存”场景不可用；无内存上限、无降级、无文档、无测试。
- **建议**：staged 缓冲设硬上限 + 超限报错/落盘 spool（tempfile + rename）；或改用“保留旧 footer、追加新数据后再切换”的流式协议（同时解决 R1）。
- **应补 TDD**：注入小上限，断言超限返回明确错误且原归档仍可打开；测量 RSS 随追加字节增长（可断言“追加 N 字节后进程 RSS 增量 ≪ N”）。

### R3【Medium｜性能；likely regression / benchmark-needed】`verify` 每卷 Catalog 读取的性能退化未被评估

- **锚点/机理/证据/建议**：同 §4.9。分类：**likely regression（相对 ee39fae 之前），benchmark-needed**；HEAD 只减少 1 卷读取。
- **确认**：代码事实 confirmed；影响量级 inference。

### R4【Low｜并发与一致性/失败原子性】`--force` 崩溃会留下隐藏备份文件，原路径消失

- **锚点**：`chunk_processor.rs:579-594`（备份命名/rename）、`:98-150`（仅显式失败路径恢复）；无启动时恢复逻辑。
- **机理**：rename-aside + 失败回滚只覆盖可捕获错误；SIGKILL/断电时备份文件保留、新文件可能半成品；下次运行不会自动把备份 rename 回原路径。
- **确认**：代码路径 confirmed；崩溃后用户影响 inference（数据仍在 `.era_overwrite_backup_*` 中，可手动恢复）。
- **分类**：新失败模式（相对修复前“直接删除原文件”仍是净改善，但引入了“原路径缺失 + 隐藏备份”的恢复负担）。
- **建议/测试**：启动时检测并提示/恢复残留备份；加模拟崩溃（子进程 kill）后恢复语义测试。

### R5【Low｜并发与一致性/持久化语义】append 期间无任何持久进度；checkpoint 提交退化为内存操作

- **锚点**：`crates/era-volume/src/writer.rs:504-513`（staged 时 `commit_checkpoint` 直接 Ok）、`:661-673`（checkpoint 块进 `staged.buf`）。
- **机理**：append 会话内 checkpoint 块与指针均只在内存；进程崩溃后本次 append 的所有进度（包括 checkpoint）丢失，只能从旧归档状态重来。原文档“crash 后自动从 checkpoint 恢复”的承诺已删除（`crates/era-engine/src/writer.rs:350-360` 更新文档，属诚实修正），但语义退化未在 API 文档/审计记录中显式声明。
- **确认**：code confirmed。
- **建议**：文档化“append 会话不是增量的、只有 finalize 才持久”；或提供“间歇 flush + 中间合法 footer”的可选模式。

### R6【Low｜代码质量】审计测试仍耦合源码字符串（§4.10 残留）

- 见 §4.10；`adversarial_audit_v3.rs:276-315`、`adversarial_audit_v2.rs:41-50`。

### R7【Low｜代码质量/文档】crate 级 AGENTS 统计与根 AGENTS 生成元数据仍过期（§5.3 残留）

- 见 §5.3；`AGENTS.md:3-4`、`crates/era-engine/src/AGENTS.md:10-18`、`crates/era-volume/src/AGENTS.md:13`。

### R8【Low｜工程/流程】审计文档纳入版本库的方式仍脆弱（§5.1 残留）

- 锚点：`.gitignore:27` 仅放行 `!docs/*-2026-11-*.md`；本机 `~/.config/git/ignore:29` 整体忽略 `docs/`；本文件 `docs/audit/round1-prior-closure.md` 即被 ignore。
- 影响：后续审计/验收文档默认不会进版本库（除非 `git add -f` 且文件名匹配），证据链可能再次断裂；CI 无“审计文档是否存在/被跟踪”检查。
- 确认：confirmed（`git check-ignore` 实测）。
- **建议**：仓库级放行 `docs/audit/**`（并提醒 `git add -f`），或在 CI 增加“docs/audit 非空且 tracked”检查。

### R9【Low｜工程/流程】flake 未跟踪 + fuzz workload 静默空转（§5.2 残留）

- 见 §5.2；`flake.nix`/`flake.lock` 未跟踪；`fuzz/` 不存在，`fuzz.yml` 现在会“成功跳过”。
- 影响：Nix 可复现构建链仍不在版本库；fuzz 门禁给人“已配置”的错觉但零覆盖。
- 确认：confirmed。**建议**：跟踪 flake；CI 明确输出“fuzz skipped (workspace absent)”为 notice 且 README 已标注 Planned（已做）。

### R10【Informational｜规格符合性】catalog 校验收紧导致 accept→reject 边界变化

- 锚点：`reader.rs:2885-2934`；`chunk_processor.rs:388-401,767-800`。
- 影响：对 writer 不会产生的异常 catalog（零 chunk File 条目、混用 packed_info、非连续偏移、长度和不等于 size），旧版 extract/verify 可能静默跳过或部分成功，HEAD 一律报错。对旧数据/第三方工具产物是行为变化；对安全/一致性是改善。
- 确认：confirmed（代码 + 测试）；无迁移说明。**建议**：在 CHANGELOG/格式文档记录该收紧；若有 v8.1 兼容需求，可加“宽松模式”开关。

### R11【Low｜代码质量/测试】`concurrency_torture` 仍为 5s 墙钟 + 50ms 延迟断言（§5.4 残留）

- 锚点：`crates/era-engine/tests/concurrency_torture.rs:36,88-92`。
- 影响：共享/慢 CI 上 `max_delay < 50ms` 可能 flaky；5s 固定耗时。确认：code confirmed。**建议**：改用可注入时钟或放宽为“相对基线倍数”，并在 CI 标为非阻塞。

### R12【Informational｜性能】`verify` 新增每卷 2×4 KiB 备份头读

- 锚点：`reader.rs:2839-2853`。属 §4.2 建议的成本（每卷 4 KiB 级），非回归；仅记录为预期成本。

---

## 4. 事实 vs 推断 / 未能核实的前序声明

| 项 | 事实（已核实） | 推断/未核实 | 依据 |
|---|---|---|---|
| 门禁全绿 | `/tmp/era_ci_baseline2.log`：`fmt_rc=0`、`clippy_rc=0`、`ws_rc=0`；164 suites/2916 passed/0 failed | 未由我独立复跑全量（任务要求不重复跑）；`ulimit -n 1024` 条件来自 lead/round0 文档，日志本身不包含该 shell 前缀 | `/tmp/era_ci_baseline2.log` 分段求和；`docs/audit/round0-baseline.md:14-21` |
| §4.1 “P0 已闭环” | finalize 前中断可恢复（3 个负例测试 + 探针 A） | finalize 中崩溃仍不可恢复（探针 B 用 IO 注入模拟，非真实 SIGKILL/断电；但产生的磁盘状态等价） | `resid_high03_checkpoint_append.rs:493/588/644`；探针输出 |
| §4.2 “覆盖仍可解析备份头” | 逐卷读取/摘要校验/可修复，测试通过 | 旧格式无摘要表时只有字节比较（降级路径） | `reader.rs:2818-2882`；`resid_high02_header_repair.rs:293` |
| §4.3 “保留用户原文件” | 可捕获失败路径保留（内容+权限断言） | 崩溃（kill/断电）会留下隐藏备份、原路径消失（R4，未做 kill 实测） | `find11_extract_overwrite_tests.rs:167` |
| §4.9 “已修复” | 只减少 1 卷读取 | 性能影响未 benchmark，无法确认/否认量级 | `reader.rs:2769-2796` vs `git show ee39fae` |
| §5.2 “工具链/依赖可复现” | Cargo.lock 已跟踪、toolchain=stable、fuzz.yml 容错 | flake 仍未跟踪；fuzz 仍为零覆盖 | `git ls-files`；`git check-ignore flake.*` |
| §5.3 “统计已对齐” | README/根 AGENTS 核心数字实测正确（2916/17/164、265、141.7k、4586） | crate 级 AGENTS 与根头部 commit 仍过期 | 见 §5.3 证据 |
| “零技术债/无遗留” | — | **不成立**：7/14 PARTIAL + 12 项残留（含 1 High、1 Medium） | 本文件 §0/§3 |

---

## 5. 工作区卫生说明（重要，交付前需处理）

- 我创建的临时探针 `crates/era-volume/tests/zz_prior_closure_probe.rs` 已在结束前删除（`rm` 后确认不存在）。
- 撰写本文件时 `git status --porcelain --untracked-files=all` 仍显示**两个 peer 审计线程创建的未跟踪临时探针**：
  - `crates/era-engine/tests/zz_probe_footer_integrity.rs`
  - `crates/era-volume/tests/zz_probe_finalize_atomicity.rs`
  这两个文件**不是我创建的**，我未删除以避免破坏其他线程正在进行的复现；请其 owner 或负责人在最终交付前删除，否则工作区不满足“git status 干净”。
- 本文件 `docs/audit/round1-prior-closure.md` 按任务要求写入且不 commit；它被用户级 global ignore（`~/.config/git/ignore:29 docs/`）标记为 ignored，因此不会出现在 `git status` 中（这也是 R8 的实证）。

---

## 6. 复现命令清单（本报告引用的全部关键命令）

```bash
# 1) 提交与改动面
git log --oneline -6
git show --stat 8c42a4c 31d358f 5ff825e b22a07e
git diff ee39fae..HEAD -- crates/era-volume/src/writer.rs crates/era-engine/src/writer.rs crates/era-engine/src/reader.rs crates/era-engine/src/repair.rs crates/era-engine/src/chunk_processor.rs

# 2) 定向回归（release；显式 nix PATH）
cargo test --release -p era-engine --test resid_high03_checkpoint_append -- --test-threads=2
cargo test --release -p era-engine --test resid_high02_header_repair -- --test-threads=2
cargo test --release -p era-cli --test resid_high02_cli_repair -- --test-threads=1
cargo test --release -p era-engine --test find11_extract_overwrite_tests -- --test-threads=2
cargo test --release -p era-engine --test bounded_fd_extraction_tests -- --test-threads=1
cargo test --release -p era-engine --test adversarial_audit_v3 -- --test-threads=2
cargo test --release -p era-storage -- --test-threads=1

# 3) 计数证据
git grep -n "#\[ignore" -- "*.rs"
grep -rn "allow(dead_code)" crates/*/src bins/*/src | wc -l
git ls-files "*.rs" | wc -l
cat $(git ls-files "*.rs") | wc -l

# 4) 全量门禁（引用 lead 日志）
grep -o "test result: ok\. [0-9]* passed; [0-9]* failed; [0-9]* ignored" /tmp/era_ci_baseline2.log
```

---

*本文件由 Round 1 独立整改核验线程生成（HEAD b22a07e，基线 ee39fae）。所有结论区分 confirmed / inference；性能断言标注分类；未修改源码/测试/既有文档。*
