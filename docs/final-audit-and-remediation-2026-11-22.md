# ERA-CORE 全仓复审与两轮修订报告（2026-11-22）

- **仓库**: `/home/ricardom/code/github.com/zapsaang/era-core`，分支 `feat_fly`
- **审计基线**: `b22a07e`（工程师声称"已修复全部问题、零技术债、无遗留"的提交）
- **最终状态**: 在 `b22a07e` 之上应用本报告所述两轮修订（工作树未提交，27 个跟踪文件修改 +2461/−878，7 个新增测试文件）
- **工具链**: Nix store `cargo 1.99.0` / `rustc 1.99.1` / `clippy 0.1.99` / `rustfmt 1.10.0`（本会话 rustup stable shim 损坏，全部命令显式 PATH；CI 使用 `stable` + `--locked`）
- **审计方式**: 5 个独立审计线程（前序闭环核验 / engine 写路径 / engine 读路径+CLI / L0–L3 低层 / 全仓卫生）→ 合并仲裁 → 4 个修订 fixer → 3 个 Round-2 复核线程 → 3 个 Round-2 修订 fixer → 冻结树全量门禁
- **证据附件**: `docs/audit/round0-baseline.md`、`docs/audit/round1-*.md`（5 份）、`docs/audit/round2-*.md`（3 份）、`docs/audit/round1-consolidated.md`
- **门禁日志**: `/tmp/era_ci_baseline2.log`（基线）、`/tmp/era_ci_final.log`（最终）

---

## 一、最终结论

1. **工程师"已修复仓库全部问题、零技术债、无遗留"的声明不成立。**
   - 基线 `b22a07e` 上，前序 14 项整改仅 7 项完全闭环、7 项部分闭环；另确认 30 项新/遗留问题（含 2 项 High）。
   - 两轮修订后，**12 项 High/Medium 已被真实修复**（含 1 项修订过程中引入、被 Round-2 抓出的 High 回归），**门禁在冻结树全绿**，但仍有 **1 项 High（append finalize 崩溃窗口）+ 2 项 Medium（staged append 内存放大、可增长卷 finalize 缺 fdatasync）属于架构/资源类遗留**，以及一批 Low/Info 级已知限制。
2. **当前工作树相对 `b22a07e` 是净改进且未引入未修复回归**：最终 `fmt`、`clippy -D warnings`、CLI 测试、workspace 测试全部通过（`ulimit -n 1024`）；Round-2 对修订本身做了对抗性复核并修复了其引入的全部阻塞问题。
3. **放行建议**：
   - 可以合并/交付当前修订（它修复了前序 High/Medium 与多项安全/一致性缺陷，且门禁全绿）；
   - **不能按"零遗留"结项**：RF-01（append finalize 崩溃窗口）、RF-03（append 内存 O(append)）、RF-06（可增长卷 finalize 屏障）需单独立项排期；其余 Low/Info 见问题清单。
   - 建议下一步 P0：finalize 原子化（临时卷 + 原子 rename，或持久化 append journal），staged append 落盘 spool，以及可增长卷 finalize 的 sync 顺序修正。

---

## 二、基线与最终门禁实测（事实）

### 2.1 审计基线 `b22a07e`（复跑确认工程师自述门禁）

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
bash -c 'ulimit -n 1024; cargo test --release -p era-cli'
bash -c 'ulimit -n 1024; cargo test --release --workspace'
```
结果：fmt=0、clippy=0、CLI **500 passed/0 failed/3 ignored（16 suites）**、workspace **2916 passed/0 failed/17 ignored（164 suites/doc-tests）**，合计 **3416 passed/0 failed/20 ignored**（`/tmp/era_ci_baseline2.log`）。基线门禁确实是绿的——这也是"看起来都修好了"的原因；缺陷在语义层，门禁未覆盖。

### 2.2 最终冻结树门禁（两轮修订后）

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
bash -c 'ulimit -n 1024; cargo test --release --locked -p era-cli'
bash -c 'ulimit -n 1024; cargo test --release --locked --workspace'
```
结果（`/tmp/era_ci_final.log`）：

| 阶段 | suites/doc-tests | passed | failed | ignored |
|---|---:|---:|---:|---:|
| fmt / clippy | — | — | 0 | — |
| era-cli | 18 | 518 | 0 | 3 |
| workspace | 171 | 2974 | 0 | 17 |
| **合计** | **189** | **3492** | **0** | **20** |

补充：`cargo test --release --locked -p era-engine --test hygiene_guards_test` → 6/6 通过（含 README 统计单源校验、CI 可复现性校验、自证式测试检测负例）。README/AGENTS 统计已刷新为上述最终值；`find crates bins -name '*.rs'` = 272（265 tracked@b22a07e + 7 新增回归测试文件）。

---

## 三、前序 14 项整改闭环核验（re-audit 2026-11-21 §4/§5）

> 详细逐项证据见 `docs/audit/round1-prior-closure.md`。基线 `b22a07e` 结论：FIXED 7 / PARTIAL 7 / NOT FIXED 0 / REGRESSED 0。

| 项 | 基线结论 | 本轮复核要点 | 两轮修订后状态 |
|---|---|---|---|
| §4.1 中断 append 后归档不可打开 | PARTIAL | finalize **之前**中断已安全（负例测试 12/12，文件逐字节不变）；但 finalize 内部先 truncate、后写 footer，窗口内崩溃仍毁归档；且 staged 全量驻留内存 | **仍 PARTIAL/OPEN（High，RF-01/RF-03）** |
| §4.2 verify 不校验备份头 | FIXED | 逐卷读 primary/backup 4096B 并用 manifest 摘要表认证；cli 3/3、engine 6/6 通过 | 已闭环，且 Round-2 追加 footer 冗余校验/修复 |
| §4.3 `--force` 失败删除原文件 | FIXED | rename-aside + 失败回滚；原内容/0444 权限保留、无备份残留 | 已闭环 |
| §4.4 非 EC 主头被数据损坏连坐 | FIXED | 先写回已认证主头再报数据不可修，CLI 文案同步 | 已闭环 |
| §4.5 单块解包缺 fsync | FIXED | 三条解包路径均 `sync_all` | 已闭环（目录 fsync 仍缺，Low RF-15） |
| §4.6 懒句柄重开 TOCTOU | FIXED | `O_NOFOLLOW` + `(dev,ino)` 校验 | 已闭环（父目录 TOCTOU 残余，Low RF-16） |
| §4.7 死代码/大面积 allow | PARTIAL | 模块级 `#![allow(dead_code)]` 已删，但生产 src 仍有 41 个 item 级 `allow(dead_code)`、49 个零引用 pub fn | **仍 PARTIAL（Medium RF-09，已知债务）** |
| §4.8 尺寸/零 chunk 校验 | FIXED | `validate_regular_file_chunks` 双端调用；Directory/Symlink 条目仍被静默忽略（RF-11） | 已闭环（条目类型为独立规格缺口） |
| §4.9 verify 每卷读 Catalog | PARTIAL | 仅少读 1 卷；无非 EC repair 重复 verify 的基准测量 | **仍 benchmark-needed（RF-17，接受）** |
| §4.10 源码字符串耦合测试 | PARTIAL | engine+cli 仍有 139+ 处 `include_str!("../src…")` 断言 | **仍 OPEN（RF-19，接受为大规模重构债）** |
| §5.1 docs 未入库 | FIXED | 4 份 11 月文档已跟踪；`.gitignore` 已放行 `docs/audit/` | 已闭环（全局 ignore 对 6 份历史 docs 仍生效，RF-10 环境限制） |
| §5.2 Cargo.lock/工具链/fuzz | PARTIAL | Cargo.lock 已跟踪、CI 全 `--locked`、ulimit/timeout 已加、fuzz.yml 缺失时跳过；`flake.nix/flake.lock` 仍未跟踪 | **仍 PARTIAL（RF-24；flake 为工程债）** |
| §5.3 统计与文档漂移 | PARTIAL | README/AGENTS 已按最终实测刷新并由 `hygiene_guards_test` 单源守护；crate 级 AGENTS 行数表仍有历史漂移 | 基本闭环（Low） |
| §5.4 测试质量 | PARTIAL | pwrite/resilience 已修；仍有无断言历史测试（Round-1 已修 7 个）、墙钟断言、`#[path]` 重复编译 | 大部分闭环（RF-25/26 接受） |

---

## 四、两轮修订修复的主要缺陷（Round 1 + Round 2）

完整清单见 `docs/issue-list-2026-11-22.md`。以下为 High/Medium 与关键 Low：

### 4.1 Round-1 审计确认、Round-1 修订修复

| 编号 | 严重度 | 问题 | 修复要点 | TDD 证据 |
|---|---|---|---|---|
| ENG-RC-01 | High | 解包全局累计 8 GiB 上限：>8 GiB 去重后数据的合法归档必然解包失败，并清理已写文件 | 取消隐藏全局上限；`ExtractOptions.max_total_output_bytes: Option<u64>`（opt-in），保留 per-block/per-chunk/per-file 炸弹防护 | 旧 API 编译 red（E0609/E0599）→ 新行为测试 green；adversarial_audit_v2 由源码字符串改为行为断言 |
| ENG-RC-02 | Medium | verify/repair 不覆盖 footer 冗余：主 footer 损坏静默回退仍 exit 0；4096 备份 footer 损坏不可见不可修 | `VolumeReader` 增加 `footer_recovered_from_backup`；verify 对两份 footer 校验并降级；repair 从幸存副本写回主/备 footer（checkpoint 卷不越界写数据区） | 主/备 footer 损坏→Degraded→repair→Healthy 行为测试 |
| ENG-RC-03 | Medium | `era create` 静默丢弃 symlink/空目录/不可读子树（`filter_map(e.ok())`）且 rc=0 | 遍历错误硬失败并带路径；symlink/特殊文件硬失败；空目录 warn+汇总 | CLI 9 项回归测试 red→green |
| ENG-RC-05/06/07 | Low | repair 不存在路径 exit 0；Degraded 文案一律"卷缺失"；repair 死分支 | 分别改为非零退出、按 missing_indices 区分文案、删除不可满足分支 | CLI 测试 red→green |
| LL-04 | Medium | 活跃 SuperHeader 未与 manifest 摘要认证，未入 AAD 的 config 被直接信任 | open 时对非恢复卷校验 primary header 摘要（fail-closed） | 头篡改测试 |
| LL-05 | Low | era-ingest 公共 API 对非法 ChunkerConfig panic | Round-1 增加 try_new/校验；Round-2 进一步把 `Chunker::new` 改为返回 `Result`，非法配置不再静默回退默认布局 | ingest 契约测试 red→green |
| LL-06/07 | Low | LocalStorageBackend::create 跟随 symlink/缺父目录 fsync；read_all_from 下溢 | `O_NOFOLLOW`+父目录 fsync（best-effort）；offset≥size 返回空 | storage 5 项 hardening 测试 red→green |
| H-03 | Medium | 1 个空体测试 + 6 个恒过测试计入验收统计 | 7 个测试改为真实断言；新增 `hygiene_guards_test` 扫描器（含负例自测） | 门禁 red→green |
| H-05/H-08 | Low | CI 未 `--locked`/无 ulimit/timeout；README 两套互斥统计、AGENTS 引用数漂移 | CI 三个 job 全部 `--locked`+ulimit+timeout；README/AGENTS 按可复现命令重算并由门禁单源守护 | YAML 解析 + 门禁测试 |

### 4.2 Round-2 复核发现、Round-2 修订修复（含修订自身引入的回归）

| 编号 | 严重度 | 问题 | 修复要点 |
|---|---|---|---|
| R2-01 | High（阻塞） | Round-1 的 header digest 硬校验把"可解析但摘要不匹配"的主头损坏变成**不可打开**，导致既有 header repair 路径不可达，CLI 门禁变红（`random_offset_corruption::test_repair_corruption_at_multiple_offsets`） | 摘要不匹配时：读取并校验 reserved backup header，只有其摘要也匹配 manifest 才采纳为工作头并标记 degraded；两份都不匹配才 fail-closed。新增"单头篡改可恢复 + 双头篡改 fail-closed"测试；CLI 门禁回绿 |
| R2-02 | Medium | 主/备 footer 都坏、靠 floating footer 恢复的卷：repair 报成功但零写回，永不收敛 | 用 floating footer 重建：canonical 布局成立时写回两处 footer 并截断尾部垃圾；布局不成立返回 `IntegrityError`（非零退出），绝不假报成功 |
| R2-03/R2-04 | Medium | 输出预算按"解码字节"计费，dedup/fanout 时实际写盘量可远超预算；CLI 无预算入口；verify 不复用 | 预算改为按 `stats.bytes_written` 实际写盘增量计费（dedup fanout 测试 red→green）；CLI `extract --max-output-bytes` 入口 + README |
| R2-05 | Low | footer/header 修复缺矩阵、dry-run、floating、多卷 adoption 等测试 | 新增 8 项 Round-2 引擎测试（12 卷 EC footer 修复、dry-run 不写、floating 正向/不可修、双头清零、多卷 adoption 等） |
| R2-08 | Low | 参与 manifest AAD 的 header 字段被可解析篡改时 manifest 先解密失败，backup 头采纳不可达 | manifest 解密失败时用 reserved backup header 的 AAD 重试一次，成功后采纳备份头并用 AEAD 认证的 AAD 校正 archive_id/epoch_id，再由 manifest digest 表兜底 |
| R2-STOR-01 | Medium | 新目录 fsync 对相对裸文件名（parent=""）失效并每卷打 WARN | 空 parent 归一化为 "."，non-unix no-op；新增路径归一化单测 |
| R2-CLI-02 | Medium | create 对树内 symlink 硬失败且无逃生口、未文档化 | 新增 `create --skip-symlinks`（warn+计数+exit 0），默认仍硬失败；help/README 文档化；两种模式均有测试 |
| R2-ING-01 | Medium | `Chunker::new` 非法配置静默回退 default，入口契约分叉 | `Chunker::new -> Result<Self>`（非法即 Err，不再静默改变 chunk 布局），仓库内全部调用点更新 |
| R2-04（测试可信度） | Medium | 4 个"修复后"的分布/容错测试在测试内重算算法，不调用生产实现（自证式） | 重写为调用生产 `MatrixDistributionStrategy`/真实归档布局/生产容错路径的端到端断言；hygiene 门禁新增"矩阵审计必须调用生产 API"负例 |

---

## 五、仍未闭环 / 接受为已知限制（必须如实记录）

| 编号 | 严重度 | 问题 | 现状与理由 | 建议 |
|---|---|---|---|---|
| RF-01 | **High** | append `finalize()` 仍先 `truncate` 旧元数据、后写新 footer（`era-volume/src/writer.rs:256-265,832-877`）：finalize 期间崩溃/取消/IO 失败会使原归档不可打开；finalize 之前的中断窗口已由 `8c42a4c` 闭合 | **未修**：正确修复需改 append 持久化协议（临时卷+原子 rename，或 journal），涉及 `StorageBackend` 扩展，超出本轮安全改动范围；当前已在 3 个测试中固定"finalize 前可恢复"的既有承诺 | P0：finalize 原子化或写回合法中间 footer 协议 + 故障注入负例 |
| RF-03 | **High/Medium** | staged append 把整段追加数据缓存在内存（`StagedAppend.buf`，上限≈`max_volume_size`，默认 GiB 级），append 体积与 RSS 线性增长；轮转后的 retired 卷也驻留 staged | **未修**：修需落盘 spool/journal（泛型 `StorageWriter` 接口需扩展）；已在报告与 README 记录该资源特性，避免误用 | P0/P1：spill-to-disk 或改为原子临时卷；补内存/大 append 基准 |
| RF-06 | Medium | 可增长卷（无 max_size）finalize 覆盖 offset 4096 恢复 footer 前缺 `fdatasync` 屏障（定长卷分支有） | **未修**：当前引擎创建的卷均定长（`with_max_size`），可增长路径主要为库/历史用法；需补 mock writer 断言 sync 顺序的测试后再改 | P1：与 RF-01 一并设计持久化顺序 |
| RF-09 | Medium | 生产 src 仍有 41 个 `allow(dead_code)`、49 个零引用 `pub fn`（前序点名的 8 个中 7 个仍在） | 未修：机械清理面大、需逐项判断是否未来 API；不阻塞正确性 | P2：清理并逐项注明保留理由 |
| RF-11 | Low | 读路径不实现 Directory/Symlink 条目（静默忽略）；README 曾称 symlinks rejected | 现状：writer 不产出这些条目；create 现对 symlink 硬失败/可跳过，语义已显式化；读路径支持是新功能 | 如有需求单独立项 |
| RF-15/16 | Low | 解包未 fsync 目录；`--force` rename→create 崩溃窗口使目标缺失；父目录 TOCTOU 残余；metadata 恢复按路径重开 | 已部分修复（rename-aside/回滚、O_NOFOLLOW+inode 校验）；剩余窗口为崩溃/竞态边界 | P2：目录 fsync、openat 化 |
| RF-17 | Low | verify 每卷完整读 Catalog（likely regression）、非 EC repair 重复 verify | benchmark-needed；正确性无问题 | 评测后决定抽样/摘要校验 |
| RF-19 | Low | 139+ 处 `include_str!("../src…")` 源码字符串耦合测试 | 大规模重构债，不影响运行时正确性 | 逐步改行为测试 |
| RF-18 | Low | verify 不检查 `entry.size > 100 GiB`，extract 检查（判定不一致） | 未修，低风险 | 统一到 catalog 校验函数 |
| RF-23 | Low | protobuf→域模型转换缺跨字段校验（BlockChunkIndex.count 等） | 防御纵深，当前调用方受限 | P2 |
| RF-10 | Informational | `docs/` 被用户级全局 gitignore 覆盖；本轮 `docs/audit/` 已由仓库规则放行，但 6 份历史 docs 仍不可跟踪 | 环境配置问题，非仓库代码缺陷 | 提交时对历史 docs 使用 `git add -f` 或修复全局 ignore |
| RF-25/26/28 | Low/Info | `#[path]` 把生产模块编入集成测试、墙钟断言、src 内联 `#[cfg(test)]` 13.5k 行 | 测试结构/稳定债务 | 逐步迁移，收益中等 |
| RF-30 | Info | VK wrap AAD 未绑定卷、encode_shards 静默补零、mlock 诊断路径未 munlock 等 | 无实际可利用性/仅诊断路径 | 观察项 |

---

## 六、变更清单（工作树，未提交）

**修改（27 个跟踪文件，+2461/−878）**：
- 核心修复：`crates/era-engine/src/{reader.rs,repair.rs}`、`crates/era-volume/src/reader.rs`、`crates/era-ingest/src/{chunker.rs,chunker/config.rs,chunker_zerocopy.rs,reader.rs}`、`crates/era-storage/src/local.rs`、`bins/era-cli/src/{commands.rs,main.rs}`
- 测试更新：`crates/era-engine/tests/{adversarial_audit_v2,deep_verification_test,fault_tolerance_test,mandatory_defaults,root_cause_analysis_test,security_tests,shard_analysis_test,third_audit}.rs`、`crates/era-codec/tests/adversarial_audit_v9.rs`、`bins/era-cli/tests/{cli_extreme_tests,cli_integration_tests,cli_integration_tests_comprehensive}.rs`、`crates/era-ingest/benches/ingest_bench.rs`
- 工程/文档：`.github/workflows/ci.yml`、`.gitignore`、`README.md`、`AGENTS.md`

**新增（7 个测试文件）**：
`crates/era-engine/tests/{round1_reader_fixes.rs,round2_engine_fixes.rs,hygiene_guards_test.rs}`、`bins/era-cli/tests/{round1_cli_create_repair_tests.rs,round2_cli_revision_tests.rs}`、`crates/era-ingest/tests/chunker_config_validation.rs`、`crates/era-storage/tests/local_backend_hardening.rs`

**证据文档（`docs/audit/`，10 份）**：round0 基线 + round1 五线程报告 + 合并清单 + round2 三线程报告。最终问题清单另见 `docs/issue-list-2026-11-22.md`。

**API/行为变更（需下游注意）**：
- `ExtractOptions` 新增 pub 字段 `max_total_output_bytes`（结构体字面量需补字段）；`Chunker::new` 改为返回 `Result`；`create` 默认拒绝目录树内 symlink（可用 `--skip-symlinks`）；`repair` 对不存在路径/不可修状态改为非零退出；CLI 新增 `extract --max-output-bytes`、`create --skip-symlinks`。

---

## 七、TDD 与验证纪律

- 所有修订均要求"先写失败测试并实跑 red → 修复 → green"；Round-1/2 各 fixer 报告均附 red→green 命令与关键输出（见 `docs/audit/round1-*.md` 与 round2 报告）。
- Root 自身修复 R2-01 的 red 证据为基线门禁的确定性失败（`cli_coverage_gap_tests::random_offset_corruption::test_repair_corruption_at_multiple_offsets`，`cli_rc=101`），修复后定向测试与最终全量门禁均绿。
- 新增/重写的测试全部纳入自动发现（`crates/*/tests/\*.rs`），最终 workspace 与 era-cli 两阶段均 0 failed。

---

## 八、结论与放行建议

1. **"全部问题已修复、零技术债、无遗留"不成立**：基线仍有 2 High + 多项 Medium/Low 语义缺陷；两轮修订修复了其中绝大多数可安全修复项，但 append 持久化/资源类 3 项（RF-01/RF-03/RF-06）属于架构级遗留，不能声称"零遗留"。
2. **当前修订质量**：冻结树门禁全绿（3492 passed / 0 failed / 20 ignored，fmt/clippy 0 警告），修订自身引入的 1 项 High 回归（R2-01）已被 Round-2 发现并修复；无新增生产 unwrap/panic/thread_rng，无新增源码字符串测试。
3. **放行**：建议以"修复后合并 + 明确遗留清单"方式交付；在 RF-01/RF-03/RF-06 排期解决前，不应对外宣称结项/零技术债。若产品要求"零遗留"作为结项门槛，则当前**不满足**，需继续 P0 整改。
4. **可复现命令**：见 §2.2；全量证据日志 `/tmp/era_ci_final.log`（本机临时路径，报告内已固化关键数字与命令）。

---

*本报告基于 2026-11-22 冻结工作树（`b22a07e` + 两轮修订）生成；所有数字均来自实跑门禁日志与 `docs/audit/` 下的可审计证据，未以工程师自述为依据。*
