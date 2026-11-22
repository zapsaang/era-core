# Round-2 独立复核：era-cli / era-ingest / era-storage / CI / 卫生门禁（round 1 修订仲裁）

- **审计日期**: 2026-11-22
- **仓库/分支**: `/home/ricardom/code/github.com/zapsaang/era-core`，`feat_fly`
- **基线**: HEAD `b22a07e` + 工作树未提交的 round-1 修订（26 改 / +1247 −329，另有 5 个新增测试文件 + `docs/audit/`）
- **复核范围**: `bins/era-cli/src/{commands.rs,main.rs}`、`bins/era-cli/tests/{round1_cli_create_repair_tests.rs,cli_integration_tests.rs,cli_integration_tests_comprehensive.rs}`、`crates/era-ingest/src/{chunker.rs,chunker/config.rs,chunker_zerocopy.rs,reader.rs}`、`crates/era-storage/src/local.rs`、`.github/workflows/ci.yml`、`README.md`、`AGENTS.md`、`.gitignore`、`crates/era-engine/tests/hygiene_guards_test.rs`
- **只读约束**: 未修改任何源码/测试/文档；只写本文件。未 `git add`/`commit`，未删除他人文件。
- **方法**: 逐条读 diff 与上下文 → 与 round-1 报告结论对照 → **黑盒复现**（`target/release/era`，由当前工作树编译）→ 直接运行已编译的定向测试二进制（避开与负责人后台门禁的 cargo 锁争用）→ 静态门禁/YAML/统计数字机器核对。
- **判据**: 每条区分 confirmed（有命令+输出/代码路径确定）/ inference（需外部条件，未复现）。

---

## 1. 总体结论

1. round-1 修订中**大部分低层修复本身成立**（CLI create 的"不静默丢数据"、repair 缺路径非零退出、footer 冗余检测、O_NOFOLLOW、read_all_from 下溢、Chunker 非法配置不 panic、CI `--locked`+ulimit+timeout、AGENTS CODE MAP 引用数），定向测试与黑盒复现均通过（见 §4）。
2. 但 **"全部修复且门禁全绿" 的声明不成立**：负责人后台门禁 **`cli_rc=101`**，`-p era-cli --test cli_coverage_gap_tests` 有 1 个测试失败；根因是**本轮 reader 修订新增的 SuperHeader 认证摘要校验在 `ArchiveReader::open` 里硬失败**，使 `era repair` 无法修复"头部被篡改但仍可解析"的归档（R2-CLI-01，**High**，`/tmp/era_ci_round1.log:95,170,173`；本人黑盒 100% 复现）。
3. 修订**自身引入**了 1 个新的存储层 bug：目录 fsync 硬化对**最常见的相对输出路径** `era create -o backup.era` 完全无效，且每次卷创建输出一条 WARN（默认 6 卷 → 6 条），把"加固"变成了"静默失效 + 日志噪声"（R2-STOR-01，Medium）。
4. 卫生/文档维度出现**"用源码字符串耦合门禁去修源码字符串耦合问题"**的自相矛盾，且新门禁只保证 README 数字"内部一致"、不保证"准确"；新增 5 个测试文件/33 个测试函数后 README/AGENTS 的 2916/265/141.7k 全部将过期（R2-HYG-01/02，Medium）。
5. 明确建议：**阻塞合并（block merge）**。至少 R2-CLI-01 必须修复并让 `cargo test --release --locked -p era-cli` 回绿后才能进入下一轮；R2-STOR-01 与 R2-HYG-01/02 建议同轮修复；其余 Low 可登记后跟进。**不建议整体回滚**——单点回滚 reader 的 header-digest 校验会重新打开 LL-04，应改为"按调用场景分级"。

### 1.1 发现汇总

| 编号 | 严重度 | 维度 | 标题 | 与 round-1 修订的关系 | 确认程度 |
|---|---|---|---|---|---|
| R2-CLI-01 | **high** | 规格符合性 / 数据可用性（CLI 契约） | `ArchiveReader::open` 新增 header-digest 硬校验，`era repair` 无法修复可解析的 header 篡改；CLI 门禁红 | 修订**引入**（LL-04 修复过度严格） | confirmed（门禁日志 + 黑盒复现） |
| R2-CLI-02 | medium | 规格符合性 / 兼容性 | create 对目录树内任意 symlink 硬失败且无策略开关，README 未文档化；常见目录树（node_modules/.config）整次备份失败 | 修订引入（ENG-RC-03 的规格选择） | confirmed（黑盒 + 源码） |
| R2-STOR-01 | medium | 正确性 / 持久化 / 可观测性 | `sync_parent_directory` 对空 parent 处理错误：相对裸文件名输出时目录 fsync 静默跳过、每次卷创建一条 WARN | 修订**引入**（LL-06 修复的缺陷） | confirmed（黑盒计数复现） |
| R2-ING-01 | medium | 规格符合性 / 静默行为漂移 | `Chunker::new` 对非法配置"warn+回退默认"，静默改变 chunk 布局；同一非法配置在不同入口表现不一致（静默回退 vs Err） | 修订引入（LL-05 修复的设计选择） | confirmed（代码 + 测试）；生产可达性有限（inference） |
| R2-HYG-01 | medium | 代码质量 / 测试可信度 | `hygiene_guards_test` 本身是跨 crate 的源码字符串耦合测试，与 H-04/ENG-RC-12 结论自相矛盾；合法重构误红，`assert!(true)` 可绕过 | 修订引入（H-03/H-04 的"修复"） | confirmed（代码 + 已运行 4/4 通过） |
| R2-HYG-02 | medium | 文档准确性 / 测试可信度 | README 统计只被保证"内部一致"而非"准确"：2916/0 failed/17 ignored/265 文件/141.7k 在本次提交后全部失真；"17 ignored" 静态不可复现（3+9=12） | 修订声称修复 H-08 但不成立 | confirmed（统计命令） |
| R2-REPAIR-01 | low | 代码质量 | ENG-RC-07 修完后 `match archive_health { Healthy => {} }` 变成新的不可达死代码（死代码从旧位置搬到新位置） | 修订引入 | confirmed（布尔推导 + chunk_processor.rs:904-919） |
| R2-REPAIR-02 | low | 规格符合性 / 可运维性 | repair 缺路径 exit 0→1 是 CLI 契约变更，README/help 均未文档化（help 无退出码语义；README 只写"Try era repair first"） | 修订引入（行为合理、文档缺口） | confirmed |
| R2-VERIFY-01 | low | 可运维性 | verify Degraded 的 warning 先在 `warn!` 循环打印，又被拼进 `anyhow::bail!` 文案，stderr 同一 warning 出现两遍；新测试只断言 contains | 修订引入 | confirmed（黑盒 stderr） |
| R2-HYG-03 | low | 测试可信度 | `ci_workflow_is_reproducible` 断言"文本出现次数"而非其声称的不变量（timeout 是否在 job 上、ulimit 是否与 cargo test 同一 run block） | 修订引入 | confirmed（代码 + ci.yml） |
| R2-CI-01 | low | 文档准确性 / CI | README:364 声称本地命令匹配 CI 资源限制，但 README:366-372 / AGENTS:104 的命令块没有 `ulimit -n 1024`；"matches ci.yml exactly" 不成立 | 修订引入 | confirmed |
| R2-CI-02 | low | CI 结构 | test-workspace 重复执行 era-cli 测试（既有 I-01）+ cargo 默认 fail-fast：CLI 一红，workspace job 在 era-cli 处再次中止，本轮新增的 ingest/storage/hygiene 用例在 CI 中实际不会被跑到 | 既有结构 + 本轮失败放大 | confirmed（日志） |
| R2-STOR-02 | low | 性能 | 每次 `create` 一次父目录 fsync（默认 6 卷 → 6 次/归档）；无基准证据 | 修订引入 | benchmark-needed（not proven） |
| R2-STOR-03 | low | 安全（防御纵深）/ 可移植性 | O_NOFOLLOW 常量与 cfg 列表硬编码且两处重复；只覆盖 linux/android/apple/BSD，solaris/illumos/aix/haiku/redox 等 unix 目标退化为 check-then-open（TOCTOU 仍在） | 修订引入 | confirmed（代码；非本机平台为 inference） |
| R2-CLI-03 | low | 性能 / 正确性（误报面） | `directory_is_empty` 对**每个**目录多做一次 `read_dir`；检查与 walkdir 实际遍历之间存在并发修改窗口，警告可能与实际归档内容不符 | 修订引入 | 代码确认；性能/竞态为 inference |
| R2-STOR-04 | informational | 可观测性 | Windows 上 `File::open(目录)` 必失败 → 每次 create 一条 WARN（未在 Windows 验证） | 修订引入 | inference |
| R2-GIT-01 | informational | 文档准确性 | `.gitignore:28-36` 注释声称"某些环境仍需 `git add -f`"，但实测仓库级 negation 已生效（`git check-ignore -v` 命中 `.gitignore:35:!docs/audit/**`，`git status` 显示 `?? docs/audit/`） | 修订引入（H-02 修复的注释） | confirmed |

**严重度统计（仅本轮确认项）**: high 1 / medium 5 / low 9 / informational 2，共 17 条。critical 0。
**建议**: 阻塞合并；不建议整体回滚。

---

## 2. 高/中严重度发现详述

### R2-CLI-01【HIGH】`ArchiveReader::open` 新增 header-digest 硬校验，`era repair` 无法修复可解析的 primary header 篡改；CLI 门禁因此变红

- **文件**: `crates/era-engine/src/reader.rs:1541-1547`（open 内的调用点）、`:2856-2884`（`verify_active_primary_headers` 实现）、`:2878-2880`（错误串）；受影响的 CLI 契约: `bins/era-cli/src/commands.rs:1281`（repair 的 `open_archive`）
- **维度**: 规格符合性 / 数据可用性（CLI repair 契约）
- **机理**: round-1 为 LL-04（"打开归档时不校验活跃 SuperHeader 的认证摘要"）新增了 `verify_active_primary_headers`，并在 `ArchiveReader::open` 的 manifest 装载阶段**无条件**对每个非"从 backup header 恢复"的卷，读原始 header 字节与 manifest 的 `volume_header_digests` 比对，任何不一致直接 `return Err(EraError::IntegrityError(...))`。
  问题在于：**"header 字节被篡改但仍能解析/魔数完好"正是 `era repair`（authenticated header/catalog repair 路径）要修的目标状态**。该校验发生在 open 期，导致 repair 在进入修复逻辑之前就失败；同时也让 `verify` 失去本轮新增的 Degraded 诊断（变成笼统的 "Failed to open archive"）。
- **证据（1）负责人后台门禁**（`/tmp/era_ci_round1.log`，工作树当前代码）:

  ```text
  test random_offset_corruption::test_repair_corruption_at_multiple_offsets ... FAILED
  ...
  command=`.../target/release/era repair /tmp/.tmp5bq3Ku/offset_1000.era --password pwd --force`
  code=1
  Error: Failed to open archive
  Caused by:
      Integrity error: Volume 0 primary header bytes do not match the authenticated manifest header digest
  ...
  error: test failed, to rerun pass `-p era-cli --test cli_coverage_gap_tests`
  cli_rc=101
  ```

  失败测试是**已跟踪、未被本轮修改**的既有回归测试 `bins/era-cli/tests/cli_coverage_gap_tests.rs:1467-1528`（对 7 个偏移逐一篡改后要求 `repair`/`verify`/`extract` 全成功）；`corrupt_archive_shard` 对 offset 处的 100 字节取反（`tests/common/mod.rs:143-158`），offset 1000 落在 4096 字节 header 区内且不破坏可解析性 → 命中新校验。offset≥4096 的用例通过。
- **证据（2）本人黑盒独立复现**（`target/release/era`，2026-11-22 02:0x 由当前工作树编译）:

  ```text
  create_rc=0                                   # era create f.txt -o a.era -p pwd
  # 在 offset 1000 写入 0xFF（等价于 corrupt_archive_shard 的效果）
  --- verify after offset-1000 corruption:
  verify_rc=1
  Error: Failed to open archive
  Caused by:
      Integrity error: Volume 0 primary header bytes do not match the authenticated manifest header digest
  --- repair after offset-1000 corruption:
  repair_rc=1
  INFO Archive appears complete. Running verification...
  Error: Failed to open archive
  Caused by:
      Integrity error: Volume 0 primary header bytes do not match the authenticated manifest header digest
  ```

  对照：offset 0（魔数损坏，走 backup header 恢复路径）时 repair 仍可修复成功——`repair_rc=0`（"✅ Archive successfully repaired!"），修复后 `verify_rc=0`。说明破坏的是**"可解析但字节被改"**这一子集。
- **确认程度**: confirmed（门禁日志 + 独立复现）。**注意**: 修复点位于 `crates/era-engine/src/reader.rs`（可能与其他 round-2 线程的 reader 范围重叠），但契约破坏与门禁证据在 CLI 侧，故在此登记，请仲裁时合并去重。
- **建议**:
  1. 分级校验：`open` 允许在 header digest 不匹配时**带 degraded 标记打开**（或至少提供给 repair 的专用打开路径），把"header 字节不符"作为 verify 的 Degraded warning，由 repair 去修；
  2. 或把 `verify_active_primary_headers` 从 `open` 移到 `verify()`（以及 extract 的严格模式），并新增"repair corrupted primary header"回归测试；
  3. 修好前不得声称"全部修复"，也不得合并。

### R2-CLI-02【MEDIUM】create 对目录树内任意 symlink 硬失败且无策略开关，README 未文档化；常见目录树整次备份失败

- **文件**: `bins/era-cli/src/commands.rs:579-590`（depth-0 特例与 symlink `bail!`）、`:625-630`（特殊文件 `bail!`）、`bins/era-cli/src/main.rs:51-57`（long_about 更新）；README 无对应说明
- **维度**: 规格符合性 / 兼容性（breaking change）
- **机理**: 旧实现 `filter_map(|e| e.ok())` + `file_type().is_file()` 静默跳过 symlink（round-1 ENG-RC-03 的确认项）。修订把"目录树内任何 symlink"改为**立即 bail**，错误串为 `Refusing to archive symbolic link '<path>': symlinks are not supported; remove or replace the link and re-run`。但：
  1. 没有任何选项（`--symlinks=skip|reject` / `--skip-symlinks`），也**不提供计数+继续**；一个 symlink 就让整次备份失败（例如 `node_modules/.bin`、`/home/*/.config` 的常见布局）；
  2. **显式命令行参数**仍是"跟随"语义（`std::fs::metadata`，`:544-546` 注释；根 symlink 被 walkdir 跟随并在 `depth()==0` 特例处理 `:579-583`，walkdir 2.5.0 `lib.rs:856-873` 会 push 根 symlink 但其 DirEntry 仍报告为 symlink——因此该分支可达，不是死代码），这一历史语义**只写在源码注释里**，`--help` 只写"inside walked directories are rejected"（`main.rs:53-56`），README 完全没有 create 的 symlink/空目录策略说明（`grep -i symlink README.md` 仅命中 :317 的解包安全描述）。
- **证据（黑盒）**:

  ```text
  --- P1 symlink-to-file in tree:   rc=1  Refusing to archive symbolic link 'src/link_file.txt': symlinks are not supported ... ; 无归档生成
  --- P2 symlink-to-dir  in tree:   rc=1  Refusing to archive symbolic link 'src/link_dir': ...
  --- P3 broken symlink   in tree:  rc=1  Refusing to archive symbolic link 'src/broken': ...
  --- P4 显式命令行 symlink（文件+目录）: rc=0；list 显示 lf.txt / ldir/a.txt / ldir/sub/b.bin  → 历史 follow 语义保持
  --- P5 空目录: rc=0 + WARN "Skipped 1 empty directory: the archive format stores files only..." + 路径
  --- P6 fifo:   rc=1  Refusing to archive 'src/pipe': unsupported file type (not a regular file or directory)
  --- P7 不可读子树: rc=1  Error: Failed to read directory 'blocked_src/blocked' / Caused by: Permission denied (os error 13)
  ```

  新增 `round1_cli_create_repair_tests` 的 9 个用例全部通过（见 §4），覆盖 symlink-in-tree / 不可读子树 / socket / 空目录 / 显式 symlink 保持 / repair exit / verify degraded / repair degraded。
- **确认程度**: confirmed（黑盒 rc/文案 + 源码路径 + README grep）。
- **建议**:
  1. 增加显式策略参数（`--symlinks=reject|skip|follow`，默认 reject 可保留"不静默"），或至少 `--skip-symlinks` 并输出"跳过了 N 个 symlink"计数；
  2. README 的 create/Features/Compatibility 章节补充该破坏性变更与迁移方法（"先自行替换/清理链接"）；
  3. 测试补齐 symlink-to-dir-in-tree、broken symlink、根 symlink 指向空目录等边界（现有测试只测了 symlink-to-file + 显式 symlink）。

### R2-STOR-01【MEDIUM】`sync_parent_directory` 空 parent 处理错误：相对裸文件名输出时目录 fsync 静默跳过 + 每次卷创建一条 WARN

- **文件**: `crates/era-storage/src/local.rs:69-91`（`let Some(parent) = path.parent()` 未处理空路径）、`:147`（每次 create 调用）、`:109-115`（`resolve_path`：`base_path.join(relative)`，base_path 可为空）
- **维度**: 正确性 / 持久化 / 可观测性（修订引入）
- **机理**: CLI 对 `-o backup.era` 这类**相对裸文件名**计算 `output.parent() == Some("")`，`LocalStorageBackend` 的 base 为空，`full_path = "backup.era"`，其 `path.parent()` 为 `Some("")`（**不是 None**），`File::open("")` 返回 `ENOENT`，于是：
  - LL-06 的"create 后 fsync 父目录"加固在**最常见调用方式下完全不生效**（静默）；
  - 每次 `create` 打一条 WARN。默认 4:2/6 卷 → 建一个归档打 6 条 `failed to open storage parent directory for fsync (best-effort) parent= error=No such file or directory (os error 2)`。main.rs `--help` 的 Quick Start 正是 `era create -o backup.era ./my-files`。
- **证据（黑盒计数，当前工作树二进制）**:

  ```text
  --- relative output:             6        # era create f.txt -o rel.era  → 6 条 WARN
  --- absolute output:             0        # -o $PWD/abs.era             → 0 条
  --- relative with parent dir:    0        # -o out/rel2.era             → 0 条
  ```

  WARN 原文（P11）：`WARN failed to open storage parent directory for fsync (best-effort) parent= error=No such file or directory (os error 2)`。新增测试 `crates/era-storage/tests/local_backend_hardening.rs` 只测 symlink/truncate/read_all_from，**没有任何 fsync 相关用例**，所以该 bug 未被覆盖。
- **确认程度**: confirmed（计数复现）。
- **建议**: `let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));`；补 unix 回归测试（相对裸文件名 → 无 WARN 且 fsync 目标为 `.`），或直接把该 helper 改为返回 `Result` 并在测试中注入失败。

### R2-ING-01【MEDIUM】`Chunker::new` 非法配置"warn+回退默认"：静默数据布局漂移，且同一非法配置在不同入口行为不一致

- **文件**: `crates/era-ingest/src/chunker.rs:34-54`（`new` 回退），`:61-64`（`try_new`），`:105-115`（`chunk_all_async` 用 `try_new` → Err），`:119-121`（`chunk_file` 前置 validate），`:180-199`（`StreamingChunker::new` 非法时 buffer=0），`:243-245`（`next_chunk` 前置 validate），`:312-317`（`into_stream` 经 next_chunk，安全）；`crates/era-ingest/src/chunker/config.rs:71-77`（移除 `assert!`）、`:86-117`（try_* 构造器）、`:123-141`（validate）；`crates/era-ingest/src/reader.rs:285-306,323-335`；`crates/era-engine/src/writer.rs:1031-1039`
- **维度**: 规格符合性 / 静默行为漂移（数据布局）
- **机理**:
  - 旧行为：`ChunkerConfig::new_with_params` 用 `assert!(min<=avg && avg<=max)` 硬失败（loud）；且 `Chunker::new` 不校验（非法配置会在 fastcdc 内部 assert / 或后续 panic）。
  - 新行为：构造器不再 assert；`Chunker::new(非法)` **静默替换为 `ChunkerConfig::default()`（4K/64K/256K）**，只打一条 `tracing::warn!`。对库调用方而言，若没有 subscriber（`tracing` 默认无输出）就完全不可见；chunk 边界/去重布局与调用方请求的尺寸不同，可能导致去重率与 archive 体积变化，且没有返回值让调用方感知。
  - 入口不一致：同一非法配置，`Chunker::new` → 成功(默认尺寸)；`Chunker::try_new` / `Chunker::chunk_all_async` / `FileReader::read_file_chunked(_stream)` / `Chunker::chunk_file` → `EraError::InvalidConfig`。这是新的公开 API 契约分叉。
  - **生产可达性有限（inference）**：era-engine 的 writer 在 `writer.rs:1036-1039` 先 clamp 再 `config.validate()?`，`chunker_config_from_archive`（`:134-149`）也校验顺序，因此 CLI/engine 路径不会静默回退（非法 `--cdc-*` 会得到 InvalidConfig 错误）；风险集中在直接使用 era-ingest 公共 API 的调用方。
- **证据**: `crates/era-ingest/tests/chunker_config_validation.rs`（12/12 通过，二进制直接运行）；其中 `invalid_config_fallback_still_preserves_data` 只断言"数据不丢"，**没有断言回退后的实际 chunk 尺寸 = default**，也没有断言回退可被调用方观测。代码路径如上行号所示。
- **确认程度**: confirmed（代码 + 测试）；生产可达性 inference。
- **建议**: 首选把 `new` 改为返回 `Result`（或引入 `ValidatedChunkerConfig` newtype 作为所有 chunker 的入参）；若必须保留 infallible 签名，至少让回退**可观测**（返回 `(Self, Option<EraError>)` 或显式 `chunker.used_fallback_config()`），并在测试中固定"回退=default 尺寸"这一契约；文档中把 `try_new` 标为推荐路径（现在文档已这么写，但 `new` 仍是默认入口）。

### R2-HYG-01【MEDIUM】`hygiene_guards_test` 本身是跨 crate 源码字符串耦合测试，与 H-04/ENG-RC-12 结论自相矛盾；合法重构误红、`assert!(true)` 可绕过

- **文件**: `crates/era-engine/tests/hygiene_guards_test.rs:12-41`（`AUDITED_TESTS`：7 个跨 crate 文件+测试函数名的硬编码清单）、`:57-66`（`fn_body` 用 `find("
}")` 截取函数体，非解析器）、`:72-90`（`body_has_failure_channel` 只查 `assert/panic!/unwrap_err/expect_err/catch_unwind` **子串**）、`:131-168`（CI 文本计数）、`:171-214`（README 文本断言）
- **维度**: 代码质量 / 测试可信度
- **机理**:
  1. round-1 H-04 / ENG-RC-12 的结论是"测试不应断言源码文本/字符串"，而本轮 H-03 的"修复"恰恰新增了一个**读取 7 个测试文件源码、README、ci.yml 并做子串匹配**的门禁；它还制造了跨 crate 耦合（`crates/era-engine` 的测试依赖 `crates/era-codec/tests/adversarial_audit_v9.rs` 的**函数名**）。
  2. 假阳性：合法重命名/移动被审计测试函数（如把 `test_mandatory_cdc_enabled` 改名）、调整函数签名换行、把 CI job 增加一个 step-level `timeout-minutes`，都会让门禁误红（`function not found` / 计数 ≠3），直接惩罚重构。
  3. 假阴性：`body_has_failure_channel` 只看 token 存在——把旧的 `println!` 换成 `assert!(true)` 即通过；它无法区分"有断言"和"断言了行为"。
  4. `fn_body` 的启发式在函数体内含以列 0 开头的 `}`（raw string/宏文本）时会截断错位；JSON/宏之类未来演进容易踩坑。
  5. 位置也值得讨论：仓库级卫生不变量放在 `era-engine` 的一个集成测试里，`cargo test -p era-engine` 之外的开发者不会跑；而它却会在 `--workspace` 中惩罚其它 crate 的重构。
- **证据**: 二进制直接运行 `target/release/deps/hygiene_guards_test-...` → `4 passed; 0 failed`（说明当前 7 个被审计测试的 token 检查通过；并不证明断言有效）；代码如上。`AGENTS.md:139` 宣称该测试"enforces ... the no-tautological-test invariant"属于过度声明。
- **确认程度**: confirmed（代码 + 运行）。
- **建议**: (a) 把 `AUDITED_TESTS` 门禁改为**行为级**验证（例如构建一个故意退化的 fixture 让测试必须红——mutation 风格），或降级为 `xtask`/脚本 advisory 而不进 `cargo test`；(b) 若保留清单，改为"按 `#[test]` 名从 `cargo test --list` 动态发现"而不是读源码文本；(c) 修正 AGENTS:139 的表述。

### R2-HYG-02【MEDIUM】README 统计只被保证"内部一致"而非"准确"；2916 / 0 failed / 17 ignored / 265 文件 / 141.7k 在本次提交后全部失真

- **文件**: `README.md:11,345,377,511`（2916 passed/0 failed/17 ignored）、`README.md:511`（141,700 附近）、`AGENTS.md:7`（~141.7k LOC / 265 .rs）、`crates/era-engine/tests/hygiene_guards_test.rs:171-214`（只断言 README 里同一数字出现且唯一）
- **维度**: 文档准确性 / 测试可信度
- **机理/证据**:
  1. **门禁只查一致性**：`readme_test_statistics_are_consistent` 收集 `<digits> passed` / `<digits> ignored` 的集合，断言集合大小 ==1。"4 处都写错的数字"照样通过。
  2. **"0 failed" 与当前门禁矛盾**：同一份工作树 `cargo test --release --locked -p era-cli` → `cli_rc=101`（R2-CLI-01）。README 的 `Last Verified` 在本次修订里被更新为 `2026-11-22 (b22a07e)`，但修订本身未通过门禁，"2916 passed, 0 failed"不能描述将要提交的树。
  3. **"17 ignored" 静态不可复现**：`grep -rn '#\[ignore'` → 3 处（`cli_boundary_tests.rs:129,206`、`cli_e2e_gap_tests.rs:69`）；再加 rustdoc 的 ignore 代码块 9 处（三反引号 + ignore，如 `era-crypto/src/secure_memory.rs:75`）= 12 个候选，与 17 不符（round-1-hygiene §C-06 也记 3）。无法从仓库独立复核 17。
  4. **计数将在同一提交内过期**（本工作树统计）:

     ```text
     tracked .rs files = 265        (README/AGENTS: 265)
     untracked .rs files = 5        → 提交后应为 270（round1_cli_create_repair_tests/hygiene_guards_test/round1_reader_fixes/chunker_config_validation/local_backend_hardening）
     tracked LOC = 142,615          (README: ~141,700 / AGENTS: ~141.7k；b22a07e 实测 141,721)
     untracked LOC = 1,185          → 提交后约 143,800
     #[test]/#[tokio::test] 新增 = 33（另有 cli_extreme_tests 新增 1 个）→ "2916 passed" 必变
     ```

  5. （公平记录）AGENTS.md 的 CODE MAP 引用数本轮**是准确的**：按文档给出的 `git grep -w <sym> b22a07e -- ...` 命令逐条复算 12 个符号全部一致（EraError=1135, ChunkHash=253, KeySession=102, SuperHeader=96, VolumeReader=82, Catalog=143, ArchiveManifest=67, ArchiveWriter=67, VolumePool=54, ArchiveReader=66, StorageBackend=33, IndexReader=26）。
- **确认程度**: confirmed（统计命令）；"17 ignored 的来源"未核实（inference：可能来自某次含 doctest 的汇总，但当前静态计数不支持）。
- **建议**: 统计数字改由 CI 产物自动生成（保存 `cargo test` 汇总到 artifact，再注入 README 占位符），或门禁改为"读取最近一次门禁日志的 `test result:` 汇总并比对"；在 gate 未全绿前不要更新 `Last Verified`/统计；同时更新 265→270 与 LOC。

---

## 3. 低严重度 / informational 发现

### R2-REPAIR-01【LOW】ENG-RC-07 修完后 `match archive_health { Healthy => {} }` 变成新的不可达死代码

- **文件**: `bins/era-cli/src/commands.rs:1301-1313`
- **机理**: `VerifyStats::is_healthy()` 定义即 `matches!(archive_health, Healthy)`（`crates/era-engine/src/chunk_processor.rs:904-906`），`needs_repair() == !is_healthy()`（`:917-919`）。修订把原来的 `Healthy && needs_repair()`（不可达）删除后改成 `if verify_stats.is_healthy() { return Ok(()) }`，随后 `match &verify_stats.archive_health { ArchiveHealthStatus::Healthy => {} ... }` 的 Healthy 分支同样不可达。**死代码被"搬家"而非消除**；且注释"reachable Degraded/Incomplete diagnostics live in the match below"与健康分支实际不可达并存。
- **确认**: confirmed（布尔推导）。**建议**: 去掉 early return、统一在一处 match 输出；或删除 Healthy 分支（不推荐 `unreachable!`）。

### R2-REPAIR-02【LOW】repair 缺路径 exit 0→1 的 CLI 契约变更未文档化

- **文件**: `bins/era-cli/src/commands.rs:1268-1275`、`bins/era-cli/src/main.rs`（repair 的 long_about，无退出码语义）；`README.md:77-78,448`（只写"Try `era repair` first"）
- **机理**: 旧行为 `info!("❌ No archive or checkpoint found. Nothing to repair."); return Ok(())}`（exit 0）；新行为 `anyhow::bail!(...)`（exit 1）。**判断合理**（typo/未挂载确实应失败），两个旧测试的预期修改也合理且相互一致（`cli_integration_tests.rs:2604-2621`、`cli_integration_tests_comprehensive.rs:3495-3512` 均改为 `.failure()` + "Archive not found" + 路径）。缺口只在文档：README/help 没有"退出码"契约，自动化脚本无法从文档判断该行为。
- **确认**: confirmed。**建议**: 在 README troubleshooting 或 repair `--help` 的 `after_help` 里写明退出码语义（0=健康/已修复，非 0=缺失/不可修复/需 `--force`）。

### R2-VERIFY-01【LOW】verify Degraded 的 warning 在 stderr 重复两遍

- **文件**: `bins/era-cli/src/commands.rs:1147-1153`（逐条 `warn!` 打印）与 `:1158-1182`（`anyhow::bail!` 里再次 `stats.warnings.join("; ")`）
- **机理/证据**（P9 黑盒，header 魔数损坏）:

  ```text
  WARN   1. Volume 0: using backup header; primary header still requires repair
  Error: Archive verification degraded: all 6 expected volume(s) are present, but the archive is not fully healthy: Volume 0: using backup header; primary header still requires repair
  ```

  新测试只断言 `contains(...)`，因此不约束重复。属可运维性小噪声（日志采集会重复计数）。**建议**: error 只给摘要，详情留在上面的 Warnings 段（或仅在 `--verbose` 时拼接）。

### R2-HYG-03【LOW】`ci_workflow_is_reproducible` 断言的是"文本出现次数"而不是它声称的不变量

- **文件**: `crates/era-engine/tests/hygiene_guards_test.rs:131-168`；对应 `.github/workflows/ci.yml:14,48,53,81-87,92,120-126`
- **机理**:
  - `ci.matches("timeout-minutes:").count() == 3`：把某个 job 的 timeout 挪成 step-level timeout（计数仍 3）而新 job 无 timeout 时依旧通过；加入第 4 个 job 或给 step 加 timeout 则误红。断言不到"每个 job 都有 job-level timeout"。
  - `ci.contains("ulimit -n 1024")`：只查字符串存在，不查它是否与 `cargo test` 在**同一个 run block**（本轮实现恰好同 block，见下，但门禁不保护该性质；若有人拆成两个 step 则静默失效）。
  - 断言恰好 2 条 `cargo test` 命令行：合法新增测试 job/target 会误红。
- **确认**: confirmed（代码+ci.yml）。**建议**: 用 YAML 解析后逐 job/job.steps 断言，或 CI 侧用 actionlint。

### R2-CI-01【LOW】"README/AGENTS 命令与 ci.yml 完全一致"不成立（缺 ulimit）

- **文件**: `README.md:364,366-372`、`AGENTS.md:104`
- **机理**: CI 的两个 test step 是 `run: | ulimit -n 1024; ulimit -n; cargo test --release --locked ...`（`ci.yml:82-87,123-126`，**同一 shell 生效，正确**）；README 正文说"so a local run above matches CI's resource limits"（:364），但紧邻的命令块（:366-372）和 AGENTS:104 的一行式命令都没有 `ulimit -n 1024`。命令本身（fmt / clippy --locked / test --release --locked -p era-cli / --workspace）与 ci.yml 等价。**建议**: 命令块加 `ulimit -n 1024 && ...`，或删掉 "matches exactly / matches CI's resource limits" 的措辞。

### R2-CI-02【LOW】workspace job 重复跑 CLI 测试 + 默认 fail-fast：CLI 一红，其余 crate（含本轮新测试）在 CI 中不会被执行

- **文件**: `.github/workflows/ci.yml:50-87`（test-era-cli）与 `:89-126`（test-workspace，未 `--exclude era-cli`、未 `--no-fail-fast`）
- **机理/证据**: `/tmp/era_ci_round1.log` 中 `-p era-cli` 在 `cli_coverage_gap_tests` 失败后 `cli_rc=101`；`cargo test --workspace` 同样会先/重跑 era-cli 并在同一目标处中止（cargo 默认 fail-fast），因此本轮新增的 `chunker_config_validation`/`local_backend_hardening`/`hygiene_guards_test` 等在 CI 门禁里**实际未被验证**（本人只好直接运行预编译测试二进制，见 §4）。重复执行 CLI 测试本身是 round-1 I-01 已记录的既有问题。**建议**: test-workspace 用 `cargo test --release --locked --workspace --exclude era-cli`（或 `--no-fail-fast` 并汇总失败），既消除重复也让一次 CI 暴露全部失败。

### R2-STOR-02【LOW / benchmark-needed】每次 create 一次父目录 fsync（默认 6 卷 → 6 次/归档），无基准证据

- **文件**: `crates/era-storage/src/local.rs:69-91,147`；调用密度由 `crates/era-volume/src/writer.rs:111`（每个卷一次 `backend.create`）决定
- **机理/评估**: 每次 `create` 打开父目录并 `sync_all()`。绝对路径输出时实测无 WARN（即每卷一次 fsync），默认 6 卷 → 每归档 6 次目录 fsync；目录 fsync 在本地 ext4/tmpfs 上通常亚毫秒~数毫秒，相对 AEAD/Coding 成本大概率可忽略；但对 `--volumes 256` 或网络文件系统会放大。**未做基准对比 → 记为 benchmark-needed，不认定为已证明回归**。**建议**: 若在意，可在 `create` 批次结束时由上层做一次目录 fsync（或提供开关），并给出 benchmark。

### R2-STOR-03【LOW】O_NOFOLLOW 常量/cfg 覆盖：两处重复清单 + 非覆盖平台 TOCTOU 仍在

- **文件**: `crates/era-storage/src/local.rs:15-36`（两个 `const O_NOFOLLOW`）、`:40-61`（`create_open_options` 内又重复同一组 cfg）、`:133-143`（预检查 + `options.open`）
- **机理/证据**:
  - Linux x86_64 常量值正确：`python3 -c 'import os;print(oct(os.O_NOFOLLOW))'` → `0o400000`，与 `:21` 一致；BSD/apple 的 `0x0100` 与 workspace 内 `libc-0.2.191/src/unix/bsd/mod.rs:276` 一致。`File::create`→`write+create+truncate` 的覆盖语义保持不变（`local_backend_hardening.rs::create_still_truncates_existing_regular_file` 通过），轮转/重试依赖未被破坏（正例）。
  - 但 cfg 仅覆盖 linux/android/apple/BSD 家族；solaris/illumos/aix/haiku/redox/cygwin 等 unix 目标上 `create_open_options` 不加 `O_NOFOLLOW`，只剩 `symlink_metadata` 预检查 → **check-then-open 的 TOCTOU 在这些目标上依然存在**（代码注释已声明"platforms where known"，属知情接受，但与"race-free guard"的表述有落差）。
  - const 与 `custom_flags` 两处 cfg 列表重复，后续增删平台极易只改一处造成"常量未用/未应用"漂移。
- **确认**: 值 confirmed（Linux/BSD 核对）；平台缺口为 inference（本机无法构建那些目标）。**建议**: 单一 cfg 谓词/宏，或直接使用 workspace 已有的 `libc`（`Cargo.lock` 已有 0.2.191，但把 libc 加进 `era-storage` 依赖图需要登记决策）；在 CI 加 `--target` 编译检查以覆盖 cfg 分支。

### R2-CLI-03【LOW】`directory_is_empty` 对每个目录多一次 `read_dir`；并发修改窗口下警告可能误报

- **文件**: `bins/era-cli/src/commands.rs:620-630`（每个 is_dir 条目调用）、`:651-656`（`directory_is_empty`）、`:579-583`（根 symlink 特例）
- **机理**: 新逻辑对 walkdir 产出的**每个**目录都执行一次 `std::fs::read_dir` + `next()`（只读 1 条 entry，成本低），大目录树上是 O(目录数) 的额外 open/close；同时"检查是否为空"与 walkdir 真正遍历该目录之间存在时间窗，目录被并发增删时"empty directory skipped"警告可能与实际归档内容不符（inference，未构造复现）。另：目录若只含被 `excluded_paths` 排除的输出卷文件，实际不会被归档但不会触发"空目录"警告（警告语义不完整）。**建议**: 只在确实需要时检查（或使用 `WalkDir::filter_entry` + 后置统计），并在 tests 里补 excluded 场景；性能记为 benchmark-needed。

### R2-STOR-04【INFORMATIONAL】Windows 上目录 fsync 每次 create 必告警（inference）

- **文件**: `crates/era-storage/src/local.rs:69-91`（未 `cfg(unix)` 门控）
- **机理**: Windows 上 `File::open(目录)` 返回访问被拒，进入 `Err` 分支 → 每次卷创建一条 WARN；目录 fsync 在 Windows 本也无对应语义。**未在 Windows 验证**（本环境 Linux/CI 只跑 ubuntu-latest），按 inference 记录。**建议**: 该 helper 用 `#[cfg(unix)]` 门控或显式跳过 non-unix。

### R2-GIT-01【INFORMATIONAL】`.gitignore` 注释自相矛盾：仓库级 negation 实测已生效，不需要 `git add -f`

- **文件**: `.gitignore:28-36`
- **机理/证据**: 注释称"this only works because repository .gitignore patterns outrank the user-level global ignore of docs/; ... in some environments 'git add -f docs/audit/...' is still required"（:30-32）。第一句符合 git 文档的优先级（仓库 `.gitignore` 高于 `core.excludesFile`），但第二句与本环境实测矛盾：

  ```text
  $ git check-ignore -v docs/audit/round1-hygiene.md
  .gitignore:35:!docs/audit/**   docs/audit/round1-hygiene.md     # 命中 negation，未被忽略
  $ git status --porcelain | grep docs
  ?? docs/audit/                                                   # untracked 可见
  ```

  即 H-02 的 `docs/audit/` 证据链入库确实生效（正例），但注释里的"仍需 -f"警告属于无依据的悲观说明，容易让后续审计者误操作。**建议**: 删除该限制说明，或写清"仅当全局 ignore 以不同优先级层规则遮蔽时需 -f"的可验证条件。

---

## 4. 已核实为正例 / 修复成立的部分（公平记录，避免"只列问题"）

| 项目 | 结论 | 证据 |
|---|---|---|
| `round1_cli_create_repair_tests`（9 用例） | **全部通过** | 直接运行 `target/release/deps/round1_cli_create_repair_tests-... --test-threads=2` → `9 passed; 0 failed`（含 symlink-in-tree/不可读子树/socket/空目录/显式 symlink/repair exit/verify degraded/repair degraded） |
| create 显式输入 symlink 历史语义 | **保持** | P4 黑盒：`era create lf.txt ldir` rc=0，list 含 `lf.txt`、`ldir/a.txt`、`ldir/sub/b.bin` |
| walkdir 根 symlink 特例分支 | **不是死代码**（正确） | walkdir 2.5.0 `lib.rs:856-873`：根 symlink 被 `push`（跟随）但 DirEntry 仍报告 symlink → `commands.rs:579` 分支可达；P4 亦证明目录内容被归档 |
| 空目录/特殊文件/不可读子树的处理 | 符合 round-1 ENG-RC-03 的意图 | P1/P2/P3/P5/P6/P7 黑盒；错误串带路径与原因；不可读子树的错误来自 `directory_is_empty`（`Failed to read directory`），未重复报错（bail 于首个错误） |
| repair 缺路径退出码 | 修复成立（exit 1 + 路径） | `eng_rc_05` 通过；P8：`rc=1` + `Error: Archive not found: /tmp/definitely-missing-r2.era ...` |
| backup-header 场景 repair/verify | 成立（可修） | P9：verify rc=1 带 "using backup header"；repair --force rc=0 "✅ Archive successfully repaired!"；修后 verify rc=0 |
| footer 冗余检测（ENG-RC-02 的 CLI 侧预期） | 成立 | 直接运行最新 `cli_extreme_tests` 二进制 `header_footer_recovery` → `6 passed`（含新增 `test_verify_backup_footer_corrupted_is_degraded` 与两处 `.failure()` 预期） |
| `ChunkerConfig::small_files()/large_files()` 仍满足 validate | 是（不会触发静默回退） | fastcdc 边界 + `try_new(4K,64K,256K)` 测试；small=(2K,16K,64K)/large=(16K,256K,1M) 均合法 |
| 全部 FileReader 入口对非法配置返回 Err（非 panic） | 成立 | `reader.rs:285-306`（stream 前置 validate）、`:310-335`（try_new）；`chunker_config_validation` 12/12 通过 |
| `StreamingChunker`/`ZeroCopy` 非法配置 buffer=0 安全性 | 成立 | `next_chunk` 先 validate（chunker.rs:243-245 / zerocopy:135-136），`into_stream` 经 `next_chunk`（chunker.rs:312-317 / zerocopy:205-210）→ 不会空 buffer 死循环 |
| `read_all_from` 语义与 Memory backend 一致 | 成立 | local.rs:291-300 与 `memory.rs:208-214` 均在 offset>=size 返回空；`local_backend_hardening` 5/5 通过 |
| `create` 覆盖/截断语义保持（轮转/重试） | 成立 | `create_still_truncates_existing_regular_file` 通过；等价 `write+create+truncate` |
| O_NOFOLLOW 阻断 symlink 目标 | 成立 | `local_backend_hardening` 2 个 symlink 用例通过；P 系列未误伤正常文件 |
| CI `ulimit` 同一 shell 生效 | 成立 | `ci.yml:82-87,123-126` 为单个 `run: |` 脚本；GitHub Actions 以同一 bash 执行该块 |
| ci.yml YAML 合法 / timeout 数值 | 成立 | `ruby -ryaml -e 'YAML.load_file(...)'` → jobs=[lint,test-era-cli,test-workspace]，timeouts=30/60/120 |
| `--locked` 覆盖 | 成立 | clippy（:48）与两个 test job（:87,:126）均有 `--locked` |
| AGENTS CODE MAP 引用数 | 成立 | 12 个符号按文档命令复算全部一致（见 R2-HYG-02 证据） |
| `docs/audit/` 可入库（H-02 部分修复） | 成立 | `git status` 出现 `?? docs/audit/`；`git check-ignore -v` 命中 `.gitignore:35:!docs/audit/**` |
| `hygiene_guards_test` 自身可运行 | 4/4 通过 | 直接运行二进制 |

---

## 5. 对 round-1 修复声明的仲裁（本范围）

| round-1 条目 | 本轮结论 | 依据 |
|---|---|---|
| ENG-RC-03 create 静默丢 symlink/空目录/不可读子树 | **修复成立（意图）**，但规格选择过于激进：破坏兼容、无开关、README 未文档化 → 新 R2-CLI-02 | §4 + R2-CLI-02 |
| ENG-RC-05 repair 缺路径 exit 0 | **修复成立**，文档缺口 → R2-REPAIR-02 | P8 / tests |
| ENG-RC-06 verify Degraded 文案 | **修复成立**（区分 missing-volume 与非卷缺失；带 warning 详情），但 stderr 重复 → R2-VERIFY-01 | P9 / commands.rs:1154-1182 |
| ENG-RC-07 repair `Healthy && needs_repair()` 死代码 | **目标达成但死代码搬家** → R2-REPAIR-01 | chunk_processor.rs:904-919 + commands.rs:1301-1313 |
| ENG-RC-02 footer 冗余覆盖（CLI 侧预期） | **CLI 侧成立**（cli_extreme footer 6/6），但 header 篡改场景被新校验阻断 → R2-CLI-01 | 直接运行 footer 测试 / 门禁 |
| LL-05 Chunker 非法配置 panic | **不 panic 成立**；但引入"静默回退"漂移与入口不一致 → R2-ING-01 | 代码+测试 |
| LL-06 create 跟随 symlink / 无父目录 fsync | **symlink 部分成立**（O_NOFOLLOW + 预检查）；**父目录 fsync 对相对路径失效** → R2-STOR-01 | P 系列 / 计数 |
| LL-07 read_all_from 下溢 | **修复成立**（与 Memory 一致） | §4 |
| H-02 docs/audit 入库 | **部分成立**（本环境可入库；注释过度悲观）→ R2-GIT-01 | check-ignore |
| H-03 无断言测试 | **7 个测试补了真断言（成立）**，但新增的元门禁是弱/脆的源码文本检查 → R2-HYG-01 | 源码+运行 |
| H-04 源码字符串耦合 | **未闭环且自相矛盾**：新增门禁本身即源码字符串耦合 → R2-HYG-01 | hygiene_guards_test.rs |
| H-05 CI 可复现性（--locked/ulimit/timeout） | **基本成立**（YAML/同 shell/lint+2 个 test job），文档等价性小缺口 → R2-CI-01；fail-fast 导致覆盖缺口 → R2-CI-02 | ci.yml + 日志 |
| H-08 README/AGENTS 统计漂移 | **仅"内部一致"成立，准确性未成立** → R2-HYG-02 | 统计命令 |
| （新）append/reader 相关 reader.rs 修订 | **引入回归**：header-digest 硬校验使 repair 失效、门禁红 → R2-CLI-01（请与 r2-engine 线程合并去重） | 门禁日志 + 黑盒 |

---

## 6. 限制与未核实

1. **后台全量门禁未跑完**（本报告写作时 `/tmp/era_ci_round1.log` 已记录 `cli_rc=101`，workspace 阶段仍在编译/执行）。因此我**没有** workspace 全量 passed/ignored 权威数字：R2-HYG-02 中"2916/17 ignored 不准确"部分依据静态计数（3 `#[ignore]` + 9 rustdoc ignore = 12）与 `0 failed` 的门禁反证，**不代表对 b22a07e 基线的否定**（该基线未重跑，避免与门禁争锁）。
2. **未构建非 Linux 目标**：O_NOFOLLOW 的 BSD/apple 常量按其 libc 定义核对，其它 unix（solaris/aix/haiku/redox）未验证，相关条目已标 inference。
3. **Windows 行为未验证**（R2-STOR-04 为 inference）。
4. **性能类结论**（R2-STOR-02、R2-CLI-03 的 syscall 开销）均标 benchmark-needed，未做基准对比。
5. **未修改任何代码**；`target/` 中其它审计线程产生的探针/测试产物不属于本线程。
6. cargo 锁争用：为不干扰负责人门禁与其它 round-2 线程，定向测试优先直接运行**当前工作树已编译**的测试二进制；运行前核对 source mtime < binary mtime（chunker/local/hygiene 均满足；`cli_extreme_tests` 曾误用旧哈希二进制，已改选最新 `-ccc0472b...` 并 6/6 通过）。

---

## 7. 复现命令与关键输出（附录）

### A-1 门禁（负责人后台）

```text
$ sed -n '90,175p' /tmp/era_ci_round1.log
test random_offset_corruption::test_repair_corruption_at_multiple_offsets ... FAILED
...
Error: Failed to open archive
Caused by:
    Integrity error: Volume 0 primary header bytes do not match the authenticated manifest header digest
...
test result: FAILED. 27 passed; 1 failed; 0 ignored; ...
error: test failed, to rerun pass `-p era-cli --test cli_coverage_gap_tests`
cli_rc=101
```

### A-2 黑盒复现 R2-CLI-01（工作树二进制）

```text
$ era create f.txt -o a.era -p pwd            # rc=0
$ dd if=/dev/zero of=a.era bs=1 seek=1000 count=1 conv=notrunc   # 或用 0xFF
$ era verify a.era -p pwd                     # rc=1
Error: Failed to open archive
Caused by: Integrity error: Volume 0 primary header bytes do not match the authenticated manifest header digest
$ era repair a.era -p pwd --force             # rc=1，同上；修复路径不可达
# 对照（offset 0 魔数损坏，走 backup header 恢复）：
$ era repair b.era -p pwd --force             # rc=0 "✅ Archive successfully repaired!"
$ era verify b.era -p pwd                     # rc=0
```

### A-3 黑盒复现 R2-STOR-01（WARN 计数）

```text
$ era create f.txt -o rel.era -p pwd 2>&1 | grep -c 'failed to open storage parent directory'   # 6
$ era create f.txt -o $PWD/abs.era -p pwd 2>&1 | grep -c 'failed to open storage parent directory' # 0
$ mkdir out; era create f.txt -o out/rel2.era -p pwd 2>&1 | grep -c 'failed to open storage parent directory' # 0
# 原文：
WARN failed to open storage parent directory for fsync (best-effort) parent= error=No such file or directory (os error 2)
```

### A-4 定向测试（直接运行已编译二进制，全部通过）

```text
round1_cli_create_repair_tests : 9 passed; 0 failed
chunker_config_validation     : 12 passed; 0 failed
local_backend_hardening       : 5 passed; 0 failed
hygiene_guards_test           : 4 passed; 0 failed
cli_extreme_tests (header_footer_recovery 过滤): 6 passed; 0 failed
```

### A-5 静态核对

```text
$ git ls-files '*.rs' | wc -l                                        -> 265
$ git ls-files --others --exclude-standard '*.rs' | wc -l            -> 5
$ git ls-files -z '*.rs' | xargs -0 cat | wc -l                      -> 142615
$ git ls-files --others --exclude-standard -z '*.rs' | xargs -0 cat | wc -l -> 1185
$ grep -rn --include=*.rs '#[ignore' . | grep -v target | wc -l      -> 3
$ rustdoc ignore 代码块（三反引号+ignore）计数                       -> 9
$ python3 -c 'import os;print(oct(os.O_NOFOLLOW))'                   -> 0o400000
$ ruby -ryaml -e 'YAML.load_file(".github/workflows/ci.yml")...'     -> jobs ok, timeouts 30/60/120
$ git check-ignore -v docs/audit/round1-hygiene.md                   -> .gitignore:35:!docs/audit/**（未被忽略）
# AGENTS CODE MAP 12 个符号按文档命令复算 -> 全部一致（1135/253/102/96/82/143/67/67/54/66/33/26）
```

### A-6 引用源码/注册表位置

- `crates/era-engine/src/reader.rs:1541-1547,2856-2884`
- `crates/era-engine/src/chunk_processor.rs:904-906,917-919`
- `crates/era-cli/src/commands.rs:579-590,620-630,651-656,864-878,1147-1182,1268-1275,1301-1313`
- `crates/era-cli/src/main.rs:51-57`
- `crates/era-ingest/src/chunker.rs:34-54,61-64,105-121,180-199,243-245,312-317`
- `crates/era-ingest/src/chunker/config.rs:71-77,86-117,123-141`
- `crates/era-ingest/src/chunker_zerocopy.rs:64-80,135-136,205-210`
- `crates/era-ingest/src/reader.rs:249-252,285-306,310-335`
- `crates/era-storage/src/local.rs:15-36,40-61,69-91,109-115,123-149,291-300`
- `crates/era-storage/src/memory.rs:208-214`
- `crates/era-engine/src/writer.rs:134-149,1031-1039`
- `crates/era-engine/tests/hygiene_guards_test.rs:12-41,57-66,72-90,131-168,171-214`
- `.github/workflows/ci.yml:14,48,53,81-87,92,120-126`
- `README.md:11,345,364,366-372,377,511`；`AGENTS.md:7,104,139`；`.gitignore:28-36`
- walkdir 2.5.0 `~/.cargo/registry/src/.../walkdir-2.5.0/src/lib.rs:856-873`
