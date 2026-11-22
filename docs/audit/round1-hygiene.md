# ERA-CORE 全仓卫生 / 技术债 / 工程配置审计（Round 1 · Hygiene）

- **审计基线**：`feat_fly` @ `b22a07e`（前序审计基线 `ee39fae`；整改提交 `8c42a4c`、`31d358f`、`5ff825e`、`b22a07e`）
- **审计日期**：2026-11-22
- **审计维度**：全仓卫生、技术债、测试质量与工程配置（规格符合性 / 代码质量 / 并发与一致性 / 性能），不评估密码学与解包正确性（由其他审计线程负责）
- **审计方法**：只读静态扫描（`git ls-files` / `git grep` / `git show` / `git check-ignore` / 自写 Python 分类器）+ 定向门禁复跑（`cargo fmt --check`、`cargo metadata --locked`）。**未修改任何源码 / 测试 / 既有文档**；未跑全量 workspace 测试（由团队负责人在后台执行）。
- **环境**：rustc 1.99.1 / cargo 1.99.0 / rustfmt 1.10.0（Nix store；`PATH` 见附录）。工作区在我开始审计时为干净（`git status --porcelain` 为空）；审计期间另一审计线程在 `crates/era-volume/tests/` 留下了 2 个未跟踪探针文件（见 §5 环境说明，非本报告发现、也非本人创建）。

---

## 1. 结论摘要

工程师声明“已修复仓库全部问题、零技术债、无遗留问题” **在本审计维度上不成立**。本轮确认 **12 项**问题（3 medium / 6 low / 3 informational），其中 3 项直接推翻前序闭环声明：

1. **§4.7“死代码与 `#![allow(dead_code)]` 清理”只完成了一半**：模块级内联属性确实清零，但生产 `src` 仍有 **41 个 `#[allow(dead_code)]`**、**49 个零引用 `pub fn`**（前序审计点名的 8 个里仍有 7 个零引用）。见 **H-01**。
2. **§5.1“审计证据链纳入仓库”只覆盖了 4 份 11 月文档**：`docs/` 目录被全局 gitignore 排除，仓库侧仅用 `!docs/*-2026-11-*.md` 做窄放行；`docs/audit/*`（本轮输出路径）与 6 份历史审计/设计文档仍不可跟踪。见 **H-02**。
3. **“2916 passed” 的统计里混入了无断言/空体测试**：至少 1 个测试函数体完全为空，另有 6 个“测试”只打印、无论被测行为如何都恒过；它们都出现在测试统计中。见 **H-03**。

另有一条与“门禁全绿”相关的**环境事实**（非仓库缺陷）：`cargo fmt --all -- --check` 在审计期间因另一线程的未跟踪探针文件而返回 1；只对**已跟踪**的 265 个 `.rs` 跑 `rustfmt --check` 为 exit 0（见 §5）。

### 1.1 严重度统计（仅本报告确认项）

| 严重度 | 数量 | 编号 |
|---|---:|---|
| critical | 0 | — |
| high | 0 | — |
| medium | 3 | H-01、H-02、H-03 |
| low | 6 | H-04、H-05、H-06、H-07、H-08、H-09 |
| informational | 3 | I-01、I-02、I-03 |
| **合计** | **12** | 全部标注 confirmed / inference |

> 说明：本维度没有高危安全问题；H-01/H-02/H-03 之所以定为 medium，是因为它们直接否证“零技术债 / 证据链完整 / 验收统计可信”这三条结项声明，而不是因为它们会造成运行时故障。

### 1.2 前序声明的核验结果（对账表）

| 前序声明 | 本轮核实 | 证据 |
|---|---|---|
| §4.7 死代码与模块级 `#![allow(dead_code)]` 清理 | **部分成立/声明过度**：模块级清零成立，零引用函数与 item 级 allow 未清理 | §2 H-01 |
| §4.10 解除源码行号强耦合测试 | **仅修了 `adversarial_audit_v3` 单点**：全仓仍有 263 处 `include_str!` 源码断言（12 个测试文件） | §2 H-04 |
| §5.1 审计证据链纳入仓库 | **部分成立**：4 份 11 月文档已跟踪；6 份历史文档 + 本轮 `docs/audit/` 仍被忽略 | §2 H-02 |
| §5.2 Cargo.lock / 工具链 / fuzz 可复现性 | **部分成立**：Cargo.lock 已跟踪且与 manifest 同步（`cargo metadata --locked` exit 0）；`rust-toolchain.toml` 与 CI 均为 `stable`；fuzz.yml 已加缺失容错。但 stable 未固定版本、CI 未用 `--locked`、`flake.nix/flake.lock` 仍未跟踪 | §2 H-05、I-03 |
| §5.3 统计与文档漂移 | **未闭环**：README 自身仍有两套互斥统计；AGENTS.md CODE MAP 引用数与实际大范围漂移 | §2 H-08 |
| §5.4 测试质量 | **部分成立**：`pwrite_test.rs` 的 `#[ignore]` 已移除且修复后语义正确（见 §4 C-08）；`resilience_tests.rs` 已补真实断言（C-09）。但无断言/空体测试、墙钟断言、`#[path]` 重复执行仍在 | §2 H-03、H-06、H-07 |
| “生产 src 无 unwrap/expect/panic、无 thread_rng、unsafe 仅 crypto” | **成立**（见 §4 C-01/C-02/C-03） | 分类器：24 处 unwrap/expect/panic 全部位于 `#[cfg(test)]` 门控文件或 rustdoc 示例 |

---

## 2. 详细发现

> 每条固定包含：编号 / 标题 / 严重度 / 维度 / 确认程度 / 锚点 / 机理 / 证据 / 影响 / 建议修复 / TDD 回归测试。

### H-01 【MEDIUM】技术债清理未闭环：41 个 `allow(dead_code)` 与 49 个零引用 `pub fn` 仍在，§4.7 声明过度

- **维度**：代码质量
- **确认程度**：**confirmed**（引用计数为静态事实；个别项“是否应保留为未来 API”属判断）
- **锚点**：
  - `crates/era-engine/src/chunk_index.rs:25`（`pub(crate) trait ChunkIndex`）、`:58/66/84/163/304`（含 `:305 create_chunk_index`）
  - `crates/era-engine/src/reader.rs:696` `ensure_embedded_index_recovered`、`:738` `has_embedded_index`
  - `crates/era-volume/src/header.rs:114` `set_ciphertext`、`:223` `set_params`、`:229` `set_encrypted_master_key`
  - `crates/era-volume/src/volume_pool.rs:387` `current_block_count`、`:465` `get_total_size`
  - `crates/era-engine/src/write_pipeline.rs:429` `encryption_mut`、`:441` `erasure_mut`、`:471` `into_parts`
  - `crates/era-engine/src/packing_stage.rs:69` `with_defaults`、`crates/era-engine/src/checkpoint.rs:791` `recover_all_checkpoints`
- **机理**：这些 item 只在 `#[cfg(test)]` 内联测试（或完全不被引用）中出现，库正常编译时被 dead_code lint 判死，于是用 `#[allow(dead_code)]` 逐个压掉。`5ff825e` 只删除了 `chunk_processor.rs` 的模块级 `#![allow(dead_code)]`（已确认全仓 `src` 现已无文件级 inner allow），未处理 41 个 item 级抑制与零引用 API。
- **证据**（命令 + 关键输出，详见附录 A-2/A-3）：
  ```text
  # 生产 src allow 统计
  total allow = 64；dead_code = 41、clippy = 18、deprecated = 3、unused_imports = 1、unreachable_patterns = 1
  # 模块级 inner allow（文件作用域）在 src 中 = 0
  # 零引用 pub fn（git grep -w 全仓仅 1 次命中，即声明本身）= 49
  crates/era-engine/src/chunk_index.rs:305 fn create_chunk_index refs=1
  crates/era-engine/src/reader.rs:696 fn ensure_embedded_index_recovered refs=1
  crates/era-engine/src/reader.rs:738 fn has_embedded_index refs=1
  crates/era-volume/src/header.rs:114 fn set_ciphertext refs=1
  crates/era-volume/src/header.rs:223 fn set_params refs=1
  crates/era-volume/src/header.rs:229 fn set_encrypted_master_key refs=1
  crates/era-volume/src/volume_pool.rs:387 fn current_block_count refs=1
  crates/era-volume/src/volume_pool.rs:465 fn get_total_size refs=1
  ...
  ```
  前序报告 §4.7 点名的 8 个零引用 `pub fn` 中，**7 个仍为 1 次引用**（上表 7 项）；`writer.rs:862` 已随重构不再对应函数（行号失效）。另有多项 `allow(dead_code)` 标注的 item 在 `git grep -w` 下同样只有定义行：`write_pipeline.rs:429/441/471`、`packing_stage.rs:69`、`checkpoint.rs:791`。需要区分：`chunk_index.rs:25` 的 `trait ChunkIndex` 本身在生产路径被 used（`index_stage.rs:20`），其 `allow(dead_code)` 抑制的是未被调用的 trait 方法；而 `:305 create_chunk_index` 是整个函数零引用。
- **影响**：`cargo clippy -D warnings` 全绿依赖 64 个抑制；任何重构（例如把 `ChunkIndex` 彻底删除）都不会被编译器提示。零引用 API 扩大维护面并误导“公开 API 已被使用”的判断；也直接否证“零技术债”。
- **建议修复**：
  1. 删除 49 个零引用 `pub fn` 中确认无未来契约的部分；确需保留的，改成 `#[cfg(test)]` + `#[doc(hidden)]` 或加 `// reason:` 注释；
  2. 逐个移除 41 个 `allow(dead_code)`（保留者必须带原因，且改为 `#[allow(dead_code, reason = "...")]` 或统一注释规范）；
  3. 对 `chunk_index.rs` 的 `MemoryChunkIndex`/`create_chunk_index` 做取舍：生产路径已用 `RedbChunkIndex`，若仅测试使用应移入测试辅助模块。
- **应补回归测试（TDD）**：
  - 先红：新增脚本 `scripts/check-debt-markers.sh`（禁止新增无 reason 的 `allow(dead_code)`、禁止 `src` 中出现零引用 `pub fn` 基线外的项）；构造一个带零引用 `pub fn` 的临时分支验证脚本 exit 1；
  - 再绿：清理后脚本 exit 0，并把基线文件（allowlist）纳入仓库。

### H-02 【MEDIUM】审计证据链只部分纳入版本库：`docs/audit/` 与 6 份历史文档仍被忽略

- **维度**：规格符合性 / 工程流程
- **确认程度**：**confirmed**（`git check-ignore`、`git ls-files` 直接可复现）
- **锚点**：`.gitignore:22`（`*.md`）、`:26`（`!doc_gen/**/*.md`）、`:27`（`!docs/*-2026-11-*.md`）；全局 `~/.config/git/ignore:29`（`docs/`）
- **机理**：仓库用“全量忽略 `*.md` + 精确放行”的方式控制文档入库；放行模式写死为 `docs/*-2026-11-*.md`（只匹配 `docs/` 直接子文件且文件名含 `2026-11`）。`docs/` 父目录本身被用户级全局 ignore 排除，git 不会递归进入该目录的其它子路径，因此 `docs/audit/**`、`docs/2026-12-*.md` 等一律不可跟踪。`b22a07e` 只 `git add` 了 4 份 11 月报告。
- **证据**（附录 A-4）：
  ```text
  $ git check-ignore -v docs/audit/round1-hygiene.md
  /home/ricardom/.config/git/ignore:29:docs/   docs/audit/round1-hygiene.md
  $ git check-ignore -v docs/branch-audit-findings-2026-09-29.md
  /home/ricardom/.config/git/ignore:29:docs/   docs/branch-audit-findings-2026-09-29.md
  $ ls docs/*.md | wc -l   # 10
  $ git ls-files 'docs/*.md' | wc -l   # 4
  UNTRACKED: docs/branch-audit-findings-2026-09-29.md
  UNTRACKED: docs/consolidated-risk-and-recovery-audit-2026-10-10.md
  UNTRACKED: docs/consolidated-risk-and-recovery-remediation-plan-2026-10-10.md
  UNTRACKED: docs/hybrid-kem-hardening-design.md
  UNTRACKED: docs/recovery-failure-scenarios-and-flaws-2026-10-10.md
  UNTRACKED: docs/risk-assessment-2026-10-09.md
  ```
- **影响**：本轮（Round 1）以及后续任何轮次的审计报告默认不可跟踪，无法与提交/CI 对应；“证据链已纳入版本库”的验收结论只对特定文件名成立。新克隆或 CI 上看不到这些结论，前三轮审计反复出现的“文档未跟踪”问题实质上仍在。
- **建议修复**：把“白名单式放行”改为“目录式放行”，例如删除 `*.md` 全量忽略，改为 `/docs/**` 显式跟踪（或至少 `!docs/**/*.md` 并把 `docs/` 从全局 ignore 中移出，或在仓库文档中固化 `git add -f` 流程）；同时把本轮 `docs/audit/` 目录纳入跟踪。
- **应补回归测试（TDD）**：新增 CI 脚本 `scripts/check-doc-tracking.sh`：遍历 `docs/**/*.md`，对每个文件执行 `git ls-files --error-unmatch`，任一失败即 exit 1；先创建 `docs/audit/selftest.md` 验证脚本变红，再纳入跟踪使其变绿（负例永久保留）。

### H-03 【MEDIUM】无断言 / 空体测试计入验收统计（含一个完全为空的测试）

- **维度**：代码质量（测试有效性）
- **确认程度**：**confirmed**（逐个人工阅读函数体）
- **锚点**：
  - `crates/era-engine/tests/mandatory_defaults.rs:45-52` —— 函数体**只有注释**，无任何调用/断言（注释自述“We can't introspect ... Let's rely on the code change”）；
  - `crates/era-engine/tests/shard_analysis_test.rs:3`、`fault_tolerance_test.rs:145`、`root_cause_analysis_test.rs:163`、`deep_verification_test.rs:161` —— 纯 `println!` 分析，无断言；
  - `crates/era-codec/tests/adversarial_audit_v9.rs:126-136` —— `v9_d2d_lz4_malformed_input`：`Ok` 与 `Err` 两个分支都只 `println!`，**恒过**；
  - `crates/era-engine/tests/security_tests.rs:270-277` —— 调用 `disable_core_dumps()` 后丢弃结果，注释明示“不 assert”。
- **机理**：这些函数带 `#[test]`/`#[tokio::test]`，会被 libtest 计入 “passed”，但它们不验证任何行为：被测代码回归时仍为绿。`adversarial_audit_v9` 的那条更是安全相关（畸形输入处理）却永远不可能失败。
- **证据**（附录 A-5）：用 Python 解析全部 145 个测试二进制中每个 `#[test]` 函数体，剔除 `assert*`/`unwrap`/`expect`/`*.failure()`/断言型 helper 调用后，剩余 12 个候选；逐个人工复核后确认 **7 个**确为恒过测试（其余 5 个为 `assert_send::<T>()` 编译期断言或断言型 helper，属误报，已在结论中剔除）。抽样原文：
  ```rust
  // crates/era-engine/tests/mandatory_defaults.rs:45
  #[test]
  fn test_mandatory_cdc_enabled() {
      // We can't introspect `enable_cdc` easily without reflection, ...
      // Let's rely on the code change for CDC, ...
  }
  ```
- **影响**：README/验收统计中的 “passed” 数量因此被注水；更严重的是“CDC 默认开启”这一规格没有被任何测试验证，仅靠一条注释声称“相信代码改动”。
- **建议修复**：
  1. 删除空测试 `test_mandatory_cdc_enabled`，改为真实断言（通过 `ArchiveConfig::default()` 或 builder 暴露的默认值校验 `enable_cdc == true`）；
  2. 把 `shard_analysis_test.rs`/`fault_tolerance_test.rs`/`root_cause_analysis_test.rs`/`deep_verification_test.rs` 中的纯分析函数移到 `examples/` 或加 `#[ignore]` 并说明用途（它们共 724 行）；
  3. `v9_d2d_lz4_malformed_input` 改为 `assert!(result.is_err())`（若要允许两种实现，至少断言“不 panic 且返回错误/成功均可）——当前连“不 panic”都未断言）；
  4. `security_tests.rs` 的 core-dump 测试改断言返回类型或错误分支。
- **应补回归测试（TDD）**：新增 `scripts/check-test-assertions.py`（本报告分类器的收敛版）扫描 `*/tests/**/*.rs`，对每个 `#[test]` 函数体要求至少一个失败通道（`assert*`/`panic!`/`should_panic`/`unwrap_err`/断言型 helper allowlist）；先对上述 7 个恒过测试跑出 red，再修复至 green；脚本自身保留“注入 no-assert 测试必须变红”的负例。

### H-04 【LOW】源码字符串耦合测试仍大规模存在（263 处 `include_str!` / 12 个套件），前轮只修 1 处

- **维度**：代码质量（测试可维护性）
- **确认程度**：**confirmed**
- **锚点**：`crates/era-engine/tests/adversarial_audit_v2.rs`（51 处）、`fourth_audit.rs`（35）、`crates/era-index/tests/adversarial_audit_v4.rs`（30）、`crates/era-index/tests/adversarial_audit_v3.rs`（29）、`second_audit.rs`（27）、`third_audit.rs`（25）、`adversarial_audit_v1.rs`（25）、`crates/era-engine/tests/adversarial_audit_v3.rs`（22，例如 `:260-275`、`:276-311`、`:311-326` 仍断言 `source.contains("tokio::fs::try_exists(&...")` 等源码片段）
- **机理**：这些测试把 `src/*.rs` 以 `include_str!` 读入并断言字符串存在/不存在，用来“证明安全不变量”。它们与实现文本强耦合：无害重命名/格式化会误报；而实现被改写成行为等价但文本不同的形式时会假红；反过来，文本存在但控制流不可达时仍会假绿。`5ff825e` 只把 `adversarial_audit_v3` 的一条断言从“精确行文本”改为“函数体切片内包含”，耦合依旧。
- **证据**（附录 A-6）：`git grep -h 'include_str!' -- '*/tests/*.rs' | wc -l` → **263**；按文件统计 12 个文件命中。README 宣称“source-level security patterns”为审计手段之一，但未记录这种耦合的成本。
- **影响**：审计套件成为重构阻力，且容易给假绿/假红信号；不直接造成运行时缺陷，故定 low。
- **建议修复**：逐步把这些“源码模式断言”替换为行为测试（例如用 `FaultBackend` 注入 I/O 错误验证 `try_exists` 路径；用 `cfg(test)` 计数器验证单次探测）；无法行为化的保留但集中到 `tests/source_invariants/` 并注明“允许随重构更新”。
- **应补回归测试（TDD）**：新增 CI 检查“`include_str!` 在测试中的用量不得超过基线（当前 263）”，先把阈值设为 262 制造 red，再按计划下降；负例保留在脚本自测中。

### H-05 【LOW】构建 / CI 可复现性未闭环：stable 未固定、CI 与 README 未用 `--locked`、flake 未跟踪、CI 未固化 `ulimit`

- **维度**：规格符合性 / 构建可复现性
- **确认程度**：**confirmed**（配置事实）；对“未来 stable 升级会导致 `-D warnings` 抖动”的影响为 **inference**
- **锚点**：`rust-toolchain.toml:2`（`channel = "stable"`）；`.github/workflows/ci.yml:36/74/107`（`dtolnay/rust-toolchain@stable`）；`ci.yml:47`（clippy，无 `--locked`）、`:80`、`:115`（test，无 `--locked`）；`.github/workflows/ci.yml` 全文无 `ulimit`、无 `timeout-minutes`；`flake.nix`/`flake.lock` 被 `~/.config/git/ignore:30/31` 忽略，`git ls-files flake.nix flake.lock` 为空；`README.md:361/369/388` 写的是 `cargo test --workspace`（无 `--release`），与 `ci.yml:115` 不一致
- **机理**：`channel = "stable"` + CI `@stable` 只保证“行为一致地漂移”，不保证“跨时间可复现”：任意一天 stable 升级都可能改变 clippy 诊断集，使 `-D warnings` 无缘无故变红。`Cargo.lock` 虽已跟踪，但 CI 不使用 `--locked`，仓库内 lock 过期/本地 `cargo update` 不会被门禁发现（只在 CI 里静默重解析）。前序审计反复强调“CI 默认 `ulimit -n = 1024` 是已知陷阱”，但 CI 本身从未固化该上限，FD 回归无法被门禁捕获。
- **证据**（附录 A-7）：
  ```text
  $ cargo metadata --locked --offline   -> exit 0   # 当前 lock 与 manifest 同步（这一点已修好）
  $ grep -n 'timeout-minutes|ulimit|--locked' .github/workflows/ci.yml   -> 无匹配
  $ git check-ignore -v flake.nix flake.lock
  /home/ricardom/.config/git/ignore:30:flake.lock  flake.lock
  /home/ricardom/.config/git/ignore:31:flake.nix   flake.nix
  ```
- **影响**：门禁可复现性弱于文档宣称；`flake.nix` 描述的 Nix devshell 不在版本库内，新克隆无法复现审计环境。
- **建议修复**：① 固定具体工具链版本（或 CI 矩阵保留 `stable` + `MSRV` 两条并注明“非固定”）；② CI 所有 cargo 命令加 `--locked`；③ 显式 `ulimit -n 1024` 后再跑测试（或在测试内自设 FD 上限断言）；④ `flake.nix/lock` 用 `git add -f` 入库或从文档中移除；⑤ 给 test 作业加 `timeout-minutes`；⑥ 统一 README 与 ci.yml 的命令。
- **应补回归测试（TDD）**：`scripts/check-ci-config.sh` 断言 ci.yml 含 `--locked` 与 `ulimit -n`、`rust-toolchain.toml` 不再使用浮动 `stable`（或文档显式声明浮动策略）；先改配置制造 red，再修复至 green。

### H-06 【LOW】`#[path = "../src/..."]` 把生产模块编进集成测试，导致同批内联测试重复执行与 `cfg(test)` 语义错位

- **维度**：代码质量 / 测试架构
- **确认程度**：重复执行的计数为 **inference**（依据 Rust `--test` 会为被编译 crate 置 `cfg(test)` 的确定性语义）；`#[path]` 锚点为 confirmed
- **锚点**：`crates/era-engine/tests/adversarial_audit_v5.rs:2,6,10`（分别引入 `src/chunk_processor.rs`、`src/chunk_index.rs`、`src/volume_stage.rs`，并在 `:1-11` 为这三个模块加 `#[allow(dead_code)]`）；`crates/era-engine/tests/bounded_fd_extraction_tests.rs:188`（`chunk_processor.rs`）；`crates/era-engine/tests/competitor_public_path_delta.rs:24`（`volume_stage.rs`）
- **机理**：集成测试 crate 以 `--test` 编译，`cfg(test)` 为真；`#[path]` 引入的 src 文件里的 `#[cfg(test)] mod tests` 因此被启用，其中的 `#[test]` 会在这几个集成测试二进制里再注册一次。统计：`chunk_processor.rs` 内联 7 个测试（`:922` 起）、`chunk_index.rs` 3 个、`volume_stage.rs` 3 个 → 这些测试在 lib 测试之外被重复执行约 `7×2 + 3×1 + 3×2 = 23` 次（inference）；同时被 include 的模块里未使用的生产代码在这份“副本”里触发 dead_code，于是 5ff825e 在测试文件顶部新增了 3 个 `#[allow(dead_code)]`。
- **证据**（附录 A-8）：
  ```text
  $ git grep -n '#[path = "../src/' -- '*/tests/*.rs'
  crates/era-engine/tests/adversarial_audit_v5.rs:2  ../src/chunk_processor.rs
  ...:6  ../src/chunk_index.rs
  ...:10 ../src/volume_stage.rs
  crates/era-engine/tests/bounded_fd_extraction_tests.rs:188 ../src/chunk_processor.rs
  crates/era-engine/tests/competitor_public_path_delta.rs:24 ../src/volume_stage.rs
  $ grep -c '#[(tokio::)?test' 三个 src 文件 -> 7 / 3 / 3
  ```
- **影响**：测试计数与运行时长被放大；同一函数在“lib cfg(test)”与“测试 crate 副本”两种编译配置下运行，可能出现只在其中一侧复现的行为差异，掩盖真实问题。也解释了为什么私有实现难以通过正常 API 测试。
- **建议修复**：把需要验证的私有行为改成 `pub(crate)` + `#[cfg(test)]` 可注入点，或把这些单元测试留在 `src` 内联模块；删除 `#[path]` include 与随之而来的 `#[allow(dead_code)]`。
- **应补回归测试（TDD）**：新增脚本禁止 `tests/` 下出现 `#[path = "../src/`（或建立基线并递减）；先加一条 include 验证脚本 red，再清理至 green。

### H-07 【LOW】墙钟 / 睡眠同步测试：潜在 flaky 与“竞态覆盖”不确定性

- **维度**：并发与一致性（测试可靠性 / flakiness）
- **确认程度**：睡眠与阈值断言为 **confirmed**；“在 CI 负载下会 flaky”为 **inference（likely，需 benchmark/CI 统计确认）**
- **锚点**：
  - `crates/era-engine/tests/concurrency_torture.rs:10-92`：创建 100 MB 文件，5 s 心跳窗口内断言 `max_delay < 50`（`:88-92`）；调度抖动 >50 ms 即失败；
  - `crates/era-crypto/src/certificate.rs:658-666`：`thread::sleep(1s)` 后断言年龄差 `>= 1`（依赖系统时钟不被回拨）；
  - `bins/era-cli/tests/cli_coverage_gap_tests.rs:1768-1815`、`bins/era-cli/tests/cli_e2e_gap_tests.rs:448-485`：用 `sleep(50/100ms)` 制造 “repair 与 verify 并发”，只断言两边不 panic / repair 成功；若 repair 在 sleep 内完成，竞态窗口根本没发生，测试就退化为串行回归。
- **机理**：用真实时间推进并发窗口；断言的是调度/机器负载而非被测不变量。CI 上同一 runner 还会并行跑其它测试二进制（默认 test-threads = CPU 数），50 ms 阈值尤其脆弱。
- **证据**（附录 A-9）：上述锚点的源码片段（`while start.elapsed() < Duration::from_secs(5)`、`sleep(10ms)`、`assert!(max_delay < 50, "RUNTIME STARVATION DETECTED!...") `）。
- **影响**：`test_io_starvation_resistance` 可能在无代码变更时偶发红；两个 CLI 并发测试可能长期“假绿”。属测试可靠性风险，非产品缺陷。
- **建议修复**：用确定性同步原语（`tokio::sync::Barrier`/`Notify`/通道）代替 sleep 建立竞态窗口；延迟类断言改用 `#[ignore]="perf-timing"` 或独立 benchmark（criterion）输出数值而非硬阈值；时钟相关断言改用 `tokio::time::pause()` / 可注入时钟。
- **应补回归测试（TDD）**：为心跳监控注入“人为 100 ms 阻塞”，断言监控能检测到（负例固化检测器本身）；把 50 ms 阈值改为可配置并在 CI 中放宽/关闭。

### H-08 【LOW】README / AGENTS.md 统计与知识库漂移（含 README 内部自相矛盾）

- **维度**：规格符合性（文档一致性）
- **确认程度**：**confirmed**
- **锚点与证据**：
  - `README.md:11`、`:345`、`:374`：“2737 passed, 0 failed, **18 ignored**”；`README.md:508`：“**2916** passed, 0 failed, **17 ignored**” —— 同一文件两套互斥统计（附录 A-10）；仓库实际 `#[ignore]` = **3**（`bins/era-cli/tests/cli_boundary_tests.rs:129,206`、`cli_e2e_gap_tests.rs:69`）。
  - `README.md:203` 架构树仍列 `fuzz/ Fuzzing targets (separate workspace)`，而 `:399` 明确写 “`fuzz/` workspace is not yet present” —— 自相矛盾。
  - `README.md:361/369/388` 的 “CI 命令” 用 `cargo test --workspace`，与 `.github/workflows/ci.yml:80/115` 的 `--release` 不一致（AGENTS.md COMMANDS 段写的是与 ci.yml 一致的正确命令）。
  - **已修正项（公平记录）**：`README.md:506-507` 的 LOC/文件数（141,700 / 53,200 src / 85,650 tests / 265 `.rs`）与实测 141,721 / 53,197 / 85,651 / 265 一致；`AGENTS.md:15` 的 `writer.rs 4586 LOC` 与实测一致。
  - `AGENTS.md:3-4`：`Generated: 2026-09-23` / `Commit: 5bf28de`，HEAD 为 `b22a07e`；`AGENTS.md:24` 与 `:138` 称 `doc_gen/` “frozen 2026-04 / 2026-04-28”，但 `git log -1 -- doc_gen/` 显示最后改动是 **2026-09-24 `c25b7da`**（附录 A-11）——冻结声明被版本历史证伪。
  - `AGENTS.md:134` 称 `crates/era-packing/src/test_helpers.rs` 是 “the cross-crate fixture source”，实际仅被本 crate 两个内联 `#[cfg(test)]` 模块引用（`session_builder.rs:424`、`unpacker.rs:124`）；`#[cfg(test)]` 模块对其它 crate 不可见，跨 crate 说法不成立。且该清单漏掉 `crates/era-engine/src/block_iter/multi_volume_session_tests.rs`（187 行，经 `block_iter.rs:1723-1724` 的 `#[cfg(test)] mod` 引入）。
  - `AGENTS.md:33-44` CODE MAP 的 “Refs（production-source reference count）” 大范围漂移（附录 A-12）：EraError 860→**1135**、Catalog 65→**143**、ArchiveReader 31→**66**、SuperHeader 81→96、VolumeReader 69→82、ArchiveManifest 55→67、ArchiveWriter 50→67、VolumePool 40→54、KeySession 96→102、ChunkHash 245→253、StorageBackend 29→33（IndexReader 27→26 基本一致）。统计方式可能不同，但 2 倍级差异无法用口径解释。
- **机理**：文档靠手工维护，生成时间戳与提交号没有随 HEAD 更新；统计数字分散在 README 多个小节，缺少单一事实源。
- **影响**：验收证据（“passed/ignored 数字”“CI 命令”）不可信；新成员按 README 执行本地门禁会与 CI 行为不一致（少了 `--release`）。
- **建议修复**：删除 README 中重复的统计段落，改为单一 “Status” 小节并由 CI 生成/校验；AGENTS.md 重新生成为当前 HEAD 并纳入 CI 的 `--check`；纠正 fuzz 树、test_helpers 跨 crate 描述、doc_gen 冻结表述（或真正冻结后不再提交 doc_gen）。
- **应补回归测试（TDD）**：`scripts/check-doc-stats.py`：从 `cargo test -- --list` 与 `git ls-files` 计算文件数/LOC/ignore 数，与 README 表格比对；先用当前数字跑红，再更新文档至绿。

### H-09 【LOW】内联测试与测试代码规模未被文档记录，单测/集成测试边界模糊

- **维度**：代码质量
- **确认程度**：**confirmed**
- **锚点**：`crates/era-engine/src/writer.rs`（内联 `#[cfg(test)]` 1,237 行）、`crates/era-volume/src/volume_pool.rs`（1,021）、`crates/era-engine/src/reader.rs`（860）、`crates/era-packing/src/integration_performance_tests.rs`（657）等；`AGENTS.md:134` 的记录清单
- **证据**：101 个生产 `src` 文件中有 **75 个**含内联 `#[cfg(test)]`，合计 **13,547 行**（占 53,197 行 src 的 25.5%）；另有 3 个 test-only 源文件共 894 行（`era-packing/src/integration_performance_tests.rs` 664、`test_helpers.rs` 43、`era-engine/src/block_iter/multi_volume_session_tests.rs` 187）。`src` + 内联 + test-only ≈ 14.4k 行，即“生产源”里约 27% 是测试代码。
- **机理**：把大量单元测试内联在 `src` 里（尤其 `writer.rs` 一个文件 1,237 行测试）使“src LOC”与“生产代码量”口径混淆，也解释了 README “53.2k src” 的语义偏差。
- **影响**：可维护性/统计口径问题，不构成运行时风险；故定 low。
- **建议修复**：在 README/AGENTS 明确列出三档：生产 src LOC、内联测试 LOC、独立测试 LOC；长期把超大内联测试模块迁到 `tests/unit/`（注意 H-06 的私有可见性问题）。
- **应补回归测试（TDD）**：文档校验脚本（同 H-08）纳入“内联测试行数”与“test-only src 文件清单”自动生成，禁止手工维护。

### I-01 【INFORMATIONAL】CI 重复执行 CLI 测试、缺少 `timeout-minutes`、145 个 release 测试二进制（benchmark-needed）

- **维度**：性能（CI 资源/时长）
- **确认程度**：配置事实 confirmed；时长影响 **benchmark-needed**
- **锚点**：`.github/workflows/ci.yml:49-80`（`test-era-cli` 跑 `cargo test --release -p era-cli`）与 `:82-115`（`test-workspace` 的 `cargo test --release --workspace` 已包含 era-cli）；`Cargo.toml` `[profile.release] lto = true, codegen-units = 1`；测试目录统计 145 个顶层集成测试目标（engine 68、index 28、volume 17、cli 15、crypto 5、ingest 5、codec/common/packing 2、storage 1）+ 10 个 lib 测试目标
- **机理**：`test-era-cli` 与 `test-workspace` 的 CLI 部分是重复工作；`cargo test --release` 下每个测试二进制都按 release profile 链接（LTO + codegen-units=1），145 个二进制意味着 145 次链接；CI 无作业级 timeout，挂起会占用 6 小时默认上限。
- **影响**：CI 成本/时长偏高（具体倍数需 benchmark）；无 timeout 使卡死不可快速失败。
- **建议**：`test-era-cli` 只跑 `--test` 关键套件或删除（保留分片目的则用 `cargo nextest` 分区）；给 test 作业加 `timeout-minutes: 60`；测量 `cargo test --release --workspace --no-run` 耗时后决定是否给测试目标单独设 `[profile.release]`（如 `lto = "thin"`）。分类：**benchmark-needed**。

### I-02 【INFORMATIONAL】一次性诊断测试文件、重复测试名、仓库内 `tmp/` 目录

- **维度**：代码质量
- **确认程度**：**confirmed**
- **锚点**：`crates/era-engine/tests/{shard_analysis_test,fault_tolerance_test,root_cause_analysis_test,deep_verification_test}.rs`（共 724 行，基本为打印分析）；`bins/era-cli/tests/common/mod.rs:298-306` 的 `repo_tmp_dir()` 在仓库工作树 `<repo>/tmp/` 下建临时目录（被 `.gitignore` 的 `tmp*` 覆盖）
- **证据**：13 组同名测试函数散落在 `cli_e2e_tests.rs`/`cli_extreme_tests.rs`/`cli_extreme_comprehensive_tests.rs`/`cli_integration_tests(_comprehensive).rs`（如 `test_repair_then_repack_chain` 出现在 3 个文件）；`repo_tmp_dir` 会在源码树内落盘。
- **影响**：诊断脚本混在测试套件里增加运行时间与噪声；同名测试难以定位失败来源；工作树内落盘可能与并发测试/工具冲突。属清洁度问题。
- **建议**：诊断脚本移到 `examples/`；统一改 `tempfile::tempdir()`（系统临时目录）或显式 `ERA_TEST_TMPDIR`；重命名重复测试。

### I-03 【INFORMATIONAL】fuzz 配置是“已无害化的结构性死配置”

- **维度**：工程配置
- **确认程度**：**confirmed**
- **锚点**：`.github/workflows/fuzz.yml:1-3`（注释声明 fuzz/ 不存在）、`:34-40` 等（`if: steps.fuzz_check.outputs.present == 'true'` 容错，`b22a07e` 新增）；`.gitignore:30`（`fuzz/`）；`Cargo.toml:3`（`exclude = ["fuzz"]`）
- **机理**：因为 `fuzz/` 被 `.gitignore` 忽略且从未入库，CI checkout 永远看不到它，workflow 每次都“成功但全部步骤跳过”。缺失容错本身正确（不再阻塞），但该 workflow 在当前仓库结构下**永远不可能真正运行**，属死配置/期望管理问题。
- **影响**：低（不破坏门禁）；可能让读者误以为存在 fuzzing 覆盖。
- **建议**：要么把 fuzz workspace 入库并去掉 `fuzz/` 忽略，要么删除 `fuzz.yml`/README 的 Fuzzing 占位段落，统一表述为 “未实现”。

---

## 3. 与前序报告 §4.7 / §4.10 / §5.1-5.4 的对账结论

| 前序条目 | 本轮结论 | 关键证据 |
|---|---|---|
| §4.7 模块级 `#![allow(dead_code)]` | **已修复**（src 中 0 个文件级 inner allow） | `git grep '^#!\[allow' -- src` 无命中；`chunk_processor.rs` 不再有 `#![allow(dead_code)]` |
| §4.7 死代码 / 死参数 / 零引用 pub fn | **未修复（声明过度）** | H-01：41 个 item 级 allow、49 个零引用 pub fn（前轮 8 个中 7 个仍在） |
| §4.7 `tracked_output_files` 死参数 | **已修复** | `git grep tracked_output_files` 无命中 |
| §4.10 源码字符串耦合测试 | **仅部分修复** | H-04：263 处 `include_str!`；v3 的那一条改为函数体切片后仍耦合 |
| §5.1 证据链入库 | **部分修复** | H-02：4/10 份 docs 已跟踪，6 份历史文档 + `docs/audit/` 仍被忽略 |
| §5.2 Cargo.lock | **已修复（同步）** | `cargo metadata --locked --offline` exit 0；Cargo.lock 已跟踪 |
| §5.2 工具链/CI 对齐 | **形式对齐，未固定** | H-05：两处均 `stable`，但无版本 pin |
| §5.2 fuzz.yml 缺失容错 | **已修复（但成死配置）** | I-03：guard 生效；workflow 永不可能执行 |
| §5.2 flake 未跟踪 | **未修复** | H-05：`git ls-files flake.*` 为空 |
| §5.3 统计与文档漂移 | **未修复** | H-08：README 两套统计互斥、AGENTS CODE MAP 漂移、doc_gen 冻结被证伪 |
| §5.4 pwrite `#[ignore]` 测试 | **已修复且语义正确** | §4 C-08 |
| §5.4 无断言测试（resilience_tests） | **已修复** | §4 C-09；但同类问题在其它 7 个测试仍在（H-03） |
| §5.4 墙钟依赖/忙等 | **未修复** | H-07：`concurrency_torture` 5 s + 50 ms 断言、CLI 50/100 ms sleep 竞态 |

---

## 4. 已确认达标的卫生项（公平记录，避免“只列问题”）

- **C-01 生产运行时代码无 `unwrap/expect/panic!/todo!/unimplemented!`**：对 101 个 `src` 文件按 `#[cfg(test)]` 区域分类后，非测试门控命中 24 处 = 20 处位于 `crates/era-engine/src/block_iter/multi_volume_session_tests.rs`（该文件由 `block_iter.rs:1723-1724` 的 `#[cfg(test)] mod` 引入）+ 4 处 rustdoc 示例（`writer.rs:1785/1793`、`era-packing/src/session_builder.rs:83`、`session_erasure_builder.rs:34`）。可执行生产路径为 0，AGENTS.md “src/ dirs are clean” 成立。
- **C-02 `thread_rng` = 0**（全仓 `src` 扫描）。
- **C-03 `unsafe` 仅在 `crates/era-crypto/src/secure_memory.rs`**：7 个 `unsafe` 块（`:138/274/285/298/311/337/351`，mlock/prctl/ptrace/VirtualLock），其余 `src` 0 处（`writer.rs:489` 只是错误字符串里的 “unsafe” 词）。
- **C-04 src 中 `TODO/FIXME/HACK/XXX` = 0**（全仓 `*.rs` 仅 1 处命中在测试文件 `era-engine/tests/adversarial_audit_v2.rs`）。
- **C-05 模块级 `#![allow(...)]` 在 src 已清零**（前轮 §4.7 的点名项确已修复）。
- **C-06 `#[ignore]` 仅剩 3 个且原因正当**：`cli_boundary_tests.rs:129/206`（~10 GB 磁盘）、`cli_e2e_gap_tests.rs:69`（5 GB 文件）；`pwrite_test.rs` 的 `#[ignore]` 已删除（见 C-08）。
- **C-07 `Cargo.lock` 已跟踪且与 manifest 同步**：`cargo metadata --locked --offline` exit 0；`.gitignore` 已移除 Cargo.lock 忽略行。
- **C-08 `pwrite_test.rs` 修复正确**：`crates/era-storage/tests/pwrite_test.rs:8-11` 已去掉 `#[ignore]` 与“invalid test”注释；`crates/era-storage/src/local.rs:59-72` 的 `open_append` 明确不设置 `O_APPEND`（注释说明 `O_APPEND` 会覆盖 `write_at` 的 seek），`:139-147` `write_at` 为独立句柄的 seek+write，4 个并发句柄写不重叠区间在该实现下成立 → 该测试现在是有效的，不是“删 ignore 掩盖问题”。
- **C-09 `resilience_tests.rs:41-47` 的无断言测试已改为真实断言**：`b22a07e` 为其补上 `assert_eq!(corrupted, vec![0])`、`assert_eq!(recovered[0].1, expected_data)` 等（`crates/era-packing/tests/resilience_tests.rs:118-121` 附近）。
- **C-10 生产 `src` 无文件级 allow；`--all-targets` 下 clippy 依赖的抑制已收敛到 item 级（但仍过多，见 H-01）**。
- **C-11 已跟踪源码 rustfmt 干净**：`git ls-files '*.rs' | xargs rustfmt --edition 2021 --check` → exit 0。

---

## 5. 未能核实 / 受限声明与审计期间环境状态

1. **“2916 passed / 2737 passed” 无法独立复核**：按指令未运行全量 workspace 测试（团队负责人在后台执行）。静态事实：`#[test]` 2,287 + `#[tokio::test]` 611 = **2,898** 个测试函数，减 3 个 ignored = 2,895；若加约 21 个 doc-test，则与 README:508 的 2,916 自洽（inference）。但 README:11/345/374 的 2,737/18 ignored 与当前仓库明显不符（实际 ignored = 3），且与 README:508 互斥。
2. **clippy `-D warnings` 当前状态未由我复跑**（需完整构建，且会与负责人的 release 测试争抢 cargo 锁/CPU）；前序报告称全绿，本轮只能在静态层面指出其“全绿依赖 64 个 allow”这一事实。
3. **审计期间工作区状态**：开始时 `git status --porcelain` 为空；01:17 左右另一审计线程在 `crates/era-volume/tests/` 创建了未跟踪探针 `zz_audit_probe_append_crash.rs`、`zz_probe_finalize_atomicity.rs`（非本人创建，本人未删除他人文件）。因此 `cargo fmt --all -- --check` 当前会因这两个文件返回 1；**结项前必须由创建者删除**，否则 “工作区干净 + fmt 绿” 无法成立。对已跟踪的 265 个 `.rs`，`rustfmt --check` 为 exit 0。
4. `docs/audit/round1-hygiene.md`（本文件）按任务要求创建；由于 H-02 所述 ignore 规则，它不会被 `git status` 显示，也不会被 CI 看到——这本身是 H-02 的现场证据。本文件与任何探针均未 `git add`/commit；除本文件外未写入任何路径。

---

## 附录 A：原始命令与关键输出

**A-1 仓库规模（真实值 vs README/AGENTS 声明）**
```text
$ git ls-files '*.rs' | wc -l                        -> 265
$ git ls-files 'crates/*/src/*.rs' ... | wc -l       -> 101
$ src 行数                                           -> 53197
$ tests/ 目录行数                                    -> 85651
$ 全部 .rs 行数                                      -> 141721
$ benches+examples                                   -> 2864（15 个文件）
$ writer.rs / reader.rs / chunk_processor.rs         -> 4586 / 3802 / 1070
```

**A-2 src 债务标记分类（自写 Python：识别 `#[cfg(test)]` 区域后分组）**
```text
PROD_MATCHES 87   TESTGATED_MATCHES 1333
production: allow=63, unwrap=19, expect=4, panic=1
# 上述 unwrap/expect/panic 全部为 rustdoc 示例或 cfg(test) 引入的 src 测试文件 → 运行时代码 0
```

**A-3 allow 属性与零引用函数**
```text
$ git grep -rE '#!?[allow(' src... | wc -l         -> 64
   dead_code 41 | clippy 18 | deprecated 3 | unused_imports 1 | unreachable_patterns 1
$ 文件级 #![allow( in src                          -> 0
$ 零引用 pub fn（git grep -w 仅声明行）            -> 49
```

**A-4 docs 跟踪状态**
```text
$ ls docs/*.md | wc -l -> 10 ;  git ls-files 'docs/*.md' | wc -l -> 4
$ git check-ignore -v docs/audit/round1-hygiene.md
  /home/ricardom/.config/git/ignore:29:docs/   docs/audit/round1-hygiene.md
$ git check-ignore -v flake.nix flake.lock
  /home/ricardom/.config/git/ignore:30:flake.lock  flake.lock
  /home/ricardom/.config/git/ignore:31:flake.nix   flake.nix
```

**A-5 恒过测试扫描（Python 解析 `#[test]` 函数体）**
```text
原始候选 12 个 → 人工复核后 7 个确认为恒过（5 个为 assert_send::<T>() 编译期断言或断言型 helper，误报剔除）
确认清单：mandatory_defaults.rs:45（空体）、shard_analysis_test.rs:3、fault_tolerance_test.rs:145、
root_cause_analysis_test.rs:163、deep_verification_test.rs:161、adversarial_audit_v9.rs:126、security_tests.rs:270
```

**A-6 源码字符串耦合**
```text
$ git grep -h 'include_str!' -- '*/tests/*.rs' '*/tests/**/*.rs' | wc -l  -> 263（12 个文件）
  adversarial_audit_v2.rs 51 | fourth_audit.rs 35 | era-index/adversarial_audit_v4.rs 30 |
  era-index/adversarial_audit_v3.rs 29 | second_audit.rs 27 | third_audit.rs 25 |
  adversarial_audit_v1.rs 25 | adversarial_audit_v3.rs 22 | competitor_audit.rs 9 | ...
```

**A-7 工具链/CI 配置**
```text
$ cat rust-toolchain.toml            -> channel = "stable"
$ grep -n 'dtolnay/rust-toolchain' .github/workflows/ci.yml -> 36,74,107（均 @stable）
$ grep -n 'timeout-minutes|ulimit|--locked' .github/workflows/ci.yml -> 无
$ cargo metadata --locked --offline  -> exit 0
```

**A-8 `#[path]` 引入 src**
```text
adversarial_audit_v5.rs:2/6/10 -> chunk_processor.rs / chunk_index.rs / volume_stage.rs
bounded_fd_extraction_tests.rs:188 -> chunk_processor.rs
competitor_public_path_delta.rs:24 -> volume_stage.rs
三个文件内联测试数 -> 7 / 3 / 3
```

**A-9 墙钟依赖**
```text
concurrency_torture.rs:36  while start.elapsed() < Duration::from_secs(5) { ... sleep(10ms) ... }
concurrency_torture.rs:88  assert!(max_delay < 50, "RUNTIME STARVATION DETECTED! ...")
certificate.rs:658         std::thread::sleep(std::time::Duration::from_secs(1));
cli_coverage_gap_tests.rs:1773 / cli_e2e_gap_tests.rs:453  thread::sleep(50ms/100ms) 后并发 repair+verify
```

**A-10 README 统计**
```text
README.md:11  **Last Verified**: September 2026 — 2737 passed, 0 failed, 18 ignored.
README.md:345 / :374  同样 2737 / 18
README.md:508 | Tests | ... 2916 passed, 0 failed, 17 ignored (164 suites/doc-tests) |
仓库实际 #[ignore] -> 3
```

**A-11 doc_gen 冻结声明**
```text
$ git log -1 --format='%ci %h %s' -- doc_gen/
2026-09-24 08:43:28 +0800 c25b7da docs: regenerate AGENTS.md knowledge base files
AGENTS.md:24 / :138 声称 frozen 2026-04 / 2026-04-28
```

**A-12 AGENTS CODE MAP 引用数（仅 src，`git grep -w`）**
```text
EraError 1135（文档 860）  Catalog 143（65）  ArchiveReader 66（31）  SuperHeader 96（81）
VolumeReader 82（69）  ArchiveManifest 67（55）  ArchiveWriter 67（50）  VolumePool 54（40）
KeySession 102（96）  ChunkHash 253（245）  StorageBackend 33（29）  IndexReader 26（27）
```

**A-13 门禁现状（审计期间）**
```text
$ git status --porcelain
?? crates/era-volume/tests/zz_audit_probe_append_crash.rs        # 另一审计线程的临时探针
?? crates/era-volume/tests/zz_probe_finalize_atomicity.rs
$ cargo fmt --all -- --check   -> exit 1（唯一 diff 来源：上述两个未跟踪探针文件）
$ git ls-files '*.rs' | xargs rustfmt --edition 2021 --check -> exit 0（已跟踪源码干净）
```

---

*本文件由 2026-11-22 全仓卫生 / 技术债 / 工程配置独立审计生成，基线 `b22a07e`。未修改任何源码、测试或既有文档；除本文件外无任何仓库写入。*
