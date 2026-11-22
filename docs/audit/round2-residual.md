# Round 2 独立复核：遗留 findings 与技术债回归（residual）

- 仓库: `/home/ricardom/code/github.com/zapsaang/era-core`，分支 `feat_fly`，HEAD `b22a07e` + 未提交 round-1 修订
- 复核范围: 当前工作树全仓（只读）；重点为 round-1 修订 diff（26 文件，+1247/−329）与未修订遗留 findings
- 工具链: cargo/rustc/clippy 1.99.1（nix store 路径），`CARGO_TERM_COLOR=never`，测试统一 `ulimit -n 1024`
- 方法: 静态 diff 复核 + 已构建产物直接执行（避免与 root 的全量门禁抢 cargo 锁）+ 定向行为探针
- 事实/推断: 每条 finding 显式标注。命令输出为节选。

## 0. 结论摘要

**放行结论：BLOCK（不建议合并/交付当前工作树）。** 两条独立理由：

1. **round-1 修订自身让门禁变红**：新增的“活跃主头 digest 校验”在 `ArchiveReader::open` 硬失败，导致主头“可解析但字节被篡改”的归档**无法打开、无法 verify、无法 extract、无法 repair**，且失败的是一个**未修改的既有回归测试**。root 后台门禁日志已记录 `cli_rc=101`。
2. **Round-1 判定的 High RF-01 完全未修订**：append finalize 的 truncate→footer 崩溃窗口仍在（`crates/era-volume/src/writer.rs:256-265, 832-877`，该文件不在本轮 diff 中），且 RF-03/RF-06 同样未动。RF-01 是 round-1 唯一未闭环的 High。

修订有效性方面：RF-02/04/05/07/12/13/14/20/21/22/24 的修复**实测成立**，但 RF-02/05/07/08 各自引入了新问题（R2-01/02/03/04），其中 R2-01 为 High 阻塞项。

严重度统计（本轮新发现，confirmed）：High 1、Medium 3、Low 7、Informational 4。

---

## 1. 门禁与可交付性现状

### 1.1 门禁：cli 测试已红（决定性证据）

root 后台全量门禁日志 `/tmp/era_ci_round1.log`（对**当前工作树**运行）：

```
$ grep -nE 'FAILED|test result:' /tmp/era_ci_round1.log
95:test random_offset_corruption::test_repair_corruption_at_multiple_offsets ... FAILED
170:test result: FAILED. 27 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 4.53s
...
error: test failed, to rerun pass `-p era-cli --test cli_coverage_gap_tests`
cli_rc=101
```

失败原因（日志内）：

```
 INFO Opened 6 volumes at sequences [0, 1, 2, 3, 4, 5] (total expected: 6)
Error: Failed to open archive
Caused by:
    Integrity error: Volume 0 primary header bytes do not match the authenticated manifest header digest
```

- 失败用例文件 `bins/era-cli/tests/cli_coverage_gap_tests.rs:1467` **未在本轮 diff 中**，即 HEAD 绿、修订后红。
- 报告撰写时 `cargo test --release --locked --workspace` 仍在编译/运行（root 后台），未取得 workspace 完整结果；但 cli 门禁已确定失败，单独即阻塞。

### 1.2 工作树状态

```
 M 26 个已跟踪文件（ci.yml/.gitignore/AGENTS.md/README.md/engine reader+repair/ingest/storage/volume + 8 个测试文件）
?? 5 个新测试文件 + docs/audit/（8 个 .md）
```

- 无残留临时探针（`zz_*`/`*probe*` 仅在已忽略的 `.omo/` 证据目录内，不属于交付物）。
- `docs/audit/` 已不再被 ignore（`git check-ignore` 返回否定规则 `!docs/audit/**`），但**仍未 `git add`**，交付前需显式加入。
- 6 份历史 docs（`docs/*2026-09-29.md`、`*2026-10-10*.md` 等）仍被 `*.md` 忽略（RF-10 只是部分缓解）。

---

## 2. 本轮新发现（R2-）

### R2-01【HIGH｜并发与一致性 / 数据可用性 / 测试可信度】**CONFIRMED — 阻塞**

- **file:line**
  - 新增检查调用点：`crates/era-engine/src/reader.rs:1541-1548`（`load_manifest` 内，open 必经）
  - 新增实现：`crates/era-engine/src/reader.rs:2856-2890`（`verify_active_primary_headers`），硬失败文案在 `:2879`
  - 被阻断的既有恢复能力：`crates/era-engine/src/repair.rs:519-545`（`volume_needs_header_repair` 对比 primary/backup 头字节）
- **机理**：RF-07/LL-04 的修复在 `ArchiveReader::open` 阶段对**每个 primary header** 重读并比对 manifest 的认证 digest，不匹配即 `EraError::IntegrityError`。但“主头字节被篡改/位翻转（含 4096 字节 padding）而 protobuf 仍可解析”正是既有 repair 路径要修的对象：repair 通过 `volume_needs_header_repair` 发现 primary≠backup，再以**认证过的 backup 头**回写 primary。现在 open 先失败，repair 根本无法进入；extract/verify 也一并被锁死。
- **证据（事实）**

  1) 门禁红（见 §1.1），失败用例未修改。

  2) 用当前树构建的 `target/release/era`（构建时间 02:02，晚于修订）直接复现（257 行脚本节选）：

  ```
  === baseline verify ===            baseline_verify_rc=0
  === verify: 100 flipped bytes at offset 1000 (header region) ===
  INFO Opened 6 volumes at sequences [0, 1, 2, 3, 4, 5] (total expected: 6)
  Error: Failed to open archive
  Caused by:
      Integrity error: Volume 0 primary header bytes do not match the authenticated manifest header digest
  === extract ===                    (同一 Integrity error，rc=1)
  === repair --force ===             (同一 Integrity error，rc=1)
  === control: magic corrupted at offset 0 (backup header 恢复路径) ===
  magic_verify_rc=1  magic_extract_rc=0  magic_repair_rc=0  magic_verify_after_repair_rc=0
  ```

  即：magic 损坏（header 无法解析）时 backup 恢复路径正常、repair 可修复；而 header **可解析但 digest 不匹配**时归档被彻底锁死。

  3) 直接运行当前树构建的失败测试二进制（无需 cargo）：
  ```
  $ target/release/deps/cli_coverage_gap_tests-07a1e7fe13438601 \
      random_offset_corruption::test_repair_corruption_at_multiple_offsets --test-threads=1
  test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 27 filtered out
  ```

- **推断（明确标注）**：`verify_active_primary_headers` 本身对“认证的 backup 头存在”这一信息完全未利用；fail-closed 与仓库既有的“备份头恢复 + repair”设计相冲突。此外 `random_offset_corruption` 的其它偏移（含 4096 备份 footer）在本用例中尚未跑到（首轮即失败），全量 workspace 可能还有同源失败。
- **建议**：digest 不匹配时不要 open 硬失败——若 backup header 通过 digest 认证，则回退使用 backup header 并标记 `Degraded`（保留 `header_recovered_from_backup` 语义，使 repair 可达）；或将强校验移到 `verify()`/`repair` 完成后。补负例测试：“header padding 位翻转后 extract/verify/repair 均可恢复”。

### R2-02【MEDIUM｜安全 / 资源】RF-02 修复的副作用：默认解包全局上限被移除，但 CLI 没有任何 opt-in 入口

- **file:line**：`crates/era-engine/src/reader.rs:70-108`（`ExtractOptions.max_total_output_bytes: Option<u64>`，默认 `None`）、`:2326-2360`；CLI 构造点 `bins/era-cli/src/commands.rs:955`（`ExtractOptions::new(output).overwrite(force)`）、`:2673`；`bins/era-cli/src/main.rs` 无 `--max-output*` 参数（`grep max-output` 无结果）。
- **机理**：原 `MAX_EXTRACTION_MEMORY = 8 GiB` 全局上限被删除，改为库 API 可选预算。CLI 是主要使用者，却没有暴露该预算 → `era extract` 对不可信归档**不再有任何端到端输出上限**（仅剩 per-block 256 MiB、per-shard、per-file 100 GiB 声明上限）。在 dedup 引用放大场景（同一 chunk/block 被 catalog 多次引用）下，磁盘/IO 放大不受总量约束。
- **证据**：
  ```
  $ grep -n 'ExtractOptions' bins/era-cli/src/commands.rs
  955:    let options = ExtractOptions::new(output).overwrite(force);
  2673:    .extract_all(&era_engine::ExtractOptions::new(&extract_dir))
  $ grep -nE 'max_total_output_bytes|max-output' bins/era-cli/src/main.rs bins/era-cli/src/commands.rs
  （无输出）
  ```
  修复本身成立：默认不设上限，避免 >8 GiB 合法归档必然失败（新增单测 `reader.rs:3860/3886/3918` 通过）。
- **是否 confirmed**：代码事实 confirmed；放大可利用性 inference。
- **建议**：CLI 增加 `--max-output-bytes`（默认建议保留一个较宽松值或至少文档化“默认无全局上限”），并在 README 的安全/限制章节写明。

### R2-03【MEDIUM｜兼容性 / 运维】RF-05 修复过度收紧：walked 目录里出现任意 symlink 会让整次 create 失败

- **file:line**：`bins/era-cli/src/commands.rs:587-591`（`anyhow::bail!("Refusing to archive symbolic link ...")`）、`:579-585`（depth 0 特判）。
- **机理**：旧行为是 `filter_map(|e| e.ok())` 静默跳过 symlink 并 rc=0；新行为在遍历到的第一个 symlink 处**整体中止**。对常见树（`node_modules`、`/etc`、含软链的备份源）属于 “合法场景失败”，是 CLI 行为破坏（不是安全修复的必然结果；也可 warn+skip+计数）。
- **证据**（当前树 binary 实测）：
  ```
  $ era create tree --output sym.era --password pwd      # tree/link.txt -> a.txt
  create_symlink_rc=1
  Refusing to archive symbolic link 'tree/link.txt': symlinks are not supported; remove or replace the link and re-run
  $ era create linkdir linkfile.txt ...                  # 显式命名的 symlink 输入
  create_explicit_symlink_rc=0                           # 显式输入仍跟随，兼容保留
  ```
  `--help` 的 long_about 已更新（`bins/era-cli/src/main.rs:51-58`），但 README 未给出迁移说明。
- **建议**：默认 warn+skip+计数（或提供 `--symlink=reject|skip`），至少把“含 symlink 即失败”写入 README/CHANGELOG。

### R2-04【MEDIUM｜测试可信度】H-03/RF-08 的“修复”是自证式测试：断言的是测试内重新实现的算法，不是生产代码

- **file:line**：
  - `crates/era-engine/tests/shard_analysis_test.rs:9-16` 新增本地 `fn distribute(...)`，全文件只断言该本地实现的性质；
  - `crates/era-engine/tests/fault_tolerance_test.rs`（`test_shard_distribution_pattern`）仍在测试内自行重算 `(shard_idx + block_seq) % vol`；
  - `crates/era-engine/tests/deep_verification_test.rs`、`root_cause_analysis_test.rs` 同理（本地重算 `shards_per_vol = total.div_ceil(vol)` 与容错公式）。
  - 生产实现 `crates/era-volume/src/distribution.rs` / `volume_pool.rs` **完全未被调用**。
- **机理**：页面里已不再是“print-only 恒过”，因此 `hygiene_guards_test.rs:72-109` 的“含 assert 即通过”扫描判定为已修复；但生产分布算法回归时这些测试**仍为绿**。这正是 H-03 想消灭的“绿而无检查”，只是从空体换成了自洽重算。
- **证据**：`grep -n 'fn distribute' crates/era-engine/tests/shard_analysis_test.rs` → `:9`；四个文件均无 `era_volume::distribution`/VolumePool 调用（grep 无匹配）。
- **建议**：改为调用生产分布/容错 API 断言（或对 `distribution.rs` 的公开函数做 property test）；`hygiene_guards_test` 应至少禁止“测试内重新实现被测算法”这种模式（例如要求审计测试引用生产符号）。

### R2-05【LOW｜兼容性 / API】**CONFIRMED**：`ExtractOptions` 新增公开字段是破坏性 API 变更

- `crates/era-engine/src/reader.rs:82` 新增 `pub max_total_output_bytes: Option<u64>`。仓库内所有 struct-literal 构造点已同步（`crates/era-engine/tests/third_audit.rs:1388/1463`），但外部下游用结构体字面量构造会编译失败。仓库状态为 “Pre-alpha — API unstable”，可接受，但需在变更记录中声明。

### R2-06【LOW｜代码质量】**CONFIRMED**：修订新增 1 个 `#[allow(unused_mut)]`

- `crates/era-storage/src/local.rs:42`。跨平台 cfg 下确有必要（`custom_flags` 仅 unix），但使 `#[allow(...)]` 总数从 64 增至 65，与 H-01/RF-09 “清理 allow 债”的方向相反；建议改用 `#[cfg_attr(..., allow(unused_mut))]` 或直接构造两条 cfg 分支以不新增 allow。

### R2-07【LOW｜代码质量】新增重复实现：footer 读取/损坏检测逻辑存在两份

- `crates/era-engine/src/reader.rs:2937-2950`（`read_footer_bytes`）
- `crates/era-engine/src/repair.rs:348-361`（`read_valid_footer`）；且 `repair.rs:363-382`（`volume_needs_footer_repair`）与 `repair.rs:384-430`（`plan_volume_footer_repairs`）重复读两份 footer 并做同样判定。三处逻辑一致但分散，后续 footer 语义变更（如 footer 长度/校验）易漂移。建议下沉到 `era-volume`（`VolumeReader` 提供 `footer_copies()`）。

### R2-08【LOW｜可运维性】footer 修复不进入 RepairStats/报告统计

- `crates/era-engine/src/repair.rs:884-889`（`apply_footer_repairs`）成功后 `RepairStats` 无 footer 字段；非 EC 分支 `:892-899` 直接返回 `RepairStats::default()`。实测 CLI 只打印 `Shards repaired: 0`（footer 修复仅有一条 tracing `INFO Restoring footer copy at offset 4096`）。dry-run 与实修在统计上无法区分。建议 `RepairStats` 增加 `footers_repaired`，CLI 输出。

### R2-09【LOW｜性能 / 语义】create 输入收集对每个目录多做一次 `read_dir`，且把“空 symlink 目录”归入“空目录”告警

- `bins/era-cli/src/commands.rs:598-614`（每个 `is_dir` 都调 `directory_is_empty`，即 walkdir 之后再次 `read_dir`，O(目录数) 额外 syscall）；`:579-585`（depth0 symlink 命中时按“empty directory”上报，文案与实体不符）。
- 影响小；建议仅在目录无子条目时判定（walkdir 已给出 depth/子项信息），或缓存。

### R2-10【LOW｜测试质量】H-04 反向：修订新增了“源码字符串耦合”型治理测试

- `crates/era-engine/tests/hygiene_guards_test.rs:131-168` 读取 `.github/workflows/ci.yml` 文本并断言 `timeout-minutes:` 计数恰为 3、包含固定子串；`:171-215` 解析 README 文本统计。作为 CI/文档治理可理解，但属于 H-04/RF-19 同类反模式且偏脆（未来新增 job/调整措辞即红）。建议至少把“计数==3”改为“每个 job 都有 timeout”的结构化解析，并在 AGENTS 中登记为例外。

### R2-11【LOW｜文档 / 工程】**CONFIRMED**：README/AGENTS 测试统计已开始漂移，且门禁只保证“自洽”不保证“正确”

- README: `README.md:11/345/377/511` 均写 “2916 passed, 0 failed, 17 ignored (2026-11-22, `b22a07e`)”。
- 当前树在 `b22a07e` 之上新增 **5 个测试文件 / 33 个测试**（见 §7.2），且修改了 8 个既有测试；`b22a07e` 从未产生该数字对应的通过数 → “Last Verified … (b22a07e)” 已不准确。
- `AGENTS.md:7` “~141.7k LOC / 265 .rs files” 已过期：`git ls-files '*.rs'` 为 265（HEAD 跟踪），`find crates bins -name '*.rs'` 为 **270**。
- `hygiene_guards_test.rs:171-215` 只断言 README 中 passed/ignored 各只有一个取值、含 `--locked/--release`，**不校验数值真实性**；AGENTS 的 LOC/文件数完全无门禁。
- 建议：(1) 统计行改为“截至 commit X 的实测值”，提交后由 CI 的 `test result: ok. N passed` 汇总生成/校验；(2) 在 `hygiene_guards_test` 增加“README 数字与最近一次 `cargo test` 汇总一致”或改为不写死总量只写命令；(3) AGENTS 的 LOC/文件数纳入同一 guard。

### R2-12【LOW｜兼容性 / 行为漂移】`Chunker::new` 对非法配置静默回退默认，而非报错

- `crates/era-ingest/src/chunker.rs:44-58`：非法配置 → warn 日志 + `ChunkerConfig::default()`。修复了 RF-20 的 panic，但静默改变 FastCDC 参数会静默改变 chunk 边界/去重效果；且 `StreamingChunker::new`（`:180-190`）对非法配置把 buffer_size 置 0、依赖 `next_chunk` 首行校验（`:248`）兜底，属脆弱耦合。建议 `Chunker::new` 保持 infallible 但返回 `Default` 的行为文档化到 crate 文档，或让引擎侧改用 `try_new` 并上抛 `InvalidConfig`。

### R2-13【INFORMATIONAL｜性能】每次 open/verify 新增 header/footer 额外读

- `reader.rs:1541` 每次 open 对每卷重读 4 KiB primary header；`reader.rs:2794` 每次 verify 对每卷再读 2×128 B footer（且 `repair` 的 `volume_needs_footer_repair` 已先读过一次）。量级小（相对 verify 的整卷 catalog 扫描可忽略），但属于新增基准未评估项（与 RF-17 同类，benchmark-needed）。

### R2-14【INFORMATIONAL｜工程】docs/audit 证据链仍处于“可跟踪但未跟踪”状态

- `.gitignore:28-36` 已放行 `docs/audit/**`（`git check-ignore -v docs/audit/round1-consolidated.md` → `!docs/audit/**`），但 `git status` 显示 `?? docs/audit/*.md`；6 份历史 docs 仍被 ignore。交付时需 `git add docs/audit`，并决定是否把 6 份历史文档也纳入（或文档化“环境限制”）。

### R2-15【INFORMATIONAL｜测试发现】**CONFIRMED**：5 个新测试文件均被 Cargo 自动发现并已构建

`crates/*/tests/*.rs`、`bins/*/tests/*.rs` 均位于标准自动发现路径。构建产物证据：

```
target/release/deps/chunker_config_validation-64ca35e747728e9d
target/release/deps/hygiene_guards_test-803bd7a29a20a683
target/release/deps/local_backend_hardening-293c826f9e93c0cb
target/release/deps/round1_cli_create_repair_tests-be755346d1b2aeb9
target/release/deps/round1_reader_fixes-9b535390721e1997
```

直接运行结果（当前树二进制）：`round1_reader_fixes` 3/3 ok；`hygiene_guards_test` 4/4 ok；`chunker_config_validation` 12/12 ok；`local_backend_hardening` 5/5 ok；`round1_cli_create_repair_tests` 9/9 ok。

---

## 3. 修订有效性复核（round-1 声明“已修复”的项目）

| 编号 | 结论 | 证据 |
|---|---|---|
| RF-02 8 GiB 解包上限 | **修复成立（有副作用 R2-02）** | `reader.rs:70-108,2326-2360`；新增单测默认无上限/显式预算失败清理（直接运行 3/3 ok） |
| RF-04 footer 冗余可见/可修 | **修复成立** | 实测：主 footer 损坏→verify rc=1 且报 footer；`repair --force` rc=0 恢复；修复后 verify rc=0。新单测 `primary_footer_corruption...`/`backup_footer_corruption...` ok |
| RF-05 create 静默丢数据 | **修复成立（有副作用 R2-03）** | symlink→rc=1 且带路径；unreadable subtree/socket→错误；空目录 warn+rc=0（实测） |
| RF-07 活跃头认证 | **修复成立但引入 R2-01（High 回归）** | `reader.rs:1541,2856-2890`；新单测 `active_primary_header_tamper_is_rejected_on_open` ok，但破坏既有可修复场景 |
| RF-08 空体/恒过测试 | **部分成立 → R2-04** | 4 个 print-only 测试改成有 assert；但改成自证式（断言本地重算），抑制回归能力仍弱 |
| RF-12 repair 不存在路径 exit 0 | **修复成立** | 实测 rc=1 + “Archive not found: …”；`cli_integration_tests.rs`/`_comprehensive` 断言已更新 |
| RF-13 verify Degraded 文案 | **修复成立** | `commands.rs:1151-1175` 区分 missing volumes / 其他；新 CLI 单测 9/9 ok |
| RF-14 repair 死分支 | **修复成立** | `commands.rs:1298-1308` 用 `verify_stats.is_healthy()` 替代不可达 `Healthy && needs_repair()` |
| RF-20 chunker 非法配置 panic | **修复成立（有副作用 R2-12）** | `chunker/config.rs` 去 assert；`try_new*`；12/12 新测 ok |
| RF-21 local create 截断/symlink | **修复成立（行为收紧）** | O_NOFOLLOW + symlink 显式拒绝 + 父目录 best-effort fsync；5/5 新测 ok（symlink 指向受害者文件不被截断） |
| RF-22 read_all_from 下溢 | **修复成立** | `local.rs:289-298`；past/at EOF 返回空，2 个新测 ok |
| RF-24 CI 可复现性 | **修复成立** | `ci.yml`：`--locked`、`ulimit -n 1024`、3 个 `timeout-minutes` |
| RF-10 docs 忽略 | **部分** | `docs/audit/**` 已放行但未 git add；6 份历史文档仍忽略（R2-14） |
| RF-27 README/AGENTS 漂移 | **部分** | 数字已统一为 2916/17，但因新增 33 测试而开始漂移；AGENTS 文件数过期（R2-11） |

---

## 4. 遗留 findings 最终状态（(a) 逐项）

图例：**OPEN**=仍存在；**FIXED**=本轮修复并经我验证；**PARTIAL**=部分缓解；**ACCEPTED**=建议文档化为已知限制。

| 编号 | 严重度 | 最终状态 | 依据（当前工作树） |
|---|---|---|---|
| RF-01 / LL-01 append finalize truncate 崩溃窗口 | High | **OPEN（未修）** | `crates/era-volume/src/writer.rs` 不在本轮 diff；`:256-265` truncate→append 无 sync；`:832` flush 后才写 footer `:850-873`，窗口不变 |
| RF-03 / LL-02 staged append 全量驻留内存 | Medium | **OPEN（未修）** | `writer.rs:248-252` `buf: Vec::new()`；`:662-663, 721-722` 累积整段 append；默认最大 4 GiB |
| RF-06 / LL-03 可增长卷 finalize 缺 fdatasync 屏障 | Medium | **OPEN（未修）** | `writer.rs:832-846` 仅 `max_size.is_some()` 时 `sync_data`；可增长卷数据写入与 footer 覆盖之间无屏障；`:875` 才整体 sync |
| RF-09 / H-01 allow(dead_code)/零引用 pub fn | Medium | **OPEN** | 生产 src `#[allow(dead_code)]` 仍 **41** 处（与 round-1 完全一致） |
| EW-04 append 轮转后永久不可 append | Low | **OPEN** | `crates/era-engine/src/writer.rs:577` “Append mode is only supported for single-volume archives” |
| EW-05 轮转中断孤儿 header-only 卷 | Low | **OPEN** | `crates/era-volume/src/volume_pool.rs:431` 先 create 卷再继续；无孤儿清理 |
| EW-06 append 无崩溃续传、API 未声明 | Low | **OPEN** | `checkpoint.rs`/`recovery.rs` 不在 diff，逻辑未变 |
| EW-07 set_max_size 破坏 staged append | Low | **OPEN** | `crates/era-volume/src/writer.rs:274-278`（`flush_staged_append` + pad） |
| EW-08 read_checkpoint 文档/实现失配 | Informational | **OPEN** | `checkpoint.rs:708` 文档 “brute-force”、`:817` 注释；实现不搜索 |
| EW-09 RecoveryManager 恢复 API 恒空 | Informational | **OPEN** | `recovery.rs:247-330` 未变（`is_file_completed`/`get_chunk_location` 等） |
| EW-10 repair 写回阻塞 std::fs | Low | **OPEN** | `repair.rs:1323` `fn apply_repairs`（同步 I/O）在 async 中被调用：`:1168`、`:1937` |
| ENG-RC-04 / RF-11 读路径不实现 Directory/Symlink | Low | **PARTIAL** | 写路径已拒绝 symlink（R2-03）；读路径仍只处理 `FileType::File`：`reader.rs:2279`、`:3019`，Directory/Symlink 静默忽略 |
| ENG-RC-08 / RF-15 解包无目录 fsync；--force rename 窗口 | Low | **OPEN** | 仅数据文件 `sync_all`：`chunk_processor.rs:412/444/523`；无父目录 fsync；--force 流程未变 |
| ENG-RC-09 / RF-16 父目录 TOCTOU / metadata 按路径重开 | Low | **OPEN** | `chunk_processor.rs:323` 仅末级 `O_NOFOLLOW`；父目录 TOCTOU 未变 |
| ENG-RC-10 / RF-17 verify 每卷全量 Catalog、无 benchmark | Low | **ACCEPTED**（benchmark-needed） | 代码未变，本轮仍无 bench 变更 |
| ENG-RC-11 / RF-18 verify 不校验 size>100 GiB | Low | **OPEN** | `reader.rs:2214` 仅 extract 路径检查 `MAX_DECLARED_FILE_SIZE`；verify 路径无 |
| ENG-RC-12 / H-04 / RF-19 源码字符串耦合测试 | Low | **OPEN** | `include_str!` 现有 **262** 处 / 12 个套件（round-1 为 263）；本轮 diff 未新增 |
| H-06 / RF-25 `#[path = "../src/..."]` | Low | **OPEN** | 仍 5 处 / 3 文件（`adversarial_audit_v5.rs` 3、`bounded_fd_extraction_tests.rs` 1、`competitor_public_path_delta.rs` 1） |
| H-07 / RF-26 墙钟/ sleep 测试 | Low | **OPEN** | `concurrency_torture.rs:38` 10 ms 轮询循环；`cli_coverage_gap_tests.rs:1773` 50 ms；`cli_e2e_gap_tests.rs:453` 100 ms |
| H-09 / RF-28 内联 cfg(test) 规模 | Low | **OPEN / ACCEPTED** | 73 个 src 文件含 `#[cfg(test)]`（round-1 为 75，本轮 src 改动最小）；文档未见三档 LOC |
| LL-08 / RF-23 protobuf→域模型跨字段校验 | Low | **OPEN** | `crates/era-common/src/conversion.rs` 不在 diff；`:336-356` 等锚点未变（round-1 已确认） |
| RF-02/04/05/07/08/12/13/14/20/21/22/24 | — | 见 §3 | 修复成立/部分成立 |

---

## 5. (b) 修订 diff 新技术债扫描（机械扫描 + 人工确认）

扫描命令（对 `git diff -U0` 的 added lines）：

```
added allow:            1 处  → crates/era-storage/src/local.rs:42 #[allow(unused_mut)]
added unwrap/expect/panic!/todo!/unimplemented!/thread_rng in src runtime: 0 处
  （扫描命中项全部位于 crates/era-engine/src/reader.rs 的 #[cfg(test)] mod tests）
added include_str!:     0 处
added TODO/FIXME/XXX/HACK: 0 处
added unsafe:           0 处
added spawn_blocking:   2 处（chunker.rs:107、ingest/reader.rs:327，均为正确方向：CPU 密集移出 async 线程）
allow(...) 总计数:       HEAD 64 → 工作树 65（新增 1）
```

- 新增生产代码无 unwrap/expect/panic；新增测试文件内 unwrap/expect 正常。
- 新增 `#[allow(unused_mut)]`（R2-06）；新增重复 footer 辅助逻辑（R2-07）；新增自证式测试（R2-04）；新增源字符串治理测试（R2-10）。
- 过宽 API 变更：`ExtractOptions` 公开字段（R2-05）；CLI 行为变更（R2-03、verify/repair 退出码语义变化见 §6）。
- 行为漂移/兼容性破坏：open 硬失败（R2-01）、create symlink 中止（R2-03）、extract 无全局上限（R2-02）、chunker 静默回退（R2-12）。
- 测试只断言源码字符串：`hygiene_guards_test.rs`（R2-10）。
- 过度严格导致合法场景失败：R2-01（修复场景）、R2-03（含软链目录）。

---

## 6. 其它行为变更（需在变更记录/文档中声明）

1. `era verify` 对“可读但 footer 冗余受损”的归档从 rc=0 改为 rc=1（Degraded）。这是 RF-04 的预期修复，但属 CLI 语义破坏；`cli_extreme_tests.rs` 已同步改断言（`:2991+`、`:3093+`）。
2. `era repair` 对不存在路径从 rc=0 改为 rc=1（RF-12，正确）。
3. `era repair` 非 EC 归档新增 footer 修复能力；输出统计不含 footer（R2-08）。
4. `LocalStorageBackend::create` 拒绝 symlink 末级（RF-21，正确），但若用户以 symlink 指向卷文件作为存储布局会开始报错（推断，未验证真实用例）。

---

## 7. (c) 工作区卫生 / 测试发现 / 交付性

### 7.1 残留探针与垃圾文件

- `git status --porcelain=v1 --untracked-files=all`：仅 5 个新测试文件 + `docs/audit/*.md`；无 `zz_*`/临时探针/garbage。
- `git status --ignored`：`.omo/`、`.codegraph`、`target/`、`logs/`、`flake.*`、6 份历史 docs 等按既有规则忽略；`tmp*` 无实体目录。
- 结论：工作树本身“可交付”，前提是 `git add docs/audit`（R2-14）并修复 R2-01。

### 7.2 新测试与自动发现

| 文件 | 测试数 | 状态 |
|---|---:|---|
| `bins/era-cli/tests/round1_cli_create_repair_tests.rs` | 9 | 自动发现，9/9 通过 |
| `crates/era-engine/tests/round1_reader_fixes.rs` | 3 | 3/3 通过 |
| `crates/era-engine/tests/hygiene_guards_test.rs` | 4 | 4/4 通过 |
| `crates/era-ingest/tests/chunker_config_validation.rs` | 12 | 12/12 通过 |
| `crates/era-storage/tests/local_backend_hardening.rs` | 5 | 5/5 通过 |
| **合计** | **33** | — |

（直接执行 `target/release/deps/<name>-*` 得到，见 R2-15。）

### 7.3 .gitignore 校验

```
$ git check-ignore -v docs/audit/round1-consolidated.md
.gitignore:35:!docs/audit/**    docs/audit/round1-consolidated.md    # 否定规则 → 不被忽略
$ git status --porcelain=v1 --untracked-files=all | grep '^??'
?? bins/era-cli/tests/round1_cli_create_repair_tests.rs
... 5 个测试文件
?? docs/audit/*.md（8 个）
```

---

## 8. (d) README/AGENTS 测试统计：已被门禁保护但数字将漂移

- 现状：README 4 处均为 “2916 passed / 0 failed / 17 ignored (2026-11-22, `b22a07e`)”。
- 门禁保护：`hygiene_guards_test::readme_test_statistics_are_consistent`（`tests/hygiene_guards_test.rs:171`）保证 README 只出现一个 passed/ignored 取值、且命令含 `--release/--locked`；`ci_workflow_is_reproducible`（`:131`）保证 CI `--locked`/`ulimit`/timeout。
- 缺口：
  1. **数值未被验证**，只验“自洽”。本轮 +33 测试 → 真实 passed 数必然 >2916，README 数字在提交瞬间即失真。
  2. **AGENTS.md 未受保护**：`:7` “~141.7k LOC / 265 .rs files” 已过期（工作树 270 个 .rs）。
  3. “Last Verified … (b22a07e)” 与“当前树包含未提交修订”矛盾。
- 建议：
  - 数字改为 “截至 commit `X` 的实测值”，并让 CI 在 test job 汇总 `test result: ok. N passed` 后与 README 比较（或改为引用 CI badge/不写死）；
  - 把 AGENTS 的 LOC/文件数纳入同一 guard（脚本化 `git ls-files`/LOC 计算）；
  - 在 README 增加“测试统计口径”说明（是否含 ignored/doc-tests），避免再次出现两套互斥统计（历史 H-08）。

---

## 9. (e) 最终放行结论

### 阻塞项（必须修复后才可合并）

| 项 | 级别 | 理由 |
|---|---|---|
| **R2-01** open 阶段活跃主头 digest 硬失败 | **High/阻塞** | 已使 CI cli 门禁红（未修改的既有用例）；把“可修复的主头损坏”变成“不可打开/不可提取/不可修复”，与 backup-header 冗余设计冲突 |
| **RF-01** append finalize truncate 崩溃窗口 | **High/阻塞（round-1 遗留，未修）** | 崩溃可致既有归档不可打开；修订完全未触碰 `era-volume/src/writer.rs` |

### 应修复（非阻塞性，建议本轮或紧随）

- R2-02 Medium：CLI 无解包总预算入口（安全姿态回退）。
- R2-03 Medium：含 symlink 目录 create 整体失败（兼容破坏）。
- R2-04 Medium：H-03 修复为自证式测试（测试可信度）。
- R2-05/R2-06/R2-07/R2-08/R2-09/R2-10/R2-11/R2-12：Low，建议排期。
- RF-03 Medium（staged append OOM）、RF-06 Medium（持久化屏障）：round-1 遗留，仍建议在合并前至少文档化其风险与上限。

### 可接受为“已知限制”（需文档化）

| 项 | 理由 |
|---|---|
| ENG-RC-10 / RF-17（verify 全量 Catalog、无 benchmark） | benchmark-needed；功能正确，只有性能量级未评估；可在性能工作项跟踪 |
| ENG-RC-12 / H-04 / RF-19（262 处 include_str!） | 大规模重构超范围；本轮未恶化，可作为长期技术债 |
| H-09 / RF-28（内联 cfg(test) 规模） | 结构性问题，不影响正确性 |
| ENG-RC-04 读路径 Directory/Symlink | 写路径已拒绝 symlink、空目录已告警；仅“外部工具生成的归档”可触发，属跨版本兼容问题 |
| H-07 / RF-26（墙钟测试） | likely flaky，非确定失败；建议后续用同步原语替换 |
| RF-30 各 Informational | 纵深项，无当前可利用路径 |
| R2-13 | 可忽略的额外小 I/O |

### 交付前 checklist

1. 修复 R2-01（必需）与 RF-01（或明确书面接受风险）。
2. 决定 RF-03/RF-06 处置（修 or 文档化上限/窗口）。
3. `git add docs/audit`；决定 6 份历史 docs 去向。
4. 完成后重跑门禁：`cargo fmt --all -- --check && cargo clippy --locked --all-targets --all-features -- -D warnings && ulimit -n 1024 && cargo test --release --locked -p era-cli && cargo test --release --locked --workspace`，确认 cli 与 workspace 均绿。
5. 更新 README “Last Verified” 与 AGENTS 统计（R2-11），并在变更记录声明 §6 的行为变更。

---

## 附录 A：本报告关键命令

```bash
# 环境
export PATH="/nix/store/c2ii5nkzv440xj9igxsd49i8f5y2vr6f-cargo-1.99.1/bin:/nix/store/mslcwkiyh6wayx8gpzlq53wvr3a5pp44-rustc-1.99.1/bin:...:$PATH"
export RUSTC=/nix/store/mslcwkiyh6wayx8gpzlq53wvr3a5pp44-rustc-1.99.1/bin/rustc
export CARGO_TERM_COLOR=never

# 1) 门禁证据（root 后台日志，未重复全量）
grep -nE 'FAILED|test result:|cli_rc' /tmp/era_ci_round1.log

# 2) 直接运行当前树测试二进制（绕过 cargo 锁）
target/release/deps/cli_coverage_gap_tests-07a1e7fe13438601 \
  random_offset_corruption::test_repair_corruption_at_multiple_offsets --test-threads=1
target/release/deps/round1_reader_fixes-9b535390721e1997 --test-threads=2
target/release/deps/hygiene_guards_test-803bd7a29a20a683 --test-threads=2
target/release/deps/chunker_config_validation-64ca35e747728e9d --test-threads=2
target/release/deps/local_backend_hardening-293c826f9e93c0cb --test-threads=2
target/release/deps/round1_cli_create_repair_tests-be755346d1b2aeb9 --test-threads=2

# 3) R2-01 复现（当前树 target/release/era）
era create data.bin --output a.era --password pwd --erasure 4:2 --no-compression
python3 -c "f=open('a.era','r+b'); f.seek(1000); b=bytearray(f.read(100)); f.seek(1000); f.write(bytes(x^0xff for x in b))"
era verify a.era --password pwd        # rc=1: primary header digest mismatch
era extract --input a.era --output out --password pwd   # 同样失败
era repair a.era --password pwd --force                 # 同样失败（无法进入 repair）

# 4) footer 冗余修复正例
python3 -c "f=open('f.era','r+b'); f.seek(4096); b=bytearray(f.read(128)); f.seek(4096); f.write(bytes(x^0xff for x in b))"
era verify f.era --password pwd        # rc=1 degraded + footer
era repair f.era --password pwd --force # rc=0 恢复
era verify f.era --password pwd        # rc=0

# 5) 机械扫描
git diff -U0 | grep -E '^\+[^+]' | grep -cE 'include_str!|TODO|FIXME|panic!|unwrap\('
git grep -c 'allow(dead_code)' -- 'crates/*/src/*.rs' 'crates/*/src/**/*.rs' | wc -l
git grep -o 'include_str!' -- 'crates/*/tests/*.rs' 'bins/*/tests/*.rs' | wc -l
git status --porcelain=v1 --untracked-files=all
git check-ignore -v docs/audit/round1-consolidated.md
```

## 附录 B：未核实的推断项（明确标注）

1. R2-02 的 dedup 放大可被利用性（磁盘耗尽）为 inference，未构造实际放大归档。
2. R2-04 关于“生产分布算法回归时测试仍绿”为推断（未人为注入回归验证），但“未调用生产代码”是 confirmed。
3. R2-03 中“用户以 symlink 指向卷文件导致 create 报错”的场景未构造。
4. RF-03 的“默认最大 4 GiB 驻留内存”沿用 round-1 结论（`max_volume_size` 默认值未在本次复核中重算）。
5. root 的 workspace 全量测试在报告完成时仍在运行，未取得最终结果；cli 门禁红已足以支撑 BLOCK。
