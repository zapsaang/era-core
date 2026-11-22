# ERA-CORE 审计报告：engine 读路径 / 解包 / verify 与 CLI（round 1）

- **仓库**：`/home/ricardom/code/github.com/zapsaang/era-core`
- **分支 / HEAD**：`feat_fly` @ `b22a07e`（审计开始时工作区干净）
- **审计基线**：`ee39fae`；整改提交 `8c42a4c`、`31d358f`、`5ff825e`、`b22a07e`
- **本轮范围**：`crates/era-engine/src/reader.rs`、`reader/catalog_repair.rs`、`block_iter.rs`、`chunk_processor.rs`、verify/repair 判定一致性、`bins/era-cli/src/main.rs`、`commands.rs`、`bins/era-cli/tests/**`
- **维度**：规格符合性 / 安全 / 性能 / 并发与一致性 / 代码质量
- **方法**：静态阅读 + `git show/diff` 对账 + 预编译 `target/release/era`（mtime 2026-11-22 00:02，晚于 `src/` 最后修改 23:47；`b22a07e` 只改 docs/tests/`Cargo.lock`/toolchain，未改 `src/`）的 CLI 端到端探针。全量 release 测试由负责人后台执行，本线程未重复跑；探针文件全部位于 `/tmp`，报告结束前已删除，`git status` 保持干净。
- **限制**：本会话默认 `cargo/rustc` 不可用，使用负责人提供的 Nix 工具链；探针期间负责人与其它线程占用了 `target` 构建锁，故定向测试未并行发起，端到端证据以预编译 CLI 二进制为准（二进制与 HEAD 的 `src/` 一致，见上）。
- **统计**：本轮 12 条 finding，**全部为 confirmed**（其中 2 条的可利用性/持久性影响标注为 inference）：High 1、Medium 2、Low 9。另有 4 项前序“已闭环”声明被部分或完全推翻（见 §2）。

---

## 1. 结论摘要

工程师“已修复仓库全部问题、零技术债、无遗留”的声明**不成立**。本线程独立确认了 12 项遗留问题，其中 1 项 High：

| 编号 | 标题 | 严重度 | 维度 | 确认 |
|---|---|---|---|---|
| ENG-RC-01 | 解包存在全局累计 8 GiB 上限：>8 GiB（去重后唯一数据）归档必然解包失败，且失败后删除全部已写文件 | **High** | 规格符合性 / 数据可用性 | confirmed（代码路径确定）；>8 GiB 实测未跑（见 §6） |
| ENG-RC-02 | `verify`/`repair` 完全不覆盖 footer 冗余：主 footer 损坏静默降级仍退出 0；备份 footer（offset 4096）损坏不可见、不可修 | **Medium** | 规格符合性 / 安全（完整性覆盖） | confirmed（CLI 复现） |
| ENG-RC-03 | `era create` 递归收集时静默丢弃符号链接、空目录与不可读子树，仍成功退出 | **Medium** | 规格符合性 / 数据可用性 | confirmed（CLI 复现） |
| ENG-RC-04 | 读路径不实现 `Directory`/`Symlink` 条目的解包与校验（静默忽略；README 却声称“symlinks are rejected”） | Low | 规格符合性 | confirmed（代码路径） |
| ENG-RC-05 | `era repair` 对不存在路径返回成功（exit 0 + “Nothing to repair”） | Low | 规格符合性 / 运维 | confirmed（CLI 复现） |
| ENG-RC-06 | `verify` Degraded 的 CLI 文案把所有降级都描述成“卷缺失”，且错误信息不带告警详情 | Low | 代码质量 / 可运维性 | confirmed（CLI 复现） |
| ENG-RC-07 | `repair` 中 `Healthy && needs_repair()` 分支不可达（死代码） | Low | 代码质量 | confirmed（布尔推导） |
| ENG-RC-08 | 解包持久化语义仍不完整：只 fsync 数据文件、不 fsync 目录；`--force` 的 rename→create 窗口在崩溃时使目标文件缺失 | Low | 并发与一致性（崩溃安全） | confirmed（代码路径）；掉电影响 inference |
| ENG-RC-09 | 解包路径校验仍有父目录 TOCTOU 窗口；metadata 恢复按路径重开会跟随符号链接 | Low | 安全（TOCTOU） | confirmed（代码路径）；可利用性 inference |
| ENG-RC-10 | §4.9 未闭环：`verify` 每卷完整读主 Catalog；`era repair` 非 EC 路径重复整卷 verify；无 benchmark 证据 | Low | 性能（provable duplicate work + benchmark-needed） | confirmed（代码 + diff） |
| ENG-RC-11 | `verify` 与 `extract` 的尺寸校验不对称：extract 拒绝 `entry.size > 100 GiB`，verify 不检查 | Low | 规格符合性（判定一致性） | confirmed（代码路径） |
| ENG-RC-12 | §4.10 未闭环：139 处 `include_str!("../src…")` 源码字符串耦合测试仍在（含 ENG-RC-01 的“内存预算”测试） | Low | 代码质量（测试质量） | confirmed（grep） |

**最关键的 Top 5**：ENG-RC-01（大归档不可解包）> ENG-RC-02（footer 冗余静默丢失、verify 假阴性）> ENG-RC-03（create 静默漏备）> ENG-RC-04（目录/软链接条目被静默忽略）> ENG-RC-10（§4.9/§4.10 的“闭环”声明无证据）。

---

## 2. 前序文档声明的逐项核验（本线程范围）

| 前序项 | 前序声明 | 本线程核验 | 证据 |
|---|---|---|---|
| §4.2 备份**头**未被 verify 校验 | 已由 `31d358f` 修复 | **属实**（正例） | 清零 `size-4224..size-4224+4096` 后：`era verify` → exit 1，Degraded，告警 “Volume 0: backup header damaged or mismatched; backup header requires repair”；`era repair --force` → “Restoring backup header”，随后 verify exit 0（§4 正例 P1） |
| §4.3 `--force` 失败删除用户原文件 | 已由 `5ff825e` 修复 | **属实**（正例） | 数据区单字节破坏 + 预置 ORIGINAL 目标 + `extract --force` → exit 1，目标内容仍为 ORIGINAL，目录内无 `.era_overwrite_backup_*` 残留（§4 正例 P2） |
| §4.5 单块文件解包不 fsync | 已修复 | **属实**（正例），但目录持久化仍缺失 → ENG-RC-08 | `chunk_processor.rs:412,444,523` 三处 `sync_all()`；全仓无目录 fsync |
| §4.6 懒句柄重开 TOCTOU | 已修复 | **末级组件已修**：`O_NOFOLLOW` + `(dev,ino)` 校验；**父目录 TOCTOU 仍在** → ENG-RC-09 | `chunk_processor.rs:317-352` vs `:643-667` |
| §4.7 死代码/死参数/allow | 已清理 | **部分属实**：`chunk_processor.rs` 模块级 `#![allow(dead_code)]` 已删除、`tracked_output_files` 已无引用；但全仓 `allow(dead_code)` 仍有 **41 处**，`repair` CLI 又新增死分支 → ENG-RC-07 | `grep -rn 'allow(dead_code)' crates/*/src bins/*/src \| wc -l` → 41 |
| §4.8 尺寸校验不完整/零 chunk 静默跳过 | 已修复 | **属实（File 条目）**：`validate_regular_file_chunks` 同时用于 extract/verify，校验零 chunk、非连续、长度和等于 size；**Directory/Symlink 条目仍被忽略** → ENG-RC-04 | `reader.rs:2885-2934`、`:2197`、`:2547` |
| §4.9 verify 每卷完整读 Catalog（likely regression，benchmark-needed） | 已“闭环” | **推翻**：代码改动保留，`git diff ee39fae..HEAD` 无任何 bench 变更，无量化证据 → ENG-RC-10 | `git diff --stat ee39fae..HEAD \| grep -i bench` → 空 |
| §4.10 源码字符串耦合测试 | 建议改为行为测试 | **推翻**：engine+cli 测试中 `include_str!("../src…")` 共 **139 处 / 12 个文件**，本轮新增/修改的 `adversarial_audit_v2.rs` 仍以字符串断言守护“解包内存预算” | grep 计数见 §7 |
| §4.4 非 EC 归档主头修复被拒 | 已由 `31d358f` 解耦 | **代码层面属实**：`repair.rs:750` 先 `apply_header_repairs`，`:755-761` 才在 verify 不 OK 时报数据损坏（多卷路径 `:1372` 先写回、`:1377-1382` 再报）；未做 CLI 端到端复现 | 代码阅读 |
| §5.1/§5.2 审计证据链/锁文件跟踪 | 已由 `b22a07e` 收口 | 本线程未重复核验（工程/流程维度） | `git show --stat b22a07e` 显示 docs/Cargo.lock/.gitignore/fuzz.yml 入仓 |
| §4.1 中断 append 后不可打开 | 已由 `8c42a4c` 修复 | **本线程未核实**（写路径/volume writer，非读路径范围）；按分工交由写路径线程 | — |

---

## 3. Findings

### ENG-RC-01【High】解包全局累计 8 GiB 上限：大归档必然解包失败，且失败后删除全部已写文件

- **维度**：规格符合性 / 数据可用性
- **确认程度**：confirmed（代码路径 + 算术边界确定；>8 GiB 实测未执行，见 §6 复现配方）
- **锚点**：
  - 常量：[`crates/era-engine/src/reader.rs:48`](../crates/era-engine/src/reader.rs#L48) `const MAX_EXTRACTION_MEMORY: u64 = 8 * 1024 * 1024 * 1024;`
  - 累计器：[`reader.rs:2099`](../crates/era-engine/src/reader.rs#L2099) `let mut cumulative_bytes_extracted: u64 = 0;`（**整个解包过程只初始化一次，循环内从不归零/回退**）
  - 累加与阈值：[`reader.rs:2298-2344`](../crates/era-engine/src/reader.rs#L2298-L2344)（每个成功解码块把 `block_bytes = Σ decoded.chunks[i].len()` 累加；`> MAX_EXTRACTION_MEMORY` 即 `fail_extraction_with_context(Security("Extraction memory budget exceeded: possible decompression bomb"))`）
  - 失败清理：[`reader.rs:2515-2531`](../crates/era-engine/src/reader.rs#L2515-L2531) 删除本次解包**全部** `created_output_paths`，再恢复 overwrite 备份
  - 对照（无此上限）：[`reader.rs:2602-2619`](../crates/era-engine/src/reader.rs#L2602-L2619) `verify_with_iterator` 流式扫描全部块，只累加 `bytes_verified`，不做上限判断
  - 唯一守护测试：[`crates/era-engine/tests/adversarial_audit_v2.rs:105-109`](../crates/era-engine/tests/adversarial_audit_v2.rs#L105-L109) `v2_sec_11_global_extraction_memory_budget_present` 只断言源码包含常量字符串，无任何行为测试
- **机理**：`cumulative_bytes_extracted` 是“解包全程累计解码 chunk 字节数”，不是单块/单文件内存占用。解包的内存峰值实际上已被“单块 ≤ `MAX_SHARD_SIZE`(16 MiB) + 64 个懒句柄”限制；把同一个计数用于**总量**判断，等价于规定“任何一次 `extract_all` 的解码总量不得超过 8 GiB（去重后）”。对无重复数据的归档，解码总量 = 归档明文总量，于是 >8 GiB 的归档在解包到约 8 GiB 时必然报 `Security("…decompression bomb")`；随后 `fail_extraction_with_context` 把已经写出的 8 GiB 文件全部删除。`verify()` 没有该上限，会给出 Healthy —— 即“verify 通过但 extract 必然失败”的判定不一致。
- **可审计证据**：
  - 静态：`git log -S 'MAX_EXTRACTION_MEMORY'` → 引入于 `89f6e31`（V2-SEC-11）；`git log -S 'cumulative_bytes_extracted'` 仅该提交；全仓其它引用只有 `reader.rs` 与上述源码字符串测试（`ops_grep` 结果）。
  - 反证测试缺失：`adversarial_audit_v2.rs:106-108` 仅 `assert!(source.contains("MAX_EXTRACTION_MEMORY"))`，即使把阈值改成 1 字节测试也照样通过。
  - 一致性反证：`verify_with_iterator` 无总量上限 → 同一归档 verify=Healthy / extract=失败。
- **影响**：这是备份/归档产品的核心可用性缺陷：用户成功创建 10 GiB 归档后无法用本工具解包；且失败发生在大量写入之后，清理会删除部分已写文件（用户可能误以为“只失败了一点”）。100 GiB 的 `MAX_DECLARED_FILE_SIZE`（`reader.rs:45`）与该 8 GiB 上限自相矛盾。
- **建议修复**：
  1. 把“防解压炸弹”落到**单块/单文件**维度：`decoded block decompressed_size ≤ expected`（已由块头/AEAD 绑定）+ 单文件 `size ≤ MAX_DECLARED_FILE_SIZE` + 可选“解压比”阈值；删除全程累计判断，或改为**可配置**的总输出预算（默认不低于 `MAX_DECLARED_FILE_SIZE`，并在 CLI 帮助/文档中说明）。
  2. 若确需总量预算，应作为 `ExtractOptions`/config 字段暴露，并从 `verify` 复用同一限制，保持 verify/extract 判定一致。
  3. 失败清理语义需明确：解包失败是否应保留已完整解出的文件应成为显式契约（当前是“全删”）。
- **应补回归测试（TDD）**：
  - 单元/集成（利用 `reader.rs:3614 injected_iterator` 同类注入模式，把预算改成可注入的小值，如 1 MiB）：注入 2 个各 1 MiB 的 DecodedBlock，断言 **成功** 且文件完整（当前实现会失败）。
  - 负例：单块解压后超过“单块上限”时仍必须报错（炸弹防护不许回退）。
  - CLI 端到端（可标 `#[ignore]` 或 feature gate）：创建约 9 GiB 唯一数据归档 → `extract` 必须成功；当前为 RED。

---

### ENG-RC-02【Medium】verify/repair 完全不覆盖 footer 冗余：主 footer 静默降级仍 exit 0，备份 footer 损坏完全不可见

- **维度**：规格符合性 / 安全（完整性验证覆盖）
- **确认程度**：confirmed（CLI 复现；两处损坏分别验证）
- **锚点**：
  - 双 footer 写入：[`crates/era-volume/src/writer.rs:860-873`](../crates/era-volume/src/writer.rs#L860-L873)（主 footer 写在备份头之后；备份 footer 写到固定 offset `HEADER_SIZE`=4096）；布局注释见 [`crates/era-engine/tests/v81_adversarial_resilience.rs:9-16`](../crates/era-engine/tests/v81_adversarial_resilience.rs#L9-L16)
  - 主 footer 损坏时静默回退：[`crates/era-volume/src/reader.rs:57-71`](../crates/era-volume/src/reader.rs#L57-L71)（只 `tracing::warn!` 后读 offset 4096 的备份 footer，**不记录任何 recovered 标志**）
  - 只有 header 的恢复标志：[`crates/era-volume/src/reader.rs:25-32`](../crates/era-volume/src/reader.rs#L25-L32) `header_recovered_from_backup: bool`（没有 footer 对应字段）
  - verify 只校验备份**头**：[`reader.rs:2818-2882`](../crates/era-engine/src/reader.rs#L2818-L2882) `verify_backup_headers` 仅读 `footer.backup_header_offset()` 处 4096 B 与主头比较，从不读 offset 4096 的备份 footer
  - verify 只对“头恢复”告警：[`reader.rs:2759-2767`](../crates/era-engine/src/reader.rs#L2759-L2767)
  - repair 无任何 footer 修复：`repair.rs` 内 footer 仅在 `volume_needs_header_repair`/`plan_volume_header_repairs` 中作为“指针来源”被读取（`repair.rs:415-441,443-523`），全文件无 footer 写回路径（`ops_grep 'backup_footer|footer' repair.rs` 无写操作）
  - CLI 语义：[`bins/era-cli/src/commands.rs:1048-1052`](../bins/era-cli/src/commands.rs#L1048-L1052)（Healthy → “Archive integrity verified successfully!” + exit 0）；`:1191-1196` repair “Archive is intact. No repair needed.”
  - **既有测试把缺陷固化为预期**：[`bins/era-cli/tests/cli_extreme_tests.rs:2973-2997`](../bins/era-cli/tests/cli_extreme_tests.rs#L2973-L2997) `test_verify_footer_corrupted_archive` 在 `corrupt_footer(&archive)` 后断言 `verify … .success()`；备份 footer 场景只有 `test_corrupted_backup_footer_primary_still_works`（`:2931-2970`）断言 extract 成功，无 verify 断言。
- **机理**：v8.2 每个卷有**两份 footer**（文件尾 `size-128`、保留区 offset 4096），`VolumeReader::open` 在主 footer 解析失败时会自动回退到备份 footer，但不设置任何“已降级”标志；`ArchiveReader::verify()` 因此看不到“其中一份 footer 已损坏”，也不会把它计入 `stats.warnings → Degraded`。offset 4096 的备份 footer 在正常打开路径（主 footer 可解析）下**从不被读取**，其 bitrot 完全不可检测。`repair` 也没有写回 footer 的能力，所以即便发现也无法自愈。这与上一轮已修复的 §4.2（备份*头*）属于同一类“冗余静默丢失”，只修了一半。
- **可审计证据（CLI 实测，单卷 `--erasure none`，200 000 B 文件）**：
  - A1 主 footer 清零（`size-128..size`）：
    ```text
    WARN Primary footer corrupted: Corrupted footer: Invalid magic: expected [69, 82, 65, 70], got [0, 0, 0, 0]. Attempting backup recovery...
    INFO ✅ Archive integrity verified successfully!      (rc=0)
    # era repair 同归档：
    INFO ✅ Archive is intact. No repair needed.          (rc=0)
    # era extract 仍可成功（cmp=OK），说明数据可用、但冗余已降级且无人知晓
    ```
  - A2 备份 footer 清零（offset 4096..4224，主 footer 完好）：`era verify` **rc=0、无任何 warning**；`era repair` **rc=0 “Archive is intact”**。即备份 footer 位腐（bitrot）不可检测。
- **威胁/影响场景**：不需要攻击者。单盘 bitrot/部分覆写即可让两份 footer 中的一份失效；系统仍报告“完全健康”，用户不会触发修复/重建。若之后主 footer 所在扇区再损坏，归档将依赖 floating-footer 反向扫描（`era-volume/src/reader.rs:73-78`）——那是最后兜底，且对 `max_volume_size` 填充分卷/尾部垃圾场景并不总成立；最坏情况归档不可打开。对“双副本冗余”契约而言，verify 覆盖度不足。
- **建议修复**：
  1. `VolumeReader` 增加 `footer_recovered_from_backup: bool`（与 header 对称），`open` 回退时置位；
  2. `verify()`：任一 `reader.footer_recovered_from_backup()` → `warnings` + Degraded（文案“primary footer still requires repair”）；
  3. `verify_backup_headers` 扩展为 `verify_redundant_metadata`：读取 offset 4096 的 footer 与 `size-128` 的 footer 做**逐字节比较**（footer 自带 BLAKE3 checksum，可直接验证），不一致/不可解析 → Degraded；
  4. `repair`：主 footer 无效而备份 footer 有效 → 写回 `size-128`；备份 footer 无效 → 写回 offset 4096；两者都无效 → 明确报不可修（或交给 floating 恢复后重写双份）。
- **应补回归测试（TDD）**：
  - engine e2e：`corrupt_primary_footer` → `verify()` 必须 `is_degraded()`；`repair(force)` 后两份 footer 逐字节相等、`verify()` Healthy。
  - engine e2e：`corrupt_backup_footer`（offset 4096）→ `verify()` 必须 degraded；`repair(force)` 后恢复。
  - CLI：更新 `cli_extreme_tests.rs:2973` 的预期（当前断言 verify 成功 = 固化缺陷），改为非零退出 + 文案包含 “footer”；新增 `test_verify_backup_footer_corrupted_degraded`。

---

### ENG-RC-03【Medium】`era create` 递归收集静默丢弃符号链接、空目录与不可读子树，仍以成功退出

- **维度**：规格符合性 / 数据可用性
- **确认程度**：confirmed（CLI 复现）
- **锚点**：
  - [`bins/era-cli/src/commands.rs:537-563`](../bins/era-cli/src/commands.rs#L537-L563)：`walkdir::WalkDir::new(path).into_iter().filter_map(|e| e.ok())` + `if entry.file_type().is_file()`；`e.ok()` 把 walkdir 的 I/O 错误（权限拒绝、路径过长等）**静默丢弃**，`is_file()` 使符号链接/空目录永远不会进入 `files_to_process`。
  - 同样策略的引擎 API：[`crates/era-engine/src/writer.rs:1359-1388`](../crates/era-engine/src/writer.rs#L1359-L1388) `collect_files_async`（注释 “Symlinks and special files are skipped”）。
  - 帮助文案只承诺 “Directories are walked recursively”（[`bins/era-cli/src/main.rs:53-56`](../bins/era-cli/src/main.rs#L53-L56)），未说明 symlink/空目录/不可读项的丢弃策略。
- **机理**：create 阶段没有任何“跳过计数/告警/失败”的出口；`collect_create_inputs` 返回的列表就是最终归档内容，writer 侧只看到文件。于是：
  - 目录中的符号链接（含指向普通文件的相对链接）→ 不入档；
  - 空目录 → 不入档（提取端也不建空目录，见 ENG-RC-04），往返后目录树结构丢失；
  - `walkdir` 因权限被拒的子树 → 整棵子树静默缺失，**退出码仍为 0**。
- **可审计证据（CLI 实测）**：构造 `srcC/{a.txt, link.txt -> a.txt, empty_dir/, unreadable/{hidden.txt}}`，`chmod 000 unreadable` 后：
  ```text
  $ era create -o c.era -p pw --erasure none srcC     # rc=0
  INFO Archive created successfully!
  INFO   Files:      1
  INFO   Total size: 6 B
  $ era list c.era -p pw
  INFO srcC/a.txt
  INFO Total: 1 files (6 B total)      # link.txt / empty_dir / unreadable/hidden.txt 全部静默缺失，无任何 warning
  ```
  对照：同一输入若 `unreadable` 可读，`hidden.txt` 会被归档；说明“丢失”纯粹由静默吞错造成，而非用户显式排除。
- **影响**：备份产品最危险的失败模式之一：备份“成功”但内容不完整，且无任何信号；用户在恢复时才发现丢失。符号链接/空目录的丢失也使 roundtrip 不等价（与 README 对归档完整性的宣传不符）。
- **建议修复**：
  1. `walkdir` 的 `Err` 不得丢弃：记录并汇总为 warning（或默认直接失败，提供 `--skip-unreadable` 显式开关）；
  2. 明确并实现符号链接策略：要么归档为 `FileType::Symlink` 条目（配合 ENG-RC-04 的解包落地），要么默认**报错/告警**并给出计数；
  3. 空目录归档为 `FileType::Directory` 条目（配合 ENG-RC-04 预创建）；
  4. 结束输出 “Files/Skipped(unsupported)/Warnings” 统计，非零 skipped 时在帮助与 `--verbose` 中可见。
- **应补回归测试（TDD）**：CLI 测试 `create_dir_with_symlink_empty_dir_unreadable`：断言（a）现在必须是告警 + skipped 计数，或（b）roundtrip 后空目录与符号链接保留；`chmod 000` 子树必须出现在 warning/错误中，**不得** rc=0 静默成功。

---

### ENG-RC-04【Low】读路径不实现 Directory/Symlink 条目：静默忽略且 verify 不报告（README 声称“rejected”）

- **维度**：规格符合性 / 安全（防御面）
- **确认程度**：confirmed（代码路径）；可达性受限（当前 writer/CLI 不产出此类条目，见 ENG-RC-03）
- **锚点**：
  - 条目类型：[`crates/era-ingest/src/entry.rs:15-23`](../crates/era-ingest/src/entry.rs#L15-L23)（`File/Directory/Symlink`）、`:171-237`（目录 size=0、chunks 为空；symlink 记录 `symlink_target`）
  - extract 只处理 `entry.is_chunked()`：[`reader.rs:2197-2256`](../crates/era-engine/src/reader.rs#L2197-L2256)；`has_pending()` 为空即 “No files to extract” 并 **Ok** 返回（`:2259-2262`，`:2373-2375`）
  - `validate_regular_file_chunks` 对非 `File` 直接放行：[`reader.rs:2885-2894`](../crates/era-engine/src/reader.rs#L2885-L2894)
  - verify 对非 chunked 条目 push 0 后跳过：[`reader.rs:2542-2600`](../crates/era-engine/src/reader.rs#L2542-L2600)
  - 目录只在写文件时被 `create_dir_all` 隐式创建（[`chunk_processor.rs:651`](../crates/era-engine/src/chunk_processor.rs#L651)），故**空目录永远不落地**；symlink 从不创建
  - README 契约：[`README.md:317`](../README.md#L317) “Path traversal prevention: Filenames are sanitized on extraction — absolute paths, `..`, and symlinks are rejected” —— 实际是“静默忽略”，既非 reject 也非 preserve
  - 项目整改计划明确要求支持：[`docs/consolidated-risk-and-recovery-remediation-plan-2026-10-10.md:435-443`](./consolidated-risk-and-recovery-remediation-plan-2026-10-10.md#L435-L443)（拟新增 `add_symlink`/`add_directory_entry`，提取端预建目录、校验 symlink target 密闭性；全仓 `grep 'fn add_directory'` 为 0，未实现）
- **机理**：读路径把“无 chunk 的条目”等同于“无需解包”，既不建目录/链接，也不计入 `stats.skipped`，最终返回成功；verify 的 `file_chunk_counts` 对这类条目为 0，`check_file_completeness` 遇到 `expected==0` 直接 `continue`（`chunk_processor.rs:810-816`），所以也“验证通过”。含 `Directory`/`Symlink` 条目的归档（外来/旧版/经引擎 API 构造）在 extract 时静默丢结构，verify 报 Healthy。
- **安全说明**：当前 writer 不产出这两类条目，目录扫描器也不使用 `DirectoryScanner`；因此正常 CLI 产物不可达，不构成现实攻击面。若未来实现 symlink 落地，必须先做 `symlink_target` 容器密闭性校验，否则会出现“绝对路径目标写出沙箱”的经典漏洞（README 的“rejected”承诺也应在实现时兑现）。
- **建议修复**：在 extract/verify 的统一规划阶段显式处理 `FileType`：
  - `Directory`：收集并在数据写入前（或收尾）以临时 0755 创建骨架，最后恢复权限/mtime；
  - `Symlink`：校验目标密闭性后 `std::os::unix::fs::symlink` 落地（并拒绝 extract 目标已存在的 symlink 碰撞），或明确返回 `Security` 错误；
  - `verify` 对未知/不支持类型计入 `warnings`/`errors`，不得静默 Healthy。
- **应补回归测试（TDD）**：构造含空目录 + 相对/绝对 symlink 的 `Catalog`（可先从“规划函数”抽成可单测的纯函数，避免整卷构造），断言：空目录被创建、相对 symlink 被创建、绝对/越界目标被 `Security` 拒绝；verify 对含未知类型条目的归档不得返回 Healthy。

---

### ENG-RC-05【Low】`era repair` 对不存在路径返回成功（exit 0）

- **维度**：规格符合性 / 运维（退出码契约）
- **确认程度**：confirmed（CLI 复现）
- **锚点**：
  - [`commands.rs:1126-1128`](../bins/era-cli/src/commands.rs#L1126-L1128) `RecoveryManager::analyze(archive)`；
  - [`crates/era-engine/src/recovery.rs:179-199`](../crates/era-engine/src/recovery.rs#L179-L199) `archive_exists=false` → `checkpoint_exists=false`、`recovery_needed=false`（`Ok`）；
  - [`commands.rs:1162-1165`](../bins/era-cli/src/commands.rs#L1162-L1165) `!checkpoint && !archive` → 打印 “No archive or checkpoint found. Nothing to repair.” 并 **`return Ok(())`**。
- **机理**：把“文件不存在”和“归档已完整无需修复”混为同一种成功出口；任何 shell/CI 里 `era repair /wrong/path -p pw` 都会得到 exit 0，自动化无法发现路径拼错/备份盘未挂载。
- **可审计证据**：
  ```text
  $ era repair /tmp/era_audit_probe/does-not-exist.era -p pw
  INFO ❌ No archive or checkpoint found. Nothing to repair.     (rc=0)
  ```
- **建议修复**：`!archive_exists` 时返回错误（exit != 0，文案 “Archive not found: <path>”）；仅当“存在 checkpoint、归档已完整”时返回成功。
- **应补回归测试（TDD）**：CLI 测试 `repair_missing_archive_fails`：`assert().failure()` 且 stderr 含路径；现状 RED。

---

### ENG-RC-06【Low】`verify` Degraded 错误文案把所有降级都描述为“卷缺失”

- **维度**：代码质量 / 可运维性
- **确认程度**：confirmed（CLI 复现）
- **锚点**：[`commands.rs:1048-1077`](../bins/era-cli/src/commands.rs#L1048-L1077)：Degraded 分支先打印 Warnings（stderr），随后
  ```rust
  anyhow::bail!("Archive verification degraded: expected volumes={}, found={}, missing sequences={:?}", ...)
  ```
- **机理**：`ArchiveHealthStatus::Degraded` 有两种来源（`reader.rs:872-878`）：`stats.warnings` 非空（如备份头/主 Catalog/备份 footer 损坏）**或** 缺失卷号；bail 文案只描述后者。备份头损坏场景输出 `missing sequences=[]`，用户会误判为“卷文件缺失”。同时 `--verbose` 只控制 Incomplete 分支的错误明细，Degraded 的 warnings 只在前面已打印，错误对象本身不含原因。
- **可审计证据**：
  ```text
  # 备份头清零后：
  WARN ⚠️  Archive data is readable, but archive health is degraded.
  WARN   1. Volume 0: backup header damaged or mismatched; backup header requires repair
  Error: Archive verification degraded: expected volumes=1, found=1, missing sequences=[]
  (rc=1)
  ```
- **建议修复**：为 Degraded 引入原因枚举/字符串（如 `Vec<String>` 或 `DegradedReason`），bail 信息包含首个原因摘要；仅在 `missing_indices` 非空时附加卷缺失描述。
- **应补回归测试（TDD）**：CLI 测试断言备份头/备份 footer/主 Catalog 三种降级场景的 stderr 分别包含对应关键词，且无缺卷时不出现误导性的 “missing sequences” 措辞。

---

### ENG-RC-07【Low】`repair` 中 `Healthy && needs_repair()` 分支不可达（死代码）

- **维度**：代码质量
- **确认程度**：confirmed（布尔推导）
- **锚点**：
  - [`commands.rs:1191-1196`](../bins/era-cli/src/commands.rs#L1191-L1196)：`if matches!(health, Healthy) && !needs_repair() { … No repair needed; return }`
  - [`commands.rs:1198-1206`](../bins/era-cli/src/commands.rs#L1198-L1206)：`if matches!(health, Healthy) && needs_repair() { … “recoverable shard corruption” }`
  - [`chunk_processor.rs:904-919`](../crates/era-engine/src/chunk_processor.rs#L904-L919)：`is_healthy() = matches!(archive_health, Healthy)`；`needs_repair() = !is_healthy()`
- **机理**：`Healthy && needs_repair()` ≡ `Healthy && !Healthy` ≡ false，该分支永不执行；其 “⚠️ Archive is readable but has recoverable shard corruption.” 文案从未出现在任何场景（EC 分片损坏时 `decoded.corrupted_shards>0` 会进 `warnings` → `Degraded`，走的是下面的 Degraded 分支）。这是 `31d358f` 邻接修改留下的死分支，也是“零技术债”声明不成立的直接证据之一。
- **建议修复**：删除该分支，或改为 `if !is_healthy() && missing_indices.is_empty()` 等可达条件。
- **应补回归测试（TDD）**：EC 单分片损坏场景的 CLI 测试，断言 degraded 时输出包含 “recovered from N corrupted shards”。

---

### ENG-RC-08【Low】解包持久化语义仍不完整：只 fsync 文件、不 fsync 目录；overwrite 的 rename→create 崩溃窗口

- **维度**：并发与一致性（崩溃安全 / 原子性）
- **确认程度**：confirmed（代码路径）；掉电后果 inference
- **锚点**：
  - 文件级 fsync 已有三处：[`chunk_processor.rs:412`](../crates/era-engine/src/chunk_processor.rs#L412)（packed）、`:444`（single）、`:523`（multi 完成）
  - `--force` 覆盖实现：[`chunk_processor.rs:561-613`](../crates/era-engine/src/chunk_processor.rs#L561-L613)：先 `fs::rename(target → .era_overwrite_backup_{pid}_{seq})`，再 `create_new(target)`；成功后才在收尾 `commit_overwritten_backups` 删除备份（[`chunk_processor.rs:104-126`](../crates/era-engine/src/chunk_processor.rs#L104-L126)，调用点 [`reader.rs:2403`](../crates/era-engine/src/reader.rs#L2403)）
  - 全仓无目录 fsync：`ops_grep 'sync_all|sync_data|fsync'` 在 `chunk_processor.rs` 只命中文件句柄；`reader.rs`/`commands.rs` 也无目录同步
- **机理**：
  1. **目录项未持久化**：`File::sync_all()` 只保证文件数据+inode 元数据落盘，不保证“目录中新增文件名”落盘。`extract` 返回成功后立即掉电，可能出现“文件内容在磁盘但目录项丢失/文件不可见”。同理 `create_dir_all` 新建的目录与 `commit_overwritten_backups` 的删除都无目录 fsync。
  2. **覆盖窗口**：`rename(target→backup)` 与 `create_new(target)` 之间进程被 kill -9 / 掉电，目标路径会暂时不存在（原内容仅存在于隐藏的 `.era_overwrite_backup_*`）。当前 `--force` 失败回滚只覆盖“返回 Err”的路径，覆盖不了进程终止；残留备份也无游标/日志可供自动恢复。
- **影响（inference）**：成功率语义为“函数返回 Ok 即已持久”的常见期望被打破；极端情况下用户“成功解包”后目标文件消失，或原文件出现在隐藏名下。数据未真正丢失（备份文件仍在），但可运维性/可恢复性差。
- **建议修复**：
  1. 在解包收尾对涉及的每个输出目录做 `File::open(dir)` + `sync_all()`（Unix），overwrite 备份删除后同样同步；
  2. 覆盖策略改为“写同目录临时文件 → `sync_all` → `rename` 原子替换”（POSIX rename 覆盖语义），不再先移走原文件；失败时临时文件删除即可，原文件始终存在；
  3. 若必须保留备份机制，备份文件名加可识别标记并在 CLI 提供恢复/清理说明。
- **应补回归测试（TDD）**：无法直接测掉电，改为可测不变式：
  - 成功 `--force` 后目录内无 `.era_overwrite_backup_*`；
  - 在 rename 后注入失败（可用 `cfg(test)` 钩子或对“备份名候选被占用”的路径测试）→ 原文件仍在原路径；
  - 断言 `extract` 收尾执行了目录同步（测试探针文件系统/计数器，或至少在文档中明确“不保证掉电持久性”）。

---

### ENG-RC-09【Low】解包路径校验仍有父目录 TOCTOU；metadata 恢复按路径重开会跟随符号链接

- **维度**：安全（TOCTOU / 符号链接）
- **确认程度**：confirmed（代码路径）；可利用性 inference
- **锚点**：
  - [`chunk_processor.rs:287`](../crates/era-engine/src/chunk_processor.rs#L287) → [`ensure_contained_output_target`（`:364-369`）](../crates/era-engine/src/chunk_processor.rs#L364-L369) → [`enforce_output_containment`（`:615-670`）](../crates/era-engine/src/chunk_processor.rs#L615-L670)：`canonicalize(parent)` 后校验 `starts_with(canonical_output_dir)`，随后按路径 `open`（[`:325`](../crates/era-engine/src/chunk_processor.rs#L325)）；末级组件已用 `O_NOFOLLOW`+`(dev,ino)` 校验（§4.6 修复），但**父目录组件在 canonicalize 之后仍可被替换为符号链接**。
  - metadata 恢复按路径重开且**跟随符号链接**：[`reader.rs:2430-2432`](../crates/era-engine/src/reader.rs#L2430-L2432) `File::options().write(true).open(&output_path).set_times(..)`、`:2454` `xattr::set`、`:2471` `set_permissions`。
- **威胁场景**：本地攻击者在解包输出目录树内具有写权限（例如多用户主机上的共享解包目录）；信任边界是“进程对输出目录之外的任意文件不可写”。
  - 前置条件：攻击者能在检查与 `open` 之间替换输出目录内的某个父目录为符号链接（Windows 不适用），或替换已创建文件为指向任意文件的符号链接（metadata 阶段）。
  - 影响：块数据（偏移由 catalog 控制、无 truncate）可被写进攻击者指向的目标文件（若解包以特权身份运行，可升级为任意文件写）；metadata 阶段可改写任意文件的 mtime/xattr/权限。按当前 CLI 默认（用户自身权限、输出目录自有）风险低，但“解包到共享目录/以 root 解包”是现实运维形态。
- **与既有的关系**：`adversarial_audit_v4/v5` 的 symlink-swap 测试与 `enforce_output_containment` 覆盖了**预检期**的父目录替换拒绝；本项是“预检/校验成功之后、实际 open 之前”的窗口，属 §4.6 修复后的残余面。
- **建议修复**：
  1. 使用 `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)`（或逐级 `openat(O_NOFOLLOW|O_DIRECTORY)` 持有 dirfd 链）打开输出目录树，所有文件创建基于 dirfd；
  2. metadata 恢复复用同一个已打开句柄（`fchmod`/`futimens`/`fsetxattr`），不要按路径重开；
  3. 若暂不实现，至少在文档中声明“解包目录必须为进程独占”。
- **应补回归测试（TDD）**：现有 `test_security_extract_rejects_symlink_parent_swap` 之外，增加“预检通过后替换父目录”的确定性测试（可在 `enforce_output_containment` 返回后、`open` 前插入测试钩子），断言 `Security` 错误；metadata 阶段用句柄/路径篡改测试断言不会跟随链接。

---

### ENG-RC-10【Low / benchmark-needed】§4.9 未闭环：verify 每卷读完整 Catalog、repair 非 EC 路径重复整卷 verify，且无 benchmark 证据

- **维度**：性能
- **确认程度**：confirmed（代码 + diff）；端到端影响 **benchmark-needed**；其中“CLI repair 重复 verify”属 **provable duplicate work**
- **锚点**：
  - verify 每卷完整读主 Catalog（`31d358f` 引入）：[`reader.rs:2768-2796`](../crates/era-engine/src/reader.rs#L2768-L2796)（AUDIT-HIGH-02 修复的实现；`read_and_verify_catalog_bytes` 会解密、拼接、`verify_catalog_commitment`）
  - CLI repair 先跑一次完整 verify：[`commands.rs:1189`](../bins/era-cli/src/commands.rs#L1189)
  - repair 内部再为“凭据校验/判定”跑第二次完整 verify（非 EC 单卷）：[`repair.rs:712-716`](../crates/era-engine/src/repair.rs#L712-L716)；多卷非 EC 同样 [`repair.rs:1333`](../crates/era-engine/src/repair.rs#L1333)
  - 无 benchmark/无量化证据：`git diff --stat ee39fae..HEAD | grep -i bench` 为空；`b22a07e` 未新增 benchmark
- **机理**：`era repair`（非 EC）至少执行两次全块扫描：CLI 预检一次、repair 引擎内部一次；再叠加“每卷一次完整 Catalog 读取与解密”（O(卷数 × catalog 明文大小)）。对 100 卷 × 100 MiB Catalog 的归档，仅 Catalog 冗余校验就多出约 10 GiB 读/解密/解析。前序 §4.9 明确要求 benchmark 后决策，本轮整改未提供任何数据即宣称闭环。
- **建议修复**：把 CLI 已获得的 `VerifyStats` 传入 repair（或让 repair 返回“是否需要修复”而不二次全扫）；Catalog 校验可采样/仅主副本/基于 manifest 摘要；补 benchmark（`benches/` 或 `cargo bench -p era-engine`）量化 1/10/100 卷场景。
- **应补回归测试/度量（TDD）**：无行为回归测试可写时，至少记录 benchmark 基线（verify/repair 的 I/O 计数或耗时），并在 CI 中保留脚本；功能侧断言 repair 不再重复调用 `verify()`（可用测试专用的 verify 计数器）。

---

### ENG-RC-11【Low】verify 与 extract 的尺寸校验不对称

- **维度**：规格符合性（判定一致性）
- **确认程度**：confirmed（代码路径）
- **锚点**：extract 拒绝超大声明：[`reader.rs:2189-2195`](../crates/era-engine/src/reader.rs#L2189-L2195)（`entry.size > MAX_DECLARED_FILE_SIZE(100 GiB)` → `CorruptedHeader`）；verify 的规划循环 [`reader.rs:2542-2600`](../crates/era-engine/src/reader.rs#L2542-L2600) **没有** size 上限检查，仅有 `validate_regular_file_chunks`（长度和 == size，但 size 本身无上限）。
- **机理**：一个带合法 catalog commitment、但 `entry.size` 超过 100 GiB 的归档（或 8 GiB~100 GiB 之间，见 ENG-RC-01）会被 `verify` 判定 Healthy，而 `extract` 直接失败。verify 的语义承诺是“归档完整性/可读性”，与 extract 判定不一致会误导自动化：verify 绿 → 定时任务宣称备份健康 → 真实恢复失败。
- **建议修复**：抽出共享的 `validate_catalog_entries()`（路径、类型、chunk 连续性、size 上限、packed 一致性），在 extract 与 verify 规划期同时调用；并把所有上限常量集中到一处、与 ENG-RC-01 的预算保持一致。
- **应补回归测试（TDD）**：构造 `entry.size = MAX_DECLARED_FILE_SIZE + 1` 的 catalog（可通过对现有测试 helper 目录/序列化路径注入），断言 extract 与 verify **都**报错且错误类别一致。

---

### ENG-RC-12【Low】§4.10 未闭环：139 处源码字符串耦合测试仍在

- **维度**：代码质量（测试质量）
- **确认程度**：confirmed（grep）
- **锚点（示例）**：
  - [`crates/era-engine/tests/adversarial_audit_v2.rs:105-109`](../crates/era-engine/tests/adversarial_audit_v2.rs#L105-L109)（“内存预算”仅断言 `source.contains("MAX_EXTRACTION_MEMORY")`）
  - [`crates/era-engine/tests/adversarial_audit_v3.rs:1-21`](../crates/era-engine/tests/adversarial_audit_v3.rs#L1-L21)（22 个 `include_str!("../src/…")`）、`:260-273`（断言 `reader.rs` 必须出现精确字符串 `tokio::fs::try_exists(&full_path).await.unwrap_or(false)`）
  - 计数：`grep -rn 'include_str!("../src' crates/era-engine/tests bins/era-cli/tests | wc -l` → **139**；覆盖 **12** 个测试文件
- **机理**：这类测试绑定源码文本形状，任何无关重构/重命名都会误报；反过来，它无法发现“常量为 1 字节”“阈值被改小”“分支被删除但常量名保留”等真实行为退化——ENG-RC-01 正是活例子（唯一守护测试只断言常量字符串存在）。
- **建议修复**：把安全不变量改为行为测试（注入小阈值/故障注入/端到端负例）；对确需静态检查的架构约束（如“禁止 blocking `Path::exists`”），改用 clippy 自定义 lint / `cargo-deny` / 构建脚本，而非逐字源码断言。
- **应补回归测试（TDD）**：逐条替换上述 139 处中涉及读路径/CLI 的断言（重点：`MAX_EXTRACTION_MEMORY`、`try_exists`、`sync_all`、`O_NOFOLLOW`），改为可验证行为的测试；先在“删除/弱化保护”时 RED，再确保实现后 GREEN。

---

## 4. 已核实为已修复的正例（不构成本轮 finding）

- **P1 §4.2 备份头校验 + 修复闭环（confirmed）**：清零 `size-4224` 处 4096 B 备份头后：
  ```text
  era verify   → rc=1, Degraded, “Volume 0: backup header damaged or mismatched; backup header requires repair”
  era repair --force → “Restoring backup header for …”; rc=0
  era verify   → rc=0, “Archive integrity verified successfully!”
  ```
  实现：[`reader.rs:2818-2882`](../crates/era-engine/src/reader.rs#L2818-L2882) + [`repair.rs:443-523`](../crates/era-engine/src/repair.rs#L443-L523)（`plan_volume_header_repairs` 用 manifest 摘要认证后写回）。
- **P2 §4.3 `--force` 失败不再删除用户原文件（confirmed）**：数据区单字节翻转 + 预置 `ORIGINAL` + `extract --force` → rc=1，目标内容仍为 `ORIGINAL`，目录内只剩 `data.bin`（无 `.era_overwrite_backup_*` 残留）。实现：[`chunk_processor.rs:561-613`](../crates/era-engine/src/chunk_processor.rs#L561-L613) + [`reader.rs:2515-2531`](../crates/era-engine/src/reader.rs#L2515-L2531)（先删新文件再 `rename` 回备份）。
- **P3 §4.5 单块/打包/多块文件均 `sync_all`（confirmed）**：`chunk_processor.rs:412,444,523`。
- **P4 §4.6 末级组件 TOCTOU 已修（confirmed）**：重开用 `O_NOFOLLOW` + `(dev,ino)` 比对（[`chunk_processor.rs:317-352`](../crates/era-engine/src/chunk_processor.rs#L317-L352)）。
- **P5 §4.8 File 条目尺寸/连续性校验（confirmed）**：[`reader.rs:2885-2934`](../crates/era-engine/src/reader.rs#L2885-L2934) 同时被 extract（`:2197`）与 verify（`:2547`）调用。
- **P6 解包 FD 上限（AUDIT-HIGH-01 类）已从“预开全部句柄”改为 LRU 懒句柄**：`MAX_OPEN_EXTRACTION_FILES=64`（[`chunk_processor.rs:17`](../crates/era-engine/src/chunk_processor.rs#L17)），预检不再 `open` 每个条目（对照旧 post-fix 报告 AUDIT-HIGH-01 的 1100 句柄场景）；本轮未在 `ulimit 1024` 下重复压测（由负责人全量门禁覆盖）。

---

## 5. 未能核实 / 范围外的前序声明

1. **§4.1（`8c42a4c`）“中断 append 后可恢复”**：属于 writer/`era-volume` 写路径与 checkpoint 范围，本线程只读路径；未核实。需要写路径线程用“truncate 后不 finalize 直接 drop → 重新 open”探针复验。
2. **§4.4（`31d358f`）“非 EC 主头修复与数据损坏解耦”**：代码顺序已符合（先 `apply_header_repairs` 再报数据损坏，`repair.rs:750`/`:755-761`，多卷 `:1372`/`:1377-1382`），但未做 CLI 端到端复现（要求 `--force` 后 verify 仍为 Degraded/Incomplete 且主头已回写）。标为“代码层面通过、端到端未核实”。
3. **§5.1/§5.2（`b22a07e`）审计证据链入仓、`Cargo.lock`/工具链对齐**：本线程只确认 `git show --stat b22a07e` 确实把 docs/Cargo.lock/.gitignore/fuzz.yml 纳入提交；未核验文档内容与 CI 一致（工程/流程维度）。
4. **§4.9 与 §4.10 的“闭环”声明被否定**（ENG-RC-10/12）：前者无 benchmark，后者仍有 139 处源码字符串测试。
5. **“零遗留/零技术债”整体声明**：除本报告 12 项外，至少还有本线程未覆盖的维度（写路径 §4.1、工程债 §5.x）。仅就本范围，声明即不成立。

---

## 6. 限制与复现方法

- 探针使用预编译二进制 `target/release/era`（mtime 2026-11-22 00:02，晚于 `src/` 最后修改 23:47；`b22a07e` 只改 docs/tests/Cargo.lock/toolchain）。若需绝对严格，可用 `cargo build --release -p era-cli` 重建后复跑 §7 脚本。
- 本会话默认 `cargo/rustc` 不可用，且负责人后台全量测试与其线程占用了 `target` 构建锁；按分工未重复全量测试，也未并发跑定向测试。端到端结论以二进制探针 + 静态代码路径为准。
- ENG-RC-01 的实证复现需要 >8 GiB **唯一内容** 的归档（去重会折叠重复数据），成本约 8.5 GiB 读/写 + 建卷；本线程未执行（避免与 CI 抢 I/O，且 `/tmp` 为 7.9 GiB tmpfs）。复现配方：
  ```bash
  head -c 9000000000 /dev/urandom > /var/tmp/big.bin        # 唯一数据，避免去重
  era create -o /var/tmp/big.era -p pw /var/tmp/big.bin     # 成功
  era verify /var/tmp/big.era -p pw                         # 预期 Healthy（无上限）
  era extract -i /var/tmp/big.era -o /var/tmp/big_out -p pw # 预期 rc!=0 且报 “Extraction memory budget exceeded”
  ```
  判定标准：`extract` 在累计解码 > 8 GiB 时报 `Security("Extraction memory budget exceeded: possible decompression bomb")`，且 `big_out` 被清理。

---

## 7. 附录：探针脚本与关键输出

探针脚本位于 `/tmp/era_audit_probe.sh`、`/tmp/era_audit_probe2.sh`（审计结束前已删除，仓库 `git status` 干净）。核心命令（节选）：

```bash
ERA=target/release/era
head -c 200000 /dev/urandom > srcA/data.bin
$ERA create -o a.era -p pw --erasure none srcA/data.bin          # rc=0
SZ=$(stat -c %s a.era)
python3 -c "b=bytearray(open('p.era','rb').read()); b[SZ-128:SZ]=bytes(128); open('p.era','wb').write(b)"
$ERA verify p.era -p pw        # ENG-RC-02: rc=0 且 “Archive integrity verified successfully!”
$ERA repair p.era -p pw        # ENG-RC-02: rc=0 且 “Archive is intact. No repair needed.”
python3 -c "b=bytearray(open('b.era','rb').read()); b[4096:4224]=bytes(128); open('b.era','wb').write(b)"
$ERA verify b.era -p pw        # ENG-RC-02: rc=0，无任何 warning
$ERA repair /nonexistent.era -p pw   # ENG-RC-05: rc=0 “Nothing to repair”
```

关键原始输出（节选，完整见 §3 各条）：

```text
=== A1: verify with corrupted PRIMARY footer (tail 128B)
rc=0
 INFO ✅ Archive integrity verified successfully!
=== A2: verify with corrupted BACKUP footer (offset 4096)
rc=0
 INFO ✅ Archive integrity verified successfully!
=== E: backup HEADER corrupted -> verify
rc=1
 WARN   1. Volume 0: backup header damaged or mismatched; backup header requires repair
Error: Archive verification degraded: expected volumes=1, found=1, missing sequences=[]
=== C: create from dir with symlink + empty dir + unreadable subdir
rc=0
 INFO   Files:      1
--- list c.era
 INFO srcC/a.txt
 INFO Total: 1 files (6 B total)
```

证据计数命令：

```text
# allow(dead_code) 残留
grep -rn 'allow(dead_code)' crates/*/src bins/*/src | wc -l          -> 41
# 源码字符串耦合测试
grep -rn 'include_str!("../src' crates/era-engine/tests bins/era-cli/tests | wc -l -> 139（12 个文件）
# 整改区间内无 benchmark 变更
git diff --stat ee39fae..HEAD | grep -iE 'bench|benches'            -> 空
# 引入 8 GiB 上限的提交
git log -S 'MAX_EXTRACTION_MEMORY' --oneline                        -> 89f6e31 …
```

---

*本文件由 2026-11-22 engine 读路径/CLI 审计线程生成；不修改任何源码/测试/既有文档，仅本文件落盘。*