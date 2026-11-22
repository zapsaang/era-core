# ERA-CORE 恢复缺陷与系统风险综合修复方案 (Consolidated Risk & Recovery Remediation Plan)

**生成日期:** 2026-10-10（末次修订 2026-10-10；历史台账 R1–R34 收敛，行级复核 R35–R36，R37/R38 锚点与门禁自洽，**裁决轮 R39**，**本次两轮 R40 / R41**）
**核查基线:** `feat_fly` @ `e4050a2`（`git rev-parse HEAD` = `e4050a2244c69b4ecbcf02a90b82b2c2b7a578ea`，与文首一致；工作树对 `crates/ bins/ Cargo.toml .github/` 无改动）
**对应审计文档:** `docs/consolidated-risk-and-recovery-audit-2026-10-10.md`
**约束声明:** 本文档是设计规程与 TDD 实施方案，**不包含任何代码改动**。当前代码处于深度测试阶段，未在任何生产环境使用，**不接受任何向后兼容妥协或过渡技术债**。

**本版相对上一版（934 行）的修订:**

- **R37《锚点全域重核与失效结论清除》**：对 §1.3 全部锚点、全部机械判据、全部缺口符号做逐条实测。纠正 **4 处事实错误**（`scan_for_typed_blocks` 被写成“生产零调用”、`filetime` 的 dev-dependency 等级被当作可生产使用、`checkpoint.rs` 锚点错位、`ExtractStats` 字段面表述）与 **5 处数字漂移**（测试计数三层口径、`backward compat` 命中数、`erasure_scan` 行区间、`volume_stage.rs` 三段落点行号、`Symlink escape` 行号复核），登记 **3 处遗漏约束**（备份块 ID 未持久化、`MAX_BLOCK_SIZE` 64MB 上界、`ExtractStats::corrupted_shards` 与 `DecodedBlock::corrupted_shards` 同名不同层）与 **1 处判据副作用**（判据 1 的跨 FIX 归属）。**同时撤销 R37 过程中一度写出的 `ArchiveWriter`“14 项公开 API”结论**（该错误在 R37 草稿中引入、在 R38 中自查发现并撤销，最终结论回到 R35 的 **10 项**，见 W9）。
- **R38《TDD 可闭环性与门禁双向自洽》**：补齐 FIX-04 读端自愈的**完整性前提**（备份 Catalog 无承诺覆盖）与写端覆盖面（`GenericArchiveWriter` 单卷路径）；把 FIX-05“废除兼容回退”的射程从 1 处扩到 **3 处**（含 CLI 分支与读端无界读放行）；新增 `DecodedBlock::corrupted_shards` 的复用裁决，消除重复统计字段；把 FIX-06 的软链接时间戳方案落到**真实可用的依赖**上；新增 3 条红测试与 2 条冻结子串。
- **R39《留白项终裁》**：对 §4.9 与 §3.5 中被标为“待裁决”的**五项**设计分叉给出**不可逆裁决**，并撤销其中一项高风险设计——**D1** 读端对无 Manifest 归档改为 **Fail-Closed**（删除 `check_read_bound` 的放行分支）；**D2** 软链接时间戳采用 **`filetime` 提升为 `era-engine` 常规依赖**（拒绝 `libc` 原生 FFI）；**D3** **不采用** `BlockHeader::reserved2` 承载块 ID 的自描述方案（字段宽 4B ≠ `BlockId(u64)`，且需格式版本推进 + 68 处偏移算式联动），改由 Footer v2 指针 + `catalog_commitment` 独立保证。三项裁决理由与反证见 §3.9。**D4**：FIX-06 删除浮动扫描后，`VolumeReader::open` 的“无 Footer 但纠删码启用则继续”宽松分支一并**删除**（Footer 全失即 `CorruptedHeader`，与纠删码配置无关）。**D5**：读端容差 `max(parity+1, 2)` **保留**并纠正定位为“未知卷数时的扫描终止条件”（读端已由 `vol_index_map` 实现空洞安全），恢复端维持严格连续——两套语义各自适用域须显式写明。
- **R40《读端放行全域清查与实现级技术债对齐》**：逐条实测 R39 五项裁决的**实施射程**，纠正 **1 处 D1 覆盖缺口**——`check_read_bound` 的 `None → Ok(())` 不是读端唯一放行分支，`crates/era-engine/src/block_iter.rs:77-79` 的 `check_commit_horizon_for_sequence` 对 `committed_ends == None` 同样 `return Ok(())`，且该 `Option` 直接来自 `ArchiveReader::committed_ends_for_iterators()`（`reader.rs:503-504`），**D1 必须两处同步**；登记 **1 处会制造技术债的实现顺序**——`checkpoint.delete()`（`checkpoint.rs:402-469`）以 `file_len - FOOTER_SIZE` 定位写偏移，且其 `Footer::builder` 链**无 `.manifest(...)`**，故“先 `set_len(committed_end)` 再 `delete()`”会（a）把 Footer 写到 `committed_end-128` 覆盖已提交数据、（b）把 `manifest_offset` 清零；同时把 `truncate_to_checkpoint()` 的 `None` 入口从 1 处扩为 **2 处生产入口**（`recovery.rs:345` 与 `commands.rs:1254`，另有测试 `recovery.rs:846`），并要求在**函数体 `None` 分支**收口；并纠正 **3 处事实/数字错误**（`backward compat` 命中口径：`crates/*/src bins/*/src` 为 **25 行 / 9 文件 / 5 crate** 且 **1 处是可执行 `debug!` 日志而非注释**；`BlockHeader::SIZE` 的 68 处须限定 `crates/*/src bins/*/src`，全 `crates` 为 82 处；`scan_for_typed_blocks` 的生产调用实为 **3 处**（全在 `era-index`），上一版把 `writer.rs` 的 4 处 `#[cfg(test)]` 调用误计为生产并漏计 `:493`/`:897`）。
- **R41《数字口径封板与依赖论证复核》**：把可机械复现的计数全部就地固化（源码属性 `#[test]` 2254 + `#[tokio::test]` 472 = **2726**，源码级 `#[ignore]` **4**；CI 实跑口径 **2755 = 2737 passed + 0 failed + 18 ignored（14 doctest + 4 源码级）**——本轮完整复跑 `cargo test --release --workspace` 两次并聚合 `test result:` 行，exit code 均为 0、逐项一致；`--no-run` 亦 exit 0）；把 `filetime` 的依赖论证从“纯安全 Rust、无 `unsafe`”改为**事实准确的传递依赖论证**（`Cargo.lock` 显示 `filetime 0.2.27` → `{cfg-if, libc, libredox}`，即它**引入 `libc` 到 `era-engine` 的依赖图**；反对 `libc::utimensat` 的真正理由是“不在 L4 写 `unsafe` 代码、不新增自维护 FFI”，而非“链条内无 `unsafe`”），并补登“`filetime` 不在 workspace 常规依赖中，提升等级属新增依赖决策”这一前提；把 §5.4 判据 8 的界定由**裸 grep 即视为兼容分支**收紧为**注释/日志行排除后的可执行残留判据**（`backward compat` 的 25 行中仅 `reader.rs:1123` 是语句，且该行是日志文案、不是兼容分支，须显式区分“注释/日志”与“可执行兼容路径”）；统一 `cleanup_partial_files`/`fail_extraction_with_cleanup` 的行区间为实测 `:1850-1875`/`:1877-1890`。

---

## 一、 修订台账与设计基线

### 1.1 历史修订决策台账（R1–R36 收敛）

> 历史三十六轮以“逐轮补正”方式记录，过程性论证已归入 §3/§4 权威章节，此处只保留**仍然约束实施的决策**；需要追溯时以 `git log` 查阅本文档历史版本。

| 轮次 | 主题 | 仍然生效的决策 / 已废除的旧结论 |
| :--: | :--- | :--- |
| R1–R4 | 静态锚点、TDD 完备性、运行时协议 | 权威分片上限目标态 **16MB 且单一来源**；目录元数据后序恢复；软链接沙箱校验；红测试禁 `is_err()` 泛断言。**废除**：保留 256MB 别名“兼容测试”。 |
| R5–R11 | 物理布局、源码断言链、多尾恢复、卷格式解冻 | Backup Footer 固定偏移 4096、`DATA_REGION_START = 4224`；0 字节文件与父目录预建归 Phase 1；未终结归档（`total_volumes == 0`）须动态探测。**废除**：“只读兼容旧 reader”与隐式算术紧邻偏移。 |
| R12–R20 | 三阶段解包、标志白名单、公理与不变量 | 三阶段解包模型定型；解压比防御 = **1MB 敏感线 + 100:1 + 16MB 绝对上限**；`flags` 白名单掩码；主备 Catalog 不得别名。**废除**：“目标行数 300/600”。 |
| R21–R23 | 区间互斥、全空归档、纠删码截断 | 主备必须**连续区间互斥**；块 ID 分配律 `[C..C+K-1]` / `[C+K..C+2K-1]`；`has_pending()` 提前返回是缺陷；单卷软截断应映射为缺失分片槽位。 |
| R24–R28 | `writer.rs` 拆分、句柄生命周期、协同截断 | 4 阶段拆分；`collect_files_async` 非死代码（删前迁移 2 处调用点）；清理前显式 drop 句柄、目录自底向上删除；Preflight→逆向 Execution；**废除**无 Manifest 的猜测性截断与浮动尾部扫描。 |
| R29–R30 | 域隔离与公理终审 | **新增** `FOOTER_DOMAIN_V2`，不得原地改写既有 `FOOTER_DOMAIN`；五大纯净性公理 + 七条数学不变量**仅作设计论证，不作门禁依据**（§5.3）。 |
| R31–R34 | 追溯、可编译红、反向实测、红绿闭环 | 问题集合为 **16 个唯一 ID**（2C/5H/5M/4L）；编译期/断言期 Red 分级与错误冻结表；解压比**分母语义**（填充稀释绕过）裁决；`checkpoint.delete()` 调用序裁决；**证伪**“Catalog 全卷冷扫描 + MAC 穷举”（`scan_for_typed_blocks(BlockType::Catalog)` 零调用——**注意**：该 API 本身在 `era-index` 对 `IndexManifest` 有在役冷恢复调用，见 §1.2 W1/W2）。 |
| R35–R36 | 行级反向复核、TDD 可闭环、判据自洽 | 纠正 11 处历史事实/锚点错误；废除全部作废口径（“18 项”“64KB 浮动窗口”“`EraError::CorruptedArchive`”“无上限分配”）；补齐红测试因果链与缺口符号；登记既有测试/文档资产同步项。 |
| R37–R38 | 锚点全域重核、TDD 与门禁双向自洽 | 见 §1.3；纠正 R35/R36 自身遗留的 9 处事实/数字偏差与 1 处判据副作用；补齐 FIX-04/05/06 三处未闭环设计项。 |
| R39 | 留白项终裁 | D1 读端无 Manifest **Fail-Closed**；D2 软链接时间戳用 `filetime`（提升为 `era-engine` 常规依赖）；D3 **撤销** `reserved2` 承载块 ID 的自描述项；D4 两 Footer 全失**无条件** `CorruptedHeader`；D5 读端容差保留（定位为扫描终止条件）、恢复端严格连续。 |
| R40–R41 | 读端放行全域清查、实现级技术债对齐、数字口径封板 | 见 §1.2；补齐 D1 的**第二处**读端放行分支（`block_iter.rs:77-79`）与 `truncate_to_checkpoint` 第三处 `None` 入口；登记 `checkpoint.delete()` 的“覆盖已提交尾 + 清 `manifest_offset`”顺序陷阱；纠正 3 处计数/性质错误（`backward compat`、`BlockHeader::SIZE`、`scan_for_typed_blocks`）；重写 `filetime` 依赖论证并固化全部可复现计数。 |

### 1.2 本版两轮修订（R40 / R41）实测结论

> 复核方式：`read`/`grep`/`sed`/`wc -l` 直读源码 + `cargo test --release --workspace` 实跑（exit 0）+ `cargo test --release --workspace --no-run`（exit 0）。基线固定在 `e4050a2`，文档不随工作树漂移。“性质”列区分**事实错误**（与代码不符）、**数字漂移**（量级正确但计数错）、**遗漏约束**（结论方向对但缺前置）、**覆盖缺口**（裁决未闭环）、**技术债**（按当前实现顺序会制造新缺陷）。

**W1–W21（R37/R38 结论，本轮全部复验仍成立；除 W8 见 W25 修正）**

| # | 对象 | 上一版表述 | 实测真值（`e4050a2`） | 性质 |
| :-- | :--- | :--- | :--- | :--- |
| W1 | `scan_for_typed_blocks` 调用面 | §1.1 R31 行与 §1.2 V15 均写“**生产零调用**（证伪冷扫描叙事）” | **错误**：`crates/era-index/src/reader.rs:462` 在生产代码中调用 `volume_reader.scan_for_typed_blocks(BlockType::IndexManifest)`（冷恢复路径，仅当 Footer 无 `index_root` 或扫描失败时进入）。审计原判据是“Catalog 不存在全卷冷扫描”，**不是**“该 API 无生产调用”。正确表述：`scan_for_typed_blocks(BlockType::Catalog)` 无任何调用者；IndexManifest/IndexPage 冷扫描**确实存在且在役**。**R41 勘误（见 W27）**：生产调用共 **3 处**（`era-index/src/reader.rs:462` IndexManifest、`:493`/`:897` IndexPage）；`era-engine/src/writer.rs:3076/3080/3197/3201` 在 `#[cfg(test)] mod tests` 内，**属测试代码而非生产调用** | 事实错误 |
| W2 | 解压比不得引入 `scan_for` 之外的冷扫描 | §3.3 “解除伪约束”段写“既有实现**不存在**全卷冷扫描” | 同上：应改为“既有实现**不存在 Catalog 的**全卷冷扫描”。`era-index` 的 IndexManifest 冷扫描是**已文档化的降级路径**，FIX-04 的收益仅限于消除 Catalog 的算术紧邻偏移，不得顺带主张删除 index 冷扫描 | 事实错误 |
| W3 | 备份 Catalog 块 ID 的持久化 | 未登记 | `crates/era-engine/src/volume_stage.rs:151-209`（`write_catalog_to_all`）与 `:211-269`（`write_catalog_blocks_to_all`）、`:275-351`（`write_catalog_block_sets_to_all`）把 `backup_block` **紧随主块写入同一卷**，但 `_backup_location` 被**丢弃**；`backup_block_ids`（`writer.rs:2149-2156`，仅 `erasure_enabled()` 为真时存在）**从不写入 Footer 或 Manifest**（`ArchiveManifest` 字段仅 `epoch_id`/`finalize_sequence`/`committed_horizon`/`catalog_commitment`/`index_commitment`/`volume_committed_ends`，`crates/era-common/src/types/manifest.rs:18-47`）。**结论**：多卷+纠删码归档目前**已在磁盘上写出**一份无处寻址的备份 Catalog；FIX-04 的真实工作是**持久化其地址**，而非新造写入路径 | 遗漏约束（缩小了工作量、也缩小了风险面） |
| W4 | 备份 Catalog 的完整性来源 | 未登记 | `catalog_commitment` 只覆盖**主 Catalog 明文**（`writer.rs::build_manifest`(`:1320` 起) → `compute_catalog_commitment(catalog_bytes)`(`:1327`，定义于 `:2943`)）。若读端改由备份指针解密，**没有任何承诺覆盖备份字节**。FIX-04 必须显式裁决：备份必须与主 Catalog **逐字节等同**（同一 `catalog_bytes` 派生的 `EncryptedMacroBlock`），从而复用 `catalog_commitment` 完成校验；**禁止**让备份走独立编码路径后只靠 AEAD 标签自证 | 遗漏约束（安全前提） |
| W5 | 单卷非纠删码归档 | FIX-04 “触发条件：`volume_indices.len() == 1`，不论是否启用纠删码” | **成立且更严重**：`writer.rs:2149` 的 `if self.pipeline.erasure_enabled()` 为假时 `backup_block_ids = None`，`volume_stage` 的所有 `if let Some(backup)` 分支全部跳过 → 单卷非纠删码归档**连不可寻址的备份都没有**。FIX-04 必须显式覆盖这条路径（否则“双写”对该配置不成立） | 覆盖缺口 |
| W6 | `GenericArchiveWriter::finalize` | §4.3 #5 要求“产出合法 v2 backup 指针” | **成立且被低估**：`writer.rs:3533-3550` 只写**一个** `pack_single(catalog_chunk)`（注意：`pack_single` 而非 `pack_single_with_type(..., BlockType::Catalog)`，类型由调用处的 `write_canonical_block(..., BlockType::Catalog)` 决定），随即 `finalize_with_catalog(..., 0, 0, 0)` 把 checkpoint 三元组清零。该写者无任何备份概念（`GenericArchiveWriter`，公开 API，自定义后端路径），必须在 FIX-04 中显式登记为**第二个写端落点** | 遗漏约束 |
| W7 | 测试计数口径 | “实测 **2727**（`#[test]` 2254 + `#[tokio::test]` 473），`#[ignore]` 4 个” | 必须分清两层（实测 `cargo test --release --workspace`，exit 0）：① **源码属性** = `#[test]` **2254** + `#[tokio::test]` **472**（并非 473）= **2726**；`#[ignore]` 属性 **4 处**（`crates/era-storage/tests/pwrite_test.rs:16`、`bins/era-cli/tests/cli_e2e_gap_tests.rs:69`、`bins/era-cli/tests/cli_boundary_tests.rs:129`、`:206`）。② **CI 实跑声明** = **2755** 项（**2737 passed / 0 failed / 18 ignored**），18 = 14 个 doctest 忽略 + 4 个源码级 `#[ignore]`。审计报告文首“2737 项”实为 **passed 数**，不是总声明数；“2727”既非属性数也非实跑数。**门禁只认 CI 实跑输出**，两层数字都不得当作断言 | 数字漂移 + 口径混淆 |
| W8 | `backward compat` 命中数（§5.4 已废除判据） | “实测命中 26 处/8 文件/5 crate，其中 **25 处**为正当文档注释” | `grep -rn 'backward compat' crates/*/src bins/*/src` = **25 行 / 9 文件 / 5 crate**（上一版的“26 行 / 8 文件”混合了 `for backward` 的并集且文件数有误，见 W25）；且 25 行中 **24 行是注释、1 行是可执行 `debug!` 日志**（`reader.rs:1123`），**不存在**可执行兼容分支。正确表述为“无任何可执行兼容分支；该判据既误伤注释又无法发现真实兼容分支” | 数字漂移 |
| W9 | `ArchiveWriter` 公开面 | R35/R36 原表述“公开 API **10 项**”**正确**；R37 草稿一度改判为“**14 项**”（R38 自查撤销） | `impl ArchiveWriter`（`writer.rs:1310-2090`）内 `pub` 方法精确为 **10 个**：`builder`@1312、`archive_id`@1511、`key_encapsulation`@1522、`is_certificate_mode`@1527、`add_path`@1536、`add_file_with_path`@1585、`add_file`@1693、`add_files`@1736、`add_bytes`@2033、`finalize`@2082。R37 误判的根因是把**调用点行号**当成签名行：`:1556`（`excluded.contains(...)`）、`:1612`（`let permissions = {`）、`:1679`（`self.add_file_chunked(...)`）、`:1758`（空行）全部不是 `pub fn`；仓内不存在 `add_path_recursive`/`add_directory_contents`/`add_directory`/`add_file_with_stored_path`（`grep -rn 'fn add_directory' crates bins` 命中 0），`:1760` 的 `add_file_single` 为**私有**。**冻结面 = 10 项**，§3.6 新增的两项接口是唯一合法扩面 | 事实错误（R37 草稿引入，已撤销） |
| W10 | `erasure_scan` 行区间 | §1.3 / §2.1 / §3.2 多处写平局分支 `:36-42`、`parity_bound_from_lengths` `:47-54` | `reconcile_stripe_prefixes` 函数体实测 `:11-45`，其中平局裁决块为 `:34-42`（`:34` `let mut best`、`:36` `if count == best_count {`、`:37-39` 遇第二个同票即 `return None`）；`parity_bound_from_lengths` 签名为 `:47`、函数体 `:47-54`（**上一版 W10 的 `:33-41` / `:45-54` 系误读，本行已改正**）；`parse_stripe_lengths` `:3-9`；`erasure_data_end` 实测 `:83-107`（**不是** `:79-104`）。其余锚点（`repair.rs:220`、`block_iter.rs:1472-1503`、`reader.rs:1129-1224`）复验通过 | 数字漂移（原表述小错，已二次校正） |
| W11 | `checkpoint.rs` 门控锚点 | §1.3 写“`footer.has_manifest()` 门控在 `:393`”（置于 `checkpoint.rs` 条目下） | `has_manifest()` 在 `crates/era-engine/src/recovery.rs:393`；`crates/era-engine/src/checkpoint.rs:393` 是 `archive_id,`（`write_checkpoint` 调用的实参）。锚点跨文件错位，须回到 recovery.rs | 事实错误 |
| W12 | `Symlink escape detected` 行号（§1.3 与 §4.0） | “见 `chunk_processor.rs:223/233`” | 该字符串实测在 `crates/era-engine/src/chunk_processor.rs:223` 与 `:233`（`enforce_output_containment` 函数体 `:192-246`）。**复验通过**，此处登记仅为消除“R37 改了行号”的误读 | 成立 |
| W13 | `ExtractStats` 字段引用 | §1.3/§2.2 写 `stats.extracted_paths` 时并称 `ExtractStats` 含 `extracted`/`skipped`/`bytes_written` | `crates/era-engine/src/chunk_processor.rs:257-266` 实测四字段：`extracted: u64`、`skipped: u64`、`bytes_written: u64`、`extracted_paths: Vec<PathBuf>`。**无** `failed_files`、**无** `corrupted_shards`（结论成立）；但“extracted 计数”与“路径列表”必须分清，§4.1 的断言只能绑定 `extracted_paths` 的成员关系 | 成立（表述收紧） |
| W14 | 分片读取的独立上界 | §1.3 未登记 | `crates/era-engine/src/block_iter.rs:67` 另有 `const MAX_BLOCK_SIZE: u32 = 64 * 1024 * 1024;`，在 `:254`、`:836`、`:1030` 三处拦截 block 尺寸。它与 `MAX_SHARD_SIZE`（单分片）、`MAX_DECOMPRESSED_SIZE`（解压产物）同为**语义互不相同**的边界。§3.2 的“条带瞬时 96MB”上界论证必须注明 64MB block 守卫**同时**存在，否则该数字的推导链不完整 | 遗漏约束 |
| W15 | `ExtractStats::corrupted_shards` 与既有计数器 | §4.0/§4.5 要求新增 `ExtractStats::corrupted_shards`，§4.5 #6 写“`stats.corrupted_shards += 1`” | **同名不同层**：`crates/era-engine/src/block_iter.rs:38` 已有 `DecodedBlock::corrupted_shards: usize`，`:49` 已有 `BlockIterStats::corrupted_shards: u32`，并在 `:586/1487/1554/1726` 累加；`crates/era-engine/src/reader.rs:1969` 已把 `decoded.corrupted_shards` 汇入 `VerifyStats::warnings`（`chunk_processor.rs:412-413`）。新增 `ExtractStats` 字段必须声明“**聚合** `DecodedBlock::corrupted_shards`”，不得新造独立计数源，否则同一事实两套口径 | 遗漏约束（命名撞车） |
| W16 | 非 Linux coredump 分支 | `secure_memory.rs:364-367` 返回 `Ok(())`，静默 no-op 且上报成功 | 复验通过：`:334` 为 `pub fn disable_core_dumps() -> Result<(), String>`，`:364` 为 `#[cfg(not(any(target_os = "linux", target_os = "macos")))]`，`:367` 为分支闭合。`main.rs:501` 已调用。文档只能写“Linux 已防护、macOS 有 ptrace 反附加、其余平台为 no-op” | 成立 |
| W17 | `filetime` 可用性（§3.6 Phase 3） | “用 `utimensat(AT_SYMLINK_NOFOLLOW)`（或 `filetime::set_symlink_file_times`，`bins/era-cli/Cargo.toml:37` 已有 `filetime`）” | `bins/era-cli/Cargo.toml:37` 位于 **`[dev-dependencies]`**（`:30` 起）：`filetime = "0.2"`、`xattr = "1"`。全仓生产代码 `crates/*/src`+`bins/*/src` 对 `filetime` 的引用为 **0**（仅 `bins/era-cli/tests/cli_coverage_gap_tests.rs` 三处使用）。`xattr` 相反，是 `era-engine` 的**正式依赖**且在 `writer.rs:1632`/`reader.rs:1816` 生产使用。因此：(a) 该方案不能直接照搬 `filetime`；(b) `xattr` 可直接用；(c) 若确需 `filetime`，必须在本 FIX 中显式登记“`filetime` 提升为 `era-engine` 常规依赖”，属**新增依赖决策** | 事实错误 |
| W18 | FIX-05 的兼容回退射程 | §3.4 只写“废除 `recovery.rs:391` 的 `backward compat` 回退分支” | 实际有 **3 处**需一并裁决：① `crates/era-engine/src/recovery.rs:391`（`if footer.has_manifest()`，无 Manifest 时不裁剪 `volume_committed_ends`）；② `bins/era-cli/src/commands.rs:1249-1254` 的 `if let Some(manifest) = reader.manifest() { ... } else { manager.truncate_to_checkpoint() }` **显式保留了无 Manifest 分支**（且是生产 `repair --force` 的现役路径）；③ `crates/era-engine/src/reader.rs:1234-1236` 的 `check_read_bound` 在 `volume_committed_ends == None` 时 `return Ok(())`——**读端对无 Manifest 归档完全放行越界读**。仅改 ① 会留下两处沉默兼容 | 遗漏约束 |
| W19 | §5.4 判据 1 的连带失效 | 判据 1 = `! grep -rn "256 \* 1024 \* 1024" crates/*/src bins/*/src` | **成立但会误伤**：该字面量的 4 处命中有 1 处是 `crates/era-codec/src/compression.rs:8` 的 `MAX_DECOMPRESSED_SIZE`。FIX-01 同样要把 256MB 降为 16MB，两条 FIX 对同一判据负责，判据本身自洽；但 §5.4 必须在判据旁标注“由 FIX-01（L2 解压产物）与 FIX-03（引擎三处）**共同**清零”，否则实施者会误以为任一条 FIX 单独即可封板 | 判据副作用（归属不清） |
| W20 | 其余锚点 | — | §1.3 全量复验**通过**：Header/Footer 常量与 128B 字段偏移（`footer.rs:36-58` 文档表 ↔ `:96-100` 结构体逐字段一致）、`reader.rs:57` 提前阻断、`reader.rs:35-41` 文档化五步恢复链中**第 2/3 步（Backup SuperHeader）无实现**、`data_region()` `:357-365`、`read_raw` `:240-242` 单行无校验、`read_typed_block` `:383` 及 `:396-405` 的 16MB 校验、浮动扫描 `:144-204` + 调用点 `:80` + `FLOATING_FOOTER_SCAN_SIZE` `:20`、`MAX_CONSECUTIVE_SCAN_MISSES` `lib.rs:24`、`checkpoint.rs` `delete()` 全域（`:402` 起、`:418` 的 `file_len - FOOTER_SIZE`、`:439-456` builder 链缺 `.manifest(...)`、`:460-465` 双写、`:487/504/591` DEPRECATED）、`recovery.rs` 各锚点、`writer.rs` 3649 行与 813/2836 行拆分口径、`MAX_VOLUME_SCAN` `multi_volume.rs:22` 私有且仅 `:312` 一处使用、`scan_for_typed_blocks` 定义 `era-volume/reader.rs:450`、`xattr` 生产使用点 | 成立 |
| W21 | 编译可达性 | — | `cargo test --release --workspace --no-run` **exit 0**：全部测试目标可编译，§4.0 缺口清单中的符号可在现有树上安全“先红后绿” | 成立 |

#### 1.2.1 R40 / R41 新增实测项（W22–W27，同一基线 `e4050a2`）

| # | 对象 | 上一版表述 | 实测真值（`e4050a2`） | 性质 |
| :-- | :--- | :--- | :--- | :--- |
| W22 | D1“唯一读端兼容后门” | §3.9 D1 依据 1 写“该分支是**唯一的**读端兼容后门” | **覆盖缺口**：`crates/era-engine/src/block_iter.rs:71-79` 的 `check_commit_horizon_for_sequence` 在 `committed_ends == None` 时同样 `return Ok(())`（`:77-79`）。该 `Option` 由 `ArchiveReader::committed_ends_for_iterators()`（`reader.rs:503-504`，即 `volume_committed_ends.clone()`）直接注入**全部**分块迭代器（`reader.rs:698/710`、`:2041/2053`、`:2105/2117`），故只改 `reader.rs:1234-1236` 会留下第二处静默放行。**D1 的射程必须扩到 2 处**；两处一致后，“无 Manifest 归档在读路径不被接受”才成立 | 覆盖缺口 |
| W23 | `truncate_to_checkpoint()` 的 `None` 入口射程 | §3.4 射程只登记 `recovery.rs:391`、`commands.rs:1249-1254`、`reader.rs:1234-1236` 三处 | 另有 **2 处生产调用点直接走 `None`**，须一并纳入射程：`crates/era-engine/src/recovery.rs:345`（`truncate_to_checkpoint()` 本体，即 `_with_manifest(None)`）与 `bins/era-cli/src/commands.rs:1254`（`repair --force` 的无 Manifest 分支）；测试内 `recovery.rs:846`（`_with_cancel_flag_and_manifest(..., None)`）是**唯一**的第三个 `None` 入口（`grep -n ', None)' recovery.rs` 仅此 1 行）。Fail-Closed 必须在**函数体内的 `None` 分支**一次性拒绝（`recovery.rs:389-412`），使全部调用点自动收敛；另注意 `RecoveryManager::cleanup()`（`:326-335`）与其 `WriterCheckpoint::finalize()`（`:663-666`）会经 `checkpoint.delete()` 触碰同一 Footer | 遗漏约束 |
| W24 | `checkpoint.delete()` 的行写副作用 | §3.4 阶段 2 写“先行 `checkpoint_manager.delete()` 清除检查点（此时 `delete()` 已去职责化，仅就地清位、绝不改长度）”；§3.4“唯一写路径”又以**将来时**要求删除 `file_len - 128` 推导 | **技术债（两处表述互相矛盾，必须先落实现再排顺序）**：`checkpoint.rs:402-469` 当前实现是 `primary_offset = file_len - FOOTER_SIZE`（`:418`）→ 读回 → `Footer::builder(...)` 重组（`:439-456`，**无 `.manifest(...)`**）→ 写回 `primary_offset`（`:460-462`）与偏移 4096（`:463-465`）。因此若在 `set_len(committed_end)` **之后**调用，会 (a) 在 `committed_end-128` 落 Footer、覆盖最后 128B 已提交数据，(b) 把 `manifest_offset` 静默清零（`has_manifest()` 随即为假，叠加 D1 后归档变为不可读）。**实现顺序硬约束**：FIX-05 阶段 2 必须**先**完成 `delete()` 的“仅就地清位、绝不改长度、保留 `manifest_*`/`backup_catalog_*`/`index_*`”改造（§3.4“唯一写路径”），**再**启用截断事务；§4.4 #6 的红测试即门禁，两者必须同 PR | 技术债 |
| W25 | `backward compat` 命中口径 | W8 写“**26 行 / 8 文件 / 5 crate**，26 行**全部**是注释”；§5.4 无效判据写“26 行 / 8 文件 / 5 crate，**全部**是注释” | `grep -rn 'backward compat' crates/*/src bins/*/src` = **25 行 / 9 文件 / 5 crate**（`era-crypto`、`era-engine`、`era-index`、`era-ingest`、`era-packing` 各至少 1 处）。且 `crates/era-engine/src/reader.rs:1123` 是**可执行语句**（`debug!("No manifest found in any volume (backward compat v8.1)")`），**不是注释**。正确表述：25 行中 **24 行为注释、1 行为日志文案**，**零处可执行兼容分支**；该判据既误伤注释又无法发现真实兼容分支（真实分支须靠行为测试证明移除） | 数字漂移 + 性质错误 |
| W26 | `BlockHeader::SIZE` 计数 | §3.9 D3 依据 2 写“`grep -rn 'BlockHeader::SIZE'` 实测 **68 处**” | 成立但**谓词必须限定 src**：`grep -rn 'BlockHeader::SIZE' crates/*/src bins/*/src` = **68**；不限定的 `crates`（含 `tests/`、`benches/`）为 **82**。§3.9 D3 与 §5.4 引用时必须写明 `crates/*/src bins/*/src`，否则同一命题会得到两个数 | 判据能力边界 |
| W27 | `scan_for_typed_blocks` 命中面 | §5.4 计数注释写“实测 10（定义 1 + 生产调用 5 + 注释 4）”；W1 亦把 4 处测试调用计入“生产” | 总数 **10** 成立，但**生产调用为 3 处**：`era-index/src/reader.rs:462`（`IndexManifest`）、`:493`（`IndexPage`）、`:897`（`IndexPage`）；`era-engine/src/writer.rs:3076/3080/3197/3201` 位于 `#[cfg(test)] mod tests`（`:2491-3225`）内，**属测试代码**，上一版将其中的 4 处误计为生产、并漏计 `era-index` 的 `:493`/`:897`。正确表述：定义 1 + 生产 3（全部在 `era-index` 冷恢复）+ 测试 4（`writer.rs`）+ 注释 2；`scan_for_typed_blocks(BlockType::Catalog)` 的生产调用仍为 **0**（判据 12 不受影响） | 数字漂移 + 性质错误 |

### 1.3 复核确认为真、后续不得再“纠偏”的锚点

> 本节为**冻结锚点**。凡与本节冲突的后续引述一律以本节为准；跨 commit 引用必须重跑 `sed -n '<N>p'` 复验。

**物理布局与卷格式**

- `HEADER_SIZE = 4096`（`crates/era-volume/src/header.rs:27`）、`DATA_REGION_START = 4224`（`header.rs:34`）、`FOOTER_SIZE = 128`（`crates/era-volume/src/footer.rs:16`）、`BACKUP_FOOTER_GAP = 128`（`footer.rs:20`）、`FOOTER_VERSION = 1`（`footer.rs:23`）、`FOOTER_DOMAIN = b"ERAFv1-footer\0"`（`footer.rs:13`，私有）。`HEADER_VERSION = 3`（`header.rs:24`），`MAGIC` 为 `ERA\x08\x02\0\0\0`（`header.rs:21`）。
- Footer 128B 字段偏移（`footer.rs:36-58` 文档表与 `:96-100` 结构体、`to_bytes`/`read_fields_from` 逐字节一致）：0..4 magic、4 version、5 reserved1、6..8 flags、8..16 data_end_offset、16..20 block_count、20..24 reserved2、24..32 sequence_number、32..40 catalog_offset、40..44 catalog_size、44..48 catalog_block_id、48..56 last_checkpoint_offset、56..60 last_checkpoint_block_id、60..64 manifest_block_id、64..72 index_offset、72..76 index_size、76..80 index_block_id、80..88 backup_header_offset、88..96 manifest_offset、96..128 checksum(Blake3)。
- 版本/标志/区间校验：`footer.version == 0 || footer.version > FOOTER_VERSION`（`footer.rs:396`）；`if footer.flags != 0`（`footer.rs:405-409`）；`validate_offset_above_header` 对 `catalog_offset`(`:435`)/`index_offset`(`:436`)/`last_checkpoint_offset`(`:437-440`)/`backup_header_offset`(`:441`)/`manifest_offset`(`:442`) **五处**调用；`validate_region_bounds` 定义 `footer.rs:476`，对 `catalog`(`:446-451`)、`index`(`:454-459`) 各调用一次，manifest 走单独的上界检查（`:462-471`）。
- `VolumeReader::open` 在 `crates/era-volume/src/reader.rs:57` 直接 `Self::try_read_header(&reader, 0).await?`；`:35-41` 文档化的五步恢复链中，**第 2/3 步（凭 Backup Footer 定位 Backup SuperHeader）从未实现**——全文件无任何读取 Backup SuperHeader 的路径。Footer 恢复只有两处确定性来源：`size - FOOTER_SIZE`（`:64`）与偏移 4096（`:71`）。
- `data_region()` 在 `reader.rs:357-365`（`start = DATA_REGION_START`，`end = footer.data_end_offset()` 或 `reader.size()`）；`read_raw(offset, len)` 在 `reader.rs:240`，函数体仅一行 `self.reader.read_at(offset, len).await`（`:241`），**无上限校验**；`read_block`（`:230`）委托 `read_typed_block`（`:383`），后者在 `:396-405` 按 `MAX_SHARD_SIZE` 校验；`read_erasure_shards`（`:256`）在 `:307-322` 亦校验（该路径不经过 `read_raw`）。故 `MAX_SHARD_SIZE` 的读侧校验点共 **4 处**：`:396`（typed block）、`:486`（扫描）、`:549`（shard），以及 `:307`（erasure shards）。**唯一无校验的公开读取入口是 `read_raw`**，这正是 FIX-03 的靶点。
- 卷尾截断校验在 `reader.rs:91-98`（`data_end_offset > size` → `CorruptedFooter`，紧随其后 `:100-110` 还有 `data_end_offset < DATA_REGION_START` 的 V30-03 校验）；浮动扫描 `try_floating_footer_recovery` 定义于 `reader.rs:144-204`，唯一调用点 `reader.rs:80`，窗口常量 `FLOATING_FOOTER_SCAN_SIZE = 1MB`（`reader.rs:20`）；`64 * 1024` 是无关的 `MAX_CONSECUTIVE_SCAN_MISSES`（`era-volume/src/lib.rs:24`）。`scan_for_typed_blocks` 定义于 `reader.rs:450`。
- `MAX_SHARD_SIZE = 16 * 1024 * 1024` 唯一定义于 `crates/era-volume/src/lib.rs:16`；`era-common` 无该常量（`crates/era-common/src/types/block.rs:10` 仅有 `DEFAULT_MACRO_BLOCK_SIZE = 4MB`）。
- Footer 偏移 80 与偏移 8 恒等：`era-volume/src/writer.rs:629`（`backup_header_offset = self.position`）→ `:652`（`data_end_offset = backup_header_offset`）→ `:673`（Primary Footer = `backup_header_offset + HEADER_SIZE`）；备用路径 `:340/354/358` 同。故 FIX-04 复用该字段承载 `backup_catalog_offset` 不丢信息。

**引擎侧边界与状态**

- 引擎侧 256MB 字面量共 **3 处**：`crates/era-engine/src/block_iter.rs:68`（`u32`）、`crates/era-engine/src/reader.rs:49`（`u64`）、`crates/era-engine/src/repair.rs:35`（`u64`）；全仓 `256 * 1024 * 1024` 字面量共 **4 处**（第 4 处是 `crates/era-codec/src/compression.rs:8` 的 `MAX_DECOMPRESSED_SIZE`）。
- 独立边界全景（四重，语义互不相同，禁止互相 `pub use` 冒充）：① `MAX_SHARD_SIZE = 16MB`（`era-volume/src/lib.rs:16`，L1 权威，写读对称——写端在 `era-volume/src/writer.rs:453`（块）与 `:530`（raw）校验，`volume_pool.rs:576-583` 另按全局上限校验，读端在 `reader.rs:307`/`:396`/`:486`/`:549` 校验）；② `MAX_DESERIALIZE_SIZE = 16MB`（`crates/era-common/src/serde.rs:9`）；③ `MAX_DECOMPRESSED_SIZE = 256MB`（`crates/era-codec/src/compression.rs:8`，绝对拦截在 `:66` Zstd 循环内与 `:141` LZ4 `declared_size` 预检）；④ `MAX_EXTRACTION_MEMORY = 8GB`（`crates/era-engine/src/reader.rs:47`）。另有 `MAX_BLOCK_SIZE = 64MB`（`block_iter.rs:67`，`:254`/`:836`/`:1030` 三处拦截 block 尺寸）与 `MAX_DECLARED_FILE_SIZE = 100GB`（`reader.rs:44`）。
- `MAX_EXTRACTION_MEMORY` 统计**累计落盘字节**（`cumulative_bytes_extracted`，`reader.rs:1479` 初始化、`:1683` 累加、`:1699` 拦截），并非峰值内存。移除理由应表述为“错误绑定到磁盘 I/O 总量、且与 L2 单块防御正交”。
- `ExtractOptions` 仅 `output_dir`/`overwrite`（`reader.rs:51-58`，结构体 `:53-58`）。`ExtractStats` 四字段（`chunk_processor.rs:257-266`）：`extracted`/`skipped`/`bytes_written`/`extracted_paths`。`VerifyStats`（`chunk_processor.rs:399-416`）含 `errors`/`warnings`/`archive_health`。
- `ExtractionContext`（`chunk_processor.rs:39`）含 `multi_chunk_files`（`:43`）、`set_canonical_output_dir`（`:65`）、`has_pending()`（`:77-81`）、`process_chunks`（`:90`）、`enforce_output_containment`（`:192-246`，`Symlink escape detected` 在 `:223`/`:233`）；**无** `created_directories`。
- `MultiChunkState` 在 `reader.rs:20-31`，`total_chunks` 在 `:32`。
- `block_iter.rs` 迭代器 `read_raw` 错误降级：`:1422-1432`（shard prefix 读取）与 `:1449-1459`（ShardHeader 读取）的 `Err(_) => { self.current_offsets[idx] = self.data_ends[idx]; continue; }`。**迭代器不会因卷尾截断崩溃**，RS 重构路径已被走到。
- **读端第二处“无 Manifest 放行”（R40 新增，D1 的必改项）**：`block_iter.rs:71-79` 的 `check_commit_horizon_for_sequence` 在 `committed_ends == None` 时 `return Ok(())`（`:77-79`）；其输入即 `ArchiveReader::committed_ends_for_iterators()`（`reader.rs:503-504`）返回的 `volume_committed_ends.clone()`，注入路径为 `reader.rs:698`/`:710`（`live_data_block_ids_from_hashes_via_iterator`）、`:2041`/`:2053`（`extract`）、`:2105`/`:2117`（`verify`）。与 `reader.rs:1234-1236` 构成**两处**同源放行，禁止只改其一（W22）。
- 分片读取错误的既有计数：`DecodedBlock::corrupted_shards: usize`（`block_iter.rs:38`）、`BlockIterStats::corrupted_shards: u32`（`:49`），累加于 `:586`/`:1487`/`:1554`/`:1726`；`reader.rs:1969` 把它汇入 `VerifyStats::warnings`。FIX-06 的新统计必须**聚合**该字段。
- 精确诊断缺口：截断与介质损坏不可区分，最终只报泛化的 `Not enough shards for recovery`（`reader.rs:1742-1750`）。
- `check_read_bound`（`reader.rs:1231-1269`）：`volume_committed_ends == None` → `return Ok(())`（`:1234-1236`，读端对无 Manifest 归档完全放行）；`Some(empty)` → `InvalidFormat` 失败关闭；溢出/越界 → `InvalidFormat`/`IntegrityError`。

**`checkpoint.rs` 与 `recovery.rs`**

- `checkpoint.rs::delete()` 在 `:402-469`：`primary_offset = file_len - FOOTER_SIZE`（`:418`，**行为随文件长度变化**）；`:428-437` 在 Primary Footer 解析失败时回退读偏移 4096 的 Backup Footer；`Footer::builder` 链 `:439-456` 只设 `catalog(0,0)`/`index`/`backup_header`，**无 `.manifest(...)`**；写回 Primary `:460-462`、Backup（偏移 4096）`:463-465`；`fetch`/`commit`/`sync`/`save` DEPRECATED 于 `:487-489`、`:504-507`、`:591-593`。
- `recovery.rs`：`truncate_to_checkpoint` 在 `:344`、`truncate_to_checkpoint_with_manifest` 在 `:348-351`；`data_end = reader.footer().map(|f| f.data_end_offset()).unwrap_or(0)` 在 `:383`；`if footer.has_manifest()` 在 `:393`；`// Skip for archives without manifest (backward compat).` 在 `:391`；`manifest.volume_committed_ends` 在 `:414`；`truncate_file_with_cancel_flag` 于 `:435`；`spawn_blocking` 于 `:453`；`RecoveryManager`（`pub struct` `:165`、`impl` `:173`、`analyze` `:179`、`new` `:247`）**没有** `discover_volumes`/`volume_path`。
- CLI `repair --force` 流程 `bins/era-cli/src/commands.rs:1236-1260`：`:1249-1254` 显式二分支（有 Manifest → `truncate_to_checkpoint_with_manifest(Some(..))`；无 Manifest → `truncate_to_checkpoint()`），`:1260` `manager.cleanup()`。`-p secret` 示例在 `main.rs:65/69/172/211/246/278/357/358`（另有 `main.rs:9` 的 crate 级 `//!` 示例，clap 不渲染该注释）。

**Catalog 双写现状（FIX-04 的基线）**

- 写端（多卷/纠删码路径）：`writer.rs:2114-2270`。`backup_block_ids` 仅在 `self.pipeline.erasure_enabled()` 为真时分配（`:2149-2156`），主块 ID 与备份块 ID 均为 `reserve_block_id()` 顺序取值（主 `[C..C+K-1]`、备 `[C+K..C+2K-1]`；`precheck_and_rotate_if_needed` 触发轮转后 `build_catalog_block_sets` 会**重跑**，但因计数器未推进，重新分配得到同一组 ID，故分配律仍成立）。
- 写端（`GenericArchiveWriter` 路径）：`writer.rs:3517-3550`，**单块、无备份**，`finalize_with_catalog(..., 0, 0, 0)` 清零 checkpoint 三元组。
- 落盘点：`crates/era-engine/src/volume_stage.rs:151-209`（单块）、`:211-269`（块集）、`:275-351`（按卷重绑定的块集）；三者的 `backup_*` 位置一律 `let _backup_location = ...` **丢弃**。
- 读端：`load_catalog`（`reader.rs:863-966`）遍历**各卷的** `footer.catalog_offset()/catalog_size()/catalog_block_id()`（`:890-895`），**只读主 Catalog**；单卷场景候选数为 1，失败即 `Err(last_error)`。`assemble_catalog_data`（`:1129-1224`）用算术紧邻偏移推进：`next_offset = catalog_offset + bh_size + catalog_size`（`:1151`）→ `next_offset += bh_size + header.length`（`:1206`），块 ID 用 `catalog_block_id + block_num`（`:1185`）；`chunk_count`/`total_len` 取自首块前 12 字节（`:1140-1145`）。
- `catalog_commitment` 只覆盖主 Catalog 明文（`writer.rs::build_manifest`(`:1320` 起) → `compute_catalog_commitment(catalog_bytes)`(`:1327`，定义于 `:2943`)）；`ArchiveManifest` 无备份指针字段（`crates/era-common/src/types/manifest.rs:18-47`）。

**路径派生（FIX-05 的 6 处缺陷 + 1 处蓝本）**

- `crates/era-volume/src/lib.rs:70-77` 的 `volume_path`：`:72` `base_path.with_extension("era")`、`:75` `base_path.with_extension(ext)`（`ext` 经变量间接传入，文本判据覆盖不到）。
- `crates/era-volume/src/multi_volume.rs:311` `first_volume_path.with_extension("")`，`:313` 调 `volume_path`；`MAX_VOLUME_SCAN = 1000` 为 `:22` **私有**且**仅 `:312` 一处使用**（`grep -n MAX_VOLUME_SCAN` 全仓仅 `:22`/`:312` 两行，后者为唯一使用点）。
- `crates/era-engine/src/writer.rs:1567-1581` `collect_own_volume_paths`：`:1571` `with_extension("")`、`:1573` `with_extension(format!("era.{:03}", seq))`。
- `bins/era-cli/src/commands.rs:452-467` `collect_archive_volume_paths`（被 `:666` 调用）：`:456`/`:458` 同型缺陷；`:1811`（卷计数展开）、`:1847`（missing-volume 卷名）为 CLI 卷名推导缺陷。
- 蓝本：`crates/era-engine/src/reader.rs:175-326` `ArchiveReader::discover_volumes`——基准名推导在 `:204-215`（`.era` 感知、纯追加，**已正确**）；`scan_tolerance` 在 `:189-194`（`(parity_shards + 1).max(2)`）；局部 `const MAX_SCAN: usize = 32` 在 `:197`；存在性判断 `try_exists` 在 `:242`；候选卷 `VolumeReader::open` 在 `:247-257`；**不读** `volume_committed_ends`；`discover_volumes` 调用点 `:334`/`:429`。
- 无关命名（不得纳入判据）：`crates/era-engine/src/repair.rs:380` 与 `:986-990` 的 `.era.bak` 备份命名。

**其他**

- `BlockHeader` 有未用字段 `reserved2: [u8; 4]`（`crates/era-common/src/types/block.rs:526`，序列化 `:556`，`SIZE = 16` 在 `:531`）。
- AEAD 依赖 `block.block_id` 派生子密钥与 AAD（`crates/era-packing/src/session_builder.rs:272-286`）。
- `EraError`（`crates/era-common/src/error.rs:12`）实测 **50** 个变体，无 `#[non_exhaustive]`，无 `TruncatedShard`；`Security` 变体 `:143`；构造助手 `compression` `:226`、`decompression` `:231`。**全仓不存在对 `EraError` 的穷尽 `match`**（仅 `repair.rs` 测试内 `Err(EraError::Io(error)) => ...` 的 `let-else`/单臂匹配），故新增变体的编译影响面为零。
- `era-cli` 依赖边：`bins/era-cli/Cargo.toml` 直接依赖 `era-{common,crypto,engine}`（`:14-16`），另有 `walkdir`（`:23`）；**无** `era-ingest`。`[dev-dependencies]`（`:30` 起）含 `filetime = "0.2"`（`:37`）、`xattr = "1"`（`:38`）、`era-volume`（`:36`）。`era-engine/src/lib.rs` 无 `pub use era_ingest`。`filetime` 在**生产源码中零引用**；`xattr` 是 `era-engine` 正式依赖（`writer.rs:1632`、`reader.rs:1816`）。
- `era_ingest::{DirectoryScanner, ScanOptions}` 导出在 `crates/era-ingest/src/lib.rs:28`；`ScanOptions` 在 `crates/era-ingest/src/reader.rs:21-32`（`root`/`include_patterns`/`exclude_patterns`/`extract_xattrs`/`extract_acls`）；`scan()` 在 `:81-87` 调用 `WalkBuilder::standard_filters(true)` + `.add_custom_ignore_filename(".gitignore"/".ignore"/".eraignore")`；`ignore` 固定在 `crates/era-ingest/Cargo.toml:14` = `0.4.25`。
- `writer.rs`：总行 **3649**（`wc -l`）；根测试 `#[cfg(test)]` `2491`–`3225`、`generic::tests` `3571`–`3648` → 测试 **813** 行、生产 **2836** 行；`collect_files_async` 定义 `:1281`（`:1304` 是注释 `// Symlinks and special files are skipped`），现役调用点 `:1301`（递归）与 `:1550`；`ArchiveWriterBuilder` `pub struct` `:141`/`impl` `:175`/`new` `:177`；`ArchiveWriter` `pub struct` `:1242-1277`/`impl` `:1310`；自由函数 `is_internal_path` `:2474`、`ArchiveStats` `:2480`；**公开 API 10 项**（逐行复核，见 W9）：`builder`(1312)、`archive_id`(1511)、`key_encapsulation`(1522)、`is_certificate_mode`(1527)、`add_path`(1536)、`add_file_with_path`(1585)、`add_file`(1693)、`add_files`(1736)、`add_bytes`(2033)、`finalize`(2082)。**`add_file_single`(1760) 为私有**；仓内不存在 `add_path_recursive`/`add_directory_contents`/`add_directory`/`add_file_with_stored_path`。
- `rust-toolchain.toml` = `channel = "1.98.1"` + `components = ["rustfmt", "clippy"]`；`.github/workflows/ci.yml:36/74/107` 用 `dtolnay/rust-toolchain@stable`（首处带 `components: rustfmt, clippy`）；根 `Cargo.toml` `[workspace.package]`（`:17-24`）无 `rust-version`；`Cargo.toml:3` `exclude = ["fuzz"]`，`fuzz/` 不存在；`.github/workflows/fuzz.yml` 仅 `workflow_dispatch` 且首行有 NOTE；`FOOTER_VERSION` 的外部引用仅测试（`adversarial_audit_v26.rs:97/229`、`property_tests.rs:187/225`）与 re-export（`era-volume/src/lib.rs:46`），**均为 `assert_eq!(footer.version(), FOOTER_VERSION)` 形式**，随常量升到 2 自动跟随。
- `crates/era-volume/tests/security_dos_tests.rs` 已存在 5 个用例（含 `test_max_shard_size_constant`，`:274-280`），**没有** `test_read_raw_rejects_oversized_allocation`——新用例落于该文件。
- 待删除/改写资产的既有依赖：`floating_footer.rs:7`（`test_floating_footer_recovery`）、`competitor_vulnerability_audit.rs:235`（`vuln_floating_footer_scan_false_positive`）、`resilient_footer_reconstruction.rs:149`（注释“prevent floating footer recovery”）；`adversarial_audit_v2.rs:54-56`（文本断言 `source.contains("const MAX_SHARD_SIZE")`，L0 上移后**天然通过**）与 `:270-277`（`spawn_blocking` AST 断言）；`adversarial_audit_v3.rs:3-19`（`:7` 断言 `const MAX_SHARD_SIZE: u64 = 256 * 1024 * 1024;`）。
- 机械判据实测（判据用）：`256 * 1024 * 1024` 全仓 src = **4**；`with_extension("")` 限定 `era-volume/src`+`bins/era-cli/src` = **2**，加 `era-engine/src` = **3**，再加 `repair.rs` 的 `.era.bak` 变体 = **4**；`with_extension('with_extension(format!("era')` = **4**（`writer.rs:1573`、`commands.rs:458/1811/1847`）；`with_extension` 于 `era-volume/src/lib.rs` = **2**（`:72`/`:75`）；`try_floating_footer_recovery` 于 `crates bins` = **2**；`MAX_SHARD_SIZE` 绑定 256MB = **3**；`const MAX_SCAN: usize = 32` = **1**；`repair.rs` 内 `as u64 > MAX_SHARD_SIZE` = **5**；`backward compat` 于 `crates/*/src bins/*/src` = **25 行 / 9 文件 / 5 crate**（24 行注释 + 1 行 `debug!` 日志，零可执行兼容分支，见 W25）；`BlockHeader::SIZE` 于 `crates/*/src bins/*/src` = **68**（不限目录为 82，见 W26）。

---

## 二、 缺陷核查与整改任务映射

### 2.1 映射表

| 审计编号 | 严重度 | 缺陷主题 | 根本原因 | 整改任务 | 核心锚点 |
| :--- | :---: | :--- | :--- | :---: | :--- |
| **SEC-CRIT-01** | **Critical** | 累计落盘字节超 8GB 误杀 + 自毁清盘 | 预算绑定全生命周期 I/O 总量；`tracked_output_files` 含已成功文件，失败即全删 | **FIX-01 / FIX-02** | `crates/era-engine/src/reader.rs:47`、`crates/era-codec/src/compression.rs:8` |
| **DATA-CRIT-02** | **Critical** | 单卷 Catalog 无副本/无纠删（SPOF） | 单卷单块裸写且 `repair` 扫描排除；备份 Catalog 块已写出但**其块 ID 从未持久化**，Footer 亦无结构化 Backup 指针 | **FIX-04** | `crates/era-engine/src/writer.rs:3533`、`crates/era-engine/src/volume_stage.rs:151-209`、`crates/era-engine/src/repair.rs:401`、`crates/era-engine/src/reader.rs:863-966` |
| **DATA-HIGH-01** | **High** | 连续 16 坏块触发全量清理（无 salvage） | 缺 salvage 模式；失败路径无差别物理删除 | **FIX-02** | `crates/era-engine/src/reader.rs:1655`、`:1705-1720` |
| **CONS-HIGH-02** | **High** | `repair --force` 截断致多卷矩阵撕裂 | `RecoveryManager` 无多卷扫描与协同截断 | **FIX-05** | `crates/era-engine/src/recovery.rs:344-435`、`bins/era-cli/src/commands.rs:1236-1260` |
| **SEC-HIGH-03** | **High** | 前缀平局降级致有界内存/IO 放大 DoS | 平局返回 `None` → `parity_bound` 丢失 → 回落信任 256MB 声明长度 | **FIX-03** | `crates/era-engine/src/erasure_scan.rs:11-45`、`crates/era-engine/src/block_iter.rs:1472-1504` |
| **DATA-HIGH-04** | **High** | 卷尾截断拒绝进入解包恢复 | `VolumeReader::open` 硬校验拒绝打开，且无软裁决通道 | **FIX-06** | `crates/era-volume/src/reader.rs:57`、`:91-98` |
| **CODE-HIGH-05** | **High** | `writer.rs` 3649 行职责高密度耦合 | 构建装配 / 元数据终结 / 管线驱动混居单文件 | **FIX-09** | `crates/era-engine/src/writer.rs` |
| **SPEC-MED-01** | **Medium** | 空目录/软链接/0 字节文件丢失 | CLI 绕过 `DirectoryScanner`；写端跳过非普通文件；解包端提前退出 + 类型过滤 | **FIX-07** | `bins/era-cli/src/commands.rs:672-690`、`crates/era-engine/src/writer.rs:1304`、`crates/era-engine/src/reader.rs:1650` |
| **SPEC-MED-02** | **Medium** | `repair` 拒绝修复丢失卷但无指引 | 错误文案未提供 `extract` 恢复路径 | **FIX-08a** | `bins/era-cli/src/commands.rs:1139-1147` |
| **SEC-MED-03** | **Medium** | 存储层 16MB 与引擎层 256MB 边界冲突 | 常量跨 crate 重复定义且数值不一致；`read_raw` 无校验 | **FIX-03** | `crates/era-volume/src/lib.rs:16`、`crates/era-volume/src/reader.rs:240`、`crates/era-engine/src/block_iter.rs:68` |
| **SEC-MED-04** | **Medium** | CLI 帮助示例明文密码误导 | 示例硬编码 `-p secret` | **FIX-08b** | `bins/era-cli/src/main.rs:65` |
| **TEST-MED-05** | **Medium** | Fuzz 设施缺失（幽灵工作流已解决） | `Cargo.toml` 排除 `fuzz/`，工作流仅手动触发 | **FIX-08c（无需整改）** | `Cargo.toml:3`、`.github/workflows/fuzz.yml` |
| **CONF-LOW-03** | **Low** | 工具链版本未声明单一来源 | 已固定 1.98.1，但 `workspace.package` 无 `rust-version`，CI 通道未显式对齐 | **FIX-08d** | `rust-toolchain.toml:2`、`.github/workflows/ci.yml:36` |
| **SEC-LOW-01** | **Low** | coredump 禁用缺回归门禁 | 生产已实现（`main.rs:501`），缺 CLI 自动化守护 | **FIX-08e** | `bins/era-cli/src/main.rs:501`、`crates/era-crypto/src/secure_memory.rs:334-367` |
| **OPS-INFO-01** | **Info** | 路径扁平化/小文件开销/纠删上限等固有特性 | 架构固有约束，需文档化 | **FIX-08f** | CLI 手册与帮助文本 |
| **SPEC-LOW-02** | **Low / Info** | 门限模式禁 Append 与重复凭证拦截 | 审计判定**已证实且符合规范** | **无需整改** | `crates/era-engine/src/writer.rs:474-481`、`bins/era-cli/src/commands.rs:254-272` |

> **追溯口径**：审计报告的原始条目为 **18 项**，去重合并后为 **16 个唯一问题 ID**（Critical 2 / High 5 / Medium 5 / Low-Info 4）；本方案以 9 个 FIX 覆盖 **15 个待修问题** + 1 项保持现状（`SPEC-LOW-02`）。**不得再以“18 项”作为工作量或验收口径**，也不得把 `SPEC-LOW-02` 计入待修。

### 2.2 既有测试与文档资产同步清单（任何 FIX 不得绕过）

| # | 资产 | 随哪项 FIX | 处置 |
| :-- | :--- | :---: | :--- |
| 1 | `crates/era-volume/tests/floating_footer.rs`（`test_floating_footer_recovery`，`:7`） | FIX-06 | 删除文件；同步 `crates/era-volume/tests/AGENTS.md:10` 分组与计数（该行 `floating_footer.rs 81` 需一并移除） |
| 2 | `crates/era-volume/tests/competitor_vulnerability_audit.rs:235`（`vuln_floating_footer_scan_false_positive`） | FIX-06 | 语义反转为“浮动扫描路径已不存在” |
| 3 | `crates/era-volume/tests/resilient_footer_reconstruction.rs:149` 相关构造与注释 | FIX-06 | 移除“防浮动恢复”的构造前提，断言双确定性 Footer 均损毁即不可恢复 |
| 4 | `crates/era-engine/tests/adversarial_audit_v2.rs:54-56`（`source.contains("const MAX_SHARD_SIZE")`） | FIX-03 | 天然通过（仍保留 `const MAX_SHARD_SIZE`），确认即可 |
| 5 | `crates/era-engine/tests/adversarial_audit_v2.rs:270-277`（`truncate_to_checkpoint` + `spawn_blocking` AST 断言） | FIX-05 | 保留门面签名与 `spawn_blocking`，禁止删除 |
| 6 | `crates/era-engine/tests/adversarial_audit_v3.rs:3-19`（256MB 文本断言 + 守卫计数） | FIX-03 | 文本断言改为引用 L0 常量；守卫计数维持（实测当前 5 次） |
| 7 | `crates/era-volume/tests/adversarial_audit_v27.rs:197`、`crates/era-volume/tests/security_dos_tests.rs:274-280` | FIX-03 | 无需改动（绑定 L1 常量，当前即 16MB） |
| 8 | `bins/era-cli/src/commands.rs:2178`（断言旧文案 `missing expected volume files`） | FIX-08a | 与新文案一并改写 |
| 9 | `crates/era-engine/tests/self_inclusion_test.rs:72`（`test_add_path_excludes_volume_files_from_input_directory`） | FIX-05 | 扩展多点号用例（现仅覆盖单点号） |
| 10 | 文档：`crates/era-volume/src/AGENTS.md:30`、根 `AGENTS.md:45` | FIX-03 / 变体评估 | 数值与措辞同步（`~49` → 50；“all length fields validated”与引擎 256MB 的冲突随 FIX-03 消解） |
| 11 | `ExtractStats`（`chunk_processor.rs:257-266`） | FIX-01 / FIX-06 | 新增 `failed_files` 与 `corrupted_shards`（后者定义为**聚合** `DecodedBlock::corrupted_shards`，不新造计数源，见 §4.5 #6） |
| 12 | `crates/era-volume/tests/adversarial_audit_v26.rs:97/229`、`crates/era-volume/tests/property_tests.rs:187/225` | FIX-04 | 无需改动（已用 `assert_eq!(footer.version(), FOOTER_VERSION)`，随常量升 2 自动跟随）；**禁止**硬编码 `version == 1` |
| 13 | `bins/era-cli/Cargo.toml:37`（`filetime` 位于 `[dev-dependencies]`） | FIX-07 | **R39/D2 终裁 + R41 事实修正：提升 `filetime = "0.2"` 为 `crates/era-engine/Cargo.toml` 常规依赖**，用 `filetime::set_symlink_file_times`；**登记时必须如实写明其传递依赖为 `cfg-if` + `libc` + `libredox`（`Cargo.lock` 锁 `0.2.27`，会把 `libc` 带进 `era-engine` 依赖图），理由只能是“不在 L4 写 `unsafe`/FFI”，不得写成“依赖链无 unsafe”**；并在 `crates/AGENTS.md` 依赖图登记（不采用 `libc::utimensat`，见 §3.9 D2） |
| 14 | §3.8 的 `ArchiveWriter` 公开面 | FIX-09 | 冻结面为 **10 项**（W9：R35/R36 的 10 项正确，R37 草稿的“14 项”已撤销）；FIX-07 新增的两项接口是第 11/12 项，属**新增**而非既有面 |

---

## 三、 详细技术整改方案设计

### 3.1 FIX-01 & FIX-02：解压炸弹防御分层下沉与非破坏性抢救清理

1. **下线 L4 的累计字节预算**
   - 删除 `const MAX_EXTRACTION_MEMORY`（`reader.rs:47`）、其累加（`:1683`）与拦截（`:1699`）及触发的自毁清理。该计数器统计**累计落盘字节**，与“内存预算”名不符实。
   - 磁盘耗尽改由两条正交防线处理：L4 声明体积校验（第 3 条）；可选全局配额 `ExtractOptions::max_total_bytes: Option<u64>`（默认 `None`，仅显式指定时生效）+ CLI `--max-extraction-bytes <BYTES>`。
2. **单块膨胀防御下沉至 L2 `era-codec`**（唯一权威实现点）
   - `MAX_DECOMPRESSED_SIZE`：`256MB` → **`16MB`**（`compression.rs:8`）。它是**解压产物上限**，与分片上限、反序列化上限、block 上限是四个独立安全边界，**禁止互相 `pub use`**。
   - 新增常量 `MAX_SAFE_DECOMPRESSION_RATIO: usize = 100`、`MIN_RATIO_CHECK_OUTPUT_BYTES: usize = 1024 * 1024`。1MB 敏感线取代历史 `16MB` 门槛——后者与绝对上限重叠构成**不可达死条件**，并放过“100 字节 → 10MB”。
   - Zstd 流式循环（`compression.rs:54-75`）在**每次迭代后**判定：
     ```rust
     let current_total = output.len() + n;
     if current_total > MIN_RATIO_CHECK_OUTPUT_BYTES && compressed_payload_len > 0 {
         let ratio = current_total / compressed_payload_len;
         if ratio > MAX_SAFE_DECOMPRESSION_RATIO {
             return Err(EraError::decompression(format!(
                 "Block decompression ratio {} exceeds safe limit ({}:1)",
                 ratio, MAX_SAFE_DECOMPRESSION_RATIO)));
         }
     }
     ```
   - LZ4 `O(1)` 零分配预检（`compression.rs:133-154`）：
     ```rust
     // data = [declared_size: u32 LE][payload]
     let payload_len = data.len().saturating_sub(4);
     if declared_size > MIN_RATIO_CHECK_OUTPUT_BYTES && payload_len > 0 {
         let ratio = declared_size / payload_len;
         if ratio > MAX_SAFE_DECOMPRESSION_RATIO {
             return Err(EraError::decompression(format!(
                 "LZ4 declared decompression ratio {} exceeds safe limit ({}:1)",
                 ratio, MAX_SAFE_DECOMPRESSION_RATIO)));
         }
     }
     ```
   - **分母语义硬约束（R34 裁决，禁止漂移）**：① 分母必须是**该块压缩载荷的实际字节数**（Zstd 取循环输入总长度，**不得**用 `data.len()`/`data.capacity()`）；② LZ4 分母 = `data.len() - 4`；③ 绝对上限判定必须早于任何 `Vec::with_capacity`/`resize`/大块分配；④ 比率判定必须**每次迭代后**执行。违反 ①② 时攻击者可用**零成本填充**抬高分母稀释真实膨胀比。
3. **L4 声明体积与空洞校验（磁盘维度）**
   - `ExtractionContext::process_chunks`（`chunk_processor.rs:90` 起）对正在落盘的多块文件用 `expected_size`（`MultiChunkState`，`:20-32`）累计：`written + chunk.len() > expected_size` 立即返回 `EraError::IntegrityError("File chunks exceed declared catalog size")`。
   - 文件完成时必须**同时**满足“字节总数 == `expected_size`”与“`chunks_written` 全为 true”，覆盖**磁盘耗尽**与**空洞注入**。
4. **分级安全清理（保护健康文件 + 句柄释放）**
   - `ExtractionContext` 三类状态：`completed_paths`（复用 `stats.extracted_paths`）、`multi_chunk_files`（`:43`）、`created_directories`（**需新增**，Phase 1 正序记录）。
   - 新增 `pub fn release_handles(&mut self)`：清空 `multi_chunk_files` 并**显式 drop** 全部 `File` 句柄（Windows 消除 `ERROR_SHARING_VIOLATION`，Linux 释放 inode 占用）。
   - `fail_extraction_with_cleanup`（`reader.rs:1877-1890`）重构为三步：① `release_handles()`（强制先行）；② 仅删 `multi_chunk_files` 中的未完成文件，**严禁删 `stats.extracted_paths`**；③ 对 `created_directories` 按深度逆序 `std::fs::remove_dir`（非空安全忽略）。
   - 彻底废除“失败即删除 `tracked_output_files` 全部路径”的逻辑（`crates/era-engine/src/reader.rs:1478` 收集、`:1554` 把**尚未落地的计划路径**一并压入，而 `cleanup_partial_files`（`:1850-1875`）只做 `remove_file`）。
5. **尽力抢救模式（Salvage）**
   - `ExtractOptions` 增加 `pub salvage_mode: bool`（CLI：`--salvage`）。为真时：单块失败或连续失败达 16 次**不触发**致命清理，改为告警并跳过；受影响未完成文件重命名为 `.corrupted` 或记入新增的 `ExtractStats::failed_files` 并从 `multi_chunk_files` 移除；继续消费剩余块。

**事实边界（防止误改）**：`ErasureCodedBlockIterator` 已把分片读取错误降级为缺失槽位并继续（`block_iter.rs:1422-1459`），**不需要**“新增崩溃修复”；“连续 16 次失败即清理”的门限本身合理（`reader.rs:1655`），缺陷在**清理范围**与**缺 salvage 通道**。

---

### 3.2 FIX-03：全局权威分片上限收敛与平局安全降级

1. **常量上移与类型化绑定（SSOT）**
   - `era-common/src/types/block.rs` 新增 `pub const MAX_SHARD_SIZE: usize = 16 * 1024 * 1024;`，并在 `era-common/src/lib.rs` `pub use types::block::MAX_SHARD_SIZE;`。
   - `crates/era-volume/src/lib.rs:16` 改为 `pub use era_common::MAX_SHARD_SIZE;`（**上移**，不是“既已在 L0”）。
   - 引擎三处按使用点选型绑定：`block_iter.rs:68` 用 `u32`（比较对象 `shard_header.length` 为 `u32`）；`reader.rs:49`、`repair.rs:35` 用 `u64`。
   - `era-codec` 的 `MAX_DECOMPRESSED_SIZE` 是**独立边界**，降为 16MB 但**不得**改为引用 `MAX_SHARD_SIZE`。
2. **`read_raw` 边界防御**（`crates/era-volume/src/reader.rs:240-242`）：
   ```rust
   if len > MAX_SHARD_SIZE {
       return Err(EraError::IntegrityError(format!(
           "read_raw requested length {} exceeds MAX_SHARD_SIZE ({})", len, MAX_SHARD_SIZE)));
   }
   ```
   `read_block`/`read_typed_block`（`:230`/`:383`，含 `:396-405` 的校验）与扫描路径的既有校验保持不变（写端 `era-volume` 已校验，保持对称）。
3. **前缀平局加固（收敛放大上界）**
   - `parse_stripe_lengths`（`erasure_scan.rs:3-9`）产出的每个长度必须满足 `len <= MAX_SHARD_SIZE as u32`，否则整个候选前缀判为伪造并剔除。
   - `reconcile_stripe_prefixes`（`erasure_scan.rs:11-45`，平局裁决块 `:34-42`）平局处理：先交叉仲裁（比对存活分片实际头部 CRC/长度，优先完全吻合的合法前缀）；仍无法判定才返回 `None`。
   - **收紧 `parity_bound` 缺口**：`parity_bound_from_lengths`（`:47-54`）返回 `None` 时的降级路径（`block_iter.rs:1472-1503`、`repair.rs:496-510`、`:1174-1194`）**强制** `parity_bound = MAX_SHARD_SIZE as u32`，禁止回落信任 `shard_header.length`。因果链：分片长度校验 + `parity_bound` 上界双保险，使 6 卷条带瞬时内存上界自当前的 `≤1.5GB`（6×256MB）收敛到 `96MB`（6×16MB）。
   - **上界论证的完整性（R37）**：上述 96MB 只约束**单个条带的分片缓冲**。读路径同时存在 `MAX_BLOCK_SIZE = 64MB`（`block_iter.rs:67`，`:254`/`:836`/`:1030` 三处拦截 block 尺寸）与 `MAX_DECOMPRESSED_SIZE`（FIX-01 后 16MB）两个正交上界。文档论述任一上界时必须声明其余两者仍在生效，**不得**把 96MB 表述为“整体内存上限”。
   - `parity_bound_from_lengths` 本身（基于 `max_stripe` 上取偶）正确，缺陷只在“无结论时缺少上界”（**不存在**“无上限分配”，引擎侧 256MB 守卫一直在生效）。

---

### 3.3 FIX-04：单卷 Catalog 镜像双写与 Footer v2 原生自愈

#### 1. 解除伪约束与 Footer v2 定义

**废除的历史技术债**：`next_offset = catalog_offset + BlockHeader::SIZE + catalog_size` 隐式算术紧邻偏移（真实存在于 `crates/era-engine/src/reader.rs:1151`，推进于 `:1206`），以及块 ID 的算术推断 `catalog_block_id + block_num`（`:1185`）。
**必须澄清（R37）**：既有实现**不存在 Catalog 的全卷冷扫描**——`scan_for_typed_blocks(BlockType::Catalog)` 在生产代码中零调用。但 `crates/era-index/src/reader.rs:462` **确实**在生产中调用 `scan_for_typed_blocks(BlockType::IndexManifest)` 作为 IndexManifest 冷恢复降级路径；该路径**属于**在役设计，FIX-04 不得宣称要删除它，也不得把“无冷扫描”表述为“全 API 无冷扫描”。FIX-04 的收益只是“消除**算术推断块 ID + 依赖 MAC 失败兜底**的脆弱耦合”。

**备份 Catalog 写入现状（R37 实测，决定本 FIX 的真实工作量）**

- 多卷+纠删码归档：`volume_stage.rs:151-209`/`:211-269`/`:275-351` 已把 `backup_block`/`backup_blocks` 紧随主块写入同一卷，但 `let _backup_location = ...` **丢弃位置**；`writer.rs:2149-2156` 分配的 `backup_block_ids` 从不写入 Footer/Manifest。→ **磁盘上已有备份，缺的是可寻址指针。**
- 单卷非纠删码归档：`erasure_enabled()` 为假 ⇒ `backup_block_ids = None` ⇒ 所有 `if let Some(backup)` 分支跳过 ⇒ **连不可寻址的备份都没有**。本 FIX 必须让该配置也双写。
- `GenericArchiveWriter::finalize`（`writer.rs:3533-3550`）：单块、无备份、`finalize_with_catalog(..., 0, 0, 0)`。**第二写端落点，必须同步覆盖。**

Footer v2（仍为 128B 单扇区原子写，`FOOTER_VERSION = 2`）：

| Offset | Size | Field | 说明 |
| --- | --- | --- | --- |
| 0 | 4 | magic (`ERAF`) | 不变 |
| 4 | 1 | version = 2 | **版本校验改为严格等于 2** |
| 5 | 1 | reserved1 | 0 |
| 6 | 2 | flags | `FLAG_HAS_BACKUP_CATALOG = 0x0001` |
| 8 | 8 | data_end_offset | 不变 |
| 16 | 4 | block_count | 不变 |
| 20 | 4 | **backup_catalog_block_id** | 原 `reserved2`；AEAD 解密必需 |
| 24 | 8 | sequence_number | 不变 |
| 32 | 8 | catalog_offset | 不变 |
| 40 | 4 | catalog_size | 不变（主备密文等长，无需备份尺寸） |
| 44 | 4 | catalog_block_id | 不变 |
| 48 | 8 | last_checkpoint_offset | 不变 |
| 56 | 4 | last_checkpoint_block_id | 不变 |
| 60 | 4 | manifest_block_id | 不变 |
| 64 | 8 | index_offset | 不变 |
| 72 | 4 | index_size | 不变 |
| 76 | 4 | index_block_id | 不变 |
| 80 | 8 | **backup_catalog_offset** | 复用 `backup_header_offset`（恒等于 `data_end_offset`，见 §1.3） |
| 88 | 8 | manifest_offset | 不变 |
| 96 | 32 | checksum (Blake3) | 使用 **`FOOTER_DOMAIN_V2`** |

**设计要点**

- **域隔离**：**新增** `const FOOTER_DOMAIN_V2: &[u8] = b"ERA-VOLUME-FOOTER-V2\0";`（R29）。**不得原地改写** `FOOTER_DOMAIN = b"ERAFv1-footer\0"`；v1 解析路径删除后旧常量整体删除。`FOOTER_VERSION = 2` 是唯一权威版本源（`footer.rs:23`），外部仅测试与 re-export 引用，见 §1.3。
- **版本严格性**：现有 `footer.version == 0 || footer.version > FOOTER_VERSION`（`footer.rs:396`）会让 `version == 1` 的旧字节流通过校验并按 v2 误解析（偏移 20/80 语义不同），必须改为**严格等于 2**（或显式拒绝 1）。因不接受兼容妥协，直接删除 v1 解析分支。
- **标志白名单**：`footer.rs:405` 现为 `if footer.flags != 0`，改为 `(footer.flags & !SUPPORTED_FLAGS) != 0`，`SUPPORTED_FLAGS = FLAG_HAS_BACKUP_CATALOG`。
- **主备非别名 + 区间互斥**（`Footer::from_bytes` 内，`has_backup_catalog()` 为真时）：
  1. `backup_catalog_offset != catalog_offset` 且**连续区间互斥**——新增 `validate_disjoint_regions(name_a, offset_a, size_a, name_b, offset_b, size_b)`，`checked_add` 防溢出，要求 `end_a <= offset_b || end_b <= offset_a`，违约 `CorruptedFooter("... physically overlap ...")`；
  2. `backup_catalog_block_id != catalog_block_id`，违约 `CorruptedFooter("... must differ ...")`；
  3. `validate_region_bounds("backup_catalog", backup_catalog_offset, catalog_size, data_end_offset)?`；
  4. `validate_offset_above_header("backup_catalog_offset", ...)` **保留**（与 `catalog_offset`/`index_offset` 等五处既有同类校验对齐，`footer.rs:435-442`）。**不得**以“原字段已废弃”为由删除该一行的结构下界校验。
  - **不得**在 Footer 层断言 `backup_catalog_block_id >= catalog_block_id + K`：128B Footer 无 `K` 字段（`K` 仅内嵌于 Catalog 首 4 字节，`crates/era-engine/src/reader.rs:1140`）。Footer 只保证**严格不等**；`== C + K` 由**写端**保证、**读端装配阶段**用块头 `chunk_count` 复核。
  - `validate_disjoint_regions(..., catalog_size, ...)` 只保证**首块区间**互斥；`K > 1` 的全区间互斥必须在装配阶段对全部块做累计校验（新增 `validate_contiguous_disjoint_block_span(primary_first, backup_first, chunk_count, max_chunk_bytes)`，要求主区间终点 `<=` 备区间起点）。**冻结表只承诺首块互斥文案，任何文档不得承诺“全 Catalog 区间互斥已由 Footer 保证”。**
- ~~**块头自描述（第二重防线）**：利用 `BlockHeader::reserved2` 持久化块 ID。~~ **R39/D3 已撤销该设计项**：字段宽 4B ≠ `BlockId(u64)`，加宽需推进 `BlockHeader::VERSION` 并联动 68 处 `BlockHeader::SIZE` 偏移算式；且该防线要防的失效场景（Footer 指针与 Catalog 首块同时不可信）不存在可信锚点。`reserved2` 保持保留语义，`BlockHeader::VERSION`/`SIZE` 不变。详见 §3.9 D3。
- **备份的完整性前提（R38，安全硬约束）**：备份 Catalog 密文必须与主 Catalog **逐字节同源**——即由同一 `catalog_bytes` 切分、同一压缩/编码路径产出，仅 `block_id` 与 `volume_index` 参与子密钥/AAD 派生。这样读端经备份指针拿到的明面数据可用**既有** `manifest.catalog_commitment` 校验。**禁止**为备份引入独立编码路径后只靠 AEAD 标签自证；若实施中确需独立路径，必须先扩展 `ArchiveManifest` 增加备份承诺字段，并同步 `crates/era-common/src/types/manifest.rs` 与其反序列化测试。

#### 2. 单卷双写镜像协议

- 触发条件：单卷归档（`volume_indices.len() == 1`）——**含非纠删码配置**（当前该配置完全没有备份块，见本节第 1 条实测）。
- 块 ID 分配：Primary `[C .. C+K-1]`，Backup `[C+K .. C+2K-1]`；AAD 严格绑定各自 `block_id`，保证子密钥与标签正交。轮转（`precheck_and_rotate_if_needed`）后重跑 `build_catalog_block_sets` 会重新加密，但 `reserve_block_id` 不推进计数器，故 ID 保持稳定——**该性质必须由 §4.3 用例 #10 固化为断言**，不得仅靠阅读代码。
- 物理布局：`[Data Stripes] [Primary Catalog] [Backup Catalog] [Backup SuperHeader 4096B] [Primary Footer 128B]`。
- 写端落点（**三处，缺一不可**）：
  1. `crates/era-engine/src/writer.rs:2114-2270`（`ArchiveWriter::finalize` 的 Catalog 段）+ `:1425-1520`（`build_catalog_block_sets`）；
  2. `crates/era-engine/src/volume_stage.rs:151-209`/`:211-269`/`:275-351`——**必须把丢掉的 `_backup_location` 收回来**并回传给 `finalize` 填 Footer；
  3. `crates/era-engine/src/writer.rs:3533-3550`（`GenericArchiveWriter::finalize`）——**当前完全无备份**，须补第二块并以 v2 指针落 Footer。

#### 3. 读端 O(1) 自愈

`load_catalog`（`reader.rs:863-966`）先按 `footer.catalog_offset()` 读解密 Primary；失败时若 `footer.has_backup_catalog()`，直接以 `backup_catalog_offset()` + `backup_catalog_block_id()` 构造 `BlockLocation` 解密；`K > 1` 时按 `chunk_index` 顺序装配（复用 `assemble_catalog_data` 的协议，但偏移推进必须改用**显式块偏移表**而非 `catalog_offset + bh_size + catalog_size` 的算术紧邻推导——这是本 FIX 消除算术紧邻的落点）。解密后必须用 `manifest.catalog_commitment` 校验（见上文完整性前提）。输出自愈告警日志。

#### 4. `repair` 元数据修复

`crates/era-engine/src/repair.rs:401` 起的单卷扫描：Primary 损坏而 Backup 完好时，按结构化指针把 Backup 写回 Primary 偏移，无需猜测。注意 `repair` 的条带扫描上界 `erasure_data_end`（`crates/era-engine/src/erasure_scan.rs:83-107`）以 `footer.catalog_offset()` 为上限，故 Catalog 修复**必须**在该循环之外单独实现，不得期望扫描循环覆盖。

#### 5. Footer 原生原子就地修改

- 痛点：`checkpoint.rs:439-456` 用 `Footer::builder` 重组，**漏 `.manifest(...)`**，且无法承载 v2 的 `backup_catalog_*`，导致元数据静默归零。
- 新增（**签名冻结**）：`pub fn clear_checkpoint(&mut self)`（仅置零 `last_checkpoint_*`，原地重算 checksum）与 `pub fn with_cleared_checkpoint(&self) -> Self`（clone + clear）。
- 保留 `manifest_*`、`backup_catalog_*`、`index_*` 与全部 flags；`checkpoint.rs` 全面改用该方法，废除破坏性 builder 重组。

---

### 3.4 FIX-05：恢复管理器多卷感知与原子协同截断

#### 1. 多卷拓扑与路径派生 SSOT

**先决事实**：工作区**已有**“多点号安全、纯追加式”实现——`ArchiveReader::discover_volumes` 的基准名推导（`reader.rs:204-215`，**已正确**）；`MAX_VOLUME_SCAN = 1000` 已存在于 `multi_volume.rs:22`（私有，仅 `:312` 一处使用）。本 FIX **不是再造第四套算法**，而是：

1. 把 `reader.rs:204-215` 的推导逻辑抽取/重写为 `era_volume` 内的**唯一权威纯函数**（重写 `lib.rs:70-77` 的 `volume_path`，删除全部 `with_extension` 实现）；
2. 让读端、写端、CLI、恢复端**共同调用**；
3. 把扫描上界收敛为单一权威常量：**上移至 L0 `era-common`**，由 `multi_volume.rs:22`、`reader.rs:197`（现局部 32）与新的 `RecoveryManager` 发现逻辑**共用**（§4.9）；
4. **探测成本论证**：当前 `discover_volumes` 的每候选成本是 1 次 `try_exists`（`reader.rs:242`）+ 命中后 1 次 `VolumeReader::open`（`reader.rs:247-257`，全量 4096B 头解析）；上限自 32 放宽到 N 后，最坏情况为 O(N) 次 stat + O(N) 次头读取，均与归档总量无关。`RecoveryManager` 的发现逻辑**必须**改为“先 `try_exists`，仅在存在时读前 4096B 校验 `archive_id`/`volume_sequence`”，避免无谓的全量 open。
5. **权威派生算法（纯追加、单射）**：已以 `.era` 结尾 → 从卷 `f"{path}.{seq:03}"`；不以 `.era` 结尾 → 主卷 `f"{path}.era"`、从卷 `f"{path}.era.{seq:03}"`；`seq = 0` 恒为主卷路径本身。

**必须替换的 6 处缺陷点**

| # | 位置 | 性质 | 失败模式 |
| :-- | :--- | :--- | :--- |
| 1 | `crates/era-volume/src/lib.rs:72` `base_path.with_extension("era")` | 缺陷（seq 0） | 多点号折叠 |
| 2 | `crates/era-volume/src/lib.rs:75` `base_path.with_extension(ext)` | 缺陷根源（seq>0） | 多点号折叠（`ext` 变量间接传入，文本判据覆盖不到，见 §5.4 3e） |
| 3 | `crates/era-volume/src/multi_volume.rs:311` `first_volume_path.with_extension("")` | 缺陷（探测端） | 探测失败 |
| 4 | `crates/era-engine/src/writer.rs:1571` + `:1573`（`collect_own_volume_paths`） | 缺陷（写端自排除） | 自排除失效 → 归档自包含 |
| 5 | `bins/era-cli/src/commands.rs:456` + `:458`（`collect_archive_volume_paths`，由 `:666` 调用） | 缺陷（CLI 写端自排除） | 同 #4 |
| 6 | `bins/era-cli/src/commands.rs:1811`（卷计数）、`:1847`（missing-volume 卷名） | 缺陷（CLI 卷名推导） | 卷名错配 |
| — | `crates/era-engine/src/reader.rs:204-215` | **已正确**，作为重构蓝本 | — |
| — | `repair.rs:380`、`:986` | 无关（`.era.bak` 备份命名，**不得纳入判据**） | — |

#### 2. RecoveryManager 三级拓扑发现

- `RecoveryManager::new/analyze(archive_path)` 打开 Volume 0 读 `SuperHeader.total_volumes()`；
- 三级仲裁：① 有合法 `manifest` → 采信 `manifest.volume_committed_ends.len()`；② 无 manifest 且 `total_volumes() > 1` → 采信静态值；③ `total_volumes() <= 1`（含断电未终结的 0）→ 文件系统动态探测 `seq = 1..MAX_VOLUME_SCAN`，逐卷读前 4096B 校验 `archive_id == primary_archive_id && volume_sequence == seq`，遇到首个缺失/不匹配即终止；
- **连续性硬约束**：探测到的序列必须是 `0..N-1` 严格连续；出现空洞（存在 `.002` 却缺 `.001`）→ Preflight 判定损坏并拒绝任何物理截断。
- **容差语义必须写死**：新发现的终止条件（首个缺失即停）**严于**现有 `discover_volumes` 的 `scan_tolerance = max(parity_shards + 1, 2)`（`reader.rs:189-194`）。恢复场景要求严格连续，故不沿用容差；读端**不**收紧（R39/D5）：其容差是“未知卷数时的扫描终止条件”，且读端空洞安全已由 `vol_index_map` 保证（`block_iter.rs:392-398`）；恢复端严格连续是因为它要做**物理写**。两套语义适用域不同，须在代码注释与本文档同时写明，**不得沉默并存**（§3.9 D5、§4.9）。

#### 3. 两阶段原子协同截断（对称卷尾重建）

- 卷物理常量：`HEADER_SIZE = 4096`、`BACKUP_FOOTER_GAP = FOOTER_SIZE = 128`、`DATA_REGION_START = 4224`。
- **阶段 1 Preflight（Fail-Closed）**：遍历 `0..N-1`，校验每卷存在、可获取独占写锁、`SuperHeader` 的 `archive_id`/`epoch_id` 匹配、物理长度 ≥ `volume_committed_ends[seq]`。任一失败即以 `EraError::IntegrityError` 退出，**不做局部截断**。
- **阶段 2 Execution（逆向 + 对称重建）**：严格 `N-1 → … → 1 → 0` 逆序，每卷：① `file.set_len(volume_committed_ends[i])`；② **先行** `checkpoint_manager.delete()` 清除检查点（**R40/W24 前置条件**：`delete()` 必须先完成“仅就地清位、绝不改长度、保留 `manifest_*`/`backup_catalog_*`/`index_*`”改造，否则本步会覆盖 `committed_end-128` 处的已提交数据并把 `manifest_offset` 清零——见下条“唯一写路径”）；③ 在 `volume_committed_ends[i]` 写 4096B Backup SuperHeader；④ 在 `+4096` 写 128B Primary Footer（`footer.with_cleared_checkpoint()`，Blake3 重算）；⑤ 在偏移 4096 更新 Backup Footer 为 cleared；⑥ `sync_all()`，最终长度严格 `= volume_committed_ends[i] + 4224`。
- **收益**：Primary Footer 恒驻留 `file_len - 128`，**杜绝**把 Footer 写到 `committed_end - 128` 覆盖已提交数据。
- **断电幂等**：从卷重建期间断电时主卷 checkpoint 未清除，重启可重跑；Preflight 接受 `actual_len >= committed_end + 4224`（已重建）或 `>= committed_end`（未截断）；主卷完成重建并落盘即**全局提交点**。
- **唯一写路径（强制，且为截断事务的启用前置）**：`checkpoint.rs:402-469` 中按 `file_len - 128` 推导写偏移的逻辑整体删除（实测当前 `:418` 仍在推导，`:460-465` 仍写回该偏移）；`delete()` 收敛为“仅就地清 checkpoint 位、绝不改变文件长度、保留 `manifest_*`/`backup_catalog_*`/`index_*` 与全部 flags”。全文**不存在**第二条尾部写路径。**实施顺序**：本改造与 §4.4 #6 红测试同 PR 先行落地，**之后**才允许启用阶段 2；顺序颠倒即制造 W24 所述的数据覆盖缺陷。
- **无 Manifest 一律 Fail-Closed（射程 3 处 + 分支内 1 处收口，R40 扩围）**：
  1. `crates/era-engine/src/recovery.rs:391` 的 `backward compat` 回退分支整体删除：`truncate_to_checkpoint_with_manifest(None)` 或卷内 Manifest 损坏/缺失 → `EraError::IntegrityError("Cannot safely truncate archive: missing authoritative ArchiveManifest")`。**R40/W23 收口要求**：判定必须落在**函数体内的 `None` 分支**（`recovery.rs:389-412`），使全部 `None` 入口自动收敛——除 CLI 外还包括 `recovery.rs:345`（`truncate_to_checkpoint()` 本体）与测试内的 `:846`；不得只在 CLI 层拦截；
  2. `bins/era-cli/src/commands.rs:1249-1254` 的 `if let Some(manifest) ... else { manager.truncate_to_checkpoint() }` 必须改为 **Fail-Closed 单一分支**（无 Manifest 直接报错并引导重新 `create`），不得保留无 Manifest 的截断入口；
  3. `crates/era-engine/src/reader.rs:1234-1236` 的 `check_read_bound` 在 `volume_committed_ends == None` 时 `return Ok(())`——**R39/D1 终裁：改为 `InvalidFormat` 失败关闭**（`None` 与 `Some(空)` 同语义），无 Manifest 归档在**读路径不再被接受**；理由与撤销成本见 §3.9 D1。
  4. **R40/W22 新增第三处（读端同源放行）**：`crates/era-engine/src/block_iter.rs:77-79` 的 `check_commit_horizon_for_sequence` 对 `committed_ends == None` 同样 `return Ok(())`。其 `Option` 直接来自 `ArchiveReader::committed_ends_for_iterators()`（`reader.rs:503-504`），注入全部分块迭代器（`reader.rs:698/710`、`:2041/2053`、`:2105/2117`）；只改第 3 处会让同一归档在**分块迭代路径**上继续无界读。**第 3、4 处必须同步给出结论，不得只改其一。**
- **AST 门面保留**：`pub async fn truncate_to_checkpoint(&self) -> Result<u64>`（`recovery.rs:344`）签名永久保留，内部加载权威 Manifest + `spawn_blocking` 物理截断，满足 `adversarial_audit_v2.rs:270-277`。

#### 4. CLI 运维引导

`bins/era-cli/src/commands.rs:1236-1260`：检测到未决检查点时输出高危警示与续传指引；仅在用户显式 `--force` 时执行全卷协同截断。

---

### 3.5 FIX-06：卷尾截断容忍、双确定性头尾自愈与废除浮动扫描

1. **软裁决通道**：
   ```rust
   #[derive(Debug, Clone, Default)]
   pub struct VolumeOpenOptions {
       pub lenient_truncation: bool,
   }
   ```
   新增 `VolumeReader::open_with_options(backend, path, options)`；`VolumeReader::open` 保持默认严格行为（零回归）。
2. **`effective_data_end` 动态闭环**：现状缺陷是 `data_region()`（`reader.rs:357-365`）右界直接取 `footer.data_end_offset()`，软截断时把**超出物理大小的脏偏移**交给上层。契约为：`VolumeReader` 显式持有 `effective_data_end: u64`；`open_with_options` 中 `effective_data_end = footer.data_end_offset().min(actual_size)`；`data_region()` 统一返回 `(DATA_REGION_START, self.effective_data_end)`。**R39/D4 对齐**：该式**不含** `unwrap_or(actual_size)` 兜底——依 D4，`open` 在 `footer.is_none()` 时已无条件返回 `CorruptedHeader`，故进入本行时 `footer` 必为 `Some`；保留 `unwrap_or` 会重新引入“无 Footer 也可读”的隐式通道。由此 `lenient_truncation` 的语义被严格限定为“**Footer 可读、且 `data_end_offset > actual_size`**”，不覆盖 Footer 缺失。
3. **端际残缺块收敛**：
   - `read_raw`（`reader.rs:240`）：`offset >= effective_data_end` → `Ok(Bytes::new())`（自然终止）；`offset < effective_data_end < offset + len` → `Err(EraError::TruncatedShard { offset, available, expected })`。本题与 §3.2 的 `len > MAX_SHARD_SIZE` 前置校验**同时存在**，顺序为先长度上限、后端际收敛。
   - `read_typed_block`（`reader.rs:383`）**不得**含混复用 `Ok(0)`/`None`；需“优雅终止”的调用方使用新增的 `Option` 包装接口。
   - 上层迭代器：常规模式透传强类型错误；`--salvage` 模式捕获并**聚合** `DecodedBlock::corrupted_shards`（`block_iter.rs:38`）到 `ExtractStats::corrupted_shards` 后结束当前卷迭代，**不得**留下未处理 I/O panic 或 1 字节步进死循环。`byte_iter` 已在 `:1422-1432`/`:1449-1459` 把 `Err(_)` 映射为缺失槽位，新通道必须与之**不重复计数**（同一缺失事件只能计一次）。
   - `EraError::TruncatedShard` 落地前置见 §4.9（`EraError` 无 `#[non_exhaustive]`，但实测全仓无穷尽 `match`，编译影响面为零）。
4. **双确定性头尾恢复**：写端已双写（`crates/era-volume/src/writer.rs:628-649`），但读端 `reader.rs:57` 用 `?` 在 Primary SuperHeader 损坏时**立即中断**，使 `reader.rs:35-41` 文档化的恢复链第 2/3 步从未生效。重构为两阶段正交恢复：① **Footer 寻址预解析**（读 Primary Footer `size - FOOTER_SIZE`，失败读偏移 4096 的 Backup Footer，任一合法即得 `data_end_offset`）；② **SuperHeader 容灾加载**（先偏移 0，失败/CRC 错时用 ① 的 `data_end_offset` 读 Backup SuperHeader）；③ 仅两者均损毁 → `EraError::CorruptedHeader`。
5. **废除 Floating Footer 逆向扫描**：删除 `try_floating_footer_recovery`（`crates/era-volume/src/reader.rs:144-204`）与调用点 `reader.rs:80`；窗口为**单一** `FLOATING_FOOTER_SCAN_SIZE = 1MB`（`reader.rs:20`），**不存在 64KB 窗口**。卷元数据仅认两个确定性来源（`size - 128` 与 4096），两处均损毁即拒绝读取，杜绝随机密文上的假阳性匹配。同步处置 §2.2 #1–#3。

**失败关闭的连带影响（R39/D4 终裁）**：删除浮动扫描后，`reader.rs:82-86` 的 `if footer.is_none() && !erasure_enabled { Err(CorruptedHeader) }` 这一“无 footer 但纠删码开启则继续”的宽松分支**一并删除**，收敛为无条件的 `if footer.is_none() { return Err(EraError::CorruptedHeader(..)) }`——**`lenient_truncation` 也不放行“两个 Footer 全丢”**（软截断只处理“Footer 可读但其 `data_end_offset` 超出物理大小”，见本节第 2 条）。理由：(a) FIX-06 的全部价值在于**元数据只有两个确定性来源**，放行即引入第三条隐性来源；(b) `erasure_enabled` 取自 `SuperHeader`（`reader.rs:59-60`，`:81-88` 的条件），而删除浮动扫描后 SuperHeader 本身也要经 Backup SuperHeader 自愈（本节第 4 条），以它作为“可继续”的依据构成循环信任；(c) 数据分片仍是分片，**没有 Footer 就没有 `data_end_offset` 与 `catalog`/`index` 定位**，纠删码救不回元数据。`lenient_truncation` 的语义因此被严格限定为“**Footer 可读但物理尾部短于声明**”，不得扩张解释。

---

### 3.6 FIX-07：CLI 接线 `DirectoryScanner` 与全文件类型往返

#### 0. 依赖边决策（实施前置）

`bins/era-cli/Cargo.toml` 当前**不含** `era-ingest`（`:13-28` 仅 `era-common`/`era-crypto`/`era-engine`），`era-engine` 也未导出 `DirectoryScanner`。**裁决：经 L4 再导出**——在 `crates/era-engine/src/lib.rs` 增加 `pub use era_ingest::{DirectoryScanner, ScanOptions};`。理由：(a) 维持 L5→{L0,L1,L4} 惯例；(b) `ignore` 的版本/特性由 `era-ingest` 单点控制（`crates/era-ingest/Cargo.toml:14` = `0.4.25`）。备选（L5 直连 L3 + Cargo 增列 + `crates/AGENTS.md` 登记）**不采用**，不得留给实施者临场决定。

#### 1. CLI 接线

`bins/era-cli/src/commands.rs:672-690`：移除裸 `walkdir::WalkDir` + `is_file()` 过滤，改用 `DirectoryScanner`。`ScanOptions` 能力边界（实测）：`root`/`include_patterns`/`exclude_patterns`/`extract_xattrs`/`extract_acls`（`era-ingest/src/reader.rs:21-32`）；`scan()` 用 `WalkBuilder::standard_filters(true)` + `.add_custom_ignore_filename(".gitignore"/".ignore"/".eraignore")`（`:81-87`）；故 **`.ignore` 已接入**；**没有** `follow_links`——帮助文本不得超出该能力。

#### 2. `ArchiveWriter` 新增非普通文件接口（FIX-07 新增项）

- `pub async fn add_directory_entry(&mut self, disk_path: &Path, stored_path: &Path) -> Result<()>`：构造 `FileType::Directory`（size=0、无 chunks）的 `FileEntry` 注册进 `Catalog`；
- `pub async fn add_symlink(&mut self, disk_path: &Path, stored_path: &Path) -> Result<()>`：`tokio::fs::read_link` 后构造 `FileType::Symlink`（size=0、`symlink_target: Some(..)`）；
- **命名裁决（R38 修正）**：全仓**不存在** `fn add_directory`（`grep -rn 'fn add_directory' crates bins` 命中 0）——上一版“`writer.rs:1679` 已占用该名”的冲突判断系误判（`:1679` 是 `self.add_file_chunked(...)` 调用点），**已撤销**。新增接口按 §3.6 第 2 条命名 `add_directory_entry`：语义清晰、与 `add_symlink` 成对，且不占用既有名字。两接口是 §3.8 冻结面的**第 11/12 项**（新增，非既有）。
- **`collect_files_async`（`writer.rs:1281`）的删除不是零成本**：现役调用点 `:1301`（递归）与 `:1550`（目录归档入口）必须**先**迁移至 `DirectoryScanner`，再删函数本体；
- 既有 10 项公开面签名与语义**保持不变**（§3.8）；FIX-07 新增的接口是扩面，不得改动既有 10 项语义。

#### 3. 三阶段解包生命周期

- **Phase 1（骨架、0 字节落地、路径安全）**：逐条校验 `entry.path`（拒绝绝对路径与 `..` 越界）；目标路径磁盘上**已存在且为软链接** → `EraError::Security("Pre-existing symlink collision detected: possible symlink planting attack")`（与既有 `Symlink escape detected` 区分）；对所有 `FileType::Directory` 预建骨架（临时 0755）并压入**新增**的 `created_directories`；对 0 字节普通文件先 `create_dir_all(parent)` 再 `File::create` 并压入 `stats.extracted_paths`；归档无 chunked 文件时**不得提前返回**，直接进入 Phase 3。
- **Phase 2（数据流式解码 + 软链接着陆）**：正常写多分块文件；软链接先对 `symlink_target` 做沙箱密闭性校验（规范化后物理着陆点必须仍在 `output_dir` 内，相对/绝对目标均适用），通过后 `tokio::fs::symlink`。
- **Phase 3（自底向上后序元数据恢复）**：`crates/era-engine/src/reader.rs:1772` 过滤条件由 `FileType::File` 扩展为 `File | Directory | Symlink`；排序双键 `(path_depth DESC, is_directory ASC)`；分类型系统调用（**现状缺陷**：`reader.rs:1792` 对一切条目用 `File::options().write(true).open()` 打 mtime，目录会 `EISDIR`、只读文件会因需写权限失败；`:1815` 的 `xattr::set` 与 `:1833` 的 `set_permissions` 也未按类型分派）：
  - 普通文件：写完 → 关闭并 `sync_all` → mtime/xattrs → **最后**设 permissions（含 0444）；
  - 目录：**严禁**写模式 `File::open`，用只读句柄/专用调用更新 mtime，随后 `set_permissions` 封闭；
  - 软链接：**严禁** `set_permissions`/`xattr::set`（会解引用穿透目标），用 `utimensat(AT_SYMLINK_NOFOLLOW)` 更新时间。
  - **依赖裁决（R39/D2 终裁）**：**把 `filetime = "0.2"` 提升为 `crates/era-engine/Cargo.toml` 的常规依赖**，用 `filetime::set_symlink_file_times`；**不采用** `libc::utimensat`。依据：`libc` 目前仅 `crates/era-crypto/Cargo.toml:38` 使用（`secure_memory.rs` mlock/prctl），`era-engine` 引入它需新增 FFI + `unsafe` 边界（工作区 `unsafe` 现仅限 `secure_memory.rs`），而 `filetime` 是纯安全 Rust、已在工作区依赖图内（CLI dev-dependency）、版本由 `Cargo.lock` 固定。落地动作：`crates/era-engine/Cargo.toml` 增列 + `crates/AGENTS.md` 依赖图登记。详见 §3.9 D2。`xattr` 可直接用（`era-engine` 正式依赖，`writer.rs:1632`/`reader.rs:1816` 已在用）。

#### 4. `has_pending()` 语义边界（关键防回归）

仅允许修改 `crates/era-engine/src/reader.rs:1650` 的提前返回守卫，改为基于 **`catalog.entries.is_empty()`**；**严禁**修改 `ExtractionContext::has_pending()`（`chunk_processor.rs:77-81`）本体语义——`reader.rs:1735`/`:1742` 依赖它判定“多块文件是否收齐”；回归测试须保留“多块文件缺失分块 → `ErasureError`”的既有行为（`:1742-1750` 的 `Not enough shards for recovery`）。

---

### 3.7 FIX-08：运维体验、安全凭证与工程治理

1. **FIX-08a（缺失卷引导）** — 改造 `bins/era-cli/src/commands.rs:1142` 文案为：
   `"Archive is missing expected volume files: ...; in-place repair cannot regenerate entire volume files on disk. If the missing count is within erasure redundancy, you can directly run 'era extract' to recover all data and then re-archive."`
   同步把 `bins/era-cli/src/commands.rs:2178` 旧子串 `missing expected volume files` 改写为冻结表新文案（**不保留兼容子串**，该子串在新文案中被 `Archive is missing expected volume files` 自然保留——见 §4.0 冻结表的**双子串**约定）。
2. **FIX-08b（帮助示例去明文密码）** — 替换 `main.rs` 中 `-p secret` 的全部示例（`65/69/172/211/246/278/357/358`）为 `-p <PASSWORD>` / 密钥文件 / 交互式提示说明。**R37 补录**：`main.rs:9` 的 crate 级 `//!` 用法示例亦含 `--password secret`；clap 因显式 `#[command(about)]`/`long_about` 而不渲染该注释（实测 `bins/era-cli/src/main.rs:24-40`），故 `--help` 断言不会覆盖它——**顺手一并改掉**，但不得据此声称“帮助输出已覆盖全部文档面”。
3. **FIX-08c（Fuzz 设施）** — 无需整改：`fuzz.yml` 仅 `workflow_dispatch` 且首行有 NOTE，`Cargo.toml:3` 排除 `fuzz/`，目录不存在。仅登记“fuzz 工作区落地后再启用计划触发”。
4. **FIX-08d（工具链单一来源）** — `rust-toolchain.toml`（`channel = "1.98.1"` + `components = ["rustfmt", "clippy"]`）是唯一版本来源；`[workspace.package]` 增加与之相同的 `rust-version`；CI 三处 `dtolnay/rust-toolchain`（`ci.yml:36/74/107`）显式声明同一 `toolchain:` 输入，消除“上游 stable 前滚后 CI 与本地分叉”的潜在漂移。**禁止**写入未经 `cargo msrv`（或等效矩阵）验证的版本区间；无法验证下界时只声明“已验证版本”。
5. **FIX-08e（coredump 回归门禁）** — 生产已具备（`main.rs:501` 调用 `disable_core_dumps()`）。交付项：CLI 新增**隐藏探测出口** `era --print-dumpable`（不进公开帮助）输出 `prctl(PR_GET_DUMPABLE)`；`#[cfg(target_os = "linux")]` 门控的集成测试断言 stdout 严格为 `"0"`，非 Linux **显式跳过并在 CI 报告可见**（跳过 ≠ 通过）；事实边界：`secure_memory.rs:364-367` 在非 Linux/macOS 平台为**静默 no-op 且上报成功**，文档只能写“Linux 已防护、macOS 有 ptrace 反附加、其余平台为 no-op”。
6. **FIX-08f（运维特性文档化）** — 在 CLI 文档说明：单文件解包路径扁平化、小文件纠删码固定开销膨胀、纠删码数学硬上限。

---

### 3.8 FIX-09：`writer.rs` 上帝对象解耦

#### 1. 现状（实测，`e4050a2`）

- 总行 **3649**（`wc -l`）；**测试 813 行（735+78），生产 2836 行**。口径：测试行数 = 自 `#[cfg(test)]` 所在行起至该 `mod` 闭合花括号止（含两端）；生产 = `wc -l` − 测试。可用 `sed -n '2491p;3225p;3571p;3648p'` 与 `wc -l` 复现。
- 结构：`ArchiveWriterBuilder`（`pub struct` `:141`、`impl` `:175`、`new` `:177`）；`ArchiveWriter`（`pub struct` `:1242-1277`，`impl` `:1310`）；自由函数区（`collect_files_async` `:1281`、`is_internal_path` `:2474`、`ArchiveStats` `:2480`）；根测试 `:2491-3225`；`generic` `:3228-3648`。
- **公开 API（10 项，R37 逐行复核 —— 已撤销上一版的“14 项”误判，见 W9）**：`builder`(1312)、`archive_id`(1511)、`key_encapsulation`(1522)、`is_certificate_mode`(1527)、`add_path`(1536)、`add_file_with_path`(1585)、`add_file`(1693)、`add_files`(1736)、`add_bytes`(2033)、`finalize`(2082)。**无** `new`，**无** `add_directory*`/`add_symlink`（`add_file_single`@1760 为私有）；`add_symlink` 与“空目录条目注册接口”是 FIX-07 新增的**第 11/12 项**（不属于兼容约束，且不得占用任何既有名字，见 §3.6 第 2 条）。

#### 2. 四阶段拆分

```mermaid
flowchart LR
    W["ArchiveWriter (3649 行)"] --> P1["阶段 1: 测试外置 (813 行 → tests/)"] --> P2["阶段 2: Builder → writer_builder.rs"] --> P3["阶段 3: CatalogFinalizer → catalog_stage.rs"] --> P4["阶段 4: ArchiveWriter 微核 Facade ≤500 行"]
```

1. 阶段 1：735 行根测试 → `tests/archive_writer_tests.rs`，78 行 → `tests/generic_writer_tests.rs`；
2. 阶段 2：`ArchiveWriterBuilder` 与配置校验 → `src/writer_builder.rs`；
3. 阶段 3：Catalog 序列化、单卷双写镜像、多卷矩阵扇出、Manifest 承诺 → `src/catalog_stage.rs`；
4. 阶段 4：`ArchiveWriter` 仅保留管线驱动与**上述 10 个既有公开方法**（+FIX-07 新增的 2 个），核心代码 **≤500 行**（门禁 `wc -l` 可复现；历史“300/600 行”口径已废除）；Builder → Pipeline → Finalizer 通过 Rust move 语义移交，禁止中间克隆。

---

### 3.9 R39 留白项终裁（D1 / D2 / D3 / D4 / D5）

> 本节把上一版标注为“显式决策项”的五处分叉**一次性定死**，实施者不得再临场选择。每项给出裁决、依据、反证与被否方案的代价。基线：`e4050a2`。

#### D1：读端对无 Manifest 归档 —— **裁决：Fail-Closed**

- **裁决**：删除 `crates/era-engine/src/reader.rs:1232-1236` 的 `volume_committed_ends == None => return Ok(())` 分支，改为 `EraError::InvalidFormat`；`BackwardCompat`（v8.1 / 无 Manifest）归档在**读路径**不再被接受。`check_read_bound` 的三种输入全部收敛为确定性语义：`Some(非空)` 按 `committed_ends` 校验；`Some(空)` 与 `None` 一律 `InvalidFormat` 失败关闭。**R40/W22 补齐射程**：第二处同源放行在 `crates/era-engine/src/block_iter.rs:77-79`（`check_commit_horizon_for_sequence` 的 `let Some(ends) = committed_ends else { return Ok(()) };`），两处必须同步改为 `InvalidFormat`；判定落在迭代器公共入口即可一次性覆盖 `extract`/`verify`/live-block 枚举三条注入路径（§1.2.1 W22）。
- **依据（事实）**：
  1. 该类分支是**读端兼容后门的全部来源**（R40 实测为 `reader.rs:1232-1236` 与 `block_iter.rs:77-79` **两处**，上一版“唯一”的表述已按 W22 撤销），且与文档目标自相矛盾——本方案已声明“不接受任何向后兼容妥协”，却在读路径保留“无 Manifest 则完全放行范围校验”。
  2. 同一 `load_manifest` 已有**姊妹硬失败分支**：`reader.rs:1118-1122` 对“卷声明有 Manifest 但加载失败”直接 `Err(IntegrityError)`。保留 `None` 放行意味着“**没有** Manifest 比“**有**但损坏”**更宽松**”，属安全语义倒置。
  3. 撤销成本已实测为 **0 个生产调用面冲突**：workspace 内不存在“只写 v8.1、不写 Manifest”的写端（`build_manifest` 是 v8.2 唯一路径），现有测试无“无 Manifest 归档仍需成功读取”的断言（`v81_adversarial_resilience.rs` 测的是损坏注入后的拒绝，不是降级读取）。
- **反证与代价（如实登记）**：一旦未来需要读历史 v8.1 归档，需重新引入**显式的** `VolumeOpenOptions`/`ExtractOptions` 兼容开关（且必须与 FIX-06 的 `lenient_truncation` 分开命名），而不是让宽松成为默认。这不是本阶段的技术债，因为历史归档不存在。
- **被否方案**：“显式登记保留宽松行为”：会留下两套读范围语义，`repair`/`verify`/`extract` 三条路径的越界判定不一致，且与 FIX-05 的截断 Fail-Closed 相互矛盾 → 否决。

#### D2：软链接时间戳实现 —— **裁决：`filetime` 提升为 `era-engine` 常规依赖**

- **裁决**：在 `crates/era-engine/Cargo.toml` 的 `[dependencies]` 增加 `filetime = "0.2"`（与 `bins/era-cli/Cargo.toml:37` 的 dev-dependency 版本约束一致；`Cargo.lock` 现锁 `0.2.27`），Phase 3 软链接分支使用 `filetime::set_symlink_file_times`；**不**改用 `libc::utimensat`。**R41 前提登记**：`filetime` 目前**不在 workspace 任何 `[dependencies]` 中**（仅 CLI dev-dependency），提升等级属**新增依赖决策**，须与 `crates/AGENTS.md` 依赖图同 PR。
- **依据（事实，R41 已按 `Cargo.lock` 重写）**：
  1. `libc` 目前在 workspace 中仅由 `crates/era-crypto/Cargo.toml:38`（`[target.'cfg(unix)'.dependencies]`，供 `secure_memory.rs` 的 mlock/prctl/ptrace 使用）与 `filetime` 自身引入；`era-engine` 的直接依赖中**没有** `libc`。采用 `utimensat` 需在 `era-engine` 新增 **自维护 FFI 边界 + `unsafe` 调用**——workspace 现状是 `unsafe` **只**出现在 `crates/era-crypto/src/secure_memory.rs`（`crates/era-volume/src/lib.rs:8` 甚至 `#![forbid(unsafe_code)]`）。**拒绝 `utimensat` 的理由是“不在 L4 写 `unsafe`/FFI、不扩大审计面”，而不是“依赖链内无 `unsafe`”**：`Cargo.lock:1068-1076` 实测 `filetime 0.2.27` 的依赖为 `cfg-if` + `libc` + `libredox`，即它**会把 `libc` 带进 `era-engine` 的依赖图**。该差异不影响裁决（`libc` 已在 `Cargo.lock` 内，无新增第三方来源），但论证必须按事实陈述。
  2. `filetime::set_symlink_file_times` 的**调用方代码**是安全 Rust，内部按平台正确选择 `AT_SYMLINK_NOFOLLOW` 语义，正好覆盖“不穿透符号链接目标”这一硬要求（§3.6 Phase 3 的 `严禁 set_permissions/xattr::set` 同源要求）。**注**：标准库 `std::fs::FileTimes`（1.75 起稳定）**只提供 `File::set_times`（跟随目标的句柄语义），无 `AT_SYMLINK_NOFOLLOW` 入口**，故不能替代本项；这也是本方案中唯一需要“非跟随目标”时间戳能力的位置（已在 §1.3 复验：`filetime` 在生产源码零引用）。
  3. 该 crate **已在工作区依赖图内**（CLI 的 dev-dependency，`bins/era-cli/Cargo.toml:37`），提升等级不引入 `Cargo.lock` 之外的新第三方来源；版本由 `Cargo.lock` 固定。
- **反证与代价**：`era-engine` 常规依赖 +1，且其传递依赖含 `libc`（已在 `Cargo.lock` 内，但会出现在 `era-engine` 的依赖清单中，需在 `crates/AGENTS.md` 如实登记）。可接受：调用方零 `unsafe`、单一用途、避免自写 FFI 的维护与审计成本。
- **被否方案**：①“`libc::utimensat` 原生实现”：需新增 `unsafe` FFI、自行处理 `timespec`/错误码/平台差异，与“L4 不引入 `unsafe`”方向相反 → 否决；②“用 `std::fs::FileTimes` 替代”：无 symlink 非跟随入口，会穿透软链接改写目标文件的 mtime，违反本节硬要求 → 否决。

#### D3：`BlockHeader::reserved2` 承载块 ID —— **裁决：不采用（撤销该设计项）**

- **裁决**：从 FIX-04 中**删除**“块头自描述（第二重防线）”整项。`crates/era-common/src/types/block.rs:526` 的 `reserved2: [u8; 4]` **保持保留字段语义不变**，`BlockHeader::VERSION` 维持 `1`，`BlockHeader::SIZE` 维持 `16`。
- **依据（事实）**：
  1. **宽度不匹配且不可无损**：`BlockId` 是 `u64`（`crates/era-common/src/types/ids.rs:98`），`reserved2` 仅 4 字节。写入必然 `u32::try_from` 截断 → 对 ≥ 2³² 的块 ID 静默失真，比不写更危险。
  2. **加宽代价是全格式级**：把该字段扩到 `u64` 需 `BlockHeader::SIZE` 16 → 24，并改动全部偏移算式（`grep -rn 'BlockHeader::SIZE' crates/*/src bins/*/src` 实测 **68 处**；**谓词必须限定 src**——若不限目录、把 `crates/*/tests` 与 `benches` 计入则为 **82 处**，见 W26），同时 `from_bytes` 的版本门控（`block.rs:565-568`）要求推进 `VERSION` → 属**格式版本推进**，与“零兼容妥协”目标冲突且收益不确定。
  3. **该防线要防的失效场景不存在**：FIX-04 的自愈路径由 `footer.backup_catalog_offset()` + `backup_catalog_block_id()`（确定性指针）与 `manifest.catalog_commitment`（完整性）共同保证；`K > 1` 后续块的身份来自 Catalog 首块 12 字节头（`chunk_count`/`total_len`）+ `validate_contiguous_disjoint_block_span`。若 Footer 指针与 Catalog 首块**同时**不可信，则不存在任何可信锚点，自描述字段也无从被安全读取（读它本身就要先猜偏移）。
  4. **算术紧邻的射程已收窄**：主备同源（§3.3 完整性前提）后，`+K` 之外的偏移推进仅发生在**一个已验证的连续块串内部**，且两端（起点指针、串长）均由 Footer/Manifest 锚定——不再是“任意猜测”。
- **反证与代价（如实登记）**：放弃“即使失去 Footer 也能凭块头字段重建 Catalog 块 ID”的**假想**能力。若将来确需块级自描述（例如引入随机布局或面向对象存储的寻址），必须作为**独立格式提案**处理：字段宽度 `u64`、`BlockHeader::VERSION` 推进、68 处偏移点同步、独立红测试；**不得**以复用 `reserved2` 的方式凑合。
- **被否方案**：“复用 `reserved2` 存 u32 块 ID”：截断风险 + 版本语义被迫推进 + 与 `catalog_commitment` 重复 → 否决（撤销）。

#### D4：两个 Footer 全失时的 `open` 行为 —— **裁决：无条件 `CorruptedHeader`**

- **裁决**：`crates/era-volume/src/reader.rs:81-88` 的 `if footer.is_none() && !erasure_enabled { return Err(CorruptedHeader(..)) }` 改为**无条件** `if footer.is_none() { return Err(EraError::CorruptedHeader(..)) }`；`erasure_enabled` 放行分支删除。`lenient_truncation` **不**放行“两个 Footer 全丢”。
- **依据（事实）**：
  1. FIX-06 的全部价值是把卷元数据收敛到**两个确定性来源**（`size - FOOTER_SIZE` 与偏移 4096）；保留一个“纠删码开启则无 Footer 也继续”的分支，等于承认第三个隐性来源，与本节第 5 条“废除浮动扫描”自相矛盾。
  2. `erasure_enabled` 取自 `SuperHeader`（`reader.rs:59-60`，`:81-88` 的条件），而在删除浮动扫描后 `SuperHeader` 自身也要经 Backup SuperHeader 自愈（本节第 4 条）。用“Header 说启用了纠删码”来决定“没有 Footer 也能读”，是**以待验证的数据为自身放行依据**的循环信任。
  3. 缺 Footer 即缺 `data_end_offset`、`catalog_offset`/`catalog_block_id`、`index_*`；纠删码只保护**数据分片**，不保护这些定位元数据。放行后所有上层读取都无锚点，只能退化为猜测——正是 FIX-04/FIX-05/FIX-06 要消除的猜测面。
- **反证与代价（如实登记）**：若一个卷的**两处 Footer 都**被覆盖（如整尾 4KB 被覆写），该卷彻底不可读。这是**有意接受**的取舍：此时任何“恢复”都只能靠猜测，且会把损坏静默化；数据面仍可由其余卷经 RS 重建（FIX-03/§5.3 的满秩自愈），不依赖本分支。
- **被否方案**：“保留为仅 `lenient_truncation` 生效的软截断通道”：`lenient_truncation` 的语义是“Footer 可读但物理尾部短于声明”（本节第 2 条的 `effective_data_end = min(footer.data_end_offset, actual_size)`），把它扩张到“Footer 不存在”会让同一个开关承载两种互斥语义，上层无法据此判断是否已有可信 `data_end_offset` → 否决。

#### D5：读端容差 vs 恢复端容差 —— **裁决：读端保持空洞安全 + 容差保留；恢复端严格连续**

- **裁决**：
  1. **读端不改**：`ArchiveReader::discover_volumes` 的 `scan_tolerance = max(parity_shards + 1, 2)`（`reader.rs:189-194`）**保留**，但其定位从“范围校验”纠正为“**未知卷数时的扫描终止条件**”；
  2. **恢复端严格连续**：`RecoveryManager` 的发现逻辑不做空洞容忍（首个缺失/不匹配即终止并 Fail-Closed，§3.4 第 2 条）；
  3. 两套语义**必须在代码注释与本文档中同时写明各自适用域**，禁止沉默并存。
- **依据（事实，推翻“读端有空洞即错位”的隐含担忧）**：读端**已经是空洞安全**的——`ErasureBlockIterator` 用 `volume_indices`（真实 `volume_sequence` 序列）构建 `vol_index_map: Vec<Option<usize>>`（`block_iter.rs:393-398`），索引按**归档序号**而非 Vec 位置，缺失卷占 `None` 槽位；分片身份另由 `reader.header().volume_id()` 给出（`block_iter.rs:272`/`:854`/`:1047`）。乱序/空缺的分片-槽位映射已被显式校验（重复序号在 `:370-378` 直接 `InvalidFormat`）。因此“空洞会导致条带错位”**不成立**；该性质**已有通过的单元测试**：`crates/era-engine/src/block_iter.rs:1991`（`test_erasure_iterator_accepts_sparse_original_indices`，断言 `vol_index_map == vec![Some(0), None, Some(1)]`）。
- **依据（为何容差不能收紧为严格）**：在 `total_volumes == 0`（断电未终结）分支下，若第一个缺失即 `break`，则远端的 `.era.002` 等卷将**永不被发现**，并把“少一卷”静默固化为最终拓扑；容差 `max(parity+1, 2)` 恰与 §5.3 的 RS 满秩自愈能力同源（可容忍至多 `parity` 个缺失卷），是有依据的停止条件。
- **依据（为何恢复端必须严格）**：截断是**物理写**（写 Backup SuperHeader 与两处 Footer 到计算出的偏移），必须保证“我据以计算偏移的卷集合就是磁盘上的全集”；此处任何空洞容忍都会把截断写到错误偏移上，故恢复端严格连续与读端空洞安全并不矛盾，而是各自领域的正确语义。
- **反证与代价**：读端容差意味着“多卷归档仅存在部分卷 + `total_volumes == 0`”时可能只发现前缀子集；但该场景下 `manifest` 缺失本身已触发 D1 的 Fail-Closed，故不会产生静默的部分恢复。
- **被否方案**：“读端同步收紧为严格连续”：会削弱未知卷数场景的发现能力，且与 `vol_index_map` 已具备的空洞安全能力相冲突 → 否决。

#### 裁决对既有章节的连带修改

| 受影响位置 | 原表述 | 终裁后 |
| :--- | :--- | :--- |
| §3.3 第 1 节“块头自描述（第二重防线）” | 用 `reserved2` 持久化块 ID | **整项删除**，见 D3 |
| §3.3 第 1 节“不得在 Footer 层断言 `+K`”段 | 依赖块头 `chunk_count` 复核 | 保留（`chunk_count` 来自 Catalog 首块 12 字节头，与 `reserved2` 无关） |
| §3.4 第 3 条射程第 3 处（读端无界放行） | “改为 `InvalidFormat` 或显式登记保留” | **定为 `InvalidFormat`**，见 D1 |
| §3.6 Phase 3 软链接时间 | “`utimensat`（或 `filetime::set_symlink_file_times`）” | **定为 `filetime`，并提升为常规依赖**，见 D2 |
| §3.5 末尾“失败关闭的连带影响” | “必须重新裁决…要么保留…要么删除” | **删除该分支，无条件失败**，见 D4 |
| §4.0 缺口清单 Footer API | 含 `BackwardCompat` 相关无 | 新增读取侧断言项，无需新符号 |
| §3.4 第 3 条射程第 4 处（**R40/W22 新增**） | 未登记 `block_iter.rs:77-79` | **与第 3 处同步定为 `InvalidFormat`**，见 D1 与 W22 |
| §3.4 阶段 2（**R40/W24 新增**） | “先行 `delete()`（已去职责化）” | **改为前置条件**：`delete()` 改造 + §4.4 #6 红测试同 PR 先行落地，之后才允许启用截断事务 |

#### R40/R41 未引入新裁决，只收紧既有裁决的实施边界

本节五项裁决（D1–D5）在 R40/R41 中**无方向性变更**；R40/R41 只做三件事：① 把 D1 的射程从 1 处扩到 **2 处**（`reader.rs:1234-1236` + `block_iter.rs:77-79`，W22）；② 把 `truncate_to_checkpoint(None)` 的收口点定在**函数体 `None` 分支**（覆盖 `recovery.rs:345`/`:846` 与 CLI，W23）；③ 登记并强制排序 `checkpoint.delete()` 的“覆盖已提交尾 + 清 `manifest_offset`”风险（W24）。**实施者不得把这三条当作可选项**：任一条未落地，D1/D5 的“无 Manifest 归档在读路径不被接受”与“截断不破坏已提交数据”两项承诺都会被同一次运行中的另一条路径绕过。

---

## 四、 测试驱动开发 (TDD) 实施规程

> 总规程：**Red（精准复现）→ Green（最小原生实现）→ Regression Guard（全量零回归）**。所有新增红测试必须绑定具体 `EraError` 变体与冻结子串，**严禁** `assert!(result.is_err())` 式泛断言。

### 4.0 红阶段两级分类、缺口清单与冻结表

- **编译期 Red（Type-Level Red）**：测试引用的类型/字段/方法尚不存在。必须先用**最小类型骨架**落地（仅签名 + 返回 `Err(EraError::X("not implemented"))`），使 `cargo test` 以**断言失败**而非编译失败呈现。骨架**严禁** `todo!()`/`unimplemented!()`/`panic!`/`unwrap()`/`expect!`。
- **断言期 Red（Behavioral Red）**：类型已存在，测试精准断言当前错误行为。

**完整缺口清单（“编译期 Red”前置；红测试引用的全部尚不存在符号）**

| 类别 | 缺失符号 |
| :--- | :--- |
| 类型/字段 | `VolumeOpenOptions{lenient_truncation}`、`VolumeReader::effective_data_end`、`ExtractOptions::salvage_mode`、`ExtractOptions::max_total_bytes`、`ExtractStats::failed_files`、`ExtractStats::corrupted_shards`、`ExtractionContext::created_directories`、`EraError::TruncatedShard` |
| Footer API | `has_backup_catalog`、`backup_catalog_offset`、`backup_catalog_block_id`、`clear_checkpoint`、`with_cleared_checkpoint`、`SUPPORTED_FLAGS`、`FLAG_HAS_BACKUP_CATALOG`、`FOOTER_DOMAIN_V2`、`validate_disjoint_regions`、`validate_contiguous_disjoint_block_span` |
| 卷 API | `VolumeReader::open_with_options`；`read_raw` 的 `MAX_SHARD_SIZE` 上限校验 + 端际收敛；`read_typed_block` 的 `Option` 包装接口（如需） |
| 恢复 API | `RecoveryManager::discover_volumes`；L0 权威 `MAX_VOLUME_SCAN` |
| 读取约束（R39/D1 + R40/W22） | `check_read_bound` 的 `None` 分支改为 `InvalidFormat`（`reader.rs:1232-1236`）**与** `check_commit_horizon_for_sequence` 的 `None` 分支改为 `InvalidFormat`（`block_iter.rs:77-79`）——**两处同 PR，无新符号**（`EraError::InvalidFormat` 已存在）；只改一处即视为未落地 |
| 技术债前置（R40/W24） | `checkpoint.delete()` 去职责化（`:402-469`：删除 `file_len - 128` 写偏移推导、保留 `manifest_*`/`backup_catalog_*`/`index_*`）——**无新符号、无新 API**，但为 §3.4 截断事务的启用前置，须与 §4.4 #6 同 PR |
| 依赖（R39/D2） | `crates/era-engine/Cargo.toml` 增列 `filetime = "0.2"`（**无新代码符号**，但属依赖面变更，须与 `crates/AGENTS.md` 依赖图同 PR） |
| CLI | `--print-dumpable`、`--salvage`、`--max-extraction-bytes` |
| Writer | `add_symlink`、`add_directory_entry`（均**新增**，见 §3.6；全仓无 `fn add_directory`，无命名冲突） |
| 常量 | L0 `era_common::MAX_SHARD_SIZE` 与其 re-export；`era-codec` 的 `MAX_SAFE_DECOMPRESSION_RATIO`/`MIN_RATIO_CHECK_OUTPUT_BYTES` |

**错误消息冻结表（实现期不可漂移）**

| 变体 | 冻结子串 | 落点 |
| :--- | :--- | :--- |
| `IntegrityError` | `missing authoritative ArchiveManifest` | FIX-05，`recovery.rs`（恢复端函数体 `None` 分支，覆盖 `:345`/`:846` 与 CLI 全部入口） |
| `InvalidFormat` | `missing authoritative ArchiveManifest` | FIX-05/D1，**读端两处**：`reader.rs:1233-1236` 与 `block_iter.rs:77-79`（与上一行同子串、不同变体、不同层；**新增于 R40**，用于 §5.4 判据 13c 与 §4.4 #12/#14 的联合断言） |
| `CorruptedFooter` | `must differ` | FIX-04，主备块 ID 别名 |
| `CorruptedFooter` | `physically overlap` | FIX-04，`validate_disjoint_regions`（**仅首块区间**语义） |
| `Security` | `Pre-existing symlink collision` | FIX-07，Phase 1（必须区别于既有 `Symlink escape detected`，后者见 `chunk_processor.rs:223/233`） |
| `IntegrityError` | `exceed declared catalog size` | FIX-01 L4，`chunk_processor.rs` |
| `Decompression` | `Block decompression ratio` | FIX-01，Zstd 流式 |
| `Decompression` | `LZ4 declared decompression ratio` | FIX-01，LZ4 预检 |
| `IntegrityError` | `exceeds MAX_SHARD_SIZE` | FIX-03，`read_raw` |
| `ErasureError` | `Not enough shards for recovery` | FIX-06，与既有 `reader.rs:1742-1750` 一致；定向诊断只能在保留该子串的前提下**追加**截断标识 |
| stderr | `Archive is missing expected volume files` | FIX-08a（保留原前缀，故 `commands.rs:2178` 的旧断言可**最小改写**而非删除） |
| stderr | `in-place repair cannot regenerate entire volume files on disk` | FIX-08a |
| stderr | `directly run 'era extract'` | FIX-08a |

> 匹配用**变体**、构造用**助手**（`EraError::decompression(..)` 在 `error.rs:231`、`compression(..)` 在 `:226`）。
> **门禁**：§4 正文中每个 `msg.contains("…")` 子串都必须能在本表找到**唯一**对应行（可 grep 机械比对）。**R38 新增**：FIX-08a 的三条 stderr 子串必须出现在**同一个测试**中（`test_repair_missing_volume_suggests_extract`），不得拆到多个用例后各自弱断言。

---

### 4.1 FIX-01 & FIX-02 TDD

**测试文件**：`crates/era-engine/tests/extraction_budget_and_salvage_tests.rs`、`crates/era-codec/tests/decompression_ratio_tests.rs`（新建）

1. `test_extraction_exceeding_8gb_succeeds_without_budget_abort` — mock 迭代器产出累计 > 8GB 的解码块（不真实写盘），`max_total_bytes = None` 时应成功。当前在 `reader.rs:1699` 返回 `Security("Extraction memory budget exceeded: possible decompression bomb")` → RED。
2. `test_salvage_mode_preserves_healthy_completed_files` — 10 个文件（含 1 个多块文件），破坏多块文件所在块，`salvage_mode = true`。当前 `fail_extraction_with_cleanup` 删除 `tracked_output_files` 全部路径（含已成功文件与尚未落地的计划路径） → RED。
3. `test_single_block_decompression_ratio_bomb_rejected_in_stream` — ~50KB 载荷解压为 8MB（160:1，< 16MB 绝对上限但 > 1MB 敏感线），断言 Zstd 返回 `Decompression` 且含 `Block decompression ratio`。当前成功返回 → RED。
4. `test_lz4_zero_memory_ratio_bomb_precheck_rejected` — **必须用完整合法 LZ4 输入**（4B LE `declared_size = 8MB` + 足量真实载荷）；**不得**用截断/畸形输入（会导致“因错误原因红”）。当前无比率防御 → RED。
5. `test_lz4_ratio_precheck_not_diluted_by_padding` — 合法高膨胀载荷 + 大量填充字节，断言仍被拦截（守护“分母剔除 4 字节前缀、不得用缓冲区容量”）。
6. `test_extraction_rejects_chunks_exceeding_declared_entry_size` — `entry.size = 100` 却注入 2×64KB 分块，断言 `IntegrityError` 含 `exceed declared catalog size` → RED。
7. `test_partial_cleanup_handles_directories_without_eisdir_and_drops_handles` — 断言清理前句柄已释放（`release_handles()`），空目录按深度逆序 `remove_dir`。当前 `cleanup_partial_files`（`reader.rs:1850-1875`）对目录调用 `remove_file` 会告警（不 panic，但清理不彻底）且句柄未释放 → RED。
8. `test_extraction_cleanup_releases_file_locks_before_deletion_on_all_platforms` — 多分块写入中途失败，断言文件成功删除且无未释放句柄 → RED。
9. `test_salvage_records_failed_file_and_continues` — salvage 下断言 `ExtractStats::failed_files` 记录受影响文件、其余文件全部落地（覆盖新增字段，避免“字段无测试”）。
10. `test_max_total_bytes_aborts_extraction_with_security_error` — 显式 `max_total_bytes = Some(N)` 且累计超限时返回 `Security` 并触发分级清理（保护已成功文件）。
11. `test_decompressed_output_capped_at_16mb` — Zstd/LZ4 各构造一份“真实膨胀比 ≤100:1 但产物 >16MB”的合法载荷（例如 400KB → 20MB，比率 50:1，明确低于 100:1 阈值），断言被 `MAX_DECOMPRESSED_SIZE` 绝对上限拦截。当前上限为 256MB → RED。

**绿实现**：下沉 1MB/100:1/16MB 至 L2（严格遵循 §3.1 四条硬约束）；删除 8GB 常量与拦截；`release_handles()` + `created_directories` + 三步分级清理；`process_chunks` 增加声明体积累计校验；`salvage_mode` + `failed_files` + `corrupted_shards`。

**验证**：
```bash
cargo test -p era-engine --test extraction_budget_and_salvage_tests
cargo test -p era-codec --test decompression_ratio_tests
```

---

### 4.2 FIX-03 TDD

**测试文件**：`crates/era-engine/tests/prefix_tie_security_tests.rs`（新建）、`crates/era-volume/tests/security_dos_tests.rs`（**既有，追加用例**）

1. `test_reconcile_tie_with_malicious_declared_length_bounded` — 2 份声明 256MB、2 份声明 1MB 造成平局；断言解出分片上限 ≤ 16MB。当前平局返回 `None` → 回落信任 256MB → RED。
   - **落点裁决**：与既有单元测试 `crates/era-engine/src/erasure_scan.rs:143`（`test_reconcile_stripe_prefixes_returns_none_on_two_way_tie`）意图重叠——**保留**该单元测试（断言平局返回 `None` 的底层语义），**新增**集成本用例断言上层 `parity_bound` 有界，二者不得合并。
2. `test_read_raw_rejects_oversized_allocation` — `read_raw(offset, 17MB)` 断言 `IntegrityError` 含 `exceeds MAX_SHARD_SIZE`；当前透传 → RED。**落于既有 `security_dos_tests.rs`**。
3. `test_max_shard_size_constant_binding_and_dual_audit_compliance` — 静态检查 `reader.rs`/`repair.rs` 绑定 `era_common::MAX_SHARD_SIZE`，且 L0 常量 == 16MB。当前两文件为 256MB 且 L0 未导出 → RED。
4. `test_parity_tie_fallback_bound_is_max_shard_size` — 构造平局并驱动 `ErasureCodedBlockIterator`，断言**实际读取的分片长度上界**为 `MAX_SHARD_SIZE as u32`（而非回落 `shard_header.length` 的 256MB 声明值）。该用例闭合“常量改动本身不产生行为差异”的缺口。
5. **R37 新增** `test_erasure_scan_length_field_exceeding_max_shard_is_rejected` — 构造某数据分片长度字段 = `MAX_SHARD_SIZE + 1`；断言该候选前缀被整体剔除、`reconcile_stripe_prefixes` 不把它当合法候选（覆盖 §3.2 第 3 条第一句，当前无任何用例）。

**绿实现**：L0 常量与 re-export；`era-volume/src/lib.rs:16` 改 `pub use`；引擎三处按使用点绑定（`block_iter` 用 `u32`，`reader`/`repair` 用 `u64`）；`read_raw` 边界；`erasure_scan` 长度校验 + 交叉仲裁 + `parity_bound` 兜底上界；更新 `adversarial_audit_v3.rs:7` 文本断言。

**验证**：
```bash
cargo test -p era-engine --test prefix_tie_security_tests
cargo test -p era-volume --test security_dos_tests
```

---

### 4.3 FIX-04 TDD

**测试文件**：`crates/era-engine/tests/single_volume_catalog_redundancy_tests.rs`、`crates/era-volume/tests/footer_v2_tests.rs`（新建）

1. `test_footer_v2_serializes_and_parses_native_backup_catalog_fields` — `version()==2`、`has_backup_catalog()`、`backup_catalog_offset() > DATA_REGION_START`、`backup_catalog_block_id() == catalog_block_id + K`（`K` 由写端保证；仅 `K==1` 时等于 `+1`）→ 编译期 RED。
2. `test_single_volume_primary_corruption_healed_via_native_footer_v2_pointer` — 覆写 `catalog_offset` 处 16 字节后 `load_catalog()` 仍成功且条目数一致。**注意**：工作区**不存在** `EraError::CorruptedArchive`，红测试须绑定 `CorruptedHeader`/`IntegrityError`/`Deserialization` 之一。
   - **R38 补充断言**：自愈后必须**再次**校验 `manifest.catalog_commitment`——即断言“备份字节与主 Catalog 同源”。构造方式：篡改备份块载荷 1 字节后断言 `load_catalog()` 失败，证明完整性校验未被绕过。
3. `test_multi_block_catalog_backup_healed_via_native_pointer_without_cold_scan` — `K=2` 且 Primary 首块损坏；断言经 backup 指针顺序装配 2 块成功，全程不触发 `scan_for_typed_blocks(BlockType::Catalog)`（可用测试内计数器/`tracing` 捕获证明）。
4. `test_single_volume_repair_heals_primary_from_native_backup_pointer` — 破坏 Primary 后 `repair_archive` 使 Primary 恢复有效。
5. `test_generic_writer_finalize_produces_native_footer_v2_backup_catalog` — `GenericArchiveWriter::finalize` 产出合法 v2 backup 指针。**R37 强化**：该用例必须与 #2 一样断言**条目数一致**，因为该写者当前完全无备份（`writer.rs:3533-3550`），红→绿跨度最大。
6. `test_footer_v2_accepts_backup_flag_and_rejects_aliased_offsets` — 合规 v2 字节流白名单放行；别名（偏移或块 ID 相同）流断言 `CorruptedFooter` 含 **`must differ`**（仅此一条，禁 `||` 二选一）。
7. `test_checkpoint_delete_preserves_manifest_and_backup_catalog_pointers` — 清除 checkpoint 后断言 `checkpoint_offset/block_id == 0` 且 `manifest_offset/manifest_block_id/backup_catalog_offset/backup_catalog_block_id` 与原始值相等。当前 builder 重组丢失 → RED。
8. `test_footer_v2_rejects_overlapping_catalog_and_backup_catalog_regions` — `catalog_offset=5000, catalog_size=4000` 与 `backup_catalog_offset=7000` 区间相交；断言 `CorruptedFooter` 含 `physically overlap`。当前只校验离散不等 → RED。
9. `test_assembly_rejects_non_contiguous_block_span_for_k_gt_1` — `K=2` 且主区间终点 > 备区间起点时，装配阶段断言 `validate_contiguous_disjoint_block_span` 报错（覆盖 Footer 层无法承诺的全区间互斥）。
10. **R37 新增** `test_rotation_preserves_catalog_and_backup_block_id_allocation_law` — 触发 `precheck_and_rotate_if_needed` 后断言主块 ID 集合 = `[C..C+K-1]`、备块 ID 集合 = `[C+K..C+2K-1]` 且两集合不交。该用例把 §3.3 第 2 条“轮转后 ID 稳定”的推理固化为回归保护（当前无任何用例）。
11. **R38 新增** `test_single_volume_non_erasure_archive_writes_backup_catalog` — 卷数=1 且 `config.erasure == None`；断言卷内存在第二份 Catalog 且 Footer v2 指针可达。当前 `erasure_enabled()` 为假 ⇒ 无备份 → RED。

**绿实现（R39/D3 已剔除块头自描述项，`reserved2`/`BlockHeader::VERSION`/`SIZE` 均不动）**：Footer v2 字段重构 + `FOOTER_VERSION=2` + **严格版本校验** + `SUPPORTED_FLAGS` + `validate_disjoint_regions` + `validate_offset_above_header("backup_catalog_offset", ..)` + 非别名 + `validate_contiguous_disjoint_block_span`；`clear_checkpoint`/`with_cleared_checkpoint` 改造 `checkpoint.rs`；写端三处落点（`writer.rs` 主路径 + `volume_stage.rs` 回收 `_backup_location` + `GenericArchiveWriter`）；读端 O(1) 自愈 + `catalog_commitment` 复校；`repair.rs` 结构化自愈（在 `erasure_data_end` 循环之外）。

**验证**：
```bash
cargo test -p era-volume --test footer_v2_tests
cargo test -p era-engine --test single_volume_catalog_redundancy_tests
```

---

### 4.4 FIX-05 TDD

**测试文件**：`crates/era-engine/tests/multi_volume_recovery_tearing_tests.rs`、`bins/era-cli/tests/multi_dot_volume_exclusion_tests.rs`（新建）、扩展 `self_inclusion_test.rs`

1. `test_recovery_manager_truncates_all_volumes_cooperatively` — 4 卷各追加 64KB 悬挂数据；断言全部卷长收敛到 `committed_ends[i]`。当前仅 Volume 0 被截 → RED。
2. `test_recovery_truncation_reverse_order_crash_idempotent` — 从卷完成后中断，重启重跑应平稳完成 → RED。
3. `test_recovery_without_manifest_fails_closed_strictly` — `truncate_to_checkpoint_with_manifest(None)` 断言 `IntegrityError` 含 `missing authoritative ArchiveManifest` → RED。
4. `test_recovery_dynamic_discovery_when_header_total_volumes_is_zero` — `total_volumes == 0` 但磁盘存在 `.era.001/.002`；断言探测出 3 卷并协同截断 → RED。
5. `test_recovery_truncate_to_checkpoint_ast_and_spawn_blocking_guard` — 保持 `adversarial_audit_v2.rs:270-277` AST 断言 + 运行时 Fail-Closed 强类型断言。
6. `test_checkpoint_delete_clamps_length_and_clears_bits` — **三条断言同时成立**：①（红点）`set_len(committed_end)` 后调用 `delete()`，文件长度必须**保持** `committed_end`——当前 `delete()` 按 `file_len - 128` 重新落盘 Footer、会把文件继续截短 → RED；② `delete()` 后偏移 4096 处的 Backup Footer 判定 `version/flags/checkpoint` 均已清空（防“空操作也通过”）；③ 阶段 2 完整序执行后最终长度 == `committed_end + 4224` 且 `committed_end-128..committed_end` 用户数据哈希不变。
   - **取代旧“序 A/序 B”用例**：旧表述允许“截断事务重建尾部”与“`delete()` 按 `file_len-128` 写回”并存，同一用例在两种实现下红/绿不确定，违反因果精准。现行契约唯一：`delete()` **绝不改长度**，尾部重建只由截断事务完成（§3.4）。
7. `test_multi_volume_discovery_with_multi_dot_filenames` — 归档 `test_archive.tar.era` 生成 `.era.001/.002`；断言探测成功并协同截断。当前 `multi_volume.rs:311` 折叠为 `test_archive.era.001` → RED。
8. `test_add_path_excludes_own_multi_dot_volume_files`（**落于既有 `self_inclusion_test.rs`**）— 输出名 `foo.tar.era` 且输入含输出目录，断言归档不含自身卷文件。当前 `writer.rs:1571/1573` 自排除集合为 `foo.era.001` → RED。
9. `test_cli_create_excludes_own_multi_dot_volume_files` — 落于 `bins/era-cli/tests/multi_dot_volume_exclusion_tests.rs`，覆盖 `commands.rs:456/458` 的 CLI 自排除路径（与 #8 同因、不同实现点）。
10. `test_explicit_committed_ends_reject_non_contiguous_sequences` — 显式传入 `committed_ends`（长度 N=2）而磁盘仅存在 `.era.000/.era.002` 时，恢复路径必须判定损坏并 **Fail-Closed**，不得据“N=2 ⇒ 存在 0/1”而误判 Volume 1 完整。
11. **R38 新增** `test_cli_repair_force_without_manifest_fails_closed` — 对无 Manifest 归档运行 `era repair --force`，断言以 `missing authoritative ArchiveManifest` 失败且**未发生任何物理截断**（比对运行前后各卷长度）。覆盖 §3.4 射程第 2 处（`commands.rs:1249-1254`），当前该分支会静默走 `truncate_to_checkpoint()` → RED。
12. **R38 新增 / R39 定稿** `test_reader_rejects_manifestless_archive_reads_fail_closed` — 对无 Manifest 归档（移除/破坏 Footer 的 `manifest_offset`）发起任意读取，断言 `check_read_bound` 返回 `InvalidFormat` 且子串为 `missing authoritative ArchiveManifest`，**不返回任何数据**。**R39/D1 已定死方向：不得再改为“断言宽松行为”**。覆盖 `reader.rs:1232-1236`。
13. **R39/D1 新增** `test_archive_declaring_manifest_but_unloadable_still_fails_closed` — 回归守护：卷声明有 Manifest（`footer.manifest_offset != 0`）但 Manifest 块整体损坏时，仍返回 `IntegrityError`（`reader.rs:1118-1122`）。该用例锁死“**有但损坏** 严于 **没有**”的语义不倒置。
14. **R40/W22 新增** `test_block_iterator_rejects_manifestless_reads_fail_closed` — 覆盖 D1 的**第二处**：不经过 `check_read_bound`，直接以 `committed_ends = None` 构造 `ErasureBlockIterator`/`MultiVolumeSessionBlockIterator` 并推进一次，断言 `check_commit_horizon_for_sequence`（`block_iter.rs:77-79`）返回 `InvalidFormat` 且子串为 `missing authoritative ArchiveManifest`（与 #12 同子串、不同变体），且迭代器**不产出任何块**。当前该分支 `return Ok(())` → RED。**该用例与 #12 不得合并**：两者分别锁死 `reader.rs` 与 `block_iter.rs` 两个独立实现点，合并会让“只改一处”也能通过。
15. **R40/W23 新增** `test_truncate_to_checkpoint_api_none_argument_fails_closed` — 覆盖三个 `None` 入口：① `RecoveryManager::truncate_to_checkpoint()`（`recovery.rs:345`，即 `_with_manifest(None)`）；② 测试内 `_with_cancel_flag_and_manifest(flag, None)`（`recovery.rs:846` 同型）；③ CLI `repair --force` 的无 Manifest 分支（`commands.rs:1254`，与 §4.4 #11 共用 CLI 门禁）。断言三者**全部**以 `missing authoritative ArchiveManifest` 失败且文件长度不变。该用例证明收口点落在**函数体**而非 CLI 层（若只在 CLI 拦截，①② 会漏过）。
16. **R40/W24 新增** `test_checkpoint_delete_preserves_manifest_and_length`（与 §4.3 #7 互补，此处加强制顺序断言）— ① 令 `set_len(committed_end)` 后调用 `delete()`，断言文件长度**保持** `committed_end`（当前 `:418/:460` 会写到 `committed_end-128`）→ RED；② 断言 `delete()` 后 `manifest_offset`/`manifest_block_id`/`backup_header_offset` 与调用前逐字段相等（当前 `Footer::builder` 链缺 `.manifest(...)` → 归零）→ RED；③ 断言偏移 4096 处的 Backup Footer 与末尾 Primary Footer 的 `last_checkpoint_*` 均已归零。该用例是 §3.4 阶段 2 的**启用门禁**。

**绿实现**：`era_volume` 内重写纯追加单射 `volume_path` 并替换 §3.4 表中 6 处缺陷点；`MAX_VOLUME_SCAN` 上移 L0 并三处共用（含 32→N 成本论证与容差语义决策）；`RecoveryManager` 三级发现 + 两阶段逆向截断（`delete()` 去职责化 + 对称尾部重建 + `committed_ends` 连续性校验）；Manifest SSOT Fail-Closed **读端 2 处（`reader.rs` + `block_iter.rs`）+ 恢复端函数体 1 处收口**，共 3 个实现点、4 个入口，禁止只改其一。

**验证**：
```bash
cargo test -p era-engine --test multi_volume_recovery_tearing_tests
cargo test -p era-engine --test self_inclusion_test
cargo test -p era-cli
```

---

### 4.5 FIX-06 TDD

**测试文件**：`crates/era-volume/tests/lenient_truncation_tests.rs`、`crates/era-volume/tests/deterministic_footer_tests.rs`（新建）

1. `test_open_lenient_truncation_allows_reading_prefix` — 尾部截断 64 字节 + `lenient_truncation: true` 应成功打开。当前无此选项 → 编译期 RED。
2. `test_strict_open_rejects_truncated_volume_without_options` — 默认 `open` 仍返回 `CorruptedFooter`。**该用例当前已通过，属回归守护而非红测试，不计入红清单验收。**
3. `test_lenient_truncation_clamps_data_region_end` — 断言 `reader.data_region().1 == physical_size`。当前未维护 `effective_data_end` → RED。**R39/D4 边界**：该用例只覆盖“Footer 可读但短于声明”；Footer 全失属 #9 的拒绝语义，两者不得合并断言。
4. `test_reader_rejects_corrupted_volume_without_floating_footer_scan` — 同时破坏 Primary（尾）与 Backup（4096）Footer，断言直接失败且**不存在**浮动扫描路径。
5. `test_volume_reader_recovers_via_backup_superheader_when_primary_corrupted` — 破坏偏移 0 处 64 字节；断言打开成功且卷配置一致。当前 `reader.rs:57` 提前阻断 → RED。
6. `test_lenient_truncation_handles_partial_trailing_block_gracefully` — 截断落在末块载荷中间；断言 `Err(EraError::TruncatedShard{..})`，并在 salvage 迭代中 `stats.corrupted_shards` 增加 1 后优雅结束。**R38 澄清**：该字段是 `ExtractStats::corrupted_shards`，其值必须**聚合自** `DecodedBlock::corrupted_shards`（`block_iter.rs:38`）；同一缺失事件不得被 `:1422-1432`/`:1449-1459` 的缺失槽位路径与新端际路径**各计一次**（用例须断言增量恰为 1）。
7. `test_erasure_coded_iterator_recovers_when_single_volume_truncated_with_lenient_options` — 4+2 归档截断 1 个校验卷；断言迭代器把该分片视为缺失、用存活分片完成重构、`corrupted_shards >= 1` 且无错误退出。
   - **事实澄清**：既有迭代器**已**把读取错误降级为缺失槽位（`block_iter.rs:1422-1459`），故本用例的 RED 来自 `lenient_truncation`/`effective_data_end` 缺失（编译期 Red）与卷尾边界失真，**不是**“迭代器崩溃”。
8. `test_truncated_volume_surfaces_targeted_diagnostic` — 断言截断场景产生可区分于介质损坏的定向诊断/统计，且错误仍含冻结子串 `Not enough shards for recovery`。
9. **R38 新增 / R39 定稿** `test_volume_without_any_footer_is_rejected_regardless_of_erasure_config` — 同时破坏 Primary（尾）与 Backup（4096）Footer；分别断言 `erasure.is_some()` 与 `erasure.is_none()` 两种配置下**均**返回 `CorruptedHeader`，且 `lenient_truncation: true` **也不**放行。该用例把 R39/D4 的裁决固化为断言（当前 `erasure.is_some()` 时 `open` 会继续 → RED）。覆盖 §3.5 末尾的 D4 裁决。
10. **R39/D5 新增**（属**扩展**、非空白覆盖）`test_erasure_iterator_reads_data_with_middle_volume_missing` — 单元层空洞映射**已有** `block_iter.rs:1991` `test_erasure_iterator_accepts_sparse_original_indices`（当前通过，守护 `vol_index_map == vec![Some(0), None, Some(1)]`）；本用例补的是**端到端**：4 卷真实写入数据后**删除中间卷**（保留 3 卷，满足 4+2 的 `M ≤ P`），断言仍能解出全部数据且分片按 `header().volume_id()` 落入正确槽位。**注意**：须提供 Manifest 才能进入读路径（否则被 D1 拦截）。**不得**把 1991 行的既有用例计入本方案的“新增红测试”数量。
11. **R40/W22 交叉引用** `test_block_iterator_rejects_manifestless_reads_fail_closed` 的**迭代器层断言落在 §4.4 #14**（本文件属 `era-volume`，该用例属 `era-engine`）；本节 #10 的端到端用例必须**显式提供 Manifest**，而 #14 必须**显式不提供**，两者构成“有 Manifest 可读 / 无 Manifest 失败关闭”的对照对，禁止互相改写为同一预期。

**绿实现**：`VolumeOpenOptions` + `open_with_options`；`effective_data_end` 与 `data_region()` 联动；`read_raw`/`read_typed_block` 端际收敛与 `TruncatedShard`；`open` 两阶段自愈；删除浮动扫描并裁决 `reader.rs:82-86` 分支；迭代器/`--salvage` 捕获并**聚合**既有计数；**同步处置 §2.2 #1–#3、#11**。

**验证**：
```bash
cargo test -p era-volume --test lenient_truncation_tests
cargo test -p era-volume --test deterministic_footer_tests
```

---

### 4.6 FIX-07 TDD

**测试文件**：`bins/era-cli/tests/directory_tree_and_symlinks_tests.rs`（新建）

1. `test_empty_dirs_and_symlinks_preserved_in_roundtrip` — 普通文件 + 空目录 + 0 字节文件 + 相对软链接往返 → RED。
2. `test_deep_nested_zero_byte_file_preserved_without_parent_dir_entry` — 仅含 `deep/nested/zero.txt` 且无显式目录条目 → RED。
3. `test_symlink_directory_traversal_rejected_on_extract` — 目标为 `../../escaped.txt` 或 `/etc/passwd`。
   - **事实边界**：既有 `enforce_output_containment`（`chunk_processor.rs:192-246`）已对**普通文件写入路径**做 canonicalize 容器校验；真实缺口是 (a) 归档不产出软链接条目（`writer.rs:1304` 注释跳过）、(b) 缺**解包前 `symlink_target` 密闭性校验**、(c) 缺**目标路径预存软链接的碰撞拒绝**。断言须写为“软链接条目未被归档”或“碰撞拒绝文案存在”。
4. `test_bottom_up_metadata_traversal_prevents_read_only_permission_deadlock` — 只读父目录（0444）+ 子文件 → RED。
5. `test_symlink_metadata_restore_does_not_dereference_target` — 软链接指向只读文件，断言目标权限/mtime 未被串改 → RED。
6. `test_all_empty_directory_and_zero_byte_archive_executes_phase_3_metadata` — 仅空目录 + 0 字节文件，断言 mtime 与权限被还原。当前 `reader.rs:1650` 提前返回 → RED。
7. `test_extraction_rejects_preexisting_symlink_collision_and_escape` — 目标目录预置 `plant -> /tmp`，归档含 `plant/file.txt`；断言 `Security` 含 `Pre-existing symlink collision` → RED。
8. `test_directory_metadata_restore_does_not_open_write_handle` — 目录条目在 Phase 3 断言**未**以写模式打开（现行 `reader.rs:1792` 对目录会命中 `EISDIR`）。
9. `test_symlink_target_pointing_outside_output_dir_rejected` — 归档含指向 `../outside` 的软链接，断言 Phase 2 以 `Security` 拒绝（覆盖 §3.6 第 3 条的密闭性校验）。
10. **R37 新增** `test_cli_dot_ignore_file_is_honored` — 目录含 `.ignore` 排除 `secret.txt`；断言归档不含 `secret.txt`（覆盖 §3.6 第 1 条“`.ignore` 已接入”的能力边界，防止帮助文本与实现漂移）。

**绿实现**：§3.6 全部内容（含第 0 步依赖边与 `filetime`/`libc` 依赖裁决）；移除 `reader.rs:1650` 守卫但**不改** `has_pending()` 本体；`apply_extracted_metadata` 按类型分派 mtime/xattr/permissions。

**验证**：
```bash
cargo test -p era-cli --test directory_tree_and_symlinks_tests
cargo test --release --workspace
```

---

### 4.7 FIX-08 TDD

**测试文件**：`bins/era-cli/tests/cli_governance_and_security_tests.rs`（新建）

1. `test_repair_missing_volume_suggests_extract` — 单个用例内断言 stderr **同时**含 `Archive is missing expected volume files`、`in-place repair cannot regenerate entire volume files on disk` 与 `directly run 'era extract'` → RED（同时最小改写 `commands.rs:2178` 的断言）。
2. `test_linux_process_disables_coredump` — 运行 `era --print-dumpable` 断言 stdout 严格为 `"0"`；`#[cfg(target_os = "linux")]` 门控，非 Linux 显式跳过且 CI 可见。当前无该出口 → RED。
   - **否决方案**：靠真实崩溃后检查 core 文件（受 `ulimit -c`/`RLIMIT_CORE`/`core_pattern`/容器配置影响，环境依赖脆弱）。**不得**把“用例不存在”表述为“转绿”。
3. `test_cli_help_examples_contain_no_plaintext_passwords` — 全命令 `--help` 不含 `-p secret` → RED。**边界声明**：该用例只覆盖 clap 渲染面；`main.rs:9` 的 crate 级 `//!` 示例不在此面内，需人工同步（§3.7 第 2 条），不得据此宣称“文档面已全覆盖”。
4. `test_toolchain_single_source_of_truth` — 断言 `rust-toolchain.toml`、`[workspace.package] rust-version` 与 CI 三处 `dtolnay/rust-toolchain` 的显式 `toolchain:` 输入三者一致 → RED。

**绿实现**：文案与断言同步改写；`--print-dumpable`；帮助示例替换与 crate 级注释同步；工具链单一来源（§3.7 第 4 条）。

**验证**：
```bash
cargo test -p era-cli --test cli_governance_and_security_tests
```

---

### 4.8 FIX-09 TDD

**测试文件**：`crates/era-engine/tests/archive_writer_modular_tests.rs`、`tests/writer_builder_tests.rs`、`tests/archive_writer_tests.rs`（迁移落点）

1. `test_modular_writer_builder_assembly_and_pipeline_execution` — 断言可经独立模块装配并完成创建全流程（编译期 RED）。
2. `test_migrated_writer_test_suites_pass` — 断言迁移后的 813 行测试等价通过。
3. `test_archive_writer_public_api_surface_frozen` — 断言 §3.8 的 **10 个**既有公开方法签名存在（`include_str!` 静态检查或编译期引用），防止拆分误删/改名；并断言 FIX-07 新增的两项接口（`add_symlink` + 空目录条目注册）为**新增**且未覆盖任何既有名字。

**绿实现**：四阶段拆分；门面 ≤500 行（`wc -l` 可复现）；`collect_files_async` 先迁移后删除。

**验证**：
```bash
cargo test -p era-engine --test archive_writer_modular_tests
cargo test --release --workspace
```

---

### 4.9 跨 FIX 前置决策（不得留白）

| 决策项 | 裁决 |
| :--- | :--- |
| FIX-07 依赖边 | **经 `era-engine` 再导出**（唯一选项，备选不采用） |
| Footer 全失时的 open 行为 | **已裁决（R39/D4）**：无条件 `CorruptedHeader`；`erasure_enabled` 知情放行分支删除，`lenient_truncation` 不放行“两 Footer 全丢”。详见 §3.9 D4 |
| FIX-07 软链接时间戳实现 | **已裁决（R39/D2）**：把 `filetime = "0.2"` 提升为 `era-engine` 常规依赖，用 `filetime::set_symlink_file_times`；**不采用** `libc::utimensat`（避免在 L4 引入 FFI/`unsafe`）。详见 §3.9 D2 |
| FIX-07 空目录接口命名 | 用 `add_directory_entry`（与 `add_symlink` 成对）。R38 已撤销“`add_directory` 被占用”的误判：全仓无 `fn add_directory`；该名并非禁用，只是本方案选更显式的名字 |
| coredump 探测出口形态 | 隐藏参数 `era --print-dumpable` + Linux 门控 |
| `MAX_VOLUME_SCAN` 是否入 L0 | **是**：`era-common` 新增权威常量，`multi_volume.rs:22`、`reader.rs:197`、`RecoveryManager` 三处共用，并附 32→N 成本论证 |
| 恢复发现容差 vs 读端容差 | **已裁决（R39/D5）**：读端 `max(parity+1, 2)` **保留**（定位为“未知卷数时的扫描终止条件”；空洞安全由 `vol_index_map` 保证，`block_iter.rs:392-398`），恢复端**严格连续**；两套语义须在注释与文档写明适用域。详见 §3.9 D5 |
| `committed_ends` 显式列表 vs 观测序列不一致 | **一律 Fail-Closed**（拒绝截断），不得按长度推断缺失卷内容（§4.4 #10） |
| `delete()` 去职责化 | **强制，且为截断事务的启用前置（R40/W24）**：`delete()` 绝不改变文件长度、必须保留 `manifest_*`/`backup_catalog_*`/`index_*`；尾部重建只由截断事务完成（§3.4、§4.4 #6/#16）。改造与其红测试合入**之前**，禁止启用阶段 2 |
| 无 Manifest 兼容回退射程 | **已裁决（R39/D1 + R40/W22）**：**读端 2 处 + 恢复端函数体 1 处收口**——`recovery.rs:391` 删除回退（判定置于函数体 `None` 分支，覆盖 `:345`/`:846` 与 CLI）；`commands.rs:1247-1257` 收敛为单一报错分支；`reader.rs:1234-1236` 改 `InvalidFormat`；**`block_iter.rs:77-79` 同改 `InvalidFormat`**。**读路径不再接受无 Manifest 归档**，四个实现点缺一不可。详见 §3.9 D1 与 §1.2.1 W22/W23 |
| 解压比分母 | Zstd = 压缩载荷总长度；LZ4 = `data.len() - 4` |
| `Footer::clear_checkpoint` 签名 | `(&mut self)` 与 `with_cleared_checkpoint(&self) -> Self`（冻结） |
| 备份 Catalog 完整性 | 备份必须与主 Catalog **同源**，复用 `manifest.catalog_commitment` 校验；若要独立编码路径，必须先扩展 Manifest 承诺字段 |
| `backup_catalog_offset` 结构下界 | **保留** `validate_offset_above_header("backup_catalog_offset", ..)`（与另五处同类校验对齐），不得删除 |
| 多点号自排除新用例落点 | 扩展 `self_inclusion_test.rs` + 新增 `bins/era-cli/tests/multi_dot_volume_exclusion_tests.rs`（§4.4 #8/#9） |
| `EraError::TruncatedShard` | **可直接新增**：实测全仓不存在对 `EraError` 的穷尽 `match`，编译影响面为零；按既有变体风格补 `#[error(...)]` Display，禁止退化为字符串拼接 |
| 版本校验 | Footer v2 落地时必须**严格等于 2**，v1 解析分支直接删除 |
| 工具链单一来源 | `rust-toolchain.toml` 为准，`rust-version` 只能声明已验证版本（§3.7 第 4 条） |
| `BlockHeader::reserved2` 承载块 ID | **已裁决（R39/D3）：不采用，整项撤销**。`reserved2` 保持保留语义；`BlockHeader::VERSION = 1`、`SIZE = 16` 不变；任何块级自描述需求须另立格式提案（`u64` 宽 + 版本推进 + 68 处偏移点同步）。详见 §3.9 D3 |

---

## 五、 分阶段实施路线图与验收门禁

### 5.1 里程碑

| 里程碑 | 内容（串行顺序） |
| :--- | :--- |
| **M1 严重缺陷阻断 (P0)** | FIX-01（移除 8GB 累计误杀；解压比防御下沉 L2 并收敛 16MB）→ FIX-02（分级清理保护健康文件；释放句柄；自底向上清理目录）→ FIX-03（L0 权威常量上移；平局兜底上界；`read_raw` 边界） |
| **M2 恢复韧性与元数据 (P1)** | FIX-04（单卷 Catalog 镜像双写 + Footer v2 原生自愈；写端三处落点）→ FIX-05（多卷协同截断：Manifest SSOT 三处 + 路径派生 SSOT + 对称卷尾）→ FIX-06（软截断容忍、双确定性头尾自愈、废除浮动扫描）→ FIX-08a/b/e（缺失卷引导、明文密码修正、coredump 门禁） |
| **M3 架构治理与能力补齐 (P2)** | FIX-07（接线 `DirectoryScanner` + 全文件类型往返；依赖边与 `filetime`/`libc` 裁决）→ FIX-09（`writer.rs` 领域拆分）→ FIX-08c/d/f（工具链单一来源、Fuzz 登记、运维手册） |

### 5.2 交付总门禁（每个里程碑合入前必须全绿）

```bash
cargo fmt --all -- --check && \
cargo clippy --all-targets --all-features -- -D warnings && \
cargo test --release -p era-cli && \
cargo test --release --workspace
```

**基线可编译性（R37 实测）**：`cargo test --release --workspace --no-run` 在当前树 **exit 0**，全部测试目标可编译。测试条目计数仅供量级参考（实测 `#[test]` 2254 + `#[tokio::test]` 472 = **2726**，`#[ignore]` **4**）；**门禁只认 CI 实跑输出**。

### 5.3 设计论证（**非门禁依据**）

以下为评审用的设计自洽性论证，**不属于验收断言**：

- **对称物理布局不变量**：正常终结与崩溃截断后，卷结构均为 `[SuperHeader 4096B][Backup Footer 128B][Data][Backup SuperHeader 4096B][Primary Footer 128B]`，总长 `= committed_end + 4224`；Primary Footer 恒位于 `committed_end + 4096 > data_end`，故 `file_len - 128` 定位必命中合法槽。
- **逆向截断幂等性**：逆向提交序使全局提交点唯一收敛于主卷 0；从卷执行期间断电时主卷 checkpoint 未清除，重启可无限次幂等重跑（`set_len` 对已收敛卷恒为 no-op）。
- **解压内存有界性**：任意输入下，单块**流式解压产物** ≤ `min(100 × 压缩载荷长度 + 64KB, 16MB)`；该上界只覆盖 L2 单块，L1 分片（≤16MB）与 block（≤64MB）上界正交并存。
- **Footer v2 自愈复杂度**：主备均驻留确定性偏移，自愈读取仅取决于 Catalog 规模 `O(K)`，与归档总量无关。**注意**：既有实现本就**没有** Catalog 全卷冷扫描（`scan_for_typed_blocks(BlockType::Catalog)` 零调用）；但 `era-index` 对 `BlockType::IndexManifest` 的冷扫描是在役降级路径，本方案不主张删除它，也不主张“终结 O(M) 退化”。
- **多卷路径单射性**：纯追加式 `f(p, s)` 对 `(p, s)` 单射且逆映射唯一，消除 `with_extension` 的多点号折叠歧义。
- **主备 AAD 正交性**：`block_id` 严格不等 ⇒ 子密钥与 AAD 正交，密文不可互相伪造/重放；同源明文 ⇒ `catalog_commitment` 对主备同时成立。
- **柯西 RS 满秩自愈**：`(D, P)` 条带中任意 `M ≤ P` 个分片缺失时，存活分片子矩阵在 `F_{2^8}` 上满秩可逆。

### 5.4 机械判据（封板前逐条勾选）

> **判据自检纪律**：每条判据都必须在**目标态**试跑确认“修好后通过、修好前失败”。凡“修好后仍失败”或“修好前已通过”的判据一律视为无效门禁。括号内为本轮在当前树的实测结果。
> **一次性计数核对命令**（用于验证下面注释里的“实测 N 处”）：
> ```bash
> grep -rn "256 \* 1024 \* 1024" crates/*/src bins/*/src | wc -l                                     # 实测 4（本判据唯一权威口径）
> grep -rn 'with_extension("")' crates/era-volume/src bins/era-cli/src | wc -l                        # 实测 2
> grep -rn 'with_extension' crates/era-engine/src/writer.rs | wc -l                                   # 实测 2（1571/1573）
> grep -rn 'with_extension(format!("era' crates/era-volume/src crates/era-engine/src bins/era-cli/src | wc -l  # 实测 4
> grep -rn 'try_floating_footer_recovery' crates bins | wc -l                                         # 实测 2
> grep -rn 'with_extension' crates/era-volume/src/lib.rs | wc -l                                      # 实测 2（72/75）
> grep -rn 'const MAX_SHARD_SIZE' crates/*/src | grep -c '256 \* 1024 \* 1024'                        # 实测 3（三处 const 定义行）
> grep -rn 'MAX_SHARD_SIZE' crates/*/src | grep -c '256 \* 1024 \* 1024'                              # 实测 4（另含 reader.rs:1445 的使用点）
> grep -rn 'const MAX_SCAN: usize = 32' crates/*/src | wc -l                                          # 实测 1
> grep -rn 'scan_for_typed_blocks' crates/*/src bins/*/src | wc -l                                    # 实测 10（定义 1 + 生产 3：index/reader.rs 462/493/897 + 测试 4：writer.rs 3076/3080/3197/3201 + 注释 2）
> grep -rn 'scan_for_typed_blocks' crates/*/src bins/*/src | grep -v 'writer.rs' | wc -l              # 实测 6（剥掉 writer.rs 的 4 处测试调用 + 2 处注释后的生产面）
> grep -rn 'scan_for_typed_blocks(BlockType::Catalog)' crates/*/src bins/*/src | wc -l                # 实测 0（判据 12 的谓词）
> grep -rn 'backward compat' crates/*/src bins/*/src | wc -l                                          # 实测 25 行 / 9 文件（其中可执行语句 1 处：reader.rs:1123 的 debug! 日志）
> grep -rn 'backward compat' crates/*/src bins/*/src | grep -v ':[0-9]*: *//' | wc -l                  # 实测 1（唯一非注释行；禁止据此宣称“存在兼容分支”）
> grep -rn 'BlockHeader::SIZE' crates/*/src bins/*/src | wc -l                                        # 实测 68（D3 的唯一权威口径；不限目录为 82）
> grep -rn 'BlockHeader::SIZE' crates | wc -l                                                         # 实测 82（含 tests/benches，禁止用于 D3 举证）
> ```
>
> **计数谓词必须与注释同口径**：`grep -c '256 \* 1024 \* 1024'` 与 `grep -c 'const MAX_SHARD_SIZE'` 得到 3 或 4 的差别只来自 `reader.rs:1445` 这一**使用点**（`if header.length as u64 > MAX_SHARD_SIZE {` 位于同一行块内）。判据 1 与判据 6 均以“字面量行数”为准（4 → 0），不得混用两种谓词后互相宣称。

```bash
# 1) 工作区 src 中不得再有 256MB 字面量（实测 4 处）                          [当前: 失败]
#    归属：FIX-01 负责 compression.rs:8（MAX_DECOMPRESSED_SIZE），FIX-03 负责引擎三处。
#    两条 FIX 必须同时完成，本判据才可勾选；任一条单独完成都不足以封板。
! grep -rn "256 \* 1024 \* 1024" crates/*/src bins/*/src

# 2) 浮动尾部扫描彻底消失（含测试）（实测 2 处）                              [当前: 失败]
! grep -rn "try_floating_footer_recovery" crates bins

# 3a) volume/CLI 写端不得用 with_extension("") 做卷名派生（实测 2 处：multi_volume.rs:311 / commands.rs:456）  [当前: 失败]
! grep -rn 'with_extension("")' crates/era-volume/src bins/era-cli/src
# 3b) 字面量替换（覆盖 lib.rs:72 的 with_extension("era")）（实测 1 处）      [当前: 失败]
! grep -rn 'with_extension("era"' crates/era-volume/src
# 3c) format! 形式卷名替换（覆盖 writer.rs:1573 / commands.rs:458/1811/1847）（实测 4 处）  [当前: 失败]
! grep -rn 'with_extension(format!("era' crates/era-volume/src crates/era-engine/src bins/era-cli/src
# 3d) engine 写端自排除不得再出现 with_extension（覆盖 writer.rs:1571/1573 与多卷探测）    [当前: 失败]
! grep -n 'with_extension' crates/era-engine/src/writer.rs
# 3e) **文本判据的能力边界（必须如实声明）**：lib.rs:75 的 with_extension(ext) 经变量间接传入，
#     3a–3d 均**无法覆盖**；清零宣告必须同时以如下位置判据 + 单元测试硬约束
#     `volume_path` 函数体内不得出现 with_extension。                        [当前: 失败]
! grep -n 'with_extension' crates/era-volume/src/lib.rs

# 4) Footer v2 不得再出现旧字段名（v2 落地后）                                [当前: 失败]
! grep -rn "backup_header_offset" crates/era-volume/src/footer.rs

# 5) 16MB 分片上限定义必须且只能存在于 L0 权威源（位置判据）                  [当前: 失败]
[ "$(grep -rlE 'pub const MAX_SHARD_SIZE: usize = 16 \* 1024 \* 1024;' crates/*/src)" = "crates/era-common/src/types/block.rs" ]

# 6) 非 L0 的 MAX_SHARD_SIZE 不得再绑定 256MB 字面量（判据 1 的 4 处中余 3 处常量 + 1 处使用点）  [当前: 4 → 目标 0]
[ "$(grep -rn 'MAX_SHARD_SIZE' crates/*/src | grep -c '256 \* 1024 \* 1024')" = "0" ]

# 7) 多卷扫描上限单一化（不得残留局部 MAX_SCAN = 32）                          [当前: 失败]
[ "$(grep -rn 'const MAX_SCAN: usize = 32' crates/*/src | wc -l)" = "0" ]

# 8) 在册兼容分支清除（只判代码路径；`backward compat` 在 recovery.rs 仅 1 处注释）  [当前: 失败]
! grep -rn 'backward compat' crates/era-engine/src/recovery.rs
grep -n 'has_manifest()' crates/era-engine/src/recovery.rs   # 必须保留：Fail-Closed 仍需该判定

# 9) 解压比分母语义：LZ4 必须剔除 4 字节前缀 + 填充稀释用例存在并转绿          [当前: 不适用→新增]
grep -q 'MIN_RATIO_CHECK_OUTPUT_BYTES' crates/era-codec/src/compression.rs
grep -q 'test_lz4_ratio_precheck_not_diluted_by_padding' crates/era-codec/tests/decompression_ratio_tests.rs

# 10) checkpoint.delete() 不得再按 file_len 推导写偏移（去职责化）            [当前: 失败]
! grep -n 'file_len - era_volume::FOOTER_SIZE' crates/era-engine/src/checkpoint.rs

# 11) 【R37 新增】Footer 的 backup_catalog_offset 必须保留结构下界校验          [当前: 不适用→新增]
grep -q 'validate_offset_above_header("backup_catalog_offset"' crates/era-volume/src/footer.rs

# 12) 【R37 新增】Catalog 冷扫描仍须为零调用（IndexManifest 冷扫描不在本判据射程内）  [当前: 通过]
[ "$(grep -rn 'scan_for_typed_blocks(BlockType::Catalog)' crates/*/src bins/*/src | wc -l)" = "0" ]
grep -q 'scan_for_typed_blocks(BlockType::IndexManifest)' crates/era-index/src/reader.rs   # 反向守护：不得顺带删除

# 13) 【R40/W22 新增】读端两处 None 放行分支必须同步消失（两处都必须命中）  [当前: 两处均失败]
#     13a reader.rs：`None => {` 之后的 5 行内不得再出现 `return Ok(())`
! sed -n '1232,1237p' crates/era-engine/src/reader.rs | grep -q 'return Ok(())'
#     13b block_iter.rs：`let Some(ends) = committed_ends else {` 之后的 3 行内不得再出现 `return Ok(())`
! sed -n '77,79p' crates/era-engine/src/block_iter.rs | grep -q 'return Ok(())'
grep -q 'fn check_read_bound' crates/era-engine/src/reader.rs                              # 反向守护：函数本体不得被删除
grep -q 'fn check_commit_horizon_for_sequence' crates/era-engine/src/block_iter.rs         # 反向守护：公共判定入口不得被删除
#     13c 且两处都必须已改为失败关闭（**不得复用 `Some(ends) if ends.is_empty()` 分支已有的
#         `InvalidFormat`**，否则即为重复计数/空转门禁）；谓词要求各自的新冻结子串恰好出现 1 次。
[ "$(sed -n '1233,1236p' crates/era-engine/src/reader.rs | grep -c 'missing authoritative ArchiveManifest')" = "1" ]
[ "$(sed -n '77,80p' crates/era-engine/src/block_iter.rs | grep -c 'missing authoritative ArchiveManifest')" = "1" ]

# 14) 【R40/W24 新增】checkpoint.delete() 保留 manifest 指针且不按 file_len 落 Footer  [当前: 失败]
grep -q 'manifest_offset' crates/era-engine/src/checkpoint.rs                              # 当前 0 命中 → 必须出现（Footer 重组链补 `.manifest(...)`）
! grep -q 'let primary_offset = file_len - era_volume::FOOTER_SIZE' crates/era-engine/src/checkpoint.rs
```

**无效判据与能力边界（严禁复活，且不得再犯）**

- ~~`[ "$(grep -rn 'MAX_SHARD_SIZE: usize = 16' crates/*/src | wc -l)" = "1" ]`~~ —— 与 FIX-03 互斥（整改后命中 0 处），属“修好即失败”。
- ~~`! grep -rn 'with_extension("")' crates/era-volume/src crates/era-engine/src bins/era-cli/src`~~ —— 实测命中 **3 处**（`multi_volume.rs:311`、`writer.rs:1571`、`commands.rs:456`），若把 `repair.rs:380` 的 `.era.bak` 变体也算入则为 4 处；原注释“实测 3 处”与谓词自相矛盾，且会误伤正当命名（V11）；已由 3a + 3d 取代。
- ~~`sed -n '1123p' crates/era-engine/src/reader.rs | grep -q 'backward compat'`~~ —— 该行与兼容分支无关，修好前已通过，属空转门禁（V12）。
- ~~`! grep -rn "backward compat\|legacy_support\|for backward" crates/*/src`~~ —— 实测命中 **26 行 / 10 文件**（`crates/*/src` 与加入 `bins/*/src` 后同为 26/10，因 `bins` 无命中；其中 `'backward compat'` 单项为 **25 行 / 9 文件 / 5 crate**，分布 `aead_context.rs` 2 + `checkpoint.rs` 16 + 其余 7 文件各 1）；**25 行是注释/文档、1 行是可执行 `debug!` 日志**（`reader.rs:1123`），**零处可执行兼容分支**（`legacy_support` 单项为 **0**；并集多出的行来自 `for backward` 的 8 处重叠）。该判据既不充分（删注释即可通过）也不必要（误伤 `era-crypto`/`era-index`/`era-ingest`/`era-packing`）。真实兼容分支必须以**行为测试**证明移除；R41 已把“注释/日志”与“可执行兼容路径”显式分离（W25）。
- ~~“`scan_for_typed_blocks` 生产零调用”~~ —— **事实错误**（生产调用实测 **3 处**：`era-index/src/reader.rs:462` 的 `IndexManifest` 与 `:493`/`:897` 的 `IndexPage`；`writer.rs:3076/3080/3197/3201` 位于 `#[cfg(test)] mod tests` 内，不计生产）。该说法只对 `BlockType::Catalog` 成立，且必须写成“该类型的冷扫描为零调用”，不得推广到整个 API（W27）。
- ~~`[ "$(grep -rn 'BlockHeader::SIZE' crates | wc -l)" = "68" ]`~~ —— 谓词未限定目录，实测 `crates` 为 **82** 处（含 `tests/`、`benches/`）；D3 举证只允许用 `crates/*/src bins/*/src`（= **68**），两种谓词不得混用后互相宣称（W26）。

### 5.5 追溯与文档完备性清单

- [ ] **追溯完备性**：16 个唯一问题 ID（含 `SPEC-LOW-02` 保持现状项）全部在 §2.1 登记，无遗漏、无“18 项”旧口径。
- [ ] **锚点可复现**：§1.2/§1.3/§2.2 的全部行号结论在 `e4050a2` 基线下可用 `sed -n '<N>p'`/`grep` 复现；跨 commit 引用须重新核验。
- [ ] **冻结表一致**：§4 正文中每个 `msg.contains("…")` 子串都能在 §4.0 冻结表找到**唯一**对应行；FIX-08a 三条 stderr 子串须同现于一个用例。
- [ ] **编译期 Red 清零**：§4.0 缺口清单中的类型/字段/变体全部有真实实现，无 `todo!()`/`unimplemented!()` 残留。
- [ ] **测试资产同 PR**：§2.2 的 14 项清单与对应 FIX 同 PR 处理，不得以“后续清理”延期。
- [ ] **门禁可执行且双向可判**：§5.4 每条判据都在当前树与目标态各试跑一次，结论记于该节；无效判据不得复活；判据 1 的**跨 FIX 归属**（FIX-01 + FIX-03）必须同时满足。
- [ ] **依赖边与依赖等级决策落地**：§3.6 第 0 步按“经 L4 再导出”实现并编译通过；`filetime`/`libc` 裁决落地并登记（§2.2 #13）。
- [ ] **FIX-04 三写端覆盖**：`writer.rs` 主路径、`volume_stage.rs`（回收 `_backup_location`）、`GenericArchiveWriter::finalize` 三处均有备份块与 v2 指针，并由 §4.3 #5/#11 覆盖。
- [ ] **FIX-05 三处 Fail-Closed 同步（含 R40 的第二处读端）**：`recovery.rs:391`（函数体 `None` 分支收口）、`commands.rs:1247-1257`、`reader.rs:1232-1236`、**`block_iter.rs:77-79`** 结论一致（R39/D1 + R40/W22 定死为 `InvalidFormat`），由 §4.4 #3/#11/#12/#14/#15 与 §4.5 #11 覆盖；**四个实现点缺一不可**。
- [ ] **R40/W24 技术债前置**：`checkpoint.delete()` 完成“仅就地清位、绝不改长度、保留 `manifest_*`/`backup_catalog_*`/`index_*`”改造并与 §4.4 #16 红测试同 PR 先行落地；**在该改造合入之前不得启用 §3.4 阶段 2 截断事务**（判据 10/14 双绿为启用条件）。
- [ ] **R37–R41 数字口径一致**：`#[test]` **2254** + `#[tokio::test]` **472** = **2726**；CI 实跑 **2755 = 2737 passed + 0 failed + 18 ignored（4 源码级 + 14 doctest）**；`BlockHeader::SIZE` 的 68 处限定 `crates/*/src bins/*/src`；`backward compat` 的 25 行/9 文件与“1 行日志、24 行注释、0 可执行分支”表述一致；`scan_for_typed_blocks` 生产调用 **3** 处、`(BlockType::Catalog)` **0** 处。
- [ ] **R39 五项裁决落地**：D4 Footer 全失即 `CorruptedHeader`，且 `lenient_truncation` 不放行两个 Footer 全丢（§4.5 #9）；D5 读端容差保留 + 空洞安全，由 §4.5 #10 回归守护，恢复端严格连续；D1 读端 Fail-Closed **两处同步**（§4.4 #12 + #14、§4.5 #11）；D2 `filetime` 提升为 `era-engine` 常规依赖并在 `crates/AGENTS.md` 登记（§2.2 #13），登记时须如实写明其传递依赖含 `libc`；D3 已从 FIX-04 撤销块头自描述项，`reserved2`/`BlockHeader::VERSION`/`BlockHeader::SIZE` 保持不变（§3.9 D3）。
- [ ] **文档同步**：`crates/era-volume/src/AGENTS.md:30`、根 `AGENTS.md:45`（`~49` → 50）、`crates/era-volume/tests/AGENTS.md:10`（移除 `floating_footer.rs` 条目）已更新。
- [ ] **测试数量口径**：门禁以 CI 实跑输出为准；源码属性 **2726**（`#[test]` 2254 + `#[tokio::test]` 472）、源码级 `#[ignore]` **4**、CI 实跑 **2755 = 2737 passed + 18 ignored（14 doctest + 4 源码级）**——三层口径必须分别标注，不得互相替代，均不作断言。
- [ ] **本方案未实施任何代码改动**：`git status --porcelain -- crates bins Cargo.toml .github` 输出为空（实测 0 条）。**注意**：仓库级 `.gitignore` 通过 `~/.config/git/ignore:29` 忽略整个 `docs/`，本文件的修改在 `git status` 中**不可见**；如需纳入版本管理须 `git add -f`。
