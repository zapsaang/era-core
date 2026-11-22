# ERA-CORE Round 2 独立复核：engine 读路径 / repair / volume reader 修订

- 复核对象：工作树未提交的 round-1 修订（scope：crates/era-engine/src/reader.rs、crates/era-engine/src/repair.rs、crates/era-volume/src/reader.rs，以及 crates/era-engine/tests/round1_reader_fixes.rs、adversarial_audit_v2.rs、bins/era-cli/tests/cli_extreme_tests.rs）
- HEAD：b22a07e（feat_fly），全部修订均未提交
- 审计时间：2026-11-22 02:00–02:25 HKT
- 只读审计：未修改任何源码/测试/文档（本文件除外），未 commit
- 工具链：cargo 1.99.1 / rustc 1.99.1 / clippy 1.99.1 / rustfmt 1.99.1（按任务指定 PATH 导出），RUSTC 指向 nix rustc

## 0. 重要前提：审计期间工作树被并发修改（快照 A / B）

审计窗口内源码被其他协作者持续推进，本报告区分两个快照：

| 快照 | 时间 | 证据 |
|---|---|---|
| **A**（root 门禁开始时） | reader.rs 为 02:00 前版本，verify_active_primary_headers 是“digest 不匹配直接 Err” | 本审计 02:02 读取的 git diff；/tmp/era_ci_round1.log（root 全量门禁） |
| **B**（当前工作树） | reader.rs mtime 02:07:53、era-volume/reader.rs 02:07:47、round1_reader_fixes.rs 02:08:07 | stat 输出；当前 git diff 新增 adopt_authenticated_backup_header 恢复路径与 2 个新测试 |

**结论口径：** R2-01 是对快照 A 的 confirmed 回归（root 门禁确实因此变红），但快照 B 已在审计窗口内修掉了它；我用当前树重建后复跑验证通过（§7 E7c/E8）。R2-02/03/04 在快照 B 仍然成立。由于 root 的全量门禁在 02:00 启动、编译期间（02:04–02:09）源码仍在变化，/tmp/era_ci_round1.log 的结果不能直接作为快照 B 的合并依据（R2-06），**合并前必须在冻结树上重跑完整门禁**。

## 1. 结论摘要

共 9 条 finding：High 1（已在窗口内修复，需重跑门禁确认）、Medium 3、Low 4、Informational 1。

| 编号 | 严重度 | 维度 | 一句话 | 状态 |
|---|---|---|---|---|
| R2-01 | High | 正确性/可用性（回归） | 快照 A：verify_active_primary_headers 在 load_manifest 硬失败，使“可解析但摘要不匹配”的主头损坏从可由 backup header 修复变为 open 失败、repair 不可用；root 门禁红 | confirmed（快照 A）；快照 B 已修复，targeted 测试通过，待全量门禁 |
| R2-02 | Medium | 正确性/一致性 | 主/备 footer 都损坏但 floating footer 可恢复时，repair --force 打印“Archive successfully repaired!”且 rc=0，但根本不写回，verify 仍 Degraded → 永久不收敛 | confirmed（CLI e2e） |
| R2-03 | Medium | 安全（防御纵深）/正确性 | max_total_output_bytes 只累加“解码块字节”，而 process_chunks 会把同一 chunk 扇出写给所有引用文件；预算不能约束实际写盘量 | confirmed（代码）+ 影响为推断 |
| R2-04 | Medium | 规格符合性/安全 | 预算默认 None，CLI/config/README 无入口，era extract 无法 opt-in；verify 不复用同一预算（与 round-1 ENG-RC-01 建议第 2 条不一致）；CLI 只剩 per-block 256 MiB / per-file 100 GiB 限制 | confirmed（代码/CLI） |
| R2-05 | Low | 测试质量 | 新测试覆盖缺口：矩阵(多卷) footer 修复、repair dry-run 不写、floating footer 不可修、>8 GiB 默认解包可行、header 多字段 tamper 均无自动化测试（floating 缺口让 R2-02 逃逸） | confirmed |
| R2-06 | Low | 工程/证据链 | 审计期间源码并发变更，root 门禁快照与当前树不一致；门禁结果不可归因，必须冻结后重跑 | confirmed |
| R2-07 | Low | 性能 | open 每卷 +1 次 4 KiB raw read + BLAKE3，verify 每卷 +2×128 B，repair 重复读 footer 两次；无 benchmark，判定 benchmark-needed / likely small，非 O(n²) | benchmark-needed |
| R2-08 | Low | 正确性（修复不完整） | primary header 中参与 manifest 块 AAD 的字段（archive_id/epoch_id/volume_sequence）被可解析篡改后 manifest 解密先失败，adoption 恢复路径不可达：open 硬失败、repair 无法修复（备份头完好）；不属回归，但 LL-04 修复未闭环 | confirmed（CLI e2e） |
| R2-09 | Informational | 代码质量/API | (a) digest 的 local_header_digests fallback 实际不可达；(b) ExtractOptions 新增 pub 字段是对外部字面量构造的 source-breaking（无 #[non_exhaustive]） | confirmed（代码） |

**合并建议（详见 §6）：** 不建议整体回滚（修订方向正确，主路径 e2e 已验证可用）；**建议阻塞合并直到**：(1) 冻结树后完整门禁绿（含快照 B 的 cli_coverage_gap 回归）；(2) R2-02 修复（不可修必须返回错误而非成功）；(3) R2-03/R2-04 明确预算语义与入口（或文档化降级）；(4) 补 R2-05 所列测试。

## 2. 逐项核查矩阵（对应任务 (a)–(e)）

### (a) load_manifest 新增 verify_active_primary_headers 的兼容性/正确性

- **正常归档是否误拒：否（已验证）。** 单卷非 EC、单卷 EC、6 卷 EC、12 卷 EC（--max-volume-size 定长）基线 verify 均 rc=0/Healthy（§7 E1、E4）。digest 表下标与写入端一致：finalized_volume_header_digests() 按 volume sequence 顺序生成并校验连续性（crates/era-volume/src/volume_pool.rs:1060-1091），load_manifest 校验 by_sequence.len() == expected_volume_count（crates/era-engine/src/reader.rs:1491-1500），故正常归档的 get(seq) 不会缺失。
- **旧格式/legacy：** digest 表为空的 v8.1/无 manifest 归档在 reader.rs:1541 被跳过（if !best_header_digests.is_empty()），不会误拒。v8.1 布局本身已有 offset 4096 的备份 footer（crates/era-volume/src/footer.rs:18-20、crates/era-engine/tests/v81_adversarial_resilience.rs:3-27），故 footer 冗余校验不会把合法 v8.1 归档判为“缺备份”。
- **恢复头：** 与 verify_recovered_backup_headers（reader.rs:1569）处理的是互斥集合：header_recovered_from_backup()==true 的卷被新函数跳过，非恢复卷才做 primary 摘要校验，不存在双重认证/冲突。
- **误拒/不可恢复：见 R2-01/R2-08。** 关键问题是校验位置（load_manifest，即一切 open 的入口）而不是 verify()；快照 A 对“可解析但摘要不匹配”的损坏直接 Err，把可修复状态变成不可打开。快照 B 增加 adoption（reader.rs:2883-2925、crates/era-volume/src/reader.rs:268-277）后，config/padding/archive_id 之外的副本类 tamper 可“degraded + repair”，但 manifest AAD 字段类仍硬失败（R2-08）。
- **性能：见 R2-07。**

### (b) footer 冗余校验/修复

- **误报（正常 finalized 归档）：未发现。** 单/多卷、EC/非 EC、定长/增长卷基线 verify 全 Healthy，offset 4096 备份 footer 与主 footer 逐字节一致（写入端同一 footer_bytes 写两处：crates/era-volume/src/writer.rs:860-873）。
- **EC 卷：** 每卷均有 footer；verify_redundant_footers 对 footer()==None 直接跳过（reader.rs:2936-2939），多卷 EC 基线未产生 footer warning（E4），无假阳性。
- **checkpoint/增长卷：** 可增长卷 checkpoint 只写 offset 4096 的 footer（crates/era-volume/src/writer.rs:504-575），此时 footer_recovered_from_backup 会为 true → verify 报 “using backup footer；primary footer still requires repair”。这是 interrupted 状态下的文案不精确（还不存在 primary footer），但语义上确实“冗余不完整”，可接受；repair 的写回 guard 用 backup_header_offset() < DATA_REGION_START 拦住 checkpoint 布局（repair.rs:413-434），不会把 footer 写进数据区（写回安全，已代码核对；缺自动化测试）。
- **漏报：** 两个 canonical 副本都坏、靠 floating reverse-scan 恢复 footer 的卷，verify 能报 degraded（reader.rs:2934-2976：primary 读 size-128 得到垃圾 → primary.is_none()；backup 亦坏 → 第二条 warning），但 repair 只 warn! “both footer copies are unreadable; cannot restore” 并 Ok(vec![])（repair.rs:435-441）→ 见 R2-02。
- **写回安全性：** plan_volume_footer_repairs 以 primary 为 canonical；只有 backup_header_offset()+HEADER_SIZE == size-128 且 offset ≥ DATA_REGION_START 才把 backup 写回 primary（repair.rs:413-434），truncated/append 中状态会被跳过；apply_metadata_repair 固定 offset 写、不 truncate、sync_all（repair.rs:1309-1320）；dry-run 分支不写（repair.rs:659-683，实测 sha 不变，E2/E4）；单卷与矩阵路径都在 header 之后、catalog 之前应用（repair.rs:886-890、1520-1524）。
- **非 EC 仅 footer 损坏时 CLI repair 是否可用：是（已验证）。** --erasure none 单卷归档：备份 footer 清 0 → verify rc=1/degraded；dry-run rc=0 且文件未变；repair --force rc=0；verify rc=0；extract rc=0 数据一致（E3）。引擎层 round1_reader_fixes 的两个 footer 测试也覆盖 primary/backup 两种损坏与修复后 Healthy（E5）。注意 CLI 默认创建是 EC（6 卷），非 EC 需显式 --erasure none（bins/era-cli/src/main.rs:122-126）。

### (c) ExtractOptions 新字段兼容性、预算缺口、预算测试

- **仓库内兼容：** 所有构造点都已更新（17 处为 ExtractOptions::new(...)/builder 风格；唯一字面量 crates/era-engine/tests/third_audit.rs:1391 与 :1466 补了 max_total_output_bytes: None）。fmt/clippy -D warnings 绿（CI 日志 fmt_rc=0/clippy_rc=0）。外部 crate 用结构体字面量构造会被破坏，但仓库 pre-alpha（README: “API unstable, breaking changes expected”），可接受；建议补 #[non_exhaustive] 或 builder（R2-09）。
- **默认 None 的炸弹防护缺口（具体代码行）：** 现存的只有
  - 单块解压上限 256 MiB：crates/era-codec/src/compression.rs:7-8（MAX_DECOMPRESSED_SIZE），流式解压在 :66-70、非流式在 :141-148；
  - 单 shard/块读上限 MAX_SHARD_SIZE（crates/era-volume / block_iter）与 catalog 上限（reader.rs:50-52）；
  - 单文件声明大小 100 GiB：crates/era-engine/src/reader.rs:45，入口校验 :2214。
  
  这些是逐块/逐文件上限，不是总量：一个含 N 个 256 MiB 块的归档、或 100 GiB×M 个文件的归档，在默认 None 下可无限写盘/耗时（解压炸弹 DoS 的经典形态）。CLI era extract 用的是 ExtractOptions::new(output).overwrite(force)（bins/era-cli/src/commands.rs:955），没有任何预算设置；Extract 子命令参数（bins/era-cli/src/main.rs:167-217）也没有输出预算 flag，Create 亦无（:113-135），README 未提及。即：round-1 报的“8 GiB 全局限额导致大归档必然失败”被移除后，防御纵深没有替代入口（R2-03/R2-04）。
- **预算计数器语义（R2-03）：** reader.rs:2326-2372 累计的是 decoded.chunks 字节和（每块一次），然后才 context.process_chunks(...)。但 process_chunks 对同一 chunk 会循环写到 chunk_to_files 的所有引用者（crates/era-engine/src/chunk_processor.rs:385-470，packed/single/multi 三个分支同理），即实际写盘量 = Σ(chunk × 引用数)。因此显式预算下磁盘写入仍可被 dedup/fanout 放大 N 倍（攻击者可用 1 GiB catalog 造出百万级引用：MAX_CATALOG_PLAINTEXT_SIZE=1 GiB、MAX_CATALOG_CHUNKS=128，见 reader.rs:50-52）。这与 round-1 建议“把预算落到单块/单文件/解压比”或“按实际写盘计费”不完全一致。
- **预算测试真实性：见 (d)，结论：三/四条测试是真实行为断言，但未覆盖 fanout、多文件清理和大归档。**

### (d) 新测试质量

- **去源码字符串化方向正确：** adversarial_audit_v2.rs:105-168 把原来的 assert!(source.contains("MAX_EXTRACTION_MEMORY")) 替换为 v2_sec_11_extraction_output_budget_is_opt_in_and_enforced：真实创建归档、默认解包成功、Some(1024) 预算 Security 报错且 payload.bin 不存在（E6）。符合 round-1 ENG-RC-12/H-03 的整改方向。
- **round1_reader_fixes.rs（快照 B 共 5 个测试）：** 全部是行为断言（创建归档→损坏→open/verify/repair/extract→比较字节），无恒过、无空体。审计时跑过一次：3 passed（当时文件 3 测试；快照 B 扩到 5 个，新增 2 个 header recovery/fail-closed 测试，见文件 :239/:325）。
- **恒过/弱断言风险：** test_extract_with_iterator_default_has_no_global_output_cap 只用 2 MiB 数据，行为部分无法区分“无上限”与“8 GiB 上限”（字段 options.max_total_output_bytes.is_none() 的直接断言起辅助作用）；adversarial_audit_v2 的默认解包只 256 KiB，同样不能证明“>8 GiB 归档可解包”这一 round-1 核心验收。建议用注入 iterator 或小预算（1 MiB）做等价回归，避免 8 GiB 实数据。
- **flaky 风险：** 低。全部 TempDir/固定数据/fsync；cli_extreme_tests 用 stderr 子串 “degraded”/“footer” 断言依赖 CLI 文案（当前稳定，但文案再改会一起红，属可接受耦合）。cli_coverage_gap_tests::random_offset_corruption 的失败不是 flaky，而是快照 A 的确定性回归（corrupt offset=1000 命中可解析 header 区，见 R2-01）。
- **覆盖缺口（R2-05）：** 无矩阵 footer 修复自动化测试（我手工验证通过，E4）；无 dry-run 不写测试（手工 sha 验证，E2/E4）；无 floating footer 不可修场景测试（导致 R2-02 逃逸）；无 archive_id/epoch_id AAD 字段 tamper 测试（R2-08）；header adoption 测试只覆盖单卷（round1_reader_fixes.rs:239/325）；CLI 端只断言 verify 失败，没有 CLI repair footer 的 e2e（cli_extreme_tests.rs 两个 footer 测试只跑 verify）。

### (e) 性能回归

见 R2-07。静态分析：ArchiveReader::open 每卷新增 1 次 read_raw(0, 4096) + BLAKE3（reader.rs:2874-2881）；verify() 每卷新增 2 次 128 B read + Footer::from_bytes（:2928-2976）；repair 单卷先 volume_needs_footer_repair 再 plan_volume_footer_repairs，同两个 footer 各读两次（repair.rs:363-443），矩阵路径同样。LocalStorageReader::read_at 每次 try_clone()+seek+read（crates/era-storage/src/local.rs:277-289），所以是 N 次 dup/read 的常数开销。没有发现 O(n²)；对万卷归档每 open 多 1 万次 4 KiB 读/哈希，属“可能的小回归”，应按 round-1 建议补 benchmark 后再下结论。LL-04 建议本身已接受“每卷 4 KiB 读 + 一次哈希”的成本，因此不作为阻塞项。

## 3. Findings

### R2-01【High｜正确性/数据可用性（回归）】快照 A：主头摘要校验放在 open 路径，硬失败阻断“可恢复主头损坏”的 repair（root 门禁红）

- **确认程度：confirmed（快照 A：代码 + CLI e2e + root 门禁日志）；快照 B 已修复并由我复跑验证。**
- **file:line（快照 A）：**
  - 调用点：crates/era-engine/src/reader.rs:1541-1547（load_manifest 内，manifest 装载成功后）
  - 旧实现：verify_active_primary_headers 对 blake3(raw 4 KiB) != digest 直接 return Err(EraError::IntegrityError(...))（快照 A 的 reader.rs:2856-2891）
  - 被阻断的既有修复路径：crates/era-engine/src/repair.rs:547-627 plan_volume_header_repairs 对 primary_valid=false && backup_valid=true 写回 offset 0（:603-615），但它需要 ArchiveReader::open 成功（repair.rs:842）
- **机理：** 主头是 4096 B 定长，SuperHeader::from_bytes 只校验 magic/版本/字段范围（不认证）；protobuf 消息内除 magic/version 外的字段与 padding 被翻转后仍可解析。修改前的 VolumeReader::open 只有“解析失败”才回退 backup header；可解析的篡改会让 open 成功、随后在 load_manifest 里被新校验判死。由于 repair 第一步就是 open，**repair 无法运行**；而 backup header 完好且与 manifest digest 一致，本来可由 plan_volume_header_repairs 一键还原。
- **证据：**
  - E1（收尾测试）：cargo test --release --locked -p era-cli --test cli_coverage_gap_tests random_offset_corruption::test_repair_corruption_at_multiple_offsets 在快照 A 树上 FAILED，/tmp/era_ci_round1.log 记录：Error: Failed to open archive / Caused by: Integrity error: Volume 0 primary header bytes do not match the authenticated manifest header digest（该错误串是新 diff 新增的，因果明确）。
  - E7b（快照 A 二进制手工复现）：对 6 卷 EC 归档的 volume 0 在 offset 1000 反转 100 B → era verify rc=1、era repair --force rc=1（同一错误）；把 size-4224 处 4096 B 备份头复制回 offset 0 后 → verify rc=0、extract rc=0 且数据一致。**证明该损坏可修，且修复算法已存在，只是被 open 硬失败挡住。**
- **快照 B 的修复（审计窗口内）：** reader.rs:2883-2925 在摘要不匹配时，仅当 backup header 字节 == 同一认证 digest（且 seq 一致）才 adopt_authenticated_backup_header（crates/era-volume/src/reader.rs:268-277，同时置 header_recovered_from_backup=true），然后 verify 报 Degraded、repair 通过既有 recovered 分支写回 primary（实测 E8：verify rc=1/degraded、extract 成功、repair rc=0、verify rc=0）；两个新测试 round1_reader_fixes.rs:239/325 覆盖 recovery 与“双头都坏→fail closed”。
- **建议：**
  1. 保留快照 B 的方案，但把“adoption 失败→fail closed”视为仅当 backup 也不可认证时；同时按 R2-08 处理 manifest AAD 字段类。
  2. 增加多卷（volume seq > 0）与 CLI 端 repair 断言“primary 字节 == 原始认证头”的测试（当前只有引擎单卷测试）。
  3. 冻结树后重跑完整门禁确认 cli_coverage_gap 回归消失（root 门禁快照不含此修复）。

### R2-02【Medium｜正确性/一致性】主/备 footer 都损坏但可 floating 恢复时，repair 报“成功”却零修复，永不收敛

- **确认程度：confirmed（CLI e2e，快照 B 复现）**
- **file:line：** crates/era-engine/src/repair.rs:435-441（(None,None) 分支只 tracing::warn! 后 Ok(Vec::new())）；repair.rs:659-683（apply_footer_repairs 空列表直接 Ok）；repair.rs:892-899（非 EC 路径因 warnings-only 的 is_ok()==true 返回 Ok(RepairStats::default())，见 crates/era-engine/src/chunk_processor.rs:893-897 is_ok 只检查 errors/blocks_failed/files_incomplete）
- **机理：** volume 主 footer 被尾部垃圾掩埋 + offset 4096 备份 footer 清 0 时，VolumeReader::open 第 3 步 floating reverse-scan 找回 footer（crates/era-volume/src/reader.rs:55-85），footer_recovered_from_backup 仍为 false；volume_needs_footer_repair 返回 true；plan_volume_footer_repairs 的 primary/backup 均读不到有效副本 → 空计划；repair 流程此后仍走“成功”出口并打印 Archive successfully repaired!，而两份 canonical footer 从未写回。
- **证据（E9）：** 单卷非 EC 归档，append 512 B 垃圾并清 0 offset 4096：
  - repair --force → rc=0，stderr 含 WARN Volume ... both footer copies are unreadable; cannot restore footer redundancy 与 INFO Archive successfully repaired!
  - 随后 verify → rc=1（仍 degraded，warnings 含两种 footer 损坏）
  - 重复 repair 永远同样结果（不收敛）。
- **建议：** 两者都不可用时返回可识别的错误（如 EraError::IntegrityError("footer redundancy unrecoverable ...")）或 RepairStats 中的不可修状态，CLI 不得打印成功；更好的实现是：floating 恢复已给出可信 footer，可按其 data_end_offset 截断尾部垃圾后重写两份 canonical footer（需确认 append 中状态与固定长度卷布局）。补 e2e 测试（负例先行）。

### R2-03【Medium｜安全（防御纵深）/正确性】输出预算只计“解码字节”不计“实际写盘字节”，dedup/fanout 可放大绕过

- **确认程度：confirmed（代码路径）；利用影响为推断（需要恶意 catalog，属信任边界内输入）**
- **file:line：** crates/era-engine/src/reader.rs:2326-2372（预算只累加 decoded.chunks 字节和，检查在 process_chunks 之前）；crates/era-engine/src/chunk_processor.rs:385-470（同一 chunk 依 packed_chunks/single_chunk_pending/chunk_to_files 扇出写多个输出文件）；catalog 规模上限 reader.rs:50-52
- **机理/威胁场景：** max_total_output_bytes=B 的意图是“一次解包最多产生 B 字节输出”。实际计数是“解码块字节（去重后按块物理出现一次）”，而写盘量 = Σ chunk_size × 文件引用数。构造 catalog 让同一 64 KiB chunk 被 K 个文件引用：预算只增加 64 KiB，磁盘却写 K×64 KiB；K 受 catalog 1 GiB 明文上限约束，仍可达 10^4–10^6 量级。因此即使调用方显式 opt-in，解压/写盘放大 DoS 仍未受 B 约束；同时大 dedup 归档（合法场景）在显式预算下也可能被误杀（计数与真实输出不一致）。
- **建议：** 把预算计数移到写路径（ExtractionContext 在 write_all/lazy chunk 写时 reserve_output(len) 并累加实际写盘字节，失败即中止+清理），或在扇出前按 refs.len()×len 预扣；并显式文档化预算语义（解码量 vs 写盘量）。预算测试要覆盖“同一 chunk 被 2 个文件引用”的 fanout 场景。
- **备注：** 这不是本次修订新引入的计数方式（旧 MAX_EXTRACTION_MEMORY 也是同口径），但修订把该计数作为“炸弹防护”对外语义（reader.rs:75-86 注释），因此“修复是否成立”需要指出。

### R2-04【Medium｜规格符合性/安全】预算默认 None 且 CLI/config/文档无入口，verify 不复用；round-1 建议第 2 条未落实

- **确认程度：confirmed（代码 + CLI help）**
- **file:line：** crates/era-engine/src/reader.rs:75-86（默认 None 的文档）、:82/:106-109（字段/setter）、:2118/:2326（只在 extract_with_iterator 生效）；bins/era-cli/src/commands.rs:955（CLI extract 不设置预算）；bins/era-cli/src/main.rs:167-217（Extract 无预算 flag）；crates/era-engine/src/reader.rs:2735（verify() 无预算参数，与 extract 判定不一致）
- **机理/影响：** round-1 ENG-RC-01 建议“删除全程累计判断，或改为可配置总输出预算（在 CLI 帮助/文档中说明）；若确需总量预算，应从 verify 复用同一限制”。修订选择了“默认无限制 + Rust API 可选”，这是可用性上正确的方向，但：
  1. 唯一交付形态 CLI 无法 opt-in（era extract 无 flag、无 config 字段），README/CLI help 未说明“默认无总量上限、需自行防护”；
  2. verify 不接受/不复用预算：同一大归档 verify=Healthy 而显式预算 extract=Security，判定不一致（round-1 已指出的不一致仅换了个方向）；
  3. round-1 的“应补回归测试：>8 GiB 合法归档可解包”没有行为测试（R2-05）。
- **建议：** 二选一并写进文档：(a) 增加 CLI --max-output-bytes/config 字段并在 help/README 说明默认无限制；或 (b) 保留默认 None 但在 README/verify 输出中明确“不解包，不保证磁盘上限”。若坚持预算语义，应让 verify 与 extract 共享同一选项（或至少在 API 文档声明两者不一致）。

### R2-05【Low｜测试质量】新测试覆盖缺口（自动化的“正向路径”够了，但负例/矩阵/dry-run 缺失）

- **确认程度：confirmed**
- **缺口清单：**
  1. 矩阵（多卷）footer 修复：无自动化；round1_reader_fixes 只有单卷非 EC。我手工验证 12 卷 EC 的 backup/primary footer 修复均可用（E4），但若矩阵路径回归不会被发现。
  2. repair dry-run 不写：无自动化断言（我手工 sha 对比未变，E2/E4）。
  3. floating footer 不可修：无测试 → R2-02 逃逸（建议负例先把新行为写成红）。
  4. 大归档默认解包可行（round-1 TDD 建议）：现测试 2 MiB/256 KiB，无法证明 8 GiB 回归消失；建议用可注入 iterator 或 1 MiB 预算做等价覆盖。
  5. header adoption：只覆盖单卷（round1_reader_fixes.rs:239/325）；多卷/EC 卷、archive_id AAD 字段类（R2-08）无覆盖。
  6. CLI 端 footer/header repair 的 e2e：cli_extreme_tests.rs 只断言 verify 失败，没有断言 repair 后 verify 成功/两份 footer 相等（引擎测试里有，但 CLI 门禁不覆盖）。
- **证据：** 上述文件/测试清单；E2–E5、E10。

### R2-06【Low｜工程/证据链】审计期间源码并发变更，root 门禁快照不可用于当前树

- **确认程度：confirmed（mtime + 内容 diff）**
- **证据：** stat：reader.rs 02:07:53、era-volume/reader.rs 02:07:47、round1_reader_fixes.rs 02:08:07（审计开始 02:00、root 门禁 02:00 启动）；快照 A 的 verify_active_primary_headers 是硬失败实现，当前树已改为 adoption 恢复，且新增 2 个测试。root 全量门禁的 cli 测试在 02:04–02:09 编译/执行，期间源码被改，故 /tmp/era_ci_round1.log 的 cli 红/绿都不能直接代表快照 B（我复跑单测已绿，但 workspace 全量未由我重跑）。
- **建议：** 冻结工作树后由 root 重跑 CI 全链路（fmt+clippy+cli+workspace）并记录 commit/tree hash；报告与门禁都必须标注快照。

### R2-07【Low｜性能，benchmark-needed】每卷常数级额外读 + hash；repair 重复读 footer

- **确认程度：confirmed（代码）；影响为 benchmark-needed**
- **file:line：** reader.rs:2874-2881（每卷 4 KiB read + BLAKE3，位于所有 open 必经的 load_manifest）；reader.rs:2928-2976（verify 每卷 2×128 B + 解析）；repair.rs:363-381 与 :384-443（同一对 footer 各读两次）；crates/era-storage/src/local.rs:277-289（每次 read = try_clone+seek+read）
- **判定：** 每卷常数开销，未见 O(n²)；万卷归档每次 open 多约 1 万次 4 KiB 读 + 哈希，verify 多 2 万次 128 B 读。LL-04 建议已接受该成本；不建议阻塞，但建议：(1) repair 合并“探测+计划”的一次读；(2) 增加多卷 open/verify benchmark 作为证据（round-1 ENG-RC-10 的 benchmark 诉求仍未闭环）。

### R2-08【Low｜正确性（修复不完整）】manifest AAD 字段被可解析篡改时 adoption 不可达：open 硬失败、repair 仍不可用

- **确认程度：confirmed（CLI e2e）；属“LL-04 修复未闭环”的残留，不是本修订引入的回归**
- **file:line：** manifest 解密先于 auth：reader.rs:1466-1489（build_aad(&self.archive_id, self.epoch_id, BlockType::Manifest, volume_sequence, ...) → decrypt）；adoption 在其后 reader.rs:1541-1547/2883-2925；AAD 字段来源 reader.rs:176-177（来自卷头）
- **机理：** 单卷归档（或所有 manifest 副本所在卷）的主头中 archive_id 值字节被翻转（仍可解析）时，self.archive_id 变错 → manifest 块 AEAD 解密失败 → load_manifest 在到达 adoption 前返回 "Archive declares manifest but manifest cannot be loaded"（reader.rs:1558-1562）。backup header 完好且 digest 可认证，但由于 manifest 无法解密，adoption 路径不可达；repair 同样 open 失败。
- **证据（E10）：** 单卷 --erasure none 归档，翻转 header 中 archive_id 的 1 个值字节（offset 34，仍可解析）：verify rc=1 WARN Failed to decrypt manifest: aead::Error → Error: Failed to open archive / Archive declares manifest but manifest cannot be loaded；repair --force rc=1 同样；把 size-4224 备份头复制回 offset 0 后 verify rc=0。即“备份头可认证、归档本可修复”。（同类字段：epoch_id、volume_sequence。）
- **建议：** 在 manifest 解密失败且卷头摘要不匹配时，用“candidate header”（primary/backup）重试 manifest 解密/定位（或先用 manifest digest 表反查候选 seq），再进入 adoption/degraded；否则至少让 repair 有恢复入口（例如显式 --recover-header 用备份头替换主头）。补测试：archive_id/epoch_id 值篡改 → 期望 degraded+repairable（当前 fail closed 但不可修）。

### R2-09【Informational｜代码质量/API】(a) digest fallback 死代码；(b) ExtractOptions 新增 pub 字段的外部 source-breaking

- **确认程度：confirmed（代码/编译）**
- (a) reader.rs:2866-2873 的 .or_else(|| local_header_digests.get(&seq)) 在调用前提（!header_digests.is_empty() 且 len == expected_volume_count，:1491-1500/1541）下不可达：能进入循环的已发现卷 seq <= expected-1，header_digests.get(seq) 必是 Some；同一 fallback 也存在于 verify_recovered_backup_headers（:1581），属于防御性死代码。可在注释中说明或删除以降低“看起来有两套认证来源”的误读。
- (b) ExtractOptions 是公开 struct 且非 #[non_exhaustive]（reader.rs:68），新增 max_total_output_bytes 使外部 crate 的 ExtractOptions { output_dir, overwrite } 字面量构造编译失败；仓库内已全部更新（third_audit.rs:1391/1466）。pre-alpha 可接受，但建议之后加 #[non_exhaustive] 或改用 builder。另：新 VolumeReader::size()/adopt_authenticated_backup_header() 是纯增量 API，不构成破坏。

## 4. 已核实为“修复成立”的正例（不构成 finding）

- **P1 footer 冗余校验接入 verify，且能报 degraded：** 单卷非 EC 主/备 footer 损坏均 rc=1 且含 footer warning；修复后 Healthy（round1_reader_fixes.rs:106/185，E2/E5）。
- **P2 footer repair 正确写回：** 备份 footer 损坏 → 写 offset 4096；主 footer 损坏 → 写 size-128；都能 parse 且两份逐字节相等、文件大小不变（E2/E4；代码 repair.rs:384-443）。
- **P3 floating footer 恢复仍可读数据：** 两份 canonical footer 都坏时 floating scan 仍能打开并解包（E9），只是修复未闭环（R2-02）。
- **P4 多卷 EC（含定长卷）footer 修复可用：** 12 卷 EC 归档，volume 1 的 backup/primary footer 损坏分别被 verify 报 degraded、dry-run 不写、repair --force 写回 offset 4096/size-128、verify 恢复 Healthy（E4）。
- **P5 写回安全性：** apply_metadata_repair 固定 offset 写、不 truncate、sync；plan_volume_footer_repairs 对 checkpoint 布局（backup_header_offset()<DATA_REGION_START 或 canonical offset 不符）拒绝写 primary，避免覆盖数据区；dry-run 全路径不写（repair.rs:413-434/659-683/1309-1320，E2/E4 sha 未变）。
- **P6 基线无假阳性：** 单卷 EC/非 EC、6 卷、12 卷归档 verify 都 Healthy；v8.1 无 manifest digest 表路径被正确跳过（§2a）；没有发现 verify_redundant_footers 对正常 finalized 卷误报。
- **P7 源码字符串测试整改：** adversarial_audit_v2.rs:105-168 已换成行为测试；round1_reader_fixes 5 个测试全部行为断言（E5/E6/E8）。

## 5. 与 round-1 建议的偏差

| round-1 建议 | 修订落实情况 | 偏差 |
|---|---|---|
| LL-04：“打开归档后对每卷 header 摘要比对，不一致 → Degraded 并纳入 repair” | 快照 A 直接 Err（比对失败→不可打开）；快照 B 改为 authenticated backup adoption → Degraded + repair | 快照 A 违背建议；快照 B 基本符合，但 manifest AAD 字段类仍硬失败（R2-08） |
| ENG-RC-01：删除全程累计，或改成可配置总预算（CLI help/文档说明），并从 verify 复用 | 改成 ExtractOptions::max_total_output_bytes: Option<u64>，默认 None | 未在 CLI/config/README 暴露；verify 未复用；预算语义（解码量 vs 写盘量）未定义/未文档化（R2-03/04） |
| ENG-RC-02：verify 报 degraded；repair 主→备、备→主双侧写回；两者都坏明确报不可修或 floating 后重写双份 | verify 已接；双侧写回已实现 | “两者都坏”只 warn 并 Ok，CLI 仍报成功（R2-02） |
| ENG-RC-02 应补测试：engine e2e primary/backup footer、CLI verify degraded、repair 后字节相等 | engine 单卷 e2e 已补；CLI 只补了 verify 断言 | 矩阵/dry-run/floating/CLI-repair 未补（R2-05） |

## 6. 合并/回滚建议

- **不建议回滚整体修订**：方向正确；快照 A 的主要回归（R2-01）已在窗口内由 adoption 修复并通过 targeted 测试；footer 可修场景（单卷非 EC 与多卷 EC）与 header 可恢复场景都经 e2e 验证可用；基线无误报。
- **建议阻塞合并（或作为合并前门禁）直到：**
  1. 冻结工作树后由 root 重跑完整门禁（fmt/clippy/cli/workspace，--release --locked）。当前 /tmp/era_ci_round1.log 的 cli 失败属于快照 A；快照 B 的单测已绿，但不等于全量绿（R2-06）。
  2. R2-02 必须修：repair 对“两份 canonical footer 都不可用”不得返回成功；至少返回可识别错误并让 CLI 非零退出，最好按 floating footer 重写并截断垃圾。补负例测试。
  3. R2-03/R2-04 需明确决策并写文档：预算按写盘计费（推荐）或明示“只限解码量”；CLI/config 暴露预算或 README/help 明确“默认无总量上限”。否则 round-1 的“炸弹防护”修复不成立。
  4. 补 R2-05 所列测试（矩阵 footer repair、dry-run 不写、floating 不可修、>8 GiB 默认解包等价测试、多卷 adoption）。
  5. R2-08 可作为后续项（不阻塞，但应记录）；若要求 LL-04 完全闭环，则需在合并前修。
- **回滚的局部选项：** 若时间紧，可只回滚快照 A 的 verify_active_primary_headers 硬失败 commit（已被快照 B 取代），但当前树已包含正确方向，无需回滚。

## 7. 复现命令与证据原文

工具链前缀（所有命令）：

    export PATH="/nix/store/c2ii5nkzv440xj9igxsd49i8f5y2vr6f-cargo-1.99.1/bin:/nix/store/mslcwkiyh6wayx8gpzlq53wvr3a5pp44-rustc-1.99.1/bin:/nix/store/0x4hw59xdvzm6v79m1rz84a7j2j2yh0z-clippy-1.99.1/bin:/nix/store/3kr36w0awz5q8yia6nwcriaj3f0065qw-rustfmt-1.99.1/bin:$PATH"
    export RUSTC=/nix/store/mslcwkiyh6wayx8gpzlq53wvr3a5pp44-rustc-1.99.1/bin/rustc
    export CARGO_TERM_COLOR=never

- **E1 快照 A：root 门禁 cli 红（/tmp/era_ci_round1.log 摘录）**

      test random_offset_corruption::test_repair_corruption_at_multiple_offsets ... FAILED
      ...
      INFO Opened 6 volumes at sequences [0, 1, 2, 3, 4, 5] (total expected: 6)
      Error: Failed to open archive
      Caused by:
          Integrity error: Volume 0 primary header bytes do not match the authenticated manifest header digest
      test result: FAILED. 27 passed; 1 failed; ...
      cli_rc=101

- **E2 单卷非 EC footer 修复（快照 A/B 同）**

      corrupt backup footer @4096 -> verify rc=1 (degraded: backup footer ... requires repair)
      repair（dry-run）rc=0，sha_before == sha_after_dryrun
      repair --force rc=0 -> verify rc=0 -> extract rc=0 且 cmp 一致

- **E4 12 卷 EC 矩阵 footer 修复（快照 A/B 同）**

      baseline verify rc=0 (Healthy)
      volume1 backup footer @4096 清 0 -> verify rc=1 (Volume 1: backup footer damaged or unreadable)
      dry-run rc=0 且目标卷 sha 不变
      repair --force rc=0 (INFO Restoring footer copy at offset 4096 for ...) -> verify rc=0
      再把 volume1 尾部 128B 清 0 -> repair --force rc=0 -> verify rc=0

- **E5 引擎回归测试（快照 A 运行）**

      cargo test --release --locked -p era-engine --test round1_reader_fixes -- --test-threads=2
      test result: ok. 3 passed; 0 failed

- **E7b 快照 A 主头可解析损坏 -> repair 被阻断，且可从备份头恢复**

      create --erasure 4:2 --no-compression；offset 1000 反转 100B
      verify_rc=1  Error: Failed to open archive ... primary header bytes do not match ...
      repair --force rc=1 同一错误
      cp 备份头(offset size-4224..+4096) -> offset 0 后：verify_after_restore_rc=0，extract_after_restore_rc=0 且数据一致

- **E8 快照 B：同一损坏 degraded + 可修（我重建后复跑）**

      verify_rc=1  WARN Volume 0: primary header does not match the authenticated manifest digest; using the authenticated backup header (primary header requires repair)
      extract_rc=0 且数据一致
      repair --force rc=0；verify_after_rc=0

- **E7c 快照 B：原 CI 失败用例复跑**

      cargo test --release --locked -p era-cli --test cli_coverage_gap_tests random_offset_corruption::test_repair_corruption_at_multiple_offsets -- --test-threads=2
      test random_offset_corruption::test_repair_corruption_at_multiple_offsets ... ok
      test result: ok. 1 passed; 0 failed

- **E6 预算测试（源码位置）**：crates/era-engine/tests/adversarial_audit_v2.rs:105-168；crates/era-engine/src/reader.rs:3895-3970（默认无 cap / 超预算 Security+清理 / 恰好等于总量允许）。
- **E9 floating footer repair 不收敛（快照 B）**

      append 512B garbage + 清 0 offset 4096
      repair --force rc=0  WARN ... both footer copies are unreadable; cannot restore footer redundancy
                          INFO Archive successfully repaired!
      verify rc=1（仍 degraded，含 both footer copies are damaged）

- **E10 manifest AAD 字段篡改（快照 B，单卷）**

      header offset 34 (archive_id 值字节) ^= 0xff（仍可解析）
      verify rc=1  WARN Failed to decrypt manifest: aead::Error
                   Error: Failed to open archive / Integrity error: Archive declares manifest but manifest cannot be loaded
      repair --force rc=1 同上
      cp 备份头 -> offset 0：verify_after_restore_rc=0

## 8. 限制与未执行项

1. **未由我重跑全量门禁/workspace**（任务要求不重复 root 全量）；我只跑了 1 个定向 cli 测试（快照 B 通过）与 1 个引擎测试文件（快照 A 3 passed）。快照 B 的 workspace 结果需 root 冻结树后重跑。
2. root 门禁在源码并发变更窗口内编译/执行，其结果对快照 B 的适用性有限（R2-06）。
3. 性能判定为静态 + benchmark-needed，未做基准测量。
4. 未构造真实“解压炸弹/fanout 放大”归档验证 R2-03 的端到端影响（受只读约束与时间限制，仅代码路径确认）。
5. checkpoint/append 中状态、崩溃窗口下的 footer 误报为代码阅读 + 推断（未注入崩溃）。
6. 外部 crate 的 API 破坏仅依据仓库内用法与 semver 状态判断（仓库 pre-alpha）。
