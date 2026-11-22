# 低层（L0–L3）专项审计报告：正确性与安全（round 1）

- **审计日期**: 2026-11-22
- **仓库/分支**: `/home/ricardom/code/github.com/zapsaang/era-core`，`feat_fly`
- **审计基线**: HEAD `b22a07e`（工作区开始审计时干净）；整改提交 `8c42a4c` / `31d358f` / `5ff825e` / `b22a07e` 均包含在基线内
- **审计范围**: `era-crypto`、`era-common`、`era-storage`、`era-volume`、`era-codec`、`era-ingest`、`era-packing`、`era-index` 的生产路径（`src/`；测试/bench 仅作辅证）
- **审计维度**: 规格符合性 / 安全 / 性能 / 并发与一致性 / 代码质量
- **审计方法**:
  1) 逐文件阅读上述 crate 关键生产代码（AAD/nonce/密钥层级、卷头尾与 BlockHeader 解析、索引 ACID、EC、chunker、存储后端）；
  2) 代码路径推导，并与文档契约（`crates/*/AGENTS.md`、源码 rustdoc 的 crash-safety 声明）对照；
  3) 定向临时探针复现（`cargo test --release -p era-volume --test <probe>`，运行后删除，见 `8）；未运行 workspace 全量测试（由团队负责人后台执行）。
- **与前序报告的关系**: 独立复核 `docs/re-audit-and-residual-findings-2026-11-21.md`（`4.1 整改进展）与 `docs/post-fix-audit-and-residual-findings-2026-11-21.md`（RESID 系列）在 L0–L3 范围内的闭环情况；发现 1 项对 `8c42a4c` 整改的残余窗口（LL-01）与 1 项由该整改引入的内存放大（LL-02）。

---

## 1. 总体结论

1. **“已修复仓库全部问题、零技术债、无遗留” 在 L0–L3 范围内不成立**：本轮确认 **1 项 High、3 项 Medium、4 项 Low、3 项 Informational**。
2. 最关键的是 **LL-01**：`8c42a4c` 引入的 append 暂存（`StagedAppend`）确实修好了“finalize 之前中断”的窗口（探针 PROBE_A 可证），但把截断推迟到 `finalize()` 内部后，**“截断旧元数据之后、新 footer 落盘之前”仍存在一个使既有归档不可再打开的崩溃窗口**（PROBE_B 可证）。因此前序 `4.1 “已闭环”只能算**部分成立**。
3. `8c42a4c` 同时引入 **LL-02**：append 会话的全部新数据缓存在内存 `Vec<u8>` 中、直到 finalize 才落盘，append 体积与 RSS 线性增长且无上限。
4. 密码学核心（AAD 域分离、nonce 唯一性、密钥层级与零化、VK wrap、commitment、Hybrid KEM 组合）在本轮**未发现可利用缺陷**；卷头/尾与 BlockHeader 的解析边界校验总体扎实（见 `6）。主要剩余风险集中在**崩溃一致性、资源上限、未认证头部元数据被直接信任**三类。

### 1.1 发现汇总

| 编号 | 严重度 | 维度 | 标题 | 与整改提交的关系 | 确认程度 |
|---|---|---|---|---|---|
| LL-01 | **high** | 并发与一致性（崩溃安全） | append 的 finalize 先截断旧元数据、后写新 footer，窗口内崩溃使归档不可打开 | 8c42a4c 不彻底（残余窗口） | 已确认（故障注入复现） |
| LL-02 | medium | 性能/资源（内存 DoS） | StagedAppend 把整个 append 负载缓存在内存，无上限 | 8c42a4c 引入 | 已确认（代码+探针） |
| LL-03 | medium | 并发与一致性（持久化） | 可增长卷 finalize 覆盖恢复 footer 前缺少 fdatasync 屏障（仅定长卷有） | 既有问题 | 代码已确认；掉电影响为推断 |
| LL-04 | medium | 安全（完整性/信任边界） | 打开归档时不校验活跃 SuperHeader 的认证摘要，未入 AAD 的 config 被直接信任 | 既有问题（与 `4.2 相邻但不同） | 代码已确认；DoS 影响为推断 |
| LL-05 | low | 代码质量/健壮性 | era-ingest 公共 API 对非法 ChunkerConfig panic（assert + fastcdc assert），validate() 未被调用 | 既有问题 | 已确认 |
| LL-06 | low | 安全/持久化 | LocalStorageBackend::create 使用截断式 File::create（跟随符号链接、无 O_EXCL），且未 fsync 父目录 | 既有问题 | 代码已确认；利用为推断 |
| LL-07 | low | 代码质量 | read_all_from(offset>size) 下溢：debug panic / release 巨量分配 | 既有问题 | 已确认（无生产调用方） |
| LL-08 | low | 规格符合性/防御纵深 | protobuf→域模型转换缺跨字段校验（BlockChunkIndex.count、ErasureBlockInfo.shard_size/data_shards） | 既有问题 | 已确认（可达性受限） |
| LL-09 | informational | 安全（纵深） | VK wrap 的 AAD 为常量，未绑定 archive/volume | 既有问题 | 已确认（无可利用性） |
| LL-10 | informational | 代码质量 | ErasureCoder::encode_shards 对少于 data_shards 的输入静默补零 | 既有问题 | 已确认（当前调用方传全量） |
| LL-11 | informational | 代码质量 | check_mlock_available 对栈缓冲 mlock 后未 munlock | 既有问题 | 已确认（仅诊断路径） |

---

## 2. High 级发现

### LL-01 【high】append 的 finalize() 在截断旧元数据之后、新 footer 落盘之前崩溃，会使既有归档不可再打开

- **维度**: 并发与一致性（崩溃安全 / 数据可用性）
- **涉及层**: era-volume（截断与 finalize 原子性）+ era-engine（append 边界选择）
- **代码锚点**:
  - `crates/era-engine/src/writer.rs:647-655`：append 以 `scan_retained_data_region` 的返回值作为 `append_retained_end`；
  - `crates/era-engine/src/writer/checkpoint_append.rs:80-111`：扫描遇到第一个非 Data 块即 break，故 `retained.end` 是**数据区末尾**（不含 catalog/index/manifest），小于 `footer.data_end_offset()`（后者在所有元数据之后）；
  - `crates/era-engine/src/writer.rs:1193-1204`：`VolumePool::open_append_single_at(..., append_retained_end, ...)`；
  - `crates/era-volume/src/writer.rs:248-253`：`open_append_at` 记录 `StagedAppend { base_offset: append_offset, .. }`，**打开时不截断**（8c42a4c 的修复点）；
  - `crates/era-volume/src/writer.rs:256-265`：`flush_staged_append()` **先 truncate(base_offset)，之后才 append 暂存数据**；
  - `crates/era-volume/src/writer.rs:832`：flush 发生在 `finalize_with_catalog` 内部；新 header/footer 到 `:850-873` 才写、`:876` 才 sync；
  - `crates/era-volume/src/reader.rs:57-78`：open 先取 footer（主 footer 失败 → 4096 处备份 footer）；`:119-127` 在 `data_end_offset > file_size` 时直接返回 `CorruptedFooter`，**footer 一旦解析成功就不再回退 floating-footer 恢复**；
  - `clear_backup_footer_gap`（`crates/era-volume/src/writer.rs:311-367`）在 StartFresh 路径改写两处 footer，但仍保留 `original_footer.data_end_offset()`（旧值）——截断后仍大于新文件长度。
- **机理**:
  1. 旧归档备份 footer（offset 4096）声称 `data_end_offset = 旧的全部元数据之后的位置`。
  2. append 进入 finalize 后，`flush_staged_append` 把文件截断到**数据区末尾**，旧 catalog/index/manifest/backup header/primary footer 全部消失；新 footer 尚未写。
  3. 若进程在 truncate 返回后、新 footer 与 sync 完成前被 kill / 掉电 / 注入 I/O 错误，磁盘上就是“文件变短 + 4096 处旧 footer 声称更大 data_end”。
  4. `VolumeReader::open` 解析该旧 footer 后，被 `data_end_offset > size` 拒绝，且不再尝试其它恢复路径，于是 verify / repair / 再次 append 全部失败。
  5. 即使后续数据把文件“撑大”超过旧 data_end，旧 footer 的 catalog/index/manifest 偏移也落在新数据区，catalog 解密/CRC 失败，同样打不开。
- **可审计证据**:
  - 并行审计线程的临时故障注入探针（`crates/era-volume/tests/zz_probe_finalize_atomicity.rs`，未提交；本审计运行，见 `8.2）：
    `PROBE_A crash-before-finalize: file unchanged=true len=13568 / PROBE_A reopen_ok=true`（8c42a4c 修复的窗口确实闭合）
    `PROBE_B finalize_err=Some("I/O error: injected crash/IO failure immediately after truncate, before the new footer is written")`
    `PROBE_B before_len=13568 after_len=8320 reopen_err=Some("Corrupted footer: Archive appears truncated: footer claims data_end_offset=9344 but file size is 8320")`
  - 本审计独立探针（`crates/era-volume/tests/zz_audit_probe_append_crash.rs`，运行后已删除）截断到数据区末尾后重开：
    `PRE_OPEN_OK=true / DATA_ONLY_END=8352 POST_OPEN_OK=false / POST_OPEN_ERR=Corrupted footer: Archive appears truncated: footer claims data_end_offset=8880 but file size is 8352`
- **确认程度**: **已确认**（代码路径必然 + 故障注入端到端复现）；掉电场景依赖写顺序，属同一窗口。
- **建议修复（P0）**:
  1. 在 `flush_staged_append` 之前写一份**过渡 footer**：`data_end_offset = base_offset`、catalog/index/manifest/checkpoint 指针清零（或指向仍保留的副本）并 sync；这样截断后即便崩溃，reader 仍能打开“无元数据但结构完整”的卷。
  2. 或截断前把 `[base_offset, old_data_end)` 的旧元数据复制/重定位到新文件末尾，待新 footer 落盘后再回收；或采用两阶段提交（新数据/新 footer 先写到新位置，最后一次 128B 原子 footer 切换）。
  3. 为 truncate 后的每个等待点补故障注入测试。
- **应补回归测试（TDD，先红后绿）**:
  - `crates/era-volume/tests/finalize_atomicity_tests.rs`：包装 StorageWriter，在 truncate() 返回后立即对 append/write_at/sync 注入 `Io` 错误（等价进程死亡）；断言 finalize() 返回 Err 后 `VolumeReader::open` 仍成功且 `footer().data_end_offset() == retained_end`。
  - 同一机制覆盖 `enable_checkpoint(false)`、`StartFresh`（clear_backup_footer_gap 已执行）两条路径。

---

## 3. Medium 级发现

### LL-02 【medium】append 暂存把整个 append 负载放进内存，无上限（内存放大/DoS）

- **维度**: 性能 / 资源耗尽
- **代码锚点**:
  - `crates/era-volume/src/writer.rs:28-33`：`struct StagedAppend { base_offset, buf: Vec<u8>, original_footer }`；
  - `crates/era-volume/src/writer.rs:661-663`（write_canonical_block）与 `:721-723`（write_raw）都执行 `staged.buf.extend_from_slice(...)`；
  - `crates/era-volume/src/writer.rs:265`：只有 finalize / set_max_size 才 `truncate + append(buf)`；`commit_checkpoint` 在 staged 状态下直接 `return Ok(())`（`:507-511`），检查点也不落盘。
- **机理**: append 期间所有新写入只在进程堆内存；写入 N 字节 ⇒ 峰值 RSS 至少 +N 字节（引擎层另有 chunk/block 缓冲）。对“1 TB 归档后追加 100 GB”的合法用法，RSS 逼近 100 GB，被 OOM kill——而 OOM kill 又恰好可能落入 LL-01 窗口。另：append 中断时这些写入全部丢失，但调用方已收到 `write_canonical_block` 的 `Ok`，语义上是“已确认写未持久化”。
- **可审计证据**: 并行探针 PROBE_C（已运行）：
  `PROBE_C on_disk_before=13568 on_disk_after=13568  writer_position=8396928 staged_bytes=8383360`
  即写入 8 MiB 后磁盘长度完全不变，8 MiB 全在 staged.buf。
- **确认程度**: **已确认**（代码 + 探针）。
- **建议修复**: 为 StagedAppend 设最大暂存字节数（如 max(64 MiB, max_volume_size/8)），超限后落盘到追加区（此时必须同时写过渡 footer，见 LL-01）或返回 `VolumeSpaceExhausted`；或改为“独立 append 影子文件 + 最终原子替换”的 spool 方案；至少文档声明 append 内存语义。
- **应补回归测试**: `staged_append_memory_bound`：计数 StorageWriter，写入 limit+1 字节后断言明确错误（或磁盘增长）；并断言 sync()/commit_checkpoint() 在 staged 状态下有定义行为。

### LL-03 【medium】可增长卷 finalize_with_catalog 覆盖恢复 footer 前没有 fdatasync 屏障

- **维度**: 并发与一致性（持久化顺序 / 掉电一致性）
- **代码锚点**:
  - `crates/era-volume/src/writer.rs:832-876`：顺序为 flush_staged_append() → 写 header（`:850-858`）→ 写 primary footer（`:861-868`）→ **原地覆盖 4096 处备份 footer**（`:871-873`）→ 最后 sync（`:876`）。
  - 唯一的数据 sync 只在定长卷分支：`:835-846`（`if let Some(max_size) = self.max_size { ... sync_data() }`）。
  - 对照 commit_checkpoint 的正确顺序：`:513-516`（pad + sync_data）与 `:542`/`:566`。
  - 该函数 rustdoc `:769-782` 声称 “On crash ... Old footer (finalize not committed) — data intact”，对可增长卷不成立（最后一步就是覆盖旧 footer）。
- **机理**: 对可增长卷，新 data 块（flush 的 append）与新 footer 覆盖（4096 处写）处于同一个未 fsync 窗口。POSIX 不保证无 fsync 的写顺序；若掉电后只有 footer 原地写持久化、数据扩展未持久化，reader 会读到“新 footer + 缺失/陈旧数据块”，catalog/commitment 校验失败而无法打开；反之只持久化数据则回落到旧状态（可接受）。因此存在“掉电后归档不可打开”的非零概率窗口。
- **确认程度**: **代码顺序已确认**；掉电后具体结果依赖文件系统，属**推断**（可用 dm-log-writes 重放或故障注入验证）。
- **建议修复**: 可增长卷在写任何 header/footer 之前执行一次 `sync_data()`（append finalize 是低频操作），与 commit_checkpoint 对齐。
- **应补回归测试**: 用记录调用序列的 StorageWriter 断言“最后一次数据区写”与“write_at(4096, footer)”之间必须出现 `sync_data()`（负例先红）。

### LL-04 【medium】打开归档时不校验活跃 SuperHeader 的认证摘要：未入 AAD 的 config 被直接信任

- **维度**: 安全（完整性 / 信任边界）、规格符合性
- **代码锚点**:
  - `crates/era-crypto/src/aead_context.rs:125-150`：AAD 仅含 archive_id ‖ epoch_id ‖ type_id ‖ volume_index ‖ block_id——**不含** config、recipients、total_volumes、creation_time。
  - `crates/era-volume/src/header.rs:500-525`：SuperHeader::from_bytes 只校验 magic/版本/字段范围，不做摘要认证。
  - `crates/era-engine/src/reader.rs:1546-1570`：`verify_recovered_backup_headers` 第一条即 `if !reader.header_recovered_from_backup() { continue; }`——**只校验“从备份恢复出来的头”，不校验当前生效的主头**；该函数在 manifest 装载流程（`:1521`）中被调用。
  - `crates/era-engine/src/reader.rs:2863-2864`：manifest 的 volume_header_digests 只在 verify/repair 的降级路径被消费。
  - 头里的 config 被用于实际行为：`crates/era-engine/src/writer.rs:583`（append 继承 loaded_header.config()）、`:1027`（compression/erasure 决定 compressor 与容量模型）、`crates/era-volume/src/reader.rs:111`（header.config().erasure 决定是否允许 footer 缺失）。
- **威胁场景 / 信任边界 / 前置条件 / 影响**:
  - 威胁场景：攻击者能改写归档文件中的 4 KiB 头区（本地磁盘篡改、备份介质/共享目录、外部提供的 .era 文件）。篡改不需要密钥。
  - 信任边界：磁盘上的 SuperHeader 是不可信输入；AEAD 只保护块数据，不保护头字段。
  - 前置条件：能让受害者对篡改后的归档执行 open/verify/repair；篡改字段不属于 AAD。
  - 影响：典型为 **DoS/行为漂移**——把 `config.compression.algorithm` 从 Zstd 改为 None 后，reader 用 NoCompressor 解压旧块，所有块解析失败；把 `config.erasure` 改为 `Some` 可让非 EC 卷跳过“无 footer 必须报错”的分支（`reader.rs:111-117`）。**不会**导致明文伪造（块 AEAD 仍校验）或密钥泄露——archive_id/epoch_id/salt 参与 AAD 或密钥派生，改动会直接导致解密失败。
- **确认程度**: **代码路径已确认**（打开期不校验主头）；“篡改后 verify 是否一定漏报”为推断（取决于 verify 对全部卷头的遍历，见前序 `4.2 同类问题）。
- **建议修复**: 在 ArchiveReader::open 装载 manifest 后，对**每个**卷（包括主头未损坏的活跃卷）计算 `blake3(header.to_bytes())` 与 manifest 的 volume_header_digests 比对；不一致 → Degraded 并纳入 repair（成本：每卷 4 KiB 读 + 一次哈希）。或在 SuperHeader 序列化中加入由 MK 派生的 keyed-BLAKE3 MAC。
- **应补回归测试**: `header_config_authentication`：创建非 EC 单卷归档 → 翻转 header 中 config.compression.algorithm 对应字节 → 断言 open 返回 Degraded/Err（当前为“打开成功、随后块解密失败”）；同时断言 verify() 不返回 Healthy。

---

## 4. Low 级发现

### LL-05 【low】era-ingest 公共 API 对非法 ChunkerConfig 直接 panic；validate() 未被构造器调用

- **维度**: 代码质量 / 健壮性（与 AGENTS.md “src/ 无 panic” 契约冲突）
- **代码锚点**:
  - `crates/era-ingest/src/chunker/config.rs:61-71`：new_with_params 用 `assert!(min<=avg)` / `assert!(avg<=max)`；
  - `crates/era-ingest/src/chunker/config.rs:73-95`：validate() 额外检查 fastcdc 边界（min 64..、avg 256..、max 1024..），但**没有调用者**；
  - `crates/era-ingest/src/chunker.rs:48-59` 与 `:229-236`：把 usize 直接 `as u32` 后传给 FastCDC::with_level_and_seed；
  - 上游 fastcdc 3.2.1（Cargo.lock:1041）`src/v2020/mod.rs:483-488` 在构造时用 `assert!` 校验参数；
  - `crates/era-ingest/src/chunker.rs:145-158`：StreamingChunker::new 直接 `vec![0u8; config.max_size * 3]`，同样不校验。
- **机理**: ChunkerConfig 字段为 pub，库使用者可构造非法组合；Chunker::new / chunk_bytes 不返回 Err，而是把非法参数交给 fastcdc → panic（或巨量分配/乘法溢出）。引擎侧当前安全：`crates/era-engine/src/writer.rs:1036-1039` 先按容量 clamp 再调用 validate()?；但这是“调用方记得校验”，不是 API 契约。
- **确认程度**: **已确认**（代码 + 上游 assert 源码）。
- **建议修复**: Chunker::new 返回 Result 或让 chunk_bytes 返回 Result；assert! 改 Result 错误；StreamingChunker::new 返回 Result 并限制 max_size（如 ≤ 64 MiB）。
- **应补回归测试**: `invalid_chunker_config_returns_err`：对 `ChunkerConfig::new(1,1,1)` 断言 `try_new(...).is_err()` 且不 panic（catch_unwind 负例先红）。

### LL-06 【low】LocalStorageBackend::create 使用截断式 File::create（跟随符号链接、无 O_EXCL），且未 fsync 父目录

- **维度**: 安全（本地文件信任边界）/ 持久化
- **代码锚点**:
  - `crates/era-storage/src/local.rs:44-57`：`File::create(&full_path)`（O_CREAT|O_WRONLY|O_TRUNC，跟随符号链接），无 create_new / O_NOFOLLOW；
  - `crates/era-storage/src/local.rs:30-37`：绝对路径直接使用，相对路径拼 base_path（不 canonicalize）；
  - `crates/era-storage/src/local.rs:169-173`：close() 只对文件 sync_all，没有父目录 fsync。
- **威胁场景 / 信任边界 / 前置条件 / 影响**:
  - 攻击者在受害者写入归档的目录中放置符号链接 `archive.era -> /home/victim/.bashrc`；create 会 O_TRUNC 目标并写入卷头。前置条件：攻击者对归档输出目录有写权限（共享目录、world-writable 目录）。影响：**任意文件截断/覆写**（以受害进程权限）。
  - 另外新建卷文件的目录项在掉电后可能丢失（父目录未 fsync），表现为“finalize 成功但文件不存在/长度 0”。
- **确认程度**: 代码行为**已确认**；利用需目录写权限，可达性为**推断**（低）。
- **建议修复**: 用 `OpenOptionsExt::custom_flags(libc::O_NOFOLLOW)` + `create_new(true)`（存在即报错，由上层显式决定覆盖策略）；创建成功后 fsync 父目录。Windows 用 FILE_FLAG_OPEN_REPARSE_POINT 等价物。
- **应补回归测试**: `create_refuses_symlink_target`：临时目录建 `link -> victim.txt`，调用 `backend.create(link)`，断言 Err 且 victim.txt 内容不变；另加父目录持久化断言。

### LL-07 【low】read_all_from(offset > size) 下溢

- **维度**: 代码质量 / 健壮性
- **代码锚点**: `crates/era-storage/src/local.rs:198-200`：`let len = (self.size - offset) as usize;`（`crates/era-storage/src/memory.rs:208` 同型）。
- **机理**: offset > size 时 u64 下溢：debug panic（违反 src/ 无 panic 契约），release 得到巨大 len 并在 read_at 中 `vec![0u8; len]` 尝试分配（OOM/abort）。当前生产无调用方（仅测试），但它是 StorageReader 公共 trait 方法，未来路径易误用。
- **确认程度**: **已确认**（无生产调用方，当前影响为潜在）。
- **建议修复**: `offset.checked_sub(self.size)` → 返回 `EraError::InvalidFormat`；memory.rs 同步修复。
- **应补回归测试**: `read_all_from_out_of_bounds_is_error`（offset = size + 1）。

### LL-08 【low】protobuf→域模型转换缺少跨字段校验（BlockChunkIndex.count、ErasureBlockInfo）

- **维度**: 规格符合性 / 防御纵深
- **代码锚点**:
  - `crates/era-common/src/conversion.rs:342-356`：TryFrom<proto::BlockChunkIndex> 校验 count ≤ u16::MAX，但**不比较 count 与 entries.len()**；消费方（`crates/era-packing/src/block_codec.rs:149-163`、`unpacker.rs:108`）都只看 entries，字段与内容不一致时静默接受。
  - `crates/era-common/src/conversion.rs:194-214`：TryFrom<proto::ErasureBlockInfo> 只把 data_shards/parity_shards 收窄到 u8，**不校验 data_shards ≥ 1、data+parity ≤ 256、shard_size ≤ MAX_SHARD_SIZE、shard_size 与 original_len 的关系**；shard_offsets/shard_volumes 仅在 BlockLocation 转换里校验长度相等与 ≤256。
  - 消费侧：`crates/era-engine/src/block_iter.rs:1493` / `repair.rs:1115` 把 catalog 的 erasure_info.shard_size 传给 `ErasureCoder::recover_data_shards`（`crates/era-codec/src/erasure.rs:330-437`），后者把每个分片 resize 到 shard_size 后解码。
- **机理**: 这些结构来自解密后的 catalog/index（完整性由 manifest 的 catalog_commitment 约束），不是无密钥攻击者可直接利用的输入；但若 catalog 来自修复/旧格式/未来“无加密”配置，超大 shard_size 会造成每个分片 shard_size 字节的临时分配（total_shards 个）；data_shards=0 可能在 div_ceil/chunks 路径触发错误。属“单侧校验”缺口（AGENTS.md 要求对称校验）。
- **确认程度**: 反序列化缺校验**已确认**；利用可达性**推断**（需要可解密的恶意 catalog）。
- **建议修复**: TryFrom 中补齐 `count == entries.len()`、`data_shards ≥ 1`、`data+parity ≤ 255`（与 era-codec::MAX_TOTAL_SHARDS 对齐）、`shard_size ≤ MAX_SHARD_SIZE` 且 `shard_size ≤ original_len.next_multiple_of(data_shards)`、`original_len ≤ MAX_SHARD_SIZE`。
- **应补回归测试**: proptest/固定例：count 与 entries 不匹配 → Err；shard_size = u32::MAX、data_shards=0 → Err；与 `era-codec::ErasureConfig::new` 边界表一致。

---

## 5. Informational

### LL-09 【informational】VK wrap 的 AAD 为常量，未绑定 archive/volume

- **代码锚点**: `crates/era-crypto/src/key_session.rs:193-210`（`VK_WRAP_AAD_DOMAIN = b"ERA_VK_WRAP_v8.1"`，wrap/unwrap 只用该常量作 AAD）。
- **结论**: 同一 MK 下，卷 i 的 encrypted_volume_key 可移植到卷 j 的头里并“解包成功”（得到错误 VK）；但数据块 AEAD 的 AAD 含 volume_index、块密钥按 VK 派生，随后所有块解密失败——**仅 DoS/诊断混淆，不泄露密钥、不产生伪造明文**。攻击者本就能破坏明文头（LL-04），故无额外能力。
- **建议**: 下一版冻结新标签时把 `archive_id ‖ volume_id ‖ volume_sequence` 纳入 VK wrap AAD；属纵深防御，不紧急。

### LL-10 【informational】ErasureCoder::encode_shards 对少于 data_shards 的输入静默补零

- **代码锚点**: `crates/era-codec/src/erasure.rs:171-201`（注释本身写着 “No, the caller should provide exactly data_shards or we should handle it”，实现选择补零）。
- **结论**: 当前生产调用方都传全量数据分片（`crates/era-engine/src/write_pipeline.rs:232`、`repair.rs:1122` 均由 recover_data_shards 得到 data_shards 个），**无当前缺陷**；但“分片序号/顺序”成为隐式契约，若调用方传 offset/乱序分片，会得到与真实数据不一致的校验分片且无错误返回。
- **建议**: 返回 Err（要求恰好 data_shards），或把“输入必须是 shard 0..data_shards、顺序固定”写成显式前置条件并加 debug_assert。

### LL-11 【informational】check_mlock_available 对栈缓冲 mlock 后未 munlock

- **代码锚点**: `crates/era-crypto/src/secure_memory.rs:390-394`：`let test_buf = [0u8;16]; mlock(test_buf.as_ptr(), 16).is_ok()`，未 munlock。
- **结论**: 仅诊断 API、调用频率低；Linux 上会留下一个被锁页（LOCKED 计数泄漏），不影响密钥安全。
- **建议**: 测试后 munlock，或改用 SecureBuffer::new()（其 Drop 会 munlock）。

---

## 6. 已核验为符合规格的项（本轮未发现缺陷）

1. **AAD 域分离**（`crates/era-crypto/src/aead_context.rs:120-150`）：AAD = archive_id(16) ‖ epoch_id(le32) ‖ type_tag ‖ volume_index(le32) ‖ block_id(le64)，8 种 BlockType tag 两两不同；tag 长度不同保证字段边界无歧义，同长度 tag（INDEX_PAGE/CHECKPOINT）字节内容不同故无碰撞。**域分离成立。**
2. **nonce 唯一性**（`aead_context.rs:152-168`、`key_session.rs:352-379`、`era-packing/src/session_builder.rs:157-161,202-264`）：数据/元数据块用 `BK = HKDF-SHA256(VK, "ERA_BLOCK_KEY_v8.1" ‖ block_id(be64) ‖ nonce_context(16))`，nonce = `BLAKE3("ERA-NONCE-V2" ‖ nonce_context ‖ block_id(le64) ‖ volume_index(le32))[..24]`；索引块使用**改写后的 nonce_context**（`era-index/src/builder.rs:332-336`，前 4 字节替换为 `"IDX\x01"`）且 block_id 区间独立分配；manifest/checkpoint 各自 derive_block_key。**未发现 nonce 复用。** 附带核验：derive_block_key 的 info 缓冲区 18+8+16=42 与域长度精确匹配（`key_session.rs:361-373`），无截断。
3. **密钥生命周期/零化/不落盘**（`key_session.rs`、`secure_memory.rs`）：MK/IK/VK/BK 全部 SecureBuffer（Drop 中 zeroize + munlock）；Debug 全 REDACTED；IK 仅运行时派生、无序列化路径；VK wrap 使用 OsRng 每卷随机 nonce。**未发现密钥落盘或日志泄漏。** 注：KeySession 的 verification_tag = HKDF(MK) 是明文头字段，可离线验证口令候选——但攻击者本可用 Argon2id + 任意已加密块做等成本验证，Argon2 成本主导，**不构成降级**。
4. **VK wrap / Hybrid KEM 组合**（`key_session.rs:196-237`、`hybrid_kem.rs:218-323`）：combine_shared_secrets = HKDF-SHA256(salt=None, ikm = x25519_shared(32) ‖ kyber_shared(32), info="ERA-v2.2-Hybrid-KEM")，固定长度拼接无歧义；两个 KEM 必须同时正确才能得到同一 key（单侧被攻破不泄露）；ML-KEM-768 secret key 用 Zeroizing<[u8;2400]> 长期保存，瞬态 SecretKey 残留已在源码注释如实声明（`hybrid_kem.rs:69-85`）。HybridCertificate::from_bytes 严格校验 1216 字节；encapsulate_for 用 Nonce::zero() 但 AEAD key 来自新鲜 KEM 共享密钥（每次封装唯一），**无 nonce 复用**。
5. **commitment**（`crates/era-crypto/src/commitment.rs:18-86`）：catalog/index 使用不同 32 字节 keyed-BLAKE3 域；空 index → [0u8;32] 且校验函数对称支持“无 index”；比较用 subtle::ConstantTimeEq。**符合契约。**
6. **卷头解析**（`crates/era-volume/src/header.rs:500-525`、`:161-199`、`:696-818`）：magic 先校验；protobuf 解前有 `data.len() ≤ 4096`；recipient 的 params/encrypted_master_key 有 4096 上界与最小 24 字节下界；key_id 长度严格；EVK nonce 必须 24 字节、ciphertext 有 [16,4096] 界；未知枚举用 try_from 拒绝（不静默 map 默认）。**边界校验扎实。**
7. **卷尾解析与恢复链**（`era-volume/src/footer.rs:367-470`、`reader.rs:46-233`）：footer 固定 128B；校验 magic/version/flags=0；checksum 覆盖原始 96 字节（含 reserved）；data_end_offset 有下限，catalog/index/manifest 区有 `offset+size ≤ data_end` 跨字段校验；备份 footer(4096)/floating-footer 逆扫（1 MiB 窗口、对齐+非对齐两遍、MAX_SCAN_RESULTS 上限）设计合理。**未发现越界读。** 已核验安全性质：footer checksum 无密钥 BLAKE3 可重算——但 footer 指向的块仍受 AEAD + manifest commitment 约束；仅“整包回滚到旧 manifest + 旧 catalog”不可检测（需外部单调状态，属格式固有边界）。
8. **BlockHeader / ShardHeader**（`era-common/src/types/block.rs:342-385,511-597`）：BlockHeader 16B 固定、version 严格 =1、未知 block type 返回 None、verify 先比长度再比 CRC；ShardHeader 8B 同样先比长度。`VolumeReader::read_typed_block` 与 scan_for_typed_blocks 使用前把 `length ≤ MAX_SHARD_SIZE` 卡住（`era-volume/src/reader.rs:430-436,517-530`）。**未发现长度越界读。**
9. **索引 ACID**（`era-index/src/store.rs`）：redb 单写事务提交；entry_count 与 bloom 位都在 **commit 成功之后**更新（`:239-255,340-353`），避免 phantom；insert_batch 用单次 read txn 过滤 bloom 命中；open_readonly 有 1 亿条上限 + bloom 容量上限 1000 万（`:109-182`）；deserialize 用 `size_of::<IndexEntry>()*4` 上限 + rkyv 校验。**符合“ACID + 冷恢复重建”声明**（冷恢复端到端未跑测，见 `7）。
10. **EC 参数约束与分片完整性**（`era-codec/src/erasure.rs:47-82`）：ErasureConfig::new 拒绝 0 分片与 `data+parity > 255`；decode 校验分片数量与“可用 ≥ data_shards”；recover_data_shards 拒绝 `len > shard_size`（避免静默截断）。**边界正确**；分片不足返回 ErasureError 而非静默。
11. **压缩炸弹上限**（`era-codec/src/compression.rs`）：Zstd 解压有 256 MiB 输出上限（`:7-8,54-75`），LZ4 先校验 4B 声明长度 ≤ 256 MiB（`:133-154`）；无递归解压。**上限存在**；256 MiB/块仍偏大（建议后续评估并发解压总预算），不构成本轮缺陷。
12. **chunker 边界（FastCDC）**：ChunkIterator 按 offset..offset+length 切片（`era-ingest/src/chunker.rs:111-121`）；StreamingChunker 每个新 chunk 从 chunk 边界重新起算（min_size=4 KiB > 滚动哈希 64B 窗口），与整块分块一致；EOF 尾部小 chunk 单独处理（`:206-217`）。**未发现边界/丢数据错误**；唯一问题是非法配置的 panic（LL-05）。
13. **存储原子写与 fsync（已有部分）**：LocalStorageWriter::append 显式 seek 到跟踪 size（避免 write_at 后 append 错位，`local.rs:127-137`）；write_at 正确维护 size（`:139-153`）；truncate 同步更新 size；close 做了 sync_all；commit_checkpoint 的“pad → sync_data → 写两处 footer → sync”顺序正确（可作为 LL-03 的对照）。**余下缺口见 LL-03/LL-06。**

---

## 7. 覆盖范围、未能核实项与前序声明核对

### 7.1 本轮未核实 / 无法核实的项

1. **全量 release 门禁**：未运行 `cargo test --release --workspace`（团队负责人后台执行）。本轮仅运行 2 个临时探针测试（已删除/由创建者删除）。
2. **engine/CLI 层**（era-engine、era-cli）：按分工不在本文件范围；前序 `4.2–`4.10、RESID-* 的闭环结论未由本文件复核。
3. **索引冷恢复端到端**（`era-index/src/reader.rs:331-870` 的 12 条 recovery 分支）：仅做代码结构审阅，未构造“footer 丢失 + 多个候选 IndexManifest”的实测。
4. **多卷 EC 分布/轮转**（`era-volume/src/volume_pool.rs` 的 write_erasure_block / ensure_stripe_capacity / retired-volume finalize）：只读了与 header digest/finalize 相关的函数（`:1042-1083`、`:597-642`），未完整审计矩阵分布与轮转容量计算。
5. **旧版 X25519 证书有效期/链**（`era-crypto/src/certificate.rs`、`timestamp.rs`）：未逐行审阅；Hybrid 证书为裸公钥（无有效期），属设计选择，未发现新增风险。
6. **性能量化**：本轮无 benchmark；LL-02 的内存放大是逐字节可推算的（非 benchmark 依赖），未给出吞吐断言。
7. **“零技术债”整体声明**：本文件只能证明 L0–L3 范围内仍有 `2–`5 所列问题，不能证明其它层无问题。

### 7.2 与前序报告/整改提交的核对

| 前序结论 | 本轮核实 | 依据 |
|---|---|---|
| `4.1“中断 append 后归档不可再打开”已由 `8c42a4c` 修复 | **部分成立**：finalize 之前的窗口已闭合（PROBE_A 文件字节不变、可重开）；**finalize 内部“截断后、footer 前”窗口仍存在**（PROBE_B / LL-01） | `2 LL-01 证据 |
| `8c42a4c` 的 StagedAppend 无副作用 | **不成立**：引入无上限内存暂存（LL-02） | PROBE_C |
| 前序 `4.2“verify 不校验仍可解析的备份头” | 未复核（engine 层）；相关但不同的问题：活跃主头 config 未认证（LL-04） | 代码路径 |
| RESID-LOW-02“读端主头回退未校验摘要” | 前序称已由 `ee39fae` 补齐 repair 侧；本轮确认**打开期仍不校验活跃主头**（LL-04），是否属设计如此需与规格确认 | `reader.rs:1546-1570` |
| “生产代码 0 unwrap/expect/panic、全部 Result” | 在 L0–L3 抽查范围内成立；但 era-ingest 公共 API 仍有 assert! 导致的 panic 路径（LL-05，且上游 fastcdc 以 assert 校验参数） | `4 LL-05 |

---

## 8. 证据附录（命令与关键输出）

环境（工具链按团队约定显式指定）：

```bash
export PATH="/nix/store/c2ii5nkzv440xj9igxsd49i8f5y2vr6f-cargo-1.99.1/bin:/nix/store/mslcwkiyh6wayx8gpzlq53wvr3a5pp44-rustc-1.99.1/bin:/nix/store/0x4hw59xdvzm6v79m1rz84a7j2j2yh0z-clippy-1.99.1/bin:/nix/store/3kr36w0awz5q8yia6nwcriaj3f0065qw-rustfmt-1.99.1/bin:$PATH"
export RUSTC=/nix/store/mslcwkiyh6wayx8gpzlq53wvr3a5pp44-rustc-1.99.1/bin/rustc
export CARGO_TERM_COLOR=never
```

### 8.1 LL-01 独立探针（本审计创建，已删除）

`crates/era-volume/tests/zz_audit_probe_append_crash.rs`（2451 字节，运行后 rm）：

```text
$ cargo test --release -p era-volume --test zz_audit_probe_append_crash -- --test-threads=2 --nocapture
running 1 test
PRE_OPEN_OK=true
DATA_ONLY_END=8352 POST_OPEN_OK=false
POST_OPEN_ERR=Corrupted footer: Archive appears truncated: footer claims data_end_offset=8880 but file size is 8352
test result: ok. 1 passed; 0 failed; 0 ignored
```

### 8.2 LL-01 端到端故障注入（并行审计线程的临时探针，本审计运行以佐证）

`crates/era-volume/tests/zz_probe_finalize_atomicity.rs`（未提交；由创建者收尾删除）：

```text
$ cargo test --release -p era-volume --test zz_probe_finalize_atomicity -- --test-threads=2 --nocapture
running 3 tests
PROBE_A crash-before-finalize: file unchanged=true len=13568
PROBE_B finalize_err=Some("I/O error: injected crash/IO failure immediately after truncate, before the new footer is written")
PROBE_A reopen_ok=true
PROBE_B before_len=13568 after_len=8320 reopen_err=Some("Corrupted footer: Archive appears truncated: footer claims data_end_offset=9344 but file size is 8320")
PROBE_C on_disk_before=13568 on_disk_after=13568          writer_position=8396928 staged_bytes=8383360
test result: ok. 3 passed; 0 failed; 0 ignored
```

### 8.3 代码事实锚点（供复核者直接跳转）

- LL-01: `crates/era-volume/src/writer.rs:256-265`, `:832`, `:850-876`; `crates/era-engine/src/writer/checkpoint_append.rs:80-111`; `crates/era-engine/src/writer.rs:647-655`, `:1193-1204`; `crates/era-volume/src/reader.rs:119-127`.
- LL-02: `crates/era-volume/src/writer.rs:28-33`, `:248-253`, `:507-511`, `:661-663`, `:721-723`, `:265`.
- LL-03: `crates/era-volume/src/writer.rs:769-782`（文档承诺）vs `:832-876`（实现顺序），对照 `:504-575`（checkpoint 的正确 sync 顺序）。
- LL-04: `crates/era-crypto/src/aead_context.rs:125-150`; `crates/era-volume/src/header.rs:500-525`; `crates/era-engine/src/reader.rs:1546-1570`, `:2863-2864`; `crates/era-engine/src/writer.rs:583`, `:1027`.
- LL-05: `crates/era-ingest/src/chunker/config.rs:61-95`; `crates/era-ingest/src/chunker.rs:48-59`, `:145-158`, `:229-236`; fastcdc 3.2.1 `src/v2020/mod.rs:483-488`（Cargo.lock:1041）。
- LL-06: `crates/era-storage/src/local.rs:30-37`, `:44-57`, `:169-173`.
- LL-07: `crates/era-storage/src/local.rs:198-200`; `crates/era-storage/src/memory.rs:208`.
- LL-08: `crates/era-common/src/conversion.rs:194-214`, `:342-356`; 消费侧 `crates/era-engine/src/block_iter.rs:1493`、`crates/era-codec/src/erasure.rs:330-437`.
- LL-09: `crates/era-crypto/src/key_session.rs:193-237`.
- LL-10: `crates/era-codec/src/erasure.rs:171-201`; 调用方 `crates/era-engine/src/write_pipeline.rs:232`、`crates/era-engine/src/repair.rs:1122`.
- LL-11: `crates/era-crypto/src/secure_memory.rs:390-394`.

### 8.4 工作区卫生

- 本审计创建的临时探针 `crates/era-volume/tests/zz_audit_probe_append_crash.rs` 已删除。
- 审计结束时 `git status --porcelain` 仍显示 `?? crates/era-volume/tests/zz_probe_finalize_atomicity.rs`（由**并行审计线程**创建、尚未删除）。本审计未删除他人文件，需由创建者或负责人收尾删除以保证工作区干净。

---

## 9. 建议优先级

1. **P0（阻塞“无遗留”声明）**：LL-01。修复方式见 `2；修复前应把 `ArchiveWriterBuilder::append_existing` 的 crash-safety 承诺改为“finalize 期间崩溃仍可能损坏既有归档”，并禁止在关键数据上使用 append。
2. **P1**：LL-02（append 内存上限/落盘策略）、LL-03（finalize 前 fdatasync 屏障）、LL-04（打开期校验每卷头摘要）。
3. **P2**：LL-05（chunker API 返回 Result）、LL-06（O_NOFOLLOW/O_EXCL + 父目录 fsync）、LL-07、LL-08（补齐跨字段校验）。
4. **P3（纵深/清理）**：LL-09、LL-10、LL-11。

---

*本文件由 L0–L3 专项审计线程（lowlevel）生成；仅写入 docs/audit/round1-lowlevel.md，未修改任何源码/测试/既有文档，未提交。*
