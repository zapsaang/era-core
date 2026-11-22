# Round 1 专项审计：era-engine 写路径 / append / checkpoint / repair

- **仓库**: /home/ricardom/code/github.com/zapsaang/era-core（branch feat_fly，HEAD b22a07e）
- **审计角色**: engine-writer（独立审计线程；共享任务 task-2）
- **审计范围**: `crates/era-engine/src/{writer.rs, writer/*.rs, checkpoint.rs, repair.rs, recovery.rs, sequence.rs, erasure_scan.rs, volume_capacity.rs, erasure_stage.rs, volume_stage.rs, index_stage.rs, packing_stage.rs, encryption_context.rs}`，以及写路径实际依赖的 `crates/era-volume/src/{writer.rs, volume_pool.rs, reader.rs}`；基线以来 4 个整改提交 `8c42a4c`、`31d358f`、`5ff825e`、`b22a07e` 中与写路径相关的 hunk。
- **方法**: 先读前序两份审计文档与 `git diff ee39fae..HEAD`，再按崩溃安全/状态机、容量与资源边界、repair 分支与幂等、错误传播与部分失败一致性逐项推导；对可疑路径用**临时故障注入探针**复现（探针已删除，见附录 A），并定向复跑既有回归套件。不修改任何源码/测试/既有文档。

## 0. 结论摘要

工程师“已修复全部问题、零技术债、无遗留”的声明 **不成立**。基线以来针对 §4.1（中断 append 不可读）、§4.2（verify 不校验备份头）、§4.4（非 EC 头修复被拒）以及 AUDIT-MED-01/02 的整改主体属实并已被回归测试覆盖，但写路径仍存在 **1 项 High、2 项 Medium、5 项 Low、2 项 Informational** 的遗留缺陷，其中 3 项由整改提交 `8c42a4c` 自身引入或未真正闭环：

| 编号 | 严重度 | 维度 | 标题 | 确认程度 |
|---|---|---|---|---|
| EW-01 | **high** | 性能 / 资源边界 | append 会话把整段追加数据常驻内存（跨卷轮转累积），`sync_data()` 对暂存数据是空操作 | 已确认（代码 + 探针） |
| EW-02 | **medium** | 并发与一致性（崩溃/失败原子性） | append 的 `finalize` 仍先 `truncate` 旧元数据再写新 footer；在 truncate 与 footer 落盘之间崩溃/取消/I/O 失败会让**原有归档不可读且无回滚** | 已确认（故障注入探针；引擎调用链推导） |
| EW-03 | **medium** | 规格符合性（完整性校验覆盖） | `verify`/`repair` 既不检测也不修复损坏的 **primary footer**（仅覆盖 primary/backup header）：footer 冗余静默丢失、且无自愈路径 | 已确认（探针） |
| EW-04 | low | 规格符合性 | 一次需要卷轮转的 append 会把归档静默变成多卷，此后所有 append 永久返回 `Append mode is only supported for single-volume archives` | 已确认（探针） |
| EW-05 | low | 并发与一致性 | 轮转后中断的 append 会在磁盘留下 header-only 的孤儿卷文件（`.era.NNN`），无清理、每次打开都产生发现警告 | 已确认（代码路径 + 既有中断测试场景） |
| EW-06 | low | 规格符合性 | append 已不具备崩溃续传能力：`Resume`/`enable_checkpoint` 只认证旧 checkpoint、丢弃全部进度；未 finalize 的追加数据被静默丢弃，公开 API 文档未声明 | 已确认（探针 + 代码） |
| EW-07 | low | 代码质量 | `VolumeWriter::set_max_size()` 会把暂存 append 尾部破坏性 flush（truncate + 追加、无 footer）并清除 staged 状态；两个 `pub` 方法组合即破坏既有归档，当前引擎路径不可达（潜在 API 陷阱） | 已确认（代码路径） |
| EW-08 | informational | 代码质量 | `read_checkpoint` 文档声称无 block_id 时“brute-force 搜索”，实现并不搜索；`recover_all_checkpoints` 对 legacy（block_id==0）永远失败 | 已确认（代码） |
| EW-09 | informational | 代码质量 | 公开导出的 `RecoveryManager` 恢复 API 永远返回空进度（从不加载 durable checkpoint），`is_file_completed`/`get_chunk_location` 恒为 false/None | 已确认（代码） |
| EW-10 | low | 代码质量 / 并发运行时 | EC repair 的写回路径 `apply_repairs` 在 async 上下文中直接做阻塞 `std::fs` I/O（含每 shard 全量读回校验），违反仓库自身 anti-pattern | 已确认（代码） |

> 事实与推断的区分贯穿每条 finding；性能断言均标注 provable / likely / benchmark-needed；安全类断言本报告未新增（见 §4）。

## 1. 环境与证据基线

- 工具链（按负责人提供的 Nix store 路径）：`cargo 1.99.1` / `rustc 1.99.1`。所有命令前置：
  `export PATH="/nix/store/c2ii5nkzv440xj9igxsd49i8f5y2vr6f-cargo-1.99.1/bin:/nix/store/mslcwkiyh6wayx8gpzlq53wvr3a5pp44-rustc-1.99.1/bin:/nix/store/0x4hw59xdvzm6v79m1rz84a7j2j2yh0z-clippy-1.99.1/bin:/nix/store/3kr36w0awz5q8yia6nwcriaj3f0065qw-rustfmt-1.99.1/bin:$PATH"; export RUSTC=/nix/store/mslcwkiyh6wayx8gpzlq53wvr3a5pp44-rustc-1.99.1/bin/rustc; export CARGO_TERM_COLOR=never`
- 本线程**未**运行全量 workspace 测试（负责人后台运行中，按要求不重复）；只运行定向套件。
- 定向回归（本线程实测，全部 exit 0）：

| 命令 | 结果 |
|---|---|
| `cargo test --release -p era-engine --test resid_high03_checkpoint_append --test resid_high02_header_repair --test resid_high01_catalog_repair --test append_committed_end_invariant --test zero_drift_append_tests -- --test-threads=2` | `resid_high03_checkpoint_append` 12 passed；`resid_high02_header_repair` 6 passed；`resid_high01_catalog_repair` 5 passed；`append_committed_end_invariant` 8 passed；`zero_drift_append_tests` 1 passed；**0 failed** |
| `cargo test --release -p era-cli --test resid_high02_cli_repair -- --test-threads=2` | 3 passed（含非 EC 主头修复、非 EC 头+数据双损文案、备份头损坏检测与修复） |

- 探测结束后 `git status --porcelain` 为空（0 行）；3 个临时探针文件已删除（附录 A）。
- 基线 diff 中与写路径相关的改动只有 4 个文件（`git diff --stat ee39fae..HEAD`）：
  `crates/era-engine/src/writer.rs (+53)、writer/checkpoint_append.rs (+13)、repair.rs (+326)、crates/era-volume/src/writer.rs (+187)`。
  因此本报告把 `8c42a4c`（staged append）、`31d358f`（header repair / verify 备份头）作为重点，其余文件按“遗留缺陷”常规审计。

---

## 2. 发现详述

### EW-01 【HIGH】append 会话把整段追加数据常驻内存，跨卷轮转累积；`sync_data()` 对暂存数据是空操作

- **维度**: 性能 / 资源边界（内存）
- **代码锚点**:
  - `crates/era-volume/src/writer.rs:28-33`：`StagedAppend { base_offset, buf: Vec<u8>, original_footer }`；
  - `crates/era-volume/src/writer.rs:248-252`：`open_append_at()` 打开既有卷后创建 `staged_append`，**不再 truncate**（这是 `8c42a4c` 的核心改动）；
  - `crates/era-volume/src/writer.rs:661-663`（`write_canonical_block`）与 `:721-723`（`write_raw`）：所有新写入 `staged.buf.extend_from_slice(...)`，只增加内存与 `position`，**不落盘**；
  - `crates/era-volume/src/writer.rs:256-265`：唯一 flush 点是 `flush_staged_append()`（`truncate(base)` 后一次性 `append(&staged.buf)`）；
  - flush 调用点只有 `crates/era-volume/src/writer.rs:274-278`（`set_max_size`，引擎 append 路径不可达，见 EW-07）与 `:832`（`finalize_with_catalog`）；
  - `crates/era-volume/src/writer.rs:906`（`close_for_later_finalize` 把 `staged_append` 原样移入 `RetiredVolumeState`）与 `:920-954`（`reopen_for_finalize` 原样恢复）：**卷轮转不会落盘，只是在内存里多保留一个整卷的 Vec**；
  - `crates/era-volume/src/writer.rs:698-700`（`VolumeWriter::sync_data`）→ `StorageWriter::sync_data`：只同步底层文件句柄，对 `staged.buf` 无任何作用。
- **机理**: `8c42a4c` 为保证“append 中断不破坏既有归档”，把 append 期间的全部写入改成内存暂存，直到 `finalize()` 才 truncate+写入。于是 append 的峰值内存 = append 期间写入的所有块（含 checkpoint/catalog/index/manifest）之和，且 `VolumePool::rotate_volumes()` 后旧卷的 `staged_append` 仍驻留内存（`close_for_later_finalize` 只是关闭文件句柄），轮转越多次、内存越大。`Vec` 扩容按倍增策略，峰值还会额外放大（最坏 ~2–3× 暂存字节）。
- **可审计证据**:
  - 代码必然性：`staged.buf.extend_from_slice` 是唯一的写入路径；flush 只在 finalize（或不可达的 `set_max_size`）；`retire/reopen` 保留 buffer。
  - 探针 C（附录 A.1，era-volume 层，8 MiB 暂存）实测：
    ```text
    PROBE_C on_disk_before=13568 on_disk_after=13568 writer_position=8396928 staged_bytes=8383360
    ```
    即 8 MiB 追加数据全部在进程内存，磁盘文件大小不变；`writer.current_size()` 与物理大小差 = 暂存字节。
  - 引擎级影响面：`writer.rs:570-579` 只拒绝 EC 与已有多卷归档，不限制 append 数据量；`volume_pool.rs:402-455` 允许 append 过程中轮转（`resid_high03_checkpoint_append` 的 `checkpointed_append_metadata_rotation_preserves_dense_data_only_ends` 测试即覆盖该行为）；默认单卷上限 `ArchiveConfig.volume.max_size = 1 GiB`（`crates/era-common/src/config.rs:152`），manifest 允许最多 1024 卷（`crates/era-common/src/types/manifest.rs:61`）。因此单次 append 在默认配置下即可要求 ~1 GiB 额外堆内存，多卷 append 可达数 GiB～数十 GiB。
- **分类**: **provable regression**（内存占用从 O(1) 流式写变为 O(append bytes) 暂存；由代码结构直接证明，无需 benchmark）。对 1 GiB+ 的 append，OOM/被内核 kill 的风险是 **likely regression**（取决于运行时剩余内存；被杀时磁盘归档因“尚未写入”仍完好，但 append 失败）。
- **影响**: 公开 API `ArchiveWriterBuilder::append_existing` 的可用性/吞吐退化；大追加在普通机器上可能直接 OOM 失败；`VolumePool` 轮转场景下内存随卷数线性增长且无上限；`sync_data()` 的语义在 append 会话内欺骗性失效（调用成功但数据未持久化）。CLI 未暴露 append，故 CLI 用户不受直接影响，但这是仓库公开引擎 API 的能力回退。
- **确认程度**: **已确认**（代码路径 + 探针 C）。
- **建议修复**:
  1. 首选：放弃“整段暂存”，改为**非破坏性追加布局**：把新数据写到旧文件末尾之后（不 truncate 旧元数据），新 catalog/index/manifest 随后写入，最后以 128B 的 backup-footer 槽（offset 4096，单扇区原子）作为提交点；这样崩溃前旧 footer（备份槽）仍指向完整的旧数据区与旧元数据（旧元数据未被覆盖），既有归档保持可读，同时内存 O(1)。这同时消解 EW-02。
  2. 若保留暂存：至少为 `staged.buf` 设上限（如 1–2 个 target block / 卷预算的固定比例），超限时要求调用方 finalize；并在 `rotate_volumes`/`retire` 时把已完整填满的卷 flush 到临时影子文件而非驻留内存。
  3. `sync_data()` 在 `staged_append.is_some()` 时必须显式返回 `Unsupported`/文档化 no-op，不能静默成功。
- **应补回归测试（TDD）**:
  - `append_large_tail_memory_is_bounded`：用可观测的 `VolumeWriter` 或后端计数，断言 append N MiB 时进程 RSS/暂存字节不超过阈值（当前实现会 FAIL，作为 RED）。
  - `append_rotation_flushes_retired_volume`：append 触发轮转后断言 retired 卷数据已写盘（当前会 FAIL）。
  - `append_sync_data_reports_unsupported_on_staged_writer`。

### EW-02 【MEDIUM】append 的 finalize 仍先 truncate 旧元数据再写新 footer：truncate 与 footer 落盘之间崩溃/取消/I/O 失败会让原有归档不可读且无回滚

- **维度**: 并发与一致性 / 崩溃安全 / 失败原子性
- **代码锚点**:
  - `crates/era-engine/src/writer.rs:2525-2534`：`finalize()` 调 `finalize_with_manifest`；
  - `crates/era-volume/src/volume_pool.rs:1218-1238`：逐卷 `writer.finalize_with_catalog(...)`；
  - `crates/era-volume/src/writer.rs:832`：`finalize_with_catalog` 在**写完内存 footer 字节之后、任何 header/footer 落盘之前**调用 `flush_staged_append()`；
  - `crates/era-volume/src/writer.rs:256-265`：`flush_staged_append` = `truncate(base_offset)` → `append(&staged.buf)`，两个 `.await` 之间无任何保护；
  - `crates/era-volume/src/writer.rs:850-873`：旧 backup header/primary footer 的删除发生在 truncate 之后；新 backup header、primary footer、4096 处 backup footer 依次写入；`:876` 才 `sync()`；
  - `crates/era-volume/src/reader.rs:119-127`：`footer.data_end_offset() > file_size` 直接 `CorruptedFooter`（拒绝打开）；
  - 旧 backup footer（offset 4096）在 truncate 时未被覆盖，仍声明旧 `data_end_offset`。
- **机理**: append 会话开始后，磁盘上的旧 footer（EOF 128B 与 4096 处备份 footer）都完好，故 finalize 之前任意中断都安全（探针 A 证实）。进入 `finalize_with_catalog` 后，`flush_staged_append` 先 `truncate(append_retained_end)`，把旧 catalog/index/manifest/backup header/primary footer 全部裁掉；**在旧 backup footer 被新 footer 覆盖之前**如果：
  - 进程崩溃/断电（截断已持久化，后续 append 内容可能只有部分落盘），或
  - future 被取消（`timeout`/`select`/Ctrl-C：`truncate().await` 返回后、`append().await` 之前 drop），或
  - 后续任一 I/O 失败（disk full、EIO，错误通过 `?` 传播、无回滚），
  则文件尺寸 = `base_offset`（或 base+部分暂存），而 4096 处旧 backup footer 声明 `data_end_offset = 旧完整长度 > file_size` → `VolumeReader::open` 必然拒绝，archive 不可读，且没有任何代码路径能回滚。原 `writer.rs:353-358` 文档“Interrupted append sessions ... leaving the previously finalized archive intact if dropped or aborted”对 **finalize 期间** 的中断不成立。
- **可审计证据（故障注入探针，附录 A.1）**: 在 `StorageWriter` 包装层，令 `truncate()` 成功后**下一次 `append()` 返回注入的 I/O 错误**（等价于 truncate 与 append 之间崩溃/故障）：
  ```text
  PROBE_B finalize_err=Some("I/O error: injected crash/IO failure immediately after truncate, before the new footer is written")
  PROBE_B before_len=13568 after_len=8320 reopen_err=Some("Corrupted footer: Archive appears truncated: footer claims data_end_offset=9344 but file size is 8320")
  ```
  对照：同一会话在 finalize 前被 drop（探针 A）→ `file unchanged=true len=13568`，`reopen_ok=true`。说明 `8c42a4c` 把窗口从“整个 append 会话”缩小到“finalize 的 flush+footer 写入”，但**没有闭环**。
- **分类**: 数据可用性；失败原子性。相对基线（`ee39fae`/`780a26a`：append 一开始就 truncate，任意中断即损坏）是**显著改善**，但相对整改声明（“原归档保持完整可读”）仍是遗留缺陷。
- **影响**: append 如果在 finalize 阶段 crash/OOM-kill/超时取消/磁盘错误，**原有已提交数据整体不可访问**；`era verify`/`repair`/再次 `build(append)` 都会因 footer 校验失败而拒绝。证据来自 era-volume 层探针 + 引擎调用链（`writer.finalize → pool.finalize_with_manifest → VolumeWriter::finalize_with_catalog`）——引擎层路径相同，无额外分支。
- **确认程度**: **已确认**（故障注入复现失败态）+ 引擎路径为代码必然性推导。
- **建议修复**:
  1. 与 EW-01 的修复合并：**不 truncate 旧元数据**；新数据写旧 EOF 之后，新元数据随后，最后以 4096 处 backup footer 的 128B 原子写作为唯一提交点（此时 reader 优先读 EOF primary footer，失败则回退 4096 备份 footer，两个时刻都指向完整数据）。旧 primary footer 变成文件中部的死数据但不再被读取，可接受；或在前一步用新 footer 覆盖旧 primary footer 后再提交 backup footer。
  2. 若保留 truncate：在 truncate **之前**先把“当前尺寸对应的合法 footer”写入 4096 槽（data_end=base+已写数据前缀），使任何时刻都有可打开的 footer；但旧 catalog/manifest 已被裁掉，解包只能靠数据区 + checkpoint，属降级恢复，需产品确认。
  3. 失败路径需要显式回滚或标记（例如 `finalize` 失败时把归档标记为需要 `repair`，并让 `repair` 能用 backup footer + checkpoint 重建）。
- **应补回归测试（TDD）**:
  - `finalize_failure_after_truncate_keeps_previous_archive_readable`：注入“truncate 后 append 失败”，断言 `ArchiveReader::open` 仍成功且能解出旧文件（当前 FAIL）。
  - `finalize_cancelled_between_truncate_and_footer_is_recoverable`：`tokio::time::timeout` 打断 finalize。
  - `finalize_io_error_during_header_write_leaves_recoverable_archive`。

### EW-03 【MEDIUM】`verify`/`repair` 不检测、不修复损坏的 primary footer：footer 冗余静默丢失且无自愈路径

- **维度**: 规格符合性 / 完整性验证覆盖
- **代码锚点**:
  - `crates/era-volume/src/reader.rs:58-78`：primary footer（EOF-128）解析失败时静默回退 4096 处 backup footer，**不记录来源标志**；
  - `crates/era-engine/src/reader.rs:100-133`：`ArchiveReader` 有 `header_recovered_from_backup` 等状态，但**没有** `footer_recovered_from_backup`；`primary_footer()`（`reader.rs:825-827`）实际返回 `VolumeReader::footer()`（可能是备份 footer），命名具误导性；
  - `crates/era-engine/src/reader.rs:2818-2882`：新增的 `verify_backup_headers()` 只比较 **primary/backup header** 的字节与 manifest digest；无任何 footer 对照逻辑；
  - `crates/era-engine/src/chunk_processor.rs:893-897`：`VerifyStats::is_ok()` 只看 blocks/files/errors，warnings 不影响；`reader.rs:853-881` 的 `classify_archive_health` 只有当 warnings 非空才 Degraded——footer 损坏不会产生 warning；
  - `crates/era-engine/src/repair.rs:415-441`（`volume_needs_header_repair`）、`:687-692`（非 EC 早退）、`:705-726`（单卷 repair 只规划 header/catalog）均无 footer 修复分支；
  - `crates/era-engine/src/repair.rs:1172-1183`：`apply_metadata_repair` 是通用“写回固定字节”工具，具备修复 footer 的能力但未被使用。
- **机理**: footer 冗余契约（EOF primary footer + offset 4096 backup footer）与 header 冗余（offset 0 + backup_header_offset）对称，但整改只给 header 加了“双副本比较 + 修复”。primary footer 损坏时：`VolumeReader::open` 回退 backup footer 成功 → 后续所有逻辑看到的就是“合法 footer”，`verify()` 无任何告警，`repair` 认为无需修复。于是归档在“冗余已减半”的状态下被报告为完全健康。
- **可审计证据（探针，附录 A.2）**: 非 EC 单卷归档，仅把文件最后 128B 的 primary footer magic 清零：
  ```text
  PROBE_FOOTER before: primary_data_end=6339 backup_data_end=6339 file_len=10563
  PROBE_FOOTER open_ok=true err=None
  PROBE_FOOTER verify health=Healthy is_ok=true warnings=[] errors=[]
  PROBE_FOOTER primary_footer()_data_end=Some(6339)
  PROBE_FOOTER repair=Err("Erasure coding error: Archive does not use erasure coding - repair not available")
  PROBE_FOOTER after: file_changed=false primary_footer_still_corrupt=true
  ```
  即：打开成功、verify 判 Healthy、repair 不做任何修改、损坏的 primary footer 保持损坏。这与此前 §4.2“备份头冗余静默丢失”是同一类缺陷，只是对象换成了 footer；前序两轮审计均未覆盖。
- **影响**: footer 是“两份”冗余设计的核心；primary footer 的 bitrot/部分覆写无法被发现，直到 backup footer 也损坏（二者都坏时 reader 只能 floating-footer 反向扫描，非 EC 归档更可能直接失败）→ 归档彻底不可打开。`repair` 无法自愈，用户只能依赖再次 append（而 append 会整卷重写，代价高且有 EW-02 风险）。属于“先静默降级、后彻底失效”的路径，与 v8.2 冗余契约、AGENTS 的“对称校验”原则不符。
- **确认程度**: **已确认**（探针复现；代码路径必然）。
- **建议修复**:
  1. `VolumeReader` 增加 `footer_recovered_from_backup: bool`（与 header 对称）；
  2. `ArchiveReader::verify()` 在 `verify_backup_headers()` 旁增加 `verify_footers()`：直接 `read_raw(size-128, 128)` 读 EOF footer（不经 fallback），与 `reader.footer()`（备份/主）逐字节比较并验证 `Footer::from_bytes`；不一致 → `warnings` + Degraded；
  3. `repair`：footer 损坏时用合法副本的 128B 原位写回坏槽（`apply_metadata_repair(path, size-128, good_bytes)` 或 `HEADER_SIZE`）；
  4. `ArchiveReader::primary_footer()` 改名或修正语义，避免误用。
- **应补回归测试（TDD）**:
  - `corrupt_primary_footer_marks_archive_degraded`（当前 FAIL：Healthy）；
  - `repair_restores_primary_footer_byte_identical_then_both_footers_corrupt_still_recoverable`；
  - `corrupt_backup_footer_then_primary_footer_still_repairable`；
  - `verify_footer_mismatch_without_parse_error_is_detected`（两份 footer 都可解析但内容不同）。

### EW-04 【LOW】一次需要卷轮转的 append 会静默把归档变成多卷，此后所有 append 永久失败

- **维度**: 规格符合性（API 能力/文档）
- **代码锚点**:
  - `crates/era-engine/src/writer.rs:570-579`：append 打开时若 `loaded_header.total_volumes() > 1` 返回 `InvalidFormat("Append mode is only supported for single-volume archives")`；
  - `crates/era-engine/src/writer.rs:431-434`：`append_existing()` 的公开文档只说“继承既有 header 的 chunking 配置”，**未提**单卷限制；
  - `crates/era-volume/src/volume_pool.rs:402-455`：append 过程中写满 `max_volume_size` 会 `rotate_volumes()`，创建新卷并把 `total_volumes` 提升；
  - 既有测试 `crates/era-engine/tests/resid_high03_checkpoint_append.rs:130-192`（`checkpointed_append_metadata_rotation_preserves_dense_data_only_ends`）即覆盖“append 期间轮转成 2 卷”。
- **机理**: `append_existing(true)` 的入参检查只针对“当前已是多卷”；但 append 会话内的数据/元数据轮转被允许，轮转后归档成为多卷，下一次 append 在 build 阶段被拒绝。该限制无预检、无警告、文档未声明，用户在一次成功 append 后才发现 archive 失去 append 能力。
- **可审计证据（探针，附录 A.3）**:
  ```text
  PROBE_ROT after create: volumes_in_manifest=1
  PROBE_ROT after rotated append: volumes_in_manifest=2 health=Healthy
  PROBE_ROT second_volume_exists=true
  PROBE_ROT third_append_ok=false err=Some("Invalid format: Append mode is only supported for single-volume archives")
  ```
  注意：第一次探针用重复字节负载（目标块去重）未触发轮转，第二次改用不重复负载后复现。归档本身 Healthy，解包不受影响——所以这是能力/规格问题，不是数据损坏。
- **影响**: append 的“可追加性”被一次写入量静默改变；对需要多次追加的备份工作流是功能性缺陷；错误信息直到下一次 append 才暴露，排障成本高。
- **确认程度**: **已确认**（探针）。
- **建议修复**: (a) 在 append 的 `finalize` 前预检：若本次会话已/将触发轮转，明确 warn 并在 API 文档声明该 append 是最后一次可追加写入；或 (b) 给 append 设置“不得轮转”的硬限制：写满 retained 卷预算时返回 `VolumeSpaceExhausted` 并回滚（staged 未落盘，可安全失败），错误信息说明“append 仅支持单卷，请改用新归档或 repack”；(c) 长期支持多卷 append（manifest 已支持多卷 committed ends，修复面较大）。
- **应补回归测试（TDD）**: `append_beyond_single_volume_capacity_returns_actionable_error_and_preserves_archive`；`append_after_rotation_error_message_documented`（断言错误类型与 CLI/文档一致）。

### EW-05 【LOW】轮转后中断的 append 在磁盘留下 header-only 孤儿卷文件

- **维度**: 并发与一致性（崩溃残留）
- **代码锚点**:
  - `crates/era-volume/src/volume_pool.rs:421-435`：`rotate_volumes()` 在新卷上立即 `VolumeWriter::create(...)`（写入 4096B header + 128B zero backup-footer gap，`crates/era-volume/src/writer.rs:106-142`），**先创建磁盘文件**再赋值给 pool；
  - `crates/era-volume/src/writer.rs:888-910`：`close_for_later_finalize` 只关闭旧 writer（staged 数据仍只在内存）；
  - append 会话被 drop/中断时，没有任何清理路径删除这些新卷文件（`VolumePool` 也没有 Drop）；
  - `crates/era-engine/src/reader.rs:289-337`：打开归档时扫描 `.era.NNN`，孤儿卷 `VolumeReader::open` 失败 → 每次 `warn!("Failed to open volume ...")`，但被容错跳过。
- **机理**: 既有测试 `crates/era-engine/tests/resid_high03_checkpoint_append.rs:643-690`（`interrupted_append_after_volume_rotation_preserves_original_archive`）明确覆盖“轮转后中断 → 原归档 Healthy”，说明轮转确实发生在新卷文件创建之后；中断后该文件既无 footer 也无有效内容，成为永久残留。
- **影响**: 磁盘垃圾（每次中断最多 N 个 4224B 文件）+ 每次打开归档产生误导性 warn 日志；若用户按 `.era.*` 通配符备份/清理，可能误收集这些无效文件。无数据损坏、无安全影响。
- **确认程度**: **已确认（代码必然性）**；未单独为“中断后文件是否存在”再跑探针（探针 A 的同源机制 + 既有测试场景足以证明 create 先于中断发生）。
- **建议修复**: (a) 最终化失败/中断路径（或下次 append 打开时）清理“与本归档 archive_id 相同、无有效 footer、total_volumes 与当前 header 不匹配”的孤儿卷；(b) 或在轮转时改为先写临时名（`.era.NNN.tmp`）最后 rename。
- **应补回归测试（TDD）**: `interrupted_rotated_append_leaves_no_orphan_volume_files`（当前 FAIL）；`subsequent_open_emits_no_orphan_warning`。

### EW-06 【LOW】append 已不具备崩溃续传能力，且公开 API 未声明“未 finalize 的追加数据会全部丢失”

- **维度**: 规格符合性（API 契约/文档）
- **代码锚点**:
  - `crates/era-engine/src/writer.rs:353-362`：`enable_checkpoint` 文档已改写为“只在 finalize 时写 checkpoint 块；被丢弃的 append 会话保持旧归档完整”，但未说明**追加数据本身丢失**；
  - `crates/era-engine/src/writer.rs:657-706`：append 的 `Resume` 只调用 `CheckpointManager::load_from_durable_checkpoint` 做认证，注释明确“never import its locations or progress into a new append session”；
  - `crates/era-engine/src/writer.rs:431-434`：`append_existing()` 文档未提崩溃语义；
  - `crates/era-volume/src/writer.rs:507-511`：staged append 期间 `commit_checkpoint()` 直接 `return Ok(())`（不落盘、不更新 footer），因此**会话内没有任何持久化进度**。
- **机理**: 为了不破坏旧归档，append 期间所有内容（包括本应成为 checkpoint 的块）都留在内存；`sync_data()` 为空操作（EW-01）。中断即全部丢失。`RecoveryStrategy::Resume`/`resume_with_verification` 这两个公开选项在 append 上只剩“认证旧 checkpoint”，名字暗示的续传语义不再成立。
- **可审计证据**: 探针 A（附录 A.1）`PROBE_A crash-before-finalize: file unchanged=true len=13568` + `reopen_ok=true`；代码注释 `writer.rs:661-662`、`writer.rs:507-510`。
- **影响**: 从旧版本迁移的用户/调用方会以为 `Resume` 可续传；实际中断后必须重做整个 append。属行为回退 + 文档未声明。
- **确认程度**: **已确认**（探针 + 代码）。
- **建议修复**: 在 `append_existing`/`enable_checkpoint`/`RecoveryOptions` 的 rustdoc 明确“append 中断 = 追加数据丢失、旧归档保持可读”；若需要续传，实现增量提交点（每 N 个块把已写前缀以新 footer 提交，见 EW-02 的非破坏性布局方案）。
- **应补回归测试（TDD）**: `aborted_append_loses_only_appended_data_and_keeps_archive_readable`（断言 API 文档化的语义）；`append_resume_does_not_claim_progress`。

### EW-07 【LOW】`set_max_size()` 对 staged append 执行破坏性 flush 并清除 staged 状态（公开 API 组合陷阱）

- **维度**: 代码质量 / 失败原子性
- **代码锚点**:
  - `crates/era-volume/src/writer.rs:274-278`：`pub async fn set_max_size(&mut self, ...)` 第一行 `self.flush_staged_append().await?`；
  - `crates/era-volume/src/writer.rs:256-265`：flush = truncate(base) + append(buf)，**不写 footer**；
  - 之后 `write_canonical_block`/`write_raw` 因 `staged_append == None` 走 `max_size.is_some()` 分支，用 `write_at(position)` 继续写，而磁盘上 4096 处仍是旧 footer（`data_end` 为旧长度）；
  - `open_append_at`（`pub`，`:165-254`）与 `set_max_size`（`pub`）同属公开 API。
- **机理/可达性**: 引擎 append 路径通过 `VolumePool::open_append_single_at` 打开 writer，从未对 append writer 调 `set_max_size`（`git grep` 仅命中 `multi_volume.rs`（无 append 路径）与 `writer.rs` 测试）；故当前仓库内**不可达**。但两个 `pub` 方法组合：`open_append_at` 后调用 `set_max_size` 会立即把旧归档截断到 data-only 边界并清空 staged 状态，此后无论 crash 还是正常结束前都处于“footer 与文件不一致”的状态（与 EW-02 同类，但入口是调用方误用而不是 crash）。`MultiVolumeWriter` 的 padded 卷路径是唯一 `set_max_size` 使用方，且其没有 open-append API。
- **影响**: 面向外部 crate 使用者的潜在数据损坏陷阱；不阻塞当前引擎。
- **确认程度**: **已确认（代码路径；仓库内不可达 → 影响为条件性）**。
- **建议修复**: `set_max_size` 在 `staged_append.is_some()` 时返回 `InvalidConfig`（或先把 staging 显式转换成“重新打开为非 staging 模式并写合法 footer”），并在 rustdoc 标注该限制。
- **应补回归测试（TDD）**: `set_max_size_on_append_writer_is_rejected`；`open_append_at_then_set_max_size_keeps_archive_readable`（负例）。

### EW-08 【INFORMATIONAL】`read_checkpoint` 文档声称无 block_id 时 brute-force 搜索，实际不搜索；legacy 冷恢复路径不可用

- **维度**: 代码质量（文档/契约失配 + 遗留死路径）
- **代码锚点**:
  - `crates/era-engine/src/checkpoint.rs:708`：文档 "`block_id` - Optional block ID for direct decryption. If `None`, falls back to brute-force search (legacy volumes)."；
  - `crates/era-engine/src/checkpoint.rs:748-779`：实现只尝试 `Some(id)`；`None` 时直接返回 `Decryption("Could not decrypt checkpoint with any candidate block ID")`，**没有搜索循环**；
  - `crates/era-engine/src/checkpoint.rs:818-822`：`recover_all_checkpoints` 对 `last_checkpoint_block_id == 0`（v8.1/legacy footer 的字段默认值）传 `None` → 必然失败；
  - `recover_all_checkpoints` 标注 `#[allow(dead_code)] // Will be used by cold recovery path`（尚未接入）。
- **影响**: 文档误导 + legacy 冷恢复 helper 事实上不可用；当前生产路径（append 认证旧 checkpoint 传 `Some(block_count)`）不受影响，属遗留技术债/契约不符，不构成现网数据风险。
- **确认程度**: **已确认（代码）**。
- **建议**: 要么实现 block_id 扫描（按 data 区 block 边界枚举 block_id 尝试 AEAD），要么删除该 doc 句子并把 `recover_all_checkpoints` 从公开/保留代码中移除或标注 unsupported（并在错信息中说明 legacy 不支持）。

### EW-09 【INFORMATIONAL】公开导出的 `RecoveryManager` 恢复 API 永远返回空进度

- **维度**: 代码质量（API 真实语义 vs 文档）
- **代码锚点**:
  - `crates/era-engine/src/lib.rs:67`：公开导出 `RecoveryManager`、`RecoveryStatus`、`RecoverableWriter`；
  - `crates/era-engine/src/recovery.rs:247-263`：`RecoveryManager::new` 只在 footer 有 checkpoint 时放入 `CheckpointManager::new(archive_path)`（空 checkpoint 实例），从不加载 durable checkpoint；
  - `recovery.rs:271-323`：`is_file_completed`/`get_chunk_location`/`bytes_written`/`current_volume` 基于这个空 checkpoint → 恒为 false/None/0；
  - `recovery.rs:179-228`：`RecoveryStatus` 的 `completed_files`/`in_progress_file`/`chunks_written` 恒为空，注释写 "Will be populated when checkpoint is loaded"，但没有任何加载代码；
  - `recovery.rs:565-612`：`RecoverableWriter::new` 在 `StartFresh` 分支调用 `old.delete()?`（同步重写 footer 指针），Resume 直接返回 "does not support durable resume"。
- **影响**: 任何外部调用方按 API 名字实现“断点续传/跳过已完成文件”都会静默地全量重做（无数据损坏）；CLI 只用 `RecoveryManager::analyze` 与 `truncate_to_checkpoint`，故 CLI 不受影响。属“零技术债”声明下的公开 API 债。
- **确认程度**: **已确认（代码）**。
- **建议**: 把 `RecoveryManager`/`RecoverableWriter` 标注 deprecated 并在文档说明它们不提供 durable resume；或实现真正的 durable 加载（需要 `KeySession`/`VolumeKey`，可复用 `CheckpointManager::load_from_durable_checkpoint` 的签名，由调用方传入）。补测试：`recovery_manager_does_not_claim_resume_state`。

### EW-10 【LOW】EC repair 写回路径在 async 上下文中进行阻塞 `std::fs` I/O（违反仓库 anti-pattern）

- **维度**: 代码质量 / 并发运行时
- **代码锚点**:
  - `crates/era-engine/src/repair.rs:1186-1233`：`fn apply_repairs(path, repairs)` 同步打开文件、逐 shard `seek/write_all/flush`，并**每个 shard 全量读回**做 CRC 校验，最后 `sync_all`；
  - 调用点 `crates/era-engine/src/repair.rs:1029-1031`（单卷）与 `:1789`（matrix）都在 `async fn` 内直接 `apply_repairs(...)?`，**没有** `spawn_blocking`；
  - 对照实现：同文件 header repair 用了 `tokio::task::spawn_blocking`（`:1172-1183`），RS 重建也用了 `spawn_blocking`（`:1091-1152`）——只有写回路径漏掉。
- **机理**: 每个损坏 shard 的写入 + 读回 + `flush` 在 tokio worker 线程上同步执行；单卷/矩阵 repair 在大归档上会阻塞 worker，若引擎被嵌入多任务运行时（CLI 是单命令进程，影响有限）会拖慢同期任务的调度与心跳。仓库根 `AGENTS.md` 明确 "NEVER block async runtime | spawn_blocking for CPU-heavy work"。
- **分类**: 属既有技术债（不在基线以来的 diff 中），非本次整改引入；CLI 场景实际影响有限。
- **确认程度**: **已确认（代码）**；运行时影响为 **likely**（需 benchmark/运行时可观测才能量化）。
- **建议**: 将 `apply_repairs` 整体移入 `spawn_blocking`（与 `apply_metadata_repair` 一致）；读回校验可改为可选/抽样或批量。
- **应补回归测试**: 难以直接测调度阻塞；可加单元测试断言 `apply_repairs` 在 `spawn_blocking` 内执行（或以 mock 后端计数），并在 benchmark 中观察 repair 期间其他 tokio 任务延迟。

---

## 3. 前序结论核验（写路径相关）

| 前序项 | 声明 | 本线程核实 | 证据 |
|---|---|---|---|
| §4.1（High）中断 append 后归档不可再打开 | `8c42a4c` 已修复 | **大部分闭环，遗留 EW-02** | 探针 A：finalize 前 drop → 文件逐字节不变、可打开；`resid_high03_checkpoint_append` 12/12 通过（含 plain/resume/start_fresh 三种中断 + 二次 append 成功）；但 finalize 阶段中断仍损坏（EW-02） |
| §4.2（Medium）verify 不校验备份头 | `31d358f` 已修复 | **已闭环** | `reader.rs:2818-2882` 新增 `verify_backup_headers`；`resid_high02_cli_repair` 3/3 通过（备份头损坏→verify 失败→repair --force 逐字节恢复→再损坏主头可解包） |
| §4.4（Medium）非 EC 头+数据双损时连认证主头也不修 | `31d358f` 已修复（解耦头修复与数据修复） | **已闭环** | `repair.rs:750-762` 先 `apply_header_repairs` 再判断 `verify_stats`；`:755-760` 数据仍损坏时返回 IntegrityError；CLI 测试断言头已恢复且失败文案不含 erasure parity（`resid_high02_cli_repair` 第 2 个用例通过） |
| AUDIT-MED-02（Medium）checkpoint 写入早于容量判定 / StartFresh 截断前删 checkpoint | 已修复 | **已闭环** | `writer.rs:2177-2186` 先 `precheck_durable_checkpoint_space()` 再取 committed ends 再 `commit_durable_checkpoint()`；StartFresh 的 footer 清理在 `pool` 打开之后（`:1203-1205`）；`resid_high03_checkpoint_append` 的 `finalize_checkpoint_respects_max_volume_size_when_volume_near_full` 与 `append_start_fresh_failure_before_truncation_preserves_existing_archive_and_checkpoint` 通过 |
| AUDIT-MED-01（Medium）GenericWriter 多 chunk 合箱超限 | 已修复 | **已闭环** | `crates/era-engine/src/writer.rs:4365-4366` `for chunks in self.capacity.chunk_groups(packed.chunks)?`，`volume_capacity.rs:138-167` 按 plaintext 预算分组；`resid_low04_packing_and_generic_writer` 由前序审计报告记录通过 |
| AUDIT-HIGH-02（High）多卷主 Catalog verify/repair | 已修复 | **代码路径成立（本线程实测套件通过）** | `reader.rs:2768-2812` 逐卷校验主 Catalog 并推入 warnings；`repair.rs:1305-1335` 规划并写回；本线程实测 `resid_high01_catalog_repair` 5/5 通过 |
| §4.3/§4.5/§4.6/§4.8/§4.9/§4.10（extract 路径） | 已修复 | **超出本线程范围，未核验** | 相关代码在 `chunk_processor.rs`/`reader.rs`，由 engine-reader 线程负责 |
| “零技术债 / 无遗留” | 成立 | **不成立** | 本报告 EW-01～EW-10；其中 EW-04/06/09 属长期存在或整改带来的 API/文档债，EW-08 为文档-实现失配，EW-10 为仓库自身 anti-pattern 违规 |

### 3.1 明确确认无缺陷/已闭环的检查项（本线程验证）

1. **append 中断（finalize 之前）不破坏既有归档**：探针 A 逐字节比较文件不变；`ArchiveReader::open` 与 `verify` 均成功；与 `resid_high03_checkpoint_append::interrupted_append_preserves_readable_archive_across_plain_resume_and_start_fresh` 一致。
2. **StartFresh 的 footer 清理是“重写”而非“清零”**：`era-volume/src/writer.rs:318-370` staged 分支用原 footer 重建并写入 4096 与（若存在）primary footer 槽，sync 后才返回；`resid_high03_checkpoint_append::append_start_fresh_failure_before_truncation_preserves_existing_archive_and_checkpoint`、`interrupted_start_fresh_on_legacy_checkpoint_allows_subsequent_append` 通过。
3. **legacy terminal checkpoint 在裁剪前必须通过 AEAD 认证**：`writer.rs:663-695` 在 `StartFresh` 缺 footer 指针时用 `read_checkpoint(..., Some(retained.block_count))` 认证；`resid_high03_checkpoint_append::legacy_append_rejects_unauthenticated_checkpoint_without_mutating_archive` 通过（错误 `Decryption` 且文件未变）。
4. **append 的 manifest 单调性防护**：`writer.rs:2447-2467` 拒绝 volume count 下降与 committed_end 下降；`:2456-2467` 的循环在 append 轮转（新增卷）场景下允许增长，`checkpointed_append_metadata_rotation_preserves_dense_data_only_ends` 通过。
5. **`VolumePool::committed_ends()` 对 append 的增量换算正确**：`volume_pool.rs:480-505` 用 `initial_committed_end + (current_position - append_start_position)`，在 staged append（`current_size()==position`）下得到“数据区已提交 end”，与 `precheck_durable_checkpoint_space` 使用的 `current_size()` 语义一致；未发现 off-by-one/陈旧值问题。
6. **repair 的 header 修复内容受认证约束**：`repair.rs:341-366` 要求 footer/backup offset 与 header 的 archive_id/epoch/total_volumes/sequence 匹配，`authenticated_header_digest_opt` 优先全局 manifest 摘要表再退本地 manifest，写回内容为“通过 blake3 摘要校验的 header 字节”（`repair.rs:492-519`）；`apply_metadata_repair` 的 offset 来自校验过等于 `data_end_offset` 的 `backup_header_offset`，未发现“任意偏移写”问题（内容亦受 digest 认证）。
7. **repair 分批/取消检查**：header/catalog 写回均有 `check_cancelled`（`repair.rs:525-553`），`--force` 失败后不会静默吞错。

---

## 4. 安全维度说明

本报告未新增 security finding。对写路径可能的安全面做了排查但均未发现可利用问题：
- repair 写回 offset 受 footer 校验（`backup_offset == data_end_offset ≤ file_size`）约束，写回内容需与 manifest 中已认证的 blake3 摘要一致；恶意归档只能让 repair 失败或在其自身末尾 4 KiB 内写回认证过的 header 字节，不构成任意文件写。
- append 的 `read_checkpoint` 走 AEAD（AAD 绑定 archive_id/epoch/volume/block_type/block_id），未认证的 legacy checkpoint 被拒绝（测试覆盖）。
- `clear_backup_footer_gap` 的 staged 分支写入的是由已认证旧 footer 重建的 footer，无外部输入。
- 未发现 `unwrap/expect/panic` 等运行时崩溃点进入写路径（前序审计已覆盖，本线程抽查 `era-volume/src/writer.rs` 与 `era-engine/src/writer.rs` 生产段无新增 panic 路径）。

---

## 5. 未能核实 / 审计限制

1. **全量门禁**：未运行 `cargo test --release --workspace`、`cargo clippy --all-targets -- -D warnings`、`cargo fmt --check`（负责人后台运行全量 release 测试；按要求不重复）。因此“门禁全绿”仅引用前序报告与本线程 35 个定向测试，未独立复验。
2. **§4.3/§4.5/§4.6/§4.8/§4.9/§4.10 的闭环声明**：这些是 extract/`chunk_processor` 路径，不属本线程范围，未核验；本报告不对它们表态。
3. **`checkpointed_append_metadata_rotation...` 之后能否再次 append**：本线程用探针（EW-04）确认不能，但未评估项目是否**有意**如此设计（无文档说明），需要负责人/产品确认该限制是否可接受。
4. **EW-01 的 OOM 阈值**：未做 RSS 基准测试；内存为 O(append bytes) 由代码结构证明（provable），具体在何种数据量下 OOM 取决于部署内存（inference）。
5. **EW-02 引擎级**：探针在 `era-volume::VolumeWriter` 层注入故障；引擎调用链（`ArchiveWriter::finalize → VolumePool::finalize_with_catalogs_and_manifest → VolumeWriter::finalize_with_catalog`）为直线调用，无额外异常分支，故判定引擎层同样受影响；未做进程级 kill -9 注入（会需要外部 harness）。
6. **EW-05**：未新增探针证明“中断后孤儿文件确实存在”；依据是 `rotate_volumes` 先 `VolumeWriter::create` 落盘（代码必然）+ 既有中断-轮转测试覆盖该路径。
7. **性能类**：EW-01 是 provable（内存结构）与 likely（OOM）；未做吞吐/延迟 benchmark。

---

## 6. 建议的 TDD 回归测试清单（按优先级）

| 优先级 | 测试 | 断言（RED 先行） |
|---|---|---|
| P0 | `finalize_failure_after_truncate_keeps_previous_archive_readable` | 注入 truncate 后 append 失败，`ArchiveReader::open` 仍成功且旧文件可解出（当前 FAIL） |
| P0 | `append_large_tail_memory_is_bounded` | append 期间暂存/内存字节有上界（当前 FAIL） |
| P1 | `corrupt_primary_footer_marks_archive_degraded_and_repairable` | verify 报 Degraded + repair 逐字节恢复（当前 FAIL） |
| P1 | `finalize_cancelled_between_truncate_and_footer_is_recoverable` | `timeout` 打断 finalize 后归档可打开（当前 FAIL） |
| P1 | `interrupted_rotated_append_leaves_no_orphan_volume_files` | 无 `.era.NNN` 残留（当前 FAIL） |
| P2 | `append_beyond_single_volume_capacity_is_actionable_or_documented` | 明确错误/警告或文档化（EW-04） |
| P2 | `set_max_size_on_append_writer_is_rejected` | 公开 API 组合被拒绝（EW-07） |
| P2 | `read_checkpoint_without_block_id_supports_or_rejects_legacy` | 文档与实现一致（EW-08） |
| P2 | `recovery_manager_api_state_is_documented_or_removed` | API 真实语义为测试固定（EW-09） |
| P2 | repair 写回路径在 `spawn_blocking` | 代码形态测试或 mock 断言（EW-10） |

---

## 7. 附录：复现探针与关键输出

> 所有探针文件均在审计结束后删除；`git status --porcelain` 为空（0 行）。探针仅使用公开 API/`StorageBackend` trait 故障注入，未修改源码。

### A.1 `crates/era-volume/tests/zz_probe_finalize_atomicity.rs`（已删除）

构造：`VolumeWriter::create` → `write_raw(4096B 数据)` → `write_raw(1024B 伪 catalog)` → `finalize_with_catalog(DATA_REGION_START+4096, 1024, 0, 0,0,0)`（`data_end=9344`，文件长 13568）。随后用 `StorageBackend` 包装 `LocalStorageWriter`：
- 探针 A：`open_append_at(DATA_REGION_START+4096, block_count=0)` → `write_raw(2048B)` → **drop（模拟崩溃/取消，未 finalize）**；
- 探针 B：同上，但包装器的 `truncate()` 成功后置 poison，下一次 `append()` 返回注入 `Io` 错误（模拟 truncate 与 append 之间崩溃/磁盘错误）；
- 探针 C：`open_append_at` → `write_raw(8 MiB)`，比较物理文件长度与 `writer.current_size()`。

输出（`cargo test --release -p era-volume --test zz_probe_finalize_atomicity -- --test-threads=2 --nocapture`）：

```text
running 3 tests
PROBE_A crash-before-finalize: file unchanged=true len=13568
PROBE_A reopen_ok=true
PROBE_B finalize_err=Some("I/O error: injected crash/IO failure immediately after truncate, before the new footer is written")
PROBE_B before_len=13568 after_len=8320 reopen_err=Some("Corrupted footer: Archive appears truncated: footer claims data_end_offset=9344 but file size is 8320")
PROBE_C on_disk_before=13568 on_disk_after=13568 writer_position=8396928 staged_bytes=8383360
test result: ok. 3 passed
```

### A.2 `crates/era-engine/tests/zz_probe_footer_integrity.rs`（已删除）

构造：`ArchiveWriter` 密码模式、`erasure=None`、无压缩，写入 200000B 文件并 finalize；读取文件最后 128B 的 `Footer` 解析确认 `data_end=6339` 且 4096 处备份 footer 相同（文件 10563B）；**只清零最后 128B 的前 4 字节（primary footer magic）**。然后 `ArchiveReader::open` / `verify()` / `repair_archive(..., RepairOptions::default())`。

输出（`cargo test --release -p era-engine --test zz_probe_footer_integrity -- --test-threads=2 --nocapture`）：

```text
PROBE_FOOTER before: primary_data_end=6339 backup_data_end=6339 file_len=10563
PROBE_FOOTER open_ok=true err=None
PROBE_FOOTER verify health=Healthy is_ok=true warnings=[] errors=[]
PROBE_FOOTER primary_footer()_data_end=Some(6339)
PROBE_FOOTER repair=Err("Erasure coding error: Archive does not use erasure coding - repair not available")
PROBE_FOOTER after: file_changed=false primary_footer_still_corrupt=true
test result: ok. 1 passed
```

### A.3 `crates/era-engine/tests/zz_probe_append_after_rotation.rs`（已删除）

构造：1 MiB 卷上限、`target_block_size=256KiB`、非 EC/无压缩 → 创建 512 KiB 归档（manifest 1 卷）→ `append_existing(true)` 追加 900 KiB **不重复**负载（xorshift64 生成，避免目标块去重；首次用重复字节负载未触发轮转，作为对照）→ finalize → 再次 `append_existing(true)`。

输出（`cargo test --release -p era-engine --test zz_probe_append_after_rotation -- --test-threads=2 --nocapture`）：

```text
PROBE_ROT after create: volumes_in_manifest=1
PROBE_ROT after rotated append: volumes_in_manifest=2 health=Healthy
PROBE_ROT second_volume_exists=true
PROBE_ROT third_append_ok=false err=Some("Invalid format: Append mode is only supported for single-volume archives")
test result: ok. 1 passed
```

### A.4 定向回归实测

```text
cargo test --release -p era-engine --test resid_high03_checkpoint_append --test resid_high02_header_repair \
  --test resid_high01_catalog_repair --test append_committed_end_invariant --test zero_drift_append_tests -- --test-threads=2
  resid_high03_checkpoint_append: 12 passed
  resid_high02_header_repair:    6 passed
  resid_high01_catalog_repair:   5 passed
  append_committed_end_invariant: 8 passed
  zero_drift_append_tests:       1 passed
  0 failed

cargo test --release -p era-cli --test resid_high02_cli_repair -- --test-threads=2
  3 passed / 0 failed
```

### A.5 清理证据

```text
$ rm -v crates/era-volume/tests/zz_probe_finalize_atomicity.rs \
        crates/era-engine/tests/zz_probe_footer_integrity.rs \
        crates/era-engine/tests/zz_probe_append_after_rotation.rs
removed ...
$ git status --porcelain
(空，0 行)
```

---

*本文件由 engine-writer 审计线程于 2026-11-22 生成；只读审计，未修改任何源码/测试/既有文档。*
