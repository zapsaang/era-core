# ERA-CORE 代码分析、事实核查与修复方案设计

- **记录与核查日期**: 2026-11-18（状态同步：2026-11-22）
- **分析基线与当前状态**: 原始问题分析与设计基线为分支 `feat_fly` (`e4050a2`)；原 5 个阶段（`Phase 1` ~ `Phase 5`）及后续交叉审计项（[`post-fix-audit-and-residual-findings-2026-11-20.md`](./post-fix-audit-and-residual-findings-2026-11-20.md)、[`post-fix-audit-and-residual-findings-2026-11-21.md`](./post-fix-audit-and-residual-findings-2026-11-21.md)）已由 [`ee39fae`](../) 闭环，复审计补充遗留（[`re-audit-and-residual-findings-2026-11-21.md`](./re-audit-and-residual-findings-2026-11-21.md) §4–§5）亦已由后续原子提交（`8c42a4c`、`31d358f`、`5ff825e` 与工程收口提交）全部清零并通过全量验证。
- **文档定位**: 补充并扩展 [`docs/consolidated-risk-and-recovery-audit-2026-10-10.md`](./consolidated-risk-and-recovery-audit-2026-10-10.md) 与 [`docs/recovery-failure-scenarios-and-flaws-2026-10-10.md`](./recovery-failure-scenarios-and-flaws-2026-10-10.md) 中的既有结论，系统汇总 2026-11-18 本轮源码走查、`era` CLI / 引擎 API 实测以及二次交叉事实核查后确认的全部问题，并记录遵循 **TDD（Red -> Green -> Refactor）** 与 **零技术债** 原则的分阶段修复方案及最终实施验证状态（2026-11-18 初稿仅作分析与方案设计，后续已按阶段全部提交落地）。
- **构建与测试环境说明**:
  - 默认 `PATH` 中的 `cargo`/`rustup` 失效（执行报 `error: command failed: 'cargo': No such file or directory (os error 2)`，系 `~/.rustup/toolchains/*/bin/cargo` 依赖已被 GC 的 `/nix/store/*-glibc-2.42-84/lib/ld-linux-x86-64.so.2` 所致）。
  - 本轮实测统一使用 Nix store 工具链编译 Release 版本二进制与库测试：
    `RUSTC=/nix/store/mslcwkiyh6wayx8gpzlq53wvr3a5pp44-rustc-1.99.1/bin/rustc /nix/store/c2ii5nkzv440xj9igxsd49i8f5y2vr6f-cargo-1.99.1/bin/cargo build --release -p era-cli`
    生成产物为 `target/release/era`（约 `6.4M`）；仓库根目录 [`rust-toolchain.toml`](../rust-toolchain.toml#L1-L3) 已与 CI 对齐为 `stable`。

---

## 一、 问题总览（按严重度与确信度排序）

| 编号 | 严重度 | 类别 / 维度 | 问题摘要 | 验证与修复状态（2026-11-21 同步） |
| --- | --- | --- | --- | --- |
| **FIND-01** | **Critical** | 正确性 / 一致性 | 分卷轮转（`max_volume_size`）存在预加密 AAD 绑定早于轮转、槽位溢出破坏矩阵映射、旧卷提前关闭致 `total_volumes` 过期、以及读/修按总卷数取模而非分卷组宽度等多重架构缺陷，导致轮转后数据错位与漏卷 | **已修复并验证**（原实测：`t7_5a`, `t7_5b`；修复：`c46bad3`..`0d05fcd`, `ab00f11`） |
| **FIND-05** | **Critical** | 正确性 / 一致性 / 容灾 | `append_existing(true)` 追加模式存在三重结构性缺陷（截断在 `data_end_offset` 夹留旧元数据块、`committed_ends` 少算 `T1` 提前截断、未加载 `chunk_index` 且不支持证书），追加任意新内容后 `verify` 与 `extract_all` 必败 | **已修复并验证**（原实测：`CASE_A`, `CASE_B`, `CASE_C`/`t7_3`, `t7_4`；修复：`c5c6733`, `7bfcfdc`, `a431b8b`, `28bd374`, `f030a39`, `77b7f5d`, `780a26a`） |
| **FIND-08** | **High** | 功能正确性 / CLI 接线 / 参数约束 | CLI `era create --max-volume-size` 仅写入 `config.volume.max_size` 而未传给 `builder.max_volume_size(val)` 致限制失效；同时引擎对小 `max_volume_size` 未收敛 `chunker`/`packer`/非 EC `target_block_size` | **已修复并验证**（原实测：`T6a`, `T6b`；修复：`ca670a0`..`6bd7b2e`, `58cb0ac`, `77b7f5d`） |
| **FIND-10** | **High** | 容灾修复 / 一致性 | `--volumes < data_shards`（合法配置如 `--volumes 3 --erasure 4:2`）时，`repair` 误以 `data_shards` 作最低卷数门限，全部修复后仍报 `Partial repair` 并返回 `rc=1` | **已修复并验证**（原实测：`T8a`；修复：`445a1e6`, `b881c85`, `75c9f15`） |
| **FIND-02** | **High** | 正确性 / 格式兼容性 | `GenericArchiveWriter` 用 `BlockType::Data` 的 AAD 加密 Catalog 且缺少 v8.2 `Manifest`，`ArchiveReader` 无法读取 | **已修复并验证**（原实测：`t7_1`；修复：`2d25807`, `d47a8bc`） |
| **FIND-03** | **High** | 容灾 / 规范符合性 | `VolumeReader::open` 未实现注释声称的 Backup Header 回退恢复，主 Header 损坏直接硬失败 | **已修复并验证**（原实测：`T5c-bad_hdr`；修复：`73c8844`, `f8baac0`, `0fc2984`, `d13e54d`, `70f91b5`, `7b35b3c`, `257cde5`） |
| **FIND-04** | **High** | 容灾可靠性 | 纠删码模式下写入的备份 Catalog 块位置被丢弃，读取端从未使用，单卷主 Catalog 损坏时无法回退 | **已修复并验证**（原实测：`T5c-bad_cat`；修复：`0fc2984`, `ce00a01`, `e4306be`） |
| **FIND-13** | **Medium** | 空间预测一致性 / 存储膨胀 | `IndexBuilder::estimated_finalized_disk_size` 用实际条目数估算 Bloom（~1.8 KB），但 `finalize` 写入了按 64 MiB 容量预分配的 `1,000,000` 项 Bloom（~1.2 MB），导致每卷膨胀 ~1.2 MB 且轮转预检查低估索引空间 | **已修复并验证**（原实测：`CASE_A`, `CASE_C`；修复：`26306df`） |
| **FIND-09** | **Medium** | 容灾 / 索引一致性 | `write_index_fanout` 写入分卷 `1..N-1` 的 `IndexManifest` 缺少 `b"IDX\x01"` nonce 前缀、未扇出 `IndexPage`（仍指向卷 0 偏移），且 `restore_embedded_index` 首卷失败即中止 | **已修复并验证**（原实测：`T5b`；修复：`0fc2984`） |
| **FIND-06** | **Medium** | 接口正确性 | 库接口 `ArchiveWriter::add_path` 传入绝对路径单文件时直接拒绝 (`stored_path must not be absolute`) | **已修复并验证**（原实测：`t7_2`；修复：`6e1700b`） |
| **FIND-07** | **Medium** | 正确性 / 边缘路径处理 | CLI `era create` 同名多单文件冲突（小文件静默覆盖、大文件跳过）、失败前提前建卷残留 6 个 `4224B` 空卷、无 `.era` 后缀输出自引用打入归档 | **已修复并验证**（原实测：`T3a`, `T3b`, `T3c`, `T3d`；修复：`382ccd8`, `8e709f8`, `bcf309c`, `d47a8bc`） |
| **FIND-11** | **Medium** | 解包行为 / 错误提示 | `extract --force` 覆盖已有 `0444` 只读文件时因 `File::create` 报 `Permission denied` 并触发清理删盘；无 EC 归档损坏时 `repair` 误导提示 `extract --force` | **已修复并验证**（原实测：`T9f`, `T8c`；修复：`c6c8471`, `0ea8aee`, `8e7697e`, `bcf309c`） |
| **FIND-12** | **Low** | 构建维护性 / CI 门禁 | Rust 1.99.1 编译 `era-engine` 触发 2 处 `Atomic::<u64>::fetch_update` 废弃警告，在 CI `clippy -D warnings` + 浮动 `stable` 工具链下构成门禁失败风险 | **已修复并验证**（原编译期观察；修复：`9e837ad`, `10c7bbe`） |
| **KNOWN-01..05** | **Critical ~ Info** | 既有已识别边界 | 8GB 解包上限、空目录与软链接静默跳过、整卷缺失 `repair` 拒修、dry-run 默认值、`repair` 头尾元数据区扫描边界 | **保持既定边界**（注：`c6c8471` 已将失败清理收敛为仅删除本次会话新建/重写文件；`FIND-03`/`04` 已完成头/Catalog 回退与自愈） |

> **假设证伪记录**：初审曾怀疑 `era repack -o bare_repacked.era`（无显式父目录路径）可能因 `parent() == ""` 在 `create_dir_all` 阶段报错。经实测 **T4b / T4c**（包括带 `0444` 文件与 `-o bare_repacked.era` / `-o ./dot_repacked.era`），`repack` 均以退出码 `0` 正常完成并通过 `verify` (`rc=0`)，原因系 Rust 标准库 `std::fs::create_dir_all("")` 正常返回 `Ok(())`。

---

## 二、 核心问题详述（源码核查机理 + 实测证据）

### FIND-01：分卷轮转（`max_volume_size`）的多重架构缺陷（条带错位、预加密 AAD 失配与漏卷）

- **严重度**: Critical
- **维度**: 正确性、一致性、加密上下文绑定
- **状态**: **实测确认 + 二次深度核查**
- **源码锚点**:
  - [`crates/era-engine/src/write_pipeline.rs:123-141, 293-339`](../crates/era-engine/src/write_pipeline.rs#L123-L141) (`process_chunks` 预加密与 `flush_stripe_internal` 延迟写入)
  - [`crates/era-volume/src/volume_pool.rs:322-399`](../crates/era-volume/src/volume_pool.rs#L322-L399) (`VolumePool::rotate_volumes` 提前锁定 `total_volumes` 并 `finalize`)
  - [`crates/era-volume/src/volume_pool.rs:467-478, 654-682`](../crates/era-volume/src/volume_pool.rs#L467-L478) (`shard_volume_slot` 与 `write_shard` 槽位溢出 / 条带中途轮转)
  - [`crates/era-engine/src/reader.rs:184-230, 684-699, 1103-1109, 2027-2042, 2091-2107`](../crates/era-engine/src/reader.rs#L184-L230) (`discover_volumes` / `load_manifest` / 读取迭代器参数)
  - [`crates/era-engine/src/block_iter.rs:1295-1303`](../crates/era-engine/src/block_iter.rs#L1295-L1303) (`SessionErasureBlockIterator`)
  - [`crates/era-engine/src/repair.rs:1027, 1057-1063`](../crates/era-engine/src/repair.rs#L1027) (`repair_matrix_archive_with_providers`)
- **核查确认的完整问题机理**:
  1. **EC 预加密 `volume_index` 早于写盘分片落位，且 `write_shard` 存在槽位溢出与条带内撕裂轮转**:
     - [`write_pipeline.rs:123-141`](../crates/era-engine/src/write_pipeline.rs#L123-L141) 在数据块送入 `ErasureStage` 缓冲之前就已用当时假设的 `active_volume_sequence`（如 `0..5`）完成了加密和 AEAD AAD 绑定。
     - 直到攒满一个条带并在 [`flush_stripe_internal`](../crates/era-engine/src/write_pipeline.rs#L293-L339) 写盘时，[`VolumePool::write_shard`](../crates/era-volume/src/volume_pool.rs#L654-L682) 若发现目标槽位空间不足，会**先尝试溢出到同一活跃组的其他槽位 `(preferred_slot + i) % len`**（直接破坏矩阵分布确定性与块头绑定的 `volume_index`），若全组满再在条带写到一半时调用 `rotate_volumes()`，将同一条带的剩余分片写到下一代分卷（如 `6..11`），既撕裂条带，又使预加密块内的 `volume_index` 与实际存储卷序号彻底失配。
  2. **多代分卷轮转后旧卷 Header 的 `total_volumes` 过期**:
     - [`rotate_volumes()`](../crates/era-volume/src/volume_pool.rs#L380-L390) 在轮转切换当即调用 `writer.update_total_volumes(new_total)` 与 `writer.finalize()` 关闭旧卷，无法感知后续轮转。若后续发生第 2 次以上轮转，Volume 0 等早期卷 Header 仍写死 `total_volumes = 2`（无 EC）或 `12`（EC）。
     - 从首卷打开时，[`ArchiveReader::discover_volumes`](../crates/era-engine/src/reader.rs#L198-L230) 按首卷的 `total_volumes` 截断扫描（漏掉包含真正最新 `Catalog` 和 `Manifest` 的末卷）；即使从末卷打开，[`load_manifest`](../crates/era-engine/src/reader.rs#L1103-L1109) 对 `ends.len() != expected_volume_count` 的 fail-closed 校验也会在多代/非连续发现情况下拒绝。
  3. **EC 读取与修复迭代器把总卷数 `G * W` 当作条带宽度 `W` 取模**:
     - [`reader.rs:688, 2031, 2095`](../crates/era-engine/src/reader.rs#L688) 与 [`repair.rs:1027, 1058`](../crates/era-engine/src/repair.rs#L1027) 都将 `header.total_volumes()`（如 `24`）作为 `original_volume_count` 传给 `distribution_strategy.calculate_volume(shard_idx, stripe_idx, original_volume_count)`，而非以每组条带卷数 `W`（`config.distribution.target_volumes`，如 `6`）按轮转代次 `generation`（`vol_idx = generation * W + calculate_volume(..., W)`）推进迭代。
- **实测证据**:
  - **`t7_5a`**（库级 API + 4:2 EC + `max_volume_size`）：生成 `24` 卷（`rot_ec.era`..`.023`）；首卷打开报错 `Err(EmptyArchive)`；末卷 `.023` `verify` 报 `blocks_verified: 4, blocks_failed: 72, files_incomplete: 12, errors: 84`（`Not enough shards for recovery: have 1, need 4`）；`extract_all` 报 `Err(Security("Aborting: 16 consecutive block failures: ..."))`。
  - **`t7_5b`**（库级 API + `--erasure none` + 小分卷触发多轮轮转）：生成 `7` 卷（`rot_noec.era`..`.006`）；首卷打开仅见 `expected_volume_count=2, found=[0, 1]`，报 `Err(EmptyArchive)`；从末卷 `.006` 打开可读出全部内容（`blocks_verified: 7, files_verified: 6, Healthy`）。

---

### FIND-05：`append_existing(true)` 追加模式三重结构性缺陷

- **严重度**: Critical
- **维度**: 正确性、一致性、容灾与 API 契约
- **状态**: **实测确认 + 二次核查**
- **源码锚点**:
  - [`crates/era-volume/src/writer.rs:111-151`](../crates/era-volume/src/writer.rs#L111-L151) (`VolumeWriter::open_append`)
  - [`crates/era-volume/src/volume_pool.rs:264-301, 424-446`](../crates/era-volume/src/volume_pool.rs#L264-L301) (`open_append_single` / `committed_ends`)
  - [`crates/era-engine/src/writer.rs:486-594, 989-1024, 1110-1173`](../crates/era-engine/src/writer.rs#L486-L594)
  - [`crates/era-engine/src/block_iter.rs:814, 927-931, 1011-1020`](../crates/era-engine/src/block_iter.rs#L814) (`SessionBlockIterator` / `MultiVolumeSessionBlockIterator`)
- **核查确认的完整问题机理**:
  1. **截断位置为 `data_end_offset` 而非 `initial_committed_end`，将旧元数据块夹留在数据区中间**:
     - `VolumeWriter::open_append` 第 130 行调用 `writer.truncate(footer.data_end_offset())`，保留了前一轮在 `[initial_committed_ends[0] .. footer.data_end_offset())` 写出的全部旧 `Catalog`、`IndexPage`、`IndexManifest`、`Manifest` 块（总大小 `T1`，受 `FIND-13` 影响至少 ~`1.26 MB`），再从 `data_end_offset()` 往后追加新数据块。
     - 注：[`writer.rs:561-570`](../crates/era-engine/src/writer.rs#L561-L570) 还试图用 `Catalog::from_bytes` 直接反序列化密文 Catalog 块导致静默失败（随后 992-995 行才通过 `ArchiveReader::load_catalog()` 重读）。
  2. **`committed_ends()` 少算 `T1` 字节，导致读端扫描提前截断**:
     - `VolumePool::committed_ends()` 第 430-435 行计算 `committed = initial + (current - start_pos) = initial_committed_ends[0] + delta`，却因为 `start_pos` 位于 `initial_committed_ends[0] + T1`，使新一轮写入的 `manifest.volume_committed_ends[0]` 永远比新数据块真实末尾小 `T1` 字节。
     - 追加写入 `delta < T1` 时，`check_commit_or_end!` 会在 `initial_committed_ends[0] + delta` 截断扫描，根本读不到第 2 轮追加的任何新块（**`CASE_A`** 实测）；只有恰好追加与第 1 轮完全相同内容时才被旧块内容“掩盖”（**`CASE_C`/`t7_3`** 实测，以及仓库现有 [`zero_drift_append_tests.rs`](../crates/era-engine/tests/zero_drift_append_tests.rs#L22-L111) 未调用 `verify()` 且追加全同硬链接副本才未暴露）。
     - 若 `delta` 跨过 `initial_committed_ends[0]`（**`CASE_B`** 实测），`block_iter.rs:814, 1011` 不跳过夹在中间的旧 `BlockType::Catalog` 块，使用 `BlockType::Data` 的 AAD 解密直接报 `Decryption error: aead::Error`。
  3. **未恢复 `chunk_index` 且不支持证书认证追加**:
     - `ArchiveWriterBuilder::build`（[`writer.rs:1110-1134`](../crates/era-engine/src/writer.rs#L1110-L1134)）未把旧归档已有 `ChunkHash -> BlockLocation` 填入 `chunk_index`，跨会话追加无法去重。
     - [`writer.rs:486-527`](../crates/era-engine/src/writer.rs#L486-L527) 仅处理 `RecipientType::Argon2idPassword`，证书模式直接失败。
- **实测证据**:
  - **`CASE_A_SMALL_DISTINCT`**: `footer_data_end=2518601, manifest_committed_ends=[4440]`; `verify` 报 `Incomplete` (`File 'second.txt': missing 1 of 1 chunks`); `extract_all` 失败，`second.txt` 未还原。
  - **`CASE_B_64K_INCOMPRESSIBLE`**: `footer_data_end=2584124, manifest_committed_ends=[69944]`; `verify` 报 `errors=["Block logic error: Decryption error: aead::Error", "File 'second_rand.bin': missing 1 of 1 chunks"]`; `extract_all` 失败。
  - **`CASE_C_64K_DUPLICATE` / `t7_3`**: `manifest_committed_ends=[4418] < footer_catalog_offset=1261473`, `verify` 返回 `Healthy`（扫描止步于 `4418`，掩盖了已多写的第 2 份重复数据块）。
  - **`t7_4`**: 证书模式 `append_existing(true)` 返回 `Err(InvalidKey("No valid credentials found for append (password/key mismatch)"))`。

---

### FIND-08：CLI `--max-volume-size` 未接入 Builder，且小分卷场景缺少分块/打包上限收敛

- **严重度**: High
- **维度**: 功能正确性、CLI 参数接线、上下限边界约束
- **状态**: **实测确认 + 二次深度核查**
- **源码锚点**:
  - [`bins/era-cli/src/commands.rs:531-535, 650-656`](../bins/era-cli/src/commands.rs#L531-L535) (`commands::create`)
  - [`crates/era-engine/src/writer.rs:438, 984-986, 1035-1050, 1146-1156, 1212-1215`](../crates/era-engine/src/writer.rs#L984-L986)
  - [`crates/era-volume/src/multi_volume.rs:18`](../crates/era-volume/src/multi_volume.rs#L18) (`MIN_VOLUME_SIZE = 20_608`), [`crates/era-volume/src/lib.rs:65`](../crates/era-volume/src/lib.rs#L65) (`PER_VOLUME_OVERHEAD = 4_248`)
  - [`bins/era-cli/tests/cli_integration_tests.rs:1276-1302`](../bins/era-cli/tests/cli_integration_tests.rs#L1276-L1302) 与 [`cli_integration_tests_comprehensive.rs:2402-2457`](../bins/era-cli/tests/cli_integration_tests_comprehensive.rs#L2402-L2457)
- **核查确认的机理**:
  1. CLI 第 532-534 行仅修改 `config.volume.max_size = val`，从未调用 `builder.max_volume_size(val)`；而 `ArchiveWriterBuilder::build` 第 984-986 行只读取 `self.max_volume_size`，忽略 `config.volume.max_size`。
  2. 更深层约束：`VolumePoolConfig::with_max_size`（[`volume_pool.rs:52-55`](../crates/era-volume/src/volume_pool.rs#L52-L55)）将分卷上限钳位至 `MIN_VOLUME_SIZE`（`20,608` 字节，扣除 `PER_VOLUME_OVERHEAD = 4,248` 字节后单卷最大有效负载仅 `16,360` 字节）。然而引擎 [`writer.rs:1146-1155`](../crates/era-engine/src/writer.rs#L1146-L1155) 只在 `enable_erasure` 为真时裁剪 `target_block_size`，**既未处理非 EC 模式，也未将 `chunker_config.max_size`（默认 `256 KiB`）与 `SmallFilePacker`（默认 `1 MiB`）裁剪至可装入单卷的大小**。若直接接线 `--max-volume-size`，现有传入 `4096` / `8192` / `10240` 并关闭压缩的 64KB CLI 测试（`cli_integration_tests.rs:1276`, `cli_integration_tests_comprehensive.rs:2402,2431`）会触发 `exceeds maximum per-volume capacity` 错误，修复时必须一并做容量收敛。
- **实测证据**:
  - **T6b** (`--erasure none --max-volume-size 262144`)：Header 显示 `Max Volume Size: 256.00 KiB`，但实际仅生成 1 个 `2,316,610` 字节（`> 2.2 MiB`）单卷。
  - **T6a** (`--erasure 4:2 --max-volume-size 262144`)：仅生成 6 个初始卷（每卷约 `1.5 MB`），未发生轮转。

---

### FIND-10：`--volumes < data_shards` 合法配置下 `repair --force` 修复后仍判 `Incomplete` 并返回 `rc=1`

- **严重度**: High
- **维度**: 容灾修复、一致性
- **状态**: **实测确认 + 二次核查**
- **源码锚点**:
  - [`crates/era-engine/src/writer.rs:940-965`](../crates/era-engine/src/writer.rs#L940-L965) (`validate_erasure_volume_count` 允许 `requested_volume_count < total_shards`)
  - [`crates/era-engine/src/repair.rs:99-135, 1009-1015, 1388-1394`](../crates/era-engine/src/repair.rs#L99-L135) (`classify_repair_archive_health`)
  - [`bins/era-cli/src/commands.rs:1185-1220`](../bins/era-cli/src/commands.rs#L1185-L1220)
- **问题机理**:
  - 当总分卷数少于 `data_shards`（如 `--volumes 3 --erasure 4:2`）时，每卷承载多个分片（`ceil(6 / 3) = 2` 个分片/卷）。全部 `3` 卷完整存在且损坏分片已全部修复后，`repair_matrix_archive_with_providers` 在第 1014 行和第 1393 行依然硬编码 `erasure_config.data_shards as usize`（`4`）作为 `minimum_required_volumes`，导致 `3 < 4` 必触发 `ArchiveHealthStatus::Incomplete`，使 `fully_repaired()` 为 `false` 并退出 `rc=1`。
- **实测证据**:
  - **T8a**: `--volumes 3 --erasure 4:2` 损坏 `.era.001` 偏移 4400 128B 后，`era repair --force` 输出 `Shards repaired: 1`、`Unrecoverable blocks: 0`，却紧接着输出 `⚠️ Partial repair: 0 blocks could not be recovered.` 并退出 `rc=1`；紧接着运行 `era verify` 直接返回 `rc=0`。

---

### FIND-02：`GenericArchiveWriter` 使用错误的 `BlockType::Data` AAD 加密 Catalog 且缺少 Manifest

- **严重度**: High
- **维度**: 正确性、格式兼容性
- **状态**: **实测确认**
- **源码锚点**:
  - [`crates/era-engine/src/writer.rs:3525-3552`](../crates/era-engine/src/writer.rs#L3525-L3552) (`GenericArchiveWriter::finalize`)
  - [`crates/era-packing/src/session_builder.rs:116-134`](../crates/era-packing/src/session_builder.rs#L116-L134) (`pack_single` vs `pack_single_with_type`)
  - [`crates/era-engine/src/reader.rs:919-923`](../crates/era-engine/src/reader.rs#L919-L923) (`ArchiveReader::load_catalog`)
- **问题机理与实测证据**:
  - 第 3533 行调用 `catalog_builder.pack_single(catalog_chunk)` 按 `BlockType::Data` 构造 AAD，第 3537 行却按 `BlockType::Catalog` 写入，且未写入 v8.2 `ArchiveManifest` 与 12 字节 Catalog 前缀。`t7_1` 实测 `ArchiveReader::load_catalog()` 返回 `Err(Decryption("aead::Error"))`。

---

### FIND-03：`VolumeReader::open` 未实现注释声称的 Backup Header 回退恢复

- **严重度**: High
- **维度**: 容灾可靠性、规范符合性
- **状态**: **实测确认**
- **源码锚点**:
  - [`crates/era-volume/src/reader.rs:35-89`](../crates/era-volume/src/reader.rs#L35-L89) (`VolumeReader::open`)
  - [`crates/era-volume/src/writer.rs:628-685`](../crates/era-volume/src/writer.rs#L628-L685) (`finalize_with_catalog` 在末尾写入 Backup Header 并在 offset `4096` 与尾部记录 `backup_header_offset`)
- **问题机理与实测证据**:
  - `VolumeReader::open` 第 57 行直接 `Self::try_read_header(&reader, 0).await?;` 未做回退。虽然下方 64-83 行恢复 Footer 不依赖 `header`（仅第 60 行 `erasure_enabled` 与第 85 行错误处理引用 `header`），但未按注释先通过 Footer 找到 `backup_header_offset`。**T5c (`bad_hdr`)** 清零偏移 `0..64` 后，`verify`/`extract`/`repair --force` 全以 `rc=1` 报错 `Invalid magic number`。

---

### FIND-04：纠删码模式下备份 Catalog 块位置被丢弃且读取端从未使用

- **严重度**: High
- **维度**: 容灾可靠性
- **状态**: **实测确认**
- **源码锚点**:
  - [`crates/era-engine/src/writer.rs:2149-2157`](../crates/era-engine/src/writer.rs#L2149-L2157) (`backup_block_ids`)
  - [`crates/era-engine/src/volume_stage.rs:322-348`](../crates/era-engine/src/volume_stage.rs#L322-L348) (`write_catalog_block_sets_to_all`)
  - [`crates/era-engine/src/reader.rs:889-984, 1129-1207`](../crates/era-engine/src/reader.rs#L889-L984) (`load_catalog` / `assemble_catalog_data`)
- **问题机理与实测证据**:
  - `write_catalog_block_sets_to_all` 在主 Catalog 块之后紧邻写完 `backup_sets`（占用连续的 `backup_block_ids = catalog_block_ids.last() + 1 ..`），却未把偏移回传或利用可推导邻接偏移回退读取。**T5c (`bad_cat`)** 损坏单卷 EC 的 `catalog_offset + 40` 后，`verify`/`extract`/`repair --force` 均以 `rc=1` 报错 `Integrity error: BlockHeader CRC verification failed`。

---

### FIND-13：`IndexBuilder` Bloom 过滤器估算尺寸与实际序列化尺寸严重失配（二次核查新发现）

- **严重度**: Medium
- **维度**: 空间预测一致性、存储膨胀、轮转契约
- **状态**: **源码核查确认**（与 `CASE_A`/`CASE_C` 实测体积完全吻合）
- **源码锚点**:
  - [`crates/era-index/src/builder.rs:20-37, 70-77`](../crates/era-index/src/builder.rs#L20-L37) (`DEFAULT_MEM_LIMIT = 64MB` -> `bloom_expected_items = 1,000,000`)
  - [`crates/era-index/src/builder.rs:219-271`](../crates/era-index/src/builder.rs#L219-L271) (`estimated_finalized_disk_size` 按 `entry_count.max(1024)` 重建尺寸估算)
  - [`crates/era-index/src/builder.rs:426-432`](../crates/era-index/src/builder.rs#L426-L432) (`finalize_with_starting_block_id` 序列化未缩容的 `self.store.bloom()`)
  - [`crates/era-engine/src/writer.rs:2161-2166, 2203-2211`](../crates/era-engine/src/writer.rs#L2161-L2166)
- **问题机理**:
  - `IndexBuilder` 打开时按 64 MiB 内存上限分配可容纳 `MAX_BLOOM_ITEMS = 1,000,000` 项的 Bloom 过滤器（在 1% FP 下约 `1.2 MB`）。
  - `estimated_finalized_disk_size()` 第 253-258 行专门用 `entry_count.max(1024)` 构造 `right_sized_bloom`（小归档仅约 `1.8 KB`）汇报给 `writer.rs:2206` 的 `precheck_and_rotate_if_needed`。
  - 但实际写入磁盘的 `finalize_with_starting_block_id()` 第 427 行直接执行 `serialize_bloom(self.store.bloom())`，写出完整的 ~`1.2 MB` 未压缩 Bloom 位图，不仅让 `CASE_A` / `CASE_C` 这种 1 个小文件归档每个分卷尾部平白多出约 `1.26 MB`（`footer_catalog_offset = 1,261,493`），还使轮转前空间预检存在 ~`1.2 MB` 盲区。

---

### FIND-09：`write_index_fanout` 写入分卷 `1..N-1` 缺失 `IDX\x01` 标签、`IndexPage` 未扇出，且读端首卷失败即停

- **严重度**: Medium
- **维度**: 容灾可靠性、索引一致性
- **状态**: **实测确认 + 二次核查**
- **源码锚点**:
  - [`crates/era-engine/src/writer.rs:2263-2317`](../crates/era-engine/src/writer.rs#L2263-L2317) (`finalize_with_starting_block_id` 仅调用在 `get_writer_mut(0)`)
  - [`crates/era-engine/src/volume_stage.rs:412-474`](../crates/era-engine/src/volume_stage.rs#L412-L474) (`VolumeStage::write_index_fanout`)
  - [`crates/era-index/src/reader.rs:365-420, 628-670`](../crates/era-index/src/reader.rs#L365-L420) (`IndexReader::recover_from_volume`)
  - [`crates/era-engine/src/reader.rs:566-597`](../crates/era-engine/src/reader.rs#L566-L597) (`ArchiveReader::restore_embedded_index`)
- **核查确认的机理**:
  1. `write_index_fanout`（`volume_stage.rs:428, 445`）派生密钥与加密 `IndexManifest` 时未先设置 `index_nonce_context[0..4].copy_from_slice(b"IDX\x01")`，与 [`IndexReader::recover_from_volume`](../crates/era-index/src/reader.rs#L365-L420)（以及 [`IndexBuilder::finalize_with_starting_block_id`](../crates/era-index/src/builder.rs#L342-L343)）不匹配。
  2. 更深一层：[`writer.rs:2264-2280`](../crates/era-engine/src/writer.rs#L2264-L2280) 仅向分卷 `0` 写入了 `IndexPage` 块；分卷 `1..N-1` 既没有各自的 `IndexPage` 副本，其扇出的 `MetaIndex` 里 `PagePointer` 偏移也指向分卷 `0` 的物理位置。一旦丢失分卷 `0`，即使修好了 `IDX\x01` 解密 `IndexManifest`，`recover_from_volume` 第 639-670 行按 `PagePointer` 在分卷 `1` 读 `IndexPage` 仍会全部失败！
  3. [`ArchiveReader::restore_embedded_index`](../crates/era-engine/src/reader.rs#L584-L594) 在首卷恢复报错时直接 `return Ok(false)`，连尝试后续分卷的机会都没有。
- **实测证据**: **T5b** 删除分卷 0 后从 `.era.001` 执行 `verify`/`repair`/`extract` 均打印 `WARN V2.1 index recovery failed, continuing without index: Decryption error: aead::Error`。

---

### FIND-06：库接口 `ArchiveWriter::add_path` 传入绝对路径单文件时直接拒绝

- **严重度**: Medium
- **维度**: 接口正确性
- **状态**: **实测确认**
- **源码锚点**: [`crates/era-engine/src/writer.rs:1536-1595`](../crates/era-engine/src/writer.rs#L1536-L1595)
- **机理与实测**: `add_path` 单文件分支（第 1562 行）直接将 `path` 作为 `stored_path` 传给 `add_file_with_path`，触发第 1587 行 `stored_path.is_absolute()` 拒绝。`t7_2` 实测返回 `Err(InvalidConfig("stored_path must not be absolute"))`。

---

### FIND-07：CLI `era create` 的三类路径处理与提前建卷缺陷

- **严重度**: Medium
- **维度**: 正确性、边界路径安全、磁盘残留
- **状态**: **实测确认**
- **源码锚点**:
  - [`bins/era-cli/src/commands.rs:452-467, 656-715`](../bins/era-cli/src/commands.rs#L452-L467) (`collect_archive_volume_paths`, `create`)
  - [`crates/era-engine/src/writer.rs:1567-1582`](../crates/era-engine/src/writer.rs#L1567-L1582) (`collect_own_volume_paths`)
  - [`crates/era-engine/src/reader.rs:1548-1595`](../crates/era-engine/src/reader.rs#L1548-L1595) (`extract_with_iterator`)
- **核查确认的机理与实测**:
  1. **同名多单文件冲突（T3b）**：`commands.rs:693-695` 剥离单文件父目录导致 Catalog 同路径重名；`extract_with_iterator` 第 1548 行在准备阶段一次性检查磁盘是否已存在同名文件（此时目录尚空，全部放入解压计划），小文件写盘时后者用 `File::create` 静默覆盖前者，大文件预创建阶段同样发生二次预创建覆盖或仅在磁盘已预先存在时跳过。
  2. **输入校验前提前建卷（T3a, T3c）**：`commands.rs:656` 先调用 `builder.build().await` 生成 6 个 `4224B` 卷文件，第 668-715 行才检验输入存在性与相对路径，失败后残留 6 个空卷（实测 `T3a` / `T3c`）。
  3. **目录内无 `.era` 后缀输出自包含排除失效（T3d）**：`collect_archive_volume_paths`（`commands.rs:454`）与 `collect_own_volume_paths`（`writer.rs:1569`）直接对传入 `output` 调用 `output.canonicalize()`，而 `VolumePool` 按 `era_volume::volume_path`（[`crates/era-volume/src/lib.rs:70-77`](../crates/era-volume/src/lib.rs#L70-L77)）实际生成 `<output>.era`..`<output>.era.005`（注：`t3_noext/my_archive` 本身无扩展名，`with_extension("era")` 变为 `my_archive.era`；而 `-o dir/sub.out` 时 `with_extension("era")` 会替换扩展名为 `sub.era`）。因原始 `my_archive` 在磁盘不存在，`canonicalize()` 失败返回空集合，**T3d** 实测 6 个分卷全被打入归档内（`Total: 7 files`）。

---

### FIND-11：`extract --force` 覆盖 `0444` 只读文件触发删盘失败，及 `repair` 误导提示

- **严重度**: Medium
- **维度**: 解包健壮性、CLI 交互一致性
- **状态**: **实测确认**
- **源码锚点**:
  - [`crates/era-engine/src/reader.rs:1554, 1607, 1618-1624`](../crates/era-engine/src/reader.rs#L1607)
  - [`crates/era-engine/src/chunk_processor.rs:101, 117`](../crates/era-engine/src/chunk_processor.rs#L101)
  - [`bins/era-cli/src/commands.rs:1209, 1217, 1220`](../bins/era-cli/src/commands.rs#L1209)
- **实测与核查**:
  1. 向包含已有 `0444` 文件的目录运行 `era extract --force`（**T9f**），由于未在覆盖前先 `remove_file`，`File::create` 对只读目标报 `I/O error: Permission denied (os error 13)`（若在多 chunk 预创建路径还会对 `tracked_output_files` 中已记录的原已存在文件执行清理删除）。
  2. 对无 EC 损坏归档运行 `era repair --force`（**T8c**），提示 `Use 'era extract --force' to recover what's possible.`（`extract --force` 仅代表文件覆盖，不启用容错提取）。

---

### FIND-12：Rust 1.99.1 下 `encryption_context.rs` 存在废弃 API 编译告警

- **严重度**: Low
- **维度**: 构建维护性、CI 门禁
- **状态**: **实测确认**
- **源码锚点**: [`crates/era-engine/src/encryption_context.rs:101-145`](../crates/era-engine/src/encryption_context.rs#L101-L145)
- **核查**: 第 103、131 行调用 `AtomicU64::fetch_update`，在 Rust 1.99.1 报 `deprecated ... renamed to try_update`。而 `AGENTS.md` 说明 CI 跟踪 `stable` 且运行 `cargo clippy --all-targets --all-features -- -D warnings`。

---

## 三、 既有已识别边界条件汇总（源码与实测交叉核对）

1. **8GB 累计解包上限与失败全量删盘**（[`reader.rs:47, 1618-1624, 1683-1708`](../crates/era-engine/src/reader.rs#L47)）：详见 [`consolidated-risk-and-recovery-audit-2026-10-10.md`](./consolidated-risk-and-recovery-audit-2026-10-10.md) `SEC-CRIT-01`。
2. **空目录与符号链接静默丢失**（[`commands.rs:676`](../bins/era-cli/src/commands.rs#L676)）：**T2 实测确认**，`empty_dir/nested_empty` 与有效/悬空符号链接均被静默跳过（`Total: 1 files`）。
3. **整卷缺失时 `repair` 拒修与 dry-run 默认值**：**T5a/T5b 实测确认**，不带 `--force` 默认 dry-run（`rc=0`，无 `.bak`）；删卷后 `repair --force` 退出 `rc=1` 拒绝重建缺失卷，而 `extract` 仍可通过在线 RS 还原全部文件（`diff -r rc=0`）。
4. **单卷归档元数据保护边界**：`repair` 仅扫描纠删码数据区 `[data_start, erasure_data_end)`，不覆盖修复头尾元数据区（参见 [`FIND-03`](#find-03)、[`FIND-04`](#find-04) 实测结果）。

---

## 四、 全面实测记录与结果矩阵

### 4.1 CLI 实测矩阵（基于 `target/release/era`）

| 用例编号 | 测试场景与操作 | 退出码 | 实际结果与关键观察 |
| --- | --- | --- | --- |
| **T1** | 目录（10 文件 / 4.06 MiB，含空文件、`0444`/`0755` 权限、Unicode/空格文件名、2MB 零与随机文件）`create -> info -> list --long -> verify -> extract -> diff -r` | 全 `0` | 全部 10 个文件完整还原，`diff -r rc=0`，权限与 0 字节文件正确保留 |
| **T1b** | 单文件（2.00 MiB）全链路 `create -> info -> list --long -> verify -> extract -> diff` | 全 `0` | 还原一致 |
| **T2** | 含空目录与有效/悬空符号链接目录 `create -> list` | `0` | `Total: 1 files`（仅普通文件），空目录与软链接均被静默跳过 |
| **T3a** | `era create /tmp/.../no_such_file.txt -o ...` | `1` | 失败后残留 **6 个 `4224B`** 空分卷（[`FIND-07`](#find-07)） |
| **T3b** | 跨目录同名多单文件（小文件 / 大文件）打包与提取 | `0` | 小文件无 `--force` 静默覆盖为 `d2`；大文件无 `--force` 跳过 `d2`，加 `--force` 覆盖（[`FIND-07`](#find-07)） |
| **T3c** | 子目录中执行 `era create .. -o ...` | `1` | 失败后残留 **6 个 `4224B`** 空分卷（[`FIND-07`](#find-07)） |
| **T3d** | 输入目录内 `-o .../t3_noext/my_archive`（无 `.era` 后缀） | `0` | `Total: 7 files`，6 个初始 `4.12 KiB` 分卷全被打入归档自身（[`FIND-07`](#find-07)） |
| **T4a** | `keygen`（x25519 + hybrid + `ERA_KEY_PASSPHRASE`）、证书加解密、2-of-3 Shamir 门限 | 符合预期 | 全部正常路径 `rc=0`；缺份额/重复口令被拒，任意 2/3 不同口令 `rc=0` |
| **T4b/c** | `era repack -o bare_repacked.era` 及 `./dot_repacked.era`（含 `0444`） | `0` | 通过（证伪初始无父目录报错猜想） |
| **T5a** | 4:2 多卷 `.era.001`/`.era.004` 损坏 128B -> `verify` -> `repair` -> `repair --force` -> `verify` -> `extract` | 符合预期 | dry-run `rc=0` 无 `.bak`；`--force` 生成 6 个 `.bak` 并修复 2 分片，`diff -r rc=0` |
| **T5b** | 删除 `.era`（Vol 0）和 `.era.003`，从 `.era.001` 执行 `verify`/`repair --force`/`extract` | `repair rc=1`, `extract rc=0` | `repair` 拒修缺失卷；`extract` 在线 RS 还原 `diff -r rc=0`；均报 `V2.1 index recovery failed: Decryption error`（[`FIND-09`](#find-09)） |
| **T5c** | 单卷 EC（`--volumes 1 --erasure 4:2`）：数据区损坏 / 清零 `0..64` / 损坏 `catalog_offset+40` | 数据区修好；头/目录全 `1` | 头损坏报 `Invalid magic number`（[`FIND-03`](#find-03)）；目录损坏报 `BlockHeader CRC verification failed`（[`FIND-04`](#find-04)） |
| **T6a/b** | `era create --max-volume-size 262144`（EC 与 non-EC） | `0` | Header 显示 `Max Volume Size: 256.00 KiB`，但未轮转（T6b 为单卷 `2,316,610B`）（[`FIND-08`](#find-08)） |
| **T8a** | `--volumes 3 --erasure 4:2` 损坏 `.era.001` -> `repair --force` -> `verify` | `repair rc=1`, `verify rc=0` | `Shards repaired: 1, Unrecoverable blocks: 0` 但误报 `Partial repair` 退出 `1`；后 `verify rc=0`（[`FIND-10`](#find-10)） |
| **T8b/c/d/e** | LZ4 配置、无 EC `repair --force`、空白密码、从 `.era.001` `repack` | 符合预期 | LZ4/repack 通过；空白密码拒绝；无 EC 损坏 `repair` 给出误导 `extract --force` 提示（[`FIND-11`](#find-11)） |
| **T9b/d/e/f/g** | `--no-compression`、双认证、1:1 损坏修复、`0444` 覆盖、Stripe 2 损坏修复 | 仅 **T9f** `rc=1` | 向已有 `0444` 文件目录再运行 `extract --force` 报 `Permission denied (os error 13)`（[`FIND-11`](#find-11)）；其余全部通过 |

### 4.2 引擎库级 API 实测矩阵（临时测试均已删除）

| 测试用例 | 测试内容 | 结果 |
| --- | --- | --- |
| **`t7_1`** | `GenericArchiveWriter` 创建归档后用 `ArchiveReader::load_catalog()` 打开 | **复现确认 `FIND-02`**：`Err(Decryption("aead::Error"))` |
| **`t7_2`** | `ArchiveWriter::add_path(&abs_file, false)` | **复现确认 `FIND-06`**：`Err(InvalidConfig("stored_path must not be absolute"))` |
| **`t7_3` / `CASE_C`** | `append_existing(true)` 追加相同 64KB `0xAB` 块 | `verify()` 返回 `Healthy`（因 `manifest_committed_ends=[4418]` 截断扫描未读取第 2 轮重复块，掩盖了重复写） |
| **`CASE_A` / `CASE_B`** | `append_existing(true)` 追加不同小文件或 64KB 不可压缩文件 | **实测确认 `FIND-05`**：`CASE_A` 报 `missing 1 of 1 chunks`；`CASE_B` 报 `Decryption error: aead::Error` + `missing 1 of 1 chunks`；`extract_all` 均失败 |
| **`t7_4`** | 证书模式 `ArchiveWriter::builder().certificate(...).append_existing(true)` | **复现确认**：`Err(InvalidKey("No valid credentials found for append (password/key mismatch)"))` |
| **`t7_5a`** | 库 API `max_volume_size` + 4:2 EC 触发轮转（生成 24 卷） | **复现确认 `FIND-01`**：首卷报 `EmptyArchive`；末卷 `.023` `verify` 报 72 块失败，`extract_all` 中止 |
| **`t7_5b`** | 库 API `max_volume_size` + `--erasure none` 触发多轮轮转（生成 7 卷） | **复现确认 `FIND-01`**：首卷报 `EmptyArchive`（`expected_volume_count=2`）；末卷 `.006` 可读 |

---

## 五、 综合结论（2026-11-18 初始基线与 2026-11-21 收口状态）

1. **2026-11-18 基线（`e4050a2`）**：仅在**固定初始分卷数、无轮转、无追加、头与 Catalog 完好**的前提下，`era` CLI 可完成常规打包、校验、分片损坏修复与丢卷在线解包；分卷轮转（`FIND-01`/`FIND-08`）、增量追加（`FIND-05`）、单卷头/目录灾备回退（`FIND-03`/`FIND-04`）、缺卷 0 索引恢复（`FIND-09`）、Bloom 预估膨胀（`FIND-13`）、`< data_shards` 卷数修复退出码（`FIND-10`）与 `GenericArchiveWriter`（`FIND-02`）及路径/权限边界（`FIND-06`/`FIND-07`/`FIND-11`/`FIND-12`）均处于待修复状态。
2. **后续收口状态（`ee39fae` 及 2026-11-22 复审计整改提交）**：上述 `FIND-01` ~ `FIND-13`、`Phase 1` ~ `Phase 5`（含 `Phase 3.5.1` ~ `3.5.5`）以及 [`post-fix-audit-and-residual-findings-2026-11-20.md`](./post-fix-audit-and-residual-findings-2026-11-20.md)、[`post-fix-audit-and-residual-findings-2026-11-21.md`](./post-fix-audit-and-residual-findings-2026-11-21.md)、[`re-audit-and-residual-findings-2026-11-21.md`](./re-audit-and-residual-findings-2026-11-21.md) 所列全部遗留问题均已完成修复与 TDD 验证（详见第六节末尾验证记录）。

---

## 六、 符合 TDD 与零技术债原则的修复方案设计

> **设计总则**：
> 1. **严格分层依赖**：遵循 `L0 (common, crypto) <- L1 (storage) <- L2 (volume, codec) <- L3 (index, ingest, packing) <- L4 (engine) <- L5 (cli)` 自底向上顺序演进，绝不引入跨层逆向依赖或双轨兼容补丁。
> 2. **严格 TDD 闭环（Red -> Green -> Refactor）**：每个问题先编写可复现失败的红灯测试（覆盖 CLI 与库 API 边界），最小闭环变绿后整理公共辅助函数并校验现有审计回归套件（包括针对源码文本做结构断言的 `adversarial_audit_v*` 套件及现有 CI 检查）。
> 3. **零技术债约束**：不留临时旁路、不屏蔽断言/告警、对既有审计断言（如 `era-index/tests/adversarial_audit_v22.rs:156` 的函数窗口大小与 `V19-F7`/`V22-F2`/`IDX\x01` 标记、`v2_log_01_threshold_append_rejected_e2e`、`cli_boundary_tests.rs` 等）保持完全兼容。

### Phase 1（L2/L3 卷级容灾与索引一致性）：`FIND-03`、`FIND-04`、`FIND-09`、`FIND-13`、`FIND-12`

> **当前状态（2026-11-21 同步）**：**已完成并补充收口**（主线修复：`9e837ad`、`26306df`、`73c8844`、`f8baac0`、`0fc2984`；后续非 EC/轮转退役卷主头修复、主 Catalog 原位自愈及读端备份头摘要校验已由 `d13e54d`、`70f91b5`、`7b35b3c`、`e4306be`、`257cde5` 补全）。

#### 1.1 `FIND-03`：`VolumeReader::open` Backup Header 回退恢复与 `repair` 主头自愈
- **设计方案**:
  1. 在 [`crates/era-volume/src/reader.rs:45-118`](../crates/era-volume/src/reader.rs#L45-L118) 中调整读取顺序：**先独立恢复 Footer**（Primary Footer `size - FOOTER_SIZE` -> Backup Footer 偏移 `HEADER_SIZE` -> Floating Footer scan，此三步均不依赖主 Header），同时将第 60、85 行的 `erasure_enabled` 判断推迟到 Header 加载完成后执行（并在需要判断的最后回退分支做安全默认处理）。
  2. 再尝试 `Self::try_read_header(&reader, 0).await`；若失败，则检查已恢复 `footer` 是否存在 `backup_header_offset >= DATA_REGION_START` 且 `backup_header_offset + HEADER_SIZE <= size`，若满足则读取 Backup Header 恢复 `SuperHeader`，记录警告并将新字段 `header_recovered_from_backup: bool` 置为 `true`（主头与备份头均损坏才返回 `CorruptedHeader`）。
  3. 在 `era-engine` 层消费 `VolumeReader::header_recovered_from_backup()`：
     - `ArchiveReader::verify()` 将其计入 `stats.warnings`（归档健康度标为 `Degraded` 而非 `Healthy`）；
     - `repair_archive*` 在扫描数据区前先检测是否存在主头通过备份恢复的卷，将 4096 字节有效 Backup Header 通过同一 `apply_repairs` / `write_at(0, ...)` 原位修回主 Header 区域（与 `.bak` 备份语义一致）。
- **TDD 用例（先红后绿）**:
  - `era-volume` 单测：将已 finalize 卷前 `0..64` 字节清零（保留尾部 Backup Header 与 Footer），断言 `VolumeReader::open` 成功且 `header_recovered_from_backup() == true`、配置与 `recipients` 完整一致；同时测试主备两份 Header 全毁时仍 fail-closed 返回 `Err(CorruptedHeader)`。
  - `era-engine` 端到端测试（对应 **T5c `bad_hdr`**）：损坏单卷 `0..64` 字节后，`verify()` 返回 `Degraded`，`repair_archive(dry_run=false)` 返回 `Healthy`，且后续 `VolumeReader::open` 不再依赖备份回退。

#### 1.2 `FIND-04`：EC 模式下备份 Catalog 块读取回退（与 `repair` 对主 Catalog 的自愈）
- **设计方案**:
  1. 利用既有写入格式不变量：[`writer.rs:2190-2202`](../crates/era-engine/src/writer.rs#L2190-L2202) 与 [`volume_stage.rs:322-348`](../crates/era-engine/src/volume_stage.rs#L322-L348) 写入的主 Catalog 与备份 Catalog 为**两组等 chunk 数、紧邻排列的块序列**，且 `backup_block_ids[k] = catalog_block_ids[k] + chunk_count`（当仅 1 块时即为紧邻主块之后的 `(catalog_offset + BlockHeader::SIZE + catalog_size, catalog_block_id + 1)`）。**不更改盘上 Footer 布局（向后兼容旧归档）**。
  2. 在 [`ArchiveReader::load_catalog`](../crates/era-engine/src/reader.rs#L889-L984) 中抽取公共辅助方法 `try_load_catalog_from_offset(reader_idx, offset, expected_size_opt, block_id)`：
     - 对每候选卷，先尝试主位置 `(footer.catalog_offset(), footer.catalog_size(), footer.catalog_block_id())`；
     - 若主位置读取、BlockHeader CRC、AEAD 解密或 [`assemble_catalog_data`](../crates/era-engine/src/reader.rs#L1129) 任一环失败，且该卷启用了 EC（`reader.header().config().erasure.is_some()`）：
       1. 若主 `BlockHeader` 可解析（或主 `catalog_size` 已知），计算紧邻主块组之后的位置作为 `backup_start_offset`；若主位置跨度因损坏无法确认 `chunk_count`，则在 `[footer.catalog_offset() .. catalog_end_bound]` 区间调用 `reader.scan_for_typed_blocks(BlockType::Catalog)` 按候选序列尝试备份块组（利用 `(offset, backup_block_id)` 解密校验 AEAD Tag 与 `ArchiveManifest::catalog_commitment` 承诺校验，防止伪造块）。
  3. 对单卷 `repair` 增加检查：若主 Catalog 校验失败但备份 Catalog 合法且通过 `catalog_commitment` 校验，可据需要告警或在独立恢复路径修复。
- **TDD 用例（先红后绿）**:
  - 单卷 EC（`--volumes 1 --erasure 4:2`）与多 chunk 大 Catalog（触发 `chunk_count > 1`）测试：破坏 `footer.catalog_offset() + 40`（`BlockHeader` / 密文 payload，对应 **T5c `bad_cat`**），断言 `load_catalog()`、`verify()`、`extract_all()` 全成功；同时验证主备 Catalog 均被篡改时仍 fail-closed。

#### 1.3 `FIND-13` & `FIND-09`：精确落盘 Bloom 尺寸 + 全部卷完备索引扇出与回退容错
- **设计方案**:
  1. **消除 `FIND-13` 的 1.2MB 膨胀与估算偏差**:
     - 在 [`crates/era-index/src/store.rs`](../crates/era-index/src/store.rs) 提取统一辅助 `build_right_sized_bloom(&self) -> Result<Bloom<ChunkHash>>`（当 `entry_count < bloom_sized_for` 时按 `entry_count.max(1024)` 分配并流式遍历 Redb key 填位，否则直接返回已紧贴容量的 `self.bloom`）。
     - 在 [`IndexBuilder::estimated_finalized_disk_size`](../crates/era-index/src/builder.rs#L219-L271) 与 [`IndexBuilder::finalize_with_starting_block_id`](../crates/era-index/src/builder.rs#L426-L432) 两处**共用这同一个辅助函数**序列化 Bloom，使估计尺寸与实际落盘尺寸零偏差，并将小归档每卷元信息体积极限压缩回数 KB 级。
     - **合规注意**：保持 `pub async fn finalize<W: StorageWriter>` 的外层包装与注释 `V19-F7`/`V22-F2`/`b"IDX\x01"` 不被挪移破坏（满足 [`adversarial_audit_v22.rs:156-176`](../crates/era-index/tests/adversarial_audit_v22.rs#L156-L176) 等审计测试对源码切片的检查）。
  2. **修复 `FIND-09` 的多卷索引扇出与读端容错**:
     - 为确保删除卷 0 后任一存活卷（`.era.001..`）均可独立恢复完整的 V2.1 嵌入式索引，不再仅向卷 0 写入 `IndexPage`：
       - 将 [`IndexBuilder::finalize_with_starting_block_id`](../crates/era-index/src/builder.rs#L308) 拆分为只读一次 Redb 生成 `(Vec<(ChunkHash, ChunkHash, BlockId, Vec<u8>)> page_plaintexts, Vec<(ChunkHash, ChunkHash, u64)> page_metadata, Vec<u8> bloom_bytes)` 的公共流程，再对所有活跃卷 `slot in 0..volume_count` 分别按其 `volume_sequence`、`IDX\x01` 域标签与各自落盘物理偏移加密写出 `IndexPage` 集合与专属 `MetaIndex`（`IndexManifest`）；或由 `VolumeStage::write_index_to_volume(...)` 为每卷独立封装生成。
       - 这样**所有现存单处实现统一使用 `IDX\x01` 域分隔标签**（彻底删除 `write_index_fanout` 中错误传原始 `nonce_context` 的分支）。
     - 同时更新 [`ArchiveReader::restore_embedded_index`](../crates/era-engine/src/reader.rs#L566-L597)：循环尝试所有 `footer.has_index()` 的分卷；某一卷解码/解密失败仅记录告警并继续尝试下一卷，仅当全部候选卷均失败时才设 `embedded_index_recovery_failed = true` 并返回 `Ok(false)`。
- **TDD 用例（先红后绿）**:
  - 断言 `IndexBuilder::estimated_finalized_disk_size()` 对任意条目数（`0`, `10`, `5000`）与 `finalize_with_starting_block_id` 实际写入卷的增量字节完全相等（**误差 <= 0 字节，严格匹配**）。
  - 多卷归档物理删除卷 0 `t1.era` 后从 `t1.era.001` 打开（对应 **T5b**），断言 `ensure_embedded_index_recovered()` 成功、`restore_embedded_index()` 返回 `Ok(true)` 且 `verify()` 零 `Decryption error` 警告。

#### 1.4 `FIND-12`：消除 `encryption_context.rs` 的 Rust 1.99 废弃方法告警
- **设计方案**：将 [`crates/era-engine/src/encryption_context.rs:103, 131`](../crates/era-engine/src/encryption_context.rs#L103) 两处 `.fetch_update(Ordering::AcqRel, Ordering::Acquire, ...)` 替换为标准显式 `load(Ordering::Acquire)` + `compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)` CAS 循环，消除废弃 API 告警同时兼容 1.98.1 与 1.99+。

---

### Phase 2（L2/L4 追加模式结构性根治）：`FIND-05`

> **当前状态（2026-11-21 同步）**：**已完成并补充收口**。Phase 3.5.1 主体修复已在提交 `c5c6733`、`7bfcfdc` 落地（统一在 `initial_committed_end` 截断、清除密文 `Catalog::from_bytes` 死代码、支持证书/混合认证追加、恢复可去重 `chunk_index`、收严 `BlockType::Data` 判定，并在未显式覆写 `max_volume_size` 时保留历史 `< 1 MiB` 归档追加兼容）；后续遗留的 `SmallFilePacker` 原始哈希去重污染、`Checkpoint` 归档追加、`volume_sequence` 索引及退化新建容量校验等边界也已由 `a431b8b`、`28bd374`、`1009dee`、`f030a39`、`77b7f5d`、`780a26a` 全部闭环修复。

- **设计目标**：让 `append_existing(true)` 在追加**不同小文件、不同不可压缩大文件、相同/去重块、单密码或证书/混合认证**归档后均做到零冗余元数据块夹留、`chunk_index` 真实跨会话去重、`manifest.volume_committed_ends` 与实际数据区末尾严丝合缝，且 `verify()` 返回 `Healthy`、`extract_all()` 完整还原所有历史与新增文件。
- **详细方案**:
  1. **统一前置只读打开与认证/元数据加载**（[`crates/era-engine/src/writer.rs:445-595, 989-1024, 1110-1135`](../crates/era-engine/src/writer.rs#L445-L595)）：
     - 在验证且拒绝 `AccessPolicy::Threshold(_)`（保留 `v2_log_01_threshold_append_rejected_e2e` 契约）以及拒绝 EC 追加（或按现有格式约束保留单卷非 EC 校验）后，直接利用现有 `auth` 模块与 `ArchiveReader::open_with_providers` 支持全套 `AuthMode`（`Password` / `Certificate` / `Hybrid` / `HybridKem` / `HybridKemWithPassword`）解密 `MK` 与 `VolumeKey`。
     - 通过 `ArchiveReader::preflight_metadata_recovery()` 加载权威的 `Catalog`、`ArchiveManifest` 与嵌入式 `IndexReader`；**删除 [`writer.rs:561-570`](../crates/era-engine/src/writer.rs#L561-L570) 对加密 Catalog 调 `Catalog::from_bytes` 的无效死代码**。
     - 从旧 `manifest.volume_committed_ends[0]` 获取真实数据区终点 `initial_committed_end`（若缺失 Manifest 的老格式归档，兼容回退为首份 `Catalog/Index/Manifest/Checkpoint` 之前的可扫描末尾）。
  2. **清理尾部旧元数据区，对齐物理偏移与 `block_id` 空间**（[`crates/era-volume/src/writer.rs:111-151`](../crates/era-volume/src/writer.rs#L111-L151)、[`crates/era-volume/src/volume_pool.rs:264-301, 424-446`](../crates/era-volume/src/volume_pool.rs#L264-L301)）：
     - 在 `VolumeWriter` 新增 `open_append_at(backend, path, header, footer, append_offset, initial_block_count)`（保留原有 `open_append` 签名不破坏 `adversarial_audit_v2.rs`/`v26.rs` 现有单测）：要求 `DATA_REGION_START <= append_offset <= footer.data_end_offset() <= actual_size`，将文件直接截断到 `append_offset = initial_committed_end`！
     - 通过快速扫描 `[DATA_REGION_START .. initial_committed_end)` 头部长度链准确统计第一轮已有 `BlockType::Data` 块数 `data_block_count`（因为之前每次 finalize 都往尾部写入了 `Catalog`/`Index`/`Manifest` 等非 Data 块并把 `footer.block_count()` 累加了 `C+I+M`，直接用 `footer.block_count()` 会包含已被截断删掉的旧元数据块 ID，但新块只应从“截断后留存的真实数据块数”接续！），将 `writer.block_count` 与 `EncryptionContext::with_starting_block_id` 设为 `data_block_count`。
     - 结果：截断之后磁盘文件中只剩纯正连续的 Session 1 数据块 `[DATA_REGION_START .. initial_committed_end)`；Session 2 新数据块紧随其后，块序号严格连续，`VolumePool::committed_ends()`（或直接读取写入端写尾部元数据前的新 `writer.current_size()`）天然等于所有数据块真实终点！
     - （崩溃安全说明：在 trunc 之前如用户环境需要极端掉电恢复，可结合既有的 Checkpoint/Journal 语义，或在 `writer.sync_data()` 后进入写入周期；但就归档结构不变量而言，截断至 `initial_committed_end` 是唯一不会产生“数据区中间夹杂非 Data 块 + 偏移错位”的技术债零残留方案。）
  3. **跨会话去重索引预热与块位置继承**（[`crates/era-engine/src/writer.rs:1110-1135, 2102`](../crates/era-engine/src/writer.rs#L1110-L1135)）：
     - 在创建新的 `chunk_index` 时，将原归档恢复出的已提交 chunk 映射（优先通过已恢复的 `IndexReader` 导入全部已有 `(ChunkHash, BlockLocation)`；若无索引，则回退扫描数据块或从已有 `Catalog` 构建映射）预插入 `chunk_index`。
     - 将旧 `catalog.block_locations` 保留并与本轮新增 `pipeline.take_written_block_locations()` 合并。
  4. **迭代器块类型收严**（[`crates/era-engine/src/block_iter.rs:814, 1011`](../crates/era-engine/src/block_iter.rs#L814)）：
     - 将 `if header.block_type != BlockType::Data && header.block_type != BlockType::Catalog` 改为 `if header.block_type != BlockType::Data`，避免非 Data 块意外被当作 Data 块解密报错。
- **TDD 用例（先红后绿）**:
  - 在 `era-engine` 新增完整追加测试覆盖：`CASE_A`（不同小文件，打包关闭/开启各一例）、`CASE_B`（不同 64KB 随机文件）、`CASE_C`（重复 64KB 块，断言追加前后物理新增 Data 块数为 `0`）、`t7_4`（证书模式 `append_existing`）、以及两轮以上连续追加，全部断言 `verify().archive_health == Healthy`、`warnings.is_empty()`、`errors.is_empty()` 且 `extract_all()` 逐字节与原数据一致；同时回归跑 `append_committed_end_invariant.rs` 与 `zero_drift_append_tests.rs`。

---

### Phase 3（L2/L4/L5 分卷轮转与 `--max-volume-size` 全链路打通）：`FIND-01`、`FIND-08`

> **当前状态（2026-11-21 同步）**：**核心修复及全部后续收口均已完成**（`feat_fly` 提交 `c46bad3`..`6bd7b2e` 落地核心轮转与容量收敛；`ab00f11` 补全随机读取路径分片边界与缺卷 `volume_index` 推导；其余边缘与次级遗留亦已在 **Phase 3.5** 全量完成）。

这是本仓库架构耦合最深的一环，设计必须彻底消除“边加密边决定落卷”“早关闭旧卷”“总卷数当组宽”三个根本病灶：

- **设计方案**:
  1. **延迟更新 `total_volumes` 并统一 Finalize 所有代次分卷**（[`crates/era-volume/src/volume_pool.rs:322-399, 917-1062`](../crates/era-volume/src/volume_pool.rs#L322-L399)）：
     - `VolumePool` 新增字段 `rotated_writers: Vec<(u16, VolumeWriter<B::Writer>)>`。
     - `rotate_volumes()` 创建新一代 writers 替换 `self.writers` 后，将上一代 `(seq, writer)` **暂存进 `rotated_writers`（若需控制 fd 数量上限可只在内存中记录路径与待回写头信息/或只在 pool 内保持关闭前更新，但注意 `SuperHeader` 主头在 offset `0`、Backup Header 在卷尾写入时都需要最终的 `total_volumes`）**：若代次很多导致 fd 顾虑，最优解是：`rotate_volumes` 先写数据区并记录每卷 `writer.position` 及预留尾部 Header/Footer 后 flush 关闭，在 `finalize_with_*` 拿到真正 `final_total_volumes` 后统一对 `rotated_sequences` 的首尾 `SuperHeader`+`Footer` 更新 `total_volumes` 并校验重建 Footer（或保持 `rotated_writers` 在合理代次上限内延迟写入 Backup Header + Footer + rewrite offset 0 `SuperHeader`）。
     - 统一计算 `final_total_volumes = rotated_count + active_count`，写入每一卷的主/备 `SuperHeader`，并保留整套 `0..final_total_volumes - 1` 的完整 `volume_sizes` 供 `ArchiveManifest::volume_committed_ends` 使用（确保 `volume_committed_ends.len() == final_total_volumes`）。
  2. **EC 模式：整条带原子预留与“轮转后加密”**（[`crates/era-engine/src/write_pipeline.rs:112-342`](../crates/era-engine/src/write_pipeline.rs#L112-L342)、[`crates/era-volume/src/volume_pool.rs:614-682`](../crates/era-volume/src/volume_pool.rs#L614-L682)）：
     - 在 `WritePipeline::process_chunks` 当启用 EC 时：**不要在入队前用暂定的 `volume_index` 预先加密块**。`ErasureStage` 缓冲待打包块的原始 `ChunkBatch { chunks, extra_hashes }`（仍受原有每条带 K 块总容量上限约束）。
     - 在 `flush_stripe_internal` 准备落盘整个条带（含尾部 `flush_stripe` 补齐 `K` 块）时：
       1. 先对这 `K` 个（及 padding）块执行压缩试算/预封包尺寸预估（或先生成明文块/密文除 `volume_index` 外大小已完全确定的密文长度：注意 `XChaCha20-Poly1305` 密文长度与 `volume_index` 无关，长度 = `Header + NONCE + compressed + TAG`）。
       2. 计算本条带每个 `shard_idx in 0..(K+M)` 目标槽位 `preferred_slot = calculate_volume(shard_idx, stripe_idx, W)` 各自会累积写入的总字节数 `per_slot_bytes[slot]`（含各分片 `stripe_lengths` 前缀 + `ShardHeader::SIZE` + `shard_len`）。
       3. 调用 `VolumePool::ensure_stripe_capacity(&per_slot_bytes)`：若当前活跃 `W` 卷中**任意一卷**无法容纳分配给它的全部字节，则在**编码加密本条带之前**整组执行 `self.rotate_volumes().await?`，切换到下一代 `W` 卷（`g * W .. g * W + W - 1`）。
       4. 在确认代次 `g` 容量充足后，以每个数据块实际归属卷序号 `g * W + slot` 派生块密钥并计算 AEAD AAD 加密生成 `EncryptedMacroBlock`，RS 编码分片，并严格写入对应 `preferred_slot`（**禁用 `write_shard` 第 658-671 行的跨槽位溢出策略**；若单个分片本身超出单卷最大容量则立即在 `validate_shard_size` 报错而非破坏条带映射）。
  3. **多代次 EC 读取与修复迭代器 + 动态卷发现**（[`crates/era-engine/src/reader.rs:198-305, 684-699, 2027-2107`](../crates/era-engine/src/reader.rs#L198-L305)、[`crates/era-engine/src/block_iter.rs:1104-1600`](../crates/era-engine/src/block_iter.rs#L1104-L1600)、[`crates/era-engine/src/repair.rs:1025-1385`](../crates/era-engine/src/repair.rs#L1025-L1385)）：
     - 发现卷阶段 `ArchiveReader::discover_volumes` 若在扫描过程发现任一打开分卷报告了更大的 `header().total_volumes()`，动态扩大 `scan_limit` 继续向后扫描，确保即使面对历史已写入但 `total_volumes` 过期的旧档也能尽力发现全部后缀分卷。
     - `SuperHeader` 已有 `config.distribution.target_volumes`（写作端在 EC 下设为了初始分卷池宽度 `W`，或若为 `0` 则回退为 `erasure.data_shards + erasure.parity_shards` 与 `total_volumes` 取合法值；并确保非 EC 模式下显式区分开）。更清晰的做法是确定条带组宽度 `group_width = header.config().distribution.target_volumes.min(total_volumes).max(1)`（注：如创建时通过 `--volumes 3 --erasure 4:2` 指定了 `3 < 6`，`writer.rs:920` 之前设 `target_volumes = 6` 而实际 `self.writers.len() == 3`！**重要核查点**：修复时必须在 `writer.rs:920` / `966` 将 `config.distribution.target_volumes` 记录为实际条带池宽度 `resolved_volume_count` 而不是固定 `total_shards`，否则 `--volumes 3 --erasure 4:2` 发生轮转时读端算错 `group_width`！）。
     - 在 `SessionErasureBlockIterator` 与 `repair_matrix_archive_with_providers` 中增加 `current_generation: usize`（初始 `0`）：
       - 当前代条带所在卷序列号为 `vol_idx = current_generation * group_width + distribution_strategy.calculate_volume(shard_idx, current_stripe_index, group_width)`；
       - 当代次 `current_generation` 所属卷均已达到各自的 `data_ends[idx]` / `committed_ends` 且仍有后续代次 `current_generation + 1` 时，自动推进 `current_generation += 1`，`offsets` 重置为新一代卷各自的 `data_region().0` 继续解码后续条带（而 `block_index` / `stripe_index` 保持与写端一致连续递增）。
  4. **打通 CLI `--max-volume-size` 与小分卷安全参数收敛**（[`bins/era-cli/src/commands.rs:531-535`](../bins/era-cli/src/commands.rs#L531-L535)、[`crates/era-engine/src/writer.rs:984-986, 1035-1050, 1146-1156, 1212-1215`](../crates/era-engine/src/writer.rs#L984-L986)）：
     - 在 `commands::create` 增加 `if let Some(val) = max_volume_size { builder = builder.max_volume_size(val); }`。
     - 在 `ArchiveWriterBuilder::build` 中以 `max_volume_size.unwrap_or(config.volume.max_size)` 确定限额（注意检查 `config.volume.max_size` 默认 1GB 与旧单测兼容性，或在 `max_volume_size` 为 `None` 时遵循 `config.volume.max_size`），然后根据 `effective_max = val.max(era_volume::MIN_VOLUME_SIZE)` 计算单卷可用有效负载上限 `usable = effective_max.saturating_sub(era_volume::PER_VOLUME_OVERHEAD + safety_metadata_margin)`：
       - 将 `target_block_size`、`chunker_config`（`min_size`/`avg_size`/`max_size`）、`SmallFilePacker` `max_pack_size` 在**EC 与非 EC 两种模式下**统一钳位到不超过单块/单分片最大容许净荷（例如对于压缩最坏略微膨胀与 AEAD `40B` + `MacroBlockIndex` 开销预留 ~2KB 余量；若单块仍大可切为更小块，而 **Catalog / Index** 也需确保满足 `FIND-13` 修复后的轻量体积或按既有 `max_catalog_chunk` 分块逻辑适配 `usable`）。
- **TDD 用例（先红后绿）**:
  - 库 API 复现：`t7_5a`（24 卷级 EC 轮转）、`t7_5b`（7 卷级非 EC 多轮轮转），以及 `--volumes 3 --erasure 4:2` 触发轮转的混合组宽用例，均从**首卷与末卷分别打开**，断言 `verify() == Healthy`、`extract_all()` 全文件还原、`repair` 损坏任意分片后可完全修复。
  - CLI 复现：**T6a**（`--erasure 4:2 --max-volume-size 262144`）与 **T6b**（`--erasure none --max-volume-size 262144`），断言确实分裂为多个大小 `<= 262144`（扣除预检查精确后的体积契约）的分卷且验证解包全通过；回归跑 `bins/era-cli/tests/cli_integration_tests.rs:1276` 与 `cli_integration_tests_comprehensive.rs:2402,2431` 及 `cli_boundary_tests.rs:240`。（注：`ed78394`/`6bd7b2e` 将新建归档 `max_volume_size` 下限设为 `1 MiB`，上述小分卷用例已相应调整为 `1 MiB` 轮转与 `< 1 MiB` 显式拒绝验证。）

---

### Phase 3.5（Phase 2 遗留根治与 Phase 3 边缘问题收敛 — 已全部完成）

本阶段集中解决了 **Phase 2（`FIND-05`）** 以及 **Phase 3 落地后识别出的全部边缘与次级问题**（2026-11-21 核查确认已全量合入 `feat_fly`）：

#### 3.5.1 `FIND-05`：完成 Phase 2 追加模式结构性根治（含 Phase 3 约束对齐）
- **实施状态（2026-11-21 同步，已完成）**：主线修复已于 `c5c6733`、`7bfcfdc` 落地，`RESID-HIGH-03` 专项（`a431b8b`、`28bd374`、`1009dee`）及 `RESID-LOW-01`/`03`（`f030a39`、`77b7f5d`、`780a26a`）已补齐全部遗留边界；参见上方 Phase 2 全部 4 项设计。
- **补充衔接要求**：
  - 在 [`VolumePool::open_append_single`](../crates/era-volume/src/volume_pool.rs#L264-L345) 中，`check_retained_volume_size` 应改为校验 `initial_committed_end`（截断后保留的数据区终点）而非包含旧元数据块的 `footer.data_end_offset()`，避免旧元数据体积干扰可用追加空间判断；
  - 维持 [`writer.rs:424-433`](../crates/era-engine/src/writer.rs#L424-L433) 的兼容契约：对历史已存在但 `config.volume.max_size < 1 MiB` 的归档在不传显式 `max_volume_size` 时允许追加，显式传入 `< 1 MiB` 时仍返回 `InvalidConfig`。
- **TDD 用例**：沿用 Phase 2 的 `CASE_A`、`CASE_B`、`CASE_C`、`t7_4` 与多轮连续追加，并补充“无显式覆盖追加历史归档 + 显式覆盖 `< 1 MiB` 拒绝”用例。

#### 3.5.2 多代次轮转历史分卷句柄释放（防海量分卷触发 `EMFILE`）
- **实施状态（2026-11-21 同步，已完成）**：已于提交 `c476f6e` 落地，通过 `RetiredVolumeState` 在轮转时关闭已退役卷写句柄，finalize 阶段逐一重开回写头尾，使打开文件句柄峰值恒定为 `O(W)`。
- **设计方案**：
  - `VolumePool` 增加 `RetiredVolumeRecord { sequence: u16, path: PathBuf, header: SuperHeader, data_end: u64, block_count: u32, last_checkpoint_offset: u64, last_checkpoint_block_id: u32 }`。
  - 在 `rotate_volumes()` 同步数据后，当 `retired_writers`（或所有历史代次）超出可配置上限（甚至对所有已轮转旧卷统一执行）：保存 `RetiredVolumeRecord` 并显式 `drop` 写句柄关闭文件；
  - 在 `install_final_volume_count()` 与 `finalize_with_catalogs_and_manifest()` 中，对已关闭的 `RetiredVolumeRecord` 逐个通过 `backend.open_append(path)`（不截断数据）定位至 offset `0` 回写更新 `total_volumes` 后的主 `SuperHeader`，并按 `data_end` 追加写入 Backup Header + Primary Footer 后立即关闭。
- **TDD 用例**：使用自定义计数 `StorageBackend` 包装器模拟大代次轮转（如 `20` 代以上），断言写期间同时打开的文件句柄峰值恒为 `O(W)`（单代池宽）而不随代次线性增长，且最终每卷 Header `total_volumes` 与 Footer 均合法可读。

#### 3.5.3 非 EC 多初始分卷（`--erasure none --volumes N`, `N > 1`）块序号与读端对齐
- **实施状态（2026-11-21 同步，已完成）**：写端单调选槽已于 `930a7b5` 落地；读端 `MultiVolumeSessionBlockIterator` 按 `committed_ends` 裁剪并推进分卷已于 `06bc1d9`、`c39720f` 补全，彻底消除非 EC 多卷乱序回填与提前终止问题。
- **设计方案**：
  - 在 `VolumePool` 新增 `active_canonical_slot: usize`（初始 `0`，`rotate_volumes()` 时重置为 `0`）。
  - `select_canonical_volume` 仅从 `self.active_canonical_slot..self.writers.len()` 中顺延查找第一个可容纳 `on_disk_size` 的槽位并更新 `self.active_canonical_slot = slot`（**禁止回退到更早槽位**）；若当前代余下槽位均无法容纳，则校验 `check_fresh_volume_space` 后整组 `rotate_volumes()` 并置于新代槽 `0`。
  - 这样非 EC 多卷写入与 `MultiVolumeSessionBlockIterator` 的卷序单调遍历、`block_index` 连续递增语义保持 100% 一致，且不改动任何盘上格式。
- **TDD 用例**：构造 `enable_erasure(false)`、`volume_count(3)`、`max_volume_size(1 MiB)`、`target_block_size(600 KiB)` 场景，依次写入 3 个 `600 KiB` 块（落入槽 0/1/2）和 1 个 `100 KiB` 块（应触发轮转落入新代卷 3，而非回填卷 0），断言 `verify()` 为 `Healthy` 且 `extract_all()` 逐字节一致。

#### 3.5.4 CLI `--block-target-size` 接线、`repack --max-volume-size` 与多块 Catalog 极限处理
- **实施状态（2026-11-21 同步，已完成）**：CLI `--block-target-size` 接线、`repack --max-volume-size` 与多块 Catalog 预算提示已于 `58cb0ac` 落地；库级 `ArchiveWriterBuilder::build` 读取 `config.block.target_size` 与建卷前 `PackingStage`/CLI 参数校验已于 `77b7f5d`、`d47a8bc` 补齐。
  1. [`ArchiveWriterBuilder::build`](../crates/era-engine/src/writer.rs) 现已原生读取 `config.block.target_size` 并保留显式 `.target_block_size(...)` 优先级；[`commands::apply_writer_overrides`](../bins/era-cli/src/commands.rs) 仅转发显式 CLI 覆写参数；`Commands::Repack` 与 [`RepackArgs`](../bins/era-cli/src/commands.rs) 已完整暴露 `--max-volume-size`。
  2. 多块 Catalog 超出单卷可用预算时在 `finalize` 明确提示增大 `--max-volume-size`。
- **设计方案**：
  1. 在 `commands::create` 与 `commands::repack` 中，若用户显式传入 `--block-target-size`（或配置文件覆写了 `config.block.target_size`），通过 `builder.target_block_size(...)` 传入 `ArchiveWriterBuilder`；为 `Commands::Repack` 与 [`RepackArgs`](../bins/era-cli/src/commands.rs#L1280-L1350) 补充 `--max-volume-size` 并调用 `era_engine::validate_max_volume_size`。
  2. 在 `writer.rs` `finalize` 的 `VolumeSpaceExhausted` 错误分支中区分“多块 Catalog 超过单卷可用预算”并给出可操作的建议提示（增大 `--max-volume-size`）；若需彻底支持任意文件规模下的极小分卷，后续可在评估兼容成本后引入跨卷 Catalog 续块索引链表。
- **TDD 用例**：CLI 测试验证 `era create --block-target-size` 生效且 `era repack --max-volume-size` 能按指定上限分裂分卷及拒绝 `< 1 MiB` 参数。

#### 3.5.5 错误类型统一与 Rust 1.99+ Clippy 门禁消除
- **实施状态（2026-11-21 同步，已完成）**：`EraError::ShardTooLarge` 统一与解包快速失败已于 `fcd25e1`、`fa105c2` 落地；`era-storage` trait 精准作用域 `#[allow(clippy::double_must_use)]` 已于 `10c7bbe` 落地，已在 Rust 1.99.1 下通过无额外抑制参数的 `cargo clippy --all-targets --all-features -- -D warnings`。
  1. [`ErasureBlockIterator`](../crates/era-engine/src/block_iter.rs#L543-L548) 与 [`ArchiveReader::read_shard`](../crates/era-engine/src/reader.rs#L1960) 已统一返回 `EraError::ShardTooLarge`。
  2. [`crates/era-storage/src/traits.rs:21, 53, 68`](../crates/era-storage/src/traits.rs#L21) 已消除 Rust 1.99.1 下全部 14 处 `clippy::double-must-use` 告警。
- **设计方案**：
  1. 将 `ErasureBlockIterator` 与 `ArchiveReader::read_shard` 的分片超限分支统一改为 `EraError::ShardTooLarge { size, max_size }`。
  2. 在 `crates/era-storage/src/traits.rs` 检查 `async-trait` 版本升级或对 `StorageWriter`/`StorageReader`/`StorageBackend` 精准作用域加注理由明确的 `#[allow(clippy::double_must_use)]`（或改用兼容写法），使无额外 flags 的 `cargo clippy --all-targets --all-features -- -D warnings` 在 Rust 1.98.1 与 1.99.1+ 均零告警通过。
- **TDD / 门禁验证**：新增 `ErasureBlockIterator` / `read_shard` 返回 `ShardTooLarge` 的单测；运行不带 `-A` 的 `cargo clippy --all-targets --all-features -- -D warnings` 全绿。

---

### Phase 4（L4 修复健康度计算与通用写入器对齐）：`FIND-10`、`FIND-02`

> **当前状态（2026-11-21 同步）**：**已完成并补充收口**（`445a1e6` 修复 `FIND-10`，`b881c85`、`75c9f15` 补全多代窄分卷与纯元数据代次门限；`2d25807` 修复 `FIND-02`，`d47a8bc` 补全 `GenericArchiveWriter` 建卷前校验与超大输入按 `target_block_size` 切分）。

#### 4.1 `FIND-10`：准确计算 `--volumes < data_shards` 下的最低可读卷数
- **设计方案**:
  - 在 [`crates/era-engine/src/repair.rs`](../crates/era-engine/src/repair.rs#L1009-L1015) 与 [`1388-1394`](../crates/era-engine/src/repair.rs#L1388-L1394) 新增辅助函数 `minimum_volumes_for_repair(erasure_config, expected_volumes)`：
    - 当 `expected_volumes > 0` 时，单卷在均匀/轮转分布下最多承载 `max_shards_per_vol = total_shards.div_ceil(expected_volumes)` 个分片；要保障至少可凑齐 `data_shards` 个分片，理论最少需要卷数为 `(erasure_config.data_shards as usize).div_ceil(max_shards_per_vol).min(expected_volumes)`；当 `found_volumes == expected_volumes` 且 `unrecoverable_blocks == 0` 时必定通过校验。
- **TDD 用例**:
  - **T8a**：`--volumes 3 --erasure 4:2` 制造损坏后调用 `repair_archive` 与 CLI `era repair --force`，断言 `repair_stats.fully_repaired() == true` 且 CLI 返回 `rc=0`；再测试若物理删除 `1` 个卷（仅剩 `2` 卷承载 `4` 个分片时实际可恢复与不足时不可恢复）验证不误报。

#### 4.2 `FIND-02`：修正 `GenericArchiveWriter` Catalog 编码格式并补写 v8.2 Manifest
- **设计方案**:
  - 在 [`crates/era-engine/src/writer.rs:3520-3555`](../crates/era-engine/src/writer.rs#L3520-L3555) (`GenericArchiveWriter::finalize`)：
    1. 对序列化后的 `catalog_bytes` 添加与 `ArchiveWriter` 一致的 12 字节头 `[u32 chunk_count = 1][u64 total_len]`（或抽成 `era-engine` 内部共享辅助函数供 `ArchiveWriter` 与 `GenericArchiveWriter` 共用，避免重复实现）；
    2. 改用 `catalog_builder.pack_single_with_type(catalog_chunk, era_common::BlockType::Catalog)?` 构造正确 `BlockType::Catalog` AAD；
    3. 构建并加密写入 `BlockType::Manifest`（记录 `committed_end` 与 `catalog_commitment`），调用 `finalize_with_manifest` / `set_manifest_info` + `finalize_with_catalog` 完成规范的 v8.2 封装。
- **TDD 用例**:
  - **`t7_1`**：使用 `MemoryStorageBackend` + `GenericArchiveWriter` 创建归档后通过标准读写路径（`ArchiveReader::open_with_storage` 或等价读写契约）校验 `load_catalog()` / `verify()` / `extract_all()` 全成功。

---

### Phase 5（L4/L5 路径校验、同名冲突、预建卷消除与只读覆盖）：`FIND-06`、`FIND-07`、`FIND-11`

> **当前状态（2026-11-21 同步）**：**已完成并补充收口**（`6e1700b` 修复 `FIND-06`；`382ccd8`、`8e709f8` 修复 `FIND-07`；`c6c8471`、`0ea8aee`、`8e7697e` 修复 `FIND-11`；`bcf309c` 补全 `overwrite=true` 同名多条目解包去重；`d47a8bc` 补全 CLI `--packing-k` / `--flush-threshold` 建卷前校验）。

#### 5.1 `FIND-06`：`ArchiveWriter::add_path` 绝对路径单文件规范化
- **设计方案**：在 [`crates/era-engine/src/writer.rs:1561-1563`](../crates/era-engine/src/writer.rs#L1561-L1563) 单文件分支复用 `add_file` 的提取 `file_name()` 策略，当单文件存在 `..` 或 `is_absolute()` 时提取安全文件名（找不到合法文件名则返回 `InvalidConfig`）。
- **TDD 用例**: **`t7_2`** 验证 `writer.add_path(&abs_file, false).await` 成功入档且 `list`/`extract` 存储路径为相对文件名。

#### 5.2 `FIND-07`：输入预检验、分卷输出路径自排除规范化、重名碰撞处理
- **设计方案**:
  1. **提取共享的分卷衍生路径推导辅助函数**（供 CLI [`collect_archive_volume_paths`](../bins/era-cli/src/commands.rs#L452-L467) 与引擎 [`collect_own_volume_paths`](../crates/era-engine/src/writer.rs#L1567-L1582) 共用）：
     - 先分别对传入 `output` 的 **parent 目录**做 `canonicalize()`（而非对可能尚未创建的输出文件直接 `canonicalize()`），拼接 `output.file_name()` 后再应用 [`era_volume::volume_path`](../crates/era-volume/src/lib.rs#L70-L77) 生成真正的首卷路径（如 `my_archive.era`）与后续分卷 `.era.001..`，**在 `builder.build()` 创建磁盘文件前就能计算出精准的排除集合**，即使不带 `.era` 后缀也能 100% 自排除。
  2. **输入全量预检查前置到 `builder.build()` 之前**（[`commands.rs:656-697`](../bins/era-cli/src/commands.rs#L656-L697)）：
     - 先收集全部 `(disk_path, stored_path)` 并校验输入文件存在、不含有 `..`/绝对路径且没有归档内重名路径碰撞（若多个输入映射到同一个 `stored_path`，快速失败并给出明确碰撞文件路径，避免静默丢数据）。
     - **确认全部输入校验通过后**再调用 `builder.build().await` 在磁盘建卷，消除失败场景下残留 `6` 个 `4224B` 半成品空卷（同时即便中后期 I/O 出错也可清理新创建空卷）。
  3. **解包端历史归档重名保护**（[`reader.rs:1548-1595`](../crates/era-engine/src/reader.rs#L1548-L1595)）：
     - 对历史上已经含重名路径的归档，在 `extract_with_iterator` 内维护 `planned_targets: HashSet<PathBuf>`，使小文件（packed）、单块文件与大文件在 `overwrite == false` 下统一保持跳过不覆盖语义。
- **TDD 用例**: 覆盖 **T3a**（输入不存在零文件残留）、**T3b**（同名多单文件）、**T3c**（`..` 输入零文件残留）、**T3d**（输入目录内无 `.era` 后缀不自引用）。

#### 5.3 `FIND-11`：`extract --force` 安全覆盖只读文件与清晰 `repair` 错误引导
- **设计方案**:
  1. 在 [`reader.rs:1548-1624`](../crates/era-engine/src/reader.rs#L1548-L1624) 与 [`chunk_processor.rs:101, 117`](../crates/era-engine/src/chunk_processor.rs#L101) 提取公共文件写入打开辅助函数 `open_output_for_extract(&output_path, overwrite)`：
     - 当 `overwrite == true` 且目标已存在（含 `0444` 只读文件或符号链接防护后的常规文件）时，先尝试删除既有文件（或仅当删除失败时返回明确 `PermissionDenied`），再创建新文件；
     - 同步修正 `tracked_output_files`：仅记录本次实际新建或已重写的文件，并注意失败清理逻辑的安全性边界（保留既有的容器 Containment 校验顺序不变）。
  2. 修正 [`bins/era-cli/src/commands.rs:1209, 1217, 1220`](../bins/era-cli/src/commands.rs#L1209) 的提示文本，明确无纠删码归档不可用 `--force` 强制修复损坏数据块，避免误导用户认为 `era extract --force` 具备容错还原能力。
- **TDD 用例**: **T9f**（两次提取含 `0444` 文件目录加 `--force` 返回 `0` 且内容一致）与 **T8c**（校验错误输出提示不再误导）。

---

### 总体回归验证记录（已完成全量验证）

截至 2026-11-22（在 `ee39fae` 基础上完成复审计 §4.1–§4.10 与 §5.1–§5.4 全量整改提交后），已在 Nix store 工具链（`rustc 1.99.1` / `cargo 1.99.1` / `clippy 1.99.1` / `rustfmt 1.99.1`）以及标准 CI **默认文件描述符软限制 `ulimit -n = 1024`** 下，按 [`ci.yml`](../.github/workflows/ci.yml) 等价流程完成全量门禁与发布态测试验证（`resid_high03_checkpoint_append`、`bounded_fd_extraction_tests` 等大批量文件用例均通过有限句柄池稳定通过）：
1. **格式与 Clippy 门禁**：
   - `cargo fmt --all -- --check`：通过（`exit 0`）
   - `cargo clippy --all-targets --all-features -- -D warnings`：零告警通过（`exit 0`）
2. **全量 Release 测试（含源码静态审计套件 `adversarial_audit_v*`、`second_audit`、`third_audit`、`fourth_audit`、`competitor_audit` 与全部 `find*` / `resid_*` / `bounded_fd_extraction_tests` 回归套件）**：
   - `cargo test --release -p era-cli`：`16` 个测试套件全部通过（`500 passed, 0 failed, 3 ignored`）
   - `cargo test --release --workspace`：`164` 个测试/文档测试套件全部通过（`2916 passed, 0 failed, 17 ignored`）
