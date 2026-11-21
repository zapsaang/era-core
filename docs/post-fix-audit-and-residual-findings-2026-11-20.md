# ERA-CORE 修复核查与遗留问题审计报告

> **后续状态同步（2026-11-22）**：本报告基于历史基线 `8e7697e` 登记的 `RESID-*` 遗留项已在 `ee39fae` 及后续收口提交中全部闭环；关于 `ee39fae` 复审计与最终整改验收结果，请见 [`docs/re-audit-and-residual-findings-2026-11-21.md`](./re-audit-and-residual-findings-2026-11-21.md)。

- **核查日期**: 2026-11-20
- **代码基线**: 分支 `feat_fly` (HEAD `8e7697e`；相对 `origin/feat_fly` `7b45fd1` 新增 36 个提交，相对前置分析基线 `e4050a2` 共 45 个提交)
- **关联前置文档**: [`docs/code-and-practical-test-findings-2026-11-18.md`](./code-and-practical-test-findings-2026-11-18.md)
- **审计范围**:
  - 逐项核实前置文档中的全部 13 项问题（`FIND-01` ~ `FIND-13`）与 5 个实施阶段（`Phase 1` ~ `Phase 5`，含 `Phase 3.5.1` ~ `3.5.5`）是否已按设计与工程规范（TDD、分层依赖、零技术债）完成修复；
  - 对 `e4050a2..8e7697e` 的全部变更进行跨特性交汇、边界条件、安全上下文与恢复一致性审计，确认是否存在遗留缺陷或新增技术债。

---

## 一、 总体审计结论

1. **前置文档点名的主路径问题均已落地修复并通过专项回归测试**：
   - 工程师针对 `FIND-01` ~ `FIND-13` 及 `Phase 3.5.1` ~ `3.5.5` 均已提交修复实现与 `find02` ~ `find13` 专项测试套件。
   - 在 Nix store `rustc 1.99.1` 工具链下，`cargo fmt --all -- --check`、无额外抑制参数的 `cargo clippy --all-targets --all-features -- -D warnings`、新增的 `find*` 测试、多卷轮转/矩阵修复/边界测试，以及 `era-index` / `era-volume` / `era-engine` 核心审计回归套件**全部通过（0 failed）**。
2. **尚未达到“零遗留、零技术债”结项标准**：
   - 跨模块源码走查发现，部分修复仅满足了文档复现场景的最小闭环，在**跨特性交汇处、故障恢复闭环与读写对称契约**上仍存在 **3 项 High 级、4 项 Medium 级、5 项 Low 级遗留问题/技术债**（详见第四节）。

---

## 二、 实测验证环境与命令记录

使用仓库已说明的 Nix store 工具链（`rustc 1.99.1` / `cargo 1.99.1` / `clippy 1.99.1` / `rustfmt 1.99.1`）：

```bash
export PATH="/nix/store/c2ii5nkzv440xj9igxsd49i8f5y2vr6f-cargo-1.99.1/bin:/nix/store/mslcwkiyh6wayx8gpzlq53wvr3a5pp44-rustc-1.99.1/bin:/nix/store/0x4hw59xdvzm6v79m1rz84a7j2j2yh0z-clippy-1.99.1/bin:/nix/store/3kr36w0awz5q8yia6nwcriaj3f0065qw-rustfmt-1.99.1/bin:$PATH"
export RUSTC="/nix/store/mslcwkiyh6wayx8gpzlq53wvr3a5pp44-rustc-1.99.1/bin/rustc"
```

| 验证批次 | 执行命令 | 实测结果 |
| --- | --- | --- |
| **门禁检查** | `cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings` | `Finished dev profile ... in 0.23s`，零告警通过（`exit 0`） |
| **FIND 专项测试** | `cargo test -p era-index --test find13_serialized_size_regression && cargo test -p era-volume --test find03_header_recovery && cargo test -p era-engine --test find02_generic_writer_tests --test find03_header_recovery --test find04_catalog_recovery --test find05_append_tests --test find06_add_path_tests --test find07_duplicate_extract_tests --test find09_index_recovery_regression --test find10_narrow_volume_repair_tests --test find11_extract_overwrite_tests && cargo test -p era-cli --test find07_cli_create_tests --test find11_cli_tests` | 全部 13 个测试文件全部通过：`find13` (2), `era-volume find03` (5), `find02` (2), `find03` (7), `find04` (3), `find05` (9), `find06` (2), `find07` (1), `find09` (2), `find10` (4), `find11` (3), `cli find07` (4), `cli find11` (2)，`0 failed` |
| **轮转/矩阵/CLI 边界** | `cargo test -p era-engine --test manifest_roundtrip --test matrix_distribution_tests --test matrix_repair_scan_tests --test volume_adjustment_test --test multi_volume_tests --test self_inclusion_test && cargo test -p era-cli --test cli_boundary_tests` | `manifest_roundtrip` (5), `matrix_distribution_tests` (9), `matrix_repair_scan_tests` (14), `multi_volume_tests` (29), `self_inclusion_test` (4), `volume_adjustment_test` (6), `cli_boundary_tests` (19 passed, 2 ignored: 4GB 磁盘测试)，`0 failed` |
| **核心与审计套件** | `cargo test -p era-index && cargo test -p era-volume && cargo test -p era-engine --test append_committed_end_invariant --test zero_drift_append_tests --test adversarial_audit_v3 --test adversarial_audit_v5 --test second_audit --test v81_adversarial_resilience` | `era-index`（全部 unit + `adversarial_audit_v2..v25` 等）、`era-volume`（81 unit + 全部集成与审计套件）及 `era-engine` 上述 6 套测试（`22+26+7+44+7+1`）全部通过，`0 failed` |

---

## 三、 前置问题（`FIND-01` ~ `FIND-13` & `Phase 3.5`）逐项核实对账

| 编号 / 阶段 | 关联提交 | 核心代码锚点 | 主路径核实结果 | 遗留问题映射 |
| --- | --- | --- | --- | --- |
| **FIND-01**<br>(Phase 3) | `c46bad3`, `55f2b03`, `7334707`, `8bb1cf1`, `e5c3977`, `eefc2d9`, `21de03c`, `5776987`, `bbc3eef`, `0d05fcd` | [`write_pipeline.rs:103-319`](../crates/era-engine/src/write_pipeline.rs#L103-L319)<br>[`session_builder.rs:202-309`](../crates/era-packing/src/session_builder.rs#L202-L309)<br>[`volume_pool.rs:403-456, 672-702, 996-1177`](../crates/era-volume/src/volume_pool.rs#L403-L456)<br>[`erasure_scan.rs:5-108`](../crates/era-engine/src/erasure_scan.rs#L5-L108)<br>[`reader.rs:193-399`](../crates/era-engine/src/reader.rs#L193-L399) | **主路径已修复**：EC 改为先 `prepare_chunks`、在 `reserve_stripe` 整条带预留/轮转后再 `seal_prepared` 绑定真实 `volume_sequence`；禁用 `write_shard` 跨槽位溢出；延迟写入最终 `total_volumes`；`MatrixScanGeometry` 按 `target_volumes` 组宽 `W` 分代扫描读/修；`discover_volumes` 动态扩展扫描上限 | [`RESID-MED-01`](#resid-med-01)（随机读取路径分片边界与缺卷 `volume_index` 错配）<br>[`RESID-HIGH-02`](#resid-high-02)（轮转退役卷无 Manifest 致主头不可修） |
| **FIND-02**<br>(Phase 4.2) | `2d25807` | [`writer.rs:4140-4238`](../crates/era-engine/src/writer.rs#L4140-L4238) | **已修复**：共用 `frame_and_chunk_catalog` 写入 12B 帧头、改用 `pack_single_with_type(..., BlockType::Catalog)`、补全 v8.2 `ArchiveManifest`（含 `catalog_commitment` 与 `header_digest`）及 `set_manifest_info` | [`RESID-LOW-04`](#resid-low-04)（`GenericArchiveWriter::add_bytes` 未切分 `>64 MiB` 单次输入） |
| **FIND-03**<br>(Phase 1.1) | `73c8844`, `f8baac0`, `0fc2984` | [`era-volume/src/reader.rs:46-147`](../crates/era-volume/src/reader.rs#L46-L147)<br>[`manifest.rs:76-109`](../crates/era-common/src/types/manifest.rs#L76-L109)<br>[`repair.rs:304-388, 475-513, 1033-1093`](../crates/era-engine/src/repair.rs#L304-L388)<br>[`reader.rs:2575-2582`](../crates/era-engine/src/reader.rs#L2575-L2582) | **部分修复**：`VolumeReader::open` 先恢复 Footer 再回退读取 Backup Header；`verify` 标为 `Degraded`；单代 EC 归档 `repair` 可校验 `volume_header_digest` 并原位写回主头 | [`RESID-HIGH-02`](#resid-high-02)（非 EC 归档与轮转退役卷主头损坏时 `repair` 拒修）<br>[`RESID-LOW-02`](#resid-low-02)（读端 `load_manifest` 未校验 `volume_header_digest`） |
| **FIND-04**<br>(Phase 1.2) | `0fc2984`, `ce00a01` | [`reader.rs:952-1326, 1468-1636, 2583-2587`](../crates/era-engine/src/reader.rs#L952-L1326) | **部分修复**：`load_catalog` 支持单块/多块 EC 备份 `Catalog` 回退（含头部损坏时的 `scan_catalog_candidates` 扫描）并通过 `catalog_commitment` 认证，`verify` 标为 `Degraded` | [`RESID-HIGH-01`](#resid-high-01)（`repair` 未修复损坏的主 `Catalog`，修复后 `verify` 仍报 `Degraded`/`rc=1`） |
| **FIND-05**<br>(Phase 2 / 3.5.1) | `c5c6733`, `7bfcfdc` | [`era-volume/src/writer.rs:150-236`](../crates/era-volume/src/writer.rs#L150-L236)<br>[`volume_pool.rs:328-384, 481-506`](../crates/era-volume/src/volume_pool.rs#L328-L384)<br>[`writer.rs:534-653, 1012-1033, 2602-2772`](../crates/era-engine/src/writer.rs#L534-L653)<br>[`block_iter.rs:818, 1015`](../crates/era-engine/src/block_iter.rs#L818) | **部分修复**：截断至 `append_retained_end`、删除密文 `Catalog::from_bytes` 死代码、支持证书/混合认证追加、恢复 `chunk_index`、收严 `BlockType::Data` 判定 | [`RESID-HIGH-03`](#resid-high-03)（`SmallFilePacker` 原始哈希污染 `chunk_index` 致丢块；`Checkpoint` 归档追加必败）<br>[`RESID-LOW-01`](#resid-low-01)、[`RESID-LOW-03`](#resid-low-03) |
| **FIND-06**<br>(Phase 5.1) | `6e1700b` | [`writer.rs:1552-1554, 2882-2902`](../crates/era-engine/src/writer.rs#L1552-L1554) | **已修复**：`add_path` 单文件分支对绝对路径或含 `..` 路径提取安全 `file_name()`，其余相对路径剔除 `.` 后保留层级 | 无遗留（注：库接口连续多次 `add_path` 同名碰撞策略见 [`RESID-MED-03`](#resid-med-03)） |
| **FIND-07**<br>(Phase 5.2) | `382ccd8`, `8e709f8` | [`commands.rs:472-598, 784-838`](../bins/era-cli/src/commands.rs#L472-L598)<br>[`writer.rs:2841-2880`](../crates/era-engine/src/writer.rs#L2841-L2880)<br>[`reader.rs:1922, 1960-1973`](../crates/era-engine/src/reader.rs#L1960-L1973) | **已修复**：CLI `create` 在 `builder.build()` 之前校验全部输入与重名冲突；基于 canonicalize 父目录推导自排除分卷集合（覆盖无 `.era` 后缀输出）；`overwrite=false` 解包期去重跳过重复目标 | [`RESID-MED-03`](#resid-med-03)（`overwrite=true` 解包同名多条目归档时存在顺序覆盖错误）<br>[`RESID-LOW-04`](#resid-low-04)（`--packing-k 0` 建卷后才校验失败） |
| **FIND-08**<br>(Phase 3.4 / 3.5.4) | `ca670a0`, `a16054e`, `19b2d9c`, `00c1f95`, `ed78394`, `6bd7b2e`, `58cb0ac` | [`volume_capacity.rs:1-275`](../crates/era-engine/src/volume_capacity.rs#L1-L275)<br>[`writer.rs:463-469, 952-978, 1132-1215, 2124-2294, 2774-2822`](../crates/era-engine/src/writer.rs#L952-L978)<br>[`commands.rs:406-446, 663, 706, 1472, 1518`](../bins/era-cli/src/commands.rs#L406-L446) | **已修复**：CLI `create`/`repack` 接线 `--max-volume-size`（强制 `>= 1 MiB`）与 `--block-target-size`；`VolumeCapacity` 统一收敛 CDC/`SmallFilePacker`/`PackingStage`/Catalog 分块上限，提供预算明细提示并在 EC 下支持省略非必需索引以保全双份 Catalog | [`RESID-LOW-03`](#resid-low-03)（库级 `ArchiveWriterBuilder::build` 未自动读取 `config.block.target_size`） |
| **FIND-09**<br>(Phase 1.3) | `0fc2984` | [`volume_stage.rs:411-470`](../crates/era-engine/src/volume_stage.rs#L411-L470)<br>[`era-index/src/builder.rs:335-356`](../crates/era-index/src/builder.rs#L335-L356)<br>[`reader.rs:630-719`](../crates/era-engine/src/reader.rs#L630-L719) | **已修复**：向所有活跃分卷独立写出带 `IDX\x01` 域前缀及本卷 `PagePointer` 偏移的 `IndexPage` + `IndexManifest`；读端遍历所有候选卷直至成功 | 性能注解：扇出每卷重复遍历 Redb（详见原审计观察，无正确性缺陷） |
| **FIND-10**<br>(Phase 4.1) | `445a1e6` | [`repair.rs:104-156, 1095, 1490`](../crates/era-engine/src/repair.rs#L104-L156) | **部分修复**：`minimum_volumes_for_repair` 按分片密度计算单代窄卷池最低卷数，`--volumes 3 --erasure 4:2` 修复后返回 `Healthy` (`rc=0`) | [`RESID-MED-02`](#resid-med-02)（多代轮转窄卷池错除以总卷数 `G * W`） |
| **FIND-11**<br>(Phase 5.3) | `c6c8471`, `0ea8aee`, `8e7697e` | [`chunk_processor.rs:114-143, 215-238`](../crates/era-engine/src/chunk_processor.rs#L215-L238)<br>[`reader.rs:1964-1966, 2020-2050, 2320-2343`](../crates/era-engine/src/reader.rs#L2020-L2050)<br>[`commands.rs:1322-1340`](../bins/era-cli/src/commands.rs#L1322-L1340) | **已修复**：containment 校验后先 unlink 只读文件/软链再用 `create_new(true)` 创建；仅追踪实际打开的文件；修正 `repair` 误导提示文案 | [`RESID-MED-03`](#resid-med-03)（同路径多条目 `--force` 交互） |
| **FIND-12** & **3.5.5** | `9e837ad`, `fcd25e1`, `10c7bbe`, `fa105c2` | [`encryption_context.rs:101-153`](../crates/era-engine/src/encryption_context.rs#L101-L153)<br>[`era-storage/src/traits.rs:21, 53, 68`](../crates/era-storage/src/traits.rs#L21)<br>[`block_iter.rs:55, 543-548, 1382-1388`](../crates/era-engine/src/block_iter.rs#L543-L548)<br>[`reader.rs:1852-1856, 2149-2156`](../crates/era-engine/src/reader.rs#L1852-L1856) | **已修复**：CAS 循环替代 `fetch_update`；三处分片超限统一返回 `ShardTooLarge` 并在解包时快速失败；`#[allow(clippy::double_must_use)]` 精准作用于 trait | 无遗留 |
| **FIND-13**<br>(Phase 1.3) | `26306df` | [`era-index/src/store.rs:414-436`](../crates/era-index/src/store.rs#L414-L436)<br>[`era-index/src/builder.rs:219-264, 434`](../crates/era-index/src/builder.rs#L219-L264) | **已修复**：共用 `build_right_sized_bloom()` 并修正 16B `TAG_SIZE` 计算，估算与实际落盘零字节偏差 | 无遗留 |
| **Phase 3.5.2**<br>(退役卷句柄) | `c476f6e` | [`era-volume/src/writer.rs:785-844`](../crates/era-volume/src/writer.rs#L785-L844)<br>[`volume_pool.rs:440-446, 1142-1151`](../crates/era-volume/src/volume_pool.rs#L440-L446) | **已修复**：`rotate_volumes` 关闭已轮转句柄仅保留 `RetiredVolumeState`，finalize 时逐一重开回写头尾，打开句柄峰值恒为 `O(W)` | [`RESID-HIGH-02`](#resid-high-02)（退役卷不写 Manifest 致主头不可修） |
| **Phase 3.5.3**<br>(非 EC 单调选槽) | `930a7b5` | [`volume_pool.rs:145, 447, 862-888`](../crates/era-volume/src/volume_pool.rs#L862-L888) | **已修复**：`active_canonical_slot` 保证非 EC 多卷写入严格单调前移，不回填前序槽位 | [`RESID-MED-04`](#resid-med-04)（非 EC 多卷迭代器未裁剪 `data_ends`） |

---

## 四、 遗留缺陷与技术债详述（按严重度排序）

### High 级别遗留缺陷

#### `RESID-HIGH-01`：`FIND-04` 遗留 — 主 `Catalog` 损坏时 `repair` 未做任何自愈，修复后 `verify` 永久处于 `Degraded` (`rc=1`)

- **严重度**: High
- **维度**: 容灾可靠性 / 规范符合性（关联 `FIND-04`、实测项 **T5c `bad_cat`**）
- **源码锚点**:
  - [`crates/era-engine/src/reader.rs:1020-1028, 2583-2587`](../crates/era-engine/src/reader.rs#L1020-L1028)
  - [`crates/era-engine/src/repair.rs:440-805, 991-1507`](../crates/era-engine/src/repair.rs#L440-L805)
  - [`bins/era-cli/src/commands.rs:1047-1071, 1183-1305`](../bins/era-cli/src/commands.rs#L1183-L1305)
- **问题机理与影响**:
  - 当 EC 归档的主 `Catalog` 块（如 **T5c `bad_cat`**）损坏时，[`ArchiveReader::load_catalog`](../crates/era-engine/src/reader.rs#L1020-L1028) 能通过 EC 备份 `Catalog` 块恢复并通过 `manifest.catalog_commitment` 校验，同时将 `self.catalog_recovered_from_backup` 置为 `true`。
  - [`ArchiveReader::verify`](../crates/era-engine/src/reader.rs#L2583-L2587) 会据此追加警告 `"Catalog recovered from EC backup; primary Catalog still requires repair"` 并返回 `ArchiveHealthStatus::Degraded`；CLI [`commands::verify`](../bins/era-cli/src/commands.rs#L1065-L1071) 对 `Degraded` 直接以 `rc=1` 报错退出。
  - 然而 [`crates/era-engine/src/repair.rs`](../crates/era-engine/src/repair.rs#L475-L530) 仅处理了主 `SuperHeader` 修复与 `[data_start, erasure_data_end)` 数据区分片修复（`erasure_data_end` 在 `footer.catalog_offset()` 处截断），**完全未检查也未修复损坏的主 `Catalog`**。
  - **可观察失效**：按 `verify` 警告执行 `era repair --force`，`repair` 扫描到 `0` 个损坏数据分片后输出 `"✅ Archive successfully repaired!"` (`rc=0`) 并未修改磁盘；紧接着执行 `era verify` 依然失败并报 `"primary Catalog still requires repair"` (`rc=1`)。
  - **次级盲区**（Low）：在多卷归档中，[`load_catalog`](../crates/era-engine/src/reader.rs#L979-L1016) 只要在任意候选卷（如卷 `1`）成功读取主 `Catalog` 即返回且保持 `catalog_recovered_from_backup = false`；若卷 `0` 的主 `Catalog` 已损坏而卷 `1` 完好，`verify()` 仅打日志不会发出警告，`repair` 亦不会修复卷 `0` 损坏的 `Catalog`。
- **修复建议（TDD / 零技术债）**:
  - 在 `repair_archive_with_providers` 与 `repair_archive_matrix_with_providers` 中（创建 `.bak` 后、非 `dry_run` 时）：检测候选卷的 `Catalog` 健康状态（对已触发 `catalog_recovered_from_backup` 或多卷中主 `Catalog` 校验失败的分卷），利用已通过 `manifest.catalog_commitment` 认证的备用/兄弟卷 `Catalog` 明文与原块长预算（保持各块偏移与 `Footer` 指针兼容或按原始块序列重加密原位写回），并在修复后验证 `ArchiveReader::verify()` 返回 `Healthy` 且无警告。

---

#### `RESID-HIGH-02`：`FIND-03` × `FIND-01` / 非 EC 交汇遗留 — 非 EC 归档及所有轮转退役分卷（含卷 0）的主 `SuperHeader` 损坏均无法修复

- **严重度**: High
- **维度**: 容灾一致性 / 跨特性耦合（关联 `FIND-03` × `FIND-01`）
- **源码锚点**:
  - [`crates/era-engine/src/repair.rs:304-331, 456-481, 1019-1049`](../crates/era-engine/src/repair.rs#L304-L331)
  - [`bins/era-cli/src/commands.rs:1263, 1329-1341`](../bins/era-cli/src/commands.rs#L1263)
  - [`crates/era-volume/src/volume_pool.rs:1012-1018, 1142-1151`](../crates/era-volume/src/volume_pool.rs#L1012-L1018)
  - [`crates/era-engine/src/writer.rs:2417-2449`](../crates/era-engine/src/writer.rs#L2417-L2449)
- **问题机理与影响**:
  1. **非 EC 归档（`--erasure none`）主头损坏被直接拒修**：
     - 非 EC 分卷在 finalize 时同样写出 Backup `SuperHeader` 并在 `ArchiveManifest` 中写入 32 字节 `volume_header_digest`。主头损坏后，`VolumeReader::open` 可从备份头打开，`verify` 报告 `Degraded` 并提示 `"Volume 0: using backup header; primary header still requires repair"`。
     - 但 [`repair_archive_with_providers`](../crates/era-engine/src/repair.rs#L456-L459) 在检查 `header_recovered_from_backup()`（第 475 行）**之前**，即通过 `header.config().erasure.ok_or_else(...)` 报错退出；CLI [`commands::repair`](../bins/era-cli/src/commands.rs#L1263) 同样在 `erasure.is_none()` 时走第 1329 行错误分支直接拒绝修复。主头回写根本不依赖 RS 纠删码，此处拦截导致非 EC 归档主头损坏无法自愈。
  2. **分卷轮转归档（`max_volume_size`）的退役分卷（`0..G-2` 代，含首卷 `.era`）主头损坏导致矩阵修复整体失败**：
     - 在分卷轮转写入中，[`VolumePool::finalized_header_digests`](../crates/era-volume/src/volume_pool.rs#L1012-L1018) 与 [`ArchiveWriter::finalize`](../crates/era-engine/src/writer.rs#L2417-L2449) 仅对**最后一代活跃分卷（`self.writers`）**计算 `header_digest` 并写入 `BlockType::Manifest`；所有前序退役分卷（`retired_volumes`，含第 `0` 代首卷）在 [`volume_pool.rs:1148-1150`](../crates/era-volume/src/volume_pool.rs#L1148-L1150) 中均调用 `writer.set_manifest_info(0, 0)` 结案，其 `footer.has_manifest()` 恒为 `false`。
     - 当任意退役分卷的主头损坏时，`VolumeReader::open` 可通过该退役卷尾部 Backup Header 成功恢复；但进入 [`repair_archive_matrix_with_providers`](../crates/era-engine/src/repair.rs#L1034-L1044) 后，[`recovered_header_bytes`](../crates/era-engine/src/repair.rs#L320-L331) 硬性要求**该损坏分卷自身**具备 `footer.has_manifest()`，导致必定抛出 `EraError::IntegrityError("Recovered header has no matching on-volume manifest")`，不仅主头修不好，还会中断整个多卷归档的 RS 数据分片修复。
- **修复建议（TDD / 零技术债）**:
  - 方案 A（非 EC 主头修复）：在 `repair_archive_with_providers` 与 `commands::repair` 中先检查是否存在可通过认证的元数据/主头修复（或为单卷/多卷非 EC 归档提供认证主头修复分支，若仅需修复主头则无需 `erasure.is_some()`）；
  - 方案 B（轮转归档退役卷主头认证）：在 `ArchiveManifest`（protobuf schema）中增加全量分卷头摘要列表 `repeated bytes volume_header_digests`（按 `volume_sequence` 排序，涵盖 `0..total_volumes` 全部退役与活跃卷），并在 `recovered_header_bytes` 中允许通过全局已认证 `ArchiveManifest` 对应 `volume_sequence` 的摘要验证该卷的 `backup_bytes`（同时校验 `archive_id`、`epoch_id`、`volume_sequence`、`total_volumes` 一致性）。

---

#### `RESID-HIGH-03`：`FIND-05` 追加模式遗留 — `SmallFilePacker` 原始哈希污染 `chunk_index` 致跨会话丢块，且开启 `Checkpoint` 的归档无法追加

- **严重度**: High
- **维度**: 数据完整性 / 去重一致性 / 恢复契约（关联 `FIND-05`）
- **源码锚点**:
  - [`crates/era-engine/src/writer.rs:1982-2005, 2709-2724`](../crates/era-engine/src/writer.rs#L1982-L2005)
  - [`crates/era-engine/src/write_pipeline.rs:108-145`](../crates/era-engine/src/write_pipeline.rs#L108-L145)
  - [`crates/era-engine/tests/find05_append_tests.rs:111-149`](../crates/era-engine/tests/find05_append_tests.rs#L111-L149)
  - [`crates/era-engine/src/writer.rs:1021-1081, 2116, 2156-2163, 2665-2672`](../crates/era-engine/src/writer.rs#L1021-L1081)
- **问题机理与影响**:
  1. **`SmallFilePacker` 原始小文件哈希 `H_raw` 污染 `chunk_index` 引发静默数据丢失（`missing 1 of 1 chunks`）**：
     - 通过 `add_file` / `add_path` / `add_files` 在 `enable_small_file_packing(true)`（Builder 默认为 `true`）下写入 `< 16 KiB` 小文件（原始哈希 `H_raw`）时，[`write_packed_files_batch`](../crates/era-engine/src/writer.rs#L1957-L2005) 将文件打入 `PackedChunk`（魔数 `"ERAP"`，哈希 `H_pack`），磁盘 `MacroBlock` 索引中**只有 `H_pack` 而不存在独立的 `H_raw` chunk**，Catalog 中通过 `ChunkRef::new_packed(H_pack, ...)` 引用。但第 2003 行把 `small_file_hashes`（`H_raw`）作为 `extra_hashes` 写入了 V2.1 嵌入式索引。
     - 当 `append_existing(true)` 运行 [`recover_append_index_entries`](../crates/era-engine/src/writer.rs#L2709-L2724) 时，它把 `index_reader.iter_entries()` 中的**全部条目**（包含 `H_raw`）灌入新一轮的 `chunk_index`。
     - 若追加会话（甚至同会话 flush 之后）通过 `add_bytes`、`enable_small_file_packing(false)` 的 `add_file`、或大文件/CDC 路径写入相同内容 `H_raw`，[`writer.rs:1779, 1824, 2075`](../crates/era-engine/src/writer.rs#L1779) 的 `self.contains_or_pending(&H_raw)` 返回 `true`，**跳过写块**并在 Catalog 生成非打包引用 `ChunkRef::new(H_raw, 0, len)`（`packed_info: None`）。由于任何 `MacroBlock` 内都不存在独立 chunk `H_raw`，随后的 `verify()` 必报 `Incomplete (missing 1 of 1 chunks)`，`extract_all()` 失败。
     - **测试覆盖假阳性**：[`find05_append_tests.rs:111-149`](../crates/era-engine/tests/find05_append_tests.rs#L111-L149) 的 `case_a_distinct_small_files_packing_enabled` 调用了 `add_bytes`，而 [`add_bytes`](../crates/era-engine/src/writer.rs#L2043-L2089) 完全不走 `small_file_packer`，因此该测试实际未覆盖 `SmallFilePacker` 的追加行为。
  2. **对开启 `.enable_checkpoint(true)` 的归档执行 `append_existing(true)` 必败**：
     - 在 [`ArchiveWriter::finalize`](../crates/era-engine/src/writer.rs#L2116) 中，第 2116 行先调用 `self.pipeline.commit_durable_checkpoint().await?`（向卷 0 数据区末尾写入一个 `BlockType::Checkpoint` 块），随后第 2159/2309 行才读取 `pool.committed_ends()`，导致 `manifest.volume_committed_ends[0]` 包含了该 `BlockType::Checkpoint` 块。
     - 后续 `append_existing(true)` 调用 [`scan_retained_data_region`](../crates/era-engine/src/writer.rs#L2665-L2672) 扫描 `[DATA_REGION_START .. manifest_committed_end)` 遇到 `BlockType::Checkpoint` 即报错 `EraError::IntegrityError("Unexpected non-Data block Checkpoint inside committed data region at offset ...")`。
     - 若追加会话本身也配置了 `.enable_checkpoint(true)`，[`writer.rs:1021-1081`](../crates/era-engine/src/writer.rs#L1021-L1081) 先在 1021 行用 `VolumePool::open_append_single_at` 截断文件尾部，后在 1042/1071 行调 `CheckpointManager::exists` / `load_from_durable_checkpoint`，此时将从偏移 `4096` 处未更新的 Backup Footer 读到已被截断删除的旧 `last_checkpoint_offset` 并失败。
- **修复建议（TDD / 零技术债）**:
  - 在 `recover_append_index_entries` 中仅将 `catalog.entries` 中 `packed_info.is_none()` 的独立 chunk hash 与 `packed_info.is_some()` 的 `chunk_ref.hash`（即 `H_pack`）导入可去重 `chunk_index`（同时修正同会话 `SmallFilePacker` 与非打包写入的索引隔离）；将 `case_a_distinct_small_files_packing_enabled` 改为使用 `add_file` 磁盘小文件并补充跨模式（Session 1 `add_file(packed)` -> Session 2 `add_bytes` / `add_file(unpacked)`）测试。
  - 若要支持 checkpoint 归档的追加：`ArchiveWriter::finalize` 应在截断恢复区/写尾部元数据前界定 `committed_ends` 不把 `BlockType::Checkpoint` 当作数据区（或在 finalize 末尾记录 data-only `committed_ends` 并使 `scan_retained_data_region` 跳过 `Checkpoint` 或不将最终 checkpoint 计入保留区），且 `build()` 中 `CheckpointManager` 逻辑应前置到 `open_append_single_at` 截断之前并在成功追加截断后清理失效旧 checkpoint 状态。

---

### Medium 级别遗留缺陷

#### `RESID-MED-01`：`FIND-01` 随机读取遗留 — `ArchiveReader::read_and_extract_chunks` 分片边界过严且缺卷时 `volume_index` 退化为 `0`

- **严重度**: Medium
- **维度**: 随机读取正确性 / AEAD 上下文绑定（关联 `FIND-01`）
- **源码锚点**: [`crates/era-engine/src/reader.rs:1785-1820`](../crates/era-engine/src/reader.rs#L1785-L1820)
- **问题机理与影响**:
  1. **用最大对齐分片长 `erasure_info.shard_size` 校验未填充的数据分片越界**：
     - 写入端 [`write_pipeline.rs:189-195, 249`](../crates/era-engine/src/write_pipeline.rs#L189-L195) 仅对 parity 分片按最大偶对齐长度 `shard_size` 落盘，data 分片按真实未填充长度 `stripe_lengths[i]` 落盘。
     - 读取端 [`reader.rs:1787-1792`](../crates/era-engine/src/reader.rs#L1787-L1792) 一律以 `u64::from(erasure_info.shard_size) + ShardHeader::SIZE` 调用 `self.check_read_bound(vol_seq, offset, ...)`。当卷末条带某数据分片短于同条带最大分片时，检查范围会越过该卷 `committed_end`，报错 `IntegrityError("Read beyond committed end for volume ...")`。
  2. **缺卷重建时 `volume_index` 硬编码回退为 `0` 致 AEAD 解密失败**：
     - [`reader.rs:1808-1813`](../crates/era-engine/src/reader.rs#L1808-L1813) 通过 `.find(|r| r.header().volume_id() == location.volume_id).map(...).unwrap_or(0)` 计算 `volume_index`。若持有该主数据分片的分卷丢失、需要通过兄弟分片 RS 重建，`.find(...)` 返回 `None` 并退化为 `0`。只要该分片原位于非 `0` 号卷（包含多卷池 `1..W-1` 及所有轮转代 `g > 0`），AEAD 解密必因 `volume_index` 失配报 `aead::Error`。
- **修复建议**:
  - 在 `check_read_bound` 中先读取该分片的 `ShardHeader`（长度 `ShardHeader::SIZE`，并在边界内检查 `header.length`），对数据分片按实际 `header.length`（不超过 `erasure_info.shard_size`）校验边界；
  - 当 `location.volume_id` 对应分卷不在 `volume_readers` 中时，根据 `location.slot_index / data_shards`（条带号）、`my_shard_idx` 与 `MatrixScanGeometry` / `shard_volumes` 反推出目标分卷的真实 `volume_sequence` 作为 `volume_index`。

---

#### `RESID-MED-02`：`FIND-10` × `FIND-01` 交汇遗留 — 多代轮转窄分卷归档的 `minimum_volumes_for_repair` 误除以总卷数 `G * W`

- **严重度**: Medium
- **维度**: 容灾修复健康度判定（关联 `FIND-10` × `FIND-01`）
- **源码锚点**: [`crates/era-engine/src/repair.rs:104-114, 1095`](../crates/era-engine/src/repair.rs#L104-L114)
- **问题机理与影响**:
  - `minimum_volumes_for_repair(erasure_config, expected_volumes)` 使用 `total_shards.div_ceil(expected_volumes)` 估算单卷分片数。
  - 当窄分卷归档（如 `--volumes 3 --erasure 4:2`，单代组宽 `W = 3`）因 `--max-volume-size` 轮转了 `G` 代（如 `G = 3`、`expected_volumes = 9`）时，每个条带的 6 个分片仍只落在同代 3 卷中（每卷 2 片、每代至少需要 2 卷、3 代共至少需要 `6` 卷）。该函数按 `expected_volumes = 9` 算得最低门限为 `4`（`W = 2, G = 2` 时算得 `2` 而非真实的 `4`）。
- **修复建议**:
  - 与 [`MatrixScanGeometry::new`](../crates/era-engine/src/erasure_scan.rs#L34-L45) 保持一致，先解析单代组宽 `W`（`config.distribution.target_volumes`），再对每个代次 `[gen_start .. (gen_start + W).min(expected_volumes))` 累加单代最低可恢复卷数。

---

#### `RESID-MED-03`：`FIND-07` × `FIND-11` 交汇遗留 — `extract_all` 在 `overwrite = true` 下解包同名多条目归档时预建句柄被 unlink 覆盖

- **严重度**: Medium
- **维度**: 解包正确性（关联 `FIND-07` × `FIND-11` × `FIND-05`）
- **源码锚点**:
  - [`crates/era-engine/src/reader.rs:1960-2074`](../crates/era-engine/src/reader.rs#L1960-L2074)
  - [`crates/era-engine/src/chunk_processor.rs:109-189`](../crates/era-engine/src/chunk_processor.rs#L109-L189)
- **问题机理与影响**:
  - 当归档内存在相同 `entry.path` 的多个条目（例如先通过 `append_existing(true)` 更新同一路径，或库 API 多次 `add_path` 同名文件）并以 `overwrite = true`（`era extract --force`）解包时：
  - [`reader.rs:1967`](../crates/era-engine/src/reader.rs#L1967) 仅在 `!options.overwrite` 时查 `planned_targets` 跳过重复条目；当 `options.overwrite == true` 时，新旧条目同时注册进 `ExtractionContext`。
  - 若旧条目是打包小文件（延后至块迭代时在 [`chunk_processor.rs:117`](../crates/era-engine/src/chunk_processor.rs#L117) 调 `open_output_for_extract(..., true)`）、新条目是非打包文件（已在规划期第 2026 行预创建并持有打开的 `File` 句柄），则块迭代解出旧小文件时会调用 `fs::remove_file` 将新大文件刚刚创建的路径 **unlink** 并写入旧内容，而新大文件后续数据会写入已被 unlink 的孤儿文件描述符中，最终磁盘留下的是**旧版本小文件内容**（且 `stats.extracted` 重复计数）。
- **修复建议**:
  - 在 `extract_with_iterator` 规划阶段处理归档内重复 `target_key`（在同一次提取中，无论是 `overwrite == false` 保留首条，还是 `overwrite == true` 按归档顺序由最后一条胜出），确保每个 `target_key` 在 `ExtractionContext` 中至多注册一次，避免多个条目同时竞争或 unlink 同一输出路径。

---

#### `RESID-MED-04`：非 EC 多卷迭代器 `MultiVolumeSessionBlockIterator` 触发 `committed_end < data_end` 时提前终止整套迭代

- **严重度**: Medium
- **维度**: 多卷读取一致性（关联 `FIND-01` / `FIND-05`）
- **源码锚点**: [`crates/era-engine/src/block_iter.rs:931-935, 978-983`](../crates/era-engine/src/block_iter.rs#L931-L935)
- **问题机理与影响**:
  - 对比 [`SessionErasureBlockIterator::new`](../crates/era-engine/src/block_iter.rs#L1193-L1202) 在构造时即使用 `committed_ends[sequence]` 裁剪 `data_ends`，[`MultiVolumeSessionBlockIterator::new`](../crates/era-engine/src/block_iter.rs#L931-L935) 直接采用 `erasure_data_end(reader)` 而不裁剪。
  - 若非 EC 多卷归档的非末卷存在 `[committed_ends[seq] .. data_ends[vol_idx])` 的未提交尾部残余，[`block_iter.rs:978-983`](../crates/era-engine/src/block_iter.rs#L978-L983) 触发 `check_commit_or_end!` 宏时会直接执行 `return None`，**终止后续所有分卷的读取**，而非推进到 `self.current_volume_idx += 1; continue;`。
- **修复建议**:
  - 在 `MultiVolumeSessionBlockIterator::new` 中参照 `SessionErasureBlockIterator` 用 `committed_ends` 裁剪各卷 `data_ends`，并使 `check_commit_or_end!` 在非末卷达到 `committed_end` 时推进 `current_volume_idx += 1` 继续读取后续分卷。

---

### Low 级别遗留技术债与文档失步项

#### `RESID-LOW-01`：`writer.rs:615` 用 1-based 的 Footer 提交序号索引 0-based 的 `volume_committed_ends`（死代码）
- **源码锚点**: [`crates/era-engine/src/writer.rs:614-625`](../crates/era-engine/src/writer.rs#L614-L625)（对比 [`crates/era-engine/src/recovery.rs:415`](../crates/era-engine/src/recovery.rs#L415)）
- **说明**: 第 615 行 `let seq = footer.sequence_number();` 取到的是 1-based 的 Footer 提交序号（初次 finalize 为 `1`），对单卷归档 `volume_committed_ends`（长度 `1`）执行 `.get(1)` 恒返回 `None`，导致该 `footer.data_end_offset() < committed_end` 校验分支形同死代码（目前仅靠第 2640 行 `scan_retained_data_region` 兜底）。应改为 `let seq = loaded_header.volume_sequence();`。

#### `RESID-LOW-02`：`ArchiveReader::load_manifest` 未在主头回退恢复时校验 `volume_header_digest`
- **源码锚点**: [`crates/era-engine/src/reader.rs:1424`](../crates/era-engine/src/reader.rs#L1424)
- **说明**: `load_manifest` 使用 `ArchiveManifest::from_bytes(&decrypted)` 丢弃了 `volume_header_digest`。当某分卷通过 Backup Header 打开时（`header_recovered_from_backup() == true`），`open` / `verify` / `extract_all` 不会校验该 Backup Header 的字节摘要是否匹配已认证 Manifest 中的 `volume_header_digest`（仅 `repair` 阶段做了该校验）。

#### `RESID-LOW-03`：`ArchiveWriterBuilder::build` 的配置读取与新建容量校验存在两处库级不一致
- **源码锚点**: [`crates/era-engine/src/writer.rs:463-470, 534, 1132-1140`](../crates/era-engine/src/writer.rs#L1132-L1140)
- **说明**:
  1. 第 1132-1140 行在 `self.target_block_size` 为 `None` 时未读取 `self.config.block.target_size`（CLI 层靠 `apply_writer_overrides` 绕过；库调用方若仅通过 `.config(ArchiveConfig::compact_preset())` 传入 16 MiB 块配置会被静默忽略并回退到 4 MiB）。
  2. 第 463-469 行在 `self.append_existing == true`、目标文件尚不存在（第 534 行 `append_to_existing == false`，退化为新建归档）且未传 `.max_volume_size(...)` 时，跳过了对 `self.config.volume.max_size >= MIN_ARCHIVE_VOLUME_SIZE` 的显式校验。

#### `RESID-LOW-04`：`PackingStage` 参数校验晚于磁盘建卷，及 `GenericArchiveWriter::add_bytes` 未切分超大块
- **源码锚点**: [`crates/era-engine/src/writer.rs:1032, 1198-1202, 4071-4089`](../crates/era-engine/src/writer.rs#L1032)
- **说明**:
  1. [`ArchiveWriterBuilder::build`](../crates/era-engine/src/writer.rs#L1032) 先调用 `VolumePool::create` 在磁盘创建 `4224B` 空卷文件，第 1198 行 `PackingStage::new` 才检验 `k_factor == 0` / `flush_threshold` 边界；CLI 若传入 `--packing-k 0` 或 `--flush-threshold 0`，失败退出后仍会残留 6 个空卷（同时 `apply_config_overrides` 也未预检这两项参数）。
  2. [`GenericArchiveWriter::add_bytes`](../crates/era-engine/src/writer.rs#L4071-L4089) 未像 `ArchiveWriter::add_bytes`（第 2048 行）那样按 `target_block_size` 切分大输入，若单次传入压缩后仍超过 `MAX_BLOCK_SIZE`（64 MiB）的数据会在读取端报 `BlockTooLarge`。

#### `RESID-LOW-05`：前置文档 `docs/code-and-practical-test-findings-2026-11-18.md` 自身状态标记未同步
- **源码锚点**: [`docs/code-and-practical-test-findings-2026-11-18.md:4-5, 363, 420-464, 514`](../docs/code-and-practical-test-findings-2026-11-18.md#L363)
- **说明**: 前置文档仅更新了 Phase 3 的状态框，第 4-5 行仍保留 `HEAD e4050a2` 与 `未改动任何源码`，第 363 行 Phase 2 仍标注 `当前状态（2026-11-20 核查）：尚未实施`，第 420-464 行 Phase 3.5（`3.5.1` ~ `3.5.5`）仍写为“遗留现状”，第 514 行仍标注“待将来实施阶段执行”，与当前 `feat_fly`（`8e7697e`）实际状态不一致。

---

## 五、 既有已知边界项（Section 3 `KNOWN-01..05`）现状复核

对照 [`docs/code-and-practical-test-findings-2026-11-18.md`](../docs/code-and-practical-test-findings-2026-11-18.md#L257-L263) 第三节，除已纳入 `FIND-*` 的修复变化外，其余边界现状如下：
1. **`KNOWN-01`（8 GiB 累计解包上限与失败清理边界）**：[`reader.rs:48, 2127`](../crates/era-engine/src/reader.rs#L48) 仍保留 `MAX_EXTRACTION_MEMORY = 8 GiB` 上限；但在 `FIND-11`（`c6c8471`）修复后，失败清理已不再“全量删盘”，改为仅删除本次会话实际新建或重写过的文件（`tracked_output_files` + `created_output_paths`），未触及的既有文件会被保留。
2. **`KNOWN-02`（空目录与符号链接静默跳过）**：保持不变（[`commands.rs:537`](../bins/era-cli/src/commands.rs#L537)、[`writer.rs:1296-1302`](../crates/era-engine/src/writer.rs#L1296-L1302) 仅收集普通文件）。
3. **`KNOWN-03` / `KNOWN-04`（整卷缺失时 `repair` 拒修与 dry-run 默认值）**：保持不变（[`commands.rs:1252-1260, 1269`](../bins/era-cli/src/commands.rs#L1252-L1260)）。
4. **`KNOWN-05`（单卷元数据保护边界）**：已部分被 `FIND-03`/`FIND-04` 推进（读取端已支持主头与 EC 备份 `Catalog` 回退），但修复端在非 EC 主头与 EC 主 `Catalog` 自愈上仍有 [`RESID-HIGH-01`](#resid-high-01) 与 [`RESID-HIGH-02`](#resid-high-02) 待闭合。

---

## 六、 后续收敛建议（结项验收门槛）

建议按以下优先级完成闭环后再标记本轮整改完全结项：
1. **P0（必须修复，消除 3 项 High 级遗留）**：
   - **修复 `RESID-HIGH-01`**：实现 `repair` 对损坏主 `Catalog` 的认证重建与原位自愈，确保 **T5c `bad_cat`** 执行 `era repair --force` 后 `era verify` 恢复 `Healthy` (`rc=0`)；
   - **修复 `RESID-HIGH-02`**：解除非 EC 归档主头损坏在 `repair` 中的前置拒修拦截，并在 `ArchiveManifest` 中为轮转归档全量分卷（含退役卷）记录头摘要以支撑退役卷主头修复；
   - **修复 `RESID-HIGH-03`**：隔离 `SmallFilePacker` 内部小文件哈希与独立 chunk 去重索引，改用真实 `add_file` 测试覆盖 `SmallFilePacker` 跨会话追加；同时处理好开启 `enable_checkpoint(true)` 归档的追加流程。
2. **P1（强烈建议修复，消除 4 项 Medium 级遗留）**：
   - 修复 `ArchiveReader::read_and_extract_chunks` 分片读边界与缺卷 `volume_index` 推断（`RESID-MED-01`）；
   - 修复多代轮转窄分卷的 `minimum_volumes_for_repair`（`RESID-MED-02`）；
   - 修复 `extract_all(..., overwrite=true)` 对归档内重复路径的规划期去重（`RESID-MED-03`）；
   - 修复 `MultiVolumeSessionBlockIterator` 在 `committed_end < data_end` 时提前终止整个迭代器的问题（`RESID-MED-04`）。
3. **P2（清理 Low 级技术债并同步文档）**：
   - 清理 `RESID-LOW-01` ~ `RESID-LOW-04` 四处库/CLI 一致性细节，并同步更新 [`docs/code-and-practical-test-findings-2026-11-18.md`](./code-and-practical-test-findings-2026-11-18.md) 状态标记（`RESID-LOW-05`）。
