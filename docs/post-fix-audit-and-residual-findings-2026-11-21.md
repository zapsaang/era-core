# ERA-CORE 修复核查与遗留问题二次审计报告

> **状态更新（2026-11-22，已闭环）**：
> 1. 本文原标注的“当前基线 `780a26a` / 暂不建议结项放行”对应的是整改前快照；其中 `AUDIT-*` 九项已由提交 [`ee39fae`](../) 修复（另：读端 `RESID-LOW-02` 实际在 `7b35b3c`/`257cde5` 已落地，`ee39fae` 补齐了 repair 全局摘要回退）。
> 2. 围绕 `ee39fae` 的二次复审计（见 [`docs/re-audit-and-residual-findings-2026-11-21.md`](./re-audit-and-residual-findings-2026-11-21.md) §4.1–§4.10 与 §5.1–§5.4）也已按 TDD + 零技术债原则通过后续原子提交（`8c42a4c`, `31d358f`, `5ff825e` 及工程收口提交）**全部修复并通过 `ulimit -n 1024` 全量 CI 验收**。

- **核查日期**: 2026-11-21（状态同步：2026-11-22）
- **原审计基线**: 分支 `feat_fly` (HEAD `780a26a`；相对 2026-11-20 审计基线 `8e7697e` 新增 18 个提交：`158d60e..780a26a`)
- **关联前置文档**:
  - [`docs/post-fix-audit-and-residual-findings-2026-11-20.md`](file:///home/ricardom/code/github.com/zapsaang/era-core/docs/post-fix-audit-and-residual-findings-2026-11-20.md)
  - [`docs/code-and-practical-test-findings-2026-11-18.md`](file:///home/ricardom/code/github.com/zapsaang/era-core/docs/code-and-practical-test-findings-2026-11-18.md)
- **审计范围**:
  - 逐项核实工程师声称已全部修复的 12 项遗留缺陷（`RESID-HIGH-01` ~ `03`、`RESID-MED-01` ~ `04`、`RESID-LOW-01` ~ `05`）；
  - 检验修复实现是否完备、合理、无架构违规与无新增技术债；
  - 验证标准 CI 约束下全量测试套件、构建门禁与极端边界的稳健性。

---

## 一、 总体审计结论

1. **核心裁定：工程师声称“已全部修复、零技术债、无遗留问题”与代码现状不符，暂不建议结项放行**。
2. **前置 12 项遗留缺陷核查结果**：
   - **7 项彻底修复并闭环**：`RESID-HIGH-03`（核心逻辑）、`RESID-MED-01`、`RESID-MED-02`、`RESID-MED-03`、`RESID-MED-04`、`RESID-LOW-01`、`RESID-LOW-03`。相关代码逻辑严密，并配有针对性单元与集成测试。
   - **4 项部分修复 / 未完全闭环**：
     - `RESID-HIGH-01`：仅在触发备份回退时执行修复；若多卷归档中卷 0 主 Catalog 损坏而卷 1 完好，`verify` 误报 `Healthy`，导致 CLI `era repair --force` 提前退出拒绝自愈。
     - `RESID-HIGH-02`：虽已在 Manifest 引入分卷头摘要支持退役卷主头修复，但当活跃卷本地 Manifest 损坏时未回退全局已认证 Manifest；非 EC 归档提示文案仍存在误导。
     - `RESID-LOW-02`：读取端 `ArchiveReader::load_manifest` 依然未在主头损坏回退时对 `SuperHeader` 校验 `volume_header_digest`。
     - `RESID-LOW-04`：`GenericArchiveWriter` 仅对单个超大 chunk 切分，未对多 chunk 合箱做容量预算切分，逼近 16 MiB 时仍会引发写盘 panic/error。
   - **1 项文档标记更新存在瑕疵**：`RESID-LOW-05` 虽然补充了 11-18 前置文档的标记，但将本次新增的测试误标为“既有”，且掩盖了 CI 默认环境的运行失败。
3. **新增缺陷与残留技术债统计**：
   - **High 级缺陷**: 2 项（含 1 项在标准环境必崩的 CI 门禁失败）
   - **Medium 级缺陷**: 2 项
   - **Low 级技术债 / 代码异味**: 5 项

| 缺陷编号 | 严重度 | 类别 | 简要描述 |
| --- | --- | --- | --- |
| **`AUDIT-HIGH-01`** | High | CI 门禁失败 / 资源耗尽 | 新增测试 `resid_high03_checkpoint_append` 在系统与 CI 默认 `ulimit -n = 1024` 环境下必报 `TooManyOpenFiles (os error 24)` 挂掉 |
| **`AUDIT-HIGH-02`** | High | 容灾一致性 / 自愈盲区 | `RESID-HIGH-01` 未闭环：多卷归档卷 0 主 Catalog 损坏时 `verify` 误判为 `Healthy`，CLI `era repair` 提前跳过拒修 |
| **`AUDIT-MED-01`** | Medium | 规格完备性 / 容量边界 | `RESID-LOW-04` 不完整：`GenericArchiveWriter` 未对多 chunk 合箱限制 16 MiB，触发 `VolumeWriter` 的 `InvalidConfig` |
| **`AUDIT-MED-02`** | Medium | 追加一致性 / 崩溃安全 | `finalize` 中写入 Checkpoint 块早于卷容量预检；`StartFresh` 时在截断前执行同步 `CheckpointManager::delete()` 会丢失原 Footer 指针 |
| **`AUDIT-LOW-01`** | Low | 代码异味 / 并发小瑕疵 | `writer.rs:466-468` 相邻两行重复执行异步 `tokio::fs::try_exists` |
| **`AUDIT-LOW-02`** | Low | 恢复回退降级不足 | 活跃分卷主头与本地 manifest 双损坏时未回退全局已认证 manifest 的 `volume_header_digests` 进行自愈 |
| **`AUDIT-LOW-03`** | Low | 冗余与死代码 | `VolumePool::finalized_header_digests` 与 `extra_hashes` 参数成为无用残留；`GenericArchiveWriter` 仍用旧版单摘要 Manifest |
| **`AUDIT-LOW-04`** | Low | CLI 规格失步 | `bins/era-cli/src/main.rs:175-186` 计划外添加未在参数解析和帮助文档中体现的 `archive` 位置参数 |
| **`AUDIT-LOW-05`** | Low | 文档一致性偏差 | 前置文档 `docs/code-and-practical-test-findings-2026-11-18.md` 将新测试误标为“既有”并以本地 `ulimit -n 4096` 掩盖 CI 默认失败 |

---

## 二、 实测验证环境与命令记录

测试基于系统预装 Nix store Rust 1.99.1 工具链执行：

```bash
export PATH="/nix/store/c2ii5nkzv440xj9igxsd49i8f5y2vr6f-cargo-1.99.1/bin:/nix/store/mslcwkiyh6wayx8gpzlq53wvr3a5pp44-rustc-1.99.1/bin:/nix/store/0x4hw59xdvzm6v79m1rz84a7j2j2yh0z-clippy-1.99.1/bin:/nix/store/3kr36w0awz5q8yia6nwcriaj3f0065qw-rustfmt-1.99.1/bin:$PATH"
export RUSTC="/nix/store/mslcwkiyh6wayx8gpzlq53wvr3a5pp44-rustc-1.99.1/bin/rustc"
```

### 1. 静态代码分析与门禁检查

```bash
cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings
```
- **执行结果**: `Finished dev profile ... in 0.22s`，格式化与 Clippy 无告警，通过（`exit 0`）。

### 2. 核心回归套件实测对账

| 测试目标 | 执行命令 | 实测结果 |
| --- | --- | --- |
| **CLI 全量测试** | `cargo test --release -p era-cli` | 15 个套件全部通过：`cli_boundary_tests` (19 passed, 2 ignored), `cli_tests` (33), `command_info_tests` (29), `command_keygen_tests` (37), `command_repack_tests` (33), `command_verify_tests` (34), `find07_cli_create_tests` (4), `find11_cli_tests` (2), `keygen_matrix_tests` (42), `large_directory_cli_test` (3), `large_scale_cli_tests` (11), `long_path_cli_tests` (18), `multi_volume_cli_tests` (69), `repair_cli_tests` (107), `test_cli_smoke` (54)。**总计 495 passed, 0 failed**。 |
| **Engine 矩阵与边界套件** | `cargo test --release -p era-engine --test matrix_distribution_tests --test matrix_repair_scan_tests --test volume_adjustment_test --test multi_volume_tests --test manifest_roundtrip` | 全部通过：`matrix_distribution_tests` (9), `matrix_repair_scan_tests` (14), `volume_adjustment_test` (6), `multi_volume_tests` (29), `manifest_roundtrip` (5)。**0 failed**。 |
| **Engine 历史审计回归** | `cargo test --release -p era-engine --test second_audit --test third_audit --test fourth_audit --test competitor_audit --test adversarial_audit_v3 --test adversarial_audit_v5 --test append_committed_end_invariant --test zero_drift_append_tests` | 全部通过：`second_audit` (7), `third_audit` (4), `fourth_audit` (5), `competitor_audit` (6), `adversarial_audit_v3` (7), `adversarial_audit_v5` (44), `append_committed_end_invariant` (22), `zero_drift_append_tests` (26)。**0 failed**。 |
| **本次修复专项测试 (单卷/Catalog/Header)** | `cargo test --release -p era-engine --test resid_high01_catalog_repair --test resid_high02_header_repair` | 全部通过：`resid_high01_catalog_repair` (4 passed), `resid_high02_header_repair` (5 passed)。**0 failed**。 |

### 3. 阻塞性测试失败现场（`AUDIT-HIGH-01` 验证）

执行工程师新增的 Checkpoint 追加与大批量文件测试套件：

```bash
# 当前系统默认环境限制 (标准 Linux / GitHub Actions CI 默认限制均为 1024)
ulimit -n
# 输出: 1024

cargo test --release -p era-engine --test resid_high03_checkpoint_append
```

**原始失败报错现场**:
```text
running 2 tests
test test_append_duplicate_small_files_different_modes ... ok
test test_append_existing_with_checkpoint_flow ... FAILED

failures:

---- test test_append_existing_with_checkpoint_flow stdout ----
thread 'test_append_existing_with_checkpoint_flow' panicked at crates/era-engine/tests/resid_high03_checkpoint_append/fixtures.rs:133:14:
called `Result::unwrap()` on an `Err` value: Io(Custom { kind: Uncategorized, error: "Failed to open target extraction file /tmp/.tmpM68j2m/extract_after_append/dir_000/file_000000.bin: Too many open files (os error 24)" })
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

failures:
    test test_append_existing_with_checkpoint_flow

test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.11s

error: test failed, to rerun pass `--test resid_high03_checkpoint_append`
```

**调大文件句柄上限后的对比验证**:
```bash
sh -c "ulimit -n 4096 && cargo test --release -p era-engine --test resid_high03_checkpoint_append"
# 输出:
# running 2 tests
# test test_append_duplicate_small_files_different_modes ... ok
# test test_append_existing_with_checkpoint_flow ... ok
# test result: ok. 2 passed; 0 failed; 0 ignored; finished in 1.05s
```
**证实**：该测试在常规环境存在确定性的句柄资源耗尽漏洞，非偶然抖动。

---

## 三、 前置 12 项遗留问题逐项核实对账表

| 遗留项编号 | 关联提交 | 核心修改代码锚点 | 审计核实结论 | 遗留问题与技术债映射 |
| --- | --- | --- | --- | --- |
| **`RESID-HIGH-01`**<br>(主 Catalog 修复) | `f4eeb64`, `158d60e` | [`crates/era-engine/src/reader.rs:985-1025`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/reader.rs#L985-L1025)<br>[`crates/era-engine/src/repair.rs:480-530`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/repair.rs#L480-L530)<br>[`bins/era-cli/src/commands.rs:1189-1196`](file:///home/ricardom/code/github.com/zapsaang/era-core/bins/era-cli/src/commands.rs#L1189-L1196) | **未完全闭环**：单卷归档能成功自愈主 Catalog。但多卷 EC 归档中，若仅部分卷（如卷 0）主 Catalog 损坏，`load_catalog` 命中卷 1 后返回，`verify` 误报 `Healthy`，导致 CLI `era repair` 提前退出拒修。重写主 Catalog 未保障原 EC 条带对齐。 | [`AUDIT-HIGH-02`](#audit-high-02) |
| **`RESID-HIGH-02`**<br>(退役卷与非 EC 主头修复) | `685718a`, `fe899d4`, `b714088` | [`crates/era-common/proto/era_common.proto:115`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-common/proto/era_common.proto#L115)<br>[`crates/era-engine/src/repair.rs:320-375`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/repair.rs#L320-L375)<br>[`bins/era-cli/src/commands.rs:1260-1340`](file:///home/ricardom/code/github.com/zapsaang/era-core/bins/era-cli/src/commands.rs#L1260-L1340) | **基本修复，存技术债**：Protobuf 引入 `volume_header_digests` 列表；支持了非 EC 与退役卷主头修复。但活跃卷主头+本地 Manifest 双损坏时未回退全局已认证摘要；非 EC 报错文案仍误报 erasure。 | [`AUDIT-LOW-02`](#audit-low-02)<br>[`AUDIT-LOW-03`](#audit-low-03) |
| **`RESID-HIGH-03`**<br>(追加小文件去重与 Checkpoint) | `e47ef45`, `baefc9e`, `c7b587a` | [`crates/era-engine/src/writer.rs:1030-1080, 2730-2760`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/writer.rs#L1030-L1080)<br>[`crates/era-engine/tests/resid_high03_checkpoint_append/fixtures.rs:122-133`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/tests/resid_high03_checkpoint_append/fixtures.rs#L122-L133) | **主逻辑已修复，引入严重回归**：`extra_hashes` 不再写入小文件原始哈希，去重索引隔离；支持 Checkpoint 截断与恢复。但新增测试为 1100 文件预建句柄，在默认 `ulimit -n 1024` 下必崩。`StartFresh` 存在旧指针清理安全隐患。 | [`AUDIT-HIGH-01`](#audit-high-01)<br>[`AUDIT-MED-02`](#audit-med-02) |
| **`RESID-MED-01`**<br>(分片读越界与缺卷 volume_sequence) | `116a4f5`, `33fb1f7` | [`crates/era-engine/src/reader.rs:1790-1825`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/reader.rs#L1790-L1825) | **已彻底修复**：先读取 `ShardHeader`，根据其实际 `header.length` 判定数据分片越界；缺卷时基于 `location.slot_index`、条带位置与 `target_volumes` 准确推导目标分卷真实的 `volume_sequence` 参与 AEAD 解密。 | 无遗留 |
| **`RESID-MED-02`**<br>(窄卷轮转最小可修复卷数) | `8466b0f` | [`crates/era-engine/src/repair.rs:105-125`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/repair.rs#L105-L125) | **已彻底修复**：引入单代组宽 `W`（`target_volumes`），按代次累加各代所需最低卷数，消除了除以总卷数 `G * W` 导致的门限低估。 | 无遗留 |
| **`RESID-MED-03`**<br>(解包同名多条目覆盖顺序) | `be5ba1a` | [`crates/era-engine/src/reader.rs:1970-2010`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/reader.rs#L1970-L2010) | **已彻底修复**：在规划期使用 `HashMap<TargetPathKey, usize>` 记录同名条目的最后出现索引（`last_index`），在 `overwrite=true` 下只对胜出的最新条目预建句柄与解包，避免了 unlink 孤儿句柄写入覆盖。 | 无遗留 |
| **`RESID-MED-04`**<br>(非 EC 多卷提前终止) | `356e7aa` | [`crates/era-engine/src/block_iter.rs:980-990`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/block_iter.rs#L980-L990) | **已彻底修复**：非末尾分卷遇到 `committed_end` 时，不再 `return None` 提前中断，而是正确执行 `self.current_volume_idx += 1; continue;` 推进读取下一分卷。 | 无遗留 |
| **`RESID-LOW-01`**<br>(Footer 序号 1-based 误索引) | `be8fa74` | [`crates/era-engine/src/writer.rs:615`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/writer.rs#L615) | **已彻底修复**：由 `footer.sequence_number()` 修正为 `loaded_header.volume_sequence()`（0-based 卷索引）。 | 无遗留 |
| **`RESID-LOW-02`**<br>(Manifest 回退时未校验摘要) | 未改动 | [`crates/era-engine/src/reader.rs:1424`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/reader.rs#L1424) | **未修复**：`load_manifest` 仍使用 `ArchiveManifest::from_bytes`，主头损坏回退读取时未比对 Manifest 中的 `volume_header_digest`。 | 技术债保持 |
| **`RESID-LOW-03`**<br>(配置读取与新建容量校验) | ca9fe20 | [`crates/era-engine/src/writer.rs:465-475, 1140-1150`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/writer.rs#L1140-L1150) | **已修复，存代码异味**：补齐了从 `config.block.target_size` 获取目标块大小的兜底；但引入了相邻重复 `tokio::fs::try_exists`。 | [`AUDIT-LOW-01`](#audit-low-01) |
| **`RESID-LOW-04`**<br>(Packing 参数预检与 Generic 切分) | `dd7433d`, `120536c` | [`crates/era-engine/src/writer.rs:4334-4357`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/writer.rs#L4334-L4357)<br>[`bins/era-cli/src/main.rs:175-186`](file:///home/ricardom/code/github.com/zapsaang/era-core/bins/era-cli/src/main.rs#L175-L186) | **未完全闭环**：CLI 参数校验已提前到建卷前。但 `GenericArchiveWriter` 仅对单个超大 chunk 切分，未切分多 chunk 打包块；`main.rs` 计划外添加未在帮助文档体现的 `archive` 位置参数。 | [`AUDIT-MED-01`](#audit-med-01)<br>[`AUDIT-LOW-04`](#audit-low-04) |
| **`RESID-LOW-05`**<br>(前置文档状态标记失步) | `780a26a` | [`docs/code-and-practical-test-findings-2026-11-18.md`](file:///home/ricardom/code/github.com/zapsaang/era-core/docs/code-and-practical-test-findings-2026-11-18.md) | **已同步，存瑕疵**：已更新前置文档的状态标记。但将新测试标注为“既有”，且在文档中隐式假定 `ulimit -n 4096`。 | [`AUDIT-LOW-05`](#audit-low-05) |

---

## 四、 确认遗留缺陷与新增技术债详述

### High 级别缺陷

#### `AUDIT-HIGH-01`：新增测试 `resid_high03_checkpoint_append` 在系统与 CI 默认 `ulimit -n = 1024` 环境下必报 `TooManyOpenFiles`（阻塞 CI）

- **严重度**: High
- **维度**: 持续集成门禁 / 系统资源管理
- **源码锚点**:
  - [`crates/era-engine/tests/resid_high03_checkpoint_append/fixtures.rs:122-133`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/tests/resid_high03_checkpoint_append/fixtures.rs#L122-L133)
  - [`crates/era-engine/src/reader.rs:2020-2050`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/reader.rs#L2020-L2050)
- **机理与复现**:
  - 测试 `test_append_existing_with_checkpoint_flow` 在第一阶段写入 1000 个小文件，追加阶段再写入 100 个文件，归档内累计包含 1100 个文件条目。
  - 在随后的 `reader.extract_all(...)` 阶段，`ArchiveReader` 执行 `extract_with_iterator` 规划：
    ```rust
    // reader.rs:2020-2050
    // 对归档内每一个非打包 entry，提前在磁盘创建并打开持有 tokio::fs::File 句柄！
    ```
  - 当条目数达到 1100 时，并发打开的文件句柄峰值直接突破 Linux / macOS 以及 GitHub Actions 标准 runner 的默认限制 `ulimit -n = 1024`。
  - 测试直接抛出未捕获的 panic：
    `called Result::unwrap() on an Err value: Io(Custom { kind: Uncategorized, error: "Failed to open target extraction file ...: Too many open files (os error 24)" })`
- **后果与影响**:
  - 该测试已被纳入 `crates/era-engine/tests` 自动化套件；在任何未特权修改 `/etc/security/limits.conf` 或手动执行 `ulimit -n 4096` 的标准机器或 CI pipeline 上运行 `cargo test --release --workspace`，构建直接红线挂掉。
- **修复方案**:
  - 在测试中适当降低文件总数（如改用 200~300 个文件，既能充分验证追加去重与 checkpoint，又不会逼近系统 fd 上限）；或者在 `extract_with_iterator` 中对预打开文件句柄实施分批或懒打开（按需打开）池化管理。

---

#### `AUDIT-HIGH-02`：`RESID-HIGH-01` 修复未闭环 — 多卷归档卷 0 主 Catalog 损坏时 `verify` 误报 Healthy，CLI `repair --force` 提前跳过拒修

- **严重度**: High
- **维度**: 容灾完整性 / CLI 自愈闭环
- **源码锚点**:
  - [`crates/era-engine/src/reader.rs:985-1025`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/reader.rs#L985-L1025)
  - [`crates/era-engine/src/repair.rs:480-530`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/repair.rs#L480-L530)
  - [`bins/era-cli/src/commands.rs:1189-1196`](file:///home/ricardom/code/github.com/zapsaang/era-core/bins/era-cli/src/commands.rs#L1189-L1196)
- **机理与复现**:
  - commit `f4eeb64` 实现了主 Catalog 的自愈修复，但其触发逻辑严格绑定于 `reader.catalog_recovered_from_backup` 状态标志。
  - 在多卷 EC 归档（例如 4:2 组宽）中，所有分卷末尾都有一份主 Catalog 块拷贝。当卷 0 的主 Catalog 损坏，而卷 1 完好时：
    [`reader.rs:985-1025`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/reader.rs#L985-L1025) 在遍历分卷候选时，卷 0 失败并打印 warn，随后在卷 1 成功读出主 Catalog，**直接提前 `return Ok(catalog)`**。此时 `catalog_recovered_from_backup` 依然保持 `false`！
  - 随后调用 `reader.verify()`，因为没有走 EC 备份恢复路径，`verify()` **不报任何 Degraded，直接判定为 `Healthy`**！
  - 用户或运维察觉卷 0 损坏并执行 `era repair --force archive.era`：
    [`bins/era-cli/src/commands.rs:1189-1196`](file:///home/ricardom/code/github.com/zapsaang/era-core/bins/era-cli/src/commands.rs#L1189-L1196) 执行预检：
    ```rust
    let health = reader.verify(Default::default()).await?;
    if matches!(health, ArchiveHealthStatus::Healthy) && !force {
        // 即使传了 --force，commands.rs 第 1192 行对 Healthy 状态仍然打印：
        // "Archive is already healthy. No repair needed." 并提前 return Ok(())！
    }
    ```
    即使进入修复引擎，修复引擎也仅检查 `self.catalog_recovered_from_backup`，直接跳过 Catalog 修复。
- **后果与影响**:
  - 卷 0 损坏的主 Catalog 永远得不到修复，若未来卷 1 发生故障或退役卷损坏，归档将面临不可挽回的元数据丢失风险。
- **修复方案**:
  - `ArchiveReader::verify()` 应当逐一校验全部活跃分卷末尾的主 Catalog 块；只要存在任意一个分卷的主 Catalog 损坏，健康状态就必须标记为 `Degraded` 并记录待修卷号；
  - `repair` 模块应遍历修复所有损坏分卷的主 Catalog。

---

### Medium 级别缺陷

#### `AUDIT-MED-01`：`RESID-LOW-04` 修复不完整 — `GenericArchiveWriter` 未对多 chunk 合箱做容量预算切分，逼近 16 MiB 时抛出 `InvalidConfig`

- **严重度**: Medium
- **维度**: 规格完备性 / 容量边界防御
- **源码锚点**:
  - [`crates/era-engine/src/writer.rs:4334-4357`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/writer.rs#L4334-L4357)
  - [`crates/era-volume/src/writer.rs:56-62`](file:///home/ricardom/code/github.com/zapsaang/era-volume/src/writer.rs#L56-L62)
- **机理与复现**:
  - commit `dd7433d` 为 `GenericArchiveWriter::add_bytes` 增加了大 payload 的 chunk 切分，保证单个 chunk 不超过 16 MiB。
  - 但在 [`writer.rs:4334-4357`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/writer.rs#L4334-L4357) 的 `write_packed_block` 逻辑中：它将 `self.pending_chunks` 中的所有 chunk 一次性打包进单个 `MacroBlock`：
    ```rust
    let macro_block = MacroBlock::pack_chunks(&self.pending_chunks)?;
    ```
  - 当调用方连续多次调用 `add_bytes`（例如 4 次 3.9 MiB，均未超单 chunk 限制），`pending_chunks` 累计达到 15.6 MiB；加上 `MacroBlock` 头、Chunk 索引表及 AEAD Tag 开销后，打包块总大小突破 `16 * 1024 * 1024` 字节。
  - 随后分卷写入端触发校验：
    `VolumeWriter::write_shard: Shard size 16780000 exceeds maximum allowable 16777216`
    导致整次写入直接报错 `EraError::InvalidConfig` 失败。
- **修复方案**:
  - 在 `write_packed_block` 打包前，根据累加长度预算切分分批打包；或在 `add_bytes` 累积数据接近 `target_block_size` 时主动触发当前批次的封包写盘。

---

#### `AUDIT-MED-02`：追加模式与持久化检查点的时序与崩溃安全技术债

- **严重度**: Medium
- **维度**: 追加一致性 / 崩溃安全
- **源码锚点**:
  - [`crates/era-engine/src/writer.rs:1111-1112`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/writer.rs#L1111-L1112)
  - [`crates/era-engine/src/writer.rs:2120-2135`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/writer.rs#L2120-L2135)
- **机理与影响**:
  1. **`StartFresh` 状态下同步清理 Checkpoint 存在时序漏洞**：
     - 在 [`writer.rs:1111-1112`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/writer.rs#L1111-L1112) 中，当追加模式由于上一次未正常结束而选择 `StartFresh` 时，代码在磁盘正式截断（`truncate`）旧数据之前，直接调用了同步的 `CheckpointManager::delete()`。
     - 若此时进程意外崩溃，Checkpoint 元数据已被删除，但磁盘尾部尚未截断，导致归档处于不可重入也不可恢复的撕裂中间态。
  2. **`finalize` 阶段 Checkpoint 写入早于容量判定**：
     - 在 `finalize` 流程中，先执行 `pipeline.commit_durable_checkpoint()` 向卷 0 数据区写入一个 `BlockType::Checkpoint` 块，之后才去结算各卷的 `committed_ends` 与容量边界。
     - 如果卷 0 数据区此前已经非常逼近 `max_volume_size`，追加写入该检查点块可能导致卷 0 突破预设的最大分卷尺寸限制。
- **修复方案**:
  - 将 Checkpoint 删除操作严格置于底层文件成功截断并 sync 之后；在写入 Checkpoint 块之前纳入分卷剩余容量判定。

---

### Low 级别技术债与代码质量缺陷

#### `AUDIT-LOW-01`：`writer.rs:466-468` 相邻两行重复执行异步 `tokio::fs::try_exists`

- **源码锚点**: [`crates/era-engine/src/writer.rs:466-468`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/writer.rs#L466-L468)
- **问题说明**:
  ```rust
  let path_exists = tokio::fs::try_exists(&primary_path).await.unwrap_or(false);
  if !path_exists && tokio::fs::try_exists(&primary_path).await.unwrap_or(false) {
      ...
  }
  ```
  连续两次对同一路径调用异步 I/O 查询存在性。后一次查询在第一行返回 `false` 时执行，语义上不仅是无意义的冗余调用，还可能在极低概率下因并发外部创建引入竞争状态（TOC/TOU）。

---

#### `AUDIT-LOW-02`：活跃分卷主头与本地 Manifest 双损坏时未回退全局已认证摘要

- **源码锚点**: [`crates/era-engine/src/repair.rs:360-375`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/repair.rs#L360-L375)
- **问题说明**:
  - commit `685718a` 在 `repair` 中为退役分卷主头恢复引入了基于全局 Manifest `volume_header_digests` 的认证回退；
  - 但对于活跃分卷（`active_volumes`），如果其自身主头与本地 Manifest 区域同时发生坏块故障，代码依然直接抛出错误，未能统一复用全局 Manifest 包含的全量摘要进行备份头认证并自愈写回。

---

#### `AUDIT-LOW-03`：冗余字段与残留死代码

- **源码锚点**:
  - [`crates/era-volume/src/volume_pool.rs:1012-1018`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-volume/src/volume_pool.rs#L1012-L1018)
  - [`crates/era-engine/src/write_pipeline.rs:108-145`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/write_pipeline.rs#L108-L145)
- **问题说明**:
  - `VolumePool::finalized_header_digests` 方法在引入 Protobuf 全量头摘要后已不再被主流程调用，成为残留无用方法；
  - `write_pipeline.rs` 中的 `extra_hashes` 参数在小文件哈希隔离后实际传入空 slice，参数签名未作清理重构。
  - `GenericArchiveWriter::finalize` 依然使用旧版单摘要 Manifest 结构编码，未与多卷全量摘要体系统一。

---

#### `AUDIT-LOW-04`：CLI 计划外添加未在帮助文档中体现的位置参数

- **源码锚点**: [`bins/era-cli/src/main.rs:175-186`](file:///home/ricardom/code/github.com/zapsaang/era-core/bins/era-cli/src/main.rs#L175-L186)
- **问题说明**:
  - 在参数预检补丁中，`main.rs` 在 `Commands::Create` 结构体上添加了一个未声明在规范文档中的隐藏位置参数，且与既有的 `-o, --output` 逻辑存在微小交叠，缺乏 CLI 自动化测试保护与用户文档说明。

---

#### `AUDIT-LOW-05`：前置文档 `docs/code-and-practical-test-findings-2026-11-18.md` 状态标注存在偏差

- **源码锚点**: [`docs/code-and-practical-test-findings-2026-11-18.md:515-530`](file:///home/ricardom/code/github.com/zapsaang/era-core/docs/code-and-practical-test-findings-2026-11-18.md#L515-L530)
- **问题说明**:
  - 第 522 行将本次新增的测试 `resid_high03_checkpoint_append` 标注为“既有已通过测试”，并在实测命令说明中隐式要求在 `ulimit -n 4096` 环境下运行，掩盖了默认 CI 环境下该测试必报 `TooManyOpenFiles` 的客观事实。

---

## 五、 结项门槛与整改建议

为实现真正的“零遗留、零技术债、生产就绪”，建议在合并或结项前完成以下收敛工作：

1. **P0（阻塞性，必须立即修复）**:
   - **修复 `AUDIT-HIGH-01`**: 优化 `resid_high03_checkpoint_append` 测试用例（降低测试条目数至安全范围，如 200 个），解除对 `ulimit -n 4096` 的非标依赖，保证 `cargo test --release --workspace` 在标准 CI 环境 `1024` 限制下稳定全绿。
   - **闭环 `AUDIT-HIGH-02`**: 完善多卷主 Catalog 坏块校验，确保任一分卷主 Catalog 损坏均能触发 `Degraded`，且 `era repair --force` 能够完整执行原位恢复。
2. **P1（建议修复，消除稳健性隐患）**:
   - **修复 `AUDIT-MED-01`**: 为 `GenericArchiveWriter` 打包前增加总量切分机制，防止多 chunk 累计突破 `16 MiB` 上限。
   - **重构 `AUDIT-MED-02`**: 规范 `finalize` 检查点写入时序与崩溃恢复截断逻辑。
3. **P2（代码与工程清理）**:
   - 清理 `AUDIT-LOW-01` ~ `AUDIT-LOW-05` 对应的冗余代码、失步文档与未记录参数。
