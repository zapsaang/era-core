# ERA-CORE 风险评估报告

**日期:** 2026-10-09
**评估方式:** 静态代码审计（写/读/修复三条链路）+ 实机端到端冒烟测试
**评估范围:** 目录/单文件压缩打包、错误修复、解包恢复的可用性与风险

## 总体结论

三条主链路（打包压缩、解包恢复、错误修复）**功能完整、可正常工作**。实机验证结果：

| 场景 | 结果 |
|---|---|
| 目录打包（7 文件，含 200KB 随机二进制）→ 校验 → 解包 → `diff -r` | 逐字节一致 |
| 单文件 create → extract → diff | 内容一致 |
| 丢失 2/6 卷后直接 extract | 全部文件完整恢复（RS 4+2 读取路径内联重建） |
| 卷内 1.5MB 覆写损坏后 extract | 数据完整恢复（CRC 检测 + RS 重建透明进行） |

生产代码中无 `todo!`/`unimplemented!`/`panic!`，CI 基线 2737 测试通过。以下风险点按维度整理，区分**已证实**（有代码/实测证据）与**需关注**（结构性风险）。

---

## 一、数据丢失类风险（最高优先级）

### 1.1 repair 不能重建丢失的卷文件 【已证实】

- 证据：`bins/era-cli/src/commands.rs:1141-1147` 明确 bail：`"current repair cannot recreate missing volume files"`；实测删除 2/6 卷后 `era repair` 报错退出。
- 影响：用户误以为 repair 能处理丢卷场景。
- 缓释：丢卷后的正确流程是 `era extract`（内联 RS 重建可读出数据）+ 重新 `create` 归档。**文档与 CLI 提示应强调这一点**。

### 1.2 同一条带丢失分片超过 parity 数即不可恢复 【已证实，设计上限】

- 证据：`crates/era-engine/src/repair.rs:596-614`，`min_shards = data_shards`；默认 4+2 意味着同一块的 6 个分片不能同时丢 3 个。
- 影响：用户容易高估"50% 冗余"的含义——丢任意 2 卷安全，丢 3 卷即开始有数据丢失风险。
- 缓释：多卷场景下增大 parity（如 `--erasure 4:3`）或增加卷数；文档明确概率模型。

### 1.3 SuperHeader 损坏 = 硬失败 【已证实的设计决策】

- 证据：`VolumeReader::open` 对 magic 不匹配直接报错；有三层兜底（主头 → 备份 footer → 1MB 反向扫描），但卷起始 4KB 头部区域整体物理损坏时无重建路径。
- 影响：头部区域坏道会导致整卷不可读。
- 缓释：多副本存储；未来可考虑"从 VK + archive_id 重建头"的手动工具。

### 1.4 未开 erasure 的归档完全不可修复 【已证实】

- 证据：`repair.rs:354-356` 直接返回 `ErasureError("Archive does not use erasure coding - repair not available")`。
- 影响：`--erasure none` 选项允许用户主动关闭防护。
- 缓释：默认已是 4:2；建议 CLI 在 `--erasure none` 时加强警告。

---

## 二、安全类风险

### 2.1 `--password` 命令行明文传参 【已证实】

- 证据：create 帮助文档示例即 `-p secret`。
- 影响：密码进入 shell history 和进程列表。
- 缓释：改用交互式输入或证书模式；**修正文档示例，避免诱导危险用法**。

### 2.2 密码强度完全依赖用户 【需关注】

- Argon2id KDF 实现合规，但 CLI 无密码强度检查；弱口令 + 归档泄露 = 离线爆破敞口。
- 缓释：增加强度提示或最小长度校验。

### 2.3 内存中密钥材料的残留面 【需关注】

- 已有 `SecureBuffer<N>` + zeroize + mlock（全 workspace 唯一 unsafe 在 `crates/era-crypto/src/secure_memory.rs`），经审计；但 debug 构建下 zeroize 不保证完全生效，coredump 策略未在 CLI 层禁用。
- 缓释：生产仅用 release；考虑 CLI 层 `prctl(PR_SET_DUMPABLE, 0)`。

### 2.4 阈值模式不支持 append 【已证实】

- 证据：`writer.rs:474-481` 显式拒绝。
- 影响：用户误以为支持会踩空；属已声明限制。

---

## 三、工程质量类风险

| 风险 | 证据 | 等级 |
|---|---|---|
| writer.rs 3649 行 god object | 50 处引用的核心编排器集中单文件，修改爆炸半径大 | 需关注 |
| 工具链漂移 | rust-toolchain.toml 钉 1.98.1，CI 用 `stable`（根 AGENTS.md 自标注 drift risk） | 已证实 |
| 无 workspace.lints / clippy.toml | 仅靠 CI `-D warnings` 兜底，本地无提前约束 | 已证实 |
| fuzz workspace 缺失 | fuzz.yml 为 workflow_dispatch 且 `fuzz/` 不在仓库（`exclude = ["fuzz"]`）——模糊测试设施文档化但不可运行 | 已证实 |
| DirectoryScanner 死代码 | glob/ACL/xattr 过滤已实现并测试，但 CLI 用裸 walkdir（commands.rs:672）；用户预期的高级过滤不存在 | 已证实（功能缺口） |
| `crates/era-storage/src/cache/` 空目录占位 | 暗示未完成设计 | 低 |

---

## 四、运维/使用类风险

1. **单文件提取不保留目录结构**：实测单文件归档解出为 `restored/file1.txt` 而非 `restored/input/file1.txt`；脚本化使用需注意路径差异。
2. **小数据量冗余开销巨大**：实测 195KB 数据产生 6 卷共 ~7.5MB（约 38 倍放大）。纠删码 + 最小分片尺寸 + 元数据冗余扇出的固有代价；小文件场景需评估。
3. **恢复语义反直觉**：repair 失败时提示 `extract --force` 抢救；"数据可读"与"归档已修复"是两回事，用户易混淆。
4. **实测范围有限**：本次验证基于 debug 构建 + 小数据集；并发压力、GB 级大文件、中断恢复场景未实测（测试套件有覆盖，生产部署前建议按自身数据规模复验）。

---

## 建议的缓释动作（按优先级）

1. 重要归档保存好全部卷文件；丢卷后立即 `extract` 而非 `repair`。
2. 密码用交互式输入或证书/混合 PQ 模式；修正文档中 `-p secret` 示例。
3. 部署前运行 CI 同款验证：`cargo test --release -p era-cli && cargo test --release --workspace`。
4. 若需 include/exclude 过滤：在 `bins/era-cli/src/commands.rs:668` 接线 `DirectoryScanner`（era-ingest 已实现）。
5. 中期：拆分 writer.rs；统一 rust-toolchain 与 CI 版本；补 workspace.lints。
6. 可选增强：CLI 增加"从幸存卷重建丢失卷文件"模式（引擎层 RS 机制已具备，仅 CLI 拒绝）；考虑 header 重建工具。

---

*本报告基于 2026-10-09 时点的代码（分支 feat_fly）与实测结果，后续代码变更可能使部分结论失效。*
