# ERA-CORE 问题清单（2026-11-22，两轮审计+修订后）

- **基线**: `feat_fly @ b22a07e`；**最终**: `b22a07e` + 未提交两轮修订（工作树）
- **状态图例**: ✅已修复（Round1/Round2，含 TDD 回归） / ⚠️部分修复 / ❌未修复（阻塞或架构级） / 📌接受为已知限制 / ℹ️信息项
- **证据**: 详细机理、命令输出、red→green 见 `docs/audit/round1-*.md`、`docs/audit/round2-*.md`；主报告 `docs/final-audit-and-remediation-2026-11-22.md`
- **ID 规则**: RF-xx = Round-1 合并清单（跨线程去重）；R2-xx = Round-2 复核发现；H/LL/ENG/EW = 原始线程编号（括号内标注）

## 一、High / Medium

| 编号 | 严重度 | 维度 | 标题 | 基线 | 最终状态 | 关键锚点/证据 |
|---|---|---|---|---|---|---|
| RF-01 (LL-01/EW-02/R1) | **High** | 并发与一致性（崩溃安全） | append finalize 先 truncate 旧元数据后写 footer，finalize 中崩溃使既有归档不可打开 | 存在 | ❌未修复（架构级） | `era-volume/src/writer.rs:256-265,832-877`；故障注入 before_len=13568/after_len=8320，reopen 报 data_end>size |
| RF-02 (ENG-RC-01) | **High** | 规格/数据可用性 | 解包全局累计 8 GiB 上限使 >8GiB 合法归档必然失败并清理已写文件 | 存在 | ✅已修复（R1+R2） | `era-engine/src/reader.rs` 预算 opt-in 且按实际写盘计费；去重 fanout 测试 |
| RF-03 (LL-02/EW-01/R2) | **Medium~High** | 性能/资源 | staged append 全量驻留内存（≈max_volume_size），O(append) RSS，可 OOM | 修订引入 | ❌未修复（架构级） | `era-volume/src/writer.rs:28-33,661-673,721-730`；探针 8 MiB append on_disk 不变、staged_bytes≈8.38M |
| RF-04 (ENG-RC-02/EW-03) | Medium | 规格/完整性 | verify/repair 不覆盖 footer 冗余；主 footer 损坏静默回退仍成功，备份 footer 损坏不可见不可修 | 存在 | ✅已修复（R1+R2） | `era-volume/src/reader.rs` footer 标志；`era-engine/src/reader.rs` verify_redundant_footers；repair 双侧写回 |
| RF-05 (ENG-RC-03) | Medium | 规格/数据可用性 | era create 静默丢弃 symlink/空目录/不可读子树且 rc=0 | 存在 | ✅已修复（R1+R2） | `bins/era-cli/src/commands.rs` 遍历错误硬失败；空目录 warn；R2 增 `--skip-symlinks` |
| RF-06 (LL-03) | Medium | 持久化 | 可增长卷 finalize 覆盖恢复 footer 前缺 fdatasync 屏障 | 存在 | ❌未修复 | `era-volume/src/writer.rs:832-877`（定长卷分支有 sync） |
| RF-07 (LL-04) | Medium | 安全/完整性 | 打开归档不校验活跃 SuperHeader 认证摘要，未入 AAD 的 config 被直接信任 | 存在 | ✅已修复（R1+R2） | digest 表校验 + 单头篡改从备份恢复 + 双头篡改 fail-closed + R2 AAD 重试 |
| RF-08 (H-03) | Medium | 测试质量 | 空体/恒过测试计入验收统计（7 个） | 存在 | ✅已修复（R1+R2） | 7 测试改真实断言；hygiene_guards_test 扫描器（拒绝 assert!(true)/空体） |
| RF-09 (H-01) | Medium | 代码质量 | 技术债清理未闭环：41 个 allow(dead_code)、49 个零引用 pub fn | 存在 | ❌未修复（债务） | `grep -rn allow(dead_code) crates/*/src` = 41；前序点名 8 个中 7 个仍零引用 |
| RF-10 (H-02) | Medium | 工程/证据链 | docs/ 全局 ignore，历史 6 份审计/设计文档不可跟踪 | 存在 | 📌部分缓解 | `.gitignore` 已放行 docs/audit；历史 docs 需 git add -f 或改全局 ignore |
| R2-01 | **High（阻塞）** | 回归 | R1 header digest 硬校验使"可解析但摘要不匹配"的主头损坏不可打开、repair 不可达、CLI 门禁红 | 修订引入 | ✅已修复（R2，root） | 基线门禁 cli_rc=101；修复为"认证 backup 头则采纳并 degraded，双头坏才 fail-closed"；定向+全量门禁回绿 |
| R2-02 | Medium | 修复假成功 | 双 footer 损坏靠 floating 恢复时 repair 报成功但零写回、永不收敛 | 修订引入 | ✅已修复（R2） | 用 floating footer 重建并截断，或返回 IntegrityError；新增 e2e 测试 |
| R2-03/R2-04 | Medium | 规格/资源 | 输出预算按解码字节计费，dedup/fanout 实际写盘可绕过；CLI 无预算入口 | 修订不完整 | ✅已修复（R2） | 按 stats.bytes_written 实际写盘计费；`extract --max-output-bytes` |
| R2-05 | Low | 测试缺口 | footer/header 修复缺矩阵/dry-run/floating/多卷 adoption 测试 | 存在 | ✅已修复（R2） | 8 项新引擎测试 |
| R2-08 | Low | 安全/完整性 | manifest AAD 字段可解析篡改导致 backup 头采纳不可达 | 存在 | ✅已修复（R2） | manifest 解密失败时用 backup AAD 重试一次 + AEAD/digest 双认证 |
| R2-STOR-01 | Medium | 持久化/噪声 | 目录 fsync 对相对裸文件名失效并每卷 WARN | 修订引入 | ✅已修复（R2） | parent 空→"."；新增路径归一化单测 |
| R2-CLI-02 | Medium | 规格/兼容 | create 对树内 symlink 硬失败且无逃生口/未文档化 | 修订引入 | ✅已修复（R2） | `--skip-symlinks` + help/README + 双模式测试 |
| R2-ING-01 | Medium | API 契约 | Chunker::new 非法配置静默回退默认布局 | 修订引入 | ✅已修复（R2） | `Chunker::new -> Result`；调用点全部更新 |
| R2-04（测试可信度） | Medium | 测试质量 | 4 个矩阵/容错测试自证式（测试内重算算法） | 修订不彻底 | ✅已修复（R2） | 改调生产 distribution/端到端布局；新增门禁负例 |

## 二、Low

| 编号 | 维度 | 标题 | 最终状态 | 锚点/说明 |
|---|---|---|---|---|
| RF-11 (ENG-RC-04) | 规格 | 读路径不实现 Directory/Symlink 条目（静默忽略） | 📌已知限制 | writer 不产出；create 语义已显式化；读支持为独立功能 |
| RF-12 (ENG-RC-05) | 规格/运维 | repair 对不存在路径 exit 0 | ✅已修复（R1） | 改为 bail 非零 |
| RF-13 (ENG-RC-06) | 可运维性 | verify Degraded 文案一律"卷缺失" | ✅已修复（R1+R2） | 按 missing_indices 区分；warning 去重 |
| RF-14 (ENG-RC-07) | 代码质量 | repair 死分支 Healthy && needs_repair() | ✅已修复（R1+R2） | 布尔不可满足；重构为穷尽 match |
| RF-15 (ENG-RC-08) | 崩溃安全 | 解包未 fsync 目录；--force rename→create 崩溃窗口 | ⚠️部分修复 | 数据文件 fsync + 回滚已修；目录 fsync 未做 |
| RF-16 (ENG-RC-09) | 安全 | 父目录 TOCTOU 残余；metadata 恢复重开跟随符号链接 | ⚠️部分修复 | 末级 O_NOFOLLOW+inode 已修；openat 化未做 |
| RF-17 (ENG-RC-10/§4.9) | 性能 | verify 每卷完整读 Catalog；非 EC repair 重复 verify | 📌benchmark-needed | 无基准；正确性无问题 |
| RF-18 (ENG-RC-11) | 规格一致性 | verify 不检查 entry.size>100GiB（extract 检查） | ❌未修复 | 低风险判定差异 |
| RF-19 (ENG-RC-12/H-04) | 测试质量 | 139+ 处 include_str! 源码字符串耦合测试 | 📌接受（大规模重构） | 与 H-04 合并 |
| RF-20 (LL-05) | 健壮性 | era-ingest 公共 API 非法 ChunkerConfig panic | ✅已修复（R1+R2） | try_new→new Result 化 |
| RF-21 (LL-06) | 安全/持久化 | LocalStorageBackend::create 跟随 symlink/无 O_EXCL/父目录未 fsync | ✅已修复（R1+R2） | O_NOFOLLOW+fsync；R2 修空 parent |
| RF-22 (LL-07) | 代码质量 | read_all_from(offset>size) 下溢 | ✅已修复（R1） | offset>=size 返回空 |
| RF-23 (LL-08) | 防御纵深 | proto→域模型缺跨字段校验（BlockChunkIndex.count 等） | ❌未修复（低风险） | 调用方受限 |
| RF-24 (H-05) | 工程 | CI 未 --locked/无 ulimit/timeout；README 命令不一致；flake 未跟踪 | ✅大部分修复 | ci.yml/README 已修；flake 仍工程债 |
| RF-25 (H-06) | 测试结构 | #[path] 生产模块编入集成测试 | 📌接受 | 重复执行/cfg(test) 错位 |
| RF-26 (H-07) | 测试稳定性 | 墙钟/ sleep 断言（concurrency_torture 5s 等） | 📌接受（likely flaky） | 可后续改事件驱动 |
| RF-27 (H-08) | 文档 | README 两套统计、AGENTS 引用数/Commit 过期 | ✅已修复（R1+R2，最终数字已刷新） | README 单源锚点，AGENTS refs 可复算一致 |
| RF-28 (H-09) | 工程 | src 内联 #[cfg(test)] 13.5k 行/75 文件 | 📌接受 | 测试组织债 |
| RF-29 | 文档/规格 | 前序 14 项中 7 项 PARTIAL（详见主报告 §3） | ⚠️大部分已改，RF-01/09/17/19/24 残留 | — |
| RF-30 (LL-09/10/11、H-I*) | 纵深/代码质量 | VK wrap AAD 未绑定卷、encode_shards 静默补零、mlock 未 munlock 等 | ℹ️信息项 | 无可利用性/仅诊断路径 |

## 三、Round-2 其他低项（已由修订覆盖或接受）

| 编号 | 标题 | 状态 |
|---|---|---|
| R2-06 | 门禁日志来自被并发修改的快照，不能作为合并依据 | ✅已解决：冻结树重跑全量门禁 |
| R2-07 | 每卷额外 4KiB 读+hash 的性能影响 | 📌benchmark-needed |
| R2-09 | ExtractOptions 新 pub 字段为 source-breaking；digest fallback 分支 | ✅已知 API 变更已记录；fallback 为有意防御 |
| R2-CLI-03 | depth-0 symlink→空目录按空目录报告 | ℹ️信息项 |
| R2-HYG-01/02 | hygiene 门禁源码字符串耦合/统计数字 | ✅已强化（trivial 检测、范围收敛、README 单源） |
| R2-VERIFY-01 | engine 侧 verify warning 与 CLI 列表重复 | ✅CLI 去重；engine 日志属正常诊断 |
| R2-05 低项 | repair exit 0→1 未文档化 | ✅README/help 已补 Exit status |

## 四、最终门禁与交付状态

- **门禁**（冻结树 `ulimit -n 1024`）：fmt 0、clippy 0、era-cli **518 passed/0 failed/3 ignored（18 suites）**、workspace **2974 passed/0 failed/17 ignored（171 suites）**，合计 **3492 passed/0 failed/20 ignored**。
- **工作树**：27 个跟踪文件修改（+2461/−878）、7 个新增回归测试文件、`docs/audit/` 10 份证据文档；未提交、未推送。
- **阻塞项**：RF-01（High）、RF-03（Medium~High）、RF-06（Medium）为架构/持久化遗留；其余 Low/Info 已在主报告 §5 记录。
