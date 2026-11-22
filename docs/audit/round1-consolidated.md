# Round 1 合并问题清单（去重后）

基线: feat_fly @ b22a07e；round1 原始报告: docs/audit/round1-*.md
状态列含义: 待修订 / 已修订待复核 / 接受为限制（需文档化）/ 信息项

| 合并编号 | 来源 | 严重度 | 维度 | 标题 | 状态 |
|---|---|---|---|---|---|
| RF-01 | LL-01 / prior-closure R1 / lead OBS-2 | High | 并发与一致性（崩溃安全） | append finalize 先 truncate 旧元数据再写新 footer：finalize 中崩溃使既有归档不可打开（finalize 前窗口已由 8c42a4c 修复） | 待修订/接受限制 |
| RF-02 | ENG-RC-01 | High | 规格符合性/数据可用性 | 解包全局累计 8 GiB 上限：>8GiB 唯一数据的合法归档必然解包失败，并清理已写文件 | 修订中 |
| RF-03 | LL-02 / prior-closure R2 / lead OBS-1 | Medium | 性能/资源 | StagedAppend 将整段 append 负载驻留内存（至多 max_volume_size，默认 4 GiB），8c42a4c 引入的 provable regression，可 OOM | 待修订/接受限制 |
| RF-04 | ENG-RC-02 | Medium | 规格/完整性 | verify/repair 不覆盖 footer 冗余：主 footer 损坏静默回退仍 exit 0；offset 4096 备份 footer 损坏不可见不可修 | 修订中 |
| RF-05 | ENG-RC-03 | Medium | 规格/数据可用性 | era create 静默丢弃 symlink/空目录/不可读子树（filter_map(e.ok())），仍 rc=0 | 修订中 |
| RF-06 | LL-03 | Medium | 持久化 | 可增长卷 finalize 覆盖恢复 footer 前缺 fdatasync 屏障（定长卷有） | 待修订 |
| RF-07 | LL-04 | Medium | 安全/完整性 | 打开归档不校验活跃 SuperHeader 认证摘要；config 未入 AAD 却被信任 | 修订中 |
| RF-08 | H-03 | Medium | 测试质量 | 至少 1 个空体测试 + 6 个恒过测试计入验收统计 | 修订中 |
| RF-09 | H-01 | Medium | 代码质量 | 技术债清理未闭环：src 仍有 41 个 allow(dead_code)、49 个零引用 pub fn | 待修订（round 2） |
| RF-10 | H-02 | Medium | 工程/证据链 | docs/ 仍被全局 ignore；本轮 docs/audit 与 6 份历史文档不可跟踪（4 份 11 月文档已跟踪） | 接受为环境限制/文档化 |
| RF-11 | ENG-RC-04 | Low | 规格 | 读路径不实现 Directory/Symlink 条目（静默忽略），README 声称 symlinks rejected | 待修订/文档化 |
| RF-12 | ENG-RC-05 | Low | 规格/运维 | era repair 对不存在路径 exit 0 "Nothing to repair" | 修订中 |
| RF-13 | ENG-RC-06 | Low | 可运维性 | verify Degraded 文案把所有降级描述为卷缺失，错误信息不带告警详情 | 修订中 |
| RF-14 | ENG-RC-07 | Low | 代码质量 | repair 中 Healthy && needs_repair() 分支不可达（死代码） | 修订中 |
| RF-15 | ENG-RC-08 | Low | 崩溃安全 | 解包未 fsync 目录；--force rename->create 窗口崩溃时目标缺失 | 待修订/文档化 |
| RF-16 | ENG-RC-09 | Low | 安全 | 解包父目录 TOCTOU 残余；metadata 恢复按路径重开跟随符号链接 | 待修订（部分） |
| RF-17 | ENG-RC-10 | Low | 性能 | §4.9 未闭环：verify 每卷完整读 Catalog；非 EC repair 重复全量 verify；无 benchmark | 接受（benchmark-needed） |
| RF-18 | ENG-RC-11 | Low | 规格一致性 | verify 不检查 entry.size>100GiB，仅 extract 检查 | 待修订 |
| RF-19 | ENG-RC-12 / H-04 | Low | 测试质量 | 源码字符串耦合测试仍在（engine+cli 139~263 处 include_str!） | 接受（大规模重构超范围） |
| RF-20 | LL-05 | Low | 健壮性 | era-ingest 公共 API 对非法 ChunkerConfig panic（assert；validate 未调用） | 修订中 |
| RF-21 | LL-06 | Low | 安全/持久化 | LocalStorageBackend::create 截断式 File::create（跟随 symlink、无 O_EXCL），父目录未 fsync | 修订中 |
| RF-22 | LL-07 | Low | 代码质量 | read_all_from(offset>size) 下溢 | 修订中 |
| RF-23 | LL-08 | Low | 防御纵深 | protobuf→域模型转换缺跨字段校验（BlockChunkIndex.count、ErasureBlockInfo） | 待评估 |
| RF-24 | H-05 | Low | 工程 | CI 未 --locked、无 ulimit -n 1024、无 timeout-minutes；README CI 命令不一致；flake 未跟踪 | 修订中 |
| RF-25 | H-06 | Low | 测试结构 | #[path="../src/..."] 把生产模块编入集成测试（5 处/3 文件），重复执行/cfg(test) 错位 | 待评估 |
| RF-26 | H-07 | Low | 测试稳定性 | 墙钟/ sleep 同步断言（concurrency_torture 5s、CLI 50/100ms）likely flaky | 待评估 |
| RF-27 | H-08 | Low | 文档 | README 两套互斥统计；AGENTS CODE MAP 引用数漂移、Commit 头过期 | 修订中 |
| RF-28 | H-09 | Low | 工程 | src 内联 #[cfg(test)] 13,547 行/75 文件（25.5%）与 894 行 test-only src 未记录 | 接受 |
| RF-29 | prior-closure §4.7/§4.10/§4.9/§5.2/§5.3/§5.4 | Low | 文档/规格 | 14 项对账中 7 项 PARTIAL（见 final 报告对账表） | 部分修订 |
| RF-30 | LL-09/10/11、H-I01~03 等 | Informational | 纵深/代码质量 | VK wrap AAD 未绑定卷；encode_shards 静默补零；mlock 未 munlock；其他 I 项 | 信息项 |
