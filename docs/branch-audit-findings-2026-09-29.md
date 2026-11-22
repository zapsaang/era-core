# 当前分支审计问题记录

- 记录日期：2026-09-29
- 审查分支：`feat_fly`
- 审查基线：`main...feat_fly`
- 审查时 HEAD：`e4050a2`
- 基线提交：`1485fc4c43d4cb196c32c4fe29ded29f77c2926d`
- 范围：相对基线的 355 个变更文件，重点检查认证、读取、验证及恢复路径。
- 方法：并行审查报告汇总、去重，以及源码调用链和状态转换复核。
- 验证边界：以下“确认”指静态源码证据充分，不代表已完成运行时复现。本轮未运行复现测试或全量测试，未修改生产代码。

行号对应上述审查版本；后续代码变化可能使行号偏移。

## 问题摘要

| 编号 | 严重度 | 问题 | 维度 | 置信度 | 状态 |
| --- | --- | --- | --- | --- | --- |
| AUD-01 | High | 丢弃检查点时覆盖已提交数据 | 正确性、一致性 | 高，静态确认 | 待修复、待复现 |
| AUD-02 | High | 异常分片长度使验证无限循环并持续占用内存 | 安全、正确性 | 高，静态确认 | 待修复、待复现 |
| AUD-03 | High | 归档控制的 Argon2 参数缺少资源上限 | 安全 | 高，静态确认 | 待修复、待复现 |

## AUD-01：丢弃检查点时覆盖已提交数据

**严重度：High。维度：正确性、一致性。类别：恢复操作顺序错误。**

### 位置与证据

- [`bins/era-cli/src/commands.rs:1247`](../bins/era-cli/src/commands.rs#L1247)：根据是否存在 manifest 调用 `truncate_to_checkpoint*()`，随后在第 1260 行调用 `manager.cleanup()`。
- [`crates/era-engine/src/recovery.rs:435`](../crates/era-engine/src/recovery.rs#L435)：以 footer 的 `data_end_offset` 为目标截断文件；第 470 行执行 `file.set_len(data_end)`。
- [`crates/era-engine/src/recovery.rs:326`](../crates/era-engine/src/recovery.rs#L326)：`cleanup()` 调用 `CheckpointManager::delete()`。
- [`crates/era-engine/src/checkpoint.rs:418`](../crates/era-engine/src/checkpoint.rs#L418)：以 `file_len - FOOTER_SIZE` 计算主 footer 地址。尾部解析失败后读取位于 `HEADER_SIZE` 的备份 footer，第 460 至 465 行仍向该主 footer 地址及备份位置写回。

### 触发条件与影响

归档存在可加载的卷内检查点，能够通过打开及截断前校验，备份 footer 有效，用户执行 `repair --force` 丢弃检查点。

截断移除了数据区之后的备份头和主 footer。随后 `delete()` 计算出的主 footer 地址为 `data_end_offset - 128`，已位于提交数据内部。因此写回 footer 会覆盖已提交数据的最后 128 字节，而非仅清除检查点指针，可能破坏密文或元数据。

这是由当前调用顺序和地址计算直接推导出的数据完整性问题，不依赖恶意输入。

### 修复建议与验收

将截断、检查点指针清除和尾部结构重建作为布局一致的恢复操作处理。截断后不能继续沿用“文件末尾已有主 footer”的假设；重建时应保留有效的 manifest、catalog 和 index 定位信息。

- 构造带有效卷内检查点的归档，执行强制丢弃检查点流程。
- 比较操作前后已提交数据区，确认没有被 footer 覆盖。
- 验证新尾部布局及元数据引用有效，并按恢复接口承诺验证重新打开、验证或后续创建行为。

## AUD-02：异常分片长度使验证无限循环并持续占用内存

**严重度：High。维度：安全、正确性。**

### 位置与证据

- [`crates/era-engine/src/erasure_scan.rs:11`](../crates/era-engine/src/erasure_scan.rs#L11)：`reconcile_stripe_prefixes()` 根据重复副本一致性选择长度前缀，没有在此约束分片长度上限。
- [`crates/era-engine/src/block_iter.rs:1475`](../crates/era-engine/src/block_iter.rs#L1475)：`SessionErasureBlockIterator::next_block()` 优先使用协调后的数据分片长度。
- [`crates/era-engine/src/block_iter.rs:1504`](../crates/era-engine/src/block_iter.rs#L1504)：长度超过 `MAX_SHARD_SIZE` 时返回 `Some(Err(...))`，没有推进当前位置、stripe 编号或设置终止状态。
- [`crates/era-engine/src/reader.rs:1965`](../crates/era-engine/src/reader.rs#L1965)：验证循环在收到错误后增加失败计数、向 `stats.errors` 追加字符串，然后继续调用 `next_block()`。

### 威胁场景、边界与影响

攻击者可修改归档中的分片元数据，使重复存储的 stripe 长度前缀一致地声明首个数据分片超过 256 MiB，同时保留正常分片头和足以通过前置读取检查的数据布局。受害者使用有效凭据验证该归档。

信任边界是磁盘上未认证的分片元数据进入验证状态机。攻击者无需重新生成数据 AEAD 标签。首个分片触发错误时，持久化迭代状态未推进，后续调用重复处理同一位置；验证器持续读取、记录相同错误，造成 CPU/I/O 消耗和错误列表无界增长，最终可能内存耗尽。

循环和列表增长由控制流直接确认；实际耗尽速度与运行环境有关，本轮没有测量。

### 修复建议与验收

不可恢复的结构错误应使迭代器进入终止状态，或在能够保证正确性的情况下明确推进。验证端应区分终止错误与可继续处理的块错误。

- 构造具有一致超限长度前缀、正常分片头的测试归档。
- 在超时约束下运行验证，确认能够有限时间退出并报告格式错误。
- 直接测试迭代器错误后的状态，确认不会重复返回同一错误。
- 检查错误列表不会因单一坏 stripe 无界增长。

## AUD-03：归档控制的 Argon2 参数缺少资源上限

**严重度：High。维度：安全。**

### 位置与证据

- [`crates/era-engine/src/auth.rs:63`](../crates/era-engine/src/auth.rs#L63)：`PasswordProvider::try_unlock()` 将 recipient slot 中的 `kdf_memory_cost`、`kdf_time_cost` 和 `kdf_parallelism` 直接复制到 `KdfParams`，第 72 行调用 `derive_key()`。
- [`crates/era-crypto/src/kdf.rs:60`](../crates/era-crypto/src/kdf.rs#L60)：参数直接传给 `Params::new()`，随后执行 `hash_password_into()`。这条路径没有应用级资源预算校验。
- 主密钥解密认证发生在 KDF 运算之后，无法阻止此前的资源消耗。

### 威胁场景、边界与影响

攻击者提供一个口令保护归档，在 recipient slot 中设置极端但算法上有效的内存或迭代参数，诱使用户尝试口令认证。

信任边界是未认证的归档头部字段直接控制本地内存分配和 CPU 工作量。攻击者无需知道用户输入的口令；即使最终解锁失败，昂贵运算仍已发生。可能造成长时间卡死、内存耗尽或宿主机资源压力。

算法参数合法性检查不能替代应用级资源上限。具体内存峰值和耗时尚未通过运行时测试测量。

### 修复建议与验收

在调用 Argon2 前，通过统一的有界参数校验限制内存、迭代次数和并行度。读写两侧采用一致约束，对超限配置返回明确错误。

- 为三类参数分别增加允许边界及超限拒绝测试。
- 确认不可信归档中的超限参数在 KDF 执行前被拒绝。
- 确认现有受支持参数的正常归档仍可解锁。
- 避免通过实际执行极端 KDF 参数来测试拒绝逻辑，以免测试自身耗尽资源。

## 未纳入确认结论的候选项

以下候选仍需要进一步核验，不应据此宣称已存在可利用漏洞或已证明端到端故障：

- 卷轮转后的物理分片位置与 AEAD volume binding 是否不一致：需要强制扩卷后的创建、读取和逐字节比对复现。
- 纠删元数据驱动的超大分配：需要进一步确认具体公开调用路径、元数据认证前提及有效长度约束。
- 冷恢复使用序列化 Bloom filter 导致假阴性：需要验证缺失已知哈希的过滤器在完整恢复路径中的行为及用户可见影响。

“主头损坏时不自动读取备份头”未采纳为确认缺陷：虽然接口注释描述恢复链，但仓库安全规则明确要求损坏 magic 硬失败。应先厘清契约冲突，而非直接认定当前行为错误。

## 审计限制

本报告不是对整个分支安全性或正确性的认证。分支变更范围很大，本轮重点复核了上述高风险路径，没有完成所有生产文件的穷尽审查。三项确认问题仍需回归测试或受控复现支持；修复后应重新审查相关读写对称性、错误状态转换和恢复一致性。
