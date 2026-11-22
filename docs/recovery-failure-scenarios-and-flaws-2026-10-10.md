# ERA-CORE 恢复失败场景与架构缺陷分析报告

**日期:** 2026-10-10  
**分支:** feat_fly (commit e4050a2)  
**评估维度:** 数据恢复盲区、架构设计缺陷、极端损坏场景下的恢复边界  
**分析方法:** 静态代码分析、调用链追踪、交叉审计报告验证  

---

## 一、 概述

在对 `era-core` 的打包（`create`）、解包（`extract`）和修复（`repair`）全流程进行深入代码审查后，确认程序在正常环境及常规单卷/多卷 RS 纠错场景下可正常工作。然而，除了基础的“纠删码超额损坏”、“未开启纠删码”、“丢失物理卷文件”和“主头/密码丢失”这 4 种常规限制外，系统中还存在多处**硬编码安全阈值误杀、元数据保护盲区、异常处理状态撕裂以及特殊文件类型支持缺失**等隐患，会导致文件在特定条件下无法恢复。

本报告对这些问题进行详细分类记录，并提供精确的代码锚点与规避建议。

---

## 二、 导致文件无法恢复的极端场景深度分析

### 1. 累计解包数据超过 8GB 时，解包强制中断并清除已提取文件 【严重缺陷】

* **源码位置**:
  * [`crates/era-engine/src/reader.rs:47`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/reader.rs#L47)
  * [`crates/era-engine/src/reader.rs:1683-1708`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/reader.rs#L1683-L1708)
* **机理分析**:
  * 引擎定义了硬编码常量 `const MAX_EXTRACTION_MEMORY: u64 = 8 * 1024 * 1024 * 1024;`（8GB），初衷是防范解压炸弹（Decompression Bomb）。
  * 但在 `extract_with_iterator` 中，程序使用 `cumulative_bytes_extracted` 累计累加了**全量提取文件的解压字节数**。
  * 一旦归档内文件的解压总大小超过 8GB（例如归档了一个 10GB 的数据库备份或视频集合），累加值达到阈值后立即触发 `EraError::Security`。
  * 触发后调用 `fail_extraction_with_cleanup`，**会物理删除之前已成功写入磁盘的所有文件**，导致正常大归档根本无法提取出任何数据。
* **影响范围**: 任何解压后总尺寸 > 8GB 的归档。
* **规避建议**: 将解压炸弹防御改为“解压膨胀比（Compression Ratio）”检查，或在 CLI/配置中开放内存预算参数；临时方案需修改常量重新编译。

---

### 2. 单卷归档中的 Catalog（目录索引）缺乏纠删码保护 【单点故障】

* **源码位置**:
  * [`crates/era-engine/src/writer.rs:3533-3538`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/writer.rs#L3533-L3538)
  * [`crates/era-engine/src/erasure_scan.rs:91-106`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/erasure_scan.rs#L91-L106)
  * [`crates/era-engine/src/repair.rs:401-410`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/repair.rs#L401-L410)
  * [`crates/era-engine/src/reader.rs:550`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/reader.rs#L550)
* **机理分析**:
  * 在单卷归档中，文件数据块（Data Blocks）被切分为纠删码条带存储，但**Catalog 仅作为一个独立的 Canonical Block 写入**，未做 Reed-Solomon 条带化。
  * `erasure_scan.rs` 中 `erasure_data_end` 显式将扫描终点截断在 `footer.catalog_offset()` 之前。
  * 因此，`repair` 命令的 RS 重建逻辑**根本不扫描、也不覆盖 Catalog**。
  * 若 Catalog 块发生 bit-rot 损坏，Poly1305 MAC 验证或 CRC 校验失败，`repair` 无法修复它。
  * 解包必须通过 `load_catalog()` 获取文件清单与 chunk 映射，缺少 Catalog 会导致所有数据块无法关联到文件路径，**整包数据彻底不可恢复**。
* **影响范围**: 单卷归档（多卷归档每卷均有一份 Catalog 副本，抗毁性显著优于单卷）。
* **规避建议**: 生产使用时建议使用多卷归档（`--volumes N`），或在单卷末尾增加多副本/纠删码保护的 Catalog 镜像。

---

### 3. 连续 16 个块损坏触发“自毁式”清理退出 【容错策略缺陷】

* **源码位置**:
  * [`crates/era-engine/src/reader.rs:1655-1726`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/reader.rs#L1655-L1726)
* **机理分析**:
  * 解包过程中维护了计数器 `consecutive_failures`，硬编码阈值为 16：
    ```rust
    const MAX_CONSECUTIVE_FAILURES: u32 = 16;
    if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
        return Self::fail_extraction_with_cleanup(...).await;
    }
    ```
  * 如果存储介质出现连续坏道，导致连续 16 个 MacroBlock 无法读取/解密，解压循环直接终止。
  * 终止时直接调用 `cleanup_partial_files`，**把损坏区间之前已经顺利恢复出来的完好文件也全部删除清空**。
* **影响范围**: 介质大面积损坏或特定区域集中损坏时，缺乏“尽最大努力抢救（Best-effort salvage）”模式。
* **规避建议**: 提供 `--salvage` 或 `--ignore-corrupt` 标志，遇到严重损坏时跳过损坏文件，保留其余完好文件。

---

### 4. 多卷归档在写入异常崩溃后运行 `repair --force` 导致矩阵撕裂 【状态机缺陷】

* **源码位置**:
  * [`crates/era-engine/src/recovery.rs:348-428`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/recovery.rs#L348-L428)
  * [`doc_gen/ARCHITECTURAL_0DAY_AUDIT_REPORT_2026-04-19.md:160-268`](file:///home/ricardom/code/github.com/zapsaang/era-core/doc_gen/ARCHITECTURAL_0DAY_AUDIT_REPORT_2026-04-19.md#L160-L268)
* **机理分析**:
  * `RecoveryManager`（崩溃恢复管理器）只接收单个 `archive_path`，**缺乏多卷感知与跨卷协同机制**。
  * 多卷条带使用轮转偏移分布矩阵：`RotatingOffset: (shard_idx + block_sequence) % volume_count`。
  * 写入意外中断（掉电/杀进程）后，若运行 `era repair --force` 丢弃中断检查点，`RecoveryManager` 只截断了 Volume 0，而其余分卷（Volume 1, 2...）仍然保留了未提交的多余数据块。
  * 这一截断破坏了多卷之间的条带序号对齐，造成**矩阵状态撕裂（Matrix State Tearing）**，导致后续 RS 纠删码重构全面失效。
* **影响范围**: 多卷创建中途异常中断后的检查点强制丢弃场景。
* **规避建议**: 中断后应优先重新运行原始 `create` 命令触发自动断点续传，避免通过 `repair --force` 盲目截断。

---

### 5. 归档文件尾部发生截断时，拒绝进入解包流程 【严格校验门槛】

* **源码位置**:
  * [`crates/era-volume/src/reader.rs:91-98`](file:///home/ricardom/code/github.com/zapsaang/era-volume/src/reader.rs#L91-L98)
* **机理分析**:
  * 在打开归档时，`VolumeReader::open` 会比对文件物理大小与 Footer 中记录的期望大小：
    ```rust
    if f.data_end_offset() > size {
        return Err(EraError::CorruptedFooter(format!(
            "Archive appears truncated: footer claims data_end_offset={} but file size is {}",
            f.data_end_offset(), size
        )));
    }
    ```
  * 如果由于网络传输中断或磁盘空间耗尽，导致文件末尾损失了部分字节，使得物理尺寸小于 `data_end_offset`，归档将被直接标记为 `CorruptedFooter` 并报错退出。
  * 即使前面的绝大部分数据块和文件完全完好无损，也无法进入解压逻辑。
* **影响范围**: 物理文件发生尾部截断的不完整传输副本。

---

### 6. 空目录、符号链接与特殊文件静默丢失 【元数据支持缺失】

* **源码位置**:
  * [`bins/era-cli/src/commands.rs:676`](file:///home/ricardom/code/github.com/zapsaang/era-core/bins/era-cli/src/commands.rs#L676)
  * [`crates/era-engine/src/writer.rs`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/writer.rs)
  * [`crates/era-ingest/src/entry.rs:15-21`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-ingest/src/entry.rs#L15-L21)
* **机理分析**:
  * CLI 在打包扫描目录时只检查普通文件：`if entry.file_type().is_file() { ... }`。
  * 虽然 `era-ingest` 的 protobuf 定义了 `FileType::Directory` 和 `FileType::Symlink`，但 `ArchiveWriter` **从未实现空目录条目或符号链接条目的写入与序列化**。
  * **空目录**：完全不被记录，解压时不会被创建，原目录树中的空目录结构丢失。
  * **符号链接（Symlinks）**：被直接忽略跳过，无法打包和还原。
  * **特殊文件**：FIFO 管道、Unix 域套接字、块/字符设备文件等不支持，静默丢弃。
  * **硬链接**：无法维持 inode 引用关系，被视为完全独立的普通文件重复打包。
* **影响范围**: 依赖复杂目录树结构、空占位目录、或存在软链接的系统工程归档。

---

### 7. 门限密钥（Shamir Secret Sharing）模式下的重复凭证拦截

* **源码位置**:
  * [`bins/era-cli/src/commands.rs:561-575`](file:///home/ricardom/code/github.com/zapsaang/era-core/bins/era-cli/src/commands.rs#L561-L575)
* **机理分析**:
  * 在采用 $T$-of-$N$ 门限保护的归档中，必须提供至少 $T$ 个**互不相同的有效凭证**。
  * 若用户在解包或修复时误将同一份密码或密钥重复输入多次（即便总数量满足 $\ge T$），系统会检查去重或导致拉格朗日多项式无法插值还原主密钥（Master Key），导致解密完全失败。

---

## 三、 架构设计与工程质量问题汇总

| 问题类型 | 源码位置 / 现象 | 严重度 | 影响分析 |
| :--- | :--- | :---: | :--- |
| **超大上帝对象 (God Object)** | [`crates/era-engine/src/writer.rs`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/writer.rs) 单文件 3650 行 | 高 | 职责过度耦合（分块、装箱池、加密状态、条带化、检查点、Catalog），代码维护和状态机并发安全的风险高。 |
| **安全边界假设冲突** | `era-volume` 声明 16MB 反 DoS，但 engine 层迭代器使用 256MB | 中 | 底层存储抽象与上层引擎安全边界不一致，容易在极端畸形条带下造成内存分配失控。 |
| **平局降级漏洞 (Tie-Downgrade)** | [`erasure_scan.rs:38`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/erasure_scan.rs#L38) 与 [`block_iter.rs:1475-1508`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/block_iter.rs#L1475-L1508) | 高 | 前缀 Quorum 平局时返回 `None`，降级路径未严格防御畸形长度，攻击者可通过构造平局条带触发 1.5GB+ 内存峰值，在低内存容器中引发 OOM 被杀。 |
| **错误处理缺乏抢救模式** | [`reader.rs:1877`](file:///home/ricardom/code/github.com/zapsaang/era-core/crates/era-engine/src/reader.rs#L1877) `fail_extraction_with_cleanup` | 中 | 任何中断均倾向于将磁盘输出清理干净，缺乏“尽可能保留完好文件”的容灾降级选项。 |

---

## 四、 生产环境规避与运维实践建议

1. **防范 8GB 限制**: 归档前核算待解压体积；若总数据量超过 8GB，目前需在源码中调大 `MAX_EXTRACTION_MEMORY` 常量后再使用。
2. **规避单卷 Catalog 风险**: 优先使用多卷模式打包（如 `--erasure 4:2 --volumes 6`），确保 Catalog 元数据在各卷均有冗余备份。
3. **软链接与空目录防护**: 若原目录包含软链接或依赖空文件夹，建议先使用 `tar -cf backup.tar ./dir` 打成 tar 包，再交由 `era create` 进行加密与冗余归档。
4. **异常中断处理纪律**: 若在归档写入过程中发生断电或崩溃，**切勿直接执行 `era repair --force`**（会破坏多卷对齐）；应重新执行原有的 `era create` 命令，让内部机制根据 checkpoint 自动续传。
5. **归档损坏应对流程**: 若发生物理坏道或多卷丢失，优先尝试直接运行 `era extract -f`（内联 RS 实时重构）；若直接报错退出，可查看日志定位损坏具体是元数据还是数据块。
