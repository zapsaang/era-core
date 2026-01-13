# ERA v8.1 Core

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**E**ncrypted **R**edundant **A**rchive - 下一代抗量子分布式归档存储核心库

## ⚠️ 版本说明

> **当前版本：v0.6.1 (P1 阶段)**
>
> ✅ **已支持特性：**
> - FastCDC 内容分块（支持任意大小文件）
> - 智能多文件打包（100KB 可打入 1 个 Block）
> - 块级去重（相同内容只存储一次）
> - 单遍提取（性能优化 2x）
> - 大文件 OOM 修复 - 多块文件使用流式提取
> - Gear 表 64 位精度 - 提升分块质量
> - RwLock 安全处理 - 防止锁中毒 panic
> - 完整性能基准套件 - 全管道性能测试
> - **[新] 归档完整性验证** - `era verify` 命令
> - **[新] 块大小验证** - 防止恶意归档无限循环攻击
> - **[新] 文件大小限制** - 防止磁盘填充攻击（单文件上限 100GB）
>
> ⚠️ **当前限制：**
> - 无增量备份 - 每次都是全量备份
> - 仅支持本地存储 - 暂不支持云存储后端
> - 无纠删码 - 暂无数据冗余保护
>
> 这些限制将在后续 P1/P2 迭代中解决。

## 特性

- 🔐 **XChaCha20-Poly1305** AEAD 加密
- 🔑 **Argon2id** 密钥派生 (64MB/3轮)
- 📦 **Zstd** 高效压缩
- ✅ **Blake3** 内容哈希
- 🛡️ **密码验证** 早期错误检测
- 🔀 **FastCDC** 内容定义分块（大文件支持）
- 📊 **135 个测试** 全面覆盖
- 🔍 **完整性验证** `era verify` 命令
- ⚡ **性能基准套件** 全管道性能测试

## 快速开始

### 安装

```bash
cargo install --path bins/era-cli
```

### 创建归档

```bash
# 创建加密归档
era create myfile.txt --output backup.era --password "your-password"

# 从目录创建
era create ./my-folder --output backup.era --password "your-password"
```

### 列出文件

```bash
era list backup.era --password "your-password"
```

### 解压归档

```bash
era extract backup.era --output ./restored --password "your-password"
```

### 查看归档信息

```bash
era info backup.era --password "your-password"
```

### 验证归档完整性

```bash
# 验证归档数据完整性
era verify backup.era --password "your-password"

# 显示详细错误信息
era verify backup.era --password "your-password" --verbose
```

## 架构

ERA v8.1 采用六层架构设计：

```
L5 Ingest     → era-ingest (文件摄取)
L4 Chunking   → era-ingest/chunker (FastCDC 分块) ✅
L3 Packing    → era-packing (MacroBlock 打包) ✅
L2 Matrix     → [P1 实现 - 纠删码]
L1 Volume     → era-volume (卷管理) ✅
L0 Physical   → era-storage (存储后端) ✅
```

### Crate 结构

| Crate | 描述 |
|-------|------|
| `era-common` | 公共类型和错误定义 |
| `era-crypto` | 加密原语 (AEAD, KDF, Hash) |
| `era-codec` | 压缩编解码 |
| `era-storage` | 存储后端抽象 |
| `era-volume` | 卷格式和读写 |
| `era-packing` | MacroBlock 打包解包 |
| `era-ingest` | 文件摄取和目录遍历 |
| `era-engine` | 高级归档 API |
| `era-cli` | 命令行工具 |

## 安全性

### 加密方案

- **密钥派生**: Argon2id (memory=64MB, time=3, parallelism=4)
- **对称加密**: XChaCha20-Poly1305 (AEAD)
- **哈希算法**: Blake3
- **Nonce 派生**: 每个归档使用唯一 salt 作为 nonce context

### 密码验证

ERA 在尝试解密前验证密码正确性，避免：
- 浪费计算资源解密错误数据
- 产生误导性的解密错误信息

## 开发

### 构建

```bash
cargo build --release
```

### 测试

```bash
# 运行所有测试
cargo test

# 运行特定 crate 测试
cargo test -p era-crypto
```

### Benchmark

```bash
cargo bench
```

### 性能基准

运行完整性能测试套件：

```bash
# 运行所有基准测试
cargo bench

# 运行特定组件基准
cargo bench -p era-ingest    # FastCDC 分块性能
cargo bench -p era-packing   # 打包/解包性能
cargo bench -p era-crypto    # 加密/哈希性能
cargo bench -p era-codec     # 压缩性能
cargo bench -p era-engine    # 端到端管道性能
```

#### 参考性能数据 (Apple M2)

| 操作 | 吞吐量 |
|------|--------|
| FastCDC 分块 | ~800 MB/s |
| Zstd 压缩 (Balanced) | ~400 MB/s |
| ChaCha20-Poly1305 加密 | ~2 GB/s |
| Blake3 哈希 | ~3 GB/s |
| 完整管道 (1MB 文件) | ~200 MB/s |

## 路线图

- [x] **MVP v0.4.0** - 核心功能完成
  - [x] 加密/解密
  - [x] 压缩
  - [x] 密码验证
  - [x] O(1) Catalog 定位
  - [x] 单遍提取优化
- [x] **P0 v0.5.0** - 大文件支持 ✅
  - [x] FastCDC 变长分块
  - [x] 多文件打包
  - [x] 块级去重
- [x] **P0 v0.5.1** - 质量修复 ✅
  - [x] 大文件提取 OOM 修复
  - [x] Gear 表 64 位精度
  - [x] RwLock panic 安全处理
  - [x] 完整性能基准套件
- [ ] **P1** - 性能优化
  - [ ] 异步 I/O
  - [ ] 全局去重
  - [ ] 泛型存储后端
  - [ ] bincode 2.0 安全反序列化
- [ ] **P2** - 企业特性
  - [ ] 云存储支持
  - [ ] 增量备份
  - [ ] 纠删码

## 文档

- [技术方案设计](docs/ERAv8.1%20Core技术方案设计.md)
- [实施工程白皮书](docs/ERAv8.1实施工程白皮书.md)
- [MVP 复盘报告](docs/MVP_REVIEW.md)
- [架构文档](docs/ARCHITECTURE.md)

## 许可证

MIT License - 详见 [LICENSE](LICENSE)

## 贡献

欢迎提交 Issue 和 Pull Request！
