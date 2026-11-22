# Round 0 基线证据（lead 自测）

日期: 2026-11-22
仓库: /home/ricardom/code/github.com/zapsaang/era-core
分支/提交: feat_fly @ b22a07e（工作区干净）
工具链: nix store cargo 1.99.0 / rustc 1.99.1 / clippy 0.1.99 / rustfmt 1.10.0
（会话内 rustup stable shim 损坏：~/.rustup/toolchains/stable/.../rustc "cannot execute: required file not found"）

## 1. 全量门禁实测（ulimit -n 1024，对齐 GitHub Actions 默认）

命令（显式 PATH 指向 nix store 工具链）:
- cargo fmt --all -- --check
- cargo clippy --all-targets --all-features -- -D warnings
- bash -c 'ulimit -n 1024; cargo test --release -p era-cli'
- bash -c 'ulimit -n 1024; cargo test --release --workspace'

结果（/tmp/era_ci_baseline2.log）:
- fmt_rc=0
- clippy_rc=0
- cli_rc=0
- ws_rc=0
- 180 个测试目标 all ok；累计 passed=3416；无 FAILED/panic/error 行。

结论: 门禁与全量测试在标准 FD 限制下全绿；AUDIT-HIGH-01（FD 耗尽）确已闭环。

## 2. lead 独立代码观察（待团队复核后定级）

### OBS-1 候选 High：append 的 staged_append 在内存中缓冲整段追加数据，最大可达 max_volume_size
- crates/era-volume/src/writer.rs:661-679（write_canonical_block）、:721-723（write_raw）、:319（clear_backup_footer_gap 分支）
- StagedAppend { base_offset, buf: Vec<u8>, original_footer }（writer.rs:28-33），flush 仅在 finalize_with_catalog（:832）、set_max_size（:275）发生。
- DEFAULT_MAX_VOLUME_SIZE = 4 GiB（multi_volume.rs:15），engine 固定 with_max_size(max_volume_size)（writer.rs:1104）。
- 影响: 向已有归档 append 大量数据时，最多约 4 GiB（或用户配置的 max_volume_size）驻留内存；相比基线流式写盘是资源回归，可能 OOM；当前无上限、无文档说明、无测试覆盖内存占用。
- 复现/证据: 代码路径必达；需专门测试才能量化。建议: 捕获上限或落盘 spool；至少文档化并在 staged.buf 超过阈值时报错/降级。

### OBS-2 候选 High/Medium：finalize 的 flush_staged_append 仍有"截断后写 footer 前"崩溃窗口
- finalize_with_catalog（writer.rs:832 起）: flush_staged_append -> truncate(base_offset) -> append(staged.buf) -> pad -> 写 backup header -> 写 footer。
- 若在 truncate 之后、footer 落盘之前进程崩溃: 旧 catalog/index/manifest（位于 base_offset 之后）已被截断，旧 fixed backup footer（offset 4096）仍指向截断前的 data_end > 文件大小；reader 打开失败。窗口长度≈整段 staged 数据拷贝时间（可达 GB 级），并非瞬时。
- 影响: "中断 append 后原归档仍可打开"的 P0 承诺仅在 finalize 之前成立；finalize 中断仍可能使原归档不可打开（数据块物理保留但元数据丢失，非 EC 单卷无法重建 catalog）。
- 现有测试 resid_high03_checkpoint_append.rs:493/644 只覆盖"drop 在 finalize 前"，未覆盖 finalize 过程中崩溃。
- 建议: finalize 原子化（临时卷 + 原子 rename，需扩展 StorageBackend），或 truncate 后立即写回一份合法中间 footer 的协议，并加负例测试。

### OBS-3 候选 Low：verify() 新增"每卷完整 Catalog 读取"未做性能评估
- reader.rs:2768-2796 对每个非主 Catalog 卷 read_catalog_copy/read_and_verify_catalog_bytes（§4.9 遗留，仍属 benchmark-needed）。

### OBS-4 工程项抽查（§5）
- docs/*.md 已被跟踪（git ls-files docs 4 个文件）；.gitignore 放行 docs/*-2026-11-*.md。
- Cargo.lock 已跟踪；rust-toolchain.toml channel = "stable" 与 CI dtolnay/rust-toolchain@stable 一致（本地 rustup 损坏属环境问题）。
- fuzz.yml 已加 fuzz/ 缺失时跳过逻辑；fuzz/ 仍不存在（仓库自述一致）。
- #[ignore] 实测仅 1 处（crates/era-storage/tests/pwrite_test.rs）。
