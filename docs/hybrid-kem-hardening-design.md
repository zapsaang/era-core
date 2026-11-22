# Hybrid KEM 接入遗留三项缺口 — 改动设计

**日期：** 2026-09-23（R4 修订：四轮自审后）
**状态：** 设计评审（已历 4 轮自审修订）
**范围：** 私钥口令保护、AAD 域常量版本治理、Hybrid key_id 快速匹配
**约束：** 事实均已按 `file:line` 核查；所有改动 TDD 先行；不留技术债。

---

## 0. 事实核查记录（Evidence）

| # | 断言 | 证据 | 结论 |
|---|------|------|------|
| F1 | keygen 写出的私钥（legacy 与 hybrid）均为明文 PEM | `bins/era-cli/src/commands.rs:1617-1627` 调用 `export_private_key_as_pem` / `export_hybrid_private_key_as_pem`；后者在 `crates/era-crypto/src/pem_support.rs:196-211` 直接写入 `secret_key_bytes()`；仅依赖 0600 文件权限（commands.rs:1630-1646） | 确认 |
| F2 | legacy PEM 加载的 `password` 参数在**全部**解码路径上都是死参数 | `pem_support.rs:311-323` `decode_pkcs8_private_key`：`let _password = password; // Currently unused`，加密 PKCS#8 显式报错 `"Encrypted PKCS#8 not yet supported"`；`pem_support.rs:326-339` `decode_openssh_private_key`：参数名为 `_password`，且**无条件拒绝所有算法**（Ed25519 与"其他"两个分支均返回 Err）——OpenSSH 路径是只拒绝的死端 | 确认 |
| F3 | hybrid PEM 加载完全没有 password 形参 | `pem_support.rs:241` `load_hybrid_private_key_from_pem_string` 无 password 参数；`load_any_private_key_from_pem_string`（:274-285）先试 hybrid（忽略 password）再 fallback legacy | 确认 |
| F4 | CLI 已预留口令传递通道 | `bins/era-cli/src/commands.rs:131-142` `load_private_keys(key_paths, password: Option<&str>)`，两个调用点（:169 `build_auth_providers`、:1331 repack）均传 `passwords.first().map(\|s\| s.as_str())`——第一个 `--password` 已被当作密钥口令传入，接线存在，下端是断的 | 确认 |
| F5 | 存在第三个无人使用的密钥文件格式 `ERAK` | `certificate.rs:349-457` `save_encrypted/load_encrypted`（Argon2 + AEAD，MAGIC=`ERAK`，格式含 KEY_ID(16)+CREATED_AT(8)）；全仓库生产调用者为零（仅 doc comment 与自身单测 :722-740 引用）。注意：当前代码已用 `KdfParams::standard()`（certificate.rs:352），V9 审计（`doc_gen/SECURITY_AUDIT_V9_REPORT.md:395`）点名的 `fast()` 问题**已被修复**，删除理由是"零调用者的第三格式"，不是 KDF 强度。**删除范围陷阱：** `KEY_FILE_VERSION`（certificate.rs:59）同时被 `EraCertificate::save/load`（:557、:588）用作 ERAC 证书文件版本——它不在删除范围内 | 确认，死代码 |
| F6 | 全部 5 个 AAD 域常量实际值均为 v8.1；**文档与代码不一致** | `CERT_ENCAPS_AAD=b"ERA_CERT_ENCAPS_v8.1"`（certificate.rs:62，私有）；`KEY_FILE_AAD=b"ERA_KEY_FILE_v8.1"`（certificate.rs:65，私有）；`MK_WRAP_AAD_DOMAIN=b"ERA_MK_WRAP_v8.1"`（auth.rs:14，`pub`）；`HYBRID_ENCAPS_AAD=b"ERA_HYBRID_CERT_ENCAPS_v8.1"`（hybrid_certificate.rs:12，私有）；`VK_WRAP_AAD_DOMAIN=b"ERA_VK_WRAP_v8.1"`（key_session.rs:195，私有）。而 `crates/era-crypto/src/AGENTS.md`「DOMAIN SEPARATION CONSTANTS」一节写成 `VK_WRAP_AAD = b"ERA_VK_WRAP_v8.2"`——**文档错误**（值错、常量名也错：实际叫 `VK_WRAP_AAD_DOMAIN`），代码里不存在任何 v8.2 常量 | 确认（修正了本设计 v0 版「VK_WRAP_AAD 已是 v8.2」的错误断言） |
| F7 | Hybrid slot 创建时 `key_id=None`（共两处），Provider 无快速匹配 | writer.rs:792-801（threshold 循环）与 writer.rs:803-811（AnyOfN）均 `RecipientSlot::new(RecipientType::HybridKem, None, ...)`；`auth.rs:149-163` `HybridCertificateProvider::try_unlock` 无 key_id 检查。对照 legacy：writer.rs:743-752 写入 `Some(cert.key_id()[..8])`，auth.rs:111-116 用 `ct_eq` 快速过滤 | 确认 |
| F8 | `HybridCertificate`/`HybridKeyPair` 无 key_id 概念 | `hybrid_certificate.rs:16-41`：`HybridCertificate` 仅持有 `HybridPublicKey`；`HybridKeyPair`（:44-47）无 key_id 方法。写入侧手上只有 `&HybridCertificate`（writer.rs:756-760），故 key_id 必须从公钥派生 | 确认 |
| F9 | 项目为 pre-alpha，允许破坏性变更 | README：「Pre-alpha — API unstable, breaking changes expected」 | 确认 |
| F10 | README 明文记录了本缺口 | README「Advanced Usage」：`Note: passphrase-protected private keys are not yet supported. Use unencrypted PEM keys.`——项目一落地时必须同步删除/改写该句及 keygen 段落、「Certificates and External Trust」一节 | 确认 |
| F11 | legacy key_id 为 16 字节，slot 只存前 8 字节 | `certificate.rs:47` `KEY_ID_LEN=16`；`compute_key_id`（:226-231）取 `blake3(pub)[..16]`；slot 侧 `cert.key_id()[..8]`（writer.rs:743）；比较侧 `my_kid[..8]`（auth.rs:113） | 确认 |
| F12 | 现有 hybrid 回归锚点 | `certificate_auth_tests.rs:416-438` `test_hybrid_provider_wrong_key_returns_none` 构造 `key_id=None` 的 slot（:430）——项目三落地后必须保持绿（验证 None 回退路径） | 确认 |
| F13 | 对 `load_encrypted`/`save_encrypted` 的文档引用共三处 | writer.rs:217、reader.rs:464 均为 ` ```ignore ` 示例；另有 certificate.rs:26-29 模块级 doc comment 演示 `save_encrypted/load_encrypted`——删除 ERAK 不会破坏 doctest，但**三处**注释都必须同步更新 | 确认 |
| F14 | era-cli 已有无回显口令 prompt 先例，不需要新依赖 | `prompt_for_passwords`（commands.rs:74-77）使用 `dialoguer::Password`（无回显 + `with_confirmation` 两次确认）；`IsTerminal` 检测已有用法（commands.rs:86、:111）；`zeroize` 已是 era-cli 依赖（Cargo.toml:28，`Zeroizing` 已在 commands.rs:1526 等处使用） | 确认 |
| F15 | pkcs8/pkcs5 依赖现状与 feature 事实 | era-crypto/Cargo.toml:30 现 pin `pkcs8 = "0.10"`（无 features）；pkcs5 **不是**现有依赖。docs.rs 核查（pkcs8 v0.10.2 / pkcs5 v0.7.1 Cargo.toml）：pkcs8 无 `scrypt` feature，`encryption = ["alloc", "pkcs5/alloc", "pkcs5/pbes2", "rand_core"]`；pkcs5 0.7 **无独立 `scrypt` feature**，`pbes2 = ["dep:aes","dep:cbc","dep:pbkdf2","dep:scrypt","dep:sha2"]` 且 `pbes2` 下 `pub use scrypt;` 重导出；pkcs8 `getrandom = ["rand_core/getrandom"]`，仅 `PrivateKeyInfo::encrypt()`（内置默认参数）需要。版本景观：pkcs8 latest 0.11.0（2026-07，依赖 pkcs5 0.8）、pkcs5 latest 0.8.1、scrypt latest 0.12.0 | 确认 |

---

## 项目一：私钥口令保护（Passphrase-Protected Private Keys）

### 现状问题

私钥落盘路径全部无保护或不可用：

1. legacy PEM（PKCS#8 明文，`export_private_key_as_pem`）
2. hybrid PEM（自定义明文块，`export_hybrid_private_key_as_pem`）
3. `ERAK` 自定义加密格式（`save_encrypted/load_encrypted`）——有加密但**零生产调用者**（F5）

同时 CLI 的 `load_private_keys` 已经把口令传进了加载层（F4），README 也把缺口写成了已知限制（F10）——这是"设计过但没做完"。

### 设计决策

**D1.1 删除 `ERAK` 格式，不保留第三种私有格式。**
理由：零调用者 + 与 PEM 路径功能重复的并行格式 + pre-alpha 无兼容负担。保留它等于保留一份没人维护的加密代码——这正是技术债。删除范围：`save_encrypted/load_encrypted`（certificate.rs:349-457）、`KEY_FILE_MAGIC`、`KEY_FILE_AAD` 常量、对应单测（certificate.rs:722-740 一带）。**`KEY_FILE_VERSION` 不在删除范围**——它被 `EraCertificate::save/load`（certificate.rs:557、:588）用作 ERAC 证书文件版本号，删除会误伤无关功能（F5；保留原名不改名，改名是无收益 churn）。同步更新 writer.rs:217、reader.rs:464 的 ```ignore 文档示例与 certificate.rs:26-29 模块文档（F13，共三处）。`KEY_FILE_AAD` 同时在项目二的冻结清单与冻结测试中移除（见项目二 D2.3 的顺序约定）。

**D1.2 legacy X25519 私钥：标准 Encrypted PKCS#8（RFC 8018 PBES2）。**
实现：workspace 现 pin `pkcs8 = "0.10"`（era-crypto/Cargo.toml:30，无 features，F15）。R3 核查 docs.rs feature 表后的正确依赖写法（v0/R2 两版写法均无法编译）：

```toml
pkcs8 = { version = "0.10", features = ["encryption"] }
pkcs5 = { version = "0.7", features = ["pbes2"] }  # 与 pkcs8 0.10 的 pkcs5 ^0.7 依赖对齐
```

要点（全部经 docs.rs/源码核实，F15）：

- pkcs8 **没有** `scrypt` feature；`encryption` 实际拉 `alloc + pkcs5/alloc + pkcs5/pbes2 + rand_core`；
- pkcs5 0.7 **没有独立 `scrypt` feature**——scrypt 由 `pbes2` 拉入，且 pkcs5 在 `pbes2` 下 `pub use scrypt;` 重导出，**不需要单独依赖 scrypt crate**；
- 不需要 `getrandom` feature：它只服务 `PrivateKeyInfo::encrypt()`（内置 rng + 默认参数），本设计走 `encrypt_with_params`，salt/IV 用现有 `rand::rngs::OsRng` 自产；
- 加密 API：`PrivateKeyInfo::encrypt_with_params(&self, pbes2_params: pkcs5::pbes2::Parameters, password)`；参数构造 `pkcs5::pbes2::Parameters::scrypt_aes256cbc(params: scrypt::Params, salt: &[u8], aes_iv: &[u8; 16]) -> pkcs5::Result<Self>`（经 `pkcs5::scrypt` 重导出取 `Params`）；
- scrypt 参数固定 `Params::new(15, 8, 1, 32)`——注意 `Params::new` 是 **4 参签名** `(log_n: u8, r: u32, p: u32, len: usize)`，`len` 不可漏；取值对齐 pkcs8 `encrypt()` 内置默认与 openssl `-scrypt` 惯例；
- 解密侧 `EncryptedPrivateKeyInfo::decrypt(password)` 在 `encryption` feature 下按 DER 内嵌参数自动走 scrypt；
- **分流必须发生在 PEM 标签层**（R4 承重修正）：`PemFormat::from_label`（pem_support.rs:57-65）当前**不识别** `ENCRYPTED PRIVATE KEY` 标签——加密块在 `load_private_key_from_pem_string` 的 `_ => continue`（:100）处被跳过，永远到不了 `decode_pkcs8_private_key`。因此需新增 `PemFormat::EncryptedPkcs8PrivateKey` 变体 + `"ENCRYPTED PRIVATE KEY"` 标签映射，路由到新的 `decode_encrypted_pkcs8_private_key(contents, password)`；`decode_pkcs8_private_key` 保持明文专用，`is_encrypted_pkcs8` 字节启发式（pem_support.rs:418-428）及其拒绝分支（:315-319）随标签路由确立后**删除**——标签自描述后启发式即成死代码，留着就是技术债。

**KDF 固定 scrypt**（memory-hard），不用纯 PBKDF2；参数显式构造，不接受 crate 默认值。
版本注记：pkcs8 0.11.0 / pkcs5 0.8.1 / scrypt 0.12.0 已发布（2026-07 起）；升级属独立决策，不在本次范围（记入风险表）。
理由：

- openssl 生态互操作（openssl ≥1.0.2 支持 PBES2+scrypt+AES-256-CBC，`-scrypt`/`-scrypt_N/-r/-p` 旗标；FIPS provider build 可能禁用 scrypt，属边缘部署面），用户可用标准工具检查密钥；
- 不发明新格式；
- `pkcs8` 已是现有依赖，只是没开 feature；
- 代价是信任面新增 scrypt/aes/cbc 等传递依赖——纯 Rust RustCrypto 生态，与现有 argon2 同源，可接受（记入风险表）。

新增 API：`export_private_key_as_encrypted_pem(keypair, password)`、`decode_encrypted_pkcs8_private_key(contents, password)`（经 `PemFormat::EncryptedPkcs8PrivateKey` 标签路由）：无口令 → `Err("passphrase required")`；口令错误 → `Err(Decryption)`（`EraError::Decryption`，error.rs:35）。

**D1.3 hybrid 私钥：版本化 `ERA ENCRYPTED HYBRID PRIVATE KEY` PEM 块。**
Hybrid 是自定义密钥材料（2432B = X25519 SK 32B + Kyber-768 SK 2400B，hybrid_kem.rs:140-151），无标准容器可用，必须自定义。容器布局（二进制 payload 置于 PEM armor 内）：

```
magic(4)   = "ERHK"
version(1) = 1
kdf_memory_cost(u32 LE) ‖ kdf_time_cost(u32 LE) ‖ kdf_parallelism(u32 LE)
salt(16)
nonce(24)
ciphertext = XChaCha20-Poly1305(key=Argon2id(passphrase, salt, params),
                                nonce,
                                aad = HYBRID_KEY_FILE_AAD ‖ 全部 header 字节(magic..nonce),
                                plaintext = hybrid_secret_key_bytes)
```

- `HYBRID_KEY_FILE_AAD = b"ERA_HYBRID_KEY_FILE_v1"`（新常量，遵守项目二的治理规则：一经发布即冻结，并纳入冻结测试清单）；
- KDF 参数入容器（与 `PasswordSlotParams`（auth.rs:28-34）同一哲学：参数随密文走，支持日后调参）；默认取 `KdfParams::standard()`；
- **AAD 绑定全部 header 字节**（magic..nonce），防参数/盐/nonce 篡改被静默吸收（纵深防御；即使篡改导致派生密钥变化最终也会认证失败，显式绑定是原则问题）；
- 解密侧先校验 magic、version==1、payload 最小长度再派生密钥（有界解析，与全仓 TryFrom 有界分配的反模式清单一致）；
- 内存卫生：派生密钥、明文私钥缓冲全程 `Zeroizing` 包裹（`HybridKeyPair::secret_key_bytes()` 本已返回 `Zeroizing<Vec<u8>>`，hybrid_certificate.rs:127-129，保持同等水平）；
- 配对的 `ERA HYBRID PUBLIC KEY` 块保持明文随附（公钥非秘密，且现有 `load_hybrid_private_key_from_pem_string` 契约要求双块，pem_support.rs:252-256）。

新增 API：`export_hybrid_private_key_as_encrypted_pem(keypair, password)`、`load_hybrid_private_key_from_pem_string_encrypted(content, password)`（命名避免改动现有明文函数的签名，明文函数保持原样继续服务旧密钥）。

**D1.4 加载侧统一自动检测，失败模式显式化，禁止跨格式静默 fallback。**

前提（R4）：分流依赖标签识别——`PemFormat` 新增 `EncryptedPkcs8PrivateKey`（标签 `ENCRYPTED PRIVATE KEY`）；ERHK 块沿用 hybrid loader 的直接标签比较惯例（pem_support.rs:246-249），在 `load_any_*` 中按标签 `ERA ENCRYPTED HYBRID PRIVATE KEY` 识别。不加这两处识别，加密块在分流前就被丢弃（见 D1.2 末条）。

- `load_private_key_from_pem_string`：Encrypted PKCS#8 + `password=None` → `Err("passphrase required")`；口令错误 → `Err(Decryption)`；正确 → 解出（F2 死参数变真功能）。
- `load_any_private_key_from_pem_string` 检测顺序：`ERHK 加密块 → 明文 hybrid 双块 → legacy PKCS#8（明文/加密）`。
  - 加密块 + `None` → `Err("passphrase required")`；
  - 加密块 + 错误口令 → `Err(Decryption)`，**不得** fallback 到其他格式分支重试（防错误信息混淆与意外明文解析）；
  - 明文块行为不变（旧密钥兼容）。
- 加密 hybrid 密钥的加载入口：`load_any_*`（自动检测）或 `load_hybrid_private_key_from_pem_string_encrypted`（显式）；`load_hybrid_private_key_from_pem(_string)` 明文双块契约保持不变。CLI 全部走 `load_any_*`（commands.rs:137），自动受益。

**D1.5 CLI 表面。**

- `keygen`：默认交互式询问口令（TTY，两次确认，**不回显**）；`--no-passphrase` 显式选择明文（打印安全警告）；非 TTY 且未给口令且未给 `--no-passphrase` → 报错退出并提示两种解法。脚本路径：环境变量 `ERA_KEY_PASSPHRASE`。**不提供 `--passphrase` 明文旗标**（防 shell history 与进程表泄漏）。
  - 不回显输入：**复用现有 `dialoguer::Password` 先例**（`prompt_for_passwords`，commands.rs:74-77，无回显 + `with_confirmation`，F14），为 keygen 新增同款 helper；返回值立即包 `Zeroizing<String>`（zeroize 已是 era-cli 依赖）。**不引入 `rpassword`**——为已有能力新增依赖本身就是技术债（R3 修正，取代 R2 的 rpassword 方案）。TTY 检测沿用 `std::io::IsTerminal`（commands.rs:86、:111 已有用法）；非 TTY 路径不交互，直接走环境变量/旗标判定。
- 读路径（`extract/list/info/verify/repair/repack` 的 `--key`）：新增 `--key-passphrase`。优先级：`--key-passphrase` > 环境变量 `ERA_KEY_PASSPHRASE` > 第一个 `--password`（F4 的现有行为，保持兼容）> TTY 交互询问 > 报错。单一密钥口令应用于所有 `--key` 文件（与现状一致；多密钥各用不同口令**不支持**，写进 CLI help 与 README 已知限制）。
- 兼容性说明：keygen 默认行为从"静默写明文"改为"要求口令或显式 `--no-passphrase`"——属行为变更，pre-alpha 可接受；README quickstart 的 `era keygen` 示例与 F10 注记同步更新；`bins/era-cli/tests/` 中调用 keygen 命令的用例同步加旗标。

### TDD 计划

**Redline（先写，必须先红）：**

1. `crates/era-crypto/tests/adversarial_audit_v9.rs::encrypted_hybrid_private_key_roundtrip`——加密导出→带正确口令加载→keypair 可用（decapsulate 成功）。
2. `crates/era-crypto/tests/adversarial_audit_v9.rs::encrypted_hybrid_private_key_wrong_passphrase_fails`——错误口令 → `Err(Decryption)`，不得返回垃圾密钥，不得 fallback。
3. `crates/era-crypto/tests/adversarial_audit_v9.rs::encrypted_pkcs8_roundtrip_and_wrong_passphrase`——legacy 加密 PKCS#8 同理；主断言为 DER 结构可被解析为 `EncryptedPrivateKeyInfo`（openssl 互操作作为可选附加断言，CI 无 openssl 时跳过）。
4. `crates/era-crypto/tests/adversarial_audit_v9.rs::encrypted_key_without_passphrase_errors`——两种加密块 + `None` → 明确的 "passphrase required" 错误，而非误导性格式错误。
5. `crates/era-crypto/tests/adversarial_audit_v9.rs::encrypted_hybrid_pem_contains_no_secret_material`——对加密导出物做字节级扫描，断言 secret key bytes 不出现在 PEM 中。
6. `bins/era-cli/tests/cli_integration_tests_comprehensive.rs::test_keygen_passphrase_create_extract_e2e`——`keygen`（带口令）→ `create --hybrid-certificate` → `extract --key ... --key-passphrase ...` 全程走通；另加 wrong-passphrase 拒绝用例。（测试中 keygen 口令经 `ERA_KEY_PASSPHRASE` 环境变量注入——按 D1.5 设计不存在 `--passphrase` 旗标；`assert_cmd` 非 TTY，交互路径不可达。）

**Green 目标：** 加密导出/加载 roundtrip；错误口令干净失败；无明文泄漏；旧明文 PEM（两种格式）继续可读。

**兼容性：** 旧明文 PEM 继续可读。`ERAK` 删除属破坏性，但零调用者（F5），无实际影响。keygen 默认行为变更见 D1.5。

**验证门禁：**

```bash
cargo test -p era-crypto
cargo test --release -p era-cli   # 与 CI 对齐（ci.yml 对 era-cli 用 --release）
cargo clippy --all-targets --all-features -- -D warnings
```

### 改动文件

- `crates/era-crypto/src/certificate.rs`（删 `save_encrypted/load_encrypted`、`KEY_FILE_MAGIC`、`KEY_FILE_AAD` 及单测；保留 `KEY_FILE_VERSION`（F5）；模块文档 :26-29 同步改写）
- `crates/era-crypto/src/pem_support.rs`（加密导出/加载 + 自动检测 + 禁 fallback）
- `crates/era-crypto/src/lib.rs`（导出面更新）
- `crates/era-crypto/Cargo.toml`（pkcs8 开 `encryption` feature；新增 `pkcs5` + `pbes2` feature，F15）
- `crates/era-engine/src/writer.rs:217`、`reader.rs:464`（```ignore 文档示例改用新 API，F13）
- `bins/era-cli/src/main.rs`、`commands.rs`（keygen 旗标 + `--key-passphrase`；口令 prompt 复用 dialoguer，**无新增依赖**）
- `bins/era-cli/tests/cli_integration_tests_comprehensive.rs`（`keygen_tests` 既有用例同步加 `--no-passphrase`/环境变量；新增 redline #6）
- `README.md`（F10 注记、keygen 示例、「Certificates and External Trust」、多密钥单口令限制）
- 测试：上述 6 个 redline + 既有 PEM roundtrip 测试（generate_valid_keys.rs 等）保持绿

---

## 项目二：AAD 域常量版本治理

### 现状问题

两个真实问题（F6）：

1. 全部 5 个 AAD 常量实际值都是 v8.1，但 `crates/era-crypto/src/AGENTS.md:37` 把 VK 常量文档化成 `VK_WRAP_AAD = b"ERA_VK_WRAP_v8.2"`——**文档与代码不符**（且常量名都写错：实际叫 `VK_WRAP_AAD_DOMAIN`）。
2. 缺少治理规则：字节值是 AEAD 认证输入，改任何一字节都会使既有归档对应 slot 全部认证失败——纯破坏、零安全收益。如果没有明文规则，"跟上格式版本号"的诱惑会一直存在。

### 设计决策

**D2.1 冻结全部字节值，语义重定义为「构造版本」而非「格式版本」。**

AAD 域分隔符的目的是防止跨上下文拼接，价值在于**唯一且稳定**。`v8.1` 字样只是历史命名，不代表缺陷。正确做法：

- 字节值一律不动；
- 在每个常量处加注释：`// FROZEN: domain separator for the <name> construction. Never change; a changed construction gets a new label.`；
- 修正 `crates/era-crypto/src/AGENTS.md`「DOMAIN SEPARATION CONSTANTS」一节：现列 3 条（`IK_DOMAIN`、`BLOCK_KEY_DOMAIN` 两条 HKDF 域 + 1 条**写错的** VK 条目）。改后结构分两组——HKDF 域（`IK_DOMAIN`、`BLOCK_KEY_DOMAIN`）+ AAD 域（5 个全列出，VK 条目改正为实际的 `VK_WRAP_AAD_DOMAIN = b"ERA_VK_WRAP_v8.1"`），并加冻结规则；
- 顺路修正 `crates/era-crypto/AGENTS.md`「WHEN CHANGING」中过时断言 "current archive unlock still routes through X25519-based certificate handling"（hybrid 已上线）。

**D2.2 新增域分隔符命名守则（写入 `crates/era-crypto/src/AGENTS.md`）。**

- 域标签按「构造」版本化：同一构造永不变更标签；构造变更（算法、拼接顺序、输入语义变化）必须换**新**标签；
- 标签不携带、也不承诺携带 volume 格式版本号；
- 新常量名与字节值评审时按此规则检查；项目一新增的 `ERA_HYBRID_KEY_FILE_v1` 即按此规则命名（v1 指该构造的第一版）。

**D2.3 与项目一的顺序约定。**
执行顺序为三→二→一（见末节）。项目二落地时冻结清单含全部 5 个常量；项目一删除 ERAK 时同步删除 `KEY_FILE_AAD` 的冻结断言与常量，并新增 `HYBRID_KEY_FILE_AAD` 的冻结断言。两步都必须保持冻结测试绿。

**明确不做的备选方案及其否决理由：**

- *全部 bump 到 v8.2*：破坏所有既有归档的 password/cert/hybrid slot 解锁（AEAD 认证失败），零安全收益。否决。
- *双 AAD 读取兼容（先试新标签再试旧标签）*：为纯装饰性变更引入双路径解密代码，是新增技术债。否决。

### TDD 计划

**Redline / 锁定测试：**

常量可见性决定测试位置——`CERT_ENCAPS_AAD`、`KEY_FILE_AAD`、`HYBRID_ENCAPS_AAD`、`VK_WRAP_AAD_DOMAIN` 均为私有 `const`，集成测试文件无法引用，**必须写在各自源文件内的 `#[cfg(test)]` 单测模块**；`MK_WRAP_AAD_DOMAIN` 是 `pub`（auth.rs:14），可同时被 era-engine 集成测试引用。

1. `crates/era-crypto/src/certificate.rs`（tests mod）`frozen_aad_cert_encaps_and_key_file`——逐字节断言两个常量当前值。
2. `crates/era-crypto/src/hybrid_certificate.rs`（tests mod）`frozen_aad_hybrid_encaps`。
3. `crates/era-crypto/src/key_session.rs`（tests mod）`frozen_aad_vk_wrap`。
4. `crates/era-engine/src/auth.rs`（新增 tests mod）`frozen_aad_mk_wrap`。
5. `crates/era-crypto/src/pem_support.rs`（或随项目一）`frozen_aad_hybrid_key_file`——项目一落地时加入。

这组测试此刻即应全绿（锁定现状，防未来被"顺手统一"）；治理项目的可执行交付物就是锁 + 文档修正。

**验证门禁：** `cargo test -p era-crypto && cargo test -p era-engine --test second_audit`（second_audit 覆盖 key wrapping 行为，确认零行为漂移）。

### 改动文件

- `crates/era-crypto/src/certificate.rs`、`hybrid_certificate.rs`、`key_session.rs`、`crates/era-engine/src/auth.rs`（注释 + 文件内冻结单测）
- `crates/era-crypto/src/AGENTS.md`（改正 VK 条目 + 补全常量表 + 冻结规则）
- `crates/era-crypto/AGENTS.md`（修正过时解锁路径断言）
- 根 `AGENTS.md`「ANTI-PATTERNS」增一条 "NEVER mutate shipped AAD domain separators — new constructions get new labels"。注意：根 AGENTS.md 头部标注为工具生成（"Generated: 2026-09-23"），若未来再生成会被覆盖——该条目需同步写入生成源（init 配置/模板），或接受人工维护该段。

---

## 项目三：Hybrid key_id 快速匹配

### 现状问题

Legacy cert slot 携带 `key_id`（writer.rs:743-752，`cert.key_id()[..8]`），`CertificateProvider` 用常时间比较快速过滤不匹配的 slot（auth.rs:111-116）；hybrid slot `key_id=None`（两处，F7），`HybridCertificateProvider` 对**每个** hybrid slot 都执行完整 X25519+Kyber decapsulation。门限 N-of-N 或 `--key` 提供多把钥匙时，复杂度为 O(keys × slots) 次完整 PQ 解密，wrong-key 试错成本远高于 legacy。

### 设计决策

**D3.1 key_id 派生算法与 legacy 同源：`BLAKE3(public_key_bytes)[..8]`。**

- legacy：`blake3(x25519_pub)` 取前 16 字节存入 keypair，slot 存前 8（F11）；
- hybrid：`crate::hash(&public_key.to_bytes())` 取前 8 直接作为 slot key_id——hybrid 无 16 字节中间形态的历史包袱，直接产 `[u8; 8]`；
- `HybridCertificate::key_id() -> [u8; 8]` 与 `HybridKeyPair::key_id() -> [u8; 8]` 均从公钥现场派生（**不**存状态，避免序列化面扩张）；`HybridKeyPair::key_id()` 委托 `self.certificate().key_id()`；
- 关键约束（F8）：写入侧手上只有 `&HybridCertificate`（writer.rs:756-760），key_id 必须是纯公钥函数——本设计满足。

**D3.2 写入侧：两处 `RecipientSlot::new(RecipientType::HybridKem, ...)` 全部填 `Some(cert.key_id())`。**
位置：writer.rs:792-801（threshold 循环）、writer.rs:803-811（AnyOfN）。`repack.rs` 走 writer builder（repack.rs:259、301-303 调 `builder.hybrid_certificate(...)` / `add_hybrid_certificate(...)`），自动继承，无需改动。

**D3.3 读取侧：`HybridCertificateProvider::try_unlock` 增加与 legacy 对称的快速路径。**

```rust
// mirror CertificateProvider (auth.rs:111-116)
if let Some(slot_kid) = slot.key_id() {           // Option<&[u8; 8]>
    let kid = self.keypair.key_id();              // [u8; 8]
    if !bool::from(slot_kid.as_ref().ct_eq(&kid[..])) {
        return Ok(None);
    }
}
// slot.key_id() == None（旧归档）→ 继续完整 decapsulation
```

- `key_id=None` 的旧 hybrid 归档**必须**仍可解锁（读侧向后兼容；现有测试 F12 即覆盖此路径，须保持绿）；
- 比较用 `subtle::ConstantTimeEq`（与 legacy 一致；key_id 非秘密，此处非严格必要，但保持一致模式避免评审分歧）；
- key_id 只有 64 bit，仅作过滤提示，不做认证依据——认证仍完全由 AEAD 标签完成。代码注释须写明这一点。

### TDD 计划

**Redline（先写，必须先红）：**

1. `crates/era-crypto/src/hybrid_certificate.rs`（tests mod）`hybrid_key_id_is_deterministic_and_public_derived`——同一 keypair 两次 `key_id()` 相等；`HybridCertificate::key_id() == HybridKeyPair::key_id()`；不同 keypair 不相等。
2. `crates/era-engine/tests/certificate_auth_tests.rs::test_hybrid_slot_carries_key_id`——建归档后读 header，断言 hybrid slot `key_id == Some(kp.key_id())`（AnyOfN 与 threshold 各一）。
3. `crates/era-engine/tests/certificate_auth_tests.rs::test_hybrid_provider_fast_rejects_mismatched_key_id`——构造 `RecipientSlot::new(HybridKem, Some(other_kid), garbage_params, garbage_emk)`，provider 必须返回 `Ok(None)`；garbage params 证明未触碰 decapsulation（若走到 decapsulate 会报 `InvalidKey` 而非 `None`）。
4. `crates/era-engine/tests/certificate_auth_tests.rs::test_legacy_hybrid_archive_without_key_id_still_unlocks`——手工构造 `key_id=None` 的 hybrid slot（用真实 `encapsulate_for` 产物），provider 回退完整 decapsulation 并成功解锁。（F12 的显式化加强版。）

**Green 目标：** 新归档 slot 带 key_id；匹配走快速路径；不匹配 O(1) 拒绝；旧归档兼容；F12 等既有测试全绿。

**验证门禁：** `cargo test -p era-engine --test certificate_auth_tests && cargo test -p era-crypto && cargo test -p era-cli`（repack/CLI 走 writer builder，需 CLI 集成测试确认无回归）

### 改动文件

- `crates/era-crypto/src/hybrid_certificate.rs`（`key_id()` ×2 + 单测）
- `crates/era-engine/src/writer.rs`（slot 构建 ×2：:792-801、:803-811）
- `crates/era-engine/src/auth.rs`（provider 快速路径）
- 上述 4 个测试

---

## 执行顺序与依赖

```
项目三 (key_id)      ── 独立，最小，先行
项目二 (AAD 治理)    ── 独立，注释+文档修正+锁定测试，次之
项目一 (口令保护)    ── 独立，最大，最后；其 D1.3 新常量遵守项目二守则，
                        并同步删除 KEY_FILE_AAD 的冻结断言（D2.3）
```

三项互相无代码依赖，可并行；若串行，建议 三 → 二 → 一（风险递增、blast radius 递增）。

**每项一个原子 commit：**

1. `engine/crypto: add key_id fast-match for hybrid recipients`
2. `crypto/docs: freeze AAD domain separators and document governance`
3. `crypto/cli: passphrase-protected private keys (encrypted PKCS#8 + ERA hybrid container); remove dead ERAK format`

## 风险与缓解

| 风险 | 缓解 |
|------|------|
| 项目一删除 `ERAK` 影响未知外部用户 | pre-alpha 无 API 承诺；全仓 grep 证明零调用（F5）；CHANGELOG/release note 注明 |
| 项目一 pkcs8 `encryption` + pkcs5 `pbes2` 引入新传递依赖（aes/cbc/pbkdf2/scrypt/sha2） | lockfile diff 评审；均为纯 Rust RustCrypto 生态，与现有 argon2 同一信任面；KDF 固定 scrypt 且参数显式，不吃 crate 默认值漂移 |
| 项目一 pkcs8 pin 0.10 落后于 latest（0.11.0） | 现状继承而非新增债务；升级 0.11/0.8 是独立决策（API 有变动，如 `getrandom` feature 语义改变），不混入本次范围；实施时在 Cargo.lock 记录确切版本 |
| 项目一 keygen 默认强制口令破坏脚本化用法 | `ERA_KEY_PASSPHRASE` 环境变量 + `--no-passphrase` 显式逃生门；不提供 `--passphrase` 明文旗标；README 与 CLI 测试同步更新（keygen 用例位于 `cli_integration_tests_comprehensive.rs:5959` `mod keygen_tests`，R3 已确认存在） |
| 项目三 key_id 64-bit 碰撞导致过滤误判 | 碰撞仅导致多一次 decapsulation（正确性由 AEAD 兜底）；代码注释声明 key_id 非认证依据 |
| 项目二冻结测试被未来改动"顺手更新" | 测试名与注释写明 "FROZEN — changing this value breaks all existing archives"；AGENTS.md 守则 + 根 AGENTS.md anti-pattern 条目双保险 |

## 全局 Out of Scope（明确不做）

- 不改任何既有归档的可读性（三项全部保持读侧向后兼容，唯一例外是被证明零调用的 `ERAK` 删除）。
- 不引入 FIDO2 slot 的 key_id（`RecipientType::Fido2Hmac` 尚无实现，不在本次范围）。
- 不做口令强度策略/zxcvbn 检查（属 CLI UX 增强，与本次三个缺口无关）。
- 不 bump volume 格式版本（无格式变更）。
- 不动 OpenSSH 解码路径（F2：该路径本就无条件拒绝所有算法；扩成可用属另一项功能，不在本次范围）。
- 不支持多密钥各自不同口令（D1.5 已声明为已知限制）。

---

## 修订记录

- **v0（2026-09-23）**：初版。
- **R1（2026-09-23，自审第一轮）**：
  - 事实修正：F6 原断言「VK_WRAP_AAD 已是 v8.2」错误——实际代码 `VK_WRAP_AAD_DOMAIN = b"ERA_VK_WRAP_v8.1"`（key_session.rs:195），v8.2 只存在于 AGENTS.md 的过时文档里；全部 5 个常量均为 v8.1。项目二目标随之从"冻结+守则"扩为"修正文档错误+冻结+守则"。
  - 事实修正：F5 删除 ERAK 的理由修正——当前代码已用 `KdfParams::standard()`（certificate.rs:352），V9 审计点名的 `fast()` 已修复；删除理由是零调用者的第三格式。
  - 事实补全：F2 补 OpenSSH 死路径（pem_support.rs:326-339 无条件拒绝所有算法）；新增 F10（README 明文承认缺口）、F11（legacy key_id 16B/slot 8B 结构）、F12（现有 None-key_id 回归锚点测试）、F13（```ignore 文档块）。
  - 设计修正：D3.2 "三处"→"两处"（writer.rs:792-801、803-811 是唯一两处 hybrid slot 构建点；repack 走 builder 自动继承，已验证 repack.rs:259/301-303）。
  - 设计修正：D3.3 伪代码修正——`slot.key_id()` 返回 `Option<&[u8;8]>`，比较写法对齐 legacy 的 `slot_kid.as_ref().ct_eq(&kid[..])`。
  - 设计修正：项目二冻结测试从"集成测试"改为"各源文件内 `#[cfg(test)]` 单测"——5 个常量中 4 个是私有 const，集成测试无法引用（TDD 可行性缺陷）。
  - 设计新增：D2.3 明确项目一/二在 `KEY_FILE_AAD` 冻结断言上的交接顺序。
  - 设计强化：D1.3 AAD 绑定全部 header 字节（防参数篡改）；D1.4 明确禁止跨格式静默 fallback；D1.5 明确 `--key-passphrase` 优先级链与 `ERA_KEY_PASSPHRASE` 环境变量、多密钥单口令限制。
  - 范围补全：README.md 列入项目一改动文件（F10）。
- **R2（2026-09-23，自审第二轮）**：
  - 事实修正（承重）：pkcs8 crate **没有 `scrypt` feature**——docs.rs feature 表确认 `encryption` 仅拉 `pkcs5/pbes2`+`rand_core`；KDF 选择权在 pkcs5。D1.2 依赖写法改为 `pkcs8 = { features = ["encryption", "getrandom"] }` + 显式 `pkcs5 = { version = "0.7", features = ["scrypt"] }`（版本与 pkcs8 0.10 对齐，实施时核实）。原写法 `features = ["encryption", "scrypt"]` 会直接编译失败。
  - 设计补漏：keygen 口令交互**不可回显**——现有 `prompt_for_input`（commands.rs:85）基于 `read_line` 会回显，口令场景不可用；D1.5 补充 `rpassword` 依赖 + `Zeroizing<String>` 包裹 + `IsTerminal` 检测；`bins/era-cli/Cargo.toml` 列入改动文件；风险表加对应行。
  - 表述澄清：D2.1 对 AGENTS.md「DOMAIN SEPARATION CONSTANTS」一节的改动从"补全其余 4 个"改为明确的分组结构（2 条 HKDF 域 + 5 条 AAD 域，修正 VK 错条目）。
  - 风险补注：根 AGENTS.md 是工具生成文件，新增的 anti-pattern 条目有再生成被覆盖的风险，已注明需同步生成源。
  - 事实坐实：keygen 的 CLI 测试确认存在于 `bins/era-cli/tests/cli_integration_tests_comprehensive.rs`（D1.5 的测试更新范围从推断变为实证）。
  - 复查通过项（无需改）：D3.3 伪代码与 legacy 模式一致（auth.rs:113 切片比较）；`subtle` 已是 era-engine 依赖（auth.rs:8）；`KdfParams::standard()` 存在（certificate.rs:352）；`RecipientSlot::new` 为 pub（header.rs:148）且 F12 已有 `None` key_id 构造先例（certificate_auth_tests.rs:430）；redline「必须先红」属性逐条复核通过（项目一 6 条全部因 API 缺失/不支持而红；项目三 #1 编译失败即红、#2 slot 现写 None 断言失败、#3 无快速路径时走 decapsulate 报 InvalidKey 而非 Ok(None)、#4 为现状锁定测试按设计即绿）。
- **R3（2026-09-23，自审第三轮，全量 `file:line` 复核 + 外部 crate 事实核查）：**
  - 事实修正（承重，R2 修正不彻底）：pkcs5 0.7 **没有独立 `scrypt` feature**——docs.rs pkcs5 v0.7.1 Cargo.toml 确认 `pbes2 = ["dep:aes","dep:cbc","dep:pbkdf2","dep:scrypt","dep:sha2"]`，scrypt 仅经 `pbes2` 拉入且被 `pub use scrypt;` 重导出。D1.2 依赖写法由 `pkcs5 features=["scrypt"]` 改为 `features=["pbes2"]`（原写法会直接编译失败）；同时删掉多余的 `getrandom` feature（仅 `PrivateKeyInfo::encrypt()` 需要，本设计走 `encrypt_with_params` + OsRng 自产 salt/IV）。F15 新增，记录完整 feature 事实与版本景观。
  - 事实补全（承重）：`scrypt::Params::new` 是 4 参签名 `(log_n: u8, r: u32, p: u32, len: usize)`；`scrypt_aes256cbc` 签名 `(scrypt::Params, &[u8], &[u8;16]) -> pkcs5::Result<Self>`；加密入口 `PrivateKeyInfo::encrypt_with_params`。D1.2 补具体签名与固定参数 `(15, 8, 1, 32)`。
  - 设计修正（误伤防护）：D1.1 删除清单移除 `KEY_FILE_VERSION`——它同时是 ERAC 证书文件版本号（certificate.rs:557、:588 共用），删除会破坏证书文件 I/O。F5 增补该陷阱说明。
  - 事实补全：F13 由两处改为三处——certificate.rs:26-29 模块级 doc comment 同样演示 `save_encrypted/load_encrypted`；D1.1 与改动文件同步。
  - 设计修正（去技术债）：D1.5 撤销 R2 引入的 `rpassword` 新依赖——era-cli 已有 `dialoguer::Password` 无回显 + 两次确认先例（commands.rs:74-77，新增 F14），为零收益新增依赖。改动文件移除 `bins/era-cli/Cargo.toml`，风险表对应行替换。
  - 设计补强：D1.3 私钥尺寸精确化（2432B = 32+2400，hybrid_kem.rs:140-151）；新增解密侧有界解析（magic/version/最小长度先验）与 Zeroizing 内存卫生两条实现要求。
  - 设计补强：D1.5 明确 keygen **不提供 `--passphrase` 明文旗标**（shell history/进程表泄漏面），脚本化仅走 `ERA_KEY_PASSPHRASE`。
  - 事实坐实：openssl 互操作主张核实通过（≥1.0.2 支持 PBES2+scrypt+AES-256-CBC；FIPS build 边缘禁用已注记）；keygen 既有测试位于 `cli_integration_tests_comprehensive.rs:5959 mod keygen_tests`（行号坐实，列入改动文件）。
  - 版本注记：pkcs8 0.11.0 / pkcs5 0.8.1 已发布，升级属独立决策，风险表新增一行说明，不混入本次范围。
- **R4（2026-09-23，自审第四轮，修订后全文一致性 + 控制流可达性复审）：**
  - 事实修正（承重，控制流可达性缺陷）：R3 版 D1.2「替换 `decode_pkcs8_private_key` 的拒绝分支」**不可达**——`PemFormat::from_label`（pem_support.rs:57-65）不识别 `ENCRYPTED PRIVATE KEY` 标签，加密块在 `load_private_key_from_pem_string` 的 `_ => continue`（:100）处即被跳过。改为标签层分流：新增 `PemFormat::EncryptedPkcs8PrivateKey` 变体 + `decode_encrypted_pkcs8_private_key`；`is_encrypted_pkcs8` 启发式（:418-428）及拒绝分支（:315-319）随路由确立后删除（标签自描述，启发式成死代码）。D1.4 补「前提」段说明两处标签识别是分流的前提条件。
  - 事实修正：F12 行号 :418-436 → :416-438（函数实际跨度）；F4 精确化——`load_private_keys` 跨度 :131-142、签名 `Option<&str>`、两个调用点 :169/:1331 均传 `passwords.first()`。
  - 设计澄清：加密 hybrid 密钥加载入口明确为 `load_any_*` 自动检测或显式 `_encrypted` 函数，明文 loader 契约不变；CLI 经 commands.rs:137 统一走 `load_any_*`。
  - TDD 补强：redline #6 注明 keygen 口令在测试中经 `ERA_KEY_PASSPHRASE` 环境变量注入（`assert_cmd` 非 TTY，交互路径不可达，且无 `--passphrase` 旗标）。
  - 复查通过项（无需改）：项目三 redline #3 红性复核——garbage params 在无快速路径时于 `hybrid_kem::decapsulate` 长度检查处报错（hybrid_kem.rs:261-264），provider 仅将 `Err(Decryption)` 映射为 `None`（auth.rs:160），其余错误上抛，断言 `Ok(None)` 有效地区分新旧行为；D1.4 检测顺序对「同文件混放 ERHK 块 + 明文 `ERA HYBRID PUBLIC KEY` 块」无误匹配（明文 loader 要求 `ERA HYBRID PRIVATE KEY` 块存在，pem_support.rs:246、:252-256）；ERAK 删除后保留的 `KEY_FILE_VERSION` 路径（certificate.rs:557、:588）不受影响；D3.3 中 `slot_kid.as_ref().ct_eq(&kid[..])`（`&[u8;8]` → `&[u8]`）与 legacy 写法同构，可编译性由 auth.rs:113 既有代码佐证。
