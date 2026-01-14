//! # PEM 和 X.509 证书支持模块
//!
//! 提供标准 PEM PKCS#8 和 X.509 格式的证书支持。
//!
//! ## 支持的格式
//!
//! ### 私钥
//! - PKCS#8 (DER 或 PEM 编码)
//!
//! ### 公钥
//! - SubjectPublicKeyInfo (SPKI) - DER 或 PEM 编码
//! - X.509 证书
//!
//! ## 使用示例
//!
//! ```rust,ignore
//! use era_crypto::pem_support::{PemFormat, load_private_key_from_pem, load_public_key_from_pem};
//!
//! // 加载私钥
//! let keypair = load_private_key_from_pem("my_key.pem", Some("password"))?;
//!
//! // 加载公钥
//! let cert = load_public_key_from_pem("my_cert.pem")?;
//! ```

use crate::certificate::{EraCertificate, EraKeyPair, KEY_LEN};
use era_common::{EraError, Result};
use std::path::Path;

/// Base64 编码
fn base64_encode(data: &[u8]) -> String {
    use base64::engine::general_purpose;
    use base64::Engine;
    general_purpose::STANDARD.encode(data)
}

/// Base64 解码
fn base64_decode(data: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose;
    use base64::Engine;
    general_purpose::STANDARD
        .decode(data)
        .map_err(|e| EraError::InvalidFormat(format!("Base64 decode error: {}", e)))
}

/// PEM 格式类型枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PemFormat {
    /// PKCS#8 格式私钥
    Pkcs8PrivateKey,
    /// SubjectPublicKeyInfo 公钥
    SubjectPublicKeyInfo,
    /// X.509 证书
    X509Certificate,
    /// OpenSSH 格式
    OpenSshPrivateKey,
    /// 自动检测格式
    Auto,
}

impl PemFormat {
    /// 根据 PEM 标签检测格式
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "PRIVATE KEY" => Some(PemFormat::Pkcs8PrivateKey),
            "PUBLIC KEY" => Some(PemFormat::SubjectPublicKeyInfo),
            "CERTIFICATE" => Some(PemFormat::X509Certificate),
            "OPENSSH PRIVATE KEY" => Some(PemFormat::OpenSshPrivateKey),
            _ => None,
        }
    }
}

/// 从 PEM 文件加载私钥
pub fn load_private_key_from_pem<P: AsRef<Path>>(
    path: P,
    password: Option<&str>,
) -> Result<EraKeyPair> {
    let content = std::fs::read_to_string(&path)
        .map_err(|e| EraError::InvalidFormat(format!("Failed to read PEM file: {}", e)))?;

    load_private_key_from_pem_string(&content, password)
}

/// 从 PEM 字符串加载私钥
pub fn load_private_key_from_pem_string(
    pem_content: &str,
    password: Option<&str>,
) -> Result<EraKeyPair> {
    let pem_blocks = extract_pem_blocks(pem_content)?;

    if pem_blocks.is_empty() {
        return Err(EraError::InvalidFormat("No PEM blocks found".into()));
    }

    // 尝试加载第一个私钥块
    for (tag, contents) in pem_blocks {
        let format = PemFormat::from_label(&tag);
        match format {
            Some(PemFormat::Pkcs8PrivateKey) => {
                return decode_pkcs8_private_key(&contents, password);
            }
            Some(PemFormat::OpenSshPrivateKey) => {
                return decode_openssh_private_key(&contents, password);
            }
            _ => continue,
        }
    }

    Err(EraError::InvalidFormat(
        "No supported private key format found in PEM file".into(),
    ))
}

/// 从 PEM 文件加载公钥
pub fn load_public_key_from_pem<P: AsRef<Path>>(path: P) -> Result<EraCertificate> {
    let content = std::fs::read_to_string(&path)
        .map_err(|e| EraError::InvalidFormat(format!("Failed to read PEM file: {}", e)))?;

    load_public_key_from_pem_string(&content)
}

/// 从 PEM 字符串加载公钥
pub fn load_public_key_from_pem_string(pem_content: &str) -> Result<EraCertificate> {
    let pem_blocks = extract_pem_blocks(pem_content)?;

    if pem_blocks.is_empty() {
        return Err(EraError::InvalidFormat("No PEM blocks found".into()));
    }

    // 尝试加载第一个公钥块
    for (tag, contents) in pem_blocks {
        let format = PemFormat::from_label(&tag);
        match format {
            Some(PemFormat::SubjectPublicKeyInfo) => {
                return decode_spki_public_key(&contents);
            }
            Some(PemFormat::X509Certificate) => {
                return decode_x509_certificate(&contents);
            }
            _ => continue,
        }
    }

    Err(EraError::InvalidFormat(
        "No supported public key format found in PEM file".into(),
    ))
}

/// 将公钥导出为 SPKI PEM 格式
pub fn export_public_key_as_pem(cert: &EraCertificate) -> Result<String> {
    encode_spki_public_key(cert.public_key())
}

/// 提取 PEM 文件中的所有 PEM 块
fn extract_pem_blocks(content: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let mut blocks = Vec::new();
    let mut lines = content.lines();

    while let Some(line) = lines.next() {
        if line.starts_with("-----BEGIN ") && line.ends_with("-----") {
            // 提取标签
            // "-----BEGIN " 是 11 个字符，结尾的 "-----" 是 5 个字符
            let label = &line[11..line.len() - 5];

            let mut data = String::new();
            while let Some(line) = lines.next() {
                if line.starts_with("-----END ") {
                    break;
                }
                data.push_str(line);
            }

            // Base64 解码
            match base64_decode(&data) {
                Ok(decoded) => blocks.push((label.to_string(), decoded)),
                Err(e) => {
                    return Err(EraError::InvalidFormat(format!(
                        "Failed to decode PEM block {}: {}",
                        label, e
                    )))
                }
            }
        }
    }

    Ok(blocks)
}

/// 解码 PKCS#8 格式的私钥
fn decode_pkcs8_private_key(der_bytes: &[u8], password: Option<&str>) -> Result<EraKeyPair> {
    let _password = password; // 暂时未使用

    // 检查是否是加密的 PKCS#8
    if der_bytes.starts_with(&[0x30]) && is_encrypted_pkcs8(der_bytes) {
        return Err(EraError::InvalidFormat(
            "Encrypted PKCS#8 not yet supported".into(),
        ));
    }

    // 解析 PKCS#8 DER
    extract_private_key_from_pkcs8(der_bytes)
}

/// 解码 OpenSSH 格式的私钥
fn decode_openssh_private_key(data: &[u8], _password: Option<&str>) -> Result<EraKeyPair> {
    const OPENSSH_MAGIC: &[u8; 15] = b"openssh-key-v1\0";

    if data.len() < 15 {
        return Err(EraError::InvalidFormat("OpenSSH key too short".into()));
    }

    // 验证魔数
    if &data[0..15] != OPENSSH_MAGIC {
        return Err(EraError::InvalidFormat(
            "Invalid OpenSSH key format (incorrect magic bytes)".into(),
        ));
    }

    // 解析 OpenSSH 格式
    let mut pos = 15;

    // 跳过 cipher 名称
    if pos + 4 > data.len() {
        return Err(EraError::InvalidFormat("Truncated OpenSSH key".into()));
    }
    let cipher_len =
        u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4 + cipher_len;

    // 跳过 KDF 名称
    if pos + 4 > data.len() {
        return Err(EraError::InvalidFormat("Truncated OpenSSH key".into()));
    }
    let kdf_len =
        u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4 + kdf_len;

    // 跳过 KDF 选项
    if pos + 4 > data.len() {
        return Err(EraError::InvalidFormat("Truncated OpenSSH key".into()));
    }
    let kdf_opts_len =
        u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4 + kdf_opts_len;

    // 跳过 numberOfKeys
    if pos + 4 > data.len() {
        return Err(EraError::InvalidFormat("Truncated OpenSSH key".into()));
    }
    let number_of_keys =
        u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4;

    if number_of_keys != 1 {
        return Err(EraError::InvalidFormat(
            "OpenSSH key must contain exactly one key".into(),
        ));
    }

    // 跳过公钥 blob
    if pos + 4 > data.len() {
        return Err(EraError::InvalidFormat("Truncated OpenSSH key".into()));
    }
    let pubkey_len =
        u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4 + pubkey_len;

    // 读取私钥 blob 长度
    if pos + 4 > data.len() {
        return Err(EraError::InvalidFormat("Truncated OpenSSH key".into()));
    }
    let privkey_len =
        u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4;

    if pos + privkey_len > data.len() {
        return Err(EraError::InvalidFormat(
            "Truncated OpenSSH private key data".into(),
        ));
    }

    // 解析私钥 blob
    let privkey_blob = &data[pos..pos + privkey_len];
    let mut blob_pos = 0;

    // 读取密钥类型
    if blob_pos + 4 > privkey_blob.len() {
        return Err(EraError::InvalidFormat("Truncated key type".into()));
    }
    let keytype_len = u32::from_be_bytes([
        privkey_blob[blob_pos],
        privkey_blob[blob_pos + 1],
        privkey_blob[blob_pos + 2],
        privkey_blob[blob_pos + 3],
    ]) as usize;
    blob_pos += 4;

    if blob_pos + keytype_len > privkey_blob.len() {
        return Err(EraError::InvalidFormat("Truncated key type string".into()));
    }
    let keytype = &privkey_blob[blob_pos..blob_pos + keytype_len];
    blob_pos += keytype_len;

    // 解析私钥数据
    match keytype {
        b"ssh-ed25519" => {
            // 跳过公钥长度和公钥（复制）
            if blob_pos + 4 > privkey_blob.len() {
                return Err(EraError::InvalidFormat(
                    "Truncated ed25519 public key len".into(),
                ));
            }
            let pub_len = u32::from_be_bytes([
                privkey_blob[blob_pos],
                privkey_blob[blob_pos + 1],
                privkey_blob[blob_pos + 2],
                privkey_blob[blob_pos + 3],
            ]) as usize;
            blob_pos += 4 + pub_len;

            // 读取私钥长度和数据
            if blob_pos + 4 > privkey_blob.len() {
                return Err(EraError::InvalidFormat(
                    "Truncated ed25519 private key len".into(),
                ));
            }
            let priv_len = u32::from_be_bytes([
                privkey_blob[blob_pos],
                privkey_blob[blob_pos + 1],
                privkey_blob[blob_pos + 2],
                privkey_blob[blob_pos + 3],
            ]) as usize;
            blob_pos += 4;

            // ed25519 私钥是 64 字节（32 字节种子 + 32 字节公钥）
            if priv_len != 64 {
                return Err(EraError::InvalidKey(format!(
                    "Invalid ed25519 private key length: {}",
                    priv_len
                )));
            }

            if blob_pos + KEY_LEN > privkey_blob.len() {
                return Err(EraError::InvalidFormat("Truncated ed25519 key seed".into()));
            }

            // 提取 32 字节的密钥种子
            let mut secret_bytes = [0u8; KEY_LEN];
            secret_bytes.copy_from_slice(&privkey_blob[blob_pos..blob_pos + KEY_LEN]);

            EraKeyPair::from_bytes(&secret_bytes)
        }
        _ => Err(EraError::InvalidFormat(format!(
            "Unsupported OpenSSH key type: {:?}",
            keytype
        ))),
    }
}

/// 解码 SPKI 格式的公钥
fn decode_spki_public_key(der_bytes: &[u8]) -> Result<EraCertificate> {
    // SPKI 结构: SEQUENCE { AlgorithmIdentifier, BIT STRING (public key) }
    extract_public_key_from_spki(der_bytes)
}

/// 解码 X.509 证书
fn decode_x509_certificate(der_bytes: &[u8]) -> Result<EraCertificate> {
    // 简单的 X.509 DER 解析：查找公钥所在位置
    // X.509 结构：SEQUENCE { TBSCertificate { ... SubjectPublicKeyInfo { ... BIT STRING } ... } ... }
    // 查找 BIT STRING 标签 (0x03) 后跟长度和公钥数据

    let mut i = 0;
    while i < der_bytes.len().saturating_sub(35) {
        // 寻找公钥候选项：BIT STRING 后跟长度字节和 0x00（无未使用位）
        if der_bytes[i] == 0x03 {
            // 0x03 是 BIT STRING
            let len = der_bytes[i + 1] as usize;

            // 检查这是否可能是有效的公钥 (应该是 33 字节: 1 byte length indicator + 32 bytes key)
            if len == KEY_LEN + 1 && i + 2 + len <= der_bytes.len() {
                // 验证这是一个有效的公钥位置（在 SubjectPublicKeyInfo 附近）
                // 检查前面是否有 SEQUENCE 和算法标识符
                let mut found_before_sequence = false;
                for j in (i.saturating_sub(50))..i {
                    if der_bytes[j] == 0x30 && j + 1 < der_bytes.len() && der_bytes[j + 1] < 100 {
                        found_before_sequence = true;
                        break;
                    }
                }

                if found_before_sequence && der_bytes[i + 2] == 0x00 {
                    // 这很可能是公钥
                    let mut public_key = [0u8; KEY_LEN];
                    public_key.copy_from_slice(&der_bytes[i + 3..i + 3 + KEY_LEN]);

                    // 验证这不完全是零（无效密钥）
                    if public_key.iter().any(|&b| b != 0) {
                        return Ok(EraCertificate::from_public_key(&public_key));
                    }
                }
            }
        }
        i += 1;
    }

    Err(EraError::InvalidKey(
        "Could not extract public key from X.509 certificate - no valid key found".into(),
    ))
}

/// 编码 SPKI 格式的公钥
fn encode_spki_public_key(public_key: &[u8; KEY_LEN]) -> Result<String> {
    // 构建 SubjectPublicKeyInfo DER 结构
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //   algorithm AlgorithmIdentifier,
    //   subjectPublicKey BIT STRING
    // }

    let mut der = Vec::new();

    // 算法标识符（X25519）
    // OID for X25519: 1.3.101.110
    der.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e]);

    // 公钥（BIT STRING）
    der.push(0x03); // BIT STRING tag
    der.push((public_key.len() + 1) as u8); // 长度 + 1 (for unused bits)
    der.push(0x00); // 未使用的位数
    der.extend_from_slice(public_key);

    // 包装在 SEQUENCE 中
    let mut result = Vec::new();
    result.push(0x30); // SEQUENCE tag

    // 添加长度（使用 DER 长格式）
    let len = der.len();
    if len <= 127 {
        result.push(len as u8);
    } else {
        // 长格式：0x80 | 字节数，然后是 BE 整数
        let len_bytes = len.to_be_bytes();
        let mut non_zero_start = 0;
        for (i, &b) in len_bytes.iter().enumerate() {
            if b != 0 {
                non_zero_start = i;
                break;
            }
        }
        let len_bytes_trimmed = &len_bytes[non_zero_start..];
        result.push(0x80 | (len_bytes_trimmed.len() as u8));
        result.extend_from_slice(len_bytes_trimmed);
    }

    result.extend_from_slice(&der);

    // 编码为 PEM
    let b64 = base64_encode(&result);
    let mut pem_str = String::new();
    pem_str.push_str("-----BEGIN PUBLIC KEY-----\n");

    // 每 64 个字符换一行
    for chunk in b64.as_bytes().chunks(64) {
        pem_str.push_str(&String::from_utf8_lossy(chunk));
        pem_str.push('\n');
    }

    pem_str.push_str("-----END PUBLIC KEY-----\n");

    Ok(pem_str)
}

/// 检查是否是加密的 PKCS#8
fn is_encrypted_pkcs8(der_bytes: &[u8]) -> bool {
    // EncryptedPrivateKeyInfo 以 SEQUENCE 开始，包含 encryptionAlgorithm
    // 简单的检查：如果第二个元素是 SEQUENCE（算法），则可能是加密的
    der_bytes.len() > 6 && der_bytes[0] == 0x30 && der_bytes[2] == 0x30
}

/// 从 PKCS#8 DER 中提取私钥
fn extract_private_key_from_pkcs8(der_bytes: &[u8]) -> Result<EraKeyPair> {
    // 查找 OCTET STRING 标签 (0x04)
    let mut i = 0;
    while i < der_bytes.len().saturating_sub(1) {
        if der_bytes[i] == 0x04 {
            // 0x04 是 OCTET STRING
            let len = der_bytes[i + 1] as usize;
            if i + 2 + len <= der_bytes.len() && len == KEY_LEN {
                let mut secret_bytes = [0u8; KEY_LEN];
                secret_bytes.copy_from_slice(&der_bytes[i + 2..i + 2 + len]);
                return EraKeyPair::from_bytes(&secret_bytes);
            }
        }
        i += 1;
    }

    Err(EraError::InvalidKey(
        "Could not extract private key from PKCS#8".into(),
    ))
}

/// 从 SPKI DER 中提取公钥
fn extract_public_key_from_spki(der_bytes: &[u8]) -> Result<EraCertificate> {
    // 查找 BIT STRING 标签 (0x03)
    let mut i = 0;
    while i < der_bytes.len().saturating_sub(1) {
        if der_bytes[i] == 0x03 {
            // 0x03 是 BIT STRING
            let len = der_bytes[i + 1] as usize;
            if i + 2 + len <= der_bytes.len() && len == KEY_LEN + 1 {
                // +1 是因为 BIT STRING 有一个"未使用位"字段
                let mut public_key = [0u8; KEY_LEN];
                public_key.copy_from_slice(&der_bytes[i + 3..i + 3 + KEY_LEN]);
                return Ok(EraCertificate::from_public_key(&public_key));
            }
        }
        i += 1;
    }

    Err(EraError::InvalidKey(
        "Could not extract public key from SPKI".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pem_format_detection() {
        assert_eq!(
            PemFormat::from_label("PRIVATE KEY"),
            Some(PemFormat::Pkcs8PrivateKey)
        );
        assert_eq!(
            PemFormat::from_label("PUBLIC KEY"),
            Some(PemFormat::SubjectPublicKeyInfo)
        );
        assert_eq!(
            PemFormat::from_label("CERTIFICATE"),
            Some(PemFormat::X509Certificate)
        );
        assert_eq!(PemFormat::from_label("INVALID"), None);
    }

    #[test]
    fn test_export_and_load_public_key_pem() {
        let keypair = EraKeyPair::generate().unwrap();
        let cert = keypair.certificate();

        // 导出为 PEM
        let pem_str = export_public_key_as_pem(&cert).unwrap();
        assert!(pem_str.contains("BEGIN PUBLIC KEY"));
        assert!(pem_str.contains("END PUBLIC KEY"));

        // 从 PEM 加载
        let loaded_cert = load_public_key_from_pem_string(&pem_str).unwrap();
        assert_eq!(loaded_cert.public_key(), cert.public_key());
    }
}
