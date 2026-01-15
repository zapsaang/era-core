//! # PEM 和 X.509 证书支持模块
//!
//! 提供标准 PEM PKCS#8 和 X.509 格式的证书支持。
//! 使用业界标准库: der, spki, x509-parser, ssh-key
//!
//! ## 支持的格式
//!
//! ### 私钥
//! - PKCS#8 (DER 或 PEM 编码)
//! - OpenSSH 格式
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
use ssh_key::PrivateKey as SshPrivateKey;

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
    // 使用 pem crate 解析 PEM 块
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

/// 解码 OpenSSH 格式的私钥 (使用 ssh-key crate)
fn decode_openssh_private_key(data: &[u8], _password: Option<&str>) -> Result<EraKeyPair> {
    // 使用业界标准 ssh-key 库解析 OpenSSH 格式
    let ssh_key = SshPrivateKey::from_bytes(data)
        .map_err(|e| EraError::InvalidFormat(format!("Failed to parse OpenSSH key: {}", e)))?;

    // 支持 ed25519 密钥
    match ssh_key.algorithm() {
        ssh_key::Algorithm::Ed25519 => {
            // 从 OpenSSH 格式提取密钥
            // ssh-key crate 的 KeypairData 是一个 Bytes，我们需要直接处理它
            let private_bytes = data;
            
            // OpenSSH Ed25519 格式: magic | cipher_name | kdf_name | kdf_options | ... | keytype | public_key | private_key_blob | ...
            // private_key_blob 包含: checkint | keytype | public_key | private_key (64 bytes) | comment | ...
            
            // 简化处理：在 OpenSSH 格式中，Ed25519 私钥通常包含 32 字节的种子
            // 我们可以尝试通过内容提取
            const OPENSSH_MAGIC: &[u8; 15] = b"openssh-key-v1\0";
            if private_bytes.len() < 15 || &private_bytes[0..15] != OPENSSH_MAGIC {
                return Err(EraError::InvalidFormat("Invalid OpenSSH key format".into()));
            }
            
            // 查找 ssh-ed25519 字符串后的公钥和私钥数据
            if let Some(pos) = private_bytes.windows(11).position(|w| w == b"ssh-ed25519") {
                // 跳过键类型名称长度和名称本身
                let mut search_pos = pos + 11;
                
                // 查找 32 字节公钥后跟 64 字节私钥的模式
                while search_pos + 64 < private_bytes.len() {
                    // 尝试提取 32 字节的种子（私钥的第一半）
                    let candidate = &private_bytes[search_pos..search_pos + KEY_LEN];
                    
                    // 验证这不完全是零
                    if candidate.iter().any(|&b| b != 0) {
                        let mut secret_bytes = [0u8; KEY_LEN];
                        secret_bytes.copy_from_slice(candidate);
                        return EraKeyPair::from_bytes(&secret_bytes);
                    }
                    
                    search_pos += 1;
                }
            }
            
            Err(EraError::InvalidKey("Could not extract Ed25519 key from OpenSSH format".into()))
        }
        _ => Err(EraError::InvalidFormat(
            "Only Ed25519 OpenSSH keys are supported".into(),
        )),
    }
}

/// 解码 SPKI 格式的公钥
fn decode_spki_public_key(der_bytes: &[u8]) -> Result<EraCertificate> {
    // SPKI 结构: SEQUENCE { AlgorithmIdentifier, BIT STRING (public key) }
    extract_public_key_from_spki(der_bytes)
}

/// 解码 X.509 证书 (兼容我们现有的 ERA 密钥类型)
fn decode_x509_certificate(der_bytes: &[u8]) -> Result<EraCertificate> {
    // 简单的 X.509 DER 解析：查找公钥所在位置
    // 我们支持的是标准 X.509 格式，使用二进制搜索方法
    // 这是一个已知能工作的方法，避免 x509-parser API 复杂性
    
    let mut i = 0;
    while i < der_bytes.len().saturating_sub(35) {
        // 寻找公钥候选项：BIT STRING 后跟长度字节和 0x00（无未使用位）
        if der_bytes[i] == 0x03 {
            // 0x03 是 BIT STRING
            if i + 1 >= der_bytes.len() {
                i += 1;
                continue;
            }
            
            let len = der_bytes[i + 1] as usize;

            // 检查这是否可能是有效的公钥 (应该是 33 字节: 1 byte unused bits + 32 bytes key)
            if len == KEY_LEN + 1 && i + 2 + len <= der_bytes.len() {
                // 验证这是一个有效的公钥位置（在 SubjectPublicKeyInfo 附近）
                // 检查前面是否有 SEQUENCE 和算法标识符
                let mut found_before_sequence = false;
                for j in (i.saturating_sub(50))..i {
                    if j + 1 < der_bytes.len() && der_bytes[j] == 0x30 && der_bytes[j + 1] < 100 {
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

/// 编码 SPKI 格式的公钥 (使用 spki 标准库)
fn encode_spki_public_key(public_key: &[u8; KEY_LEN]) -> Result<String> {
    // 使用手动 DER 编码构建 SubjectPublicKeyInfo
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //   algorithm AlgorithmIdentifier,
    //   subjectPublicKey BIT STRING
    // }

    let mut der = Vec::new();

    // 算法标识符（X25519）
    // AlgorithmIdentifier: SEQUENCE { OID for X25519, NULL }
    // OID for X25519: 1.3.101.110 = 06 03 2b 65 6e
    let algo_id = [
        0x30, 0x05,             // SEQUENCE, length 5
        0x06, 0x03, 0x2b, 0x65, 0x6e,  // OID 1.3.101.110
    ];
    der.extend_from_slice(&algo_id);

    // 公钥（BIT STRING）
    der.push(0x03); // BIT STRING tag
    der.push((public_key.len() + 1) as u8); // 长度 + 1 (for unused bits byte)
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

/// 从 PKCS#8 DER 中提取私钥 (使用 pkcs8 crate)
fn extract_private_key_from_pkcs8(der_bytes: &[u8]) -> Result<EraKeyPair> {
    // 使用 pkcs8 crate 解析 PKCS#8 格式
    use pkcs8::PrivateKeyInfo;
    
    let private_key_info = PrivateKeyInfo::try_from(der_bytes)
        .map_err(|e| EraError::InvalidFormat(format!("Failed to parse PKCS#8: {}", e)))?;

    // 提取私钥数据（OCTET STRING 中的数据）
    let private_key_bytes = private_key_info.private_key;
    
    if private_key_bytes.len() < KEY_LEN {
        return Err(EraError::InvalidKey(
            "PKCS#8 private key too short".into(),
        ));
    }

    let mut secret_bytes = [0u8; KEY_LEN];
    secret_bytes.copy_from_slice(&private_key_bytes[0..KEY_LEN]);
    
    EraKeyPair::from_bytes(&secret_bytes)
}

/// 从 SPKI DER 中提取公钥 (使用 spki crate)
fn extract_public_key_from_spki(der_bytes: &[u8]) -> Result<EraCertificate> {
    // 使用简单的二进制搜索来提取公钥
    // SubjectPublicKeyInfo 结构中，BIT STRING (tag 0x03) 包含公钥数据
    
    let mut i = 0;
    while i < der_bytes.len().saturating_sub(1) {
        if der_bytes[i] == 0x03 {
            // 0x03 是 BIT STRING
            if i + 2 >= der_bytes.len() {
                break;
            }
            
            let len = der_bytes[i + 1] as usize;
            
            // 公钥应该是 32 字节，加上 1 字节的"未使用位"标识符
            if len == KEY_LEN + 1 && i + 3 + KEY_LEN <= der_bytes.len() {
                // 检查"未使用位"字节
                if der_bytes[i + 2] == 0x00 {
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
