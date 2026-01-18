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
use ssh_key::PrivateKey as SshPrivateKey;
use std::path::Path;

/// Base64 编码
fn base64_encode(data: &[u8]) -> String {
    use base64::engine::general_purpose;
    use base64::Engine;
    general_purpose::STANDARD.encode(data)
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

/// 将私钥导出为 PKCS#8 PEM 格式 (未加密)
///
/// 注意：此函数不加密私钥！仅用于测试或导出到安全位置。
pub fn export_private_key_as_pem(keypair: &EraKeyPair) -> Result<String> {
    // Manually construct PKCS#8 components for X25519
    let secret = keypair.secret_key.to_bytes();

    // 1. Inner CurvePrivateKey ::= OCTET STRING (32 bytes)
    // Structure: 04 20 [32 bytes]
    let mut key_field = Vec::with_capacity(34);
    key_field.push(0x04);
    key_field.push(0x20); // 32 bytes length
    key_field.extend_from_slice(&secret);

    // 2. AlgorithmIdentifier for X25519
    // OID: 1.3.101.110 -> 2B 65 6E
    // Sequence: 30 05 06 03 2B 65 6E
    let algo_id = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e];

    // 3. Version: 0 -> 02 01 00
    let version = [0x02, 0x01, 0x00];

    // 4. PrivateKey wrapper field (OCTET STRING containing key_field)
    // Structure: 04 [len] [key_field]
    let mut key_wrapper = Vec::with_capacity(36);
    key_wrapper.push(0x04);
    key_wrapper.push(key_field.len() as u8);
    key_wrapper.extend_from_slice(&key_field);

    // 5. Outer Sequence (PrivateKeyInfo)
    // Structure: 30 [len] [Version] [Algo] [KeyWrapper]
    let mut seq_content = Vec::new();
    seq_content.extend_from_slice(&version);
    seq_content.extend_from_slice(&algo_id);
    seq_content.extend_from_slice(&key_wrapper);

    let mut der = Vec::new();
    der.push(0x30); // SEQUENCE
    der.push(seq_content.len() as u8);
    der.extend_from_slice(&seq_content);

    // Encode as PEM
    let b64 = base64_encode(&der);
    let mut pem = String::new();
    pem.push_str("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(chunk));
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");

    Ok(pem)
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
    // 使用 pem crate 解析所有 PEM 块
    use pem::parse_many;

    let pem_blocks = parse_many(content)
        .map_err(|e| EraError::InvalidFormat(format!("Failed to parse PEM: {}", e)))?;

    let blocks: Vec<(String, Vec<u8>)> = pem_blocks
        .into_iter()
        .map(|block| (block.tag().to_string(), block.contents().to_vec()))
        .collect();

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

            Err(EraError::InvalidKey(
                "Could not extract Ed25519 key from OpenSSH format".into(),
            ))
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

/// 解码 X.509 证书 (使用 x509-cert crate)
fn decode_x509_certificate(der_bytes: &[u8]) -> Result<EraCertificate> {
    use der::Decode;
    use x509_cert::Certificate;

    // 使用 x509-cert crate 解析证书
    let cert = Certificate::from_der(der_bytes).map_err(|e| {
        EraError::InvalidFormat(format!("Failed to parse X.509 certificate: {}", e))
    })?;

    // 从证书中提取 SubjectPublicKeyInfo
    let spki = &cert.tbs_certificate.subject_public_key_info;

    // 提取公钥数据
    let public_key_bytes = spki.subject_public_key.raw_bytes();

    if public_key_bytes.len() != KEY_LEN {
        return Err(EraError::InvalidKey(format!(
            "Invalid public key length in X.509 certificate: expected {}, got {}",
            KEY_LEN,
            public_key_bytes.len()
        )));
    }

    let mut public_key = [0u8; KEY_LEN];
    public_key.copy_from_slice(public_key_bytes);

    // 验证这不完全是零（无效密钥）
    if public_key.iter().all(|&b| b == 0) {
        return Err(EraError::InvalidKey("Public key is all zeros".into()));
    }

    Ok(EraCertificate::from_public_key(&public_key))
}

/// 编码 SPKI 格式的公钥 (使用 spki 标准库)
fn encode_spki_public_key(public_key: &[u8; KEY_LEN]) -> Result<String> {
    use der::Encode;
    use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};

    // X25519 OID: 1.3.101.110
    const X25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");

    // 创建算法标识符
    let algorithm = AlgorithmIdentifierOwned {
        oid: X25519_OID,
        parameters: None, // X25519 不需要参数
    };

    // 创建 SubjectPublicKeyInfo
    let spki = SubjectPublicKeyInfoOwned {
        algorithm,
        subject_public_key: der::asn1::BitString::new(0, public_key.to_vec())
            .map_err(|e| EraError::Serialization(format!("Failed to create BitString: {}", e)))?,
    };

    // 编码为 DER
    let der_bytes = spki
        .to_der()
        .map_err(|e| EraError::Serialization(format!("Failed to encode SPKI to DER: {}", e)))?;

    // 编码为 PEM
    let b64 = base64_encode(&der_bytes);
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
    // EncryptedPrivateKeyInfo 是一个 SEQUENCE，其第一个元素是 AlgorithmIdentifier (也是 SEQUENCE)
    // 普通 PKCS#8 PrivateKeyInfo 的第一个元素是 INTEGER (version)
    // 使用 der crate 简单解析来区分
    if der_bytes.len() < 4 {
        return false;
    }

    // 检查结构：SEQUENCE { SEQUENCE ... } 表示加密的
    // SEQUENCE { INTEGER ... } 表示未加密的
    der_bytes[0] == 0x30 && der_bytes.len() > 2 && der_bytes[2] == 0x30
}

/// 从 PKCS#8 DER 中提取私钥 (使用 pkcs8 crate)
fn extract_private_key_from_pkcs8(der_bytes: &[u8]) -> Result<EraKeyPair> {
    // 使用 pkcs8 crate 解析 PKCS#8 格式
    use pkcs8::PrivateKeyInfo;

    let private_key_info = PrivateKeyInfo::try_from(der_bytes)
        .map_err(|e| EraError::InvalidFormat(format!("Failed to parse PKCS#8: {}", e)))?;

    // 提取私钥数据（OCTET STRING 中的数据）
    let mut private_key_bytes = private_key_info.private_key;

    // Fix for X25519 wrapping (CurvePrivateKey ::= OCTET STRING)
    // standard PKCS#8 for X25519 wraps the key in an OCTET STRING
    // which results in 04 20 <32 bytes> (total 34 bytes)
    if private_key_bytes.len() == KEY_LEN + 2
        && private_key_bytes[0] == 0x04
        && private_key_bytes[1] == 0x20
    {
        private_key_bytes = &private_key_bytes[2..];
    }

    if private_key_bytes.len() < KEY_LEN {
        return Err(EraError::InvalidKey("PKCS#8 private key too short".into()));
    }

    let mut secret_bytes = [0u8; KEY_LEN];
    secret_bytes.copy_from_slice(&private_key_bytes[0..KEY_LEN]);

    EraKeyPair::from_bytes(&secret_bytes)
}

/// 从 SPKI DER 中提取公钥 (使用 spki crate)
fn extract_public_key_from_spki(der_bytes: &[u8]) -> Result<EraCertificate> {
    use spki::SubjectPublicKeyInfoRef;

    // 使用 spki crate 解析 SubjectPublicKeyInfo
    let spki = SubjectPublicKeyInfoRef::try_from(der_bytes)
        .map_err(|e| EraError::InvalidFormat(format!("Failed to parse SPKI: {}", e)))?;

    // 提取公钥数据（BIT STRING 的内容）
    let public_key_bytes = spki.subject_public_key.raw_bytes();

    if public_key_bytes.len() != KEY_LEN {
        return Err(EraError::InvalidKey(format!(
            "Invalid public key length: expected {}, got {}",
            KEY_LEN,
            public_key_bytes.len()
        )));
    }

    let mut public_key = [0u8; KEY_LEN];
    public_key.copy_from_slice(public_key_bytes);

    // 验证这不完全是零（无效密钥）
    if public_key.iter().all(|&b| b == 0) {
        return Err(EraError::InvalidKey("Public key is all zeros".into()));
    }

    Ok(EraCertificate::from_public_key(&public_key))
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
