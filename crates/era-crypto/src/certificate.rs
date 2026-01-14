//! # ERA 证书密钥模块
//!
//! 提供基于X25519的密钥交换方案，作为Argon2密码派生的高性能替代。
//!
//! ## 性能对比
//!
//! | 方案 | 密钥派生时间 |
//! |------|-------------|
//! | Argon2 (64MB) | ~80ms |
//! | Argon2 (256MB) | ~343ms |
//! | X25519 | ~0.05ms |
//!
//! ## 使用方式
//!
//! ```rust,ignore
//! use era_crypto::certificate::{EraKeyPair, EraCertificate};
//!
//! // 生成密钥对
//! let keypair = EraKeyPair::generate()?;
//!
//! // 导出公钥证书（可以分发）
//! let cert = keypair.certificate();
//!
//! // 保存密钥对（加密存储）
//! keypair.save_encrypted("my_key.era-key", "key_password")?;
//!
//! // 加载密钥对
//! let keypair = EraKeyPair::load_encrypted("my_key.era-key", "key_password")?;
//! ```

use crate::aead::{AeadCipher, AeadKey, Nonce};
use crate::kdf::{derive_key, KdfParams};
use crate::Salt;
use era_common::{EraError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 密钥ID长度 (16 bytes = 128 bits)
pub const KEY_ID_LEN: usize = 16;

/// X25519密钥长度
pub const KEY_LEN: usize = 32;

/// 密钥文件魔数
const KEY_FILE_MAGIC: &[u8; 4] = b"ERAK";

/// 证书文件魔数
const CERT_FILE_MAGIC: &[u8; 4] = b"ERAC";

/// 密钥文件版本
const KEY_FILE_VERSION: u8 = 1;

/// ERA 密钥对
///
/// 包含私钥和公钥，用于创建和解密归档。
/// 私钥使用安全内存保护，drop时自动清零。
#[derive(ZeroizeOnDrop)]
pub struct EraKeyPair {
    /// 私钥 (32 bytes)
    #[zeroize(skip)] // StaticSecret has its own zeroize
    secret_key: StaticSecret,
    /// 公钥 (32 bytes)
    public_key: PublicKey,
    /// 密钥ID (用于识别密钥)
    key_id: [u8; KEY_ID_LEN],
    /// 创建时间 (Unix timestamp)
    created_at: u64,
}

/// ERA 公钥证书
///
/// 只包含公钥信息，可以安全分发。
/// 用于创建只有对应私钥持有者才能解密的归档。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EraCertificate {
    /// 公钥 (32 bytes)
    public_key: [u8; KEY_LEN],
    /// 密钥ID
    key_id: [u8; KEY_ID_LEN],
    /// 创建时间 (Unix timestamp)
    created_at: u64,
    /// 可选：过期时间
    expires_at: Option<u64>,
    /// 可选：备注/标签
    label: Option<String>,
}

/// 临时密钥对（用于ECDH）
#[derive(ZeroizeOnDrop)]
pub struct EphemeralKeyPair {
    #[zeroize(skip)]
    secret: StaticSecret,
    public: PublicKey,
}

/// 密钥封装结果
pub struct KeyEncapsulation {
    /// 临时公钥（需要存储在归档中）
    pub ephemeral_public: [u8; KEY_LEN],
    /// 加密后的主密钥
    pub encrypted_master_key: Vec<u8>,
}

/// 解封装的主密钥
pub struct DecapsulatedKey {
    /// 主密钥（32 bytes），内部使用Vec并在drop时清零
    master_key: Vec<u8>,
}

impl DecapsulatedKey {
    /// 获取主密钥字节
    pub fn as_bytes(&self) -> &[u8] {
        &self.master_key
    }

    /// 获取32字节数组
    pub fn to_array(&self) -> [u8; KEY_LEN] {
        let mut arr = [0u8; KEY_LEN];
        arr.copy_from_slice(&self.master_key);
        arr
    }
}

impl Drop for DecapsulatedKey {
    fn drop(&mut self) {
        self.master_key.zeroize();
    }
}

impl EraKeyPair {
    /// 生成新的密钥对
    pub fn generate() -> Result<Self> {
        let mut rng = rand::thread_rng();

        // 生成X25519密钥对
        let secret_key = StaticSecret::random_from_rng(&mut rng);
        let public_key = PublicKey::from(&secret_key);

        // 生成密钥ID（公钥的前16字节hash）
        let key_id = Self::compute_key_id(&public_key);

        // 获取当前时间
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(Self {
            secret_key,
            public_key,
            key_id,
            created_at,
        })
    }

    /// 从原始字节创建密钥对
    pub fn from_bytes(secret_bytes: &[u8; KEY_LEN]) -> Result<Self> {
        let secret_key = StaticSecret::from(*secret_bytes);
        let public_key = PublicKey::from(&secret_key);
        let key_id = Self::compute_key_id(&public_key);

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(Self {
            secret_key,
            public_key,
            key_id,
            created_at,
        })
    }

    /// 计算密钥ID（公钥的BLAKE3 hash的前16字节）
    fn compute_key_id(public_key: &PublicKey) -> [u8; KEY_ID_LEN] {
        let hash = crate::hash(public_key.as_bytes());
        let mut key_id = [0u8; KEY_ID_LEN];
        key_id.copy_from_slice(&hash.0[..KEY_ID_LEN]);
        key_id
    }

    /// 获取密钥ID
    pub fn key_id(&self) -> &[u8; KEY_ID_LEN] {
        &self.key_id
    }

    /// 获取公钥
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// 获取公钥字节
    pub fn public_key_bytes(&self) -> [u8; KEY_LEN] {
        *self.public_key.as_bytes()
    }

    /// 获取创建时间
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// 导出公钥证书
    pub fn certificate(&self) -> EraCertificate {
        EraCertificate {
            public_key: *self.public_key.as_bytes(),
            key_id: self.key_id,
            created_at: self.created_at,
            expires_at: None,
            label: None,
        }
    }

    /// 使用接收者公钥封装主密钥
    ///
    /// 生成临时密钥对，与接收者公钥进行ECDH，然后加密主密钥。
    pub fn encapsulate_for(
        recipient: &EraCertificate,
        master_key: &[u8],
    ) -> Result<KeyEncapsulation> {
        if master_key.len() != KEY_LEN {
            return Err(EraError::InvalidKey("Master key must be 32 bytes".into()));
        }

        // 生成临时密钥对
        let ephemeral = EphemeralKeyPair::generate();

        // 与接收者公钥进行ECDH
        let recipient_public = PublicKey::from(recipient.public_key);
        let shared_secret = ephemeral.secret.diffie_hellman(&recipient_public);

        // 使用HKDF派生加密密钥
        let wrap_key = Self::derive_wrap_key(shared_secret.as_bytes())?;

        // 加密主密钥
        let aead = AeadCipher::new();
        let nonce = Nonce::zero(); // 因为wrap_key是一次性的，可以用零nonce
        let encrypted = aead.encrypt(&wrap_key, &nonce, master_key)?;

        Ok(KeyEncapsulation {
            ephemeral_public: *ephemeral.public.as_bytes(),
            encrypted_master_key: encrypted,
        })
    }

    /// 解封装主密钥
    ///
    /// 使用私钥与临时公钥进行ECDH，然后解密主密钥。
    pub fn decapsulate(&self, encapsulation: &KeyEncapsulation) -> Result<DecapsulatedKey> {
        // 恢复临时公钥
        let ephemeral_public = PublicKey::from(encapsulation.ephemeral_public);

        // 进行ECDH
        let shared_secret = self.secret_key.diffie_hellman(&ephemeral_public);

        // 使用HKDF派生解密密钥
        let wrap_key = Self::derive_wrap_key(shared_secret.as_bytes())?;

        // 解密主密钥
        let aead = AeadCipher::new();
        let nonce = Nonce::zero();
        let mut decrypted = aead.decrypt(&wrap_key, &nonce, &encapsulation.encrypted_master_key)?;

        if decrypted.len() != KEY_LEN {
            decrypted.zeroize();
            return Err(EraError::InvalidKey("Decrypted key has wrong length".into()));
        }

        Ok(DecapsulatedKey {
            master_key: decrypted,
        })
    }

    /// 使用HKDF派生密钥封装密钥
    fn derive_wrap_key(shared_secret: &[u8]) -> Result<AeadKey> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
        let mut okm = [0u8; 32];
        hkdf.expand(b"ERA-KEY-WRAP-V1", &mut okm)
            .map_err(|_| EraError::KeyDerivation("HKDF expand failed".into()))?;

        Ok(AeadKey(okm))
    }

    /// 保存密钥对到文件（加密存储）
    ///
    /// 使用Argon2派生加密密钥来保护私钥。
    /// 这里Argon2的开销是可接受的，因为密钥文件只在初始化时加载一次。
    pub fn save_encrypted<P: AsRef<Path>>(&self, path: P, password: &str) -> Result<()> {
        // 使用Argon2派生加密密钥（这里用较轻的参数，因为私钥本身是高熵的）
        let salt = Salt::generate();
        let params = KdfParams::fast(); // 1MB内存，快速
        let encryption_key = derive_key(password.as_bytes(), &salt, &params)?;

        // 加密私钥
        let aead = AeadCipher::new();
        let nonce = Nonce::generate();
        let secret_bytes = self.secret_key.as_bytes();
        let encrypted_secret = aead.encrypt(
            &AeadKey(*encryption_key.as_bytes()),
            &nonce,
            secret_bytes,
        )?;

        // 构建文件内容
        // Format: MAGIC(4) + VERSION(1) + SALT(16) + NONCE(24) + KEY_ID(16) + CREATED_AT(8) + ENCRYPTED_SECRET(32+16)
        let mut file_data = Vec::with_capacity(128);
        file_data.extend_from_slice(KEY_FILE_MAGIC);
        file_data.push(KEY_FILE_VERSION);
        file_data.extend_from_slice(salt.as_bytes());
        file_data.extend_from_slice(nonce.as_bytes());
        file_data.extend_from_slice(&self.key_id);
        file_data.extend_from_slice(&self.created_at.to_le_bytes());
        file_data.extend_from_slice(&encrypted_secret);

        // 写入文件
        let mut file = fs::File::create(path)?;
        file.write_all(&file_data)?;

        Ok(())
    }

    /// 从加密文件加载密钥对
    pub fn load_encrypted<P: AsRef<Path>>(path: P, password: &str) -> Result<Self> {
        let mut file = fs::File::open(path)?;
        let mut file_data = Vec::new();
        file.read_to_end(&mut file_data)?;

        // 验证魔数和版本
        // Format: MAGIC(4) + VERSION(1) + SALT(16) + NONCE(24) + KEY_ID(16) + CREATED_AT(8) + ENCRYPTED_SECRET
        // Minimum: 4+1+16+24+16+8+48 = 117 bytes
        if file_data.len() < 117 {
            return Err(EraError::InvalidFormat("Key file too short".into()));
        }

        if &file_data[0..4] != KEY_FILE_MAGIC {
            return Err(EraError::InvalidFormat("Invalid key file magic".into()));
        }

        if file_data[4] != KEY_FILE_VERSION {
            return Err(EraError::InvalidFormat("Unsupported key file version".into()));
        }

        // 解析文件内容
        let salt_bytes: [u8; 16] = file_data[5..21].try_into()
            .map_err(|_| EraError::InvalidFormat("Invalid salt length".into()))?;
        let salt = Salt::from_bytes(salt_bytes);
        let nonce = Nonce::from_bytes(&file_data[21..45])?;
        let mut key_id = [0u8; KEY_ID_LEN];
        key_id.copy_from_slice(&file_data[45..61]);
        let created_at = u64::from_le_bytes(file_data[61..69].try_into().unwrap());
        let encrypted_secret = &file_data[69..];

        // 使用Argon2派生解密密钥
        let params = KdfParams::fast();
        let encryption_key = derive_key(password.as_bytes(), &salt, &params)?;

        // 解密私钥
        let aead = AeadCipher::new();
        let secret_bytes = aead.decrypt(
            &AeadKey(*encryption_key.as_bytes()),
            &nonce,
            encrypted_secret,
        )?;

        if secret_bytes.len() != KEY_LEN {
            return Err(EraError::InvalidKey("Invalid secret key length".into()));
        }

        let mut secret_array = [0u8; KEY_LEN];
        secret_array.copy_from_slice(&secret_bytes);
        let secret_key = StaticSecret::from(secret_array);
        secret_array.zeroize();

        let public_key = PublicKey::from(&secret_key);

        // 验证key_id匹配
        let computed_key_id = Self::compute_key_id(&public_key);
        if computed_key_id != key_id {
            return Err(EraError::InvalidKey("Key ID mismatch".into()));
        }

        Ok(Self {
            secret_key,
            public_key,
            key_id,
            created_at,
        })
    }
}

impl EraCertificate {
    /// 创建新证书
    pub fn new(public_key: [u8; KEY_LEN], key_id: [u8; KEY_ID_LEN], created_at: u64) -> Self {
        Self {
            public_key,
            key_id,
            created_at,
            expires_at: None,
            label: None,
        }
    }

    /// 从公钥字节创建
    pub fn from_public_key(public_key: &[u8; KEY_LEN]) -> Self {
        let hash = crate::hash(public_key);
        let mut key_id = [0u8; KEY_ID_LEN];
        key_id.copy_from_slice(&hash.0[..KEY_ID_LEN]);

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            public_key: *public_key,
            key_id,
            created_at,
            expires_at: None,
            label: None,
        }
    }

    /// 设置过期时间
    pub fn with_expiry(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// 设置标签
    pub fn with_label(mut self, label: String) -> Self {
        self.label = Some(label);
        self
    }

    /// 获取公钥
    pub fn public_key(&self) -> &[u8; KEY_LEN] {
        &self.public_key
    }

    /// 获取密钥ID
    pub fn key_id(&self) -> &[u8; KEY_ID_LEN] {
        &self.key_id
    }

    /// 获取创建时间
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// 检查是否过期
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            now > expires_at
        } else {
            false
        }
    }

    /// 保存证书到文件
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file_data = Vec::with_capacity(128);
        file_data.extend_from_slice(CERT_FILE_MAGIC);
        file_data.push(KEY_FILE_VERSION);

        // 序列化证书数据
        let cert_data =
            bincode::serialize(self).map_err(|e| EraError::Serialization(e.to_string()))?;
        file_data.extend_from_slice(&(cert_data.len() as u32).to_le_bytes());
        file_data.extend_from_slice(&cert_data);

        let mut file = fs::File::create(path)?;
        file.write_all(&file_data)?;

        Ok(())
    }

    /// 从文件加载证书
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = fs::File::open(path)?;
        let mut file_data = Vec::new();
        file.read_to_end(&mut file_data)?;

        if file_data.len() < 9 {
            return Err(EraError::InvalidFormat("Certificate file too short".into()));
        }

        if &file_data[0..4] != CERT_FILE_MAGIC {
            return Err(EraError::InvalidFormat(
                "Invalid certificate file magic".into(),
            ));
        }

        if file_data[4] != KEY_FILE_VERSION {
            return Err(EraError::InvalidFormat(
                "Unsupported certificate file version".into(),
            ));
        }

        let cert_len = u32::from_le_bytes(file_data[5..9].try_into().unwrap()) as usize;
        if file_data.len() < 9 + cert_len {
            return Err(EraError::InvalidFormat("Certificate file truncated".into()));
        }

        let cert: EraCertificate = bincode::deserialize(&file_data[9..9 + cert_len])
            .map_err(|e| EraError::Deserialization(e.to_string()))?;

        Ok(cert)
    }
}

impl EphemeralKeyPair {
    /// 生成新的临时密钥对
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let secret = StaticSecret::random_from_rng(&mut rng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}

impl std::fmt::Debug for EraKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EraKeyPair")
            .field("key_id", &hex::encode(&self.key_id))
            .field("public_key", &hex::encode(self.public_key.as_bytes()))
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use tempfile::TempDir;

    #[test]
    fn test_keypair_generation() {
        let keypair = EraKeyPair::generate().unwrap();
        assert_eq!(keypair.key_id().len(), KEY_ID_LEN);
        assert_eq!(keypair.public_key_bytes().len(), KEY_LEN);
    }

    #[test]
    fn test_certificate_export() {
        let keypair = EraKeyPair::generate().unwrap();
        let cert = keypair.certificate();

        assert_eq!(cert.key_id(), keypair.key_id());
        assert_eq!(cert.public_key(), &keypair.public_key_bytes());
    }

    #[test]
    fn test_key_encapsulation_roundtrip() {
        let recipient = EraKeyPair::generate().unwrap();
        let cert = recipient.certificate();

        // 要封装的主密钥
        let mut master_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut master_key);

        // 封装
        let encapsulation = EraKeyPair::encapsulate_for(&cert, &master_key).unwrap();

        // 解封装
        let decapsulated = recipient.decapsulate(&encapsulation).unwrap();

        assert_eq!(decapsulated.master_key.as_slice(), &master_key);
    }

    #[test]
    fn test_keypair_save_load() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test.era-key");

        let original = EraKeyPair::generate().unwrap();
        original.save_encrypted(&key_path, "test_password").unwrap();

        let loaded = EraKeyPair::load_encrypted(&key_path, "test_password").unwrap();

        assert_eq!(loaded.key_id(), original.key_id());
        assert_eq!(loaded.public_key_bytes(), original.public_key_bytes());
    }

    #[test]
    fn test_keypair_wrong_password() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test.era-key");

        let original = EraKeyPair::generate().unwrap();
        original.save_encrypted(&key_path, "correct_password").unwrap();

        let result = EraKeyPair::load_encrypted(&key_path, "wrong_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_certificate_save_load() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("test.era-cert");

        let keypair = EraKeyPair::generate().unwrap();
        let original = keypair.certificate().with_label("Test Key".to_string());
        original.save(&cert_path).unwrap();

        let loaded = EraCertificate::load(&cert_path).unwrap();

        assert_eq!(loaded.key_id(), original.key_id());
        assert_eq!(loaded.public_key(), original.public_key());
        assert_eq!(loaded.label, Some("Test Key".to_string()));
    }

    #[test]
    fn test_certificate_expiry() {
        let keypair = EraKeyPair::generate().unwrap();

        // 未过期
        let cert = keypair.certificate().with_expiry(u64::MAX);
        assert!(!cert.is_expired());

        // 已过期
        let cert = keypair.certificate().with_expiry(0);
        assert!(cert.is_expired());
    }
}
