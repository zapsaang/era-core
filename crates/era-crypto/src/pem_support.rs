//! # PEM and X.509 Certificate Support
//!
//! Provides standard PEM PKCS#8 and X.509 parsing utilities.
//! Uses industry-standard crates: der, spki, x509-cert, ssh-key.
//!
//! ## Supported Formats
//!
//! ### Private Keys
//! - PKCS#8 (DER or PEM; plaintext, or RFC 8018 PBES2-encrypted with scrypt + AES-256-CBC)
//! - OpenSSH (unencrypted only; passphrase-protected keys are not supported)
//! - ERA HYBRID PRIVATE KEY / ERA HYBRID PUBLIC KEY pairs (plaintext)
//! - ERA ENCRYPTED HYBRID PRIVATE KEY / ERA HYBRID PUBLIC KEY pairs (passphrase-protected)
//!
//! ### Public Keys
//! - SubjectPublicKeyInfo (SPKI) - DER or PEM
//! - X.509 Certificates
//! - ERA HYBRID PUBLIC KEY
//!
//! ## Example
//!
//! ```rust,ignore
//! use era_crypto::pem_support::{PemFormat, load_private_key_from_pem, load_public_key_from_pem};
//!
//! // Load private key
//! let keypair = load_private_key_from_pem("my_key.pem", None)?;
//!
//! // Load public key
//! let cert = load_public_key_from_pem("my_cert.pem")?;
//! ```

use crate::certificate::{EraCertificate, EraKeyPair, KEY_LEN};
use crate::hybrid_certificate::{HybridCertificate, HybridKeyPair};
use era_common::{EraError, Result};
use spki::ObjectIdentifier;
use ssh_key::PrivateKey as SshPrivateKey;
use std::path::Path;

/// X25519 OID: 1.3.101.110
const X25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");

/// FROZEN: domain separator for the encrypted hybrid key file construction.
/// Never change; a changed construction gets a new label.
const HYBRID_KEY_FILE_AAD: &[u8] = b"ERA_HYBRID_KEY_FILE_v1";

/// Magic bytes of the versioned encrypted hybrid key file container.
const HYBRID_KEY_FILE_MAGIC: &[u8; 4] = b"ERHK";

/// Current version of the encrypted hybrid key file container.
const HYBRID_KEY_FILE_VERSION: u8 = 1;

/// PEM label of the encrypted hybrid private key block.
const ENCRYPTED_HYBRID_PRIVATE_KEY_LABEL: &str = "ERA ENCRYPTED HYBRID PRIVATE KEY";

/// Header length of the encrypted hybrid key file container:
/// magic(4) + version(1) + kdf params(12) + salt(16) + nonce(24).
const HYBRID_KEY_FILE_HEADER_LEN: usize = 4 + 1 + 12 + 16 + 24;

/// PEM format type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PemFormat {
    /// PKCS#8 private key
    Pkcs8PrivateKey,
    /// Encrypted PKCS#8 private key (RFC 8018 PBES2)
    EncryptedPkcs8PrivateKey,
    /// SubjectPublicKeyInfo public key
    SubjectPublicKeyInfo,
    /// X.509 certificate
    X509Certificate,
    /// OpenSSH private key
    OpenSshPrivateKey,
    /// Auto-detect
    Auto,
}

impl PemFormat {
    /// Detect format from PEM label
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "PRIVATE KEY" => Some(PemFormat::Pkcs8PrivateKey),
            "ENCRYPTED PRIVATE KEY" => Some(PemFormat::EncryptedPkcs8PrivateKey),
            "PUBLIC KEY" => Some(PemFormat::SubjectPublicKeyInfo),
            "CERTIFICATE" => Some(PemFormat::X509Certificate),
            "OPENSSH PRIVATE KEY" => Some(PemFormat::OpenSshPrivateKey),
            _ => None,
        }
    }
}

/// Load a private key from a PEM file
pub fn load_private_key_from_pem<P: AsRef<Path>>(
    path: P,
    password: Option<&str>,
) -> Result<EraKeyPair> {
    let content = std::fs::read_to_string(&path)
        .map_err(|e| EraError::InvalidFormat(format!("Failed to read PEM file: {}", e)))?;

    load_private_key_from_pem_string(&content, password)
}

/// Load a private key from PEM content
pub fn load_private_key_from_pem_string(
    pem_content: &str,
    password: Option<&str>,
) -> Result<EraKeyPair> {
    let pem_blocks = extract_pem_blocks(pem_content)?;

    if pem_blocks.is_empty() {
        return Err(EraError::InvalidFormat("No PEM blocks found".into()));
    }

    // Try the first supported private-key block
    for (tag, contents) in pem_blocks {
        let format = PemFormat::from_label(&tag);
        match format {
            Some(PemFormat::Pkcs8PrivateKey) => {
                return decode_pkcs8_private_key(&contents);
            }
            Some(PemFormat::EncryptedPkcs8PrivateKey) => {
                return decode_encrypted_pkcs8_private_key(&contents, password);
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

/// Export private key as PKCS#8 PEM (unencrypted).
///
/// WARNING: This does not encrypt the private key. Use only for testing or
/// exporting to a secure location.
pub fn export_private_key_as_pem(keypair: &EraKeyPair) -> Result<String> {
    use zeroize::Zeroize;

    let der = build_pkcs8_private_key_der(keypair);

    let pem_obj = pem::Pem::new("PRIVATE KEY", der.to_vec());
    let encoded = pem::encode(&pem_obj);

    pem_obj.into_contents().zeroize();

    Ok(encoded)
}

/// Export private key as encrypted PKCS#8 PEM (RFC 8018 PBES2, scrypt + AES-256-CBC).
///
/// The scrypt parameters are fixed at log_n=15, r=8, p=1 — aligned with the
/// pkcs8 crate defaults and the openssl `-scrypt` convention — and are stored
/// inside the DER structure, so the decrypt side needs only the passphrase.
pub fn export_private_key_as_encrypted_pem(keypair: &EraKeyPair, password: &str) -> Result<String> {
    use der::Decode;
    use rand::RngCore;

    let der = build_pkcs8_private_key_der(keypair);
    let private_key_info = pkcs8::PrivateKeyInfo::from_der(&der).map_err(|e| {
        EraError::Serialization(format!("Failed to re-parse generated PKCS#8: {}", e))
    })?;

    let mut salt = [0u8; 16];
    let mut aes_iv = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut aes_iv);

    let scrypt_params = pkcs5::scrypt::Params::new(15, 8, 1, 32)
        .map_err(|e| EraError::KeyDerivation(format!("Invalid scrypt parameters: {}", e)))?;
    let pbes2_params = pkcs5::pbes2::Parameters::scrypt_aes256cbc(scrypt_params, &salt, &aes_iv)
        .map_err(|e| EraError::Encryption(format!("Failed to build PBES2 parameters: {}", e)))?;

    let encrypted_doc = private_key_info
        .encrypt_with_params(pbes2_params, password.as_bytes())
        .map_err(|e| EraError::Encryption(format!("Failed to encrypt PKCS#8: {}", e)))?;

    Ok(pem::encode(&pem::Pem::new(
        "ENCRYPTED PRIVATE KEY",
        encrypted_doc.as_bytes().to_vec(),
    )))
}

/// Build the unencrypted PKCS#8 DER for an X25519 keypair.
fn build_pkcs8_private_key_der(keypair: &EraKeyPair) -> zeroize::Zeroizing<Vec<u8>> {
    let secret = zeroize::Zeroizing::new(keypair.secret_key.to_bytes());

    let mut key_field = zeroize::Zeroizing::new(Vec::with_capacity(34));
    key_field.push(0x04);
    key_field.push(0x20);
    key_field.extend_from_slice(&*secret);

    let algo_id = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e];
    let version = [0x02, 0x01, 0x00];

    let mut key_wrapper = zeroize::Zeroizing::new(Vec::with_capacity(36));
    key_wrapper.push(0x04);
    key_wrapper.push(key_field.len() as u8);
    key_wrapper.extend_from_slice(&key_field);

    let mut seq_content = zeroize::Zeroizing::new(Vec::new());
    seq_content.extend_from_slice(&version);
    seq_content.extend_from_slice(&algo_id);
    seq_content.extend_from_slice(&key_wrapper);

    let mut der = zeroize::Zeroizing::new(Vec::with_capacity(seq_content.len() + 2));
    der.push(0x30);
    der.push(seq_content.len() as u8);
    der.extend_from_slice(&seq_content);
    der
}

/// Load a public key from a PEM file
pub fn load_public_key_from_pem<P: AsRef<Path>>(path: P) -> Result<EraCertificate> {
    let content = std::fs::read_to_string(&path)
        .map_err(|e| EraError::InvalidFormat(format!("Failed to read PEM file: {}", e)))?;

    load_public_key_from_pem_string(&content)
}

/// Load a public key from PEM content
pub fn load_public_key_from_pem_string(pem_content: &str) -> Result<EraCertificate> {
    let pem_blocks = extract_pem_blocks(pem_content)?;

    if pem_blocks.is_empty() {
        return Err(EraError::InvalidFormat("No PEM blocks found".into()));
    }

    // Try the first supported public-key block
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

/// Export public key as SPKI PEM
pub fn export_public_key_as_pem(cert: &EraCertificate) -> Result<String> {
    encode_spki_public_key(cert.public_key())
}

/// Export hybrid public key as custom PEM
pub fn export_hybrid_public_key_as_pem(cert: &HybridCertificate) -> Result<String> {
    let pem = pem::Pem::new("ERA HYBRID PUBLIC KEY", cert.to_bytes());
    Ok(pem::encode(&pem))
}

/// Export hybrid private key as custom PEM (includes public key block for reconstruction).
pub fn export_hybrid_private_key_as_pem(keypair: &HybridKeyPair) -> Result<String> {
    use zeroize::Zeroize;

    let private_pem = pem::Pem::new(
        "ERA HYBRID PRIVATE KEY",
        keypair.secret_key_bytes().to_vec(),
    );
    let public_pem = pem::Pem::new("ERA HYBRID PUBLIC KEY", keypair.public_key_bytes());

    let private_encoded = pem::encode(&private_pem);
    let public_encoded = pem::encode(&public_pem);

    private_pem.into_contents().zeroize();

    Ok(format!("{}\n{}", private_encoded, public_encoded))
}

/// Export hybrid private key as a passphrase-protected custom PEM.
///
/// Container layout (binary payload inside the `ERA ENCRYPTED HYBRID PRIVATE KEY`
/// armor): magic "ERHK"(4) ‖ version(1) ‖ kdf params (3 × u32 LE) ‖ salt(16) ‖
/// nonce(24) ‖ XChaCha20-Poly1305 ciphertext. The AEAD AAD binds
/// `HYBRID_KEY_FILE_AAD` together with every header byte (magic..nonce), so any
/// tampering with KDF parameters, salt, or nonce fails authentication. KDF
/// parameters travel with the ciphertext, allowing future cost adjustments.
/// The accompanying `ERA HYBRID PUBLIC KEY` block stays plaintext (public keys
/// are not secret, and the loader contract requires it).
pub fn export_hybrid_private_key_as_encrypted_pem(
    keypair: &HybridKeyPair,
    password: &str,
) -> Result<String> {
    use crate::aead::{AeadCipher, AeadKey, Nonce};
    use crate::kdf::KdfParams;
    use crate::Salt;

    let kdf_params = KdfParams::standard();
    let salt = Salt::generate();
    let nonce = Nonce::generate();

    let mut header = Vec::with_capacity(HYBRID_KEY_FILE_HEADER_LEN);
    header.extend_from_slice(HYBRID_KEY_FILE_MAGIC);
    header.push(HYBRID_KEY_FILE_VERSION);
    header.extend_from_slice(&kdf_params.memory_cost.to_le_bytes());
    header.extend_from_slice(&kdf_params.time_cost.to_le_bytes());
    header.extend_from_slice(&kdf_params.parallelism.to_le_bytes());
    header.extend_from_slice(salt.as_bytes());
    header.extend_from_slice(nonce.as_bytes());

    let encryption_key = crate::derive_key(password.as_bytes(), &salt, &kdf_params)?;

    let aad = hybrid_key_file_aad(&header);

    let aead = AeadCipher::new();
    let secret = keypair.secret_key_bytes();
    let ciphertext = aead.encrypt(&AeadKey(*encryption_key.as_bytes()), &nonce, &aad, &secret)?;

    let mut payload = header;
    payload.extend_from_slice(&ciphertext);

    let private_pem = pem::Pem::new(ENCRYPTED_HYBRID_PRIVATE_KEY_LABEL, payload);
    let public_pem = pem::Pem::new("ERA HYBRID PUBLIC KEY", keypair.public_key_bytes());

    Ok(format!(
        "{}\n{}",
        pem::encode(&private_pem),
        pem::encode(&public_pem)
    ))
}

/// AAD for the encrypted hybrid key file: domain separator ‖ all header bytes.
fn hybrid_key_file_aad(header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HYBRID_KEY_FILE_AAD.len() + header.len());
    aad.extend_from_slice(HYBRID_KEY_FILE_AAD);
    aad.extend_from_slice(header);
    aad
}

/// Load a hybrid public key from a PEM file
pub fn load_hybrid_public_key_from_pem<P: AsRef<Path>>(path: P) -> Result<HybridCertificate> {
    let content = std::fs::read_to_string(&path)
        .map_err(|e| EraError::InvalidFormat(format!("Failed to read PEM file: {}", e)))?;
    load_hybrid_public_key_from_pem_string(&content)
}

/// Load a hybrid public key from PEM content
pub fn load_hybrid_public_key_from_pem_string(pem_content: &str) -> Result<HybridCertificate> {
    let pem_blocks = extract_pem_blocks(pem_content)?;
    for (tag, contents) in pem_blocks {
        if tag == "ERA HYBRID PUBLIC KEY" {
            return HybridCertificate::from_bytes(&contents);
        }
    }
    Err(EraError::InvalidFormat(
        "No ERA HYBRID PUBLIC KEY block found in PEM file".into(),
    ))
}

/// Load a passphrase-protected hybrid private key from PEM content.
///
/// Expects an `ERA ENCRYPTED HYBRID PRIVATE KEY` block plus the accompanying
/// plaintext `ERA HYBRID PUBLIC KEY` block. Wrong passphrases fail with
/// `EraError::Decryption`.
pub fn load_hybrid_private_key_from_pem_string_encrypted(
    pem_content: &str,
    password: &str,
) -> Result<HybridKeyPair> {
    let pem_blocks = extract_pem_blocks(pem_content)?;
    let mut payload: Option<Vec<u8>> = None;
    let mut public_bytes: Option<Vec<u8>> = None;
    for (tag, contents) in pem_blocks {
        if tag == ENCRYPTED_HYBRID_PRIVATE_KEY_LABEL {
            payload = Some(contents);
        } else if tag == "ERA HYBRID PUBLIC KEY" {
            public_bytes = Some(contents);
        }
    }
    let payload = payload.ok_or_else(|| {
        EraError::InvalidFormat(format!(
            "No {} block found in PEM file",
            ENCRYPTED_HYBRID_PRIVATE_KEY_LABEL
        ))
    })?;
    let public_bytes = public_bytes.ok_or_else(|| {
        EraError::InvalidFormat(
            "Encrypted hybrid private key PEM requires an accompanying ERA HYBRID PUBLIC KEY block"
                .into(),
        )
    })?;

    let secret = decrypt_hybrid_key_file(&payload, password)?;
    HybridKeyPair::from_secret_and_public_bytes(&secret, &public_bytes)
}

/// Decrypt an ERHK container payload, returning the zeroized secret key bytes.
fn decrypt_hybrid_key_file(payload: &[u8], password: &str) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    use crate::aead::{AeadCipher, AeadKey, Nonce};
    use crate::kdf::KdfParams;
    use crate::Salt;

    if payload.len() < HYBRID_KEY_FILE_HEADER_LEN + 16 {
        return Err(EraError::InvalidFormat(
            "Encrypted hybrid key file too short".into(),
        ));
    }
    if payload[0..4] != HYBRID_KEY_FILE_MAGIC[..] {
        return Err(EraError::InvalidFormat(
            "Invalid encrypted hybrid key file magic".into(),
        ));
    }
    if payload[4] != HYBRID_KEY_FILE_VERSION {
        return Err(EraError::InvalidFormat(
            "Unsupported encrypted hybrid key file version".into(),
        ));
    }

    let read_u32 = |range: std::ops::Range<usize>| -> Result<u32> {
        payload[range]
            .try_into()
            .map(u32::from_le_bytes)
            .map_err(|_| EraError::InvalidFormat("Invalid KDF parameter length".into()))
    };
    let kdf_params = KdfParams {
        memory_cost: read_u32(5..9)?,
        time_cost: read_u32(9..13)?,
        parallelism: read_u32(13..17)?,
    };

    let salt_bytes: [u8; 16] = payload[17..33]
        .try_into()
        .map_err(|_| EraError::InvalidFormat("Invalid salt length".into()))?;
    let salt = Salt::from_bytes(salt_bytes);
    let nonce = Nonce::from_bytes(&payload[33..HYBRID_KEY_FILE_HEADER_LEN])?;

    let encryption_key = crate::derive_key(password.as_bytes(), &salt, &kdf_params)?;

    let header = &payload[..HYBRID_KEY_FILE_HEADER_LEN];
    let aad = hybrid_key_file_aad(header);

    let aead = AeadCipher::new();
    let plaintext = aead.decrypt(
        &AeadKey(*encryption_key.as_bytes()),
        &nonce,
        &aad,
        &payload[HYBRID_KEY_FILE_HEADER_LEN..],
    )?;

    Ok(zeroize::Zeroizing::new(plaintext))
}

/// Load a hybrid private key from a PEM file
pub fn load_hybrid_private_key_from_pem<P: AsRef<Path>>(path: P) -> Result<HybridKeyPair> {
    let content = std::fs::read_to_string(&path)
        .map_err(|e| EraError::InvalidFormat(format!("Failed to read PEM file: {}", e)))?;
    load_hybrid_private_key_from_pem_string(&content)
}

/// Load a hybrid private key from PEM content
pub fn load_hybrid_private_key_from_pem_string(pem_content: &str) -> Result<HybridKeyPair> {
    let pem_blocks = extract_pem_blocks(pem_content)?;
    let mut secret_bytes: Option<Vec<u8>> = None;
    let mut public_bytes: Option<Vec<u8>> = None;
    for (tag, contents) in pem_blocks {
        if tag == "ERA HYBRID PRIVATE KEY" {
            secret_bytes = Some(contents);
        } else if tag == "ERA HYBRID PUBLIC KEY" {
            public_bytes = Some(contents);
        }
    }
    match (secret_bytes, public_bytes) {
        (Some(sec), Some(pub_)) => HybridKeyPair::from_secret_and_public_bytes(&sec, &pub_),
        (Some(_sec), None) => Err(EraError::InvalidFormat(
            "Hybrid private key PEM requires an accompanying ERA HYBRID PUBLIC KEY block".into(),
        )),
        _ => Err(EraError::InvalidFormat(
            "No ERA HYBRID PRIVATE KEY block found in PEM file".into(),
        )),
    }
}

/// Load any supported private key from a PEM file (legacy or hybrid).
pub fn load_any_private_key_from_pem<P: AsRef<Path>>(
    path: P,
    password: Option<&str>,
) -> Result<EitherKeyPair> {
    let content = std::fs::read_to_string(&path)
        .map_err(|e| EraError::InvalidFormat(format!("Failed to read PEM file: {}", e)))?;
    load_any_private_key_from_pem_string(&content, password)
}

/// Load any supported private key from PEM content (legacy or hybrid).
///
/// Detection order: encrypted hybrid container → plaintext hybrid dual-block →
/// legacy PKCS#8 (plaintext or encrypted). Encrypted blocks never fall back to
/// another format branch: a missing passphrase yields
/// `EraError::PassphraseRequired`, a wrong one `EraError::Decryption`.
pub fn load_any_private_key_from_pem_string(
    pem_content: &str,
    password: Option<&str>,
) -> Result<EitherKeyPair> {
    let pem_blocks = extract_pem_blocks(pem_content)?;

    if pem_blocks
        .iter()
        .any(|(tag, _)| tag == ENCRYPTED_HYBRID_PRIVATE_KEY_LABEL)
    {
        let password = password.ok_or_else(|| {
            EraError::PassphraseRequired(
                "passphrase required for encrypted hybrid private key".into(),
            )
        })?;
        let keypair = load_hybrid_private_key_from_pem_string_encrypted(pem_content, password)?;
        return Ok(EitherKeyPair::Hybrid(Box::new(keypair)));
    }

    if pem_blocks
        .iter()
        .any(|(tag, _)| tag == "ERA HYBRID PRIVATE KEY")
    {
        let hybrid = load_hybrid_private_key_from_pem_string(pem_content)?;
        return Ok(EitherKeyPair::Hybrid(Box::new(hybrid)));
    }

    // Fall back to legacy X25519 PKCS#8 (plaintext or encrypted)
    let legacy = load_private_key_from_pem_string(pem_content, password)?;
    Ok(EitherKeyPair::Legacy(legacy))
}

/// Either a legacy X25519 keypair or a post-quantum hybrid keypair.
#[derive(Debug)]
pub enum EitherKeyPair {
    Legacy(EraKeyPair),
    Hybrid(Box<HybridKeyPair>),
}

/// Extract all PEM blocks from content
fn extract_pem_blocks(content: &str) -> Result<Vec<(String, Vec<u8>)>> {
    // Use the pem crate to parse all blocks
    use pem::parse_many;

    let pem_blocks = parse_many(content)
        .map_err(|e| EraError::InvalidFormat(format!("Failed to parse PEM: {}", e)))?;

    let blocks: Vec<(String, Vec<u8>)> = pem_blocks
        .into_iter()
        .map(|block| (block.tag().to_string(), block.contents().to_vec()))
        .collect();

    Ok(blocks)
}

/// Decode PKCS#8 private key (plaintext only — encrypted blocks route to
/// `decode_encrypted_pkcs8_private_key` via the PEM label).
fn decode_pkcs8_private_key(der_bytes: &[u8]) -> Result<EraKeyPair> {
    extract_private_key_from_pkcs8(der_bytes)
}

/// Decode an encrypted PKCS#8 private key (RFC 8018 PBES2).
///
/// The KDF and cipher parameters are read from the DER structure; only the
/// passphrase is required. Wrong passphrases fail with `EraError::Decryption`.
fn decode_encrypted_pkcs8_private_key(
    der_bytes: &[u8],
    password: Option<&str>,
) -> Result<EraKeyPair> {
    use der::Decode;

    let password = password.ok_or_else(|| {
        EraError::PassphraseRequired("passphrase required for encrypted PKCS#8 private key".into())
    })?;

    let encrypted_info = pkcs8::EncryptedPrivateKeyInfo::from_der(der_bytes)
        .map_err(|e| EraError::InvalidFormat(format!("Failed to parse encrypted PKCS#8: {}", e)))?;

    let decrypted_doc = encrypted_info.decrypt(password.as_bytes()).map_err(|_| {
        EraError::Decryption("Failed to decrypt PKCS#8 private key (wrong passphrase?)".into())
    })?;

    extract_private_key_from_pkcs8(decrypted_doc.as_bytes())
}

/// Decode OpenSSH private key (ssh-key crate)
fn decode_openssh_private_key(data: &[u8], _password: Option<&str>) -> Result<EraKeyPair> {
    // Parse OpenSSH format using ssh-key
    let ssh_key = SshPrivateKey::from_bytes(data)
        .map_err(|e| EraError::InvalidFormat(format!("Failed to parse OpenSSH key: {}", e)))?;

    match ssh_key.algorithm() {
        ssh_key::Algorithm::Ed25519 => Err(EraError::InvalidKey(
            "Unsupported OpenSSH key algorithm: Ed25519 is not X25519".into(),
        )),
        _ => Err(EraError::InvalidKey(
            "Unsupported OpenSSH key algorithm: only X25519 is supported".into(),
        )),
    }
}

/// Decode SPKI public key
fn decode_spki_public_key(der_bytes: &[u8]) -> Result<EraCertificate> {
    // SPKI structure: SEQUENCE { AlgorithmIdentifier, BIT STRING (public key) }
    extract_public_key_from_spki(der_bytes)
}

/// Decode X.509 certificate (x509-cert crate)
fn decode_x509_certificate(der_bytes: &[u8]) -> Result<EraCertificate> {
    use der::Decode;
    use x509_cert::Certificate;

    // Parse certificate with x509-cert
    let cert = Certificate::from_der(der_bytes).map_err(|e| {
        EraError::InvalidFormat(format!("Failed to parse X.509 certificate: {}", e))
    })?;

    // Extract SubjectPublicKeyInfo
    let spki = &cert.tbs_certificate.subject_public_key_info;

    // Validate algorithm is X25519
    if spki.algorithm.oid != X25519_OID {
        return Err(EraError::InvalidKey(format!(
            "Unsupported certificate algorithm OID: expected X25519 ({}), got {}",
            X25519_OID, spki.algorithm.oid
        )));
    }

    // Extract public key data
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

    // Validate this is not all zeros (invalid key)
    if public_key.iter().all(|&b| b == 0) {
        return Err(EraError::InvalidKey("Public key is all zeros".into()));
    }

    Ok(EraCertificate::from_public_key(&public_key))
}

/// Encode public key as SPKI (spki crate)
fn encode_spki_public_key(public_key: &[u8; KEY_LEN]) -> Result<String> {
    use der::Encode;
    use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

    // Build AlgorithmIdentifier
    let algorithm = AlgorithmIdentifierOwned {
        oid: X25519_OID,
        parameters: None, // X25519 has no parameters
    };

    // Build SubjectPublicKeyInfo
    let spki = SubjectPublicKeyInfoOwned {
        algorithm,
        subject_public_key: der::asn1::BitString::new(0, public_key.to_vec())
            .map_err(|e| EraError::Serialization(format!("Failed to create BitString: {}", e)))?,
    };

    // Encode to DER
    let der_bytes = spki
        .to_der()
        .map_err(|e| EraError::Serialization(format!("Failed to encode SPKI to DER: {}", e)))?;

    let pem = pem::Pem::new("PUBLIC KEY", der_bytes);
    Ok(pem::encode(&pem))
}

/// Extract private key from PKCS#8 DER (pkcs8 crate)
fn extract_private_key_from_pkcs8(der_bytes: &[u8]) -> Result<EraKeyPair> {
    // Parse PKCS#8 via pkcs8 crate
    use pkcs8::PrivateKeyInfo;

    let private_key_info = PrivateKeyInfo::try_from(der_bytes)
        .map_err(|e| EraError::InvalidFormat(format!("Failed to parse PKCS#8: {}", e)))?;

    if private_key_info.algorithm.oid != X25519_OID {
        return Err(EraError::InvalidKey(format!(
            "Unsupported private key algorithm OID: expected X25519 ({}), got {}",
            X25519_OID, private_key_info.algorithm.oid
        )));
    }

    // Extract private key data (OCTET STRING payload)
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

/// Extract public key from SPKI DER (spki crate)
fn extract_public_key_from_spki(der_bytes: &[u8]) -> Result<EraCertificate> {
    use spki::SubjectPublicKeyInfoRef;

    // Parse SubjectPublicKeyInfo via spki
    let spki = SubjectPublicKeyInfoRef::try_from(der_bytes)
        .map_err(|e| EraError::InvalidFormat(format!("Failed to parse SPKI: {}", e)))?;

    // Validate algorithm is X25519
    if spki.algorithm.oid != X25519_OID {
        return Err(EraError::InvalidKey(format!(
            "Unsupported public key algorithm OID: expected X25519 ({}), got {}",
            X25519_OID, spki.algorithm.oid
        )));
    }

    // Extract public key bytes (BIT STRING payload)
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

    // Validate not all zeros (invalid key)
    if public_key.iter().all(|&b| b == 0) {
        return Err(EraError::InvalidKey("Public key is all zeros".into()));
    }

    Ok(EraCertificate::from_public_key(&public_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FROZEN — changing this value breaks all existing encrypted hybrid key files.
    #[test]
    fn frozen_aad_hybrid_key_file() {
        assert_eq!(HYBRID_KEY_FILE_AAD, b"ERA_HYBRID_KEY_FILE_v1");
    }

    #[test]
    fn test_pem_format_detection() {
        assert_eq!(
            PemFormat::from_label("PRIVATE KEY"),
            Some(PemFormat::Pkcs8PrivateKey)
        );
        assert_eq!(
            PemFormat::from_label("ENCRYPTED PRIVATE KEY"),
            Some(PemFormat::EncryptedPkcs8PrivateKey)
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

        // Export as PEM
        let pem_str = export_public_key_as_pem(&cert).unwrap();
        assert!(pem_str.contains("BEGIN PUBLIC KEY"));
        assert!(pem_str.contains("END PUBLIC KEY"));

        // Load from PEM
        let loaded_cert = load_public_key_from_pem_string(&pem_str).unwrap();
        assert_eq!(loaded_cert.public_key(), cert.public_key());
    }

    #[test]
    fn test_load_private_key_rejects_ed25519_pkcs8() {
        use std::process::Command;
        let temp =
            std::env::temp_dir().join(format!("era_ed25519_pkcs8_{}.pem", std::process::id()));
        let output = Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "ed25519",
                "-out",
                temp.to_str().unwrap(),
            ])
            .output()
            .expect("openssl should be available");
        assert!(output.status.success(), "openssl genpkey ed25519 failed");

        let err = load_private_key_from_pem(&temp, None).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("Unsupported private key algorithm"),
            "Expected unsupported algorithm error, got: {}",
            msg
        );

        let _ = std::fs::remove_file(&temp);
    }

    #[test]
    fn test_load_private_key_rejects_ed25519_openssh() {
        use std::process::Command;
        let temp_dir =
            std::env::temp_dir().join(format!("era_ed25519_openssh_{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let openssh_key = temp_dir.join("key");

        let output = Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                openssh_key.to_str().unwrap(),
                "-N",
                "",
                "-C",
                "test",
            ])
            .output()
            .expect("ssh-keygen should be available");
        assert!(output.status.success(), "ssh-keygen ed25519 failed");

        let err = load_private_key_from_pem(&openssh_key, None).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("Unsupported OpenSSH key algorithm"),
            "Expected unsupported algorithm error, got: {}",
            msg
        );

        let _ = std::fs::remove_file(&openssh_key);
        let _ = std::fs::remove_file(openssh_key.with_extension("pub"));
        let _ = std::fs::remove_dir(&temp_dir);
    }
}
