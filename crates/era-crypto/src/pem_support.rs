//! # PEM and X.509 Certificate Support
//!
//! Provides standard PEM PKCS#8 and X.509 parsing utilities.
//! Uses industry-standard crates: der, spki, x509-cert, ssh-key.
//!
//! ## Supported Formats
//!
//! ### Private Keys
//! - PKCS#8 (DER or PEM)
//! - OpenSSH (unencrypted only; passphrase-protected keys are not yet supported)
//! - ERA HYBRID PRIVATE KEY / ERA HYBRID PUBLIC KEY pairs
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

/// PEM format type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PemFormat {
    /// PKCS#8 private key
    Pkcs8PrivateKey,
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

/// Export private key as PKCS#8 PEM (unencrypted).
///
/// WARNING: This does not encrypt the private key. Use only for testing or
/// exporting to a secure location.
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

    let pem = pem::Pem::new("PRIVATE KEY", der);
    Ok(pem::encode(&pem))
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
    let private_pem = pem::Pem::new("ERA HYBRID PRIVATE KEY", keypair.secret_key_bytes());
    let public_pem = pem::Pem::new("ERA HYBRID PUBLIC KEY", keypair.public_key_bytes());
    Ok(format!(
        "{}\n{}",
        pem::encode(&private_pem),
        pem::encode(&public_pem)
    ))
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
pub fn load_any_private_key_from_pem_string(
    pem_content: &str,
    password: Option<&str>,
) -> Result<EitherKeyPair> {
    // Try hybrid first (explicit tag avoids ambiguity)
    if let Ok(hybrid) = load_hybrid_private_key_from_pem_string(pem_content) {
        return Ok(EitherKeyPair::Hybrid(Box::new(hybrid)));
    }
    // Fall back to legacy X25519/Ed25519
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

/// Decode PKCS#8 private key
fn decode_pkcs8_private_key(der_bytes: &[u8], password: Option<&str>) -> Result<EraKeyPair> {
    let _password = password; // Currently unused

    // Check for encrypted PKCS#8
    if der_bytes.starts_with(&[0x30]) && is_encrypted_pkcs8(der_bytes) {
        return Err(EraError::InvalidFormat(
            "Encrypted PKCS#8 not yet supported".into(),
        ));
    }

    // Parse PKCS#8 DER
    extract_private_key_from_pkcs8(der_bytes)
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

/// Check whether PKCS#8 is encrypted
fn is_encrypted_pkcs8(der_bytes: &[u8]) -> bool {
    // EncryptedPrivateKeyInfo is a SEQUENCE whose first element is an AlgorithmIdentifier (SEQUENCE)
    // Plain PrivateKeyInfo starts with INTEGER (version). Use a lightweight DER heuristic.
    if der_bytes.len() < 4 {
        return false;
    }

    // SEQUENCE { SEQUENCE ... } indicates encrypted
    // SEQUENCE { INTEGER ... } indicates unencrypted
    der_bytes[0] == 0x30 && der_bytes.len() > 2 && der_bytes[2] == 0x30
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
