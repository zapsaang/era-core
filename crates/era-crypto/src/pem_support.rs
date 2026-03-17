//! # PEM and X.509 Certificate Support
//!
//! Provides standard PEM PKCS#8 and X.509 parsing utilities.
//! Uses industry-standard crates: der, spki, x509-cert, ssh-key.
//!
//! ## Supported Formats
//!
//! ### Private Keys
//! - PKCS#8 (DER or PEM)
//! - OpenSSH
//!
//! ### Public Keys
//! - SubjectPublicKeyInfo (SPKI) - DER or PEM
//! - X.509 Certificates
//!
//! ## Example
//!
//! ```rust,ignore
//! use era_crypto::pem_support::{PemFormat, load_private_key_from_pem, load_public_key_from_pem};
//!
//! // Load private key
//! let keypair = load_private_key_from_pem("my_key.pem", Some("password"))?;
//!
//! // Load public key
//! let cert = load_public_key_from_pem("my_cert.pem")?;
//! ```

use crate::certificate::{EraCertificate, EraKeyPair, KEY_LEN};
use era_common::{EraError, Result};
use ssh_key::PrivateKey as SshPrivateKey;
use std::path::Path;

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

    // Support ed25519 keys
    match ssh_key.algorithm() {
        ssh_key::Algorithm::Ed25519 => {
            // Extract key material from OpenSSH format.
            // ssh-key KeypairData is Bytes, so we parse directly.
            let private_bytes = data;

            // OpenSSH Ed25519 format: magic | cipher_name | kdf_name | kdf_options | ...
            // | keytype | public_key | private_key_blob | ...
            // private_key_blob contains: checkint | keytype | public_key | private_key (64 bytes) | comment | ...

            // Simplified handling: Ed25519 private keys usually contain a 32-byte seed.
            // Attempt to recover it by scanning the blob.
            const OPENSSH_MAGIC: &[u8; 15] = b"openssh-key-v1\0";
            if private_bytes.len() < 15 || &private_bytes[0..15] != OPENSSH_MAGIC {
                return Err(EraError::InvalidFormat("Invalid OpenSSH key format".into()));
            }

            // Search for public/private key data after the "ssh-ed25519" marker
            if let Some(pos) = private_bytes.windows(11).position(|w| w == b"ssh-ed25519") {
                // Skip key type name length and content
                let mut search_pos = pos + 11;

                // Look for a 32-byte public key followed by 64-byte private key blob
                while search_pos + 64 < private_bytes.len() {
                    // Attempt to extract a 32-byte seed (first half of the private key)
                    let candidate = &private_bytes[search_pos..search_pos + KEY_LEN];

                    // Validate not all zeros
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
    use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};

    // X25519 OID: 1.3.101.110
    const X25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");

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
}
