//! Cryptographic commitment functions for v8.2.
//!
//! Commitments provide domain-separated semantic binding of catalog and index
//! contents. They are stored in ArchiveManifest and verified during archive open.
//!
//! # Commitment Contract
//!
//! - Commitments are computed over **serialized plaintext bytes** (not ciphertext)
//! - Same plaintext always produces the same commitment (deterministic)
//! - Different plaintexts produce different commitments (collision-resistant)
//! - Catalog and Index commitments use different domain keys (domain separation)
//! - Empty index plaintext yields `[0u8; 32]` (indicating "no index")

use blake3::Hasher;

/// Domain separation key for catalog commitment.
/// 32 bytes, required by blake3::Hasher::new_keyed.
pub(crate) const CATALOG_COMMITMENT_DOMAIN: &[u8; 32] = b"ERA-CAT-COMMIT-v1_______________";

/// Domain separation key for index commitment.
/// 32 bytes, required by blake3::Hasher::new_keyed.
pub(crate) const INDEX_COMMITMENT_DOMAIN: &[u8; 32] = b"ERA-IDX-COMMIT-v1_______________";

/// Compute the cryptographic commitment of catalog plaintext.
///
/// Uses Blake3 keyed_hash with domain separation to prevent cross-protocol
/// collisions and provide semantic binding.
///
/// # Arguments
/// * `catalog_plaintext` - The serialized catalog bytes (protobuf encoding)
///
/// # Returns
/// 32-byte commitment value
pub fn compute_catalog_commitment(catalog_plaintext: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_keyed(CATALOG_COMMITMENT_DOMAIN);
    hasher.update(catalog_plaintext);
    *hasher.finalize().as_bytes()
}

/// Compute the cryptographic commitment of index plaintext.
///
/// Uses Blake3 keyed_hash with domain separation.
///
/// # Arguments
/// * `index_plaintext` - The serialized index bytes
///
/// # Returns
/// 32-byte commitment value, or all zeros if index_plaintext is empty
pub fn compute_index_commitment(index_plaintext: &[u8]) -> [u8; 32] {
    if index_plaintext.is_empty() {
        return [0u8; 32];
    }
    let mut hasher = Hasher::new_keyed(INDEX_COMMITMENT_DOMAIN);
    hasher.update(index_plaintext);
    *hasher.finalize().as_bytes()
}

/// Verify a catalog commitment against expected value.
///
/// # Errors
/// Returns `EraError::CatalogCommitmentMismatch` if commitment does not match.
pub fn verify_catalog_commitment(
    catalog_plaintext: &[u8],
    expected: &[u8; 32],
) -> crate::Result<()> {
    let computed = compute_catalog_commitment(catalog_plaintext);
    use subtle::ConstantTimeEq;
    if computed.ct_eq(expected).unwrap_u8() == 0 {
        return Err(crate::EraError::CatalogCommitmentMismatch);
    }
    Ok(())
}

/// Verify an index commitment against expected value.
///
/// # Errors
/// Returns `EraError::IndexCommitmentMismatch` if commitment does not match.
/// Pass `expected = [0u8; 32]` to verify that no index exists.
pub fn verify_index_commitment(index_plaintext: &[u8], expected: &[u8; 32]) -> crate::Result<()> {
    let computed = compute_index_commitment(index_plaintext);
    use subtle::ConstantTimeEq;
    if computed.ct_eq(expected).unwrap_u8() == 0 {
        return Err(crate::EraError::IndexCommitmentMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_commitment_deterministic() {
        let data = b"test catalog data";
        let c1 = compute_catalog_commitment(data);
        let c2 = compute_catalog_commitment(data);
        assert_eq!(c1, c2);
    }

    #[test]
    fn catalog_commitment_different_input_different_output() {
        let c1 = compute_catalog_commitment(b"data1");
        let c2 = compute_catalog_commitment(b"data2");
        assert_ne!(c1, c2);
    }

    #[test]
    fn index_commitment_empty_returns_zeroes() {
        let c = compute_index_commitment(b"");
        assert_eq!(c, [0u8; 32]);
    }

    #[test]
    fn index_commitment_nonempty_is_nonzero() {
        let c = compute_index_commitment(b"index data");
        assert_ne!(c, [0u8; 32]);
    }

    #[test]
    fn verify_catalog_commitment_ok() {
        let data = b"catalog";
        let commitment = compute_catalog_commitment(data);
        assert!(verify_catalog_commitment(data, &commitment).is_ok());
    }

    #[test]
    fn verify_catalog_commitment_mismatch() {
        let data = b"catalog";
        let wrong = [0xFFu8; 32];
        assert!(verify_catalog_commitment(data, &wrong).is_err());
    }

    #[test]
    fn verify_index_commitment_ok() {
        let data = b"index";
        let commitment = compute_index_commitment(data);
        assert!(verify_index_commitment(data, &commitment).is_ok());
    }

    #[test]
    fn verify_index_commitment_mismatch() {
        let data = b"index";
        let wrong = [0xFFu8; 32];
        assert!(verify_index_commitment(data, &wrong).is_err());
    }

    #[test]
    fn verify_index_commitment_empty_ok() {
        let commitment = compute_index_commitment(b"");
        assert_eq!(commitment, [0u8; 32]);
        assert!(verify_index_commitment(b"", &commitment).is_ok());
    }

    #[test]
    fn domains_are_32_bytes() {
        assert_eq!(CATALOG_COMMITMENT_DOMAIN.len(), 32);
        assert_eq!(INDEX_COMMITMENT_DOMAIN.len(), 32);
    }

    #[test]
    fn catalog_and_index_domains_differ() {
        assert_ne!(CATALOG_COMMITMENT_DOMAIN, INDEX_COMMITMENT_DOMAIN);
    }

    #[test]
    fn catalog_and_index_commitments_differ_for_same_input() {
        let data = b"same input";
        let cat = compute_catalog_commitment(data);
        let idx = compute_index_commitment(data);
        assert_ne!(cat, idx);
    }
}
