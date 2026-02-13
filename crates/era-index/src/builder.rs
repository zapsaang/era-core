//! # IndexBuilder — Redb-backed Index Construction
//!
//! Manages index construction with ACID guarantees via Redb.
//! Entries are inserted into a staging Redb database during archive creation.
//! At finalization, entries are read in sorted order and written as encrypted
//! IndexPage blocks to the volume.

use bloomfilter::Bloom;

use era_common::{BlockType, ChunkHash, EncryptedMacroBlock, EraError, Result};
use era_crypto::{KeySession, VolumeKey};
use era_storage::StorageWriter;

use crate::store::IndexStore;
use crate::IndexEntry;

/// Default memory limit (64MB) — used for bloom filter sizing
const DEFAULT_MEM_LIMIT: usize = 64 * 1024 * 1024;

/// Bloom filter false positive rate (1%)
const BLOOM_FP_RATE: f64 = 0.01;

/// Bloom filter expected items — derived from mem_limit / entry size
fn bloom_expected_items(mem_limit: usize) -> usize {
    let entry_size = std::mem::size_of::<IndexEntry>().max(1);
    (mem_limit / entry_size).max(1024)
}

/// IndexBuilder manages index construction with Redb-backed ACID storage.
///
/// During archive creation, entries are inserted into a staging Redb database.
/// At finalization, all entries are read in sorted order (Redb B-tree guarantees
/// this) and written as encrypted IndexPage/IndexManifest blocks to the volume.
pub struct IndexBuilder {
    /// Redb-backed index store (replaces memtable + spiller + merger)
    store: IndexStore,
}

impl IndexBuilder {
    /// Create a new IndexBuilder with specified memory limit.
    ///
    /// Creates a temporary Redb file for staging entries.
    pub fn new(mem_limit: usize) -> Self {
        let temp_file = tempfile::Builder::new()
            .prefix("era-staging-")
            .suffix(".redb")
            .tempfile()
            .expect("Failed to create temp file for staging IndexStore");
        let (_, temp_path) = temp_file
            .keep()
            .expect("Failed to persist temp file path");
        let store = IndexStore::create(&temp_path, bloom_expected_items(mem_limit))
            .expect("Failed to create staging IndexStore");
        Self { store }
    }

    /// Create a new IndexBuilder with a specific path for the Redb file.
    pub fn with_path(path: &std::path::Path, mem_limit: usize) -> Result<Self> {
        let store = IndexStore::create(path, bloom_expected_items(mem_limit))?;
        Ok(Self { store })
    }

    /// Create with default memory limit (64MB)
    pub fn new_default() -> Self {
        Self::new(DEFAULT_MEM_LIMIT)
    }

    /// Insert an entry into the index.
    ///
    /// The entry is immediately written to the Redb staging database
    /// with ACID guarantees.
    pub fn insert(&mut self, entry: IndexEntry) -> Result<()> {
        self.store.insert(&entry)
    }

    /// Get total number of entries inserted
    pub fn entry_count(&self) -> usize {
        self.store.entry_count()
    }

    /// Check if a hash exists in the Bloom filter
    pub fn bloom_contains(&self, hash: &ChunkHash) -> bool {
        self.store.bloom_contains(hash)
    }

    /// Get reference to the bloom filter
    pub fn bloom(&self) -> &Bloom<ChunkHash> {
        self.store.bloom()
    }

    /// Get reference to the underlying IndexStore
    pub fn store(&self) -> &IndexStore {
        &self.store
    }

    /// Finalize the index (EMBEDDED MODE — writes to volume)
    ///
    /// Reads all entries from the Redb staging database in sorted order,
    /// then writes encrypted IndexPage blocks and an IndexManifest block
    /// to the volume. Returns the MetaIndex and its BlockLocation.
    pub async fn finalize<W: StorageWriter>(
        &mut self,
        volume_writer: &mut era_volume::VolumeWriter<W>,
        session: &KeySession,
        volume_key: &VolumeKey,
        nonce_context: [u8; 16],
    ) -> Result<(super::MetaIndex, era_common::BlockLocation)> {
        use super::{IndexPage, ENTRIES_PER_PAGE};
        use era_common::BlockId;

        // Read all entries from Redb in sorted order (B-tree guarantees sort)
        let all_entries = self.store.drain_sorted()?;

        // Build L1 MetaIndex
        let mut meta = super::MetaIndex::new();

        // Write L2 pages as typed blocks to volume
        let mut block_id_counter = 0u64;
        for page_entries in all_entries.chunks(ENTRIES_PER_PAGE) {
            if page_entries.is_empty() {
                continue;
            }

            // Create IndexPage
            let page = IndexPage::new(page_entries.to_vec());

            // Serialize page to rkyv
            let page_bytes = rkyv::to_bytes::<_, 4096>(&page)
                .map_err(|e| EraError::Serialization(e.to_string()))?;

            // Encrypt page with session keys
            let block_id = BlockId::new(block_id_counter);
            let block_key =
                session.derive_block_key(volume_key, block_id.sequence(), &nonce_context);
            let derived_key = block_key.to_derived_key();
            let encrypted_data = era_crypto::encrypt_with_context(
                &derived_key,
                &nonce_context,
                block_id,
                &page_bytes,
            )?;

            // Create EncryptedMacroBlock
            let encrypted_block = EncryptedMacroBlock {
                block_id,
                data: encrypted_data,
                original_size: page_bytes.len() as u32,
                compressed_size: page_bytes.len() as u32,
                chunk_count: page_entries.len() as u16,
            };

            // Write as canonical block to volume
            let _location = volume_writer
                .write_canonical_block(&encrypted_block, BlockType::IndexPage)
                .await?;

            // Add PagePointer to L1
            meta.add_page(page.min_hash, page.max_hash, block_id);

            block_id_counter += 1;
        }

        // Rebuild a right-sized bloom from actual entries for the on-disk format.
        let finalized_bloom = if all_entries.is_empty() {
            self.store.bloom().clone()
        } else {
            let mut compact =
                Bloom::new_for_fp_rate(all_entries.len().max(1024), BLOOM_FP_RATE);
            for entry in &all_entries {
                compact.set(&entry.hash);
            }
            compact
        };
        let bloom_bytes = super::serialize_bloom(&finalized_bloom)?;
        meta.set_bloom_filter(bloom_bytes);

        // Encrypt and write MetaIndex as IndexManifest block
        let meta_bytes = rkyv::to_bytes::<_, 4096>(&meta)
            .map_err(|e| EraError::Serialization(e.to_string()))?;

        let manifest_block_id = BlockId::new(block_id_counter);
        let manifest_key =
            session.derive_block_key(volume_key, manifest_block_id.sequence(), &nonce_context);
        let manifest_derived_key = manifest_key.to_derived_key();
        let encrypted_manifest = era_crypto::encrypt_with_context(
            &manifest_derived_key,
            &nonce_context,
            manifest_block_id,
            &meta_bytes,
        )?;

        let manifest_encrypted_block = EncryptedMacroBlock {
            block_id: manifest_block_id,
            data: encrypted_manifest,
            original_size: meta_bytes.len() as u32,
            compressed_size: meta_bytes.len() as u32,
            chunk_count: 0,
        };

        // Write MetaIndex as IndexManifest block
        let manifest_location = volume_writer
            .write_canonical_block(&manifest_encrypted_block, BlockType::IndexManifest)
            .await?;

        Ok((meta, manifest_location))
    }
}

impl Drop for IndexBuilder {
    fn drop(&mut self) {
        // Best-effort cleanup of the staging Redb file
        let path = self.store.path().to_path_buf();
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use era_common::{BlockId, VolumeId};

    fn test_hash(value: u64) -> ChunkHash {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        ChunkHash::from_bytes(bytes)
    }

    #[test]
    fn test_builder_insert() {
        let mut builder = IndexBuilder::new(1024 * 1024);

        for i in 0..100u64 {
            let entry = IndexEntry::new(
                test_hash(i),
                VolumeId::new(),
                BlockId::new(i / 100),
                (i % 100) as u32 * 1024,
                1024,
            );
            builder.insert(entry).unwrap();
        }

        assert_eq!(builder.entry_count(), 100);
    }

    #[test]
    fn test_bloom_filter() {
        let mut builder = IndexBuilder::new_default();

        for i in 0..1000u64 {
            let entry = IndexEntry::new(
                test_hash(i),
                VolumeId::new(),
                BlockId::new(i / 100),
                (i % 100) as u32 * 1024,
                1024,
            );
            builder.insert(entry).unwrap();
        }

        // Check all inserted hashes are found
        for i in 0..1000u64 {
            assert!(builder.bloom_contains(&test_hash(i)));
        }

        // Check false positive rate on non-existent hashes
        let mut false_positives = 0;
        for i in 1000..2000u64 {
            if builder.bloom_contains(&test_hash(i)) {
                false_positives += 1;
            }
        }

        // Should be < 20 false positives (2% of 1000 queries)
        assert!(false_positives < 20);
    }
}
