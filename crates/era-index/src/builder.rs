//! # IndexBuilder - In-memory Buffering with Bounded Memory
//!
//! Manages the MemTable and Bloom filter during index construction.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use bloomfilter::Bloom;

use era_common::{BlockType, ChunkHash, EncryptedMacroBlock, EraError, Result};
use era_crypto::{KeySession, VolumeKey};
use era_storage::StorageWriter;

use super::{IndexEntry, Spiller, TieredMerger};

/// Default MemTable size limit (64MB)
const DEFAULT_MEM_LIMIT: usize = 64 * 1024 * 1024;

/// Bloom filter expected items (10M items)
const BLOOM_EXPECTED_ITEMS: usize = 10_000_000;

/// Bloom filter false positive rate (1%)
const BLOOM_FP_RATE: f64 = 0.01;

/// IndexBuilder manages index construction with bounded memory
pub struct IndexBuilder {
    /// In-memory buffer for entries
    memtable: Vec<IndexEntry>,
    /// Global Bloom filter (survives spills)
    bloom: Bloom<ChunkHash>,
    /// Secure spiller for temp files
    spiller: Spiller,
    /// List of spill file paths
    spilled_segments: Vec<PathBuf>,
    /// Memory limit in bytes
    mem_limit: usize,
}

impl IndexBuilder {
    /// Create a new IndexBuilder with specified memory limit
    pub fn new(mem_limit: usize) -> Self {
        Self {
            memtable: Vec::with_capacity(mem_limit / IndexEntry::memory_size()),
            bloom: Bloom::new_for_fp_rate(BLOOM_EXPECTED_ITEMS, BLOOM_FP_RATE),
            spiller: Spiller::new(),
            spilled_segments: Vec::new(),
            mem_limit,
        }
    }

    /// Create with default memory limit (64MB)
    pub fn new_default() -> Self {
        Self::new(DEFAULT_MEM_LIMIT)
    }

    /// Insert an entry into the index
    pub fn insert(&mut self, entry: IndexEntry, temp_dir: &Path) -> Result<()> {
        // Update Bloom filter (RAM-resident, survives spills)
        self.bloom.set(&entry.hash);

        // Add to MemTable
        self.memtable.push(entry);

        // Check if we need to spill
        if self.memtable_size_bytes() >= self.mem_limit {
            self.flush_memtable(temp_dir)?;
        }

        Ok(())
    }

    /// Get current MemTable memory usage in bytes
    pub fn memtable_size_bytes(&self) -> usize {
        self.memtable.len() * IndexEntry::memory_size()
    }

    /// Get number of spill files created
    pub fn spill_count(&self) -> usize {
        self.spilled_segments.len()
    }

    /// Check if a hash exists in the Bloom filter
    pub fn bloom_contains(&self, hash: &ChunkHash) -> bool {
        self.bloom.check(hash)
    }

    /// Flush MemTable to encrypted spill file
    fn flush_memtable(&mut self, temp_dir: &Path) -> Result<()> {
        if self.memtable.is_empty() {
            return Ok(());
        }

        // Sort entries before spilling
        self.memtable.sort_unstable_by_key(|e| e.hash);

        // Spill to encrypted temp file
        let spill_path = self.spiller.spill(&self.memtable, temp_dir)?;
        self.spilled_segments.push(spill_path);

        // Clear MemTable
        self.memtable.clear();

        tracing::debug!(
            "Flushed MemTable to spill file, total spills: {}",
            self.spilled_segments.len()
        );

        Ok(())
    }

    /// Snapshot the Bloom filter to disk (for crash recovery)
    pub fn snapshot_bloom(&self, path: &Path) -> Result<()> {
        // Serialize Bloom filter using serde_json (bloomfilter crate uses serde)
        let bloom_json =
            serde_json::to_vec(&self.bloom).map_err(|e| EraError::Serialization(e.to_string()))?;

        // Write to file
        let mut file = File::create(path).map_err(EraError::Io)?;
        file.write_all(&bloom_json).map_err(EraError::Io)?;
        file.sync_all().map_err(EraError::Io)?;

        tracing::info!("Bloom filter snapshot written: {:?}", path);
        Ok(())
    }

    /// Restore IndexBuilder from a Bloom filter snapshot
    pub fn restore_from_snapshot(path: &Path) -> Result<Self> {
        let mut file = File::open(path).map_err(EraError::Io)?;
        let mut bloom_bytes = Vec::new();
        file.read_to_end(&mut bloom_bytes).map_err(EraError::Io)?;

        let bloom = serde_json::from_slice(&bloom_bytes)
            .map_err(|e| EraError::Deserialization(e.to_string()))?;

        tracing::info!("Restored Bloom filter from snapshot: {:?}", path);

        Ok(Self {
            memtable: Vec::new(),
            bloom,
            spiller: Spiller::new(), // New ephemeral key for this session
            spilled_segments: Vec::new(),
            mem_limit: DEFAULT_MEM_LIMIT,
        })
    }

    /// Finalize the index (EMBEDDED MODE - writes to volume)
    ///
    /// **CRITICAL CHANGE:** Index pages are now written as typed blocks to the volume,
    /// not as external files. This enables cold recovery.
    ///
    /// Returns the MetaIndex and its BlockLocation in the volume
    pub fn finalize<W: StorageWriter>(
        &mut self,
        volume_writer: &mut era_volume::VolumeWriter<W>,
        session: &KeySession,
        volume_key: &VolumeKey,
        nonce_context: [u8; 16],
    ) -> Result<(super::MetaIndex, era_common::BlockLocation)> {
        use super::{IndexPage, ENTRIES_PER_PAGE};
        use era_common::BlockId;

        // Flush any remaining entries in MemTable
        if !self.memtable.is_empty() {
            self.memtable.sort_unstable_by_key(|e| e.hash);
        }

        // Get sorted entries via tiered merge
        let all_entries = if self.spilled_segments.is_empty() {
            // No spills: just use sorted MemTable
            self.memtable.clone()
        } else {
            // Merge all spill files
            let merger = TieredMerger::new(self.spilled_segments.clone(), &self.spiller)?;
            let mut merged: Vec<IndexEntry> = merger.collect();

            // Add MemTable entries to the merged stream
            merged.extend_from_slice(&self.memtable);
            merged.sort_unstable_by_key(|e| e.hash);
            merged
        };

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

            // Serialize page to JSON
            let page_json =
                serde_json::to_vec(&page).map_err(|e| EraError::Serialization(e.to_string()))?;

            // Encrypt page with session keys
            let block_id = BlockId::new(block_id_counter);
            let block_key =
                session.derive_block_key(volume_key, block_id.sequence(), &nonce_context);
            let derived_key = block_key.to_derived_key();
            let encrypted_data = era_crypto::encrypt_with_context(
                &derived_key,
                &nonce_context,
                block_id,
                &page_json,
            )?;

            // Create EncryptedMacroBlock
            let encrypted_block = EncryptedMacroBlock {
                block_id,
                data: encrypted_data,
                original_size: page_json.len() as u32,
                compressed_size: page_json.len() as u32, // No compression for index
                chunk_count: page_entries.len() as u16,
            };

            // Write as typed block to volume
            let _location =
                volume_writer.write_typed_block(&encrypted_block, BlockType::IndexPage)?;

            // Add PagePointer to L1
            meta.add_page(page.min_hash, page.max_hash, block_id);

            block_id_counter += 1;
        }

        // Serialize Bloom filter
        let bloom_bytes =
            serde_json::to_vec(&self.bloom).map_err(|e| EraError::Serialization(e.to_string()))?;
        meta.set_bloom_filter(bloom_bytes);

        // Encrypt and write MetaIndex as IndexManifest block
        let meta_json =
            serde_json::to_vec(&meta).map_err(|e| EraError::Serialization(e.to_string()))?;

        let manifest_block_id = BlockId::new(block_id_counter);
        let manifest_key =
            session.derive_block_key(volume_key, manifest_block_id.sequence(), &nonce_context);
        let manifest_derived_key = manifest_key.to_derived_key();
        let encrypted_manifest = era_crypto::encrypt_with_context(
            &manifest_derived_key,
            &nonce_context,
            manifest_block_id,
            &meta_json,
        )?;

        let manifest_encrypted_block = EncryptedMacroBlock {
            block_id: manifest_block_id,
            data: encrypted_manifest,
            original_size: meta_json.len() as u32,
            compressed_size: meta_json.len() as u32,
            chunk_count: 0,
        };

        // Write MetaIndex as IndexManifest block
        let manifest_location =
            volume_writer.write_typed_block(&manifest_encrypted_block, BlockType::IndexManifest)?;

        Ok((meta, manifest_location))
    }

    /// Legacy finalize for external file storage (DEPRECATED)
    ///
    /// **WARNING:** This creates "Zombie Archives" - DO NOT USE in production
    #[deprecated(
        since = "8.1.0",
        note = "Use finalize() with VolumeWriter for self-contained archives"
    )]
    pub fn finalize_external(&mut self, output_dir: &Path) -> Result<super::MetaIndex> {
        use super::{IndexPage, ENTRIES_PER_PAGE};
        use std::fs;

        // Flush any remaining entries in MemTable
        if !self.memtable.is_empty() {
            self.memtable.sort_unstable_by_key(|e| e.hash);
        }

        // Get sorted entries via tiered merge
        let all_entries = if self.spilled_segments.is_empty() {
            self.memtable.clone()
        } else {
            let merger = TieredMerger::new(self.spilled_segments.clone(), &self.spiller)?;
            let mut merged: Vec<IndexEntry> = merger.collect();
            merged.extend_from_slice(&self.memtable);
            merged.sort_unstable_by_key(|e| e.hash);
            merged
        };

        let mut meta = super::MetaIndex::new();
        let mut block_id_counter = 0u64;

        for page_entries in all_entries.chunks(ENTRIES_PER_PAGE) {
            if page_entries.is_empty() {
                continue;
            }

            let page = IndexPage::new(page_entries.to_vec());
            let page_json =
                serde_json::to_vec(&page).map_err(|e| EraError::Serialization(e.to_string()))?;
            let page_path = output_dir.join(format!("page_{}.bin", block_id_counter));
            fs::write(&page_path, &page_json).map_err(EraError::Io)?;

            meta.add_page(
                page.min_hash,
                page.max_hash,
                era_common::BlockId::new(block_id_counter),
            );

            block_id_counter += 1;
        }

        let bloom_bytes =
            serde_json::to_vec(&self.bloom).map_err(|e| EraError::Serialization(e.to_string()))?;
        meta.set_bloom_filter(bloom_bytes);

        Ok(meta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use era_common::{BlockId, VolumeId};
    use tempfile::TempDir;

    fn test_hash(value: u64) -> ChunkHash {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        ChunkHash::from_bytes(bytes)
    }

    #[test]
    fn test_builder_insert_and_spill() {
        let temp_dir = TempDir::new().unwrap();
        let mut builder = IndexBuilder::new(1024 * 1024); // 1MB limit

        // Insert entries until spill is triggered
        let entries_per_spill = 1024 * 1024 / IndexEntry::memory_size();

        for i in 0..(entries_per_spill * 2) {
            let entry = IndexEntry::new(
                test_hash(i as u64),
                VolumeId::new(),
                BlockId::new(i as u64 / 100),
                (i % 100) as u32 * 1024,
                1024,
            );
            builder.insert(entry, temp_dir.path()).unwrap();
        }

        // Should have triggered at least one spill
        assert!(builder.spill_count() >= 1);
        assert!(builder.memtable_size_bytes() <= 1024 * 1024);
    }

    #[test]
    fn test_bloom_filter() {
        let temp_dir = TempDir::new().unwrap();
        let mut builder = IndexBuilder::new_default();

        // Insert 1000 hashes
        for i in 0..1000 {
            let entry = IndexEntry::new(
                test_hash(i),
                VolumeId::new(),
                BlockId::new(i / 100),
                (i % 100) as u32 * 1024,
                1024,
            );
            builder.insert(entry, temp_dir.path()).unwrap();
        }

        // Check all inserted hashes are found
        for i in 0..1000 {
            assert!(builder.bloom_contains(&test_hash(i)));
        }

        // Check false positive rate on non-existent hashes
        let mut false_positives = 0;
        for i in 1000..2000 {
            if builder.bloom_contains(&test_hash(i)) {
                false_positives += 1;
            }
        }

        // Should be < 20 false positives (2% of 1000 queries)
        assert!(false_positives < 20);
    }

    #[test]
    fn test_bloom_snapshot_and_restore() {
        let temp_dir = TempDir::new().unwrap();
        let mut builder = IndexBuilder::new_default();

        // Insert hashes
        for i in 0..100 {
            let entry = IndexEntry::new(
                test_hash(i),
                VolumeId::new(),
                BlockId::new(0),
                i as u32 * 1024,
                1024,
            );
            builder.insert(entry, temp_dir.path()).unwrap();
        }

        // Snapshot
        let snapshot_path = temp_dir.path().join("bloom.snap");
        builder.snapshot_bloom(&snapshot_path).unwrap();

        // Restore
        let restored = IndexBuilder::restore_from_snapshot(&snapshot_path).unwrap();

        // Verify all hashes are present
        for i in 0..100 {
            assert!(restored.bloom_contains(&test_hash(i)));
        }
    }
}
