//! Compact `.erac` bundle → extracted files.

use crate::auth::{AuthProvider, PasswordProvider};
use bytes::Bytes;
use era_common::{BlockId, ChunkHash, EraError, Result};
use era_compact::CompactBundleReader;
use era_crypto::{KeySession, VolumeKey};
use era_ingest::Catalog;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct CompactExtractStats {
    pub files_extracted: usize,
    pub bytes_written: u64,
    pub blocks_decrypted: usize,
}

type BlockCache = HashMap<u64, (era_common::BlockChunkIndex, Bytes)>;

pub struct CompactArchiveReader {
    bundle: CompactBundleReader,
    session: KeySession,
    volume_key: VolumeKey,
    nonce_context: [u8; 16],
    archive_id: [u8; 16],
    epoch_id: u32,
    catalog: Catalog,
}

impl CompactArchiveReader {
    pub fn open(bundle_path: &Path, password: &str) -> Result<Self> {
        let mut bundle = CompactBundleReader::open(bundle_path)?;
        let header = bundle.header().clone();

        let provider = PasswordProvider::new(password.to_string());
        let mut master_key = None;
        for slot in header.recipients() {
            if let Ok(Some(mk)) = provider.try_unlock(slot) {
                master_key = Some(mk);
                break;
            }
        }
        let mk_bytes: Vec<u8> = master_key.ok_or(EraError::InvalidKey(
            "no valid credentials for compact archive".into(),
        ))?;
        let mk_array: [u8; 32] = mk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| EraError::InvalidKey("invalid master key length".into()))?;

        let session = KeySession::from_master_key(&mk_array)?;
        let evk = header.encrypted_volume_key();
        let volume_key = session.unwrap_volume_key(evk.nonce(), evk.ciphertext())?;

        let nonce_context = *header.salt();
        let archive_id = *header.archive_id().0.as_bytes();
        let epoch_id = header.epoch_id();

        let (_cat_id, cat_bytes) = bundle.read_catalog()?;
        let catalog = Catalog::from_bytes(&cat_bytes)?;

        Ok(Self {
            bundle,
            session,
            volume_key,
            nonce_context,
            archive_id,
            epoch_id,
            catalog,
        })
    }

    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    pub fn extract_all(&mut self, output_dir: &Path) -> Result<CompactExtractStats> {
        fs::create_dir_all(output_dir)?;
        let mut stats = CompactExtractStats::default();

        let (chunk_to_block, block_cache) = self.build_chunk_block_map()?;
        stats.blocks_decrypted = block_cache.len();

        let entries = self.catalog.entries.clone();

        for entry in &entries {
            if entry.path.to_string_lossy().starts_with(".era/meta/") {
                continue;
            }

            let output_path = output_dir.join(&entry.path);
            validate_path_safety(&entry.path)?;

            if let Some(parent) = output_path.parent() {
                fs::create_dir_all(parent)?;
            }

            if entry.chunks.is_empty() {
                if entry.file_type == era_ingest::FileType::Directory {
                    fs::create_dir_all(&output_path)?;
                } else {
                    fs::File::create(&output_path)?;
                }
                stats.files_extracted += 1;
                continue;
            }

            let mut file_data = Vec::with_capacity(entry.size as usize);

            for chunk_ref in &entry.chunks {
                let block_seq = chunk_to_block.get(&chunk_ref.hash).ok_or_else(|| {
                    EraError::IntegrityError(format!(
                        "chunk hash not found in any block for file {}",
                        entry.path.display()
                    ))
                })?;

                let (index, data) = block_cache
                    .get(block_seq)
                    .ok_or_else(|| EraError::IntegrityError("block cache miss".into()))?;

                let chunk_data = era_packing::extract_chunk_by_hash(index, data, &chunk_ref.hash)?
                    .ok_or_else(|| {
                        EraError::IntegrityError(format!(
                            "chunk not found in block {} for file {}",
                            block_seq,
                            entry.path.display()
                        ))
                    })?;

                if let Some(packed_info) = &chunk_ref.packed_info {
                    let unpacked = era_packing::unpack_file(&chunk_data, packed_info.file_index)
                        .map_err(|e| {
                            EraError::IntegrityError(format!("packed unpack failed: {e}"))
                        })?;
                    file_data.extend_from_slice(&unpacked);
                } else {
                    file_data.extend_from_slice(&chunk_data);
                }
            }

            let mut file = fs::File::create(&output_path)?;
            file.write_all(&file_data)?;
            stats.bytes_written += file_data.len() as u64;
            stats.files_extracted += 1;
        }

        Ok(stats)
    }

    fn decrypt_block(&mut self, block_seq: u64) -> Result<(era_common::BlockChunkIndex, Bytes)> {
        let block_id = BlockId::new(block_seq);
        let encrypted = self.bundle.read_encrypted_block(block_id)?;
        let block_key =
            self.session
                .derive_block_key(&self.volume_key, block_seq, &self.nonce_context)?;
        let derived = block_key.to_derived_key()?;
        let compressor = era_packing::create_compressor();
        era_packing::decrypt_and_decompress(
            &derived,
            &self.nonce_context,
            &self.archive_id,
            self.epoch_id,
            block_id,
            &encrypted,
            compressor.as_ref(),
        )
    }

    fn build_chunk_block_map(&mut self) -> Result<(HashMap<ChunkHash, u64>, BlockCache)> {
        let mut map = HashMap::new();
        let mut block_cache = HashMap::new();

        let needed: HashSet<ChunkHash> = self
            .catalog
            .entries
            .iter()
            .filter(|e| !e.path.to_string_lossy().starts_with(".era/meta/"))
            .flat_map(|e| e.chunks.iter().map(|c| c.hash))
            .collect();

        let mut remaining = needed;
        let block_ids = self.bundle.data_block_ids();

        for block_id in block_ids {
            if remaining.is_empty() {
                break;
            }

            let block_seq = block_id.sequence();
            let (index, data) = self.decrypt_block(block_seq)?;

            for entry in &index.entries {
                if remaining.remove(&entry.hash) {
                    map.insert(entry.hash, block_seq);
                }
            }

            block_cache.insert(block_seq, (index, data));
        }

        if !remaining.is_empty() {
            return Err(EraError::IntegrityError(format!(
                "{} chunks not found in any compact block",
                remaining.len()
            )));
        }

        Ok((map, block_cache))
    }
}

fn validate_path_safety(path: &Path) -> Result<()> {
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                return Err(EraError::Security(format!(
                    "path traversal detected: {}",
                    path.display()
                )));
            }
            std::path::Component::RootDir => {
                return Err(EraError::Security(format!(
                    "absolute path in archive: {}",
                    path.display()
                )));
            }
            _ => {}
        }
    }
    Ok(())
}
