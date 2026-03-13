use crate::reader::ArchiveReader;
use crate::source_block_snapshot::{ensure_complete_source_volume_set, SourceDataBlockSnapshot};
use era_common::{BlockId, ChunkHash, EraError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactLiveBlockDiscovery {
    EmbeddedIndex,
    IteratorFallback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactLiveDataBlocks {
    pub block_ids: Vec<BlockId>,
    pub source: CompactLiveBlockDiscovery,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactSourcePreflight {
    pub archive_id: [u8; 16],
    pub expected_total_volumes: usize,
    pub available_volume_indices: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactPreparedSource {
    pub preflight: CompactSourcePreflight,
    pub live_data_blocks: CompactLiveDataBlocks,
    pub snapshots: Vec<SourceDataBlockSnapshot>,
}

impl CompactSourcePreflight {
    pub fn from_archive_reader(reader: &ArchiveReader) -> Result<Self> {
        let expected_total_volumes = usize::from(reader.header().total_volumes());
        let available_volume_indices = reader
            .volume_indices()
            .iter()
            .map(|i| *i as u16)
            .collect::<Vec<_>>();

        if expected_total_volumes > 0 && reader.header().config().erasure.is_some() {
            ensure_complete_source_volume_set(expected_total_volumes, &available_volume_indices)?;
        }

        Ok(Self {
            archive_id: *reader.header().archive_id().0.as_bytes(),
            expected_total_volumes,
            available_volume_indices,
        })
    }

    pub async fn live_data_block_ids(reader: &mut ArchiveReader) -> Result<Vec<BlockId>> {
        Ok(Self::discover_live_data_blocks(reader).await?.block_ids)
    }

    pub async fn discover_live_data_blocks(
        reader: &mut ArchiveReader,
    ) -> Result<CompactLiveDataBlocks> {
        reader.preflight_metadata_recovery().await?;
        let live_hashes = reader.live_catalog_chunk_hashes()?;
        if live_hashes.is_empty() {
            return Ok(CompactLiveDataBlocks {
                block_ids: Vec::new(),
                source: CompactLiveBlockDiscovery::EmbeddedIndex,
            });
        }

        if let Some(index) = reader.index_reader() {
            let out = resolve_live_data_block_ids_via_index(index, &live_hashes)?;
            return Ok(CompactLiveDataBlocks {
                block_ids: out,
                source: CompactLiveBlockDiscovery::EmbeddedIndex,
            });
        }

        if reader.embedded_index_recovery_failed() {
            return Ok(CompactLiveDataBlocks {
                block_ids: reader
                    .live_data_block_ids_from_hashes_via_iterator(&live_hashes)
                    .await?,
                source: CompactLiveBlockDiscovery::IteratorFallback,
            });
        }

        Err(EraError::IntegrityError(
            "embedded index unavailable after preflight".into(),
        ))
    }
}

impl CompactPreparedSource {
    pub async fn from_archive_reader(reader: &mut ArchiveReader) -> Result<Self> {
        let preflight = CompactSourcePreflight::from_archive_reader(reader)?;
        let live_data_blocks = CompactSourcePreflight::discover_live_data_blocks(reader).await?;
        let snapshots = reader
            .source_snapshots_for_block_ids(&live_data_blocks.block_ids)
            .await?;

        Ok(Self {
            preflight,
            live_data_blocks,
            snapshots,
        })
    }
}

fn resolve_live_data_block_ids_via_index(
    index: &era_index::IndexReader,
    live_hashes: &[ChunkHash],
) -> Result<Vec<BlockId>> {
    let mut out = Vec::with_capacity(live_hashes.len());
    for hash in live_hashes {
        let loc = index.lookup(hash)?.ok_or_else(|| {
            EraError::IntegrityError(format!(
                "embedded index missing live catalog hash {} during compact preflight",
                hash
            ))
        })?;
        out.push(loc.block_id);
    }

    out.sort_by_key(|b| b.sequence());
    out.dedup_by_key(|b| b.sequence());
    Ok(out)
}
