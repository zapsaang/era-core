//! Checkpoint-aware retained-data boundaries for single-volume append.

use era_common::{BlockHeader, BlockType, EraError, Result};
use era_volume::{Footer, VolumeReader, DATA_REGION_START};

pub(crate) struct RetainedVolume<'a> {
    pub reader: &'a VolumeReader<era_storage::LocalStorageReader>,
    pub footer: &'a Footer,
    pub manifest_committed_end: Option<u64>,
}

pub(crate) struct RetainedDataRegion {
    pub end: u64,
    pub block_count: u32,
    pub block_spans: Vec<(u64, u32)>,
    /// The authenticated legacy horizon includes exactly this terminal checkpoint.
    /// The caller must authenticate it before truncating to `end`.
    pub legacy_terminal_checkpoint: bool,
}

pub(crate) fn extend_data_ends_for_rotation(
    data_ends: &[u64],
    active_width: usize,
) -> Result<Vec<u64>> {
    let rotated_len = data_ends
        .len()
        .checked_add(active_width)
        .ok_or_else(|| EraError::Other("manifest volume count overflow".into()))?;
    let mut rotated = data_ends.to_vec();
    rotated.resize(rotated_len, DATA_REGION_START);
    Ok(rotated)
}

pub(crate) async fn scan_retained_data_region(
    volume: RetainedVolume<'_>,
) -> Result<RetainedDataRegion> {
    const MAX_SCAN_BLOCK_SIZE: u32 = 64 * 1024 * 1024;

    let start = DATA_REGION_START;
    let data_end_offset = volume.footer.data_end_offset();
    let bound = match volume.manifest_committed_end {
        Some(end) => {
            if end < start || end > data_end_offset {
                return Err(EraError::IntegrityError(format!(
                    "Manifest committed end {end} out of bounds [{start}..={data_end_offset}]"
                )));
            }
            end
        }
        None => data_end_offset,
    };

    let mut offset = start;
    let mut block_count = 0u32;
    let mut block_spans = Vec::new();
    let mut legacy_terminal_checkpoint = false;
    while offset < bound {
        if offset + BlockHeader::SIZE as u64 > bound {
            return Err(EraError::CorruptedHeader(format!(
                "Truncated BlockHeader at offset {offset} before retained boundary {bound}"
            )));
        }
        let header_bytes = volume.reader.read_raw(offset, BlockHeader::SIZE).await?;
        let header = BlockHeader::from_bytes(&header_bytes).ok_or_else(|| {
            EraError::CorruptedHeader(format!("Invalid BlockHeader at offset {offset}"))
        })?;
        if header.length == 0 || header.length > MAX_SCAN_BLOCK_SIZE {
            return Err(EraError::CorruptedHeader(format!(
                "Invalid BlockHeader length {} at offset {offset}",
                header.length
            )));
        }
        let next_offset = offset + BlockHeader::SIZE as u64 + u64::from(header.length);
        if next_offset > bound {
            return Err(EraError::CorruptedHeader(format!(
                "Block at offset {offset} extends past retained boundary {bound}"
            )));
        }

        match header.block_type {
            BlockType::Data => {
                block_spans.push((offset, header.length));
                block_count = block_count
                    .checked_add(1)
                    .ok_or_else(|| EraError::InvalidFormat("data block count overflow".into()))?;
                offset = next_offset;
            }
            kind @ (BlockType::IndexPage
            | BlockType::IndexManifest
            | BlockType::Catalog
            | BlockType::LsmManifest
            | BlockType::Checkpoint
            | BlockType::Manifest
            | BlockType::Reserved) => {
                let legacy_end = volume.manifest_committed_end.is_some()
                    && kind == BlockType::Checkpoint
                    && offset == volume.footer.last_checkpoint_offset()
                    && next_offset == bound;
                if legacy_end {
                    legacy_terminal_checkpoint = true;
                    break;
                }
                if volume.manifest_committed_end.is_none() {
                    break;
                }
                return Err(EraError::IntegrityError(format!(
                    "Unexpected non-Data block {kind:?} inside committed data region at offset {offset}"
                )));
            }
        }
    }

    Ok(RetainedDataRegion {
        end: offset,
        block_count,
        block_spans,
        legacy_terminal_checkpoint,
    })
}
