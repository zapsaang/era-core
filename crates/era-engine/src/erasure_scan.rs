use bytes::Bytes;
use era_common::{ArchiveConfig, EraError, MatrixDistributionStrategy, Result, ShardHeader};
use era_volume::{DistributionCalculator, VolumeReader};

pub(crate) struct MatrixScanGeometry {
    width: usize,
    strategy: MatrixDistributionStrategy,
    readers_by_sequence: Vec<Option<usize>>,
    generation_start: usize,
}

impl MatrixScanGeometry {
    pub(crate) fn new(
        config: &ArchiveConfig,
        expected_volumes: usize,
        sequences: &[usize],
        strategy: MatrixDistributionStrategy,
    ) -> Result<Self> {
        let mut volume_count = expected_volumes;
        for &sequence in sequences {
            if sequence > usize::from(u16::MAX) {
                return Err(EraError::InvalidFormat(
                    "Volume sequence exceeds u16".into(),
                ));
            }
            volume_count = volume_count.max(sequence + 1);
        }
        if volume_count > usize::from(u16::MAX) + 1 {
            return Err(EraError::InvalidFormat(
                "Volume count exceeds sequence range".into(),
            ));
        }

        let target = config.distribution.target_volumes;
        let width = if target == 0 {
            config.erasure.map_or(1, |ec| ec.total_shards())
        } else {
            target
        };
        // Legacy single-generation headers advertised K+M even for a narrower pool.
        let width = if expected_volumes > 0 {
            width.min(volume_count)
        } else {
            width
        };
        if width == 0 || width > usize::from(u16::MAX) {
            return Err(EraError::InvalidFormat(
                "Invalid EC generation width".into(),
            ));
        }

        let mut readers_by_sequence = vec![None; volume_count];
        for (reader_idx, &sequence) in sequences.iter().enumerate() {
            if readers_by_sequence[sequence].replace(reader_idx).is_some() {
                return Err(EraError::InvalidFormat(format!(
                    "Duplicate volume sequence {sequence}"
                )));
            }
        }
        Ok(Self {
            width,
            strategy,
            readers_by_sequence,
            generation_start: 0,
        })
    }

    pub(crate) fn generation_width(&self) -> usize {
        self.width
    }

    pub(crate) fn advance_to_data(&mut self, offsets: &[u64], ends: &[u64]) -> Result<bool> {
        while self.generation_start < self.readers_by_sequence.len() {
            let end = (self.generation_start + self.width).min(self.readers_by_sequence.len());
            let mut readers = self.readers_by_sequence[self.generation_start..end]
                .iter()
                .flatten();
            let Some(&first) = readers.next() else {
                // The global stripe number after a wholly missing generation is unknowable.
                let generation = self.generation_start / self.width;
                self.finish();
                return Err(EraError::ErasureError(format!(
                    "No surviving volumes in EC generation {generation}"
                )));
            };
            if offsets[first] < ends[first] || readers.any(|&idx| offsets[idx] < ends[idx]) {
                return Ok(true);
            }
            self.generation_start += self.width;
        }
        Ok(false)
    }

    pub(crate) fn volume_sequence(&self, shard: usize, global_stripe: u64) -> Result<usize> {
        Ok(self.generation_start
            + self
                .strategy
                .calculate_volume(shard, global_stripe, self.width)?)
    }

    pub(crate) fn reader_index(&self, sequence: usize) -> Option<usize> {
        self.readers_by_sequence.get(sequence).copied().flatten()
    }

    pub(crate) fn finish(&mut self) {
        self.generation_start = self.readers_by_sequence.len();
    }

    pub(crate) fn has_generation(&self) -> bool {
        self.generation_start < self.readers_by_sequence.len()
    }
}

pub(crate) async fn read_matrix_shard_header<R: era_storage::StorageReader>(
    reader: &VolumeReader<R>,
    offset: u64,
    end: u64,
    prefix_len: usize,
) -> Option<(Bytes, ShardHeader)> {
    let len = prefix_len + ShardHeader::SIZE;
    let len_u64 = u64::try_from(len).ok()?;
    if len_u64 > end.saturating_sub(offset) {
        return None;
    }
    match reader.read_raw(offset, len).await {
        Ok(bytes) if bytes.len() == len => {
            let header = ShardHeader::from_bytes(&bytes[prefix_len..])?;
            Some((bytes.slice(..prefix_len), header))
        }
        Ok(_) | Err(_) => None,
    }
}

pub(crate) fn parse_stripe_lengths(prefix_bytes: &[u8], data_shards: usize) -> Vec<u32> {
    let mut lengths = Vec::with_capacity(data_shards);
    for chunk in prefix_bytes.as_chunks::<4>().0 {
        lengths.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    lengths
}

pub(crate) fn reconcile_stripe_prefixes(
    prefix_copies: &[Bytes],
    data_shards: usize,
) -> Option<Vec<u32>> {
    if prefix_copies.len() < 2 {
        return None;
    }

    let mut counts: std::collections::HashMap<&[u8], usize> = std::collections::HashMap::new();
    for copy in prefix_copies {
        *counts.entry(copy.as_ref()).or_insert(0) += 1;
    }

    let mut best_count: usize = 0;
    for &count in counts.values() {
        if count >= 2 && count > best_count {
            best_count = count;
        }
    }
    if best_count < 2 {
        return None;
    }

    let mut best: Option<&[u8]> = None;
    for (bytes, count) in counts {
        if count == best_count {
            if best.is_some() {
                return None;
            }
            best = Some(bytes);
        }
    }

    best.map(|bytes| parse_stripe_lengths(bytes, data_shards))
}

pub(crate) fn parity_bound_from_lengths(stripe_lengths: Option<&[u32]>) -> Option<u32> {
    let max_stripe = stripe_lengths?.iter().copied().max()?;
    Some(if max_stripe.is_multiple_of(2) {
        max_stripe
    } else {
        max_stripe.checked_add(1)?
    })
}

pub(crate) fn even_aligned_shard_size(max_len: usize) -> usize {
    if max_len.is_multiple_of(2) {
        max_len
    } else {
        max_len + 1
    }
}

pub(crate) fn normalize_data_lengths(
    data_lengths: &mut [Option<u32>],
    stripe_lengths: Option<&[u32]>,
    max_len: &mut usize,
) {
    if let Some(lengths) = stripe_lengths {
        if let Some(stripe_max) = lengths.iter().copied().max() {
            if stripe_max as usize > *max_len {
                *max_len = stripe_max as usize;
            }
        }
        for (idx, len) in lengths.iter().copied().enumerate() {
            if idx < data_lengths.len() && data_lengths[idx].is_none() && len > 0 {
                data_lengths[idx] = Some(len);
            }
        }
    }
}

pub(crate) fn erasure_data_end<R: era_storage::StorageReader>(
    reader: &era_volume::VolumeReader<R>,
) -> u64 {
    let (_, end) = reader.data_region();
    let Some(footer) = reader.footer() else {
        return end;
    };

    let mut limit = if footer.has_catalog_location() {
        end.min(footer.catalog_offset())
    } else {
        end
    };

    if footer.has_index() && footer.index_offset() < limit {
        limit = footer.index_offset();
    }

    if footer.has_manifest() {
        limit = limit.min(footer.manifest_offset());
    }

    let ckpt_off = footer.last_checkpoint_offset();
    if ckpt_off > 0 && ckpt_off < limit {
        limit = ckpt_off;
    }

    limit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_stripe_lengths() {
        let bytes = [100u8, 0, 0, 0, 200, 0, 0, 0];
        assert_eq!(parse_stripe_lengths(&bytes, 2), vec![100, 200]);
    }

    #[test]
    fn test_reconcile_stripe_prefixes_prefers_repeated_copy() {
        let true_prefix = Bytes::from(vec![100u8, 0, 0, 0, 200, 0, 0, 0]);
        let corrupted = Bytes::from(vec![99u8, 0, 0, 0, 200, 0, 0, 0]);
        let copies = vec![corrupted.clone(), true_prefix.clone(), true_prefix.clone()];
        assert_eq!(reconcile_stripe_prefixes(&copies, 2), Some(vec![100, 200]));
    }

    #[test]
    fn test_reconcile_stripe_prefixes_returns_none_without_duplicate_agreement() {
        let a = Bytes::from(vec![1u8, 0, 0, 0]);
        let b = Bytes::from(vec![2u8, 0, 0, 0]);
        let c = Bytes::from(vec![3u8, 0, 0, 0]);
        let copies = vec![a, b, c];
        assert_eq!(reconcile_stripe_prefixes(&copies, 1), None);
    }

    #[test]
    fn test_reconcile_stripe_prefixes_returns_none_for_single_copy() {
        let copies = vec![Bytes::from(vec![1u8, 0, 0, 0])];
        assert_eq!(reconcile_stripe_prefixes(&copies, 1), None);
    }

    #[test]
    fn test_reconcile_stripe_prefixes_returns_none_on_two_way_tie() {
        let a = Bytes::from(vec![1u8, 0, 0, 0]);
        let b = Bytes::from(vec![2u8, 0, 0, 0]);
        let copies = vec![a.clone(), a.clone(), b.clone(), b.clone()];
        assert_eq!(reconcile_stripe_prefixes(&copies, 1), None);
    }

    #[test]
    fn test_reconcile_stripe_prefixes_returns_none_on_three_way_tie() {
        let a = Bytes::from(vec![1u8, 0, 0, 0]);
        let b = Bytes::from(vec![2u8, 0, 0, 0]);
        let c = Bytes::from(vec![3u8, 0, 0, 0]);
        let copies = vec![
            a.clone(),
            b.clone(),
            c.clone(),
            a.clone(),
            b.clone(),
            c.clone(),
        ];
        assert_eq!(reconcile_stripe_prefixes(&copies, 1), None);
    }

    #[test]
    fn test_reconcile_stripe_prefixes_exactly_two_identical_copies_wins() {
        let a = Bytes::from(vec![1u8, 0, 0, 0]);
        let b = Bytes::from(vec![2u8, 0, 0, 0]);
        let c = Bytes::from(vec![3u8, 0, 0, 0]);
        let copies = vec![a.clone(), a.clone(), b, c];
        assert_eq!(reconcile_stripe_prefixes(&copies, 1), Some(vec![1]));
    }

    #[test]
    fn test_reconcile_stripe_prefixes_wins_despite_lower_tie() {
        let a = Bytes::from(vec![1u8, 0, 0, 0]);
        let b = Bytes::from(vec![2u8, 0, 0, 0]);
        let c = Bytes::from(vec![3u8, 0, 0, 0]);
        let copies = vec![
            a.clone(),
            a.clone(),
            b.clone(),
            b.clone(),
            c.clone(),
            c.clone(),
            c.clone(),
        ];
        assert_eq!(reconcile_stripe_prefixes(&copies, 1), Some(vec![3]));
    }

    #[test]
    fn test_reconcile_stripe_prefixes_wins_despite_later_lower_tie() {
        let a = Bytes::from(vec![1u8, 0, 0, 0]);
        let b = Bytes::from(vec![2u8, 0, 0, 0]);
        let c = Bytes::from(vec![3u8, 0, 0, 0]);
        let copies = vec![
            a.clone(),
            a.clone(),
            a.clone(),
            b.clone(),
            b.clone(),
            c.clone(),
            c.clone(),
        ];
        assert_eq!(reconcile_stripe_prefixes(&copies, 1), Some(vec![1]));
    }

    #[test]
    fn test_parity_bound_rounds_up_to_even_max_data_length() {
        assert_eq!(parity_bound_from_lengths(Some(&[100, 200])), Some(200));
        assert_eq!(parity_bound_from_lengths(Some(&[100, 201])), Some(202));
    }

    #[test]
    fn test_parity_bound_from_lengths_returns_none_for_empty() {
        assert_eq!(parity_bound_from_lengths(Some(&[])), None);
        assert_eq!(parity_bound_from_lengths(None), None);
    }

    #[test]
    fn test_parity_bound_from_lengths_does_not_overflow_on_u32_max() {
        assert_eq!(parity_bound_from_lengths(Some(&[u32::MAX])), None);
        assert_eq!(parity_bound_from_lengths(Some(&[100, u32::MAX])), None);
    }

    #[test]
    fn test_even_aligned_shard_size() {
        assert_eq!(even_aligned_shard_size(100), 100);
        assert_eq!(even_aligned_shard_size(101), 102);
        assert_eq!(even_aligned_shard_size(0), 0);
    }

    #[test]
    fn test_data_length_normalization_backfills_missing_data_lengths_from_consensus_prefix() {
        let mut data_lengths = vec![Some(50u32), None, None];
        let mut max_len = 50usize;
        normalize_data_lengths(&mut data_lengths, Some(&[50, 100, 200]), &mut max_len);
        assert_eq!(max_len, 200);
        assert_eq!(data_lengths, vec![Some(50), Some(100), Some(200)]);
    }

    #[test]
    fn test_data_length_normalization_no_panic_when_stripe_lengths_none() {
        let mut data_lengths = vec![None, None];
        let mut max_len = 0usize;
        normalize_data_lengths(&mut data_lengths, None, &mut max_len);
        assert_eq!(max_len, 0);
        assert_eq!(data_lengths, vec![None, None]);
    }
}
