use super::{ArchiveReader, CatalogBlockLocator};
use era_common::{
    compute_shard_crc, BlockHeader, BlockId, BlockLocation, BlockType, EraError, Result,
};
use era_crypto::{AeadContext, XChaCha20Poly1305Context};

pub(crate) struct CatalogRepair {
    pub(crate) sequence: u16,
    pub(crate) offset: u64,
    pub(crate) bytes: Vec<u8>,
}

struct CopyLayout {
    locator: CatalogBlockLocator,
    lengths: Vec<u32>,
}

impl CopyLayout {
    fn span(&self) -> u64 {
        self.lengths
            .iter()
            .map(|&len| BlockHeader::SIZE as u64 + u64::from(len))
            .sum()
    }
}

impl ArchiveReader {
    pub(crate) async fn plan_catalog_repairs(&self) -> Result<Vec<CatalogRepair>> {
        let mut damaged = Vec::new();
        let mut source = None;
        for (reader_idx, reader) in self.volume_readers.iter().enumerate() {
            let Some(footer) = reader.footer().filter(|f| f.has_catalog_location()) else {
                continue;
            };
            let primary = CatalogBlockLocator {
                reader_idx,
                offset: footer.catalog_offset(),
                expected_size: Some(footer.catalog_size()),
                block_id: footer.catalog_block_id(),
                require_manifest: false,
            };
            match self.read_catalog_copy(primary).await {
                Ok((_, lengths)) => {
                    source.get_or_insert(CopyLayout {
                        locator: primary,
                        lengths,
                    });
                }
                Err(_) => damaged.push(primary),
            }
        }

        if !damaged.is_empty() && self.manifest.is_none() {
            return Err(EraError::IntegrityError(
                "Primary Catalog repair requires an authenticated manifest".into(),
            ));
        }
        if source.is_none() {
            for &primary in &damaged {
                if let Ok((_, locator, lengths)) = self.recover_ec_catalog_backup(primary).await {
                    let copy = CopyLayout { locator, lengths };
                    if primary.offset.checked_add(copy.span()) == Some(locator.offset) {
                        source = Some(copy);
                        break;
                    }
                }
            }
        }
        let mut repairs = Vec::new();
        for primary in damaged {
            let copy = source.as_ref().ok_or_else(|| {
                EraError::IntegrityError(
                    "No authenticated Catalog copy is available for repair".into(),
                )
            })?;
            repairs.push(self.rebuild_primary_catalog(primary, copy).await?);
        }
        Ok(repairs)
    }

    async fn rebuild_primary_catalog(
        &self,
        primary: CatalogBlockLocator,
        source: &CopyLayout,
    ) -> Result<CatalogRepair> {
        let origin = &self.volume_readers[source.locator.reader_idx];
        let target = &self.volume_readers[primary.reader_idx];
        let sequence = target.header().volume_sequence();
        let count = u32::try_from(source.lengths.len())
            .map_err(|_| EraError::IntegrityError("Catalog chunk count overflow".into()))?;
        let manifest = self.manifest.as_ref().ok_or_else(|| {
            EraError::IntegrityError(
                "Primary Catalog repair requires an authenticated manifest".into(),
            )
        })?;
        let catalog_end = self.catalog_metadata_end(primary.reader_idx, primary.offset)?;
        let valid_range = manifest
            .volume_committed_ends
            .get(usize::from(sequence))
            .is_some_and(|&end| end <= primary.offset && end >= era_volume::DATA_REGION_START);
        let origin_primary_id = origin.footer().map(|f| f.catalog_block_id());
        let same_generation = origin.footer().map(|f| f.manifest_block_id())
            == target.footer().map(|f| f.manifest_block_id());
        let copy_multiplier: u64 = if target.header().config().erasure.is_some() {
            2
        } else {
            1
        };
        if !valid_range
            || !same_generation
            || origin_primary_id != Some(primary.block_id)
            || (source.locator.block_id != primary.block_id
                && primary.block_id.checked_add(count) != Some(source.locator.block_id))
            || primary.expected_size != source.lengths.first().copied()
            || !source
                .span()
                .checked_mul(copy_multiplier)
                .and_then(|span| primary.offset.checked_add(span))
                .is_some_and(|end| end <= catalog_end)
        {
            return Err(EraError::IntegrityError(format!(
                "Cannot establish original Catalog block spans for volume {sequence} (offset {}, metadata end {catalog_end}, footer size {:?}, source sizes {:?}, source primary {origin_primary_id:?}, target primary {}, committed end {:?})",
                primary.offset, primary.expected_size, source.lengths, primary.block_id,
                manifest.volume_committed_ends.get(usize::from(sequence)),
            )));
        }

        let mut bytes = Vec::new();
        let mut offset = source.locator.offset;
        for (ordinal, &len) in (0..count).zip(&source.lengths) {
            let source_id = source
                .locator
                .block_id
                .checked_add(ordinal)
                .ok_or_else(|| {
                    EraError::IntegrityError("Catalog source block ID overflow".into())
                })?;
            let target_id = primary.block_id.checked_add(ordinal).ok_or_else(|| {
                EraError::IntegrityError("Catalog target block ID overflow".into())
            })?;
            let location =
                BlockLocation::single(origin.header().volume_id(), source_id, offset, len);
            let (kind, block) = origin.read_typed_block(&location).await?;
            if kind != BlockType::Catalog || block.compressed_size != len {
                return Err(EraError::IntegrityError(
                    "Catalog source span changed during repair".into(),
                ));
            }
            let source_key = self.session.derive_block_key(
                &self.volume_key,
                u64::from(source_id),
                &self.nonce_context,
            )?;
            let source_aead =
                XChaCha20Poly1305Context::from_derived_key(&source_key.to_derived_key()?)?;
            let compressed = source_aead.decrypt_with_context_for_type(
                &self.nonce_context,
                &self.archive_id,
                self.epoch_id,
                u32::from(origin.header().volume_sequence()),
                BlockType::Catalog,
                BlockId::new(u64::from(source_id)),
                &block.data,
            )?;
            let target_key = self.session.derive_block_key(
                &self.volume_key,
                u64::from(target_id),
                &self.nonce_context,
            )?;
            let target_aead =
                XChaCha20Poly1305Context::from_derived_key(&target_key.to_derived_key()?)?;
            // Finalization compresses the same framed chunk for every matching copy.
            // Keep those exact compressed bytes; recompressing could change nonce plaintext.
            let ciphertext = target_aead.encrypt_with_context_for_type(
                &self.nonce_context,
                &self.archive_id,
                self.epoch_id,
                u32::from(sequence),
                BlockType::Catalog,
                BlockId::new(u64::from(target_id)),
                &compressed,
            )?;
            if usize::try_from(len).ok() != Some(ciphertext.len()) {
                return Err(EraError::IntegrityError(
                    "Rebuilt Catalog block changed length".into(),
                ));
            }
            let header = BlockHeader::new(BlockType::Catalog, len, compute_shard_crc(&ciphertext));
            bytes.extend_from_slice(&header.to_bytes());
            bytes.extend_from_slice(&ciphertext);
            offset += BlockHeader::SIZE as u64 + u64::from(len);
        }
        Ok(CatalogRepair {
            sequence,
            offset: primary.offset,
            bytes,
        })
    }
}
