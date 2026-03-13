use crate::directory::{CompactDirectory, CompactDirectoryEntry};
use crate::footer::CompactVolumeFooter;
use crate::header::CompactSuperHeader;
use crate::stripe::CompactShardRecordHeader;
use era_common::{EraError, Result};
use std::fs;
use std::io::{BufWriter, Write};
use std::path::Path;

pub fn prepare_bundle_staging(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(EraError::InvalidConfig(format!(
            "staging path already exists: {}",
            path.display()
        )));
    }
    fs::create_dir_all(path)?;
    Ok(())
}

pub struct CompactVolumeWriter {
    file: BufWriter<fs::File>,
    header_bytes: Vec<u8>,
    position: u64,
    directory_entries: Vec<CompactDirectoryEntry>,
    catalog_offset: u64,
    catalog_size: u32,
    catalog_block_id: u64,
    index_offset: u64,
    index_size: u32,
    index_block_id: u64,
    finalized: bool,
}

impl CompactVolumeWriter {
    pub fn create(path: &Path, header: &CompactSuperHeader) -> Result<Self> {
        let header_bytes = header.to_bytes()?;
        let file = fs::File::create(path)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(&header_bytes)?;
        let position = header_bytes.len() as u64;

        Ok(Self {
            file: writer,
            header_bytes,
            position,
            directory_entries: Vec::new(),
            catalog_offset: 0,
            catalog_size: 0,
            catalog_block_id: 0,
            index_offset: 0,
            index_size: 0,
            index_block_id: 0,
            finalized: false,
        })
    }

    pub fn write_shard_record(
        &mut self,
        shard_header: &CompactShardRecordHeader,
        payload: &[u8],
    ) -> Result<(u64, u64)> {
        let offset = self.position;
        let header_bytes = shard_header.to_bytes()?;
        let header_len = u32::try_from(header_bytes.len())
            .map_err(|_| EraError::InvalidFormat("shard header exceeds u32::MAX".into()))?;

        self.file.write_all(&header_len.to_le_bytes())?;
        self.file.write_all(&header_bytes)?;
        self.file.write_all(payload)?;

        let total_written = 4 + header_bytes.len() as u64 + payload.len() as u64;
        self.position += total_written;
        Ok((offset, total_written))
    }

    pub fn write_replicated_block(&mut self, block_id: u64, data: &[u8]) -> Result<(u64, u32)> {
        let offset = self.position;
        let size = u32::try_from(data.len())
            .map_err(|_| EraError::InvalidFormat("replicated block exceeds u32::MAX".into()))?;

        let len_bytes = size.to_le_bytes();
        self.file.write_all(&len_bytes)?;
        let block_id_bytes = block_id.to_le_bytes();
        self.file.write_all(&block_id_bytes)?;
        self.file.write_all(data)?;

        self.position += 4 + 8 + data.len() as u64;
        Ok((offset, size))
    }

    pub fn set_catalog(&mut self, offset: u64, size: u32, block_id: u64) {
        self.catalog_offset = offset;
        self.catalog_size = size;
        self.catalog_block_id = block_id;
    }

    pub fn set_index(&mut self, offset: u64, size: u32, block_id: u64) {
        self.index_offset = offset;
        self.index_size = size;
        self.index_block_id = block_id;
    }

    pub fn add_directory_entry(&mut self, entry: CompactDirectoryEntry) {
        self.directory_entries.push(entry);
    }

    pub fn position(&self) -> u64 {
        self.position
    }

    pub fn finalize(mut self) -> Result<()> {
        if self.finalized {
            return Err(EraError::InvalidFormat(
                "compact volume already finalized".into(),
            ));
        }
        self.finalized = true;

        let data_region_end = self.position;
        let meta_region_offset = data_region_end;

        let directory = CompactDirectory::new(self.directory_entries)?;
        let directory_bytes =
            bincode::serde::encode_to_vec(&directory, bincode::config::standard())
                .map_err(|e| EraError::Serialization(format!("directory encode failed: {e}")))?;

        let directory_offset = self.position;
        let directory_size = u32::try_from(directory_bytes.len())
            .map_err(|_| EraError::InvalidFormat("directory exceeds u32::MAX".into()))?;
        let directory_count = u32::try_from(directory.entries().len()).map_err(|_| {
            EraError::InvalidFormat("directory entry count exceeds u32::MAX".into())
        })?;

        self.file.write_all(&directory_bytes)?;
        self.position += directory_bytes.len() as u64;

        let header_hash = *blake3::hash(&self.header_bytes).as_bytes();
        let directory_hash = *blake3::hash(&directory_bytes).as_bytes();

        let footer = CompactVolumeFooter::new(
            data_region_end,
            meta_region_offset,
            directory_offset,
            directory_size,
            directory_count,
            self.catalog_offset,
            self.catalog_size,
            self.catalog_block_id,
            self.index_offset,
            self.index_size,
            self.index_block_id,
            header_hash,
            directory_hash,
        )?;

        let footer_bytes = footer.to_bytes()?;
        let footer_size = footer_bytes.len() as u32;
        self.file.write_all(&footer_bytes)?;
        self.file.write_all(&footer_size.to_le_bytes())?;

        self.file.flush()?;

        Ok(())
    }
}
