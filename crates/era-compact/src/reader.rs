use crate::directory::CompactDirectory;
use crate::footer::CompactVolumeFooter;
use crate::header::CompactSuperHeader;
use crate::stripe::CompactShardRecordHeader;
use era_common::{EraError, Result};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub fn is_compact_bundle_path(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()) == Some("erac") && path.is_dir()
}

pub fn reject_legacy_era_magic(data: &[u8]) -> Result<()> {
    if data.starts_with(&era_volume::MAGIC) {
        return Err(era_common::EraError::InvalidMagic);
    }
    Ok(())
}

pub struct CompactVolumeReader {
    file: fs::File,
    header: CompactSuperHeader,
    footer: CompactVolumeFooter,
    directory: CompactDirectory,
}

impl CompactVolumeReader {
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = fs::File::open(path)?;
        let file_len = file.metadata()?.len();

        if file_len < 4 {
            return Err(EraError::InvalidFormat("compact volume too small".into()));
        }

        file.seek(SeekFrom::End(-4))?;
        let mut footer_size_buf = [0u8; 4];
        file.read_exact(&mut footer_size_buf)?;
        let footer_size = u32::from_le_bytes(footer_size_buf) as u64;

        if footer_size > crate::MAX_COMPACT_FOOTER_SIZE {
            return Err(EraError::InvalidFormat(format!(
                "compact footer size {} exceeds limit {}",
                footer_size,
                crate::MAX_COMPACT_FOOTER_SIZE
            )));
        }

        if footer_size + 4 > file_len {
            return Err(EraError::InvalidFormat(
                "compact footer size exceeds file".into(),
            ));
        }

        let footer_offset = file_len - 4 - footer_size;
        file.seek(SeekFrom::Start(footer_offset))?;
        let mut footer_buf = vec![0u8; footer_size as usize];
        file.read_exact(&mut footer_buf)?;
        let footer = CompactVolumeFooter::from_bytes(&footer_buf)?;

        let max_header_read = 64 * 1024_usize;
        let mut header_buf = vec![0u8; max_header_read.min(file_len as usize)];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut header_buf)?;
        let header = CompactSuperHeader::from_bytes(&header_buf)?;

        let header_bytes = header.to_bytes()?;
        let computed_header_hash = *blake3::hash(&header_bytes).as_bytes();
        if &computed_header_hash != footer.header_hash() {
            return Err(EraError::IntegrityError(
                "compact header hash mismatch".into(),
            ));
        }

        let dir_offset = footer.directory_offset();
        let dir_size = footer.directory_size() as usize;
        if dir_size > crate::MAX_COMPACT_DIRECTORY_SIZE {
            return Err(EraError::InvalidFormat(format!(
                "compact directory size {} exceeds limit {}",
                dir_size,
                crate::MAX_COMPACT_DIRECTORY_SIZE
            )));
        }
        file.seek(SeekFrom::Start(dir_offset))?;
        let mut dir_buf = vec![0u8; dir_size];
        file.read_exact(&mut dir_buf)?;

        let computed_dir_hash = *blake3::hash(&dir_buf).as_bytes();
        if &computed_dir_hash != footer.directory_hash() {
            return Err(EraError::IntegrityError(
                "compact directory hash mismatch".into(),
            ));
        }

        let (directory, _): (CompactDirectory, usize) =
            bincode::serde::decode_from_slice(&dir_buf, bincode::config::standard())
                .map_err(|e| EraError::Deserialization(format!("directory decode failed: {e}")))?;

        Ok(Self {
            file,
            header,
            footer,
            directory,
        })
    }

    pub fn read_shard_at(&mut self, offset: u64) -> Result<(CompactShardRecordHeader, Vec<u8>)> {
        self.file.seek(SeekFrom::Start(offset))?;

        let mut len_buf = [0u8; 4];
        self.file.read_exact(&mut len_buf)?;
        let header_len = u32::from_le_bytes(len_buf) as usize;

        if header_len > 1024 * 1024 {
            return Err(EraError::InvalidFormat(
                "shard header length exceeds 1MB".into(),
            ));
        }

        let mut header_buf = vec![0u8; header_len];
        self.file.read_exact(&mut header_buf)?;
        let shard_header = CompactShardRecordHeader::from_bytes(&header_buf)?;

        let payload_len = shard_header.shard_len as usize;
        if payload_len > crate::MAX_COMPACT_SHARD_PAYLOAD {
            return Err(EraError::InvalidFormat(format!(
                "compact shard payload {} exceeds limit {}",
                payload_len,
                crate::MAX_COMPACT_SHARD_PAYLOAD
            )));
        }
        let mut payload = vec![0u8; payload_len];
        self.file.read_exact(&mut payload)?;

        shard_header.validate_payload_crc(&payload)?;

        Ok((shard_header, payload))
    }

    pub fn read_replicated_block_at(&mut self, offset: u64) -> Result<(u64, Vec<u8>)> {
        self.file.seek(SeekFrom::Start(offset))?;

        let mut size_buf = [0u8; 4];
        self.file.read_exact(&mut size_buf)?;
        let size = u32::from_le_bytes(size_buf) as usize;

        if size > crate::MAX_COMPACT_REPLICATED_BLOCK {
            return Err(EraError::InvalidFormat(format!(
                "compact replicated block size {} exceeds limit {}",
                size,
                crate::MAX_COMPACT_REPLICATED_BLOCK
            )));
        }

        let mut block_id_buf = [0u8; 8];
        self.file.read_exact(&mut block_id_buf)?;
        let block_id = u64::from_le_bytes(block_id_buf);

        let mut data = vec![0u8; size];
        self.file.read_exact(&mut data)?;

        Ok((block_id, data))
    }

    pub fn header(&self) -> &CompactSuperHeader {
        &self.header
    }

    pub fn footer(&self) -> &CompactVolumeFooter {
        &self.footer
    }

    pub fn directory(&self) -> &CompactDirectory {
        &self.directory
    }
}
