//! # Packed Chunk - 小文件打包支持
//!
//! 将多个小文件打包到单个chunk中，以减少加密和KDF开销。
//!
//! ## 格式设计
//!
//! ```text
//! +------------------+
//! | PackedHeader     | 17 bytes
//! +------------------+
//! | PackedEntry[0]   | 48 bytes
//! | PackedEntry[1]   |
//! | ...              |
//! +------------------+
//! | File[0] data     |
//! | File[1] data     |
//! | ...              |
//! +------------------+
//! ```

use std::io::{self, Cursor, Read, Write};

const PACKED_MAGIC: &[u8; 4] = b"PACK";
const PACKED_VERSION: u8 = 1;

/// 打包的chunk头部
#[derive(Debug, Clone)]
pub struct PackedHeader {
    pub magic: [u8; 4],
    pub version: u8,
    pub entry_count: u32,
    pub total_data_size: u64,
}

impl PackedHeader {
    pub fn new(entry_count: u32, total_data_size: u64) -> Self {
        Self {
            magic: *PACKED_MAGIC,
            version: PACKED_VERSION,
            entry_count,
            total_data_size,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(17);
        buf.extend_from_slice(&self.magic);
        buf.push(self.version);
        buf.extend_from_slice(&self.entry_count.to_le_bytes());
        buf.extend_from_slice(&self.total_data_size.to_le_bytes());
        buf
    }

    pub fn deserialize(data: &[u8]) -> io::Result<Self> {
        if data.len() < 17 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Packed header too short",
            ));
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[0..4]);

        if &magic != PACKED_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid packed magic: {:?}", magic),
            ));
        }

        let version = data[4];
        if version != PACKED_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported packed version: {}", version),
            ));
        }

        let entry_count = u32::from_le_bytes([data[5], data[6], data[7], data[8]]);
        let total_data_size = u64::from_le_bytes([
            data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16],
        ]);

        Ok(Self {
            magic,
            version,
            entry_count,
            total_data_size,
        })
    }
}

/// 单个文件在pack中的条目
#[derive(Debug, Clone)]
pub struct PackedEntry {
    /// 在data section中的偏移
    pub offset: u64,
    /// 文件大小
    pub size: u64,
    /// BLAKE3 checksum
    pub checksum: [u8; 32],
}

impl PackedEntry {
    pub fn new(offset: u64, size: u64, checksum: [u8; 32]) -> Self {
        Self {
            offset,
            size,
            checksum,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(48);
        buf.extend_from_slice(&self.offset.to_le_bytes());
        buf.extend_from_slice(&self.size.to_le_bytes());
        buf.extend_from_slice(&self.checksum);
        buf
    }

    pub fn deserialize(data: &[u8]) -> io::Result<Self> {
        if data.len() < 48 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Packed entry too short",
            ));
        }

        let offset = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let size = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&data[16..48]);

        Ok(Self {
            offset,
            size,
            checksum,
        })
    }
}

/// 打包的chunk
#[derive(Debug)]
pub struct PackedChunk {
    header: PackedHeader,
    entries: Vec<PackedEntry>,
    data: Vec<u8>,
}

impl PackedChunk {
    /// 创建新的空packed chunk
    pub fn new() -> Self {
        Self {
            header: PackedHeader::new(0, 0),
            entries: Vec::new(),
            data: Vec::new(),
        }
    }

    /// 添加一个文件到pack中
    pub fn add_file(&mut self, file_data: &[u8]) -> io::Result<()> {
        let offset = self.data.len() as u64;
        let size = file_data.len() as u64;

        // 计算BLAKE3校验和
        let checksum = blake3::hash(file_data);

        // 添加条目
        self.entries
            .push(PackedEntry::new(offset, size, *checksum.as_bytes()));

        // 添加数据
        self.data.extend_from_slice(file_data);

        // 更新头部
        self.header.entry_count = self.entries.len() as u32;
        self.header.total_data_size = self.data.len() as u64;

        Ok(())
    }

    /// 序列化整个packed chunk
    pub fn serialize(&self) -> io::Result<Vec<u8>> {
        let header_size = 17;
        let entries_size = self.entries.len() * 48;
        let total_size = header_size + entries_size + self.data.len();

        let mut buf = Vec::with_capacity(total_size);

        // 写入header
        buf.write_all(&self.header.serialize())?;

        // 写入所有entries
        for entry in &self.entries {
            buf.write_all(&entry.serialize())?;
        }

        // 写入数据
        buf.write_all(&self.data)?;

        Ok(buf)
    }

    /// 反序列化packed chunk
    pub fn deserialize(data: &[u8]) -> io::Result<Self> {
        let mut cursor = Cursor::new(data);

        // 读取header
        let mut header_bytes = [0u8; 17];
        cursor.read_exact(&mut header_bytes)?;
        let header = PackedHeader::deserialize(&header_bytes)?;

        // 读取entries
        let mut entries = Vec::with_capacity(header.entry_count as usize);
        for _ in 0..header.entry_count {
            let mut entry_bytes = [0u8; 48];
            cursor.read_exact(&mut entry_bytes)?;
            entries.push(PackedEntry::deserialize(&entry_bytes)?);
        }

        // 读取数据
        let mut file_data = vec![0u8; header.total_data_size as usize];
        cursor.read_exact(&mut file_data)?;

        Ok(Self {
            header,
            entries,
            data: file_data,
        })
    }

    /// 提取特定文件的数据
    pub fn extract_file(&self, file_index: usize) -> io::Result<Vec<u8>> {
        if file_index >= self.entries.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("File index {} out of bounds", file_index),
            ));
        }

        let entry = &self.entries[file_index];
        let start = entry.offset as usize;
        let end = start + entry.size as usize;

        if end > self.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "File data extends beyond packed chunk",
            ));
        }

        let file_data = self.data[start..end].to_vec();

        // 验证校验和
        let checksum = blake3::hash(&file_data);
        if checksum.as_bytes() != &entry.checksum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Checksum mismatch",
            ));
        }

        Ok(file_data)
    }

    /// 获取文件数量
    pub fn file_count(&self) -> usize {
        self.entries.len()
    }

    /// 获取总数据大小
    pub fn total_size(&self) -> u64 {
        self.header.total_data_size
    }
}

impl Default for PackedChunk {
    fn default() -> Self {
        Self::new()
    }
}

/// 便捷函数：打包多个文件
pub fn pack_files(files: &[&[u8]]) -> io::Result<Vec<u8>> {
    let mut packed = PackedChunk::new();

    for file_data in files {
        packed.add_file(file_data)?;
    }

    packed.serialize()
}

/// 便捷函数：从packed data中提取特定文件
pub fn unpack_file(packed_data: &[u8], file_index: usize) -> io::Result<Vec<u8>> {
    let packed = PackedChunk::deserialize(packed_data)?;
    packed.extract_file(file_index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packed_header_roundtrip() {
        let header = PackedHeader::new(10, 1024);
        let serialized = header.serialize();
        let deserialized = PackedHeader::deserialize(&serialized).unwrap();

        assert_eq!(header.magic, deserialized.magic);
        assert_eq!(header.version, deserialized.version);
        assert_eq!(header.entry_count, deserialized.entry_count);
        assert_eq!(header.total_data_size, deserialized.total_data_size);
    }

    #[test]
    fn test_packed_entry_roundtrip() {
        let checksum = blake3::hash(b"test data");
        let entry = PackedEntry::new(0, 100, *checksum.as_bytes());
        let serialized = entry.serialize();
        let deserialized = PackedEntry::deserialize(&serialized).unwrap();

        assert_eq!(entry.offset, deserialized.offset);
        assert_eq!(entry.size, deserialized.size);
        assert_eq!(entry.checksum, deserialized.checksum);
    }

    #[test]
    fn test_pack_single_file() {
        let mut packed = PackedChunk::new();
        let data = b"Hello, world!";
        packed.add_file(data).unwrap();

        assert_eq!(packed.file_count(), 1);
        assert_eq!(packed.total_size(), data.len() as u64);

        let extracted = packed.extract_file(0).unwrap();
        assert_eq!(&extracted, data);
    }

    #[test]
    fn test_pack_multiple_files() {
        let mut packed = PackedChunk::new();
        let files = vec![b"file1".as_slice(), b"file2".as_slice(), b"file3".as_slice()];

        for file in &files {
            packed.add_file(file).unwrap();
        }

        assert_eq!(packed.file_count(), 3);

        for (i, expected) in files.iter().enumerate() {
            let extracted = packed.extract_file(i).unwrap();
            assert_eq!(&extracted, expected);
        }
    }

    #[test]
    fn test_pack_roundtrip() {
        let mut packed = PackedChunk::new();
        packed.add_file(b"file1").unwrap();
        packed.add_file(b"file2").unwrap();

        let serialized = packed.serialize().unwrap();
        let deserialized = PackedChunk::deserialize(&serialized).unwrap();

        assert_eq!(packed.file_count(), deserialized.file_count());
        assert_eq!(packed.total_size(), deserialized.total_size());

        let extracted1 = deserialized.extract_file(0).unwrap();
        let extracted2 = deserialized.extract_file(1).unwrap();
        assert_eq!(&extracted1, b"file1");
        assert_eq!(&extracted2, b"file2");
    }

    #[test]
    fn test_pack_files_convenience() {
        let files = &[b"file1".as_slice(), b"file2".as_slice()];
        let packed_data = pack_files(files).unwrap();

        let file1 = unpack_file(&packed_data, 0).unwrap();
        let file2 = unpack_file(&packed_data, 1).unwrap();

        assert_eq!(&file1, b"file1");
        assert_eq!(&file2, b"file2");
    }

    #[test]
    fn test_checksum_verification() {
        let mut packed = PackedChunk::new();
        packed.add_file(b"test data").unwrap();

        let mut serialized = packed.serialize().unwrap();

        // 篡改数据
        let data_offset = 17 + 48; // header + entry
        serialized[data_offset] ^= 0xFF;

        let deserialized = PackedChunk::deserialize(&serialized).unwrap();
        let result = deserialized.extract_file(0);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
}
