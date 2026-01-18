//! # Packed Chunk - Small File Packing
//!
//! Pack multiple small files into a single chunk to reduce encryption and KDF overhead.
//!
//! ## Format Layout
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

use bytemuck::{Pod, Zeroable};
use std::io::{self, Cursor, Read, Write};

const PACKED_MAGIC: &[u8; 4] = b"PACK";
const PACKED_VERSION: u8 = 1;

/// Packed chunk header
///
/// Uses bytemuck for zero-copy serialization and cross-platform compatibility.
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
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

    /// Zero-copy serialization: returns the raw byte view
    pub fn as_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }

    /// Deserialize from a byte slice
    pub fn from_bytes(data: &[u8]) -> io::Result<Self> {
        if data.len() < std::mem::size_of::<Self>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Packed header too short",
            ));
        }

        let header: Self = *bytemuck::try_from_bytes(&data[..std::mem::size_of::<Self>()])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        if &header.magic != PACKED_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid packed magic: {:?}", header.magic),
            ));
        }

        if header.version != PACKED_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported packed version: {}", header.version),
            ));
        }

        Ok(header)
    }
}

/// Single file entry inside a packed chunk
///
/// Uses bytemuck for zero-copy serialization.
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
pub struct PackedEntry {
    /// Offset in the data section
    pub offset: u64,
    /// File size
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

    /// Zero-copy serialization: returns the raw byte view
    pub fn as_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }

    /// Deserialize from a byte slice
    pub fn from_bytes(data: &[u8]) -> io::Result<Self> {
        if data.len() < std::mem::size_of::<Self>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Packed entry too short",
            ));
        }

        bytemuck::try_from_bytes(&data[..std::mem::size_of::<Self>()])
            .copied()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }
}

/// Packed chunk
#[derive(Debug)]
pub struct PackedChunk {
    header: PackedHeader,
    entries: Vec<PackedEntry>,
    data: Vec<u8>,
}

impl PackedChunk {
    /// Create a new empty packed chunk
    pub fn new() -> Self {
        Self {
            header: PackedHeader::new(0, 0),
            entries: Vec::new(),
            data: Vec::new(),
        }
    }

    /// Add a file to the pack
    pub fn add_file(&mut self, file_data: &[u8]) -> io::Result<()> {
        let offset = self.data.len() as u64;
        let size = file_data.len() as u64;

        // Compute BLAKE3 checksum
        let checksum = blake3::hash(file_data);

        // Add entry
        self.entries
            .push(PackedEntry::new(offset, size, *checksum.as_bytes()));

        // Append data
        self.data.extend_from_slice(file_data);

        // Update header
        self.header.entry_count = self.entries.len() as u32;
        self.header.total_data_size = self.data.len() as u64;

        Ok(())
    }

    /// Serialize the entire packed chunk
    pub fn serialize(&self) -> io::Result<Vec<u8>> {
        let header_size = std::mem::size_of::<PackedHeader>();
        let entries_size = self.entries.len() * std::mem::size_of::<PackedEntry>();
        let total_size = header_size + entries_size + self.data.len();

        let mut buf = Vec::with_capacity(total_size);

        // Write header (zero-copy)
        buf.write_all(self.header.as_bytes())?;

        // Write all entries (zero-copy)
        for entry in &self.entries {
            buf.write_all(entry.as_bytes())?;
        }

        // Write data
        buf.write_all(&self.data)?;

        Ok(buf)
    }

    /// Deserialize a packed chunk
    pub fn deserialize(data: &[u8]) -> io::Result<Self> {
        let mut cursor = Cursor::new(data);

        // Read header
        let mut header_bytes = [0u8; std::mem::size_of::<PackedHeader>()];
        cursor.read_exact(&mut header_bytes)?;
        let header = PackedHeader::from_bytes(&header_bytes)?;

        // Copy packed fields to avoid unaligned access
        let entry_count = header.entry_count;
        let total_data_size = header.total_data_size;

        // Read entries
        let mut entries = Vec::with_capacity(entry_count as usize);
        for _ in 0..entry_count {
            let mut entry_bytes = [0u8; std::mem::size_of::<PackedEntry>()];
            cursor.read_exact(&mut entry_bytes)?;
            entries.push(PackedEntry::from_bytes(&entry_bytes)?);
        }

        // Read data
        let mut file_data = vec![0u8; total_data_size as usize];
        cursor.read_exact(&mut file_data)?;

        Ok(Self {
            header,
            entries,
            data: file_data,
        })
    }

    /// Extract data for a specific file
    pub fn extract_file(&self, file_index: usize) -> io::Result<Vec<u8>> {
        if file_index >= self.entries.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("File index {} out of bounds", file_index),
            ));
        }

        let entry = &self.entries[file_index];
        // Copy packed fields to avoid unaligned access
        let offset = entry.offset;
        let size = entry.size;
        let start = offset as usize;
        let end = start + size as usize;

        if end > self.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "File data extends beyond packed chunk",
            ));
        }

        let file_data = self.data[start..end].to_vec();

        // Verify checksum
        let checksum = blake3::hash(&file_data);
        if checksum.as_bytes() != &entry.checksum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Checksum mismatch",
            ));
        }

        Ok(file_data)
    }

    /// Get file count
    pub fn file_count(&self) -> usize {
        self.entries.len()
    }

    /// Get total data size
    pub fn total_size(&self) -> u64 {
        // Copy packed fields to avoid unaligned access
        self.header.total_data_size
    }
}

impl Default for PackedChunk {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience: pack multiple files
pub fn pack_files(files: &[&[u8]]) -> io::Result<Vec<u8>> {
    let mut packed = PackedChunk::new();

    for file_data in files {
        packed.add_file(file_data)?;
    }

    packed.serialize()
}

/// Convenience: extract a file from packed data
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
        let serialized = header.as_bytes();
        let deserialized = PackedHeader::from_bytes(serialized).unwrap();

        assert_eq!(header.magic, deserialized.magic);
        assert_eq!(header.version, deserialized.version);
        // Copy packed fields to avoid unaligned access
        let orig_entry_count = header.entry_count;
        let orig_total_data_size = header.total_data_size;
        let new_entry_count = deserialized.entry_count;
        let new_total_data_size = deserialized.total_data_size;
        assert_eq!(orig_entry_count, new_entry_count);
        assert_eq!(orig_total_data_size, new_total_data_size);
    }

    #[test]
    fn test_packed_entry_roundtrip() {
        let checksum = blake3::hash(b"test data");
        let entry = PackedEntry::new(0, 100, *checksum.as_bytes());
        let serialized = entry.as_bytes();
        let deserialized = PackedEntry::from_bytes(serialized).unwrap();

        // Copy packed fields to avoid unaligned access
        let orig_offset = entry.offset;
        let orig_size = entry.size;
        let new_offset = deserialized.offset;
        let new_size = deserialized.size;
        assert_eq!(orig_offset, new_offset);
        assert_eq!(orig_size, new_size);
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
        let files = vec![
            b"file1".as_slice(),
            b"file2".as_slice(),
            b"file3".as_slice(),
        ];

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

        // Tamper with data
        let data_offset = 17 + 48; // header + entry
        serialized[data_offset] ^= 0xFF;

        let deserialized = PackedChunk::deserialize(&serialized).unwrap();
        let result = deserialized.extract_file(0);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
}
