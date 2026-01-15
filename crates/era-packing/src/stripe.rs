use era_codec::ErasureCoder;
use era_common::{ChunkHash, EncryptedMacroBlock, ErasureCodeConfig, Result};

/// Metadata for a block to allow index updates after writing.
#[derive(Debug)]
pub struct BlockMeta {
    /// Hashes of chunks in this block, in order.
    pub chunk_hashes: Vec<ChunkHash>,
    /// Offsets/Lengths if needed (assuming sequential packing for now or provided elsewhere)
    /// Actually, if we use the ChunkRef from Ingest, we might need exact offsets.
    /// But SessionBlockBuilder builds the block. The offset inside the block is determined there.
    /// We should probably store (Hash, Offset, Length).
    pub chunk_entries: Vec<(ChunkHash, u32, u32)>,
}

/// A stripe of data blocks and their corresponding parity shards.
///
/// In Virtual Striping, K MacroBlocks are treated as data shards,
/// and M parity shards are generated from them.
#[derive(Debug)]
pub struct Stripe {
    /// The data blocks (MacroBlocks) in this stripe
    pub data_blocks: Vec<EncryptedMacroBlock>,
    /// Metadata for each data block (1-to-1 correspondence with data_blocks)
    pub block_meta: Vec<BlockMeta>,
    /// The generated parity shards
    pub parity_shards: Vec<Vec<u8>>,
    /// The erasure code configuration used
    pub config: ErasureCodeConfig,
}

/// Buffer for accumulating MacroBlocks to form a stripe.
#[derive(Debug)]
pub struct StripeBuffer {
    /// Pending data blocks
    data_blocks: Vec<EncryptedMacroBlock>,
    /// Metadata for pending blocks
    block_meta: Vec<BlockMeta>,
    /// Erasure code configuration
    config: ErasureCodeConfig,
}

impl StripeBuffer {
    /// Create a new stripe buffer.
    pub fn new(config: ErasureCodeConfig) -> Self {
        Self {
            data_blocks: Vec::with_capacity(config.data_shards as usize),
            block_meta: Vec::with_capacity(config.data_shards as usize),
            config,
        }
    }

    /// Add a block to the buffer.
    ///
    /// If enough blocks are collected (equal to data_shards), returns a complete Stripe.
    /// Otherwise returns None.
    pub fn push(&mut self, block: EncryptedMacroBlock, meta: BlockMeta) -> Result<Option<Stripe>> {
        self.data_blocks.push(block);
        self.block_meta.push(meta);

        if self.data_blocks.len() >= self.config.data_shards as usize {
            Ok(Some(self.flush()?))
        } else {
            Ok(None)
        }
    }

    /// Flush pending blocks as a partial stripe.
    ///
    /// This should be called when finalizing the archive.
    /// If there are any pending blocks, they will be encoded (padding will be used for missing blocks).
    pub fn flush(&mut self) -> Result<Stripe> {
        if self.data_blocks.is_empty() {
            return Ok(Stripe {
                data_blocks: Vec::new(),
                block_meta: Vec::new(),
                parity_shards: Vec::new(),
                config: self.config,
            });
        }

        let blocks = std::mem::take(&mut self.data_blocks);
        let meta = std::mem::take(&mut self.block_meta);

        // Prepare shards for encoding
        // We need to extract the data bytes from EncryptedMacroBlock
        let shards: Vec<Vec<u8>> = blocks.iter().map(|b| b.data.to_vec()).collect();

        let coder = ErasureCoder::new(era_codec::ErasureConfig::new(
            self.config.data_shards as usize,
            self.config.parity_shards as usize,
        )?)?;

        // Encode using our new encode_shards method
        // Note: encode_shards returns (padded_data_shards + parity_shards)
        let all_shards = coder.encode_shards(&shards)?;

        // Extract parity shards (they are at the end)
        let parity_count = self.config.parity_shards as usize;
        let total_count = all_shards.len();
        let parity_shards = all_shards[total_count - parity_count..].to_vec();

        Ok(Stripe {
            data_blocks: blocks,
            block_meta: meta,
            parity_shards,
            config: self.config,
        })
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data_blocks.is_empty()
    }
}
