use crate::PreparedMacroBlock;
use era_common::{ChunkHash, ErasureCodeConfig};

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

/// Prepared data blocks awaiting volume selection, sealing, and parity encoding.
pub struct Stripe {
    /// The data blocks (MacroBlocks) in this stripe
    pub data_blocks: Vec<PreparedMacroBlock>,
    /// Metadata for each data block (1-to-1 correspondence with data_blocks)
    pub block_meta: Vec<BlockMeta>,
    /// The erasure code configuration used
    pub config: ErasureCodeConfig,
}

/// Buffer for accumulating MacroBlocks to form a stripe.
pub struct StripeBuffer {
    /// Pending data blocks
    data_blocks: Vec<PreparedMacroBlock>,
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
    pub fn push(&mut self, block: PreparedMacroBlock, meta: BlockMeta) -> Option<Stripe> {
        self.data_blocks.push(block);
        self.block_meta.push(meta);

        if self.data_blocks.len() >= self.config.data_shards as usize {
            self.flush()
        } else {
            None
        }
    }

    /// Flush pending blocks as a partial stripe.
    ///
    /// An empty buffer returns `None`.
    pub fn flush(&mut self) -> Option<Stripe> {
        if self.data_blocks.is_empty() {
            return None;
        }

        Some(Stripe {
            data_blocks: std::mem::take(&mut self.data_blocks),
            block_meta: std::mem::take(&mut self.block_meta),
            config: self.config,
        })
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data_blocks.is_empty()
    }
}
