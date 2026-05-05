//!
//! Model structures which are related to IBD pruning point syncing logic. These structures encode
//! a specific syncing protocol and thus do not belong within consensus core.
//!

use cryptix_consensus_core::{
    block::Block,
    blockhash::ORIGIN,
    pruning::PruningPointAtomicState,
    trusted::{TrustedBlock, TrustedGhostdagData, TrustedHeader},
    BlockHashMap, BlockHashSet, HashMapCustomHasher,
};

use crate::common::ProtocolError;

pub const TRUSTED_ATOMIC_STATE_CHUNK_SIZE: usize = 4 * 1024 * 1024;
// The pruning-point atomic consensus state is assembled in memory during IBD.
// Keep this bounded separately from AtomicIndex snapshot bootstrap data.
pub const MAX_TRUSTED_ATOMIC_STATE_CHUNKS: u64 = 2_048;
pub const MAX_TRUSTED_ATOMIC_STATE_BYTES: u64 = TRUSTED_ATOMIC_STATE_CHUNK_SIZE as u64 * MAX_TRUSTED_ATOMIC_STATE_CHUNKS;

pub fn trusted_atomic_state_chunk_count(byte_length: u64) -> u64 {
    if byte_length == 0 {
        0
    } else {
        ((byte_length - 1) / TRUSTED_ATOMIC_STATE_CHUNK_SIZE as u64) + 1
    }
}

/// A package of *semi-trusted data* used by a syncing node in order to build
/// the sub-DAG in the anticone and in the recent past of the synced pruning point
pub struct TrustedDataPackage {
    pub daa_window: Vec<TrustedHeader>,
    pub ghostdag_window: Vec<TrustedGhostdagData>,
    pub atomic_state: Option<PruningPointAtomicState>,
    pub atomic_state_hash: Option<[u8; 32]>,
    pub atomic_state_byte_length: u64,
    pub atomic_state_chunk_count: u64,
}

impl TrustedDataPackage {
    pub fn new(
        daa_window: Vec<TrustedHeader>,
        ghostdag_window: Vec<TrustedGhostdagData>,
        atomic_state: Option<PruningPointAtomicState>,
    ) -> Self {
        let atomic_state_hash = atomic_state.as_ref().map(|state| state.state_hash);
        let atomic_state_byte_length = atomic_state.as_ref().map(|state| state.serialized_state.len() as u64).unwrap_or_default();
        Self { daa_window, ghostdag_window, atomic_state, atomic_state_hash, atomic_state_byte_length, atomic_state_chunk_count: 0 }
    }

    pub fn new_chunked(
        daa_window: Vec<TrustedHeader>,
        ghostdag_window: Vec<TrustedGhostdagData>,
        atomic_state_hash: [u8; 32],
        atomic_state_byte_length: u64,
        atomic_state_chunk_count: u64,
    ) -> Self {
        Self {
            daa_window,
            ghostdag_window,
            atomic_state: None,
            atomic_state_hash: Some(atomic_state_hash),
            atomic_state_byte_length,
            atomic_state_chunk_count,
        }
    }

    pub fn has_chunked_atomic_state(&self) -> bool {
        self.atomic_state.is_none() && self.atomic_state_hash.is_some() && self.atomic_state_chunk_count > 0
    }

    /// Returns the trusted set -- a sub-DAG in the anti-future of the pruning point which contains
    /// all the blocks and ghostdag data needed in order to validate the headers in the future of
    /// the pruning point
    pub fn build_trusted_subdag(self, entries: Vec<TrustedDataEntry>) -> Result<Vec<TrustedBlock>, ProtocolError> {
        let mut blocks = Vec::with_capacity(entries.len());
        let mut set = BlockHashSet::new();
        let mut map = BlockHashMap::new();

        for th in self.ghostdag_window.iter() {
            map.insert(th.hash, th.ghostdag.clone());
        }

        for th in self.daa_window.iter() {
            map.insert(th.header.hash, th.ghostdag.clone());
        }

        for entry in entries {
            let block = entry.block;
            if set.insert(block.hash()) {
                if let Some(ghostdag) = map.get(&block.hash()) {
                    blocks.push(TrustedBlock::new(block, ghostdag.clone()));
                } else {
                    return Err(ProtocolError::Other("missing ghostdag data for some trusted entries"));
                }
            }
        }

        for th in self.daa_window.iter() {
            if set.insert(th.header.hash) {
                blocks.push(TrustedBlock::new(Block::from_header_arc(th.header.clone()), th.ghostdag.clone()));
            }
        }

        // Prune all missing ghostdag mergeset blocks. If due to this prune data becomes insufficient, future
        // IBD blocks will not validate correctly which will lead to a rule error and peer disconnection
        for tb in blocks.iter_mut() {
            tb.ghostdag.mergeset_blues.retain(|h| set.contains(h));
            tb.ghostdag.mergeset_reds.retain(|h| set.contains(h));
            tb.ghostdag.blues_anticone_sizes.retain(|k, _| set.contains(k));
            if !set.contains(&tb.ghostdag.selected_parent) {
                tb.ghostdag.selected_parent = ORIGIN;
            }
        }

        // Topological sort
        blocks.sort_by(|a, b| a.block.header.blue_work.cmp(&b.block.header.blue_work));

        Ok(blocks)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedAtomicStateChunk {
    pub state_hash: [u8; 32],
    pub chunk_index: u64,
    pub total_chunks: u64,
    pub total_bytes: u64,
    pub chunk: Vec<u8>,
}

impl TrustedAtomicStateChunk {
    pub fn new(state_hash: [u8; 32], chunk_index: u64, total_chunks: u64, total_bytes: u64, chunk: Vec<u8>) -> Self {
        Self { state_hash, chunk_index, total_chunks, total_bytes, chunk }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_atomic_state_transfer_limit_is_chunk_aligned() {
        assert_eq!(MAX_TRUSTED_ATOMIC_STATE_BYTES, 8 * 1024 * 1024 * 1024);
        assert_eq!(trusted_atomic_state_chunk_count(MAX_TRUSTED_ATOMIC_STATE_BYTES), MAX_TRUSTED_ATOMIC_STATE_CHUNKS);
        assert_eq!(trusted_atomic_state_chunk_count(MAX_TRUSTED_ATOMIC_STATE_BYTES + 1), MAX_TRUSTED_ATOMIC_STATE_CHUNKS + 1);
    }
}

/// A block with DAA/Ghostdag indices corresponding to data location within a `TrustedDataPackage`
pub struct TrustedDataEntry {
    pub block: Block,
    pub daa_window_indices: Vec<u64>,
    pub ghostdag_window_indices: Vec<u64>,
    //
    // Rust rewrite note: the indices fields are no longer needed with the way the pruning point anti-future
    // is maintained now. Meaning we simply build this sub-DAG in a way that the usual traversal operations will
    // return the correct blocks/data without the need for explicitly provided indices.
    //
}

impl TrustedDataEntry {
    pub fn new(block: Block, daa_window_indices: Vec<u64>, ghostdag_window_indices: Vec<u64>) -> Self {
        Self { block, daa_window_indices, ghostdag_window_indices }
    }
}
