use crate::{
    header::Header,
    trusted::{TrustedGhostdagData, TrustedHeader},
};
use cryptix_hashes::Hash;
use std::sync::Arc;

pub type PruningPointProof = Vec<Vec<Arc<Header>>>;

pub type PruningPointsList = Vec<Arc<Header>>;

#[derive(Clone, Debug)]
pub struct PruningPointAtomicState {
    pub serialized_state: Vec<u8>,
    pub state_hash: [u8; 32],
}

pub struct PruningPointTrustedData {
    /// The pruning point anticone from virtual PoV
    pub anticone: Vec<Hash>,

    /// Union of DAA window data required to verify blocks in the future of the pruning point
    pub daa_window_blocks: Vec<TrustedHeader>,

    /// Union of GHOSTDAG data required to verify blocks in the future of the pruning point
    pub ghostdag_blocks: Vec<TrustedGhostdagData>,

    /// Canonically serialized consensus Atomic state at the pruning point.
    /// This is required for post-payload-HF pruning imports because token/liquidity
    /// validation cannot be reconstructed from the UTXO set alone.
    pub atomic_state: Option<PruningPointAtomicState>,
}
