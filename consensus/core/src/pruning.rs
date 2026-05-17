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
    /// Atomic state root at the pruning point. The full token state is intentionally not carried
    /// inside pruning trusted data; post-HF nodes must obtain the state through Atomic snapshot
    /// bootstrap and verify it against this root.
    pub state_hash: [u8; 32],
}

pub struct PruningPointTrustedData {
    /// The pruning point anticone from virtual PoV
    pub anticone: Vec<Hash>,

    /// Union of DAA window data required to verify blocks in the future of the pruning point
    pub daa_window_blocks: Vec<TrustedHeader>,

    /// Union of GHOSTDAG data required to verify blocks in the future of the pruning point
    pub ghostdag_blocks: Vec<TrustedGhostdagData>,

    /// Atomic root at the pruning point. Full token state is synchronized separately by the
    /// Atomic snapshot/bootstrap protocol so pruning proofs cannot balloon with token state size.
    pub atomic_state: Option<PruningPointAtomicState>,
}
