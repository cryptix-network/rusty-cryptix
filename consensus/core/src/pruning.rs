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
    /// Atomic state root at the pruning point.
    pub state_hash: [u8; 32],

    /// Optional canonical full Atomic state bytes carried by the node sync protocol.
    /// When absent, the receiver only has a root and can use local replay or legacy root-only fallback.
    pub state_bytes: Option<Vec<u8>>,
}

pub struct PruningPointTrustedData {
    /// The pruning point anticone from virtual PoV
    pub anticone: Vec<Hash>,

    /// Union of DAA window data required to verify blocks in the future of the pruning point
    pub daa_window_blocks: Vec<TrustedHeader>,

    /// Union of GHOSTDAG data required to verify blocks in the future of the pruning point
    pub ghostdag_blocks: Vec<TrustedGhostdagData>,

    /// Atomic root/full state at the pruning point, synchronized through the normal node sync protocol.
    pub atomic_state: Option<PruningPointAtomicState>,
}
