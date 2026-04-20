use cryptix_consensus_core::errors::consensus::ConsensusError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AtomicTokenError {
    #[error("Cryptix Atomic startup failed: invalid network id `{0}`")]
    InvalidNetworkId(String),

    #[error("Cryptix Atomic startup failed: finality depth mismatch (expected {expected}, consensus has {actual})")]
    FinalityDepthMismatch { expected: u64, actual: u64 },

    #[error("Cryptix Atomic startup failed: cryptographic binding self-test failed")]
    CryptoBindingSelfTestFailed,

    #[error("Cryptix Atomic degraded mode: {0}")]
    Degraded(String),

    #[error("Cryptix Atomic snapshot schema mismatch: expected {expected}, got {actual}")]
    SnapshotSchemaMismatch { expected: u16, actual: u16 },

    #[error("Cryptix Atomic snapshot protocol mismatch: expected {expected}, got {actual}")]
    SnapshotProtocolMismatch { expected: u16, actual: u16 },

    #[error("Cryptix Atomic snapshot network mismatch: expected `{expected}`, got `{actual}`")]
    SnapshotNetworkMismatch { expected: String, actual: String },

    #[error("Cryptix Atomic processing failed: {0}")]
    Processing(String),

    #[error(transparent)]
    Consensus(#[from] ConsensusError),
}

pub type AtomicTokenResult<T> = Result<T, AtomicTokenError>;
