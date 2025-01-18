// public for benchmarks
#[doc(hidden)]
pub mod matrix;
#[cfg(feature = "wasm32-sdk")]
pub mod wasm;
#[doc(hidden)]
pub mod xoshiro;

use std::cmp::max;

use crate::matrix::Matrix;
use cryptix_consensus_core::{hashing, header::Header, BlockLevel};
use cryptix_hashes::PowHash;
use cryptix_math::Uint256;
use sha3::{Digest, Sha3_256};

/// State is an intermediate data structure with pre-computed values to speed up mining.
pub struct State {
    pub(crate) matrix: Matrix,
    pub(crate) target: Uint256,
    // PRE_POW_HASH || TIME || 32 zero byte padding; without NONCE
    pub(crate) hasher: PowHash,
}

impl State {
    #[inline]
    pub fn new(header: &Header) -> Self {
        let target = Uint256::from_compact_target_bits(header.bits);
        // Zero out the time and nonce.
        let pre_pow_hash = hashing::header::hash_override_nonce_time(header, 0, 0);
        // PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
        let hasher = PowHash::new(pre_pow_hash, header.timestamp);
        let matrix = Matrix::generate(pre_pow_hash);

        Self { matrix, target, hasher }
    }

    // #[inline]
    // #[must_use]
    // /// PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
    // pub fn calculate_pow(&self, nonce: u64) -> Uint256 {
    //     // Hasher already contains PRE_POW_HASH || TIME || 32 zero byte padding; so only the NONCE is missing
    //     let hash = self.hasher.clone().finalize_with_nonce(nonce);
        // let hash = self.matrix.heavy_hash(hash);
    //     Uint256::from_le_bytes(hash.as_bytes())
    // }

    #[inline]
    #[must_use]
    /// PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
    pub fn calculate_pow(&self, nonce: u64) -> Uint256 {
        let hash = self.hasher.clone().finalize_with_nonce(nonce);
        let hash_bytes: [u8; 32] = hash.as_bytes().try_into().expect("Hash output length mismatch");
    
        let mut sha3_hasher = Sha3_256::new();
        sha3_hasher.update(hash_bytes);
        let sha3_hash = sha3_hasher.finalize();
        let sha3_hash_bytes: [u8; 32] = sha3_hash.as_slice().try_into().expect("SHA-3 output length mismatch");
    
        let final_hash = self.matrix.heavy_hash(cryptix_hashes::Hash::from(sha3_hash_bytes));
    
        Uint256::from_le_bytes(final_hash.as_bytes())
    }
    

    #[inline]
    #[must_use]
    pub fn check_pow(&self, nonce: u64) -> (bool, Uint256) {
        let pow = self.calculate_pow(nonce);
        // The pow hash must be less or equal than the claimed target.
        (pow <= self.target, pow)
    }
}

pub fn calc_block_level(header: &Header, max_block_level: BlockLevel) -> BlockLevel {
    if header.parents_by_level.is_empty() {
        return max_block_level; // Genesis has the max block level
    }

    let state = State::new(header);
    let (_, pow) = state.check_pow(header.nonce);
    let signed_block_level = max_block_level as i64 - pow.bits() as i64;
    max(signed_block_level, 0) as BlockLevel
}
