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
use blake3;

// Constants for the offsets
const SHA3_ROUND_OFFSET: usize = 8;
const B3_ROUND_OFFSET: usize = 4;
const ROUND_RANGE_SIZE: usize = 4;


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

    // SHA3-256 Hash Function
    fn sha3_hash(input: [u8; 32]) -> Result<[u8; 32], String> {
        let mut sha3_hasher = Sha3_256::new();
        sha3_hasher.update(&input);
        let hash = sha3_hasher.finalize();
        Ok(hash.into())
    }

    // Blake3 Hash Function
    fn blake3_hash(input: [u8; 32]) -> Result<[u8; 32], String> {
        let hash = blake3::hash(&input);
        Ok(hash.into()) 
    }

    // **Calculate BLAKE3 rounds based on input**
    fn calculate_b3_rounds(input: [u8; 32]) -> Result<usize, String> {
        // Extract the slice from input based on the B3_ROUND_OFFSET and ROUND_RANGE_SIZE
        let slice = input.get(B3_ROUND_OFFSET..B3_ROUND_OFFSET + ROUND_RANGE_SIZE)
            .ok_or("Input slice for Blake3 rounds is out of bounds")?;
    
        let value = u32::from_le_bytes(slice.try_into().map_err(|_| "Failed to convert slice to u32".to_string())?);
        Ok((value % 5 + 1) as usize) // Returns rounds between 1 and 5
    }

    // **Calculate SHA3 rounds based on input**
    fn calculate_sha3_rounds(input: [u8; 32]) -> Result<usize, String> {
        // Extract the slice from input based on the SHA3_ROUND_OFFSET and ROUND_RANGE_SIZE
        let slice = input.get(SHA3_ROUND_OFFSET..SHA3_ROUND_OFFSET + ROUND_RANGE_SIZE)
            .ok_or("Input slice for SHA3 rounds is out of bounds")?;
    
        let value = u32::from_le_bytes(slice.try_into().map_err(|_| "Failed to convert slice to u32".to_string())?);
        Ok((value % 4 + 1) as usize) // Returns rounds between 1 and 4
    }

    // Bitwise manipulations on data
    fn bit_manipulations(data: &mut [u8; 32]) {
        for i in 0..32 {
            // Non-linear manipulations with pseudo-random patterns
            let b = data[(i + 1) % 32];
            data[i] ^= b; // XOR with next byte
            data[i] = data[i].rotate_left(3); // Rotation
            data[i] = data[i].wrapping_add(0x9F) & 0xFF; // Random constant
            data[i] &= 0xFE; // AND with mask to set certain bits
            data[i] ^= ((i as u8) << 2) & 0xFF; // XOR with index shifted
        }
    }
    
    //Byte Mixing
    fn byte_mixing(sha3_hash: &[u8; 32], b3_hash: &[u8; 32]) -> [u8; 32] {
        let mut temp_buf = [0u8; 32];
        for i in 0..32 {
            let a = sha3_hash[i];
            let b = b3_hash[i];
            
            // bitwise AND and OR
            let and_result = a & b;
            let or_result = a | b;
            
            // bitwise rotation and shift
            let rotated = or_result.rotate_left(5);  // Rotate left by 5 bits
            let shifted = and_result.wrapping_shl(3);  // Shift left by 3 bits
            
            // Combine the results
            let mixed = rotated ^ shifted;  // XOR the results
            
            temp_buf[i] = mixed;  // Store the result in the temporary buffer
        }
        temp_buf
    }

    #[inline]
    #[must_use]
    /// PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
    pub fn calculate_pow(&self, nonce: u64) -> Uint256 {
        // Hasher already contains PRE_POW_HASH || TIME || 32 zero byte padding; so only the NONCE is missing
        let hash = self.hasher.clone().finalize_with_nonce(nonce);
    
        let mut hash_bytes: [u8; 32];
        match hash.as_bytes().try_into() {
            Ok(bytes) => hash_bytes = bytes,
            Err(_) => {
                println!("Hash output length mismatch");
                return Uint256::default();  
            }
        }

        /*
    
        // **Branches for Byte Manipulation**
        for i in 0..32 {
            let condition = (hash_bytes[i] ^ (nonce as u8)) % 6; // 6 Cases
            match condition {
                0 => {
                    hash_bytes[i] = hash_bytes[i].wrapping_add(13); // Add 13
                    hash_bytes[i] = hash_bytes[i].rotate_left(3);  // Rotate left by 3 bits
                },
                1 => {
                    hash_bytes[i] = hash_bytes[i].wrapping_sub(7);  // Subtract 7
                    hash_bytes[i] = hash_bytes[i].rotate_left(5);   // Rotate left by 5 bits
                },
                2 => {
                    hash_bytes[i] ^= 0x5A;                         // XOR with 0x5A
                    hash_bytes[i] = hash_bytes[i].wrapping_add(0xAC); // Add 0xAC
                },
                3 => {
                    hash_bytes[i] = hash_bytes[i].wrapping_mul(17); // Multiply by 17
                    hash_bytes[i] ^= 0xAA;                          // XOR with 0xAA
                },
                4 => {
                    hash_bytes[i] = hash_bytes[i].wrapping_sub(29); // Subtract 29
                    hash_bytes[i] = hash_bytes[i].rotate_left(1);  // Rotate left by 1 bit
                },
                5 => {
                    hash_bytes[i] = hash_bytes[i].wrapping_add(0xAA ^ nonce as u8); // Add XOR of 0xAA and nonce
                    hash_bytes[i] ^= 0x45;                          // XOR with 0x45
                },
                _ => unreachable!(), // Should never happens
            }
        }

        // **Bitmanipulation**
        Self::bit_manipulations(&mut hash_bytes);

         */

        let b3_rounds = State::calculate_b3_rounds(hash_bytes).unwrap_or(1); // default 1
        let sha3_rounds = State::calculate_sha3_rounds(hash_bytes).unwrap_or(1); // default 1

        let extra_rounds = (hash_bytes[0] % 6) as usize;  // Dynamic rounds 0 - 5

        let sha3_hash: [u8; 32];
        let b3_hash: [u8; 32];
        let m_hash: [u8; 32];

        // **Dynamic Number of Rounds for Blake3**
        for _ in 0..(b3_rounds + extra_rounds) {
            hash_bytes = Self::blake3_hash(hash_bytes).unwrap_or([0; 32]); // Apply Blake3 hash

            // Branching based on hash value
            if hash_bytes[5] % 2 == 0 { 
                hash_bytes[10] ^= 0xAA; // XOR with 0xAA if byte 5 is even
            } else {
                hash_bytes[15] = hash_bytes[15].wrapping_add(23); // Add 23 if byte 5 is odd
            }
        }

        b3_hash = hash_bytes; // Store final Blake3 hash

        // **Dynamic Number of Rounds for SHA3**
        for _ in 0..(sha3_rounds + extra_rounds) {
            hash_bytes = Self::sha3_hash(hash_bytes).unwrap_or([0; 32]); // Apply SHA3 hash

            // ASIC-unfriendly conditions
            if hash_bytes[3] % 3 == 0 { 
                hash_bytes[20] ^= 0x55; // XOR with 0x55 if byte 3 is divisible by 3
            } else if hash_bytes[7] % 5 == 0 { 
                hash_bytes[25] = hash_bytes[25].rotate_left(7); // Rotate left by 7 if byte 7 is divisible by 5
            }
        }

        sha3_hash = hash_bytes; // Store final sha3 hash

        // Mix SHA3 and Blake3 hash results
        m_hash = Self::byte_mixing(&sha3_hash, &b3_hash);
    
        // Final computation with matrix.heavy_hash
        let final_hash = self.matrix.cryptix_hash(cryptix_hashes::Hash::from(m_hash));
        
        // Finally 
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
    let (block_level, _) = calc_block_level_check_pow(header, max_block_level);
    block_level
}

pub fn calc_block_level_check_pow(header: &Header, max_block_level: BlockLevel) -> (BlockLevel, bool) {
    if header.parents_by_level.is_empty() {
        return (max_block_level, true); // Genesis has the max block level
    }

    let state = State::new(header);
    let (passed, pow) = state.check_pow(header.nonce);
    let block_level = calc_level_from_pow(pow, max_block_level);
    (block_level, passed)
}

pub fn calc_level_from_pow(pow: Uint256, max_block_level: BlockLevel) -> BlockLevel {
    let signed_block_level = max_block_level as i64 - pow.bits() as i64;
    max(signed_block_level, 0) as BlockLevel
}
