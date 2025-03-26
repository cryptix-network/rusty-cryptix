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
        // Calculate hash with nonce
        let hash = self.hasher.clone().finalize_with_nonce(nonce);
        let hash_bytes: [u8; 32] = hash.as_bytes().try_into().expect("Hash output length mismatch");

        // Determine number of iterations from the first byte of the hash
        let iterations = (hash_bytes[0] % 2) + 1;  // 1 or 2 iterations based on first byte
        
        // Start iterative SHA-3 process
        let mut sha3_hasher = Sha3_256::new();
        let mut current_hash = hash_bytes;

        // Perform iterations
        for _ in 0..iterations {
            sha3_hasher.update(&current_hash);
            let sha3_hash = sha3_hasher.finalize_reset();
            current_hash = sha3_hash.as_slice().try_into().expect("SHA-3 output length mismatch");

            // Perform dynamic hash transformation based on conditions
            if current_hash[1] % 4 == 0 {
                // Calculate the number of iterations based on byte 2 (mod 4), ensuring it is between 1 and 4
                let repeat = (current_hash[2] % 4) + 1; // 1-4 iterations based on the value of byte 2
                
                for _ in 0..repeat {
                    // Apply XOR operation to byte 15 of the hash to alter its value
                    current_hash[15] ^= 0xAA; // XOR with 0xAA (hexadecimal value)

                    // Calculate a dynamic rotation amount based on the first byte of the hash
                    let first_byte = current_hash[0];  // First byte determines rotation
                    let rotation_amount = (first_byte % 5) + 1; // Rotation value is between 1 and 5
                    
                    // Perform rotation based on whether the first byte is even or odd
                    if first_byte % 2 == 0 {
                        // Rotate byte 15 to the left by 'rotation_amount' positions
                        current_hash[15] = current_hash[15].rotate_left(rotation_amount as u32);
                    } else {
                        // Rotate byte 15 to the right by 'rotation_amount' positions
                        current_hash[15] = current_hash[15].rotate_right(rotation_amount as u32);
                    }

                    // Perform additional bitwise manipulation on byte 15 using a shift
                    // The shift amount is dynamically determined based on byte 4 (mod 8), with a range from 1 to 8
                    let shift_amount = (current_hash[4] % 8) + 1; // Shift range: 1-8 positions
                    current_hash[15] ^= current_hash[15].rotate_left(shift_amount as u32); // XOR with rotated value
                }
            } else if current_hash[3] % 3 == 0 {
                let repeat = (current_hash[4] % 5) + 1; // 1-5 iterations based on byte 4
                for _ in 0..repeat {
                    current_hash[20] ^= 0x55; // XOR operation

                    // Dynamic rotation based on first byte
                    let first_byte = current_hash[0];
                    let rotation_amount = (first_byte % 4) + 1;
                    if first_byte % 2 == 0 {
                        current_hash[20] = current_hash[20].rotate_left(rotation_amount as u32);
                    } else {
                        current_hash[20] = current_hash[20].rotate_right(rotation_amount as u32);
                    }

                    // Additional bit manipulation
                    let shift_amount = (current_hash[5] % 8) + 2;
                    current_hash[20] ^= current_hash[20].rotate_left(shift_amount as u32);
                }
            } else if current_hash[2] % 6 == 0 {
                let repeat = (current_hash[6] % 4) + 1; // 1-4 iterations based on byte 6
                for _ in 0..repeat {
                    current_hash[10] ^= 0xFF; // XOR operation

                    // Dynamic rotation based on first byte
                    let first_byte = current_hash[0];
                    let rotation_amount = (first_byte % 3) + 1;
                    if first_byte % 2 == 0 {
                        current_hash[10] = current_hash[10].rotate_left(rotation_amount as u32);
                    } else {
                        current_hash[10] = current_hash[10].rotate_right(rotation_amount as u32);
                    }

                    // Additional bit manipulation
                    let shift_amount = (current_hash[7] % 5) + 3;
                    current_hash[10] ^= current_hash[10].rotate_left(shift_amount as u32);
                }
            } else if current_hash[7] % 5 == 0 {
                let repeat = (current_hash[8] % 4) + 1; // 1-4 iterations based on byte 8
                for _ in 0..repeat {
                    current_hash[25] ^= 0x66; // XOR operation

                    // Dynamic rotation based on first byte
                    let first_byte = current_hash[0];
                    let rotation_amount = (first_byte % 3) + 2;
                    if first_byte % 2 == 0 {
                        current_hash[25] = current_hash[25].rotate_left(rotation_amount as u32);
                    } else {
                        current_hash[25] = current_hash[25].rotate_right(rotation_amount as u32);
                    }

                    // Additional bit manipulation
                    let shift_amount = (current_hash[10] % 6) + 4;
                    current_hash[25] ^= current_hash[25].rotate_left(shift_amount as u32);
                }
            } else if current_hash[8] % 7 == 0 {
                let repeat = (current_hash[9] % 5) + 1; // 1-5 iterations based on byte 9
                for _ in 0..repeat {
                    current_hash[30] ^= 0x77; // XOR operation

                    // Dynamic rotation based on first byte
                    let first_byte = current_hash[0];
                    let rotation_amount = (first_byte % 4) + 1;
                    if first_byte % 2 == 0 {
                        current_hash[30] = current_hash[30].rotate_left(rotation_amount as u32);
                    } else {
                        current_hash[30] = current_hash[30].rotate_right(rotation_amount as u32);
                    }

                    // Additional bit manipulation
                    let shift_amount = (current_hash[11] % 7) + 2;
                    current_hash[30] ^= current_hash[30].rotate_left(shift_amount as u32);
                }
            }
        }

        // Final computation using matrix.cryptix_hash
        let final_hash = self.matrix.cryptix_hash(cryptix_hashes::Hash::from(current_hash));

        // Return the final result as Uint256
        Uint256::from_le_bytes(final_hash.as_bytes())
    }


/*


#[inline(always)]
// PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
pub fn calculate_pow(&self, nonce: u64) -> Uint256 {
    // Calculate the first hash
    let hash = self.hasher.clone().finalize_with_nonce(nonce);
    let mut current_hash: [u8; 32] = hash.to_le_bytes();

    // FPGA-Zerstörungs-Feedback-Loop
    let mut state = 0xA5A5A5A5A5A5A5A5u64;
    for i in 0..32 {
        state ^= current_hash[i] as u64;
        state = state.rotate_left(7);
        state = state.wrapping_mul(0x41C64E6D7);
        current_hash[i] ^= (state as u8);
    }

    // Use the first byte of the hash to determine the number of iterations
    let iterations = (current_hash[0] % 2) + 1;  // The first byte modulo 2, plus 1 for the range [1, 2]

    // Iterative SHA-3 process
    let mut sha3_hasher = Sha3_256::new();

    for _ in 0..iterations {
        sha3_hasher.update(&current_hash);
        let sha3_hash = sha3_hasher.finalize_reset();
        current_hash = sha3_hash.as_slice().try_into().expect("SHA-3 output length mismatch");

        // FPGA-Killer mit sequentieller Feedback-Manipulation
        let mut feedback = 0xC3C3C3C3C3C3C3C3u64;
        for i in 0..current_hash.len() {
            feedback ^= current_hash[i] as u64;
            feedback = feedback.rotate_left((feedback % 13) as u32);
            feedback = feedback.wrapping_mul(0x9E3779B97F4A7C15);
            current_hash[i] ^= (feedback as u8);
        }

        // Conditions
        if current_hash[3] % 3 == 0 { 
            let repeat = (current_hash[4] % 3) + 1;
            for _ in 0..repeat {
                current_hash[20] ^= 0x55;
            }
        } else if current_hash[7] % 5 == 0 { 
            let repeat = (current_hash[8] % 3) + 1;
            for _ in 0..repeat {
                current_hash[25] = current_hash[25].rotate_left(7);
            }
        } else if current_hash[5] % 2 == 0 { 
            let repeat = (current_hash[6] % 3) + 1;
            for _ in 0..repeat {
                current_hash[10] ^= 0xAA;
            }
        } else if current_hash[6] % 4 == 0 {
            let repeat = (current_hash[7] % 3) + 1;
            for _ in 0..repeat {
                current_hash[15] = current_hash[15].rotate_left(3);
            }
        } else if current_hash[8] % 7 == 0 {
            let repeat = (current_hash[9] % 3) + 1;
            for _ in 0..repeat {
                current_hash[30] ^= 0xFF;
            }
        } else if current_hash[9] % 11 == 0 {
            let repeat = (current_hash[10] % 3) + 1;
            for _ in 0..repeat {
                current_hash[5] = current_hash[5].rotate_right(4);
            }
        } else if current_hash[12] % 13 == 0 {
            let repeat = (current_hash[13] % 3) + 1;
            for _ in 0..repeat {
                current_hash[18] = current_hash[18].rotate_left(2);
            }
        }
    }

    // Send to heavy hash
    self.matrix.heavy_hash(Hash::from_le_bytes(current_hash))
}
 */
    
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


/* 
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


*/