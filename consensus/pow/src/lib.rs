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

    /// Calculates a Proof-of-Work (PoW) hash using an iterative, non-linear, and dynamic process.
    /// 
    /// The function takes a `nonce` as input and performs a series of cryptographic transformations, including
    /// SHA-3-256 hashing, XOR operations, rotations, and shifts. The process is determined by dynamic conditions
    /// and non-linear operations, making the algorithm harder to predict and protecting against hardware-based attacks
    /// such as those using FPGAs.
    /// 
    /// # Key Operations and Non-linear Behavior:
    /// 
    /// 1. **Initial Hash Calculation:**  
    ///    - A hash is calculated using the `nonce` via the `finalize_with_nonce` function, providing the starting point
    ///      for all subsequent transformations.
    ///    - The first byte of the resulting hash determines the number of iterations for the following SHA-3 hashing process, 
    ///      introducing dynamic behavior that affects the flow of the calculation.
    /// 
    /// 2. **Iterations Based on the First Byte of the Hash:**  
    ///    - The number of iterations (1 or 2) is determined by the first byte of the initial hash, making the process dynamic.
    ///      This decision logic is non-linear and impacts the subsequent computations.
    /// 
    /// 3. **Dynamic Manipulations of the Hash Values:**  
    ///    - In each iteration, the hash is further transformed through multiple dynamic conditions:
    ///        - **XOR Operations:** Different bytes of the hash are XORed with fixed values (e.g., `0xA5`, `0x55`, `0xFF`) based on the 
    ///          values of other bytes. This creates unpredictable changes and contributes to the non-linear behavior.
    ///        - **Rotations and Shifts:**  
    ///          - Certain bytes in the hash are rotated (left or right) dynamically, based on hash values (e.g., byte 1, byte 2, byte 3),
    ///            introducing non-linear changes to the hash.
    ///          - Shifts are also applied based on specific bytes. For example, bytes 7, 9, and 10 are involved in dynamic rotations and shifts, 
    ///            further adding to the non-linear manipulation of the hash.
    /// 
    /// 4. **Repeated Transformations:**  
    ///    - The number of repetitions for specific manipulations is controlled by values within the hash itself (e.g., `current_hash[2] % 4 + 1`).
    ///      This means the number of operations varies dynamically with each iteration. The repetitions vary based on the values in different
    ///      bytes of the hash (e.g., byte 2, byte 4, byte 7, etc.), and are determined dynamically at each iteration.
    /// 
    /// 5. **Dynamic Selection of Operations Based on Hash Values:**  
    ///    - Different transformations are applied based on specific bytes in the hash. For example:
    ///      - If `current_hash[1] % 4 == 0`, an XOR and rotation operation is performed on byte 15 (and similar for other conditions).
    ///      - If `current_hash[3] % 3 == 0`, a different manipulation is applied to byte 20.
    ///      - This dynamic selection ensures that each iteration is different and unpredictable, making the algorithm more resistant to attack.
    /// 
    /// 6. **Final Transformation and Result:**  
    ///    - After all iterations, a final transformation of the hash is performed using the `matrix.cryptix_hash` function.
    ///      This final calculation ensures that the result is influenced by all previous dynamic manipulations.
    /// 
    /// 7. **Returning the Final PoW Hash:**  
    ///    - The calculated hash is returned as a `Uint256`, representing the final result of the PoW calculation.

    #[inline]
    #[must_use]
    /// PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
    pub fn calculate_pow(&self, nonce: u64) -> Uint256 {
        // Calculate hash with nonce
        let hash = self.hasher.clone().finalize_with_nonce(nonce);
        let hash_bytes: [u8; 32] = hash.as_bytes().try_into().expect("Hash output length mismatch");

        // Determine number of iterations from the first byte of the hash
        let iterations = (hash_bytes[0] % 2) + 1;  // 1 - 2 iterations based on first byte
        
        // Start iterative SHA-3 process
        let mut sha3_hasher = Sha3_256::new();
        let mut current_hash = hash_bytes;

        // Perform iterations based on the first byte of the hash
        for i in 0..iterations {
            sha3_hasher.update(&current_hash);
            let sha3_hash = sha3_hasher.finalize_reset();
            current_hash = sha3_hash.as_slice().try_into().expect("SHA-3 output length mismatch");

            // Perform dynamic hash transformation based on conditions
            if current_hash[1] % 4 == 0 {
                // Calculate the number of iterations based on byte 2 (mod 4), ensuring it is between 1 and 4
                let repeat = (current_hash[2] % 4) + 1; // 1-4 iterations based on the value of byte 2
                
                for _ in 0..repeat {
                    // Dynamically select the byte to modify based on a combination of hash bytes and iteration
                    let target_byte = ((current_hash[1] as usize) + (i as u8) as usize) % 32; // Dynamic byte position for XOR
                    let xor_value = current_hash[(i % 16) as usize] ^ 0xA5; // Dynamic XOR value based on iteration index and hash
                    current_hash[target_byte] ^= xor_value;  // XOR on dynamically selected byte

                    // Dynamically choose the byte to calculate rotation based on the current iteration
                    let rotation_byte = current_hash[(i % 32) as usize];  // Use different byte based on iteration index
                    let rotation_amount = ((current_hash[1] as u32) + (current_hash[3] as u32)) % 4 + 2; // Combined rotation calculation
                    
                    // Perform rotation based on whether the rotation byte is even or odd
                    if rotation_byte % 2 == 0 {
                        // Rotate byte at dynamic position to the left by 'rotation_amount' positions
                        current_hash[target_byte] = current_hash[target_byte].rotate_left(rotation_amount);
                    } else {
                        // Rotate byte at dynamic position to the right by 'rotation_amount' positions
                        current_hash[target_byte] = current_hash[target_byte].rotate_right(rotation_amount);
                    }

                    // Perform additional bitwise manipulation on the target byte using a shift
                    let shift_amount = ((current_hash[5] as u32) + (current_hash[1] as u32)) % 3 + 1; // Combined shift calculation
                    current_hash[target_byte] ^= current_hash[target_byte].rotate_left(shift_amount); // XOR with rotated value
                }
            } else if current_hash[3] % 3 == 0 {
                let repeat = (current_hash[4] % 5) + 1;
                for _ in 0..repeat {
                    let target_byte = ((current_hash[6] as usize) + (i as u8) as usize) % 32; 
                    let xor_value = current_hash[(i % 16) as usize] ^ 0x55;
                    current_hash[target_byte] ^= xor_value;

                    let rotation_byte = current_hash[(i % 32) as usize];
                    let rotation_amount = ((current_hash[7] as u32) + (current_hash[2] as u32)) % 6 + 1;
                    if rotation_byte % 2 == 0 {
                        current_hash[target_byte] = current_hash[target_byte].rotate_left(rotation_amount as u32);
                    } else {
                        current_hash[target_byte] = current_hash[target_byte].rotate_right(rotation_amount as u32);
                    }

                    let shift_amount = ((current_hash[1] as u32) + (current_hash[3] as u32)) % 4 + 1; 
                    current_hash[target_byte] ^= current_hash[target_byte].rotate_left(shift_amount);
                }
            } else if current_hash[2] % 6 == 0 {
                let repeat = (current_hash[6] % 4) + 1;
                for _ in 0..repeat {
                    let target_byte = ((current_hash[10] as usize) + (i as u8) as usize) % 32; 
                    let xor_value = current_hash[(i % 16) as usize] ^ 0xFF;
                    current_hash[target_byte] ^= xor_value;

                    let rotation_byte = current_hash[(i % 32) as usize];  
                    let rotation_amount = ((current_hash[7] as u32) + (current_hash[7] as u32)) % 7 + 1;
                    if rotation_byte % 2 == 0 {
                        current_hash[target_byte] = current_hash[target_byte].rotate_left(rotation_amount as u32);
                    } else {
                        current_hash[target_byte] = current_hash[target_byte].rotate_right(rotation_amount as u32);
                    }

                    let shift_amount = ((current_hash[3] as u32) + (current_hash[5] as u32)) % 5 + 2; 
                    current_hash[target_byte] ^= current_hash[target_byte].rotate_left(shift_amount as u32);
                }
            } else if current_hash[7] % 5 == 0 {
                let repeat = (current_hash[8] % 4) + 1;
                for _ in 0..repeat {
                    let target_byte = ((current_hash[25] as usize) + (i as u8) as usize) % 32; 
                    let xor_value = current_hash[(i % 16) as usize] ^ 0x66;
                    current_hash[target_byte] ^= xor_value;

                    let rotation_byte = current_hash[(i % 32) as usize]; 
                    let rotation_amount = ((current_hash[1] as u32) + (current_hash[3] as u32)) % 4 + 2;
                    if rotation_byte % 2 == 0 {
                        current_hash[target_byte] = current_hash[target_byte].rotate_left(rotation_amount as u32);
                    } else {
                        current_hash[target_byte] = current_hash[target_byte].rotate_right(rotation_amount as u32);
                    }

                    let shift_amount = ((current_hash[1] as u32) + (current_hash[3] as u32)) % 4 + 1; 
                    current_hash[target_byte] ^= current_hash[target_byte].rotate_left(shift_amount as u32);
                }
            } else if current_hash[8] % 7 == 0 {
                let repeat = (current_hash[9] % 5) + 1;
                for _ in 0..repeat {
                    let target_byte = ((current_hash[30] as usize) + (i as u8) as usize) % 32; 
                    let xor_value = current_hash[(i % 16) as usize] ^ 0x77; 
                    current_hash[target_byte] ^= xor_value;

                    let rotation_byte = current_hash[(i % 32) as usize];  
                    let rotation_amount = ((current_hash[2] as u32) + (current_hash[5] as u32)) % 5 + 1;
                    if rotation_byte % 2 == 0 {
                        current_hash[target_byte] = current_hash[target_byte].rotate_left(rotation_amount as u32);
                    } else {
                        current_hash[target_byte] = current_hash[target_byte].rotate_right(rotation_amount as u32);
                    }

                    let shift_amount = ((current_hash[7] as u32) + (current_hash[9] as u32)) % 6 + 2; 
                    current_hash[target_byte] ^= current_hash[target_byte].rotate_left(shift_amount as u32);
                }
            }
        }

        // Final computation using matrix.cryptix_hash
        let final_hash = self.matrix.cryptix_hash(cryptix_hashes::Hash::from(current_hash));

        // Return the final result as Uint256
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
