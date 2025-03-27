use crate::xoshiro::XoShiRo256PlusPlus;
use cryptix_hashes::{Hash, CryptixHashV2};
use std::mem::MaybeUninit;

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct Matrix([[u16; 64]; 64]);


impl Matrix {
    // pub fn generate(hash: Hash) -> Self {
    //     let mut generator = XoShiRo256PlusPlus::new(hash);
    //     let mut mat = Matrix([[0u16; 64]; 64]);
    //     loop {
    //         for i in 0..64 {
    //             for j in (0..64).step_by(16) {
    //                 let val = generator.u64();
    //                 for shift in 0..16 {
    //                     mat.0[i][j + shift] = (val >> (4 * shift) & 0x0F) as u16;
    //                 }
    //             }
    //         }
    //         if mat.compute_rank() == 64 {
    //             return mat;
    //         }
    //     }
    // }

    #[inline(always)]
    pub fn generate(hash: Hash) -> Self {
        let mut generator = XoShiRo256PlusPlus::new(hash);
        loop {
            let mat = Self::rand_matrix_no_rank_check(&mut generator);
            if mat.compute_rank() == 64 {
                return mat;
            }
        }
    }

    #[inline(always)]
    fn rand_matrix_no_rank_check(generator: &mut XoShiRo256PlusPlus) -> Self {
        Self(array_from_fn(|_| {
            let mut val = 0;
            array_from_fn(|j| {
                let shift = j % 16;
                if shift == 0 {
                    val = generator.u64();
                }
                (val >> (4 * shift) & 0x0F) as u16
            })
        }))
    }

    #[inline(always)]
    fn convert_to_float(&self) -> [[f64; 64]; 64] {
        // SAFETY: An uninitialized MaybeUninit is always safe.
        let mut out: [[MaybeUninit<f64>; 64]; 64] = unsafe { MaybeUninit::uninit().assume_init() };

        out.iter_mut().zip(self.0.iter()).for_each(|(out_row, mat_row)| {
            out_row.iter_mut().zip(mat_row).for_each(|(out_element, &element)| {
                out_element.write(f64::from(element));
            })
        });
        // SAFETY: The loop above wrote into all indexes.
        unsafe { std::mem::transmute(out) }
    }

    pub fn compute_rank(&self) -> usize {
        const EPS: f64 = 1e-9;
        let mut mat_float = self.convert_to_float();
        let mut rank = 0;
        let mut row_selected = [false; 64];
        for i in 0..64 {
            if i >= 64 {
                // Required for optimization, See https://github.com/rust-lang/rust/issues/90794
                unreachable!()
            }
            let mut j = 0;
            while j < 64 {
                if !row_selected[j] && mat_float[j][i].abs() > EPS {
                    break;
                }
                j += 1;
            }
            if j != 64 {
                rank += 1;
                row_selected[j] = true;
                for p in (i + 1)..64 {
                    mat_float[j][p] /= mat_float[j][i];
                }
                for k in 0..64 {
                    if k != j && mat_float[k][i].abs() > EPS {
                        for p in (i + 1)..64 {
                            mat_float[k][p] -= mat_float[j][p] * mat_float[k][i];
                        }
                    }
                }
            }
        }
        rank
    }

    /* 
    // ### Cryptixhash v3

    // generate_non_linear_sbox method
    pub fn generate_non_linear_sbox(input: u8, key: u8) -> u8 {
        let mut result = input;

        // Calculate the inverse in GF(2^8)
        result = Self::gf_invert(result);

        // Affine transformation (left rotation, XOR with constant 0x63)
        result = Self::affine_transform(result);

        // XOR with the key for additional diffusion
        result ^= key;

        result
    }

    // Inverse calculation and affine transformation
    fn gf_invert(value: u8) -> u8 {
        if value == 0 {
            return 0; // The inverse of 0 is 0
        }

        let mut t = 0u8;
        let r: u16 = 0x11b; // The irreducible polynomial as u16
        let mut v = value;
        let mut u: u16 = 1; // 1 in GF(2^8)

        // Extended Euclidean algorithm
        for _ in 0..8 {
            if v & 1 == 1 {
                t ^= u as u8; // Cast the result as u8
            }

            v >>= 1;
            u = (u << 1) ^ (if v & 0x80 != 0 { r } else { 0 });

            if u & 0x100 != 0 {
                u ^= 0x11b; // XOR with irreducible polynomial
            }
        }

        t
    }

    // Affine Transformation (left rotation + XOR with constant 0x63)
    fn affine_transform(value: u8) -> u8 {
        let mut result = value;
        result = result.rotate_left(4) ^ result; // Left rotation + XOR with itself (for diffusion)
        result ^= 0x63; // XOR with a constant (similar to AES)
        result
    }*/

    fn octonion_multiply(a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
        let mut result = [0; 8];

        /*
            Multiplication table of octonions (non-commutative):

                ×    |  1   e₁   e₂   e₃   e₄   e₅   e₆   e₇  
                ------------------------------------------------
                1    |  1   e₁   e₂   e₃   e₄   e₅   e₆   e₇  
                e₁   | e₁  -1   e₃  -e₂   e₅  -e₆   e₄  -e₇  
                e₂   | e₂  -e₃  -1    e₁   e₆   e₄  -e₅   e₇  
                e₃   | e₃   e₂  -e₁  -1    e₄  -e₇   e₆  -e₅  
                e₄   | e₄  -e₅  -e₆  -e₄  -1    e₇   e₂   e₃  
                e₅   | e₅   e₆   e₄   e₇  -e₇  -1   -e₃   e₂  
                e₆   | e₆  -e₄  -e₅   e₆  -e₂   e₃  -1    e₁  
                e₇   | e₇   e₄  -e₇   e₅  -e₃  -e₂   e₁  -1  

        
        // The rules for multiplying octonions
        result[0] = a[0] * b[0] - a[1] * b[1] - a[2] * b[2] - a[3] * b[3] - a[4] * b[4] - a[5] * b[5] - a[6] * b[6] - a[7] * b[7];
        result[1] = a[0] * b[1] + a[1] * b[0] + a[2] * b[3] - a[3] * b[2] + a[4] * b[5] - a[5] * b[4] - a[6] * b[7] + a[7] * b[6];
        result[2] = a[0] * b[2] - a[1] * b[3] + a[2] * b[0] + a[3] * b[1] + a[4] * b[6] - a[5] * b[7] + a[6] * b[4] - a[7] * b[5];
        result[3] = a[0] * b[3] + a[1] * b[2] - a[2] * b[1] + a[3] * b[0] + a[4] * b[7] + a[5] * b[6] - a[6] * b[5] + a[7] * b[4];
        result[4] = a[0] * b[4] - a[1] * b[5] - a[2] * b[6] - a[3] * b[7] + a[4] * b[0] + a[5] * b[1] + a[6] * b[2] + a[7] * b[3];
        result[5] = a[0] * b[5] + a[1] * b[4] - a[2] * b[7] + a[3] * b[6] - a[4] * b[1] + a[5] * b[0] + a[6] * b[3] + a[7] * b[2];
        result[6] = a[0] * b[6] + a[1] * b[7] + a[2] * b[4] - a[3] * b[5] - a[4] * b[2] + a[5] * b[3] + a[6] * b[0] + a[7] * b[1];
        result[7] = a[0] * b[7] - a[1] * b[6] + a[2] * b[5] + a[3] * b[4] - a[4] * b[3] + a[5] * b[2] + a[6] * b[1] + a[7] * b[0];

        result
        */
    
        result[0] = a[0].wrapping_mul(b[0])
            .wrapping_sub(a[1].wrapping_mul(b[1]))
            .wrapping_sub(a[2].wrapping_mul(b[2]))
            .wrapping_sub(a[3].wrapping_mul(b[3]))
            .wrapping_sub(a[4].wrapping_mul(b[4]))
            .wrapping_sub(a[5].wrapping_mul(b[5]))
            .wrapping_sub(a[6].wrapping_mul(b[6]))
            .wrapping_sub(a[7].wrapping_mul(b[7]));
    
        result[1] = a[0].wrapping_mul(b[1])
            .wrapping_add(a[1].wrapping_mul(b[0]))
            .wrapping_add(a[2].wrapping_mul(b[3]))
            .wrapping_sub(a[3].wrapping_mul(b[2]))
            .wrapping_add(a[4].wrapping_mul(b[5]))
            .wrapping_sub(a[5].wrapping_mul(b[4]))
            .wrapping_sub(a[6].wrapping_mul(b[7]))
            .wrapping_add(a[7].wrapping_mul(b[6]));
    
        result[2] = a[0].wrapping_mul(b[2])
            .wrapping_sub(a[1].wrapping_mul(b[3]))
            .wrapping_add(a[2].wrapping_mul(b[0]))
            .wrapping_add(a[3].wrapping_mul(b[1]))
            .wrapping_add(a[4].wrapping_mul(b[6]))
            .wrapping_sub(a[5].wrapping_mul(b[7]))
            .wrapping_add(a[6].wrapping_mul(b[4]))
            .wrapping_sub(a[7].wrapping_mul(b[5]));
    
        result[3] = a[0].wrapping_mul(b[3])
            .wrapping_add(a[1].wrapping_mul(b[2]))
            .wrapping_sub(a[2].wrapping_mul(b[1]))
            .wrapping_add(a[3].wrapping_mul(b[0]))
            .wrapping_add(a[4].wrapping_mul(b[7]))
            .wrapping_add(a[5].wrapping_mul(b[6]))
            .wrapping_sub(a[6].wrapping_mul(b[5]))
            .wrapping_add(a[7].wrapping_mul(b[4]));
    
        result[4] = a[0].wrapping_mul(b[4])
            .wrapping_sub(a[1].wrapping_mul(b[5]))
            .wrapping_sub(a[2].wrapping_mul(b[6]))
            .wrapping_sub(a[3].wrapping_mul(b[7]))
            .wrapping_add(a[4].wrapping_mul(b[0]))
            .wrapping_add(a[5].wrapping_mul(b[1]))
            .wrapping_add(a[6].wrapping_mul(b[2]))
            .wrapping_add(a[7].wrapping_mul(b[3]));
    
        result[5] = a[0].wrapping_mul(b[5])
            .wrapping_add(a[1].wrapping_mul(b[4]))
            .wrapping_sub(a[2].wrapping_mul(b[7]))
            .wrapping_add(a[3].wrapping_mul(b[6]))
            .wrapping_sub(a[4].wrapping_mul(b[1]))
            .wrapping_add(a[5].wrapping_mul(b[0]))
            .wrapping_add(a[6].wrapping_mul(b[3]))
            .wrapping_add(a[7].wrapping_mul(b[2]));
    
        result[6] = a[0].wrapping_mul(b[6])
            .wrapping_add(a[1].wrapping_mul(b[7]))
            .wrapping_add(a[2].wrapping_mul(b[4]))
            .wrapping_sub(a[3].wrapping_mul(b[5]))
            .wrapping_sub(a[4].wrapping_mul(b[2]))
            .wrapping_add(a[5].wrapping_mul(b[3]))
            .wrapping_add(a[6].wrapping_mul(b[0]))
            .wrapping_add(a[7].wrapping_mul(b[1]));
    
        result[7] = a[0].wrapping_mul(b[7])
            .wrapping_sub(a[1].wrapping_mul(b[6]))
            .wrapping_add(a[2].wrapping_mul(b[5]))
            .wrapping_add(a[3].wrapping_mul(b[4]))
            .wrapping_sub(a[4].wrapping_mul(b[3]))
            .wrapping_add(a[5].wrapping_mul(b[2]))
            .wrapping_add(a[6].wrapping_mul(b[1]))
            .wrapping_add(a[7].wrapping_mul(b[0]));
    
        result
    }
    
    fn octonion_hash(input_hash: &[u8; 32]) -> [u64; 8] {
        let mut oct = [
            input_hash[0] as u64,
            input_hash[1] as u64,
            input_hash[2] as u64,
            input_hash[3] as u64,
            input_hash[4] as u64,
            input_hash[5] as u64,
            input_hash[6] as u64,
            input_hash[7] as u64,
        ];
    
        for i in 8..input_hash.len() {
            let rotation = [
                input_hash[i % 32] as u64,
                input_hash[(i + 1) % 32] as u64,
                input_hash[(i + 2) % 32] as u64,
                input_hash[(i + 3) % 32] as u64,
                input_hash[(i + 4) % 32] as u64,
                input_hash[(i + 5) % 32] as u64,
                input_hash[(i + 6) % 32] as u64,
                input_hash[(i + 7) % 32] as u64,
            ];
    
            oct = Self::octonion_multiply(&oct, &rotation);
        }
    
        oct
    }    

    // Non-linear S-box generation
    pub fn generate_non_linear_sbox(input: u8, key: u8) -> u8 {
        let mut result = input;

        // Combination of multiplication and bitwise permutation
        result = result.wrapping_mul(key);          // Multiply by the key
        result = (result >> 3) | (result << 5);    // Bitwise permutation (Rotation)
        result ^= 0x5A;                             // XOR with 0x5A

        result
    }

    pub fn cryptix_hash(&self, hash: Hash) -> Hash {
        // Convert the hash to its byte representation
        let hash_bytes = hash.as_bytes();

        // Create an array containing the nibbles (4-bit halves of the bytes)
        let nibbles: [u8; 64] = {
            let o_bytes = hash.as_bytes();
            let mut arr = [0u8; 64];
            for (i, &byte) in o_bytes.iter().enumerate() {
                arr[2 * i]     = byte >> 4;               // Store the high nibble
                arr[2 * i + 1] = byte & 0x0F;             // Store the low nibble
            }
            arr
        };
    
        let mut product = [0u8; 32];
    
        for i in 0..32 {
            let mut sum1 = 0u16;
            let mut sum2 = 0u16;
            for j in 0..64 {
                let elem = nibbles[j] as u16;
                sum1 += self.0[2 * i][j] * elem;   // Matrix multiplication
                sum2 += self.0[2 * i + 1][j] * elem;
            }
            
            // Combine the nibbles back into bytes
            let a_nibble = (sum1 & 0xF) ^ ((sum2 >> 4) & 0xF) ^ ((sum1 >> 8) & 0xF); // Combine the bits
            let b_nibble = (sum2 & 0xF) ^ ((sum1 >> 4) & 0xF) ^ ((sum2 >> 8) & 0xF);
    
            product[i] = ((a_nibble << 4) | b_nibble) as u8; // Combine to form final byte
        }

        // XOR the product with the original hash   
        product.iter_mut().zip(hash.as_bytes()).for_each(|(p, h)| *p ^= h); // Apply XOR with the hash
        
        // ### Memory Hard
                
        // **Apply nonlinear S-Box**
        let mut sbox: [u8; 256] = [0; 256];

        // Fill the S-box using the bytes of the hash
        for i in 0..256 {
            sbox[i] = hash_bytes[i % hash_bytes.len()]; // Wrap around the hash bytes
        }

        // Number of iterations depends on the first byte of the product
        let iterations = 3 + (product[0] % 4);  // Modulo 4 gives values ​​from 0 to 3 → +3 gives 3 to 6

        for _ in 0..iterations {  
            let mut temp_sbox = sbox;
            
            for i in 0..256 { 
                let mut value = temp_sbox[i];  
                
                // Generate nonlinear value based on Hash + Product
                value = Self::generate_non_linear_sbox(value, hash_bytes[i % hash_bytes.len()] ^ product[i % product.len()]); 
                
                // Bitwise rotation + XOR
                value ^= value.rotate_left(4) | value.rotate_right(2); 
                temp_sbox[i] = value; 
            }

            sbox = temp_sbox; // Update the S-Box after the round
        }

        // Apply the final S-Box transformation to the product with XOR
        for i in 0..32 {
            product[i] ^= sbox[product[i] as usize]; // XOR product with S-Box values
        }

        // **Branches for Byte Manipulation**
        for i in 0..32 {
            // Nonce from s-box product
            let cryptix_nonce = product[i];
            let condition = (product[i] ^ (hash_bytes[i % hash_bytes.len()] ^ cryptix_nonce)) % 9;
            
            match condition {
                0 => {
                    // Main case 0
                    product[i] = product[i].wrapping_add(13);  // Add 13
                    product[i] = product[i].rotate_left(3);    // Rotate left by 3 bits
                    
                    // Nested cases in case 0
                    if product[i] > 100 {
                        product[i] = product[i].wrapping_add(0x20);  // Add 0x20 if greater than 100
                    } else {
                        product[i] = product[i].wrapping_sub(0x10);  // Subtract 0x10 if not
                    }
                },
                1 => {
                    // Main case 1
                    product[i] = product[i].wrapping_sub(7);   // Subtract 7
                    product[i] = product[i].rotate_left(5);    // Rotate left by 5 bits
                    
                    // Nested case inside case 1
                    if product[i] % 2 == 0 {
                        product[i] = product[i].wrapping_add(0x11); // Add 0x11 if even
                    } else {
                        product[i] = product[i].wrapping_sub(0x05); // Subtract 0x05 if odd
                    }
                },
                2 => {
                    // Main case 2
                    product[i] ^= 0x5A;                       // XOR with 0x5A
                    product[i] = product[i].wrapping_add(0xAC); // Add 0xAC
                    
                    // Nested case inside case 2
                    if product[i] > 0x50 {
                        product[i] = product[i].wrapping_mul(2);   // Multiply by 2 if greater than 0x50
                    } else {
                        product[i] = product[i].wrapping_div(3);   // Divide by 3 if not
                    }
                },
                3 => {
                    // Main case 3
                    product[i] = product[i].wrapping_mul(17);   // Multiply by 17
                    product[i] ^= 0xAA;                        // XOR with 0xAA
                    
                    // Nested case inside case 3
                    if product[i] % 4 == 0 {
                        product[i] = product[i].rotate_left(4); // Rotate left by 4 bits if divisible by 4
                    } else {
                        product[i] = product[i].rotate_right(2); // Rotate right by 2 bits if not
                    }
                },
                4 => {
                    // Main case 4
                    product[i] = product[i].wrapping_sub(29);   // Subtract 29
                    product[i] = product[i].rotate_left(1);     // Rotate left by 1 bit
                    
                    // Nested case inside case 4
                    if product[i] < 50 {
                        product[i] = product[i].wrapping_add(0x55); // Add 0x55 if less than 50
                    } else {
                        product[i] = product[i].wrapping_sub(0x22); // Subtract 0x22 if not
                    }
                },
                5 => {
                    // Main case 5
                    product[i] = product[i].wrapping_add(0xAA ^ cryptix_nonce as u8); // Add XOR of 0xAA and nonce
                    product[i] ^= 0x45;                        // XOR with 0x45
                    
                    // Nested case inside case 5
                    if product[i] & 0x0F == 0 {
                        product[i] = product[i].rotate_left(6); // Rotate left by 6 bits if lower nibble is 0
                    } else {
                        product[i] = product[i].rotate_right(3); // Rotate right by 3 bits if not
                    }
                },
                6 => {
                    // Main case 6
                    product[i] = product[i].wrapping_add(0x33);  // Add 0x33
                    product[i] = product[i].rotate_right(4);     // Rotate right by 4 bits
                    
                    // Nested case inside case 6
                    if product[i] < 0x80 {
                        product[i] = product[i].wrapping_sub(0x22); // Subtract 0x22 if less than 0x80
                    } else {
                        product[i] = product[i].wrapping_add(0x44); // Add 0x44 if not
                    }
                },
                7 => {
                    // Main case 7
                    product[i] = product[i].wrapping_mul(3);     // Multiply by 3
                    product[i] = product[i].rotate_left(2);      // Rotate left by 2 bits
                    
                    // Nested case inside case 7
                    if product[i] > 0x50 {
                        product[i] = product[i].wrapping_add(0x11); // Add 0x11 if greater than 0x50
                    } else {
                        product[i] = product[i].wrapping_sub(0x11); // Subtract 0x11 if not
                    }
                },
                8 => {
                    // Main case 8
                    product[i] = product[i].wrapping_sub(0x10);   // Subtract 0x10
                    product[i] = product[i].rotate_right(3);      // Rotate right by 3 bits
                    
                    // Nested case inside case 8
                    if product[i] % 3 == 0 {
                        product[i] = product[i].wrapping_add(0x55); // Add 0x55 if divisible by 3
                    } else {
                        product[i] = product[i].wrapping_sub(0x33); // Subtract 0x33 if not
                    }
                },
                _ => unreachable!(), // This should never happen
            }
        }

        // ** Octonion Function **
        let octonion_result = Self::octonion_hash(&product); // Compute the octonion hash of the product
        
        // XOR with u64 values - convert to u8
        for i in 0..32 {
            let oct_value = octonion_result[i / 8];
            
            // Extract the relevant byte from the u64 value
            let oct_value_u8 = ((oct_value >> (8 * (i % 8))) & 0xFF) as u8; 

            // XOR the values and store the result in the product
            product[i] ^= oct_value_u8;
        }

        // Final Cryptixhash v2
        CryptixHashV2::hash(Hash::from_bytes(product)) // Return
    }
}

pub fn array_from_fn<F, T, const N: usize>(mut cb: F) -> [T; N]
where
    F: FnMut(usize) -> T,
{
    let mut idx = 0;
    [(); N].map(|_| {
        let res = cb(idx);
        idx += 1;
        res
    })
}

#[cfg(test)]
mod tests {
    use super::Matrix;
    use crate::xoshiro::XoShiRo256PlusPlus;
    use cryptix_hashes::Hash;

    #[test]
    fn test_compute_rank() {
        let zero = Matrix([[0; 64]; 64]);
        assert_eq!(zero.compute_rank(), 0);
        let mut matrix = zero;
        let mut gen = XoShiRo256PlusPlus::new(Hash::from_bytes([42; 32]));
        matrix.0.iter_mut().for_each(|row| {
            row.iter_mut().for_each(|val| {
                *val = gen.u64() as u16;
            })
        });
        assert_eq!(matrix.compute_rank(), 64);

        matrix.0[0] = matrix.0[1];
        assert_eq!(matrix.compute_rank(), 63);
    }

    #[test]
    fn test_cryptix_hash() {
        let expected_hash = Hash::from_bytes([
            135, 104, 159, 55, 153, 67, 234, 249, 183, 71, 92, 169, 83, 37, 104, 119, 114, 191, 204, 104, 252, 120, 153, 202, 235, 68,
            9, 236, 69, 144, 195, 37,
        ]);
        #[rustfmt::skip]
            let test_matrix = Matrix([
            [13, 2, 14, 13, 2, 15, 14, 3, 10, 4, 1, 8, 4, 3, 8, 15, 15, 15, 15, 15, 2, 11, 15, 15, 15, 1, 7, 12, 12, 4, 2, 0, 6, 1, 14, 10, 12, 14, 15, 8, 10, 12, 0, 5, 13, 3, 14, 10, 10, 6, 12, 11, 11, 7, 6, 6, 10, 2, 2, 4, 11, 12, 0, 5],
            [4, 13, 0, 2, 1, 15, 13, 13, 11, 2, 5, 12, 15, 7, 0, 10, 7, 2, 6, 3, 12, 0, 12, 0, 2, 6, 7, 7, 7, 7, 10, 12, 11, 14, 12, 12, 4, 11, 10, 0, 10, 11, 2, 10, 1, 7, 7, 12, 15, 9, 5, 14, 9, 12, 3, 0, 12, 13, 4, 13, 8, 15, 11, 6],
            [14, 6, 15, 9, 8, 2, 2, 12, 2, 3, 4, 12, 13, 15, 4, 5, 13, 4, 3, 0, 14, 3, 5, 14, 3, 13, 4, 15, 9, 12, 7, 15, 5, 1, 13, 12, 9, 9, 8, 11, 14, 11, 4, 10, 12, 6, 12, 8, 6, 3, 9, 8, 1, 6, 0, 5, 8, 9, 12, 5, 14, 15, 2, 2],
            [9, 6, 7, 6, 0, 11, 5, 6, 2, 14, 12, 6, 4, 13, 8, 9, 2, 1, 9, 7, 4, 5, 10, 8, 11, 11, 11, 15, 7, 11, 1, 14, 3, 8, 14, 8, 2, 8, 13, 7, 8, 8, 15, 7, 1, 13, 7, 9, 1, 7, 15, 15, 0, 0, 12, 15, 13, 5, 13, 10, 1, 5, 6, 13],
            [4, 0, 12, 10, 6, 11, 14, 2, 2, 15, 4, 1, 2, 4, 2, 12, 13, 1, 9, 10, 8, 0, 2, 10, 13, 8, 9, 7, 5, 3, 8, 2, 6, 6, 1, 12, 3, 0, 1, 4, 2, 8, 3, 13, 6, 15, 0, 13, 14, 4, 15, 0, 7, 3, 7, 8, 5, 14, 14, 5, 5, 0, 1, 2],
            [12, 14, 6, 3, 3, 4, 6, 7, 1, 3, 2, 7, 15, 15, 15, 10, 9, 12, 0, 6, 3, 8, 5, 0, 13, 5, 0, 6, 0, 14, 2, 12, 10, 4, 11, 2, 10, 7, 7, 6, 8, 11, 4, 4, 11, 9, 3, 12, 10, 5, 2, 6, 5, 5, 10, 13, 12, 10, 1, 6, 14, 7, 12, 4],
            [7, 14, 6, 7, 7, 12, 4, 1, 8, 6, 8, 13, 13, 5, 12, 14, 10, 8, 6, 2, 12, 3, 8, 15, 5, 15, 15, 3, 14, 0, 8, 6, 9, 12, 9, 7, 3, 8, 4, 0, 7, 14, 3, 3, 13, 14, 3, 7, 3, 2, 2, 3, 3, 12, 6, 7, 4, 1, 14, 10, 6, 10, 2, 9],
            [14, 11, 15, 5, 7, 10, 1, 11, 4, 2, 6, 2, 9, 7, 4, 0, 9, 12, 11, 2, 3, 13, 1, 5, 4, 10, 5, 6, 6, 12, 8, 1, 1, 15, 4, 2, 12, 12, 0, 4, 14, 3, 11, 1, 7, 5, 9, 4, 3, 15, 7, 3, 15, 9, 8, 3, 8, 3, 3, 6, 7, 6, 9, 2],
            [10, 4, 6, 10, 5, 2, 15, 12, 0, 14, 14, 15, 14, 0, 12, 9, 1, 12, 4, 5, 5, 2, 10, 4, 2, 13, 11, 3, 1, 8, 10, 0, 7, 0, 12, 4, 11, 1, 14, 6, 14, 5, 5, 11, 11, 1, 3, 8, 0, 6, 11, 11, 8, 4, 7, 6, 14, 4, 9, 14, 9, 7, 13, 9],
            [12, 7, 9, 8, 2, 3, 3, 5, 14, 8, 0, 9, 7, 4, 2, 15, 15, 3, 11, 11, 8, 5, 7, 5, 0, 15, 10, 8, 0, 13, 1, 14, 8, 10, 1, 4, 13, 1, 13, 3, 11, 11, 2, 3, 10, 6, 8, 14, 15, 2, 10, 10, 12, 7, 7, 6, 6, 3, 13, 8, 1, 14, 2, 1],
            [2, 11, 6, 9, 13, 3, 12, 6, 0, 4, 6, 13, 8, 14, 6, 9, 10, 2, 10, 8, 4, 13, 6, 5, 0, 13, 15, 4, 2, 2, 1, 7, 5, 3, 3, 13, 7, 3, 5, 9, 15, 14, 14, 6, 0, 15, 11, 2, 4, 15, 6, 9, 8, 9, 15, 2, 6, 9, 15, 8, 4, 4, 11, 1],
            [10, 11, 8, 3, 11, 13, 10, 2, 2, 5, 2, 14, 15, 10, 2, 11, 0, 1, 8, 2, 14, 1, 10, 0, 3, 7, 5, 10, 7, 8, 15, 7, 2, 5, 13, 4, 10, 3, 6, 2, 3, 9, 6, 11, 7, 14, 1, 11, 9, 3, 3, 7, 6, 0, 9, 11, 4, 10, 4, 1, 9, 7, 4, 15],
            [13, 8, 15, 14, 11, 12, 5, 3, 9, 14, 1, 5, 14, 13, 14, 5, 13, 5, 4, 10, 9, 9, 0, 0, 6, 12, 5, 7, 2, 7, 2, 6, 6, 6, 1, 12, 9, 15, 7, 11, 11, 10, 11, 1, 10, 10, 0, 8, 1, 4, 5, 5, 8, 10, 10, 15, 6, 8, 13, 11, 11, 3, 15, 5],
            [8, 11, 5, 10, 1, 10, 9, 1, 12, 7, 6, 11, 1, 1, 4, 1, 2, 8, 4, 4, 7, 7, 8, 2, 7, 1, 14, 1, 8, 15, 15, 12, 10, 4, 15, 11, 3, 6, 10, 7, 4, 0, 10, 9, 11, 7, 1, 14, 4, 14, 3, 14, 10, 4, 13, 12, 5, 3, 12, 7, 10, 8, 0, 3],
            [9, 11, 6, 15, 14, 10, 0, 4, 7, 7, 6, 0, 7, 7, 12, 15, 5, 4, 12, 3, 7, 3, 0, 12, 2, 7, 11, 6, 7, 3, 2, 8, 5, 11, 9, 4, 3, 8, 11, 12, 3, 5, 14, 12, 4, 13, 12, 0, 3, 14, 4, 9, 1, 1, 9, 14, 10, 14, 8, 15, 6, 14, 10, 15],
            [10, 14, 10, 0, 10, 12, 15, 0, 3, 9, 11, 10, 3, 5, 1, 1, 9, 1, 7, 15, 7, 8, 10, 10, 12, 11, 5, 1, 10, 3, 6, 6, 13, 0, 13, 1, 4, 5, 9, 4, 9, 15, 8, 4, 13, 13, 4, 5, 5, 11, 1, 13, 15, 3, 10, 15, 7, 11, 10, 15, 8, 12, 10, 3],
            [8, 5, 11, 3, 8, 13, 15, 15, 3, 12, 1, 13, 1, 7, 1, 5, 6, 13, 7, 8, 5, 1, 12, 3, 10, 7, 12, 6, 14, 12, 15, 5, 3, 12, 2, 15, 11, 13, 1, 13, 8, 5, 8, 0, 13, 15, 7, 13, 6, 13, 10, 1, 11, 0, 8, 9, 5, 11, 2, 9, 9, 10, 4, 15],
            [0, 4, 12, 14, 3, 1, 7, 5, 11, 13, 5, 3, 11, 12, 6, 8, 10, 15, 11, 8, 7, 10, 0, 2, 5, 15, 6, 10, 4, 2, 3, 1, 13, 7, 6, 12, 14, 7, 6, 14, 12, 10, 6, 14, 12, 0, 12, 11, 6, 9, 3, 1, 12, 15, 15, 3, 5, 5, 10, 11, 7, 15, 13, 3],
            [12, 14, 2, 14, 13, 6, 15, 7, 8, 8, 14, 13, 9, 2, 2, 10, 3, 15, 6, 10, 11, 7, 13, 0, 12, 1, 5, 8, 8, 12, 1, 11, 1, 3, 2, 4, 10, 7, 7, 7, 3, 10, 7, 2, 2, 3, 0, 1, 13, 5, 8, 2, 14, 0, 11, 13, 9, 3, 13, 2, 14, 2, 15, 4],
            [0, 0, 13, 6, 9, 12, 15, 7, 8, 0, 7, 4, 12, 15, 3, 2, 7, 1, 14, 4, 9, 3, 13, 12, 11, 12, 9, 9, 3, 7, 10, 9, 1, 9, 10, 2, 10, 14, 11, 0, 14, 4, 15, 12, 12, 9, 9, 8, 14, 1, 9, 14, 0, 6, 1, 0, 13, 9, 7, 6, 13, 2, 3, 9],
            [8, 0, 10, 13, 0, 7, 9, 7, 5, 1, 0, 3, 7, 10, 3, 15, 1, 15, 3, 11, 2, 6, 3, 10, 0, 10, 10, 3, 4, 15, 8, 6, 11, 11, 7, 5, 8, 5, 7, 15, 1, 11, 7, 13, 13, 6, 13, 13, 4, 2, 3, 15, 9, 5, 10, 6, 6, 6, 3, 11, 15, 13, 1, 15],
            [1, 1, 2, 10, 2, 2, 9, 5, 9, 2, 0, 1, 14, 2, 11, 6, 11, 6, 1, 0, 13, 7, 14, 1, 15, 14, 13, 7, 12, 11, 8, 11, 2, 11, 6, 10, 2, 3, 0, 0, 15, 0, 4, 6, 4, 12, 5, 5, 7, 14, 10, 6, 0, 3, 13, 0, 8, 1, 13, 10, 5, 1, 7, 5],
            [0, 5, 2, 12, 10, 2, 5, 1, 14, 0, 1, 4, 15, 11, 8, 7, 11, 14, 15, 6, 4, 1, 6, 6, 7, 13, 12, 5, 13, 2, 1, 6, 2, 13, 5, 15, 0, 8, 8, 6, 5, 5, 2, 0, 3, 13, 14, 2, 10, 5, 7, 6, 14, 5, 1, 4, 11, 2, 11, 1, 8, 15, 2, 4],
            [9, 9, 4, 5, 2, 5, 3, 12, 14, 5, 1, 3, 3, 0, 0, 6, 7, 14, 0, 15, 14, 11, 3, 10, 1, 9, 4, 14, 7, 14, 1, 0, 15, 11, 5, 9, 4, 0, 0, 10, 4, 4, 0, 7, 8, 15, 12, 8, 10, 8, 1, 2, 1, 11, 12, 14, 14, 14, 8, 10, 1, 5, 13, 10],
            [5, 10, 4, 4, 11, 10, 0, 6, 0, 12, 10, 5, 9, 11, 8, 10, 11, 3, 11, 14, 12, 9, 4, 6, 11, 12, 8, 7, 6, 14, 0, 6, 12, 4, 5, 3, 9, 0, 11, 6, 1, 3, 2, 12, 8, 9, 7, 12, 14, 7, 12, 6, 11, 13, 0, 2, 1, 3, 1, 8, 12, 2, 15, 15],
            [10, 11, 2, 3, 11, 10, 1, 7, 1, 10, 10, 14, 5, 13, 10, 3, 11, 15, 9, 14, 11, 11, 3, 15, 11, 6, 15, 13, 13, 1, 1, 10, 5, 1, 5, 11, 10, 3, 9, 12, 12, 1, 5, 6, 3, 3, 1, 1, 12, 8, 3, 15, 6, 2, 8, 14, 3, 4, 10, 9, 7, 13, 2, 6],
            [12, 0, 1, 0, 4, 3, 3, 6, 8, 3, 1, 13, 6, 12, 1, 1, 1, 4, 12, 4, 4, 9, 9, 14, 15, 3, 6, 4, 11, 1, 12, 5, 6, 0, 10, 9, 1, 8, 14, 5, 2, 8, 4, 15, 12, 13, 7, 14, 12, 2, 6, 9, 4, 13, 0, 15, 10, 10, 6, 12, 7, 12, 9, 10],
            [0, 8, 5, 11, 12, 12, 11, 7, 2, 9, 2, 15, 1, 1, 0, 0, 6, 5, 10, 1, 11, 12, 8, 7, 1, 7, 10, 4, 2, 8, 2, 5, 1, 1, 2, 9, 2, 0, 3, 7, 5, 1, 5, 5, 3, 1, 4, 3, 14, 8, 11, 7, 8, 0, 2, 13, 3, 15, 1, 13, 14, 15, 11, 13],
            [8, 13, 5, 14, 2, 9, 9, 13, 15, 8, 2, 14, 4, 2, 6, 0, 1, 13, 10, 13, 6, 12, 15, 11, 6, 11, 9, 9, 2, 9, 6, 14, 2, 9, 12, 1, 13, 9, 5, 11, 10, 4, 4, 5, 8, 9, 13, 10, 9, 0, 5, 15, 4, 12, 7, 10, 6, 5, 5, 15, 8, 8, 11, 14],
            [6, 9, 6, 7, 1, 15, 0, 1, 4, 15, 5, 3, 10, 9, 15, 9, 14, 12, 7, 6, 3, 0, 12, 8, 12, 2, 11, 8, 11, 8, 1, 10, 10, 7, 7, 5, 3, 5, 1, 2, 13, 11, 2, 5, 2, 10, 10, 1, 14, 14, 8, 1, 11, 1, 2, 6, 15, 10, 8, 7, 10, 7, 0, 3],
            [12, 6, 11, 1, 1, 7, 8, 1, 5, 5, 8, 4, 6, 5, 6, 4, 2, 8, 4, 1, 0, 0, 14, 2, 10, 14, 14, 11, 2, 9, 14, 15, 12, 14, 9, 3, 7, 14, 4, 7, 12, 9, 3, 5, 1, 0, 12, 9, 10, 5, 11, 12, 10, 10, 6, 14, 6, 13, 13, 5, 5, 10, 13, 10],
            [12, 6, 13, 0, 8, 0, 10, 6, 15, 15, 7, 3, 0, 10, 13, 14, 10, 13, 5, 13, 15, 14, 3, 4, 10, 10, 9, 6, 6, 15, 2, 7, 0, 10, 6, 14, 2, 9, 11, 7, 5, 5, 13, 14, 11, 15, 9, 4, 2, 0, 15, 5, 4, 14, 14, 1, 3, 4, 5, 8, 1, 1, 10, 12],
            [2, 5, 0, 4, 11, 5, 5, 6, 10, 4, 6, 7, 10, 3, 0, 14, 14, 0, 12, 15, 11, 12, 13, 7, 6, 3, 9, 1, 9, 8, 8, 8, 4, 10, 3, 1, 7, 10, 3, 2, 12, 6, 15, 14, 0, 6, 8, 10, 1, 9, 12, 12, 15, 7, 1, 11, 15, 13, 0, 4, 10, 0, 12, 11],
            [8, 12, 14, 15, 14, 15, 10, 0, 2, 14, 3, 1, 2, 6, 0, 2, 1, 7, 9, 0, 15, 13, 5, 14, 6, 8, 15, 4, 15, 6, 10, 6, 15, 3, 12, 8, 5, 4, 10, 5, 3, 0, 4, 13, 10, 9, 8, 4, 6, 3, 9, 6, 12, 11, 9, 13, 8, 10, 9, 9, 8, 12, 1, 2],
            [11, 10, 15, 15, 5, 14, 15, 7, 5, 9, 14, 14, 7, 11, 6, 6, 3, 8, 2, 3, 4, 14, 11, 1, 12, 15, 11, 6, 0, 0, 13, 7, 14, 3, 12, 14, 0, 15, 6, 1, 11, 2, 11, 8, 3, 13, 4, 12, 10, 13, 7, 14, 9, 13, 3, 10, 2, 14, 13, 4, 12, 13, 14, 10],
            [1, 11, 2, 12, 1, 10, 7, 12, 3, 3, 14, 9, 1, 10, 0, 11, 8, 10, 12, 12, 4, 12, 2, 11, 5, 0, 3, 15, 8, 2, 14, 3, 10, 2, 1, 13, 6, 14, 0, 0, 8, 11, 6, 13, 15, 10, 12, 7, 7, 11, 14, 9, 2, 7, 6, 8, 14, 9, 14, 10, 11, 9, 9, 12],
            [5, 10, 14, 2, 1, 4, 11, 5, 10, 2, 13, 9, 6, 12, 11, 5, 13, 4, 5, 14, 8, 7, 15, 9, 8, 4, 5, 2, 9, 11, 5, 3, 12, 2, 6, 1, 7, 4, 11, 4, 15, 0, 5, 2, 13, 11, 11, 2, 15, 10, 0, 12, 5, 8, 10, 1, 4, 11, 3, 13, 11, 7, 9, 14],
            [9, 8, 10, 5, 0, 2, 5, 8, 7, 3, 3, 6, 11, 1, 13, 15, 4, 4, 11, 6, 2, 6, 13, 11, 2, 6, 9, 4, 5, 13, 12, 2, 8, 7, 7, 12, 14, 15, 5, 12, 7, 0, 15, 15, 0, 5, 15, 0, 3, 9, 10, 15, 9, 11, 10, 10, 5, 3, 9, 3, 12, 13, 0, 13],
            [1, 11, 15, 0, 10, 5, 3, 5, 6, 7, 1, 11, 4, 11, 4, 2, 5, 12, 2, 5, 5, 6, 1, 5, 14, 9, 1, 5, 14, 12, 6, 10, 0, 8, 5, 11, 11, 11, 12, 10, 8, 10, 10, 1, 14, 1, 0, 8, 4, 7, 0, 11, 3, 1, 11, 12, 11, 8, 14, 15, 9, 3, 1, 14],
            [14, 11, 12, 12, 4, 6, 8, 14, 15, 1, 11, 2, 13, 3, 6, 2, 7, 1, 8, 1, 4, 9, 11, 15, 8, 1, 10, 13, 4, 13, 2, 7, 7, 10, 5, 2, 12, 12, 12, 3, 10, 8, 2, 11, 0, 3, 8, 9, 4, 2, 15, 7, 15, 6, 4, 6, 12, 7, 14, 9, 9, 8, 14, 12],
            [15, 4, 8, 12, 11, 11, 9, 5, 0, 0, 7, 6, 10, 5, 8, 2, 5, 6, 14, 11, 13, 0, 13, 15, 5, 4, 9, 15, 13, 12, 14, 15, 10, 2, 3, 6, 10, 14, 1, 8, 6, 7, 10, 1, 14, 9, 12, 13, 7, 2, 12, 10, 6, 11, 15, 1, 15, 11, 13, 0, 6, 13, 7, 15],
            [3, 3, 12, 5, 14, 9, 14, 14, 8, 0, 9, 1, 2, 2, 14, 11, 7, 1, 3, 1, 14, 15, 12, 8, 14, 2, 4, 13, 10, 5, 10, 8, 1, 7, 6, 5, 4, 2, 11, 5, 4, 13, 14, 6, 13, 15, 6, 6, 7, 12, 11, 5, 13, 10, 9, 13, 9, 14, 5, 6, 7, 14, 11, 7],
            [14, 12, 11, 5, 0, 5, 10, 5, 7, 1, 7, 11, 1, 0, 13, 6, 5, 14, 3, 0, 5, 14, 6, 7, 8, 5, 8, 6, 6, 3, 6, 1, 8, 3, 10, 7, 15, 6, 11, 6, 6, 7, 13, 2, 2, 0, 0, 11, 1, 15, 2, 14, 5, 1, 4, 8, 0, 1, 8, 0, 1, 1, 2, 2],
            [10, 13, 13, 3, 15, 14, 9, 12, 15, 15, 8, 5, 8, 10, 5, 9, 6, 6, 7, 15, 1, 0, 14, 9, 1, 11, 6, 11, 13, 4, 6, 14, 9, 12, 13, 8, 14, 6, 14, 2, 3, 15, 4, 4, 14, 4, 9, 12, 8, 0, 9, 11, 13, 10, 8, 14, 3, 5, 7, 11, 6, 7, 15, 2],
            [9, 9, 11, 6, 11, 0, 5, 4, 8, 10, 8, 11, 2, 12, 8, 7, 11, 13, 6, 1, 13, 13, 11, 4, 5, 7, 7, 9, 6, 4, 12, 0, 11, 8, 6, 12, 11, 4, 15, 11, 12, 8, 11, 11, 1, 3, 6, 14, 9, 6, 7, 5, 0, 10, 3, 15, 13, 7, 0, 1, 13, 15, 1, 14],
            [10, 6, 8, 7, 3, 6, 9, 15, 1, 3, 10, 14, 9, 0, 0, 10, 0, 15, 2, 0, 0, 0, 6, 0, 13, 9, 9, 1, 8, 6, 13, 2, 1, 9, 14, 9, 1, 4, 8, 4, 2, 0, 8, 5, 0, 11, 12, 15, 13, 1, 14, 14, 15, 7, 8, 4, 4, 12, 1, 12, 8, 3, 9, 5],
            [12, 11, 1, 4, 10, 14, 8, 12, 2, 4, 15, 2, 9, 7, 7, 11, 15, 12, 10, 11, 7, 4, 13, 0, 8, 6, 8, 8, 10, 5, 5, 13, 3, 7, 9, 13, 13, 14, 6, 8, 1, 5, 7, 12, 4, 4, 6, 9, 13, 1, 6, 1, 6, 14, 5, 8, 2, 10, 4, 10, 1, 9, 6, 15],
            [4, 13, 4, 9, 6, 11, 1, 8, 7, 11, 11, 1, 3, 10, 12, 11, 1, 10, 6, 10, 0, 7, 3, 0, 0, 6, 3, 9, 2, 1, 4, 8, 2, 10, 2, 15, 9, 15, 14, 14, 15, 14, 3, 2, 7, 6, 6, 10, 8, 8, 4, 11, 1, 13, 6, 0, 2, 10, 0, 11, 15, 14, 6, 9],
            [15, 0, 12, 13, 0, 9, 10, 4, 11, 5, 10, 0, 8, 7, 3, 2, 12, 6, 3, 8, 5, 15, 14, 2, 13, 13, 6, 11, 5, 6, 9, 10, 14, 5, 14, 4, 9, 7, 5, 11, 13, 2, 7, 1, 14, 9, 0, 7, 8, 12, 11, 15, 2, 1, 5, 11, 3, 7, 5, 1, 6, 3, 8, 6],
            [0, 3, 8, 1, 4, 6, 3, 1, 3, 8, 2, 0, 15, 15, 14, 15, 13, 10, 11, 9, 2, 11, 5, 12, 3, 3, 0, 1, 5, 3, 11, 6, 10, 11, 8, 5, 7, 15, 4, 12, 8, 8, 12, 12, 12, 1, 9, 4, 11, 6, 10, 11, 1, 12, 8, 12, 5, 6, 1, 14, 2, 10, 3, 0],
            [10, 13, 6, 9, 11, 1, 4, 10, 0, 13, 8, 7, 4, 12, 15, 5, 14, 12, 6, 9, 0, 0, 10, 5, 13, 10, 15, 3, 0, 8, 7, 0, 9, 8, 10, 6, 11, 8, 10, 13, 11, 7, 5, 5, 9, 13, 1, 15, 0, 5, 15, 5, 4, 7, 9, 9, 15, 8, 2, 6, 3, 8, 5, 8],
            [14, 0, 6, 2, 4, 12, 2, 13, 6, 10, 5, 2, 2, 1, 6, 11, 1, 6, 9, 13, 0, 13, 9, 3, 12, 4, 3, 8, 7, 0, 9, 12, 0, 1, 7, 10, 10, 7, 3, 9, 13, 5, 15, 4, 13, 0, 8, 5, 4, 14, 11, 3, 3, 13, 15, 9, 9, 12, 9, 5, 2, 0, 1, 14],
            [4, 14, 13, 0, 14, 15, 11, 10, 11, 1, 3, 3, 9, 1, 12, 8, 6, 5, 15, 11, 1, 7, 5, 3, 8, 13, 0, 13, 11, 5, 8, 1, 8, 6, 13, 4, 13, 7, 12, 6, 5, 5, 7, 0, 12, 1, 1, 8, 1, 6, 4, 2, 8, 8, 15, 11, 11, 11, 4, 4, 4, 7, 13, 12],
            [14, 15, 10, 0, 4, 3, 1, 9, 13, 7, 9, 9, 15, 5, 0, 3, 9, 6, 4, 7, 13, 11, 3, 2, 7, 1, 6, 8, 13, 7, 10, 4, 3, 9, 5, 9, 2, 6, 10, 7, 9, 13, 2, 14, 2, 14, 7, 2, 14, 2, 8, 8, 0, 9, 0, 9, 12, 6, 7, 7, 6, 8, 12, 13],
            [5, 15, 8, 12, 11, 3, 13, 4, 5, 14, 10, 4, 15, 15, 1, 10, 9, 14, 6, 6, 4, 12, 4, 9, 12, 2, 15, 13, 2, 5, 12, 2, 3, 2, 15, 11, 12, 2, 6, 2, 11, 6, 7, 9, 12, 10, 5, 1, 1, 5, 9, 6, 14, 11, 3, 11, 6, 10, 11, 11, 0, 12, 15, 1],
            [12, 6, 8, 10, 2, 5, 7, 9, 8, 14, 15, 15, 13, 10, 15, 3, 10, 10, 6, 10, 14, 10, 7, 5, 3, 7, 6, 12, 11, 12, 8, 9, 12, 9, 15, 15, 15, 7, 8, 3, 15, 14, 1, 12, 0, 0, 4, 0, 9, 10, 8, 7, 14, 10, 8, 14, 6, 2, 8, 1, 11, 10, 0, 1],
            [12, 1, 2, 12, 7, 10, 4, 11, 5, 14, 10, 2, 2, 9, 4, 13, 3, 14, 3, 15, 5, 0, 14, 7, 7, 15, 6, 5, 2, 8, 15, 9, 6, 6, 13, 10, 9, 8, 6, 3, 14, 7, 12, 9, 7, 8, 13, 12, 14, 13, 6, 0, 5, 1, 9, 12, 14, 0, 11, 11, 6, 3, 11, 7],
            [15, 4, 8, 12, 8, 11, 4, 15, 1, 6, 2, 13, 1, 7, 7, 12, 0, 8, 14, 14, 10, 14, 0, 12, 0, 3, 3, 11, 7, 4, 2, 13, 0, 0, 11, 2, 5, 8, 12, 11, 6, 5, 6, 0, 0, 4, 0, 0, 1, 9, 9, 11, 3, 2, 13, 4, 13, 9, 15, 4, 7, 8, 3, 2],
            [3, 13, 8, 8, 12, 10, 5, 4, 7, 13, 10, 13, 14, 3, 2, 12, 11, 0, 9, 5, 6, 4, 14, 4, 6, 9, 2, 5, 10, 3, 9, 10, 5, 0, 12, 5, 15, 5, 15, 15, 2, 12, 3, 11, 0, 15, 9, 14, 1, 5, 6, 6, 14, 5, 8, 0, 5, 9, 3, 7, 7, 12, 15, 1],
            [1, 11, 7, 4, 13, 3, 0, 8, 11, 9, 15, 1, 4, 12, 2, 12, 10, 4, 14, 3, 9, 14, 14, 2, 3, 11, 12, 4, 5, 10, 6, 15, 2, 13, 13, 9, 9, 1, 11, 12, 12, 14, 1, 5, 15, 1, 7, 14, 12, 10, 11, 13, 13, 5, 2, 4, 7, 7, 9, 4, 14, 15, 13, 10],
            [14, 15, 9, 14, 9, 5, 13, 2, 0, 0, 14, 8, 6, 2, 0, 7, 11, 10, 2, 13, 2, 14, 9, 6, 4, 11, 5, 14, 6, 1, 6, 14, 6, 3, 9, 5, 2, 9, 3, 11, 1, 14, 5, 4, 12, 5, 3, 5, 11, 3, 11, 6, 13, 7, 13, 7, 4, 9, 4, 13, 8, 3, 5, 11],
            [13, 12, 12, 13, 8, 2, 4, 2, 10, 6, 3, 5, 7, 7, 6, 13, 8, 6, 15, 4, 12, 7, 15, 4, 3, 9, 8, 15, 0, 3, 12, 1, 9, 8, 13, 10, 15, 4, 14, 1, 6, 15, 0, 4, 8, 9, 3, 1, 3, 15, 5, 5, 1, 11, 11, 10, 11, 10, 8, 8, 5, 4, 13, 0],
            [8, 4, 15, 9, 14, 9, 5, 8, 8, 10, 5, 15, 9, 8, 12, 5, 11, 10, 2, 12, 13, 1, 0, 2, 6, 13, 11, 9, 12, 0, 5, 0, 11, 5, 14, 12, 3, 4, 2, 10, 3, 12, 5, 15, 4, 8, 14, 1, 0, 13, 9, 5, 2, 4, 13, 8, 2, 5, 8, 9, 15, 3, 5, 5],
            [0, 3, 3, 4, 6, 5, 5, 1, 3, 2, 14, 5, 10, 7, 15, 11, 7, 13, 15, 4, 0, 12, 9, 15, 12, 0, 3, 1, 14, 1, 12, 9, 13, 8, 9, 15, 12, 3, 5, 11, 3, 11, 4, 1, 9, 4, 13, 7, 4, 10, 6, 14, 13, 0, 9, 11, 15, 15, 3, 3, 13, 15, 10, 15],
        ]);
        let hash = Hash::from_bytes([
            82, 46, 212, 218, 28, 192, 143, 92, 213, 66, 86, 63, 245, 241, 155, 189, 73, 159, 229, 180, 202, 105, 159, 166, 109, 172,
            128, 136, 169, 195, 97, 41,
        ]);
        assert_eq!(test_matrix.cryptix_hash(hash), expected_hash);
    }
    #[test]
    fn test_generate_matrix() {
        #[rustfmt::skip]
            let expected_matrix = Matrix([
            [4, 5, 4, 5, 4, 5, 4, 5, 4, 5, 4, 5, 4, 5, 4, 5, 15, 3, 15, 3, 15, 3, 15, 3, 15, 3, 15, 3, 15, 3, 15, 3, 2, 10, 2, 10, 2, 10, 2, 10, 2, 10, 2, 10, 2, 10, 2, 10, 14, 1, 2, 2, 14, 10, 4, 12, 4, 12, 10, 10, 10, 10, 10, 10],
            [9, 11, 1, 11, 1, 11, 9, 11, 9, 11, 9, 3, 12, 13, 11, 5, 15, 15, 5, 0, 6, 8, 1, 8, 6, 11, 15, 5, 3, 6, 7, 3, 2, 15, 14, 3, 7, 11, 14, 7, 3, 6, 14, 12, 3, 9, 5, 1, 1, 0, 8, 4, 10, 15, 9, 10, 6, 13, 1, 1, 7, 4, 4, 6],
            [2, 6, 0, 8, 11, 15, 4, 0, 5, 2, 7, 13, 15, 3, 11, 12, 6, 2, 1, 8, 13, 4, 11, 4, 10, 14, 13, 2, 6, 15, 10, 6, 6, 5, 6, 9, 3, 3, 3, 1, 9, 12, 12, 15, 6, 0, 1, 5, 7, 13, 14, 1, 10, 10, 5, 14, 4, 0, 12, 13, 2, 15, 8, 4],
            [8, 6, 5, 1, 0, 6, 4, 8, 13, 0, 8, 12, 7, 2, 4, 3, 10, 5, 9, 3, 12, 13, 2, 4, 13, 14, 7, 7, 9, 12, 10, 8, 11, 6, 14, 3, 12, 8, 8, 0, 2, 10, 0, 9, 1, 9, 7, 8, 5, 2, 9, 13, 15, 6, 13, 10, 1, 9, 1, 10, 6, 2, 10, 9],
            [4, 2, 6, 14, 4, 2, 5, 7, 15, 6, 0, 4, 11, 9, 12, 0, 3, 2, 0, 4, 10, 5, 12, 3, 3, 4, 10, 1, 0, 13, 3, 12, 15, 0, 7, 10, 2, 2, 15, 0, 2, 15, 8, 2, 15, 12, 10, 6, 6, 2, 13, 3, 8, 14, 3, 13, 10, 5, 4, 5, 1, 6, 5, 10],
            [0, 3, 13, 12, 11, 4, 11, 13, 1, 12, 4, 11, 15, 14, 13, 4, 7, 1, 3, 0, 10, 3, 8, 8, 1, 2, 5, 14, 4, 5, 14, 1, 1, 3, 3, 1, 5, 15, 7, 5, 11, 8, 8, 12, 10, 5, 7, 9, 2, 10, 13, 11, 4, 2, 12, 15, 10, 6, 6, 0, 6, 6, 3, 12],
            [9, 12, 3, 3, 5, 8, 12, 13, 7, 4, 5, 11, 4, 0, 7, 2, 2, 15, 12, 14, 12, 5, 4, 2, 8, 8, 8, 13, 6, 1, 1, 5, 0, 15, 12, 13, 8, 5, 0, 4, 13, 1, 6, 1, 12, 14, 1, 0, 13, 12, 10, 10, 1, 4, 13, 13, 8, 4, 15, 13, 6, 6, 14, 10],
            [14, 15, 8, 0, 7, 2, 5, 10, 5, 3, 12, 0, 11, 3, 4, 2, 8, 11, 6, 14, 14, 3, 3, 12, 3, 7, 6, 2, 6, 12, 15, 1, 1, 13, 0, 6, 9, 9, 7, 7, 13, 4, 4, 2, 15, 5, 2, 15, 13, 13, 10, 6, 9, 15, 2, 9, 6, 10, 6, 14, 14, 3, 5, 11],
            [6, 4, 7, 8, 11, 0, 13, 11, 0, 7, 0, 0, 13, 6, 3, 11, 15, 14, 10, 2, 7, 8, 13, 14, 8, 15, 10, 8, 14, 6, 10, 14, 3, 11, 5, 11, 13, 5, 3, 12, 3, 0, 2, 0, 6, 14, 4, 12, 4, 4, 8, 15, 7, 8, 12, 11, 3, 9, 5, 13, 10, 14, 13, 4],
            [10, 0, 0, 15, 1, 4, 13, 3, 15, 10, 2, 5, 11, 2, 9, 14, 7, 3, 2, 8, 6, 15, 0, 12, 1, 4, 1, 9, 3, 0, 15, 8, 9, 13, 0, 7, 9, 10, 6, 14, 3, 7, 9, 7, 4, 0, 11, 8, 4, 6, 5, 8, 8, 0, 5, 14, 7, 12, 12, 2, 5, 6, 5, 6],
            [12, 0, 0, 14, 8, 3, 0, 3, 13, 10, 5, 13, 5, 7, 2, 4, 13, 11, 3, 1, 11, 2, 14, 5, 10, 5, 5, 9, 12, 15, 12, 8, 1, 0, 11, 13, 8, 1, 1, 11, 10, 0, 11, 15, 13, 9, 12, 14, 5, 4, 5, 14, 2, 7, 2, 1, 4, 12, 11, 11, 9, 12, 11, 15],
            [3, 15, 9, 8, 13, 12, 15, 7, 8, 7, 14, 6, 10, 3, 0, 5, 2, 2, 6, 6, 3, 2, 5, 12, 11, 2, 10, 11, 13, 3, 9, 7, 7, 6, 8, 15, 14, 14, 11, 11, 9, 7, 1, 3, 8, 5, 11, 11, 1, 2, 15, 8, 13, 8, 11, 4, 1, 5, 3, 12, 5, 3, 7, 7],
            [13, 13, 2, 14, 4, 3, 15, 2, 0, 15, 1, 5, 4, 1, 5, 1, 4, 14, 5, 1, 11, 13, 15, 1, 3, 3, 5, 13, 14, 1, 0, 4, 6, 1, 15, 7, 7, 0, 15, 8, 15, 3, 14, 7, 7, 8, 12, 10, 2, 14, 9, 2, 11, 11, 7, 10, 4, 3, 12, 13, 4, 13, 0, 14],
            [12, 14, 15, 15, 2, 0, 0, 13, 4, 6, 4, 2, 14, 11, 5, 6, 14, 8, 14, 7, 13, 15, 6, 15, 7, 9, 1, 0, 11, 9, 9, 0, 2, 12, 8, 8, 14, 11, 7, 5, 3, 0, 11, 12, 9, 2, 8, 9, 0, 0, 9, 8, 9, 8, 2, 14, 12, 2, 0, 14, 13, 8, 4, 10],
            [7, 10, 1, 15, 12, 14, 7, 4, 7, 13, 4, 8, 13, 12, 1, 7, 10, 6, 5, 14, 14, 3, 14, 4, 11, 14, 6, 12, 15, 12, 15, 12, 4, 5, 9, 8, 7, 7, 3, 0, 5, 7, 3, 8, 4, 4, 7, 5, 6, 12, 13, 0, 12, 10, 2, 5, 14, 9, 6, 4, 13, 13, 14, 5],
            [14, 5, 8, 3, 4, 15, 13, 14, 14, 10, 7, 14, 15, 2, 11, 14, 13, 13, 12, 10, 6, 9, 5, 5, 6, 13, 15, 13, 7, 0, 15, 11, 4, 12, 15, 7, 7, 4, 3, 11, 8, 14, 5, 10, 2, 4, 4, 12, 3, 6, 1, 9, 15, 1, 1, 13, 7, 5, 0, 14, 15, 7, 8, 6],
            [1, 2, 10, 5, 2, 13, 1, 11, 15, 10, 4, 9, 9, 12, 14, 13, 3, 5, 0, 3, 7, 11, 10, 3, 12, 5, 10, 2, 13, 7, 1, 7, 13, 8, 2, 8, 3, 14, 10, 3, 5, 12, 0, 9, 3, 9, 11, 2, 10, 9, 0, 6, 4, 0, 1, 14, 11, 0, 8, 6, 1, 15, 3, 10],
            [13, 9, 0, 5, 8, 7, 12, 15, 10, 10, 5, 1, 1, 7, 6, 1, 14, 5, 15, 2, 3, 5, 3, 5, 7, 3, 7, 7, 1, 4, 3, 14, 5, 0, 12, 0, 12, 10, 10, 6, 12, 6, 3, 5, 5, 11, 10, 1, 11, 3, 13, 3, 9, 11, 1, 7, 14, 14, 0, 8, 15, 5, 2, 7],
            [8, 5, 11, 6, 15, 0, 1, 13, 1, 6, 7, 15, 4, 3, 14, 12, 9, 3, 11, 6, 4, 12, 1, 11, 6, 12, 5, 11, 1, 12, 2, 3, 1, 2, 11, 12, 0, 5, 11, 5, 3, 13, 11, 3, 11, 14, 10, 8, 3, 9, 4, 8, 13, 11, 9, 11, 2, 4, 12, 3, 0, 14, 7, 11],
            [10, 11, 4, 10, 7, 8, 3, 14, 15, 8, 15, 6, 9, 8, 5, 6, 12, 1, 15, 6, 5, 5, 14, 13, 2, 12, 14, 6, 5, 5, 14, 9, 1, 10, 11, 14, 8, 6, 14, 11, 1, 15, 6, 11, 11, 8, 1, 2, 8, 5, 4, 15, 6, 8, 0, 8, 0, 11, 0, 1, 0, 7, 8, 15],
            [0, 15, 5, 0, 11, 4, 4, 2, 0, 4, 8, 12, 2, 2, 0, 8, 1, 2, 6, 5, 6, 12, 3, 1, 12, 1, 6, 10, 2, 5, 0, 2, 0, 11, 8, 6, 13, 4, 14, 4, 15, 5, 8, 11, 9, 6, 2, 6, 9, 1, 4, 2, 14, 10, 4, 4, 1, 1, 11, 8, 6, 11, 11, 9],
            [7, 3, 6, 5, 9, 1, 11, 0, 15, 13, 13, 13, 4, 14, 14, 12, 3, 7, 9, 3, 1, 6, 5, 9, 7, 6, 2, 11, 10, 4, 11, 14, 10, 13, 11, 8, 11, 8, 1, 15, 5, 0, 10, 5, 6, 0, 5, 15, 11, 6, 6, 4, 10, 11, 8, 12, 0, 10, 11, 11, 11, 1, 13, 6],
            [7, 15, 0, 0, 11, 5, 7, 13, 3, 7, 3, 2, 5, 12, 6, 11, 14, 4, 9, 8, 9, 9, 13, 0, 15, 2, 13, 2, 15, 6, 15, 1, 1, 7, 4, 0, 10, 1, 8, 14, 0, 10, 12, 4, 5, 13, 9, 0, 7, 12, 13, 11, 11, 8, 8, 15, 2, 15, 4, 4, 9, 3, 10, 7],
            [0, 9, 3, 5, 14, 6, 7, 14, 7, 2, 13, 7, 3, 15, 9, 15, 2, 8, 0, 4, 6, 0, 15, 6, 2, 1, 14, 8, 5, 8, 2, 4, 2, 11, 9, 2, 15, 13, 11, 12, 8, 15, 3, 13, 2, 2, 10, 13, 1, 8, 7, 15, 13, 6, 7, 7, 4, 3, 14, 7, 0, 9, 15, 11],
            [8, 13, 7, 7, 8, 8, 7, 8, 1, 4, 10, 1, 12, 4, 14, 11, 7, 12, 15, 0, 10, 15, 9, 2, 14, 2, 14, 2, 4, 5, 13, 3, 2, 10, 0, 15, 7, 6, 8, 11, 7, 6, 10, 10, 4, 7, 10, 6, 6, 14, 10, 4, 14, 6, 12, 2, 8, 1, 9, 13, 3, 4, 3, 14],
            [10, 10, 6, 3, 8, 5, 10, 7, 11, 10, 9, 4, 8, 14, 9, 10, 0, 9, 8, 14, 11, 15, 8, 13, 13, 7, 13, 13, 13, 9, 12, 11, 6, 3, 9, 6, 0, 0, 6, 6, 11, 6, 4, 8, 1, 5, 1, 7, 9, 6, 13, 4, 3, 8, 8, 11, 9, 10, 6, 11, 12, 13, 14, 14],
            [14, 10, 0, 15, 14, 4, 3, 0, 12, 4, 0, 14, 11, 9, 0, 6, 4, 6, 0, 9, 8, 14, 4, 4, 6, 8, 2, 8, 10, 3, 8, 0, 1, 1, 15, 4, 2, 4, 13, 9, 9, 4, 0, 5, 5, 1, 2, 5, 11, 6, 2, 1, 7, 8, 10, 10, 1, 5, 8, 6, 7, 0, 4, 14],
            [0, 15, 10, 11, 13, 12, 7, 7, 4, 0, 9, 5, 2, 8, 0, 10, 6, 6, 7, 5, 6, 7, 9, 0, 1, 4, 8, 14, 10, 3, 5, 5, 11, 5, 1, 10, 6, 10, 0, 14, 1, 15, 11, 12, 8, 2, 7, 8, 4, 0, 3, 11, 9, 15, 3, 5, 15, 15, 14, 15, 3, 4, 5, 14],
            [5, 12, 12, 8, 0, 0, 14, 1, 4, 15, 3, 2, 2, 6, 1, 10, 7, 10, 14, 5, 14, 0, 8, 5, 9, 0, 12, 8, 9, 10, 3, 12, 3, 2, 0, 0, 12, 12, 7, 13, 2, 6, 4, 7, 10, 10, 14, 1, 11, 6, 10, 3, 12, 2, 1, 10, 7, 13, 10, 12, 14, 11, 14, 8],
            [9, 5, 3, 12, 4, 3, 10, 14, 7, 5, 11, 12, 2, 13, 9, 8, 5, 2, 6, 2, 4, 9, 10, 10, 4, 3, 4, 0, 11, 1, 10, 9, 4, 10, 4, 5, 8, 11, 1, 7, 13, 7, 6, 6, 3, 12, 0, 0, 15, 6, 12, 12, 13, 7, 14, 14, 11, 15, 7, 14, 12, 6, 15, 2],
            [15, 2, 0, 12, 15, 14, 8, 14, 7, 14, 0, 3, 3, 11, 12, 2, 3, 14, 13, 5, 12, 9, 6, 11, 7, 4, 5, 1, 7, 12, 0, 11, 1, 5, 6, 6, 8, 6, 12, 2, 12, 3, 10, 3, 4, 10, 3, 3, 3, 10, 10, 14, 3, 13, 15, 0, 7, 6, 15, 6, 13, 7, 4, 11],
            [11, 15, 5, 14, 0, 1, 1, 14, 2, 3, 15, 14, 4, 3, 11, 1, 6, 6, 0, 12, 3, 5, 15, 6, 3, 11, 13, 11, 7, 7, 8, 11, 5, 9, 10, 10, 9, 14, 7, 1, 7, 2, 8, 6, 6, 5, 1, 9, 6, 5, 8, 14, 2, 14, 2, 9, 3, 3, 4, 15, 13, 5, 2, 7],
            [7, 8, 13, 9, 15, 8, 11, 7, 1, 9, 15, 12, 6, 9, 3, 1, 10, 10, 11, 0, 0, 8, 14, 5, 11, 12, 14, 4, 3, 9, 12, 9, 14, 0, 0, 9, 12, 4, 1, 13, 3, 6, 3, 4, 13, 10, 2, 9, 3, 7, 7, 10, 7, 10, 10, 3, 5, 15, 8, 9, 11, 7, 1, 14],
            [5, 5, 9, 1, 15, 3, 3, 11, 6, 11, 13, 13, 4, 12, 7, 12, 4, 8, 14, 13, 7, 12, 13, 8, 10, 2, 1, 12, 11, 7, 0, 8, 10, 9, 15, 1, 3, 9, 10, 0, 9, 1, 14, 1, 1, 9, 2, 2, 8, 9, 5, 6, 3, 2, 15, 9, 15, 6, 3, 11, 14, 4, 0, 4],
            [9, 2, 10, 2, 0, 9, 6, 13, 13, 0, 13, 14, 3, 12, 1, 15, 9, 3, 12, 2, 5, 15, 6, 6, 15, 11, 7, 11, 0, 4, 0, 11, 10, 12, 7, 9, 3, 0, 2, 2, 13, 13, 9, 6, 9, 2, 6, 4, 3, 6, 5, 10, 10, 9, 7, 2, 4, 9, 13, 11, 2, 13, 6, 8],
            [13, 15, 9, 8, 6, 2, 3, 2, 2, 12, 5, 3, 8, 6, 11, 6, 15, 7, 10, 3, 15, 8, 7, 5, 3, 8, 4, 2, 11, 1, 0, 4, 1, 1, 6, 1, 13, 6, 5, 1, 2, 6, 7, 10, 4, 3, 10, 6, 2, 0, 7, 13, 15, 1, 13, 0, 12, 10, 15, 6, 2, 4, 14, 3],
            [5, 11, 14, 4, 0, 7, 12, 4, 4, 14, 12, 3, 4, 10, 7, 14, 6, 4, 14, 7, 0, 12, 5, 9, 15, 6, 15, 6, 3, 12, 0, 10, 11, 7, 1, 14, 13, 5, 1, 14, 5, 15, 12, 1, 9, 13, 9, 13, 14, 5, 10, 11, 12, 10, 15, 11, 9, 13, 2, 14, 9, 12, 2, 11],
            [2, 12, 5, 7, 1, 5, 2, 11, 8, 4, 15, 6, 9, 14, 5, 1, 15, 4, 3, 1, 11, 4, 2, 1, 4, 5, 4, 4, 7, 3, 3, 12, 4, 3, 2, 15, 13, 1, 14, 15, 1, 4, 6, 11, 13, 15, 6, 12, 12, 13, 6, 8, 10, 0, 10, 12, 1, 10, 3, 2, 9, 8, 2, 8],
            [10, 12, 12, 6, 8, 5, 4, 4, 5, 3, 6, 7, 15, 5, 10, 3, 8, 15, 14, 5, 6, 2, 14, 4, 1, 7, 1, 3, 12, 3, 12, 4, 10, 15, 6, 6, 0, 6, 6, 8, 6, 9, 5, 7, 5, 1, 9, 2, 4, 9, 0, 8, 1, 1, 14, 3, 7, 14, 8, 9, 0, 4, 11, 7],
            [13, 11, 14, 7, 0, 4, 0, 10, 12, 11, 10, 8, 6, 12, 13, 15, 9, 2, 14, 9, 3, 0, 12, 14, 11, 15, 4, 7, 15, 14, 4, 8, 15, 12, 9, 14, 7, 7, 9, 13, 14, 14, 4, 9, 13, 8, 1, 13, 6, 3, 12, 7, 0, 15, 6, 15, 7, 2, 3, 0, 9, 5, 13, 0],
            [3, 8, 12, 11, 5, 9, 9, 14, 8, 14, 14, 5, 9, 9, 12, 10, 3, 12, 13, 0, 0, 0, 6, 7, 12, 4, 2, 3, 8, 8, 9, 15, 11, 1, 12, 13, 10, 15, 11, 1, 2, 13, 10, 1, 7, 2, 7, 11, 8, 15, 7, 6, 4, 6, 5, 11, 11, 15, 2, 1, 11, 1, 1, 8],
            [10, 7, 7, 1, 4, 13, 9, 10, 2, 2, 3, 7, 12, 8, 5, 5, 5, 5, 3, 1, 5, 6, 8, 2, 8, 11, 5, 0, 4, 12, 12, 6, 7, 9, 14, 10, 11, 8, 0, 9, 11, 4, 14, 7, 7, 8, 2, 15, 12, 7, 4, 4, 13, 2, 0, 3, 14, 0, 1, 5, 2, 15, 7, 11],
            [3, 8, 10, 4, 1, 7, 3, 13, 5, 14, 0, 9, 3, 1, 0, 11, 2, 15, 4, 9, 6, 5, 14, 0, 2, 8, 1, 14, 7, 6, 1, 5, 5, 7, 2, 0, 5, 3, 4, 15, 13, 10, 9, 13, 13, 12, 5, 11, 11, 14, 13, 10, 8, 14, 0, 8, 1, 7, 2, 10, 12, 12, 1, 11],
            [11, 14, 4, 13, 3, 11, 10, 6, 15, 2, 5, 10, 14, 4, 13, 3, 12, 7, 12, 10, 4, 0, 0, 1, 14, 6, 1, 2, 2, 12, 9, 2, 3, 11, 1, 4, 10, 4, 4, 7, 7, 12, 4, 3, 12, 11, 9, 3, 15, 13, 6, 13, 7, 11, 5, 12, 5, 13, 15, 12, 0, 13, 12, 9],
            [8, 7, 2, 2, 5, 3, 10, 15, 10, 8, 1, 0, 4, 5, 7, 6, 15, 13, 2, 14, 6, 2, 9, 5, 9, 0, 5, 12, 8, 6, 4, 12, 6, 8, 14, 15, 7, 15, 11, 2, 2, 12, 7, 9, 7, 11, 15, 7, 0, 4, 5, 13, 7, 2, 5, 9, 0, 5, 7, 6, 7, 12, 4, 1],
            [11, 4, 2, 13, 6, 10, 9, 4, 12, 9, 9, 6, 4, 2, 14, 14, 9, 5, 5, 15, 15, 9, 8, 11, 4, 2, 8, 11, 14, 3, 8, 10, 14, 9, 6, 6, 4, 7, 11, 2, 3, 7, 5, 1, 14, 2, 9, 4, 0, 1, 10, 7, 6, 7, 1, 3, 13, 7, 3, 2, 12, 3, 6, 6],
            [11, 1, 14, 3, 14, 3, 9, 9, 0, 11, 14, 6, 14, 7, 14, 8, 4, 2, 5, 6, 13, 3, 4, 10, 8, 8, 10, 11, 5, 1, 15, 15, 7, 0, 4, 14, 15, 13, 14, 13, 3, 2, 1, 6, 0, 6, 6, 4, 15, 6, 0, 12, 5, 11, 1, 7, 3, 3, 13, 12, 12, 6, 3, 2],
            [7, 2, 10, 14, 14, 13, 4, 14, 10, 6, 0, 2, 7, 7, 2, 5, 14, 1, 5, 14, 15, 1, 2, 9, 2, 13, 1, 3, 6, 1, 3, 13, 10, 6, 11, 13, 1, 7, 13, 15, 2, 11, 9, 6, 13, 7, 9, 2, 3, 13, 10, 10, 6, 2, 5, 9, 1, 3, 0, 3, 1, 5, 3, 12],
            [11, 14, 4, 2, 10, 11, 15, 5, 9, 7, 8, 11, 10, 9, 5, 7, 14, 3, 12, 2, 7, 15, 12, 15, 4, 15, 12, 9, 2, 6, 6, 6, 8, 5, 0, 7, 14, 15, 14, 14, 3, 12, 7, 12, 2, 4, 1, 7, 1, 3, 4, 7, 1, 9, 11, 15, 15, 3, 7, 1, 10, 9, 14, 14],
            [4, 13, 11, 1, 9, 6, 5, 1, 11, 6, 6, 8, 3, 9, 8, 15, 13, 12, 3, 13, 5, 9, 10, 5, 12, 1, 15, 14, 12, 1, 10, 11, 5, 7, 3, 12, 9, 12, 0, 2, 2, 3, 14, 4, 2, 13, 1, 15, 11, 8, 3, 13, 0, 10, 5, 4, 6, 0, 14, 8, 1, 0, 6, 15],
            [15, 2, 0, 5, 2, 14, 9, 0, 10, 5, 12, 8, 5, 6, 0, 1, 9, 4, 4, 1, 4, 6, 14, 5, 3, 0, 2, 2, 14, 9, 7, 0, 2, 15, 12, 0, 10, 12, 9, 12, 15, 1, 9, 4, 15, 3, 0, 13, 0, 6, 5, 0, 2, 6, 11, 9, 13, 15, 6, 3, 5, 4, 0, 8],
            [4, 14, 8, 14, 13, 4, 4, 10, 6, 12, 15, 11, 7, 2, 15, 6, 9, 9, 1, 11, 13, 2, 7, 10, 4, 4, 5, 12, 14, 15, 8, 5, 6, 1, 11, 15, 4, 11, 5, 2, 5, 7, 3, 4, 5, 7, 3, 8, 10, 13, 7, 5, 6, 5, 10, 1, 12, 13, 3, 6, 2, 8, 7, 15],
            [3, 15, 4, 9, 14, 12, 6, 1, 7, 0, 7, 15, 10, 6, 5, 5, 15, 5, 9, 4, 7, 6, 14, 2, 1, 4, 10, 3, 12, 1, 7, 1, 0, 10, 2, 11, 14, 13, 7, 10, 5, 11, 5, 11, 15, 5, 0, 3, 15, 1, 2, 14, 13, 13, 10, 9, 15, 12, 10, 5, 2, 10, 0, 6],
            [4, 6, 5, 13, 11, 10, 15, 4, 2, 15, 13, 6, 7, 7, 4, 0, 4, 6, 7, 4, 9, 1, 6, 7, 6, 1, 4, 2, 0, 11, 6, 3, 14, 5, 9, 2, 2, 10, 1, 2, 13, 14, 4, 11, 4, 7, 12, 9, 8, 2, 2, 9, 5, 7, 9, 12, 8, 15, 0, 9, 12, 11, 1, 12],
            [11, 12, 11, 9, 8, 15, 4, 12, 13, 10, 6, 6, 6, 12, 3, 0, 6, 15, 15, 10, 6, 12, 5, 7, 10, 2, 7, 1, 6, 12, 9, 11, 11, 14, 1, 12, 15, 0, 6, 2, 12, 15, 4, 15, 14, 8, 3, 4, 15, 4, 13, 3, 14, 1, 3, 7, 6, 13, 9, 1, 0, 12, 4, 14],
            [12, 11, 13, 10, 10, 10, 3, 7, 12, 3, 13, 9, 6, 0, 12, 10, 4, 11, 5, 4, 11, 5, 7, 14, 6, 10, 12, 12, 13, 15, 12, 1, 13, 15, 15, 7, 1, 2, 8, 6, 1, 12, 12, 0, 4, 3, 3, 3, 7, 8, 9, 10, 7, 7, 0, 0, 11, 13, 15, 4, 9, 5, 10, 9],
            [6, 12, 3, 0, 9, 11, 6, 4, 9, 9, 1, 5, 9, 14, 3, 7, 15, 3, 5, 0, 5, 11, 7, 6, 13, 5, 10, 2, 12, 10, 2, 6, 0, 1, 1, 13, 9, 3, 11, 7, 8, 2, 10, 9, 13, 6, 6, 4, 12, 0, 3, 10, 9, 4, 15, 11, 14, 1, 9, 3, 0, 14, 6, 1],
            [11, 14, 10, 10, 11, 6, 4, 7, 10, 0, 7, 9, 3, 2, 13, 13, 9, 9, 2, 3, 3, 14, 10, 4, 14, 1, 10, 7, 14, 4, 9, 15, 3, 11, 5, 10, 7, 8, 3, 0, 1, 2, 2, 3, 12, 9, 6, 2, 11, 15, 3, 9, 3, 6, 8, 0, 4, 5, 7, 3, 0, 14, 7, 9],
            [4, 11, 13, 12, 6, 2, 3, 15, 15, 3, 5, 1, 0, 5, 10, 2, 5, 3, 7, 10, 15, 0, 5, 3, 2, 10, 12, 10, 8, 3, 9, 15, 5, 3, 7, 13, 5, 7, 13, 12, 5, 10, 2, 9, 10, 1, 9, 4, 14, 1, 10, 13, 1, 2, 2, 12, 5, 3, 14, 7, 7, 8, 13, 13],
            [10, 12, 11, 10, 0, 15, 4, 3, 0, 8, 3, 0, 15, 0, 3, 10, 10, 9, 15, 3, 13, 3, 8, 3, 8, 2, 14, 7, 1, 6, 13, 8, 2, 2, 12, 3, 3, 0, 10, 12, 0, 1, 1, 7, 5, 0, 13, 10, 7, 13, 9, 9, 13, 7, 0, 1, 0, 2, 14, 2, 13, 0, 8, 3],
            [11, 3, 11, 10, 12, 15, 11, 6, 14, 8, 8, 5, 7, 11, 3, 1, 13, 7, 13, 4, 15, 7, 2, 3, 8, 7, 3, 8, 9, 15, 10, 15, 9, 0, 5, 4, 1, 7, 13, 8, 2, 7, 1, 10, 1, 12, 12, 1, 7, 12, 13, 5, 14, 10, 9, 15, 12, 2, 10, 3, 10, 3, 9, 12],
            [9, 8, 11, 0, 5, 6, 1, 5, 9, 1, 0, 12, 12, 0, 12, 11, 2, 8, 4, 0, 1, 7, 7, 5, 1, 14, 1, 9, 13, 7, 2, 12, 8, 9, 12, 13, 1, 11, 5, 3, 12, 14, 15, 4, 9, 8, 12, 7, 11, 1, 3, 9, 11, 5, 7, 14, 4, 6, 12, 3, 4, 12, 7, 9],
            [10, 12, 2, 14, 14, 1, 11, 8, 3, 7, 13, 7, 2, 1, 14, 13, 7, 6, 15, 8, 15, 12, 13, 10, 11, 15, 4, 2, 6, 13, 12, 3, 2, 10, 15, 14, 10, 11, 8, 14, 9, 3, 12, 9, 15, 2, 14, 14, 5, 13, 7, 6, 2, 1, 1, 4, 1, 0, 13, 10, 1, 0, 2, 9],
            [10, 5, 11, 14, 12, 1, 12, 7, 12, 8, 10, 5, 6, 10, 0, 7, 5, 6, 11, 11, 13, 12, 0, 13, 0, 6, 11, 0, 14, 4, 2, 1, 12, 7, 1, 10, 7, 15, 5, 3, 14, 15, 1, 3, 1, 2, 10, 4, 11, 8, 2, 11, 2, 5, 5, 4, 15, 5, 10, 3, 1, 7, 2, 14],
        ]);
        let hash = Hash::from_bytes([42; 32]);
        let matrix = Matrix::generate(hash);
        assert_eq!(matrix, expected_matrix);
    }
}

        /*
        // ### Cryptixhash v3

        // Memory Hard Function - Inline Code
        let mut memory_table: [u8; 16 * 1024] = [0; 16 * 1024]; // 16 KB
        let nonce = hash.as_bytes(); 
        
        // **Fill the memory with the nonce**
        for i in 0..memory_table.len() {
            memory_table[i] = nonce[i % nonce.len()];  
        }
        
        let mut index: usize = 0;
        
        // Repeat the calculations and manipulations in memory
        for i in 0..32 {
            let mut sum = 0u16;
        
             // Memory on product
            for j in 0..32 {
                sum += product[j] as u16 * self.0[2 * i][j % self.0[2 * i].len()] as u16;
            }
        
            // **non-linear memory accesses**
            for _ in 0..12 { 
                index ^= (memory_table[(index * 7 + i) % memory_table.len()] as usize * 19) ^ ((i * 53) % 13);
                index = (index * 73 + i * 41) % memory_table.len(); 
                
                // Index-Path
                let shifted = (index.wrapping_add(i * 13)) % memory_table.len();
                memory_table[shifted] ^= (sum & 0xFF) as u8;
            }
        }
        
        // Final hash result in memory
        for i in 0..32 {
            let shift_val = (product[i] as usize * 47 + i) % memory_table.len();
            product[i] ^= memory_table[shift_val];
        } 

        */
