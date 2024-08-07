//
// Compact Winternitz Signatures
//
// In this variant, the user doesn't need to provide the message in the unlocking script.
// Instead, we calculate the message from the signature hashes.
// This reduces stack usage at the expense of script size.
//

//
// Winternitz signatures are an improved version of Lamport signatures.
// A detailed introduction to Winternitz signatures can be found
// in "A Graduate Course in Applied Cryptography" in chapter 14.3
// https://toc.cryptobook.us/book.pdf
//
// We are trying to closely follow the authors' notation here.
//

//
// BEAT OUR IMPLEMENTATION AND WIN A CODE GOLF BOUNTY!
//

use crate::treepp::*;
use bitcoin::hashes::{hash160, Hash};
use hex::decode as hex_decode;
use num_bigint::BigUint;

/// Bits per digit
const LOG_D: u32 = 8;
/// Digits are base d+1
pub const D: u32 = (1 << LOG_D) - 1;
/// Number of digits of the message
const N0: u32 = 32;
/// Number of digits of the checksum
const N1: usize = 2;
/// Total number of digits to be signed
const N: u32 = N0 + N1 as u32;

//
// Helper functions
//

/// Generate the public key for the i-th digit of the message
pub fn public_key(secret_key: &str, digit_index: u32) -> Script {
    // Convert secret_key from hex string to bytes
    let mut secret_i = match hex_decode(secret_key) {
        Ok(bytes) => bytes,
        Err(_) => panic!("Invalid hex string"),
    };

    secret_i.push(digit_index as u8);

    let mut hash = hash160::Hash::hash(&secret_i);

    for _ in 0..D {
        hash = hash160::Hash::hash(&hash[..]);
    }

    let hash_bytes = hash.as_byte_array().to_vec();

    script! {
        { hash_bytes }
    }
}

/// Compute the signature for the i-th digit of the message
pub fn digit_signature(secret_key: &str, digit_index: u32, message_digit: u8) -> Script {
    // Convert secret_key from hex string to bytes
    let mut secret_i = match hex_decode(secret_key) {
        Ok(bytes) => bytes,
        Err(_) => panic!("Invalid hex string"),
    };

    secret_i.push(digit_index as u8);

    let mut hash = hash160::Hash::hash(&secret_i);

    for _ in 0..message_digit {
        hash = hash160::Hash::hash(&hash[..]);
    }

    let hash_bytes = hash.as_byte_array().to_vec();

    script! {
        { hash_bytes }
    }
}

/// Compute the checksum of the message's digits.
/// Further infos in chapter "A domination free function for Winternitz signatures"
pub fn checksum(digits: [u8; N0 as usize]) -> u32 {
    let mut sum = 0;
    for digit in digits {
        sum += digit as u32;
    }
    D * N0 - sum
}

/// Convert a number to digits
pub fn to_digits<const DIGIT_COUNT: usize>(mut number: u32) -> [u8; DIGIT_COUNT] {
    let mut digits: [u8; DIGIT_COUNT] = [0; DIGIT_COUNT];
    for i in 0..DIGIT_COUNT {
        let digit = number % (D + 1);
        number = (number - digit) / (D + 1);
        digits[i] = digit as u8;
    }
    digits
}

/// Compute the signature for a given message
pub fn sign(secret_key: &str, message_digits: [u8; N0 as usize]) -> Script {
    let mut checksum_digits = to_digits::<N1>(checksum(message_digits)).to_vec();
    checksum_digits.append(&mut message_digits.to_vec());

    
    let (mut info1, mut info2) = (0, 0);
    for i in (N/2..N).rev() {
        info1 *= 2;
        info1 += ((checksum_digits[ (N-1-i) as usize] as u32) < (D+1)/2) as u32;
    }
    for i in (0..N/2).rev() {
        info2 *= 2;
        info2 += ((checksum_digits[ (N-1-i) as usize] as u32) < (D+1)/2) as u32;
    }

    println!("{:?}", checksum_digits);
    script! {
        //N must be even or change the below lines
        for i in 0..N/2 {
            { digit_signature(secret_key, i, checksum_digits[ (N-1-i) as usize]) }
        }
        { info2 }
        for i in N/2..N {
            { digit_signature(secret_key, i, checksum_digits[ (N-1-i) as usize]) }
        }
        { info1 }
    }

}

/// Winternitz Signature verification
///
/// Note that the script inputs are malleable.
///
/// Optimized by @SergioDemianLerner, @tomkosm
pub fn checksig_verify(secret_key: &str) -> Script {
    script! {
        //
        // Verify the hash chain for each digit
        //

        // Repeat this for every of the n many digits
        { 1 << (N/2 - 1) }
        OP_SWAP
        for digit_index in 0..N/2 {

            OP_2DUP
            OP_LESSTHANOREQUAL
            OP_IF
                OP_OVER OP_SUB
                OP_ROT
                for _ in 0..(D+1)/2 {
                    OP_HASH160
                }
                0 OP_TOALTSTACK
            OP_ELSE
                OP_ROT
                { (D + 1)/2 } OP_TOALTSTACK
            OP_ENDIF
            { public_key(secret_key, N - 1 - digit_index) }

            OP_SWAP

            OP_2DUP
            OP_EQUAL

            OP_IF

                {D - (D+1)/2}

                OP_TOALTSTACK

            OP_ENDIF

            for i in 0..D/2 {
                OP_HASH160

                OP_2DUP

                OP_EQUAL

                OP_IF

                    {D-i-1 - (D+1)/2}

                    OP_TOALTSTACK

                OP_ENDIF
            }

            OP_2DROP

            OP_FROMALTSTACK
            OP_FROMALTSTACK
            OP_ADD
            OP_TOALTSTACK
            OP_DUP
            OP_ADD
            
        }

        OP_DROP
        OP_SWAP

        for digit_index in N/2..N {

            OP_2DUP
            OP_LESSTHANOREQUAL
            OP_IF
                OP_OVER OP_SUB
                OP_ROT
                for _ in 0..(D+1)/2 {
                    OP_HASH160
                }
                0 OP_TOALTSTACK
            OP_ELSE
                OP_ROT
                { (D + 1)/2 } OP_TOALTSTACK
            OP_ENDIF
            { public_key(secret_key, N - 1 - digit_index) }

            OP_SWAP

            OP_2DUP
            OP_EQUAL

            OP_IF

                {D - (D+1)/2}

                OP_TOALTSTACK

            OP_ENDIF

            for i in 0..D/2 {
                OP_HASH160

                OP_2DUP

                OP_EQUAL

                OP_IF

                    {D-i-1 - (D+1)/2}

                    OP_TOALTSTACK

                OP_ENDIF
            }

            OP_2DROP

            OP_FROMALTSTACK
            OP_FROMALTSTACK
            OP_ADD
            OP_TOALTSTACK
            OP_DUP
            OP_ADD
            
        }

        OP_2DROP


        // 1. Compute the checksum of the message's digits
        OP_FROMALTSTACK OP_DUP OP_NEGATE
        for _ in 1..N0{
            OP_FROMALTSTACK OP_TUCK OP_SUB
        }
        { D * N0 }
        OP_ADD


        // 2. Sum up the signed checksum's digits
        OP_FROMALTSTACK
        for _ in 0..N1 - 1 {
            for _ in 0..LOG_D {
                OP_DUP OP_ADD
            }
            OP_FROMALTSTACK
            OP_ADD
        }

        // // 3. Ensure both checksums are equal
        OP_EQUALVERIFY

    }
}


fn u254_to_digits(a: BigUint) -> [u8; N0 as usize] {
    let mut digits = [0_u8; N0 as usize];
    for (i, byte) in a.to_bytes_le().iter().enumerate() {
        digits[i] = *byte;
    }
    digits
}

#[cfg(test)]
mod test {
    use crate::bigint::U254;
    use crate::{bn254::fq::Fq, execute_script_without_stack_limit};
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::treepp::*;

    use core::ops::Rem;
    use std::ops::Mul;
    use ark_ff::UniformRand;
    use ark_std::{end_timer, start_timer};
    use num_bigint::BigUint;
    use num_traits::Num;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    // The secret key
    const MY_SECKEY: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";


    fn exe_script(script: Script) -> bool {
        let size = script.len();
        let start = start_timer!(|| "execute_script");
        let exec_result = execute_script_without_stack_limit(script);
        let max_stack_items = exec_result.stats.max_nb_stack_items;
        println!("script size: {:?}", size);
        println!("max stack items: {:?}", max_stack_items);
        end_timer!(start);
        return exec_result.success;
    }
    
    #[test]
    fn test_winternitz() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let r = BigUint::from_str_radix(Fq::MONTGOMERY_ONE, 16).unwrap();
        let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();

        let fq = ark_bn254::Fq::rand(&mut prng);
        let fq_biguint = BigUint::from(fq).mul(r.clone()).rem(p.clone());
        
        println!("{fq_biguint}");

        let message = u254_to_digits(fq_biguint.clone());

        println!("message: {:?}", message);
        
        let script = script! {
            { sign(MY_SECKEY, message) }
            { checksig_verify(MY_SECKEY) }
            { U254::from_bytes() }
        };

        println!(
            "Winternitz signature size:\n \t{:?} bytes / {:?} bits \n\t{:?} bytes / bit",
            script.len(),
            N0 * LOG_D,
            script.len() as f64 / (N0 * LOG_D) as f64
        );

        let final_script = script! {
            { sign(MY_SECKEY, message) }
            { checksig_verify(MY_SECKEY) }

            for i in 1..N0 {
                { i } OP_ROLL
            }

            { U254::from_bytes() }

            { U254::push_u32_le(&fq_biguint.to_u32_digits()) }

            { U254::equalverify(1, 0) }

            OP_TRUE

            
        };

        assert!(exe_script(final_script));


    }

    // TODO: test the error cases: negative digits, digits > D, ...
}
