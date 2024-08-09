use crate::treepp::*;
use bitcoin::hashes::{hash160, Hash};

/// Generate the public key for the i-th digit of the message
pub fn public_key<const D: u32>(sk: Vec<u8>, digit_index: u32) -> Script {
    let mut secret_i = sk;
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

/// Compute the signature for a given message
pub fn sign<const D: u32, const N0: usize, const N1: usize, const N: usize>(sk: Vec<u8>, message_digits: [u8; N0]) -> Script {
    let mut checksum_digits = to_digits::<D, N1>(checksum::<D, N0>(message_digits)).to_vec();
    checksum_digits.append(&mut message_digits.to_vec());
    
    let (mut info1, mut info2) = (0, 0);
    for i in (N/2..N).rev() {
        info1 *= 2;
        info1 += ((checksum_digits[(N-1-i) as usize] as u32) < (D+1)/2) as u32;
    }
    for i in (0..N/2).rev() {
        info2 *= 2;
        info2 += ((checksum_digits[(N-1-i) as usize] as u32) < (D+1)/2) as u32;
    }
    if N % 2 == 1 {
        info2 *= 2;
    }

    println!("{:?}", checksum_digits);
    script! {
        for i in 0..N/2 {
            { digit_signature(sk.clone(), i, checksum_digits[(N-1-i) as usize]) }
        }
        { info2 }
        for i in N/2..N {
            { digit_signature(sk.clone(), i, checksum_digits[(N-1-i) as usize]) }
        }
        { info1 }
    }
}

/// Convert a number to digits
pub fn to_digits<const D: u32, const DIGIT_COUNT: usize>(mut number: u32) -> [u8; DIGIT_COUNT] {
    let mut digits: [u8; DIGIT_COUNT] = [0; DIGIT_COUNT];
    for i in 0..DIGIT_COUNT {
        let digit = number % (D + 1);
        number = (number - digit) / (D + 1);
        digits[i] = digit as u8;
    }
    digits
}

/// Compute the checksum of the message's digits.
pub fn checksum<const D: u32, const N0: usize>(digits: [u8; N0]) -> u32 {
    let mut sum = 0;
    for digit in digits {
        sum += digit as u32;
    }
    D * (N0 as u32) - sum
}

/// Compute the signature for the i-th digit of the message
pub fn digit_signature(sk: Vec<u8>, digit_index: usize, message_digit: u8) -> Script {
    let mut secret_i = sk;
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

/// Winternitz Signature verification
pub fn checksig_verify<const D: u32, const LOG_D: u32, const N0: usize, const N1: usize, const N: usize>(sk: Vec<u8>) -> Script {
    script! {
        //
        // Verify the hash chain for each digit
        //

        // Repeat this for every of the n many digits
        { 1 << ((N+1)/2 - 1) }
        OP_SWAP
        for digit_index in 0..(N+1)/2 {

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
            { public_key::<D>(sk.clone(), (N - 1 - digit_index) as u32) }

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

        for digit_index in (N+1)/2..N {

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
            { public_key::<D>(sk.clone(), (N - 1 - digit_index) as u32) }

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
        for _ in 1..N0 {
            OP_FROMALTSTACK OP_TUCK OP_SUB
        }
        { D * (N0 as u32) }
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

#[cfg(test)]
mod test {
    use crate::bigint::U254;
    use crate::{bn254::fq::Fq, execute_script_without_stack_limit};
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::treepp::*;
    use crate::signatures::winternitz_compact::{sign, checksig_verify};
    use core::ops::Rem;
    use std::ops::Mul;
    use ark_ff::UniformRand;
    use ark_std::{end_timer, start_timer};
    use num_bigint::BigUint;
    use num_traits::Num;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use num_traits::Zero;

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

    pub fn biguint_to_digits<const D: u32, const N0: usize>(mut number: BigUint) -> [u8; N0] {
        let mut digits: [u8; N0] = [0; N0];
        for i in 0..N0 {
            let digit = number.clone() % (D + 1);
            number = (number - digit.clone()) / (D + 1);
            if digit.is_zero() {
                digits[i] = 0;
            } else {
                digits[i] = digit.to_u32_digits()[0] as u8;
            }
        }
        digits
    }
    
    #[test]
    fn test_winternitz() {
        const LOG_D: u32   = 8;                    // Bits per digit
        const D    : u32   = (1 << LOG_D) - 1;     // Digits are base d+1
        const N0   : usize = 32;                   // Number of digits of the message
        const N1   : usize = 2;                    // Number of digits of the checksum
        const N    : usize = N0 + N1;              // Total number of digits to be signed
        // N must be smaller than 62 for current version.

        let sk = hex::decode(MY_SECKEY).unwrap();

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let r = BigUint::from_str_radix(Fq::MONTGOMERY_ONE, 16).unwrap();
        let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();

        let fq = ark_bn254::Fq::rand(&mut prng);
        let fq_biguint = BigUint::from(fq).mul(r.clone()).rem(p.clone());
        
        println!("{fq_biguint}");

        let message = biguint_to_digits::<D, N0>(fq_biguint.clone());

        println!("message: {:?}", message);
        
        let script = script! {
            { sign::<D, N0, N1, N>(sk.clone(), message) }
            { checksig_verify::<D, LOG_D, N0, N1, N>(sk.clone()) }
            { U254::from_bytes() }
        };

        println!(
            "Winternitz signature size:\n \t{:?} bytes / {:?} bits \n\t{:?} bytes / bit",
            script.len(),
            (N0 as u32) * LOG_D,
            script.len() as f64 / ((N0 as u32) * LOG_D) as f64
        );

        let final_script = script! {
            { sign::<D, N0, N1, N>(sk.clone(), message) }
            { checksig_verify::<D, LOG_D, N0, N1, N>(sk.clone()) }

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
}
