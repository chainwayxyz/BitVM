use crate::treepp::*;
use bitcoin::hashes::{hash160, Hash};

/// Generate the public key for the i-th digit of the message
pub fn public_key<const D: u32>(sk: Vec<u8>, digit_index: usize) -> Vec<u8> {
    let mut secret_i = sk;
    secret_i.push(digit_index as u8);
    let mut hash = hash160::Hash::hash(&secret_i);

    for _ in 0..D {
        hash = hash160::Hash::hash(&hash[..]);
    }

    let hash_bytes = hash.as_byte_array().to_vec();
    hash_bytes
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
pub fn checksig_verify<const D: u32, const LOG_D: u32, const N0: usize, const N1: usize, const N: usize>(pks: Vec<Vec<u8>>) -> Script {
    script! {
        //
        // Verify the hash chain for each digit
        //

        // Repeat this for every of the n many digits
        { 1 << ((N + 1) / 2 - 1) }
        OP_SWAP
        for digit_index in 0..(N + 1) / 2 {
            OP_2DUP
            OP_LESSTHANOREQUAL
            OP_IF
                OP_OVER OP_SUB
                OP_ROT
                for _ in 0..(D + 1) / 2 {
                    OP_HASH160
                }
                0 OP_TOALTSTACK
            OP_ELSE
                OP_ROT
                { (D + 1) / 2 } OP_TOALTSTACK
            OP_ENDIF
            { pks[N - 1 - digit_index].clone() }

            OP_SWAP
            OP_2DUP
            OP_EQUAL

            OP_IF
                { D - (D + 1) / 2 }
                OP_TOALTSTACK
            OP_ENDIF

            for i in 0..D / 2 {
                OP_HASH160
                OP_2DUP
                OP_EQUAL
                OP_IF
                    { D - i - 1 - (D + 1) / 2 }
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

        for digit_index in (N + 1)/ 2..N {
            OP_2DUP
            OP_LESSTHANOREQUAL
            OP_IF
                OP_OVER OP_SUB
                OP_ROT
                for _ in 0..(D + 1) / 2 {
                    OP_HASH160
                }
                0 OP_TOALTSTACK
            OP_ELSE
                OP_ROT
                { (D + 1) / 2 } OP_TOALTSTACK
            OP_ENDIF
            { pks[N - 1 - digit_index].clone() }

            OP_SWAP
            OP_2DUP
            OP_EQUAL

            OP_IF
                { D - (D + 1) / 2 }
                OP_TOALTSTACK
            OP_ENDIF

            for i in 0..D/2 {
                OP_HASH160
                OP_2DUP
                OP_EQUAL
                OP_IF
                    { D - i - 1 - (D + 1) / 2 }
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

        // 3. Ensure both checksums are equal
        OP_EQUALVERIFY

        for i in 0..N0 - 1 {
            { i + 1 } OP_ROLL
        }
    }
}

pub fn sign_bit<const D: u32>(sk: Vec<u8>, bit: u8) -> Script {
    script! {
        { digit_signature(sk.clone(), 0, bit) }
        { digit_signature(sk.clone(), 1, D as u8 - bit) }
        { D as u8 * bit + (D as u8 - bit) }
    }
}

pub fn checksig_verify_bit<const D: u32>(pks: Vec<Vec<u8>>) -> Script {
    script! {
        // bit_sig, x_sig, compressed
        { D }
        OP_2DUP
        OP_GREATERTHAN
        OP_DUP
        OP_TOALTSTACK
        OP_IF
            OP_SUB
        OP_ELSE
            OP_DROP
        OP_ENDIF
        // bit_sig, x_sig, x=D-bit | bit
        { checksig_verify_digit::<D>(pks[1].clone()) }
        // bit_sig, x | bit
        OP_FROMALTSTACK
        // bit_sig, x, bit
        OP_ROT
        // x, bit, bit_sig
        OP_SWAP
        // x, bit_sig, bit
        { checksig_verify_digit::<D>(pks[0].clone()) }
        // x, bit
        OP_DUP
        // x, bit, bit
        OP_ROT
        // bit, bit, x
        OP_ADD
        // bit, bit+x
        { D }
        // bit, bit+x, D
        OP_EQUALVERIFY
        // bit
        OP_TOALTSTACK
    }
}

pub fn checksig_verify_digit<const D: u32>(pk: Vec<u8>) -> Script {
    script! {
        { D }
        OP_MIN

        OP_DUP
        OP_TOALTSTACK
        OP_TOALTSTACK

        for _ in 0..D {
            OP_DUP OP_HASH160
        }

        OP_FROMALTSTACK
        OP_PICK
        { pk }
        OP_EQUALVERIFY

        for _ in 0..(D + 1) / 2 {
            OP_2DROP
        }

        OP_FROMALTSTACK
    }
}

#[cfg(test)]
mod test {
    use crate::{bn254::fq::Fq, execute_script_without_stack_limit};
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::treepp::*;
    use crate::signatures::winternitz_compact::{checksig_verify, public_key, sign};
    use core::ops::Rem;
    use std::iter::zip;
    use std::ops::Mul;
    use ark_ff::UniformRand;
    use ark_std::{end_timer, start_timer};
    use num_bigint::BigUint;
    use num_traits::Num;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use num_traits::Zero;
    use rand::Rng;

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
        const LOG_D: u32   = 7;                                       // Bits per digit
        const D    : u32   = (1 << LOG_D) - 1;                        // Digits are base d+1
        const N0   : usize = 1 + (254 - 1) / (LOG_D as usize);        // Number of digits of the message fq, ceil(254 / logd)
        const N1   : usize = 2;                                       // Number of digits of the checksum
        const N    : usize = N0 + N1;                                 // Total number of digits to be signed
        
        assert!(N <= 62);                                             // N must be smaller than 62 for current version.
        assert!(D.pow(N1 as u32) > D * (N0 as u32));
        assert!(D.pow(N1 as u32 - 1) <= D * (N0 as u32));

        let sk = hex::decode(MY_SECKEY).unwrap();
        let pks = (0..N).map(|digit_index| public_key::<D>(sk.clone(), digit_index)).collect::<Vec<Vec<u8>>>();

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let r = BigUint::from_str_radix(Fq::MONTGOMERY_ONE, 16).unwrap();
        let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();

        let fq = ark_bn254::Fq::rand(&mut prng);
        let fq_biguint = BigUint::from(fq).mul(r.clone()).rem(p.clone());

        let message = biguint_to_digits::<D, N0>(fq_biguint.clone());
        
        let sign_size = sign::<D, N0, N1, N>(sk.clone(), message).len();
        let checksig_size = checksig_verify::<D, LOG_D, N0, N1, N>(pks.clone()).len();
        let signature_stack_size = N + 2;
        let fq_fit = 1000 / signature_stack_size;

        println!("LOGD, D = ({:?}, {:?})", LOG_D, D);
        println!("N = {:?}, N0 = {:?}, N1 = {:?}", N, N0, N1);
        println!("sign script size: {:?}", sign_size);
        println!("checksig script size: {:?}", checksig_size);
        println!("Fq signature size in stack: {:?}", signature_stack_size);
        println!("{:?} Fqs can fit", fq_fit);
        println!("remaining script size: {:?}", 4_000_000 - checksig_size * fq_fit);

        let script = script! {
            { sign::<D, N0, N1, N>(sk.clone(), message) }
            { checksig_verify::<D, LOG_D, N0, N1, N>(pks.clone()) }
            { Fq::from_digits::<LOG_D>() }
            { Fq::push_u32_le(&BigUint::from(fq).to_u32_digits()) }
            { Fq::equalverify(1, 0) }
            OP_TRUE
        };

        assert!(exe_script(script));
    }

    #[test]
    fn test_winternitz_multiple_fq() {
        const LOG_D: u32   = 7;                                       // Bits per digit
        const D    : u32   = (1 << LOG_D) - 1;                        // Digits are base d+1
        const N0   : usize = 1 + (254 - 1) / (LOG_D as usize);        // Number of digits of the message fq, ceil(254 / logd)
        const N1   : usize = 2;                                       // Number of digits of the checksum
        const N    : usize = N0 + N1;                                 // Total number of digits to be signed

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let fq_count = 24;
        let sk_bytes = (0..fq_count).map(|_| {let sk: [u8; 32] = rand::thread_rng().gen(); sk.to_vec()}).collect::<Vec<Vec<u8>>>();
        let r = BigUint::from_str_radix(Fq::MONTGOMERY_ONE, 16).unwrap();
        let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();
        let fq_list = (0..fq_count).map(|_| {ark_bn254::Fq::rand(&mut prng)}).collect::<Vec<_>>();
        let digits_list = fq_list.iter().map(|fq| {biguint_to_digits::<D, N0>(BigUint::from(*fq).mul(r.clone()).rem(p.clone()))}).collect::<Vec<_>>();

        let commit_script_inputs = script! {
            for (sk, digits) in zip(sk_bytes.clone(), digits_list) {
                { sign::<D, N0, N1, N>(sk, digits) }
            }
        };

        let mut pks: Vec<Vec<Vec<u8>>> = Vec::new();
        for sk in sk_bytes.iter() {
            let mut digit_pks: Vec<Vec<u8>> = Vec::new();
            for i in 0..68 {
                digit_pks.push(public_key::<D>(sk.clone(), i));
            }
            pks.push(digit_pks);
        }

        let commit_script = script! {
            for pk in pks.iter().rev() {
                { checksig_verify::<D, LOG_D, N0, N1, N>(pk.clone()) }
                { Fq::from_digits::<LOG_D>() }
                { Fq::toaltstack() }
            }
        };

        let commit_script_test = script! {
            { commit_script_inputs }
            { commit_script }
            for fq in fq_list {
                { Fq::fromaltstack() }
                { Fq::push_u32_le(&BigUint::from(fq).to_u32_digits()) }
                { Fq::equalverify(1, 0) }
            }
            OP_TRUE
        };
        
        assert!(exe_script(commit_script_test));
    }
}
