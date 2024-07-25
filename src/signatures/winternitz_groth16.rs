use crate::treepp::*;
use bitcoin::hashes::{hash160, Hash};

const LOG_D: u32 = 4;                   // bits per digit
const D:     u32 = (1 << LOG_D) - 1;    // digits are base d+1
const N0:    u32 = 64;                  // number of digits of the message
const N1:    u32 = 4;                   // number of digits of the checksum.  N1 = ⌈log_{D+1}(D*N0)⌉ + 1
const N:     u32 = N0 + N1 as u32;      // total number of digits to be signed

pub fn sign_digits(sk: Vec<u8>, message_digits: [u8; N0 as usize]) -> Script {
    let mut digits = to_digits::<{N1 as usize}>(checksum(message_digits)).to_vec();
    digits.append(&mut message_digits.to_vec());
    digits.reverse();

    script! {
        for i in 0..N {
            { digit_signature(sk.clone(), i, digits[i as usize]) }
        }
    }
}

pub fn checksum(message_digits: [u8; N0 as usize]) -> u32 {
    let mut sum = 0;
    for digit in message_digits {
        sum += digit as u32;
    }
    D * N0 - sum
}

pub fn digit_signature(sk: Vec<u8>, digit_index: u32, digit: u8) -> Script {
    let sk_i = sk.into_iter().chain(std::iter::once(digit_index as u8)).collect::<Vec<u8>>();
    let mut hash = hash160::Hash::hash(&sk_i);

    for _ in 0..digit {
        hash = hash160::Hash::hash(&hash[..]);
    }

    let hash_bytes = hash.as_byte_array().to_vec();

    script! {
        { hash_bytes }
        { digit }
    }
}

pub fn digit_pk(sk: Vec<u8>, digit_index: u32) -> Script {
    let sk_i = sk.into_iter().chain(std::iter::once(digit_index as u8)).collect::<Vec<u8>>();
    let mut hash = hash160::Hash::hash(&sk_i);

    for _ in 0..D {
        hash = hash160::Hash::hash(&hash[..]);
    }

    let hash_bytes = hash.as_byte_array().to_vec();

    script! {
        { hash_bytes }
    }
}

pub fn to_digits<const DIGIT_COUNT: usize>(mut number: u32) -> [u8; DIGIT_COUNT] {
    let mut digits: [u8; DIGIT_COUNT] = [0; DIGIT_COUNT];
    for i in 0..DIGIT_COUNT {
        let digit = number % (D + 1);
        number = (number - digit) / (D + 1);
        digits[i] = digit as u8;
    }
    digits
}

pub fn checksig_verify(sk: Vec<u8>) -> Script {
    script! {
        for digit_index in (0..N).rev() {
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
            { digit_pk(sk.clone(), digit_index) }
            OP_EQUALVERIFY

            for _ in 0..(D + 1) / 2 {
                OP_2DROP
            }
        }

        OP_FROMALTSTACK OP_DUP OP_NEGATE
        for _ in 1..N0 {
            OP_FROMALTSTACK OP_TUCK OP_SUB
        }
        { D * N0 }
        OP_ADD

        OP_FROMALTSTACK
        for _ in 0..N1 - 1 {
            for _ in 0..LOG_D {
                OP_DUP OP_ADD
            }
            OP_FROMALTSTACK
            OP_ADD
        }

        OP_EQUALVERIFY
    }
}

pub fn digits_to_bytes() -> Script {
    script! {
        for i in 0..N0 / 2 {
            OP_SWAP
            for _ in 0..LOG_D {
                OP_DUP OP_ADD
            }
            OP_ADD

            if i != (N0 / 2) - 1 {
                OP_TOALTSTACK
            }
        }

        for _ in 0..N0 / 2 - 1{
            OP_FROMALTSTACK
        }
    }
}

#[cfg(test)]
mod test {
    use super::{sign_digits, checksig_verify, digits_to_bytes, LOG_D, D, N0, N1, N};
    use ark_ff::UniformRand;
    use hex::decode as hex_decode;
    use num_bigint::BigUint;
    use rand_chacha::ChaCha20Rng;
    use rand::SeedableRng;
    use crate::{bigint::U254, bn254::{fp254impl::Fp254Impl, fq::Fq}, treepp::*};
    use num_traits::Num;
    use std::ops::{Mul, Rem};

    fn u254_to_digits(a: BigUint) -> [u8; N0 as usize] {
        let mut digits = [0_u8; N0 as usize];
        for (i, byte) in a.to_bytes_le().iter().enumerate() {
            let (x, y) = (byte % 16, byte / 16);
            digits[2 * i] = x;
            digits[2 * i + 1] = y;
        }
        digits
    }

    #[test]
    fn test_winternitz() {
        println!("LOGD: {:?}, D: {:?}", LOG_D, D);
        println!("N0: {:?}, N1: {:?}, N = N0 + N1: {:?}", N0, N1, N);

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let sk_bytes = hex_decode("b138982ce17ac813d505b5b40b665d404e9528e7").unwrap();

        let message_fq = ark_bn254::Fq::rand(&mut prng);
        let message_biguint = BigUint::from(message_fq);

        println!("message bytes: {:?}", message_biguint.to_bytes_le());
        println!("message digits: {:?}", u254_to_digits(message_biguint.clone()));
        let message_digits = u254_to_digits(message_biguint);

        let script = script! {
            { sign_digits(sk_bytes.clone(), message_digits) }
            { checksig_verify(sk_bytes.clone()) }
        };

        println!("Winternitz signature size: {:?} bytes / {:?} bits ({:?} bytes / bit)", script.len(), N0 * LOG_D, script.len() as f64 / (N0 * LOG_D) as f64);
        println!("winternitz sign digits size: {:?}", sign_digits(sk_bytes.clone(), message_digits).len());
        println!("winternitz checksig verify size: {:?}", checksig_verify(sk_bytes.clone()).len());

        let script = script! {
            { sign_digits(sk_bytes.clone(), message_digits) }
            { checksig_verify(sk_bytes.clone()) }
            { digits_to_bytes() }
            for i in 0..31 {
                { i + 1 } OP_ROLL
            }
            { U254::from_bytes() }
            { U254::push_u32_le(&BigUint::from(message_fq).to_u32_digits()) }
            { U254::equal(1, 0) }
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_winternitz_fq() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a_sk_bytes = hex_decode("b138982ce17ac813d505b5b40b665d404e9528e7").unwrap();
        let b_sk_bytes = hex_decode("b70213ef9871ba987bdb987e3b623b60982be094").unwrap();
        let c_sk_bytes = hex_decode("c0eb2ba9810975befa90db8923b19823ba097344").unwrap();

        let r = BigUint::from_str_radix(Fq::MONTGOMERY_ONE, 16).unwrap();
        let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();

        let a_fq = ark_bn254::Fq::rand(&mut prng);
        let b_fq = ark_bn254::Fq::rand(&mut prng);
        let c_fq = a_fq * b_fq;

        let a_biguint = BigUint::from(a_fq).mul(r.clone()).rem(p.clone());
        let a_digits = u254_to_digits(a_biguint);

        let b_biguint = BigUint::from(b_fq).mul(r.clone()).rem(p.clone());
        let b_digits = u254_to_digits(b_biguint);

        let c_biguint = BigUint::from(c_fq).mul(r.clone()).rem(p.clone());
        let c_digits = u254_to_digits(c_biguint);

        let script = script! {
            // inputs
            { sign_digits(c_sk_bytes.clone(), c_digits) }
            { sign_digits(a_sk_bytes.clone(), a_digits) }
            { sign_digits(b_sk_bytes.clone(), b_digits) }
            
            // check sig b
            { checksig_verify(b_sk_bytes.clone()) }
            { Fq::from_digits() }
            { Fq::toaltstack() }

            // check sig a
            { checksig_verify(a_sk_bytes.clone()) }
            { Fq::from_digits() }
            { Fq::toaltstack() }

            // check sig c
            { checksig_verify(c_sk_bytes.clone()) }
            { Fq::from_digits() }

            { Fq::fromaltstack() }
            { Fq::fromaltstack() }

            { Fq::mul() }
            { Fq::equalverify(1, 0) }

            OP_TRUE
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
