use crate::treepp::*;
use bitcoin::hashes::{hash160, Hash};

const LOG_D: u32 = 4;                   // bits per digit
const D:     u32 = (1 << LOG_D) - 1;    // digits are base d+1
const N0:    u32 = 64;                  // number of digits of the message
const N1:    u32 = 4;                   // number of digits of the checksum.  N1 = ⌈log_{D+1}(D*N0)⌉ + 1
const N:     u32 = N0 + N1 as u32;      // total number of digits to be signed

// const LOG_D: u32 = 4;                   // bits per digit
// const D:     u32 = (1 << LOG_D) - 1;    // digits are base d+1
// const N0:    u32 = 64 * 12;             // number of digits of the message
// const N1:    u32 = 5;                   // number of digits of the checksum.  N1 = ⌈log_{D+1}(D*N0)⌉ + 1
// const N:     u32 = N0 + N1 as u32;      // total number of digits to be signed

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
    use ark_ff::{Field, UniformRand};
    use ark_std::{end_timer, start_timer};
    use hex::decode as hex_decode;
    use num_bigint::BigUint;
    use rand_chacha::ChaCha20Rng;
    use rand::{Rng, SeedableRng};
    use sha2::{Digest, Sha256};
    use crate::{bigint::U254, bn254::{fp254impl::Fp254Impl, fq::Fq, fq12::Fq12, fq6::Fq6, utils::{fq12_push, fq6_push}}, execute_script_without_stack_limit, hash::{blake3::{blake3, blake3_var_length}, sha256::sha256}, treepp::*};
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

        let r = BigUint::from_str_radix(Fq::MONTGOMERY_ONE, 16).unwrap();
        let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();

        let a_fq = ark_bn254::Fq::rand(&mut prng);

        let a_biguint = BigUint::from(a_fq).mul(r.clone()).rem(p.clone());
        let a_digits = u254_to_digits(a_biguint);

        let commit_script_inputs = script! {
            { sign_digits(a_sk_bytes.clone(), a_digits) }
        };

        let commit_script = script! {
            { commit_script_inputs }
            { checksig_verify(a_sk_bytes.clone()) }
            for _ in 0..64 { OP_DROP }
            OP_TRUE
        };

        println!("commit script size: {:?}", commit_script.len());

        assert!(exe_script(commit_script));
    }

    #[test]
    fn test_winternitz_fq_minimal_signature() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a_sk_bytes = hex_decode("b138982ce17ac813d505b5b40b665d404e9528e7").unwrap();

        let r = BigUint::from_str_radix(Fq::MONTGOMERY_ONE, 16).unwrap();
        let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();

        let a_fq = ark_bn254::Fq::rand(&mut prng);

        let a_biguint = BigUint::from(a_fq).mul(r.clone()).rem(p.clone());
        let a_digits = u254_to_digits(a_biguint);

        let commit_script_inputs = script! {
            { sign_digits(a_sk_bytes.clone(), a_digits) }
        };

        let commit_script = script! {
            { commit_script_inputs }
            // { checksig_verify(a_sk_bytes.clone()) }
            // for _ in 0..64 { OP_DROP }
            // OP_TRUE
        };

        println!("commit script size: {:?}", commit_script.len());

        assert!(exe_script(commit_script));
    }

    #[test]
    fn test_winternitz_fq_op() {
        // verify ab + c = d
        // ab = e, e + c = d
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a_sk_bytes = hex_decode("b138982ce17ac813d505b5b40b665d404e9528e7").unwrap();
        let b_sk_bytes = hex_decode("b70213ef9871ba987bdb987e3b623b60982be094").unwrap();
        let c_sk_bytes = hex_decode("c0eb2ba9810975befa90db8923b19823ba097344").unwrap();
        let d_sk_bytes = hex_decode("9b87d409bae90105656de83247896ba787862378").unwrap();
        let e_sk_bytes = hex_decode("0eb2ba9810982ce17ac6de8390ba90723eb908f9").unwrap();

        let r = BigUint::from_str_radix(Fq::MONTGOMERY_ONE, 16).unwrap();
        let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();

        let a_fq = ark_bn254::Fq::rand(&mut prng);
        let b_fq = ark_bn254::Fq::rand(&mut prng);
        let c_fq = ark_bn254::Fq::rand(&mut prng);
        let d_fq = a_fq * b_fq + c_fq;
        let e_fq = a_fq * b_fq; // intermediate step

        let a_biguint = BigUint::from(a_fq).mul(r.clone()).rem(p.clone());
        let a_digits = u254_to_digits(a_biguint);

        let b_biguint = BigUint::from(b_fq).mul(r.clone()).rem(p.clone());
        let b_digits = u254_to_digits(b_biguint);

        let c_biguint = BigUint::from(c_fq).mul(r.clone()).rem(p.clone());
        let c_digits = u254_to_digits(c_biguint);

        let d_biguint = BigUint::from(d_fq).mul(r.clone()).rem(p.clone());
        let d_digits = u254_to_digits(d_biguint);

        let e_biguint = BigUint::from(e_fq).mul(r.clone()).rem(p.clone());
        let e_digits = u254_to_digits(e_biguint);

        let commit_script_inputs = script! {
            { sign_digits(a_sk_bytes.clone(), a_digits) }
            { sign_digits(b_sk_bytes.clone(), b_digits) }
            { sign_digits(c_sk_bytes.clone(), c_digits) }
            { sign_digits(d_sk_bytes.clone(), d_digits) }
            { sign_digits(e_sk_bytes.clone(), e_digits) }
        };

        let commit_script = script! {
            { commit_script_inputs }
            { checksig_verify(e_sk_bytes.clone()) }
            for _ in 0..64 { OP_DROP }
            { checksig_verify(d_sk_bytes.clone()) }
            for _ in 0..64 { OP_DROP }
            { checksig_verify(c_sk_bytes.clone()) }
            for _ in 0..64 { OP_DROP }
            { checksig_verify(b_sk_bytes.clone()) }
            for _ in 0..64 { OP_DROP }
            { checksig_verify(a_sk_bytes.clone()) }
            for _ in 0..64 { OP_DROP }
            OP_TRUE
        };

        println!("commit script size: {:?}", commit_script.len());

        let disprove_script1_inputs = script! {
            { sign_digits(e_sk_bytes.clone(), e_digits) }
            { sign_digits(a_sk_bytes.clone(), a_digits) }
            { sign_digits(b_sk_bytes.clone(), b_digits) }
        };

        let disprove_script1 = script! {
            { disprove_script1_inputs }
            
            // check sig b
            { checksig_verify(b_sk_bytes.clone()) }
            { Fq::from_digits() }
            { Fq::toaltstack() }

            // check sig a
            { checksig_verify(a_sk_bytes.clone()) }
            { Fq::from_digits() }
            { Fq::toaltstack() }

            // check sig e
            { checksig_verify(e_sk_bytes.clone()) }
            { Fq::from_digits() }

            { Fq::fromaltstack() }
            { Fq::fromaltstack() }

            { Fq::mul() }
            { Fq::equalverify(1, 0) }
            // OP_NOT

            OP_TRUE
        };

        let disprove_script2_inputs = script! {
            { sign_digits(d_sk_bytes.clone(), d_digits) }
            { sign_digits(c_sk_bytes.clone(), c_digits) }
            { sign_digits(e_sk_bytes.clone(), e_digits) }
        };

        let disprove_script2 = script! {
            { disprove_script2_inputs }
            
            // check sig e
            { checksig_verify(e_sk_bytes.clone()) }
            { Fq::from_digits() }
            { Fq::toaltstack() }

            // check sig c
            { checksig_verify(c_sk_bytes.clone()) }
            { Fq::from_digits() }
            { Fq::toaltstack() }

            // check sig d
            { checksig_verify(d_sk_bytes.clone()) }
            { Fq::from_digits() }

            { Fq::fromaltstack() }
            { Fq::fromaltstack() }

            { Fq::add(1, 0) }
            { Fq::equalverify(1, 0) }
            // OP_NOT
            
            OP_TRUE
        };

        let s = script! {
            { checksig_verify(e_sk_bytes.clone()) }
            { Fq::from_digits() }
        };

        println!("check sig and from digits size: {:?}", s.len());

        assert!(exe_script(commit_script));
        assert!(exe_script(disprove_script1));
        assert!(exe_script(disprove_script2));
    }

    // #[test]
    // fn test_winternitz_fq12() {
    //     // verify ab + c = d
    //     // ab = e, e + c = d
    //     let mut prng = ChaCha20Rng::seed_from_u64(0);

    //     let a_sk_bytes = hex_decode("b138982ce17ac813d505b5b40b665d404e9528e7").unwrap();
    //     let b_sk_bytes = hex_decode("b70213ef9871ba987bdb987e3b623b60982be094").unwrap();
    //     let c_sk_bytes = hex_decode("c0eb2ba9810975befa90db8923b19823ba097344").unwrap();
    //     let d_sk_bytes = hex_decode("9b87d409bae90105656de83247896ba787862378").unwrap();
    //     let e_sk_bytes = hex_decode("0eb2ba9810982ce17ac6de8390ba90723eb908f9").unwrap();

    //     let r = BigUint::from_str_radix(Fq::MONTGOMERY_ONE, 16).unwrap();
    //     let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();

    //     let a_fq12 = ark_bn254::Fq12::rand(&mut prng);
    //     let b_fq12 = ark_bn254::Fq12::rand(&mut prng);
    //     let c_fq12 = ark_bn254::Fq12::rand(&mut prng);
    //     let d_fq12 = a_fq12 * b_fq12 + c_fq12;
    //     let e_fq12 = a_fq12 * b_fq12; // intermediate step

    //     let mut a_digits = [0_u8; 64 * 12];
    //     for (i, x) in a_fq12.to_base_prime_field_elements().enumerate() {
    //         let x_digits = u254_to_digits(BigUint::from(x).mul(r.clone()).rem(p.clone()));
    //         for j in 0..64 {
    //             a_digits[64 * i + j] = x_digits[j];
    //         }
    //     }

    //     let script = script! {
    //         { sign_digits(a_sk_bytes.clone(), a_digits) }
    //         { checksig_verify(a_sk_bytes) }
    //         { Fq12::from_digits() }
    //         { fq12_push(a_fq12) }
    //         { Fq12::equalverify() }
    //         OP_TRUE
    //     };

    //     assert!(exe_script(script));
    // }

    #[test]
    fn test_winternitz_fq12_hash() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a_sk_bytes = hex_decode("b138982ce17ac813d505b5b40b665d404e9528e7").unwrap();

        let r = BigUint::from_str_radix(Fq::MONTGOMERY_ONE, 16).unwrap();
        let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();

        let a_fq12 = ark_bn254::Fq12::rand(&mut prng);

        let mut a_digits = [0_u8; 64 * 12];
        for (i, x) in a_fq12.to_base_prime_field_elements().enumerate() {
            let x_digits = u254_to_digits(BigUint::from(x).mul(r.clone()).rem(p.clone()));
            for j in 0..64 {
                a_digits[64 * i + j] = x_digits[j];
            }
        }

        let mut a_bytes = [0_u8; 32 * 12];
        for (i, x) in a_fq12.to_base_prime_field_elements().enumerate() {
            let x_bytes = BigUint::from(x).to_bytes_le();
            for j in 0..32 {
                a_bytes[32 * i + j] = x_bytes[j];
            }
        }
        a_bytes.reverse();

        let mut hasher_sha256 = Sha256::new();
        hasher_sha256.update(&a_bytes);
        let result_sha256 = hasher_sha256.finalize();
        let mut result_sha256_digits = [0_u8; 64];
        for (i, byte) in result_sha256.iter().enumerate() {
            let (u, v) = (byte % 16, byte / 16);
            result_sha256_digits[2 * i] = u;
            result_sha256_digits[2 * i + 1] = v;
        }

        let mut hasher_blake3 = blake3::Hasher::new();
        hasher_blake3.update(&a_bytes);
        let result_blake3 = hasher_blake3.finalize();
        let mut result_blake3_digits = [0_u8; 64];
        for (i, byte) in result_blake3.as_bytes().iter().enumerate() {
            let (u, v) = (byte % 16, byte / 16);
            result_blake3_digits[2 * i] = u;
            result_blake3_digits[2 * i + 1] = v;
        }

        let script_inputs_blake3 = script! {
            { sign_digits(a_sk_bytes.clone(), result_blake3_digits) }
            { fq12_push(a_fq12) }
        };

        let script_blake3 = script! {
            { script_inputs_blake3.clone() }
            for _ in 0..11 {
                { Fq::toaltstack() }
            }
            { Fq::convert_to_be_bytes() }
            for _ in 0..11 {
                { Fq::fromaltstack() }
                { Fq::convert_to_be_bytes() }
            }
            { blake3_var_length(32 * 12) }
            for _ in 0..32 {
                OP_TOALTSTACK
            }
            { checksig_verify(a_sk_bytes.clone()) }
            { digits_to_bytes() }
            for _ in 0..8 {
                for _ in 0..4 {
                    OP_FROMALTSTACK
                }
                4 OP_ROLL OP_EQUALVERIFY 3 OP_ROLL OP_EQUALVERIFY 2 OP_ROLL OP_EQUALVERIFY OP_EQUALVERIFY
            }
            OP_TRUE
        };

        assert!(exe_script(script_blake3));

        let script_inputs_sha256 = script! {
            { sign_digits(a_sk_bytes.clone(), result_sha256_digits) }
            { fq12_push(a_fq12) }
        };

        let script_sha256 = script! {
            { script_inputs_sha256 }
            for _ in 0..11 {
                { Fq::toaltstack() }
            }
            { Fq::convert_to_be_bytes() }
            for _ in 0..11 {
                { Fq::fromaltstack() }
                { Fq::convert_to_be_bytes() }
            }
            { sha256(32 * 12) }
            for _ in 0..32 {
                OP_TOALTSTACK
            }
            { checksig_verify(a_sk_bytes) }
            { digits_to_bytes() }
            for _ in 0..32 {
                OP_FROMALTSTACK
            }
            for i in (2..33).rev() {
                { i } OP_ROLL OP_EQUALVERIFY
            }
            OP_EQUALVERIFY

            OP_TRUE
        };

        assert!(exe_script(script_sha256));
    }

    #[test]
    fn test_winternitz_fq12_hash_mul() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let abc_hash_sk_bytes = hex_decode("b138982ce17ac813d505b5b40b665d404e9528e7").unwrap();

        let r = BigUint::from_str_radix(Fq::MONTGOMERY_ONE, 16).unwrap();
        let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();

        let a_fq12 = ark_bn254::Fq12::rand(&mut prng);
        let b_fq12 = ark_bn254::Fq12::rand(&mut prng);
        let c_fq12 = a_fq12 * b_fq12;

        // let mut a_digits = [0_u8; 64 * 12];
        // for (i, x) in a_fq12.to_base_prime_field_elements().enumerate() {
        //     let x_digits = u254_to_digits(BigUint::from(x).mul(r.clone()).rem(p.clone()));
        //     for j in 0..64 {
        //         a_digits[64 * i + j] = x_digits[j];
        //     }
        // }

        let mut a_bytes = [0_u8; 32 * 12];
        for (i, x) in a_fq12.to_base_prime_field_elements().enumerate() {
            let mut x_bytes = BigUint::from(x).to_bytes_le();
            for _ in 0..(32 - x_bytes.len()) {
                x_bytes.push(0);
            }
            for j in 0..32 {
                a_bytes[32 * i + j] = x_bytes[j];
            }
        }
        a_bytes.reverse();

        let mut b_bytes = [0_u8; 32 * 12];
        for (i, x) in b_fq12.to_base_prime_field_elements().enumerate() {
            let mut x_bytes = BigUint::from(x).to_bytes_le();
            for _ in 0..(32 - x_bytes.len()) {
                x_bytes.push(0);
            }
            for j in 0..32 {
                b_bytes[32 * i + j] = x_bytes[j];
            }
        }
        b_bytes.reverse();

        let mut c_bytes = [0_u8; 32 * 12];
        for (i, x) in c_fq12.to_base_prime_field_elements().enumerate() {
            let mut x_bytes = BigUint::from(x).to_bytes_le();
            for _ in 0..(32 - x_bytes.len()) {
                x_bytes.push(0);
            }
            for j in 0..32 {
                c_bytes[32 * i + j] = x_bytes[j];
            }
        }
        c_bytes.reverse();

        let abc_bytes: Vec<u8> = [a_bytes, b_bytes, c_bytes].concat();

        let mut hasher_sha256 = Sha256::new();
        hasher_sha256.update(&abc_bytes);
        let result_sha256 = hasher_sha256.finalize();
        let mut result_sha256_digits = [0_u8; 64];
        for (i, byte) in result_sha256.iter().enumerate() {
            let (u, v) = (byte % 16, byte / 16);
            result_sha256_digits[2 * i] = u;
            result_sha256_digits[2 * i + 1] = v;
        }

        let mut hasher_blake3 = blake3::Hasher::new();
        hasher_blake3.update(&a_bytes);
        let result_blake3 = hasher_blake3.finalize();
        let mut a_blake3 = result_blake3.as_bytes().to_vec();
        a_blake3.extend(b_bytes);

        let mut hasher_blake3 = blake3::Hasher::new();
        hasher_blake3.update(&a_blake3);
        let result_blake3 = hasher_blake3.finalize();
        let mut ab_blake3 = result_blake3.as_bytes().to_vec();
        ab_blake3.extend(c_bytes);

        let mut hasher_blake3 = blake3::Hasher::new();
        hasher_blake3.update(&ab_blake3);
        let result_blake3 = hasher_blake3.finalize();
        let abc_blake3 = result_blake3.as_bytes().to_vec();

        let mut abc_blake3_digits = [0_u8; 64];
        for (i, byte) in abc_blake3.iter().enumerate() {
            let (u, v) = (byte % 16, byte / 16);
            abc_blake3_digits[2 * i] = u;
            abc_blake3_digits[2 * i + 1] = v;
        }

        let script_inputs_blake3 = script! {
            { sign_digits(abc_hash_sk_bytes.clone(), abc_blake3_digits) }
            { fq12_push(c_fq12) }
            { fq12_push(b_fq12) }
            { fq12_push(a_fq12) }
        };

        let script_blake3 = script! {
            { script_inputs_blake3.clone() }
            for _ in 0..11 {
                { Fq::toaltstack() }
            }
            { Fq::convert_to_be_bytes() }
            for _ in 0..11 {
                { Fq::fromaltstack() }
                { Fq::convert_to_be_bytes() }
            }
            { blake3_var_length(32 * 12) }
            for _ in 0..32 {
                OP_TOALTSTACK
            }
            for _ in 0..8 {
                for _ in 0..4 {
                    OP_FROMALTSTACK
                }
                OP_SWAP 2 OP_ROLL 3 OP_ROLL
            }
            for _ in 0..32 {
                OP_TOALTSTACK
            }
            for _ in 0..11 {
                { Fq::toaltstack() }
            }
            { Fq::convert_to_be_bytes() }
            for _ in 0..11 {
                { Fq::fromaltstack() }
                { Fq::convert_to_be_bytes() }
            }
            for _ in 0..32 {
                OP_FROMALTSTACK
            }
            for i in 0..31 {
                { i + 1} OP_ROLL
            }
            { blake3_var_length(32 * 12 + 32) }
            for _ in 0..32 {
                OP_TOALTSTACK
            }
            for _ in 0..8 {
                for _ in 0..4 {
                    OP_FROMALTSTACK
                }
                OP_SWAP 2 OP_ROLL 3 OP_ROLL
            }
            for _ in 0..32 {
                OP_TOALTSTACK
            }
            for _ in 0..11 {
                { Fq::toaltstack() }
            }
            { Fq::convert_to_be_bytes() }
            for _ in 0..11 {
                { Fq::fromaltstack() }
                { Fq::convert_to_be_bytes() }
            }
            for _ in 0..32 {
                OP_FROMALTSTACK
            }
            for i in 0..31 {
                { i + 1} OP_ROLL
            }
            { blake3_var_length(32 * 12 + 32) }
            for _ in 0..32 {
                OP_TOALTSTACK
            }
            for _ in 0..8 {
                for _ in 0..4 {
                    OP_FROMALTSTACK
                }
                OP_SWAP 2 OP_ROLL 3 OP_ROLL
            }
            for _ in 0..32 {
                OP_TOALTSTACK
            }
            { checksig_verify(abc_hash_sk_bytes.clone()) }
            { digits_to_bytes() }
            for _ in 0..32 {
                OP_FROMALTSTACK
                OP_EQUALVERIFY
            }
            OP_TRUE
        };

        assert!(exe_script(script_blake3));
    }

    #[test]
    fn test_winternitz_fq6_hash_mul() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let abc_hash_sk_bytes = hex_decode("b138982ce17ac813d505b5b40b665d404e9528e7").unwrap();

        let r = BigUint::from_str_radix(Fq::MONTGOMERY_ONE, 16).unwrap();
        let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();

        let a_fq6 = ark_bn254::Fq6::rand(&mut prng);
        let b_fq6 = ark_bn254::Fq6::rand(&mut prng);
        let c_fq6 = a_fq6 * b_fq6;

        let mut a_bytes = [0_u8; 32 * 6];
        for (i, x) in a_fq6.to_base_prime_field_elements().enumerate() {
            let mut x_bytes = BigUint::from(x).to_bytes_le();
            for _ in 0..(32 - x_bytes.len()) {
                x_bytes.push(0);
            }
            for j in 0..32 {
                a_bytes[32 * i + j] = x_bytes[j];
            }
        }
        a_bytes.reverse();

        let mut b_bytes = [0_u8; 32 * 6];
        for (i, x) in b_fq6.to_base_prime_field_elements().enumerate() {
            let mut x_bytes = BigUint::from(x).to_bytes_le();
            for _ in 0..(32 - x_bytes.len()) {
                x_bytes.push(0);
            }
            for j in 0..32 {
                b_bytes[32 * i + j] = x_bytes[j];
            }
        }
        b_bytes.reverse();

        let mut c_bytes = [0_u8; 32 * 6];
        for (i, x) in c_fq6.to_base_prime_field_elements().enumerate() {
            let mut x_bytes = BigUint::from(x).to_bytes_le();
            for _ in 0..(32 - x_bytes.len()) {
                x_bytes.push(0);
            }
            for j in 0..32 {
                c_bytes[32 * i + j] = x_bytes[j];
            }
        }
        c_bytes.reverse();

        let abc_bytes: Vec<u8> = [a_bytes, b_bytes, c_bytes].concat();

        let mut hasher_sha256 = Sha256::new();
        hasher_sha256.update(&abc_bytes);
        let result_sha256 = hasher_sha256.finalize();
        let mut result_sha256_digits = [0_u8; 64];
        for (i, byte) in result_sha256.iter().enumerate() {
            let (u, v) = (byte % 16, byte / 16);
            result_sha256_digits[2 * i] = u;
            result_sha256_digits[2 * i + 1] = v;
        }

        let mut hasher_blake3 = blake3::Hasher::new();
        hasher_blake3.update(&a_bytes);
        let result_blake3 = hasher_blake3.finalize();
        let mut a_blake3 = result_blake3.as_bytes().to_vec();
        a_blake3.extend(b_bytes);

        let mut hasher_blake3 = blake3::Hasher::new();
        hasher_blake3.update(&a_blake3);
        let result_blake3 = hasher_blake3.finalize();
        let mut ab_blake3 = result_blake3.as_bytes().to_vec();
        ab_blake3.extend(c_bytes);

        let mut hasher_blake3 = blake3::Hasher::new();
        hasher_blake3.update(&ab_blake3);
        let result_blake3 = hasher_blake3.finalize();
        let abc_blake3 = result_blake3.as_bytes().to_vec();

        let mut abc_blake3_digits = [0_u8; 64];
        for (i, byte) in abc_blake3.iter().enumerate() {
            let (u, v) = (byte % 16, byte / 16);
            abc_blake3_digits[2 * i] = u;
            abc_blake3_digits[2 * i + 1] = v;
        }

        let script_inputs_blake3 = script! {
            { sign_digits(abc_hash_sk_bytes.clone(), abc_blake3_digits) }
            { fq6_push(c_fq6) }
            { fq6_push(b_fq6) }
            { fq6_push(a_fq6) }
        };

        let script_blake3 = script! {
            { script_inputs_blake3.clone() }
            { Fq6::copy(0) }
            { Fq6::toaltstack() }
            { Fq6::copy(6) }
            { Fq6::toaltstack() }
            { Fq6::copy(12) }
            { Fq6::toaltstack() }
            for _ in 0..5 {
                { Fq::toaltstack() }
            }
            { Fq::convert_to_be_bytes() }
            for _ in 0..5 {
                { Fq::fromaltstack() }
                { Fq::convert_to_be_bytes() }
            }
            { blake3_var_length(32 * 6) }
            for _ in 0..32 {
                OP_TOALTSTACK
            }
            for _ in 0..8 {
                for _ in 0..4 {
                    OP_FROMALTSTACK
                }
                OP_SWAP 2 OP_ROLL 3 OP_ROLL
            }
            for _ in 0..32 {
                OP_TOALTSTACK
            }
            for _ in 0..5 {
                { Fq::toaltstack() }
            }
            { Fq::convert_to_be_bytes() }
            for _ in 0..5 {
                { Fq::fromaltstack() }
                { Fq::convert_to_be_bytes() }
            }
            for _ in 0..32 {
                OP_FROMALTSTACK
            }
            for i in 0..31 {
                { i + 1} OP_ROLL
            }
            { blake3_var_length(32 * 6 + 32) }
            for _ in 0..32 {
                OP_TOALTSTACK
            }
            for _ in 0..8 {
                for _ in 0..4 {
                    OP_FROMALTSTACK
                }
                OP_SWAP 2 OP_ROLL 3 OP_ROLL
            }
            for _ in 0..32 {
                OP_TOALTSTACK
            }
            for _ in 0..5 {
                { Fq::toaltstack() }
            }
            { Fq::convert_to_be_bytes() }
            for _ in 0..5 {
                { Fq::fromaltstack() }
                { Fq::convert_to_be_bytes() }
            }
            for _ in 0..32 {
                OP_FROMALTSTACK
            }
            for i in 0..31 {
                { i + 1} OP_ROLL
            }
            { blake3_var_length(32 * 6 + 32) }
            for _ in 0..32 {
                OP_TOALTSTACK
            }
            for _ in 0..8 {
                for _ in 0..4 {
                    OP_FROMALTSTACK
                }
                OP_SWAP 2 OP_ROLL 3 OP_ROLL
            }
            for _ in 0..32 {
                OP_TOALTSTACK
            }
            { checksig_verify(abc_hash_sk_bytes.clone()) }
            { digits_to_bytes() }
            for _ in 0..32 {
                OP_FROMALTSTACK
                OP_EQUALVERIFY
            }
            { Fq6::fromaltstack() }
            { Fq6::fromaltstack() }
            { Fq6::fromaltstack() }
            { Fq6::mul(6, 0) }
            { Fq6::equalverify() }
            OP_TRUE
        };

        assert!(exe_script(script_blake3));
    }

    #[test]
    fn test_winternitz_fq12_mul() {
        // ab=c
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a_sk_bytes = (0..12).map(|_| {
            let sk: [u8; 32] = rand::thread_rng().gen();
            sk.to_vec()
        }).collect::<Vec<Vec<u8>>>();
        let b_sk_bytes = (0..12).map(|_| {
            let sk: [u8; 32] = rand::thread_rng().gen();
            sk.to_vec()
        }).collect::<Vec<Vec<u8>>>();
        let c_sk_bytes = (0..12).map(|_| {
            let sk: [u8; 32] = rand::thread_rng().gen();
            sk.to_vec()
        }).collect::<Vec<Vec<u8>>>();

        let a_fq12 = ark_bn254::Fq12::rand(&mut prng);
        let b_fq12 = ark_bn254::Fq12::rand(&mut prng);
        let c_fq12 = a_fq12 * b_fq12;

        let r = BigUint::from_str_radix(Fq::MONTGOMERY_ONE, 16).unwrap();
        let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();

        let mut a_digits = Vec::new();
        for fq in a_fq12.to_base_prime_field_elements() {
            let fq_biguint = BigUint::from(fq).mul(r.clone()).rem(p.clone());
            let fq_digits = u254_to_digits(fq_biguint);
            a_digits.push(fq_digits);
        }

        let mut b_digits = Vec::new();
        for fq in b_fq12.to_base_prime_field_elements() {
            let fq_biguint = BigUint::from(fq).mul(r.clone()).rem(p.clone());
            let fq_digits = u254_to_digits(fq_biguint);
            b_digits.push(fq_digits);
        }

        let mut c_digits = Vec::new();
        for fq in c_fq12.to_base_prime_field_elements() {
            let fq_biguint = BigUint::from(fq).mul(r.clone()).rem(p.clone());
            let fq_digits = u254_to_digits(fq_biguint);
            c_digits.push(fq_digits);
        }

        let script_inputs = script! {
            for (i, fq_digits) in c_digits.iter().enumerate() {
                { sign_digits(c_sk_bytes[i].clone(), *fq_digits) }
            }
            for (i, fq_digits) in b_digits.iter().enumerate() {
                { sign_digits(b_sk_bytes[i].clone(), *fq_digits) }
            }
            for (i, fq_digits) in a_digits.iter().enumerate() {
                { sign_digits(a_sk_bytes[i].clone(), *fq_digits) }
            }
        };

        let script = script! {
            { script_inputs }
            for i in 0..12 {
                { checksig_verify(a_sk_bytes[11 - i].clone()) }
                { Fq::from_digits() }
                { Fq::toaltstack() }
            }
            for i in 0..12 {
                { checksig_verify(b_sk_bytes[11 - i].clone()) }
                { Fq::from_digits() }
                { Fq::toaltstack() }
            }
            for i in 0..12 {
                { checksig_verify(c_sk_bytes[11 - i].clone()) }
                { Fq::from_digits() }
                { Fq::toaltstack() }
            }
            { Fq12::fromaltstack() }
            { Fq12::fromaltstack() }
            { Fq12::fromaltstack() }
            { Fq12::mul(12, 0) }
            { Fq12::equalverify() }
            OP_TRUE
        };

        assert!(exe_script(script));
    }
}
