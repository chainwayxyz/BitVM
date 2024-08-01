use std::{cmp::min, ops::{Mul, Rem}};

use crate::{bigint::std::OP_16MUL, bn254::{fp254impl::Fp254Impl, fq::Fq, utils::u254_to_digits}, treepp::*};
use bitcoin::hashes::{hash160, Hash};
use num_bigint::BigUint;
use num_traits::Num;

const LOG_D: u32 = 4;                   // bits per digit
const D:     u32 = (1 << LOG_D) - 1;    // digits are base d+1
const N0:    u32 = 64;                  // number of digits of the message
const N1:    u32 = 4;                   // number of digits of the checksum.  N1 = ⌈log_{D+1}(D*N0)⌉ + 1
const N:     u32 = N0 + N1 as u32;      // total number of digits to be signed


pub fn public_key(secret_key: &Vec<u8>) -> Vec<u8> {

    let mut hash: hash160::Hash = hash160::Hash::hash(&secret_key);

    for _ in 0..D {
        hash = hash160::Hash::hash(&hash[..]);
    }

    hash.as_byte_array().to_vec()
    
}

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

pub fn sign_fq_compressed(sk: Vec<u8>, fq: ark_bn254::Fq) -> Script {
    let r = BigUint::from_str_radix(Fq::MONTGOMERY_ONE, 16).unwrap();
    let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();
    let message_digits = u254_to_digits(BigUint::from(fq).mul(r.clone()).rem(p.clone()));

    sign_digits(sk, message_digits)
    

}

pub fn sign_digits_compressed(sk: Vec<u8>, message_digits: [u8; N0 as usize]) -> Script {
    let mut digits = to_digits::<{N1 as usize}>(checksum(message_digits)).to_vec();
    digits.append(&mut message_digits.to_vec());
    digits.reverse();

    script! {
        for i in 0..N {
            { winternitz_signature(sk.clone(), i, digits[i as usize]) }
        }
        { compress_digits(digits) }
    }
}

pub fn compress_digits(digits: Vec<u8>) -> Script {
    let mut compressed_digits: Vec<u32> = Vec::new();
    let compress_size: usize = 28 / LOG_D as usize;

    let mut index = 0;
    while index < digits.len() {
        let mut val: u32 = 0;
        for j in index..(min(index + compress_size, digits.len())) {
            val *= D + 1;
            val += digits[j] as u32;
        }
        compressed_digits.push(val);
        index += compress_size; 

    }

    script!{
        for compressed in compressed_digits{
            { compressed }
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

pub fn winternitz_signature(sk: Vec<u8>, digit_index: u32, digit: u8) -> Script {
    let sk_i = sk.into_iter().chain(std::iter::once(digit_index as u8)).collect::<Vec<u8>>();
    let mut hash = hash160::Hash::hash(&sk_i);

    for _ in 0..digit {
        hash = hash160::Hash::hash(&hash[..]);
    }

    let hash_bytes = hash.as_byte_array().to_vec();

    script! {
        { hash_bytes }
    }
}

pub fn digit_signature(sk: Vec<u8>, digit_index: u32, digit: u8) -> Script {
    let sk_i = sk.into_iter().chain(std::iter::once(digit_index as u8)).collect::<Vec<u8>>();
    let mut hash = hash160::Hash::hash(&sk_i);

    for _ in 0..digit {
        hash = hash160::Hash::hash(&hash[..]);
    }

    let hash_bytes = hash.as_byte_array().to_vec();

    println!("{:?}", hash_bytes);
    script! {
        { hash_bytes }
        { digit }
    }
}

pub fn digit_pk_script(sk: Vec<u8>, digit_index: u32) -> Script {
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

pub fn digit_pk(sk: Vec<u8>, digit_index: u32) -> Vec<u8> {
    let sk_i = sk.into_iter().chain(std::iter::once(digit_index as u8)).collect::<Vec<u8>>();
    let mut hash = hash160::Hash::hash(&sk_i);

    for _ in 0..D {
        hash = hash160::Hash::hash(&hash[..]);
    }

    hash.as_byte_array().to_vec()
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

pub fn reveal(sk: Vec<u8>) -> Script {
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
            { digit_pk_script(sk.clone(), digit_index) }
            OP_EQUALVERIFY

            for _ in 0..(D + 1) / 2 {
                OP_2DROP
            }
        }

        OP_FROMALTSTACK OP_NEGATE
        for _ in 1..N0 {
            OP_FROMALTSTACK OP_SUB
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

pub fn u20_to_digits() -> Script {
    script! {
        { 1<<19 }
        OP_SWAP
        // 2^19 A_{19...0}
        for _ in 0..4 {
            OP_2DUP 
            OP_LESSTHANOREQUAL 
            OP_IF
                OP_OVER OP_SUB OP_8
            OP_ELSE
                OP_0
            OP_ENDIF
            OP_TOALTSTACK
            OP_DUP OP_ADD

            OP_2DUP 
            OP_LESSTHANOREQUAL 
            OP_IF
                OP_OVER OP_SUB
                OP_FROMALTSTACK OP_4 OP_ADD OP_TOALTSTACK
            OP_ENDIF
            OP_DUP OP_ADD

            OP_2DUP 
            OP_LESSTHANOREQUAL 
            OP_IF
                OP_OVER OP_SUB
                OP_FROMALTSTACK OP_2 OP_ADD OP_TOALTSTACK
            OP_ENDIF
            OP_DUP OP_ADD

            OP_2DUP 
            OP_LESSTHANOREQUAL 
            OP_IF
                OP_OVER OP_SUB
                OP_FROMALTSTACK OP_1ADD OP_TOALTSTACK
            OP_ENDIF
            OP_DUP OP_ADD
        }

        OP_2DUP 
        OP_LESSTHANOREQUAL 
        OP_IF
            OP_OVER OP_SUB OP_8
        OP_ELSE
            OP_0
        OP_ENDIF
        OP_TOALTSTACK
        OP_DUP OP_ADD

        OP_2DUP 
        OP_LESSTHANOREQUAL 
        OP_IF
            OP_OVER OP_SUB
            OP_FROMALTSTACK OP_4 OP_ADD OP_TOALTSTACK
        OP_ENDIF
        OP_DUP OP_ADD

        OP_2DUP 
        OP_LESSTHANOREQUAL 
        OP_IF
            OP_OVER OP_SUB
            OP_FROMALTSTACK OP_2 OP_ADD OP_TOALTSTACK
        OP_ENDIF

        OP_NIP
        OP_0NOTEQUAL
        OP_FROMALTSTACK OP_ADD OP_TOALTSTACK

    }
}

pub fn u28_to_digits() -> Script {
    script! {
        { 1<<27 }
        OP_SWAP
        // 2^27 A_{27...0}
        for _ in 0..6 {
            OP_2DUP 
            OP_LESSTHANOREQUAL 
            OP_IF
                OP_OVER OP_SUB OP_8
            OP_ELSE
                OP_0
            OP_ENDIF
            OP_TOALTSTACK
            OP_DUP OP_ADD

            OP_2DUP 
            OP_LESSTHANOREQUAL 
            OP_IF
                OP_OVER OP_SUB
                OP_FROMALTSTACK OP_4 OP_ADD OP_TOALTSTACK
            OP_ENDIF
            OP_DUP OP_ADD

            OP_2DUP 
            OP_LESSTHANOREQUAL 
            OP_IF
                OP_OVER OP_SUB
                OP_FROMALTSTACK OP_2 OP_ADD OP_TOALTSTACK
            OP_ENDIF
            OP_DUP OP_ADD

            OP_2DUP 
            OP_LESSTHANOREQUAL 
            OP_IF
                OP_OVER OP_SUB
                OP_FROMALTSTACK OP_1ADD OP_TOALTSTACK
            OP_ENDIF
            OP_DUP OP_ADD
        }

        OP_2DUP 
        OP_LESSTHANOREQUAL 
        OP_IF
            OP_OVER OP_SUB OP_8
        OP_ELSE
            OP_0
        OP_ENDIF
        OP_TOALTSTACK
        OP_DUP OP_ADD

        OP_2DUP 
        OP_LESSTHANOREQUAL 
        OP_IF
            OP_OVER OP_SUB
            OP_FROMALTSTACK OP_4 OP_ADD OP_TOALTSTACK
        OP_ENDIF
        OP_DUP OP_ADD

        OP_2DUP 
        OP_LESSTHANOREQUAL 
        OP_IF
            OP_OVER OP_SUB
            OP_FROMALTSTACK OP_2 OP_ADD OP_TOALTSTACK
        OP_ENDIF

        OP_NIP
        OP_0NOTEQUAL
        OP_FROMALTSTACK OP_ADD OP_TOALTSTACK

    }
}

pub fn checksig_verify_compressed(pks: Vec<Vec<u8>>) -> Script {
    script! {
        { u20_to_digits() }
        for i in 0..5 {
            { 9 + i }  OP_ROLL
            OP_FROMALTSTACK
            { checksig_verify_digit(pks[67 - i].clone()) }
        }

        for i in 0..9 {
            { 5 + i * 7 } OP_ROLL
            { u28_to_digits() }
            for j in 0..7 {
                { 5 + i * 6 + 8 + j }  OP_ROLL
                OP_FROMALTSTACK
                { checksig_verify_digit(pks[62 - 7*i - j].clone()) }
            }
        }

        for _ in 0..4 {
            { 67 } OP_ROLL
        }

        for _ in 0..3 {
            OP_16MUL
            OP_ADD
        }

        for i in 0..64 {
            { i + 1 } OP_PICK 
            OP_ADD
        }         

        { D * N0 }
        OP_EQUALVERIFY   
        
        for i in 0..63 {
            {i + 1} OP_ROLL
        }

        { Fq::from_digits() }
        { Fq::toaltstack() }
    }
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
            { digit_pk_script(sk.clone(), digit_index) }
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

pub fn checksig_verify_digit(pk: Vec<u8>) -> Script {
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
    use ark_ff::UniformRand;
    use ark_std::{end_timer, start_timer};
    use num_bigint::BigUint;
    use rand_chacha::ChaCha20Rng;
    use rand::{Rng, SeedableRng};
    use crate::{bn254::{fp254impl::Fp254Impl, fq::Fq, utils::u254_to_digits}, execute_script_without_stack_limit, signatures::winternitz_groth16::{checksig_verify_compressed, digit_pk, sign_digits_compressed}, treepp::*};
    use num_traits::Num;
    use std::{iter::zip, ops::{Mul, Rem}};

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
    fn test_winternitz_multiple_compressed_fq() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let fq_count = 12;
        let sk_bytes = (0..fq_count).map(|_| {let sk: [u8; 32] = rand::thread_rng().gen(); sk.to_vec()}).collect::<Vec<Vec<u8>>>();
        let r = BigUint::from_str_radix(Fq::MONTGOMERY_ONE, 16).unwrap();
        let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();
        let fq_list = (0..fq_count).map(|_| {ark_bn254::Fq::rand(&mut prng)}).collect::<Vec<_>>();
        let digits_list = fq_list.iter().map(|fq| {u254_to_digits(BigUint::from(*fq).mul(r.clone()).rem(p.clone()))}).collect::<Vec<_>>();

        let commit_script_inputs = script! {
            for (sk, digits) in zip(sk_bytes.clone(), digits_list) {
                { sign_digits_compressed(sk, digits) }
            }
        };


        let mut pks: Vec<Vec<Vec<u8>>> = Vec::new();
        for sk in sk_bytes.iter() {
            let mut digit_pks: Vec<Vec<u8>> = Vec::new();
            for i in 0..68 {
                digit_pks.push(digit_pk(sk.clone(), i));
            }
            pks.push(digit_pks);
        }

        let commit_script = script! {
            for pk in pks.iter().rev() {
                { checksig_verify_compressed(pk.clone()) } 
            }
        };
        let n = commit_script.len();
        println!("commit script size ({:?} Fq): {:?}", fq_count, n);
        println!("you can put {:?} of these in a single block, so in a single block, you can commit to {:?} Fq", 4_000_000 / n, (4_000_000 / n) * fq_count);

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