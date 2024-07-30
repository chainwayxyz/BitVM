use crate::{bn254::{fp254impl::Fp254Impl, fq::Fq}, treepp::*};
use bitcoin::hashes::{hash160, Hash};
use std::cmp::min;

const LOG_D: u32 = 4;                   // bits per digit
const D:     u32 = (1 << LOG_D) - 1;    // digits are base d+1
const N0:    u32 = 64;                  // number of digits of the message
const N1:    u32 = 4;                   // number of digits of the checksum.  N1 = ⌈log_{D+1}(D*N0)⌉ + 1
const N:     u32 = N0 + N1 as u32;      // total number of digits to be signed

pub fn OP_16MUL() -> Script {
    script! {
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
    }
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
            val *= (D + 1);
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
            { digit_pk(sk.clone(), digit_index) }
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

pub fn checksig_verify_compressed(sk: Vec<u8>) -> Script {
    script! {
        { u20_to_digits() }
        for i in 0..5 {
            { 9 + i }  OP_ROLL
            OP_FROMALTSTACK
            { checksig_verify_digit(sk.clone(), 67 - i) }
        }


        for i in 0..9 {
            { 5 + i * 7 } OP_ROLL
            { u28_to_digits() }
            for j in 0..7 {
                { 5 + i * 6 + 8 + j }  OP_ROLL
                OP_FROMALTSTACK
                { checksig_verify_digit(sk.clone(), 62 - 7*i - j) }
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

pub fn checksig_verify_digit(sk: Vec<u8>, digit_index: u32) -> Script {
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
        { digit_pk(sk.clone(), digit_index) }
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
    use super::N0;
    use ark_ff::UniformRand;
    use ark_std::{end_timer, start_timer};
    use rand_chacha::ChaCha20Rng;
    use rand::{Rng, SeedableRng};
    use crate::{bn254::{fp254impl::Fp254Impl, fq::Fq, pairing::Pairing}, execute_script_without_stack_limit, signatures::winternitz_ell::{checksig_verify_compressed, sign_digits_compressed}, treepp::*};
    use std::{collections::HashMap, iter::zip};

    fn test_script_with_signatures(script: Script, sks: Vec<Vec<u8>>, digits: Vec<[u8; N0 as usize]>) -> (bool, usize, usize) {
        let script_test = script! {
            for (sk, d) in zip(sks.clone(), digits) {
                { sign_digits_compressed(sk, d) }
            }
            for sk in sks.iter().rev() {
                { checksig_verify_compressed(sk.clone()) }
            }
            for _ in 0..sks.len() {
                { Fq::fromaltstack() }
            }
            { script }
        };
        let size = script_test.len();
        let start = start_timer!(|| "execute_script");
        let exec_result = execute_script_without_stack_limit(script_test);
        let max_stack_items = exec_result.stats.max_nb_stack_items;
        end_timer!(start);
        (exec_result.success, size, max_stack_items)
    }

    #[test]
    fn test_winternitz_ell() {
        let (ell_scripts, ell_calculate_inputs) = Pairing::ell_verify();
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a = ark_bn254::Fq12::rand(&mut prng);
        let c0 = ark_bn254::Fq2::rand(&mut prng);
        let c1 = ark_bn254::Fq2::rand(&mut prng);
        let c2 = ark_bn254::Fq2::rand(&mut prng);
        let p = ark_bn254::G1Affine::rand(&mut prng);

        let b = {
            let mut c0new = c0;
            c0new.mul_assign_by_fp(&p.y);

            let mut c1new = c1;
            c1new.mul_assign_by_fp(&p.x);

            let mut b = a;
            b.mul_by_034(&c0new, &c1new, &c2);
            b
        };

        let (ell_script_inputs, ell_intermediate) = ell_calculate_inputs(a, &(c0, c1, c2), p, b);

        let mut ell_labels = HashMap::new();
        let mut sks = HashMap::new();
        let mut index = 0;
        for element in ell_intermediate {
            ell_labels.insert(element.clone(), index);
            for _ in 0..element.size() {
                sks.insert(index.clone(), rand::thread_rng().gen::<[u8; 32]>().to_vec());
                index += 1;
            }
        }

        for (script, inputs) in zip(ell_scripts, ell_script_inputs) {
            let mut script_sks = Vec::new();
            let mut script_digits = Vec::new();
            for inp in inputs.clone() {
                script_digits.extend(inp.to_digits());
                let u = ell_labels.get(&inp).unwrap().clone();
                for i in 0..inp.size() {
                    script_sks.push(sks[&(u + i)].clone());
                }
            }
            let (success, size, max_stack_items) = test_script_with_signatures(script, script_sks, script_digits);
            assert!(success);
            println!("size: {:?}, max stack items: {:?}", size, max_stack_items);
        }
    }
}
