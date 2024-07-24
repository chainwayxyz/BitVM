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
    use hex::decode as hex_decode;
    use crate::treepp::*;

    #[test]
    fn test_winternitz() {
        println!("LOGD: {:?}, D: {:?}", LOG_D, D);
        println!("N0: {:?}, N1: {:?}, N = N0 + N1: {:?}", N0, N1, N);

        let sk_bytes = hex_decode("b138982ce17ac813d505b5b40b665d404e9528e7").unwrap();

        let message_digits: [u8; N0 as usize] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 7, 7, 7, 7, 7,
            1, 2, 3, 4, 
        ];

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

            0x21 OP_EQUALVERIFY
            0x43 OP_EQUALVERIFY
            0x65 OP_EQUALVERIFY
            0x87 OP_EQUALVERIFY
            0xA9 OP_EQUALVERIFY
            0xCB OP_EQUALVERIFY
            0xED OP_EQUALVERIFY
            0x7F OP_EQUALVERIFY
            0x77 OP_EQUALVERIFY
            0x77 OP_EQUALVERIFY

            0x21 OP_EQUALVERIFY
            0x43 OP_EQUALVERIFY
            0x65 OP_EQUALVERIFY
            0x87 OP_EQUALVERIFY
            0xA9 OP_EQUALVERIFY
            0xCB OP_EQUALVERIFY
            0xED OP_EQUALVERIFY
            0x7F OP_EQUALVERIFY
            0x77 OP_EQUALVERIFY
            0x77 OP_EQUALVERIFY

            0x21 OP_EQUALVERIFY
            0x43 OP_EQUALVERIFY
            0x65 OP_EQUALVERIFY
            0x87 OP_EQUALVERIFY
            0xA9 OP_EQUALVERIFY
            0xCB OP_EQUALVERIFY
            0xED OP_EQUALVERIFY
            0x7F OP_EQUALVERIFY
            0x77 OP_EQUALVERIFY
            0x77 OP_EQUALVERIFY

            0x21 OP_EQUALVERIFY
            0x43 OP_EQUAL
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
