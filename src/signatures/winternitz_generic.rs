//
// Winternitz One-time Signatures
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

const fn log_base_ceil(mut n: u32, base: u32) -> usize {
    let mut res: usize = 0;
    let mut cur: u64 = 1;
    while cur < (n as u64) {
        cur *= base as u64;
        res += 1;
    }
    return res;
}

use crate::treepp::*;
use bitcoin::hashes::{hash160, Hash};
use hex::decode as hex_decode;

const BLAKE3_SIZE: u32 = 20;

/// Bits per digit
const LOG_D: u32 = 8;
/// Digits are base d+1
pub const D: u8 = (((1 as u32) << LOG_D) - 1) as u8;
/// Number of digits of the message
const N0: u32 = BLAKE3_SIZE * 8 / LOG_D;

/// Number of digits of the checksum.  N1 = ⌈log_{D+1}(D*N0)⌉ + 1
const N1: usize = log_base_ceil(D as u32 * N0, (D as u32) + 1) + 1;
/// Total number of digits to be signed
const N: u32 = N0 + N1 as u32;
/// The public key type
pub type PublicKey = [[u8; 20]; N as usize];

//
// Helper functions
//

/// Generate a public key for the i-th digit of the message
pub fn public_key_for_digit(secret_key: &str, digit_index: u32) -> [u8; 20] {
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

    *hash.as_byte_array()
}

/// Generate a public key from a secret key 
pub fn generate_public_key(secret_key: &str) -> PublicKey {
    let mut public_key_array = [[0u8; 20]; N as usize];
    for i in 0..N {
        public_key_array[i as usize] = public_key_for_digit(secret_key, i);
    }
    public_key_array
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
        { message_digit }
    }
}

/// Compute the checksum of the message's digits.
/// Further infos in chapter "A domination free function for Winternitz signatures"
pub fn checksum(digits: [u8; N0 as usize]) -> u32 {
    let mut sum = 0;
    for digit in digits {
        sum += digit as u32;
    }
    D  as u32 * N0 - sum
}

/// Convert a number to digits
pub fn to_digits<const DIGIT_COUNT: usize>(mut number: u32) -> [u8; DIGIT_COUNT] {
    let mut digits: [u8; DIGIT_COUNT] = [0; DIGIT_COUNT];
    for i in 0..DIGIT_COUNT {
        let digit = number % (D as u32 + 1);
        number = (number - digit) / (D as u32 + 1);
        digits[i] = digit as u8;
    }
    digits
}



/// Compute the signature for a given message
pub fn sign_digits(secret_key: &str, message_digits: [u8; N0 as usize]) -> Script {
    // const message_digits = to_digits(message, n0)
    let mut checksum_digits = to_digits::<N1>(checksum(message_digits)).to_vec();
    checksum_digits.append(&mut message_digits.to_vec());

    script! {
        for i in 0..N {
            { digit_signature(secret_key, i, checksum_digits[ (N-1-i) as usize]) }
        }
    }
}

pub fn sign(secret_key: &str, message_bytes: &[u8]) -> Script {
    // Convert message to digits
    let mut message_digits = [0u8; N0 as usize];
    for (digits, byte) in message_digits.chunks_mut(2).zip(message_bytes) {
        digits[0] = byte & 0b00001111;
        digits[1] = byte >> 4;
    }

    sign_digits(secret_key, message_digits)
}

pub fn checksig_verify(public_key: &PublicKey) -> Script {
    // for digit_index in 0..N {
    //     print!("{}: {:?}\n", digit_index, (public_key[N as usize - 1 - digit_index as usize]).to_vec());
    // }
    script! {
        //
        // Verify the hash chain for each digit
        //

        // Repeat this for every of the n many digits
        for digit_index in 0..N {
            // Verify that the digit is in the range [0, d]
            // See https://github.com/BitVM/BitVM/issues/35
            { D }
            OP_MIN

            // Push two copies of the digit onto the altstack
            OP_DUP
            OP_TOALTSTACK
            OP_TOALTSTACK

            // Hash the input hash d times and put every result on the stack
            for _ in 0..D {
                OP_DUP OP_HASH160
            }

            // Verify the signature for this digit
            OP_FROMALTSTACK
            OP_PICK
            { (public_key[N as usize - 1 - digit_index as usize]).to_vec() }
            OP_EQUALVERIFY

            // Drop the d+1 stack items
            for _ in 0..(D as u32+1)/2 {
                OP_2DROP
            }
        }

        //
        // Verify the Checksum
        //

        // 1. Compute the checksum of the message's digits
        OP_FROMALTSTACK OP_DUP OP_NEGATE
        for _ in 1..N0 {
            OP_FROMALTSTACK OP_TUCK OP_SUB
        }
        { D as u32 * N0 }
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


        // Convert the message's digits to bytes
        for i in 0..N0 / 2 {
            OP_SWAP
            for _ in 0..LOG_D {
                OP_DUP OP_ADD
            }
            OP_ADD
            // Push all bytes to the altstack, except for the last byte
            if i != (N0/2) - 1 {
                OP_TOALTSTACK
            }
        }
        // Read the bytes from the altstack
        for _ in 0..N0 / 2 - 1{
            OP_FROMALTSTACK
        }

    }
}


#[cfg(test)]
mod test {
    use bitcoin::opcodes::all::OP_EQUALVERIFY;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use super::*;

    // The secret key
    const MY_SECKEY: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";


    #[test]
    fn test_winternitz() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        // The message to sign
        for _ in 0..100 {
            let mut message = [0u8; N0 as usize];
            for i in 0..N0 {
                message[i as usize] = prng.gen_range(0 as u8..=D);
            }


            let public_key = generate_public_key(MY_SECKEY);

            let script = script! {
                { sign_digits(MY_SECKEY, message) }
                { checksig_verify(&public_key) }
            };

            println!(
                "Winternitz signature size:\n \t{:?} bytes / {:?} bits \n\t{:?} bytes / bit",
                script.len(),
                N0 * 4,
                script.len() as f64 / (N0 * 4) as f64
            );

            print!("{:x?}\n", message);
            print!("{:?}\n", message);
            execute_script(script! {
                { sign_digits(MY_SECKEY, message) }
                
                { checksig_verify(&public_key) }
                /* 
                for i in 0..N0/2 {
                    {(D as u32 + 1) * message[(2 * i + 1) as usize] as u32 + message[(2 * i) as usize] as u32}
                    OP_EQUAL
                    if i != N0/2-1 {
                        OP_VERIFY
                    } 
                }
                */
            });
        }
    }
    // TODO: test the error cases: negative digits, digits > D, ...
}
