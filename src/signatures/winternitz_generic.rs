use crate::treepp::*;
use bitcoin::{hashes::{hash160, Hash}, opcodes::all::{OP_EQUALVERIFY, OP_FROMALTSTACK, OP_TOALTSTACK}};
use hex::decode as hex_decode;
use regex::bytes;

const fn log_base_ceil(n: u32, base: u32) -> u32 { //use the fact that base = 2^N and use ilog() to optimize this later 
    let mut res: u32 = 0;
    let mut cur: u64 = 1;
    while cur < (n as u64) {
        cur *= base as u64;
        res += 1;
    }
    return res;
}

/// Convert a number to digits
pub fn to_digits(mut number: u32, base: u32, digit_count: i32) -> Vec<u32> {
    let mut digits = Vec::new();
    if digit_count == -1 {
        while number > 0 {
            let digit = number % base;
            number = (number - digit) / base;
            digits.push(digit);
        }
    } else {
        digits.reserve(digit_count as usize);
        for i in 0..digit_count {
            let digit = number % base;
            number = (number - digit) / base;
            digits.push(digit);
        }
    }
    digits
}

pub fn bytes_to_u32s(len:u32, bits_per_item:u32, bytes: &Vec<u8>) -> Vec<u32> {
    assert!(bytes.len() as u32 * 8 <= len * bits_per_item); //I'm not sure if the asserts are fine so I need to ask this to someone
    let mut res = vec![0u32; len as usize];
    let mut cur_index: u32 = 0;
    let mut cur_bit: u32 = 0;
    for byte in bytes {
        let mut x: u8 = *byte;
        for i in 0..8 {
            if cur_bit == bits_per_item {
                cur_bit = 0;
                cur_index += 1;
            }
            res[cur_index as usize] |= ((x & 1) as u32) << cur_bit;
            x >>= 1;
            cur_bit += 1;
        }
    }
    res
}

/* 

/// Bits per digit
const LOG_D: u32 = 4;
/// Digits are base d+1
pub const D: u32 = (1 << LOG_D) - 1;
/// Number of digits of the message
const N0: u32 = 40;
/// Number of digits of the checksum.  N1 = ⌈log_{D+1}(D*N0)⌉ + 1
const N1: usize = 4;
/// Total number of digits to be signed
const N: u32 = N0 + N1 as u32;
/// The public key type
pub type PublicKey = [[u8; 20]; N as usize];

*/
//
// Helper functions
//

pub type KeyDigit = [u8; 20];
pub type Key = Vec<KeyDigit>;

pub struct Parameters {
    n0: u32, 
    log_d: u32,
    n1: u32,
    d: u32,  
    n: u32
}
impl Parameters {
    pub fn new(n0: u32, log_d: u32) -> Self {
        let d: u32 = (1 << log_d) - 1;
        let n1: u32 = log_base_ceil(d * n0, d + 1) + 1;
        let n: u32= n0 + n1;
        Parameters{n0, log_d, n1, d, n}
    }
    pub fn byte_message_length(&self) -> u32 {
        return (self.n0 * self.log_d + 7) / 8;
    }
}

/// Generate a public key for the i-th digit of the message
pub fn public_key_for_digit(ps: &Parameters, secret_key: &str, digit_index: u32) -> KeyDigit {
    // Convert secret_key from hex string to bytes
    let mut secret_i = match hex_decode(secret_key) {
        Ok(bytes) => bytes,
        Err(_) => panic!("Invalid hex string"),
    };
    secret_i.push(digit_index as u8);
    let mut hash = hash160::Hash::hash(&secret_i);
    for _ in 0..ps.d {
        hash = hash160::Hash::hash(&hash[..]);
    }
    *hash.as_byte_array()
}

/// Generate a public key from a secret key 
pub fn generate_public_key(ps: &Parameters, secret_key: &str) -> Key {
    let mut public_key = Key::new();
    public_key.reserve(ps.n as usize);
    for i in 0..ps.n {
        public_key.push(public_key_for_digit(ps, secret_key, i));
    }
    public_key
}

/// Compute the signature for the i-th digit of the message
pub fn digit_signature(secret_key: &str, digit_index: u32, message_digit: u32) -> Script {
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
pub fn checksum(ps: &Parameters, digits: Vec<u32>) -> u32 {
    let mut sum = 0;
    for digit in digits {
        sum += digit as u32;
    }
    ps.d * ps.n0 - sum
}

/// Compute the signature for a given message
pub fn sign_digits(ps: &Parameters, secret_key: &str, mut message_digits: Vec<u32>) -> Script {
    // const message_digits = to_digits(message, n0)
    let mut checksum_digits = to_digits(checksum(ps, message_digits.clone()), ps.d+1, ps.n1 as i32);
    checksum_digits.append(&mut message_digits);
    checksum_digits.reverse();
    script! {
        for i in 0..ps.n {
            { digit_signature(secret_key, i, checksum_digits[i as usize]) }
        }
    }
}

pub fn sign(ps: &Parameters, secret_key: &str, message_bytes: Vec<u8>) -> Script {
    sign_digits(ps, secret_key, bytes_to_u32s(ps.n0, ps.log_d, &message_bytes))
}

pub fn checksig_verify(ps: &Parameters, public_key: &Key) -> Script {
    // for digit_index in 0..N {
    //     print!("{}: {:?}\n", digit_index, (public_key[N as usize - 1 - digit_index as usize]).to_vec());
    // }
    assert!(ps.log_d == 8);
    script! {
        //
        // Verify the hash chain for each digit
        //

        // Repeat this for every of the n many digits
        for digit_index in 0..ps.n {
            // Verify that the digit is in the range [0, d]
            // See https://github.com/BitVM/BitVM/issues/35
            { ps.d }
            OP_MIN

            // Push two copies of the digit onto the altstack
            OP_DUP
            OP_TOALTSTACK
            OP_TOALTSTACK

            // Hash the input hash d times and put every result on the stack
            for _ in 0..ps.d {
                OP_DUP OP_HASH160
            }

            // Verify the signature for this digit
            OP_FROMALTSTACK
            OP_PICK
            { (public_key[ps.n as usize - 1 - digit_index as usize]).to_vec() }
            OP_EQUALVERIFY

            // Drop the d+1 stack items
            for _ in 0..(ps.d as u32+1)/2 {
                OP_2DROP
            }
        }

        //
        // Verify the Checksum
        //

        // 1. Compute the checksum of the message's digits
        OP_FROMALTSTACK OP_DUP OP_NEGATE
        for _ in 1..ps.n0 {
            OP_FROMALTSTACK OP_TUCK OP_SUB
        }
        { ps.d as u32 * ps.n0 }
        OP_ADD


        // 2. Sum up the signed checksum's digits
        OP_FROMALTSTACK
        for _ in 0..ps.n1 - 1 {
            for _ in 0..ps.log_d {
                OP_DUP OP_ADD
            }
            OP_FROMALTSTACK
            OP_ADD
        }

        // 3. Ensure both checksums are equal
        OP_EQUALVERIFY
        //this part is ommited due to log_d = 8 condition, I will edit this part later probably to be fit for values in the range [4, 8]
        /* 
        // Convert the message's digits to bytes
        for i in 0..ps.n0 / 2 {
            OP_SWAP
            for _ in 0..ps.log_d {
                OP_DUP OP_ADD
            }
            OP_ADD
            // Push all bytes to the altstack, except for the last byte
            if i != (ps.n0/2) - 1 {
                OP_TOALTSTACK
            }
        }
        // Read the bytes from the altstack
        for _ in 0..ps.n0 / 2 - 1{
            OP_FROMALTSTACK
        }
        */
    }
}

//https://github.com/chainwayxyz/BitVM/issues/10
//{sig(X)}
pub fn winternitz_sig_check(ps: &Parameters, public_key: &Key, /* XOnlyPublicKey */) -> Script {
    script! {
       { checksig_verify(ps, public_key) }
    }
}
//{sig_0(A), sig_1(B)}
pub fn double_winternitz_sig_check(ps: &Parameters, public_keys: &[Key; 2], /* XOnlyPublicKey */) -> Script {
    let len = ps.byte_message_length(); //assuming we're turning messages to bytes when we're using them 
    script! {
        { checksig_verify(ps, &public_keys[1]) }
        for _ in 0..len {
            OP_TOALTSTACK
        }
        { checksig_verify(ps, &public_keys[0]) }
        //{A_0, A_1, A_2, A_3...} {B_0, B_1, B_2, B_3...}
        for i in 0..len {
            OP_FROMALTSTACK
            if i == len - 1 {
                OP_EQUAL
            } else {
                {len - i} OP_ROLL
                OP_EQUALVERIFY
            }
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
    #[test]
    fn test_double_winternitz_sig_check_equal() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let ps = Parameters::new(37, 8);
        let message_byte_size = ps.n0 * ps.log_d / 8;
        let mut message = vec![0u8; message_byte_size as usize];
        for i in 0..message_byte_size {
            message[i as usize] = prng.gen_range(0u8..=255);
        }
        const SECKEY_0: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";
        const SECKEY_1: &str = "a138982ce17ac813d505b5b40b665d404e9528e7";
        let public_key_0 = generate_public_key(&ps, SECKEY_0);
        let public_key_1 = generate_public_key(&ps, SECKEY_1);
        execute_script(script!{
            { sign(&ps, SECKEY_0, message.clone()) }
            { sign(&ps, SECKEY_1, message.clone()) }
            { double_winternitz_sig_check(&ps, &[public_key_0, public_key_1]) }
        });
    }   
    #[test]
    fn test_double_winternitz_sig_check_notequal() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let ps = Parameters::new(37, 8);
        let message_byte_size = ps.n0 * ps.log_d / 8;
        let mut message0 = vec![0u8; message_byte_size as usize];
        let mut message1 = vec![0u8; message_byte_size as usize];
        for i in 0..message_byte_size {
            message0[i as usize] = prng.gen_range(0u8..=255);
            message1[i as usize] = prng.gen_range(0u8..=255);
        }
        const SECKEY_0: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";
        const SECKEY_1: &str = "a138982ce17ac813d505b5b40b665d404e9528e7";
        let public_key_0 = generate_public_key(&ps, SECKEY_0);
        let public_key_1 = generate_public_key(&ps, SECKEY_1);
        execute_script(script!{
            { sign(&ps, SECKEY_0, message0.clone()) }
            { sign(&ps, SECKEY_1, message1.clone()) }
            { double_winternitz_sig_check(&ps, &[public_key_0, public_key_1]) }
        });
    }   
    #[test]
    fn test_winternitz() {
        const MY_SECKEY: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let ps = Parameters::new(37, 8);
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        // The message to sign
        for _ in 0..100 {
            let message_byte_size = ps.n0 * ps.log_d / 8;
            let mut message = vec![0u8; message_byte_size as usize];
            for i in 0..message_byte_size {
                message[i as usize] = prng.gen_range(0u8..=255);
            }
            let message_digits = bytes_to_u32s(ps.n0, ps.log_d, &message);
            let public_key = generate_public_key(&ps, MY_SECKEY);
            let script = script! {
                { sign_digits(&ps, MY_SECKEY, message_digits.clone()) }
                { checksig_verify(&ps, &public_key) }
            };

            println!(
                "Winternitz signature size:\n \t{:?} bytes / {:?} bits \n\t{:?} bytes / bit",
                script.len(),
                ps.n0 * 4,
                script.len() as f64 / (ps.n0 * 4) as f64
            );

            print!("{:x?}\n", message);
            print!("{:?}\n", message);
            execute_script(script! {
                { sign_digits(&ps, MY_SECKEY, message_digits.clone()) }
                { checksig_verify(&ps, &public_key) }
                for i in 0..message_byte_size {
                    {message[i as usize]}
                    if i == message_byte_size - 1 {
                        OP_EQUAL
                    } else {
                        OP_EQUALVERIFY
                    }
                }
            });
        }
    }
    // TODO: test the error cases: negative digits, digits > D, ...
}
