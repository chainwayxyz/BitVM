//Outlines of functions that probably don't fit for the current usage, note that are probably very inefficient
use crate::treepp::*;
use bitcoin_script_stack::stack::StackTracker;
use crate::hash::blake3_u4_compact::blake3_u4_compact;
use crate::bigint::U256;

pub fn hash_n_bytes(n : u32) -> Script {
    let mut stack = StackTracker::new();
    blake3_u4_compact(&mut stack, n, true, true);
    stack.get_script()
}

// Last elements are removed (i.e. set to zero) to transform 32 bytes blake3 to 20 bytes, but this might not be safe SO ALL CAPS 
pub fn remove_bits_to_transform_hash_from_32_bytes_to_20() -> Script {
    script! {
        for _ in 0..12 {
            OP_2DROP
        }
    }
}

pub fn push_blake3_32_hash(hash: [u8; 32]) -> Script {
    script! {
        for b in hash {
            { (b >> 4) & 15 }
            { b & 15 }
        }
    }  
}

fn add_padding_bytes_for_blake3(v: &mut Vec<u8>) {
    while v.len() % 64 != 0 {
        v.push(0)
    }
}

/// Pushes in the required format for blake3 
fn push_byte_vector_and_transform_on_stack(mut v: Vec<u8>) -> Script {
    add_padding_bytes_for_blake3(&mut v);
    // Reverse each 4-byte chunk in place (IDK why???)
    v.chunks_mut(4).for_each(|chunk| chunk.reverse());
    script! {
        for chunk in v.chunks(64).rev(){
            for (i,byte) in chunk.iter().enumerate(){
                {*byte}
                if i == 31 || i == 63 {
                    {U256::transform_limbsize(8,29)}
                }
            }
        }
    } 
}

// Thıs is for optimization after further talk 
/* 
fn push_byte_array_transformed(mut v: Vec<u8>) -> Script {
    add_padding_bytes_for_blake3(&mut v);
    script ! { }
}
*/

pub struct WinternitzCircuitOutput {
    pub winternitz_pubkeys_digest: [u8; 20],     
    pub correct_watchtowers: Vec<bool>, 
    pub payout_tx_blockhash: [u8; 32],
    pub last_blockhash: [u8; 32],
    pub deposit_txid: [u8; 32],
    pub operator_id: Vec<u8>,
}

impl WinternitzCircuitOutput {
    fn transform_to_byte_array(&self) -> Vec<u8> {
        let mut res = Vec::new();
        res.extend_from_slice(&self.winternitz_pubkeys_digest);
        res.extend_from_slice(&self.payout_tx_blockhash);
        res.extend_from_slice(&self.last_blockhash);
        res.extend_from_slice(&self.deposit_txid);
        let mut bool_bytes = Vec::new();
        let mut bit_buffer = 0u8;
        let mut bit_count = 0;        
        for &bit in &self.correct_watchtowers {
            if bit { bit_buffer |= 1 << bit_count; }
            bit_count += 1;
            if bit_count == 8 {
                bool_bytes.push(bit_buffer);
                bit_buffer = 0;
                bit_count = 0;
            }
        }
        if bit_count > 0 { 
            bool_bytes.push(bit_buffer);
        }
        res.extend_from_slice(&bool_bytes); // IS THIS FINE? I PUSH PADDING BYTES FOR %8 != 0 WATCTOWER COUNTS
        res.extend_from_slice(&self.operator_id);        
        res
    }
    fn get_journal_hash_32_bytes(&self) -> [u8; 32] {
        blake3::hash(&self.transform_to_byte_array()).as_bytes().clone()
    }
    fn get_journal_hash_with_constant_32_bytes(&self, constant: [u8; 32]) -> [u8; 32] {
        let mut h = self.get_journal_hash_32_bytes().to_vec();
        for i in 20..32 {
            h[i] = 0; //to 20 bytes
        }
        h.chunks_mut(4).for_each(|chunk| chunk.reverse()); // IDK why do we need this still???
        h.extend(constant);
        blake3::hash(&h).as_bytes().clone()
    }
}

// Expects in the stack [wco.byte_array(), constants] (last one on top) (in the hashable form)
pub fn hash_journal_and_constant(byte_array_len: u32) -> Script {
    script! { 
        for _ in 0..9 { OP_TOALTSTACK } //send constant to altstack (blake3 requries empty stack)
        { hash_n_bytes(byte_array_len) }
        { remove_bits_to_transform_hash_from_32_bytes_to_20() } 
        for _ in 0..24 { 0 } // push the bits back for padding
        { U256::transform_limbsize(4, 29) }
        for _ in 0..9 { OP_FROMALTSTACK }
        { hash_n_bytes(64) }
        { remove_bits_to_transform_hash_from_32_bytes_to_20() }
     }
}

fn verify_hash_journal_and_constant(constant: [u8; 32], wco: WinternitzCircuitOutput) -> Script {
    script! {
        { hash_journal_and_constant(wco.transform_to_byte_array().len() as u32) }
        { push_blake3_32_hash(wco.get_journal_hash_with_constant_32_bytes(constant)) }
        { remove_bits_to_transform_hash_from_32_bytes_to_20() }
        for i in (2..41).rev() {
            { i }
            OP_ROLL
            OP_EQUALVERIFY
        }
        OP_EQUAL
    }
}

#[cfg(test)]
mod test {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use super::*;

    pub fn generate_random_wco(seed: u64) -> WinternitzCircuitOutput {
        let mut prng = ChaCha20Rng::seed_from_u64(seed);
        let watchtower_count = prng.gen_range(1..100);
        let operator_count = prng.gen_range(1..100);
        WinternitzCircuitOutput {
            winternitz_pubkeys_digest: prng.gen(),
            correct_watchtowers: (0..watchtower_count).map(|_| prng.gen()).collect(),
            payout_tx_blockhash: prng.gen(),
            last_blockhash: prng.gen(),
            deposit_txid: prng.gen(),
            operator_id: (0..operator_count).map(|_| prng.gen()).collect()
        }
    }

    #[test]
    fn test_journal_hash() {
        for seed in 0..100 {
            let wco = generate_random_wco(seed);
            let byte_array = wco.transform_to_byte_array();
            let s = script! {
                { push_byte_vector_and_transform_on_stack(byte_array.clone()) }
                { hash_n_bytes(byte_array.len() as u32) }
                { remove_bits_to_transform_hash_from_32_bytes_to_20() }
                { push_blake3_32_hash(wco.get_journal_hash_32_bytes()) }
                { remove_bits_to_transform_hash_from_32_bytes_to_20() }
                for i in (2..41).rev() {
                    { i }
                    OP_ROLL
                    OP_EQUALVERIFY
                }
                OP_EQUAL
            };
            run(s);
        }
    }
 
    #[test]
    fn test_verifying() {
        for seed in 0..100 {
            let mut prng = ChaCha20Rng::seed_from_u64(seed);    
            let wco = generate_random_wco(seed);
            let wco_byte_array = wco.transform_to_byte_array();
            //print!("len:{}\n", wco_byte_array.len());
            let constant : [u8; 32] = prng.gen();
            let s = script! {
                { push_byte_vector_and_transform_on_stack(wco_byte_array.clone()) }
                { push_byte_vector_and_transform_on_stack(constant.to_vec()) } for _  in 0..9 { OP_DROP } // drop paddings
                { verify_hash_journal_and_constant(constant, wco) }
            };
            run(s);
        }
    }
}