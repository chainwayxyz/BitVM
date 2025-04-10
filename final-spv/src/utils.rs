use sha2::{Digest, Sha256};

pub fn calculate_double_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(input);
    let result = hasher.finalize_reset();
    hasher.update(result);
    hasher.finalize().into()
}

pub fn calculate_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(input);
    hasher.finalize().into()
}

/// Utility function to hash two nodes together
pub fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

pub fn u8_32_to_u32_8(bytes: [u8; 32]) -> [u32; 8] {
    let mut result = [0u32; 8];
    for i in 0..8 {
        result[i] = u32::from_le_bytes(bytes[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    result
}
