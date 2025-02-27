use crate::treepp::*;
use crate::signatures::wots_api::{wots160, wots256};

pub fn create_additional_disprove_scripts(
    combined_method_id_constant: [u8; 32], 
    deposit_constant: [u8; 32], 
    g16_public_input_pk: wots256::PublicKey, 
    payout_tx_blockhash_pk: wots160::PublicKey, 
    latest_blockhash_pk: wots160::PublicKey, 
    challenge_sending_watchtowers_pk: wots160::PublicKey, 
    operator_challenge_ack_hashes: &[[u8; 20]]
) -> (Script, Script) {
    todo!()
}

pub fn validate_assertions_for_additional_scripts(
    additional_scripts: (Script, Script), 
    combined_method_id_constant: [u8; 32], 
    deposit_constant: [u8; 32], 
    // g16_public_input_assert, 
    // payout_tx_blockhash_assert, 
    // latest_blockhash_assert, 
    // challenge_sending_watchtowers_assert, 
    operator_challenge_ack_preimages: &[Option<[u8; 20]>]
) {
    todo!()
}
