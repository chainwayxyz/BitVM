use final_circuit::FinalCircuitInput;
use risc0_zkvm::guest::env;
use utils::u8_32_to_u32_8;
use zkvm::ZkvmGuest;

pub mod final_circuit;
pub mod merkle_tree;
pub mod spv;
pub mod transaction;
pub mod utils;
pub mod zkvm;
pub use risc0_zkvm;

/// The method ID for the header chain circuit.
const HEADER_CHAIN_GUEST_ID: [u8; 32] = {
    match option_env!("BITCOIN_NETWORK") {
        Some(network) if matches!(network.as_bytes(), b"mainnet") => {
            hex_literal::hex!("a764839f5d78b6027146a178338b86c45600828bdc05993c457dd689021b4ebf")
        }
        Some(network) if matches!(network.as_bytes(), b"testnet4") => {
            hex_literal::hex!("3f0e327745831156507c290d7e71ea24829a4c1af0020bac2ed4df9ab1d314f0")
        }
        Some(network) if matches!(network.as_bytes(), b"signet") => {
            hex_literal::hex!("c20d2289319ef9bd0ccb210bda359e3cbd4cab4e08747f9f87b3639c898aac0c")
        }
        Some(network) if matches!(network.as_bytes(), b"regtest") => {
            hex_literal::hex!("bc2b6560aeb587f7dca25c067d72badaadade5ec360b4006bcc76e99c4c6838f")
        }
        None => {
            hex_literal::hex!("a764839f5d78b6027146a178338b86c45600828bdc05993c457dd689021b4ebf")
        }
        _ => panic!("Invalid network type"),
    }
};

/// The final circuit that verifies the output of the header chain circuit.
pub fn final_circuit(guest: &impl ZkvmGuest) {
    let start = env::cycle_count();
    let input: FinalCircuitInput = guest.read_from_host::<FinalCircuitInput>();
    let header_chain_guest_id = u8_32_to_u32_8(HEADER_CHAIN_GUEST_ID);
    guest.verify(header_chain_guest_id, &input.block_header_circuit_output);
    input.spv.verify(
        input
            .block_header_circuit_output
            .chain_state
            .block_hashes_mmr,
    );
    let mut hasher = blake3::Hasher::new();

    hasher.update(&input.spv.transaction.txid());
    hasher.update(
        &input
            .block_header_circuit_output
            .chain_state
            .best_block_hash,
    );
    hasher.update(&input.block_header_circuit_output.chain_state.total_work);
    let final_output = hasher.finalize();
    guest.commit(final_output.as_bytes());
    let end = env::cycle_count();
    println!("Final circuit took {:?} cycles", end - start);
}
