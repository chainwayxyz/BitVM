use final_circuit::FinalCircuitInput;
use risc0_zkvm::guest::env;
use zkvm::ZkvmGuest;

pub mod final_circuit;
pub mod merkle_tree;
pub mod spv;
pub mod transaction;
pub mod utils;
pub mod zkvm;
pub use risc0_zkvm;

/// The method ID for the header chain circuit.
const HEADER_CHAIN_GUEST_ID: [u32; 8] = {
    match option_env!("BITCOIN_NETWORK") {
        Some(network) if matches!(network.as_bytes(), b"mainnet") => {
            [2676188327, 45512797, 2023835249, 3297151795, 2340552790, 1016661468, 2312535365, 3209566978]
        }
        Some(network) if matches!(network.as_bytes(), b"testnet4") => {
            [1999769151, 1443988293, 220822608, 619344254, 441227906, 2886402800, 2598360110, 4027896753]
        }
        Some(network) if matches!(network.as_bytes(), b"signet") => {
            [2300710338, 3187252785, 186764044, 1017001434, 1319849149, 2675930120, 2623779719, 212634249]
        }
        Some(network) if matches!(network.as_bytes(), b"regtest") => {
            [1617243068, 4152866222, 106734300, 3669652093, 3974475181, 104860470, 2574174140, 2407777988]
        }
        None => {
            [2676188327, 45512797, 2023835249, 3297151795, 2340552790, 1016661468, 2312535365, 3209566978]
        }
        _ => panic!("Invalid network type"),
    }
};

/// The final circuit that verifies the output of the header chain circuit.
pub fn final_circuit(guest: &impl ZkvmGuest) {
    let start = env::cycle_count();
    let input: FinalCircuitInput = guest.read_from_host::<FinalCircuitInput>();
    guest.verify(HEADER_CHAIN_GUEST_ID, &input.block_header_circuit_output);
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
