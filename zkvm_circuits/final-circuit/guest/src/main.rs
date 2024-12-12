#![no_main]
circuits::risc0_zkvm::guest::entry!(main);
fn main() {
    let zkvm_guest = circuits::Risc0Guest::new();
    circuits::header_chain::final_circuit(&zkvm_guest);
}