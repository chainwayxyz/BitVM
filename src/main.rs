use std::io::BufReader;

use bitvm::{execute_script, execute_script_without_stack_limit, fflonk::fflonk_verify_script::{fflonk_verify, fflonk_verify_all, push_proof, push_public, push_vk, Proof, PublicInputs, VerificationKey}};

pub fn main() {
    let proof: Proof = serde_json::from_reader(BufReader::new(std::fs::File::open("src/fflonk/circom_ref/proof.json").unwrap())).unwrap();
    let public: PublicInputs = serde_json::from_reader(BufReader::new(std::fs::File::open("src/fflonk/circom_ref/public.json").unwrap())).unwrap();
    let vk: VerificationKey = serde_json::from_reader(BufReader::new(std::fs::File::open("src/fflonk/circom_ref/verification_key.json").unwrap())).unwrap();
        
    let script = fflonk_verify_all(public, vk, proof);
    println!("script = {} bytes", script.len());
    let exec_result = execute_script_without_stack_limit(script);
    println!("{}", exec_result);
    assert!(exec_result.success);
    println!("hello world");
}