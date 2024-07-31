use crate::execute_script_without_stack_limit;
use crate::groth16::utils::Groth16Data;
use crate::groth16::verifier::Verifier;
use ark_bn254::Bn254;
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{end_timer, start_timer, test_rng, UniformRand};
use rand::{RngCore, SeedableRng};

use crate::treepp::{script, Script};
use std::iter::zip;

fn test_script_with_input_signatures(script: Script, input_signatures: Vec<Script>) -> (bool, usize, usize) {
    let script_test = script! {
        for input_signature_script in input_signatures {
            { input_signature_script }
        }
        { script }
    };
    let size = script_test.len();
    let start = start_timer!(|| "execute_script");
    let exec_result = execute_script_without_stack_limit(script_test);
    let max_stack_items = exec_result.stats.max_nb_stack_items;
    end_timer!(start);
    (exec_result.success, size, max_stack_items)
}

#[test]
fn test_groth16_scripts_and_inputs() {
    let groth16_data = Groth16Data::new("src/groth16/data/proof.json", "src/groth16/data/public.json", "src/groth16/data/vk.json");

    let (scripts, script_input_signatures) = Verifier::verify(&groth16_data.vk, &groth16_data.proof, &groth16_data.public[0]);
    let n = scripts.len();

    assert_eq!(scripts.len(), script_input_signatures.len());

    let mut script_sizes = Vec::new();
    let mut max_stack_sizes = Vec::new();

    for (i, (script, input_signature)) in zip(scripts, script_input_signatures).enumerate() {
        let (result, script_size, max_stack_size) = test_script_with_input_signatures(script.clone(), input_signature);
        script_sizes.push(script_size);
        max_stack_sizes.push(max_stack_size);
        println!("script[{:?}]: size: {:?} bytes, max stack size: {:?} items", i, script_size, max_stack_size);
        assert!(result);
    }

    println!();
    println!("number of pieces: {:?}", n);
    println!("max (script size): {:?} bytes", script_sizes.iter().max().unwrap());
    println!("max (max stack size): {:?} items", max_stack_sizes.iter().max().unwrap());
}

#[derive(Copy)]
struct DummyCircuit<F: PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: PrimeField> Clone for DummyCircuit<F> {
    fn clone(&self) -> Self {
        DummyCircuit {
            a: self.a,
            b: self.b,
            num_variables: self.num_variables,
            num_constraints: self.num_constraints,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            Ok(a * b)
        })?;

        for _ in 0..(self.num_variables - 3) {
            let _ = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        }

        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        }

        cs.enforce_constraint(lc!(), lc!(), lc!())?;

        Ok(())
    }
}

#[test]
fn test_groth16_verifier() {
    type E = Bn254;
    let k = 6;
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let circuit = DummyCircuit::<<E as Pairing>::ScalarField> {
        a: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
        b: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << k,
    };
    let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();

    let c = circuit.a.unwrap() * circuit.b.unwrap();

    let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();

    let start = start_timer!(|| "collect_script");
    let script = Verifier::verify_proof(&vec![c], &proof, &vk);
    end_timer!(start);

    println!("groth16::test_verify_proof = {} bytes", script.len());

    let start = start_timer!(|| "execute_script");
    let exec_result = execute_script_without_stack_limit(script);
    end_timer!(start);

    assert!(exec_result.success);
}
