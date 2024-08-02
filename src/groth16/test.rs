use crate::execute_script_without_stack_limit;
use crate::groth16::verifier::Verifier;
use crate::bn254::utils::ScriptInput;
use crate::treepp::{script, Script};
use ark_bn254::Bn254;
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{end_timer, start_timer, test_rng, UniformRand};
use rand::{RngCore, SeedableRng};
use std::iter::zip;
use std::str::FromStr;
use std::io::BufReader;
use serde_json::Value;

struct Groth16Data {
    proof: Proof<ark_bn254::Bn254>,
    public: Vec<<ark_bn254::Bn254 as ark_ec::pairing::Pairing>::ScalarField>,
    vk: VerifyingKey<ark_bn254::Bn254>
}

impl Groth16Data {
    fn new(proof_filename: &str, public_filename: &str, vk_filename: &str) -> Self {
        let proof = Groth16Data::read_proof(proof_filename);
        let public = Groth16Data::read_public(public_filename);
        let vk = Groth16Data::read_vk(vk_filename);
        Self { proof, public, vk }
    }

    fn read_proof(filename: &str) -> Proof<ark_bn254::Bn254> {
        let proof_value: Value = serde_json::from_reader(BufReader::new(std::fs::File::open(filename).unwrap())).unwrap();
        let proof_a = Groth16Data::value2g1(proof_value.as_object().unwrap()["pi_a"].clone());
        let proof_b = Groth16Data::value2g2(proof_value.as_object().unwrap()["pi_b"].clone());
        let proof_c = Groth16Data::value2g1(proof_value.as_object().unwrap()["pi_c"].clone());
        Proof { a: proof_a.into_affine(), b: proof_b.into_affine(), c: proof_c.into_affine() }
    }

    fn read_public(filename: &str) -> Vec<<ark_bn254::Bn254 as ark_ec::pairing::Pairing>::ScalarField> {
        let public_value: Value = serde_json::from_reader(BufReader::new(std::fs::File::open(filename).unwrap())).unwrap();
        public_value.as_array().unwrap().iter().map(|x| ark_bn254::Fr::from_str(x.as_str().unwrap()).unwrap()).collect::<Vec<ark_bn254::Fr>>()
    }

    fn read_vk(filename: &str) -> VerifyingKey<ark_bn254::Bn254> {
        let vk_value: Value = serde_json::from_reader(BufReader::new(std::fs::File::open(filename).unwrap())).unwrap();
        let alpha_g1 = Groth16Data::value2g1(vk_value.as_object().unwrap()["vk_alpha_1"].clone()).into_affine();
        let beta_g2 = Groth16Data::value2g2(vk_value.as_object().unwrap()["vk_beta_2"].clone()).into_affine();
        let gamma_g2 = Groth16Data::value2g2(vk_value.as_object().unwrap()["vk_gamma_2"].clone()).into_affine();
        let delta_g2 = Groth16Data::value2g2(vk_value.as_object().unwrap()["vk_delta_2"].clone()).into_affine();
        let gamma_abc_g1 = vk_value.as_object().unwrap()["IC"].as_array().unwrap().iter().map(|x| Groth16Data::value2g1(x.clone()).into_affine()).collect::<Vec<ark_bn254::G1Affine>>();
        VerifyingKey { alpha_g1, beta_g2, gamma_g2, delta_g2, gamma_abc_g1 }
    }

    fn value2g1(value: Value) -> ark_bn254::G1Projective {
        let v = value.as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect::<Vec<&str>>();
        ark_bn254::G1Projective::new(ark_bn254::Fq::from_str(&v[0]).unwrap(), ark_bn254::Fq::from_str(&v[1]).unwrap(), ark_bn254::Fq::from_str(&v[2]).unwrap())
    }

    fn value2g2(value: Value) -> ark_bn254::G2Projective {
        let v = value.as_array().unwrap().iter().map(|x| x.as_array().unwrap().iter().map(|y| y.as_str().unwrap()).collect::<Vec<&str>>()).collect::<Vec<Vec<&str>>>();
        ark_bn254::G2Projective::new(ark_bn254::Fq2::new(ark_bn254::Fq::from_str(&v[0][0]).unwrap(), ark_bn254::Fq::from_str(&v[0][1]).unwrap()), ark_bn254::Fq2::new(ark_bn254::Fq::from_str(&v[1][0]).unwrap(), ark_bn254::Fq::from_str(&v[1][1]).unwrap()), ark_bn254::Fq2::new(ark_bn254::Fq::from_str(&v[2][0]).unwrap(), ark_bn254::Fq::from_str(&v[2][1]).unwrap()))
    }
}

fn test_script_with_inputs(script: Script, inputs: Vec<ScriptInput>) -> (bool, usize, usize) {
    let script_test = script! {
        for input in inputs {
            { input.push() }
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

    let (scripts, inputs) = Verifier::groth16_scripts_and_inputs(&groth16_data.vk, &groth16_data.proof, &groth16_data.public[0]);
    let n = scripts.len();

    assert_eq!(scripts.len(), inputs.len());

    let mut script_sizes = Vec::new();
    let mut max_stack_sizes = Vec::new();
    let mut script_total_size: u64 = 0;

    for (i, (script, input)) in zip(scripts, inputs).enumerate() {
        let (result, script_size, max_stack_size) = test_script_with_inputs(script.clone(), input.to_vec());
        script_total_size += script_size as u64;
        script_sizes.push(script_size);
        max_stack_sizes.push(max_stack_size);
        println!("script[{:?}]: size: {:?} bytes, max stack size: {:?} items", i, script_size, max_stack_size);
        assert!(result);
    }

    println!();
    println!("number of pieces: {:?}", n);
    println!("script total size: {:?}", script_total_size);
    println!("max (script size): {:?} bytes", script_sizes.iter().max().unwrap());
    println!("max (max stack size): {:?} items", max_stack_sizes.iter().max().unwrap());
}

fn test_script_with_input_signatures(scripts: Vec<Script>, inputs: Vec<Script>) -> (bool, usize, usize) {
    let script_test = script! {
        for input in inputs {
            { input }
        }
        for script in scripts {
            { script }
        }
    };
    let size = script_test.len();
    let start = start_timer!(|| "execute_script");
    let exec_result = execute_script_without_stack_limit(script_test);
    let max_stack_items = exec_result.stats.max_nb_stack_items;
    end_timer!(start);
    (exec_result.success, size, max_stack_items)
}

#[test]
fn test_groth16_verifier() {
    let groth16_data = Groth16Data::new("src/groth16/data/proof.json", "src/groth16/data/public.json", "src/groth16/data/vk.json");

    let (scripts, inputs, _) = Verifier::verify(&groth16_data.vk, &groth16_data.proof, &groth16_data.public[0]);
    let n = scripts.len();

    assert_eq!(scripts.len(), inputs.len());

    let mut script_sizes = Vec::new();
    let mut max_stack_sizes = Vec::new();
    let mut script_total_size: u64 = 0;

    for (i, (script, input)) in zip(scripts, inputs).enumerate() {
        let (result, script_size, max_stack_size) = test_script_with_input_signatures(script.clone(), input.to_vec());
        script_total_size += script_size as u64;
        script_sizes.push(script_size);
        max_stack_sizes.push(max_stack_size);
        println!("script[{:?}]: size: {:?} bytes, max stack size: {:?} items", i, script_size, max_stack_size);
        assert!(result);
    }

    println!();
    println!("number of pieces: {:?}", n);
    println!("script total size: {:?}", script_total_size);
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
fn test_groth16_verifier2() {
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
    let pvk = prepare_verifying_key::<E>(&vk);

    let c = circuit.a.unwrap() * circuit.b.unwrap();

    let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();
    assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &[c], &proof).unwrap());

    let start = start_timer!(|| "collect_script");
    let script = Verifier::verify_proof(&vec![c], &proof, &vk);
    end_timer!(start);

    println!("groth16::test_verify_proof = {} bytes", script.len());

    let start = start_timer!(|| "execute_script");
    let exec_result = execute_script_without_stack_limit(script);
    end_timer!(start);

    assert!(exec_result.success);
}

#[test]
fn test_groth16_verifier_split() {
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
    let pvk = prepare_verifying_key::<E>(&vk);

    let c = circuit.a.unwrap() * circuit.b.unwrap();

    let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();
    assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &[c], &proof).unwrap());

    let start = start_timer!(|| "collect_script");
    let script = Verifier::verify_proof(&vec![c], &proof, &vk);
    end_timer!(start);

    println!("groth16::test_verify_proof = {} bytes", script.len());

    let start = start_timer!(|| "execute_script");
    let exec_result = execute_script_without_stack_limit(script);
    end_timer!(start);

    assert!(exec_result.success);
}

