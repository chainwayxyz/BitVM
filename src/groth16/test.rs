use std::io::BufReader;

use crate::execute_script_without_stack_limit;
use crate::groth16::verifier::Verifier;
use ark_bn254::Bn254;
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::iterable::Iterable;
use ark_std::{end_timer, start_timer, test_rng, UniformRand};
use rand::{RngCore, SeedableRng};
use ark_ec::pairing::Pairing as ark_Pairing;
use serde_json::Value;
use std::str::FromStr;

pub fn value2g1(value: Value) -> ark_bn254::G1Projective {
    let v = value.as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect::<Vec<&str>>();
    ark_bn254::G1Projective::new(ark_bn254::Fq::from_str(&v[0]).unwrap(), ark_bn254::Fq::from_str(&v[1]).unwrap(), ark_bn254::Fq::from_str(&v[2]).unwrap())
}

pub fn value2g2(value: Value) -> ark_bn254::G2Projective {
    let v = value.as_array().unwrap().iter().map(|x| x.as_array().unwrap().iter().map(|y| y.as_str().unwrap()).collect::<Vec<&str>>()).collect::<Vec<Vec<&str>>>();
    ark_bn254::G2Projective::new(ark_bn254::Fq2::new(ark_bn254::Fq::from_str(&v[0][0]).unwrap(), ark_bn254::Fq::from_str(&v[0][1]).unwrap()), ark_bn254::Fq2::new(ark_bn254::Fq::from_str(&v[1][0]).unwrap(), ark_bn254::Fq::from_str(&v[1][1]).unwrap()), ark_bn254::Fq2::new(ark_bn254::Fq::from_str(&v[2][0]).unwrap(), ark_bn254::Fq::from_str(&v[2][1]).unwrap()))
}

pub fn read_proof() -> Proof<Bn254> {
    let proof_value: Value = serde_json::from_reader(BufReader::new(std::fs::File::open("src/groth16/data/proof.json").unwrap())).unwrap();
    let proof_a = value2g1(proof_value.as_object().unwrap()["pi_a"].clone());
    let proof_b = value2g2(proof_value.as_object().unwrap()["pi_b"].clone());
    let proof_c = value2g1(proof_value.as_object().unwrap()["pi_c"].clone());
    Proof { a: proof_a.into_affine(), b: proof_b.into_affine(), c: proof_c.into_affine() }
}

pub fn read_public() -> Vec<<Bn254 as ark_Pairing>::ScalarField> {
    let public_value: Value = serde_json::from_reader(BufReader::new(std::fs::File::open("src/groth16/data/public.json").unwrap())).unwrap();
    public_value.as_array().unwrap().iter().map(|x| ark_bn254::Fr::from_str(x.as_str().unwrap()).unwrap()).collect::<Vec<ark_bn254::Fr>>()
}

pub fn read_vk() -> VerifyingKey<Bn254> {
    let vk_value: Value = serde_json::from_reader(BufReader::new(std::fs::File::open("src/groth16/data/vk.json").unwrap())).unwrap();
    let alpha_g1 = value2g1(vk_value.as_object().unwrap()["vk_alpha_1"].clone()).into_affine();
    let beta_g2 = value2g2(vk_value.as_object().unwrap()["vk_beta_2"].clone()).into_affine();
    let gamma_g2 = value2g2(vk_value.as_object().unwrap()["vk_gamma_2"].clone()).into_affine();
    let delta_g2 = value2g2(vk_value.as_object().unwrap()["vk_delta_2"].clone()).into_affine();
    let gamma_abc_g1 = vk_value.as_object().unwrap()["IC"].as_array().unwrap().iter().map(|x| value2g1(x.clone()).into_affine()).collect::<Vec<ark_bn254::G1Affine>>();
    VerifyingKey { alpha_g1, beta_g2, gamma_g2, delta_g2, gamma_abc_g1 }
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
fn test_groth16() {
    // let proof: Proof<Bn254> = serde_json::from_reader(BufReader::new(std::fs::File::open("src/groth16/data/proof.json").unwrap())).unwrap();
    // let public_inputs: Vec<<Bn254 as ark_Pairing>::ScalarField> = serde_json::from_reader(BufReader::new(std::fs::File::open("src/groth16/data/public.json").unwrap())).unwrap();
    // let vk: VerifyingKey<Bn254> = serde_json::from_reader(BufReader::new(std::fs::File::open("src/groth16/data/verification_key.json").unwrap())).unwrap();

    let proof = read_proof();
    println!("proof: {:?}", proof);

    let public = read_public();
    println!("public: {:?}", public);

    let vk = read_vk();
    println!("vk: {:?}", vk);


    let start = start_timer!(|| "collect_script");
    let script = Verifier::verify_proof(&public, &proof, &vk);
    end_timer!(start);

    println!("groth16::test_verify_proof = {} bytes", script.len());

    let start = start_timer!(|| "execute_script");
    let exec_result = execute_script_without_stack_limit(script);
    end_timer!(start);

    assert!(exec_result.success);
}
