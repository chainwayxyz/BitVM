use crate::bn254::curves::G1Projective;
use crate::bn254::fr::Fr;
use crate::bn254::pairing::Pairing;
use crate::execute_script_without_stack_limit;
use crate::bn254::ell_coeffs::G2Prepared;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq2::Fq2;
use crate::bn254::fq6::Fq6;
use crate::bn254::fq12::Fq12;
use crate::bn254::utils::{fq12_push, fq2_push, fq6_push};
use crate::groth16::constants::{LAMBDA, P_POW3};
use crate::groth16::offchain_checker::compute_c_wi;
use crate::treepp::{script, Script};
use crate::execute_script;
// use crate::bn254::ell_coeffs::G2Prepared;

use ark_ec::pairing::Pairing as ark_Pairing;
// use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Proof, VerifyingKey};
use ark_std::iterable::Iterable;
use ark_std::{end_timer, start_timer, UniformRand};
use ark_ec::bn::{G1Prepared, BnConfig};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ec::{CurveGroup, VariableBaseMSM, Group, AffineRepr};
use ark_ff::Field;
use ark_ff::PrimeField;

use num_bigint::BigUint;
use num_traits::{Num, One};
use num_traits::Zero;

// use rand::{RngCore, SeedableRng};
use serde_json::Value;
use std::str::FromStr;
use std::io::BufReader;
use std::collections::HashMap;
use core::ops::{Mul, Div, Rem};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[derive(Clone)]
pub enum ScriptInput {
    InputFq12(ark_bn254::Fq12),
    InputFq6(ark_bn254::Fq6),
    InputFq2(ark_bn254::Fq2),
    InputFq(ark_bn254::Fq),
    InputFr(ark_bn254::Fr),
    InputG1P(ark_bn254::G1Projective),
    InputG1A(ark_bn254::G1Affine),
    InputG2P(ark_bn254::G2Projective),
    InputG2A(ark_bn254::G2Affine)
}

impl ScriptInput {
    pub fn push(&self) -> Script {
        match self {
            ScriptInput::InputFq12(fq12) => script! {
                { fq12_push(*fq12) }
            },
            ScriptInput::InputFq6(fq6) => script! {
                { fq6_push(*fq6) }
            },
            ScriptInput::InputFq2(fq2) => script! {
                // { Fq::push_u32_le(&BigUint::from(fq2.c0).to_u32_digits()) }
                // { Fq::push_u32_le(&BigUint::from(fq2.c1).to_u32_digits()) }
                { fq2_push(*fq2) }
            },
            ScriptInput::InputFq(fq) => script! {
                { Fq::push_u32_le(&BigUint::from(*fq).to_u32_digits()) }
            },
            ScriptInput::InputFr(fr) => script! {
                { Fr::push_u32_le(&BigUint::from(*fr).to_u32_digits()) }
            },
            ScriptInput::InputG1P(g1p) => script! {
                { Fq::push_u32_le(&BigUint::from(g1p.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(g1p.y).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(g1p.z).to_u32_digits()) }
            },
            ScriptInput::InputG1A(g1a) => script! {
                { Fq::push_u32_le(&BigUint::from(g1a.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(g1a.y).to_u32_digits()) }
            },
            ScriptInput::InputG2P(g2p) => script! {
                { Fq::push_u32_le(&BigUint::from(g2p.x.c0).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(g2p.x.c1).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(g2p.y.c0).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(g2p.y.c1).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(g2p.z.c0).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(g2p.z.c1).to_u32_digits()) }
            },
            ScriptInput::InputG2A(g2a) => script! {
                { Fq::push_u32_le(&BigUint::from(g2a.x.c0).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(g2a.x.c1).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(g2a.y.c0).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(g2a.y.c1).to_u32_digits()) }
            },
        }
    }
}

pub fn test_script_with_inputs(script: Script, inputs: Vec<ScriptInput>) -> bool {
    println!("script size: {:?}", script.len());
    let script_test = script! {
        for input in inputs {
            { input.push() }
        }
        { script }
    };
    let start = start_timer!(|| "execute_script");
    let exec_result = execute_script_without_stack_limit(script_test);
    end_timer!(start);
    exec_result.success
}

pub fn value2g1(value: Value) -> ark_bn254::G1Projective {
    let v = value.as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect::<Vec<&str>>();
    ark_bn254::G1Projective::new(ark_bn254::Fq::from_str(&v[0]).unwrap(), ark_bn254::Fq::from_str(&v[1]).unwrap(), ark_bn254::Fq::from_str(&v[2]).unwrap())
}

pub fn value2g2(value: Value) -> ark_bn254::G2Projective {
    let v = value.as_array().unwrap().iter().map(|x| x.as_array().unwrap().iter().map(|y| y.as_str().unwrap()).collect::<Vec<&str>>()).collect::<Vec<Vec<&str>>>();
    ark_bn254::G2Projective::new(ark_bn254::Fq2::new(ark_bn254::Fq::from_str(&v[0][0]).unwrap(), ark_bn254::Fq::from_str(&v[0][1]).unwrap()), ark_bn254::Fq2::new(ark_bn254::Fq::from_str(&v[1][0]).unwrap(), ark_bn254::Fq::from_str(&v[1][1]).unwrap()), ark_bn254::Fq2::new(ark_bn254::Fq::from_str(&v[2][0]).unwrap(), ark_bn254::Fq::from_str(&v[2][1]).unwrap()))
}

pub fn read_proof(filename: &str) -> Proof<ark_bn254::Bn254> {
    let proof_value: Value = serde_json::from_reader(BufReader::new(std::fs::File::open(filename).unwrap())).unwrap();
    let proof_a = value2g1(proof_value.as_object().unwrap()["pi_a"].clone());
    let proof_b = value2g2(proof_value.as_object().unwrap()["pi_b"].clone());
    let proof_c = value2g1(proof_value.as_object().unwrap()["pi_c"].clone());
    Proof { a: proof_a.into_affine(), b: proof_b.into_affine(), c: proof_c.into_affine() }
}

pub fn read_public(filename: &str) -> Vec<<ark_bn254::Bn254 as ark_ec::pairing::Pairing>::ScalarField> {
    let public_value: Value = serde_json::from_reader(BufReader::new(std::fs::File::open(filename).unwrap())).unwrap();
    public_value.as_array().unwrap().iter().map(|x| ark_bn254::Fr::from_str(x.as_str().unwrap()).unwrap()).collect::<Vec<ark_bn254::Fr>>()
}

pub fn read_vk(filename: &str) -> VerifyingKey<ark_bn254::Bn254> {
    let vk_value: Value = serde_json::from_reader(BufReader::new(std::fs::File::open(filename).unwrap())).unwrap();
    let alpha_g1 = value2g1(vk_value.as_object().unwrap()["vk_alpha_1"].clone()).into_affine();
    let beta_g2 = value2g2(vk_value.as_object().unwrap()["vk_beta_2"].clone()).into_affine();
    let gamma_g2 = value2g2(vk_value.as_object().unwrap()["vk_gamma_2"].clone()).into_affine();
    let delta_g2 = value2g2(vk_value.as_object().unwrap()["vk_delta_2"].clone()).into_affine();
    let gamma_abc_g1 = vk_value.as_object().unwrap()["IC"].as_array().unwrap().iter().map(|x| value2g1(x.clone()).into_affine()).collect::<Vec<ark_bn254::G1Affine>>();
    VerifyingKey { alpha_g1, beta_g2, gamma_g2, delta_g2, gamma_abc_g1 }
}

pub fn g1_projective_push(point: ark_bn254::G1Projective) -> Script {
    script! {
        { Fq::push_u32_le(&BigUint::from(point.x).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(point.y).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(point.z).to_u32_digits()) }
    }
}

pub fn g1_affine_push(point: ark_bn254::G1Affine) -> Script {
    script! {
        { Fq::push_u32_le(&BigUint::from(point.x).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(point.y).to_u32_digits()) }
    }
}

#[test]
fn test_g1_projective_scalar_mul_split() {
    let mut prng = ChaCha20Rng::seed_from_u64(0);

    let a = ark_bn254::Fr::rand(&mut prng);

    let p = ark_bn254::G1Projective::rand(&mut prng);
    let two_p = p + p;
    let three_p = p + p + p;
    let q = p.mul(a);

    let bits = BigUint::from(a).to_bytes_le().iter().map(|x| (0..8).map(|i| {(1 << i) & x > 0}).collect()).collect::<Vec<Vec<bool>>>().into_iter().flatten().rev().map(|x| if x {1} else {0}).collect::<Vec<usize>>();
    let bits = bits.split_at(2).1;

    let mut g1_projs = vec![ark_bn254::G1Projective::zero()];

    for i in 0..(Fr::N_BITS / 2) {
        let t = 2 * bits[2 * i as usize] + bits[2 * i as usize + 1];
        let four_last = g1_projs.last().unwrap().double().double();
        if t == 3 {
            g1_projs.push(four_last + three_p);
        }
        else if t == 2 {
            g1_projs.push(four_last + two_p);
        }
        else if t == 1 {
            g1_projs.push(four_last + p);
        }
        else {
            g1_projs.push(four_last);
        }
    }

    assert_eq!(q, *g1_projs.last().unwrap());

    let script_initial = script! {
        { Fr::decode_montgomery() }
        { Fr::convert_to_le_bits() }

        for i in (0..Fr::N_BITS).rev() {
            { i + 1 } OP_ROLL OP_EQUALVERIFY
        }

        { G1Projective::copy(2) }
        { G1Projective::copy(2) }
        { G1Projective::add() }
        { G1Projective::equalverify() }

        { G1Projective::roll(1) }
        { G1Projective::double() }
        { G1Projective::equalverify() }
        OP_TRUE
    };

    println!("g1 scalar mul init: {:?}", script_initial.len());

    let script_initial_test = script! {
        { g1_projective_push(p) }
        { g1_projective_push(two_p) }
        { g1_projective_push(three_p) }
        for b in bits {
            { *b }
        }
        { Fr::push_u32_le(&BigUint::from(a).to_u32_digits()) }
        { script_initial.clone() }
    };

    let exec_result = execute_script(script_initial_test);
    assert!(exec_result.success);

    let script_loop = script! {
        OP_TOALTSTACK OP_TOALTSTACK

        { G1Projective::double() }
        { G1Projective::double() }

        OP_FROMALTSTACK OP_FROMALTSTACK
        OP_IF
            OP_IF
                { G1Projective::copy(1) }
            OP_ELSE
                { G1Projective::copy(3) }
            OP_ENDIF
            OP_TRUE
        OP_ELSE
            OP_IF
                { G1Projective::copy(2) }
                OP_TRUE
            OP_ELSE
                OP_FALSE
            OP_ENDIF
        OP_ENDIF
        OP_IF
            { G1Projective::add() }
        OP_ENDIF

        { G1Projective::toaltstack() }
        { G1Projective::drop() }
        { G1Projective::drop() }
        { G1Projective::drop() }
        { G1Projective::fromaltstack() }
        { G1Projective::equalverify() }
        OP_TRUE
    };

    println!("g1 scalar mul loop: {:?}", script_loop.len());

    for i in 0..(Fr::N_BITS / 2) {
        let script_loop_test = script! {
            { g1_projective_push(g1_projs[i as usize + 1]) }
            { g1_projective_push(p) }
            { g1_projective_push(two_p) }
            { g1_projective_push(three_p) }
            { g1_projective_push(g1_projs[i as usize]) }
            { bits[2 * i as usize] }
            { bits[2 * i as usize + 1] }
            { script_loop.clone() }
        };

        let exec_result = execute_script(script_loop_test);
        assert!(exec_result.success);
    }
}

pub fn fq12_mul_verify(
    a1: &str, 
    a2: &str, 
    a3: &str, 
    a4: &str, 
    a5: &str, 
    a6: &str, 
    a7: &str, 
    a8: &str, 
    a9: &str, 
    a10: &str, 
    a11: &str, 
    a12: &str, 
    b1: &str, 
    b2: &str, 
    b3: &str, 
    b4: &str, 
    b5: &str, 
    b6: &str, 
    b7: &str, 
    b8: &str, 
    b9: &str, 
    b10: &str, 
    b11: &str, 
    b12: &str, 
    c1: &str, 
    c2: &str, 
    c3: &str, 
    c4: &str, 
    c5: &str, 
    c6: &str, 
    c7: &str, 
    c8: &str, 
    c9: &str, 
    c10: &str, 
    c11: &str, 
    c12: &str, 
    // id: &str,
) -> (Vec<(Script, Vec<String>)>, fn(&mut HashMap<String, ark_bn254::Fq>)) {

    // inputs: ax, bx, d (a1, a2, a3, a4, a5, a6, b1, b2, b3, b4, b5, b6, d1, d2, d3, d4, d5, d6)
    // checks d=ax*bx
    let script1 = script! {
        { Fq6::mul(12, 6) }
        { Fq6::equalverify() }
        OP_TRUE
    };
    let (d1, d2, d3, d4, d5, d6) = ("d1", "d2", "d3", "d4", "d5", "d6");
    let x1 = vec![a1, a2, a3, a4, a5, a6, b1, b2, b3, b4, b5, b6, d1, d2, d3, d4, d5, d6];
    // scripts.push((script1, x1.iter().map(|s| s.to_string()).collect()));

    // inputs: ay, by, e 
    // checks e=ay*by
    let script2 = script! {
        { Fq6::mul(12, 6) }
        { Fq6::equalverify() }
        OP_TRUE
    };
    let (e1, e2, e3, e4, e5, e6) = ("e1", "e2", "e3", "e4", "e5", "e6");
    let x2 = vec![a7, a8, a9, a10, a11, a12, b7, b8, b9, b10, b11, b12, e1, e2, e3, e4, e5, e6];
    // scripts.push((script2, x2.iter().map(|s| s.to_string()).collect()));

    // inputs: a, b, d, e, c 
    // checks cx=d+eß, cy=ax*by+ay*bx=(ax+ay)*(bx+by)-(d+e)
    let script3 = script! {
        { Fq6::add(42, 36) }
        { Fq6::add(36, 30) }
        { Fq6::mul(6, 0) }
        { Fq6::copy(24) }
        { Fq6::copy(24) }
        { Fq12::mul_fq6_by_nonresidue() }
        { Fq6::add(6, 0) }
        { Fq6::add(30, 24) }
        { Fq6::sub(12, 0) }
        { Fq12::equalverify() }
        OP_TRUE
    };
    let x3 = vec![a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, d1, d2, d3, d4, d5, d6, e1, e2, e3, e4, e5, e6, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12];
    // scripts.push((script3, x3.iter().map(|s| s.to_string()).collect()));

    fn eval_intermediate_values(values: &mut HashMap<String, ark_bn254::Fq>) {
        // let a = ark_bn254::Fq12::from_base_prime_field_elems(&[values.get(a1).unwrap().clone()]);
    }

    // let eval_intermediate_values = |values: &mut HashMap<String, ark_bn254::Fq>| {
    //     let a = ark_bn254::Fq12::from_base_prime_field_elems(&[values.get(a1).unwrap().clone(), values.get(a2).unwrap().clone(), values.get(a3).unwrap().clone(), values.get(a4).unwrap().clone(), values.get(a5).unwrap().clone(), values.get(a6).unwrap().clone(), values.get(a7).unwrap().clone(), values.get(a8).unwrap().clone(), values.get(a9).unwrap().clone(), values.get(a10).unwrap().clone(), values.get(a11).unwrap().clone(), values.get(a12).unwrap().clone()]).unwrap();
    //     values.insert("hello".to_string(), a.c0.c0.c0);
    // };

    let scripts = vec![
        (script1, x1.iter().map(|s| s.to_string()).collect()), 
        (script2, x2.iter().map(|s| s.to_string()).collect()),
        (script3, x3.iter().map(|s| s.to_string()).collect()),
    ];

    (scripts, eval_intermediate_values)
}

#[test]
fn test_bn254_fq12_mul_split() {
    let mut prng = ChaCha20Rng::seed_from_u64(0);

    let a = ark_bn254::Fq12::rand(&mut prng);
    let b = ark_bn254::Fq12::rand(&mut prng);
    let c = a.mul(&b);

    let d = a.c0.mul(b.c0);
    let e = a.c1.mul(b.c1);

    let mut dct = HashMap::<String, ark_bn254::Fq>::new();

    dct.insert("a1".to_string(), a.c0.c0.c0);
    dct.insert("a2".to_string(), a.c0.c0.c1);
    dct.insert("a3".to_string(), a.c0.c1.c0);
    dct.insert("a4".to_string(), a.c0.c1.c1);
    dct.insert("a5".to_string(), a.c0.c2.c0);
    dct.insert("a6".to_string(), a.c0.c2.c1);
    dct.insert("a7".to_string(), a.c1.c0.c0);
    dct.insert("a8".to_string(), a.c1.c0.c1);
    dct.insert("a9".to_string(), a.c1.c1.c0);
    dct.insert("a10".to_string(), a.c1.c1.c1);
    dct.insert("a11".to_string(), a.c1.c2.c0);
    dct.insert("a12".to_string(), a.c1.c2.c1);

    dct.insert("b1".to_string(), b.c0.c0.c0);
    dct.insert("b2".to_string(), b.c0.c0.c1);
    dct.insert("b3".to_string(), b.c0.c1.c0);
    dct.insert("b4".to_string(), b.c0.c1.c1);
    dct.insert("b5".to_string(), b.c0.c2.c0);
    dct.insert("b6".to_string(), b.c0.c2.c1);
    dct.insert("b7".to_string(), b.c1.c0.c0);
    dct.insert("b8".to_string(), b.c1.c0.c1);
    dct.insert("b9".to_string(), b.c1.c1.c0);
    dct.insert("b10".to_string(), b.c1.c1.c1);
    dct.insert("b11".to_string(), b.c1.c2.c0);
    dct.insert("b12".to_string(), b.c1.c2.c1);

    dct.insert("c1".to_string(), c.c0.c0.c0);
    dct.insert("c2".to_string(), c.c0.c0.c1);
    dct.insert("c3".to_string(), c.c0.c1.c0);
    dct.insert("c4".to_string(), c.c0.c1.c1);
    dct.insert("c5".to_string(), c.c0.c2.c0);
    dct.insert("c6".to_string(), c.c0.c2.c1);
    dct.insert("c7".to_string(), c.c1.c0.c0);
    dct.insert("c8".to_string(), c.c1.c0.c1);
    dct.insert("c9".to_string(), c.c1.c1.c0);
    dct.insert("c10".to_string(), c.c1.c1.c1);
    dct.insert("c11".to_string(), c.c1.c2.c0);
    dct.insert("c12".to_string(), c.c1.c2.c1);

    let (scripts, eval) = fq12_mul_verify("a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10", "a11", "a12", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "b10", "b11", "b12", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "c10", "c11", "c12");

    eval(&mut dct);

    dct.insert("d1".to_string(), d.c0.c0);
    dct.insert("d2".to_string(), d.c0.c1);
    dct.insert("d3".to_string(), d.c1.c0);
    dct.insert("d4".to_string(), d.c1.c1);
    dct.insert("d5".to_string(), d.c2.c0);
    dct.insert("d6".to_string(), d.c2.c1);

    dct.insert("e1".to_string(), e.c0.c0);
    dct.insert("e2".to_string(), e.c0.c1);
    dct.insert("e3".to_string(), e.c1.c0);
    dct.insert("e4".to_string(), e.c1.c1);
    dct.insert("e5".to_string(), e.c2.c0);
    dct.insert("e6".to_string(), e.c2.c1);

    // println!("dct: {:?}", dct);

    for (script, labels) in scripts {
        // println!("labels: {:?}", labels);
        let v = labels.iter().map(|str| dct.get(str).unwrap().clone()).collect::<Vec<ark_bn254::Fq>>();
        let s = script! {
            for element in v {
                { Fq::push_u32_le(&BigUint::from(element).to_u32_digits()) }
            }
            { script.clone() }
        };
        let exec_result = execute_script(s);
        assert!(exec_result.success);
        // break;
    }
}

pub fn verify(
    proof: &Proof<ark_bn254::Bn254>,
    public_inputs: &Vec<<ark_bn254::Bn254 as ark_ec::pairing::Pairing>::ScalarField>,
    vk: &VerifyingKey<ark_bn254::Bn254>
) -> Script {
    assert!(public_inputs.len() == 1);
    let scalars = vec![<ark_bn254::Bn254 as ark_ec::pairing::Pairing>::ScalarField::ONE, public_inputs[0]];
    let msm_g1 = ark_bn254::G1Projective::msm(&vk.gamma_abc_g1, &scalars).expect("failed to calculate msm");

    let msm_script = script! {
        // 1. init the sum=base1;
        { g1_projective_push(vk.gamma_abc_g1[0].into()) }

        // 2. add base2*public
        { g1_projective_push(vk.gamma_abc_g1[1].into()) }
        { Fr::push_u32_le(&BigUint::from(public_inputs[0]).to_u32_digits()) }
        { G1Projective::scalar_mul() }
        { G1Projective::add() }

        // convert into Affine
        { G1Projective::into_affine() }
    };

    let exp = &*P_POW3 - &*LAMBDA;

    let pvk = prepare_verifying_key::<ark_bn254::Bn254>(vk);
    let beta_prepared = (-vk.beta_g2).into();
    let gamma_g2_neg_pc = pvk.gamma_g2_neg_pc.clone().into();
    let delta_g2_neg_pc = pvk.delta_g2_neg_pc.clone().into();

    let q_prepared = [gamma_g2_neg_pc, delta_g2_neg_pc, beta_prepared].to_vec();

    // let sum_ai_abc_gamma = msm_g1.into_affine();

    let a: [G1Prepared<ark_bn254::Config>; 4] = [
        msm_g1.into_affine().into(),
        proof.c.into(),
        vk.alpha_g1.into(),
        proof.a.into(),
    ];

    let b = [
        pvk.gamma_g2_neg_pc.clone(),
        pvk.delta_g2_neg_pc.clone(),
        (-vk.beta_g2).into(),
        proof.b.into(),
    ];

    let qap = ark_bn254::Bn254::multi_miller_loop(a, b);
    let f = qap.0;
    let (c, wi) = compute_c_wi(f);
    let c_inv = c.inverse().unwrap();

    let hint = f * wi * c.pow(exp.to_u64_digits());

    assert_eq!(hint, c.pow(P_POW3.to_u64_digits()), "hint isn't correct!");

    let p1 = msm_g1.into_affine();
    let p2 = proof.c;
    let p3 = vk.alpha_g1;
    let p4 = proof.a;
    let q4 = proof.b;

    script! {
        // 1. push constants to stack
        // beta_12
        { Fq::push_dec("21575463638280843010398324269430826099269044274347216827212613867836435027261") }
        { Fq::push_dec("10307601595873709700152284273816112264069230130616436755625194854815875713954") }

         // beta_13
        { Fq::push_dec("2821565182194536844548159561693502659359617185244120367078079554186484126554") }
        { Fq::push_dec("3505843767911556378687030309984248845540243509899259641013678093033130930403") }

        // beta_22
        { Fq::push_dec("21888242871839275220042445260109153167277707414472061641714758635765020556616") }
        { Fq::push_zero() }

        // 1/2
        { Fq::push_u32_le(&BigUint::from(ark_bn254::Fq::one().double().inverse().unwrap()).to_u32_digits()) }

        // B
        { Fq::push_u32_le(&BigUint::from(ark_bn254::g2::Config::COEFF_B.c0).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(ark_bn254::g2::Config::COEFF_B.c1).to_u32_digits()) }

        // 2. push params to stack

        // 2.1 compute p1 with msm
        { msm_script }
        // 2.2 push other pairing points
        { Fq::push_u32_le(&BigUint::from(p2.x).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(p2.y).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(p3.x).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(p3.y).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(p4.x).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(p4.y).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(q4.x.c0).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(q4.x.c1).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(q4.y.c0).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(q4.y.c1).to_u32_digits()) }
        { fq12_push(c) }
        { fq12_push(c_inv) }
        { fq12_push(wi) }
        // push t4: t4.x = q4.x, t4.y = q4.y, t4.z = Fq2::ONE
        { Fq::push_u32_le(&BigUint::from(q4.x.c0).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(q4.x.c1).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(q4.y.c0).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(q4.y.c1).to_u32_digits()) }
        { Fq::push_one() }
        { Fq::push_zero() }
        // stack: [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4]

        // 3. verifier pairing
        // Input stack: [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4]
        // Output stack: [final_f]
        { Pairing::quad_miller_loop_with_c_wi(&q_prepared) }

        // check final_f == hint
        { fq12_push(hint) }
        { Fq12::equalverify() }
        OP_TRUE
    }
}

#[test]
fn test_groth16() {
    let proof = read_proof("src/groth16/data/proof.json");
    let public = read_public("src/groth16/data/public.json");
    let vk = read_vk("src/groth16/data/vk.json");

    let start = start_timer!(|| "collect_script");
    let script = verify(&proof, &public, &vk);
    end_timer!(start);

    println!("groth16::test_verify_proof = {} bytes", script.len());

    let start = start_timer!(|| "execute_script");
    let exec_result = execute_script_without_stack_limit(script);
    end_timer!(start);

    assert!(exec_result.success);
}

#[test]
fn test_groth16_split() {
    let proof = read_proof("src/groth16/data/proof.json");
    let public = read_public("src/groth16/data/public.json");
    let vk = read_vk("src/groth16/data/vk.json");

    let mut scripts_and_inputs = Vec::new();

    // we have only one public input
    assert_eq!(public.len(), 1);
    let public = public[0];

    let msm_g1 = ark_bn254::G1Projective::msm(&vk.gamma_abc_g1, &[<ark_bn254::Bn254 as ark_Pairing>::ScalarField::ONE, public.clone()]).expect("failed to calculate msm");

    let base1: ark_bn254::G1Projective = vk.gamma_abc_g1[0].into();
    let base2: ark_bn254::G1Projective = vk.gamma_abc_g1[1].into();

    let msm_script = script! {
        { Fq::push_u32_le(&BigUint::from(base1.x).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(base1.y).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(base1.z).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(base2.x).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(base2.y).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(base2.z).to_u32_digits()) }
        { Fr::roll(6) }
        { G1Projective::scalar_mul() }
        { G1Projective::add() }
        { G1Projective::equalverify() }
        OP_TRUE
    };

    scripts_and_inputs.push((msm_script.clone(), vec![ScriptInput::InputG1P(msm_g1), ScriptInput::InputFr(public)]));

    // verify with prepared inputs
    let exp = &*P_POW3 - &*LAMBDA;

    let pvk = prepare_verifying_key::<ark_bn254::Bn254>(&vk);
    let beta_prepared = (-vk.beta_g2).into();
    let gamma_g2_neg_pc = pvk.gamma_g2_neg_pc.clone().into();
    let delta_g2_neg_pc = pvk.delta_g2_neg_pc.clone().into();

    let q_prepared: Vec<G2Prepared> = [gamma_g2_neg_pc, delta_g2_neg_pc, beta_prepared].to_vec();

    let a: [G1Prepared<ark_bn254::Config>; 4] = [
        msm_g1.into_affine().into(),
        proof.c.into(),
        vk.alpha_g1.into(),
        proof.a.into(),
    ];

    let b = [
        pvk.gamma_g2_neg_pc.clone(),
        pvk.delta_g2_neg_pc.clone(),
        (-vk.beta_g2).into(),
        proof.b.into(),
    ];

    let qap = ark_bn254::Bn254::multi_miller_loop(a, b);
    let f = qap.0;
    let (c, wi) = compute_c_wi(f);
    let c_inv = c.inverse().unwrap();

    let hint = f * wi * c.pow(exp.to_u64_digits());

    assert_eq!(hint, c.pow(P_POW3.to_u64_digits()), "hint isn't correct!");

    let p1 = msm_g1.into_affine();
    let p2 = proof.c;
    let p3 = vk.alpha_g1;
    let p4 = proof.a;
    let p_lst = vec![p1, p2, p3, p4];
    let q4 = proof.b;

    let num_constant = 3;
    let mut constant_iters = vec![q_prepared[0].ell_coeffs.iter(), q_prepared[1].ell_coeffs.iter(), q_prepared[2].ell_coeffs.iter()];

    let mut t4 = q4.into_group();
    let two_inv = ark_bn254::Fq::from(2).inverse().unwrap();

    let mut f_iters = vec![q_prepared[0].ell_coeffs.iter(), q_prepared[1].ell_coeffs.iter(), q_prepared[2].ell_coeffs.iter()];

    let mut f_vec = vec![c_inv.clone()];
    let mut t4_vec = vec![t4.clone()];
    for jj in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        let mut f_next = f_vec.last().unwrap().clone();
        f_next = f_next.square();

        if ark_bn254::Config::ATE_LOOP_COUNT[jj - 1] == 1 {
            f_next = f_next * c_inv;
        }
        else if ark_bn254::Config::ATE_LOOP_COUNT[jj - 1] == -1 {
            f_next = f_next * c;
        }

        for k in 0..num_constant {
            let coeffs = f_iters[k].next().unwrap();

            let mut c0new = coeffs.0;
            c0new.mul_assign_by_fp(&p_lst[k].y);

            let mut c1new = coeffs.1;
            c1new.mul_assign_by_fp(&p_lst[k].x);

            f_next.mul_by_034(&c0new, &c1new, &coeffs.2);
        }

        let mut a = t4.x * &t4.y;
        a.mul_assign_by_fp(&two_inv);
        let b = t4.y.square();
        let c = t4.z.square();
        let e = ark_bn254::g2::Config::COEFF_B * &(c.double() + &c);
        let f = e.double() + &e;
        let mut g = b + &f;
        g.mul_assign_by_fp(&two_inv);
        let h = (t4.y + &t4.z).square() - &(b + &c);
        let i = e - &b;
        let j = t4.x.square();
        let e_square = e.square();
        t4.x = a * &(b - &f);
        t4.y = g.square() - &(e_square.double() + &e_square);
        t4.z = b * &h;

        let coeffs = (-h, j.double() + &j, i);

        let mut c0new = coeffs.0;
        c0new.mul_assign_by_fp(&p4.y);

        let mut c1new = coeffs.1;
        c1new.mul_assign_by_fp(&p4.x);

        f_next.mul_by_034(&c0new, &c1new, &coeffs.2);

        if ark_bn254::Config::ATE_LOOP_COUNT[jj - 1] == 1 || ark_bn254::Config::ATE_LOOP_COUNT[jj - 1] == -1 {
            for k in 0..num_constant {
                let coeffs = f_iters[k].next().unwrap();
    
                let mut c0new = coeffs.0;
                c0new.mul_assign_by_fp(&p_lst[k].y);
    
                let mut c1new = coeffs.1;
                c1new.mul_assign_by_fp(&p_lst[k].x);
    
                f_next.mul_by_034(&c0new, &c1new, &coeffs.2);
            }

            let q4y = if ark_bn254::Config::ATE_LOOP_COUNT[jj - 1] == 1 {q4.y} else {-q4.y};

            let theta = t4.y - &(q4y * &t4.z);
            let lambda = t4.x - &(q4.x * &t4.z);
            let c = theta.square();
            let d = lambda.square();
            let e = lambda * &d;
            let f = t4.z * &c;
            let g = t4.x * &d;
            let h = e + &f - &g.double();
            t4.x = lambda * &h;
            t4.y = theta * &(g - &h) - &(e * &t4.y);
            t4.z *= &e;
            let j = theta * &q4.x - &(lambda * &q4y);
            
            let coeffs = (lambda, -theta, j);
    
            let mut c0new = coeffs.0;
            c0new.mul_assign_by_fp(&p4.y);
    
            let mut c1new = coeffs.1;
            c1new.mul_assign_by_fp(&p4.x);
    
            f_next.mul_by_034(&c0new, &c1new, &coeffs.2);
        }

        f_vec.push(f_next);
        t4_vec.push(t4.clone());
    }

    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        let mut f1 = f_vec[ark_bn254::Config::ATE_LOOP_COUNT.len() - i - 1].clone();
        let f2 = f_vec[ark_bn254::Config::ATE_LOOP_COUNT.len() - i].clone();

        let mut t4_1 = t4_vec[ark_bn254::Config::ATE_LOOP_COUNT.len() - i - 1].clone();
        let t4_2 = t4_vec[ark_bn254::Config::ATE_LOOP_COUNT.len() - i].clone();

        let ate_loop_s1 = script! {
            { Fq12::square() }
            { Fq12::equalverify() }
            OP_TRUE
        };

        let fx = f1.square();
        scripts_and_inputs.push((ate_loop_s1, vec![ScriptInput::InputFq12(fx), ScriptInput::InputFq12(f1)]));
        f1 = fx;

        if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 {
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f^2 * c_inv]
            let fx = f1 * c_inv;
            let ate_loop_s2 = script! {
                { Fq12::mul(12, 0) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            scripts_and_inputs.push((ate_loop_s2, vec![ScriptInput::InputFq12(fx), ScriptInput::InputFq12(c_inv), ScriptInput::InputFq12(f1)]));
            f1 = fx;
        }
        else if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f^2 * c]
            let fx = f1 * c;
            let ate_loop_s2 = script! {
                { Fq12::mul(12, 0) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            scripts_and_inputs.push((ate_loop_s2, vec![ScriptInput::InputFq12(fx), ScriptInput::InputFq12(c), ScriptInput::InputFq12(f1)]));
            f1 = fx;
        }

        for j in 0..num_constant {
            let mut fx = f1.clone();
            let coeffs = constant_iters[j].next().unwrap();

            let mut c0new = coeffs.0;
            c0new.mul_assign_by_fp(&p_lst[j].y);

            let mut c1new = coeffs.1;
            c1new.mul_assign_by_fp(&p_lst[j].x);

            fx.mul_by_034(&c0new, &c1new, &coeffs.2);

            let ate_loop_s3 = script! {
                { Pairing::ell_by_constant(coeffs) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            scripts_and_inputs.push((ate_loop_s3, vec![ScriptInput::InputFq12(fx), ScriptInput::InputFq12(f1), ScriptInput::InputG1A(p_lst[j])]));
            f1 = fx;
        }

        let mut t4x = t4_1.clone();

        let mut a = t4x.x * &t4x.y;
        a.mul_assign_by_fp(&two_inv);
        let b = t4x.y.square();
        let cc = t4x.z.square();
        let e = ark_bn254::g2::Config::COEFF_B * &(cc.double() + &cc);
        let f = e.double() + &e;
        let mut g = b + &f;
        g.mul_assign_by_fp(&two_inv);
        let h = (t4x.y + &t4x.z).square() - &(b + &cc);
        let ii = e - &b;
        let j = t4x.x.square();
        let e_square = e.square();
        t4x.x = a * &(b - &f);
        t4x.y = g.square() - &(e_square.double() + &e_square);
        t4x.z = b * &h;

        let coeffs = (-h, j.double() + &j, ii);

        let modified_double_line = script! {
            // let mut a = self.x * &self.y;
            // Px, Py, Tx, Ty, Tz
            { Fq2::copy(4) }
            // Px, Py, Tx, Ty, Tz, Tx
            { Fq2::copy(4) }
            // Px, Py, Tx, Ty, Tz, Tx, Ty
            { Fq2::mul(2, 0) }
            // Px, Py, Tx, Ty, Tz, Tx * Ty
    
            // a.mul_assign_by_fp(two_inv);
            // Px, Py, Tx, Ty, Tz, a
            { Fq::push_u32_le(&BigUint::from(ark_bn254::Fq::one().double().inverse().unwrap()).to_u32_digits()) }
            // Px, Py, Tx, Ty, Tz, a, 1/2
            { Fq2::mul_by_fq(1, 0) }
            // Px, Py, Tx, Ty, Tz, a * 1/2
    
            // let b = self.y.square();
            // Px, Py, Tx, Ty, Tz, a
            { Fq2::copy(4) }
            // Px, Py, Tx, Ty, Tz, a, Ty
            { Fq2::square() }
            // Px, Py, Tx, Ty, Tz, a, Ty^2
    
            // let c = self.z.square();
            // Px, Py, Tx, Ty, Tz, a, b
            { Fq2::copy(4) }
            // Px, Py, Tx, Ty, Tz, a, b, Tz
            { Fq2::square() }
            // Px, Py, Tx, Ty, Tz, a, b, Tz^2
    
            // let e = ark_bn254::g2::Config::COEFF_B * &(c.double() + &c);
            // Px, Py, Tx, Ty, Tz, a, b, c
            { Fq2::copy(0) }
            { Fq2::copy(0) }
            // Px, Py, Tx, Ty, Tz, a, b, c, c, c
            { Fq2::double(0) }
            // Px, Py, Tx, Ty, Tz, a, b, c, c, 2 * c
            { Fq2::add(2, 0) }
            // Px, Py, Tx, Ty, Tz, a, b, c, 3 * c
            // B
            { Fq::push_u32_le(&BigUint::from(ark_bn254::g2::Config::COEFF_B.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(ark_bn254::g2::Config::COEFF_B.c1).to_u32_digits()) }
            // Px, Py, Tx, Ty, Tz, a, b, c, 3 * c, B
            { Fq2::mul(2, 0) }
            // Px, Py, Tx, Ty, Tz, a, b, c, 3 * c * B
    
            // let f = e.double() + &e;
            // Px, Py, Tx, Ty, Tz, a, b, c, e
            { Fq2::copy(0) }
            { Fq2::copy(0) }
            // Px, Py, Tx, Ty, Tz, a, b, c, e, e, e
            { Fq2::double(0) }
            // Px, Py, Tx, Ty, Tz, a, b, c, e, e, 2 * e
            { Fq2::add(2, 0) }
            // Px, Py, Tx, Ty, Tz, a, b, c, e, 3 * e
    
            // let mut g = b + &f;
            // Px, Py, Tx, Ty, Tz, a, b, c, e, f
            { Fq2::copy(0) }
            // Px, Py, Tx, Ty, Tz, a, b, c, e, f, f
            { Fq2::copy(8) }
            // Px, Py, Tx, Ty, Tz, a, b, c, e, f, f, b
            { Fq2::add(2, 0) }
            // Px, Py, Tx, Ty, Tz, a, b, c, e, f, f + b
    
            // g.mul_assign_by_fp(two_inv);
            // Px, Py, Tx, Ty, Tz, a, b, c, e, f, g
            { Fq::push_u32_le(&BigUint::from(ark_bn254::Fq::one().double().inverse().unwrap()).to_u32_digits()) }
            // Px, Py, Tx, Ty, Tz, a, b, c, e, f, g, 1/2
            { Fq2::mul_by_fq(1, 0) }
            // Px, Py, Tx, Ty, Tz, a, b, c, e, f, g * 1/2
    
            // let h = (self.y + &self.z).square() - &(b + &c);
            // Px, Py, Tx, Ty, Tz, a, b, c, e, f, g
            { Fq2::roll(14) }
            // Px, Py, Tx, Tz, a, b, c, e, f, g, Ty
            { Fq2::roll(14) }
            // Px, Py, Tx, a, b, c, e, f, g, Ty, Tz
            { Fq2::add(2, 0) }
            // Px, Py, Tx, a, b, c, e, f, g, Ty + Tz
            { Fq2::square() }
            // Px, Py, Tx, a, b, c, e, f, g, (Ty + Tz)^2
            { Fq2::copy(10) }
            // Px, Py, Tx, a, b, c, e, f, g, (Ty + Tz)^2, b
            { Fq2::roll(10) }
            // Px, Py, Tx, a, b, e, f, g, (Ty + Tz)^2, b, c
            { Fq2::add(2, 0) }
            // Px, Py, Tx, a, b, e, f, g, (Ty + Tz)^2, b + c
            { Fq2::sub(2, 0) }
            // Px, Py, Tx, a, b, e, f, g, (Ty + Tz)^2 - (b + c)
    
            // let i = e - &b;
            // Px, Py, Tx, a, b, e, f, g, h
            { Fq2::copy(6) }
            // Px, Py, Tx, a, b, e, f, g, h, e
            { Fq2::copy(10) }
            // Px, Py, Tx, a, b, e, f, g, h, e, b
            { Fq2::sub(2, 0) }
            // Px, Py, Tx, a, b, e, f, g, h, e - b
    
            // let j = self.x.square();
            // Px, Py, Tx, a, b, e, f, g, h, i
            { Fq2::roll(14) }
            // Px, Py, a, b, e, f, g, h, i, Tx
            { Fq2::square() }
            // Px, Py, a, b, e, f, g, h, i, Tx^2
    
            // let e_square = e.square();
            // Px, Py, a, b, e, f, g, h, i, j
            { Fq2::roll(10) }
            // Px, Py, a, b, f, g, h, i, j, e
            { Fq2::square() }
            // Px, Py, a, b, f, g, h, i, j, e^2
    
            // self.x = a * &(b - &f);
            // Px, Py, a, b, f, g, h, i, j, e^2
            { Fq2::roll(14) }
            // Px, Py, b, f, g, h, i, j, e^2, a
            { Fq2::copy(14) }
            // Px, Py, b, f, g, h, i, j, e^2, a, b
            { Fq2::roll(14) }
            // Px, Py, b, g, h, i, j, e^2, a, b, f
            { Fq2::sub(2, 0) }
            // Px, Py, b, g, h, i, j, e^2, a, b - f
            { Fq2::mul(2, 0) }
            // Px, Py, b, g, h, i, j, e^2, a * (b - f)
    
            // self.y = g.square() - &(e_square.double() + &e_square);
            // Px, Py, b, g, h, i, j, e^2, x
            { Fq2::roll(10) }
            // Px, Py, b, h, i, j, e^2, x, g
            { Fq2::square() }
            // Px, Py, b, h, i, j, e^2, x, g^2
            { Fq2::roll(4) }
            // Px, Py, b, h, i, j, x, g^2, e^2
            { Fq2::copy(0) }
            // Px, Py, b, h, i, j, x, g^2, e^2, e^2
            { Fq2::double(0) }
            // Px, Py, b, h, i, j, x, g^2, e^2, 2 * e^2
            { Fq2::add(2, 0) }
            // Px, Py, b, h, i, j, x, g^2, 3 * e^2
            { Fq2::sub(2, 0) }
            // Px, Py, b, h, i, j, x, g^2 - 3 * e^2
    
            // self.z = b * &h;
            // Px, Py, b, h, i, j, x, y
            { Fq2::roll(10) }
            // Px, Py, h, i, j, x, y, b
            { Fq2::roll(10) }
            // Px, Py, i, j, x, y, b, h
            { Fq2::copy(0) }
            // Px, Py, i, j, x, y, b, h, h
            { Fq2::mul(4, 2) }
            // Px, Py, i, j, x, y, h, z
    
            // (-h, j.double() + &j, i)
            // Px, Py, i, j, x, y, h, z
            { Fq2::roll(2) }
            // Px, Py, i, j, x, y, z, h
            { Fq2::neg(0) }
            // Px, Py, i, j, x, y, z, -h
            { Fq2::roll(8) }
            // Px, Py, i, x, y, z, -h, j
            { Fq2::copy(0) }
            // Px, Py, i, x, y, z, -h, j, j
            { Fq2::double(0) }
            // Px, Py, i, x, y, z, -h, j, 2 * j
            { Fq2::add(2, 0) }
            // Px, Py, i, x, y, z, -h, 3 * j
            { Fq2::roll(10) }
            // Px, Py, x, y, z, -h, 3 * j, i
    
        };

        let ate_loop_s4_1 = script! {
            // [T4x, c0, c1, c2, P4, T4]
            { modified_double_line.clone() }
            // [T4x, c0, c1, c2, P4, T4x, c0, c1, c2]
            // compare coeffs
            { Fq2::roll(14) }
            { Fq2::equalverify() }
            { Fq2::roll(12) }
            { Fq2::equalverify() }
            { Fq2::roll(10) }
            { Fq2::equalverify() }
            // [T4x, P4, T4x]
            // compare T4
            { Fq6::toaltstack() }
            { Fq2::drop() }
            { Fq6::fromaltstack() }
            { Fq6::equalverify() }
            OP_TRUE
        };
        scripts_and_inputs.push((ate_loop_s4_1, vec![ScriptInput::InputG2P(t4x), ScriptInput::InputFq2(coeffs.0), ScriptInput::InputFq2(coeffs.1), ScriptInput::InputFq2(coeffs.2), ScriptInput::InputG1A(p4), ScriptInput::InputG2P(t4_1)]));
        t4_1 = t4x;

        let mut fx = f1.clone();

        let mut c0new = coeffs.0;
        c0new.mul_assign_by_fp(&p4.y);

        let mut c1new = coeffs.1;
        c1new.mul_assign_by_fp(&p4.x);

        fx.mul_by_034(&c0new, &c1new, &coeffs.2);

        let ate_loop_s4_2 = script! {
            { Pairing::ell() }
            { Fq12::equalverify() }
            OP_TRUE
        };
        scripts_and_inputs.push((ate_loop_s4_2, vec![ScriptInput::InputFq12(fx), ScriptInput::InputFq12(f1), ScriptInput::InputFq2(coeffs.0), ScriptInput::InputFq2(coeffs.1), ScriptInput::InputFq2(coeffs.2), ScriptInput::InputG1A(p4)]));
        f1 = fx;

        if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
            for j in 0..num_constant {
                let mut fx = f1.clone();
                let coeffs = constant_iters[j].next().unwrap();
    
                let mut c0new = coeffs.0;
                c0new.mul_assign_by_fp(&p_lst[j].y);
    
                let mut c1new = coeffs.1;
                c1new.mul_assign_by_fp(&p_lst[j].x);
    
                fx.mul_by_034(&c0new, &c1new, &coeffs.2);
    
                let ate_loop_s5 = script! {
                    { Pairing::ell_by_constant(coeffs) }
                    { Fq12::equalverify() }
                    OP_TRUE
                };
                scripts_and_inputs.push((ate_loop_s5, vec![ScriptInput::InputFq12(fx), ScriptInput::InputFq12(f1), ScriptInput::InputG1A(p_lst[j])]));
                f1 = fx;
            }

            let mut t4x = t4_1.clone();

            let q4y = if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 {q4.y} else {-q4.y};

            let theta = t4x.y - &(q4y * &t4x.z);
            let lambda = t4x.x - &(q4.x * &t4x.z);
            let c = theta.square();
            let d = lambda.square();
            let e = lambda * &d;
            let f = t4x.z * &c;
            let g = t4x.x * &d;
            let h = e + &f - &g.double();
            t4x.x = lambda * &h;
            t4x.y = theta * &(g - &h) - &(e * &t4x.y);
            t4x.z *= &e;
            let j = theta * &q4.x - &(lambda * &q4y);
            
            let coeffs = (lambda, -theta, j);

            let ate_loop_s6_1 = script! {
                // [T4x, c0, c1, c2, P4, T4, Q4]
                { Pairing::add_line_with_flag(ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1) }
                // [T4x, c0, c1, c2, P4, T4x, c0, c1, c2]
                // compare coeffs
                { Fq2::roll(14) }
                { Fq2::equalverify() }
                { Fq2::roll(12) }
                { Fq2::equalverify() }
                { Fq2::roll(10) }
                { Fq2::equalverify() }
                // [T4x, P4, T4x]
                // compare T4
                { Fq6::toaltstack() }
                { Fq2::drop() }
                { Fq6::fromaltstack() }
                { Fq6::equalverify() }
                OP_TRUE
            };
            scripts_and_inputs.push((ate_loop_s6_1, vec![ScriptInput::InputG2P(t4x), ScriptInput::InputFq2(coeffs.0), ScriptInput::InputFq2(coeffs.1), ScriptInput::InputFq2(coeffs.2), ScriptInput::InputG1A(p4), ScriptInput::InputG2P(t4_1), ScriptInput::InputG2A(q4)]));
            t4_1 = t4x;

            let mut fx = f1.clone();

            let mut c0new = coeffs.0;
            c0new.mul_assign_by_fp(&p4.y);

            let mut c1new = coeffs.1;
            c1new.mul_assign_by_fp(&p4.x);

            fx.mul_by_034(&c0new, &c1new, &coeffs.2);

            let ate_loop_s6_2 = script! {
                { Pairing::ell() }
                { Fq12::equalverify() }
                OP_TRUE
            };
            scripts_and_inputs.push((ate_loop_s6_2, vec![ScriptInput::InputFq12(fx), ScriptInput::InputFq12(f1), ScriptInput::InputFq2(coeffs.0), ScriptInput::InputFq2(coeffs.1), ScriptInput::InputFq2(coeffs.2), ScriptInput::InputG1A(p4)]));
            f1 = fx;
        }

        assert_eq!(f1, f2);
        assert_eq!(t4_1, t4_2);
        // break;
    }

    let mut f = f_vec[ark_bn254::Config::ATE_LOOP_COUNT.len() - 1];
    let c_inv_p = c_inv.frobenius_map(1);

    let quad_miller_s3_1 = script! {
        { Fq12::frobenius_map(1) }
        { Fq12::equalverify() }
        OP_TRUE
    };
    scripts_and_inputs.push((quad_miller_s3_1, vec![ScriptInput::InputFq12(c_inv_p), ScriptInput::InputFq12(c_inv)]));

    let fx = f * c_inv_p;

    let quad_miller_s3_2 = script! {
        { Fq12::mul(12, 0) }
        { Fq12::equalverify() }
        OP_TRUE
    };
    scripts_and_inputs.push((quad_miller_s3_2, vec![ScriptInput::InputFq12(fx), ScriptInput::InputFq12(f), ScriptInput::InputFq12(c_inv_p)]));
    f = fx;

    let c_p2 = c.frobenius_map(2);

    let quad_miller_s3_3 = script! {
        { Fq12::frobenius_map(2) }
        { Fq12::equalverify() }
        OP_TRUE
    };
    scripts_and_inputs.push((quad_miller_s3_3, vec![ScriptInput::InputFq12(c_p2), ScriptInput::InputFq12(c)]));

    let fx = f * c_p2;

    let quad_miller_s3_4 = script! {
        { Fq12::mul(12, 0) }
        { Fq12::equalverify() }
        OP_TRUE
    };
    scripts_and_inputs.push((quad_miller_s3_4, vec![ScriptInput::InputFq12(fx), ScriptInput::InputFq12(f), ScriptInput::InputFq12(c_p2)]));
    f = fx;

    let fx = f * wi;

    let quad_miller_s4 = script! {
        { Fq12::mul(12, 0) }
        { Fq12::equalverify() }
        OP_TRUE
    };
    scripts_and_inputs.push((quad_miller_s4, vec![ScriptInput::InputFq12(fx), ScriptInput::InputFq12(f), ScriptInput::InputFq12(wi)]));
    f = fx;

    for j in 0..num_constant {
        let mut fx = f.clone();
        let coeffs = constant_iters[j].next().unwrap();

        let mut c0new = coeffs.0;
        c0new.mul_assign_by_fp(&p_lst[j].y);

        let mut c1new = coeffs.1;
        c1new.mul_assign_by_fp(&p_lst[j].x);

        fx.mul_by_034(&c0new, &c1new, &coeffs.2);

        let quad_miller_s5_1 = script! {
            { Pairing::ell_by_constant(coeffs) }
            { Fq12::equalverify() }
            OP_TRUE
        };
        scripts_and_inputs.push((quad_miller_s5_1, vec![ScriptInput::InputFq12(fx), ScriptInput::InputFq12(f), ScriptInput::InputG1A(p_lst[j])]));
        f = fx;
    }

    let beta_12x = BigUint::from_str("21575463638280843010398324269430826099269044274347216827212613867836435027261").unwrap();
    let beta_12y = BigUint::from_str("10307601595873709700152284273816112264069230130616436755625194854815875713954").unwrap();
    let beta_12 = ark_bn254::Fq2::from_base_prime_field_elems(&[ark_bn254::Fq::from(beta_12x.clone()), ark_bn254::Fq::from(beta_12y.clone())]).unwrap();

    let beta_13x = BigUint::from_str("2821565182194536844548159561693502659359617185244120367078079554186484126554").unwrap();
    let beta_13y = BigUint::from_str("3505843767911556378687030309984248845540243509899259641013678093033130930403").unwrap();
    let beta_13 = ark_bn254::Fq2::from_base_prime_field_elems(&[ark_bn254::Fq::from(beta_13x.clone()), ark_bn254::Fq::from(beta_13y.clone())]).unwrap();
    
    let mut q4x = q4.x;
    q4x.conjugate_in_place();
    q4x = q4x * beta_12;

    let mut q4y = q4.y;
    q4y.conjugate_in_place();
    q4y = q4y * beta_13;

    let quad_miller_s5_2 = script! {
        { Fq::neg(0) }

        // beta_12
        { Fq::push_dec("21575463638280843010398324269430826099269044274347216827212613867836435027261") }
        { Fq::push_dec("10307601595873709700152284273816112264069230130616436755625194854815875713954") }

        { Fq2::mul(2, 0) }

        { Fq2::equalverify() }

        { Fq::neg(0) }

        // // beta_13
        { Fq::push_dec("2821565182194536844548159561693502659359617185244120367078079554186484126554") }
        { Fq::push_dec("3505843767911556378687030309984248845540243509899259641013678093033130930403") }

        { Fq2::mul(2, 0) }

        { Fq2::equalverify() }

        OP_TRUE
    };
    scripts_and_inputs.push((quad_miller_s5_2, vec![ScriptInput::InputFq2(q4y), ScriptInput::InputFq2(q4.y), ScriptInput::InputFq2(q4x), ScriptInput::InputFq2(q4.x)]));

    let mut t4 = t4_vec[ark_bn254::Config::ATE_LOOP_COUNT.len() - 1];
    let mut t4x = t4.clone();

    let theta = t4x.y - &(q4y * &t4x.z);
    let lambda = t4x.x - &(q4x * &t4x.z);
    let c = theta.square();
    let d = lambda.square();
    let e = lambda * &d;
    let ff = t4x.z * &c;
    let g = t4x.x * &d;
    let h = e + &ff - &g.double();
    t4x.x = lambda * &h;
    t4x.y = theta * &(g - &h) - &(e * &t4x.y);
    t4x.z *= &e;
    let j = theta * &q4x - &(lambda * &q4y);
    
    let coeffs = (lambda, -theta, j);

    let quad_miller_s5_3 = script! {
        // [T4x, c0, c1, c2, P4, T4, Q4]
        { Pairing::add_line_with_flag(true) }
        // [T4x, c0, c1, c2, P4, T4x, c0, c1, c2]
        // compare coeffs
        { Fq2::roll(14) }
        { Fq2::equalverify() }
        { Fq2::roll(12) }
        { Fq2::equalverify() }
        { Fq2::roll(10) }
        { Fq2::equalverify() }
        // [T4x, P4, T4x]
        // compare T4
        { Fq6::toaltstack() }
        { Fq2::drop() }
        { Fq6::fromaltstack() }
        { Fq6::equalverify() }
        OP_TRUE
    };
    scripts_and_inputs.push((quad_miller_s5_3, vec![ScriptInput::InputG2P(t4x), ScriptInput::InputFq2(coeffs.0), ScriptInput::InputFq2(coeffs.1), ScriptInput::InputFq2(coeffs.2), ScriptInput::InputG1A(p4), ScriptInput::InputG2P(t4), ScriptInput::InputFq2(q4x), ScriptInput::InputFq2(q4y)]));
    t4 = t4x;

    let mut fx = f.clone();

    let mut c0new = coeffs.0;
    c0new.mul_assign_by_fp(&p4.y);

    let mut c1new = coeffs.1;
    c1new.mul_assign_by_fp(&p4.x);

    fx.mul_by_034(&c0new, &c1new, &coeffs.2);

    let quad_miller_s5_4 = script! {
        { Pairing::ell() }
        { Fq12::equalverify() }
        OP_TRUE
    };
    scripts_and_inputs.push((quad_miller_s5_4, vec![ScriptInput::InputFq12(fx), ScriptInput::InputFq12(f), ScriptInput::InputFq2(coeffs.0), ScriptInput::InputFq2(coeffs.1), ScriptInput::InputFq2(coeffs.2), ScriptInput::InputG1A(p4)]));
    f = fx;

    for j in 0..num_constant {
        let mut fx = f.clone();
        let coeffs = constant_iters[j].next().unwrap();

        let mut c0new = coeffs.0;
        c0new.mul_assign_by_fp(&p_lst[j].y);

        let mut c1new = coeffs.1;
        c1new.mul_assign_by_fp(&p_lst[j].x);

        fx.mul_by_034(&c0new, &c1new, &coeffs.2);

        let quad_miller_s6_1 = script! {
            { Pairing::ell_by_constant(coeffs) }
            { Fq12::equalverify() }
            OP_TRUE
        };
        scripts_and_inputs.push((quad_miller_s6_1, vec![ScriptInput::InputFq12(fx), ScriptInput::InputFq12(f), ScriptInput::InputG1A(p_lst[j])]));
        f = fx;
    }

    let beta_22x = BigUint::from_str("21888242871839275220042445260109153167277707414472061641714758635765020556616").unwrap();
    let beta_22y = BigUint::from_str("0").unwrap();
    let beta_22 = ark_bn254::Fq2::from_base_prime_field_elems(&[ark_bn254::Fq::from(beta_22x.clone()), ark_bn254::Fq::from(beta_22y.clone())]).unwrap();

    let mut q4x = q4.x;
    q4x.conjugate_in_place();
    q4x = q4x * beta_22;

    let q4y = q4.y;

    let quad_miller_s6_2 = script! {
        { Fq::neg(0) }

        // beta_22
        { Fq::push_dec("21888242871839275220042445260109153167277707414472061641714758635765020556616") }
        { Fq::push_dec("0") }

        { Fq2::mul(2, 0) }

        { Fq2::equalverify() }

        OP_TRUE
    };
    scripts_and_inputs.push((quad_miller_s6_2, vec![ScriptInput::InputFq2(q4x), ScriptInput::InputFq2(q4.x)]));

    let mut t4x = t4.clone();

    let theta = t4x.y - &(q4y * &t4x.z);
    let lambda = t4x.x - &(q4x * &t4x.z);
    let c = theta.square();
    let d = lambda.square();
    let e = lambda * &d;
    let ff = t4x.z * &c;
    let g = t4x.x * &d;
    let h = e + &ff - &g.double();
    t4x.x = lambda * &h;
    t4x.y = theta * &(g - &h) - &(e * &t4x.y);
    t4x.z *= &e;
    let j = theta * &q4x - &(lambda * &q4y);
    
    let coeffs = (lambda, -theta, j);

    let quad_miller_s6_3 = script! {
        // [T4x, c0, c1, c2, P4, T4, Q4]
        { Pairing::add_line_with_flag(true) }
        // [T4x, c0, c1, c2, P4, T4x, c0, c1, c2]
        // compare coeffs
        { Fq2::roll(14) }
        { Fq2::equalverify() }
        { Fq2::roll(12) }
        { Fq2::equalverify() }
        { Fq2::roll(10) }
        { Fq2::equalverify() }
        // [T4x, P4, T4x]
        // compare T4
        { Fq6::toaltstack() }
        { Fq2::drop() }
        { Fq6::fromaltstack() }
        { Fq6::equalverify() }
        OP_TRUE
    };
    scripts_and_inputs.push((quad_miller_s6_3, vec![ScriptInput::InputG2P(t4x), ScriptInput::InputFq2(coeffs.0), ScriptInput::InputFq2(coeffs.1), ScriptInput::InputFq2(coeffs.2), ScriptInput::InputG1A(p4), ScriptInput::InputG2P(t4), ScriptInput::InputFq2(q4x), ScriptInput::InputFq2(q4y)]));
    t4 = t4x;

    let mut fx = f.clone();

    let mut c0new = coeffs.0;
    c0new.mul_assign_by_fp(&p4.y);

    let mut c1new = coeffs.1;
    c1new.mul_assign_by_fp(&p4.x);

    fx.mul_by_034(&c0new, &c1new, &coeffs.2);

    let quad_miller_s6_4 = script! {
        { Pairing::ell() }
        { Fq12::equalverify() }
        OP_TRUE
    };
    scripts_and_inputs.push((quad_miller_s6_4, vec![ScriptInput::InputFq12(fx), ScriptInput::InputFq12(f), ScriptInput::InputFq2(coeffs.0), ScriptInput::InputFq2(coeffs.1), ScriptInput::InputFq2(coeffs.2), ScriptInput::InputG1A(p4)]));
    f = fx;

    // assert_eq!(f, hint);

    for (i, (script, inputs)) in scripts_and_inputs.iter().enumerate() {
        print!("script [{}] ", i);
        assert!(test_script_with_inputs(script.clone(), inputs.to_vec()));
    }
}
