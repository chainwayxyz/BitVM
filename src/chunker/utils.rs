use ark_ff::Field;
use num_bigint::BigUint;

use crate::bn254::{fp254impl::Fp254Impl, fq::Fq, fr::Fr};
use crate::treepp::*;

use num_traits::Num;
use std::ops::{Mul, Rem};

use ark_ec::CurveGroup;
use ark_groth16::{Proof, VerifyingKey};
use std::str::FromStr;
use std::io::BufReader;
use serde_json::Value;

use num_traits::Zero;

pub fn biguint_to_digits<const D: u32, const DIGIT_COUNT: usize>(mut number: BigUint) -> [u8; DIGIT_COUNT] {
    let mut digits: [u8; DIGIT_COUNT] = [0; DIGIT_COUNT];
    for i in 0..DIGIT_COUNT {
        let digit = number.clone() % (D + 1);
        number = (number - digit.clone()) / (D + 1);
        if digit.is_zero() {
            digits[i] = 0;
        } else {
            digits[i] = digit.to_u32_digits()[0] as u8;
        }
    }
    digits
}

pub fn fr_push(element: ark_bn254::Fr) -> Script {
    script! {
        { Fr::push_u32_le(&BigUint::from(element).to_u32_digits()) }
    }
}

pub fn fq_push(element: ark_bn254::Fq) -> Script {
    script! {
        { Fq::push_u32_le(&BigUint::from(element).to_u32_digits()) }
    }
}

pub fn fq2_push(element: ark_bn254::Fq2) -> Script {
    script! {
        { Fq::push_u32_le(&BigUint::from(element.c0).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(element.c1).to_u32_digits()) }
    }
}

pub fn fq6_push(element: ark_bn254::Fq6) -> Script {
    script! {
        for elem in element.to_base_prime_field_elements() {
            { Fq::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
       }
    }
}

pub fn fq12_push(element: ark_bn254::Fq12) -> Script {
    script! {
        for elem in element.to_base_prime_field_elements() {
            { Fq::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
       }
    }
}

pub fn g1p_push(element: ark_bn254::G1Projective) -> Script {
    script! {
        { Fq::push_u32_le(&BigUint::from(element.x).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(element.y).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(element.z).to_u32_digits()) }
    }
}

pub fn g1a_push(element: ark_bn254::G1Affine) -> Script {
    script! {
        { Fq::push_u32_le(&BigUint::from(element.x).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(element.y).to_u32_digits()) }
    }
}

pub fn g2p_push(element: ark_bn254::G2Projective) -> Script {
    script! {
        { Fq::push_u32_le(&BigUint::from(element.x.c0).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(element.x.c1).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(element.y.c0).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(element.y.c1).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(element.z.c0).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(element.z.c1).to_u32_digits()) }
    }
}

pub fn g2a_push(element: ark_bn254::G2Affine) -> Script {
    script! {
        { Fq::push_u32_le(&BigUint::from(element.x.c0).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(element.x.c1).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(element.y.c0).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(element.y.c1).to_u32_digits()) }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum ScriptInput {
    Fq12(ark_bn254::Fq12),
    Fq6(ark_bn254::Fq6),
    Fq2(ark_bn254::Fq2),
    Fq(ark_bn254::Fq),
    Fr(ark_bn254::Fr),
    G1P(ark_bn254::G1Projective),
    G1A(ark_bn254::G1Affine),
    G2P(ark_bn254::G2Projective),
    G2A(ark_bn254::G2Affine),
    Bit(usize, String),
}

impl ScriptInput {
    pub fn push(&self) -> Script {
        match self {
            ScriptInput::Fq12(fq12) => script! {
                { fq12_push(*fq12) }
            },
            ScriptInput::Fq6(fq6) => script! {
                { fq6_push(*fq6) }
            },
            ScriptInput::Fq2(fq2) => script! {
                { fq2_push(*fq2) }
            },
            ScriptInput::Fq(fq) => script! {
                { fq_push(*fq) }
            },
            ScriptInput::Fr(fr) => script! {
                { fr_push(*fr) }
            },
            ScriptInput::G1P(g1p) => script! {
                { g1p_push(*g1p) }
            },
            ScriptInput::G1A(g1a) => script! {
                { g1a_push(*g1a) }
            },
            ScriptInput::G2P(g2p) => script! {
                { g2p_push(*g2p) }
            },
            ScriptInput::G2A(g2a) => script! {
                { g2a_push(*g2a) }
            },
            ScriptInput::Bit(b, _) => script! {
                { *b }
            }
        }
    }
    
    pub fn size(&self) -> usize {
        match self {
            ScriptInput::Fq12(_fq12) => 12,
            ScriptInput::Fq6(_fq6) => 6,
            ScriptInput::Fq2(_fq2) => 2,
            ScriptInput::Fq(_fq) => 1,
            ScriptInput::Fr(_fr) => 1,
            ScriptInput::G1P(_g1p) => 3,
            ScriptInput::G1A(_g1a) => 2,
            ScriptInput::G2P(_g2p) => 6,
            ScriptInput::G2A(_g2a) => 4,
            ScriptInput::Bit(_b, _) => 0
        }
    }

    pub fn to_digits<const D: u32, const DIGIT_COUNT: usize>(&self) -> Vec<[u8; DIGIT_COUNT]> {
        let r = BigUint::from_str_radix(Fq::MONTGOMERY_ONE, 16).unwrap();
        let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();
        match self {
            ScriptInput::Fq12(fq12) => fq12.to_base_prime_field_elements().into_iter().map(|fq| {biguint_to_digits::<D, DIGIT_COUNT>(BigUint::from(fq).mul(r.clone()).rem(p.clone()))}).collect::<Vec<[u8; DIGIT_COUNT]>>(),
            ScriptInput::Fq6(fq6) => fq6.to_base_prime_field_elements().into_iter().map(|fq| {biguint_to_digits::<D, DIGIT_COUNT>(BigUint::from(fq).mul(r.clone()).rem(p.clone()))}).collect::<Vec<[u8; DIGIT_COUNT]>>(),
            ScriptInput::Fq2(fq2) => fq2.to_base_prime_field_elements().into_iter().map(|fq| {biguint_to_digits::<D, DIGIT_COUNT>(BigUint::from(fq).mul(r.clone()).rem(p.clone()))}).collect::<Vec<[u8; DIGIT_COUNT]>>(),
            ScriptInput::Fq(fq) => vec![biguint_to_digits::<D, DIGIT_COUNT>(BigUint::from(*fq).mul(r.clone()).rem(p.clone()))],
            ScriptInput::Fr(_fr) => vec![],
            ScriptInput::G1P(g1p) => vec![biguint_to_digits::<D, DIGIT_COUNT>(BigUint::from(g1p.x).mul(r.clone()).rem(p.clone())), biguint_to_digits::<D, DIGIT_COUNT>(BigUint::from(g1p.y).mul(r.clone()).rem(p.clone())), biguint_to_digits::<D, DIGIT_COUNT>(BigUint::from(g1p.z).mul(r.clone()).rem(p.clone()))],
            ScriptInput::G1A(g1a) => vec![biguint_to_digits::<D, DIGIT_COUNT>(BigUint::from(g1a.x).mul(r.clone()).rem(p.clone())), biguint_to_digits::<D, DIGIT_COUNT>(BigUint::from(g1a.y).mul(r.clone()).rem(p.clone()))],
            ScriptInput::G2P(g2p) => vec![biguint_to_digits::<D, DIGIT_COUNT>(BigUint::from(g2p.x.c0).mul(r.clone()).rem(p.clone())), biguint_to_digits::<D, DIGIT_COUNT>(BigUint::from(g2p.x.c1).mul(r.clone()).rem(p.clone())), biguint_to_digits::<D, DIGIT_COUNT>(BigUint::from(g2p.y.c0).mul(r.clone()).rem(p.clone())), biguint_to_digits::<D, DIGIT_COUNT>(BigUint::from(g2p.y.c1).mul(r.clone()).rem(p.clone())), biguint_to_digits::<D, DIGIT_COUNT>(BigUint::from(g2p.z.c0).mul(r.clone()).rem(p.clone())), biguint_to_digits::<D, DIGIT_COUNT>(BigUint::from(g2p.z.c1).mul(r.clone()).rem(p.clone()))],
            ScriptInput::G2A(g2a) => vec![biguint_to_digits::<D, DIGIT_COUNT>(BigUint::from(g2a.x.c0).mul(r.clone()).rem(p.clone())), biguint_to_digits::<D, DIGIT_COUNT>(BigUint::from(g2a.x.c1).mul(r.clone()).rem(p.clone())), biguint_to_digits::<D, DIGIT_COUNT>(BigUint::from(g2a.y.c0).mul(r.clone()).rem(p.clone())), biguint_to_digits::<D, DIGIT_COUNT>(BigUint::from(g2a.y.c1).mul(r.clone()).rem(p.clone()))],
            ScriptInput::Bit(_b, _) => vec![]
        }
    }

    pub fn to_fq(&self) -> Vec<ark_bn254::Fq> {
        match self {
            ScriptInput::Fq12(fq12) => fq12.to_base_prime_field_elements().collect(),
            ScriptInput::Fq6(fq6) => fq6.to_base_prime_field_elements().collect(),
            ScriptInput::Fq2(fq2) => fq2.to_base_prime_field_elements().collect(),
            ScriptInput::Fq(fq) => vec![*fq],
            ScriptInput::Fr(_fr) => vec![],
            ScriptInput::G1P(g1p) => vec![g1p.x, g1p.y, g1p.z],
            ScriptInput::G1A(g1a) => vec![g1a.x, g1a.y],
            ScriptInput::G2P(g2p) => vec![g2p.x.c0, g2p.x.c1, g2p.y.c0, g2p.y.c1, g2p.z.c0, g2p.z.c1],
            ScriptInput::G2A(g2a) => vec![g2a.x.c0, g2a.x.c1, g2a.y.c0, g2a.y.c1],
            ScriptInput::Bit(_b, _) => vec![]
        }
    }

    pub fn sign(&self) -> Vec<ark_bn254::Fq> {
        match self {
            ScriptInput::Fq12(fq12) => fq12.to_base_prime_field_elements().collect(),
            ScriptInput::Fq6(fq6) => fq6.to_base_prime_field_elements().collect(),
            ScriptInput::Fq2(fq2) => fq2.to_base_prime_field_elements().collect(),
            ScriptInput::Fq(fq) => vec![*fq],
            ScriptInput::Fr(_fr) => vec![],
            ScriptInput::G1P(g1p) => vec![g1p.x, g1p.y, g1p.z],
            ScriptInput::G1A(g1a) => vec![g1a.x, g1a.y],
            ScriptInput::G2P(g2p) => vec![g2p.x.c0, g2p.x.c1, g2p.y.c0, g2p.y.c1, g2p.z.c0, g2p.z.c1],
            ScriptInput::G2A(g2a) => vec![g2a.x.c0, g2a.x.c1, g2a.y.c0, g2a.y.c1],
            ScriptInput::Bit(_b, _) => vec![]
        }
    }
}

pub struct Groth16Data {
    pub proof: Proof<ark_bn254::Bn254>,
    pub public: Vec<<ark_bn254::Bn254 as ark_ec::pairing::Pairing>::ScalarField>,
    pub vk: VerifyingKey<ark_bn254::Bn254>
}

impl Groth16Data {
    pub fn new(proof_filename: &str, public_filename: &str, vk_filename: &str) -> Self {
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
