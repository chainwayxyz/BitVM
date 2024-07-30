// utils for push fields into stack
use ark_ff::Field;
use num_bigint::BigUint;

use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq, fr::Fr},
    treepp::*,
};

use num_traits::Num;
use std::ops::{Mul, Rem};

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

fn u254_to_digits(a: BigUint) -> [u8; 64] {
    let mut digits = [0_u8; 64];
    for (i, byte) in a.to_bytes_le().iter().enumerate() {
        let (x, y) = (byte % 16, byte / 16);
        digits[2 * i] = x;
        digits[2 * i + 1] = y;
    }
    digits
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
    Bit(usize),
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
            ScriptInput::Bit(b) => script! {
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
            ScriptInput::Bit(_b) => 0
        }
    }

    pub fn to_digits(&self) -> Vec<[u8; 64]> {
        let r = BigUint::from_str_radix(Fq::MONTGOMERY_ONE, 16).unwrap();
        let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();
        match self {
            ScriptInput::Fq12(fq12) => fq12.to_base_prime_field_elements().into_iter().map(|fq| {u254_to_digits(BigUint::from(fq).mul(r.clone()).rem(p.clone()))}).collect::<Vec<[u8; 64]>>(),
            ScriptInput::Fq6(fq6) => fq6.to_base_prime_field_elements().into_iter().map(|fq| {u254_to_digits(BigUint::from(fq).mul(r.clone()).rem(p.clone()))}).collect::<Vec<[u8; 64]>>(),
            ScriptInput::Fq2(fq2) => fq2.to_base_prime_field_elements().into_iter().map(|fq| {u254_to_digits(BigUint::from(fq).mul(r.clone()).rem(p.clone()))}).collect::<Vec<[u8; 64]>>(),
            ScriptInput::Fq(fq) => vec![u254_to_digits(BigUint::from(*fq).mul(r.clone()).rem(p.clone()))],
            ScriptInput::Fr(_fr) => vec![],
            ScriptInput::G1P(g1p) => vec![u254_to_digits(BigUint::from(g1p.x).mul(r.clone()).rem(p.clone())), u254_to_digits(BigUint::from(g1p.y).mul(r.clone()).rem(p.clone())), u254_to_digits(BigUint::from(g1p.z).mul(r.clone()).rem(p.clone()))],
            ScriptInput::G1A(g1a) => vec![u254_to_digits(BigUint::from(g1a.x).mul(r.clone()).rem(p.clone())), u254_to_digits(BigUint::from(g1a.y).mul(r.clone()).rem(p.clone()))],
            ScriptInput::G2P(g2p) => vec![u254_to_digits(BigUint::from(g2p.x.c0).mul(r.clone()).rem(p.clone())), u254_to_digits(BigUint::from(g2p.x.c1).mul(r.clone()).rem(p.clone())), u254_to_digits(BigUint::from(g2p.y.c0).mul(r.clone()).rem(p.clone())), u254_to_digits(BigUint::from(g2p.y.c1).mul(r.clone()).rem(p.clone())), u254_to_digits(BigUint::from(g2p.z.c0).mul(r.clone()).rem(p.clone())), u254_to_digits(BigUint::from(g2p.z.c1).mul(r.clone()).rem(p.clone()))],
            ScriptInput::G2A(g2a) => vec![u254_to_digits(BigUint::from(g2a.x.c0).mul(r.clone()).rem(p.clone())), u254_to_digits(BigUint::from(g2a.x.c1).mul(r.clone()).rem(p.clone())), u254_to_digits(BigUint::from(g2a.y.c0).mul(r.clone()).rem(p.clone())), u254_to_digits(BigUint::from(g2a.y.c1).mul(r.clone()).rem(p.clone()))],
            ScriptInput::Bit(_b) => vec![]
        }
    }
}
