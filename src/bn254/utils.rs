// utils for push fields into stack
use ark_ff::Field;
use num_bigint::BigUint;

use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq, fr::Fr},
    treepp::*,
};

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

#[derive(Clone)]
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
}
