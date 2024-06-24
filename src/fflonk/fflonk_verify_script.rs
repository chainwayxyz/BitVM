use crate::bn254::curves::G1Affine;
use crate::bn254::curves::G1Projective;
use crate::bn254::ell_coeffs::G2Prepared;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq12::Fq12;
use crate::bn254::fr::Fr;
use crate::bn254::pairing::Pairing;

use crate::hash::blake3::blake3_var_length;
use crate::treepp::*;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing as ArkPairing;
use ark_ec::CurveGroup;
use ark_ff::{Field, One};
use ark_std::UniformRand;
use num_bigint::BigUint;
use num_traits::{Num, ToPrimitive};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::str::FromStr;
use serde::Deserialize;
use serde::Serialize;
use std::ops::Rem;
use std::ops::Mul;
use num_traits::Pow;

#[derive(Serialize, Deserialize, Debug)]
pub struct Polynomials {
    pub C1: Vec<String>,
    pub C2: Vec<String>,
    pub W1: Vec<String>,
    pub W2: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Evaluations {
    pub ql: String,
    pub qr: String,
    pub qm: String,
    pub qo: String,
    pub qc: String,
    pub s1: String,
    pub s2: String,
    pub s3: String,
    pub a: String,
    pub b: String,
    pub c: String,
    pub z: String,
    pub zw: String,
    pub t1w: String,
    pub t2w: String,
    pub inv: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Proof {
    pub polynomials: Polynomials,
    pub evaluations: Evaluations,
    pub protocol: String,
    pub curve: String,
}

pub type PublicInputs = Vec<String>;

#[derive(Serialize, Deserialize, Debug)]
pub struct VerificationKey {
    pub protocol: String,
    pub curve: String,
    pub nPublic: u32,
    pub power: u32,
    pub k1: String,
    pub k2: String,
    pub w: String,
    pub w3: String,
    pub w4: String,
    pub w8: String,
    pub wr: String,
    pub X_2: Vec<Vec<String>>,
    pub C0: Vec<String>,
}

pub fn push_proof(proof: Proof) -> Script {
    script! {
        { G1Projective::push_vec(proof.polynomials.C1) }
        { G1Projective::push_vec(proof.polynomials.C2) }
        { G1Projective::push_vec(proof.polynomials.W1) }
        { G1Projective::push_vec(proof.polynomials.W2) }
        { Fr::push_dec(&proof.evaluations.ql) }
        { Fr::push_dec(&proof.evaluations.qr) }
        { Fr::push_dec(&proof.evaluations.qm) }
        { Fr::push_dec(&proof.evaluations.qo) }
        { Fr::push_dec(&proof.evaluations.qc) }
        { Fr::push_dec(&proof.evaluations.s1) }
        { Fr::push_dec(&proof.evaluations.s2) }
        { Fr::push_dec(&proof.evaluations.s3) }
        { Fr::push_dec(&proof.evaluations.a) }
        { Fr::push_dec(&proof.evaluations.b) }
        { Fr::push_dec(&proof.evaluations.c) }
        { Fr::push_dec(&proof.evaluations.z) }
        { Fr::push_dec(&proof.evaluations.zw) }
        { Fr::push_dec(&proof.evaluations.t1w) }
        { Fr::push_dec(&proof.evaluations.t2w) }
        { Fr::push_dec(&proof.evaluations.inv) }
    }
}

pub fn push_vk(vk: VerificationKey) -> Script {
    script! {
        { G1Projective::push_vec(vk.C0) }
        { Fr::push_dec(&vk.w) }
        { Fr::push_dec(&vk.w3) }
        { Fr::push_dec(&vk.w4) }
        { Fr::push_dec(&vk.w8) }
        { Fr::push_dec(&vk.wr) }
    }
}

pub fn push_public(public: PublicInputs) -> Script {
    script! {
        for public_input in public {
            { Fq::push_dec(&public_input) } 
        }
    }
}

pub fn fflonk_verify_all(public: PublicInputs, vk: VerificationKey, proof: Proof) -> Script {
    script! {
        { push_vk(vk) }
        { push_public(public) }
        { push_proof(proof) }

        // C0
        { Fq::copy(37) }
        { Fq::copy(36 + 1) }

        // public
        { Fq::copy(29 + 2) }
        { Fq::copy(28 + 3) }

        // C1
        { Fq::copy(27 + 4) }
        { Fq::copy(26 + 5) }

        // send C0 to altstack
        { Fq::roll(4) } { Fq::toaltstack() }
        { Fq::roll(4) } { Fq::toaltstack() }

        // send the public input to altstack
        { Fq::roll(3) } { Fq::toaltstack() }
        { Fq::roll(2) } { Fq::toaltstack() }

        // convert C1 into bytes
        { G1Affine::convert_to_compressed() }

        // convert the public input into bytes
        { Fq::fromaltstack() } { Fq::convert_to_be_bytes() }
        { Fq::fromaltstack() } { Fq::convert_to_be_bytes() }

        // convert C0 into bytes
        { Fq::fromaltstack() } { Fq::fromaltstack() }
        { G1Affine::convert_to_compressed() }

        // beta
        { blake3_var_length(128) }
        { Fr::from_hash() }

        // copy beta
        { Fr::copy(0) }
        { Fr::convert_to_be_bytes() }

        // gamma
        { blake3_var_length(32) }
        { Fr::from_hash() }

        // copy gamma
        { Fr::copy(0) }

        // C2
        { Fq::copy(24 + 3) }
        { Fq::copy(23 + 4) }

        // xiseed
        { Fr::roll(2) }
        { Fr::toaltstack() }
        { G1Affine::convert_to_compressed() }
        { Fr::fromaltstack() }
        { Fr::convert_to_be_bytes() }
        { blake3_var_length(64) }
        { Fr::from_hash() }

        // copy xiseed
        { Fr::copy(0) }

        // alpha
        { Fr::copy(15 + 4) }
        { Fr::copy(14 + 5) }
        { Fr::copy(13 + 6) }
        { Fr::copy(12 + 7) }
        { Fr::copy(11 + 8) }
        { Fr::copy(10 + 9) }
        { Fr::copy(9 + 10) }
        { Fr::copy(8 + 11) }
        { Fr::copy(7 + 12) }
        { Fr::copy(6 + 13) }
        { Fr::copy(5 + 14) }
        { Fr::copy(4 + 15) }
        { Fr::copy(3 + 16) }
        { Fr::copy(2 + 17) }
        { Fr::copy(1 + 18) }
        for i in 1..16 {
            { Fr::roll(16 - i) } { Fr::toaltstack() }
        }
        { Fr::convert_to_be_bytes() }
        for _ in 0..15 {
            { Fr::fromaltstack() } { Fr::convert_to_be_bytes() }
        }
        { blake3_var_length(512) }
        { Fr::from_hash() }

        // copy alpha
        { Fr::copy(0) }

        // copy W2
        { Fq::copy(21 + 5) }
        { Fq::copy(20 + 6) }

        // y
        { Fr::roll(2) }
        { Fr::toaltstack() }
        { G1Affine::convert_to_compressed() }
        { Fr::fromaltstack() }
        { Fr::convert_to_be_bytes() }
        { blake3_var_length(64) }
        { Fr::from_hash() }

    }
}

pub fn fflonk_verify() -> Script {
    script! {

    }
}
