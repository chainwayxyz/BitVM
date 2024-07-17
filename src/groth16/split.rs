use std::str::FromStr;
use std::ops::Mul;
use crate::bn254::curves::G1Projective;
use crate::bn254::ell_coeffs::G2Prepared;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fr::Fr;
use crate::bn254::fq::Fq;
use crate::bn254::fq2::Fq2;
use crate::bn254::fq6::Fq6;
use crate::bn254::fq12::Fq12;
use crate::bn254::utils::{fq12_push, fq2_push, fq6_push};
use crate::groth16::constants::{LAMBDA, P_POW3};
use crate::groth16::offchain_checker::compute_c_wi;
use crate::treepp::{script, Script};
use ark_groth16::{prepare_verifying_key, Proof, VerifyingKey};
use ark_ec::bn::{G1Prepared, BnConfig};
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::{CurveGroup, VariableBaseMSM, Group, AffineRepr};
use ark_ec::pairing::Pairing as ark_Pairing;
use ark_ff::Field;
use num_bigint::BigUint;
use num_traits::One;
use num_traits::Zero;

// script inputs can be Fq12, Fq6, Fq2, Fq, Fr, G1Projective, G1Affine, G2Projective, G2Affine, bit
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
                { Fq::push_u32_le(&BigUint::from(*fq).to_u32_digits()) }
            },
            ScriptInput::Fr(fr) => script! {
                { Fr::push_u32_le(&BigUint::from(*fr).to_u32_digits()) }
            },
            ScriptInput::G1P(g1p) => script! {
                { Fq::push_u32_le(&BigUint::from(g1p.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(g1p.y).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(g1p.z).to_u32_digits()) }
            },
            ScriptInput::G1A(g1a) => script! {
                { Fq::push_u32_le(&BigUint::from(g1a.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(g1a.y).to_u32_digits()) }
            },
            ScriptInput::G2P(g2p) => script! {
                { Fq::push_u32_le(&BigUint::from(g2p.x.c0).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(g2p.x.c1).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(g2p.y.c0).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(g2p.y.c1).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(g2p.z.c0).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(g2p.z.c1).to_u32_digits()) }
            },
            ScriptInput::G2A(g2a) => script! {
                { Fq::push_u32_le(&BigUint::from(g2a.x.c0).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(g2a.x.c1).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(g2a.y.c0).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(g2a.y.c1).to_u32_digits()) }
            },
            ScriptInput::Bit(b) => script! {
                { *b }
            }
        }
    }
}

fn g1_projective_mul_scripts() -> Vec<Script> {
    let mut scripts = Vec::new();

    let script_initial_s1 = script! {
        { Fr::decode_montgomery() }
        { Fr::convert_to_le_bits() }

        for i in (0..Fr::N_BITS).rev() {
            { i + 1 } OP_ROLL OP_EQUALVERIFY
        }

        { G1Projective::roll(2) }
        { G1Projective::roll(2) }
        { G1Projective::add() }
        { G1Projective::equalverify() }
        OP_TRUE
    };
    scripts.push(script_initial_s1);

    let script_initial_s2 = script! {
        { G1Projective::roll(1) }
        { G1Projective::double() }
        { G1Projective::equalverify() }
        OP_TRUE
    };
    scripts.push(script_initial_s2);

    for i in 0..(Fr::N_BITS / 2) {
        let script_loop_1 = script! {
            { G1Projective::double() }
            { G1Projective::double() }
            { G1Projective::equalverify() }
            OP_TRUE
        };
        scripts.push(script_loop_1.clone());

        let script_loop_2 = script! {
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
        scripts.push(script_loop_2.clone());
    }

    scripts
}

fn g1_projective_mul_inputs(g1: ark_bn254::G1Projective, scalar: ark_bn254::Fr, result: ark_bn254::G1Projective) -> Vec<Vec<ScriptInput>> {
    let mut inputs = Vec::new();

    let a = scalar;
    let p = g1;
    let two_p = p + p;
    let three_p = p + p + p;
    let q = p.mul(a);

    assert_eq!(q, result);

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

    let mut inputs_bits = vec![ScriptInput::G1P(p), ScriptInput::G1P(two_p), ScriptInput::G1P(three_p)];
    for b in bits {
        inputs_bits.push(ScriptInput::Bit(*b));
    }
    inputs_bits.push(ScriptInput::Fr(a));
    inputs.push(inputs_bits);

    inputs.push(vec![ScriptInput::G1P(p), ScriptInput::G1P(two_p)]);

    for i in 0..(Fr::N_BITS / 2) {
        let g = g1_projs[i as usize];
        let four_g = g.double().double();

        inputs.push(vec![ScriptInput::G1P(four_g), ScriptInput::G1P(g)]);

        inputs.push(vec![ScriptInput::G1P(g1_projs[i as usize + 1]), ScriptInput::G1P(p), ScriptInput::G1P(two_p), ScriptInput::G1P(three_p), ScriptInput::G1P(four_g), ScriptInput::Bit(bits[2 * i as usize]), ScriptInput::Bit(bits[2 * i as usize + 1])]);
    }

    inputs
}

fn fq12_mul_scripts() -> Vec<Script> {
    let mut scripts = Vec::new();

    // inputs: ax, bx, d
    // checks d=ax*bx
    let script1 = script! {
        { Fq6::mul(6, 0) }
        { Fq6::equalverify() }
        OP_TRUE
    };
    scripts.push(script1);

    // inputs: ay, by, e 
    // checks e=ay*by
    let script2 = script! {
        { Fq6::mul(6, 0) }
        { Fq6::equalverify() }
        OP_TRUE
    };
    scripts.push(script2);

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
    scripts.push(script3);

    scripts
}

fn fq12_mul_inputs(a: ark_bn254::Fq12, b: ark_bn254::Fq12, c: ark_bn254::Fq12) -> Vec<Vec<ScriptInput>> {
    let mut inputs = Vec::new();

    let d = a.c0 * b.c0;

    inputs.push(vec![ScriptInput::Fq6(d), ScriptInput::Fq6(a.c0), ScriptInput::Fq6(b.c0)]);

    let e = a.c1 * b.c1;

    inputs.push(vec![ScriptInput::Fq6(e), ScriptInput::Fq6(a.c1), ScriptInput::Fq6(b.c1)]);

    inputs.push(vec![ScriptInput::Fq6(a.c0), ScriptInput::Fq6(a.c1), ScriptInput::Fq6(b.c0), ScriptInput::Fq6(b.c1), ScriptInput::Fq6(d), ScriptInput::Fq6(e), ScriptInput::Fq12(c)]);

    inputs
}

fn fq12_square_scripts() -> Vec<Script> {
    let mut scripts = Vec::new();

    // let s1 = script! {
    //     // v0 = c0 + c1
    //     { Fq6::copy(6) }
    //     { Fq6::copy(6) }
    //     { Fq6::add(6, 0) }

    //     // v3 = c0 + beta * c1
    //     { Fq6::copy(6) }
    //     { Fq12::mul_fq6_by_nonresidue() }
    //     { Fq6::copy(18) }
    //     { Fq6::add(0, 6) }

    //     // v2 = c0 * c1
    //     { Fq6::mul(12, 18) }

    //     // v0 = v0 * v3
    //     { Fq6::mul(12, 6) }

    //     // final c0 = v0 - (beta + 1) * v2
    //     { Fq6::copy(6) }
    //     { Fq12::mul_fq6_by_nonresidue() }
    //     { Fq6::copy(12) }
    //     { Fq6::add(6, 0) }
    //     { Fq6::sub(6, 0) }

    //     // final c1 = 2 * v2
    //     { Fq6::double(6) }

    //     { Fq12::equalverify() }

    //     OP_TRUE
    // };
    // scripts.push(s1);

    scripts.extend(fq12_mul_scripts());

    scripts
}

fn fq12_square_inputs(a: ark_bn254::Fq12, a2: ark_bn254::Fq12) -> Vec<Vec<ScriptInput>> {
    let mut inputs = Vec::new();

    // inputs.push(vec![ScriptInput::Fq12(a2), ScriptInput::Fq12(a)]);

    inputs.extend(fq12_mul_inputs(a, a, a2));

    inputs
}

fn add_line_with_flag_scripts(flag: bool) -> Vec<Script> {
    let mut scripts = Vec::new();

    let s1 = script! {
        // let theta = self.y - &(q.y * &self.z);
        // theta, lambda, c, d, Tx, Ty, Tz, Qx, Qy
        { Fq2::copy(6) }
        // theta, lambda, c, d, Tx, Ty, Tz, Qx, Qy, Ty
        { Fq2::copy(2) }
        // theta, lambda, c, d, Tx, Ty, Tz, Qx, Qy, Ty, Qy
        if !flag {
            { Fq2::neg(0) }
        // theta, lambda, c, d, Tx, Ty, Tz, Qx, Qy, Ty, -Qy
        }
        { Fq2::copy(8) }
        // theta, lambda, c, d, Tx, Ty, Tz, Qx, Qy, Ty, Qy, Tz
        { Fq2::mul(2, 0) }
        // theta, lambda, c, d, Tx, Ty, Tz, Qx, Qy, Ty, Qy * Tz
        { Fq2::sub(2, 0) }
        // theta, lambda, c, d, Tx, Ty, Tz, Qx, Qy, Ty - Qy * Tz

        // let lambda = self.x - &(q.x * &self.z);
        // theta, lambda, c, d, Tx, Ty, Tz, Qx, Qy, theta
        { Fq2::copy(10) }
        // theta, lambda, c, d, Tx, Ty, Tz, Qx, Qy, theta, Tx
        { Fq2::copy(6) }
        // theta, lambda, c, d, Tx, Ty, Tz, Qx, Qy, theta, Tx, Qx
        { Fq2::copy(10) }
        // theta, lambda, c, d, Tx, Ty, Tz, Qx, Qy, theta, Tx, Qx, Tz
        { Fq2::mul(2, 0) }
        // theta, lambda, c, d, Tx, Ty, Tz, Qx, Qy, theta, Tx, Qx * Tz
        { Fq2::sub(2, 0) }
        // theta, lambda, c, d, Tx, Ty, Tz, Qx, Qy, theta, Tx - Qx * Tz

        // let c = theta.square();
        // theta, lambda, c, d, Tx, Ty, Tz, Qx, Qy, theta, lambda
        { Fq2::copy(2) }
        // theta, lambda, c, d, Tx, Ty, Tz, Qx, Qy, theta, lambda, theta
        { Fq2::square() }
        // theta, lambda, c, d, Tx, Ty, Tz, Qx, Qy, theta, lambda, theta^2

        // let d = lambda.square();
        // theta, lambda, c, d, Tx, Ty, Tz, Qx, Qy, theta, lambda, c
        { Fq2::copy(2) }
        // theta, lambda, c, d, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, lambda
        { Fq2::square() }
        // theta, lambda, c, d, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, lambda^2
        // theta, lambda, c, d, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d
        { Fq2::toaltstack() }
        { Fq2::toaltstack() }
        { Fq2::toaltstack() }
        { Fq2::toaltstack() }
        { Fq2::drop() }
        { Fq2::drop() }
        { Fq2::drop() }
        { Fq2::drop() }
        { Fq2::drop() }
        { Fq2::fromaltstack() }
        { Fq2::roll(8) }
        { Fq2::equalverify() }
        { Fq2::fromaltstack() }
        { Fq2::roll(6) }
        { Fq2::equalverify() }
        { Fq2::fromaltstack() }
        { Fq2::roll(4) }
        { Fq2::equalverify() }
        { Fq2::fromaltstack() }
        { Fq2::equalverify() }
        OP_TRUE
    };
    scripts.push(s1);

    let s2 = script! {
        // let e = lambda * &d;
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d
        { Fq2::copy(4) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d, lambda
        { Fq2::copy(2) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d, lambda, d
        { Fq2::mul(2, 0) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d, lambda * d

        // let f = self.z * &c;
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d, e
        { Fq2::copy(14) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d, e, Tz
        { Fq2::roll(6) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Tx, Ty, Tz, Qx, Qy, theta, lambda, d, e, Tz, c
        { Fq2::mul(2, 0) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Tx, Ty, Tz, Qx, Qy, theta, lambda, d, e, Tz * c

        // let g = self.x * &d;
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Tx, Ty, Tz, Qx, Qy, theta, lambda, d, e, ff
        { Fq2::roll(18) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Ty, Tz, Qx, Qy, theta, lambda, d, e, ff, Tx
        { Fq2::roll(6) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Ty, Tz, Qx, Qy, theta, lambda, e, ff, Tx, d
        { Fq2::mul(2, 0) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Ty, Tz, Qx, Qy, theta, lambda, e, ff, Tx * d

        // let h = e + &f - &g.double();
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Ty, Tz, Qx, Qy, theta, lambda, e, ff, g
        { Fq2::copy(0) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Ty, Tz, Qx, Qy, theta, lambda, e, ff, g, g
        { Fq2::neg(0) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Ty, Tz, Qx, Qy, theta, lambda, e, ff, g, -g
        { Fq2::double(0) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Ty, Tz, Qx, Qy, theta, lambda, e, ff, g, -2g
        { Fq2::roll(4) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Ty, Tz, Qx, Qy, theta, lambda, e, g, -2g, ff
        { Fq2::add(2, 0) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Ty, Tz, Qx, Qy, theta, lambda, e, g, -2g + ff
        { Fq2::copy(4) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Ty, Tz, Qx, Qy, theta, lambda, e, g, -2g + ff, e
        { Fq2::add(2, 0) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Ty, Tz, Qx, Qy, theta, lambda, e, g, -2g + ff + e

        // self.x = lambda * &h;
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Ty, Tz, Qx, Qy, theta, lambda, e, g, h
        { Fq2::copy(0) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Ty, Tz, Qx, Qy, theta, lambda, e, g, h, h
        { Fq2::copy(8) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Ty, Tz, Qx, Qy, theta, lambda, e, g, h, h, lambda
        { Fq2::mul(2, 0) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Ty, Tz, Qx, Qy, theta, lambda, e, g, h, h * lambda

        // self.y = theta * &(g - &h) - &(e * &self.y);
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Ty, Tz, Qx, Qy, theta, lambda, e, g, h, x
        { Fq2::copy(10) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Ty, Tz, Qx, Qy, theta, lambda, e, g, h, x, theta
        { Fq2::roll(6) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Ty, Tz, Qx, Qy, theta, lambda, e, h, x, theta, g
        { Fq2::roll(6) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Ty, Tz, Qx, Qy, theta, lambda, e, x, theta, g, h
        { Fq2::sub(2, 0) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Ty, Tz, Qx, Qy, theta, lambda, e, x, theta, g - h
        { Fq2::mul(2, 0) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Ty, Tz, Qx, Qy, theta, lambda, e, x, theta * (g - h)
        { Fq2::copy(4) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Ty, Tz, Qx, Qy, theta, lambda, e, x, theta * (g - h), e
        { Fq2::roll(18) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Tz, Qx, Qy, theta, lambda, e, x, theta * (g - h), e, Ty
        { Fq2::mul(2, 0) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Tz, Qx, Qy, theta, lambda, e, x, theta * (g - h), e * Ty
        { Fq2::sub(2, 0) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Tz, Qx, Qy, theta, lambda, e, x, theta * (g - h) - e * Ty

        // self.z *= &e;
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Tz, Qx, Qy, theta, lambda, e, x, y
        { Fq2::roll(14) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Qx, Qy, theta, lambda, e, x, y, Tz
        { Fq2::roll(6) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Qx, Qy, theta, lambda, x, y, Tz, e
        { Fq2::mul(2, 0) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Qx, Qy, theta, lambda, x, y, Tz * e

        // let j = theta * &q.x - &(lambda * &q.y);
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Qx, Qy, theta, lambda, x, y, z
        { Fq2::copy(8) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Qx, Qy, theta, lambda, x, y, z, theta
        { Fq2::roll(14) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Qy, theta, lambda, x, y, z, theta, Qx
        { Fq2::mul(2, 0) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Qy, theta, lambda, x, y, z, theta * Qx
        { Fq2::copy(8) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, Qy, theta, lambda, x, y, z, theta * Qx, lambda
        { Fq2::roll(14) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, theta, lambda, x, y, z, theta * Qx, lambda, Qy
        if !flag {
            { Fq2::neg(0) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, theta, lambda, x, y, z, theta * Qx, lambda, -Qy
        }
        { Fq2::mul(2, 0) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, theta, lambda, x, y, z, theta * Qx, lambda * Qy
        { Fq2::sub(2, 0) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, theta, lambda, x, y, z, theta * Qx - lambda * Qy

        // (lambda, -theta, j)
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, theta, lambda, x, y, z, j
        { Fq2::roll(8) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, theta, x, y, z, j, lambda
        { Fq2::roll(10) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, x, y, z, j, lambda, theta
        { Fq2::neg(0) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, x, y, z, j, lambda, -theta
        { Fq2::roll(4) }
        // coeffs.0, coeffs.1, coeffs.2, Txx, Txy, Txz, x, y, z, lambda, -theta, j

        { Fq2::toaltstack() }
        { Fq2::toaltstack() }
        { Fq2::toaltstack() }
        { Fq6::equalverify() }
        { Fq2::fromaltstack() }
        { Fq2::fromaltstack() }
        { Fq2::fromaltstack() }
        { Fq6::equalverify() }
        OP_TRUE
    };
    scripts.push(s2);

    scripts
}

fn add_line_with_flag_inputs(flag: bool, t4: ark_bn254::G2Projective, q4x: ark_bn254::Fq2, q4y: ark_bn254::Fq2) -> Vec<Vec<ScriptInput>> {
    let mut inputs = Vec::new();

    let mut t4x = t4.clone();

    let q4ye = if flag {q4y} else {-q4y};
    let q4xe = q4x;

    let theta = t4x.y - &(q4ye * &t4x.z);
    let lambda = t4x.x - &(q4xe * &t4x.z);
    let c = theta.square();
    let d = lambda.square();
    let e = lambda * &d;
    let f = t4x.z * &c;
    let g = t4x.x * &d;
    let h = e + &f - &g.double();
    t4x.x = lambda * &h;
    t4x.y = theta * &(g - &h) - &(e * &t4x.y);
    t4x.z *= &e;
    let j = theta * &q4xe - &(lambda * &q4ye);
    
    let coeffs = (lambda, -theta, j);

    inputs.push(vec![ScriptInput::Fq2(theta), ScriptInput::Fq2(lambda), ScriptInput::Fq2(c), ScriptInput::Fq2(d), ScriptInput::G2P(t4), ScriptInput::Fq2(q4x), ScriptInput::Fq2(q4y)]);

    inputs.push(vec![ScriptInput::Fq2(coeffs.0), ScriptInput::Fq2(coeffs.1), ScriptInput::Fq2(coeffs.2), ScriptInput::G2P(t4x), ScriptInput::G2P(t4), ScriptInput::Fq2(q4x), ScriptInput::Fq2(q4y), ScriptInput::Fq2(theta), ScriptInput::Fq2(lambda), ScriptInput::Fq2(c), ScriptInput::Fq2(d)]);

    inputs
}

fn ell_by_constant_scripts(c0: ark_bn254::Fq2, c1: ark_bn254::Fq2, c2: ark_bn254::Fq2) -> Vec<Script> {
    let mut scripts = Vec::new();

    let constant = (c0, c1, c2);

    let s1 = script! {
        // [f, px, py]
        // compute the new c0
        // [f, px, py, py]
        { Fq::copy(0) }
        // [f, px, py, py * q1.x1]
        { Fq::mul_by_constant(&constant.0.c0) }
        // [f, px, py * q1.x1, py]
        { Fq::roll(1) }
        // [f, px, py * q1.x1, py * q1.x2]
        { Fq::mul_by_constant(&constant.0.c1) }

        // compute the new c1
        // [f, px, py * q1.x1, py * q1.x2, px]
        { Fq::copy(2) }
        // [f, px, py * q1.x1, py * q1.x2, px * q1.y1]
        { Fq::mul_by_constant(&constant.1.c0) }
        // [f, py * q1.x1, py * q1.x2, px * q1.y1, px]
        { Fq::roll(3) }
        // [f, py * q1.x1, py * q1.x2, px * q1.y1, px * q1.y2]
        { Fq::mul_by_constant(&constant.1.c1) }

        // take p.c0, c0
        { Fq6::roll(10) }
        { Fq2::roll(8) }

        // compute a = p.c0 * c0
        { Fq6::mul_by_fp2() }

        // take p.c1, c3, c4
        { Fq6::roll(8) }
        { Fq2::roll(12) }

        // compute b = p.c1 * (c3, c4)
        { Fq6::mul_by_01_with_1_constant(&constant.2) }

        { Fq6::roll(12) }
        { Fq6::equalverify() }
        { Fq6::equalverify() }
        OP_TRUE
    };
    scripts.push(s1);

    let s2 = script! {
        // [f, px, py]
        // compute the new c0
        // [f, px, py, py]
        { Fq::copy(0) }
        // [f, px, py, py * q1.x1]
        { Fq::mul_by_constant(&constant.0.c0) }
        // [f, px, py * q1.x1, py]
        { Fq::roll(1) }
        // [f, px, py * q1.x1, py * q1.x2]
        { Fq::mul_by_constant(&constant.0.c1) }

        // compute the new c1
        // [f, px, py * q1.x1, py * q1.x2, px]
        { Fq::copy(2) }
        // [f, px, py * q1.x1, py * q1.x2, px * q1.y1]
        { Fq::mul_by_constant(&constant.1.c0) }
        // [f, py * q1.x1, py * q1.x2, px * q1.y1, px]
        { Fq::roll(3) }
        // [f, py * q1.x1, py * q1.x2, px * q1.y1, px * q1.y2]
        { Fq::mul_by_constant(&constant.1.c1) }

        // compute e = p.c0 + p.c1
        { Fq6::add(10, 4) }

        // compute c0 + c3
        { Fq2::add(8, 6) }

        // update e = e * (c0 + c3, c4)
        { Fq6::mul_by_01_with_1_constant(&constant.2) }

        // compute c0 = a + beta * b
        { Fq6::copy(12) }
        { Fq6::copy(12) }
        { Fq12::mul_fq6_by_nonresidue() }
        { Fq6::add(6, 0) }

        // compute a + b
        { Fq6::add(18, 12) }

        // compute final c1 = e - (a + b)
        { Fq6::sub(12, 0) }

        { Fq12::equalverify() }
        OP_TRUE
    };
    scripts.push(s2);

    scripts
}

fn ell_by_constant_inputs(f: ark_bn254::Fq12, c0: ark_bn254::Fq2, c1: ark_bn254::Fq2, c2: ark_bn254::Fq2, p: ark_bn254::G1Affine, f2: ark_bn254::Fq12) -> Vec<Vec<ScriptInput>> {
    let mut inputs = Vec::new();

    let constant = (c0, c1, c2);

    let mut fx = f.clone();

    let mut c0new = constant.0;
    c0new.mul_assign_by_fp(&p.y);

    let mut c1new = constant.1;
    c1new.mul_assign_by_fp(&p.x);

    let (c0u, c3u, c4u) = (c0new, c1new, constant.2);

    let a0 = f.c0.c0 * c0u;
    let a1 = f.c0.c1 * c0u;
    let a2 = f.c0.c2 * c0u;
    let a = ark_bn254::Fq6::new(a0, a1, a2);
    let mut b = f.c1;
    b.mul_by_01(&c3u, &c4u);

    fx.mul_by_034(&c0new, &c1new, &constant.2);

    assert_eq!(fx, f2);

    inputs.push(vec![ScriptInput::Fq6(a), ScriptInput::Fq6(b), ScriptInput::Fq12(f), ScriptInput::G1A(p)]);

    inputs.push(vec![ScriptInput::Fq12(fx), ScriptInput::Fq6(a), ScriptInput::Fq6(b), ScriptInput::Fq12(f), ScriptInput::G1A(p)]);

    inputs
}

fn ell_scripts() -> Vec<Script> {
    let mut scripts = Vec::new();

    let s1 = script! {
        // compute the new c0
        { Fq2::mul_by_fq(6, 0) }

        // compute the new c1
        { Fq2::mul_by_fq(5, 2) }

        // roll c2
        { Fq2::roll(4) }

        // compute the new f
        // input:
        //   p   (12 elements)
        //   c0  (2 elements)
        //   c3  (2 elements)
        //   c4  (2 elements)

        // take p.c0, c0
        { Fq6::roll(12) }
        { Fq2::roll(10) }
        // compute a = p.c0 * c0
        { Fq6::mul_by_fp2() }
        // take p.c1, c3, c4
        { Fq6::roll(10) }
        { Fq2::roll(14) }
        { Fq2::roll(14) }
        // compute b = p.c1 * (c3, c4)
        { Fq6::mul_by_01() }

        { Fq6::roll(12) }
        { Fq6::equalverify() }
        { Fq6::equalverify() }
        OP_TRUE
    };
    scripts.push(s1);

    let s2 = script! {
        // compute the new c0
        { Fq2::mul_by_fq(6, 0) }

        // compute the new c1
        { Fq2::mul_by_fq(5, 2) }

        // roll c2
        { Fq2::roll(4) }

        // compute e = p.c0 + p.c1
        { Fq6::add(12, 6) }

        // compute c0 + c3
        { Fq2::add(10, 8) }

        // roll c4
        { Fq2::roll(8) }

        // update e = e * (c0 + c3, c4)
        { Fq6::mul_by_01() }

        // compute c0 = a + beta * b
        { Fq6::copy(12) }
        { Fq6::copy(12) }
        { Fq12::mul_fq6_by_nonresidue() }
        { Fq6::add(6, 0) }

        // compute a + b
        { Fq6::add(18, 12) }

        // compute final c1 = e - (a + b)
        { Fq6::sub(12, 0) }

        { Fq12::equalverify() }
        OP_TRUE
    };
    scripts.push(s2);

    scripts
}

fn ell_inputs(f: ark_bn254::Fq12, c0: ark_bn254::Fq2, c1: ark_bn254::Fq2, c2: ark_bn254::Fq2, p: ark_bn254::G1Affine, f2: ark_bn254::Fq12) -> Vec<Vec<ScriptInput>> {
    let mut inputs = Vec::new();

    let mut fx = f.clone();

    let mut c0new = c0;
    c0new.mul_assign_by_fp(&p.y);

    let mut c1new = c1;
    c1new.mul_assign_by_fp(&p.x);

    let (c0u, c3u, c4u) = (c0new, c1new, c2);

    let a0 = f.c0.c0 * c0u;
    let a1 = f.c0.c1 * c0u;
    let a2 = f.c0.c2 * c0u;
    let a = ark_bn254::Fq6::new(a0, a1, a2);
    let mut b = f.c1;
    b.mul_by_01(&c3u, &c4u);

    fx.mul_by_034(&c0new, &c1new, &c2);

    assert_eq!(fx, f2);

    inputs.push(vec![ScriptInput::Fq6(a), ScriptInput::Fq6(b), ScriptInput::Fq12(f), ScriptInput::Fq2(c0), ScriptInput::Fq2(c1), ScriptInput::Fq2(c2), ScriptInput::G1A(p)]);

    inputs.push(vec![ScriptInput::Fq12(f2), ScriptInput::Fq6(a), ScriptInput::Fq6(b), ScriptInput::Fq12(f), ScriptInput::Fq2(c0), ScriptInput::Fq2(c1), ScriptInput::Fq2(c2), ScriptInput::G1A(p)]);

    inputs
}

pub fn groth16_scripts(vk: VerifyingKey<ark_bn254::Bn254>) -> Vec<Script> {
    let mut scripts = Vec::new();

    let base1: ark_bn254::G1Projective = vk.gamma_abc_g1[0].into();
    let base2: ark_bn254::G1Projective = vk.gamma_abc_g1[1].into();

    scripts.extend(g1_projective_mul_scripts());

    let msm_addition_script = script! {
        { Fq::push_u32_le(&BigUint::from(base1.x).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(base1.y).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(base1.z).to_u32_digits()) }
        { G1Projective::add() }
        { G1Projective::equalverify() }
        OP_TRUE
    };
    scripts.push(msm_addition_script);

    let pvk = prepare_verifying_key::<ark_bn254::Bn254>(&vk);
    let beta_prepared = (-vk.beta_g2).into();
    let gamma_g2_neg_pc = pvk.gamma_g2_neg_pc.clone().into();
    let delta_g2_neg_pc = pvk.delta_g2_neg_pc.clone().into();

    let q_prepared: Vec<G2Prepared> = [gamma_g2_neg_pc, delta_g2_neg_pc, beta_prepared].to_vec();

    let num_constant = 3;
    let mut constant_iters = vec![q_prepared[0].ell_coeffs.iter(), q_prepared[1].ell_coeffs.iter(), q_prepared[2].ell_coeffs.iter()];

    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        scripts.extend(fq12_square_scripts());

        if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 {
            scripts.extend(fq12_mul_scripts());
        }
        else if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
            scripts.extend(fq12_mul_scripts());
        }

        for j in 0..num_constant {
            let coeffs = constant_iters[j].next().unwrap();

            scripts.extend(ell_by_constant_scripts(coeffs.0, coeffs.1, coeffs.2));
        }

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
        scripts.push(ate_loop_s4_1);

        scripts.extend(ell_scripts());

        if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
            for j in 0..num_constant {
                let coeffs = constant_iters[j].next().unwrap();
    
                scripts.extend(ell_by_constant_scripts(coeffs.0, coeffs.1, coeffs.2));
            }

            scripts.extend(add_line_with_flag_scripts(ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1));

            scripts.extend(ell_scripts());
        }
    }

    let quad_miller_s3_1 = script! {
        { Fq12::frobenius_map(1) }
        { Fq12::equalverify() }
        OP_TRUE
    };
    scripts.push(quad_miller_s3_1);

    scripts.extend(fq12_mul_scripts());

    let quad_miller_s3_3 = script! {
        { Fq12::frobenius_map(2) }
        { Fq12::equalverify() }
        OP_TRUE
    };
    scripts.push(quad_miller_s3_3);

    scripts.extend(fq12_mul_scripts());

    scripts.extend(fq12_mul_scripts());

    for j in 0..num_constant {
        let coeffs = constant_iters[j].next().unwrap();

        scripts.extend(ell_by_constant_scripts(coeffs.0, coeffs.1, coeffs.2));
    }

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
    scripts.push(quad_miller_s5_2);

    scripts.extend(add_line_with_flag_scripts(true));

    scripts.extend(ell_scripts());

    for j in 0..num_constant {
        let coeffs = constant_iters[j].next().unwrap();

        scripts.extend(ell_by_constant_scripts(coeffs.0, coeffs.1, coeffs.2));
    }

    let quad_miller_s6_2 = script! {
        // beta_22
        { Fq::push_dec("21888242871839275220042445260109153167277707414472061641714758635765020556616") }
        { Fq::push_zero() }

        { Fq2::mul(2, 0) }

        { Fq2::equalverify() }

        OP_TRUE
    };
    scripts.push(quad_miller_s6_2);

    scripts.extend(add_line_with_flag_scripts(true));

    scripts.extend(ell_scripts());

    for i in 0..num_constant {
        assert_eq!(constant_iters[i].next(), None);
    }

    scripts
}

pub fn groth16_inputs(proof: Proof<ark_bn254::Bn254>, public: Vec<<ark_bn254::Bn254 as ark_ec::pairing::Pairing>::ScalarField>, vk: VerifyingKey<ark_bn254::Bn254>) -> Vec<Vec<ScriptInput>> {
    let mut inputs = Vec::new();

    // we have only one public input
    assert_eq!(public.len(), 1);
    let public = public[0];

    let msm_g1 = ark_bn254::G1Projective::msm(&vk.gamma_abc_g1, &[<ark_bn254::Bn254 as ark_Pairing>::ScalarField::ONE, public.clone()]).expect("failed to calculate msm");

    let base1: ark_bn254::G1Projective = vk.gamma_abc_g1[0].into();
    let base2: ark_bn254::G1Projective = vk.gamma_abc_g1[1].into();
    let base2_times_public = base2 * public;

    inputs.extend(g1_projective_mul_inputs(base2, public, base2_times_public));

    inputs.push(vec![ScriptInput::G1P(msm_g1), ScriptInput::G1P(base2_times_public)]);

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

        let fx = f1.square();
        inputs.extend(fq12_square_inputs(f1, fx));
        f1 = fx;

        if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 {
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f^2 * c_inv]
            let fx = f1 * c_inv;
            inputs.extend(fq12_mul_inputs(f1, c_inv, fx));
            f1 = fx;
        }
        else if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f^2 * c]
            let fx = f1 * c;
            inputs.extend(fq12_mul_inputs(f1, c, fx));
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

            inputs.extend(ell_by_constant_inputs(f1, coeffs.0, coeffs.1, coeffs.2, p_lst[j], fx));
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

        inputs.push(vec![ScriptInput::G2P(t4x), ScriptInput::Fq2(coeffs.0), ScriptInput::Fq2(coeffs.1), ScriptInput::Fq2(coeffs.2), ScriptInput::G1A(p4), ScriptInput::G2P(t4_1)]);
        t4_1 = t4x;

        let mut fx = f1.clone();

        let mut c0new = coeffs.0;
        c0new.mul_assign_by_fp(&p4.y);

        let mut c1new = coeffs.1;
        c1new.mul_assign_by_fp(&p4.x);

        fx.mul_by_034(&c0new, &c1new, &coeffs.2);

        // inputs.push(vec![ScriptInput::Fq12(fx), ScriptInput::Fq12(f1), ScriptInput::Fq2(coeffs.0), ScriptInput::Fq2(coeffs.1), ScriptInput::Fq2(coeffs.2), ScriptInput::G1A(p4)]);
        inputs.extend(ell_inputs(f1, coeffs.0, coeffs.1, coeffs.2, p4, fx));
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
    
                inputs.extend(ell_by_constant_inputs(f1, coeffs.0, coeffs.1, coeffs.2, p_lst[j], fx));
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

            inputs.extend(add_line_with_flag_inputs(ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1, t4_1, q4.x, q4.y));
            t4_1 = t4x;

            let mut fx = f1.clone();

            let mut c0new = coeffs.0;
            c0new.mul_assign_by_fp(&p4.y);

            let mut c1new = coeffs.1;
            c1new.mul_assign_by_fp(&p4.x);

            fx.mul_by_034(&c0new, &c1new, &coeffs.2);

            // inputs.push(vec![ScriptInput::Fq12(fx), ScriptInput::Fq12(f1), ScriptInput::Fq2(coeffs.0), ScriptInput::Fq2(coeffs.1), ScriptInput::Fq2(coeffs.2), ScriptInput::G1A(p4)]);
            inputs.extend(ell_inputs(f1, coeffs.0, coeffs.1, coeffs.2, p4, fx));
            f1 = fx;
        }

        assert_eq!(f1, f2);
        assert_eq!(t4_1, t4_2);
    }

    let mut f = f_vec[ark_bn254::Config::ATE_LOOP_COUNT.len() - 1];

    let c_inv_p = c_inv.frobenius_map(1);

    inputs.push(vec![ScriptInput::Fq12(c_inv_p), ScriptInput::Fq12(c_inv)]);

    let fx = f * c_inv_p;
    inputs.extend(fq12_mul_inputs(f, c_inv_p, fx));
    f = fx;

    let c_p2 = c.frobenius_map(2);

    inputs.push(vec![ScriptInput::Fq12(c_p2), ScriptInput::Fq12(c)]);

    let fx = f * c_p2;
    inputs.extend(fq12_mul_inputs(f, c_p2, fx));
    f = fx;

    let fx = f * wi;
    inputs.extend(fq12_mul_inputs(f, wi, fx));
    f = fx;

    for j in 0..num_constant {
        let mut fx = f.clone();
        let coeffs = constant_iters[j].next().unwrap();

        let mut c0new = coeffs.0;
        c0new.mul_assign_by_fp(&p_lst[j].y);

        let mut c1new = coeffs.1;
        c1new.mul_assign_by_fp(&p_lst[j].x);

        fx.mul_by_034(&c0new, &c1new, &coeffs.2);

        inputs.extend(ell_by_constant_inputs(f, coeffs.0, coeffs.1, coeffs.2, p_lst[j], fx));
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

    inputs.push(vec![ScriptInput::Fq2(q4y), ScriptInput::Fq2(q4.y), ScriptInput::Fq2(q4x), ScriptInput::Fq2(q4.x)]);

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

    inputs.extend(add_line_with_flag_inputs(true, t4, q4x, q4y));
    t4 = t4x;

    let mut fx = f.clone();

    let mut c0new = coeffs.0;
    c0new.mul_assign_by_fp(&p4.y);

    let mut c1new = coeffs.1;
    c1new.mul_assign_by_fp(&p4.x);

    fx.mul_by_034(&c0new, &c1new, &coeffs.2);

    // inputs.push(vec![ScriptInput::Fq12(fx), ScriptInput::Fq12(f), ScriptInput::Fq2(coeffs.0), ScriptInput::Fq2(coeffs.1), ScriptInput::Fq2(coeffs.2), ScriptInput::G1A(p4)]);
    inputs.extend(ell_inputs(f, coeffs.0, coeffs.1, coeffs.2, p4, fx));
    f = fx;

    for j in 0..num_constant {
        let mut fx = f.clone();
        let coeffs = constant_iters[j].next().unwrap();

        let mut c0new = coeffs.0;
        c0new.mul_assign_by_fp(&p_lst[j].y);

        let mut c1new = coeffs.1;
        c1new.mul_assign_by_fp(&p_lst[j].x);

        fx.mul_by_034(&c0new, &c1new, &coeffs.2);

        inputs.extend(ell_by_constant_inputs(f, coeffs.0, coeffs.1, coeffs.2, p_lst[j], fx));
        f = fx;
    }

    let beta_22x = BigUint::from_str("21888242871839275220042445260109153167277707414472061641714758635765020556616").unwrap();
    let beta_22y = BigUint::ZERO;
    let beta_22 = ark_bn254::Fq2::from_base_prime_field_elems(&[ark_bn254::Fq::from(beta_22x.clone()), ark_bn254::Fq::from(beta_22y.clone())]).unwrap();

    let mut q4x = q4.x;
    q4x = q4x * beta_22;

    let q4y = q4.y;

    inputs.push(vec![ScriptInput::Fq2(q4x), ScriptInput::Fq2(q4.x)]);

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

    inputs.extend(add_line_with_flag_inputs(true, t4, q4x, q4y));
    t4 = t4x;

    let mut fx = f.clone();

    let mut c0new = coeffs.0;
    c0new.mul_assign_by_fp(&p4.y);

    let mut c1new = coeffs.1;
    c1new.mul_assign_by_fp(&p4.x);

    fx.mul_by_034(&c0new, &c1new, &coeffs.2);

    // inputs.push(vec![ScriptInput::Fq12(fx), ScriptInput::Fq12(f), ScriptInput::Fq2(coeffs.0), ScriptInput::Fq2(coeffs.1), ScriptInput::Fq2(coeffs.2), ScriptInput::G1A(p4)]);
    inputs.extend(ell_inputs(f, coeffs.0, coeffs.1, coeffs.2, p4, fx));
    f = fx;

    assert_eq!(f, hint);

    for i in 0..num_constant {
        assert_eq!(constant_iters[i].next(), None);
    }

    inputs
}

#[cfg(test)]
mod tests {
    use std::iter::zip;
    use std::str::FromStr;
    use std::io::BufReader;
    use crate::execute_script_without_stack_limit;
    use crate::groth16::split::{groth16_inputs, groth16_scripts, ScriptInput};
    use crate::treepp::{script, Script};
    use ark_groth16::{Proof, VerifyingKey};
    use ark_ec::CurveGroup;
    use ark_std::{end_timer, start_timer};
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

        let scripts = groth16_scripts(groth16_data.vk.clone());
        let inputs = groth16_inputs(groth16_data.proof, groth16_data.public, groth16_data.vk);
        let n = scripts.len();

        assert_eq!(scripts.len(), inputs.len());

        let mut script_sizes = Vec::new();
        let mut max_stack_sizes = Vec::new();

        for (i, (script, input)) in zip(scripts, inputs).enumerate() {
            let (result, script_size, max_stack_size) = test_script_with_inputs(script.clone(), input.to_vec());
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
}
