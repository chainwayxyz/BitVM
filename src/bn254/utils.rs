// utils for push fields into stack
use crate::bn254::ell_coeffs::EllCoeff;
use crate::bn254::ell_coeffs::G2Prepared;
use crate::bn254::fq6::Fq6;
use crate::bn254::{fq12::Fq12, fq2::Fq2};
use crate::groth16::utils::ScriptInput;
use ark_bn254::Fq12Config;
use ark_ec::{bn::BnConfig, AffineRepr};
use ark_ff::Field;
use ark_ff::Fp12Config;
use num_bigint::BigUint;
use num_traits::Zero;

use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};

// pub fn u254_to_digits<const D: u32, const DIGIT_COUNT: usize>(a: BigUint) -> [u8; DIGIT_COUNT] {
//     let mut digits = [0_u8; DIGIT_COUNT];
//     for (i, byte) in a.to_bytes_le().iter().enumerate() {
//         let (x, y) = (byte % 16, byte / 16);
//         digits[2 * i] = x;
//         digits[2 * i + 1] = y;
//     }
//     digits
// }

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

// input:
//  f            12 elements
//  coeffs.c0    2 elements
//  coeffs.c1    2 elements
//  coeffs.c2    2 elements
//  p.x          1 element
//  p.y          1 element
//
// output:
//  new f        12 elements
pub fn ell() -> Script {
    script! {
        // compute the new c0
        { Fq2::mul_by_fq(6, 0) }

        // compute the new c1
        { Fq2::mul_by_fq(5, 2) }

        // roll c2
        { Fq2::roll(4) }

        // compute the new f
        { Fq12::mul_by_034() }
    }
}

// input:
//  f            12 elements
//  p.x          1 element
//  p.y          1 element
//
// output:
//  new f        12 elements
pub fn ell_by_constant(constant: &EllCoeff) -> Script {
    script! {
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

        // compute the new f
        // [f, py * q1.x1, py * q1.x2, px * q1.y1, px * q1.y2]
        { Fq12::mul_by_034_with_4_constant(&constant.2) }
    }
}

// stack input:
//  f            12 elements
//  x': -p.x / p.y   1 element
//  y': 1 / p.y      1 element
// func params:
//  (c0, c1, c2) where c0 is a trival value ONE in affine mode
//
// output:
//  new f        12 elements
pub fn ell_by_constant_affine(constant: &EllCoeff) -> Script {
    assert_eq!(constant.0, ark_bn254::Fq2::ONE);
    script! {
        // [f, x', y']
        // update c1, c1' = x' * c1
        { Fq::copy(1) }
        { Fq::mul_by_constant(&constant.1.c0) }
        // [f, x', y', x' * c1.0]
        { Fq::roll(2) }
        { Fq::mul_by_constant(&constant.1.c1) }
        // [f, y', x' * c1.0, x' * c1.1]
        // [f, y', x' * c1]

        // update c2, c2' = -y' * c2
        { Fq::copy(2) }
        { Fq::mul_by_constant(&constant.2.c0) }
        // [f, y', x' * c1, y' * c2.0]
        { Fq::roll(3) }
        { Fq::mul_by_constant(&constant.2.c1) }
        // [f, x' * c1, y' * c2.0, y' * c2.1]
        // [f, x' * c1, y' * c2]
        // [f, c1', c2']

        // compute the new f with c1'(c3) and c2'(c4), where c1 is trival value 1
        { Fq12::mul_by_34() }
        // [f]
    }
}

// stack input:
//  f            12 elements
//  x': -p.x / p.y   1 element
//  y': 1 / p.y      1 element
// func params:
//  (c0, c1, c2) where c0 is a trival value ONE in affine mode
//
// output:
//  new f        12 elements
pub fn ell_by_constant_affine_verify(f: ark_bn254::Fq12, x: ark_bn254::Fq, y: ark_bn254::Fq, constant: &EllCoeff, f_new: ark_bn254::Fq12) -> (Vec<Script>, Vec<Vec<ScriptInput>>) {
    let (mut scripts, mut inputs) = (Vec::new(), Vec::new());
    
    assert_eq!(constant.0, ark_bn254::Fq2::ONE);

    let c0 = constant.0;
    let mut c3 = constant.1;
    let mut c4 = constant.2;

    c3.mul_assign_by_fp(&x);
    c4.mul_assign_by_fp(&y);


    let a0 = f.c0.c0 * c0;
    let a1 = f.c0.c1 * c0;
    let a2 = f.c0.c2 * c0;
    let a = ark_bn254::Fq6::new(a0, a1, a2);
    let mut b = f.c1;
    b.mul_by_01(&c3, &c4);

    let cc0 = c0 + c3;
    let cc1 = c4;
    let mut e = f.c0 + &f.c1;
    e.mul_by_01(&cc0, &cc1);

    let mut fx: ark_ff::QuadExtField<ark_ff::Fp12ConfigWrapper<ark_bn254::Fq12Config>> = f.clone();
    fx.c1 = e - &(a + &b);
    fx.c0 = b;
    Fq12Config::mul_fp6_by_nonresidue_in_place(&mut fx.c0);
    fx.c0 += &a;

    assert_eq!(fx, f_new);

    // inputs [fx.c0, f.c0, b, f.c1, y, x]
    // verified: [fx.c0, b]
    let script1 = script! {
        // fx.c0, f.c0, b, f.c1, y, x
        { Fq::copy(0) }
        { Fq::mul_by_constant(&constant.1.c0) }
        { Fq::roll(1) }
        { Fq::mul_by_constant(&constant.1.c1) }
        // fx.c0, f.c0, b, f.c1, y, c3

        { Fq::copy(2) }
        { Fq::mul_by_constant(&constant.2.c0) }
        { Fq::roll(3) }
        { Fq::mul_by_constant(&constant.2.c1) }
        // fx.c0, f.c0, b, f.c1, c3, c4

        { Fq6::mul_by_01() }
        { Fq6::copy(6) }
        { Fq6::equalverify() }
        // fx.c0, f.c0, b

        { Fq12::mul_fq6_by_nonresidue() }
        { Fq6::add(6, 0) }
        { Fq6::equalverify() }

        OP_TRUE
    };
    scripts.push(script1);
    inputs.push(vec![ScriptInput::Fq6(fx.c0), ScriptInput::Fq6(f.c0), ScriptInput::Fq6(b), ScriptInput::Fq6(f.c1), ScriptInput::Fq(y), ScriptInput::Fq(x)]);

    // inputs [fx.c1, b, y, x, f.c0, f.c1]
    // verified: [fx.c1]
    let script2 = script! {
        // fx.c1, b, y, x, f.c0, f.c1
        { Fq6::copy(6) }
        { Fq6::add(6, 0) }
        // fx.c1, b, y, x, f.c0, f.c0+f.c1

        { Fq::copy(12) }
        { Fq::mul_by_constant(&constant.1.c0) }
        { Fq::roll(13) }
        { Fq::mul_by_constant(&constant.1.c1) }
        { Fq2::push_one() }
        { Fq2::add(2, 0) }
        // fx.c1, b, y, f.c0, f.c0+f.c1, cc0

        { Fq::copy(14) }
        { Fq::mul_by_constant(&constant.2.c0) }
        { Fq::roll(15) }
        { Fq::mul_by_constant(&constant.2.c1) }
        // fx.c1, b, f.c0, f.c0+f.c1, cc0, cc1

        { Fq6::mul_by_01() }
        // fx.c1, b, f.c0, e

        { Fq6::add(12, 6) }
        { Fq6::sub(6, 0) }
        // // fx.c1, e-(b+f.c0)
        { Fq6::equalverify() }

        OP_TRUE
    };
    scripts.push(script2);
    inputs.push(vec![ScriptInput::Fq6(fx.c1), ScriptInput::Fq6(b), ScriptInput::Fq(y), ScriptInput::Fq(x), ScriptInput::Fq6(f.c0), ScriptInput::Fq6(f.c1)]);

    (scripts, inputs)
}

pub fn double_ell_by_constant_affine_verify(f: ark_bn254::Fq12, x: Vec<ark_bn254::Fq>, y: Vec<ark_bn254::Fq>, constant: Vec<EllCoeff>, f_new: ark_bn254::Fq12) -> (Vec<Script>, Vec<Vec<ScriptInput>>) {
    let (mut scripts, mut inputs) = (Vec::new(), Vec::new());

    assert_eq!(constant[0].0, ark_bn254::Fq2::ONE);
    assert_eq!(constant[1].0, ark_bn254::Fq2::ONE);

    let mut c3 = constant[0].1;
    let mut c4 = constant[0].2;
    c3.mul_assign_by_fp(&x[0]);
    c4.mul_assign_by_fp(&y[0]);
    
    let cc3 = constant[0].0 + c3;
    let cc4 = c4;

    let mut s0 = f.c1;
    s0.mul_by_01(&c3, &c4);
    let mut s0beta = s0;
    Fq12Config::mul_fp6_by_nonresidue_in_place(&mut s0beta);

    let mut s1 = f.c0 + f.c1;
    s1.mul_by_01(&cc3, &cc4);

    let mut xc3 = constant[1].1;
    let mut xc4 = constant[1].2;
    xc3.mul_assign_by_fp(&x[1]);
    xc4.mul_assign_by_fp(&y[1]);
    
    let xcc3 = constant[1].0 + xc3;
    let xcc4 = xc4;
    
    let mut xs0 = s1 - (f.c0 + s0);
    xs0.mul_by_01(&xc3, &xc4);
    let mut xs0beta = xs0;
    Fq12Config::mul_fp6_by_nonresidue_in_place(&mut xs0beta);

    let mut xs1 = s0beta + s1 - s0;
    xs1.mul_by_01(&xcc3, &xcc4);

    let xxf = ark_bn254::Fq12::new(
        xs0beta + s0beta + f.c0,
        xs1 - (xs0 + s0beta + f.c0)
    );

    assert_eq!(xxf, f_new);

    // inputs [s0, f.c1, y[0], x[0]]
    // verified: [s0]
    let script1 = script! {
        // s0, f.c1, y[0], x[0]
        { Fq::copy(0) }
        { Fq::mul_by_constant(&constant[0].1.c0) }
        { Fq::roll(1) }
        { Fq::mul_by_constant(&constant[0].1.c1) }
        // s0, f.c1, y[0], c3
        { Fq::copy(2) }
        { Fq::mul_by_constant(&constant[0].2.c0) }
        { Fq::roll(3) }
        { Fq::mul_by_constant(&constant[0].2.c1) }
        // s0, f.c1, c3, c4
        { Fq6::mul_by_01() }
        { Fq6::equalverify() }

        OP_TRUE
    };
    scripts.push(script1);
    inputs.push(vec![ScriptInput::Fq6(s0), ScriptInput::Fq6(f.c1), ScriptInput::Fq(y[0]), ScriptInput::Fq(x[0])]);

    // inputs [s1, y[0], x[0], f]
    // verified: [s1]
    let script2 = script! {
        { Fq6::add(6, 0) }
        // s1, y[0], x[0], f.c1+f.c0
        { Fq::copy(6) }
        { Fq::mul_by_constant(&constant[0].1.c0) }
        { Fq::roll(7) }
        { Fq::mul_by_constant(&constant[0].1.c1) }
        { Fq2::push_one() }
        { Fq2::add(2, 0) }
        // s1, y[0], f.c1+f.c0, cc3
        { Fq::copy(8) }
        { Fq::mul_by_constant(&constant[0].2.c0) }
        { Fq::roll(9) }
        { Fq::mul_by_constant(&constant[0].2.c1) }
        // s1, f.c1+f.c0, cc3, cc4
        { Fq6::mul_by_01() }
        { Fq6::equalverify() }

        OP_TRUE
    };
    scripts.push(script2);
    inputs.push(vec![ScriptInput::Fq6(s1), ScriptInput::Fq(y[0]), ScriptInput::Fq(x[0]), ScriptInput::Fq12(f)]);

    // inputs [xxf.c0, xs0, y[1], x[1], s1, f.c0, s0]
    // verified: [xxf.c0, xs0]
    let script3 = script! {
        { Fq6::copy(6) }
        { Fq6::copy(6) }
        // xxf.c0, xs0, y[1], x[1], s1, f.c0, s0, f.c0, s0
        { Fq6::add(6, 0) }
        { Fq6::sub(18, 0) }
        // xxf.c0, xs0, y[1], x[1], f.c0, s0, s1-(f.c0+s0)
        { Fq::copy(18) }
        { Fq::mul_by_constant(&constant[1].1.c0) }
        { Fq::roll(19) }
        { Fq::mul_by_constant(&constant[1].1.c1) }
        // xxf.c0, xs0, y[1], f.c0, s0, s1-(f.c0+s0), xc3
        { Fq::copy(20) }
        { Fq::mul_by_constant(&constant[1].2.c0) }
        { Fq::roll(21) }
        { Fq::mul_by_constant(&constant[1].2.c1) }
        // xxf.c0, xs0, f.c0, s0, s1-(f.c0+s0), xc3, xc4
        { Fq6::mul_by_01() }
        { Fq6::copy(18) }
        { Fq6::equalverify() }
        // xxf.c0, xs0, f.c0, s0,
        { Fq12::mul_fq6_by_nonresidue() }
        { Fq6::roll(12) }
        { Fq12::mul_fq6_by_nonresidue() }
        { Fq6::add(6, 0) }
        { Fq6::add(6, 0) }
        { Fq6::equalverify() }

        OP_TRUE
    };
    scripts.push(script3);
    inputs.push(vec![ScriptInput::Fq6(xxf.c0), ScriptInput::Fq6(xs0), ScriptInput::Fq(y[1]), ScriptInput::Fq(x[1]), ScriptInput::Fq6(s1), ScriptInput::Fq6(f.c0), ScriptInput::Fq6(s0)]);

    // inputs [xxf.c1, xs0, f.c0, y[1], x[1], s1, s0]
    // verified: [xxf.c1]
    let script4 = script! {
        // xxf.c1, xs0, f.c0, y[1], x[1], s1, s0
        { Fq6::copy(0) }
        { Fq12::mul_fq6_by_nonresidue() }
        { Fq6::copy(0) }
        { Fq6::sub(0, 12) }
        // xxf.c1, xs0, f.c0, y[1], x[1], s1, s0*beta, (s0*beta)-s0
        { Fq6::add(12, 0) }
        // xxf.c1, xs0, f.c0, y[1], x[1], s0*beta, ((s0*beta)-s0)+s1
        { Fq::copy(12) }
        { Fq::mul_by_constant(&constant[1].1.c0) }
        { Fq::roll(13) }
        { Fq::mul_by_constant(&constant[1].1.c1) }
        { Fq2::push_one() }
        { Fq2::add(2, 0) }
        // xxf.c1, xs0, f.c0, y[1], s0*beta, ((s0*beta)-s0)+s1, xcc3
        { Fq::copy(14) }
        { Fq::mul_by_constant(&constant[1].2.c0) }
        { Fq::roll(15) }
        { Fq::mul_by_constant(&constant[1].2.c1) }
        // xxf.c1, xs0, f.c0, s0*beta, ((s0*beta)-s0)+s1, xcc3, xcc4
        { Fq6::mul_by_01() }
        // xxf.c1, xs0, f.c0, s0*beta, xs1
        { Fq6::add(12, 6) }
        { Fq6::add(12, 0) }
        // xxf.c1, xs1, (f.c0+(s0*beta))+xs0
        { Fq6::sub(6, 0) }
        { Fq6::equalverify() }
        
        OP_TRUE
    };
    scripts.push(script4);
    inputs.push(vec![ScriptInput::Fq6(xxf.c1), ScriptInput::Fq6(xs0), ScriptInput::Fq6(f.c0), ScriptInput::Fq(y[1]), ScriptInput::Fq(x[1]), ScriptInput::Fq6(s1), ScriptInput::Fq6(s0)]);

    (scripts, inputs)
}

pub fn collect_line_coeffs(
    constants: Vec<G2Prepared>,
) -> Vec<Vec<Vec<(ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2)>>> {
    let mut constant_iters = constants
        .iter()
        .map(|item| item.ell_coeffs.iter())
        .collect::<Vec<_>>();
    let mut all_line_coeffs = vec![];

    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        let mut line_coeffs = vec![];
        for j in 0..constants.len() {
            // double line coeff
            let mut line_coeff = vec![];
            line_coeff.push(*constant_iters[j].next().unwrap());
            // add line coeff
            if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1
                || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1
            {
                line_coeff.push(*constant_iters[j].next().unwrap());
            }
            // line coeff for single point
            line_coeffs.push(line_coeff);
        }
        // line coeffs for all points
        all_line_coeffs.push(line_coeffs);
    }
    {
        let mut line_coeffs = vec![];
        for j in 0..constants.len() {
            // add line coeff
            line_coeffs.push(vec![*constant_iters[j].next().unwrap()]);
        }
        all_line_coeffs.push(line_coeffs);
    }
    {
        let mut line_coeffs = vec![];
        for j in 0..constants.len() {
            // add line coeff
            line_coeffs.push(vec![*constant_iters[j].next().unwrap()]);
        }
        all_line_coeffs.push(line_coeffs);
    }
    for i in 0..constant_iters.len() {
        assert_eq!(constant_iters[i].next(), None);
    }
    assert_eq!(
        all_line_coeffs.len(),
        ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 + 2
    );
    all_line_coeffs
}

/// input of func (params):
///      p.x, p.y
/// output on stack:
///      x' = -p.x / p.y
///      y' = 1 / p.y
pub fn from_eval_point(p: ark_bn254::G1Affine) -> Script {
    let py_inv = p.y().unwrap().inverse().unwrap();
    script! {
        { Fq::push_u32_le(&BigUint::from(py_inv).to_u32_digits()) }
        // [1/y]
        // check p.y.inv() is valid
        { Fq::copy(0) }
        // [1/y, 1/y]
        { Fq::push_u32_le(&BigUint::from(p.y).to_u32_digits()) }
        // [1/y, 1/y, y]
        { Fq::mul() }
        // [1/y, 1]
        { Fq::push_one() }
        // [1/y, 1, 1]
        { Fq::equalverify(1, 0) }
        // [1/y]

        // -p.x / p.y
        { Fq::copy(0) }
        // [1/y, 1/y]
        { Fq::push_u32_le(&BigUint::from(p.x).to_u32_digits()) }
        // [1/y, 1/y, x]
        { Fq::neg(0) }
        // [1/y, 1/y, -x]
        { Fq::mul() }
        // [1/y, -x/y]
        { Fq::roll(1) }
        // [-x/y, 1/y]
    }
}

/// input of stack:
///      p.x, p.y (affine space)
/// output on stack:
///      x' = -p.x / p.y
///      y' = 1 / p.y
pub fn from_eval_point_in_stack() -> Script {
    script! {
        // [x, y]
        { Fq::copy(0) }
        // [x, y, y]
        { Fq::copy(0) }
        // [x, y, y, y]
        { Fq::inv() }
        // [x, y, y, 1/y]
        // check p.y.inv() is valid
        { Fq::mul() }
        // [x, y, 1]
        { Fq::push_one() }
        // [x, y, 1, 1]
        { Fq::equalverify(1, 0) }
        // [x, y]
        { Fq::inv() }
        // [x, 1/y]

        // -p.x / p.y
        { Fq::copy(0) }
        // [x, 1/y, 1/y]
        { Fq::roll(2)}
        // [1/y, 1/y, x]
        { Fq::neg(0) }
        // [1/y, 1/y, -x]
        { Fq::mul() }
        // [1/y, -x/y]
        { Fq::roll(1) }
        // [-x/y, 1/y]
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

/// add two points T and Q
///     x' = alpha^2 - T.x - Q.x
///     y' = -bias - alpha * x'
///
/// input on stack:
///     T.x (2 elements)
///     Q.x (2 elements)
///
/// input of parameters:
///     c3: alpha - line slope
///     c4: -bias - line intercept
///
/// output on stack:
///     T'.x (2 elements)
///     T'.y (2 elements)
pub fn affine_add_line(c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> Script {
    script! {
        // [T.x, Q.x]
        { Fq2::neg(0) }
        // [T.x, -Q.x]
        { Fq2::roll(2) }
        // [-Q.x, T.x]
        { Fq2::neg(0) }
        // [-T.x - Q.x]
        { Fq2::add(2, 0) }
        // [-T.x - Q.x]
        { fq2_push(c3) }
        // [-T.x - Q.x, alpha]
        { Fq2::copy(0) }
        // [-T.x - Q.x, alpha, alpha]
        { Fq2::square() }
        // [-T.x - Q.x, alpha, alpha^2]
        // calculate x' = alpha^2 - T.x - Q.x
        { Fq2::add(4, 0) }
        // [alpha, x']
        { Fq2::copy(0) }
        // [alpha, x', x']
        { Fq2::mul(4, 0) }
        // [x', alpha * x']
        { Fq2::neg(0) }
        // [x', -alpha * x']
        { fq2_push(c4) }
        // [x', -alpha * x', -bias]
        // compute y' = -bias - alpha * x'
        { Fq2::add(2, 0) }
        // [x', y']
    }
}

/// double a point T:
///     x' = alpha^2 - 2 * T.x
///     y' = -bias - alpha* x'
///
/// input on stack:
///     T.x (2 elements)
///
/// output on stack:
///     T'.x (2 elements)
///     T'.y (2 elements)
pub fn affine_double_line(c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> Script {
    script! {
        { Fq2::double(0) }
        { Fq2::neg(0) }
        // [- 2 * T.x]
        { fq2_push(c3) }
        { Fq2::copy(0) }
        { Fq2::square() }
        // [- 2 * T.x, alpha, alpha^2]
        { Fq2::add(4, 0) }
        { Fq2::copy(0) }
        // [alpha, x', x']
        { Fq2::mul(4, 0) }
        { Fq2::neg(0) }
        // [x', -alpha * x']

        { fq2_push(c4) }
        { Fq2::add(2, 0) }
        // [x', y']
    }
}

/// check line through one point, that is:
///     y - alpha * x - bias = 0
///
/// input on stack:
///     x (2 elements)
///     y (2 elements)
///
/// input of parameters:
///     c3: alpha
///     c4: -bias
///
/// output:
///     true or false (consumed on stack)
pub fn check_line_through_point(c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> Script {
    script! {
        // [x, y]
        { Fq2::roll(2) }
        // [y, x]
        { Fq2::mul_by_constant(&c3) }
        // [y, alpha * x]
        { Fq2::neg(0) }
        // [y, -alpha * x]
        { Fq2::add(2, 0) }
        // [y - alpha * x]

        { fq2_push(c4) }
        // [y - alpha * x, -bias]
        { Fq2::add(2, 0) }
        // [y - alpha * x - bias]

        { Fq2::push_zero() }
        // [y - alpha * x - bias, 0]
        { Fq2::equalverify() }
    }
}

/// check whether a tuple coefficient (alpha, -bias) of a tangent line is satisfied with expected point T (affine)
/// two aspects:
///     1. alpha * (2 * T.y) = 3 * T.x^2, make sure the alpha is the right ONE
///     2. T.y - alpha * T.x - bias = 0, make sure the -bias is the right ONE
///
/// input on stack:
///     T.x (2 element)
///     T.y (2 element)
///
/// input of parameters:
///     c3: alpha
///     c4: -bias
///
/// output:
///     true or false (consumed on stack)
pub fn check_tangent_line(c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> Script {
    script! {
        // alpha * (2 * T.y) = 3 * T.x^2
        { Fq2::copy(0) }
        { Fq2::double(0) }
        { Fq2::mul_by_constant(&c3) }
        // [T.x, T.y, alpha * (2 * T.y)]
        { Fq2::copy(4) }
        { Fq2::square() }
        { Fq2::copy(0) }
        { Fq2::double(0) }
        { Fq2::add(2, 0) }
        // [T.x, T.y, alpha * (2 * T.y), 3 * T.x^2]
        { Fq2::neg(0) }
        { Fq2::add(2, 0) }
        { Fq2::push_zero() }
        { Fq2::equalverify() }
        // [T.x, T.y]

        // check: T.y - alpha * T.x - bias = 0
        { check_line_through_point(c3, c4) }
        // []
    }
}

/// check whether a tuple coefficient (alpha, -bias) of a chord line is satisfied with expected points T and Q (both are affine cooordinates)
/// two aspects:
///     1. T.y - alpha * T.x - bias = 0
///     2. Q.y - alpha * Q.x - bias = 0, make sure the alpha/-bias are the right ONEs
///
/// input on stack:
///     T.x (2 elements)
///     T.y (2 elements)
///     Q.x (2 elements)
///     Q.y (2 elements)
///
/// input of parameters:
///     c3: alpha
///     c4: -bias
/// output:
///     true or false (consumed on stack)
pub fn check_chord_line(c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> Script {
    script! {
        // check: Q.y - alpha * Q.x - bias = 0
        { check_line_through_point(c3, c4) }
        // [T.x, T.y]
        // check: T.y - alpha * T.x - bias = 0
        { check_line_through_point(c3, c4) }
        // []
    }
}

// stack data: beta^{2 * (p - 1) / 6}, beta^{3 * (p - 1) / 6}, beta^{2 * (p^2 - 1) / 6}, 1/2, B,
// P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, Qx, Qy
// [..., Fq12, Fq12, Fq12, Fq12, Fq, Fq, (Fq, Fq), (Fq, Fq), (Fq, Fq), (Fq, Fq), (Fq, Fq)]
//
// flag == true ? T + Q : T - Q
pub fn add_line_with_flag(flag: bool) -> Script {
    script! {
    // let theta = self.y - &(q.y * &self.z);
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy
    { Fq2::copy(6) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, Ty
    { Fq2::copy(2) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, Ty, Qy
    if !flag {
        { Fq2::neg(0) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, Ty, -Qy
    }
    { Fq2::copy(8) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, Ty, Qy, Tz
    { Fq2::mul(2, 0) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, Ty, Qy * Tz
    { Fq2::sub(2, 0) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, Ty - Qy * Tz

    // let lambda = self.x - &(q.x * &self.z);
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta
    { Fq2::copy(10) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, Tx
    { Fq2::copy(6) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, Tx, Qx
    { Fq2::copy(10) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, Tx, Qx, Tz
    { Fq2::mul(2, 0) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, Tx, Qx * Tz
    { Fq2::sub(2, 0) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, Tx - Qx * Tz

    // let c = theta.square();
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda
    { Fq2::copy(2) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, theta
    { Fq2::square() }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, theta^2

    // let d = lambda.square();
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c
    { Fq2::copy(2) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, lambda
    { Fq2::square() }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, lambda^2

    // let e = lambda * &d;
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d
    { Fq2::copy(4) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d, lambda
    { Fq2::copy(2) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d, lambda, d
    { Fq2::mul(2, 0) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d, lambda * d

    // let f = self.z * &c;
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d, e
    { Fq2::copy(14) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d, e, Tz
    { Fq2::roll(6) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, d, e, Tz, c
    { Fq2::mul(2, 0) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, d, e, Tz * c

    // let g = self.x * &d;
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, d, e, ff
    { Fq2::roll(18) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, d, e, ff, Tx
    { Fq2::roll(6) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, ff, Tx, d
    { Fq2::mul(2, 0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, ff, Tx * d

    // let h = e + &f - &g.double();
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, ff, g
    { Fq2::copy(0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, ff, g, g
    { Fq2::neg(0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, ff, g, -g
    { Fq2::double(0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, ff, g, -2g
    { Fq2::roll(4) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, -2g, ff
    { Fq2::add(2, 0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, -2g + ff
    { Fq2::copy(4) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, -2g + ff, e
    { Fq2::add(2, 0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, -2g + ff + e

    // self.x = lambda * &h;
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, h
    { Fq2::copy(0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, h, h
    { Fq2::copy(8) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, h, h, lambda
    { Fq2::mul(2, 0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, h, h * lambda

    // self.y = theta * &(g - &h) - &(e * &self.y);
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, h, x
    { Fq2::copy(10) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, h, x, theta
    { Fq2::roll(6) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, h, x, theta, g
    { Fq2::roll(6) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, x, theta, g, h
    { Fq2::sub(2, 0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, x, theta, g - h
    { Fq2::mul(2, 0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, x, theta * (g - h)
    { Fq2::copy(4) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, x, theta * (g - h), e
    { Fq2::roll(18) }
    // f, Px, Py, Tz, Qx, Qy, theta, lambda, e, x, theta * (g - h), e, Ty
    { Fq2::mul(2, 0) }
    // f, Px, Py, Tz, Qx, Qy, theta, lambda, e, x, theta * (g - h), e * Ty
    { Fq2::sub(2, 0) }
    // f, Px, Py, Tz, Qx, Qy, theta, lambda, e, x, theta * (g - h) - e * Ty

    // self.z *= &e;
    // f, Px, Py, Tz, Qx, Qy, theta, lambda, e, x, y
    { Fq2::roll(14) }
    // f, Px, Py, Qx, Qy, theta, lambda, e, x, y, Tz
    { Fq2::roll(6) }
    // f, Px, Py, Qx, Qy, theta, lambda, x, y, Tz, e
    { Fq2::mul(2, 0) }
    // f, Px, Py, Qx, Qy, theta, lambda, x, y, Tz * e

    // let j = theta * &q.x - &(lambda * &q.y);
    // f, Px, Py, Qx, Qy, theta, lambda, x, y, z
    { Fq2::copy(8) }
    // f, Px, Py, Qx, Qy, theta, lambda, x, y, z, theta
    { Fq2::roll(14) }
    // f, Px, Py, Qy, theta, lambda, x, y, z, theta, Qx
    { Fq2::mul(2, 0) }
    // f, Px, Py, Qy, theta, lambda, x, y, z, theta * Qx
    { Fq2::copy(8) }
    // f, Px, Py, Qy, theta, lambda, x, y, z, theta * Qx, lambda
    { Fq2::roll(14) }
    // f, Px, Py, theta, lambda, x, y, z, theta * Qx, lambda, Qy
    if !flag {
        { Fq2::neg(0) }
    // f, Px, Py, theta, lambda, x, y, z, theta * Qx, lambda, -Qy
    }
    { Fq2::mul(2, 0) }
    // f, Px, Py, theta, lambda, x, y, z, theta * Qx, lambda * Qy
    { Fq2::sub(2, 0) }
    // f, Px, Py, theta, lambda, x, y, z, theta * Qx - lambda * Qy

    // (lambda, -theta, j)
    // f, Px, Py, theta, lambda, x, y, z, j
    { Fq2::roll(8) }
    // f, Px, Py, theta, x, y, z, j, lambda
    { Fq2::roll(10) }
    // f, Px, Py, x, y, z, j, lambda, theta
    { Fq2::neg(0) }
    // f, Px, Py, x, y, z, j, lambda, -theta
    { Fq2::roll(4) }
    // f, Px, Py, x, y, z, lambda, -theta, j

    }
}

// script of double line for the purpose of non-fixed point in miller loop
// stack data: beta^{2 * (p - 1) / 6}, beta^{3 * (p - 1) / 6}, beta^{2 * (p^2 - 1) / 6}, 1/2, B,
// P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz
// [..., Fq12, Fq12, Fq12, Fq12, Fq, Fq, (Fq, Fq), (Fq, Fq), (Fq, Fq)]
pub fn double_line() -> Script {
    script! {

    // let mut a = self.x * &self.y;
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz
    { Fq2::copy(4) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, Tx
    { Fq2::copy(4) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, Tx, Ty
    { Fq2::mul(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, Tx * Ty

    // a.mul_assign_by_fp(two_inv);
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a
    { Fq::copy(72) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, 1/2
    { Fq2::mul_by_fq(1, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a * 1/2

    // let b = self.y.square();
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a
    { Fq2::copy(4) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, Ty
    { Fq2::square() }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, Ty^2

    // let c = self.z.square();
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b
    { Fq2::copy(4) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, Tz
    { Fq2::square() }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, Tz^2

    // let e = ark_bn254::g2::Config::COEFF_B * &(c.double() + &c);
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c
    { Fq2::copy(0) }
    { Fq2::copy(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, c, c
    { Fq2::double(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, c, 2 * c
    { Fq2::add(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, 3 * c
    { Fq2::copy(76) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, 3 * c, B
    { Fq2::mul(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, 3 * c * B

    // let f = e.double() + &e;
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e
    { Fq2::copy(0) }
    { Fq2::copy(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, e, e
    { Fq2::double(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, e, 2 * e
    { Fq2::add(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, 3 * e

    // let mut g = b + &f;
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f
    { Fq2::copy(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f, f
    { Fq2::copy(8) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f, f, b
    { Fq2::add(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f, f + b

    // g.mul_assign_by_fp(two_inv);
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f, g
    { Fq::copy(82) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f, g, 1/2
    { Fq2::mul_by_fq(1, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f, g * 1/2

    // let h = (self.y + &self.z).square() - &(b + &c);
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f, g
    { Fq2::roll(14) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Tz, a, b, c, e, f, g, Ty
    { Fq2::roll(14) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, c, e, f, g, Ty, Tz
    { Fq2::add(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, c, e, f, g, Ty + Tz
    { Fq2::square() }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, c, e, f, g, (Ty + Tz)^2
    { Fq2::copy(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, c, e, f, g, (Ty + Tz)^2, b
    { Fq2::roll(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, (Ty + Tz)^2, b, c
    { Fq2::add(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, (Ty + Tz)^2, b + c
    { Fq2::sub(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, (Ty + Tz)^2 - (b + c)

    // let i = e - &b;
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, h
    { Fq2::copy(6) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, h, e
    { Fq2::copy(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, h, e, b
    { Fq2::sub(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, h, e - b

    // let j = self.x.square();
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, h, i
    { Fq2::roll(14) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, a, b, e, f, g, h, i, Tx
    { Fq2::square() }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, a, b, e, f, g, h, i, Tx^2

    // let e_square = e.square();
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, a, b, e, f, g, h, i, j
    { Fq2::roll(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, a, b, f, g, h, i, j, e
    { Fq2::square() }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, a, b, f, g, h, i, j, e^2

    // self.x = a * &(b - &f);
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, a, b, f, g, h, i, j, e^2
    { Fq2::roll(14) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, f, g, h, i, j, e^2, a
    { Fq2::copy(14) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, f, g, h, i, j, e^2, a, b
    { Fq2::roll(14) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, g, h, i, j, e^2, a, b, f
    { Fq2::sub(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, g, h, i, j, e^2, a, b - f
    { Fq2::mul(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, g, h, i, j, e^2, a * (b - f)

    // self.y = g.square() - &(e_square.double() + &e_square);
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, g, h, i, j, e^2, x
    { Fq2::roll(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, e^2, x, g
    { Fq2::square() }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, e^2, x, g^2
    { Fq2::roll(4) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, x, g^2, e^2
    { Fq2::copy(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, x, g^2, e^2, e^2
    { Fq2::double(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, x, g^2, e^2, 2 * e^2
    { Fq2::add(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, x, g^2, 3 * e^2
    { Fq2::sub(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, x, g^2 - 3 * e^2

    // self.z = b * &h;
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, x, y
    { Fq2::roll(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, h, i, j, x, y, b
    { Fq2::roll(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, j, x, y, b, h
    { Fq2::copy(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, j, x, y, b, h, h
    { Fq2::mul(4, 2) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, j, x, y, h, z

    // (-h, j.double() + &j, i)
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, j, x, y, h, z
    { Fq2::roll(2) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, j, x, y, z, h
    { Fq2::neg(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, j, x, y, z, -h
    { Fq2::roll(8) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, x, y, z, -h, j
    { Fq2::copy(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, x, y, z, -h, j, j
    { Fq2::double(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, x, y, z, -h, j, 2 * j
    { Fq2::add(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, x, y, z, -h, 3 * j
    { Fq2::roll(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, x, y, z, -h, 3 * j, i

    }
}

#[cfg(test)]
mod test {
    use std::iter::zip;

    use super::*;
    use crate::{bn254::fq2::Fq2, execute_script_without_stack_limit};
    use ark_ff::AdditiveGroup;
    use ark_std::{end_timer, start_timer, UniformRand};
    use num_traits::One;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

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
    fn test_ell() {
        println!("Pairing.ell: {} bytes", ell().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let c0 = ark_bn254::Fq2::rand(&mut prng);
            let c1 = ark_bn254::Fq2::rand(&mut prng);
            let c2 = ark_bn254::Fq2::rand(&mut prng);
            let px = ark_bn254::Fq::rand(&mut prng);
            let py = ark_bn254::Fq::rand(&mut prng);

            let b = {
                let mut c0new = c0;
                c0new.mul_assign_by_fp(&py);

                let mut c1new = c1;
                c1new.mul_assign_by_fp(&px);

                let mut b = a;
                b.mul_by_034(&c0new, &c1new, &c2);
                b
            };

            let script = script! {
                { fq12_push(a) }
                { fq2_push(c0) }
                { fq2_push(c1) }
                { fq2_push(c2) }
                { Fq::push_u32_le(&BigUint::from(px).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(py).to_u32_digits()) }
                ell
                { fq12_push(b) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_ell_by_constant_projective() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = ark_bn254::g2::G2Affine::rand(&mut prng);
            let px = ark_bn254::Fq::rand(&mut prng);
            let py = ark_bn254::Fq::rand(&mut prng);

            // projective mode
            let coeffs = G2Prepared::from(b);
            let ell_by_constant_script = ell_by_constant(&coeffs.ell_coeffs[0]);
            println!(
                "Pairing.ell_by_constant: {} bytes",
                ell_by_constant_script.len()
            );

            // projective mode as well
            let b = {
                let mut c0new = coeffs.ell_coeffs[0].0;
                c0new.mul_assign_by_fp(&py);

                let mut c1new = coeffs.ell_coeffs[0].1;
                c1new.mul_assign_by_fp(&px);

                let mut b = a;
                b.mul_by_034(&c0new, &c1new, &coeffs.ell_coeffs[0].2);
                b
            };

            let script = script! {
                { fq12_push(a) }
                { Fq::push_u32_le(&BigUint::from(px).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(py).to_u32_digits()) }
                { ell_by_constant_script.clone() }
                { fq12_push(b) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_ell_by_constant_affine() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let f = ark_bn254::Fq12::rand(&mut prng);
        let b = ark_bn254::g2::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);

        // affine mode
        let coeffs = G2Prepared::from_affine(b);
        let ell_by_constant_affine_script = ell_by_constant_affine(&coeffs.ell_coeffs[0]);
        println!(
            "Pairing.ell_by_constant_affine: {} bytes",
            ell_by_constant_affine_script.len()
        );

        // affine mode as well
        let hint = {
            assert_eq!(coeffs.ell_coeffs[0].0, ark_bn254::fq2::Fq2::ONE);

            let mut f1 = f;
            let mut c1new = coeffs.ell_coeffs[0].1;
            c1new.mul_assign_by_fp(&(-p.x / p.y));

            let mut c2new = coeffs.ell_coeffs[0].2;
            c2new.mul_assign_by_fp(&(p.y.inverse().unwrap()));

            f1.mul_by_034(&coeffs.ell_coeffs[0].0, &c1new, &c2new);
            f1
        };

        let script = script! {
            { fq12_push(f) }
            { from_eval_point(p) }
            { ell_by_constant_affine_script.clone() }
            { fq12_push(hint) }
            { Fq12::equalverify() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_ell_by_constant_affine_verify() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let f = ark_bn254::Fq12::rand(&mut prng);
        let b: ark_ec::short_weierstrass::Affine<ark_bn254::g2::Config> = ark_bn254::g2::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);

        
        // affine mode
        let coeffs = G2Prepared::from_affine(b);
        
        // affine mode as well
        let hint = {
            assert_eq!(coeffs.ell_coeffs[0].0, ark_bn254::fq2::Fq2::ONE);

            let mut f1 = f;
            let mut c1new = coeffs.ell_coeffs[0].1;
            c1new.mul_assign_by_fp(&(-p.x / p.y));

            let mut c2new = coeffs.ell_coeffs[0].2;
            c2new.mul_assign_by_fp(&(p.y.inverse().unwrap()));

            f1.mul_by_034(&coeffs.ell_coeffs[0].0, &c1new, &c2new);
            f1
        };

        
        let (scripts, inputs) = ell_by_constant_affine_verify(f, -p.x / p.y, p.y.inverse().unwrap(),&coeffs.ell_coeffs[0], hint);
        let n = scripts.len();

        assert_eq!(scripts.len(), inputs.len());

        let mut script_sizes = Vec::new();
        let mut max_stack_sizes = Vec::new();
        let mut fq_counts = Vec::new();
        let mut script_total_size: u64 = 0;

        for (i, (script, input)) in zip(scripts, inputs).enumerate() {
            let (result, script_size, max_stack_size) = test_script_with_inputs(script.clone(), input.to_vec());
            script_total_size += script_size as u64;
            let fq_count = input.iter().map(|inp| inp.size()).sum::<usize>();
            script_sizes.push(script_size);
            max_stack_sizes.push(max_stack_size);
            fq_counts.push(fq_count);
            println!("script[{:?}]: size: {:?} bytes, max stack size: {:?} items, input fq count: {:?}", i, script_size, max_stack_size, fq_count);
            assert!(result);
        }
        
        println!();
        println!("number of pieces: {:?}", n);
        println!("script total size: {:?}", script_total_size);
        println!("max (script size): {:?} bytes", script_sizes.iter().max().unwrap());
        println!("max (max stack size): {:?} items", max_stack_sizes.iter().max().unwrap());
        println!("max fq count: {:?} fqs", fq_counts.iter().max().unwrap());
           
    }

    #[test]
    fn test_double_ell_by_constant_affine_verify() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let f = ark_bn254::Fq12::rand(&mut prng);
        let b: Vec<ark_ec::short_weierstrass::Affine<ark_bn254::g2::Config>> = (0..2).map(|_| ark_bn254::g2::G2Affine::rand(&mut prng)).collect();
        let p: Vec<_> = (0..2).map(|_| ark_bn254::g1::G1Affine::rand(&mut prng)).collect();

        // affine mode
        let coeffs: Vec<_> = b.iter().map(|elem| G2Prepared::from_affine(*elem).ell_coeffs[0]).collect();
        
        // affine mode as well
        let mut hint = f.clone();
        for i in 0..2 { 
            assert_eq!(coeffs[i].0, ark_bn254::fq2::Fq2::ONE);

            let mut c1new = coeffs[i].1;
            c1new.mul_assign_by_fp(&(-p[i].x / p[i].y));

            let mut c2new = coeffs[i].2;
            c2new.mul_assign_by_fp(&(p[i].y.inverse().unwrap()));

            hint.mul_by_034(&coeffs[i].0, &c1new, &c2new);
        }

        let x: Vec<_> = p.iter().map(|elem| -elem.x / elem.y).collect();
        let y: Vec<_> = p.iter().map(|elem| elem.y.inverse().unwrap()).collect();

        let (scripts, inputs) = double_ell_by_constant_affine_verify(f, x, y, coeffs, hint);
        let n = scripts.len();

        assert_eq!(scripts.len(), inputs.len());

        let mut script_sizes = Vec::new();
        let mut max_stack_sizes = Vec::new();
        let mut fq_counts = Vec::new();
        let mut script_total_size: u64 = 0;

        for (i, (script, input)) in zip(scripts, inputs).enumerate() {
            let (result, script_size, max_stack_size) = test_script_with_inputs(script.clone(), input.to_vec());
            script_total_size += script_size as u64;
            let fq_count = input.iter().map(|inp| inp.size()).sum::<usize>();
            script_sizes.push(script_size);
            max_stack_sizes.push(max_stack_size);
            fq_counts.push(fq_count);
            println!("script[{:?}]: size: {:?} bytes, max stack size: {:?} items, input fq count: {:?}", i, script_size, max_stack_size, fq_count);
            assert!(result);
        }
        
        println!();
        println!("number of pieces: {:?}", n);
        println!("script total size: {:?}", script_total_size);
        println!("max (script size): {:?} bytes", script_sizes.iter().max().unwrap());
        println!("max (max stack size): {:?} items", max_stack_sizes.iter().max().unwrap());
        println!("max fq count: {:?} fqs", fq_counts.iter().max().unwrap());
           
    }

    #[test]
    fn test_from_eval_point() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let script = script! {
            { from_eval_point(p) }
            { Fq::push_u32_le(&BigUint::from(-p.x / p.y).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(p.y.inverse().unwrap()).to_u32_digits()) }
            { Fq::equalverify(2, 0) }
            { Fq::equalverify(1, 0) }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_affine_add_line() {
        // alpha = (t.y - q.y) / (t.x - q.x)
        // bias = t.y - alpha * t.x
        // x' = alpha^2 - T.x - Q.x
        // y' = -bias - alpha * x'
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let alpha = (t.y - q.y) / (t.x - q.x);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let x = alpha.square() - t.x - q.x;
        let y = bias_minus - alpha * x;

        println!("affine add line size: {:?}", affine_add_line(alpha, bias_minus).len());

        let script = script! {
            { fq2_push(t.x) }
            { fq2_push(q.x) }
            { affine_add_line(alpha, bias_minus) }
            // [x']
            { fq2_push(y) }
            // [x', y', y]
            { Fq2::equalverify() }
            // [x']
            { fq2_push(x) }
            // [x', x]
            { Fq2::equalverify() }
            // []
            OP_TRUE
            // [OP_TRUE]
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_affine_double_line() {
        // slope: alpha = 3 * x^2 / 2 * y
        // intercept: bias = y - alpha * x
        // x' = alpha^2 - 2 * x
        // y' = -bias - alpha * x'
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
        let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
        let mut alpha = t.x.square();
        alpha /= t.y;
        alpha.mul_assign_by_fp(&three_div_two);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let x = alpha.square() - t.x.double();
        let y = bias_minus - alpha * x;

        println!("affine double line size: {:?}", affine_double_line(alpha, bias_minus).len());

        let script = script! {
            { fq2_push(t.x) }
            { affine_double_line(alpha, bias_minus) }
            // [x']
            { fq2_push(y) }
            // [x', y', y]
            { Fq2::equalverify() }
            // [x']
            { fq2_push(x) }
            // [x', x]
            { Fq2::equalverify() }
            // []
            OP_TRUE
            // [OP_TRUE]
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_check_tangent_line() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
        let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
        let mut alpha = t.x.square();
        alpha /= t.y;
        alpha.mul_assign_by_fp(&three_div_two);
        // -bias
        let bias_minus = alpha * t.x - t.y;
        println!("check tangent line size: {:?}", check_line_through_point(alpha, bias_minus).len());
        assert_eq!(alpha * t.x - t.y, bias_minus);
        let script = script! {
            { fq2_push(t.x) }
            { fq2_push(t.y) }
            { check_line_through_point(alpha, bias_minus) }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_check_chord_line() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let alpha = (t.y - q.y) / (t.x - q.x);
        // -bias
        let bias_minus = alpha * t.x - t.y;
        println!("check chord line size: {:?}", check_chord_line(alpha, bias_minus).len());
        assert_eq!(alpha * t.x - t.y, bias_minus);
        let script = script! {
            { fq2_push(t.x) }
            { fq2_push(t.y) }
            { check_line_through_point(alpha, bias_minus) }
            { fq2_push(q.x) }
            { fq2_push(q.y) }
            { check_line_through_point(alpha, bias_minus) }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
