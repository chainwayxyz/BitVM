use crate::bn254::ell_coeffs::G2Prepared;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq2::Fq2;
use crate::bn254::fr::Fr;
use crate::bn254::fq::Fq;
use crate::bn254::fq12::Fq12;
use crate::bn254::msm::msm;
use crate::bn254::pairing::Pairing;
use crate::bn254::utils::{affine_add_line, affine_double_line, biguint_to_digits, check_chord_line, check_tangent_line, collect_line_coeffs, ell_by_constant_affine_verify, from_eval_point};
use crate::bn254::curves::G1Projective;
use crate::execute_script_without_stack_limit;
use crate::groth16::constants::{LAMBDA, P_POW3};
use crate::groth16::offchain_checker::compute_c_wi;
use crate::groth16::utils::{fq12_push, fq2_push, g2a_push, Groth16Data, ScriptInput};
use crate::treepp::{script, Script};
use crate::signatures::winternitz_compact::*;
use ark_bn254::Bn254;
use ark_ec::bn::BnConfig;
use ark_ec::pairing::Pairing as ark_Pairing;
use ark_ec::short_weierstrass::Projective;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::Field;
use ark_groth16::{Proof, VerifyingKey};
use num_bigint::BigUint;
use rand::Rng;
use num_traits::Num;
use std::collections::HashMap;
use std::{iter::zip, ops::{Mul, Rem, Neg}};
use num_traits::One;
use ark_ff::AdditiveGroup;

#[derive(Clone, Copy, Debug)]
pub struct Verifier;

impl Verifier {
    pub fn verify(vk: &VerifyingKey<Bn254>, proof: &Proof<Bn254>, public: &<Bn254 as ark_Pairing>::ScalarField) -> (Vec<Script>, Vec<Vec<Script>>, Vec<Vec<Vec<Vec<u8>>>>) {
        const LOG_D: u32   = 7;                                       // Bits per digit
        const D    : u32   = (1 << LOG_D) - 1;                        // Digits are base d+1
        const N0   : usize = 1 + (254 - 1) / (LOG_D as usize);        // Number of digits of the message fq, ceil(254 / logd)
        const N1   : usize = 2;                                       // Number of digits of the checksum
        const N    : usize = N0 + N1;                                 // Total number of digits to be signed

        let (mut scripts, mut script_input_signatures, mut pks) = (Vec::new(), Vec::new(), Vec::new());
        let mut sks_map: HashMap<ScriptInput, (Vec<u8>, Vec<Vec<u8>>)> = HashMap::new();

        let dummy = Groth16Data::new("src/groth16/data/proof.json", "src/groth16/data/public.json", "src/groth16/data/vk.json");
        let (_, dummy_inputs) = Verifier::groth16_scripts_and_inputs(&dummy.vk, &dummy.proof, &dummy.public[0]);

        for input_list in dummy_inputs.clone() {
            for input in input_list {
                match input {
                    ScriptInput::Bit(b, label) => {
                        if !sks_map.contains_key(&ScriptInput::Bit(b, label.clone())) {
                            let sk: [u8; 32] = rand::thread_rng().gen();  // TODO: Better RNG function
                            let sk_vec = sk.to_vec();
                            let mut digit_pks: Vec<Vec<u8>> = Vec::new();
                            for i in 0..2 {
                                digit_pks.push(public_key::<D>(sk_vec.clone(), i));
                            }
                            sks_map.insert(ScriptInput::Bit(b, label), (sk_vec.clone(), digit_pks));
                        }
                    },
                    ScriptInput::Fr(fr) => {
                        if !sks_map.contains_key(&ScriptInput::Fr(fr)) {
                            let sk: [u8; 32] = rand::thread_rng().gen();  // TODO: Better RNG function
                            let sk_vec = sk.to_vec();
                            let mut digit_pks: Vec<Vec<u8>> = Vec::new();
                            for i in 0..68 {
                                digit_pks.push(public_key::<D>(sk_vec.clone(), i));
                            }
                            sks_map.insert(ScriptInput::Fr(fr), (sk_vec.clone(), digit_pks));
                        }
                    },
                    fqs => {
                        for fq_element in fqs.to_fq() {
                            if !sks_map.contains_key(&ScriptInput::Fq(fq_element)) {
                                let sk: [u8; 32] = rand::thread_rng().gen();  // TODO: Better RNG function
                                let sk_vec = sk.to_vec();
                                let mut digit_pks: Vec<Vec<u8>> = Vec::new();
                                for i in 0..68 {
                                    digit_pks.push(public_key::<D>(sk_vec.clone(), i));
                                }
                                sks_map.insert(ScriptInput::Fq(fq_element), (sk_vec.clone(), digit_pks));
                            }
                        }
                    }
                }
            }
        }

        let (main_scripts, main_inputs) = Verifier::groth16_scripts_and_inputs(vk, proof, public);
        let r = BigUint::from_str_radix(Fq::MONTGOMERY_ONE, 16).unwrap();
        let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();
        let r_fr = BigUint::from_str_radix(Fr::MONTGOMERY_ONE, 16).unwrap();
        let p_fr = BigUint::from_str_radix(Fr::MODULUS, 16).unwrap();
        
        for (script, input_list) in zip(main_scripts, main_inputs) {
            let (mut signatures, mut public_keys, mut commit_scripts) = (Vec::new(), Vec::new(), Vec::new());
            for input in input_list.iter().rev() {
                match input {
                    ScriptInput::Bit(b, label) => {
                        commit_scripts.push(checksig_verify_bit::<D>(sks_map.get(&ScriptInput::Bit(*b, label.clone())).unwrap().clone().1));
                    },
                    ScriptInput::Fr(fr) => {
                        commit_scripts.push(checksig_verify::<D, LOG_D, N0, N1, N>(sks_map.get(&ScriptInput::Fr(*fr)).unwrap().clone().1));
                    },
                    fqs => {
                        for fq_element in fqs.to_fq().iter().rev() {
                            commit_scripts.push(checksig_verify::<D, LOG_D, N0, N1, N>(sks_map.get(&ScriptInput::Fq(*fq_element)).unwrap().clone().1));
                        }
                    }
                }
            }
            for input in input_list.clone() {
                match input {
                    ScriptInput::Bit(b, label) => {
                        signatures.push(sign_bit::<D>(sks_map.get(&ScriptInput::Bit(b, label.clone())).unwrap().clone().0, b as u8));
                        public_keys.push(sks_map.get(&ScriptInput::Bit(b, label)).unwrap().clone().1);
                    },
                    ScriptInput::Fr(fr) => {
                        signatures.push(sign::<D, N0, N1, N>(sks_map.get(&ScriptInput::Fr(fr)).unwrap().clone().0, biguint_to_digits::<D, N0>(BigUint::from(fr.clone()).mul(r_fr.clone()).rem(p_fr.clone()))));
                        public_keys.push(sks_map.get(&ScriptInput::Fr(fr)).unwrap().clone().1);
                    },
                    fqs => {
                        for fq_element in fqs.to_fq() {
                            signatures.push(sign::<D, N0, N1, N>(sks_map.get(&ScriptInput::Fq(fq_element)).unwrap().clone().0, biguint_to_digits::<D, N0>(BigUint::from(fq_element.clone()).mul(r.clone()).rem(p.clone()))));
                            public_keys.push(sks_map.get(&ScriptInput::Fq(fq_element)).unwrap().clone().1);
                        }
                    }
                }
            }
            for input in input_list {
                match input {
                    ScriptInput::Bit(_b, _label) => {
                        commit_scripts.push(script! {OP_FROMALTSTACK})
                    },
                    ScriptInput::Fr(_fr) => {
                        commit_scripts.push(Fr::fromaltstack());
                    },
                    fqs => {
                        for _ in fqs.to_fq().iter().rev() {
                            commit_scripts.push(Fq::fromaltstack());
                        }
                    }
                };
            }
            commit_scripts.push(script);

            let c_script = script! {
                for commit_script in commit_scripts {
                    { commit_script }
                }
            };

            scripts.push(c_script);
            script_input_signatures.push(signatures);
            pks.push(public_keys);
        }

        (scripts, script_input_signatures, pks)
    }

    pub fn groth16_scripts_and_inputs(vk: &VerifyingKey<Bn254>, proof: &Proof<Bn254>, public: &<Bn254 as ark_Pairing>::ScalarField) -> (Vec<Script>, Vec<Vec<ScriptInput>>) {
        let (mut scripts, mut inputs) = (Vec::new(), Vec::new());

        let base1: ark_bn254::G1Projective = vk.gamma_abc_g1[0].into();
        let base2: ark_bn254::G1Projective = vk.gamma_abc_g1[1].into();
        let base2_times_public = base2 * public;
        let msm_g1 = ark_bn254::G1Projective::msm(&vk.gamma_abc_g1, &[<ark_bn254::Bn254 as ark_Pairing>::ScalarField::ONE, public.clone()]).unwrap();

        // let (sx, ix) = Fr::mul_by_constant_g1_verify(base2, *public, base2_times_public);
        // scripts.extend(sx);
        // inputs.extend(ix);

        let msm_scalar_mul_script = script! {
            { G1Projective::scalar_mul() }
            { G1Projective::equalverify() }
            OP_TRUE
        };
        scripts.push(msm_scalar_mul_script);
        inputs.push(vec![ScriptInput::G1P(base2_times_public), ScriptInput::G1P(base2), ScriptInput::Fr(*public)]);

        let msm_addition_script = script! {
            { Fq::push_u32_le(&BigUint::from(base1.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(base1.y).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(base1.z).to_u32_digits()) }
            { G1Projective::add() }
            { G1Projective::equalverify() }
            OP_TRUE
        };
        scripts.push(msm_addition_script);
        inputs.push(vec![ScriptInput::G1P(msm_g1), ScriptInput::G1P(base2_times_public)]);
        
        let exp = &*P_POW3 - &*LAMBDA;

        // G1/G2 points for pairings
        let (p1, p2, p3, p4) = (msm_g1.into_affine(), proof.c, vk.alpha_g1, proof.a);
        let (q1, q2, q3, q4) = (
            vk.gamma_g2.into_group().neg().into_affine(),
            vk.delta_g2.into_group().neg().into_affine(),
            -vk.beta_g2,
            proof.b,
        );

        // hint from arkworks
        let f = Bn254::multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4]).0;
        let (c, wi) = compute_c_wi(f);
        let c_inv = c.inverse().unwrap();
        let hint = f * wi * c.pow(exp.to_u64_digits());

        assert_eq!(hint, c.pow(P_POW3.to_u64_digits()), "hint isn't correct!");

        let q_prepared = vec![
            G2Prepared::from_affine(q1),
            G2Prepared::from_affine(q2),
            G2Prepared::from_affine(q3),
            G2Prepared::from_affine(q4),
        ];

        let p_lst = vec![p1, p2, p3, p4];

        let mut f = c_inv;
        let mut t4 = q4;

        let num_line_groups = q_prepared.len();
        let num_constant = 3;

        let line_coeffs = collect_line_coeffs(q_prepared);
        let num_lines = line_coeffs.len();

        for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
            let fx = f.square();
            let (sx, ix) = Fq12::mul_verify(f, f, fx);
            scripts.extend(sx);
            inputs.extend(ix);
            f = fx;

            if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 {
                let fx = f * c_inv;
                let (sx, ix) = Fq12::mul_verify(f, c_inv, fx);
                scripts.extend(sx);
                inputs.extend(ix);
                f = fx;
            }
            else if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                let fx = f * c;
                let (sx, ix) = Fq12::mul_verify(f, c, fx);
                scripts.extend(sx);
                inputs.extend(ix);
                f = fx;
            }

            for j in 0..num_line_groups {
                let p = p_lst[j];
                let coeffs = &line_coeffs[num_lines - (i + 2)][j][0];
                assert_eq!(coeffs.0, ark_bn254::Fq2::ONE);
                let mut fx = f;
                let mut c1new = coeffs.1;
                c1new.mul_assign_by_fp(&(-p.x / p.y));
                let mut c2new = coeffs.2;
                c2new.mul_assign_by_fp(&(p.y.inverse().unwrap()));
                fx.mul_by_034(&coeffs.0, &c1new, &c2new);
                
                let (sx, ix) = ell_by_constant_affine_verify(f, -p.x / p.y, p.y.inverse().unwrap(), coeffs, fx);
                scripts.extend(sx);
                inputs.extend(ix);
                f = fx;

                if j == num_constant {
                    let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
                    let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
                    let mut alpha = t4.x.square();
                    alpha /= t4.y;
                    alpha.mul_assign_by_fp(&three_div_two);
                    let bias_minus = alpha * t4.x - t4.y;
                    let x = alpha.square() - t4.x.double();
                    let y = bias_minus - alpha * x;
                    let t4x = ark_bn254::G2Affine::new(x, y);
                    
                    let s = script! {
                        { Fq2::copy(2) }
                        { Fq2::copy(2) }
                        { check_tangent_line(line_coeffs[num_lines - (i + 2)][j][0].1, line_coeffs[num_lines - (i + 2)][j][0].2) }
                        { Fq2::drop() }
                        { affine_double_line(line_coeffs[num_lines - (i + 2)][j][0].1, line_coeffs[num_lines - (i + 2)][j][0].2) }
                        { Fq2::roll(4) }
                        { Fq2::equalverify() }
                        { Fq2::equalverify() }
                        OP_TRUE
                    };
                    scripts.push(s);
                    inputs.push(vec![ScriptInput::G2A(t4x), ScriptInput::G2A(t4)]);
                    t4 = t4x;
                }
            }

            if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                for j in 0..num_line_groups {
                    let p = p_lst[j];
                    let coeffs = &line_coeffs[num_lines - (i + 2)][j][1];
                    assert_eq!(coeffs.0, ark_bn254::Fq2::ONE);
                    let mut fx = f;
                    let mut c1new = coeffs.1;
                    c1new.mul_assign_by_fp(&(-p.x / p.y));
                    let mut c2new = coeffs.2;
                    c2new.mul_assign_by_fp(&(p.y.inverse().unwrap()));
                    fx.mul_by_034(&coeffs.0, &c1new, &c2new);
                    
                    let (sx, ix) = ell_by_constant_affine_verify(f, -p.x / p.y, p.y.inverse().unwrap(), coeffs, fx);
                    scripts.extend(sx);
                    inputs.extend(ix);
                    f = fx;

                    if j == num_constant {
                        let mut pm_q4 = q4;
                        if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                            pm_q4 = q4.neg();
                        }
                        let alpha = (t4.y - pm_q4.y) / (t4.x - pm_q4.x);
                        let bias_minus = alpha * t4.x - t4.y;
                        let x = alpha.square() - t4.x - pm_q4.x;
                        let y = bias_minus - alpha * x;
                        let t4x = ark_bn254::G2Affine::new(x, y);
                        
                        let s = script! {
                            { Fq2::copy(2) }
                            { Fq2::toaltstack() }
                            { Fq2::copy(6) }
                            { Fq2::toaltstack() }
                            if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                                { Fq2::neg(0) }
                            }
                            { check_chord_line(line_coeffs[num_lines - (i + 2)][j][1].1, line_coeffs[num_lines - (i + 2)][j][1].2) }
                            { Fq2::fromaltstack() }
                            { Fq2::fromaltstack() }
                            { affine_add_line(line_coeffs[num_lines - (i + 2)][j][1].1, line_coeffs[num_lines - (i + 2)][j][1].2) }
                            { Fq2::roll(4) }
                            { Fq2::equalverify() }
                            { Fq2::equalverify() }
                            OP_TRUE
                        };
                        scripts.push(s);
                        inputs.push(vec![ScriptInput::G2A(t4x), ScriptInput::G2A(t4), ScriptInput::G2A(q4)]);
                        t4 = t4x;
                    }
                }
            }
        }

        // let s = script! {
        //     { constants() }
        //     { from_eval_point(p1) }
        //     { from_eval_point(p2) }
        //     { from_eval_point(p3) }
        //     { from_eval_point(p4) }
        //     { g2a_push(q4) }

        //     { fq12_push(c) }
        //     { fq12_push(c_inv) }
        //     { fq12_push(wi) }

        //     { g2a_push(t4) }

        //     // stack: [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, c, c_inv, wi, T4]
        //     { Pairing::quad_miller_loop_with_c_wi(q_prepared) }

        //     { fq12_push(hint) }
        //     { Fq12::equalverify() }
        //     OP_TRUE
        // };

        // let exec_result = execute_script_without_stack_limit(s);
        // assert!(exec_result.success);

        (scripts, inputs)
    }

    pub fn verify_proof(
        public_inputs: &Vec<<Bn254 as ark_Pairing>::ScalarField>,
        proof: &Proof<Bn254>,
        vk: &VerifyingKey<Bn254>,
    ) -> Script {
        let (msm_script, msm_g1) = Self::prepare_inputs(public_inputs, vk);
        Self::verify_proof_with_prepared_inputs(proof, vk, msm_script, msm_g1)
    }

    pub fn prepare_inputs(
        public_inputs: &Vec<<Bn254 as ark_Pairing>::ScalarField>,
        vk: &VerifyingKey<Bn254>,
    ) -> (Script, Projective<ark_bn254::g1::Config>) {
        let scalars = [
            vec![<Bn254 as ark_Pairing>::ScalarField::ONE],
            public_inputs.clone(),
        ]
        .concat();
        let sum_ai_abc_gamma =
            ark_bn254::G1Projective::msm(&vk.gamma_abc_g1, &scalars).expect("failed to calculate msm");
        (msm(&vk.gamma_abc_g1, &scalars), sum_ai_abc_gamma)
    }

    pub fn verify_proof_with_prepared_inputs(
        proof: &Proof<Bn254>,
        vk: &VerifyingKey<Bn254>,
        msm_script: Script,
        msm_g1: Projective<ark_bn254::g1::Config>,
    ) -> Script {
        let (exp, sign) = if LAMBDA.gt(&P_POW3) {
            (&*LAMBDA - &*P_POW3, true)
        } else {
            (&*P_POW3 - &*LAMBDA, false)
        };

        // G1/G2 points for pairings
        let (p1, p2, p3, p4) = (msm_g1.into_affine(), proof.c, vk.alpha_g1, proof.a);
        let (q1, q2, q3, q4) = (
            vk.gamma_g2.into_group().neg().into_affine(),
            vk.delta_g2.into_group().neg().into_affine(),
            -vk.beta_g2,
            proof.b,
        );
        let t4 = q4;

        // hint from arkworks
        let f = Bn254::multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4]).0;
        let (c, wi) = compute_c_wi(f);
        let c_inv = c.inverse().unwrap();
        let hint = if sign {
            f * wi * (c_inv.pow((exp).to_u64_digits()))
        } else {
            f * wi * (c_inv.pow((exp).to_u64_digits()).inverse().unwrap())
        };
        assert_eq!(hint, c.pow(P_POW3.to_u64_digits()), "hint isn't correct!");

        let q_prepared = vec![
            G2Prepared::from_affine(q1),
            G2Prepared::from_affine(q2),
            G2Prepared::from_affine(q3),
            G2Prepared::from_affine(q4),
        ];
        script! {
            // constants
            { constants() }

            // variant of p1, say -p1.x / p1.y, 1 / p1.y
            { msm_script }
            { Fq::inv() }
            { Fq::copy(0) }
            { Fq::roll(2) }
            { Fq::neg(0) }
            { Fq::mul() }
            { Fq::roll(1) }

            // variants of G1 points
            { from_eval_point(p2) }
            { from_eval_point(p3) }
            { from_eval_point(p4) }

            // the only non-fixed G2 point, say q4
            { fq2_push(q4.x) }
            { fq2_push(q4.y) }

            // proofs for verifying final exp
            { fq12_push(c) }
            { fq12_push(c_inv) }
            { fq12_push(wi) }

            // accumulator of q4, say t4
            { fq2_push(t4.x) }
            { fq2_push(t4.y) }
            // stack: [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, c, c_inv, wi, T4]

            // 3. verify pairing
            { check_pairing(&q_prepared, hint) }
        }
    }
}

// Groth16's pairing verifier
//
// To verify e(P1,Q1)*e(P2,Q2)*e(P3,Q3)*e(P4,Q4)=1
//
// Here is only support to verify groth16's pairing, which (Q1,Q2,Q3) are fixed, Q4 is non-fixed.
//
// params:
//  @eval_points: [P1,P2,P3]. which has fixed {Q1,Q2,Q3}
//  @P4: P4
//  @Q4: Q4
//  @lines: []precompute miller lines for Qi. Only support fixed Qi.
//  @c: c^lambda = f*w^i
//  @c_inv: inverse of c
//  @hint: expect final_f
//
// verify c^lambda = f * wi, namely c_inv^lambda * f * wi = 1
pub fn check_pairing(precompute_lines: &Vec<G2Prepared>, hint: ark_bn254::Fq12) -> Script {
    script! {
        // Input stack: [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, c, c_inv, wi, T4]
        // Output stack: [final_f]
        { Pairing::quad_miller_loop_with_c_wi(precompute_lines.to_vec()) }

        // check final_f == hint
        { fq12_push(hint) }
        { Fq12::equalverify() }
        OP_TRUE
    }
}

// Push constants to stack
// Return Stack: [beta_12, beta_13, beta_22, 1/2, B]
fn constants() -> Script {
    script! {
        // beta_12
        { Fq::push_dec("21575463638280843010398324269430826099269044274347216827212613867836435027261") }
        { Fq::push_dec("10307601595873709700152284273816112264069230130616436755625194854815875713954") }

         // beta_13
        { Fq::push_dec("2821565182194536844548159561693502659359617185244120367078079554186484126554") }
        { Fq::push_dec("3505843767911556378687030309984248845540243509899259641013678093033130930403") }

        // beta_22
        { Fq::push_dec("21888242871839275220042445260109153167277707414472061641714758635765020556616") }
        { Fq::push_zero() }
    }
}
