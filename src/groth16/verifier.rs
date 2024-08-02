use crate::bn254::ell_coeffs::G2Prepared;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq2::Fq2;
use crate::bn254::fq6::Fq6;
use crate::bn254::fq12::Fq12;
use crate::bn254::fr::Fr;
use crate::bn254::curves::G1Projective;
use crate::bn254::msm::msm;
use crate::bn254::pairing::Pairing;
use crate::bn254::utils::{fq12_push, u254_to_digits, ScriptInput};
use crate::groth16::constants::{LAMBDA, P_POW3};
use crate::groth16::offchain_checker::compute_c_wi;
use crate::signatures::winternitz_groth16::{checksig_verify_compressed, digit_pk, sign_digits_compressed};
use crate::treepp::{script, Script};

use ark_bn254::Bn254;
use ark_ec::bn::{BnConfig, G1Prepared};
use ark_ec::pairing::Pairing as ark_Pairing;
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ec::{CurveGroup, VariableBaseMSM, AffineRepr};
use ark_ff::Field;
use ark_groth16::{prepare_verifying_key, Proof, VerifyingKey};
use num_bigint::BigUint;
use rand::Rng;
use std::collections::HashMap;
use std::str::FromStr;
use num_traits::{Num, One};
use std::{iter::zip, ops::{Mul, Rem}};

use super::utils::Groth16Data;
#[derive(Clone, Copy, Debug)]
pub struct Verifier;

impl Verifier {
    pub fn groth16_scripts_and_inputs(vk: &VerifyingKey<Bn254>, proof: &Proof<Bn254>, public_inputs: &<Bn254 as ark_Pairing>::ScalarField) -> (Vec<Script>, Vec<Vec<ScriptInput>>) {
        let (scripts, inputs) = (Vec::new(), Vec::new());
        (scripts, inputs)
    }

    pub fn sign(vk: &VerifyingKey<Bn254>, proof: &Proof<Bn254>, public: &<Bn254 as ark_Pairing>::ScalarField) -> (Vec<Vec<Script>>, Vec<Vec<Script>>, Vec<Vec<Vec<Vec<u8>>>>) {
        let (mut scripts, mut script_input_signatures, mut pks) = (Vec::new(), Vec::new(), Vec::new());
        let mut sks_map: HashMap<ark_bn254::Fq, (Vec<u8>, Vec<Vec<u8>>)> = HashMap::new();

        let dummy = Groth16Data::new("src/groth16/data/proof.json", "src/groth16/data/public.json", "src/groth16/data/vk.json");
        let (_, dummy_inputs) = Verifier::verify(&dummy.vk, &dummy.proof, &dummy.public[0]);

        for input_list in dummy_inputs.clone() {
            for input in input_list {
                for fq_element in input.to_fq() {
                    if !sks_map.contains_key(&fq_element) {
                        let sk: [u8; 32] = rand::thread_rng().gen();  // TODO: Better RNG function
                        let sk_vec = sk.to_vec();
                        let mut digit_pks: Vec<Vec<u8>> = Vec::new();
                        for i in 0..68 {
                            digit_pks.push(digit_pk(sk_vec.clone(), i));
                        }
                        sks_map.insert(fq_element, (sk_vec.clone(), digit_pks));
                    } 
                }
            }
        }

        let (main_scripts, main_inputs) = Verifier::verify(vk, proof, public);
        let r = BigUint::from_str_radix(Fq::MONTGOMERY_ONE, 16).unwrap();
        let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();
        
        for (script, input_list) in zip(main_scripts, main_inputs) {
            let (mut signatures, mut public_keys, mut commit_scripts) = (Vec::new(), Vec::new(), Vec::new());
            let mut fq_counter = 0;
            for input in input_list.iter().rev() {
                for fq_element in input.to_fq().iter().rev() {
                    fq_counter += 1;
                    commit_scripts.push(checksig_verify_compressed(sks_map.get(&fq_element).unwrap().clone().1));
                }
            }
            for input in input_list {
                for fq_element in input.to_fq() {
                    signatures.push(sign_digits_compressed(sks_map.get(&fq_element).unwrap().clone().0, u254_to_digits(BigUint::from(fq_element.clone()).mul(r.clone()).rem(p.clone()))));
                    public_keys.push(sks_map.get(&fq_element).unwrap().clone().1);
                }
            }
            commit_scripts.push(script! {
                for _ in 0..fq_counter {
                    { Fq::fromaltstack() }
                }
            });
            commit_scripts.push(script);

            scripts.push(commit_scripts);
            script_input_signatures.push(signatures);
            pks.push(public_keys);
        }

        (scripts, script_input_signatures, pks)
    }

    pub fn verify_proof(
        public_inputs: &Vec<<ark_bn254::Bn254 as ark_Pairing>::ScalarField>,
        proof: &Proof<ark_bn254::Bn254>,
        vk: &VerifyingKey<ark_bn254::Bn254>,
    ) -> Script {
        let (msm_script, msm_g1) = Self::prepare_inputs(public_inputs, vk);
        Self::verify_proof_with_prepared_inputs(proof, vk, msm_script, msm_g1)
    }

    pub fn prepare_inputs(
        public_inputs: &Vec<<ark_bn254::Bn254 as ark_Pairing>::ScalarField>,
        vk: &VerifyingKey<ark_bn254::Bn254>,
    ) -> (Script, Projective<ark_bn254::g1::Config>) {
        let scalars = [
            vec![<ark_bn254::Bn254 as ark_Pairing>::ScalarField::ONE],
            public_inputs.clone(),
        ]
        .concat();
        let sum_ai_abc_gamma =
            ark_bn254::G1Projective::msm(&vk.gamma_abc_g1, &scalars).expect("failed to calculate msm");
        (msm(&vk.gamma_abc_g1, &scalars), sum_ai_abc_gamma)
    }

    pub fn verify_proof_with_prepared_inputs(
        proof: &Proof<ark_bn254::Bn254>,
        vk: &VerifyingKey<ark_bn254::Bn254>,
        msm_script: Script,
        msm_g1: Projective<ark_bn254::g1::Config>,
    ) -> Script {
        let (exp, sign) = if LAMBDA.gt(&P_POW3) {
            (&*LAMBDA - &*P_POW3, true)
        } else {
            (&*P_POW3 - &*LAMBDA, false)
        };

        let pvk = prepare_verifying_key::<ark_bn254::Bn254>(vk);
        let beta_prepared = (-vk.beta_g2).into();
        let gamma_g2_neg_pc = pvk.gamma_g2_neg_pc.clone().into();
        let delta_g2_neg_pc = pvk.delta_g2_neg_pc.clone().into();

        let q_prepared = [gamma_g2_neg_pc, delta_g2_neg_pc, beta_prepared].to_vec();

        let sum_ai_abc_gamma = msm_g1.into_affine();

        let a: [G1Prepared<ark_bn254::Config>; 4] = [
            sum_ai_abc_gamma.into(),
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

        let hint = if sign {
            f * wi * (c_inv.pow((exp).to_u64_digits()))
        } else {
            f * wi * (c_inv.pow((exp).to_u64_digits()).inverse().unwrap())
        };

        assert_eq!(hint, c.pow(P_POW3.to_u64_digits()), "hint isn't correct!");

        let p2 = proof.c;
        let p3 = vk.alpha_g1;
        let p4 = proof.a;
        let q4 = proof.b;

        script! {
            // 1. push constants to stack
            { constants() }
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
            { check_pairing(&q_prepared, hint) }
        }
    }

    // scripts and the function for verifying a groth16 proof
    pub fn verify(vk: &VerifyingKey<ark_bn254::Bn254>, proof: &Proof<ark_bn254::Bn254>, public: &<ark_bn254::Bn254 as ark_Pairing>::ScalarField) -> (Vec<Script>, Vec<Vec<ScriptInput>>) {
        let (mut scripts, mut inputs) = (Vec::new(), Vec::new());

        let base1: ark_bn254::G1Projective = vk.gamma_abc_g1[0].into();
        let base2: ark_bn254::G1Projective = vk.gamma_abc_g1[1].into();
        let base2_times_public = base2 * public;

        let (sx, ix) = Fr::mul_by_constant_g1_verify(base2, *public, base2_times_public);
        // scripts.extend(sx);
        // inputs.extend(ix);

        let msm_addition_script = script! {
            { Fq::push_u32_le(&BigUint::from(base1.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(base1.y).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(base1.z).to_u32_digits()) }
            { G1Projective::add() }
            { G1Projective::equalverify() }
            OP_TRUE
        };
        // scripts.push(msm_addition_script);
        let msm_g1 = ark_bn254::G1Projective::msm(&vk.gamma_abc_g1, &[<ark_bn254::Bn254 as ark_Pairing>::ScalarField::ONE, public.clone()]).unwrap();
        // inputs.push(vec![ScriptInput::G1P(msm_g1), ScriptInput::G1P(base2_times_public)]);

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

        let two_inv = ark_bn254::Fq::from(2).inverse().unwrap();

        let mut f = c_inv;
        let mut t4 = q4.into_group();

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

            for j in 0..num_constant {
                let mut fx = f.clone();

                let coeffs = constant_iters[j].next().unwrap();

                let mut c0new = coeffs.0;
                c0new.mul_assign_by_fp(&p_lst[j].y);

                let mut c1new = coeffs.1;
                c1new.mul_assign_by_fp(&p_lst[j].x);

                fx.mul_by_034(&c0new, &c1new, &coeffs.2);

                let (sx, ix) = Pairing::ell_by_constant_verify(f, coeffs, p_lst[j], fx);
                scripts.extend(sx);
                inputs.extend(ix);

                f = fx;
            }

            let mut t4x = t4.clone();
            let mut a = t4x.x * &t4x.y;
            a.mul_assign_by_fp(&two_inv);
            let b = t4x.y.square();
            let cc = t4x.z.square();
            let e = ark_bn254::g2::Config::COEFF_B * &(cc.double() + &cc);
            let ff = e.double() + &e;
            let mut g = b + &ff;
            g.mul_assign_by_fp(&two_inv);
            let h = (t4x.y + &t4x.z).square() - &(b + &cc);
            let ii = e - &b;
            let j = t4x.x.square();
            let e_square = e.square();
            t4x.x = a * &(b - &ff);
            t4x.y = g.square() - &(e_square.double() + &e_square);
            t4x.z = b * &h;
            let coeffs = (-h, j.double() + &j, ii);
            let (sx, ix) = Pairing::modified_double_line_verify(t4, t4x, coeffs);
            scripts.extend(sx);
            inputs.extend(ix);
            t4 = t4x;

            let mut fx = f.clone();

            let mut c0new = coeffs.0;
            c0new.mul_assign_by_fp(&p4.y);

            let mut c1new = coeffs.1;
            c1new.mul_assign_by_fp(&p4.x);

            fx.mul_by_034(&c0new, &c1new, &coeffs.2);

            let (sx, ix) = Pairing::ell_verify(f, &coeffs, p4, fx);
            scripts.extend(sx);
            inputs.extend(ix);
            f = fx;

            if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                for j in 0..num_constant {
                    let mut fx = f.clone();

                    let coeffs = constant_iters[j].next().unwrap();

                    let mut c0new = coeffs.0;
                    c0new.mul_assign_by_fp(&p_lst[j].y);

                    let mut c1new = coeffs.1;
                    c1new.mul_assign_by_fp(&p_lst[j].x);

                    fx.mul_by_034(&c0new, &c1new, &coeffs.2);

                    let (sx, ix) = Pairing::ell_by_constant_verify(f, coeffs, p_lst[j], fx);
                    scripts.extend(sx);
                    inputs.extend(ix);

                    f = fx;
                }

                let mut t4x = t4.clone();
                let q4y = if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 {q4.y} else {-q4.y};
                let theta = t4x.y - &(q4y * &t4x.z);
                let lambda = t4x.x - &(q4.x * &t4x.z);
                let c = theta.square();
                let d = lambda.square();
                let e = lambda * &d;
                let ff = t4x.z * &c;
                let g = t4x.x * &d;
                let h = e + &ff - &g.double();
                t4x.x = lambda * &h;
                t4x.y = theta * &(g - &h) - &(e * &t4x.y);
                t4x.z *= &e;
                let j = theta * &q4.x - &(lambda * &q4y);
                let coeffs = (lambda, -theta, j);
                let (sx, ix) = Pairing::add_line_with_flag_verify(ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1, t4, q4.x, q4.y, t4x, coeffs);
                scripts.extend(sx);
                inputs.extend(ix);
                t4 = t4x;

                let mut fx = f.clone();
                let mut c0new = coeffs.0;
                c0new.mul_assign_by_fp(&p4.y);
                let mut c1new = coeffs.1;
                c1new.mul_assign_by_fp(&p4.x);
                fx.mul_by_034(&c0new, &c1new, &coeffs.2);
                let (sx, ix) = Pairing::ell_verify(f, &coeffs, p4, fx);
                scripts.extend(sx);
                inputs.extend(ix);
                f = fx;
            }
        }

        let c_inv_p = c_inv.frobenius_map(1);
        let (sx, ix) = Fq12::frobenius_map_verify(1, c_inv_p, c_inv);
        scripts.extend(sx);
        inputs.extend(ix);

        let fx = f * c_inv_p;
        let (sx, ix) = Fq12::mul_verify(f, c_inv_p, fx);
        scripts.extend(sx);
        inputs.extend(ix);
        f = fx;

        let c_p2 = c.frobenius_map(2);
        let (sx, ix) = Fq12::frobenius_map_verify(2, c_p2, c);
        scripts.extend(sx);
        inputs.extend(ix);

        let fx = f * c_p2;
        let (sx, ix) = Fq12::mul_verify(f, c_p2, fx);
        scripts.extend(sx);
        inputs.extend(ix);
        f = fx;

        let fx = f * wi;
        let (sx, ix) = Fq12::mul_verify(f, wi, fx);
        scripts.extend(sx);
        inputs.extend(ix);
        f = fx;

        for j in 0..num_constant {
            let mut fx = f.clone();

            let coeffs = constant_iters[j].next().unwrap();

            let mut c0new = coeffs.0;
            c0new.mul_assign_by_fp(&p_lst[j].y);

            let mut c1new = coeffs.1;
            c1new.mul_assign_by_fp(&p_lst[j].x);

            fx.mul_by_034(&c0new, &c1new, &coeffs.2);

            let (sx, ix) = Pairing::ell_by_constant_verify(f, coeffs, p_lst[j], fx);
            scripts.extend(sx);
            inputs.extend(ix);

            f = fx;
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
        let (sx, ix) = Pairing::add_line_with_flag_verify(true, t4, q4x, q4y, t4x, coeffs);
        scripts.extend(sx);
        inputs.extend(ix);
        t4 = t4x;

        let mut fx = f.clone();
        let mut c0new = coeffs.0;
        c0new.mul_assign_by_fp(&p4.y);
        let mut c1new = coeffs.1;
        c1new.mul_assign_by_fp(&p4.x);
        fx.mul_by_034(&c0new, &c1new, &coeffs.2);
        let (sx, ix) = Pairing::ell_verify(f, &coeffs, p4, fx);
        scripts.extend(sx);
        inputs.extend(ix);
        f = fx;

        for j in 0..num_constant {
            let mut fx = f.clone();

            let coeffs = constant_iters[j].next().unwrap();

            let mut c0new = coeffs.0;
            c0new.mul_assign_by_fp(&p_lst[j].y);

            let mut c1new = coeffs.1;
            c1new.mul_assign_by_fp(&p_lst[j].x);

            fx.mul_by_034(&c0new, &c1new, &coeffs.2);

            let (sx, ix) = Pairing::ell_by_constant_verify(f, coeffs, p_lst[j], fx);
            scripts.extend(sx);
            inputs.extend(ix);

            f = fx;
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
        let (sx, ix) = Pairing::add_line_with_flag_verify(true, t4, q4x, q4y, t4x, coeffs);
        scripts.extend(sx);
        inputs.extend(ix);
        t4 = t4x;

        let mut fx = f.clone();
        let mut c0new = coeffs.0;
        c0new.mul_assign_by_fp(&p4.y);
        let mut c1new = coeffs.1;
        c1new.mul_assign_by_fp(&p4.x);
        fx.mul_by_034(&c0new, &c1new, &coeffs.2);
        let (sx, ix) = Pairing::ell_verify(f, &coeffs, p4, fx);
        scripts.extend(sx);
        inputs.extend(ix);
        f = fx;

        assert_eq!(f, hint);

        for i in 0..num_constant {
            assert_eq!(constant_iters[i].next(), None);
        }

        (scripts, inputs)
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
        // Input stack: [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4]
        // Output stack: [final_f]
        { Pairing::quad_miller_loop_with_c_wi(precompute_lines) }

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

        // 1/2
        { Fq::push_u32_le(&BigUint::from(ark_bn254::Fq::one().double().inverse().unwrap()).to_u32_digits()) }

        // B
        { Fq::push_u32_le(&BigUint::from(ark_bn254::g2::Config::COEFF_B.c0).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(ark_bn254::g2::Config::COEFF_B.c1).to_u32_digits()) }
    }
}
