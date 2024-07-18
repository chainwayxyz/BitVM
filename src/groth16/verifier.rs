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
use crate::bn254::utils::{fq12_push, ScriptInput};
use crate::groth16::constants::{LAMBDA, P_POW3};
use crate::groth16::offchain_checker::compute_c_wi;
use crate::treepp::{script, Script};
use ark_ec::bn::{G1Prepared, BnConfig};
use ark_ec::pairing::Pairing as ark_Pairing;
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ec::{CurveGroup, VariableBaseMSM, AffineRepr};
use ark_ff::Field;
use ark_groth16::{prepare_verifying_key, Proof, VerifyingKey};
use num_bigint::BigUint;
use num_traits::One;
use std::str::FromStr;

#[derive(Clone, Copy, Debug)]
pub struct Verifier;

impl Verifier {
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
    pub fn verify(vk: VerifyingKey<ark_bn254::Bn254>) -> (Vec<Script>, fn(VerifyingKey<ark_bn254::Bn254>, Proof<ark_bn254::Bn254>, Vec<<ark_bn254::Bn254 as ark_ec::pairing::Pairing>::ScalarField>) -> Vec<Vec<ScriptInput>>) {
        let mut scripts = Vec::new();

        let base1: ark_bn254::G1Projective = vk.gamma_abc_g1[0].into();
        let base2: ark_bn254::G1Projective = vk.gamma_abc_g1[1].into();

        scripts.extend(Fr::mul_by_constant_g1_verify(base2).0);

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
            scripts.extend(Fq12::mul_verify().0);

            if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 {
                scripts.extend(Fq12::mul_verify().0);
            }
            else if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                scripts.extend(Fq12::mul_verify().0);
            }

            for j in 0..num_constant {
                let coeffs = constant_iters[j].next().unwrap();

                scripts.extend(Pairing::ell_by_constant_verify(coeffs).0);
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

            scripts.extend(Pairing::ell_verify().0);

            if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                for j in 0..num_constant {
                    let coeffs = constant_iters[j].next().unwrap();
        
                    scripts.extend(Pairing::ell_by_constant_verify(coeffs).0);
                }

                scripts.extend(Pairing::add_line_with_flag_verify(ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1).0);

                scripts.extend(Pairing::ell_verify().0);
            }
        }

        let quad_miller_s3_1 = script! {
            { Fq12::frobenius_map(1) }
            { Fq12::equalverify() }
            OP_TRUE
        };
        scripts.push(quad_miller_s3_1);

        scripts.extend(Fq12::mul_verify().0);

        let quad_miller_s3_3 = script! {
            { Fq12::frobenius_map(2) }
            { Fq12::equalverify() }
            OP_TRUE
        };
        scripts.push(quad_miller_s3_3);

        scripts.extend(Fq12::mul_verify().0);

        scripts.extend(Fq12::mul_verify().0);

        for j in 0..num_constant {
            let coeffs = constant_iters[j].next().unwrap();

            scripts.extend(Pairing::ell_by_constant_verify(coeffs).0);
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

        scripts.extend(Pairing::add_line_with_flag_verify(true).0);

        scripts.extend(Pairing::ell_verify().0);

        for j in 0..num_constant {
            let coeffs = constant_iters[j].next().unwrap();

            scripts.extend(Pairing::ell_by_constant_verify(coeffs).0);
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

        scripts.extend(Pairing::add_line_with_flag_verify(true).0);

        scripts.extend(Pairing::ell_verify().0);

        for i in 0..num_constant {
            assert_eq!(constant_iters[i].next(), None);
        }

        fn calculate_inputs(vk: VerifyingKey<ark_bn254::Bn254>, proof: Proof<ark_bn254::Bn254>, public: Vec<<ark_bn254::Bn254 as ark_ec::pairing::Pairing>::ScalarField>) -> Vec<Vec<ScriptInput>> {
            let mut inputs = Vec::new();

            // we have only one public input
            assert_eq!(public.len(), 1);
            let public = public[0];

            let msm_g1 = ark_bn254::G1Projective::msm(&vk.gamma_abc_g1, &[<ark_bn254::Bn254 as ark_Pairing>::ScalarField::ONE, public.clone()]).expect("failed to calculate msm");

            let base1: ark_bn254::G1Projective = vk.gamma_abc_g1[0].into();
            let base2: ark_bn254::G1Projective = vk.gamma_abc_g1[1].into();
            let base2_times_public = base2 * public;

            assert_eq!(msm_g1, base2_times_public + base1);

            inputs.extend(Fr::mul_by_constant_g1_verify(base2).1(base2, public, base2_times_public));

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
                inputs.extend(Fq12::mul_verify().1(f1, f1, fx));
                f1 = fx;

                if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 {
                    // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f^2 * c_inv]
                    let fx = f1 * c_inv;
                    inputs.extend(Fq12::mul_verify().1(f1, c_inv, fx));
                    f1 = fx;
                }
                else if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                    // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f^2 * c]
                    let fx = f1 * c;
                    inputs.extend(Fq12::mul_verify().1(f1, c, fx));
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

                    inputs.extend(Pairing::ell_by_constant_verify(coeffs).1(f1, coeffs, p_lst[j], fx));
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
                inputs.extend(Pairing::ell_verify().1(f1, &coeffs, p4, fx));
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
            
                        inputs.extend(Pairing::ell_by_constant_verify(coeffs).1(f1, coeffs, p_lst[j], fx));
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

                    inputs.extend(Pairing::add_line_with_flag_verify(ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1).1(ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1, t4_1, q4.x, q4.y));
                    t4_1 = t4x;

                    let mut fx = f1.clone();

                    let mut c0new = coeffs.0;
                    c0new.mul_assign_by_fp(&p4.y);

                    let mut c1new = coeffs.1;
                    c1new.mul_assign_by_fp(&p4.x);

                    fx.mul_by_034(&c0new, &c1new, &coeffs.2);

                    // inputs.push(vec![ScriptInput::Fq12(fx), ScriptInput::Fq12(f1), ScriptInput::Fq2(coeffs.0), ScriptInput::Fq2(coeffs.1), ScriptInput::Fq2(coeffs.2), ScriptInput::G1A(p4)]);
                    inputs.extend(Pairing::ell_verify().1(f1, &coeffs, p4, fx));
                    f1 = fx;
                }

                assert_eq!(f1, f2);
                assert_eq!(t4_1, t4_2);
            }

            let mut f = f_vec[ark_bn254::Config::ATE_LOOP_COUNT.len() - 1];

            let c_inv_p = c_inv.frobenius_map(1);

            inputs.push(vec![ScriptInput::Fq12(c_inv_p), ScriptInput::Fq12(c_inv)]);

            let fx = f * c_inv_p;
            inputs.extend(Fq12::mul_verify().1(f, c_inv_p, fx));
            f = fx;

            let c_p2 = c.frobenius_map(2);

            inputs.push(vec![ScriptInput::Fq12(c_p2), ScriptInput::Fq12(c)]);

            let fx = f * c_p2;
            inputs.extend(Fq12::mul_verify().1(f, c_p2, fx));
            f = fx;

            let fx = f * wi;
            inputs.extend(Fq12::mul_verify().1(f, wi, fx));
            f = fx;

            for j in 0..num_constant {
                let mut fx = f.clone();
                let coeffs = constant_iters[j].next().unwrap();

                let mut c0new = coeffs.0;
                c0new.mul_assign_by_fp(&p_lst[j].y);

                let mut c1new = coeffs.1;
                c1new.mul_assign_by_fp(&p_lst[j].x);

                fx.mul_by_034(&c0new, &c1new, &coeffs.2);

                inputs.extend(Pairing::ell_by_constant_verify(coeffs).1(f, coeffs, p_lst[j], fx));
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

            inputs.extend(Pairing::add_line_with_flag_verify(true).1(true, t4, q4x, q4y));
            t4 = t4x;

            let mut fx = f.clone();

            let mut c0new = coeffs.0;
            c0new.mul_assign_by_fp(&p4.y);

            let mut c1new = coeffs.1;
            c1new.mul_assign_by_fp(&p4.x);

            fx.mul_by_034(&c0new, &c1new, &coeffs.2);

            inputs.extend(Pairing::ell_verify().1(f, &coeffs, p4, fx));
            f = fx;

            for j in 0..num_constant {
                let mut fx = f.clone();
                let coeffs = constant_iters[j].next().unwrap();

                let mut c0new = coeffs.0;
                c0new.mul_assign_by_fp(&p_lst[j].y);

                let mut c1new = coeffs.1;
                c1new.mul_assign_by_fp(&p_lst[j].x);

                fx.mul_by_034(&c0new, &c1new, &coeffs.2);

                inputs.extend(Pairing::ell_by_constant_verify(coeffs).1(f, coeffs, p_lst[j], fx));
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

            inputs.extend(Pairing::add_line_with_flag_verify(true).1(true, t4, q4x, q4y));
            // t4 = t4x;

            let mut fx = f.clone();

            let mut c0new = coeffs.0;
            c0new.mul_assign_by_fp(&p4.y);

            let mut c1new = coeffs.1;
            c1new.mul_assign_by_fp(&p4.x);

            fx.mul_by_034(&c0new, &c1new, &coeffs.2);

            // inputs.push(vec![ScriptInput::Fq12(fx), ScriptInput::Fq12(f), ScriptInput::Fq2(coeffs.0), ScriptInput::Fq2(coeffs.1), ScriptInput::Fq2(coeffs.2), ScriptInput::G1A(p4)]);
            inputs.extend(Pairing::ell_verify().1(f, &coeffs, p4, fx));
            f = fx;

            assert_eq!(f, hint);

            for i in 0..num_constant {
                assert_eq!(constant_iters[i].next(), None);
            }

            inputs
        }

        (scripts, calculate_inputs)
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
