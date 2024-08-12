use crate::bn254::ell_coeffs::G2Prepared;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fr::Fr;
use crate::bn254::fq::Fq;
use crate::bn254::fq12::Fq12;
use crate::bn254::msm::msm;
use crate::bn254::pairing::Pairing;
use crate::bn254::utils::{biguint_to_digits, from_eval_point};
use crate::groth16::constants::{LAMBDA, P_POW3};
use crate::groth16::offchain_checker::compute_c_wi;
use crate::groth16::utils::{ScriptInput, Groth16Data, fq12_push, fq2_push};
use crate::treepp::{script, Script};
use crate::signatures::winternitz_compact::*;
use ark_bn254::{Bn254, G1Projective};
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
            G1Projective::msm(&vk.gamma_abc_g1, &scalars).expect("failed to calculate msm");
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
