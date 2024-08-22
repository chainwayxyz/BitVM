use num_bigint::BigUint;
use crate::bn254::curves::G1Projective;
use crate::groth16::utils::g1p_push;
use crate::{bn254::fp254impl::Fp254Impl, groth16::utils::ScriptInput};
use crate::treepp::*;
use std::cmp::min;
use std::ops::Mul;
use num_traits::Zero;
use ark_ec::AdditiveGroup;

pub struct Fr;

impl Fp254Impl for Fr {
    const MODULUS: &'static str =
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

    // 2²⁶¹ mod p  <=>  0xdc83629563d44755301fa84819caa8075bba827a494b01a2fd4e1568fffff57
    const MONTGOMERY_ONE: &'static str =
        "dc83629563d44755301fa84819caa8075bba827a494b01a2fd4e1568fffff57";

    // p = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
    const MODULUS_LIMBS: [u32; Self::N_LIMBS as usize] = [
        0x10000001, 0x1f0fac9f, 0xe5c2450, 0x7d090f3, 0x1585d283, 0x2db40c0, 0xa6e141, 0xe5c2634, 0x30644e
    ];
    // inv₂₆₁ p  <=>  0xd8c07d0e2f27cbe4d1c6567d766f9dc6e9a7979b4b396ee4c3d1e0a6c10000001
    const MODULUS_INV_261: [u32; Self::N_LIMBS as usize] = [
        0x10000001, 0x8f05360, 0x5bb930f, 0x12f36967, 0x1dc6e9a7, 0x13ebb37c, 0x19347195, 0x1c5e4f97, 0xd8c07d0
    ];

    const P_PLUS_ONE_DIV2: &'static str =
        "183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000001";

    const TWO_P_PLUS_ONE_DIV3: &'static str =
        "2042def740cbc01bd03583cf0100e59370229adafbd0f5b62d414e62a0000001";

    const P_PLUS_TWO_DIV3: &'static str =
        "10216f7ba065e00de81ac1e7808072c9b8114d6d7de87adb16a0a73150000001";
    type ConstantType = ark_bn254::Fr;

}

pub fn dfs(index: u32, depth: u32,  mask: u32, p_mul: &Vec<ark_bn254::G1Projective>) -> Script {
    if depth == 0 {
        return script!{
            OP_IF
                { g1p_push(p_mul[(mask + (1<<index) - 1) as usize]) }
            OP_ELSE
                if mask == 0 {
                    OP_FROMALTSTACK
                    OP_NOT
                    OP_TOALTSTACK
                } else {
                    { g1p_push(p_mul[(mask - 1) as usize]) }
                }
            OP_ENDIF
        };
    }
    script!{
        OP_IF 
            { dfs(index+1, depth-1, mask + (1<<index), p_mul) }
        OP_ELSE
            { dfs(index+1, depth-1, mask, p_mul) }
        OP_ENDIF
    }

}

impl Fr {
    // scripts and the function for calculating corresponding inputs for verifying a*P=Q where P is a constant G1, a is a scalar Fr, and Q is a G1
    pub fn mul_by_constant_g1_verify(g1: ark_bn254::G1Projective, scalar: ark_bn254::Fr, result: ark_bn254::G1Projective) -> (Vec<Script>, Vec<Vec<ScriptInput>>) {
        let (mut scripts, mut inputs) = (Vec::new(), Vec::new());

        let p = g1;

        let a = scalar;
        let q = p.mul(a);

        assert_eq!(q, result);

        let bits = BigUint::from(a).to_bytes_le().iter().map(|x| (0..8).map(|i| {(1 << i) & x > 0}).collect()).collect::<Vec<Vec<bool>>>().into_iter().flatten().rev().map(|x| if x {1} else {0}).collect::<Vec<usize>>();
        let bits = bits.split_at(2).1;

        let script_initial = script! {
            { Fr::decode_montgomery() }
            { Fr::convert_to_le_bits() }

            for i in (0..Fr::N_BITS).rev() {
                { i + 1 } OP_ROLL OP_EQUALVERIFY
            }
            OP_TRUE
        };
        scripts.push(script_initial);
        let mut inputs_bits = vec![];
        for (i, b) in bits.iter().enumerate() {
            inputs_bits.push(ScriptInput::Bit(*b, i.to_string()));
        }
        inputs_bits.push(ScriptInput::Fr(a));
        inputs.push(inputs_bits);

        let mut g = ark_bn254::G1Projective::zero();
        let script_loop_0 = script! {
            { G1Projective::push_zero() }
            { G1Projective::equalverify() }
            OP_TRUE
        };
        scripts.push(script_loop_0);
        inputs.push(vec![ScriptInput::G1P(g)]);
        
        // i_step=14, j_step=3 -> 442363186
        // i_step=13, j_step=3 -> 434534759
        // i_step=12, j_step=3 -> 417517517
        // i_step=11, j_step=3 -> 427537163
        // i_step=10, j_step=3 -> 440993138
        // i_step=8,  j_step=3 -> 450612486

        // i_step=14, j_step=2 -> 481593624
        // i_step=13, j_step=2 -> 477034398
        // i_step=12, j_step=2 -> 463286391
        // i_step=11, j_step=2 -> 477664973
        // i_step=10, j_step=2 -> 468236549
        // i_step=8,  j_step=2 -> 485484046
        // i_step=2,  j_step=2 -> 795099453


        let mut i = 0;
        let i_step = 8;
        let j_step = 2;

        let mut p_mul: Vec<ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>> = Vec::new();
        p_mul.push(p);
        for _ in 0..(1<<i_step) { 
            p_mul.push(p_mul.last().unwrap() + p);
        }
        
        while i < Fr::N_BITS { 
            let mut j = i;
            let ibound = min(Fr::N_BITS, i + i_step);

            if i > 0 {
                while j < ibound {
                    let jbound = min(ibound, j + j_step);
                    let mut g_new = g;

                    for _ in j..jbound {
                        g_new.double_in_place();
                    }

                    let script_loop = script! {
                        for _ in j..jbound {
                            { G1Projective::double() }
                        }
                        { G1Projective::equalverify() }
                        OP_TRUE
                    };
                    scripts.push(script_loop.clone());
                    inputs.push(vec![ScriptInput::G1P(g_new), ScriptInput::G1P(g)]);

                    g = g_new;
                    j += j_step;
                }
            }

            let mut coeff = 0;
            for x in i..ibound {
                coeff *= 2;
                coeff += bits[x as usize];
            }
            let mut g_new = g;
            if coeff != 0 {
                g_new += p_mul[coeff - 1];
            }

            let depth = ibound - i;
            let script_loop_2 = script! {
                OP_TRUE
                OP_TOALTSTACK
                { dfs(0, depth - 1, 0, &p_mul) }
                OP_FROMALTSTACK
                
                OP_IF
                    { G1Projective::add() }
                OP_ENDIF
        
                { G1Projective::equalverify() }
                OP_TRUE
            };
            scripts.push(script_loop_2.clone());
            let mut input = Vec::new();
            input.push(ScriptInput::G1P(g_new));
            input.push(ScriptInput::G1P(g));
            for x in i..ibound {
                input.push(ScriptInput::Bit(bits[x as usize], (x).to_string()));
            }
            inputs.push(input);

            g = g_new;
            i += i_step;
        }

        assert_eq!(q, g);

        (scripts, inputs)
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fr::Fr;
    use crate::treepp::*;
    use ark_ff::{BigInteger, Field, PrimeField};
    use ark_std::UniformRand;
    use core::ops::{Add, Mul, Rem, Sub};
    use num_bigint::{BigUint, RandomBits};
    use num_traits::Num;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use ark_ff::AdditiveGroup;

    #[test]
    fn test_decode_montgomery() {
        println!("Fr.decode_montgomery: {} bytes", Fr::decode_montgomery().len());
        let script = script! {
            { Fr::push_one() }
            { Fr::push_u32_le(&BigUint::from_str_radix(Fr::MONTGOMERY_ONE, 16).unwrap().to_u32_digits()) }
            { Fr::decode_montgomery() }
            { Fr::equalverify(1, 0) }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_add() {
        println!("Fr.add: {} bytes", Fr::add(0, 1).len());

        let m = BigUint::from_str_radix(Fr::MODULUS, 16).unwrap();

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));

            let a = a.rem(&m);
            let b = b.rem(&m);
            let c: BigUint = a.clone().add(b.clone()).rem(&m);

            let script = script! {
                { Fr::push_u32_le(&a.to_u32_digits()) }
                { Fr::push_u32_le(&b.to_u32_digits()) }
                { Fr::add(1, 0) }
                { Fr::push_u32_le(&c.to_u32_digits()) }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_sub() {
        println!("Fr.sub: {} bytes", Fr::sub(0, 1).len());

        let m = BigUint::from_str_radix(Fr::MODULUS, 16).unwrap();

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));

            let a = a.rem(&m);
            let b = b.rem(&m);
            let c: BigUint = a.clone().add(&m).sub(b.clone()).rem(&m);

            let script = script! {
                { Fr::push_u32_le(&a.to_u32_digits()) }
                { Fr::push_u32_le(&b.to_u32_digits()) }
                { Fr::sub(1, 0) }
                { Fr::push_u32_le(&c.to_u32_digits()) }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_double() {
        println!("Fr.double: {} bytes", Fr::double(0).len());
        let m = BigUint::from_str_radix(Fr::MODULUS, 16).unwrap();

        for _ in 0..100 {
            let a: BigUint = m.clone().sub(BigUint::new(vec![1]));

            let a = a.rem(&m);
            let c: BigUint = a.clone().add(a.clone()).rem(&m);

            let script = script! {
                { Fr::push_u32_le(&a.to_u32_digits()) }
                { Fr::double(0) }
                { Fr::push_u32_le(&c.to_u32_digits()) }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_mul() {
        println!("Fr.mul: {} bytes", Fr::mul().len());
        let m = BigUint::from_str_radix(Fr::MODULUS, 16).unwrap();
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..3 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));

            let a = a.rem(&m);
            let b = b.rem(&m);
            let c: BigUint = a.clone().mul(b.clone()).rem(&m);

            let script = script! {
                { Fr::push_u32_le(&a.to_u32_digits()) }
                { Fr::push_u32_le(&b.to_u32_digits()) }
                { Fr::mul() }
                { Fr::push_u32_le(&c.to_u32_digits()) }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_square() {
        println!("Fr.square: {} bytes", Fr::square().len());
        let m = BigUint::from_str_radix(Fr::MODULUS, 16).unwrap();

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..10 {
            let a: BigUint = prng.sample(RandomBits::new(254));

            let a = a.rem(&m);
            let c: BigUint = a.clone().mul(a.clone()).rem(&m);

            let script = script! {
                { Fr::push_u32_le(&a.to_u32_digits()) }
                { Fr::square() }
                { Fr::push_u32_le(&c.to_u32_digits()) }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_neg() {
        println!("Fr.neg: {} bytes", Fr::neg(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let a: BigUint = prng.sample(RandomBits::new(254));

            let script = script! {
                { Fr::push_u32_le(&a.to_u32_digits()) }
                { Fr::copy(0) }
                { Fr::neg(0) }
                { Fr::add(0, 1) }
                { Fr::push_zero() }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_inv() {
        println!("Fr.inv: {} bytes", Fr::inv().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fr::rand(&mut prng);
            let c = a.inverse().unwrap();

            let script = script! {
                { Fr::push_u32_le(&BigUint::from(a).to_u32_digits()) }
                { Fr::inv() }
                { Fr::push_u32_le(&BigUint::from(c).to_u32_digits()) }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_div2() {
        println!("Fr.div2: {} bytes", Fr::div2().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let a = ark_bn254::Fr::rand(&mut prng);
            let c = a.double();

            let script = script! {
                { Fr::push_u32_le(&BigUint::from(c).to_u32_digits()) }
                { Fr::div2() }
                { Fr::push_u32_le(&BigUint::from(a).to_u32_digits()) }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_div3() {
        println!("Fr.div3: {} bytes", Fr::div3().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let a = ark_bn254::Fr::rand(&mut prng);
            let b = a.clone().double();
            let c = a.add(b);

            let script = script! {
                { Fr::push_u32_le(&BigUint::from(c).to_u32_digits()) }
                { Fr::div3() }
                { Fr::push_u32_le(&BigUint::from(a).to_u32_digits()) }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_is_one() {
        println!("Fr.is_one: {} bytes", Fr::is_one(0).len());
        println!("Fr.is_one_keep_element: {} bytes", Fr::is_one_keep_element(0).len());
        let script = script! {
            { Fr::push_one() }
            { Fr::is_one_keep_element(0) }
            { Fr::is_one(1) }
            OP_BOOLAND
        };
    }

    #[test]
    fn test_is_zero() {
        println!("Fr.is_zero: {} bytes", Fr::is_zero(0).len());
        println!("Fr.is_zero_keep_element: {} bytes", Fr::is_zero_keep_element(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let a = ark_bn254::Fr::rand(&mut prng);

            let script = script! {
                // Push three Fr elements
                { Fr::push_zero() }
                { Fr::push_u32_le(&BigUint::from(a).to_u32_digits()) }
                { Fr::push_u32_le(&BigUint::from(a).to_u32_digits()) }

                // The first element should not be zero
                { Fr::is_zero_keep_element(0) }
                OP_NOT
                OP_TOALTSTACK

                // The third element should be zero
                { Fr::is_zero_keep_element(2) }
                OP_TOALTSTACK

                // Drop all three elements
                { Fr::drop() }
                { Fr::drop() }
                { Fr::drop() }

                // Both results should be true
                OP_FROMALTSTACK
                OP_FROMALTSTACK
                OP_BOOLAND
                { Fr::push_zero() }
                { Fr::is_zero(0) }
                OP_BOOLAND
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_mul_by_constant() {
        let m = BigUint::from_str_radix(Fr::MODULUS, 16).unwrap();
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for i in 0..3 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let a = a.rem(&m);

            let b: BigUint = prng.sample(RandomBits::new(254));
            let b = b.rem(&m);

            let mul_by_constant = Fr::mul_by_constant(&ark_bn254::Fr::from(b.clone()));

            if i == 0 {
                println!("Fr.mul_by_constant: {} bytes", mul_by_constant.len());
            }

            let c: BigUint = a.clone().mul(b.clone()).rem(&m);

            let script = script! {
                { Fr::push_u32_le(&a.to_u32_digits()) }
                { mul_by_constant.clone() }
                { Fr::push_u32_le(&c.to_u32_digits()) }
                { Fr::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_is_field() {
        let m = BigUint::from_str_radix(Fr::MODULUS, 16).unwrap();
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        println!("Fr.is_field: {} bytes", Fr::is_field().len());

        for _ in 0..10 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let a = a.rem(&m);

            let script = script! {
                { Fr::push_u32_le(&a.to_u32_digits()) }
                { Fr::is_field() }
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        let script = script! {
            { Fr::push_modulus() } OP_1 OP_ADD
            { Fr::is_field() }
            OP_NOT
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);

        let script = script! {
            { Fr::push_modulus() } OP_1 OP_SUB
            OP_NEGATE
            { Fr::is_field() }
            OP_NOT
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_convert_to_be_bytes() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let convert_to_be_bytes_script = Fr::convert_to_be_bytes();
        println!(
            "Fr.convert_to_be_bytes: {} bytes",
            convert_to_be_bytes_script.len()
        );

        for _ in 0..10 {
            let fr = ark_bn254::Fr::rand(&mut prng);
            let bytes = fr.into_bigint().to_bytes_be();

            let script = script! {
                { Fr::push_u32_le(&BigUint::from(fr).to_u32_digits()) }
                { convert_to_be_bytes_script.clone() }
                for i in 0..32 {
                    { bytes[i] } OP_EQUALVERIFY
                }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
