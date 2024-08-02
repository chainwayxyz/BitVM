use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::curves::G1Projective;
use crate::bn254::utils::{g1p_push, ScriptInput};
use crate::treepp::{script, Script};
use num_traits::Zero;
use num_bigint::BigUint;
use ark_ec::Group;
use std::ops::Mul;

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

impl Fr {
    // scripts and the function for calculating corresponding inputs for verifying a*P=Q where P is a constant G1, a is a scalar Fr, and Q is a G1
    pub fn mul_by_constant_g1_verify(g1: ark_bn254::G1Projective, scalar: ark_bn254::Fr, result: ark_bn254::G1Projective) -> (Vec<Script>, Vec<Vec<ScriptInput>>) {
        let (mut scripts, mut inputs) = (Vec::new(), Vec::new());

        let p = g1;
        let two_p = p + p;
        let three_p = p + p + p;

        let a = scalar;
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

        for i in 0..(Fr::N_BITS / 2) {
            let g = g1_projs[i as usize];
            let four_g = g.double().double();

            if i == 0 {
                let script_loop_0 = script! {
                    { G1Projective::push_zero() }
                    { G1Projective::equalverify() }
                    OP_TRUE
                };
                scripts.push(script_loop_0);
                inputs.push(vec![ScriptInput::G1P(g)]);
            }

            let script_loop_1 = script! {
                { G1Projective::double() }
                { G1Projective::double() }
                { G1Projective::equalverify() }
                OP_TRUE
            };
            scripts.push(script_loop_1.clone());
            inputs.push(vec![ScriptInput::G1P(four_g), ScriptInput::G1P(g)]);

            let script_loop_2 = script! {
                OP_IF
                    OP_IF
                        { g1p_push(three_p) }
                    OP_ELSE
                        { g1p_push(p) }
                    OP_ENDIF
                    OP_TRUE
                OP_ELSE
                    OP_IF
                        { g1p_push(two_p) }
                        OP_TRUE
                    OP_ELSE
                        OP_FALSE
                    OP_ENDIF
                OP_ENDIF
                OP_IF
                    { G1Projective::add() }
                OP_ENDIF
        
                { G1Projective::equalverify() }
                OP_TRUE
            };
            scripts.push(script_loop_2.clone());
            inputs.push(vec![ScriptInput::G1P(g1_projs[i as usize + 1]), ScriptInput::G1P(four_g), ScriptInput::Bit(bits[2 * i as usize], (2 * i).to_string()), ScriptInput::Bit(bits[2 * i as usize + 1], (2 * i + 1).to_string())]);
        }

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
