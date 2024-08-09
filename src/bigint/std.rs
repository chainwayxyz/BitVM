use num_bigint::BigUint;
use num_traits::Num;
use std::str::FromStr;

use crate::bigint::BigIntImpl;
use crate::pseudo::push_to_stack;
use crate::treepp::*;

pub fn OP_256MUL() -> Script {
    script! {
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
    }
}

pub fn OP_128MUL() -> Script {
    script! {
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD
    }
}

pub fn OP_64MUL() -> Script {
    script! {
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
    }
}

pub fn OP_32MUL() -> Script {
    script! {
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD
    }
}

pub fn OP_16MUL() -> Script {
    script! {
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
    }
}

pub fn OP_8MUL() -> Script {
    script! {
        OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
    }
}

pub fn OP_4MUL() -> Script {
    script! {
        OP_DUP OP_ADD OP_DUP OP_ADD
    }
}

pub fn OP_2MUL() -> Script {
    script! {
        OP_DUP OP_ADD
    }
}

impl<const N_BITS: u32, const LIMB_SIZE: u32> BigIntImpl<N_BITS, LIMB_SIZE> {
    pub fn push_u32_le(v: &[u32]) -> Script {
        let mut bits = vec![];
        for elem in v.iter() {
            for i in 0..32 {
                bits.push((elem & (1 << i)) != 0);
            }
        }
        bits.resize(N_BITS as usize, false);

        let mut limbs = vec![];
        for chunk in bits.chunks(LIMB_SIZE as usize) {
            let mut chunk_vec = chunk.to_vec();
            chunk_vec.resize(LIMB_SIZE as usize, false);

            let mut elem = 0u32;
            for i in 0..LIMB_SIZE as usize {
                if chunk_vec[i] {
                    elem += 1 << i;
                }
            }

            limbs.push(elem);
        }

        limbs.reverse();

        script! {
            for limb in &limbs {
                { *limb }
            }
            { push_to_stack(0,Self::N_LIMBS as usize - limbs.len()) }
        }
    }

    pub fn push_u64_le(v: &[u64]) -> Script {
        let v = v
            .iter()
            .flat_map(|v| {
                [
                    (v & 0xffffffffu64) as u32,
                    ((v >> 32) & 0xffffffffu64) as u32,
                ]
            })
            .collect::<Vec<u32>>();

        Self::push_u32_le(&v)
    }

    pub fn from_bytes() -> Script {
        script! {
            for _ in 0..28 { OP_TOALTSTACK }
            // b0, b1, b2, b3

            { 0x80 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_4 OP_ELSE OP_DROP OP_0 OP_ENDIF OP_TOALTSTACK
            { 0x40 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_2 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            { 0x20 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_1 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_256MUL OP_ADD
            OP_256MUL OP_ADD
            OP_256MUL OP_ADD
            OP_FROMALTSTACK

            for _ in 0..4 { OP_FROMALTSTACK }
            // c0, x, b4, b5, b6, b7

            { 0x80 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB { 32 } OP_ELSE OP_DROP OP_0 OP_ENDIF OP_TOALTSTACK
            { 0x40 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_16 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            { 0x20 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_8 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_16 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_4 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_8 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_2 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_4 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_1 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_256MUL OP_ADD
            OP_256MUL OP_ADD
            OP_256MUL OP_ADD
            OP_8MUL OP_ADD
            OP_FROMALTSTACK

            for _ in 0..3 { OP_FROMALTSTACK }
            // c0, c1, x, b8, b9, b10

            { 0x80 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_1 OP_ELSE OP_DROP OP_0 OP_ENDIF OP_TOALTSTACK
            OP_256MUL OP_ADD
            OP_256MUL OP_ADD
            OP_64MUL OP_ADD
            OP_FROMALTSTACK

            for _ in 0..4 { OP_FROMALTSTACK }
            // c0, c1, c2, x, b11, b12, b13, b14

            { 0x80 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_8 OP_ELSE OP_DROP OP_0 OP_ENDIF OP_TOALTSTACK
            { 0x40 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_4 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            { 0x20 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_2 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_16 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_1 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_256MUL OP_ADD
            OP_256MUL OP_ADD
            OP_256MUL OP_ADD
            { OP_2MUL() } OP_ADD
            OP_FROMALTSTACK

            for _ in 0..4 { OP_FROMALTSTACK }
            // c0, c1, c2, c3, x, b15, b16, b17, b18

            { 0x80 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB { 64 } OP_ELSE OP_DROP OP_0 OP_ENDIF OP_TOALTSTACK
            { 0x40 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB { 32 } OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            { 0x20 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_16 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_16 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_8 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_8 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_4 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_4 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_2 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_2 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_1 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_256MUL OP_ADD
            OP_256MUL OP_ADD
            OP_256MUL OP_ADD
            OP_16MUL OP_ADD
            OP_FROMALTSTACK

            for _ in 0..3 { OP_FROMALTSTACK }
            // c0, c1, c2, c3, c4, x, b19, b20, b21

            { 0x80 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_2 OP_ELSE OP_DROP OP_0 OP_ENDIF OP_TOALTSTACK
            { 0x40 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_1 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_256MUL OP_ADD
            OP_256MUL OP_ADD
            OP_128MUL OP_ADD
            OP_FROMALTSTACK

            for _ in 0..4 { OP_FROMALTSTACK }
            // c0, c1, c2, c3, c4, c5, x, b22, b23, b24, b25

            { 0x80 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_16 OP_ELSE OP_DROP OP_0 OP_ENDIF OP_TOALTSTACK
            { 0x40 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_8 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            { 0x20 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_4 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_16 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_2 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_8 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_1 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_256MUL OP_ADD
            OP_256MUL OP_ADD
            OP_256MUL OP_ADD
            OP_4MUL OP_ADD
            OP_FROMALTSTACK

            for _ in 0..3 { OP_FROMALTSTACK }
            // c0, c1, c2, c3, c4, c5, c6, x, b26, b27, b28

            OP_256MUL OP_ADD
            OP_256MUL OP_ADD
            OP_32MUL OP_ADD

            for _ in 0..3 { OP_FROMALTSTACK }
            // c0, c1, c2, c3, c4, c5, c6, c7, b29, b30, b31

            OP_256MUL OP_ADD
            OP_256MUL OP_ADD

            // c0, c1, c2, c3, c4, c5, c6, c7, c8

            for i in 0..8 {
                { i + 1 } OP_ROLL
            }
            // c8, c7, c6, c5, c4, c3, c2, c1, c0
        }
    }

    pub fn from_digits() -> Script {
        script! {
            // reverse digits
            for i in 0..63 {
                { i + 1 } OP_ROLL
            }

            for _ in 0..56 { OP_TOALTSTACK }
            // b0, b1, b2, b3, b4, b5, b6, b7

            OP_8 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_4 OP_ELSE OP_DROP OP_0 OP_ENDIF OP_TOALTSTACK
            OP_4 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_2 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_2 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_1 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD

            for _ in 0..8 { OP_FROMALTSTACK }
            // c0, b7>>1, b8, b9, b10, b11, b12, b13, b14

            OP_8 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_2 OP_ELSE OP_DROP OP_0 OP_ENDIF OP_TOALTSTACK
            OP_4 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_1 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_8MUL OP_ADD

            for _ in 0..8 { OP_FROMALTSTACK }
            // c0, c1, b14>>2, b15, b16, b17, b18, b19, b20, b21

            OP_8 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_1 OP_ELSE OP_DROP OP_0 OP_ENDIF OP_TOALTSTACK
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_4MUL OP_ADD

            for _ in 0..8 { OP_FROMALTSTACK }
            // c0, c1, c2, b21>>3, b22, b23, b24, b25, b26, b27, b28

            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            { OP_2MUL() } OP_ADD

            for _ in 0..8 { OP_FROMALTSTACK }
            // c0, c1, c2, c3, b29, b30, b31, b32, b33, b34, b35, b36

            OP_8 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_4 OP_ELSE OP_DROP OP_0 OP_ENDIF OP_TOALTSTACK
            OP_4 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_2 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_2 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_1 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD

            for _ in 0..8 { OP_FROMALTSTACK }
            // c0, c1, c2, c3, c4, b36>>1, b37, b38, b39, b40, b41, b42, b43

            OP_8 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_2 OP_ELSE OP_DROP OP_0 OP_ENDIF OP_TOALTSTACK
            OP_4 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_1 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_8MUL OP_ADD

            for _ in 0..8 { OP_FROMALTSTACK }
            // c0, c1, c2, c3, c4, c5, b43>>2, b44, b45, b46, b47, b48, b49, b50

            OP_8 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_1 OP_ELSE OP_DROP OP_0 OP_ENDIF OP_TOALTSTACK
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_4MUL OP_ADD

            for _ in 0..8 { OP_FROMALTSTACK }
            // c0, c1, c2, c3, c4, c5, c6, b50>>3, b51, b52, b53, b54, b55, b56, b57

            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            { OP_2MUL() } OP_ADD

            for _ in 0..6 { OP_FROMALTSTACK }
            // c0, c1, c2, c3, c4, c5, c6, c7, b58, b59, b60, b61, b62, b63

            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD
            OP_16MUL OP_ADD

            // c0, c1, c2, c3, c4, c5, c6, c7, c8

            for i in 0..8 {
                { i + 1 } OP_ROLL
            }
            // c8, c7, c6, c5, c4, c3, c2, c1, c0

        }
    }

    /// Zip the top two u{16N} elements
    /// input:  a0 ... a{N-1} b0 ... b{N-1}
    /// output: a0 b0 ... ... a{N-1} b{N-1}
    pub fn zip(mut a: u32, mut b: u32) -> Script {
        a = (a + 1) * Self::N_LIMBS - 1;
        b = (b + 1) * Self::N_LIMBS - 1;

        assert_ne!(a, b);
        if a < b {
            script! {
                for i in 0..Self::N_LIMBS {
                    { a + i }
                    OP_ROLL
                    { b }
                    OP_ROLL
                }
            }
        } else {
            script! {
                for i in 0..Self::N_LIMBS {
                    { a }
                    OP_ROLL
                    { b + i + 1 }
                    OP_ROLL
                }
            }
        }
    }

    pub fn copy_zip(mut a: u32, mut b: u32) -> Script {
        a = (a + 1) * Self::N_LIMBS - 1;
        b = (b + 1) * Self::N_LIMBS - 1;

        script! {
            for i in 0..Self::N_LIMBS {
                { a + i } OP_PICK { b + 1 + i } OP_PICK
            }
        }
    }

    pub fn dup_zip(mut a: u32) -> Script {
        a = (a + 1) * Self::N_LIMBS - 1;

        script! {
            for i in 0..Self::N_LIMBS {
                { a + i } OP_ROLL OP_DUP
            }
        }
    }

    pub fn copy(mut a: u32) -> Script {
        a = (a + 1) * Self::N_LIMBS - 1;

        script! {
            if a < 134 {
                for _ in 0..Self::N_LIMBS {
                    { a } OP_PICK
                }
            } else {
                { a + 1 }
                for _ in 0..Self::N_LIMBS - 1 {
                    OP_DUP OP_PICK OP_SWAP
                }
                OP_1SUB OP_PICK
            }
        }
    }

    pub fn roll(mut a: u32) -> Script {
        if a == 0 {
            return script! { }
        }
        a = (a + 1) * Self::N_LIMBS - 1;

        script! {
            for _ in 0..Self::N_LIMBS {
                { a } OP_ROLL
            }
        }
    }

    pub fn drop() -> Script {
        script! {
            for _ in 0..Self::N_LIMBS / 2 {
                OP_2DROP
            }
            if Self::N_LIMBS & 1 == 1 {
                OP_DROP
            }
        }
    }

    pub fn push_dec(dec_string: &str) -> Script {
        Self::push_u32_le(&BigUint::from_str(dec_string).unwrap().to_u32_digits())
    }

    pub fn push_hex(hex_string: &str) -> Script {
        Self::push_u32_le(
            &BigUint::from_str_radix(hex_string, 16)
                .unwrap()
                .to_u32_digits(),
        )
    }

    #[inline]
    pub fn push_zero() -> Script { push_to_stack(0, Self::N_LIMBS as usize) }

    #[inline]
    pub fn push_one() -> Script {
        script! {
            { push_to_stack(0,(Self::N_LIMBS - 1) as usize) }
            1
        }
    }

    pub fn is_zero_keep_element(a: u32) -> Script {
        let a = Self::N_LIMBS * a;
        script! {
            1
            for i in 0..Self::N_LIMBS {
                { a + i+1 } OP_PICK
                OP_NOT
                OP_BOOLAND
            }
        }
    }

    pub fn is_zero(a: u32) -> Script {
        let a = Self::N_LIMBS * a;
        script! {
            1
            for _ in 0..Self::N_LIMBS {
                { a +1 } OP_ROLL
                OP_NOT
                OP_BOOLAND
            }
        }
    }

    pub fn is_one_keep_element(a: u32) -> Script {
        let a = Self::N_LIMBS * a;
        script! {
            1
            { a + 1 } OP_PICK
            1 OP_EQUAL OP_BOOLAND
            for i in 1..Self::N_LIMBS {
                { a + i + 1 } OP_PICK
                OP_NOT
                OP_BOOLAND
            }
        }
    }

    pub fn is_one(a: u32) -> Script {
        let a = Self::N_LIMBS * a;
        script! {
            1
            { a + 1 } OP_ROLL
            1 OP_EQUAL OP_BOOLAND
            for _ in 1..Self::N_LIMBS {
                { a + 1 } OP_ROLL
                OP_NOT
                OP_BOOLAND
            }
        }
    }

    pub fn toaltstack() -> Script {
        script! {
            for _ in 0..Self::N_LIMBS {
                OP_TOALTSTACK
            }
        }
    }

    pub fn fromaltstack() -> Script {
        script! {
            for _ in 0..Self::N_LIMBS {
                OP_FROMALTSTACK
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bigint::{BigIntImpl, U254};
    use crate::treepp::*;
    use bitcoin_script::script;
    use num_bigint::{BigUint, RandomBits};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_zip() {
        const N_BITS: u32 = 1450;
        const N_U30_LIMBS: u32 = 50;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let mut v = vec![];
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[i as usize]);
                expected.push(v[(N_U30_LIMBS + i) as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { BigIntImpl::<N_BITS, 29>::zip(1, 0) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..50 {
            let mut v = vec![];
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[(N_U30_LIMBS + i) as usize]);
                expected.push(v[i as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { BigIntImpl::<N_BITS, 29>::zip(0, 1) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_copy() {
        println!("U254.copy(0): {} bytes", U254::copy(0).len());
        println!("U254.copy(13): {} bytes", U254::copy(13).len());
        println!("U254.copy(14): {} bytes", U254::copy(14).len());
        const N_U30_LIMBS: u32 = 9;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let mut v = vec![];
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[i as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::copy(1) }
                for i in 0..N_U30_LIMBS {
                    { expected[(N_U30_LIMBS - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                { U254::drop() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_roll() {
        const N_U30_LIMBS: u32 = 9;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let mut v = vec![];
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[i as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::roll(1) }
                for i in 0..N_U30_LIMBS {
                    { expected[(N_U30_LIMBS - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_copy_zip() {
        const N_U30_LIMBS: u32 = 9;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let mut v = vec![];
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[i as usize]);
                expected.push(v[(N_U30_LIMBS + i) as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::copy_zip(1, 0) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                { U254::drop() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[(N_U30_LIMBS + i) as usize]);
                expected.push(v[i as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::copy_zip(0, 1) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                { U254::drop() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[i as usize]);
                expected.push(v[i as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::copy_zip(1, 1) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                { U254::drop() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::dup_zip(1) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn push_hex() {
        let exec_result = execute_script(script! {
            { U254::push_hex("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47") }
            { 0x187cfd47 } OP_EQUALVERIFY // 410844487
            { 0x10460b6 } OP_EQUALVERIFY // 813838427
            { 0x1c72a34f } OP_EQUALVERIFY // 119318739
            { 0x2d522d0 } OP_EQUALVERIFY // 542811226
            { 0x1585d978 } OP_EQUALVERIFY // 22568343
            { 0x2db40c0 } OP_EQUALVERIFY // 18274822
            { 0xa6e141 } OP_EQUALVERIFY // 436378501
            { 0xe5c2634 } OP_EQUALVERIFY // 329037900
            { 0x30644e } OP_EQUAL // 12388
        });
        assert!(exec_result.success);
    }

    #[test]
    fn test_from_bytes() {
        println!("U254.from_bytes: {} bytes", U254::from_bytes().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a: BigUint = prng.sample(RandomBits::new(254));
        println!("a bytes: {:?}", a.to_bytes_le());

        let script = script! {
            { U254::push_u32_le(&a.to_u32_digits()) }
            for byte in a.to_bytes_le() {
                { byte }
            }
            { U254::from_bytes() }
            { U254::equal(1, 0) }
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_from_digits() {
        println!("U254.from_digits: {} bytes", U254::from_digits().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a: BigUint = prng.sample(RandomBits::new(254));
        let mut a_digits = Vec::new();

        for byte in a.to_bytes_le() {
            let (x, y) = (byte % 16, byte / 16);
            a_digits.push(x);
            a_digits.push(y);
        }

        println!("a bytes: {:?}", a.to_bytes_le());
        println!("a digits: {:?}", a_digits);

        let script = script! {
            { U254::push_u32_le(&a.to_u32_digits()) }
            for digit in a_digits {
                { digit }
            }
            { U254::from_digits() }
            { U254::equal(1, 0) }
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
