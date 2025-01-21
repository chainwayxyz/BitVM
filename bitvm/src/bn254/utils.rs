use crate::bigint::BigIntImpl;
use crate::bn254::fq::bigint_to_u32_limbs;
use crate::bn254::fq::Fq;
use crate::bn254::fr::Fr;
use crate::treepp::*;

#[derive(Debug, Clone)]
pub enum Hint {
    U32(u32),
    Fq(ark_bn254::Fq),
    Fr(ark_bn254::Fr),
    BigIntegerTmulLC1(num_bigint::BigInt),
    BigIntegerTmulLC2(num_bigint::BigInt),
}

impl Hint {
    pub fn push(&self) -> Script {
        const K1: (u32, u32) = Fq::bigint_tmul_lc_1();
        const K2: (u32, u32) = Fq::bigint_tmul_lc_2();
        pub type T1 = BigIntImpl<{ K1.0 }, { K1.1 }>;
        pub type T2 = BigIntImpl<{ K2.0 }, { K2.1 }>;
        match self {
            Hint::U32(f)  => script!{
                {*f}
            },
            Hint::Fq(fq) => script! {
                { Fq::push(*fq) }
            },
            Hint::Fr(fr) => script! {
                { Fr::push(*fr) }
            },
            Hint::BigIntegerTmulLC1(a) => script! {
                { T1::push_u32_le(&bigint_to_u32_limbs(a.clone(), T1::N_BITS)) }
            },
            Hint::BigIntegerTmulLC2(a) => script! {
                { T2::push_u32_le(&bigint_to_u32_limbs(a.clone(), T2::N_BITS)) }
            },
        }
    }
}
