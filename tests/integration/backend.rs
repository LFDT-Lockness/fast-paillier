use fast_paillier::backend::num_bigint::Integer as NbiInteger;
use fast_paillier::backend::rug::Integer as RugInteger;
use fast_paillier::backend::IsPrime;

#[test]
fn negative_power() {
    let m_nbi = NbiInteger::from(-10);
    let x_nbi = NbiInteger::from(2);
    let e_nbi = NbiInteger::from(6);
    let r_nbi = x_nbi.pow_mod(&e_nbi, &m_nbi);

    let m_rug = RugInteger::from(-10);
    let x_rug = RugInteger::from(2);
    let e_rug = RugInteger::from(6);
    let r_rug = x_rug.pow_mod(&e_rug, &m_rug);

    assert!(AssertsEq::asserts_eq(r_nbi, r_rug));
}

macro_rules! make_quickcheck {
    ($method:ident $($(, $arg:ident: $t:ty)+)?) => {
        quickcheck::quickcheck! {
            fn $method(nbi: NbiInteger $($(, $arg: $t)+)?) -> bool {
                #[allow(unused_mut)]
                let mut nbi = nbi; // rebind because mut is not allowed in
                                   // quickcheck macro
                let (bytes, sign) = nbi.to_bytes_msf_signed();
                #[allow(unused_mut)]
                let mut rug = RugInteger::from_bytes_msf_signed(&bytes, sign);

                let r1 = nbi.$method(
                    $($(
                        Arg::to_nbi( &$arg ),
                    )+)?
                );
                let r2 = rug.$method(
                    $($(
                        Arg::to_rug( &$arg ),
                    )+)?
                );

                r1.asserts_eq(r2)
            }
        }
    }
}

make_quickcheck!(is_one);
make_quickcheck!(is_even);
make_quickcheck!(cmp_abs, other: RefInteger);
make_quickcheck!(lcm_ref, other: RefInteger);
make_quickcheck!(gcd_ref, other: RefInteger);
make_quickcheck!(cmp0);
make_quickcheck!(pow_mod, exponent: RefInteger, modulo: Positive<RefInteger>);
make_quickcheck!(pow_mod_ref, exponent: RefInteger, modulo: Positive<RefInteger>);
//make_quickcheck!(Self::u_pow_u, exponent: RefInteger, modulo: RefInteger);
make_quickcheck!(square);
make_quickcheck!(square_ref);
make_quickcheck!(sqrt);
make_quickcheck!(sqrt_ref);
make_quickcheck!(modulo, divisor: Positive<RefInteger>);
make_quickcheck!(modulo_ref, divisor: Positive<RefInteger>);
make_quickcheck!(modulo_mut, divisor: Positive<RefInteger>);
make_quickcheck!(mod_u, divisor: Positive<u32>);
make_quickcheck!(significant_bits);
make_quickcheck!(significant_dwords);
make_quickcheck!(invert, modulo: Positive<RefInteger>);
make_quickcheck!(invert_ref, modulo: Positive<RefInteger>);
make_quickcheck!(set_bit, index: SmallU32, value: bool);
make_quickcheck!(is_probably_prime, const25: Const25);
make_quickcheck!(jacobi, n: OddPositive);
make_quickcheck!(combine, l: RefInteger, le: RefInteger, r: RefInteger, re: RefInteger);

/// Helper trait for tests above. Mostly calls assert_eq for its args, but
/// to compare rug and nbi integer we convert them to one type first
trait AssertsEq<Rhs> {
    fn asserts_eq(self, rhs: Rhs) -> bool;
}
impl AssertsEq<RugInteger> for NbiInteger {
    fn asserts_eq(self, rhs: RugInteger) -> bool {
        let (bytes, sign) = self.to_bytes_msf_signed();
        let lhs = RugInteger::from_bytes_msf_signed(&bytes, sign);
        eprintln!("{lhs} != {rhs}");
        lhs == rhs
    }
}
impl AssertsEq<&mut RugInteger> for &mut NbiInteger {
    fn asserts_eq(self, rhs: &mut RugInteger) -> bool {
        let (bytes, sign) = self.to_bytes_msf_signed();
        let lhs = RugInteger::from_bytes_msf_signed(&bytes, sign);
        eprintln!("{lhs} != {rhs}");
        lhs == *rhs
    }
}
impl AssertsEq<IsPrime> for IsPrime {
    fn asserts_eq(self, rhs: IsPrime) -> bool {
        use IsPrime::*;
        match (self, rhs) {
            (No, No) => true,
            (Yes | Probably, Yes | Probably) => true,
            _ => {
                eprintln!("{self:?} != {rhs:?}");
                false
            }
        }
    }
}
impl AssertsEq<Option<RugInteger>> for Option<NbiInteger> {
    fn asserts_eq(self, rhs: Option<RugInteger>) -> bool {
        let lhs = self.map(|x| {
            let (bytes, sign) = x.to_bytes_msf_signed();
            RugInteger::from_bytes_msf_signed(&bytes, sign)
        });
        eprintln!("{lhs:?} != {rhs:?}");
        lhs == rhs
    }
}

macro_rules! trivial_assertion {
    ( $($t:ty,)+ ) => {
        $(
            impl AssertsEq <$t> for $t {
                fn asserts_eq(self, rhs: $t) -> bool {
                    eprintln!("{self:?} != {rhs:?}");
                    self == rhs
                }
            }
        )+
    }
}
trivial_assertion! {
    bool,
    std::cmp::Ordering,
    u32,
    u64,
    usize,
    i32,
}

trait Arg<'a> {
    type NbiArg;
    type RugArg;

    fn to_nbi(&'a self) -> Self::NbiArg;
    fn to_rug(&'a self) -> Self::RugArg;
}

macro_rules! trivial_args {
    ( $($t:ty,)+ ) => {
        $(
            impl Arg<'_> for $t {
                type NbiArg = $t;
                type RugArg = $t;
                fn to_nbi(&self) -> Self::NbiArg {
                    self.clone()
                }
                fn to_rug(&self) -> Self::NbiArg {
                    self.clone()
                }
            }
        )+
    }
}
trivial_args! {
    u32,
    bool,
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
struct RefInteger(NbiInteger, RugInteger);
impl<'a> Arg<'a> for RefInteger {
    type NbiArg = &'a NbiInteger;
    type RugArg = &'a RugInteger;
    fn to_nbi(&'a self) -> Self::NbiArg {
        &self.0
    }
    fn to_rug(&'a self) -> Self::RugArg {
        &self.1
    }
}
impl quickcheck::Arbitrary for RefInteger {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let nbi = NbiInteger::arbitrary(g);
        let (bytes, sign) = nbi.to_bytes_msf_signed();
        let rug = RugInteger::from_bytes_msf_signed(&bytes, sign);
        RefInteger(nbi, rug)
    }
}

impl From<u8> for RefInteger {
    fn from(value: u8) -> Self {
        Self(
            NbiInteger::from(u32::from(value)),
            RugInteger::from(u32::from(value)),
        )
    }
}

#[derive(Clone, Debug)]
struct OddPositive(NbiInteger, RugInteger);
impl<'a> Arg<'a> for OddPositive {
    type NbiArg = &'a NbiInteger;
    type RugArg = &'a RugInteger;
    fn to_nbi(&'a self) -> Self::NbiArg {
        &self.0
    }
    fn to_rug(&'a self) -> Self::RugArg {
        &self.1
    }
}
impl quickcheck::Arbitrary for OddPositive {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let nbi = NbiInteger::arbitrary(g);

        // make odd positive
        let (_, nbi) = nbi.to_num_bigint().into_parts();
        let nbi = num_bigint::BigInt::from_biguint(num_bigint::Sign::Plus, nbi);
        let mut nbi = NbiInteger::from_num_bigint(nbi);
        if nbi < NbiInteger::from(2) {
            nbi |= 2;
        }
        nbi |= 1;

        let rug = RugInteger::from_bytes_msf(&nbi.to_bytes_msf());
        OddPositive(nbi, rug)
    }
}

#[derive(Clone, Debug)]
struct SmallU32(u32);
impl Arg<'_> for SmallU32 {
    type NbiArg = u32;
    type RugArg = u32;
    fn to_nbi(&self) -> Self::NbiArg {
        self.0
    }
    fn to_rug(&self) -> Self::RugArg {
        self.0
    }
}
impl quickcheck::Arbitrary for SmallU32 {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let mut num = u32::arbitrary(g);
        num &= 0xffff;
        SmallU32(num)
    }
}

#[derive(Clone, Debug)]
struct Const25;
impl Arg<'_> for Const25 {
    type NbiArg = u32;
    type RugArg = u32;
    fn to_nbi(&self) -> Self::NbiArg {
        25
    }
    fn to_rug(&self) -> Self::RugArg {
        25
    }
}
impl quickcheck::Arbitrary for Const25 {
    fn arbitrary(_: &mut quickcheck::Gen) -> Self {
        Const25
    }
}

#[derive(Clone, Debug)]
struct Positive<T>(T);
impl<'a, T: Arg<'a>> Arg<'a> for Positive<T> {
    type NbiArg = T::NbiArg;
    type RugArg = T::RugArg;
    fn to_nbi(&'a self) -> Self::NbiArg {
        self.0.to_nbi()
    }
    fn to_rug(&'a self) -> Self::RugArg {
        self.0.to_rug()
    }
}
impl<T> quickcheck::Arbitrary for Positive<T>
where
    T: quickcheck::Arbitrary,
    T: From<u8>,
    T: PartialOrd,
{
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let zero = T::from(0u8);
        loop {
            let x = T::arbitrary(g);
            if x > zero {
                break Positive(x);
            }
        }
    }
}
