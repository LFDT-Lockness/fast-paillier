use fast_paillier::backend::num_bigint::Integer as NbiInteger;
use fast_paillier::backend::rug::Integer as RugInteger;
use fast_paillier::backend::IsPrime;

#[test]
fn negative_power() {
    let m_nbi = NbiInteger::from(-10);
    let x_nbi = NbiInteger::from(1);
    let e_nbi = NbiInteger::from(-6);
    let r_nbi = x_nbi.pow_mod(&e_nbi, &m_nbi);

    let m_rug = RugInteger::from(-10);
    let x_rug = RugInteger::from(1);
    let e_rug = RugInteger::from(-6);
    let r_rug = x_rug.pow_mod(&e_rug, &m_rug);

    assert!(AssertsEq::asserts_eq(r_nbi, r_rug));
}

macro_rules! make_quickcheck {
    ($method:ident ( self: $self_ty:ty $($(, $arg:ident: $t:ty)+)? ) ) => {
        quickcheck::quickcheck! {
            fn $method(nbi: $self_ty $($(, $arg: $t)+)?) -> bool {
                #[allow(unused_mut)]
                let mut nbi = NbiInteger::from(nbi);
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
    };
    (Self :: $method:ident($arg:ident: $t:ty $(, $args:ident: $ts:ty)*)) => {
        quickcheck::quickcheck! {
            fn $method($arg: $t $(, $args: $ts)*) -> bool {
                let r1 = NbiInteger::$method(
                    Arg::to_nbi( &$arg ),
                    $(
                        Arg::to_nbi( &$args ),
                    )*
                );
                let r2 = RugInteger::$method(
                    Arg::to_rug( &$arg ),
                    $(
                        Arg::to_rug( &$args ),
                    )*
                );

                eprintln!("asserting eq {r1}, {r2}");
                r1.asserts_eq(r2)
            }
        }
    };
}

make_quickcheck!(is_one(self: NbiInteger));
make_quickcheck!(is_even(self: NbiInteger));
make_quickcheck!(cmp_abs(self: NbiInteger, other: RefInteger));
make_quickcheck!(lcm_ref(self: NbiInteger, other: RefInteger));
make_quickcheck!(gcd_ref(self: NbiInteger, other: RefInteger));
make_quickcheck!(cmp0(self: NbiInteger));
make_quickcheck!(pow_mod(self: NbiInteger, exponent: RefInteger, modulo: NonZero<RefInteger>));
make_quickcheck!(pow_mod_ref(self: NbiInteger, exponent: RefInteger, modulo: NonZero<RefInteger>));
make_quickcheck!(Self::u_pow_u(base: u32, exponent: SmallU32));
make_quickcheck!(square(self: NbiInteger));
make_quickcheck!(square_ref(self: NbiInteger));
make_quickcheck!(sqrt(self: NbiInteger));
make_quickcheck!(sqrt_ref(self: NbiInteger));
make_quickcheck!(modulo(self: NbiInteger, divisor: Positive<RefInteger>));
make_quickcheck!(modulo_ref(self: NbiInteger, divisor: Positive<RefInteger>));
make_quickcheck!(modulo_mut(self: NbiInteger, divisor: Positive<RefInteger>));
make_quickcheck!(mod_u(self: NbiInteger, divisor: Positive<u32>));
make_quickcheck!(significant_bits(self: NbiInteger));
make_quickcheck!(significant_dwords(self: NbiInteger));
make_quickcheck!(invert(self: NbiInteger, modulo: Positive<RefInteger>));
make_quickcheck!(invert_ref(self: NbiInteger, modulo: Positive<RefInteger>));
make_quickcheck!(set_bit(self: NbiInteger, index: SmallU32, value: bool));
make_quickcheck!(is_probably_prime(self: NbiInteger, const25: Const25));
make_quickcheck!(jacobi(self: NbiInteger, n: OddPositive));
make_quickcheck!(combine(self: NonZero<NbiInteger>, l: RefInteger, le: RefInteger, r: RefInteger, re: RefInteger));

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

#[derive(Clone, PartialEq, PartialOrd)]
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

impl std::fmt::Debug for RefInteger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
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

#[derive(Clone, Copy, Debug)]
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
        let mut num = u16::arbitrary(g);
        num &= 0xfff;
        SmallU32(num.into())
    }
    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let mut val = *self;
        Box::new(std::iter::from_fn(move || {
            if val.0 == 0 {
                None
            } else {
                val.0 >>= 1;
                Some(val)
            }
        }))
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
struct NonZero<T>(T);
impl<'a, T: Arg<'a>> Arg<'a> for NonZero<T> {
    type NbiArg = T::NbiArg;
    type RugArg = T::RugArg;
    fn to_nbi(&'a self) -> Self::NbiArg {
        self.0.to_nbi()
    }
    fn to_rug(&'a self) -> Self::RugArg {
        self.0.to_rug()
    }
}
impl<T> quickcheck::Arbitrary for NonZero<T>
where
    T: quickcheck::Arbitrary,
    T: From<u8>,
    T: PartialEq,
{
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let zero = T::from(0u8);
        loop {
            let x = T::arbitrary(g);
            if x != zero {
                break NonZero(x);
            }
        }
    }
}

impl From<NonZero<NbiInteger>> for NbiInteger {
    fn from(value: NonZero<NbiInteger>) -> Self {
        value.0
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
