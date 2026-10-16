//! Test that all deterministic methods of both integer backends produces
//! identical results. We use quickcheck to test it for every method. For
//! brevity, the quickcheck properties to test are defined as macros

use fast_paillier::backend::num_bigint::Integer as NbiInteger;
use fast_paillier::backend::rug::Integer as RugInteger;

/// Generates a quickcheck test for a given method. Uses [`Arg`] to convert the
/// arguments to either num-bigint or rug compatible, and uses [`HeteroEq`] to
/// compare resulting values
macro_rules! make_quickcheck {
    // Case for normal methods. Called like `make_quickcheck!(method_name(self:
    // T1, arg: T2, arg2: T3))`
    ($method:ident ( self: $self_ty:ty $(, $arg:ident: $t:ty)* $(,)? ) ) => {
        quickcheck::quickcheck! {
            fn $method(nbi: $self_ty $(, $arg: $t)*) -> bool {
                #[allow(unused_mut)]
                let mut nbi = NbiInteger::from(nbi);
                let (bytes, sign) = nbi.to_bytes_msf_signed();
                #[allow(unused_mut)]
                let mut rug = RugInteger::from_bytes_msf_signed(&bytes, sign);


                let r1 = {
                    // Since Arg::to_nbi takes mutable reference to the arg, we clone them,
                    // so the `rug` method below receives the same args as provided by
                    // quickcheck without any modification
                    eprintln!("int: {nbi:?}");
                    $(
                        let mut $arg = $arg.clone();
                        eprintln!("arg: {:?}", $arg);
                    )*
                    nbi.$method(
                        $(
                            Arg::to_nbi( &mut $arg ),
                        )*
                    )
                };
                let r2 = {
                    // Change args mutability
                    $(
                        let mut $arg = $arg;
                    )*

                    rug.$method(
                        $(
                            Arg::to_rug( &mut $arg ),
                        )*
                    )
                };

                r1.equals(r2)
            }
        }
    };
    // Case for static methods. Called like `make_quickcheck!(Self::method_name(
    // arg: T2, arg2: T3))`
    //
    // Have to separate $arg and $args as the quickcheck macro doesn't support
    // trailing comma
    (Self :: $method:ident($arg:ident: $t:ty $(, $args:ident: $ts:ty)*)) => {
        quickcheck::quickcheck! {
            fn $method($arg: $t $(, $args: $ts)*) -> bool {
                let r1 = {
                    // Since Arg::to_nbi takes mutable reference to the arg, we clone them,
                    // so the `rug` method below receives the same args as provided by
                    // quickcheck without any modification
                    let mut $arg = $arg.clone();
                    $(
                        let mut $args = $args.clone();
                    )*
                    NbiInteger::$method(
                        Arg::to_nbi( &mut $arg ),
                        $(
                            Arg::to_nbi( &mut $args ),
                        )*
                    )
                };
                let r2 = {
                    // Change args mutability
                    let mut $arg = $arg;
                    $(
                        let mut $args = $args;
                    )*
                    RugInteger::$method(
                        Arg::to_rug( &mut $arg ),
                        $(
                            Arg::to_rug( &mut $args ),
                        )*
                    )
                };

                r1.equals(r2)
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
make_quickcheck!(
    pow_mod(self: NbiInteger, exponent: RefInteger, modulo: RefInteger)
);
make_quickcheck!(
    pow_mod_ref(self: NbiInteger, exponent: RefInteger, modulo: RefInteger)
);
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
make_quickcheck!(random_below(self: Positive<NbiInteger>, rng: Prng));
make_quickcheck!(random_below_ref(self: Positive<NbiInteger>, rng: Prng));
make_quickcheck!(Self::random_bits(bits: SmallU32, rng: Prng));
make_quickcheck!(Self::random_bits_signed(bits: SmallU32, rng: Prng));
make_quickcheck!(assign_random_below(self: NbiInteger, modulo: Positive<RefInteger>, rng: Prng));
make_quickcheck!(assign_random_bits(self: NbiInteger, bits: SmallU32, rng: Prng));
make_quickcheck!(jacobi(self: NbiInteger, n: OddPositive));
make_quickcheck!(
    combine(
        self: NonZero<NbiInteger>,
        l: RefInteger,
        le: RefInteger,
        r: RefInteger,
        re: RefInteger,
    )
);
make_quickcheck!(to_bytes_msf(self: NbiInteger));
make_quickcheck!(to_bytes_msf_signed(self: NbiInteger));
make_quickcheck!(to_bytes_lsf(self: NbiInteger));

#[test]
fn round_random() {
    let mut nbi_rng = rand_dev::DevRng::new();
    let mut rug_rng = nbi_rng.clone();
    let nbi = NbiInteger::from(8);
    let rug = RugInteger::from(8);

    for _ in 0..32 {
        let nbi_random = nbi.random_below_ref(&mut nbi_rng);
        let rug_random = rug.random_below_ref(&mut rug_rng);
        assert!(nbi_random.equals(rug_random));
    }
}

quickcheck::quickcheck! {
    fn serde_json(nbi: NbiInteger) -> bool {
        let r1 = serde_json::to_string(&nbi).unwrap();

        let (bytes, sign) = nbi.to_bytes_msf_signed();
        let rug = RugInteger::from_bytes_msf_signed(&bytes, sign);
        let r2 = serde_json::to_string(&rug).unwrap();
        r1 == r2
    }

    fn is_probably_prime(nbi: NbiInteger, rng: Prng) -> bool {
        use fast_paillier::backend::IsPrime;

        let mut rng = rng;
        let (bytes, sign) = nbi.to_bytes_msf_signed();
        let rug = RugInteger::from_bytes_msf_signed(&bytes, sign);

        let r1 = nbi.is_probably_prime(25, &mut rng.rng);
        let r2 = rug.is_probably_prime(25, &mut rng.rng);

        // It doesn't matter if one backend returns `Yes`, and the other returns `Probably`.
        // It matters to check if one returns `Yes|Probably`, and the other returns `No`
        matches!((r1, r2), (IsPrime::Yes | IsPrime::Probably, IsPrime::Yes | IsPrime::Probably) | (IsPrime::No, IsPrime::No))
    }

    fn from_radix(s: AsciiString) -> bool {
        let nbi = NbiInteger::from_str_radix(&s.0, 16);
        let rug = RugInteger::from_str_radix(&s.0, 16);
        eprintln!("{nbi:?}, {rug:?}");
        match (nbi, rug) {
            (Some(a), Some(b)) => a.equals(b),
            (None, None) => true,
            _ => false
        }
    }
}

///// Helper traits for macro /////

/// Helper trait for tests above, to compare the results when they are of
/// different types: nbi int and rug int. Will convert the results to one type
/// before comparing them
trait HeteroEq<Rhs> {
    fn equals(self, rhs: Rhs) -> bool;
}
impl HeteroEq<RugInteger> for NbiInteger {
    fn equals(self, rhs: RugInteger) -> bool {
        let (bytes, sign) = self.to_bytes_msf_signed();
        let lhs = RugInteger::from_bytes_msf_signed(&bytes, sign);
        eprintln!("{lhs} != {rhs}");
        lhs == rhs
    }
}
impl HeteroEq<&mut RugInteger> for &mut NbiInteger {
    fn equals(self, rhs: &mut RugInteger) -> bool {
        let (bytes, sign) = self.to_bytes_msf_signed();
        let lhs = RugInteger::from_bytes_msf_signed(&bytes, sign);
        eprintln!("{lhs} != {rhs}");
        lhs == *rhs
    }
}
impl HeteroEq<Option<RugInteger>> for Option<NbiInteger> {
    fn equals(self, rhs: Option<RugInteger>) -> bool {
        let lhs = self.map(|x| {
            let (bytes, sign) = x.to_bytes_msf_signed();
            RugInteger::from_bytes_msf_signed(&bytes, sign)
        });
        eprintln!("{lhs:?} != {rhs:?}");
        lhs == rhs
    }
}
impl<T> HeteroEq<T> for T
where
    T: Eq,
{
    fn equals(self, rhs: T) -> bool {
        self == rhs
    }
}

/// Helper trait to generate and convert values for quickcheck. Most methods
/// accept only the integers of matching type: nbi or rug, and this trait is
/// used to select the correct one
trait Arg<'a> {
    type NbiArg;
    type RugArg;

    fn to_nbi(&'a mut self) -> Self::NbiArg;
    fn to_rug(&'a mut self) -> Self::RugArg;
}

macro_rules! trivial_arg {
    ( $($t:ty,)+ ) => {
        $(
            impl Arg<'_> for $t {
                type NbiArg = $t;
                type RugArg = $t;
                fn to_nbi(&mut self) -> Self::NbiArg {
                    self.clone()
                }
                fn to_rug(&mut self) -> Self::NbiArg {
                    self.clone()
                }
            }
        )+
    }
}
trivial_arg! {
    u32,
    bool,
}

///// Newtypes for quickcheck's Arbitrary /////

/// Helper quickcheck newtype: generates a big integer, and passes it as [`Arg`]
/// by reference instead of by value
#[derive(Clone, PartialEq, PartialOrd)]
struct RefInteger(NbiInteger, RugInteger);
impl<'a> Arg<'a> for RefInteger {
    type NbiArg = &'a NbiInteger;
    type RugArg = &'a RugInteger;
    fn to_nbi(&'a mut self) -> Self::NbiArg {
        &self.0
    }
    fn to_rug(&'a mut self) -> Self::RugArg {
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

/// Helper quickcheck newtype. Similar to [`RefInteger`], but generates integers
/// that are odd and larger than 2 (to be used as an argument to `jacobi`)
#[derive(Clone, Debug)]
struct OddPositive(NbiInteger, RugInteger);
impl<'a> Arg<'a> for OddPositive {
    type NbiArg = &'a NbiInteger;
    type RugArg = &'a RugInteger;
    fn to_nbi(&'a mut self) -> Self::NbiArg {
        &self.0
    }
    fn to_rug(&'a mut self) -> Self::RugArg {
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

/// Helper quickcheck newtype: generates a u32 that is small enough to be used
/// as a bit index or a (non-modular) exponent
#[derive(Clone, Copy, Debug)]
struct SmallU32(u32);
impl Arg<'_> for SmallU32 {
    type NbiArg = u32;
    type RugArg = u32;
    fn to_nbi(&mut self) -> Self::NbiArg {
        self.0
    }
    fn to_rug(&mut self) -> Self::RugArg {
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

/// Helper quickcheck newtype: generates a non-zero integral value
#[derive(Clone, Debug)]
struct NonZero<T>(T);
impl<'a, T: Arg<'a>> Arg<'a> for NonZero<T> {
    type NbiArg = T::NbiArg;
    type RugArg = T::RugArg;
    fn to_nbi(&'a mut self) -> Self::NbiArg {
        self.0.to_nbi()
    }
    fn to_rug(&'a mut self) -> Self::RugArg {
        self.0.to_rug()
    }
}
impl<T> quickcheck::Arbitrary for NonZero<T>
where
    T: quickcheck::Arbitrary + From<u8> + PartialEq,
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

/// Helper quickcheck newtype: generates a strictly positive integral value
#[derive(Clone, Debug)]
struct Positive<T>(T);
impl<'a, T: Arg<'a>> Arg<'a> for Positive<T> {
    type NbiArg = T::NbiArg;
    type RugArg = T::RugArg;
    fn to_nbi(&'a mut self) -> Self::NbiArg {
        self.0.to_nbi()
    }
    fn to_rug(&'a mut self) -> Self::RugArg {
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
impl From<Positive<NbiInteger>> for NbiInteger {
    fn from(value: Positive<NbiInteger>) -> Self {
        value.0
    }
}

#[derive(Clone, Debug)]
struct Prng {
    // Used in debug impl to print the generated seed
    _seed: [u8; 32],
    rng: rand_dev::DevRng,
}
impl quickcheck::Arbitrary for Prng {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        // this seed is not going to be uniform as there's no way to sample
        // uniform distribution from Gen
        let seed = [0u8; 32].map(|_| u8::arbitrary(g));
        let rng = rand_core::SeedableRng::from_seed(seed);
        Prng { _seed: seed, rng }
    }
}
impl<'a> Arg<'a> for Prng {
    type NbiArg = &'a mut rand_dev::DevRng;
    type RugArg = &'a mut rand_dev::DevRng;

    fn to_nbi(&'a mut self) -> Self::NbiArg {
        &mut self.rng
    }
    fn to_rug(&'a mut self) -> Self::RugArg {
        &mut self.rng
    }
}

#[derive(Debug, Clone)]
struct AsciiString(String);
impl quickcheck::Arbitrary for AsciiString {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let size = u8::arbitrary(g) % 32;
        let s = std::iter::repeat_with(|| u8::arbitrary(g) & 0x7F)
            .take(usize::from(size))
            .map(char::from)
            .collect();
        Self(s)
    }
}
