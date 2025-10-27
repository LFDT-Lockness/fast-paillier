#![allow(missing_docs)]

use super::IsPrime;
use rug::Complete;

/// Big integer type used in this crate
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct Integer(rug::Integer);

impl Integer {
    /// Converts to bytes, with bytes representing _least_ significant base256
    /// digits appearing first. Discards the sign
    ///
    /// ## Example
    /// ```rust
    /// # use fast_paillier::backend::rug::Integer;
    /// let x = Integer::from(0x11223344);
    /// assert_eq!(x.to_bytes_lsf(), vec![0x44, 0x33, 0x22, 0x11]);
    /// ```
    pub fn to_bytes_lsf(&self) -> Vec<u8> {
        self.0.to_digits(rug::integer::Order::Lsf)
    }
    /// Converts to bytes, with bytes representing _most_ significant base256
    /// digits appearing first. Discards the sign
    ///
    /// ## Example
    /// ```rust
    /// # use fast_paillier::backend::rug::Integer;
    /// let x = Integer::from(0x11223344);
    /// assert_eq!(x.to_bytes_msf(), vec![0x11, 0x22, 0x33, 0x44]);
    /// ```
    pub fn to_bytes_msf(&self) -> Vec<u8> {
        self.0.to_digits(rug::integer::Order::Msf)
    }
    /// Converts bytes to Integer. Inverse of [`Integer::to_bytes_msf`]
    pub fn from_bytes_msf(bytes: &[u8]) -> Self {
        Integer(rug::Integer::from_digits(bytes, rug::integer::Order::Msf))
    }
    /// Returns a string representation of the number for the specified radix
    pub fn to_str_radix(&self, radix: u16) -> String {
        self.0.to_string_radix(radix.into())
    }
    /// Parses the integer using the given radix
    pub fn from_str_radix(s: &str, radix: u16) -> Option<Self> {
        rug::Integer::from_str_radix(s, radix.into())
            .ok()
            .map(Integer)
    }
    /// Convert the number to the underlying backend representation
    pub fn to_rug(self) -> rug::Integer {
        self.0
    }
    /// Convert the number from the underlying backend representation
    pub fn from_rug(x: rug::Integer) -> Self {
        Self(x)
    }
}

use super::macro_defs;

macro_defs::make_all_ops!(Integer, complete);
macro_defs::make_all_bitops!(Integer);

///// Methods from rug /////

impl Integer {
    pub fn one() -> Self {
        Integer(rug::Integer::ONE.clone())
    }
    pub fn zero() -> Self {
        Integer(rug::Integer::new())
    }
    pub fn is_one(&self) -> bool {
        &self.0 == rug::Integer::ONE
    }

    pub fn is_even(&self) -> bool {
        self.0.is_even()
    }

    pub fn cmp_abs(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp_abs(&other.0)
    }

    pub fn lcm_ref(&self, other: &Self) -> Self {
        Integer(self.0.lcm_ref(&other.0).complete())
    }
    pub fn gcd_ref(&self, other: &Self) -> Self {
        Integer(self.0.gcd_ref(&other.0).complete())
    }

    pub fn cmp0(&self) -> std::cmp::Ordering {
        self.0.cmp0()
    }

    pub fn pow_mod(self, exponent: &Self, modulo: &Self) -> Option<Self> {
        self.0.pow_mod(&exponent.0, &modulo.0).map(Integer).ok()
    }
    pub fn pow_mod_ref(&self, exponent: &Self, modulo: &Self) -> Option<Self> {
        self.0
            .pow_mod_ref(&exponent.0, &modulo.0)
            .map(Complete::complete)
            .map(Integer)
    }
    pub fn u_pow_u(base: u32, exponent: u32) -> Self {
        Integer(rug::Integer::u_pow_u(base, exponent).complete())
    }

    pub fn square(self) -> Self {
        Integer(self.0.square())
    }
    pub fn square_ref(&self) -> Self {
        Integer(self.0.square_ref().complete())
    }
    pub fn sqrt(self) -> Self {
        Integer(self.0.sqrt())
    }
    pub fn sqrt_ref(&self) -> Self {
        Integer(self.0.sqrt_ref().complete())
    }

    pub fn modulo(self, divisor: &Self) -> Self {
        Integer(self.0.modulo(&divisor.0))
    }
    pub fn modulo_ref(&self, divisor: &Self) -> Self {
        Integer(self.0.modulo_ref(&divisor.0).complete())
    }
    pub fn modulo_mut(&mut self, divisor: &Self) {
        self.0.modulo_mut(&divisor.0)
    }
    pub fn mod_u(&self, modulo: u32) -> u32 {
        self.0.mod_u(modulo)
    }

    pub fn significant_bits(&self) -> u64 {
        self.0.significant_bits().into()
    }
    pub fn significant_dwords(&self) -> usize {
        self.0.significant_digits::<u32>()
    }

    pub fn invert(self, modulo: &Self) -> Option<Self> {
        self.0.invert(&modulo.0).ok().map(Integer)
    }
    pub fn invert_ref(&self, modulo: &Self) -> Option<Self> {
        self.0
            .invert_ref(&modulo.0)
            .map(Complete::complete)
            .map(Integer)
    }

    pub fn set_bit(&mut self, index: u32, value: bool) -> &mut Self {
        self.0.set_bit(index, value);
        self
    }

    pub fn random_below(self, rng: &mut impl rand_core::RngCore) -> Self {
        let mut rng = external_rand(rng);
        Integer(self.0.random_below(&mut rng))
    }
    pub fn random_below_ref(&self, rng: &mut impl rand_core::RngCore) -> Self {
        let mut rng = external_rand(rng);
        Integer(self.0.random_below_ref(&mut rng).complete())
    }
    pub fn random_bits(bits: u32, rng: &mut impl rand_core::RngCore) -> Self {
        let mut rng = external_rand(rng);
        Integer(rug::Integer::random_bits(bits, &mut rng).complete())
    }

    pub fn assign_random_below(&mut self, modulo: &Self, rng: &mut impl rand_core::RngCore) {
        let mut rng = external_rand(rng);
        let r = modulo.0.random_below_ref(&mut rng);
        rug::Assign::assign(&mut self.0, r)
    }

    pub fn assign_random_bits(&mut self, bits: u32, rng: &mut impl rand_core::RngCore) {
        let mut rng = external_rand(rng);
        let r = rug::Integer::random_bits(bits, &mut rng);
        rug::Assign::assign(&mut self.0, r)
    }

    pub fn is_probably_prime(&self, reps: u32) -> IsPrime {
        let r = self.0.is_probably_prime(reps);
        match r {
            rug::integer::IsPrime::No => IsPrime::No,
            rug::integer::IsPrime::Probably => IsPrime::Probably,
            rug::integer::IsPrime::Yes => IsPrime::Yes,
        }
    }

    pub fn generate_prime(rng: &mut impl rand_core::RngCore, bit_size: u32) -> Self {
        let mut x = Integer::zero();
        loop {
            x.assign_random_bits(bit_size, rng);
            x.set_bit(bit_size - 1, true);
            x |= 1u32;
            if let IsPrime::Yes | IsPrime::Probably = x.is_probably_prime(25) {
                return x;
            }
        }
    }

    pub fn jacobi(&self, n: &Self) -> i32 {
        self.0.jacobi(&n.0)
    }

    /// Compute l^le * r^re modulo self
    pub fn combine(&self, l: &Self, le: &Self, r: &Self, re: &Self) -> Option<Self> {
        let l_to_le = l.0.pow_mod_ref(&le.0, &self.0)?.complete();
        let r_to_re = r.0.pow_mod_ref(&re.0, &self.0)?.complete();
        let r = (l_to_le * r_to_re).modulo(&self.0);
        Some(Integer(r))
    }
}

/// Wraps any randomness source that implements [`rand_core::RngCore`] and makes
/// it compatible with [`rug::rand`].
pub fn external_rand(rng: &mut impl rand_core::RngCore) -> rug::rand::ThreadRandState<'_> {
    use bytemuck::TransparentWrapper;

    #[derive(TransparentWrapper)]
    #[repr(transparent)]
    pub struct ExternalRand<R>(R);

    impl<R: rand_core::RngCore> rug::rand::ThreadRandGen for ExternalRand<R> {
        fn gen(&mut self) -> u32 {
            self.0.next_u32()
        }
    }

    rug::rand::ThreadRandState::new_custom(ExternalRand::wrap_mut(rng))
}
