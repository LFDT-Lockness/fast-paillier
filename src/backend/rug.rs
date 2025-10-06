#![allow(missing_docs)]
use rug::Complete;
use super::IsPrime;

/// Big integer type
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct Integer(rug::Integer);

///// Add /////

impl std::ops::Add<Integer> for Integer {
    type Output = Integer;
    fn add(self, rhs: Integer) -> Self::Output {
        Integer(self.0 + rhs.0)
    }
}
impl std::ops::Add<&Integer> for Integer {
    type Output = Integer;
    fn add(self, rhs: &Integer) -> Self::Output {
        Integer(self.0 + &rhs.0)
    }
}
impl std::ops::Add<Integer> for &Integer {
    type Output = Integer;
    fn add(self, rhs: Integer) -> Self::Output {
        Integer(&self.0 + rhs.0)
    }
}
impl std::ops::Add<&Integer> for &Integer {
    type Output = Integer;
    fn add(self, rhs: &Integer) -> Self::Output {
        Integer((&self.0 + &rhs.0).complete())
    }
}
impl std::ops::Add<u32> for Integer {
    type Output = Integer;
    fn add(self, rhs: u32) -> Self::Output {
        Integer(self.0 + rhs)
    }
}
impl std::ops::Add<i32> for Integer {
    type Output = Integer;
    fn add(self, rhs: i32) -> Self::Output {
        Integer(self.0 + rhs)
    }
}
impl std::ops::Add<u8> for Integer {
    type Output = Integer;
    fn add(self, rhs: u8) -> Self::Output {
        Integer(self.0 + rhs)
    }
}
impl std::ops::Add<u32> for &Integer {
    type Output = Integer;
    fn add(self, rhs: u32) -> Self::Output {
        Integer((&self.0 + rhs).complete())
    }
}

impl std::ops::AddAssign<u32> for Integer {
    fn add_assign(&mut self, rhs: u32) {
        self.0 += rhs
    }
}

impl std::ops::AddAssign<&Integer> for Integer {
    fn add_assign(&mut self, rhs: &Integer) {
        self.0 += &rhs.0
    }
}

///// Sub /////

impl std::ops::Sub<Integer> for Integer {
    type Output = Integer;
    fn sub(self, rhs: Integer) -> Self::Output {
        Integer(&self.0 - rhs.0)
    }
}
impl std::ops::Sub<Integer> for &Integer {
    type Output = Integer;
    fn sub(self, rhs: Integer) -> Self::Output {
        Integer(&self.0 - rhs.0)
    }
}
impl std::ops::Sub<&Integer> for Integer {
    type Output = Integer;
    fn sub(self, rhs: &Integer) -> Self::Output {
        Integer(self.0 - &rhs.0)
    }
}
impl std::ops::Sub<&Integer> for &Integer {
    type Output = Integer;
    fn sub(self, rhs: &Integer) -> Self::Output {
        Integer((&self.0 - &rhs.0).complete())
    }
}
impl std::ops::Sub<i32> for Integer {
    type Output = Integer;
    fn sub(self, rhs: i32) -> Self::Output {
        Integer(self.0 - rhs)
    }
}
impl std::ops::Sub<u32> for Integer {
    type Output = Integer;
    fn sub(self, rhs: u32) -> Self::Output {
        Integer(self.0 - rhs)
    }
}
impl std::ops::Sub<u32> for &Integer {
    type Output = Integer;
    fn sub(self, rhs: u32) -> Self::Output {
        Integer((&self.0 - rhs).complete())
    }
}
impl std::ops::Sub<i32> for &Integer {
    type Output = Integer;
    fn sub(self, rhs: i32) -> Self::Output {
        Integer((&self.0 - rhs).complete())
    }
}
impl std::ops::Sub<u8> for Integer {
    type Output = Integer;
    fn sub(self, rhs: u8) -> Self::Output {
        Integer(self.0 - rhs)
    }
}
impl std::ops::Sub<u8> for &Integer {
    type Output = Integer;
    fn sub(self, rhs: u8) -> Self::Output {
        Integer((&self.0 - rhs).complete())
    }
}

///// Neg /////

impl std::ops::Neg for Integer {
    type Output = Integer;
    fn neg(self) -> Self::Output {
        Integer(self.0.neg())
    }
}
impl std::ops::Neg for &Integer {
    type Output = Integer;
    fn neg(self) -> Self::Output {
        Integer((-&self.0).complete())
    }
}

///// Mul /////

impl std::ops::Mul<Integer> for Integer {
    type Output = Integer;
    fn mul(self, rhs: Integer) -> Self::Output {
        Integer(self.0 * rhs.0)
    }
}
impl std::ops::Mul<&Integer> for Integer {
    type Output = Integer;
    fn mul(self, rhs: &Integer) -> Self::Output {
        Integer(self.0 * &rhs.0)
    }
}
impl std::ops::Mul<Integer> for &Integer {
    type Output = Integer;
    fn mul(self, rhs: Integer) -> Self::Output {
        Integer(&self.0 * rhs.0)
    }
}
impl std::ops::Mul<&Integer> for &Integer {
    type Output = Integer;
    fn mul(self, rhs: &Integer) -> Self::Output {
        Integer((&self.0 * &rhs.0).complete())
    }
}
impl std::ops::Mul<&Integer> for u8 {
    type Output = Integer;
    fn mul(self, rhs: &Integer) -> Self::Output {
        Integer((self * &rhs.0).complete())
    }
}
impl std::ops::MulAssign<&Integer> for Integer {
    fn mul_assign(&mut self, rhs: &Integer) {
        self.0 *= &rhs.0
    }
}

///// Div /////

impl std::ops::Div<&Integer> for Integer {
    type Output = Integer;
    fn div(self, rhs: &Integer) -> Self::Output {
        Integer(self.0 / &rhs.0)
    }
}
impl std::ops::Div<u8> for Integer {
    type Output = Integer;
    fn div(self, rhs: u8) -> Self::Output {
        Integer(self.0 / rhs)
    }
}
impl std::ops::Div<i32> for Integer {
    type Output = Integer;
    fn div(self, rhs: i32) -> Self::Output {
        Integer(self.0 / rhs)
    }
}
impl std::ops::Div<u8> for &Integer {
    type Output = Integer;
    fn div(self, rhs: u8) -> Self::Output {
        Integer((&self.0 / rhs).complete())
    }
}

///// Rem /////

impl std::ops::Rem<Integer> for Integer {
    type Output = Integer;
    fn rem(self, rhs: Integer) -> Self::Output {
        Integer(self.0 % rhs.0)
    }
}
impl std::ops::Rem<&Integer> for Integer {
    type Output = Integer;
    fn rem(self, rhs: &Integer) -> Self::Output {
        Integer(self.0 % &rhs.0)
    }
}
impl std::ops::Rem<&Integer> for &Integer {
    type Output = Integer;
    fn rem(self, rhs: &Integer) -> Self::Output {
        Integer((&self.0 % &rhs.0).complete())
    }
}
impl std::ops::RemAssign<&Integer> for Integer {
    fn rem_assign(&mut self, rhs: &Integer) {
        self.0 %= &rhs.0
    }
}

///// Shl /////

impl std::ops::Shl<u32> for Integer {
    type Output = Integer;
    fn shl(self, rhs: u32) -> Self::Output {
        Integer(self.0 << rhs)
    }
}

impl std::ops::Shl<usize> for Integer {
    type Output = Integer;
    fn shl(self, rhs: usize) -> Self::Output {
        Integer(self.0 << rhs)
    }
}

impl std::ops::Shl<u32> for &Integer {
    type Output = Integer;
    fn shl(self, rhs: u32) -> Self::Output {
        Integer((&self.0 << rhs).complete())
    }
}

impl std::ops::ShlAssign<u32> for Integer {
    fn shl_assign(&mut self, rhs: u32) {
        self.0 <<= rhs
    }
}

///// Shr /////

impl std::ops::Shr<u32> for Integer {
    type Output = Integer;
    fn shr(self, rhs: u32) -> Self::Output {
        Integer(self.0 >> rhs)
    }
}
impl std::ops::Shr<u32> for &Integer {
    type Output = Integer;
    fn shr(self, rhs: u32) -> Self::Output {
        Integer((&self.0 >> rhs).complete())
    }
}
impl std::ops::ShrAssign<u32> for Integer {
    fn shr_assign(&mut self, rhs: u32) {
        self.0 >>= rhs
    }
}

///// BitOr /////

impl std::ops::BitOrAssign<u32> for Integer {
    fn bitor_assign(&mut self, rhs: u32) {
        self.0 |= rhs
    }
}

///// From /////

impl From<u16> for Integer {
    fn from(value: u16) -> Self {
        Integer(value.into())
    }
}
impl From<i32> for Integer {
    fn from(value: i32) -> Self {
        Integer(value.into())
    }
}
impl From<u32> for Integer {
    fn from(value: u32) -> Self {
        Integer(value.into())
    }
}

///// Various /////

impl std::fmt::Display for Integer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

///// Methods from rug /////

impl Integer {
    pub fn one() -> Self {
        Integer(rug::Integer::ONE.clone())
    }
    pub fn zero() -> Self {
        Integer(rug::Integer::new())
    }
    pub(crate) fn is_one(&self) -> bool {
        &self.0 == rug::Integer::ONE
    }

    pub fn is_even(&self) -> bool {
        self.0.is_even()
    }

    pub(crate) fn cmp_abs(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp_abs(&other.0)
    }

    pub(crate) fn lcm(self, other: &Self) -> Self {
        Integer(self.0.lcm(&other.0))
    }
    pub fn gcd_ref(&self, other: &Self) -> Self {
        Integer(self.0.gcd_ref(&other.0).complete())
    }

    pub fn cmp0(&self) -> std::cmp::Ordering {
        self.0.cmp0()
    }

    pub fn pow_mod(self, exponent: &Self, modulo: &Self) -> Option<Self> {
        self.0
            .pow_mod(&exponent.0, &modulo.0)
            .map(Integer)
            .ok()
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

    pub(crate) fn invert(self, modulo: &Self) -> Option<Self> {
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

    pub(crate) fn assign_random_below(&mut self, modulo: &Self, rng: &mut impl rand_core::RngCore) {
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
        for _ in 0..4096 {
            x.assign_random_bits(bit_size, rng);
            x.set_bit(bit_size - 1, true);
            x |= 1u32;
            if let IsPrime::Yes | IsPrime::Probably = x.is_probably_prime(25) {
                return x;
            }
        }
        panic!("Defective RNG: didn't find a prime number in 4096 attempts");
    }

    pub fn jacobi(&self, n: &Self) -> i32 {
        self.0.jacobi(&n.0)
    }

    /// Discards the sign
    pub fn to_bytes_lsf(&self) -> Vec<u8> {
        self.0.to_digits(rug::integer::Order::Lsf)
    }
    /// Discards the sign
    pub fn to_bytes_msf(&self) -> Vec<u8> {
        self.0.to_digits(rug::integer::Order::Msf)
    }
    pub fn from_bytes_msf(bytes: &[u8]) -> Self {
        Integer(rug::Integer::from_digits(bytes, rug::integer::Order::Msf))
    }
    pub fn from_str_radix(s: &str, radix: u16) -> Option<Self> {
        rug::Integer::from_str_radix(s, radix.into()).ok().map(Integer)
    }
    pub fn to_str_radix(&self, radix: u16) -> String {
        self.0.to_string_radix(radix.into())
    }
}

/// Wraps any randomness source that implements [`rand_core::RngCore`] and makes
/// it compatible with [`rug::rand`].
pub(crate) fn external_rand(rng: &mut impl rand_core::RngCore) -> rug::rand::ThreadRandState<'_> {
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

