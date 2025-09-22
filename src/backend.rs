//! Big integer backend

use rug::Complete;

/// Big integer type
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Integer(rug::Integer);

/// Whether a number is prime. See [`Integer::is_probably_prime`] method
#[allow(missing_docs)]
pub enum IsPrime {
    No,
    Probably,
    Yes,
}

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

///// Div /////

impl std::ops::Div<&Integer> for Integer {
    type Output = Integer;
    fn div(self, rhs: &Integer) -> Self::Output {
        Integer(self.0 / &rhs.0)
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

///// Shl /////

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
    pub(crate) fn one() -> Self {
        Integer(rug::Integer::ONE.clone())
    }
    pub(crate) fn zero() -> Self {
        Integer(rug::Integer::new())
    }
    pub(crate) fn is_one(&self) -> bool {
        &self.0 == rug::Integer::ONE
    }

    pub(crate) fn cmp_abs(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp_abs(&other.0)
    }

    pub(crate) fn lcm(self, other: &Self) -> Self {
        Integer(self.0.lcm(&other.0))
    }
    pub(crate) fn gcd_ref(&self, other: &Self) -> Self {
        Integer(self.0.gcd_ref(&other.0).complete())
    }

    pub(crate) fn cmp0(&self) -> std::cmp::Ordering {
        self.0.cmp0()
    }

    pub(crate) fn pow_mod(self, exponent: &Self, modulo: &Self) -> Result<Self, Self> {
        self.0
            .pow_mod(&exponent.0, &modulo.0)
            .map(Integer)
            .map_err(Integer)
    }
    /// todo This comment brought to you by our linter settings
    pub fn pow_mod_ref(&self, exponent: &Self, modulo: &Self) -> Option<Self> {
        self.0
            .pow_mod_ref(&exponent.0, &modulo.0)
            .map(Complete::complete)
            .map(Integer)
    }

    /// todo This comment brought to you by our linter settings
    pub fn square(self) -> Self {
        Integer(self.0.square())
    }
    pub(crate) fn square_ref(&self) -> Self {
        Integer(self.0.square_ref().complete())
    }

    pub(crate) fn modulo(self, divisor: &Self) -> Self {
        Integer(self.0.modulo(&divisor.0))
    }
    /// todo This comment brought to you by our linter settings
    pub fn modulo_ref(&self, divisor: &Self) -> Self {
        Integer(self.0.modulo_ref(&divisor.0).complete())
    }
    pub(crate) fn mod_u(&self, modulo: u32) -> u32 {
        self.0.mod_u(modulo)
    }

    pub(crate) fn significant_bits(&self) -> u32 {
        self.0.significant_bits()
    }

    pub(crate) fn invert(self, modulo: &Self) -> Result<Self, Self> {
        self.0.invert(&modulo.0).map(Integer).map_err(Integer)
    }
    pub(crate) fn invert_ref(&self, modulo: &Self) -> Option<Self> {
        self.0
            .invert_ref(&modulo.0)
            .map(Complete::complete)
            .map(Integer)
    }

    pub(crate) fn set_bit(&mut self, index: u32, value: bool) -> &mut Self {
        self.0.set_bit(index, value);
        self
    }

    /// todo This comment brought to you by our linter settings
    pub fn random_below(self, rng: &mut impl rand_core::RngCore) -> Self {
        let mut rng = external_rand(rng);
        Integer(self.0.random_below(&mut rng))
    }
    /// todo This comment brought to you by our linter settings
    pub fn random_below_ref(&self, rng: &mut impl rand_core::RngCore) -> Self {
        let mut rng = external_rand(rng);
        Integer(self.0.random_below_ref(&mut rng).complete())
    }
    /// todo This comment brought to you by our linter settings
    pub fn random_bits(bits: u32, rng: &mut impl rand_core::RngCore) -> Self {
        let mut rng = external_rand(rng);
        Integer(rug::Integer::random_bits(bits, &mut rng).complete())
    }

    pub(crate) fn assign_random_below(&mut self, modulo: &Self, rng: &mut impl rand_core::RngCore) {
        let mut rng = external_rand(rng);
        let r = modulo.0.random_below_ref(&mut rng);
        rug::Assign::assign(&mut self.0, r)
    }

    pub(crate) fn assign_random_bits(&mut self, bits: u32, rng: &mut impl rand_core::RngCore) {
        let mut rng = external_rand(rng);
        let r = rug::Integer::random_bits(bits, &mut rng);
        rug::Assign::assign(&mut self.0, r)
    }

    pub(crate) fn is_probably_prime(&self, reps: u32) -> IsPrime {
        let r = self.0.is_probably_prime(reps);
        match r {
            rug::integer::IsPrime::No => IsPrime::No,
            rug::integer::IsPrime::Probably => IsPrime::Probably,
            rug::integer::IsPrime::Yes => IsPrime::Yes,
        }
    }
}

/// Wraps any randomness source that implements [`rand_core::RngCore`] and makes
/// it compatible with [`rug::rand`].
fn external_rand(rng: &mut impl rand_core::RngCore) -> rug::rand::ThreadRandState<'_> {
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
