#![allow(missing_docs)]

use super::IsPrime;
use num_integer::Integer as _;
use num_traits::Signed as _;

/// Big integer type used in this crate
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct Integer(num_bigint::BigInt);

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
        self.0.to_bytes_le().1
    }
    /// Converts to bytes, with bytes representing _most_ significant base256
    /// digits appearing first. Discards the sign
    ///
    /// ## Example
    /// ```rust
    /// # use fast_paillier::backend::rug::Integer;
    /// let x = Integer::from(0x11223344);
    /// assert_eq!(x.to_bytes_lsf(), vec![0x11, 0x22, 0x33, 0x44]);
    /// ```
    pub fn to_bytes_msf(&self) -> Vec<u8> {
        self.0.to_bytes_be().1
    }
    /// Converts bytes to Integer. Inverse of [`to_bytes_msf`]
    pub fn from_bytes_msf(bytes: &[u8]) -> Self {
        Integer(num_bigint::BigInt::from_bytes_be(
            num_bigint::Sign::Plus,
            bytes,
        ))
    }
    /// Returns a string representation of the number for the specified radix
    pub fn to_str_radix(&self, radix: u16) -> String {
        self.0.to_str_radix(radix.into())
    }
    /// Parses the integer using the given radix
    pub fn from_str_radix(s: &str, radix: u16) -> Option<Self> {
        num_traits::Num::from_str_radix(s, radix.into()).ok().map(Integer)
    }
    /// Convert the number to the underlying backend representation
    pub fn to_num_bigint(self) -> num_bigint::BigInt {
        self.0
    }
    /// Convert the number from the underlying backend representation
    pub fn from_num_bigint(x: num_bigint::BigInt) -> Self {
        Self(x)
    }
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
impl std::ops::Add<Integer> for &Integer {
    type Output = Integer;
    fn add(self, rhs: Integer) -> Self::Output {
        Integer(&self.0 + rhs.0)
    }
}
impl std::ops::Add<&Integer> for &Integer {
    type Output = Integer;
    fn add(self, rhs: &Integer) -> Self::Output {
        Integer(&self.0 + &rhs.0)
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
        Integer(&self.0 + rhs)
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
        Integer(&self.0 - &rhs.0)
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
        Integer(&self.0 - rhs)
    }
}
impl std::ops::Sub<i32> for &Integer {
    type Output = Integer;
    fn sub(self, rhs: i32) -> Self::Output {
        Integer(&self.0 - rhs)
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
        Integer(&self.0 - rhs)
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
        Integer(-&self.0)
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
        Integer(&self.0 * &rhs.0)
    }
}
impl std::ops::Mul<&Integer> for u8 {
    type Output = Integer;
    fn mul(self, rhs: &Integer) -> Self::Output {
        Integer(self * &rhs.0)
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
        Integer(&self.0 / rhs)
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
        Integer(&self.0 % &rhs.0)
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
        Integer(&self.0 << rhs)
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
        Integer(&self.0 >> rhs)
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
        self.0 |= num_bigint::BigInt::from(rhs)
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
        Integer(num_traits::One::one())
    }
    pub fn zero() -> Self {
        Integer(num_traits::Zero::zero())
    }
    pub(crate) fn is_one(&self) -> bool {
        num_traits::One::is_one(&self.0)
    }

    pub fn is_even(&self) -> bool {
        self.0.is_even()
    }

    pub(crate) fn cmp_abs(&self, other: &Self) -> std::cmp::Ordering {
        self.0.magnitude().cmp(other.0.magnitude())
    }

    pub(crate) fn lcm(self, other: &Self) -> Self {
        Integer(self.0.lcm(&other.0))
    }
    pub fn gcd_ref(&self, other: &Self) -> Self {
        Integer(self.0.gcd(&other.0))
    }

    pub fn cmp0(&self) -> std::cmp::Ordering {
        if num_traits::Zero::is_zero(&self.0) {
            std::cmp::Ordering::Equal
        } else if self.0.is_positive() {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Less
        }
    }

    pub fn pow_mod(self, exponent: &Self, modulo: &Self) -> Option<Self> {
        self.pow_mod_ref(exponent, modulo)
    }
    pub fn pow_mod_ref(&self, exponent: &Self, modulo: &Self) -> Option<Self> {
        if exponent.0.is_negative() {
            let nself = self.0.modinv(&modulo.0)?;
            Some(Integer(nself.modpow(&-&exponent.0, &modulo.0)))
        } else {
            Some(Integer(self.0.modpow(&exponent.0, &modulo.0)))
        }
    }
    pub fn u_pow_u(base: u32, exponent: u32) -> Self {
        let base = num_bigint::BigInt::from(base);
        Integer(base.pow(exponent))
    }

    pub fn square(self) -> Self {
        &self * &self
    }
    pub fn square_ref(&self) -> Self {
        self * self
    }
    pub fn sqrt(self) -> Self {
        self.sqrt_ref()
    }
    pub fn sqrt_ref(&self) -> Self {
        Integer(self.0.sqrt())
    }

    pub fn modulo(self, divisor: &Self) -> Self {
        Integer(num_traits::Euclid::rem_euclid(&self.0, &divisor.0))
    }
    pub fn modulo_ref(&self, divisor: &Self) -> Self {
        Integer(num_traits::Euclid::rem_euclid(&self.0, &divisor.0))
    }
    pub fn modulo_mut(&mut self, divisor: &Self) {
        self.0 = num_traits::Euclid::rem_euclid(&self.0, &divisor.0);
    }
    pub fn mod_u(&self, modulo: u32) -> u32 {
        let big = num_traits::Euclid::rem_euclid(&self.0, &num_bigint::BigInt::from(modulo));
        if num_traits::Zero::is_zero(&big) {
            0
        } else {
            let (sign, digits) = big.to_u32_digits();
            debug_assert_eq!(sign, num_bigint::Sign::Plus);
            debug_assert_eq!(digits.len(), 1);
            digits[0]
        }
    }

    pub fn significant_bits(&self) -> u64 {
        self.0.bits()
    }
    pub fn significant_dwords(&self) -> usize {
        (usize::try_from(self.0.bits()).expect("length overflows usize") + 31) / 32
    }

    pub(crate) fn invert(self, modulo: &Self) -> Option<Self> {
        self.0.modinv(&modulo.0).map(Integer)
    }
    pub fn invert_ref(&self, modulo: &Self) -> Option<Self> {
        self.0.modinv(&modulo.0).map(Integer)
    }

    pub fn set_bit(&mut self, index: u32, value: bool) -> &mut Self {
        self.0.set_bit(index.into(), value);
        self
    }

    pub fn random_below(self, rng: &mut impl rand_core::RngCore) -> Self {
        let range = num_traits::ConstZero::ZERO..self.0;
        Integer(rand::Rng::gen_range(rng, range))
    }
    pub fn random_below_ref(&self, rng: &mut impl rand_core::RngCore) -> Self {
        let range = num_traits::ConstZero::ZERO..self.0.clone();
        Integer(rand::Rng::gen_range(rng, range))
    }
    pub fn random_bits(bits: u32, rng: &mut impl rand_core::RngCore) -> Self {
        let dist = num_bigint::RandomBits::new(bits.into());
        let uint = rand::distributions::Distribution::sample(&dist, rng);
        Integer(num_bigint::BigInt::from_biguint(num_bigint::Sign::Plus, uint))
    }

    pub(crate) fn assign_random_below(&mut self, modulo: &Self, rng: &mut impl rand_core::RngCore) {
        *self = modulo.random_below_ref(rng);
    }

    pub fn assign_random_bits(&mut self, bits: u32, rng: &mut impl rand_core::RngCore) {
        *self = Self::random_bits(bits, rng);
    }

    // TODO reps is unused here, need to unify with rug
    pub fn is_probably_prime(&self, _reps: u32) -> IsPrime {
        if self.cmp0().is_le() {
            IsPrime::No
        } else if glass_pumpkin::prime::check(self.0.magnitude()) {
            IsPrime::Yes
        } else {
            IsPrime::No
        }
    }

    pub fn generate_prime(rng: &mut impl rand_core::RngCore, bit_size: u32) -> Self {
        let mut x = Integer::zero();
        loop {
            x.assign_random_bits(bit_size, rng);
            x.set_bit(bit_size - 1, true);
            x |= 1u32;
            if glass_pumpkin::prime::check_with(x.0.magnitude(), rng) {
                break x
            }
        }
    }

    /// Compute jacobi symbol of a over n
    ///
    /// Requires odd `n >= 3`. If it doesn't hold, function
    /// panics if debug asserts are enabled, or returns 0 otherwise.
    ///
    /// Implementation is taken from [Handbook of Applied cryptography][book],
    /// p. 73, Algorithm 2.149
    ///
    /// [book]: https://cacr.uwaterloo.ca/hac/about/chap2.pdf
    #[inline(always)]
    pub fn jacobi(&self, n: &Self) -> i32 {
        if n.0.is_even() || n.0 <= num_bigint::BigInt::from(2) {
            debug_assert!(false, "n should be an odd number larger than 2");
            return 0;
        }
        let a = self.modulo_ref(n);
        jacobi_inner(1, &a.0, &n.0)
    }
}

/// Computes jacobi symbol of `a` over `n` multiplied at `mult`
///
/// `mult` is a small modification over original algorithm defined in the book,
/// it helps to keep function in tail recursion form, which ensures that
/// recursion is optimized out
fn jacobi_inner(mult: i32, a: &num_bigint::BigInt, n: &num_bigint::BigInt) -> i32 {
    // Step 1
    if num_traits::Zero::is_zero(a) {
        return 0;
    }
    // Step 2
    if num_traits::One::is_one(a) {
        return mult * 1;
    }

    // Step 3. Find a1, e such that a = 2^e * a1 where a1 is odd
    let mut a1 = a.clone();
    let mut e = 0_u32;
    while a1.is_even() {
        e += 1;
        a1 >>= 1;
    }
    debug_assert_eq!(*a, &a1 << e);

    // Step 4
    let n_mod_8 = last_limb(&n) % 8;
    let mut s = if e % 2 == 0 {
        // if e is even, s = 1
        1
    } else if n_mod_8 == 1 || n_mod_8 == 7 {
        // if n = 1 or 7 (mod 8), s = 1
        1
    } else if n_mod_8 == 3 || n_mod_8 == 5 {
        // if n = 3 or 5 (mod 8), s = -1
        -1
    } else {
        unreachable!()
    };

    // Step 5
    if last_limb(&n) % 4 == 3 && last_limb(&a1) % 4 == 3 {
        s = -s
    }

    // Step 6
    let n1 = num_traits::Euclid::rem_euclid(n, &a1);

    // Step 7
    if num_traits::One::is_one(&a1) {
        mult * s
    } else {
        jacobi_inner(mult * s, &n1, &a1)
    }
}

fn last_limb(x: &num_bigint::BigInt) -> u32 {
    x.magnitude().iter_u32_digits().next().unwrap_or(0)
}

#[cfg(test)]
mod test {
    use super::Integer;

    fn blum_prime(len: u32, rng: &mut impl rand_core::RngCore) -> Integer {
        for _ in 0..4096 {
            let mut r = Integer::random_bits(len, rng);
            r.set_bit(0, true);
            if r.is_probably_prime(25) != super::IsPrime::No && super::last_limb(&r.0) % 4 == 3 {
                return r;
            }
        }
        panic!("defective randomness: did not generate a prime after 4096 attempts");
    }

    /// Find principal square root in a Blum modulus quotient ring.
    ///
    /// Pre-requisites:
    /// - x is a quadratic residue in Zn
    /// - `n = pq`, p and q are Blum primes
    /// If these don't hold, the result is a bogus number in Zn
    fn blum_sqrt(x: &Integer, p: &Integer, q: &Integer, n: &Integer) -> Integer {
        // Exponent in pq Blum modulus to obtain the principal square root.
        // Described in [Handbook of Applied cryptography, p. 75, Fact
        // 2.160](https://cacr.uwaterloo.ca/hac/about/chap2.pdf)
        let e = ((p - 1) * (q - 1) + 4) / 8;
        x.pow_mod_ref(&e, n)
            .expect("e guaranteed to be non-negative")
    }

    #[test]
    fn jacobi_and_sqrt() {
        let mut rng = rand_dev::DevRng::new();

        let p = blum_prime(128, &mut rng);
        let q = blum_prime(128, &mut rng);
        let n = &p * &q;

        for _ in 0..100 {
            let x = n.random_below_ref(&mut rng);
            let root = blum_sqrt(&x, &p, &q, &n);
            let x_ = root.square().modulo(&n);

            let jp = x.modulo_ref(&p).jacobi(&p);
            let jq = x.modulo_ref(&q).jacobi(&q);
            let j = x.jacobi(&n);
            assert_eq!(jp * jq, j);

            if jp == 1 && jq == 1 {
                assert_eq!(x_, x);
            } else {
                assert_ne!(x_, x);
            }
        }
    }

    #[cfg(feature = "backend-rug")]
    #[test]
    fn jacobi() {
        use crate::backend::rug::Integer as RugInteger;
        let mut rng = rand_dev::DevRng::new();

        for _ in 0..32 {
            let a = Integer::random_bits(16, &mut rng);
            let mut b = Integer::random_bits(16, &mut rng);
            b.set_bit(0, false); // make it odd
            if b.cmp0().is_lt() {
                b = -b;
            }
            b.set_bit(0, true);
            let j = a.jacobi(&b);

            let a_ = RugInteger::from_bytes_msf(&a.to_bytes_msf());
            let a_ = if a.cmp0().is_lt() { -a_ } else { a_ };
            let b_ = RugInteger::from_bytes_msf(&b.to_bytes_msf());
            let j_ = a_.jacobi(&b_);

            assert_eq!(j, j_);
        }
    }
}
