#![allow(missing_docs)]

use alloc::{string::String, vec::Vec};

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
    /// # use fast_paillier::backend::num_bigint::Integer;
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
    /// # use fast_paillier::backend::num_bigint::Integer;
    /// let x = Integer::from(0x11223344);
    /// assert_eq!(x.to_bytes_msf(), vec![0x11, 0x22, 0x33, 0x44]);
    /// ```
    pub fn to_bytes_msf(&self) -> Vec<u8> {
        self.0.to_bytes_be().1
    }
    /// Converts to bytes, with bytes representing _most_ significant base256
    /// digits appearing first
    ///
    /// ## Example
    /// ```rust
    /// # use fast_paillier::backend::{num_bigint::Integer, Sign};
    /// let x = Integer::from(-0x11223344);
    /// assert_eq!(x.to_bytes_msf_signed(), (vec![0x11, 0x22, 0x33, 0x44],
    /// Sign::Negative));
    /// ```
    pub fn to_bytes_msf_signed(&self) -> (Vec<u8>, super::Sign) {
        (self.0.to_bytes_be().1, self.sign())
    }
    /// Converts bytes to Integer. Inverse of [`Integer::to_bytes_msf`]
    pub fn from_bytes_msf(bytes: &[u8]) -> Self {
        Integer(num_bigint::BigInt::from_bytes_be(
            num_bigint::Sign::Plus,
            bytes,
        ))
    }
    /// Converts bytes to Integer. Inverse of [`Integer::to_bytes_msf_signed`]
    pub fn from_bytes_msf_signed(bytes: &[u8], sign: super::Sign) -> Self {
        let r = Integer(num_bigint::BigInt::from_bytes_be(
            num_bigint::Sign::Plus,
            bytes,
        ));
        if sign == super::Sign::Negative {
            -r
        } else {
            r
        }
    }
    /// Returns a string representation of the number for the specified radix
    pub fn to_str_radix(&self, radix: u16) -> String {
        self.0.to_str_radix(radix.into())
    }
    /// Parses the integer using the given radix
    pub fn from_str_radix(s: &str, radix: u16) -> Option<Self> {
        num_traits::Num::from_str_radix(s, radix.into())
            .ok()
            .map(Integer)
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

use super::macro_defs;

macro_defs::make_all_ops!(Integer);
macro_defs::make_all_bitops!(Integer, num_bigint::BigInt::from);

///// Methods from rug /////

impl Integer {
    pub fn one() -> Self {
        Integer(num_traits::One::one())
    }
    pub fn zero() -> Self {
        Integer(num_traits::Zero::zero())
    }
    pub fn is_one(&self) -> bool {
        num_traits::One::is_one(&self.0)
    }

    pub fn is_even(&self) -> bool {
        self.0.is_even()
    }

    pub fn abs(self) -> Self {
        // Abs in the backend crate clones, but we can do better
        let (_sign, val) = self.0.into_parts();
        Self(num_bigint::BigInt::from(val))
    }
    pub fn cmp_abs(&self, other: &Self) -> core::cmp::Ordering {
        self.0.magnitude().cmp(other.0.magnitude())
    }

    pub fn lcm_ref(&self, other: &Self) -> Self {
        Integer(self.0.lcm(&other.0))
    }
    pub fn gcd_ref(&self, other: &Self) -> Self {
        Integer(self.0.gcd(&other.0))
    }

    pub fn cmp0(&self) -> core::cmp::Ordering {
        match self.0.sign() {
            num_bigint::Sign::NoSign => core::cmp::Ordering::Equal,
            num_bigint::Sign::Plus => core::cmp::Ordering::Greater,
            num_bigint::Sign::Minus => core::cmp::Ordering::Less,
        }
    }
    pub fn sign(&self) -> super::Sign {
        match self.0.sign() {
            num_bigint::Sign::Minus => super::Sign::Negative,
            _ => super::Sign::NonNegative,
        }
    }

    pub fn pow_mod(self, exponent: &Self, modulo: &Self) -> Option<Self> {
        self.pow_mod_ref(exponent, modulo)
    }
    pub fn pow_mod_ref(&self, exponent: &Self, modulo: &Self) -> Option<Self> {
        let r = if exponent.0.is_negative() {
            let nself = self.0.modinv(&modulo.0)?;
            Integer(nself.modpow(&-&exponent.0, &modulo.0))
        } else {
            Integer(self.0.modpow(&exponent.0, &modulo.0))
        };
        // Rug always produces a positive result here. Num-bigint always
        // produces a result between zero and modulo. When modulo is negative,
        // adjust by it to obtain a result identical to rug
        if modulo.cmp0().is_lt() && r.cmp0().is_ne() {
            Some(r - modulo)
        } else {
            Some(r)
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
    pub fn sqrt(self) -> Option<Self> {
        self.sqrt_ref()
    }
    pub fn sqrt_ref(&self) -> Option<Self> {
        if self.cmp0().is_lt() {
            None
        } else {
            Some(Integer(self.0.sqrt()))
        }
    }

    pub fn modulo(self, divisor: &Self) -> Self {
        Integer(num_traits::Euclid::rem_euclid(&self.0, &divisor.0))
    }
    pub fn modulo_ref(&self, divisor: &Self) -> Self {
        Integer(num_traits::Euclid::rem_euclid(&self.0, &divisor.0))
    }
    pub fn modulo_mut(&mut self, divisor: &Self) -> &mut Self {
        self.0 = num_traits::Euclid::rem_euclid(&self.0, &divisor.0);
        self
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
        self.0.iter_u32_digits().len()
    }

    pub fn invert(self, modulo: &Self) -> Option<Self> {
        self.invert_ref(modulo)
    }
    pub fn invert_ref(&self, modulo: &Self) -> Option<Self> {
        let r = self.0.modinv(&modulo.0).map(Integer)?;
        // Rug always produces a positive result here. Num-bigint always
        // produces a result between zero and modulo. When modulo is negative,
        // adjust by it to obtain a result identical to rug
        if modulo.cmp0().is_lt() && r.cmp0().is_ne() {
            Some(r - modulo)
        } else {
            Some(r)
        }
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
        Integer(num_bigint::BigInt::from_biguint(
            num_bigint::Sign::Plus,
            uint,
        ))
    }
    pub fn random_bits_signed(bits: u32, rng: &mut impl rand_core::RngCore) -> Self {
        let dist = num_bigint::RandomBits::new(bits.into());
        let uint = rand::distributions::Distribution::sample(&dist, rng);
        let negative = rand::Rng::gen(rng);
        let sign = if negative {
            num_bigint::Sign::Minus
        } else {
            num_bigint::Sign::Plus
        };
        Integer(num_bigint::BigInt::from_biguint(sign, uint))
    }

    pub fn assign_random_below(&mut self, modulo: &Self, rng: &mut impl rand_core::RngCore) {
        *self = modulo.random_below_ref(rng);
    }

    pub fn assign_random_bits(&mut self, bits: u32, rng: &mut impl rand_core::RngCore) {
        *self = Self::random_bits(bits, rng);
    }

    // TODO reps is unused here, need to unify with rug
    pub fn is_probably_prime(&self, _reps: u32, rng: &mut impl rand_core::RngCore) -> IsPrime {
        if self.cmp0().is_le() {
            IsPrime::No
        } else if glass_pumpkin::prime::check_with(self.0.magnitude(), rng) {
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
                break x;
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

    /// Compute l^le * r^re modulo self
    pub fn combine(&self, l: &Self, le: &Self, r: &Self, re: &Self) -> Option<Self> {
        let l_to_le = l.pow_mod_ref(le, self)?;
        let r_to_re = r.pow_mod_ref(re, self)?;
        let r = (l_to_le * r_to_re).modulo(self);
        Some(r)
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
        return mult;
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
    let n_mod_8 = last_limb(n) % 8;
    let mut s = if e.is_multiple_of(2) {
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
    if last_limb(n) % 4 == 3 && last_limb(&a1) % 4 == 3 {
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

#[cfg(feature = "quickcheck")]
impl quickcheck::Arbitrary for Integer {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let bytes = Vec::<u8>::arbitrary(g);
        let sign = super::Sign::arbitrary(g);
        Integer::from_bytes_msf_signed(&bytes, sign)
    }

    fn shrink(&self) -> alloc::boxed::Box<dyn Iterator<Item = Self>> {
        let mut prev = self.clone();
        alloc::boxed::Box::new(core::iter::from_fn(move || {
            if prev.cmp0().is_eq() {
                None
            } else {
                prev >>= 1;
                Some(prev.clone())
            }
        }))
    }
}

#[cfg(test)]
mod test {
    use super::Integer;

    fn blum_prime(len: u32, rng: &mut impl rand_core::RngCore) -> Integer {
        for _ in 0..4096 {
            let mut r = Integer::random_bits(len, rng);
            r.set_bit(0, true);
            if r.is_probably_prime(25, rng) != super::IsPrime::No && super::last_limb(&r.0) % 4 == 3
            {
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
    ///
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
}
