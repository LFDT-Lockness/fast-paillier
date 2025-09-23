//! Various utilities

use std::fmt;

use rand_core::RngCore;

use crate::backend::Integer;

mod small_primes;

/// Checks that `x` is in Z<super>*</super><sub>n</sub>
#[inline(always)]
pub fn in_mult_group(x: &Integer, n: &Integer) -> bool {
    x.cmp0().is_gt() && x < n && x.gcd_ref(n).is_one()
}

/// Checks that `abs(x)` is in Z<super>*</super><sub>n</sub>
#[inline(always)]
pub fn in_mult_group_abs(x: &Integer, n: &Integer) -> bool {
    x.cmp_abs(n).is_lt() && x.gcd_ref(n).is_one()
}

/// Samples `x` in Z*_n
pub fn sample_in_mult_group(rng: &mut impl RngCore, n: &Integer) -> Integer {
    let mut x = Integer::zero();
    loop {
        x.assign_random_below(n, rng);
        if in_mult_group(&x, n) {
            return x;
        }
    }
}

/// Generates a random safe prime
pub fn generate_safe_prime(rng: &mut impl RngCore, bits: u32) -> Integer {
    sieve_generate_safe_primes(rng, bits, 135)
}

/// Generate a random safe prime with a given sieve parameter.
///
/// For different bit sizes, different parameter value will give fastest
/// generation, the higher bit size - the higher the sieve parameter.
/// The best way to select the parameter is by trial. The one used by
/// [`generate_safe_prime`] is indistinguishable from optimal for 500-1700 bit
/// lengths.
pub fn sieve_generate_safe_primes(rng: &mut impl RngCore, bits: u32, amount: usize) -> Integer {
    use crate::backend::IsPrime;

    let amount = amount.min(small_primes::SMALL_PRIMES.len());
    let mut x = Integer::zero();

    'trial: loop {
        // generate an odd number of length `bits - 2`
        x.assign_random_bits(bits - 1, rng);
        // `random_bits` is guaranteed to not set `bits-1`-th bit, but not
        // guaranteed to set the `bits-2`-th
        x.set_bit(bits - 2, true);
        x |= 1u32;

        for &small_prime in &small_primes::SMALL_PRIMES[0..amount] {
            let mod_result = x.mod_u(small_prime);
            if mod_result == (small_prime - 1) / 2 {
                continue 'trial;
            }
        }

        // 25 taken same as one used in mpz_nextprime
        if let IsPrime::Yes | IsPrime::Probably = x.is_probably_prime(25) {
            x <<= 1;
            x += 1;
            if let IsPrime::Yes | IsPrime::Probably = x.is_probably_prime(25) {
                return x;
            }
        }
    }
}

/// Faster algorithm for modular exponentiation based on Chinese remainder theorem when modulo factorization is known
///
/// `CrtExp` makes exponentation modulo `n` faster when factorization `n = n1 * n2` is known as well as `phi(n1)` and `phi(n2)`
/// (note that `n1` and `n2` don't need to be primes). In this case, you can [build](Self::build) a `CrtExp` and use provided
/// [exponentiation algorithm](Self::exp).
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CrtExp {
    n: Integer,
    n1: Integer,
    phi_n1: Integer,
    n2: Integer,
    phi_n2: Integer,
    beta: Integer,
}

/// Exponent for [modular exponentiation](CrtExp::exp) via [`CrtExp`]
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Exponent {
    e_mod_phi_pp: Integer,
    e_mod_phi_qq: Integer,
    is_negative: bool,
}

impl CrtExp {
    /// Builds a `CrtExp` for exponentation modulo `n = n1 * n2`
    ///
    /// `phi_n1 = phi(n1)` and `phi_n2 = phi(n2)` need to be known. For instance, if `p` is a prime,
    /// then `phi(p) = p - 1` and `phi(p^2) = p * (p - 1)`.
    ///
    /// [`CrtExp::build_n`] and [`CrtExp::build_nn`] can be used when `n1` and `n2` are primes or
    /// square of primes.
    pub fn build(n1: Integer, phi_n1: Integer, n2: Integer, phi_n2: Integer) -> Option<Self> {
        if n1.cmp0().is_le()
            || n2.cmp0().is_le()
            || phi_n1.cmp0().is_le()
            || phi_n2.cmp0().is_le()
            || phi_n1 >= n1
            || phi_n2 >= n2
        {
            return None;
        }

        let beta = n1.invert_ref(&n2)?;
        Some(Self {
            n: &n1 * &n2,
            n1,
            phi_n1,
            n2,
            phi_n2,
            beta,
        })
    }

    /// Builds a `CrtExp` for exponentiation modulo `n = p * q` where `p`, `q` are primes
    pub fn build_n(p: &Integer, q: &Integer) -> Option<Self> {
        let phi_p = p - 1u8;
        let phi_q = q - 1u8;
        Self::build(p.clone(), phi_p, q.clone(), phi_q)
    }

    /// Builds a `CrtExp` for exponentiation modulo `nn = (p * q)^2` where `p`, `q` are primes
    pub fn build_nn(p: &Integer, q: &Integer) -> Option<Self> {
        let pp = p.square_ref();
        let qq = q.square_ref();
        let phi_pp = &pp - p;
        let phi_qq = &qq - q;
        Self::build(pp, phi_pp, qq, phi_qq)
    }

    /// Prepares exponent to perform [modular exponentiation](Self::exp)
    pub fn prepare_exponent(&self, e: &Integer) -> Exponent {
        let neg_e = -e;
        let is_negative = e.cmp0().is_lt();
        let e = if is_negative { &neg_e } else { e };
        let e_mod_phi_pp = e.modulo_ref(&self.phi_n1);
        let e_mod_phi_qq = e.modulo_ref(&self.phi_n2);
        Exponent {
            e_mod_phi_pp,
            e_mod_phi_qq,
            is_negative,
        }
    }

    /// Performs exponentiation modulo `n`
    ///
    /// Exponent needs to be output of [`CrtExp::prepare_exponent`]
    pub fn exp(&self, x: &Integer, e: &Exponent) -> Option<Integer> {
        let s1 = x.modulo_ref(&self.n1);
        let s2 = x.modulo_ref(&self.n2);

        // `e_mod_phi_pp` and `e_mod_phi_qq` are guaranteed to be non-negative by construction
        #[allow(clippy::expect_used)]
        let r1 = s1
            .pow_mod(&e.e_mod_phi_pp, &self.n1)
            .expect("exponent is guaranteed to be non-negative");
        #[allow(clippy::expect_used)]
        let r2 = s2
            .pow_mod(&e.e_mod_phi_qq, &self.n2)
            .expect("exponent is guaranteed to be non-negative");

        let result = ((r2 - &r1) * &self.beta).modulo(&self.n2) * &self.n1 + &r1;

        if e.is_negative {
            result.invert(&self.n)
        } else {
            Some(result)
        }
    }
}

impl fmt::Debug for CrtExp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // CRT likely contains secret data (such as factorization) so we make sure none of it
        // is leaked through `fmt::Debug`
        f.write_str("CrtExp")
    }
}

impl fmt::Debug for Exponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Exponent may contain secret data, so we make sure none of it is leaked through
        // `fmt::Debug`
        f.write_str("CrtExponent")
    }
}

#[cfg(test)]
mod test {
    use crate::backend::Integer;

    #[test]
    fn safe_prime_size() {
        let mut rng = rand_dev::DevRng::new();
        for size in [500, 512, 513, 514] {
            let mut prime = super::generate_safe_prime(&mut rng, size);
            // rug doesn't have bit length operations, so
            prime >>= size - 1;
            assert_eq!(prime.significant_bits(), 1);
            assert_eq!(prime, Integer::one());
        }
    }

    #[test]
    fn mult_group_check() {
        use super::{in_mult_group, in_mult_group_abs};

        let n = Integer::from(10);

        let mult_group = [1, 3, 7, 9].map(Integer::from);
        let not_mult_group = [0, 2, 4, 5, 6, 8, 10].map(Integer::from);

        for x in mult_group {
            assert!(in_mult_group(&x, &n));
            assert!(in_mult_group_abs(&x, &n));
            assert!(in_mult_group_abs(&-x, &n));
        }
        for x in not_mult_group {
            assert!(!in_mult_group(&x, &n));
            assert!(!in_mult_group_abs(&x, &n));
            assert!(!in_mult_group_abs(&-x, &n));
        }
        for delta in 0..15_u32 {
            let x = &n + delta;
            assert!(!in_mult_group(&x, &n));
            assert!(!in_mult_group_abs(&x, &n));
            assert!(!in_mult_group_abs(&-x, &n));
        }
    }
}
