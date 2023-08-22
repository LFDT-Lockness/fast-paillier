use rand_core::RngCore;
use rug::{Assign, Complete, Integer};

/// Wraps any randomness source that implements [`rand_core::RngCore`] and makes
/// it compatible with [`rug::rand`].
pub fn external_rand(rng: &mut impl RngCore) -> rug::rand::ThreadRandState {
    use bytemuck::TransparentWrapper;

    #[derive(TransparentWrapper)]
    #[repr(transparent)]
    pub struct ExternalRand<R>(R);

    impl<R: RngCore> rug::rand::ThreadRandGen for ExternalRand<R> {
        fn gen(&mut self) -> u32 {
            self.0.next_u32()
        }
    }

    rug::rand::ThreadRandState::new_custom(ExternalRand::wrap_mut(rng))
}

/// Checks that `x` is in Z*_n
#[inline(always)]
pub fn in_mult_group(x: &Integer, n: &Integer) -> bool {
    x.cmp0().is_ge() && in_mult_group_abs(x, n)
}

/// Checks that `abs(x)` is in Z*_n
#[inline(always)]
pub fn in_mult_group_abs(x: &Integer, n: &Integer) -> bool {
    x.gcd_ref(n).complete() == *Integer::ONE
}

/// Samples `x` in Z*_n
pub fn sample_in_mult_group(rng: &mut impl RngCore, n: &Integer) -> Integer {
    let mut rng = external_rand(rng);
    let mut x = Integer::new();
    loop {
        x.assign(n.random_below_ref(&mut rng));
        if in_mult_group(&x, n) {
            return x;
        }
    }
}

/// Generates a random safe prime
pub fn generate_safe_prime(rng: &mut impl RngCore, bits: u32) -> Integer {
    use rug::integer::IsPrime;
    let mut rng = external_rand(rng);
    let mut x = Integer::new();
    loop {
        x.assign(Integer::random_bits(bits - 1, &mut rng));
        x.set_bit(bits - 2, true);
        x.next_prime_mut();
        x <<= 1;
        x += 1;

        if let IsPrime::Yes | IsPrime::Probably = x.is_probably_prime(25) {
            return x;
        }
    }
}

/// Provides functionality that's yet missing in [`rug::Integer`]
pub trait IntegerExt {
    /// Returns `self mod module`
    fn modulo(&self, module: &Self) -> Self;
}

impl IntegerExt for Integer {
    fn modulo(&self, module: &Self) -> Self {
        let c = (self % module).complete();
        if c.cmp0().is_lt() {
            module + c
        } else {
            c
        }
    }
}

/// Faster exponentiation `x^e mod N^2` when factorization of `N = pq` is known and `e` is fixed
pub trait FactorizedExp: Sized {
    /// Precomputes data for exponentiation
    fn build(e: &Integer, p: &Integer, q: &Integer) -> Option<Self>;
    /// Returns `x^e mod (p q)^2`
    fn exp(&self, x: &Integer) -> Integer;
}

/// Naive `x^e mod N` implementation without optimizations
#[derive(Clone)]
pub struct NaiveExp {
    nn: Integer,
    e: Integer,
}

impl FactorizedExp for NaiveExp {
    fn build(e: &Integer, p: &Integer, q: &Integer) -> Option<Self> {
        if e.cmp0().is_lt() || p.cmp0().is_le() || q.cmp0().is_le() {
            return None;
        }
        let n = (p * q).complete();
        Some(Self {
            e: e.clone(),
            nn: n.square(),
        })
    }

    fn exp(&self, x: &Integer) -> Integer {
        // We check that `e` is non-negative at the construction in `Self::build`
        #[allow(clippy::expect_used)]
        x.pow_mod_ref(&self.e, &self.nn)
            .expect("`e` is checked to be non-negative")
            .into()
    }
}

/// Faster algorithm for exponentiation based on Chinese remainder theorem
#[derive(Clone)]
pub struct CrtExp {
    pp: Integer,
    qq: Integer,
    e_mod_phi_pp: Integer,
    e_mod_phi_qq: Integer,
    beta: Integer,
}

impl FactorizedExp for CrtExp {
    fn build(e: &Integer, p: &Integer, q: &Integer) -> Option<Self> {
        if e.cmp0().is_lt() || p.cmp0().is_le() || q.cmp0().is_le() {
            return None;
        }

        let pp = p.square_ref().complete();
        let qq = q.square_ref().complete();
        let e_mod_phi_pp = e % (&pp - p).complete();
        let e_mod_phi_qq = e % (&qq - q).complete();
        let beta = pp.invert_ref(&qq)?.into();
        Some(Self {
            e_mod_phi_pp,
            e_mod_phi_qq,
            pp,
            qq,
            beta,
        })
    }

    fn exp(&self, x: &Integer) -> Integer {
        let s1 = (x % &self.pp).complete();
        let s2 = (x % &self.qq).complete();

        // `e_mod_phi_pp` and `e_mod_phi_qq` are guaranteed to be non-negative by construction
        #[allow(clippy::expect_used)]
        let r1 = s1
            .pow_mod(&self.e_mod_phi_pp, &self.pp)
            .expect("exponent is guaranteed to be non-negative");
        #[allow(clippy::expect_used)]
        let r2 = s2
            .pow_mod(&self.e_mod_phi_qq, &self.qq)
            .expect("exponent is guaranteed to be non-negative");

        ((r2 - &r1) * &self.beta).modulo(&self.qq) * &self.pp + &r1
    }
}
