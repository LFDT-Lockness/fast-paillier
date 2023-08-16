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
        if in_mult_group(&x, &n) {
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

/// Computes base^n mod (pq)^2
pub fn factorized_exp(
    base: &Integer,
    n_mod_phi_pp: &Integer,
    n_mod_phi_qq: &Integer,
    p: &Integer,
    q: &Integer,
    beta: &Integer,
) -> Integer {
    let qq = (q * q).complete();
    let pp = (p * p).complete();

    let x1 = n_mod_phi_pp;
    let x2 = n_mod_phi_qq;

    let s1 = base % (p * p).complete();
    let s2 = base % (q * q).complete();

    let r1 = s1.pow_mod(&x1, &pp).unwrap();
    let mut r2 = s2.pow_mod(&x2, &qq).unwrap();

    r2 -= &r1;
    while r2 < 0 {
        // TODO fuck
        r2 += &qq;
    }
    r2 *= beta;
    r2 %= qq;
    r2 *= pp;
    r2 += r1;
    r2
}
