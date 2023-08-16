use rand_core::{CryptoRng, RngCore};
use rug::{Complete, Integer};

use crate::utils::IntegerExt;
use crate::{utils, Ciphertext, EncryptionKey, Nonce, Plaintext};
use crate::{Bug, Error, Reason};

#[derive(Clone)]
pub struct DecryptionKey<FastExp = utils::CrtExp> {
    ek: EncryptionKey,
    /// `lcm(p-1, q-1)`
    lambda: Integer,
    /// `L((N + 1)^lambda mod N^2)-1 mod N`
    u: Integer,

    p: Integer,
    q: Integer,

    /// Calculates `x ^ N mod N^2`. It's used for faster encryption
    exp_to_n_mod_nn: FastExp,
    /// Calculates `x ^ lambda mod N^2`. It's used for faster decryption
    exp_to_lambda_mod_nn: FastExp,
}

impl<FastExp: utils::FactorizedExp> DecryptionKey<FastExp> {
    /// Generates a paillier key
    ///
    /// Samples two safe 1536-bits primes that meets 128 bits security level
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Result<Self, Error> {
        let p = utils::generate_safe_prime(rng, 1536);
        let q = utils::generate_safe_prime(rng, 1536);
        Self::from_primes(p, q)
    }

    /// Constructs a paillier key from primes `p`, `q`
    ///
    /// `p` and `q` need to be safe primes sufficiently large to meet security level requirements.
    ///
    /// Returns error if `p` and `q` do not correspond to a valid paillier key.
    #[allow(clippy::many_single_char_names)]
    pub fn from_primes(p: Integer, q: Integer) -> Result<Self, Error> {
        // Paillier doesn't work if p == q
        if p == q {
            return Err(Reason::InvalidPQ.into());
        }
        let pm1 = Integer::from(&p - 1);
        let qm1 = Integer::from(&q - 1);
        let ek = EncryptionKey::from_n((&p * &q).complete());
        let lambda = pm1.clone().lcm(&qm1);
        if lambda.cmp0().is_eq() {
            return Err(Reason::InvalidPQ.into());
        }

        // (N+1)^lambda mod N^2
        let t = Integer::from(ek.n() + 1);
        let tt = t
            .clone()
            .pow_mod(&lambda, ek.nn())
            .map_err(|_| Bug::PowModUndef)?;

        // L((N+1)^lambda mod N^2)^-1 mod N
        let u = ek
            .l(&tt)
            .ok_or(Reason::InvalidPQ)?
            .invert(ek.n())
            .map_err(|_| Reason::InvalidPQ)?;

        let exp_to_n_mod_nn = FastExp::build(ek.n(), &p, &q).ok_or(Reason::BuildFastExp)?;
        let exp_to_lambda_mod_nn = FastExp::build(&lambda, &p, &q).ok_or(Reason::BuildFastExp)?;

        Ok(Self {
            ek,
            lambda,
            u,
            p,
            q,
            exp_to_n_mod_nn,
            exp_to_lambda_mod_nn,
        })
    }

    /// Decrypts the ciphertext, returns plaintext in `{-N/2, .., N_2}`
    pub fn decrypt(&self, c: &Ciphertext) -> Result<Plaintext, Error> {
        if !utils::in_mult_group(&c, &self.ek.nn()) {
            return Err(Reason::Decrypt.into());
        }

        // a = c^\lambda mod n^2
        let a = self.exp_to_lambda_mod_nn.exp(c);

        // ell = L(a, N)
        let l = self.ek.l(&a).ok_or(Reason::Decrypt)?;

        // m = lu = L(a)*u = L(c^\lamba*)u mod n
        let plaintext = (l * &self.u) % self.ek.n();

        if Integer::from(&plaintext << 1) >= *self.n() {
            Ok(plaintext - self.n())
        } else {
            Ok(plaintext)
        }
    }

    /// Encrypts a plaintext `x` in `{-N/2, .., N/2}` with `nonce` from `Z*_n`
    ///
    /// It uses the fact that factorization of `N` is known to speed up encryption.
    ///
    /// Returns error if inputs are not in specified range
    pub fn encrypt_with(&self, x: &Plaintext, nonce: &Nonce) -> Result<Ciphertext, Error> {
        if !self.ek.in_signed_group(x) || !utils::in_mult_group(nonce, self.n()) {
            return Err(Reason::Encrypt.into());
        }

        let x = if x.cmp0().is_ge() {
            x.clone()
        } else {
            (x + self.n()).complete()
        };

        // a = (1 + N)^x mod N^2 = (1 + xN) mod N^2
        let a = (Integer::ONE + x * self.ek.n()) % self.ek.nn();
        // b = nonce^N mod N^2
        let b = self.exp_to_n_mod_nn.exp(nonce);

        Ok((a * b) % self.ek.nn())
    }

    /// Encrypts the plaintext `x` in `{-N/2, .., N_2}`
    ///
    /// It's uses the fact that factorization of `N` is known to speed up encryption.
    ///
    /// Nonce is sampled randomly using `rng`.
    ///
    /// Returns error if plaintext is not in specified range
    pub fn encrypt_with_random(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        x: &Plaintext,
    ) -> Result<(Ciphertext, Nonce), Error> {
        let nonce = utils::sample_in_mult_group(rng, self.ek.n());
        let ciphertext = self.encrypt_with(x, &nonce)?;
        Ok((ciphertext, nonce))
    }

    /// Returns a (public) encryption key corresponding to the (secret) decryption key
    pub fn encryption_key(&self) -> EncryptionKey {
        self.ek.clone()
    }

    /// The Paillier modulus
    pub fn n(&self) -> &Integer {
        self.ek.n()
    }

    /// The Paillier `lambda`
    pub fn lambda(&self) -> &Integer {
        &self.lambda
    }

    /// The Paillier `u`
    pub fn u(&self) -> &Integer {
        &self.u
    }

    /// Prime `p`
    pub fn p(&self) -> &Integer {
        &self.p
    }
    /// Prime `q`
    pub fn q(&self) -> &Integer {
        &self.q
    }

    /// Bits length of smaller prime (`p` or `q`)
    pub fn bits_length(&self) -> u32 {
        self.p.significant_bits().min(self.q.significant_bits())
    }
}
