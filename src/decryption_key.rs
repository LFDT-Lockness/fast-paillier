use rand_core::{CryptoRng, RngCore};
use rug::{Complete, Integer};

use crate::utils::IntegerExt;
use crate::{utils, Ciphertext, EncryptionKey, Nonce, Plaintext};
use crate::{Bug, Error, Reason};

mod faster_encryption;

#[derive(Clone)]
pub struct DecryptionKey {
    ek: EncryptionKey,
    /// `lcm(p, q)`
    lambda: Integer,
    /// `(p - 1)(q - 1)`
    totient: Integer,
    /// `L((N + 1)^lambda mod N^2)-1 mod N`
    u: Integer,

    lambda_mod_phi_pp: Integer,
    lambda_mod_phi_qq: Integer,
    beta: Integer,

    p: Integer,
    q: Integer,

    faster_encryption: faster_encryption::EncryptWithKnownFactorization,
}

impl DecryptionKey {
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
        let totient = (&pm1 * &qm1).complete();

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

        let pp = (&p * &p).complete();
        let qq = (&q * &q).complete();
        let lambda_mod_phi_pp = &lambda % (&pp - &p).complete();
        let lambda_mod_phi_qq = &lambda % (&qq - &q).complete();
        let beta = (pp % &qq).invert(&qq).unwrap();

        let faster_encryption =
            faster_encryption::EncryptWithKnownFactorization::new(p.clone(), q.clone())
                .ok_or(Bug::NewFasterEncrypt)?;

        Ok(Self {
            ek,
            lambda,
            totient,
            u,
            p,
            q,
            lambda_mod_phi_pp,
            lambda_mod_phi_qq,
            beta,
            faster_encryption,
        })
    }

    /// Decrypts the ciphertext, returns plaintext in `[-N/2; N_2)`
    pub fn decrypt(&self, c: &Ciphertext) -> Result<Plaintext, Error> {
        if !utils::in_mult_group(&c, &self.ek.nn()) {
            return Err(Reason::Decrypt.into());
        }

        // a = c^\lambda mod n^2
        let a = utils::factorized_exp(
            c,
            &self.lambda_mod_phi_pp,
            &self.lambda_mod_phi_qq,
            &self.p,
            &self.q,
            &self.beta,
        );

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

    #[inline(always)]
    pub fn encrypt_with(&self, x: &Plaintext, nonce: &Nonce) -> Result<Ciphertext, Error> {
        if !self.ek.in_signed_group(x) || !utils::in_mult_group(nonce, self.n()) {
            return Err(Reason::Encrypt.into());
        }

        let x = x.modulo(self.n());
        Ok(self.faster_encryption.encrypt(&x, nonce))
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

    /// The Paillier `totient`
    pub fn totient(&self) -> &Integer {
        &self.totient
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
