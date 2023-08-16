use rug::{Complete, Integer};

use crate::utils;

/// Paillier encryption can be faster if N=pq factorization is known
#[derive(Clone)]
pub struct EncryptWithKnownFactorization {
    n: Integer,
    nn: Integer,
    p: Integer,
    q: Integer,

    n_mod_phi_pp: Integer,
    n_mod_phi_qq: Integer,

    beta: Integer,
}

impl EncryptWithKnownFactorization {
    pub fn new(p: Integer, q: Integer) -> Option<Self> {
        let n = (&p * &q).complete();
        let nn = (&n * &n).complete();
        let pp = (&p * &p).complete();
        let qq = (&q * &q).complete();
        let n_mod_phi_pp = &n % (&pp - &p).complete();
        let n_mod_phi_qq = &n % (&qq - &q).complete();
        let beta = (pp % &qq).invert(&qq).unwrap();
        Some(Self {
            n,
            nn,
            n_mod_phi_pp,
            n_mod_phi_qq,
            beta,
            p,
            q,
        })
    }

    pub fn encrypt(&self, x: &Integer, nonce: &Integer) -> Integer {
        // a = (1 + N)^x mod N^2 = (1 + xN) mod N^2
        let mut a = (Integer::ONE + x * &self.n).complete() % &self.nn;
        // b = nonce^N mod N^2
        let b = utils::factorized_exp(
            nonce,
            &self.n_mod_phi_pp,
            &self.n_mod_phi_qq,
            &self.p,
            &self.q,
            &self.beta,
        );

        a *= b;
        a %= &self.nn;
        a
    }
}
