![License](https://img.shields.io/crates/l/fast-paillier.svg)
[![Docs](https://docs.rs/fast-paillier/badge.svg)](https://docs.rs/fast-paillier)
[![Crates io](https://img.shields.io/crates/v/fast-paillier.svg)](https://crates.io/crates/fast-paillier)

# Optimized Paillier encryption scheme

Library implements Paillier encryption scheme with optimization such as:

* Faster encryption and homomorphic operations via Chinese Remainder Theorem when
  the private key is known
* Faster secret key generation (a.k.a faster safe primes generation)

Built on top of [`rug`](https://docs.rs/rug) big integers library (which is based on GMP).