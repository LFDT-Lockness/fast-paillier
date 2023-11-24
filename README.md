# Optimized Paillier encryption scheme

Library implements Paillier encryption scheme with optimization such as:

* Faster encryption and homomorphic operations via Chinese Remainder Theorem when
  the private key is known
* Faster secret key generation (a.k.a faster safe primes generation)

Built on top of [`rug`](https://docs.rs/rug) big integers library (which is based on GMP).