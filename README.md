![License](https://img.shields.io/crates/l/fast-paillier.svg)
[![Docs](https://docs.rs/fast-paillier/badge.svg)](https://docs.rs/fast-paillier)
[![Crates io](https://img.shields.io/crates/v/fast-paillier.svg)](https://crates.io/crates/fast-paillier)
[![Discord](https://img.shields.io/discord/905194001349627914?logo=discord&logoColor=ffffff&label=Discord)][in Discord]

# Optimized Paillier encryption scheme

Library implements Paillier encryption scheme with optimization such as:

* Faster encryption and homomorphic operations via Chinese Remainder Theorem when
  the private key is known
* Faster secret key generation (a.k.a faster safe primes generation)

## Big integer backend

This crate uses an abstraction over the big integer implementation, available in `backend` module. The concrete backend can be selected with a feature flag:

- `backend-num-bigint` (default) - use [`num-bigit`](https://docs.rs/num-bigint)
- `backend-rug` - use [`rug`](https://docs.rs/rug). This backend is based on GNU GMP and can be several times faster.

The applicability of this backend to your uses is not guaranteed, any
additional functionality to it will not be added. However, you can convert them
to bytes or, if using a fixed backend, to the underlying format, and perform
the necessary operations with those.

## Join us in Discord!
Feel free to reach out to us [in Discord]!

[in Discord]: https://discordapp.com/channels/905194001349627914/1285268686147424388
