## v0.3.3
* Unify encoding of integer=0 across backends [#45]
* Deserialize returns an error on invalid radix, instead of panicking [#45]
* Use `crypto-primes` for primality test instead of `glass_pumpkin` on num-bigint backend [#46]
* Fix divergent behavior on different integer backends. [#49] \
  **Possibly breaking** if your program was relying on following behavior:
  * `Integer::from_str_radix(s, radix)` requires that `s` is composed of optional leading single
    sign (`+` or `-`) and followed by ASCII alphanum characters
    * `num-bigint` backend used to allow underscore characters `_` in integer encoding, which now
      lead to a parsing error
    * `rug` backend used to allow whitspace characters (` `, `\t`, `\n`) in integer encoding,
      which is no longer accepted as well.
  * `num-bigint` backend used to panic when called `invert`, `pow_mod`, or `combine` with
    `modulo=0`. Now it returns `None` in these cases (which is aligned with `rug` backend)
  * `Integer::random_below`, `random_below_ref`, and `assign_random_below` panic if upper bound
    is `<= 0` (there are no number to sample the integer from). `rug` already panicked in those
    cases, while `num-bigint` ignored this condition, and simply ignored the sign of the input.
  * `jacobi` panics when invalid `n` is provided. Both backend behaved differently: `rug` used to
    return some integer, while `num-bigint` used to return `0` in release and panic in debug build
  * `num_bigint` integer used to panic in `x << shift` (or `>>`) when the `shift` was negative. Now
    it reverses the shift direction, like `rug` does: e.g. `x << -3` becomes `x >> 3`
  * Safe prime generation panics if asked to generate a prime of bit length `< 100`, as sampling
    small primes is not supported by the algorithm. Note that cryptographic primes need to be way
    larger. E.g. RSA requires primes to be at least 1536-bits.
  * Prime generation panics if asked to generate a prime of bit length `< 2` (there are no primes
    of that bitsize). Previously, function would panic or hang in infinite loop.
  * `sample[_pm]_in_mult_group_of` now panics if provided `n < 2`. Previously, `n=0` would panic or
    hang (depending on the backend), and `n=1` would hang in infinite loop

[#45]: https://github.com/LFDT-Lockness/fast-paillier/pull/45
[#46]: https://github.com/LFDT-Lockness/fast-paillier/pull/46
[#49]: https://github.com/LFDT-Lockness/fast-paillier/pull/49

## v0.3.2
* Make `random_below`, `random_below_ref`, `random_bits`, `random_bits_signed`,
  `assign_random_below`, `assign_random_bits` methods for both backends
  generate the same numbers [#22]

[#22]: https://github.com/LFDT-Lockness/fast-paillier/pull/22

## v0.3.1
* Improve implementation of `num_bigint::Integer::significant_dwords` [#21]

See [#21](https://github.com/LFDT-Lockness/fast-paillier/pull/21)

## v0.3.0
* Crate is now `#[no_std]` friendly as long as you enable `no_std` feature, and you use only
  these features: `backend-num-bigint`, `serde`. Enabling other features will introduce transitive
  dependency on `std`.
* Breaking change in Integer API in a part where we do not offer any stability

See [#20](https://github.com/LFDT-Lockness/fast-paillier/pull/20)

## v0.2.0
* Change big integer backend to be abstract, selectable between rug and num-bigint [#18]

[#18]: https://github.com/LFDT-Lockness/fast-paillier/pull/18

## v0.1.1
* `utils::{in_mult_group, in_mult_group_abs}`: rejects `x` such that `abs(x) >= n` as they do
  not belong to the multiplicative group [#16]
* Update links in crate settings, update readme [#12]

[#12]: https://github.com/LFDT-Lockness/fast-paillier/pull/12
[#16]: https://github.com/LFDT-Lockness/fast-paillier/pull/16

## v0.1.0

First release!
