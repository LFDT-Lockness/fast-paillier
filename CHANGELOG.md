## v0.2.1
* Crate is now `#[no_std]` friendly as long as you enable `no_std` feature, and you use only
  these features: `backend-num-bigint`, `serde`. Enabling other features will intoduce transitive
  dependency on `std`.

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
