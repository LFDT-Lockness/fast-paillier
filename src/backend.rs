//! Big integer backend

mod rug;
#[allow(dead_code)]
mod num_bigint;

pub use rug::*;

/// Whether a number is prime. See [`Integer::is_probably_prime`] method
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Eq)]
pub enum IsPrime {
    No,
    Probably,
    Yes,
}
