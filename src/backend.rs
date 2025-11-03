//! Abstract big integer backend. This module makes no guarantees of
//! applicability, all methods are considered internal, except for conversion
//! functions:
//!
//! - [`Integer::to_bytes_lsf`]
//! - [`Integer::to_bytes_msf`]
//! - [`Integer::from_bytes_msf`]
//! - [`Integer::to_str_radix`]
//! - [`Integer::from_str_radix`]
//! - [`num_bigint::Integer::to_num_bigint`]
//! - [`num_bigint::Integer::from_num_bigint`]
//! - [`rug::Integer::to_rug`]
//! - [`rug::Integer::from_rug`]
//!
//! Likewise, the serde serialization format is also well-defined and stable,
//! even compatible with older versions of this library.
//!
//! To select a backend, use a feature flag:
//!
//! - `backend-num-bigint` (default) - use [`num-bigit`](https://docs.rs/num-bigint)
//! - `backend-rug` - use [`rug`](https://docs.rs/rug)
//!
//! When both features are enabled at once, num-bigint is used

pub(crate) mod macro_defs;

#[cfg(feature = "backend-num-bigint")]
pub mod num_bigint;
#[cfg(feature = "backend-rug")]
pub mod rug;
#[cfg(not(any(feature = "backend-num-bigint", feature = "backend-rug")))]
compile_error!(
    r#"A backend must be selected for fast-paillier: either set feature "backend-num-bigit" or "backend-rug""#
);

// num-bigint backend is used when both backends are turned on. This is useful
// for tests and benchmarks, as one could explicitly refer to the backends by
// the module name to compare their behaviour
#[cfg(feature = "backend-num-bigint")]
pub use num_bigint::*;
#[cfg(all(not(feature = "backend-num-bigint"), feature = "backend-rug"))]
pub use rug::*;

/// Whether a number is prime. See [`Integer::is_probably_prime`] method
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum IsPrime {
    No,
    Probably,
    Yes,
}

/// Sign of a number, to distinguish positives and zero from negatives
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Sign {
    /// Positive or zero
    NonNegative,
    Negative,
}

impl Integer {
    /// Checks that `self` is in Z<super>*</super><sub>n</sub>
    #[inline(always)]
    pub fn in_mult_group_of(&self, n: &Self) -> bool {
        self.cmp0().is_gt() && self < n && self.gcd_ref(n).is_one()
    }

    /// Checks that `abs(self)` is in Z<super>*</super><sub>n</sub>
    #[inline(always)]
    pub fn abs_in_mult_group_of(self: &Integer, n: &Integer) -> bool {
        self.cmp_abs(n).is_lt() && self.gcd_ref(n).is_one()
    }

    /// Samples `x` in Z*_n
    pub fn sample_in_mult_group_of(rng: &mut impl rand_core::RngCore, n: &Self) -> Self {
        let mut x = Integer::zero();
        loop {
            x.assign_random_below(n, rng);
            if x.in_mult_group_of(n) {
                return x;
            }
        }
    }

    /// Samples `x` such that abs(x) is in `Z*_n`
    pub fn sample_pm_in_mult_group_of(rng: &mut impl rand_core::RngCore, n: &Self) -> Self {
        let mut x = Integer::zero();
        let mut sign_buf = [0u8; 1];
        loop {
            x.assign_random_below(n, rng);
            rng.fill_bytes(&mut sign_buf);
            if sign_buf[0] & 1 == 1 {
                x = -x;
            }
            if x.abs_in_mult_group_of(n) {
                return x;
            }
        }
    }

    /// Generates a random safe prime
    pub fn generate_safe_prime(rng: &mut impl rand_core::RngCore, bits: u32) -> Self {
        sieve_generate_safe_primes(rng, bits, 135)
    }
}

/// Generate a random safe prime with a given sieve parameter.
///
/// For different bit sizes, different parameter value will give fastest
/// generation, the higher bit size - the higher the sieve parameter.
/// The best way to select the parameter is by trial. The one used by
/// [`generate_safe_prime`] is indistinguishable from optimal for 500-1700 bit
/// lengths.
pub fn sieve_generate_safe_primes(
    rng: &mut impl rand_core::RngCore,
    bits: u32,
    amount: usize,
) -> Integer {
    use crate::backend::IsPrime;
    use crate::utils::small_primes;

    let amount = amount.min(small_primes::SMALL_PRIMES.len());
    let mut x = Integer::zero();

    'trial: loop {
        // generate an odd number of length `bits - 2`
        x.assign_random_bits(bits - 1, rng);
        // `random_bits` is guaranteed to not set `bits-1`-th bit, but not
        // guaranteed to set the `bits-2`-th
        x.set_bit(bits - 2, true);
        x |= 1u32;

        for &small_prime in &small_primes::SMALL_PRIMES[0..amount] {
            let mod_result = x.mod_u(small_prime);
            if mod_result == (small_prime - 1) / 2 {
                continue 'trial;
            }
        }

        // 25 taken same as one used in mpz_nextprime
        if let IsPrime::Yes | IsPrime::Probably = x.is_probably_prime(25) {
            x <<= 1;
            x += 1;
            if let IsPrime::Yes | IsPrime::Probably = x.is_probably_prime(25) {
                return x;
            }
        }
    }
}

#[cfg(feature = "quickcheck")]
impl quickcheck::Arbitrary for Sign {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        if bool::arbitrary(g) {
            Sign::NonNegative
        } else {
            Sign::Negative
        }
    }
}

#[cfg(feature = "serde")]
mod serialize {
    /// Currently rug serializes the numbers into a format like
    /// ```json
    /// {
    ///   "radix": 16,
    ///   "value": "995d245c8ec97f55e23a1dff88684269b8678297f2659b4b02fde7db4128e9987e9838a93f6dba6591b14bae1a96145bab391214abad56e73ecebc67f37396c4813b2cd34aedb4b6bf532e452a1f43646b2bfe07a34ff791746941e27712d405128c929b416e036674dbe58abff1ae0dd886f9b5262c1bf477bab09fe06d167e0a4b05b5b80195baf77e51946b20408cc6f8d581db5bf0d32f93fd247c119347d4819730862141b315b9a14a9b01d3216013dd22e18cdcfbbae4c2af790dbbeb"
    /// }
    /// ```
    /// A number is represented as a dict with a radix and alphanumeric digits
    /// with most significant first. The radix is always 16. We keep our format
    /// compatible
    #[derive(serde::Serialize, serde::Deserialize)]
    struct DictFormat<'a> {
        radix: u16,
        value: std::borrow::Cow<'a, str>,
    }

    macro_rules! make_serde {
        ($integer:ty) => {
            impl serde::Serialize for $integer {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: serde::Serializer,
                {
                    let value = self.to_str_radix(16).into();
                    let dict = DictFormat { radix: 16, value };
                    dict.serialize(serializer)
                }
            }

            impl<'de> serde::Deserialize<'de> for $integer {
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    let dict = DictFormat::deserialize(deserializer)?;

                    <$integer>::from_str_radix(&dict.value, dict.radix)
                        .ok_or(serde::de::Error::custom("Invalid hex number"))
                }
            }
        };
    }

    #[cfg(feature = "backend-num-bigint")]
    make_serde!(super::num_bigint::Integer);
    #[cfg(feature = "backend-rug")]
    make_serde!(super::rug::Integer);

    #[cfg(test)]
    mod test {
        use crate::backend::Integer;

        #[cfg(feature = "backend-rug")]
        #[test]
        fn rug_compatible_deser_json() {
            let mut rng = rand_dev::DevRng::new();
            let num = crate::backend::rug::Integer::random_bits(128, &mut rng).to_rug();
            let num_s = serde_json::to_vec(&num).unwrap();
            let num_: Integer = serde_json::from_slice(&num_s).unwrap();

            assert_eq!(num.to_string(), num_.to_string());
        }

        #[cfg(feature = "backend-rug")]
        #[test]
        fn rug_compatible_ser_json() {
            let mut rng = rand_dev::DevRng::new();
            let num = Integer::random_bits(128, &mut rng);
            let num_s = serde_json::to_vec(&num).unwrap();
            let num_: rug::Integer = serde_json::from_slice(&num_s).unwrap();

            assert_eq!(num.to_string(), num_.to_string());
        }

        #[cfg(feature = "backend-rug")]
        #[test]
        fn rug_compatible_deser_cbor() {
            let mut rng = rand_dev::DevRng::new();
            let num = crate::backend::rug::Integer::random_bits(128, &mut rng).to_rug();
            let mut buf = Vec::new();
            ciborium::into_writer(&num, &mut buf).unwrap();
            let num_: Integer = ciborium::from_reader(buf.as_slice()).unwrap();

            assert_eq!(num.to_string(), num_.to_string());
        }

        #[cfg(feature = "backend-rug")]
        #[test]
        fn rug_compatible_ser_cbor() {
            let mut rng = rand_dev::DevRng::new();
            let num = Integer::random_bits(128, &mut rng);
            let mut buf = Vec::new();
            ciborium::into_writer(&num, &mut buf).unwrap();
            let num_: rug::Integer = ciborium::from_reader(buf.as_slice()).unwrap();

            assert_eq!(num.to_string(), num_.to_string());
        }

        #[test]
        fn decode_odd_length() {
            let json = r#"{"radix": 16, "value": "12345"}"#;
            let num: Integer = serde_json::from_str(json).unwrap();
            assert_eq!(num, Integer::from(0x12345));
        }

        #[test]
        fn decode_negative() {
            let json = r#"{"radix": 16, "value": "-ffffff"}"#;
            let num: Integer = serde_json::from_str(json).unwrap();
            assert_eq!(num, Integer::from(-0xffffff));
        }
    }
}

#[cfg(test)]
mod test {
    use super::Integer;

    #[test]
    fn safe_prime_size() {
        let mut rng = rand_dev::DevRng::new();
        for size in [500, 512, 513, 514] {
            let mut prime = Integer::generate_safe_prime(&mut rng, size);
            // rug doesn't have bit length operations, so
            prime >>= size - 1;
            assert_eq!(prime, Integer::one());
        }
    }

    #[test]
    fn mult_group_check() {
        let n = Integer::from(10);

        let mult_group = [1, 3, 7, 9].map(Integer::from);
        let not_mult_group = [0, 2, 4, 5, 6, 8, 10].map(Integer::from);

        for x in mult_group {
            assert!(x.in_mult_group_of(&n));
            assert!(x.abs_in_mult_group_of(&n));
            assert!((-x).abs_in_mult_group_of(&n));
        }
        for x in not_mult_group {
            assert!(!x.in_mult_group_of(&n));
            assert!(!x.abs_in_mult_group_of(&n));
            assert!(!(-x).abs_in_mult_group_of(&n));
        }
        for delta in 0..15_u32 {
            let x = &n + delta;
            assert!(!x.in_mult_group_of(&n));
            assert!(!x.abs_in_mult_group_of(&n));
            assert!(!(-x).abs_in_mult_group_of(&n));
        }
    }
}
