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

#[cfg(feature = "serde")]
mod serialize {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct DictFormat<'a> {
        radix: usize,
        value: std::borrow::Cow<'a, str>,
    }

    impl serde::Serialize for super::Integer {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer
        {
            let bytes = self.to_bytes_msf();
            let value = hex::encode(bytes).into();
            let dict = DictFormat {
                radix: 16,
                value,
            };
            dict.serialize(serializer)
        }
    }

    impl<'de> serde::Deserialize<'de> for super::Integer {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>
        {
            let dict = DictFormat::deserialize(deserializer)?;

            if dict.radix != 16 {
                return Err(serde::de::Error::custom(format!(
                    "unsupported radix: {}, only radix 16 is supported",
                    dict.radix
                )));
            }

            let bytes = hex::decode(dict.value.as_bytes()).map_err(|e| serde::de::Error::custom(e))?;
            Ok(super::Integer::from_bytes_msf(&bytes))
        }
    }

    #[cfg(test)]
    mod test {
        use crate::backend::Integer;

        #[test]
        fn rug_compatible_deser_json() {
            let mut rng = rand_dev::DevRng::new();
            let mut rng = crate::backend::rug::external_rand(&mut rng);
            let num: rug::Integer = rug::Integer::random_bits(128, &mut rng).into();
            let num_s = serde_json::to_vec(&num).unwrap();
            let num_: Integer = serde_json::from_slice(&num_s).unwrap();

            assert_eq!(num.to_string(), num_.to_string());
        }

        #[test]
        fn rug_compatible_ser_json() {
            let mut rng = rand_dev::DevRng::new();
            let num = Integer::random_bits(128, &mut rng);
            let num_s = serde_json::to_vec(&num).unwrap();
            let num_: rug::Integer = serde_json::from_slice(&num_s).unwrap();

            assert_eq!(num.to_string(), num_.to_string());
        }

        #[test]
        fn rug_compatible_deser_cbor() {
            let mut rng = rand_dev::DevRng::new();
            let mut rng = crate::backend::rug::external_rand(&mut rng);
            let num: rug::Integer = rug::Integer::random_bits(128, &mut rng).into();
            let mut buf = Vec::new();
            ciborium::into_writer(&num, &mut buf).unwrap();
            let num_: Integer = ciborium::from_reader(buf.as_slice()).unwrap();

            assert_eq!(num.to_string(), num_.to_string());
        }

        #[test]
        fn rug_compatible_ser_cbor() {
            let mut rng = rand_dev::DevRng::new();
            let num = Integer::random_bits(128, &mut rng);
            let mut buf = Vec::new();
            ciborium::into_writer(&num, &mut buf).unwrap();
            let num_: rug::Integer = ciborium::from_reader(buf.as_slice()).unwrap();

            assert_eq!(num.to_string(), num_.to_string());
        }
    }
}
