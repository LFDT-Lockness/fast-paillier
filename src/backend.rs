//! Big integer backend

#[allow(dead_code)]
mod num_bigint;
#[allow(dead_code)]
mod rug;

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
    /// Currently rug serializes the numbers into a format like
    /// ```json
    /// {
    ///   "radix": 16,
    ///   "value": "995d245c8ec97f55e23a1dff88684269b8678297f2659b4b02fde7db4128e9987e9838a93f6dba6591b14bae1a96145bab391214abad56e73ecebc67f37396c4813b2cd34aedb4b6bf532e452a1f43646b2bfe07a34ff791746941e27712d405128c929b416e036674dbe58abff1ae0dd886f9b5262c1bf477bab09fe06d167e0a4b05b5b80195baf77e51946b20408cc6f8d581db5bf0d32f93fd247c119347d4819730862141b315b9a14a9b01d3216013dd22e18cdcfbbae4c2af790dbbeb"
    /// }
    /// ```
    /// A number is represented as a dict with a radix and alphanumeric digits.
    /// The radix is always 16. We keep our format compatible
    #[derive(serde::Serialize, serde::Deserialize)]
    struct DictFormat<'a> {
        radix: usize,
        value: std::borrow::Cow<'a, str>,
    }

    impl serde::Serialize for super::Integer {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let bytes = self.to_bytes_msf();
            let value = hex::encode(bytes).into();
            let dict = DictFormat { radix: 16, value };
            dict.serialize(serializer)
        }
    }

    impl<'de> serde::Deserialize<'de> for super::Integer {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let dict = DictFormat::deserialize(deserializer)?;

            if dict.radix != 16 {
                return Err(serde::de::Error::custom(format!(
                    "unsupported radix: {}, only radix 16 is supported",
                    dict.radix
                )));
            }

            let value_ascii = dict.value.as_bytes();
            let positive = value_ascii[0] != b'-';
            let value_hex = if positive { value_ascii } else {&value_ascii[1..]};

            let bytes = if value_hex.len() % 2 == 1 {
                // hex crate can't handle odd length, so we decode the first
                // byte by hand
                let len = value_hex.len() / 2 + 1;
                let mut buf = Vec::with_capacity(len);
                buf.resize(len, 0);

                let first_byte_hex = [b'0', value_hex[0]];
                hex::decode_to_slice(&first_byte_hex, &mut buf[0..1])
                    .map_err(serde::de::Error::custom)?;

                // Decode the rest of the bytes
                hex::decode_to_slice(&value_hex[1..], &mut buf[1..])
                    .map_err(serde::de::Error::custom)?;
                buf
            } else {
                hex::decode(value_hex).map_err(|e| serde::de::Error::custom(e))?
            };
            let r = super::Integer::from_bytes_msf(&bytes);
            Ok(if positive { r } else { -r })
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
