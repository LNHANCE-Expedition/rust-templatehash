//! Tests TEMPLATEHASH test vectors from BIP-???

#![cfg(feature = "serde")]

use bitcoin::Transaction;

use serde::{de::Expected, de::Visitor, Deserialize, Deserializer};

use std::u8;

use templatehash::{TemplateHash, ToTemplateHash};

struct HexVecVisitor;

struct ExpectedLen;

impl Expected for ExpectedLen {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("even number of hex bytes")
    }
}

impl<'de> Visitor<'de> for HexVecVisitor {
    type Value = Option<Vec<u8>>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("hex string")
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        let s: String = Deserialize::deserialize(deserializer)?;

        if s.len() % 2 != 0 {
            return Err(serde::de::Error::invalid_length(s.len(), &ExpectedLen));
        }

        let mut result = Vec::new();

        let mut i = 0;
        while i < s.len() {
            let byte = u8::from_str_radix(&s[i..i + 2], 16).map_err(serde::de::Error::custom)?;
            result.push(byte);
            i += 2;
        }

        Ok(Some(result))
    }
}

fn deserialize_hex_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<u8>>, D::Error> {
    deserializer.deserialize_option(HexVecVisitor)
}

#[derive(Debug, Deserialize)]
struct TestVector {
    #[serde(
        rename = "tx",
        with = "bitcoin::consensus::serde::With::<bitcoin::consensus::serde::Hex>"
    )]
    transaction: Transaction,

    input_index: u32,

    templatehash: TemplateHash,

    #[serde(default)]
    #[serde(deserialize_with = "deserialize_hex_bytes")]
    annex: Option<Vec<u8>>,

    #[allow(dead_code)]
    comment: String,
}

#[test]
fn test_templatehash() {
    let test_vectors: Vec<TestVector> =
        serde_json::from_str(include_str!("data/templatehash.json"))
            .expect("failed to parse test vectors");

    for test_vector in test_vectors {
        let computed_templatehash = test_vector
            .transaction
            .to_templatehash(test_vector.input_index, test_vector.annex.as_deref());

        assert_eq!(computed_templatehash, test_vector.templatehash);
    }
}
