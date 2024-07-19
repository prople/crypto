use rst_common::standard::bytes::Bytes;
use rst_common::with_cryptography::blake3::{self, Hash};
use rst_common::with_cryptography::ed25519_dalek::VerifyingKey;
use rst_common::with_cryptography::hex;
use rst_common::with_cryptography::x25519_dalek::{PublicKey as ECDHPublicKey, SharedSecret};

use super::errors::CommonError;

/// `Hexer` is a trait used for any value or data types that possible to encode it's
/// original value to the hex encoded format
pub trait Hexer {
    fn hex(&self) -> String;
}

pub trait Value<T> {
    fn get(&self) -> Result<T, CommonError>;
}

pub trait StringValue {
    fn get_string(&self) -> String;
}

/// `BytesValue` is a trait used to get common bytes array
/// The return value will be wrapped in [`Bytes`] container object to simplify
/// the bytes arrary process
pub trait BytesValue {
    fn bytes(&self) -> Bytes;
}

/// `VectorValue` is a trait used to get main vector value. It has a generic parameter used to
/// indicate a real data types will used inside the vector
pub trait VectorValue<T> {
    fn vec(&self) -> Vec<T>;
}

/// `ByteHex` is a new type that wrap the [`String`] which should be an output of encoded hex format
/// This *newtype* will able to generated from the [`SharedSecret`] and [`ECDHPublicKey`], and if there is
/// a common string value it also possible to generate from it
#[derive(PartialEq, Debug, Clone)]
pub struct ByteHex(String);

impl Hexer for ByteHex {
    fn hex(&self) -> String {
        self.0.to_owned()
    }
}

impl From<String> for ByteHex {
    fn from(value: String) -> Self {
        ByteHex(value)
    }
}

impl From<SharedSecret> for ByteHex {
    fn from(value: SharedSecret) -> Self {
        ByteHex::from(hex::encode(value.to_bytes()))
    }
}

impl From<ECDHPublicKey> for ByteHex {
    fn from(value: ECDHPublicKey) -> Self {
        ByteHex::from(hex::encode(value.to_bytes()))
    }
}

impl From<VerifyingKey> for ByteHex {
    fn from(value: VerifyingKey) -> Self {
        ByteHex::from(hex::encode(value.to_bytes()))
    }
}

/// `Blake3Hash` is a *newtype* used to wrap given [`blake3::Hash`] value type
/// This *newtype* will implement [`Hexer`] which means it's possible to get a hex encoded
/// format from the hash bytes value. It also possible to generate from vector of byte which
/// will automatically hash the given bytes array into hash
#[derive(PartialEq, Debug, Clone)]
pub struct Blake3Hash(Hash);

impl BytesValue for Blake3Hash {
    fn bytes(&self) -> Bytes {
        Bytes::from(self.0.as_bytes().to_vec())
    }
}

impl Hexer for Blake3Hash {
    fn hex(&self) -> String {
        hex::encode(self.0.as_bytes())
    }
}

impl From<Vec<u8>> for Blake3Hash {
    fn from(value: Vec<u8>) -> Self {
        let hashed = blake3::hash(value.as_slice());
        Blake3Hash(hashed)
    }
}
