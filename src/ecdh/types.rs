//! `types` module provides base data types used at `ecdh` module

use rst_common::standard::bytes::Bytes;
use rst_common::with_cryptography::hex;

use crate::types::{ByteHex, BytesValue, Hexer, Value};

use errors::*;

pub mod errors {
    use rst_common::with_errors::thiserror::{self, Error};

    pub use crate::errors::CommonError;
    use crate::keysecure::types::errors::KeySecureError;

    /// `EcdhError` used specifically when manage public and private keys used
    /// through `ECDH` algorithm
    #[derive(Debug, Error, PartialEq)]
    pub enum EcdhError {
        #[error("ecdh: unable to parse public key: `{0}`")]
        ParsePublicKeyError(String),

        #[error("ecdh: unable to parse shared secret: `{0}`")]
        ParseSharedError(String),

        #[error("ecdh: unable to parse bytes: `{0}`")]
        ParseBytesError(String),

        #[error("ecdh: common error")]
        Common(#[from] CommonError),

        #[error("eddsa: keysecure error")]
        KeySecure(#[from] KeySecureError),
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct PublicKeyBytes([u8; 32]);

impl Value<[u8; 32]> for PublicKeyBytes {
    fn get(&self) -> Result<[u8; 32], CommonError> {
        let byte_slice = self.bytes().slice(0..32);
        let byte_output = &byte_slice[..];

        let output: Result<[u8; 32], CommonError> = <&[u8; 32]>::try_from(byte_output)
            .map(|val| val.to_owned())
            .map_err(|_| CommonError::ParseValueError("unable to parse bytes".to_string()));

        output
    }
}

impl TryFrom<ByteHex> for PublicKeyBytes {
    type Error = EcdhError;

    fn try_from(value: ByteHex) -> Result<Self, Self::Error> {
        let result = hex::decode(value.hex())
            .map_err(|err| EcdhError::Common(CommonError::ParseHexError(err.to_string())))?;

        let peer_pub_bytes: [u8; 32] = match result.try_into() {
            Ok(value) => value,
            Err(_) => {
                return Err(EcdhError::ParsePublicKeyError(
                    "unable to parse given public key".to_string(),
                ))
            }
        };

        Ok(PublicKeyBytes(peer_pub_bytes))
    }
}

impl BytesValue for PublicKeyBytes {
    fn bytes(&self) -> Bytes {
        Bytes::from(self.0.to_vec())
    }
}

impl From<[u8; 32]> for PublicKeyBytes {
    fn from(value: [u8; 32]) -> Self {
        PublicKeyBytes(value)
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct PrivateKeyBytes([u8; 32]);

impl Value<[u8; 32]> for PrivateKeyBytes {
    fn get(&self) -> Result<[u8; 32], CommonError> {
        let byte_slice = self.bytes().slice(0..32);
        let byte_output = &byte_slice[..];

        let output: Result<[u8; 32], CommonError> = <&[u8; 32]>::try_from(byte_output)
            .map(|val| val.to_owned())
            .map_err(|_| CommonError::ParseValueError("unable to parse bytes".to_string()));

        output
    }
}

impl BytesValue for PrivateKeyBytes {
    fn bytes(&self) -> Bytes {
        Bytes::from(self.0.to_vec())
    }
}

impl From<[u8; 32]> for PrivateKeyBytes {
    fn from(value: [u8; 32]) -> Self {
        PrivateKeyBytes(value)
    }
}
