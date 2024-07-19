//! `types` is a module that provides all base types used at `eddsa` module
use rst_common::standard::bytes::Bytes;
use rst_common::with_cryptography::ed25519_dalek::{
    PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
};
use rst_common::with_cryptography::hex;

pub mod errors {
    use rst_common::with_errors::thiserror::{self, Error};

    pub use crate::errors::CommonError;
    use crate::keysecure::types::errors::KeySecureError;
    use crate::passphrase::types::errors::PassphraseError;

    /// `EddsaError` used specifically when manage public and private keys through
    /// `Eddsa` algorithm
    #[derive(Debug, Error, PartialEq)]
    pub enum EddsaError {
        #[error("eddsa: unable to parse signature: `{0}`")]
        ParseSignatureError(String),

        #[error("eddsa: unable to encode pem: `{0}`")]
        EncodePemError(String),

        #[error("eddsa: unable to decode pem: `{0}`")]
        DecodePemError(String),

        #[error("eddsa: invalid given signature: `{0}`")]
        InvalidSignatureError(String),

        #[error("eddsa: invalid given public key: `{0}`")]
        InvalidPubKeyError(String),

        #[error("eddsa: unable to parse public key: `{0}`")]
        ParsePublicKeyError(String),

        #[error("eddsa: common error")]
        Common(#[from] CommonError),

        #[error("eddsa: keysecure error")]
        KeySecure(#[from] KeySecureError),

        #[error("eddsa: passphrase error")]
        Passphrase(#[from] PassphraseError),
    }
}

use crate::types::{ByteHex, BytesValue, Hexer, Value};
use errors::{CommonError, EddsaError};

#[derive(PartialEq, Debug, Clone)]
pub struct PublicKeyBytes([u8; PUBLIC_KEY_LENGTH]);

impl Value<[u8; PUBLIC_KEY_LENGTH]> for PublicKeyBytes {
    fn get(&self) -> Result<[u8; PUBLIC_KEY_LENGTH], CommonError> {
        let byte_slice = self.bytes().slice(0..PUBLIC_KEY_LENGTH);
        let byte_output = &byte_slice[..];

        let output: Result<[u8; PUBLIC_KEY_LENGTH], CommonError> =
            <&[u8; PUBLIC_KEY_LENGTH]>::try_from(byte_output)
                .map(|val| val.to_owned())
                .map_err(|_| CommonError::ParseValueError("unable to parse bytes".to_string()));

        output
    }
}

impl TryFrom<ByteHex> for PublicKeyBytes {
    type Error = EddsaError;

    fn try_from(value: ByteHex) -> Result<Self, Self::Error> {
        let result = hex::decode(value.hex())
            .map_err(|err| EddsaError::Common(CommonError::ParseHexError(err.to_string())))?;

        let peer_pub_bytes: [u8; PUBLIC_KEY_LENGTH] = match result.try_into() {
            Ok(value) => value,
            Err(_) => {
                return Err(EddsaError::ParsePublicKeyError(
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

impl From<[u8; PUBLIC_KEY_LENGTH]> for PublicKeyBytes {
    fn from(value: [u8; PUBLIC_KEY_LENGTH]) -> Self {
        PublicKeyBytes(value)
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct PrivateKeyBytes([u8; SECRET_KEY_LENGTH]);

impl Value<[u8; PUBLIC_KEY_LENGTH]> for PrivateKeyBytes {
    fn get(&self) -> Result<[u8; SECRET_KEY_LENGTH], CommonError> {
        let byte_slice = self.bytes().slice(0..SECRET_KEY_LENGTH);
        let byte_output = &byte_slice[..];

        let output: Result<[u8; SECRET_KEY_LENGTH], CommonError> =
            <&[u8; SECRET_KEY_LENGTH]>::try_from(byte_output)
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

impl From<[u8; SECRET_KEY_LENGTH]> for PrivateKeyBytes {
    fn from(value: [u8; SECRET_KEY_LENGTH]) -> Self {
        PrivateKeyBytes(value)
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct SignatureBytes([u8; SIGNATURE_LENGTH]);

impl Value<[u8; SIGNATURE_LENGTH]> for SignatureBytes {
    fn get(&self) -> Result<[u8; SIGNATURE_LENGTH], CommonError> {
        let byte_slice = self.bytes().slice(0..SIGNATURE_LENGTH);
        let byte_output = &byte_slice[..];

        let output: Result<[u8; SIGNATURE_LENGTH], CommonError> =
            <&[u8; SIGNATURE_LENGTH]>::try_from(byte_output)
                .map(|val| val.to_owned())
                .map_err(|_| CommonError::ParseValueError("unable to parse bytes".to_string()));

        output
    }
}

impl TryFrom<ByteHex> for SignatureBytes {
    type Error = EddsaError;

    fn try_from(value: ByteHex) -> Result<Self, Self::Error> {
        let result = hex::decode(value.hex())
            .map_err(|err| EddsaError::Common(CommonError::ParseHexError(err.to_string())))?;

        let peer_sig_bytes: [u8; SIGNATURE_LENGTH] = match result.try_into() {
            Ok(value) => value,
            Err(_) => {
                return Err(EddsaError::ParsePublicKeyError(
                    "unable to parse given public key".to_string(),
                ))
            }
        };

        Ok(SignatureBytes(peer_sig_bytes))
    }
}

impl BytesValue for SignatureBytes {
    fn bytes(&self) -> Bytes {
        Bytes::from(self.0.to_vec())
    }
}

impl From<[u8; SIGNATURE_LENGTH]> for SignatureBytes {
    fn from(value: [u8; SIGNATURE_LENGTH]) -> Self {
        SignatureBytes(value)
    }
}
