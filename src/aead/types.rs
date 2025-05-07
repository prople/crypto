use rst_common::standard::bytes::Bytes;

use crate::errors::CommonError;
use crate::types::{BytesValue, Value, VectorValue};

pub struct Nonce(Vec<u8>);

impl From<Vec<u8>> for Nonce {
    fn from(value: Vec<u8>) -> Self {
        Nonce(value)
    }
}

impl VectorValue<u8> for Nonce {
    fn vec(&self) -> Vec<u8> {
        self.0.to_owned()
    }
}

pub struct MessagePlain(Vec<u8>);

impl From<Vec<u8>> for MessagePlain {
    fn from(value: Vec<u8>) -> Self {
        MessagePlain(value)
    }
}

impl From<String> for MessagePlain {
    fn from(value: String) -> Self {
        MessagePlain(value.as_bytes().to_vec())
    }
}

impl VectorValue<u8> for MessagePlain {
    fn vec(&self) -> Vec<u8> {
        self.0.to_owned()
    }
}

pub struct MessageCipher(Vec<u8>);

impl From<Vec<u8>> for MessageCipher {
    fn from(value: Vec<u8>) -> Self {
        MessageCipher(value)
    }
}

impl From<String> for MessageCipher {
    fn from(value: String) -> Self {
        MessageCipher(value.as_bytes().to_vec())
    }
}

impl VectorValue<u8> for MessageCipher {
    fn vec(&self) -> Vec<u8> {
        self.0.to_owned()
    }
}

#[derive(Clone, Debug)]
pub struct KeyEncryption([u8; 32]);

impl BytesValue for KeyEncryption {
    fn bytes(&self) -> Bytes {
        Bytes::from(self.0.to_vec())
    }
}

impl Value<[u8; 32]> for KeyEncryption {
    fn get(&self) -> Result<[u8; 32], CommonError> {
        let byte_slice = self.bytes().slice(0..32);
        let byte_output = &byte_slice[..];

        let output: Result<[u8; 32], CommonError> = <&[u8; 32]>::try_from(byte_output)
            .map(|val| val.to_owned())
            .map_err(|_| CommonError::ParseValueError("unable to parse bytes".to_string()));

        output
    }
}

impl TryFrom<Bytes> for KeyEncryption {
    type Error = CommonError;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        let mut val32 = Bytes::new();

        if value.len() < 32 || value.is_empty() {
            return Err(CommonError::ParseValueError(
                "invalid bytes length".to_string(),
            ));
        }

        if value.len() >= 32 {
            let val_slice = value.slice(0..32);
            val32 = Bytes::copy_from_slice(&val_slice);
        }

        let byte_slice = &val32[..];
        let bytes_output: Result<&[u8; 32], CommonError> = <&[u8; 32]>::try_from(byte_slice)
            .map_err(|_| CommonError::ParseValueError("unable to parse bytes".to_string()));

        bytes_output.map(|val| KeyEncryption(val.to_owned()))
    }
}

impl From<[u8; 32]> for KeyEncryption {
    fn from(value: [u8; 32]) -> Self {
        KeyEncryption(value)
    }
}

#[derive(Clone, Debug)]
pub struct KeyNonce([u8; 24]);

impl Value<[u8; 24]> for KeyNonce {
    fn get(&self) -> Result<[u8; 24], CommonError> {
        let byte_slice = self.bytes().slice(0..24);
        let byte_output = &byte_slice[..];

        let output: Result<[u8; 24], CommonError> = <&[u8; 24]>::try_from(byte_output)
            .map(|val| val.to_owned())
            .map_err(|_| CommonError::ParseValueError("unable to parse bytes".to_string()));

        output
    }
}

impl TryFrom<Bytes> for KeyNonce {
    type Error = CommonError;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        let mut val24 = Bytes::new();

        if value.len() < 24 || value.is_empty() {
            return Err(CommonError::ParseValueError(
                "mismatch bytes length".to_string(),
            ));
        }

        if value.len() >= 24 {
            let val_slice = value.slice(0..24);
            val24 = Bytes::copy_from_slice(&val_slice);
        }

        let byte_slice = &val24[..];
        let bytes_output: Result<&[u8; 24], CommonError> = <&[u8; 24]>::try_from(byte_slice)
            .map_err(|_| CommonError::ParseValueError("unable to parse bytes".to_string()));

        bytes_output.map(|val| KeyNonce(val.to_owned()))
    }
}

impl BytesValue for KeyNonce {
    fn bytes(&self) -> Bytes {
        Bytes::from(self.0.to_vec())
    }
}

impl From<[u8; 24]> for KeyNonce {
    fn from(value: [u8; 24]) -> Self {
        KeyNonce(value)
    }
}
