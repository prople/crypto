//! `signature` module provides primary object of [`Signature`] which will be used
//! to generate a digital signature based on given message (in bytes)
use rst_common::with_cryptography::ed25519_dalek::{Signer, SigningKey};
use rst_common::with_cryptography::hex;

/// `Signature` is an object that consists of a raw message (in bytes) and also it's [`SigningKey`]
///
/// This object will be able to sign and encode the signature into `HEX` format
#[derive(Clone, Debug)]
pub struct Signature {
    message: Vec<u8>,
    key: SigningKey,
}

impl Signature {
    pub fn new(sign_key: SigningKey, message: Vec<u8>) -> Self {
        Self {
            message,
            key: sign_key,
        }
    }

    pub fn sign(&self) -> [u8; 64] {
        let signature = self.key.sign(self.message.as_slice());
        signature.to_bytes()
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.sign())
    }
}
