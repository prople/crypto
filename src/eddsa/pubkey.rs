//! `pubkey` is a module that provides a [`PubKey`] data structure which will be used
//! to verify given digital signature
use rst_common::with_cryptography::ed25519_dalek::{
    Signature as EdDSASignature, Verifier, VerifyingKey,
};

use crate::eddsa::types::errors::*;
use crate::eddsa::types::{PublicKeyBytes, SignatureBytes};
use crate::types::{ByteHex, Value};

/// `PubKey` is an object that will serialize and encode the [`VerifyingKey`]
///
/// This key should be able used to validate the signature that made by it's private key
#[derive(Debug, Clone, PartialEq)]
pub struct PubKey {
    key: VerifyingKey,
}

impl PubKey {
    pub fn new(key: VerifyingKey) -> Self {
        Self { key }
    }

    pub fn serialize(&self) -> PublicKeyBytes {
        PublicKeyBytes::from(self.key.to_bytes())
    }

    pub fn to_hex(&self) -> ByteHex {
        ByteHex::from(self.key)
    }

    pub fn from_hex(val: ByteHex) -> Result<Self, EddsaError> {
        let pub_bytes = PublicKeyBytes::try_from(val)?;
        let pub_bytes_val = pub_bytes
            .get()
            .map_err(|err| EddsaError::ParsePublicKeyError(err.to_string()))?;

        VerifyingKey::from_bytes(&pub_bytes_val)
            .map(|val| Self { key: val })
            .map_err(|err| EddsaError::InvalidPubKeyError(err.to_string()))
    }

    pub fn verify(&self, message: &[u8], signature_hex: ByteHex) -> Result<bool, EddsaError> {
        let signature_bytes = SignatureBytes::try_from(signature_hex)?;
        let signature_bytes_val = signature_bytes
            .get()
            .map_err(|err| EddsaError::ParseSignatureError(err.to_string()))?;

        let signature = EdDSASignature::from_bytes(&signature_bytes_val);
        self.key
            .verify(message, &signature)
            .map(|_| true)
            .map_err(|err| EddsaError::InvalidSignatureError(err.to_string()))
    }
}
