//! `pubkey` is a module that provides a [`PubKey`] data structure which will be used
//! to verify given digital signature
use rst_common::with_cryptography::ed25519_dalek::{
    Signature as EdDSASignature, Verifier, VerifyingKey,
};
use rst_common::with_cryptography::hex;

use crate::eddsa::types::errors::*;
use crate::eddsa::types::{EdDSAPubKeyBytes, EdDSASignatureBytes};

/// `PubKey` is an object that will serialize and encode the [`VerifyingKey`]
///
/// This key should be able used to validate the signature that made by it's private key
#[derive(Debug)]
pub struct PubKey {
    key: VerifyingKey,
}

impl PubKey {
    pub fn new(key: VerifyingKey) -> Self {
        Self { key }
    }

    pub fn serialize(&self) -> EdDSAPubKeyBytes {
        self.key.to_bytes()
    }

    pub fn to_hex(&self) -> String {
        let pub_byte = self.serialize();
        hex::encode(pub_byte)
    }

    pub fn from_hex(val: String) -> Result<Self, EddsaError> {
        let decoded = hex::decode(val)
            .map_err(|err| EddsaError::Common(CommonError::ParseHexError(err.to_string())))?;

        let try_to_pub_bytes: Result<EdDSAPubKeyBytes, _> = decoded.try_into();
        let pub_bytes = try_to_pub_bytes
            .map_err(|_| EddsaError::InvalidPubKeyError("error invalid public key".to_string()))?;

        VerifyingKey::from_bytes(&pub_bytes)
            .map(|val| Self { key: val })
            .map_err(|err| EddsaError::InvalidPubKeyError(err.to_string()))
    }

    pub fn verify(&self, message: &[u8], signature_hex: String) -> Result<bool, EddsaError> {
        let signature_decoded = hex::decode(signature_hex)
            .map_err(|err| EddsaError::Common(CommonError::ParseHexError(err.to_string())))?;

        let signature_decode_bytes: Result<EdDSASignatureBytes, _> = signature_decoded.try_into();
        let signature_decoded_bytes = signature_decode_bytes.map_err(|_| {
            EddsaError::InvalidSignatureError("error invalid signature".to_string())
        })?;

        let signature = EdDSASignature::from_bytes(&signature_decoded_bytes);
        self.key
            .verify(message, &signature)
            .map(|_| true)
            .map_err(|err| EddsaError::InvalidSignatureError(err.to_string()))
    }
}
