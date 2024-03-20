//! `privkey` is a module that provides a primary object of [`PrivKey`]
use rst_common::with_cryptography::ed25519_dalek::pkcs8::EncodePrivateKey;
use rst_common::with_cryptography::ed25519_dalek::{self, SigningKey};

use crate::keysecure::types::constants::CONTEXT_ED25519;
use crate::keysecure::types::errors::KeySecureError;
use crate::keysecure::types::ToKeySecure;
use crate::keysecure::builder::Builder;
use crate::keysecure::KeySecure;

use crate::eddsa::types::errors::EddsaError;
use crate::eddsa::types::EdDSAPrivKeyBytes;

/// `PrivKey` is a private key generated from [`SigningKey`]
///
/// This object also able to serialize and encode the private key into `PEM` format
/// Once this object encoded into `PEM`, we also able to encrypt the data and generate [`KeySecure`]
/// object from it through trait [`ToKeySecure`].
#[derive(Debug, Clone)]
pub struct PrivKey {
    key: SigningKey,
}

impl PrivKey {
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }

    pub fn serialize(&self) -> EdDSAPrivKeyBytes {
        self.key.to_bytes()
    }

    pub fn to_pem(&self) -> Result<String, EddsaError> {
        self.key
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::default())
            .map(|val| val.to_string())
            .map_err(|err| EddsaError::EncodePemError(err.to_string()))
    }
}

impl ToKeySecure for PrivKey {
    fn to_keysecure(&self, password: String) -> Result<KeySecure, KeySecureError> {
        let pem = self
            .to_pem()
            .map_err(|err| KeySecureError::BuildKeySecureError(err.to_string()))?;

        let keysecure_builder = Builder::new(CONTEXT_ED25519.to_string(), password);
        let keysecure = keysecure_builder.secure(pem)?;

        Ok(keysecure)
    }
}
