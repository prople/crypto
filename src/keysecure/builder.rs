//! `builder` provides main object of [`Builder`] which will be used to generate
//! a [`KeySecure`] format based on some parameters
use rst_common::with_cryptography::hex;

use crate::keysecure::objects::{KdfParams as KeySecureKdfParams, KeySecureCrypto};
use crate::keysecure::types::errors::KeySecureError;
use crate::keysecure::types::ToKeySecure;
use crate::keysecure::KeySecure;

use crate::aead::{Key, AEAD};
use crate::passphrase::prelude::*;

/// `Builder` used to generate a [`KeySecure`] data structure based on some context
/// 
/// This object will depends on three important parameters:
/// - password
/// - context
/// - message
/// 
/// The `message` property will depends on it's context. If the context is `ED25519`
/// the given message will be generated `PEM` format from it's private key
/// 
/// If the context is `ECDH` or `X25519`, the given message will be hex-ed string value of
/// it's private key in bytes 
pub struct Builder {
    password: String,
    context: String,
}

impl Builder {
    pub fn new(context: String, password: String) -> Self {
        Self { password, context }
    }

    pub fn build(password: String, entity: impl ToKeySecure) -> Result<KeySecure, KeySecureError> {
        entity.to_keysecure(password)
    }

    pub fn secure(&self, message: String) -> Result<KeySecure, KeySecureError> {
        let passphrase_salt = Salt::generate();
        let passphrase_kdf_params = KdfParams::default();
        let passphrase = Passphrase::new(passphrase_kdf_params.clone());

        let password_hashed = passphrase
            .hash(self.password.clone(), passphrase_salt.clone())
            .map_err(|err| KeySecureError::BuildKeySecureError(err.to_string()))?;

        let aead_nonce = AEAD::nonce();
        let try_aead_nonce: Result<[u8; 24], _> = aead_nonce.try_into();
        let aead_nonce_value = try_aead_nonce.map_err(|_| {
            KeySecureError::BuildKeySecureError("unable to generate nonce".to_string())
        })?;

        let aead_key = Key::generate(password_hashed, aead_nonce_value);
        let ciphertext_pem =
            AEAD::encrypt(&aead_key, &message.as_bytes().to_vec()).map_err(|_| {
                KeySecureError::BuildKeySecureError("unable to encrypt given message".to_string())
            })?;

        let passphrase_salt_value = Salt::from_vec(passphrase_salt.clone())
            .map_err(|err| KeySecureError::BuildKeySecureError(err.to_string()))?;

        let keysecure_kdf_params =
            KeySecureKdfParams::new(passphrase_kdf_params.clone(), passphrase_salt_value);
        let keysecure_ciphertext = hex::encode(ciphertext_pem);
        let keysecure_nonce = hex::encode(aead_nonce_value);
        let keysecure_crypto =
            KeySecureCrypto::new(keysecure_nonce, keysecure_ciphertext, keysecure_kdf_params);
        let keysecure = KeySecure::new(self.context.to_string(), keysecure_crypto);

        Ok(keysecure)
    }
}
