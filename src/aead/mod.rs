//! `aead` is a module used to maintain the primary object of `AEAD (Authenticated Encryption with Associated Data`
//!
//! This module provides an abstraction to maintain `AEAD` on top of `aead` from `RustCrypto/traits` repository
use rst_common::with_cryptography::chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    XChaCha20Poly1305,
};

use rst_common::with_cryptography::rand::{rngs::adapter::ReseedingRng, SeedableRng};
use rst_common::with_cryptography::rand_chacha::{rand_core::OsRng as RandCoreOsRng, ChaCha20Core};

mod key;
pub use key::Key;

mod types;
pub use types::{KeyEncryption, KeyNonce, MessageCipher, MessagePlain, Nonce};

use crate::{passphrase::prelude::errors::CommonError, types::VectorValue};

pub mod errors {
    use rst_common::with_errors::thiserror::{self, Error};

    /// `AeadError` used specifically when manage cipher management
    /// specifically `AEAD`
    #[derive(Debug, Error)]
    pub enum AeadError {
        #[error("aead: unable to parse bytes: `{0}`")]
        CipherGeneratorError(String),
    }
}

/// `AEAD` is a main entrypoint to encrypt and decrypt the given data (in bytes), and also
/// generate nonce (in bytes)
pub struct AEAD;

impl AEAD {
    pub fn nonce() -> Nonce {
        let prng = ChaCha20Core::from_entropy();
        let reseeding_rng = ReseedingRng::new(prng, 0, RandCoreOsRng);
        let nonce = XChaCha20Poly1305::generate_nonce(reseeding_rng);
        Nonce::from(nonce.to_vec())
    }

    pub fn encrypt(key: &Key, message: &MessagePlain) -> Result<MessageCipher, errors::AeadError> {
        let (key_bytes, nonce_bytes) = AEAD::key_extractor(key)
            .map_err(|err| errors::AeadError::CipherGeneratorError(err.to_string()))?;

        let cipher = XChaCha20Poly1305::new(&key_bytes.into());
        cipher
            .encrypt(&nonce_bytes.into(), message.vec().as_slice())
            .map(MessageCipher::from)
            .map_err(|err| errors::AeadError::CipherGeneratorError(err.to_string()))
    }

    pub fn decrypt(
        key: &Key,
        encrypted: &MessageCipher,
    ) -> Result<MessagePlain, errors::AeadError> {
        let (key_bytes, nonce_bytes) = AEAD::key_extractor(key)
            .map_err(|err| errors::AeadError::CipherGeneratorError(err.to_string()))?;

        let cipher = XChaCha20Poly1305::new(&key_bytes.into());
        cipher
            .decrypt(&nonce_bytes.into(), encrypted.vec().as_ref())
            .map(MessagePlain::from)
            .map_err(|err| errors::AeadError::CipherGeneratorError(err.to_string()))
    }

    fn key_extractor(key: &Key) -> Result<([u8; 32], [u8; 24]), CommonError> {
        let nonce_bytes = key.get_nonce_bytes()?;
        let key_bytes = key.get_key_bytes()?;

        Ok((key_bytes, nonce_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ecdh::keypair::KeyPair, types::BytesValue};

    #[test]
    fn test_nonce() {
        let nonce = AEAD::nonce();
        let nonce_value: Result<[u8; 24], _> = nonce.vec().try_into();
        assert!(!nonce_value.is_err())
    }

    #[test]
    fn test_encrypt_decrypt() {
        let keypair_alice = KeyPair::generate();
        let keypair_bob = KeyPair::generate();

        let pubkey_bob = keypair_bob.pub_key();
        let public_bob_hex = pubkey_bob.to_hex();

        let secret_alice = keypair_alice.secret(public_bob_hex);
        let shared_secret_alice_blake3 = secret_alice.to_blake3();

        let nonce = AEAD::nonce();
        let nonce_value: Result<[u8; 24], _> = nonce.vec().try_into();

        let alice_key = shared_secret_alice_blake3.unwrap();
        let alice_key_bytes = alice_key.bytes();

        let alice_key_encryption_builder = KeyEncryption::try_from(alice_key_bytes);
        assert!(!alice_key_encryption_builder.is_err());

        let key = Key::new(
            alice_key_encryption_builder.as_ref().unwrap().to_owned(),
            KeyNonce::from(nonce_value.unwrap()),
        );

        let message = String::from("plaintext");
        let encrypted = AEAD::encrypt(&key, &MessagePlain::from(message.clone()));
        assert!(!encrypted.is_err());

        let encrypted_str = encrypted.unwrap();
        let decrypted = AEAD::decrypt(&key, &encrypted_str);
        assert!(!decrypted.is_err());

        let decrypted_value = decrypted.unwrap();
        let result = String::from_utf8(decrypted_value.vec());
        assert!(!result.is_err());
        assert_eq!(result.unwrap(), message);
        assert_eq!(decrypted_value.vec(), message.clone().as_bytes().to_vec());

        let nonce_missed = AEAD::nonce();
        let nonce_missed_value: Result<[u8; 24], _> = nonce_missed.vec().try_into();

        let key_invalid = Key::new(
            alice_key_encryption_builder.unwrap(),
            KeyNonce::from(nonce_missed_value.unwrap()),
        );
        let encrypted2 = AEAD::encrypt(&key, &MessagePlain::from(message));
        let decrypted_unmatched = AEAD::decrypt(&key_invalid, &encrypted2.unwrap());

        assert!(decrypted_unmatched.is_err());
        assert!(matches!(
            decrypted_unmatched,
            Err(errors::AeadError::CipherGeneratorError(_))
        ))
    }
}
