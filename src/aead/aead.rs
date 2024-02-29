use rst_common::with_cryptography::chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    XChaCha20Poly1305,
};

use rst_common::with_cryptography::rand::{rngs::adapter::ReseedingRng, SeedableRng};
use rst_common::with_cryptography::rand_chacha::{rand_core::OsRng as RandCoreOsRng, ChaCha20Core};

use crate::errors::AeadError;

pub struct Key {
    pub key: [u8; 32],
    pub nonce: [u8; 24],
}

impl Key {
    pub fn generate(key: [u8; 32], nonce: [u8; 24]) -> Self {
        Self { key, nonce }
    }
}

pub struct AEAD;

impl AEAD {
    pub fn nonce() -> Vec<u8> {
        let prng = ChaCha20Core::from_entropy();
        let reseeding_rng = ReseedingRng::new(prng, 0, RandCoreOsRng);
        let nonce = XChaCha20Poly1305::generate_nonce(reseeding_rng);
        nonce.to_vec()
    }

    pub fn encrypt(key: &Key, message: &Vec<u8>) -> Result<Vec<u8>, AeadError> {
        let cipher = XChaCha20Poly1305::new(&key.key.into());
        cipher
            .encrypt(&key.nonce.into(), message.as_slice())
            .map_err(|err| AeadError::CipherGeneratorError(err.to_string()))
    }

    pub fn decrypt(key: &Key, encrypted: &Vec<u8>) -> Result<Vec<u8>, AeadError> {
        let cipher = XChaCha20Poly1305::new(&key.key.into());
        cipher
            .decrypt(&key.nonce.into(), encrypted.as_ref())
            .map_err(|err| AeadError::CipherGeneratorError(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ECDH::KeyPair;

    #[test]
    fn test_nonce() {
        let nonce = AEAD::nonce();
        let nonce_value: Result<[u8; 24], _> = nonce.try_into();
        assert!(!nonce_value.is_err())
    }

    #[test]
    fn test_encrypt_decrypt() {
        let keypair_alice = KeyPair::generate();
        let keypair_bob = KeyPair::generate();

        let pubkey_bob = keypair_bob.pub_key();
        let public_bob_hex = pubkey_bob.to_hex();

        let secret_alice = keypair_alice.secret(&public_bob_hex);
        let shared_secret_alice_blake3 = secret_alice.to_blake3();
        let shared_secret_alice_value: &Result<[u8; 32], _> =
            &shared_secret_alice_blake3.unwrap().as_bytes()[..32].try_into();
        assert!(!shared_secret_alice_value.is_err());

        let nonce = AEAD::nonce();
        let nonce_value: Result<[u8; 24], _> = nonce.try_into();
        let alice_key = shared_secret_alice_value.unwrap();
        let key = Key::generate(alice_key, nonce_value.unwrap());

        let message = String::from("plaintext");
        let encrypted = AEAD::encrypt(&key, &message.as_bytes().to_vec());
        assert!(!encrypted.is_err());

        let encrypted_str = encrypted.unwrap();
        let decrypted = AEAD::decrypt(&key, &encrypted_str.clone());
        assert!(!decrypted.is_err());

        let decrypted_value = decrypted.unwrap();
        let result = String::from_utf8(decrypted_value.clone());
        assert!(!result.is_err());
        assert_eq!(result.unwrap(), message);
        assert_eq!(decrypted_value.clone(), message.clone().as_bytes().to_vec());

        let nonce_missed = AEAD::nonce();
        let nonce_missed_value: Result<[u8; 24], _> = nonce_missed.try_into();
        let key_invalid = Key::generate(alice_key, nonce_missed_value.unwrap());
        let encrypted2 = AEAD::encrypt(&key, &message.as_bytes().to_vec());
        let decrypted_unmatched = AEAD::decrypt(&key_invalid, &encrypted2.unwrap());
        assert!(decrypted_unmatched.is_err());
        assert!(matches!(
            decrypted_unmatched,
            Err(AeadError::CipherGeneratorError(_))
        ))
    }
}
