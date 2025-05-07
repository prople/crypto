//! `keysecure` is a module used to save a critical information such as for generated `Private Key`
//!
//! The generated private key will be saved following `Ethereum KeyStorage` strategy where the encryption
//! key will be using a `password`
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;
use rst_common::standard::uuid::Uuid;
use rst_common::with_cryptography::hex;

pub mod builder;
pub mod objects;
pub mod types;

use crate::aead::{Key, KeyEncryption, KeyNonce, MessageCipher, MessagePlain, AEAD};
use crate::passphrase::kdf_params::KdfParams as PassphraseKDFParams;
use crate::passphrase::types::SaltBytes;
use crate::passphrase::Passphrase;

use objects::*;
use types::{errors::*, ContextOptions};

/// `KeySecure` is a main entrypoint to generate the data, it will depends to
/// [`KeySecureCrypto`]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "self::serde")]
pub struct KeySecure {
    pub id: Uuid,
    pub context: ContextOptions,
    pub crypto: KeySecureCrypto,
}

impl KeySecure {
    pub fn new(context: ContextOptions, crypto: KeySecureCrypto) -> Self {
        let id = Uuid::new_v4();
        Self {
            id,
            context,
            crypto,
        }
    }

    pub fn to_json(&self) -> Result<String, CommonError> {
        serde_json::to_string(self).map_err(|err| CommonError::BuildJSONError(err.to_string()))
    }

    pub fn decrypt(&self, password: String) -> Result<MessagePlain, KeySecureError> {
        let encrypted_data = self.crypto.cipher_text.to_owned();
        let encrypted_data_decoded = hex::decode(encrypted_data)
            .map_err(|err| KeySecureError::DecryptError(err.to_string()))?;

        let kdf_params = self.crypto.kdf_params.to_owned();
        let passphrase_kdf_params = PassphraseKDFParams {
            m_cost: kdf_params.params.m_cost,
            p_cost: kdf_params.params.p_cost,
            t_cost: kdf_params.params.t_cost,
            output_len: kdf_params.params.output_len,
        };

        let kdf = Passphrase::new(passphrase_kdf_params);
        let salt_vec = kdf_params.salt.as_bytes().to_vec();
        let salt_bytes = SaltBytes::from(salt_vec);
        let password_hash = kdf
            .hash(password, salt_bytes)
            .map_err(|err| KeySecureError::DecryptError(err.to_string()))?;

        let nonce_str = self.crypto.cipher_params.nonce.to_owned();
        let nonce_str_decoded =
            hex::decode(nonce_str).map_err(|err| KeySecureError::DecryptError(err.to_string()))?;

        let nonce_value: [u8; 24] = nonce_str_decoded
            .clone()
            .try_into()
            .map_err(|_| KeySecureError::DecryptError("unable to decode nonce".to_string()))?;

        let key = Key::new(
            KeyEncryption::from(password_hash),
            KeyNonce::from(nonce_value),
        );
        let decrypted = AEAD::decrypt(&key, &MessageCipher::from(encrypted_data_decoded))
            .map_err(|err| KeySecureError::DecryptError(err.to_string()))?;

        Ok(decrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::aead::{Key, KeyEncryption, KeyNonce, AEAD};
    use crate::ecdh::keypair::KeyPair;
    use crate::passphrase::kdf_params::KdfParams as PassphraseKDFParams;
    use crate::passphrase::salt::Salt;
    use crate::passphrase::Passphrase;
    use crate::types::{BytesValue, VectorValue};
    use types::ContextOptions;

    use rst_common::with_cryptography::hex;

    fn generate_alice_key() -> [u8; 32] {
        let keypair_alice = KeyPair::generate();
        let keypair_bob = KeyPair::generate();

        let pubkey_bob = keypair_bob.pub_key();
        let public_bob_hex = pubkey_bob.to_hex();

        let secret_alice = keypair_alice.secret(public_bob_hex);
        let shared_secret_alice_blake3 = secret_alice.to_blake3();
        let shared_secret_alice_value: &Result<[u8; 32], _> =
            &shared_secret_alice_blake3.unwrap().bytes()[..32].try_into();

        shared_secret_alice_value.unwrap()
    }

    fn generate_ecdh_keysecure() -> (KeySecure, [u8; 32]) {
        let alice_key = generate_alice_key();

        let nonce = AEAD::nonce();
        let nonce_value: Result<[u8; 24], _> = nonce.vec().clone().try_into();

        let salt = Salt::generate();
        let salt_string = Salt::from_vec(salt.clone());

        let kdf_params = PassphraseKDFParams::default();
        let kdf = Passphrase::new(kdf_params.clone());

        let try_hash = kdf.hash(String::from("password"), salt.clone());
        let key = Key::new(
            KeyEncryption::from(try_hash.unwrap()),
            KeyNonce::from(nonce_value.unwrap()),
        );
        let encrypted = AEAD::encrypt(&key, &MessagePlain::from(alice_key.to_vec()));

        let encrypted_hex = hex::encode(encrypted.unwrap().vec());
        let crypto_nonce_hex = hex::encode(nonce.vec().clone());
        let keysecure_kdf_params = KdfParams::new(kdf_params, salt_string.unwrap());
        let crypto = KeySecureCrypto::new(crypto_nonce_hex, encrypted_hex, keysecure_kdf_params);

        (KeySecure::new(ContextOptions::X25519, crypto), alice_key)
    }

    #[test]
    fn test_generate_json() {
        let keysecure = generate_ecdh_keysecure();
        let keysecure_json = keysecure.0.to_json();
        assert!(!keysecure_json.is_err());
    }

    #[test]
    fn test_decrypt_keysecure() {
        let keysecure = generate_ecdh_keysecure();
        let alice_key = keysecure.1;
        let decrypted = keysecure.0.decrypt(String::from("password"));
        assert!(!decrypted.is_err());
        assert_eq!(alice_key.to_vec(), decrypted.unwrap().vec())
    }

    #[test]
    fn test_decrypt_keysecure_check_bytes() {
        let keysecure1 = generate_ecdh_keysecure();
        let keysecure2 = generate_ecdh_keysecure();

        let alice_key1 = keysecure1.1;
        let alice_key2 = keysecure2.1;
        assert_ne!(alice_key1.to_vec(), alice_key2.to_vec());

        let decrypted1 = keysecure1.0.decrypt(String::from("password"));
        assert!(!decrypted1.is_err());

        let decrypted_value1 = decrypted1.unwrap();
        assert_eq!(alice_key1.to_vec(), decrypted_value1.vec().clone());
        assert_ne!(alice_key2.to_vec(), decrypted_value1.vec().clone());

        let decrypted2 = keysecure2.0.decrypt(String::from("password"));
        assert!(!decrypted2.is_err());

        let decrypted_value2 = decrypted2.unwrap();
        assert_eq!(alice_key2.to_vec(), decrypted_value2.vec().clone());
        assert_ne!(alice_key1.to_vec(), decrypted_value2.vec().clone());
    }

    #[test]
    fn test_decrypt_keysecure_invalid_password() {
        let keysecure = generate_ecdh_keysecure();
        let decrypted = keysecure.0.decrypt(String::from("invalid"));
        assert!(decrypted.is_err());
    }
}
