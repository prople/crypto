//! `keysecure` is a module used to save a critical information such as for generated `Private Key`
//!
//! The generated private key will be saved following `Ethereum KeyStorage` strategy where the encryption
//! key will be using a `password`
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;
use rst_common::standard::uuid::Uuid;

pub mod builder;
pub mod objects;
pub mod types;

use objects::*;
use types::errors::*;

/// `KeySecure` is a main entrypoint to generate the data, it will depends to
/// [`KeySecureCrypto`]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "self::serde")]
pub struct KeySecure {
    pub id: Uuid,
    pub context: String,
    pub crypto: KeySecureCrypto,
}

impl KeySecure {
    pub fn new(context: String, crypto: KeySecureCrypto) -> Self {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::aead::{Key, AEAD};
    use crate::ecdh::keypair::KeyPair;
    use crate::passphrase::kdf_params::KdfParams as PassphraseKDFParams;
    use crate::passphrase::salt::Salt;
    use crate::passphrase::Passphrase;
    use types::constants::CONTEXT_X25519;

    use rst_common::with_cryptography::hex;

    fn generate_alice_key() -> [u8; 32] {
        let keypair_alice = KeyPair::generate();
        let keypair_bob = KeyPair::generate();

        let pubkey_bob = keypair_bob.pub_key();
        let public_bob_hex = pubkey_bob.to_hex();

        let secret_alice = keypair_alice.secret(&public_bob_hex);
        let shared_secret_alice_blake3 = secret_alice.to_blake3();
        let shared_secret_alice_value: &Result<[u8; 32], _> =
            &shared_secret_alice_blake3.unwrap().as_bytes()[..32].try_into();

        shared_secret_alice_value.unwrap()
    }

    fn generate_ecdh_keysecure() -> (KeySecure, [u8; 32]) {
        let alice_key = generate_alice_key();

        let nonce = AEAD::nonce();
        let nonce_value: Result<[u8; 24], _> = nonce.clone().try_into();

        let salt = Salt::generate();
        let salt_string = Salt::from_vec(salt.clone());

        let kdf_params = PassphraseKDFParams::default();
        let kdf = Passphrase::new(kdf_params.clone());

        let try_hash = kdf.hash(String::from("password"), salt.clone());
        let key = Key::generate(try_hash.unwrap(), nonce_value.unwrap());
        let encrypted = AEAD::encrypt(&key, &alice_key.to_vec());

        let encrypted_hex = hex::encode(encrypted.unwrap());
        let crypto_nonce_hex = hex::encode(nonce.clone());
        let keysecure_kdf_params = KdfParams::new(kdf_params, salt_string.unwrap());
        let crypto = KeySecureCrypto::new(crypto_nonce_hex, encrypted_hex, keysecure_kdf_params);

        (
            KeySecure::new(CONTEXT_X25519.to_string(), crypto),
            alice_key,
        )
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
        let encrypted_hex = keysecure.0.crypto.cipher_text;
        let try_encrypted_original = hex::decode(encrypted_hex);
        assert!(!try_encrypted_original.is_err());

        let encrypted = try_encrypted_original.unwrap();
        let kdf_params = keysecure.0.crypto.kdf_params;

        let passphrase_kdf_params = PassphraseKDFParams {
            m_cost: kdf_params.params.m_cost,
            p_cost: kdf_params.params.p_cost,
            t_cost: kdf_params.params.t_cost,
            output_len: kdf_params.params.output_len,
        };

        let kdf = Passphrase::new(passphrase_kdf_params);
        let salt_vec = kdf_params.salt.as_bytes().to_vec();
        let try_hash = kdf.hash(String::from("password"), salt_vec.clone());
        assert!(!try_hash.is_err());

        let nonce_str = keysecure.0.crypto.cipher_params.nonce;
        let try_nonce = hex::decode(nonce_str);
        assert!(!try_nonce.is_err());

        let nonce_value: Result<[u8; 24], _> = try_nonce.unwrap().clone().try_into();
        let key = Key::generate(try_hash.unwrap(), nonce_value.unwrap());
        let decrypted = AEAD::decrypt(&key, &encrypted);
        assert!(!decrypted.is_err());

        let alice_key = keysecure.1;
        assert_eq!(alice_key.to_vec(), decrypted.unwrap())
    }
}
