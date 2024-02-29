use core::fmt;

use rst_common::with_cryptography::rand::{rngs::adapter::ReseedingRng, SeedableRng};
use rst_common::with_cryptography::rand_chacha::{rand_core::OsRng, ChaCha20Core};
use rst_common::with_cryptography::x25519_dalek::{
    PublicKey as ECDHPublicKey, SharedSecret, StaticSecret,
};
use rst_common::with_cryptography::{blake3, hex};

use crate::base::ToKeySecure;
use crate::KeySecure::CONTEXT_X25519;
use crate::KeySecure::{KdfParams as KeySecureKdfParams, KeySecure, KeySecureCrypto};
use crate::Passphrase::{KdfParams, Passphrase, Salt};
use crate::AEAD::{Key, AEAD};

pub type ECDHPublicKeyBytes = [u8; 32];
pub type ECDHPrivateKeyBytes = [u8; 32];

use crate::errors::{CommonError, EcdhError, KeySecureError};

#[derive(Debug, PartialEq)]
pub struct PublicKey {
    key: ECDHPublicKey,
}

impl PublicKey {
    pub fn new(key: ECDHPublicKey) -> Self {
        Self { key }
    }

    pub fn to_bytes(&self) -> ECDHPublicKeyBytes {
        self.key.to_bytes()
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.key.to_bytes())
    }

    pub fn from_hex(key: &String) -> Result<Self, EcdhError> {
        let result = hex::decode(key)
            .map_err(|err| EcdhError::Common(CommonError::ParseHexError(err.to_string())))?;

        let peer_pub_bytes: [u8; 32] = match result.try_into() {
            Ok(value) => value,
            Err(_) => {
                return Err(EcdhError::ParsePublicKeyError(
                    "unable to parse given public key".to_string(),
                ))
            }
        };

        Ok(Self {
            key: ECDHPublicKey::from(peer_pub_bytes),
        })
    }
}

pub struct Secret {
    peer: String,
    secret: StaticSecret,
}

impl Secret {
    pub fn new(secret: StaticSecret, peer: String) -> Self {
        Self { peer, secret }
    }

    pub fn to_blake3(self) -> Result<String, EcdhError> {
        let hexed = self.to_hex().map_err(|_| {
            EcdhError::Common(CommonError::ParseHexError(
                "unable to parse hex".to_string(),
            ))
        })?;

        let result = hex::decode(hexed).map_err(|_| {
            EcdhError::Common(CommonError::ParseHexError(
                "unable to decode given hex".to_string(),
            ))
        })?;

        let hashed = blake3::hash(result.as_slice());
        Ok(hex::encode(hashed.as_bytes()))
    }

    pub fn to_hex(self) -> Result<String, EcdhError> {
        let result = self.shared().map_err(|_| {
            EcdhError::ParseSharedError("unable to parse shared secret".to_string())
        })?;

        Ok(hex::encode(result.to_bytes()))
    }

    pub fn shared(self) -> Result<SharedSecret, EcdhError> {
        let peer_pub = PublicKey::from_hex(&self.peer)
            .map_err(|err| EcdhError::ParsePublicKeyError(err.to_string()))?;

        let peer_pub_key = ECDHPublicKey::from(peer_pub.to_bytes());
        let shared_secret = self.secret.diffie_hellman(&peer_pub_key);
        Ok(shared_secret)
    }
}

pub struct KeyPair {
    secret: StaticSecret,
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPairs")
            .field("secret_in_hex", &self.to_hex())
            .finish()
    }
}

impl std::clone::Clone for KeyPair {
    fn clone(&self) -> Self {
        let in_bytes = self.to_bytes();
        let from_bytes = KeyPair::from_bytes(in_bytes);
        from_bytes
    }
}

impl KeyPair {
    pub fn generate() -> Self {
        let prng = ChaCha20Core::from_entropy();
        let mut reseeding_rng = ReseedingRng::new(prng, 0, OsRng);
        let secret = StaticSecret::random_from_rng(&mut reseeding_rng);
        Self { secret }
    }

    pub fn pub_key(&self) -> PublicKey {
        PublicKey::new(ECDHPublicKey::from(&self.secret))
    }

    pub fn secret(self, peer_hex: &String) -> Secret {
        Secret::new(self.secret, peer_hex.into())
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    pub fn from_hex(val: String) -> Result<Self, EcdhError> {
        let decoded = hex::decode(val)
            .map_err(|err| EcdhError::Common(CommonError::ParseHexError(err.to_string())))?;

        let valid_bytes: Result<[u8; 32], _> = decoded.try_into();
        valid_bytes
            .map(|val| Self {
                secret: StaticSecret::from(val),
            })
            .map_err(|_| EcdhError::ParseBytesError("unable to parse decode bytes".to_string()))
    }

    pub fn to_bytes(&self) -> ECDHPrivateKeyBytes {
        self.secret.to_bytes()
    }

    pub fn from_bytes(val: ECDHPrivateKeyBytes) -> Self {
        Self {
            secret: StaticSecret::from(val),
        }
    }
}

impl ToKeySecure for KeyPair {
    fn to_keysecure(&self, password: String) -> Result<KeySecure, KeySecureError> {
        let priv_key_hex = self.to_hex();

        let passphrase_salt = Salt::generate();
        let passphrase_kdf_params = KdfParams::default();
        let passphrase = Passphrase::new(passphrase_kdf_params.clone());

        let password_hashed = passphrase
            .hash(password, passphrase_salt.clone())
            .map_err(|err| KeySecureError::BuildKeySecureError(err.to_string()))?;

        let aead_nonce = AEAD::nonce();
        let try_aead_nonce: Result<[u8; 24], _> = aead_nonce.try_into();
        let aead_nonce_value = try_aead_nonce.map_err(|_| {
            KeySecureError::BuildKeySecureError("unable to generate error".to_string())
        })?;

        let aead_key = Key::generate(password_hashed, aead_nonce_value);
        let ciphertext = AEAD::encrypt(&aead_key, &priv_key_hex.as_bytes().to_vec())
            .map_err(|err| KeySecureError::BuildKeySecureError(err.to_string()))?;

        let passphrase_salt_value = Salt::from_vec(passphrase_salt.clone())
            .map_err(|err| KeySecureError::BuildKeySecureError(err.to_string()))?;

        let keysecure_kdf_params =
            KeySecureKdfParams::new(passphrase_kdf_params.clone(), passphrase_salt_value);
        let keysecure_ciphertext = hex::encode(ciphertext);
        let keysecure_nonce = hex::encode(aead_nonce_value);
        let keysecure_crypto =
            KeySecureCrypto::new(keysecure_nonce, keysecure_ciphertext, keysecure_kdf_params);
        let keysecure = KeySecure::new(CONTEXT_X25519.to_string(), keysecure_crypto);

        Ok(keysecure)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_pub_key_from_hex() {
        let keypair = KeyPair::generate();
        let pubkey = keypair.pub_key();

        let pubkeyhex = pubkey.to_hex();
        let pubkey_decode = PublicKey::from_hex(&pubkeyhex);
        assert!(!pubkey_decode.is_err());
        assert_eq!(pubkey_decode.unwrap(), pubkey)
    }

    #[test]
    fn test_gen_pub_key_from_hex_error() {
        let given = b"test";
        let given_hex = hex::encode(given);

        let pubkey_decode = PublicKey::from_hex(&given_hex);
        assert!(pubkey_decode.is_err());
        assert!(matches!(
            pubkey_decode,
            Err(EcdhError::ParsePublicKeyError(_))
        ))
    }

    #[test]
    fn test_gen_shared_secret() {
        let keypair_alice = KeyPair::generate();
        let keypair_bob = KeyPair::generate();
        let pubkey_alice = keypair_alice.pub_key();
        let pubkey_bob = keypair_bob.pub_key();

        let public_alice_hex = pubkey_alice.to_hex();
        let public_bob_hex = pubkey_bob.to_hex();

        let secret_alice = keypair_alice.secret(&public_bob_hex);
        let secret_bob = keypair_bob.secret(&public_alice_hex);

        let shared_secret_alice_blake3 = secret_alice.to_blake3();
        let shared_secret_bob_blake3 = secret_bob.to_blake3();

        assert!(!&shared_secret_alice_blake3.is_err());
        assert!(!&shared_secret_bob_blake3.is_err());

        assert_eq!(
            shared_secret_alice_blake3.unwrap(),
            shared_secret_bob_blake3.unwrap()
        )
    }

    #[test]
    fn test_serialize_deserialize() {
        let keypair = KeyPair::generate();
        let pubkey = keypair.pub_key();
        let pubkey_hex = pubkey.to_hex();

        let bytes_serialized = keypair.to_bytes();
        let keypair_from_bytes = KeyPair::from_bytes(bytes_serialized);
        let pubkey_from_bytes = keypair_from_bytes.pub_key();
        let pubkey_from_bytes_hex = pubkey_from_bytes.to_hex();

        assert_eq!(pubkey_hex, pubkey_from_bytes_hex)
    }

    #[test]
    fn test_to_keyseucre() {
        let keypair = KeyPair::generate();
        let try_keysecure = keypair.to_keysecure("test".to_string());
        assert!(!try_keysecure.is_err());

        let keysecure = try_keysecure.unwrap();
        let keysecure_json = keysecure.to_json();
        assert!(!keysecure_json.is_err());
    }

    #[test]
    fn test_secret_from_hex() {
        let keypair = KeyPair::generate();
        let pubkey = keypair.pub_key();
        let pubkey_hex = pubkey.to_hex();

        let keypair_hex = keypair.to_hex();
        let keypair_from_hex = KeyPair::from_hex(keypair_hex);
        assert!(!keypair_from_hex.is_err());

        let keypair_generated = keypair_from_hex.unwrap();
        let pubkey_generated = keypair_generated.pub_key();
        let pubkey_generated_hex = pubkey_generated.to_hex();
        assert_eq!(pubkey_hex, pubkey_generated_hex)
    }
}
