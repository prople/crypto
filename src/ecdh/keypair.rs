//! `keypair` module used to generate primary [`KeyPair`] data format
use core::fmt;

use rst_common::with_cryptography::hex;
use rst_common::with_cryptography::rand::{rngs::adapter::ReseedingRng, SeedableRng};
use rst_common::with_cryptography::rand_chacha::{rand_core::OsRng, ChaCha20Core};
use rst_common::with_cryptography::x25519_dalek::{PublicKey as ECDHPublicKey, StaticSecret};

use crate::errors::CommonError;
use crate::types::{ByteHex, BytesValue, Hexer, Value};

use crate::keysecure::builder::Builder;
use crate::keysecure::types::errors::KeySecureError;
use crate::keysecure::types::ToKeySecure;
use crate::keysecure::types::{ContextOptions, Password};
use crate::keysecure::KeySecure;

use crate::ecdh::pubkey::PublicKey;
use crate::ecdh::secret::Secret;
use crate::ecdh::types::errors::*;
use crate::ecdh::types::PrivateKeyBytes;

/// `KeyPair` used to store [`StaticSecret`] and implement [`fmt::Debug`] and [`std::clone::Clone`]
///
/// This object provides methods to generate [`PublicKey`], [`Secret`], and [`ECDHPrivateKeyBytes`].
/// Besides of it, this object also implement [`ToKeySecure`]
#[derive(Clone)]
pub struct KeyPair {
    secret: StaticSecret,
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPairs")
            .field("secret_in_hex", &self.to_hex().hex())
            .finish()
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

    pub fn secret(self, peer_hex: ByteHex) -> Secret {
        Secret::new(self.secret, peer_hex)
    }

    pub fn to_hex(&self) -> ByteHex {
        ByteHex::from(hex::encode(self.to_bytes().bytes()))
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

    pub fn to_bytes(&self) -> PrivateKeyBytes {
        PrivateKeyBytes::from(self.secret.to_bytes())
    }

    pub fn from_bytes(val: PrivateKeyBytes) -> Result<Self, CommonError> {
        let private_key_bytes = val.get()?;
        Ok(Self {
            secret: StaticSecret::from(private_key_bytes),
        })
    }
}

impl ToKeySecure for KeyPair {
    fn to_keysecure(&self, password: Password) -> Result<KeySecure, KeySecureError> {
        let priv_key_hex = self.to_hex();

        let keysecure_builder = Builder::new(ContextOptions::X25519, password);
        let keysecure = keysecure_builder.secure(priv_key_hex.hex())?;

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
        let pubkey_decode = PublicKey::from_hex(pubkeyhex);
        assert!(!pubkey_decode.is_err());
        assert_eq!(pubkey_decode.unwrap(), pubkey)
    }

    #[test]
    fn test_gen_pub_key_from_hex_error() {
        let given = b"test";
        let given_hex = hex::encode(given);

        let pubkey_decode = PublicKey::from_hex(ByteHex::from(given_hex));
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

        let secret_alice = keypair_alice.secret(public_bob_hex);
        let secret_bob = keypair_bob.secret(public_alice_hex);

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
        let pubkey_from_bytes = keypair_from_bytes.unwrap().pub_key();
        let pubkey_from_bytes_hex = pubkey_from_bytes.to_hex();

        assert_eq!(pubkey_hex, pubkey_from_bytes_hex)
    }

    #[test]
    fn test_to_keyseucre() {
        let keypair = KeyPair::generate();
        let try_keysecure = keypair.to_keysecure(Password::from("test".to_string()));
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
        let keypair_from_hex = KeyPair::from_hex(keypair_hex.hex());
        assert!(!keypair_from_hex.is_err());

        let keypair_generated = keypair_from_hex.unwrap();
        let pubkey_generated = keypair_generated.pub_key();
        let pubkey_generated_hex = pubkey_generated.to_hex();
        assert_eq!(pubkey_hex, pubkey_generated_hex)
    }
}
