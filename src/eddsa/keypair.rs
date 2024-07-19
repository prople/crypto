//! `keypair` module provide primary object to generate [`KeyPair`] which hold the [`SigningKey`]
//! data structure
use rst_common::with_cryptography::ed25519_dalek::{pkcs8::DecodePrivateKey, SigningKey};

use rst_common::with_cryptography::rand::{rngs::adapter::ReseedingRng, SeedableRng};
use rst_common::with_cryptography::rand_chacha::{rand_core::OsRng, ChaCha20Core};

use crate::eddsa::privkey::PrivKey;
use crate::eddsa::pubkey::PubKey;
use crate::eddsa::signature::Signature;
use crate::eddsa::types::errors::EddsaError;

/// `KeyPair` actually is main entrypoint used to generate the [`SigningKey`]
///
/// From this signing key we will also able to generate [`PubKey`] and also [`Signature`] objects.
/// Besides to generate all necessary objects, this object also able to import given `PEM` data format
/// into its self
#[derive(Clone, Debug)]
pub struct KeyPair {
    keypair: SigningKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let prng = ChaCha20Core::from_entropy();
        let mut reseeding_rng = ReseedingRng::new(prng, 0, OsRng);
        let sign_key = SigningKey::generate(&mut reseeding_rng);
        Self { keypair: sign_key }
    }

    pub fn pub_key(&self) -> PubKey {
        PubKey::new(self.keypair.verifying_key())
    }

    pub fn priv_key(&self) -> PrivKey {
        PrivKey::new(self.keypair.clone())
    }

    pub fn from_pem(pem: String) -> Result<Self, EddsaError> {
        SigningKey::from_pkcs8_pem(pem.as_str())
            .map(|val| Self { keypair: val })
            .map_err(|err| EddsaError::DecodePemError(err.to_string()))
    }

    pub fn signature(&self, message: &[u8]) -> Signature {
        Signature::new(self.keypair.clone(), message.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rst_common::with_cryptography::hex;

    use crate::{
        keysecure::types::{Password, ToKeySecure},
        types::{ByteHex, Hexer, Value},
    };

    #[test]
    fn test_gen_pub_key_multiple() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let keypair3 = KeyPair::generate();

        let pubkey1 = keypair1.pub_key();
        let pubkey2 = keypair2.pub_key();
        let pubkey3 = keypair3.pub_key();

        let pubkeyhex1 = pubkey1.to_hex();
        let pubkeyhex2 = pubkey2.to_hex();
        let pubkeyhex3 = pubkey3.to_hex();

        assert_ne!(pubkeyhex1, pubkeyhex2);
        assert_ne!(pubkeyhex1, pubkeyhex3);
        assert_ne!(pubkeyhex2, pubkeyhex3)
    }

    #[test]
    fn test_gen_pub_key() {
        let keypair = KeyPair::generate();
        let pubkey = keypair.pub_key();
        let pubkeybytes = pubkey.serialize();
        let pubkeyhex = pubkey.to_hex();
        let pubkeytoorig = hex::decode(pubkeyhex.clone().hex());

        let pubkeybytes_val = pubkeybytes.get();
        assert!(!pubkeybytes_val.is_err());

        assert!(!pubkeytoorig.is_err());
        assert_eq!(
            pubkeybytes_val.unwrap(),
            pubkeytoorig.clone().unwrap().as_slice()
        );
        assert_eq!(
            pubkeyhex.hex(),
            hex::encode(pubkeytoorig.unwrap().as_slice())
        )
    }

    #[test]
    fn test_gen_pub_key_from_hex() {
        let keypair = KeyPair::generate();
        let pubkey = keypair.pub_key();
        let pubkeyhex = pubkey.to_hex();

        let pubkey_from_hex = PubKey::from_hex(pubkeyhex);
        assert!(!pubkey_from_hex.is_err());

        let pubkey2 = pubkey_from_hex.unwrap();
        assert_eq!(pubkey2.serialize(), pubkey.serialize());
        assert_eq!(pubkey2.to_hex(), pubkey.to_hex())
    }

    #[test]
    fn test_sign_to_hex() {
        let message = b"hello world";
        let keypair = KeyPair::generate();
        let pubkey = keypair.pub_key();
        let signature = keypair.signature(message);
        let signature_hex = signature.to_hex();

        let verify_hex_valid = pubkey.verify(message, ByteHex::from(signature_hex.clone()));
        assert!(!verify_hex_valid.is_err());

        let verify_hex_invalid = pubkey.verify(b"invalid", ByteHex::from(signature_hex));
        assert!(verify_hex_invalid.is_err());
        assert!(matches!(
            verify_hex_invalid,
            Err(EddsaError::InvalidSignatureError(_))
        ));
    }

    #[test]
    fn test_encode_priv_key_to_pem() {
        let keypair = KeyPair::generate();
        let priv_key_pem = keypair.priv_key().to_pem();
        assert!(!priv_key_pem.is_err());
        assert!(priv_key_pem.unwrap().contains("BEGIN PRIVATE KEY"))
    }

    #[test]
    fn test_priv_key_to_keysecure() {
        let keypair = KeyPair::generate();
        let priv_key = keypair.priv_key();
        let priv_key_pem = priv_key.to_pem();
        assert!(!priv_key_pem.is_err());

        let priv_key_secure = priv_key.to_keysecure(Password::from("test".to_string()));
        assert!(!priv_key_secure.is_err());

        let keysecure = priv_key_secure.unwrap();
        let keysecure_json = keysecure.to_json();
        assert!(!keysecure_json.is_err())
    }

    #[test]
    fn test_decode_pem() {
        let keypair = KeyPair::generate();
        let priv_key = keypair.priv_key();
        let priv_key_pem = priv_key.to_pem();
        let keypair2 = KeyPair::from_pem(priv_key_pem.unwrap());

        assert!(!keypair2.is_err());
        assert_eq!(
            priv_key.serialize(),
            keypair2.unwrap().clone().priv_key().serialize()
        );
    }
}
