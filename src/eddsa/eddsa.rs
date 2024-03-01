use rst_common::with_cryptography::ed25519_dalek::{
    self, pkcs8::DecodePrivateKey, pkcs8::EncodePrivateKey, Signature as EdDSASignature, Signer,
    SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
};
use rst_common::with_cryptography::hex;

use rst_common::with_cryptography::rand::{rngs::adapter::ReseedingRng, SeedableRng};
use rst_common::with_cryptography::rand_chacha::{rand_core::OsRng, ChaCha20Core};

use crate::base::ToKeySecure;
use crate::KeySecure::CONTEXT_ED25519;
use crate::KeySecure::{KdfParams as KeySecureKdfParams, KeySecure, KeySecureCrypto};
use crate::Passphrase::{KdfParams, Passphrase, Salt};
use crate::AEAD::{Key, AEAD};

pub type EdDSAPubKeyBytes = [u8; PUBLIC_KEY_LENGTH];
pub type EdDSAPrivKeyBytes = [u8; SECRET_KEY_LENGTH];
pub type EdDSASignatureBytes = [u8; SIGNATURE_LENGTH];

use crate::errors::{CommonError, EddsaError, KeySecureError};

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

        let passphrase_salt = Salt::generate();
        let passphrase_kdf_params = KdfParams::default();
        let passphrase = Passphrase::new(passphrase_kdf_params.clone());

        let password_hashed = passphrase
            .hash(password, passphrase_salt.clone())
            .map_err(|err| KeySecureError::BuildKeySecureError(err.to_string()))?;

        let aead_nonce = AEAD::nonce();
        let try_aead_nonce: Result<[u8; 24], _> = aead_nonce.try_into();
        let aead_nonce_value = try_aead_nonce.map_err(|_| {
            KeySecureError::BuildKeySecureError("unable to generate nonce".to_string())
        })?;

        let aead_key = Key::generate(password_hashed, aead_nonce_value);
        let ciphertext_pem = AEAD::encrypt(&aead_key, &pem.as_bytes().to_vec()).map_err(|_| {
            KeySecureError::BuildKeySecureError("unable to encrypt pem".to_string())
        })?;

        let passphrase_salt_value = Salt::from_vec(passphrase_salt.clone())
            .map_err(|err| KeySecureError::BuildKeySecureError(err.to_string()))?;

        let keysecure_kdf_params =
            KeySecureKdfParams::new(passphrase_kdf_params.clone(), passphrase_salt_value);
        let keysecure_ciphertext = hex::encode(ciphertext_pem);
        let keysecure_nonce = hex::encode(aead_nonce_value);
        let keysecure_crypto =
            KeySecureCrypto::new(keysecure_nonce, keysecure_ciphertext, keysecure_kdf_params);
        let keysecure = KeySecure::new(CONTEXT_ED25519.to_string(), keysecure_crypto);

        Ok(keysecure)
    }
}

/// `Signature` is an object that consists of a raw message (in bytes) and also it's [`SigningKey`]
///
/// This object will be able to sign and encode the signature into `HEX` format
pub struct Signature {
    message: Vec<u8>,
    key: SigningKey,
}

impl Signature {
    pub fn new(sign_key: SigningKey, message: Vec<u8>) -> Self {
        Self {
            message,
            key: sign_key,
        }
    }

    pub fn to_hex(&self) -> String {
        let signature = self.key.sign(self.message.as_slice());
        hex::encode(signature.to_bytes())
    }
}

/// `KeyPair` actually is main entrypoint used to generate the [`SigningKey`]
///
/// From this signing key we will also able to generate [`PubKey`] and also [`Signature`] objects.
/// Besides to generate all necessary objects, this object also able to import given `PEM` data format
/// into its self
#[derive(Clone)]
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
        let pubkeytoorig = hex::decode(pubkeyhex.clone());

        assert!(!pubkeytoorig.is_err());
        assert_eq!(pubkeybytes, pubkeytoorig.clone().unwrap().as_slice());
        assert_eq!(
            pubkeyhex,
            hex::encode(pubkeytoorig.clone().unwrap().as_slice())
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

        let verify_hex_valid = pubkey.verify(message, signature_hex.clone());
        assert!(!verify_hex_valid.is_err());

        let verify_hex_invalid = pubkey.verify(b"invalid", signature_hex.clone());
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

        let priv_key_secure = priv_key.to_keysecure("test".to_string());
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
