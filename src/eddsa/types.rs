//! `types` is a module that provides all base types used at `eddsa` module
use rst_common::with_cryptography::ed25519_dalek::{
    PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
};

pub type EdDSAPubKeyBytes = [u8; PUBLIC_KEY_LENGTH];
pub type EdDSAPrivKeyBytes = [u8; SECRET_KEY_LENGTH];
pub type EdDSASignatureBytes = [u8; SIGNATURE_LENGTH];

pub mod errors {
    use rst_common::with_errors::thiserror::{self, Error};

    pub use crate::errors::CommonError;
    use crate::keysecure::types::errors::KeySecureError;
    use crate::passphrase::types::errors::PassphraseError;

    /// `EddsaError` used specifically when manage public and private keys through
    /// `Eddsa` algorithm
    #[derive(Debug, Error, PartialEq)]
    pub enum EddsaError {
        #[error("eddsa: unable to parse signature: `{0}`")]
        ParseSignatureError(String),

        #[error("eddsa: unable to encode pem: `{0}`")]
        EncodePemError(String),

        #[error("eddsa: unable to decode pem: `{0}`")]
        DecodePemError(String),

        #[error("eddsa: invalid given signature: `{0}`")]
        InvalidSignatureError(String),

        #[error("eddsa: invalid given public key: `{0}`")]
        InvalidPubKeyError(String),

        #[error("eddsa: common error")]
        Common(#[from] CommonError),

        #[error("eddsa: keysecure error")]
        KeySecure(#[from] KeySecureError),

        #[error("eddsa: passphrase error")]
        Passphrase(#[from] PassphraseError),
    }
}
