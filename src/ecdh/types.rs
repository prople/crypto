//! `types` module provides base data types used at `ecdh` module
pub type ECDHPublicKeyBytes = [u8; 32];
pub type ECDHPrivateKeyBytes = [u8; 32];

pub mod errors {
    use rst_common::with_errors::thiserror::{self, Error};

    pub use crate::errors::CommonError;
    use crate::keysecure::types::errors::KeySecureError;

    /// `EcdhError` used specifically when manage public and private keys used
    /// through `ECDH` algorithm
    #[derive(Debug, Error, PartialEq)]
    pub enum EcdhError {
        #[error("ecdh: unable to parse public key: `{0}`")]
        ParsePublicKeyError(String),

        #[error("ecdh: unable to parse shared secret: `{0}`")]
        ParseSharedError(String),

        #[error("ecdh: unable to parse bytes: `{0}`")]
        ParseBytesError(String),

        #[error("ecdh: common error")]
        Common(#[from] CommonError),

        #[error("eddsa: keysecure error")]
        KeySecure(#[from] KeySecureError),
    }
}
