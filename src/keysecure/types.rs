//! `types` provides base data types that will be used at `keysecure` module
use crate::keysecure::KeySecure;

pub mod constants {
    pub const CONTEXT_X25519: &str = "X25519";
    pub const CONTEXT_ED25519: &str = "Ed25519";
    pub const KDF_ALGO: &str = "argon2";
    pub const CRYPTO_CIPHER_ALGO: &str = "xchacha20poly1305";
}

pub mod errors {
    use rst_common::with_errors::thiserror::{self, Error};

    pub use crate::errors::CommonError;

    /// `KeySecureError` used specifically for for the `KeySecure` management. This
    /// error type also extends from [`CommonError`]
    #[derive(Debug, Error, PartialEq)]
    pub enum KeySecureError {
        #[error("keysecure: unable to build key secure: `{0}`")]
        BuildKeySecureError(String),

        #[error("eddsa: common error")]
        Common(#[from] CommonError),
    }
}

/// `ToKeySecure` is a base trait / interface used to save an object
/// to the encrypted format using [`KeySecure`] format
pub trait ToKeySecure {
    fn to_keysecure(&self, password: String) -> Result<KeySecure, errors::KeySecureError>;
}
