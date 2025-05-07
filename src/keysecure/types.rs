//! `types` provides base data types that will be used at `keysecure` module
use rst_common::standard::serde::{self, Deserialize, Serialize};

use crate::keysecure::KeySecure;

pub mod constants {
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

        #[error("keysecure: unable to decrypt: `{0}`")]
        DecryptError(String),

        #[error("eddsa: common error")]
        Common(#[from] CommonError),
    }
}

use crate::types::StringValue;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
pub enum ContextOptions {
    X25519,
    ED25519,
}

impl ContextOptions {
    pub fn get(&self) -> String {
        match self {
            ContextOptions::X25519 => String::from("X25519"),
            ContextOptions::ED25519 => String::from("Ed25519"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Password(String);

impl StringValue for Password {
    fn get_string(&self) -> String {
        self.0.to_owned()
    }
}

impl From<String> for Password {
    fn from(value: String) -> Self {
        Password(value)
    }
}

/// `ToKeySecure` is a base trait / interface used to save an object
/// to the encrypted format using [`KeySecure`] format
pub trait ToKeySecure {
    fn to_keysecure(&self, password: Password) -> Result<KeySecure, errors::KeySecureError>;
}
