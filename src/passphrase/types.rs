//! `types` module provides base types for `passphrase` module
pub type KeyBytesRange = [u8; 32];

pub mod errors {
    use rst_common::with_errors::thiserror::{self, Error};

    pub use crate::errors::CommonError;

    /// `PassphraseError` used specifically when manage password based encryption
    #[derive(Debug, Error, PartialEq)]
    pub enum PassphraseError {
        #[error("passphrase: unable to build params: `{0}`")]
        BuildParamsError(String),

        #[error("passphrase: unable to hash password: `{0}`")]
        HashPasswordError(String),

        #[error("passphrase: unable to parse salt: `{0}`")]
        ParseSaltError(String),
    }
}
