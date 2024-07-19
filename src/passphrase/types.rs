//! `types` module provides base types for `passphrase` module
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

pub type KeyBytesRange = [u8; 32];

use crate::types::Value;

#[derive(Clone, Debug)]
pub struct SaltBytes(Vec<u8>);

impl Value<Vec<u8>> for SaltBytes {
    fn get(&self) -> Result<Vec<u8>, errors::CommonError> {
        Ok(self.0.to_owned())
    }
}

impl From<Vec<u8>> for SaltBytes {
    fn from(value: Vec<u8>) -> Self {
        SaltBytes(value)
    }
}
