//! `key` module provides a simple object struct to maintain
//! generated key and nonce used to encrypt and decrypt a message

use crate::{errors::CommonError, types::Value};

use super::{KeyEncryption, KeyNonce};

/// `Key` used to store `key` and `nonce`
///
/// The `key` field used to store bytes that defined by
/// `chacha20poly1305` key properties which is an alias of
/// `GenericArray<u8, U32>`  
///
/// The `nonce` field used when encrypt and decrypt given message
/// which is an alias of `GenericArray<u8, <A as AeadCore>::NonceSize>`
/// taken from `aead` crate
///
/// Both of these properties grouped into this single object to simplify
/// the API library
pub struct Key {
    key: KeyEncryption,
    nonce: KeyNonce,
}

impl Key {
    pub fn new(key: KeyEncryption, nonce: KeyNonce) -> Self {
        Self { key, nonce }
    }

    pub fn get_key_bytes(&self) -> Result<[u8; 32], CommonError> {
        self.key.get()
    }

    pub fn get_nonce_bytes(&self) -> Result<[u8; 24], CommonError> {
        self.nonce.get()
    }
}
