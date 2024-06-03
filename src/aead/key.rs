//! `key` module provides a simple object struct to maintain
//! generated key and nonce used to encrypt and decrypt a message

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
    key: [u8; 32],
    nonce: [u8; 24],
}

impl Key {
    pub fn generate(key: [u8; 32], nonce: [u8; 24]) -> Self {
        Self { key, nonce }
    }

    pub fn get_key(&self) -> [u8; 32] {
        self.key
    }

    pub fn get_nonce(&self) -> [u8; 24] {
        self.nonce
    }
}
