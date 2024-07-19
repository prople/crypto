//! `pubkey` module used to maintain generated `ECDH` [`PublicKey`] struct
//! object
use rst_common::with_cryptography::x25519_dalek::PublicKey as ECDHPublicKey;

use crate::ecdh::types::errors::*;
use crate::ecdh::types::PublicKeyBytes;
use crate::types::{ByteHex, Value};

/// `PublicKey` used to store the [`ECDHPublicKey`] object or a wrapper of it
///
/// This object give a helper methods to convert, encode and decode the data, which is
/// a public key
#[derive(Debug, PartialEq)]
pub struct PublicKey {
    key: ECDHPublicKey,
}

impl PublicKey {
    pub fn new(key: ECDHPublicKey) -> Self {
        Self { key }
    }

    pub fn to_bytes(&self) -> PublicKeyBytes {
        PublicKeyBytes::from(self.key.to_bytes())
    }

    pub fn to_hex(&self) -> ByteHex {
        ByteHex::from(self.key)
    }

    pub fn from_hex(key: ByteHex) -> Result<Self, EcdhError> {
        let key_bytes = PublicKeyBytes::try_from(key)?;
        let key_bytes_val = key_bytes
            .get()
            .map_err(|err| EcdhError::ParseBytesError(err.to_string()))?;

        Ok(Self {
            key: ECDHPublicKey::from(key_bytes_val),
        })
    }
}
