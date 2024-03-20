//! `pubkey` module used to maintain generated `ECDH` [`PublicKey`] struct
//! object
use rst_common::with_cryptography::hex;
use rst_common::with_cryptography::x25519_dalek::PublicKey as ECDHPublicKey;

use crate::ecdh::types::errors::*;
use crate::ecdh::types::ECDHPublicKeyBytes;

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

    pub fn to_bytes(&self) -> ECDHPublicKeyBytes {
        self.key.to_bytes()
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.key.to_bytes())
    }

    pub fn from_hex(key: &String) -> Result<Self, EcdhError> {
        let result = hex::decode(key)
            .map_err(|err| EcdhError::Common(CommonError::ParseHexError(err.to_string())))?;

        let peer_pub_bytes: [u8; 32] = match result.try_into() {
            Ok(value) => value,
            Err(_) => {
                return Err(EcdhError::ParsePublicKeyError(
                    "unable to parse given public key".to_string(),
                ))
            }
        };

        Ok(Self {
            key: ECDHPublicKey::from(peer_pub_bytes),
        })
    }
}
