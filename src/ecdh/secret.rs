//! `secret` module provides [`Secret`] object as primary data structure
//! to generate shared secret
use rst_common::with_cryptography::x25519_dalek::{
    PublicKey as ECDHPublicKey, SharedSecret, StaticSecret,
};

use rst_common::with_cryptography::{blake3, hex};

use crate::ecdh::pubkey::PublicKey;
use crate::ecdh::types::errors::*;

/// `Secret` used to generate shared secret
///
/// The generated shared secret will be able to hash the secret through `BLAKE3`
pub struct Secret {
    peer: String,
    secret: StaticSecret,
}

impl Secret {
    pub fn new(secret: StaticSecret, peer: String) -> Self {
        Self { peer, secret }
    }

    pub fn to_blake3(self) -> Result<String, EcdhError> {
        let hexed = self.to_hex().map_err(|_| {
            EcdhError::Common(CommonError::ParseHexError(
                "unable to parse hex".to_string(),
            ))
        })?;

        let result = hex::decode(hexed).map_err(|_| {
            EcdhError::Common(CommonError::ParseHexError(
                "unable to decode given hex".to_string(),
            ))
        })?;

        let hashed = blake3::hash(result.as_slice());
        Ok(hex::encode(hashed.as_bytes()))
    }

    pub fn to_hex(self) -> Result<String, EcdhError> {
        let result = self.shared().map_err(|_| {
            EcdhError::ParseSharedError("unable to parse shared secret".to_string())
        })?;

        Ok(hex::encode(result.to_bytes()))
    }

    // `shared` used to generate the `ECDH` shared secret from given peer public key using `DiffieHelman`
    // algorithm
    pub fn shared(self) -> Result<SharedSecret, EcdhError> {
        let peer_pub = PublicKey::from_hex(&self.peer)
            .map_err(|err| EcdhError::ParsePublicKeyError(err.to_string()))?;

        let peer_pub_key = ECDHPublicKey::from(peer_pub.to_bytes());
        let shared_secret = self.secret.diffie_hellman(&peer_pub_key);
        Ok(shared_secret)
    }
}
