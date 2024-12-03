//! `secret` module provides [`Secret`] object as primary data structure
//! to generate shared secret
use rst_common::with_cryptography::x25519_dalek::{
    PublicKey as ECDHPublicKey, SharedSecret, StaticSecret,
};

use rst_common::with_cryptography::hex;

use crate::ecdh::pubkey::PublicKey;
use crate::ecdh::types::errors::*;
use crate::types::{Blake3Hash, ByteHex, Hexer, Value};

/// `Secret` used to generate shared secret
///
/// The generated shared secret will be able to hash the secret through `BLAKE3`
#[derive(Clone)]
pub struct Secret {
    peer: ByteHex,
    secret: StaticSecret,
}

impl Secret {
    pub fn new(secret: StaticSecret, peer: ByteHex) -> Self {
        Self { peer, secret }
    }

    pub fn to_blake3(self) -> Result<Blake3Hash, EcdhError> {
        let hexed = self.to_hex().map_err(|_| {
            EcdhError::Common(CommonError::ParseHexError(
                "unable to parse hex".to_string(),
            ))
        })?;

        let result = hex::decode(hexed.hex()).map_err(|_| {
            EcdhError::Common(CommonError::ParseHexError(
                "unable to decode given hex".to_string(),
            ))
        })?;

        let hashed = Blake3Hash::from(result);
        Ok(hashed)
    }

    pub fn to_hex(self) -> Result<ByteHex, EcdhError> {
        let result = self.shared().map_err(|_| {
            EcdhError::ParseSharedError("unable to parse shared secret".to_string())
        })?;

        Ok(ByteHex::from(result))
    }

    // `shared` used to generate the `ECDH` shared secret from given peer public key using `DiffieHelman`
    // algorithm
    pub fn shared(self) -> Result<SharedSecret, EcdhError> {
        let peer_pub = PublicKey::from_hex(self.peer)
            .map_err(|err| EcdhError::ParsePublicKeyError(err.to_string()))?;

        let public_key = peer_pub.to_bytes();
        let public_key_bytes = public_key
            .get()
            .map_err(|err| EcdhError::ParseBytesError(err.to_string()))?;

        let peer_pub_key = ECDHPublicKey::from(public_key_bytes);
        let shared_secret = self.secret.diffie_hellman(&peer_pub_key);
        Ok(shared_secret)
    }
}
