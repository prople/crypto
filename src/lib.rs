#![doc = include_str!("../README.md")]

mod aead;
mod ecdh;
mod eddsa;
mod keysecure;
mod passphrase;

pub mod errors;

pub use aead::aead as AEAD;
pub use ecdh::ecdh as ECDH;
pub use eddsa::eddsa as EDDSA;
pub use keysecure::keysecure as KeySecure;
pub use passphrase::passphrase as Passphrase;

pub mod base {
    use super::*;

    pub use keysecure::base::ToKeySecure;
}

pub mod external {
    pub use rst_common::with_cryptography as crypto;
}
