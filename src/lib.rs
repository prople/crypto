#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]

pub mod aead;
pub mod ecdh;
pub mod eddsa;
pub mod errors;
pub mod keysecure;
pub mod passphrase;

/// `external` used to re-export all cryptography libraries from `rst_common`
pub mod external {
    pub use rst_common::with_cryptography as crypto;
}
