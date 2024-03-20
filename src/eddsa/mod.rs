//! `eddsa` is a module that provides a set of abstraction built on top of
//! `ed25519_dalek` library.
//!
//! The abstractions designed to make it easier to working with several important
//! concepts:
//!
//! - `Keypair`
//! - `Public Key`
//! - `Private Key`
//! - `Signature`
//!
//! The `EdDSA` algorithm used to provides digital signature. A `signature` that will be
//! generated from a given `message` and signed using `private key`, that should be able
//! to verify using the `public key`
pub mod keypair;
pub mod privkey;
pub mod pubkey;
pub mod signature;
pub mod types;
