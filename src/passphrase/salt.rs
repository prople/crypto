//! `salt` module provides a [`Salt`] that will generate a random salt
use rst_common::with_cryptography::argon2::password_hash::SaltString;
use rst_common::with_cryptography::rand::{rngs::adapter::ReseedingRng, SeedableRng};
use rst_common::with_cryptography::rand_chacha::{rand_core::OsRng as RandCoreOsRng, ChaCha20Core};

use crate::passphrase::types::errors::PassphraseError;
use crate::types::Value;

use super::types::SaltBytes;

/// `Salt` used to generate chiper salt management
///
/// The *salt* generated through [`ChaCha20Core`], and also
/// used built-in [`SaltString`]
pub struct Salt;

impl Salt {
    pub fn generate() -> SaltBytes {
        let prng = ChaCha20Core::from_entropy();
        let reseeding_rng = ReseedingRng::new(prng, 0, RandCoreOsRng);
        let salt = SaltString::generate(reseeding_rng);
        SaltBytes::from(salt.as_str().as_bytes().to_vec())
    }

    pub fn from_vec(v: SaltBytes) -> Result<String, PassphraseError> {
        let salt_bytes_vec = v
            .get()
            .map_err(|err| PassphraseError::ParseSaltError(err.to_string()))?;

        String::from_utf8(salt_bytes_vec)
            .map_err(|err| PassphraseError::ParseSaltError(err.to_string()))
    }
}
