//! `passphrase` is a module used to hash a given secret passphrase or a `password`
//!
//! This hashed password will be used as secret key to encrypt and decrypt some critical
//! information such as for encrypted `Private Key`
pub mod kdf_params;
pub mod salt;
pub mod types;

use rst_common::with_cryptography::argon2::{Algorithm, Argon2, Params, Version};

use kdf_params::KdfParams;
use types::errors::PassphraseError;
use types::{KeyBytesRange, SaltBytes};

use crate::types::Value;

/// `Passphrase` used to hash given input password used to
/// encrypt the private keys and depends to [`KdfParams`]
pub struct Passphrase {
    params: KdfParams,
}

impl Passphrase {
    pub fn new(params: KdfParams) -> Self {
        Self { params }
    }

    // `hash` will hash given password using `Argon2` based on generated salt too
    pub fn hash(
        &self,
        password: String,
        salt: SaltBytes,
    ) -> Result<KeyBytesRange, PassphraseError> {
        let argon_params = Params::new(
            self.params.m_cost,
            self.params.t_cost,
            self.params.p_cost,
            Some(self.params.output_len),
        )
        .map_err(|err| PassphraseError::BuildParamsError(err.to_string()))?;

        let mut output_key_material = [0u8; 32];
        let argon = Argon2::new(Algorithm::default(), Version::default(), argon_params);

        let salt_bytes_val = salt
            .get()
            .map_err(|err| PassphraseError::ParseSaltError(err.to_string()))?;

        argon
            .hash_password_into(
                password.as_bytes(),
                salt_bytes_val.as_slice(),
                &mut output_key_material,
            )
            .map(|_| output_key_material)
            .map_err(|err| PassphraseError::HashPasswordError(err.to_string()))
    }
}

/// `prelude` used to grouping all defined types and objects
/// used to simplify the import operations.
///
/// This module will be usefull when we need to import all of defined object and types without need
/// to import one by one
pub mod prelude {
    use super::*;

    pub use crate::passphrase::Passphrase;
    pub use kdf_params::KdfParams;
    pub use salt::Salt;
    pub use types::*;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rst_common::with_cryptography::hex;
    use salt::Salt;

    #[test]
    fn test_hash() {
        let params = KdfParams::default();

        let salt = Salt::generate();
        let salt_bytes_val = salt.get().unwrap();
        let salt_to_string = String::from_utf8(salt_bytes_val.clone());
        assert!(!salt_to_string.is_err());

        let kdf = Passphrase::new(params.clone());
        let try_hash = kdf.hash("rawatext".to_string(), salt.clone());
        assert!(!try_hash.is_err());

        let try_input = kdf.hash("rawatext".to_string(), salt.clone());
        assert!(!try_input.is_err());

        let hashed_hex = hex::encode(try_hash.unwrap());
        let hashed_input = hex::encode(try_input.unwrap());
        assert_eq!(hashed_hex, hashed_input);

        let salt2 = Salt::generate();
        let try_invalid = kdf.hash("rawatext".to_string(), salt2);
        assert!(!try_invalid.is_err());

        let hashed_invalid_hex = hex::encode(try_invalid.unwrap());
        assert_ne!(hashed_hex, hashed_invalid_hex)
    }

    #[test]
    fn test_generate_salt_from_vec() {
        let salt = Salt::generate();
        let salt_new = Salt::from_vec(salt);
        assert!(!salt_new.is_err());
    }
}
