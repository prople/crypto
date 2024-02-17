use rst_common::with_cryptography::argon2::{password_hash::SaltString, Algorithm, Argon2, Params, Version};
use rst_common::with_cryptography::rand::{rngs::adapter::ReseedingRng, SeedableRng};
use rst_common::with_cryptography::rand_chacha::{rand_core::OsRng as RandCoreOsRng, ChaCha20Core};
use serde::{Deserialize, Serialize};

pub type KeyBytesRange = [u8; 32];

use crate::errors::PassphraseError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,

    #[serde(rename = "outputLen")]
    pub output_len: usize,
}

impl KdfParams {
    pub fn default() -> Self {
        let argon2_default_params = Params::default();

        Self {
            m_cost: argon2_default_params.m_cost(),
            t_cost: argon2_default_params.t_cost(),
            p_cost: argon2_default_params.p_cost(),
            output_len: argon2_default_params
                .output_len()
                .map_or(Params::DEFAULT_OUTPUT_LEN, |val| val),
        }
    }
}

pub struct Salt;

impl Salt {
    pub fn generate() -> Vec<u8> {
        let prng = ChaCha20Core::from_entropy();
        let reseeding_rng = ReseedingRng::new(prng, 0, RandCoreOsRng);
        let salt = SaltString::generate(reseeding_rng);
        salt.as_str().as_bytes().to_vec()
    }

    pub fn from_vec(v: Vec<u8>) -> Result<String, PassphraseError> {
        let try_salt_string = String::from_utf8(v);
        match try_salt_string {
            Ok(value) => Ok(value),
            Err(err) => Err(PassphraseError::ParseSaltError(err.to_string())),
        }
    }
}

pub struct Passphrase {
    params: KdfParams,
}

impl Passphrase {
    pub fn new(params: KdfParams) -> Self {
        Self { params }
    }

    pub fn hash(&self, password: String, salt: Vec<u8>) -> Result<KeyBytesRange, PassphraseError> {
        let try_argon_params = Params::new(
            self.params.m_cost,
            self.params.t_cost,
            self.params.p_cost,
            Some(self.params.output_len),
        );

        let argon_params = match try_argon_params {
            Ok(value) => value,
            Err(err) => return Err(PassphraseError::BuildParamsError(err.to_string())),
        };

        let mut output_key_material = [0u8; 32];
        let argon = Argon2::new(Algorithm::default(), Version::default(), argon_params);
        let hashed = argon.hash_password_into(
            password.as_bytes(),
            salt.as_slice(),
            &mut output_key_material,
        );
        match hashed {
            Ok(_) => Ok(output_key_material),
            Err(err) => Err(PassphraseError::HashPasswordError(err.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rst_common::with_cryptography::hex;

    #[test]
    fn test_hash() {
        let params = KdfParams::default();

        let salt = Salt::generate();
        let salt_to_string = String::from_utf8(salt.clone());
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
