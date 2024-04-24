//! `objects` provides multiple data objects used to generate `KeySecure` data format
use rst_common::standard::serde::{self, Deserialize, Serialize};

use crate::keysecure::types::constants::*;
use crate::passphrase::kdf_params::KdfParams as PassphraseKDFParams;

/// `KeySecureCryptoParams` store a single field for the `nonce`
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "self::serde")]
pub struct KeySecureCryptoParams {
    pub nonce: String,
}

/// `KeySecureCrypto` will be used to store the encrypted data including for
/// it's supported components
///
/// This data will consists of:
/// - cipher
/// - cipher_text
/// - cipher_params
/// - kdf
/// - kdf_params
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "self::serde")]
pub struct KeySecureCrypto {
    pub cipher: String,

    #[serde(rename = "cipherText")]
    pub cipher_text: String,

    #[serde(rename = "cipherParams")]
    pub cipher_params: KeySecureCryptoParams,

    pub kdf: String,

    #[serde(rename = "kdfParams")]
    pub kdf_params: KdfParams,
}

impl KeySecureCrypto {
    pub fn new(nonce: String, ciphertext: String, kdf_params: KdfParams) -> Self {
        let params = KeySecureCryptoParams { nonce };
        Self {
            cipher: CRYPTO_CIPHER_ALGO.to_string(),
            cipher_text: ciphertext,
            cipher_params: params,
            kdf: KDF_ALGO.to_string(),
            kdf_params,
        }
    }
}

/// `KdfParams` used to store passphrase kdf params and it's salt
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "self::serde")]
pub struct KdfParams {
    pub params: PassphraseKDFParams,
    pub salt: String,
}

impl KdfParams {
    pub fn new(params: PassphraseKDFParams, salt: String) -> Self {
        Self { params, salt }
    }
}
