use rst_common::with_errors::thiserror::{self, Error};

#[derive(Debug, Error, PartialEq)]
pub enum CommonError {
    #[error("hex: unable to parse given hex: `{0}`")]
    ParseHexError(String),

    #[error("json: unable to parse given hex: `{0}`")]
    BuildJSONError(String),

    #[error("unknown: something unknown goes went wrong")]
    UnknownError,
}

#[derive(Debug, Error, PartialEq)]
pub enum KeySecureError {
    #[error("keysecure: unable to build key secure: `{0}`")]
    BuildKeySecureError(String),

    #[error("eddsa: common error")]
    Common(#[from] CommonError),
}

#[derive(Debug, Error, PartialEq)]
pub enum PassphraseError {
    #[error("passphrase: unable to build params: `{0}`")]
    BuildParamsError(String),

    #[error("passphrase: unable to hash password: `{0}`")]
    HashPasswordError(String),

    #[error("passphrase: unable to parse salt: `{0}`")]
    ParseSaltError(String),
}

#[derive(Debug, Error, PartialEq)]
pub enum EddsaError {
    #[error("eddsa: unable to parse signature: `{0}`")]
    ParseSignatureError(String),

    #[error("eddsa: unable to encode pem: `{0}`")]
    EncodePemError(String),

    #[error("eddsa: unable to decode pem: `{0}`")]
    DecodePemError(String),

    #[error("eddsa: invalid given signature: `{0}`")]
    InvalidSignatureError(String),

    #[error("eddsa: invalid given public key: `{0}`")]
    InvalidPubKeyError(String),

    #[error("eddsa: common error")]
    Common(#[from] CommonError),

    #[error("eddsa: keysecure error")]
    KeySecure(#[from] KeySecureError),

    #[error("eddsa: passphrase error")]
    Passphrase(#[from] PassphraseError),
}

#[derive(Debug, Error, PartialEq)]
pub enum EcdhError {
    #[error("ecdh: unable to parse public key: `{0}`")]
    ParsePublicKeyError(String),

    #[error("ecdh: unable to parse shared secret: `{0}`")]
    ParseSharedError(String),

    #[error("ecdh: unable to parse bytes: `{0}`")]
    ParseBytesError(String),

    #[error("ecdh: common error")]
    Common(#[from] CommonError),

    #[error("eddsa: keysecure error")]
    KeySecure(#[from] KeySecureError),
}

#[derive(Debug, Error)]
pub enum AeadError {
    #[error("aead: unable to parse bytes: `{0}`")]
    CipherGeneratorError(String),
}
