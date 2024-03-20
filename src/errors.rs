//! `errors` provides base error which is [`CommonError`]
use rst_common::with_errors::thiserror::{self, Error};

/// `CommonError` this kind of error types used for all common errors
#[derive(Debug, Error, PartialEq)]
pub enum CommonError {
    #[error("hex: unable to parse given hex: `{0}`")]
    ParseHexError(String),

    #[error("json: unable to parse given hex: `{0}`")]
    BuildJSONError(String),

    #[error("unknown: something unknown goes went wrong")]
    UnknownError,
}
