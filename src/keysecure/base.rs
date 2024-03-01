use crate::errors::KeySecureError;
use crate::KeySecure::KeySecure;

/// `ToKeySecure` is a base trait / interface used to save an object
/// to the encrypted format using [`KeySecure`] format
pub trait ToKeySecure {
    fn to_keysecure(&self, password: String) -> Result<KeySecure, KeySecureError>;
}
