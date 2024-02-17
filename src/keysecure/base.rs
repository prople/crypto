use crate::errors::KeySecureError;
use crate::KeySecure::KeySecure;

pub trait ToKeySecure {
    fn to_keysecure(&self, password: String) -> Result<KeySecure, KeySecureError>;
}
