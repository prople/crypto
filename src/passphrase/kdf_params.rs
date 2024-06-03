//! `kdf_params` module provides an object of [`KdfParams`] which hold important
//! parameters shadowing the `Argon2 Params`
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::with_cryptography::argon2::Params;

/// `KdfParams` used to store `Argon2` main parameters
///
/// Parameters to store
///
/// - `m_cost`
/// - `t_cost`
/// - `p_cost`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
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
