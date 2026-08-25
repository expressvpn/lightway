use clap::ValueEnum;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use lightway_core::KeyShare as LWKeyShare;

#[derive(
    Copy, Clone, PartialEq, Eq, Debug, JsonSchema, ValueEnum, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lowercase")]
/// [`LWKeyShare`] wrapper compatible with clap and twelf
pub enum KeyShare {
    /// P-521 + ML-KEM-1024 (wolfSSL only)
    #[cfg(wolfssl)]
    #[default]
    P521Mlkem1024,
    /// X25519 + ML-KEM-768
    // Default whenever P521Mlkem1024 is unavailable, including when this crate
    // is built without any backend feature (as a dev-dependency).
    #[cfg_attr(not(wolfssl), default)]
    X25519Mlkem768,
}

impl From<KeyShare> for LWKeyShare {
    fn from(item: KeyShare) -> LWKeyShare {
        match item {
            #[cfg(wolfssl)]
            KeyShare::P521Mlkem1024 => LWKeyShare::P521MLKEM1024,
            KeyShare::X25519Mlkem768 => LWKeyShare::X25519MLKEM768,
        }
    }
}
