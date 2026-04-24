use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use lightway_core::KeyShare as LWKeyShare;

#[derive(Copy, Clone, Debug, ValueEnum, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lowercase")]
/// [`LWKeyShare`] wrapper compatible with clap and twelf
pub enum KeyShare {
    /// P-521 + ML-KEM-1024
    #[default]
    P521Mlkem1024,
    /// X25519 + ML-KEM-768
    X25519Mlkem768,
}

impl From<KeyShare> for LWKeyShare {
    fn from(item: KeyShare) -> LWKeyShare {
        match item {
            KeyShare::P521Mlkem1024 => LWKeyShare::P521MLKEM1024,
            KeyShare::X25519Mlkem768 => LWKeyShare::X25519MLKEM768,
        }
    }
}
