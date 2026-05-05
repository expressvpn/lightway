use clap::ValueEnum;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use lightway_core::Cipher as LWCipher;

#[derive(
    Copy, Clone, PartialEq, Eq, Debug, JsonSchema, ValueEnum, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lowercase")]
/// [`LWCipher`] wrapper compatible with clap
pub enum Cipher {
    /// AES256 Cipher
    #[default]
    Aes256,
    /// Chacha20 Cipher
    Chacha20,
}

impl From<Cipher> for LWCipher {
    fn from(item: Cipher) -> LWCipher {
        match item {
            Cipher::Aes256 => LWCipher::Aes256,
            Cipher::Chacha20 => LWCipher::Chacha20,
        }
    }
}
