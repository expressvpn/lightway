use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use lightway_core::Cipher as LWCipher;

#[derive(Copy, Clone, Debug, ValueEnum, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
/// [`LWCipher`] wrapper compatible with clap and twelf
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
