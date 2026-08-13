//! wolfSSL-backed AEAD, for consumers that link wolfSSL directly.
//!
//! `wolfssl::Aes256Gcm::{encrypt, decrypt}` take `&mut self`, and that receiver
//! is what the crate's `unsafe impl Sync` is justified on: one instance per
//! thread, never shared. `Aes256Gcm` is `Send`, so it goes in a pool instead -
//! see [`crate::aead::pool`].
//!
//! The pool is not a workaround for a missing `&self` API - it is the only
//! sound way to offer one. wolfSSL's armasm targets pass `aes->tmp`/`aes->reg`
//! to the assembly as per-call scratch, so two concurrent calls on one context
//! silently corrupt each other's output; `&mut self` is what makes the crate's
//! `Sync` impl hold. What the pool should stop doing is serialising on one
//! mutex: an unshared control reaches 55.8% of linear scaling at 8 threads
//! where this reaches 3.5%, and this lock is the only one the TX path takes
//! per packet.

use bytes::BytesMut;

use crate::aead::pool::{PooledAead, PooledCipher};
use crate::{ExpresslaneError, ExpresslaneKey, ExpresslaneResult};

/// AES-256-GCM backed by wolfSSL.
pub type WolfsslAead = PooledAead<wolfssl::Aes256Gcm>;

impl PooledCipher for wolfssl::Aes256Gcm {
    fn build(key: &ExpresslaneKey) -> ExpresslaneResult<Self> {
        let mut cipher =
            wolfssl::Aes256Gcm::new().map_err(|_| ExpresslaneError::NewCipherFailed)?;
        cipher
            .set_key(key.0)
            .map_err(|_| ExpresslaneError::SetKeyFailed)?;
        Ok(cipher)
    }

    fn encrypt(
        &mut self,
        iv: [u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> ExpresslaneResult<(BytesMut, [u8; 16])> {
        wolfssl::Aes256Gcm::encrypt(self, iv, plaintext, aad)
            .map_err(|_| ExpresslaneError::EncryptFailed)
    }

    fn decrypt(
        &mut self,
        iv: [u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; 16],
    ) -> ExpresslaneResult<BytesMut> {
        wolfssl::Aes256Gcm::decrypt(self, iv, ciphertext, aad, tag)
            .map_err(|_| ExpresslaneError::AuthFailed)
    }

    fn encrypt_into(
        &mut self,
        iv: [u8; 12],
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> ExpresslaneResult<[u8; 16]> {
        wolfssl::Aes256Gcm::encrypt_into(self, iv, plaintext, aad, out)
            .map_err(|_| ExpresslaneError::EncryptFailed)
    }

    fn decrypt_into(
        &mut self,
        iv: [u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; 16],
        out: &mut [u8],
    ) -> ExpresslaneResult<usize> {
        wolfssl::Aes256Gcm::decrypt_into(self, iv, ciphertext, aad, tag, out)
            .map_err(|_| ExpresslaneError::AuthFailed)
    }
}
