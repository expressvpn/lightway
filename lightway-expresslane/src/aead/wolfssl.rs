//! wolfSSL-backed AEAD.
//!
//! `wolfssl::Aes256Gcm::{encrypt, decrypt}` take `&mut self`, and that receiver
//! is what the crate's `unsafe impl Sync` is justified on: one instance per
//! thread, never shared. `Aes256Gcm` is `Send`, so we keep a pool instead -
//! each call takes an instance, uses it, and returns it. One-shot AES-GCM
//! carries no state between packets (the IV arrives per call, the key is set
//! once), so identically keyed instances are interchangeable.
//!
//! The pool is not a workaround for a missing `&self` API - it is the only
//! sound way to offer one. wolfSSL's armasm targets pass `aes->tmp`/`aes->reg`
//! to the assembly as per-call scratch, so two concurrent calls on one context
//! silently corrupt each other's output; `&mut self` is what makes the crate's
//! `Sync` impl hold. What the pool should stop doing is serialising on one
//! mutex: an unshared control reaches 55.8% of linear scaling at 8 threads
//! where this reaches 3.5%, and this lock is the only one the TX path takes
//! per packet.

use std::sync::Mutex;

use bytes::BytesMut;

use crate::aead::ExpresslaneAead;
use crate::{ExpresslaneError, ExpresslaneKey, ExpresslaneResult};

/// Upper bound on retained cipher instances. Past this, extras are dropped
/// rather than held, so a burst of threads does not pin memory forever.
const MAX_POOLED: usize = 64;

/// AES-256-GCM backed by wolfSSL.
pub struct WolfsslAead {
    key: ExpresslaneKey,
    pool: Mutex<Vec<wolfssl::Aes256Gcm>>,
}

impl WolfsslAead {
    fn build(key: &ExpresslaneKey) -> ExpresslaneResult<wolfssl::Aes256Gcm> {
        let mut cipher =
            wolfssl::Aes256Gcm::new().map_err(|_| ExpresslaneError::NewCipherFailed)?;
        cipher
            .set_key(key.0)
            .map_err(|_| ExpresslaneError::SetKeyFailed)?;
        Ok(cipher)
    }

    fn take(&self) -> ExpresslaneResult<wolfssl::Aes256Gcm> {
        if let Some(cipher) = self.pool.lock().expect("aead pool poisoned").pop() {
            return Ok(cipher);
        }
        Self::build(&self.key)
    }

    fn give_back(&self, cipher: wolfssl::Aes256Gcm) {
        let mut pool = self.pool.lock().expect("aead pool poisoned");
        if pool.len() < MAX_POOLED {
            pool.push(cipher);
        }
    }
}

impl ExpresslaneAead for WolfsslAead {
    fn new(key: &ExpresslaneKey) -> ExpresslaneResult<Self> {
        // Build one eagerly so a bad key fails here rather than on first packet.
        let first = Self::build(key)?;
        Ok(Self {
            key: *key,
            pool: Mutex::new(vec![first]),
        })
    }

    fn seal(
        &self,
        iv: [u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> ExpresslaneResult<(BytesMut, [u8; 16])> {
        let mut cipher = self.take()?;
        let out = cipher
            .encrypt(iv, plaintext, aad)
            .map_err(|_| ExpresslaneError::EncryptFailed);
        self.give_back(cipher);
        out
    }

    fn open(
        &self,
        iv: [u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; 16],
    ) -> ExpresslaneResult<BytesMut> {
        let mut cipher = self.take()?;
        let out = cipher
            .decrypt(iv, ciphertext, aad, tag)
            .map_err(|_| ExpresslaneError::AuthFailed);
        self.give_back(cipher);
        out
    }

    fn seal_into(
        &self,
        iv: [u8; 12],
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> ExpresslaneResult<[u8; 16]> {
        let mut cipher = self.take()?;
        let tag = cipher
            .encrypt_into(iv, plaintext, aad, out)
            .map_err(|_| ExpresslaneError::EncryptFailed);
        self.give_back(cipher);
        tag
    }

    fn open_into(
        &self,
        iv: [u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; 16],
        out: &mut [u8],
    ) -> ExpresslaneResult<usize> {
        let mut cipher = self.take()?;
        let len = cipher
            .decrypt_into(iv, ciphertext, aad, tag, out)
            .map_err(|_| ExpresslaneError::AuthFailed);
        self.give_back(cipher);
        len
    }
}
