//! A pooled [`ExpresslaneAead`] over any cipher that needs `&mut self`.
//!
//! One-shot AES-GCM carries no state between packets - the IV arrives per call
//! and the key is set once - so identically keyed instances are
//! interchangeable. That is what lets a pool present an `&self` API over a
//! cipher whose own methods take `&mut self`: each call takes an instance, uses
//! it, and returns it.
//!
//! The cipher is a type parameter because the AEAD is the caller's to choose.
//! `lightway-core` supplies whichever `Aes256Gcm` its TLS backend provides, so
//! ExpressLane never pins a second TLS stack into the build; the wolfSSL
//! adapter in this crate is for consumers that link wolfSSL directly.

use std::sync::Mutex;

use bytes::BytesMut;

use crate::aead::ExpresslaneAead;
use crate::{ExpresslaneKey, ExpresslaneResult};

/// Upper bound on retained cipher instances. Past this, extras are dropped
/// rather than held, so a burst of threads does not pin memory forever.
const MAX_POOLED: usize = 64;

/// A cipher a [`PooledAead`] can hand out and take back.
///
/// Implementors need only the allocating forms. The in-place entry points
/// default to those plus a copy; a cipher that can work in place should
/// override them.
pub trait PooledCipher: Send + Sized {
    /// Build an instance already keyed with `key`.
    fn build(key: &ExpresslaneKey) -> ExpresslaneResult<Self>;

    /// Encrypt, returning the ciphertext and the 16-byte tag.
    fn encrypt(
        &mut self,
        iv: [u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> ExpresslaneResult<(BytesMut, [u8; 16])>;

    /// Decrypt and authenticate.
    fn decrypt(
        &mut self,
        iv: [u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; 16],
    ) -> ExpresslaneResult<BytesMut>;

    /// Encrypt into `out`, which is exactly plaintext-sized.
    fn encrypt_into(
        &mut self,
        iv: [u8; 12],
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> ExpresslaneResult<[u8; 16]> {
        let (ct, tag) = self.encrypt(iv, plaintext, aad)?;
        out.copy_from_slice(&ct);
        Ok(tag)
    }

    /// Decrypt into `out`, returning the plaintext length.
    fn decrypt_into(
        &mut self,
        iv: [u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; 16],
        out: &mut [u8],
    ) -> ExpresslaneResult<usize> {
        let pt = self.decrypt(iv, ciphertext, aad, tag)?;
        out[..pt.len()].copy_from_slice(&pt);
        Ok(pt.len())
    }
}

/// AES-256-GCM over a pool of `C`.
pub struct PooledAead<C: PooledCipher> {
    key: ExpresslaneKey,
    pool: Mutex<Vec<C>>,
}

impl<C: PooledCipher> PooledAead<C> {
    fn take(&self) -> ExpresslaneResult<C> {
        if let Some(cipher) = self.pool.lock().expect("aead pool poisoned").pop() {
            return Ok(cipher);
        }
        C::build(&self.key)
    }

    fn give_back(&self, cipher: C) {
        let mut pool = self.pool.lock().expect("aead pool poisoned");
        if pool.len() < MAX_POOLED {
            pool.push(cipher);
        }
    }
}

impl<C: PooledCipher> ExpresslaneAead for PooledAead<C> {
    fn new(key: &ExpresslaneKey) -> ExpresslaneResult<Self> {
        // Build one eagerly so a bad key fails here rather than on first packet.
        let first = C::build(key)?;
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
        let out = cipher.encrypt(iv, plaintext, aad);
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
        let out = cipher.decrypt(iv, ciphertext, aad, tag);
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
        let tag = cipher.encrypt_into(iv, plaintext, aad, out);
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
        let len = cipher.decrypt_into(iv, ciphertext, aad, tag, out);
        self.give_back(cipher);
        len
    }
}
