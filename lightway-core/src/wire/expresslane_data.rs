//! ExpressLane data-packet types.
//!
//! The implementation lives in the `lightway-expresslane` crate so external
//! offload engines can use it without linking the TLS stack. This module
//! re-exports it under the names the rest of lightway-core already uses, and
//! supplies the AEAD: the same `Aes256Gcm` the rest of the tunnel uses, so
//! ExpressLane follows whichever TLS backend is compiled in rather than
//! pinning a second one into the build.

use bytes::BytesMut;
use lightway_expresslane::{ExpresslaneResult, PooledAead, PooledCipher};

pub use lightway_expresslane::{
    EXPRESSLANE_KEY_SIZE, ExpresslaneError, ExpresslaneKey, ExpresslaneVersion,
};

// Make sure TLS library Aes256Gcm key size is as expected
const _: () = {
    assert!(crate::tls::Aes256Gcm::KEY_SIZE == EXPRESSLANE_KEY_SIZE);
};

/// The active TLS backend's AES-256-GCM, pooled so the `&mut self` cipher can
/// be driven through the shared reference the TX path needs.
pub(crate) struct TlsAesGcm(crate::tls::Aes256Gcm);

impl PooledCipher for TlsAesGcm {
    fn build(key: &ExpresslaneKey) -> ExpresslaneResult<Self> {
        let mut cipher =
            crate::tls::Aes256Gcm::new().map_err(|_| ExpresslaneError::NewCipherFailed)?;
        cipher
            .set_key(key.0)
            .map_err(|_| ExpresslaneError::SetKeyFailed)?;
        Ok(Self(cipher))
    }

    fn encrypt(
        &mut self,
        iv: [u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> ExpresslaneResult<(BytesMut, [u8; 16])> {
        self.0
            .encrypt(iv, plaintext, aad)
            .map_err(|_| ExpresslaneError::EncryptFailed)
    }

    fn decrypt(
        &mut self,
        iv: [u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; 16],
    ) -> ExpresslaneResult<BytesMut> {
        self.0
            .decrypt(iv, ciphertext, aad, tag)
            .map_err(|_| ExpresslaneError::AuthFailed)
    }

    // BoringSSL's binding has no in-place entry points, so it takes the
    // allocating default.
    #[cfg(wolfssl)]
    fn encrypt_into(
        &mut self,
        iv: [u8; 12],
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> ExpresslaneResult<[u8; 16]> {
        self.0
            .encrypt_into(iv, plaintext, aad, out)
            .map_err(|_| ExpresslaneError::EncryptFailed)
    }

    #[cfg(wolfssl)]
    fn decrypt_into(
        &mut self,
        iv: [u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; 16],
        out: &mut [u8],
    ) -> ExpresslaneResult<usize> {
        self.0
            .decrypt_into(iv, ciphertext, aad, tag, out)
            .map_err(|_| ExpresslaneError::AuthFailed)
    }
}

/// The concrete session type lightway-core uses.
pub(crate) type ExpresslaneData = lightway_expresslane::ExpresslaneSession<PooledAead<TlsAesGcm>>;
