//! The AEAD the caller supplies to an ExpressLane session.

use bytes::BytesMut;

use crate::{ExpresslaneKey, ExpresslaneResult};

#[cfg(feature = "wolfssl-backend")]
pub mod wolfssl;

/// AES-256-GCM for ExpressLane data packets.
///
/// Implementations must be usable concurrently through `&self`: the TX path
/// encrypts in parallel. A backend whose underlying cipher needs `&mut`
/// (wolfSSL) satisfies this with a pool of instances - one-shot AES-GCM has no
/// cross-packet state, since the IV arrives per call and the key is set once,
/// so identically keyed instances are interchangeable.
pub trait ExpresslaneAead: Send + Sync + Sized {
    /// Build an AEAD for `key`.
    fn new(key: &ExpresslaneKey) -> ExpresslaneResult<Self>;

    /// Encrypt `plaintext`, returning the ciphertext and the 16-byte tag.
    fn seal(
        &self,
        iv: [u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> ExpresslaneResult<(BytesMut, [u8; 16])>;

    /// Decrypt and authenticate `ciphertext`.
    ///
    /// # Contract
    ///
    /// On failure the contents of any caller-visible buffer are
    /// **unspecified**. A caller that retries the same bytes under a different
    /// key MUST hold its own copy of the ciphertext. Backends differ here:
    /// RustCrypto `aes-gcm` verifies the tag before applying the keystream and
    /// leaves the buffer intact, `ring` documents no such guarantee.
    fn open(
        &self,
        iv: [u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; 16],
    ) -> ExpresslaneResult<BytesMut>;
}

#[cfg(all(test, feature = "wolfssl-backend"))]
mod tests {
    use self::wolfssl::WolfsslAead;
    use super::*;
    use crate::EXPRESSLANE_KEY_SIZE;

    fn key() -> ExpresslaneKey {
        ExpresslaneKey([7u8; EXPRESSLANE_KEY_SIZE])
    }

    #[test]
    fn round_trip() {
        let aead = WolfsslAead::new(&key()).unwrap();
        let (ct, tag) = aead.seal([1u8; 12], b"hello", b"aad").unwrap();
        let pt = aead.open([1u8; 12], &ct, b"aad", &tag).unwrap();
        assert_eq!(&pt[..], b"hello");
    }

    #[test]
    fn wrong_aad_fails() {
        let aead = WolfsslAead::new(&key()).unwrap();
        let (ct, tag) = aead.seal([1u8; 12], b"hello", b"aad").unwrap();
        assert!(aead.open([1u8; 12], &ct, b"different", &tag).is_err());
    }

    #[test]
    fn tampered_tag_fails() {
        let aead = WolfsslAead::new(&key()).unwrap();
        let (ct, mut tag) = aead.seal([1u8; 12], b"hello", b"aad").unwrap();
        tag[0] ^= 0xFF;
        assert!(aead.open([1u8; 12], &ct, b"aad", &tag).is_err());
    }

    /// The TX path encrypts in parallel, so `seal` must work through a shared
    /// reference even though the wolfSSL cipher itself needs `&mut`.
    #[test]
    fn parallel_seal_through_shared_ref() {
        let aead = std::sync::Arc::new(WolfsslAead::new(&key()).unwrap());
        std::thread::scope(|s| {
            for i in 0..8u8 {
                let aead = aead.clone();
                s.spawn(move || {
                    for _ in 0..100 {
                        let (ct, tag) = aead.seal([i; 12], b"payload", b"aad").unwrap();
                        let pt = aead.open([i; 12], &ct, b"aad", &tag).unwrap();
                        assert_eq!(&pt[..], b"payload");
                    }
                });
            }
        });
    }
}
