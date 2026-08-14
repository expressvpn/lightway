//! AES-256-GCM cipher
//!
//! Uses BoringSSL's `EVP_AEAD` one-shot AEAD interface via the safe
//! `boring::aead::AeadCtx` wrapper. The context is bound to a key in
//! `set_key`; subsequent `encrypt`/`decrypt` calls reuse that context with
//! per-packet nonces, so the AES key schedule runs once per session rather
//! than once per packet.

use boring::aead::{AeadCtx, Algorithm};
use boring::error::ErrorStack;
use bytes::BytesMut;
use thiserror::Error;

#[derive(Error, Debug)]
/// The failure result of an AES-256-GCM operation.
pub enum Aes256GcmError {
    /// AES init failed
    #[error("Aes Init Failed")]
    AesInitFailed,

    /// Cipher used before set_key was called
    #[error("Key not set")]
    KeyNotSet,

    #[error("Auth tag mismatch")]
    AuthTagMismatch,

    /// BoringSSL error
    #[error("Fatal: {0}")]
    Fatal(#[from] ErrorStack),
}

/// AES-256-GCM authenticated encryption cipher.
///
/// Contains a BoringSSL `EVP_AEAD_CTX` that is initialised with the key in `set_key` and reused
/// across many `encrypt`/`decrypt` calls with different per-packet nonces.
pub struct Aes256Gcm {
    /// `None` until `set_key` is called.
    ctx: Option<AeadCtx>,
}

impl Aes256Gcm {
    /// Size of key (256 bits)
    pub const KEY_SIZE: usize = 32;

    /// Size of initialisation vector / nonce
    pub const IV_SIZE: usize = 12;

    /// Size of authentication tag
    pub const AUTHTAG_SIZE: usize = 16;

    /// Creates a new `Aes256Gcm` cipher instance.
    ///
    /// The instance is not usable for encryption/decryption until `set_key`
    /// is called.
    pub fn new() -> Result<Self, Aes256GcmError> {
        Ok(Aes256Gcm { ctx: None })
    }

    /// Set the encryption/decryption key.
    ///
    /// Initialises the underlying `EVP_AEAD_CTX` with AES-256-GCM and the
    /// supplied key. The AES key schedule runs here once.
    pub fn set_key(&mut self, key: [u8; Self::KEY_SIZE]) -> Result<(), Aes256GcmError> {
        let ctx = AeadCtx::new_default_tag(&Algorithm::aes_256_gcm(), &key)
            .map_err(|_| Aes256GcmError::AesInitFailed)?;
        self.ctx = Some(ctx);
        Ok(())
    }

    /// Encrypt plaintext using AES-256-GCM.
    ///
    /// Returns the ciphertext and the 16-byte authentication tag.
    pub fn encrypt(
        &mut self,
        iv: [u8; Self::IV_SIZE],
        plain_text: &[u8],
        auth_vec: &[u8],
    ) -> Result<(BytesMut, [u8; Self::AUTHTAG_SIZE]), Aes256GcmError> {
        let ctx = self.ctx.as_ref().ok_or(Aes256GcmError::KeyNotSet)?;

        let mut out = BytesMut::from(plain_text);
        let mut tag = [0u8; Self::AUTHTAG_SIZE];

        ctx.seal_in_place(&iv, &mut out, &mut tag, auth_vec)?;

        Ok((out, tag))
    }

    /// Decrypt ciphertext using AES-256-GCM.
    ///
    /// Verifies the authentication tag before returning the plaintext.
    pub fn decrypt(
        &mut self,
        iv: [u8; Self::IV_SIZE],
        cipher_text: &[u8],
        auth_vec: &[u8],
        auth_tag: &[u8; Self::AUTHTAG_SIZE],
    ) -> Result<BytesMut, Aes256GcmError> {
        let ctx = self.ctx.as_ref().ok_or(Aes256GcmError::KeyNotSet)?;

        let mut out = BytesMut::from(cipher_text);

        ctx.open_in_place(&iv, &mut out, auth_tag, auth_vec)
            .map_err(|_| Aes256GcmError::AuthTagMismatch)?;

        Ok(out)
    }
}

impl crate::AeadCipher for Aes256Gcm {
    const KEY_SIZE: usize = Self::KEY_SIZE;
    const IV_SIZE: usize = Self::IV_SIZE;
    const AUTHTAG_SIZE: usize = Self::AUTHTAG_SIZE;

    type Error = Aes256GcmError;

    fn encrypt(
        &mut self,
        iv: [u8; 12],
        plain_text: &[u8],
        aad: &[u8],
    ) -> Result<(BytesMut, [u8; 16]), Self::Error> {
        self.encrypt(iv, plain_text, aad)
    }

    fn decrypt(
        &mut self,
        iv: [u8; 12],
        cipher_text: &[u8],
        aad: &[u8],
        auth_tag: &[u8; 16],
    ) -> Result<BytesMut, Self::Error> {
        self.decrypt(iv, cipher_text, aad, auth_tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; Aes256Gcm::KEY_SIZE] = [
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83,
        0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
        0x83, 0x08,
    ];
    const PLAIN_TEXT: [u8; 60] = [
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26,
        0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31,
        0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49,
        0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39,
    ];
    const IV: [u8; Aes256Gcm::IV_SIZE] = [
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
    ];
    const AUTH_VEC: &[u8] = &[
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe,
        0xef, 0xab, 0xad, 0xda, 0xd2,
    ];
    // Expected ciphertext from NIST GCM test vectors
    const CIPHER_TEXT: [u8; 60] = [
        0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42,
        0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55,
        0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56,
        0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62,
    ];
    const EXP_AUTH_TAG: &[u8; Aes256Gcm::AUTHTAG_SIZE] = &[
        0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68, 0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55,
        0x1b,
    ];

    #[test]
    fn test_aes256gcm_new() {
        let _ = Aes256Gcm::new().unwrap();
    }

    #[test]
    fn test_aes256gcm_encrypt() {
        let mut cipher = Aes256Gcm::new().unwrap();
        cipher.set_key(KEY).unwrap();

        let (cipher_text, auth_tag) = cipher.encrypt(IV, &PLAIN_TEXT, AUTH_VEC).unwrap();
        assert_eq!(&cipher_text[..], &CIPHER_TEXT);
        assert_eq!(&auth_tag[..], &EXP_AUTH_TAG[..]);
    }

    #[test]
    fn test_aes256gcm_encrypt_wo_key() {
        let mut cipher = Aes256Gcm::new().unwrap();
        let res = cipher.encrypt(IV, &PLAIN_TEXT, AUTH_VEC);
        assert!(matches!(res, Err(Aes256GcmError::KeyNotSet)));
    }

    #[test]
    fn test_aes256gcm_decrypt_wo_key() {
        let mut cipher = Aes256Gcm::new().unwrap();
        let res = cipher.decrypt(IV, CIPHER_TEXT.as_ref(), AUTH_VEC, EXP_AUTH_TAG);
        assert!(matches!(res, Err(Aes256GcmError::KeyNotSet)));
    }

    #[test]
    fn test_aes256gcm_decrypt() {
        let mut cipher = Aes256Gcm::new().unwrap();
        cipher.set_key(KEY).unwrap();

        let plain_text = cipher
            .decrypt(IV, CIPHER_TEXT.as_ref(), AUTH_VEC, EXP_AUTH_TAG)
            .unwrap();
        assert_eq!(&plain_text[..], &PLAIN_TEXT);
    }

    #[test]
    fn test_aes256gcm_roundtrip() {
        let mut cipher = Aes256Gcm::new().unwrap();
        cipher.set_key(KEY).unwrap();

        let data = b"hello expresslane";
        let aad = b"session-id-and-counter";

        let (encrypted, tag) = cipher.encrypt(IV, data, aad).unwrap();
        let decrypted = cipher.decrypt(IV, &encrypted, aad, &tag).unwrap();
        assert_eq!(&decrypted[..], &data[..]);
    }

    #[test]
    fn test_aes256gcm_tampered_tag() {
        let mut cipher = Aes256Gcm::new().unwrap();
        cipher.set_key(KEY).unwrap();

        let (encrypted, mut tag) = cipher.encrypt(IV, &PLAIN_TEXT, AUTH_VEC).unwrap();
        tag[0] ^= 0xff; // tamper with tag
        let res = cipher.decrypt(IV, &encrypted, AUTH_VEC, &tag);
        assert!(matches!(res, Err(Aes256GcmError::AuthTagMismatch)));
    }

    #[test]
    fn test_constants() {
        assert_eq!(Aes256Gcm::KEY_SIZE, 32);
        assert_eq!(Aes256Gcm::IV_SIZE, 12);
        assert_eq!(Aes256Gcm::AUTHTAG_SIZE, 16);
    }

    #[test]
    fn test_reuse_after_multiple_encrypts() {
        // Verify the context is correctly reused between calls
        let mut cipher = Aes256Gcm::new().unwrap();
        cipher.set_key(KEY).unwrap();

        let iv2 = [0x01u8; Aes256Gcm::IV_SIZE];

        let (ct1, tag1) = cipher.encrypt(IV, &PLAIN_TEXT, AUTH_VEC).unwrap();
        let (ct2, tag2) = cipher.encrypt(iv2, &PLAIN_TEXT, AUTH_VEC).unwrap();

        // Same plaintext + different IV → different ciphertext
        assert_ne!(&ct1[..], &ct2[..]);
        assert_ne!(&tag1[..], &tag2[..]);

        // Both must decrypt correctly with their respective IVs
        let pt1 = cipher.decrypt(IV, &ct1, AUTH_VEC, &tag1).unwrap();
        let pt2 = cipher.decrypt(iv2, &ct2, AUTH_VEC, &tag2).unwrap();
        assert_eq!(&pt1[..], &PLAIN_TEXT);
        assert_eq!(&pt2[..], &PLAIN_TEXT);
    }
}
