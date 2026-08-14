//! Shared interface over the AEAD ciphers implemented in this crate.
//!
//! Callers that want to be generic over the concrete cipher (e.g.
//! AES-256-GCM vs. ChaCha20-Poly1305) should be generic over `C: AeadCipher`.
//! That is resolved entirely at compile time via monomorphization: there is
//! no `Box<dyn AeadCipher>` here, and there can't be one. The associated
//! constants below make the trait dyn-incompatible per Rust's object-safety
//! rules (<https://doc.rust-lang.org/reference/items/traits.html#dyn-compatibility>),
//! independent of anything else on the trait. That's not a limitation in
//! practice: nothing in this codebase picks a cipher (or a TLS backend) at
//! runtime, so there is never a point where dynamic dispatch would be
//! needed in the first place.
//!
//! `iv`/tag sizes are fixed to 12/16 bytes directly in the method
//! signatures rather than sized from `Self::IV_SIZE`/`Self::AUTHTAG_SIZE`:
//! a fixed-size array cannot be sized from an associated const of a generic
//! `Self` without the unstable `generic_const_exprs` feature. Both ciphers
//! below happen to share the same 256-bit-key / 96-bit-nonce / 128-bit-tag
//! shape, so this isn't a real restriction here; the `KEY_SIZE`/`IV_SIZE`/
//! `AUTHTAG_SIZE` associated constants are kept for self-description and
//! are cross-checked against the hardcoded sizes in the tests below.
//!
//! `Error` is deliberately left as an associated type rather than unified:
//! BoringSSL and wolfSSL fail differently, and forcing a shared error type
//! would either lose information a security-conscious caller needs, or
//! paper over backend-specific failure modes. The trait still gives
//! compiler-checked conformance on the shape of the API (methods + sizes);
//! only the error surfaces on the caller side, same as with feature-gating.

use bytes::BytesMut;

/// A 256-bit-key / 96-bit-nonce / 128-bit-tag AEAD cipher.
pub trait AeadCipher {
    /// Size of key in bytes.
    const KEY_SIZE: usize;

    /// Size of initialisation vector / nonce in bytes.
    const IV_SIZE: usize;

    /// Size of authentication tag in bytes.
    const AUTHTAG_SIZE: usize;

    /// Error type returned by cipher operations.
    type Error;

    /// Encrypt `plain_text`, returning ciphertext and the authentication tag.
    ///
    /// The nonce must be unique for every call made with the same key.
    fn encrypt(
        &mut self,
        iv: [u8; 12],
        plain_text: &[u8],
        aad: &[u8],
    ) -> Result<(BytesMut, [u8; 16]), Self::Error>;

    /// Decrypt `cipher_text`, verifying `auth_tag` before returning plaintext.
    fn decrypt(
        &mut self,
        iv: [u8; 12],
        cipher_text: &[u8],
        aad: &[u8],
        auth_tag: &[u8; 16],
    ) -> Result<BytesMut, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Aes256Gcm, Chacha20Poly1305Aead};

    #[test]
    fn hardcoded_sizes_match_each_ciphers_own_constants() {
        assert_eq!(<Aes256Gcm as AeadCipher>::IV_SIZE, 12);
        assert_eq!(<Aes256Gcm as AeadCipher>::AUTHTAG_SIZE, 16);
        assert_eq!(<Chacha20Poly1305Aead as AeadCipher>::IV_SIZE, 12);
        assert_eq!(<Chacha20Poly1305Aead as AeadCipher>::AUTHTAG_SIZE, 16);
    }

    // Generic over the cipher: monomorphized per concrete type at compile
    // time, same codegen as calling the concrete type directly. No `dyn`,
    // no vtable, no indirect calls.
    fn roundtrip<C: AeadCipher>(cipher: &mut C, iv: [u8; 12], plain_text: &[u8]) -> BytesMut {
        let (cipher_text, tag) = cipher.encrypt(iv, plain_text, &[]).ok().unwrap();
        cipher.decrypt(iv, &cipher_text, &[], &tag).ok().unwrap()
    }

    #[test]
    fn generic_roundtrip_works_for_both_backends_without_dyn() {
        let iv = [0x24u8; 12];
        let data = b"same call site, two different concrete ciphers";

        let mut aes = Aes256Gcm::new().unwrap();
        aes.set_key([0x11u8; Aes256Gcm::KEY_SIZE]).unwrap();
        assert_eq!(&roundtrip(&mut aes, iv, data)[..], &data[..]);

        let mut chacha = Chacha20Poly1305Aead::new([0x22u8; Chacha20Poly1305Aead::KEY_SIZE]);
        assert_eq!(&roundtrip(&mut chacha, iv, data)[..], &data[..]);
    }
}
