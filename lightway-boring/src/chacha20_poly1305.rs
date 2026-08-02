//! ChaCha20-Poly1305 AEAD cipher (RFC 8439)

use boring::aead::{AeadCtx, Algorithm};
use bytes::BytesMut;
use zeroize::Zeroizing;

/// ChaCha20-Poly1305 authenticated encryption cipher.
pub struct Chacha20Poly1305Aead {
    ctx: Option<AeadCtx>,
}

impl Chacha20Poly1305Aead {
    /// Size of key in bytes
    pub const KEY_SIZE: usize = 32;

    /// Size of initialisation vector / nonce in bytes
    pub const IV_SIZE: usize = 12;

    /// Size of authentication tag in bytes
    pub const AUTHTAG_SIZE: usize = 16;

    /// Creates a new `Chacha20Poly1305Aead` instance bound to `key`.
    pub fn new(key: [u8; Self::KEY_SIZE]) -> Self {
        let key = Zeroizing::new(key);
        let ctx = AeadCtx::new_default_tag(&Algorithm::chacha20_poly1305(), key.as_ref()).ok();
        Self { ctx }
    }

    /// Encrypt plaintext using ChaCha20-Poly1305.
    ///
    /// Returns the ciphertext and the 16-byte Poly1305 authentication tag.
    ///
    /// The nonce must be unique for every call made with the same key.
    pub fn encrypt(
        &self,
        iv: [u8; Self::IV_SIZE],
        plain_text: &[u8],
    ) -> Result<(BytesMut, [u8; Self::AUTHTAG_SIZE]), String> {
        let ctx = self
            .ctx
            .as_ref()
            .ok_or_else(|| String::from("Encrypt failed"))?;

        let mut out = BytesMut::from(plain_text);
        let mut tag = [0u8; Self::AUTHTAG_SIZE];

        ctx.seal_in_place(&iv, &mut out, &mut tag, &[])
            .map_err(|_| String::from("Encrypt failed"))?;

        Ok((out, tag))
    }

    /// Decrypt ciphertext using ChaCha20-Poly1305.
    ///
    /// Verifies the authentication tag before returning the plaintext; on
    /// tag mismatch no plaintext is returned (BoringSSL zeroes the buffer).
    pub fn decrypt(
        &self,
        iv: [u8; Self::IV_SIZE],
        cipher_text: &[u8],
        auth_tag: [u8; Self::AUTHTAG_SIZE],
    ) -> Result<BytesMut, String> {
        let ctx = self
            .ctx
            .as_ref()
            .ok_or_else(|| String::from("Decrypt failed"))?;

        let mut out = BytesMut::from(cipher_text);

        ctx.open_in_place(&iv, &mut out, &auth_tag, &[])
            .map_err(|_| String::from("Decrypt failed"))?;

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These test vectors come from wolfssl crate's chacha20_poly1305 tests, which is also from RFC 8439:
    // https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
    // Notice to future reader: The tests from RFC 8439 uses AAD, while ours don't.
    // So the tag bytes will be different here.
    const KEY: [u8; Chacha20Poly1305Aead::KEY_SIZE] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    const PLAIN_TEXT: [u8; 114] = [
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74,
        0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c,
        0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20,
        0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79,
        0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70,
        0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65,
        0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75,
        0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69, 0x74, 0x2e,
    ];
    const IV: [u8; Chacha20Poly1305Aead::IV_SIZE] = [
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ];
    const CIPHER_TEXT: [u8; 114] = [
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e,
        0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee,
        0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda,
        0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
        0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae,
        0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85,
        0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5,
        0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16,
    ];
    const AUTH_TAG: [u8; Chacha20Poly1305Aead::AUTHTAG_SIZE] = [
        0x6a, 0x23, 0xa4, 0x68, 0x1f, 0xd5, 0x94, 0x56, 0xae, 0xa1, 0xd2, 0x9f, 0x82, 0x47, 0x72,
        0x16,
    ];

    #[test]
    fn test_chacha20_encrypt() {
        let cipher = Chacha20Poly1305Aead::new(KEY);

        let (cipher_text, auth_tag) = cipher.encrypt(IV, &PLAIN_TEXT).unwrap();
        assert_eq!(&cipher_text[..], &CIPHER_TEXT);
        assert_eq!(auth_tag, AUTH_TAG);
    }

    #[test]
    fn test_chacha20_decrypt() {
        let cipher = Chacha20Poly1305Aead::new(KEY);

        let plain_text = cipher.decrypt(IV, &CIPHER_TEXT, AUTH_TAG).unwrap();
        assert_eq!(&plain_text[..], &PLAIN_TEXT);
    }

    #[test]
    fn test_chacha20_roundtrip() {
        let cipher = Chacha20Poly1305Aead::new(KEY);

        let data = b"hello testing content";

        let (encrypted, tag) = cipher.encrypt(IV, data).unwrap();
        let decrypted = cipher.decrypt(IV, &encrypted, tag).unwrap();
        assert_eq!(&decrypted[..], &data[..]);
    }

    #[test]
    fn test_chacha20_tampered_tag() {
        let cipher = Chacha20Poly1305Aead::new(KEY);

        let (encrypted, mut tag) = cipher.encrypt(IV, &PLAIN_TEXT).unwrap();
        tag[0] ^= 0xff; // try tampering with tag
        let res = cipher.decrypt(IV, &encrypted, tag);
        assert_eq!(res.unwrap_err(), "Decrypt failed");
    }

    #[test]
    fn test_chacha20_tampered_ciphertext() {
        let cipher = Chacha20Poly1305Aead::new(KEY);

        let (mut encrypted, tag) = cipher.encrypt(IV, &PLAIN_TEXT).unwrap();
        encrypted[0] ^= 0xff; // try tampering with ciphertext
        let res = cipher.decrypt(IV, &encrypted, tag);
        assert_eq!(res.unwrap_err(), "Decrypt failed");
    }

    #[test]
    fn test_chacha20_decrypt_wrong_iv() {
        let cipher = Chacha20Poly1305Aead::new(KEY);

        let (encrypted, tag) = cipher.encrypt(IV, &PLAIN_TEXT).unwrap();
        let mut wrong_iv = IV;
        wrong_iv[0] ^= 0xff;
        let res = cipher.decrypt(wrong_iv, &encrypted, tag);
        assert_eq!(res.unwrap_err(), "Decrypt failed");
    }

    #[test]
    fn test_chacha20_decrypt_wrong_key() {
        let cipher = Chacha20Poly1305Aead::new(KEY);

        let (encrypted, tag) = cipher.encrypt(IV, &PLAIN_TEXT).unwrap();
        let mut wrong_key = KEY;
        wrong_key[0] ^= 0xff;
        let other = Chacha20Poly1305Aead::new(wrong_key);
        let res = other.decrypt(IV, &encrypted, tag);
        assert_eq!(res.unwrap_err(), "Decrypt failed");
    }

    #[test]
    fn test_constants() {
        // Pin our constants to what BoringSSL reports for this algorithm.
        let alg = Algorithm::chacha20_poly1305();
        assert_eq!(alg.key_length(), Chacha20Poly1305Aead::KEY_SIZE);
        assert_eq!(alg.nonce_len(), Chacha20Poly1305Aead::IV_SIZE);
        assert_eq!(alg.max_tag_len(), Chacha20Poly1305Aead::AUTHTAG_SIZE);
        assert_eq!(alg.max_overhead(), Chacha20Poly1305Aead::AUTHTAG_SIZE);
    }

    #[test]
    fn test_reuse_after_multiple_encrypts() {
        let cipher = Chacha20Poly1305Aead::new(KEY);

        let iv2 = [0x01u8; Chacha20Poly1305Aead::IV_SIZE];

        let (ct1, tag1) = cipher.encrypt(IV, &PLAIN_TEXT).unwrap();
        let (ct2, tag2) = cipher.encrypt(iv2, &PLAIN_TEXT).unwrap();

        // Same plaintext + different IV = should have different ciphertext
        assert_ne!(&ct1[..], &ct2[..]);
        assert_ne!(&tag1[..], &tag2[..]);

        // Both must decrypt correctly with their respective IVs
        let pt1 = cipher.decrypt(IV, &ct1, tag1).unwrap();
        let pt2 = cipher.decrypt(iv2, &ct2, tag2).unwrap();
        assert_eq!(&pt1[..], &PLAIN_TEXT);
        assert_eq!(&pt2[..], &PLAIN_TEXT);
    }
}
