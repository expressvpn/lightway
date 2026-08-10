//! Certificate and secret key types for TLS/DTLS authentication.
//!
//! Matches the wolfssl crate's enum-based API so lightway-core compiles
//! with either TLS backend.

use std::path::Path;

/// Root certificate for CA trust anchors.
///
/// Mirrors wolfssl's `RootCertificate` enum — data is borrowed, not owned.
/// The actual BoringSSL loading happens in the context builder when these
/// values are consumed.
#[derive(Debug, Clone, Copy)]
pub enum RootCertificate<'a> {
    /// In-memory PEM buffer
    PemBuffer(&'a [u8]),
    /// In-memory DER/ASN1 buffer
    Asn1Buffer(&'a [u8]),
    /// Path to a PEM file, or a directory of PEM files
    PemFileOrDirectory(&'a Path),
}

/// Private key or certificate secret.
///
/// Mirrors wolfssl's `Secret` enum — data is borrowed, not owned.
/// The actual BoringSSL loading happens in the context builder when these
/// values are consumed.
#[derive(Debug, Clone, Copy)]
pub enum Secret<'a> {
    /// In-memory DER/ASN1 buffer
    Asn1Buffer(&'a [u8]),
    /// Path to a DER/ASN1 file
    Asn1File(&'a Path),
    /// In-memory PEM buffer
    PemBuffer(&'a [u8]),
    /// Path to a PEM file
    PemFile(&'a Path),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_creation() {
        let secret_data = b"test secret data";
        // Secret is now an enum with borrowed data, matching wolfssl's API
        let secret = Secret::PemBuffer(secret_data);
        assert!(matches!(secret, Secret::PemBuffer(b"test secret data")));

        let secret = Secret::Asn1Buffer(secret_data);
        assert!(matches!(secret, Secret::Asn1Buffer(_)));
    }
}
