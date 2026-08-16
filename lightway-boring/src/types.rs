//! Core types for the TLS/DTLS abstraction layer.
//!
//! Defines protocol methods, curve groups, protocol versions, I/O callback
//! traits and result types used across the lightway module.

use bytes::Bytes;

use super::error::{Error, TlsError};

/// Protocol method for TLS/DTLS connections
#[derive(Debug, Clone, Copy)]
pub enum Method {
    /// TLS 1.2 client (TCP)
    TlsClientV1_2,
    /// TLS 1.3 client (TCP)
    TlsClientV1_3,
    /// TLS 1.3 server (TCP)
    TlsServerV1_3,
    /// DTLS 1.3 client (UDP)
    DtlsClientV1_3,
    /// DTLS 1.3 server (UDP)
    DtlsServerV1_3,
}

impl Method {
    pub fn is_dtls(self) -> bool {
        !self.is_tls()
    }
    pub fn is_tls(self) -> bool {
        match self {
            Method::TlsClientV1_2 | Method::TlsServerV1_3 | Method::TlsClientV1_3 => true,
            Method::DtlsClientV1_3 | Method::DtlsServerV1_3 => false,
        }
    }
    pub fn is_v1_3(self) -> bool {
        match self {
            Method::TlsClientV1_2 => false,
            Method::TlsClientV1_3 | Method::TlsServerV1_3 => true,
            Method::DtlsClientV1_3 | Method::DtlsServerV1_3 => true,
        }
    }
    pub fn is_server(self) -> bool {
        match self {
            Method::TlsClientV1_2 | Method::DtlsClientV1_3 | Method::TlsClientV1_3 => false,
            Method::TlsServerV1_3 | Method::DtlsServerV1_3 => true,
        }
    }
    pub fn is_client(self) -> bool {
        !self.is_server()
    }
}

/// Elliptic curve groups for key exchange.
///
/// A subset of the wolfssl `CurveGroup` enum, listing only the groups
/// BoringSSL accepts as a TLS key share. lightway-core gates wolfssl-only
/// variants with `#[cfg(wolfssl)]` so both backends share the same call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurveGroup {
    // ── Classical curves ──────────────────────────────────────────────
    /// P-256 (secp256r1)
    /// Maps to: SSL_GROUP_SECP256R1
    EccSecp256R1,

    /// X25519
    /// Maps to: SSL_GROUP_X25519
    EccX25519,

    /// X25519 + ML-KEM-768 — exact match in BoringSSL
    /// Maps to: SSL_GROUP_X25519_MLKEM768
    X25519MLKEM768,
}

impl CurveGroup {
    /// Convert to the BoringSSL TLS group ID (`SSL_GROUP_*`) for this group.
    ///
    /// These are IANA-assigned TLS group identifiers, used with the
    /// `SSL_CTX_set1_group_ids` / `SSL_set1_group_ids` APIs.
    pub fn to_ssl_group(self) -> Result<u16, TlsError> {
        use boring_sys::*;

        match self {
            CurveGroup::EccSecp256R1 => Ok(SSL_GROUP_SECP256R1 as u16),
            CurveGroup::EccX25519 => Ok(SSL_GROUP_X25519 as u16),
            CurveGroup::X25519MLKEM768 => Ok(SSL_GROUP_X25519_MLKEM768 as u16),
        }
    }

    pub fn is_pq(self) -> bool {
        !matches!(self, CurveGroup::EccX25519 | CurveGroup::EccSecp256R1)
    }
}

/// SSL verification mode.
#[derive(Debug, Default, Copy, Clone)]
pub enum SslVerifyMode {
    /// No verification done
    /// Note: Unlike WolfSSL, BoringSSL still verifies the cert under this mode, it just doesn't abort the connection. `verify_result()` still stores the verification result.
    SslVerifyNone,
    /// Verify peers certificate
    #[default]
    SslVerifyPeer,
}

impl From<SslVerifyMode> for boring::ssl::SslVerifyMode {
    fn from(value: SslVerifyMode) -> Self {
        match value {
            SslVerifyMode::SslVerifyNone => boring::ssl::SslVerifyMode::NONE,
            SslVerifyMode::SslVerifyPeer => boring::ssl::SslVerifyMode::PEER,
        }
    }
}

/// Protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    /// Unknown protocol version
    Unknown,
    /// TLS 1.2
    TlsV1_2,
    /// TLS 1.3 (alias for compatibility)
    TlsV1_3,
    /// DTLS 1.3
    DtlsV1_3,
}

impl ProtocolVersion {
    /// Get string representation of protocol version
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtocolVersion::Unknown => "unknown",
            ProtocolVersion::TlsV1_3 => "tls_1_3",
            ProtocolVersion::DtlsV1_3 => "dtls_1_3",
            ProtocolVersion::TlsV1_2 => "tls_1_2",
        }
    }
}

/// Trait for TLS/DTLS I/O callbacks
///
/// Implementors provide the underlying transport (TCP/UDP) for the TLS session.
/// This matches the wolfssl-rs `IOCallbacks` trait.
pub trait IOCallbacks {
    fn recv(&mut self, buf: &mut [u8]) -> IOCallbackResult;
    fn send(&mut self, buf: &[u8]) -> IOCallbackResult;
}

/// Result of IO callback operations
#[derive(Debug)]
pub enum IOCallbackResult<T = usize> {
    /// Operation succeeded
    Ok(T),
    /// Would block (EAGAIN/EWOULDBLOCK)
    WouldBlock,
    /// Error occurred
    Err(std::io::Error),
}

impl<T> IOCallbackResult<T> {
    /// Check if this is Ok
    pub fn is_ok(&self) -> bool {
        matches!(self, IOCallbackResult::Ok(_))
    }

    /// Check if this is WouldBlock
    pub fn is_would_block(&self) -> bool {
        matches!(self, IOCallbackResult::WouldBlock)
    }

    /// Check if this is an error
    pub fn is_err(&self) -> bool {
        matches!(self, IOCallbackResult::Err(_))
    }
}

impl From<Result<usize, std::io::Error>> for IOCallbackResult<usize> {
    fn from(result: Result<usize, std::io::Error>) -> Self {
        match result {
            Ok(n) => IOCallbackResult::Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => IOCallbackResult::WouldBlock,
            Err(e) => IOCallbackResult::Err(e),
        }
    }
}

/// Poll result for TLS/DTLS operations
#[derive(Debug)]
pub enum Poll<T> {
    /// Pending write operation
    PendingWrite,
    /// Pending read operation
    PendingRead,
    /// An output has been generated.
    Ready(T),
    /// This is added for parity with wolfSSL.
    /// TLS1.3 removes the renegotiation that
    /// causes interleaved app data.
    AppData(Bytes),
}

/// Result type alias for TLS poll operations
pub type PollResult<T> = Result<Poll<T>, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curve_group_to_ssl_group() {
        assert!(CurveGroup::EccSecp256R1.to_ssl_group().is_ok());
        assert!(CurveGroup::EccX25519.to_ssl_group().is_ok());
        assert!(CurveGroup::X25519MLKEM768.to_ssl_group().is_ok());
    }

    #[test]
    fn test_iocallback_result_conversions() {
        // Test Ok conversion
        let result: IOCallbackResult<usize> = Ok(42).into();
        assert!(result.is_ok());
        assert!(!result.is_would_block());
        assert!(!result.is_err());

        // Test WouldBlock conversion
        let result: IOCallbackResult<usize> =
            Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "test")).into();
        assert!(!result.is_ok());
        assert!(result.is_would_block());
        assert!(!result.is_err());

        // Test UnexpectedEof maps to Err
        let result: IOCallbackResult<usize> = Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "test",
        ))
        .into();
        assert!(!result.is_ok());
        assert!(!result.is_would_block());
        assert!(result.is_err());
        assert!(matches!(result, IOCallbackResult::Err(_)));

        // Test other error conversion
        let result: IOCallbackResult<usize> = Err(std::io::Error::other("test")).into();
        assert!(!result.is_ok());
        assert!(!result.is_would_block());
        assert!(result.is_err());
    }

    #[test]
    fn test_post_quantum_curves() {
        // Verify all PQ curves are available
        let curves = vec![CurveGroup::X25519MLKEM768];

        for curve in curves {
            assert!(curve.to_ssl_group().is_ok());
        }
    }
}
