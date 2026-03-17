//! Error types for the TLS/DTLS abstraction layer.
//!
//! Provides error enums for context building and session creation.
use boring::error::ErrorStack;
use thiserror::Error;

/// Errors that can occur when building or using TLS/DTLS contexts
#[derive(Debug, Error)]
pub enum TlsError {
    /// BoringSSL error
    #[error("BoringSSL error: {0}")]
    BoringSSL(#[from] ErrorStack),

    /// Invalid parameter
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Error when creating a new context builder
#[derive(Debug, Error)]
#[error("Failed to create context builder: {0}")]
pub struct NewContextBuilderError(pub String);

impl From<TlsError> for NewContextBuilderError {
    fn from(e: TlsError) -> Self {
        NewContextBuilderError(e.to_string())
    }
}

/// Error when creating a new session
#[derive(Debug, Error)]
#[error("Failed to create session: {0}")]
pub struct NewSessionError(pub String);

impl From<TlsError> for NewSessionError {
    fn from(e: TlsError) -> Self {
        NewSessionError(e.to_string())
    }
}

#[derive(Debug, Error)]
pub enum Error {
    /// Fatal error with specific kind
    #[error("Fatal error: {0:?}")]
    Fatal(ErrorKind),
    /// TLS context/configuration error
    #[error("TLS error: {0}")]
    Tls(#[from] TlsError),
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        match self {
            Error::Fatal(kind) => kind.clone(),
            Error::Tls(e) => ErrorKind::Other {
                what: e.to_string(),
                code: 0,
            },
        }
    }
}

/// TLS/DTLS error kinds
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    /// Domain name mismatch during certificate verification
    DomainNameMismatch,
    /// Certificate verification failed (expired, invalid signature, untrusted CA, etc.)
    CertVerificationFailed,
    /// Duplicate message
    DuplicateMessage,
    /// Peer closed connection
    PeerClosed,
    /// CA certificate not available
    CaCertNotAvailable,
    /// Generic fatal error
    Other { what: String, code: i32 },
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_and_kind() {
        let err = Error::Fatal(ErrorKind::DomainNameMismatch);
        assert!(format!("{}", err).contains("Fatal"));
        assert_eq!(err.kind(), ErrorKind::DomainNameMismatch);

        let err = Error::Fatal(ErrorKind::Other {
            what: "test error".to_string(),
            code: 0,
        });
        assert!(format!("{}", err).contains("Fatal"));
        assert!(matches!(err.kind(), ErrorKind::Other { .. }));

        let tls_err = Error::Tls(TlsError::InvalidParameter("bad param".into()));
        assert!(format!("{}", tls_err).contains("TLS error"));
        assert!(matches!(tls_err.kind(), ErrorKind::Other { .. }));
    }
}
