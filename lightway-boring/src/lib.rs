//! BoringSSL-backed TLS/DTLS abstraction layer for Lightway.
//!
//! This crate provides TLS 1.3 and DTLS 1.3 support using BoringSSL,
//! designed as a drop-in replacement for the `wolfssl` crate.
//!
//! All public types are re-exported at the crate root for convenience:
//!
//! ```rust,ignore
//! use lightway_boring::{
//!     ContextBuilder, Context, Session, SessionConfig,
//!     Method, CurveGroup, IOCallbacks, IOCallbackResult,
//!     RootCertificate, Secret,
//!     Error, ErrorKind, Poll, PollResult,
//! };
//! ```

mod aes256;
mod cert;
mod chacha20_poly1305;
mod config;
mod context;
#[cfg(feature = "debug")]
mod debug;
mod error;
mod session;
#[cfg(test)]
mod test_utils;
mod types;

// Re-export all public types at crate root (drop-in replacement for wolfssl crate)
pub use aes256::{Aes256Gcm, Aes256GcmError};
pub use boring::version::version as get_version_string;
pub use cert::{RootCertificate, Secret};
pub use chacha20_poly1305::Chacha20Poly1305Aead;
pub use config::SessionConfig;
pub use context::{Context, ContextBuilder};
pub use error::{Error, ErrorKind, NewContextBuilderError, NewSessionError, TlsError};
pub use session::Session;
pub use types::{
    CurveGroup, IOCallbackResult, IOCallbacks, Method, Poll, PollResult, ProtocolVersion,
};

#[cfg(feature = "debug")]
pub use debug::{
    LoggingCallback, Tls13SecretCallbacks, Tls13SecretCallbacksArg, enable_debugging,
    install_logging_callback,
};
