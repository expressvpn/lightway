//! TLS/DTLS context builder and context.
//!
//! [`ContextBuilder`] configures TLS/DTLS parameters (method, certificates,
//! cipher list, curve groups) and produces a [`Context`] which can create
//! [`Session`]s for individual connections.
//!
//! Like wolfssl's `ContextBuilder`, each `with_*` method immediately applies
//! the configuration to the underlying BoringSSL `SSL_CTX`.

#![allow(unsafe_code)]
use crate::error::Result;
use crate::NewContextBuilderError;

use super::{CurveGroup, IOCallbacks, Method, RootCertificate, Secret, TlsError};
use boring::error::ErrorStack;
use boring::pkey::PKey;
use boring::ssl::{SslContext, SslContextBuilder, SslMethod, SslVerifyMode, SslVersion};
use boring::x509::store::X509StoreBuilder;
use boring::x509::X509;

use super::config::SessionConfig;
use super::session::Session;

/// BoringSSL context builder.
///
/// Wraps `SslContextBuilder` directly — each `with_*` call configures
/// the underlying SSL_CTX immediately, just like the wolfssl backend.
pub struct ContextBuilder {
    builder: SslContextBuilder,
    method: Method,
}

impl ContextBuilder {
    /// Create a new BoringSSL context builder
    pub fn new(method: Method) -> std::result::Result<Self, NewContextBuilderError> {
        let mut builder = match method {
            Method::TlsClientV1_3 => SslContext::builder(SslMethod::tls()),
            Method::TlsServerV1_3 => SslContext::builder(SslMethod::tls()),
            Method::DtlsClientV1_3 | Method::DtlsServerV1_3 => {
                SslContext::builder(SslMethod::dtls())
            }
        }
        .map_err(|e| NewContextBuilderError(e.to_string()))?;

        if matches!(method, Method::DtlsClientV1_3 | Method::TlsClientV1_3) {
            builder.set_verify(SslVerifyMode::PEER);
        }

        // Set TLS 1.3 or DTLS 1.3 only
        match method {
            Method::TlsClientV1_3 | Method::TlsServerV1_3 => {
                builder
                    .set_min_proto_version(Some(SslVersion::TLS1_3))
                    .map_err(|e| NewContextBuilderError(e.to_string()))?;
                builder
                    .set_max_proto_version(Some(SslVersion::TLS1_3))
                    .map_err(|e| NewContextBuilderError(e.to_string()))?;
            }
            Method::DtlsClientV1_3 | Method::DtlsServerV1_3 => {
                builder
                    .set_min_proto_version(Some(SslVersion::DTLS1_3))
                    .map_err(|e| NewContextBuilderError(e.to_string()))?;
                builder
                    .set_max_proto_version(Some(SslVersion::DTLS1_3))
                    .map_err(|e| NewContextBuilderError(e.to_string()))?;
            }
        }

        Ok(Self { builder, method })
    }

    /// When `cond` is True call fallible `func` on `Self`
    pub fn try_when<F>(self, cond: bool, func: F) -> Result<Self>
    where
        F: FnOnce(Self) -> Result<Self>,
    {
        if cond {
            func(self)
        } else {
            Ok(self)
        }
    }

    /// When `maybe` is Some(_) call fallible `func` on `Self` and the contained value
    pub fn try_when_some<F, T>(self, maybe: Option<T>, func: F) -> Result<Self>
    where
        F: FnOnce(Self, T) -> Result<Self>,
    {
        if let Some(t) = maybe {
            func(self, t)
        } else {
            Ok(self)
        }
    }

    /// Load a root certificate into the SSL context immediately.
    pub fn with_root_certificate(mut self, cert: RootCertificate) -> Result<Self> {
        let mut store_builder = X509StoreBuilder::new().map_err(TlsError::BoringSSL)?;

        let certs = match cert {
            RootCertificate::Asn1Buffer(buf) => {
                vec![X509::from_der(buf).map_err(TlsError::BoringSSL)?]
            }
            RootCertificate::PemBuffer(buf) => {
                X509::stack_from_pem(buf).map_err(TlsError::BoringSSL)?
            }
            RootCertificate::PemFileOrDirectory(path) => {
                let data = std::fs::read(path).map_err(TlsError::Io)?;
                X509::stack_from_pem(&data).map_err(TlsError::BoringSSL)?
            }
        };

        for c in certs {
            store_builder.add_cert(&c).map_err(TlsError::BoringSSL)?;
        }
        self.builder
            .set_verify_cert_store(store_builder.build())
            .map_err(TlsError::BoringSSL)?;

        Ok(self)
    }

    /// Load a private key into the SSL context immediately.
    pub fn with_private_key(mut self, key: Secret) -> Result<Self> {
        let data = read_secret(key)?;

        // Try DER first, fallback to PEM
        let pkey = match PKey::private_key_from_der(&data) {
            Ok(k) => k,
            Err(_) => PKey::private_key_from_pem(&data).map_err(TlsError::BoringSSL)?,
        };
        self.builder
            .set_private_key(&pkey)
            .map_err(TlsError::BoringSSL)?;

        Ok(self)
    }

    /// Load a certificate into the SSL context immediately.
    pub fn with_certificate(mut self, cert: Secret) -> Result<Self> {
        let data = read_secret(cert)?;

        // Try DER first, fallback to PEM
        let x509 = match X509::from_der(&data) {
            Ok(c) => c,
            Err(_) => X509::from_pem(&data).map_err(TlsError::BoringSSL)?,
        };
        self.builder
            .set_certificate(&x509)
            .map_err(TlsError::BoringSSL)?;

        Ok(self)
    }

    /// Set the cipher list (no-op for TLS 1.3 / DTLS 1.3).
    ///
    /// BoringSSL uses secure defaults for TLS 1.3 ciphersuites.
    /// This method exists only for API compatibility with the WolfSSL backend.
    pub fn with_cipher_list(self, _cipher_list: &str) -> Result<Self> {
        Ok(self)
    }

    /// Set the supported curve groups.
    pub fn with_groups(self, groups: &[CurveGroup]) -> Result<Self> {
        let group_ids = groups
            .iter()
            .map(|g| g.to_ssl_group())
            .collect::<std::result::Result<Vec<_>, TlsError>>()?;

        if !group_ids.is_empty() {
            // SAFETY: `builder.as_ptr()` is the SSL_CTX owned by this builder,
            // valid for the call. SSL_CTX_set1_group_ids copies the ids from the
            // slice (valid for its length) and does not retain the pointer.
            unsafe {
                let ctx_ptr = self.builder.as_ptr();
                let result = boring_sys::SSL_CTX_set1_group_ids(
                    ctx_ptr,
                    group_ids.as_ptr(),
                    group_ids.len(),
                );
                if result != 1 {
                    return Err(TlsError::BoringSSL(ErrorStack::get()).into());
                }
            }
        }

        Ok(self)
    }

    /// Finalize and build the context.
    pub fn build(self) -> Context {
        Context {
            ssl_ctx: self.builder.build(),
            method: self.method,
        }
    }
}

/// Read bytes from a Secret enum variant.
fn read_secret(secret: Secret) -> std::result::Result<Vec<u8>, TlsError> {
    match secret {
        Secret::Asn1Buffer(buf) | Secret::PemBuffer(buf) => Ok(buf.to_vec()),
        Secret::Asn1File(path) | Secret::PemFile(path) => std::fs::read(path).map_err(TlsError::Io),
    }
}

/// BoringSSL context — holds a built `SslContext` ready to create sessions.
pub struct Context {
    pub(crate) ssl_ctx: SslContext,
    pub(crate) method: Method,
}

impl Context {
    /// Create a new session from this context
    pub fn new_session<IOCB>(
        &self,
        config: SessionConfig<IOCB>,
    ) -> std::result::Result<Session<IOCB>, super::NewSessionError>
    where
        IOCB: IOCallbacks,
    {
        Session::new(self, config).map_err(|e| super::NewSessionError(e.to_string()))
    }

    /// Check if this is a DTLS context
    pub(crate) fn is_dtls(&self) -> bool {
        matches!(self.method, Method::DtlsClientV1_3 | Method::DtlsServerV1_3)
    }
}
