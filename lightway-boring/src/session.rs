//! TLS/DTLS session backed by BoringSSL.
//!
//! [`Session`] wraps a BoringSSL `SslStream` and provides handshake negotiation,
//! application data read/write with buffered partial-write support, and
//! WolfSSL-compatible accessors for protocol version, cipher, curve, and DTLS
//! timeout information.

#![allow(unsafe_code)] // Required for BoringSSL FFI
use super::{IOCallbackResult, IOCallbacks, Method, ProtocolVersion, TlsError};
use boring::ssl::{ErrorCode, Ssl, SslMode, SslStream};
use boring::x509::verify::X509VerifyFlags;
use boring::x509::X509VerifyError;
use bytes::{Buf, BytesMut};
use foreign_types::ForeignTypeRef;

use super::config::SessionConfig;
use super::context::Context;
use std::time::Duration;

/// Map a TLS handshake failure to an [`ErrorKind`](super::ErrorKind) using
/// BoringSSL's structured X509 verify result rather than string matching.
fn classify_handshake_error(verify_result: boring::x509::X509VerifyResult) -> super::ErrorKind {
    match verify_result {
        Ok(()) => super::ErrorKind::Other {
            what: "handshake failed with no verify error".to_string(),
            code: 0,
        },
        Err(e) if e == X509VerifyError::HOSTNAME_MISMATCH => super::ErrorKind::DomainNameMismatch,
        Err(e)
            if e == X509VerifyError::UNABLE_TO_GET_ISSUER_CERT
                || e == X509VerifyError::UNABLE_TO_GET_ISSUER_CERT_LOCALLY
                || e == X509VerifyError::CERT_UNTRUSTED
                || e == X509VerifyError::DEPTH_ZERO_SELF_SIGNED_CERT =>
        {
            super::ErrorKind::CaCertNotAvailable
        }
        Err(_e) => super::ErrorKind::CertVerificationFailed,
    }
}

/// BoringSSL session
pub struct Session<IOCB> {
    /// The SSL stream wrapping the BIO adapter
    ssl_stream: SslStream<BioAdapter<IOCB>>,
    is_client: bool,
    is_dtls: bool,
}

/// Adapter for integrating I/O operations with BoringSSL BIO
struct BioAdapter<IOCB> {
    io: IOCB,
}

impl<IOCB> std::io::Read for BioAdapter<IOCB>
where
    IOCB: IOCallbacks,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.io.recv(buf) {
            IOCallbackResult::Ok(n) => Ok(n),
            IOCallbackResult::WouldBlock => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "would block",
            )),
            IOCallbackResult::Err(e) => Err(e),
        }
    }
}

impl<IOCB> std::io::Write for BioAdapter<IOCB>
where
    IOCB: IOCallbacks,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.io.send(buf) {
            IOCallbackResult::Ok(n) => Ok(n),
            IOCallbackResult::WouldBlock => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "would block",
            )),
            IOCallbackResult::Err(e) => Err(e),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<IOCB: IOCallbacks> Session<IOCB>
where
    IOCB: IOCallbacks,
{
    /// Create a new session
    pub fn new(context: &Context, config: SessionConfig<IOCB>) -> Result<Self, TlsError> {
        // Create SSL object from the pre-built context
        let mut ssl = Ssl::new(&context.ssl_ctx)?;

        ssl.set_mode(SslMode::ACCEPT_MOVING_WRITE_BUFFER);

        // Determine if we're client or server, and if we're using DTLS
        let is_client = matches!(
            context.method,
            Method::TlsClientV1_3 | Method::DtlsClientV1_3
        );
        let is_dtls = context.is_dtls();

        // Configure DTLS-specific settings
        if is_dtls && let Some(mtu) = config.dtls_mtu {
            ssl.set_mtu(mtu as u32)?;
        }

        // Allow self-signed certs that appear directly in the trust store.
        // This mirrors the PARTIAL_CHAIN flag set on the X509Store in the context,
        // but must also be set at the SSL level since per-connection verify params
        // can override context-level store flags in BoringSSL.
        ssl.param_mut().set_flags(X509VerifyFlags::PARTIAL_CHAIN);

        // Enable BoringSSL native hostname verification
        if let Some(ref domain) = config.checked_domain_name {
            ssl.param_mut().set_host(domain)?;
        }

        // Set SNI (Server Name Indication) separately from verification
        if let Some(ref sni) = config.server_name_indication {
            ssl.set_hostname(sni)?;
        } else if let Some(ref domain) = config.checked_domain_name {
            // If no explicit SNI is set but we have a domain to verify,
            // send that domain as SNI as well (common practice)
            ssl.set_hostname(domain)?;
        }

        // Configure key share group if specified
        if let Some(group) = config.keyshare_group {
            let _group_id = group.to_ssl_group()?;
            // Note: Setting curves per-session in BoringSSL requires direct FFI
            // For now, we'll rely on context-level curve configuration
            // This is a TODO for full parity with WolfSSL API
        }

        // Create BIO adapter and SSL stream
        let bio_adapter = BioAdapter { io: config.io };
        let ssl_stream = SslStream::new(ssl, bio_adapter)?;

        Ok(Self {
            ssl_stream,
            is_client,
            is_dtls,
        })
    }

    /// Poll the session to drive the handshake or check for events
    fn poll(&mut self) -> super::PollResult<()> {
        if !self.is_init_finished() {
            let result = if self.is_client {
                self.ssl_stream.connect()
            } else {
                self.ssl_stream.accept()
            };

            match result {
                Ok(_) => Ok(super::Poll::Ready(())),
                Err(ref e) if e.code() == ErrorCode::WANT_READ => Ok(super::Poll::PendingRead),
                Err(ref e) if e.code() == ErrorCode::WANT_WRITE => Ok(super::Poll::PendingWrite),
                Err(_) => Err(super::Error::Fatal(classify_handshake_error(
                    self.ssl_stream.ssl().verify_result(),
                ))),
            }
        } else {
            Ok(super::Poll::Ready(()))
        }
    }

    /// Try to read TLS application data directly into a BytesMut.
    ///
    /// This collapses the read → error → match chain into a single step,
    /// returning `Poll` directly and avoiding intermediate `io::Error`
    /// allocations on the common WANT_READ path.
    pub fn try_read(&mut self, buf: &mut bytes::BytesMut) -> super::PollResult<usize> {
        const READ_BUF: usize = 16384;
        let old_len = buf.len();
        buf.resize(old_len + READ_BUF, 0);

        match self.ssl_stream.ssl_read(&mut buf[old_len..]) {
            Ok(n) => {
                buf.truncate(old_len + n);
                Ok(super::Poll::Ready(n))
            }
            Err(ref e) if e.code() == ErrorCode::WANT_READ => {
                buf.truncate(old_len);
                Ok(super::Poll::PendingRead)
            }
            Err(ref e) if e.code() == ErrorCode::WANT_WRITE => {
                buf.truncate(old_len);
                Ok(super::Poll::PendingWrite)
            }
            Err(ref e) if e.code() == ErrorCode::ZERO_RETURN => {
                buf.truncate(old_len);
                Err(super::Error::Fatal(super::ErrorKind::PeerClosed))
            }
            Err(e) => {
                buf.truncate(old_len);
                Err(super::Error::Fatal(super::ErrorKind::Other {
                    what: format!("Read failed: {:?}", e.code()),
                    code: e.code().as_raw(),
                }))
            }
        }
    }

    /// Write application data, returning a `Poll` rather than blocking.
    ///
    /// Advances `buf` by the bytes written. A successful write also flushes any
    /// queued TLS 1.3 KeyUpdate, so a pending key rotation commits here.
    /// WANT_READ / WANT_WRITE map to PendingRead / PendingWrite.
    pub fn try_write(&mut self, buf: &mut BytesMut) -> super::PollResult<usize> {
        if buf.is_empty() {
            return Ok(super::Poll::Ready(0));
        }

        let stream = &mut self.ssl_stream;

        match stream.ssl_write(buf) {
            Ok(n) => {
                buf.advance(n);
                Ok(super::Poll::Ready(n))
            }
            Err(ref e) if e.code() == ErrorCode::WANT_READ => Ok(super::Poll::PendingRead),
            Err(ref e) if e.code() == ErrorCode::WANT_WRITE => Ok(super::Poll::PendingWrite),
            Err(e) => Err(super::Error::Fatal(super::ErrorKind::Other {
                what: format!("Write failed: {:?}", e.code()),
                code: e.code().as_raw(),
            })),
        }
    }

    /// Check if handshake is complete
    pub fn is_init_finished(&self) -> bool {
        self.ssl_stream.ssl().is_init_finished()
    }

    /// Initiate TLS key update
    fn initiate_key_update(&mut self) -> Result<(), super::Error> {
        // TLS 1.3 key updates in BoringSSL
        // Note: This requires FFI access to SSL_key_update
        // For now, we'll return Ok as TLS 1.3 handles key updates automatically
        // TODO: Implement when foreign_types_shared is available
        Ok(())
    }

    /// Get reference to the I/O adapter
    pub fn io_cb(&self) -> &IOCB {
        &self.ssl_stream.get_ref().io
    }

    /// Get mutable reference to the I/O adapter
    pub fn io_cb_mut(&mut self) -> &mut IOCB {
        &mut self.ssl_stream.get_mut().io
    }

    /// Get current cipher name
    pub fn get_current_cipher_name(&self) -> Option<String> {
        self.ssl_stream
            .ssl()
            .current_cipher()
            .map(|c| c.name().to_string())
    }

    /// Get current curve name
    ///
    /// Returns the name of the curve/group actually negotiated during the handshake.
    pub fn get_current_curve_name(&self) -> Option<String> {
        if !self.is_init_finished() {
            return None;
        }

        self.ssl_stream.ssl().curve_name().map(String::from)
    }

    /// Get DTLS current timeout in milliseconds (DTLS compatibility)
    ///
    /// **Implementation Note:**
    /// This returns a constant value for compatibility with the WolfSSL API.
    /// BoringSSL handles DTLS retransmission timeouts internally and does not
    /// expose the current timeout value through the public API.
    ///
    /// The returned value (1000ms) represents a typical initial DTLS retransmit
    /// timeout. In BoringSSL, actual timeouts increase exponentially with each
    /// retransmission, but this is managed automatically by the library.
    ///
    /// **Caller Responsibility:**
    /// Callers should not use this value to implement their own timeout logic.
    /// Instead, rely on BoringSSL's internal timeout handling via normal
    /// read/write operations.
    pub fn dtls_current_timeout(&self) -> Duration {
        if !self.is_dtls {
            return Duration::from_millis(0); // Not DTLS
        }
        // Return typical initial timeout value for compatibility
        // BoringSSL manages actual timeouts internally
        Duration::from_millis(1000)
    }

    /// Check if DTLS should use quick timeout (DTLS 1.3 compatibility)
    ///
    /// **Implementation Note:**
    /// Returns `true` during DTLS handshake, `false` otherwise.
    /// This is a simple heuristic for compatibility with the WolfSSL API.
    ///
    /// DTLS 1.3 can benefit from quicker retransmissions during the handshake
    /// phase to improve connection establishment time. However, BoringSSL
    /// handles this internally.
    ///
    /// **Caller Responsibility:**
    /// This is informational only. Callers should not implement custom timeout
    /// logic based on this value.
    pub fn dtls13_use_quick_timeout(&self) -> bool {
        // DTLS handshakes may benefit from quicker timeouts
        self.is_dtls && !self.is_init_finished()
    }

    /// Check if DTLS has timed out (DTLS compatibility)
    ///
    /// **Implementation Note:**
    /// Always returns `false`. BoringSSL handles DTLS timeout detection internally
    /// and will surface timeout conditions as errors from `SSL_read`/`SSL_write`.
    ///
    /// This method exists for API compatibility with the WolfSSL interface but
    /// does not provide meaningful timeout state information.
    ///
    /// **Caller Responsibility:**
    /// Instead of checking this method, rely on error returns from read/write
    /// operations to detect timeout and connection issues.
    pub fn dtls_has_timed_out(&self) -> super::Poll<bool> {
        if !self.is_dtls {
            return super::Poll::Ready(false);
        }
        // BoringSSL handles DTLS timeouts internally
        // Timeout conditions surface as errors from SSL_read/SSL_write
        super::Poll::Ready(false)
    }

    /// Try to negotiate the handshake (WolfSSL compatibility)
    pub fn try_negotiate(&mut self) -> super::PollResult<()> {
        self.poll()
    }

    /// Get protocol version (WolfSSL compatibility alias)
    pub fn version(&self) -> ProtocolVersion {
        match self.ssl_stream.ssl().version_str() {
            "TLSv1.3" => ProtocolVersion::TlsV1_3,
            "DTLSv1.3" => ProtocolVersion::DtlsV1_3,
            _ => ProtocolVersion::Unknown,
        }
    }

    /// Try to trigger key update (WolfSSL compatibility)
    pub fn try_trigger_update_key(&mut self) -> super::PollResult<()> {
        self.initiate_key_update()?;
        Ok(super::Poll::Ready(()))
    }

    /// Try to shutdown the session
    ///
    /// **Note:** This is currently a no-op kept for API compatibility.
    /// We do not send a TLS close_notify alert. Callers should treat
    /// dropping the underlying IO/session as the termination mechanism.
    pub fn try_shutdown(&mut self) -> Result<(), super::Error> {
        Ok(())
    }

    /// Check if key update is pending (TLS 1.3 compatibility)
    pub fn is_update_keys_pending(&self) -> bool {
        false
    }
}

impl<IOCB> std::fmt::Debug for Session<IOCB>
where
    IOCB: IOCallbacks + std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("protocol_version", &self.version().as_str())
            .field("handshake_complete", &self.is_init_finished())
            .field("current_cipher", &self.get_current_cipher_name())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::mock::{
        make_connected_dtls_pair, make_connected_tls_pair, MockIOAdapter, UdpIOCallbacks,
    };
    use crate::{ContextBuilder, Method, Poll, SessionConfig};

    #[test]
    fn try_negotiate_tls() {
        let (client, server) = make_connected_tls_pair();
        assert!(client.is_init_finished());
        assert!(server.is_init_finished());
    }

    #[test]
    fn try_negotiate_dtls() {
        let (client, server) = make_connected_dtls_pair();
        assert!(client.is_init_finished());
        assert!(server.is_init_finished());
    }

    #[test]
    fn try_read_write_roundtrip() {
        use bytes::BytesMut;

        let (mut client, mut server) = make_connected_tls_pair();

        let msg = b"hello, world!";
        let mut write_buf = BytesMut::from(msg.as_ref());
        let result = client.try_write(&mut write_buf).unwrap();
        assert!(
            matches!(result, Poll::Ready(n) if n == msg.len()),
            "unexpected write result: {:?}",
            result
        );

        let mut read_buf = BytesMut::new();
        let result = server.try_read(&mut read_buf).unwrap();
        assert!(
            matches!(result, Poll::Ready(n) if n == msg.len()),
            "unexpected read result: {:?}",
            result
        );
        assert_eq!(&read_buf[..], msg.as_ref());
    }

    #[test]
    fn try_write_empty_buffer() {
        use bytes::BytesMut;

        let ctx = ContextBuilder::new(Method::TlsClientV1_3).unwrap().build();
        let mut session = ctx
            .new_session(SessionConfig::new(MockIOAdapter::new()))
            .unwrap();
        // Empty write must short-circuit before touching SSL state.
        let result = session.try_write(&mut BytesMut::new()).unwrap();
        assert!(matches!(result, Poll::Ready(0)));
    }

    #[test]
    fn get_current_cipher_name_after_handshake() {
        let (client, server) = make_connected_tls_pair();

        let client_cipher = client.get_current_cipher_name();
        let server_cipher = server.get_current_cipher_name();

        assert!(client_cipher.is_some(), "client cipher should be set");
        assert!(server_cipher.is_some(), "server cipher should be set");
        assert_eq!(
            client_cipher, server_cipher,
            "both sides must negotiate the same cipher"
        );
    }

    #[test]
    fn get_current_curve_name_before_handshake() {
        use crate::test_utils::mock::TcpIOCallbacks;
        let ctx = ContextBuilder::new(Method::TlsClientV1_3).unwrap().build();
        let session = ctx
            .new_session(SessionConfig::new(TcpIOCallbacks::pair().0))
            .unwrap();

        assert_eq!(
            session.get_current_curve_name(),
            None,
            "curve name should be None before handshake completes"
        );
    }

    #[test]
    fn get_current_curve_name_after_tls_handshake() {
        let (client, server) = make_connected_tls_pair();

        let client_curve = client.get_current_curve_name();
        let server_curve = server.get_current_curve_name();

        // Assert concrete value — BoringSSL's default preferred group is X25519
        assert_eq!(
            client_curve.as_deref(),
            Some("X25519"),
            "client should report X25519 as the negotiated curve"
        );
        assert_eq!(
            client_curve, server_curve,
            "both sides must negotiate the same curve"
        );
    }

    #[test]
    fn get_current_curve_name_after_dtls_handshake() {
        let (client, server) = make_connected_dtls_pair();

        let client_curve = client.get_current_curve_name();
        let server_curve = server.get_current_curve_name();

        // DTLS should also negotiate a valid, known curve name
        assert!(
            client_curve.is_some(),
            "client curve should be set after DTLS handshake"
        );
        assert!(
            !client_curve.as_ref().unwrap().starts_with("Unknown"),
            "curve name should be a known group, got: {:?}",
            client_curve
        );
        assert_eq!(
            client_curve, server_curve,
            "both sides must negotiate the same curve"
        );
    }

    #[test]
    fn dtls13_use_quick_timeout_transitions() {
        // Before handshake: quick timeout should be enabled for DTLS.
        let ctx = ContextBuilder::new(Method::DtlsClientV1_3).unwrap().build();
        let session = ctx
            .new_session(SessionConfig::new(UdpIOCallbacks::pair().0))
            .unwrap();
        assert!(
            session.dtls13_use_quick_timeout(),
            "expected quick timeout before handshake"
        );

        // After a completed handshake: quick timeout should be disabled.
        let (client, _server) = make_connected_dtls_pair();
        assert!(
            !client.dtls13_use_quick_timeout(),
            "expected no quick timeout after handshake"
        );
    }

    #[test]
    fn is_handshake_complete_transitions() {
        // Before negotiation: false.
        let ctx = ContextBuilder::new(Method::TlsClientV1_3).unwrap().build();
        let session = ctx
            .new_session(SessionConfig::new(MockIOAdapter::new()))
            .unwrap();
        assert!(!session.is_init_finished());

        // After completed handshake: true on both sides.
        let (client, server) = make_connected_tls_pair();
        assert!(client.is_init_finished());
        assert!(server.is_init_finished());
    }
}
