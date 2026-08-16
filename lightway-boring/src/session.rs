//! TLS/DTLS session backed by BoringSSL.
//!
//! [`Session`] wraps a BoringSSL `SslStream` and provides handshake negotiation,
//! application data read/write with buffered partial-write support, and
//! WolfSSL-compatible accessors for protocol version, cipher, curve, and DTLS
//! timeout information.

#![allow(unsafe_code)]

// Required for BoringSSL FFI
use super::{IOCallbackResult, IOCallbacks, ProtocolVersion, TlsError};
use boring::ssl::{ErrorCode, ShutdownResult, Ssl, SslMode, SslStream};
use boring::x509::X509VerifyError;
use boring::x509::verify::X509VerifyFlags;
use bytes::{Buf, BytesMut};
use foreign_types::ForeignTypeRef;

use super::config::SessionConfig;
use super::context::Context;
use std::time::Duration;

/// Poll interval reported when DTLS has no retransmit timer armed (handshake not
/// started yet or already finished). BoringSSL returns 0 from
/// `DTLSv1_get_timeout` in that state; we surface a non-zero default so callers
/// re-poll periodically instead of treating it as "fire immediately".
const DTLS_DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(1000);

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
    pending_key_update: bool,
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
        let is_client = context.method.is_client();
        let is_dtls = context.method.is_dtls();

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
        }

        // Per-session verify mode overrides the context-level SSL_CTX_set_verify,
        // matching wolfssl's wolfSSL_set_verify behavior. No verify callback.
        if let Some(mode) = config.ssl_verify_mode {
            ssl.set_verify(mode.into());
        }

        // Configure key share group if specified
        if let Some(group) = config.keyshare_group {
            let group_id = group.to_ssl_group()?;
            // SAFETY: `ssl.as_ptr()` is the SSL owned by `ssl`, valid for this
            // call. `key_shares` is a stack array valid for its length;
            // SSL_set1_client_key_shares copies the group ids and does not
            // retain the pointer.
            unsafe {
                let ssl_ptr = ssl.as_ptr();
                if is_client && group.is_pq() {
                    let key_shares: [u16; 1] = [group_id];
                    let ret = boring_sys::SSL_set1_client_key_shares(
                        ssl_ptr,
                        key_shares.as_ptr(),
                        key_shares.len(),
                    );
                    if ret != 1 {
                        return Err(super::TlsError::InvalidParameter(
                            "Failed to set client key shares".into(),
                        ));
                    }
                }
            }
        }

        // No per-session keylog hook: BoringSSL only exposes keylog at the
        // SSL_CTX level, wired via ContextBuilder::with_key_logger.

        // Create BIO adapter and SSL stream
        let bio_adapter = BioAdapter { io: config.io };
        let ssl_stream = SslStream::new(ssl, bio_adapter)?;

        Ok(Self {
            ssl_stream,
            is_client,
            is_dtls,
            pending_key_update: false,
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
                // A successful SSL_write flushes any queued KeyUpdate, so the
                // key rotation is committed even if the transport write is partial.
                self.pending_key_update = false;
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
        // SAFETY: `ssl().as_ptr()` is the SSL owned by the SslStream, valid for
        // this call; SSL_key_update only mutates that SSL's state.
        unsafe {
            let ssl_ptr = self.ssl_stream.ssl().as_ptr();
            let ret = boring_sys::SSL_key_update(ssl_ptr, boring_sys::SSL_KEY_UPDATE_NOT_REQUESTED);
            if ret != 1 {
                return Err(super::Error::Fatal(super::ErrorKind::Other {
                    what: format!("SSL_key_update failed (ret={})", ret),
                    code: ret,
                }));
            }
        }
        self.pending_key_update = true;
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

    /// Sets verification method for remote peers via `SSL_set_verify`.
    pub fn set_verify(&mut self, mode: super::SslVerifyMode) {
        self.ssl_stream.ssl_mut().set_verify(mode.into());
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
    pub fn dtls_current_timeout(&mut self) -> Duration {
        if !self.is_dtls {
            return Duration::from_millis(0); // Not DTLS
        }
        // SAFETY: `ssl().as_ptr()` is the SSL owned by the SslStream, valid for
        // this call. `tv` is a stack timeval; `zeroed` is a valid bit pattern
        // for it, and DTLSv1_get_timeout only reads the SSL and writes `tv`.
        unsafe {
            let ssl_ptr = self.ssl_stream.ssl().as_ptr();
            let mut tv = std::mem::zeroed::<libc::timeval>();
            if DTLSv1_get_timeout(ssl_ptr, &mut tv) == 1 {
                Duration::new(tv.tv_sec as u64, (tv.tv_usec as u32) * 1000)
            } else {
                // No active timer (handshake not in flight).
                DTLS_DEFAULT_POLL_INTERVAL
            }
        }
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

    /// Handle an expired DTLS retransmit timer (wraps `DTLSv1_handle_timeout`).
    ///
    /// The return value breaks the usual convention (BoringSSL's own header
    /// warns about this):
    ///   0  => no timer had expired, nothing to do
    ///   1  => the flight was retransmitted
    ///   -1 => error; SSL_get_error must be consulted to interpret it
    ///
    /// A -1 is NOT automatically fatal. If the retransmit could not be written
    /// because the transport would block, SSL_get_error reports
    /// SSL_ERROR_WANT_WRITE and the caller retries when writable. Only a
    /// different error is a genuine timeout. Do NOT collapse this to
    /// `ret != 1 => fatal`: that turns ordinary write backpressure into a
    /// dropped connection.
    ///
    /// Ref: <https://github.com/google/boringssl/blob/master/include/openssl/ssl.h> (DTLSv1_handle_timeout)
    pub fn dtls_has_timed_out(&mut self) -> super::Poll<bool> {
        if !self.is_dtls {
            return super::Poll::Ready(false);
        }
        // SAFETY: `ssl().as_ptr()` is the SSL owned by the SslStream, valid for
        // these calls; DTLSv1_handle_timeout and SSL_get_error only operate on
        // that SSL.
        unsafe {
            let ssl_ptr = self.ssl_stream.ssl().as_ptr();
            match DTLSv1_handle_timeout(ssl_ptr) {
                0 => super::Poll::Ready(false), // no timer expired
                1 => super::Poll::Ready(false), // retransmitted the flight
                ret => {
                    // -1: classify via SSL_get_error. WANT_WRITE = transport
                    // backpressure, retry when writable (documented by the
                    // header).
                    let err = boring_sys::SSL_get_error(ssl_ptr, ret);
                    match err {
                        boring_sys::SSL_ERROR_WANT_WRITE => super::Poll::PendingWrite,
                        boring_sys::SSL_ERROR_WANT_READ => super::Poll::PendingRead,
                        _ => super::Poll::Ready(true),
                    }
                }
            }
        }
    }

    /// Try to negotiate the handshake (WolfSSL compatibility)
    pub fn try_negotiate(&mut self) -> super::PollResult<()> {
        self.poll()
    }

    /// Get protocol version (WolfSSL compatibility alias)
    pub fn version(&self) -> ProtocolVersion {
        match self.ssl_stream.ssl().version_str() {
            "TLSv1.2" => ProtocolVersion::TlsV1_2,
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

    /// Send a close_notify, returning a `Poll<bool>`.
    ///
    /// `Ready(false)` means our close_notify was sent; `Ready(true)` means the
    /// peer's close_notify was received. WANT_READ / WANT_WRITE map to
    /// PendingRead / PendingWrite.
    pub fn try_shutdown(&mut self) -> super::PollResult<bool> {
        match self.ssl_stream.shutdown() {
            Ok(ShutdownResult::Sent) => Ok(super::Poll::Ready(false)),
            Ok(ShutdownResult::Received) => Ok(super::Poll::Ready(true)),
            Err(ref e) if e.code() == ErrorCode::WANT_WRITE => Ok(super::Poll::PendingWrite),
            Err(ref e) if e.code() == ErrorCode::WANT_READ => Ok(super::Poll::PendingRead),
            Err(e) => Err(super::Error::Fatal(super::ErrorKind::Other {
                what: format!("Shutdown failed: {:?}", e.code()),
                code: e.code().as_raw(),
            })),
        }
    }

    /// Check if key update is pending (TLS 1.3 compatibility)
    pub fn is_update_keys_pending(&self) -> bool {
        self.pending_key_update
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

// Declared by hand: boring-sys at the pinned revision does not bind the DTLS
// timeout helpers, so we link BoringSSL's exported symbols directly.
unsafe extern "C" {
    /// Ref: <https://github.com/google/boringssl/blob/master/include/openssl/ssl.h> (DTLSv1_get_timeout)
    fn DTLSv1_get_timeout(ssl: *const boring_sys::SSL, out: *mut libc::timeval) -> i32;
    /// Ref: <https://github.com/google/boringssl/blob/master/include/openssl/ssl.h> (DTLSv1_handle_timeout)
    fn DTLSv1_handle_timeout(ssl: *mut boring_sys::SSL) -> i32;
}

#[cfg(test)]
mod tests {
    use crate::test_utils::mock::{
        MockIOAdapter, TcpIOCallbacks, UdpIOCallbacks, make_connected_dtls_pair,
        make_connected_tls_pair,
    };
    use crate::{
        ContextBuilder, CurveGroup, IOCallbackResult, IOCallbacks, Method, Poll, SessionConfig,
    };
    use std::time::Duration;

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

        assert_eq!(
            client_curve.as_deref(),
            Some("X25519MLKEM768"),
            "client should report X25519MLKEM768 as the negotiated curve"
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

    #[test]
    fn try_trigger_update_key() {
        use bytes::BytesMut;

        let (mut client, mut _server) = make_connected_tls_pair();

        let result = client.try_trigger_update_key();
        assert!(
            matches!(result, Ok(Poll::Ready(()))),
            "try_trigger_update_key failed: {:?}",
            result
        );

        // The queued KeyUpdate is flushed on the next ssl_write.
        let mut buf = BytesMut::from(b"post-key-update".as_ref());
        let result = client.try_write(&mut buf);
        assert!(
            result.is_ok(),
            "try_write after key update failed: {:?}",
            result
        );
    }

    #[test]
    fn is_update_keys_pending_clears_on_write() {
        use bytes::BytesMut;

        let (mut client, mut _server) = make_connected_tls_pair();

        client.try_trigger_update_key().unwrap();
        assert!(
            client.is_update_keys_pending(),
            "expected pending_key_update=true"
        );

        let mut buf = BytesMut::from(b"data".as_ref());
        let result = client.try_write(&mut buf).unwrap();
        assert!(
            matches!(result, Poll::Ready(_)),
            "expected Ready after write, got {:?}",
            result
        );
        assert!(
            !client.is_update_keys_pending(),
            "expected pending_key_update=false after write"
        );
    }

    #[test]
    fn test_dtls_current_timeout() {
        let ctx = ContextBuilder::new(Method::DtlsClientV1_3).unwrap().build();
        let mut session = ctx
            .new_session(SessionConfig::new(MockIOAdapter::new()))
            .unwrap();
        let timeout = session.dtls_current_timeout();
        assert_eq!(timeout, Duration::from_millis(1000));
    }

    #[test]
    fn test_dtls_current_timeout_non_dtls() {
        let ctx = ContextBuilder::new(Method::TlsClientV1_3).unwrap().build();
        let mut session = ctx
            .new_session(SessionConfig::new(MockIOAdapter::new()))
            .unwrap();
        let timeout = session.dtls_current_timeout();
        assert_eq!(timeout, Duration::from_millis(0));
    }

    #[test]
    fn test_dtls_has_timed_out_non_dtls() {
        let ctx = ContextBuilder::new(Method::TlsClientV1_3).unwrap().build();
        let mut session = ctx
            .new_session(SessionConfig::new(MockIOAdapter::new()))
            .unwrap();
        let result = session.dtls_has_timed_out();
        assert!(matches!(result, Poll::Ready(false)));
    }

    #[test]
    fn test_dtls_has_timed_out_no_timeout() {
        let ctx = ContextBuilder::new(Method::DtlsClientV1_3).unwrap().build();
        let mut session = ctx
            .new_session(SessionConfig::new(MockIOAdapter::new()))
            .unwrap();
        // No time has passed, so no timeout should have expired
        let result = session.dtls_has_timed_out();
        assert!(matches!(result, Poll::Ready(false)));
    }

    #[test]
    fn try_shutdown_tls() {
        let (mut client, mut _server) = make_connected_tls_pair();
        // Shutdown should not panic or return a fatal error.
        // The first call sends our close_notify (Sent = Ready(false)).
        // Under single-threaded in-memory IO the peer alert may or may not
        // have arrived yet, so we accept Sent, Received, or pending states.
        let result = client.try_shutdown();
        assert!(result.is_ok(), "try_shutdown returned error: {:?}", result);
        let poll = result.unwrap();
        assert!(
            matches!(
                poll,
                Poll::Ready(_) | Poll::PendingRead | Poll::PendingWrite
            ),
            "unexpected shutdown poll: {:?}",
            poll
        );
    }

    #[test]
    fn test_session_with_keyshare_group_classical() {
        let ctx = ContextBuilder::new(Method::TlsClientV1_3).unwrap().build();
        let config =
            SessionConfig::new(MockIOAdapter::new()).with_keyshare_group(CurveGroup::EccX25519);
        // Session creation succeeds → SSL_set1_group_ids accepted the group
        ctx.new_session(config).unwrap();
    }

    #[test]
    fn test_session_with_keyshare_group_pq() {
        let ctx = ContextBuilder::new(Method::TlsClientV1_3)
            .unwrap()
            .with_groups(&[CurveGroup::X25519MLKEM768])
            .unwrap()
            .build();
        let config = SessionConfig::new(MockIOAdapter::new())
            .with_keyshare_group(CurveGroup::X25519MLKEM768);
        ctx.new_session(config).unwrap();
    }

    #[test]
    fn test_session_with_each_curve_group() {
        let classical_groups = [CurveGroup::EccSecp256R1, CurveGroup::EccX25519];

        for group in classical_groups {
            let ctx = ContextBuilder::new(Method::TlsClientV1_3).unwrap().build();
            let config = SessionConfig::new(MockIOAdapter::new()).with_keyshare_group(group);
            ctx.new_session(config)
                .unwrap_or_else(|e| panic!("Session creation failed for {:?}: {}", group, e));
        }

        {
            let pq_groups = [CurveGroup::X25519MLKEM768];

            for group in pq_groups {
                // The context must include all PQ groups in its supported list
                // so that SSL_set1_client_key_shares can reference them.
                let ctx = ContextBuilder::new(Method::TlsClientV1_3)
                    .unwrap()
                    .with_groups(&pq_groups)
                    .unwrap()
                    .build();
                let config = SessionConfig::new(MockIOAdapter::new()).with_keyshare_group(group);
                ctx.new_session(config)
                    .unwrap_or_else(|e| panic!("Session creation failed for {:?}: {}", group, e));
            }
        }
    }

    /// Check that the SNI should remain empty even if domain name is given.
    /// In other words, do not default the SNI to domain name even if the SNI is not explictly given.
    ///
    /// This is done to match wolfssl's default behaviour. Not matching the 2 lib behaviour would allow
    /// a easier detection of wolfssl and boringssl backends.
    #[test]
    fn test_domain_name_is_not_sent_as_sni() {
        // Build a client session with the given config and capture the raw
        // ClientHello bytes it emits on the first negotiate step.
        let capture_client_hello =
            |config_fn: &dyn Fn(SessionConfig<TcpIOCallbacks>) -> SessionConfig<TcpIOCallbacks>| {
                let ctx = ContextBuilder::new(Method::TlsClientV1_3).unwrap().build();
                let (client_io, mut peer_io) = TcpIOCallbacks::pair();
                let mut session = ctx
                    .new_session(config_fn(SessionConfig::new(client_io)))
                    .unwrap();
                let _ = session.try_negotiate();

                let mut wire = Vec::new();
                let mut buf = [0u8; 4096];
                while let IOCallbackResult::Ok(n) = peer_io.recv(&mut buf) {
                    wire.extend_from_slice(&buf[..n]);
                }
                assert!(!wire.is_empty(), "no ClientHello captured");
                wire
            };

        let domain = b"example.com";
        let contains = |wire: &[u8]| wire.windows(domain.len()).any(|w| w == domain);

        let wire = capture_client_hello(&|c| c.with_sni("example.com"));
        assert!(
            contains(&wire),
            "explicitly configured SNI missing from the ClientHello"
        );

        let wire = capture_client_hello(&|c| c.with_checked_domain_name("example.com"));
        assert!(
            !contains(&wire),
            "checked_domain_name leaked into the ClientHello as SNI"
        );
    }
}
