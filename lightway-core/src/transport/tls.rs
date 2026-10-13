//! TLS over a stream, or DTLS over datagrams, through the
//! backend selected at build time.

mod io_adapter;

use std::net::SocketAddr;
use std::time::Duration;

use bytes::BytesMut;

use super::{
    ClientTransportArgs, ClientTransportFactory, PollResult, Transport, TransportArgs,
    TransportCaps, TransportError,
};
use crate::tls::{ErrorKind, IOCallbackResult, Poll, ProtocolVersion, Session};
use crate::{
    BuilderPredicates, Cipher, ConnectionType, IPV4_HEADER_SIZE, MAX_DTLS_HEADER_SIZE,
    OutsideIOSendCallbackArg, RootCertificate, Secret, SessionId, UDP_HEADER_SIZE, wire,
};
use io_adapter::TlsIOAdapter;

/// An error while building a TLS factory.
#[derive(Debug, thiserror::Error)]
pub enum TlsFactoryError {
    /// Failed to create the TLS context builder
    #[error("TLS Error: {0}")]
    FailedNew(#[from] crate::tls::NewContextBuilderError),

    /// A TLS error occurred
    #[error("TLS Error: {0}")]
    Tls(#[from] crate::tls::Error),
}

/// server curves when PQC is not enabled, in decreasing order of preference.
const SERVER_CURVE_BASE_GROUPS: &[crate::tls::CurveGroup] = &[
    crate::tls::CurveGroup::EccSecp256R1,
    crate::tls::CurveGroup::EccX25519,
];

const SERVER_CURVE_PQC_GROUPS: &[crate::tls::CurveGroup] = &[
    #[cfg(wolfssl)]
    crate::tls::CurveGroup::P521MLKEM1024,
    #[cfg(wolfssl)]
    crate::tls::CurveGroup::P521KyberLevel5,
    crate::tls::CurveGroup::X25519MLKEM768,
    #[cfg(wolfssl)]
    crate::tls::CurveGroup::P256MLKEM512,
    #[cfg(wolfssl)]
    crate::tls::CurveGroup::P256KyberLevel1,
    crate::tls::CurveGroup::EccSecp256R1,
    crate::tls::CurveGroup::EccX25519,
];

/// Builds [`TlsClientFactory`].
pub struct TlsClientFactoryBuilder {
    tls_ctx: crate::tls::ContextBuilder,
    connection_type: ConnectionType,
    #[cfg(all(feature = "debug", wolfssl))]
    key_logger: Option<crate::tls::Tls13SecretCallbacksArg>,
}

impl TlsClientFactoryBuilder {
    /// Sets the cipher which should be used for Lightway connection.
    /// See [`Cipher`].
    pub fn with_cipher(self, cipher: Cipher) -> Result<Self, TlsFactoryError> {
        let tls_ctx = self
            .tls_ctx
            .with_cipher_list(cipher.as_cipher_list(self.connection_type))?;
        Ok(Self { tls_ctx, ..self })
    }

    /// Enable post-quantum cryptography by configuring PQC curve groups.
    ///
    /// On BoringSSL this sets the context's supported_groups to the PQ list
    /// so a per-connection PQ key share can be offered. On wolfSSL it is a
    /// no-op: PQ groups are configured per session instead.
    pub fn enable_pq_crypto(self) -> Result<Self, TlsFactoryError> {
        #[cfg(boringssl)]
        let tls_ctx = self.tls_ctx.with_groups(SERVER_CURVE_PQC_GROUPS)?;
        #[cfg(wolfssl)]
        let tls_ctx = self.tls_ctx;
        Ok(Self { tls_ctx, ..self })
    }

    /// Register a TLS key logger.
    ///
    /// BoringSSL exposes keylog only at the SSL_CTX level, so the callback is
    /// set on the context here. wolfSSL logs per session, so the callback is
    /// stored and applied to each session the factory creates.
    #[cfg(feature = "debug")]
    pub fn with_key_logger(self, keylog: crate::tls::Tls13SecretCallbacksArg) -> Self {
        #[cfg(boringssl)]
        {
            Self {
                tls_ctx: self.tls_ctx.with_key_logger(keylog),
                ..self
            }
        }
        #[cfg(wolfssl)]
        {
            Self {
                key_logger: Some(keylog),
                ..self
            }
        }
    }

    /// Finalize the builder.
    pub fn build(self) -> TlsClientFactory {
        TlsClientFactory {
            tls_ctx: self.tls_ctx.build(),
            connection_type: self.connection_type,
            #[cfg(all(feature = "debug", wolfssl))]
            key_logger: self.key_logger,
        }
    }
}

impl BuilderPredicates for TlsClientFactoryBuilder {
    type Error = TlsFactoryError;
}

/// Builds a TLS or DTLS transport for each client connection.
pub struct TlsClientFactory {
    tls_ctx: crate::tls::Context,
    connection_type: ConnectionType,
    #[cfg(all(feature = "debug", wolfssl))]
    key_logger: Option<crate::tls::Tls13SecretCallbacksArg>,
}

impl TlsClientFactory {
    /// Start building a factory that verifies the server against `root_ca`.
    pub fn builder(
        connection_type: ConnectionType,
        root_ca: RootCertificate,
    ) -> Result<TlsClientFactoryBuilder, TlsFactoryError> {
        let protocol = match connection_type {
            ConnectionType::Stream => crate::tls::Method::TlsClientV1_3,
            ConnectionType::Datagram => crate::tls::Method::DtlsClientV1_3,
        };

        let tls_ctx = crate::tls::ContextBuilder::new(protocol)?
            .with_root_certificate(root_ca)?
            .with_cipher_list(Cipher::default().as_cipher_list(connection_type))?;

        Ok(TlsClientFactoryBuilder {
            tls_ctx,
            connection_type,
            #[cfg(all(feature = "debug", wolfssl))]
            key_logger: None,
        })
    }
}

impl ClientTransportFactory for TlsClientFactory {
    fn connect(
        &self,
        args: TransportArgs,
        client: ClientTransportArgs,
    ) -> Result<Box<dyn Transport>, TransportError> {
        let connection_type = self.connection_type;
        let io = TlsIOAdapter::new(connection_type, connection_type.is_datagram(), &args);
        let config = crate::tls::SessionConfig::new(io)
            .when(connection_type.is_datagram(), |s| {
                s.with_dtls_mtu(max_dtls_outside_mtu(args.outside_mtu) as u16)
                    .with_dtls_nonblocking(true)
            })
            .when_some(client.domain_name.as_deref(), |s, dn| {
                s.with_checked_domain_name(dn)
            })
            .when_some(client.sni.as_deref(), |s, sni| s.with_sni(sni))
            .when_some(client.key_share, |s, ks| s.with_key_share(ks));

        // wolfSSL logs TLS secrets per session, so apply the factory's key
        // logger (if set) to this session.
        #[cfg(all(feature = "debug", wolfssl))]
        let config = match self.key_logger.clone() {
            Some(k) => config.with_key_logger(k),
            None => config,
        };

        let session = self
            .tls_ctx
            .new_session(config)
            .map_err(|e| TransportError::new(true, e))?;
        Ok(Box::new(TlsTransport::new(session, connection_type)))
    }
}

/// Builds a TLS or DTLS transport for each accepted server connection.
pub struct TlsServerFactory {
    tls_ctx: crate::tls::Context,
    connection_type: ConnectionType,
}

impl TlsServerFactory {
    /// Build a factory that presents `server_cert`. `pqc` adds the
    /// post-quantum key exchange groups.
    pub fn new(
        connection_type: ConnectionType,
        server_cert: Secret,
        server_key: Secret,
        pqc: bool,
    ) -> Result<Self, TlsFactoryError> {
        let protocol = match connection_type {
            ConnectionType::Stream => crate::tls::Method::TlsServerV1_3,
            ConnectionType::Datagram => crate::tls::Method::DtlsServerV1_3,
        };

        let cipher_list = match connection_type {
            ConnectionType::Stream => "TLS13-AES256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256",
            ConnectionType::Datagram => "TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES256-GCM-SHA384",
        };

        let tls_ctx = crate::tls::ContextBuilder::new(protocol)?
            .with_private_key(server_key)?
            .with_certificate(server_cert)?
            .with_groups(if pqc {
                SERVER_CURVE_PQC_GROUPS
            } else {
                SERVER_CURVE_BASE_GROUPS
            })?
            .with_cipher_list(cipher_list)?;

        Ok(Self {
            tls_ctx: tls_ctx.build(),
            connection_type,
        })
    }

    /// Build a transport for the peer behind `args.outside_io`.
    pub fn accept(&self, args: TransportArgs) -> Result<Box<dyn Transport>, TransportError> {
        let connection_type = self.connection_type;
        let io = TlsIOAdapter::new(connection_type, false, &args);
        let config = crate::tls::SessionConfig::new(io).when(connection_type.is_datagram(), |s| {
            s.with_dtls_mtu(max_dtls_outside_mtu(args.outside_mtu) as u16)
                .with_dtls_nonblocking(true)
                .with_dtls13_allow_ch_frag(true)
        });

        let session = self
            .tls_ctx
            .new_session(config)
            .map_err(|e| TransportError::new(true, e))?;
        Ok(Box::new(TlsTransport::new(session, connection_type)))
    }
}

/// Default MTU size for DTLS on the outside path (max outside MTU less IP and UDP header size)
pub(crate) const fn max_dtls_outside_mtu(outside_mtu: usize) -> usize {
    outside_mtu - IPV4_HEADER_SIZE - UDP_HEADER_SIZE - wire::Header::WIRE_SIZE
}

/// Default MTU size for DTLS payload (max DTLS wire MTU less DTLS overheads)
pub(crate) const fn max_dtls_mtu(outside_mtu: usize) -> usize {
    max_dtls_outside_mtu(outside_mtu) - MAX_DTLS_HEADER_SIZE
}

/// D/TLS is a UDP based protocol and requires the application
/// (rather than the OS as with TCP) to keep track of the need to do
/// retransmits on packet loss.
///
/// Currently the TLS library has timeouts based in seconds. However this is not
/// sufficient for our goal of sub-second connection times.
///
/// As the TLS library lacks millisecond timers we use its internal timers but
/// change its definition to be in 100 millisecond intervals instead of
/// seconds. So a TLS timeout of 1 second means 100 milliseconds.
///
/// By default the TLS library's DTLS max timeout is 64 seconds which translates to
/// 6.4 seconds. Since it scales from 1 to 64 by a factor
/// of 2 each timeout. The total timeout is 12.7 seconds with this scaling
/// which for our purposes is plenty.
///
/// In lightway for simplicity we do not treat this as a strict
/// timeout (firing after a period of inactivity) but instead treat it
/// as a tick (albeit with an interval which may be adjusted over
/// time). This tick runs until the connection reaches `State::Online`.
const TLS_TICK_INTERVAL_DIVISOR: u32 = 1000 / 100;

const TLS_TICK_DTLS13_QUICK_TIMEOUT_DIVISOR: u32 = 4;

pub(crate) struct TlsTransport {
    session: Session<TlsIOAdapter>,
    connection_type: ConnectionType,
}

impl TlsTransport {
    pub(crate) fn new(session: Session<TlsIOAdapter>, connection_type: ConnectionType) -> Self {
        Self {
            session,
            connection_type,
        }
    }

    /// Every error ends a stream. On datagrams only these errors end
    /// the connection.
    fn error(&self, err: crate::tls::Error) -> TransportError {
        use crate::tls::Error::Fatal;
        let fatal = !self.connection_type.is_datagram()
            || matches!(
                err,
                Fatal(ErrorKind::DomainNameMismatch)
                    | Fatal(ErrorKind::DuplicateMessage)
                    | Fatal(ErrorKind::PeerClosed)
                    | Fatal(ErrorKind::CaCertNotAvailable)
            );
        #[cfg(wolfssl)]
        let fatal = fatal || matches!(err, Fatal(ErrorKind::PeerFatalAlert));
        TransportError::new(fatal, err)
    }
}

impl Transport for TlsTransport {
    fn caps(&self) -> TransportCaps {
        let datagram = self.connection_type.is_datagram();
        TransportCaps {
            lossy: datagram,
            reliable_control: !datagram,
            wire_header: datagram,
            supports_roaming: datagram,
        }
    }

    fn max_frame_payload(&self) -> usize {
        max_dtls_mtu(self.session.io_cb().outside_mtu)
    }

    fn handshake(&mut self) -> PollResult<()> {
        self.session.try_negotiate().map_err(|e| self.error(e))
    }

    fn feed(&mut self, buf: &[u8]) {
        self.session.io_cb_mut().recv_buf.extend_from_slice(buf);
    }

    fn packet_done(&mut self) {
        // RFC6347 mandates each datagram should have full record and one TLS record cannot span
        // over multiple datagrams
        // https://datatracker.ietf.org/doc/html/rfc6347#section-4.1.2.6
        if self.connection_type.is_datagram() {
            self.session.io_cb_mut().recv_buf.clear();
        }
    }

    fn read(&mut self, into: &mut BytesMut) -> PollResult<usize> {
        self.session.try_read(into).map_err(|e| self.error(e))
    }

    fn write(&mut self, buf: &mut BytesMut) -> PollResult<usize> {
        self.session.try_write(buf).map_err(|e| self.error(e))
    }

    fn shutdown(&mut self) -> PollResult<bool> {
        self.session.try_shutdown().map_err(|e| self.error(e))
    }

    fn key_update(&mut self) -> PollResult<()> {
        self.session
            .try_trigger_update_key()
            .map_err(|e| self.error(e))
    }

    fn key_update_pending(&mut self) -> bool {
        self.session.is_update_keys_pending()
    }

    fn tick_interval(&mut self) -> Option<Duration> {
        if !self.connection_type.is_datagram() {
            return None;
        }
        let mut interval = self.session.dtls_current_timeout() / TLS_TICK_INTERVAL_DIVISOR;
        if matches!(self.session.version(), ProtocolVersion::DtlsV1_3)
            && self.session.dtls13_use_quick_timeout()
        {
            interval /= TLS_TICK_DTLS13_QUICK_TIMEOUT_DIVISOR;
        }
        Some(interval)
    }

    fn has_timed_out(&mut self) -> Poll<bool> {
        if !self.connection_type.is_datagram() {
            return Poll::Ready(false);
        }
        self.session.dtls_has_timed_out()
    }

    fn protocol_version(&mut self) -> ProtocolVersion {
        self.session.version()
    }

    fn current_cipher(&mut self) -> Option<String> {
        self.session.get_current_cipher_name()
    }

    fn current_curve(&mut self) -> Option<String> {
        self.session.get_current_curve_name()
    }

    fn set_session_id(&mut self, id: SessionId) {
        self.session.io_cb_mut().set_session_id(id);
    }

    /// Aggressive send covers the handshake and the auth exchange, so
    /// it ends here and not when the TLS handshake completes.
    fn online(&mut self) {
        self.session.io_cb_mut().aggressive_send = false;
    }

    fn pmtud_probe(&mut self, on: bool) {
        if on {
            self.session.io_cb().enable_pmtud_probe();
        } else {
            self.session.io_cb().disable_pmtud_probe();
        }
    }

    fn set_outside_io(&mut self, io: OutsideIOSendCallbackArg) {
        self.session.io_cb_mut().io = io;
    }

    fn peer_addr(&self) -> SocketAddr {
        self.session.io_cb().io.peer_addr()
    }

    fn set_peer_addr(&mut self, addr: SocketAddr) -> SocketAddr {
        self.session.io_cb().io.set_peer_addr(addr)
    }

    fn send_expresslane(&mut self, buf: &[u8]) -> IOCallbackResult<usize> {
        self.session.io_cb_mut().udp_send(buf, true)
    }

    #[cfg(target_os = "linux")]
    fn batch_begin(&mut self) {
        self.session.io_cb_mut().gso_buf.open();
    }

    #[cfg(target_os = "linux")]
    fn batch_end(&mut self, send: bool) -> IOCallbackResult<usize> {
        let io = self.session.io_cb_mut();
        let res = if send {
            io.udp_send_gso()
        } else {
            IOCallbackResult::Ok(0)
        };
        io.gso_buf.reset();
        res
    }
}
