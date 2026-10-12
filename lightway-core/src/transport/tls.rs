//! TLS over a stream, or DTLS over datagrams, through the
//! backend selected at build time.

pub(crate) mod io_adapter;

use std::time::Duration;

use bytes::BytesMut;

use super::{Delivery, PollResult, Transport, TransportCaps, TransportError};
use crate::tls::{ErrorKind, Poll, ProtocolVersion, Session};
use crate::{ConnectionType, IPV4_HEADER_SIZE, MAX_DTLS_HEADER_SIZE, UDP_HEADER_SIZE, wire};
use io_adapter::TlsIOAdapter;

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
    outside_mtu: usize,
}

impl TlsTransport {
    pub(crate) fn new(
        session: Session<TlsIOAdapter>,
        connection_type: ConnectionType,
        outside_mtu: usize,
    ) -> Self {
        Self {
            session,
            connection_type,
            outside_mtu,
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
            delivery: if datagram {
                Delivery::Datagram { wire_header: true }
            } else {
                Delivery::Stream
            },
        }
    }

    fn max_frame_payload(&self) -> usize {
        max_dtls_mtu(self.outside_mtu)
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

    fn poll_transmit(&mut self) -> Option<BytesMut> {
        self.session.io_cb_mut().records.pop_front()
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

    /// Aggressive send covers the handshake and the auth exchange, so
    /// it ends here and not when the TLS handshake completes.
    fn online(&mut self) {
        self.session.io_cb_mut().aggressive_send = false;
    }
}
