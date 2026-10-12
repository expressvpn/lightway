//! TLS over a stream, or DTLS over datagrams, through the
//! backend selected at build time.

pub(crate) mod io_adapter;

use std::time::Duration;

use bytes::BytesMut;

use super::Transport;
use crate::tls::{Poll, ProtocolVersion, Session};
use io_adapter::TlsIOAdapter;

use super::PollResult;
use crate::ConnectionType;

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
}

impl Transport for TlsTransport {
    fn handshake(&mut self) -> PollResult<()> {
        self.session.try_negotiate()
    }

    fn feed(&mut self, buf: &[u8]) {
        self.session.io_cb_mut().recv_buf.extend_from_slice(buf);
    }

    fn discard_pending(&mut self) {
        self.session.io_cb_mut().recv_buf.clear();
    }

    fn read(&mut self, into: &mut BytesMut) -> PollResult<usize> {
        self.session.try_read(into)
    }

    fn write(&mut self, buf: &mut BytesMut) -> PollResult<usize> {
        self.session.try_write(buf)
    }

    fn poll_transmit(&mut self) -> Option<BytesMut> {
        self.session.io_cb_mut().records.pop_front()
    }

    fn shutdown(&mut self) -> PollResult<bool> {
        self.session.try_shutdown()
    }

    fn key_update(&mut self) -> PollResult<()> {
        self.session.try_trigger_update_key()
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
