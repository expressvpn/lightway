//! Datagram dispatch and receive loop.

use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;
use lightway_core::{
    ConnectionType, Header, IOCallbackResult, MAX_IO_BATCH_SIZE, MAX_OUTSIDE_MTU, OutsidePacket,
    SessionId, Version,
};
use std::sync::Arc;
use tracing::warn;

use super::{OutsideIO, RecvMeta, Server};
use crate::{connection::Connection, connection_manager::ConnectionManager, metrics};

/// Runs a datagram [`OutsideIO`] against the connection manager.
///
/// Owns the carrier so a receive can hold scratch across iterations
/// without a lock.
pub(crate) struct DatagramServer {
    io: Box<dyn OutsideIO>,
    conn_manager: Arc<ConnectionManager>,
}

impl DatagramServer {
    pub(crate) fn new(io: Box<dyn OutsideIO>, conn_manager: Arc<ConnectionManager>) -> Self {
        Self { io, conn_manager }
    }

    /// Parse and validate one wire packet.
    ///
    /// `None` means the packet was dropped and the reason was metered.
    fn parse<'pkt>(&self, buf: &'pkt mut BytesMut) -> Option<(OutsidePacket<'pkt>, Header)> {
        let pkt = OutsidePacket::Wire(buf, ConnectionType::Datagram);
        let pkt = match self.conn_manager.parse_raw_outside_packet(pkt) {
            Ok(pkt) => pkt,
            Err(e) => {
                metrics::udp_parse_wire_failed();
                warn!("Extracting header from packet failed: {e}");
                return None;
            }
        };
        let hdr = *pkt.header().expect("a parsed datagram carries a header");

        if !self.conn_manager.is_supported_version(hdr.version) {
            // If the protocol version is not supported then drop
            // the packet.
            metrics::udp_bad_packet_version(hdr.version);
            return None;
        }

        Some((pkt, hdr))
    }

    /// Find the connection this packet belongs to, keyed by peer address
    /// and falling back to the session id in `hdr`. The `bool` is set
    /// when the peer roamed.
    ///
    /// `None` means the packet was dropped and the peer answered, if it
    /// was owed an answer.
    fn route(&self, hdr: Header, meta: &RecvMeta) -> Option<(Arc<Connection>, bool)> {
        // A peer address hit delivers even when the session id in `hdr`
        // does not match. The create path below rejects that mismatch,
        // so do not fold the two together.
        if let Some(conn) = self.conn_manager.find_datagram_connection_with(meta.peer) {
            return Some((conn, false));
        }

        match self.conn_manager.find_or_create_datagram_connection_with(
            meta.peer,
            hdr.version,
            hdr.session,
            meta.local,
            || self.io.send_callback(meta),
        ) {
            Ok(routed) => Some(routed),
            Err(_e) => {
                self.send_reject(meta);
                None
            }
        }
    }

    /// Parse, route and deliver one received packet.
    fn dispatch(&self, buf: &mut BytesMut, meta: &RecvMeta) {
        let Some((pkt, hdr)) = self.parse(buf) else {
            return;
        };

        let Some((conn, roamed)) = self.route(hdr, meta) else {
            return;
        };

        match conn.outside_data_received(pkt) {
            Ok(0) => {
                // We will hit this case when there is UDP packet duplication.
                // TLS library skips duplicate packets and thus no frames read.
                // It is also possible that adversary can capture the packet
                // and replay it. In any case, skip processing further
                if roamed {
                    metrics::udp_session_rotation_attempted_via_replay();
                }
            }
            Ok(_) => {
                // NOTE: We wait until the first successful TLS
                // decrypt to protect against the case where a crafted
                // packet with a session ID causes us to change the
                // connection IP without verifying the SSL connection
                // first
                if roamed {
                    metrics::udp_conn_recovered_via_session(hdr.session);
                    // Address first: the rotation announce must go to the
                    // address the client roamed to.
                    self.conn_manager.set_peer_addr(&conn, meta.peer);
                    conn.begin_session_id_rotation();
                }
            }
            Err(err) => {
                warn!("Failed to process outside data: {err}");
                let _ = conn.handle_outside_data_error(&err);
                // Fatal or not, we are done with this packet.
            }
        }
    }

    /// Tell a peer with no connection to restart, rather than let it wait
    /// out a timeout.
    fn send_reject(&self, meta: &RecvMeta) {
        metrics::udp_rejected_session();
        let msg = Header {
            version: Version::MINIMUM,
            aggressive_mode: false,
            session: SessionId::REJECTED,
            expresslane_data: false,
        };

        let mut buf = BytesMut::with_capacity(Header::WIRE_SIZE);
        msg.append_to_wire(&mut buf);

        self.io.send_unconnected(meta, &buf);
    }
}

#[async_trait]
impl Server for DatagramServer {
    async fn run(&mut self) -> Result<()> {
        let mut bufs: [BytesMut; MAX_IO_BATCH_SIZE] =
            std::array::from_fn(|_| BytesMut::with_capacity(MAX_OUTSIDE_MTU));
        let mut metas: Vec<RecvMeta> = Vec::with_capacity(MAX_IO_BATCH_SIZE);
        loop {
            metas.clear();

            match self.io.recv_many(&mut bufs, &mut metas).await {
                IOCallbackResult::Ok(()) => {}
                IOCallbackResult::WouldBlock => continue,
                IOCallbackResult::Err(err) => return Err(err.into()),
            }

            for (buf, meta) in bufs.iter_mut().zip(metas.iter()) {
                self.dispatch(buf, meta);
            }

            // A carrier that receives through a manual readiness API charges
            // no cooperative budget. A backlog of ready packets then never
            // parks this task and starves the inside loop. Charge one unit
            // per datagram, as tokio's own charged IO paths do. See
            // `CVPN-2732` for the same fix on the client.
            for _ in 0..metas.len() {
                tokio::task::coop::consume_budget().await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::ConnectionState;
    use crate::ip_manager::IpManager;
    use ipnet::Ipv4Net;
    use lightway_app_utils::connection_ticker_cb;
    use lightway_core::{
        AuthMethod, IOCallbackResult, InsideIOSendCallback, InsideIpConfig,
        OutsideIOSendCallbackArg, Secret, ServerAuth, ServerAuthResult, ServerContextBuilder,
    };
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::Path;
    use std::sync::Mutex;
    use std::time::Duration;

    const PEER_A: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 5000);
    const PEER_B: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)), 5001);
    const LOCAL: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 27690);

    struct StubAuth;

    impl ServerAuth<ConnectionState> for StubAuth {
        fn authorize(
            &self,
            _method: &AuthMethod,
            _app_state: &mut ConnectionState,
        ) -> ServerAuthResult {
            // No test packet here carries valid DTLS, so no handshake
            // ever completes and nothing calls this.
            unimplemented!("dispatch tests never reach authorization")
        }
    }

    struct StubInsideIo;

    impl InsideIOSendCallback<ConnectionState> for StubInsideIo {
        fn send(&self, buf: BytesMut, _state: &mut ConnectionState) -> IOCallbackResult<usize> {
            IOCallbackResult::Ok(buf.len())
        }

        fn mtu(&self) -> usize {
            1350
        }

        fn if_index(&self) -> std::io::Result<u32> {
            Ok(0)
        }

        fn name(&self) -> std::io::Result<String> {
            Ok("stub".to_string())
        }
    }

    fn test_conn_manager() -> Arc<ConnectionManager> {
        test_conn_manager_with_minimum_version(Version::MINIMUM)
    }

    fn test_conn_manager_with_minimum_version(minimum: Version) -> Arc<ConnectionManager> {
        let cert = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/certs/server.crt"
        ));
        let key = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/certs/server.key"
        ));

        let pool: Ipv4Net = "10.125.0.0/16".parse().unwrap();
        let ip_manager = Arc::new(IpManager::new(
            pool,
            HashMap::new(),
            std::iter::empty::<Ipv4Addr>(),
            InsideIpConfig {
                client_ip: Ipv4Addr::new(10, 125, 0, 5),
                server_ip: Ipv4Addr::new(10, 125, 0, 6),
                dns_ip: Ipv4Addr::new(10, 125, 0, 1),
            },
            false,
            true,
        ));

        let ctx = ServerContextBuilder::new(
            ConnectionType::Datagram,
            Secret::PemFile(cert),
            Secret::PemFile(key),
            Arc::new(StubAuth),
            ip_manager,
            Arc::new(StubInsideIo),
            connection_ticker_cb,
        )
        .unwrap()
        .with_minimum_protocol_version(minimum)
        .unwrap()
        .build()
        .unwrap();

        ConnectionManager::new(ctx, None, None, Duration::from_secs(60))
    }

    /// Outside IO that records what the dispatch asked of it.
    #[derive(Default)]
    struct MockIo {
        minted: Mutex<Vec<SocketAddr>>,
        unconnected: Mutex<Vec<(SocketAddr, Vec<u8>)>>,
    }

    fn meta(peer: SocketAddr) -> RecvMeta {
        RecvMeta { peer, local: LOCAL }
    }

    struct MockSend(SocketAddr);

    impl lightway_core::OutsideIOSendCallback for MockSend {
        fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
            IOCallbackResult::Ok(buf.len())
        }

        fn send_gso(
            &self,
            _bufs: &[std::io::IoSlice<'_>],
            _gso_size: u16,
        ) -> IOCallbackResult<usize> {
            IOCallbackResult::Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        }

        fn peer_addr(&self) -> SocketAddr {
            self.0
        }
    }

    #[async_trait]
    impl OutsideIO for Arc<MockIo> {
        async fn recv(&mut self, _buf: &mut BytesMut) -> IOCallbackResult<RecvMeta> {
            unimplemented!("dispatch tests drive the dispatch directly")
        }

        fn send_callback(&self, meta: &RecvMeta) -> OutsideIOSendCallbackArg {
            self.minted.lock().unwrap().push(meta.peer);
            Arc::new(MockSend(meta.peer))
        }

        fn send_unconnected(&self, meta: &RecvMeta, buf: &[u8]) {
            self.unconnected
                .lock()
                .unwrap()
                .push((meta.peer, buf.to_vec()));
        }
    }

    fn server(io: &Arc<MockIo>, manager: Arc<ConnectionManager>) -> DatagramServer {
        DatagramServer::new(Box::new(io.clone()), manager)
    }

    /// A wire packet with a valid lightway header and an opaque body.
    ///
    /// The body is never valid DTLS, so `outside_data_received` always
    /// fails. That is enough to exercise parsing, routing and the rule
    /// that a failed decrypt must not move a peer address.
    fn wire_packet(version: Version, session: SessionId) -> BytesMut {
        let mut buf = BytesMut::with_capacity(MAX_OUTSIDE_MTU);
        Header {
            version,
            aggressive_mode: false,
            session,
            expresslane_data: false,
        }
        .append_to_wire(&mut buf);
        buf.extend_from_slice(&[0xab; 64]);
        buf
    }

    #[tokio::test]
    async fn unparseable_packet_is_dropped() {
        let manager = test_conn_manager();
        let io = Arc::new(MockIo::default());
        let server = server(&io, manager.clone());

        // No `He` magic, so the header never parses.
        let mut buf = BytesMut::from(&[0u8; 32][..]);
        server.dispatch(&mut buf, &meta(PEER_A));

        assert_eq!(manager.total_sessions(), 0);
        assert!(io.minted.lock().unwrap().is_empty());
        assert!(io.unconnected.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unsupported_version_is_dropped() {
        // A version the wire parser accepts but this server does not. A
        // malformed version such as 0.0 fails `Version::try_new` inside
        // `Header::try_from_wire` and never reaches the gate.
        let manager = test_conn_manager_with_minimum_version(Version::MAXIMUM);
        let io = Arc::new(MockIo::default());
        let server = server(&io, manager.clone());

        let mut buf = wire_packet(Version::MINIMUM, SessionId::EMPTY);
        server.dispatch(&mut buf, &meta(PEER_A));

        assert_eq!(manager.total_sessions(), 0);
        assert!(io.minted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn peer_addr_keying_creates_a_connection_for_an_empty_session() {
        let manager = test_conn_manager();
        let io = Arc::new(MockIo::default());
        let server = server(&io, manager.clone());

        let mut buf = wire_packet(Version::MINIMUM, SessionId::EMPTY);
        server.dispatch(&mut buf, &meta(PEER_A));

        assert_eq!(manager.total_sessions(), 1);
        assert!(
            manager.find_datagram_connection_with(PEER_A).is_some(),
            "total_sessions counts every session ever, so check the map too"
        );
        assert_eq!(&io.minted.lock().unwrap()[..], &[PEER_A]);
        assert!(io.unconnected.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn peer_addr_keying_rejects_an_unknown_session() {
        let manager = test_conn_manager();
        let io = Arc::new(MockIo::default());
        let server = server(&io, manager.clone());

        // A client claiming a session the server has never seen.
        let unknown = SessionId::from_const([9u8; 8]);
        let mut buf = wire_packet(Version::MINIMUM, unknown);
        server.dispatch(&mut buf, &meta(PEER_A));

        assert_eq!(manager.total_sessions(), 0);
        assert!(io.minted.lock().unwrap().is_empty());

        let sent = io.unconnected.lock().unwrap();
        assert_eq!(sent.len(), 1, "an unknown session must be rejected");
        assert_eq!(sent[0].0, PEER_A);

        let mut frame = BytesMut::from(&sent[0].1[..]);
        let hdr = Header::try_from_wire(&mut frame).expect("reject frame must parse");
        assert_eq!(hdr.session, SessionId::REJECTED);
    }

    #[tokio::test]
    async fn a_failed_decrypt_does_not_move_the_peer_address() {
        let manager = test_conn_manager();
        let io = Arc::new(MockIo::default());
        let server = server(&io, manager.clone());

        let mut buf = wire_packet(Version::MINIMUM, SessionId::EMPTY);
        server.dispatch(&mut buf, &meta(PEER_A));

        let conn = manager
            .find_datagram_connection_with(PEER_A)
            .expect("connection created for PEER_A");
        let session = conn.session_id();
        assert_eq!(conn.peer_addr(), PEER_A);

        // The same session arriving from a new address. The body is not
        // valid DTLS, so the decrypt fails and the address must stay put.
        let mut buf = wire_packet(Version::MINIMUM, session);
        server.dispatch(&mut buf, &meta(PEER_B));

        assert_eq!(
            conn.peer_addr(),
            PEER_A,
            "peer address must only move after a successful decrypt"
        );
        assert!(
            manager.find_datagram_connection_with(PEER_B).is_none(),
            "the routing index must not have moved either"
        );
    }
}
