//! An in-memory transport for tests. A record is the frame itself,
//! with no encryption, so a test can drive the connection state
//! machine without a TLS backend.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::BytesMut;

use super::{
    ClientTransportArgs, ClientTransportFactory, Poll, PollResult, Transport, TransportArgs,
    TransportCaps, TransportError,
};
use crate::OutsideIOSendCallback;
use crate::tls::{IOCallbackResult, ProtocolVersion};

/// The queue of outside packets to one end of a [`MockOutsideIo::pair`].
pub type Inbox = Arc<Mutex<VecDeque<BytesMut>>>;

/// One end of an in-memory outside path.
pub struct MockOutsideIo {
    inbox: Inbox,
    peer_inbox: Inbox,
    blocked_sends: AtomicUsize,
}

impl MockOutsideIo {
    /// Two ends joined back to back.
    pub fn pair() -> (Arc<Self>, Arc<Self>) {
        let a: Inbox = Default::default();
        let b: Inbox = Default::default();
        (
            Arc::new(Self::new(a.clone(), b.clone())),
            Arc::new(Self::new(b, a)),
        )
    }

    fn new(inbox: Inbox, peer_inbox: Inbox) -> Self {
        Self {
            inbox,
            peer_inbox,
            blocked_sends: AtomicUsize::new(0),
        }
    }

    /// Outside packets sent by the peer and not yet delivered.
    pub fn inbox(&self) -> Inbox {
        self.inbox.clone()
    }

    /// Block the next `n` sends.
    pub fn block_sends(&self, n: usize) {
        self.blocked_sends.store(n, Ordering::SeqCst);
    }
}

impl OutsideIOSendCallback for MockOutsideIo {
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        let blocked = self
            .blocked_sends
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
        if blocked.is_ok() {
            return IOCallbackResult::WouldBlock;
        }
        self.peer_inbox
            .lock()
            .unwrap()
            .push_back(BytesMut::from(buf));
        IOCallbackResult::Ok(buf.len())
    }

    fn send_gso(&self, _bufs: &[std::io::IoSlice<'_>], _gso_size: u16) -> IOCallbackResult<usize> {
        IOCallbackResult::Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    fn peer_addr(&self) -> SocketAddr {
        "127.0.0.1:1".parse().unwrap()
    }
}

/// The largest frame payload of a [`MockTransport`].
const MAX_FRAME_PAYLOAD: usize = 1419;

/// A transport whose record is the frame itself.
pub struct MockTransport {
    caps: TransportCaps,
    pending: BytesMut,
    records: VecDeque<BytesMut>,
}

impl MockTransport {
    /// A transport that reports `caps`.
    pub fn new(caps: TransportCaps) -> Self {
        Self {
            caps,
            pending: BytesMut::new(),
            records: VecDeque::new(),
        }
    }
}

impl Transport for MockTransport {
    fn caps(&self) -> TransportCaps {
        self.caps
    }

    fn max_frame_payload(&self) -> usize {
        MAX_FRAME_PAYLOAD
    }

    fn handshake(&mut self) -> PollResult<()> {
        Ok(Poll::Ready(()))
    }

    fn feed(&mut self, buf: &[u8]) {
        self.pending.extend_from_slice(buf);
    }

    fn packet_done(&mut self) {
        if self.caps.is_lossy() {
            self.pending.clear();
        }
    }

    fn read(&mut self, into: &mut BytesMut) -> PollResult<usize> {
        if self.pending.is_empty() {
            return Ok(Poll::Pending);
        }
        let n = self.pending.len();
        into.extend_from_slice(&self.pending.split());
        Ok(Poll::Ready(n))
    }

    fn write(&mut self, frame: &mut BytesMut) -> Result<(), TransportError> {
        self.records.push_back(frame.split());
        Ok(())
    }

    fn poll_transmit(&mut self) -> Option<BytesMut> {
        self.records.pop_front()
    }

    fn shutdown(&mut self) {}

    fn key_update(&mut self) -> PollResult<()> {
        Ok(Poll::Ready(()))
    }

    fn key_update_pending(&mut self) -> bool {
        false
    }

    fn tick_interval(&mut self) -> Option<Duration> {
        None
    }

    fn has_timed_out(&mut self) -> bool {
        false
    }

    fn protocol_version(&mut self) -> ProtocolVersion {
        ProtocolVersion::Unknown
    }

    fn current_cipher(&mut self) -> Option<String> {
        None
    }

    fn current_curve(&mut self) -> Option<String> {
        None
    }

    fn online(&mut self) {}
}

/// Hands out one prepared transport, then fails.
pub struct MockFactory(Mutex<Option<MockTransport>>);

impl MockFactory {
    /// A factory that hands out `transport`.
    pub fn new(transport: MockTransport) -> Self {
        Self(Mutex::new(Some(transport)))
    }
}

impl ClientTransportFactory for MockFactory {
    fn connect(
        &self,
        _args: TransportArgs,
        _client: ClientTransportArgs,
    ) -> Result<Box<dyn Transport>, TransportError> {
        let transport = self
            .0
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| TransportError::new(true, "mock transport already taken"))?;
        Ok(Box::new(transport))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ClientContextBuilder, ClientIpConfig, CodecStatus, Connection, Delivery, Event,
        EventCallback, InsideIOSendCallback, InsideIpConfig, LightwayFeature, MAX_OUTSIDE_MTU,
        OutsidePacket, PacketCodecResult, PacketDecoder, PacketEncoder, ServerAuth,
        ServerAuthHandle, ServerAuthResult, ServerContextBuilder, ServerIpPool, State, TickType,
        Version, wire::AuthMethod,
    };
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, Ordering};

    const LOSSY: TransportCaps = TransportCaps {
        delivery: Delivery::Datagram { wire_header: false },
        supports_roaming: false,
    };

    const RELIABLE: TransportCaps = TransportCaps {
        delivery: Delivery::Stream,
        supports_roaming: false,
    };

    const WIRE_HEADER: TransportCaps = TransportCaps {
        delivery: Delivery::Datagram { wire_header: true },
        supports_roaming: true,
    };

    struct Auth;

    impl ServerAuth<()> for Auth {
        fn authorize(&self, method: &AuthMethod, _state: &mut ()) -> ServerAuthResult {
            match method {
                AuthMethod::Token { .. } | AuthMethod::VersionedToken { .. } => {
                    ServerAuthResult::Granted {
                        handle: Some(Box::new(Handle)),
                        tunnel_protocol_version: None,
                    }
                }
                _ => ServerAuthResult::Denied,
            }
        }
    }

    #[derive(Debug)]
    struct Handle;

    impl ServerAuthHandle for Handle {
        fn expired(&self) -> bool {
            false
        }

        fn features(&self) -> HashSet<LightwayFeature> {
            HashSet::from([LightwayFeature::InsidePktCodec])
        }
    }

    struct Pool;

    impl ServerIpPool<()> for Pool {
        fn alloc(&self, _state: &mut ()) -> Option<InsideIpConfig> {
            Some(InsideIpConfig {
                client_ip: "10.125.0.2".parse().unwrap(),
                server_ip: "10.125.0.1".parse().unwrap(),
                dns_ip: "10.125.0.1".parse().unwrap(),
                mtu: None,
            })
        }

        fn free(&self, _state: &mut ()) {}
    }

    struct ClientIp;

    impl ClientIpConfig<()> for ClientIp {
        fn ip_config(&self, _state: &mut (), _config: InsideIpConfig) {}
    }

    #[derive(Default)]
    struct Tun(Mutex<Vec<BytesMut>>);

    impl InsideIOSendCallback<()> for Tun {
        fn send(&self, buf: BytesMut, _state: &mut ()) -> IOCallbackResult<usize> {
            let n = buf.len();
            self.0.lock().unwrap().push(buf);
            IOCallbackResult::Ok(n)
        }

        fn mtu(&self) -> usize {
            1350
        }

        fn if_index(&self) -> std::io::Result<u32> {
            Err(std::io::Error::other("none"))
        }

        fn name(&self) -> std::io::Result<String> {
            Err(std::io::Error::other("none"))
        }
    }

    #[derive(Default)]
    struct Events(Arc<Mutex<Vec<Event>>>);

    impl EventCallback for Events {
        fn event(&mut self, event: Event) {
            self.0.lock().unwrap().push(event);
        }
    }

    fn tick(_d: Duration, _state: &mut (), _t: TickType) {}

    /// Accepts every packet and never emits it.
    struct BlackHole(AtomicBool);

    impl PacketEncoder for BlackHole {
        fn store(&self, _data: &mut BytesMut) -> PacketCodecResult<CodecStatus> {
            if self.0.load(Ordering::SeqCst) {
                Ok(CodecStatus::PacketAccepted)
            } else {
                Ok(CodecStatus::SkipPacket)
            }
        }

        fn get_encoding_state(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }

        fn set_encoding_state(&self, enabled: bool) {
            self.0.store(enabled, Ordering::SeqCst)
        }
    }

    impl PacketDecoder for BlackHole {
        fn store(&self, _data: &mut BytesMut) -> PacketCodecResult<CodecStatus> {
            Ok(CodecStatus::SkipPacket)
        }
    }

    struct Pair {
        client: Connection<()>,
        server: Connection<()>,
        client_io: Arc<MockOutsideIo>,
        server_io: Arc<MockOutsideIo>,
        client_tun: Arc<Tun>,
        server_tun: Arc<Tun>,
        events: Arc<Mutex<Vec<Event>>>,
    }

    fn pair(caps: TransportCaps) -> Pair {
        pair_with(caps, None, 0)
    }

    /// `codecs` are the client and the server codecs. The first
    /// `blocked_sends` client sends block.
    fn pair_with(
        caps: TransportCaps,
        codecs: Option<(Arc<BlackHole>, Arc<BlackHole>)>,
        blocked_sends: usize,
    ) -> Pair {
        let (client_io, server_io) = MockOutsideIo::pair();
        client_io.block_sends(blocked_sends);
        let client_tun = Arc::new(Tun::default());
        let server_tun = Arc::new(Tun::default());
        let events = Events::default();
        let log = events.0.clone();
        let codec = |c: Arc<BlackHole>| {
            (
                c.clone() as crate::PacketEncoderType,
                c as crate::PacketDecoderType,
            )
        };
        let (client_codec, server_codec) = match codecs {
            Some((c, s)) => (Some(codec(c)), Some(codec(s))),
            None => (None, None),
        };

        let client = ClientContextBuilder::new(
            Arc::new(MockFactory::new(MockTransport::new(caps))),
            Some(client_tun.clone()),
            Arc::new(ClientIp),
            tick,
        )
        .build()
        .start_connect(client_io.clone(), MAX_OUTSIDE_MTU)
        .unwrap()
        .with_auth_token("LET ME IN")
        .with_event_cb(Box::new(events))
        .with_inside_pkt_codec(client_codec)
        .connect(())
        .unwrap();

        let server_ctx =
            ServerContextBuilder::new(Arc::new(Auth), Arc::new(Pool), server_tun.clone(), tick)
                .build()
                .unwrap();
        let server = server_ctx
            .start_accept(Version::MAXIMUM, server_io.clone())
            .unwrap()
            .with_inside_pkt_codec(server_codec)
            .accept(
                (),
                Box::new(move |_| Ok(Box::new(MockTransport::new(caps)))),
            )
            .unwrap();

        Pair {
            client,
            server,
            client_io,
            server_io,
            client_tun,
            server_tun,
            events: log,
        }
    }

    fn deliver(conn: &mut Connection<()>, io: &MockOutsideIo) -> bool {
        let inbox = io.inbox();
        let mut moved = false;
        while let Some(mut buf) = inbox.lock().unwrap().pop_front() {
            conn.outside_data_received(OutsidePacket::Wire(&mut buf))
                .unwrap();
            moved = true;
        }
        moved
    }

    impl Pair {
        fn pump(&mut self) {
            loop {
                let a = deliver(&mut self.client, &self.client_io);
                let b = deliver(&mut self.server, &self.server_io);
                if !a && !b {
                    break;
                }
            }
        }

        fn pump_to_online(mut self) -> Self {
            self.pump();
            assert_eq!(self.client.state(), State::Online);
            assert_eq!(self.server.state(), State::Online);
            self
        }
    }

    #[test]
    fn handshake_and_auth_reach_online() {
        let p = pair(LOSSY).pump_to_online();
        let states: Vec<State> = p
            .events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                Event::StateChanged(s) => Some(*s),
                _ => None,
            })
            .collect();
        assert_eq!(
            states,
            [State::LinkUp, State::Authenticating, State::Online]
        );
    }

    #[test]
    fn keepalive_pong_fires_event() {
        let mut p = pair(LOSSY).pump_to_online();
        p.client.keepalive().unwrap();
        p.pump();
        let events = p.events.lock().unwrap();
        assert!(events.iter().any(|e| matches!(e, Event::KeepaliveReply)));
    }

    #[test]
    fn data_frames_cross_both_ways() {
        let mut p = pair(LOSSY).pump_to_online();
        let mut up = BytesMut::from(&b"\x40up"[..]);
        p.client.inside_data_received(&mut up).unwrap();
        p.pump();
        assert_eq!(&p.server_tun.0.lock().unwrap()[0][..], b"\x40up");

        let mut down = BytesMut::from(&b"\x40down"[..]);
        p.server.inside_data_received(&mut down).unwrap();
        p.pump();
        assert_eq!(&p.client_tun.0.lock().unwrap()[0][..], b"\x40down");
    }

    #[test]
    fn stalled_codec_is_downgraded() {
        let codecs = (
            Arc::new(BlackHole(AtomicBool::new(false))),
            Arc::new(BlackHole(AtomicBool::new(false))),
        );
        let mut p = pair_with(LOSSY, Some(codecs), 0).pump_to_online();

        p.client.set_encoding(true).unwrap();
        p.pump();
        assert!(p.client.is_encoding_enabled());

        let mut up = BytesMut::from(&b"\x40up"[..]);
        p.client.inside_data_received(&mut up).unwrap();
        p.pump();
        assert!(p.server_tun.0.lock().unwrap().is_empty());

        let long = Duration::from_secs(3600);
        assert!(
            !p.client
                .downgrade_inside_pkt_codec_if_stalled(long)
                .unwrap()
        );
        let short = Duration::from_nanos(1);
        assert!(
            p.client
                .downgrade_inside_pkt_codec_if_stalled(short)
                .unwrap()
        );
        p.pump();
        assert!(!p.client.is_encoding_enabled());

        let mut up = BytesMut::from(&b"\x40up"[..]);
        p.client.inside_data_received(&mut up).unwrap();
        p.pump();
        assert_eq!(&p.server_tun.0.lock().unwrap()[0][..], b"\x40up");
    }

    #[test]
    fn control_frames_queue_behind_a_blocked_stream() {
        let mut p = pair_with(RELIABLE, None, 1);
        let server_inbox = p.server_io.inbox();
        assert!(
            server_inbox.lock().unwrap().is_empty(),
            "auth request went through a blocked send"
        );

        // The tick resends the auth request, and that send also
        // flushes the one that waited.
        p.client.tick(TickType::ConnectionTick).unwrap();
        assert_eq!(server_inbox.lock().unwrap().len(), 2);
        p.pump_to_online();
    }

    #[test]
    fn a_blocked_lossy_packet_is_dropped() {
        let mut p = pair_with(LOSSY, None, 1);
        let server_inbox = p.server_io.inbox();
        assert!(server_inbox.lock().unwrap().is_empty());

        // Only the resent auth request arrives.
        p.client.tick(TickType::ConnectionTick).unwrap();
        assert_eq!(server_inbox.lock().unwrap().len(), 1);
        p.pump_to_online();
    }

    #[test]
    fn a_session_id_rotation_reaches_the_client_in_the_wire_header() {
        let mut p = pair(WIRE_HEADER).pump_to_online();
        let new = p.server.rotate_session_id().unwrap();
        p.pump();
        assert_eq!(p.client.session_id(), new);

        // The next client packet carries the new id and ends the
        // rotation on the server.
        p.client.keepalive().unwrap();
        p.pump();
        assert_eq!(p.server.session_id(), new);
    }
}
