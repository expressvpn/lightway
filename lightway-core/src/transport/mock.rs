//! An in-memory transport for tests. Frames cross a pair of queues
//! with no encryption, so a test can drive the connection state
//! machine without a TLS backend.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::BytesMut;

use super::{
    ClientTransportArgs, ClientTransportFactory, Poll, PollResult, Transport, TransportArgs,
    TransportCaps, TransportError,
};
use crate::tls::{IOCallbackResult, ProtocolVersion};
use crate::{OutsideIOSendCallback, OutsideIOSendCallbackArg, SessionId};

/// The queue of packets to one end of a [`MockTransport::pair`].
pub type Inbox = Arc<Mutex<VecDeque<BytesMut>>>;

/// An outside path that accepts every packet and sends nothing.
pub struct NullOutsideIo;

impl OutsideIOSendCallback for NullOutsideIo {
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        IOCallbackResult::Ok(buf.len())
    }

    fn send_gso(&self, bufs: &[std::io::IoSlice<'_>], _gso_size: u16) -> IOCallbackResult<usize> {
        IOCallbackResult::Ok(bufs.iter().map(|b| b.len()).sum())
    }

    fn peer_addr(&self) -> SocketAddr {
        "127.0.0.1:1".parse().unwrap()
    }
}

/// The largest frame payload of a [`MockTransport`].
const MAX_FRAME_PAYLOAD: usize = 1419;

/// One end of an in-memory link.
pub struct MockTransport {
    caps: TransportCaps,
    pending: BytesMut,
    inbox: Inbox,
    peer_inbox: Inbox,
    outside_io: OutsideIOSendCallbackArg,
    /// Number of next writes that return `Pending`.
    pub blocked_writes: usize,
}

impl MockTransport {
    /// Two ends joined back to back.
    ///
    /// The mock writes no wire header, so `caps.wire_header` must be
    /// false.
    pub fn pair(caps: TransportCaps) -> (Self, Self) {
        assert!(!caps.wire_header, "the mock writes no wire header");
        let a: Inbox = Default::default();
        let b: Inbox = Default::default();
        (Self::new(caps, a.clone(), b.clone()), Self::new(caps, b, a))
    }

    fn new(caps: TransportCaps, inbox: Inbox, peer_inbox: Inbox) -> Self {
        Self {
            caps,
            pending: BytesMut::new(),
            inbox,
            peer_inbox,
            outside_io: Arc::new(NullOutsideIo),
            blocked_writes: 0,
        }
    }

    /// Packets written by the peer and not yet delivered.
    pub fn inbox(&self) -> Inbox {
        self.inbox.clone()
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
        if self.caps.lossy {
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

    fn write(&mut self, buf: &mut BytesMut) -> PollResult<usize> {
        if self.blocked_writes > 0 {
            self.blocked_writes -= 1;
            return Ok(Poll::Pending);
        }
        let n = buf.len();
        self.peer_inbox.lock().unwrap().push_back(buf.split());
        Ok(Poll::Ready(n))
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

    fn set_session_id(&mut self, _id: SessionId) {}

    fn online(&mut self) {}

    fn pmtud_probe(&mut self, _on: bool) {}

    fn set_outside_io(&mut self, io: OutsideIOSendCallbackArg) {
        self.outside_io = io;
    }

    fn peer_addr(&self) -> SocketAddr {
        self.outside_io.peer_addr()
    }

    fn set_peer_addr(&mut self, addr: SocketAddr) -> SocketAddr {
        self.outside_io.set_peer_addr(addr)
    }

    fn send_expresslane(&mut self, buf: &[u8]) -> IOCallbackResult<usize> {
        self.peer_inbox
            .lock()
            .unwrap()
            .push_back(BytesMut::from(buf));
        IOCallbackResult::Ok(buf.len())
    }

    #[cfg(target_os = "linux")]
    fn batch_begin(&mut self) {}

    #[cfg(target_os = "linux")]
    fn batch_end(&mut self, _send: bool) -> IOCallbackResult<usize> {
        IOCallbackResult::Ok(0)
    }
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
        args: TransportArgs,
        _client: ClientTransportArgs,
    ) -> Result<Box<dyn Transport>, TransportError> {
        let mut transport = self
            .0
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| TransportError::new(true, "mock transport already taken"))?;
        transport.outside_io = args.outside_io;
        Ok(Box::new(transport))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ClientContextBuilder, ClientIpConfig, CodecStatus, Connection, Event, EventCallback,
        InsideIOSendCallback, InsideIpConfig, LightwayFeature, MAX_OUTSIDE_MTU, OutsidePacket,
        PacketCodecResult, PacketDecoder, PacketEncoder, ServerAuth, ServerAuthHandle,
        ServerAuthResult, ServerContextBuilder, ServerIpPool, State, TickType, Version,
        wire::AuthMethod,
    };
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, Ordering};

    const LOSSY: TransportCaps = TransportCaps {
        lossy: true,
        reliable_control: false,
        wire_header: false,
        supports_roaming: false,
    };

    const RELIABLE: TransportCaps = TransportCaps {
        lossy: false,
        reliable_control: true,
        wire_header: false,
        supports_roaming: false,
    };

    const LOSSY_RELIABLE_CONTROL: TransportCaps = TransportCaps {
        lossy: true,
        reliable_control: true,
        wire_header: false,
        supports_roaming: false,
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
        client_inbox: Inbox,
        server_inbox: Inbox,
        client_tun: Arc<Tun>,
        server_tun: Arc<Tun>,
        events: Arc<Mutex<Vec<Event>>>,
    }

    fn pair(caps: TransportCaps) -> Pair {
        pair_with(caps, None, 0)
    }

    /// `codecs` are the client and the server codecs. The first
    /// `blocked_writes` client writes return `Pending`.
    fn pair_with(
        caps: TransportCaps,
        codecs: Option<(Arc<BlackHole>, Arc<BlackHole>)>,
        blocked_writes: usize,
    ) -> Pair {
        let (mut ct, mut st) = MockTransport::pair(caps);
        ct.blocked_writes = blocked_writes;
        let client_inbox = ct.inbox();
        let server_inbox = st.inbox();
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
            Arc::new(MockFactory::new(ct)),
            Some(client_tun.clone()),
            Arc::new(ClientIp),
            tick,
        )
        .build()
        .start_connect(Arc::new(NullOutsideIo), MAX_OUTSIDE_MTU)
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
            .start_accept(Version::MAXIMUM, Arc::new(NullOutsideIo))
            .unwrap()
            .with_inside_pkt_codec(server_codec)
            .accept(
                (),
                Box::new(move |args| {
                    st.outside_io = args.outside_io;
                    Ok(Box::new(st))
                }),
            )
            .unwrap();

        Pair {
            client,
            server,
            client_inbox,
            server_inbox,
            client_tun,
            server_tun,
            events: log,
        }
    }

    fn deliver(conn: &mut Connection<()>, inbox: &Inbox) -> bool {
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
                let a = deliver(&mut self.client, &self.client_inbox);
                let b = deliver(&mut self.server, &self.server_inbox);
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
    }

    #[test_case::test_case(RELIABLE; "reliable")]
    #[test_case::test_case(LOSSY_RELIABLE_CONTROL; "lossy with reliable control")]
    fn control_frames_queue_behind_a_blocked_write(caps: TransportCaps) {
        let mut p = pair_with(caps, None, 1);
        assert!(
            p.server_inbox.lock().unwrap().is_empty(),
            "auth request went through a blocked write"
        );

        // The tick resends the auth request, and that write also
        // flushes the one the connection queued.
        p.client.tick(TickType::ConnectionTick).unwrap();
        assert_eq!(p.server_inbox.lock().unwrap().len(), 2);
        p.pump_to_online();
    }
}
