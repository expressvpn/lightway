use crate::common::packet_codec::TestPacketCodecFactory;
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use lightway_app_utils::{
    ConnectionTicker, ConnectionTickerState, EventStreamCallback, PacketCodecFactory,
    connection_ticker_cb,
};
use lightway_core::*;
use more_asserts::*;
use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};
use tokio_stream::StreamExt;

use crate::common::certgen::gen_shared_testing_pki;

#[derive(Default)]
pub struct TestAuth {
    /// Captures the last [`AuthMethod`] seen by [`ServerAuth::authorize`]
    /// so integration tests can assert which auth variant the server
    /// actually received.
    last_method: Arc<Mutex<Option<AuthMethod>>>,
}

impl TestAuth {
    pub fn new() -> (Arc<Self>, Arc<Mutex<Option<AuthMethod>>>) {
        let auth = Arc::new(Self::default());
        let last_method = auth.last_method.clone();
        (auth, last_method)
    }
}

impl ServerAuth<ConnectionTicker> for TestAuth {
    fn authorize(&self, method: &AuthMethod, app_state: &mut ConnectionTicker) -> ServerAuthResult {
        *self.last_method.lock().unwrap() = Some(method.clone());
        match method {
            AuthMethod::Token { token } | AuthMethod::VersionedToken { token, .. } => {
                self.authorize_token(token, app_state)
            }
            _ => ServerAuthResult::Denied,
        }
    }

    fn authorize_token(&self, _token: &str, _app_state: &mut ConnectionTicker) -> ServerAuthResult {
        ServerAuthResult::Granted {
            handle: Some(Box::new(TestAuthHandle)),
            tunnel_protocol_version: None,
        }
    }
}

#[derive(Debug)]
pub struct TestAuthHandle;

impl ServerAuthHandle for TestAuthHandle {
    fn expired(&self) -> bool {
        false
    }

    fn features(&self) -> HashSet<LightwayFeature> {
        HashSet::from([LightwayFeature::InsidePktCodec])
    }
}

pub struct ChannelTun(mpsc::UnboundedSender<Bytes>);

impl ChannelTun {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<Bytes>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self(tx), rx)
    }
}
impl<T> InsideIOSendCallback<T> for ChannelTun {
    fn send(&self, buf: BytesMut, _state: &mut T) -> IOCallbackResult<usize> {
        let buf_len = buf.len();
        self.0.send(buf.freeze()).expect("Send");
        IOCallbackResult::Ok(buf_len)
    }

    fn mtu(&self) -> usize {
        1350
    }

    fn if_index(&self) -> std::io::Result<u32> {
        Err(std::io::Error::other("Not Implemented"))
    }

    fn name(&self) -> std::io::Result<String> {
        Err(std::io::Error::other("Not Implemented"))
    }
}

// Static IP pool
pub struct StaticIpPool;

impl ServerIpPool<ConnectionTicker> for StaticIpPool {
    fn alloc(&self, _state: &mut ConnectionTicker) -> Option<InsideIpConfig> {
        Some(InsideIpConfig {
            client_ip: "10.125.0.2".parse().unwrap(),
            server_ip: "10.125.0.1".parse().unwrap(),
            dns_ip: "10.125.0.1".parse().unwrap(),
        })
    }

    /// Allocate IP from free pool
    fn free(&self, _state: &mut ConnectionTicker) {}
}

#[async_trait]
pub trait TestSock {
    fn connection_type(&self) -> ConnectionType;

    fn into_io_send_callback(self: Arc<Self>) -> OutsideIOSendCallbackArg;

    async fn writable(&self) -> std::io::Result<()>;
    async fn readable(&self) -> std::io::Result<()>;

    fn try_recv_buf<B: BufMut>(&self, buf: &mut B) -> std::io::Result<usize>;
}

pub struct TestDatagramSock(pub tokio::net::UnixDatagram);

#[async_trait]
impl TestSock for TestDatagramSock {
    fn connection_type(&self) -> ConnectionType {
        ConnectionType::Datagram
    }

    fn into_io_send_callback(self: Arc<Self>) -> OutsideIOSendCallbackArg {
        self
    }

    async fn writable(&self) -> std::io::Result<()> {
        self.0.writable().await
    }

    async fn readable(&self) -> std::io::Result<()> {
        self.0.readable().await
    }

    fn try_recv_buf<B: BufMut>(&self, buf: &mut B) -> std::io::Result<usize> {
        self.0.try_recv_buf(buf)
    }
}

impl OutsideIOSendCallback for TestDatagramSock {
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        match self.0.try_send(buf) {
            Ok(nr) => IOCallbackResult::Ok(nr),
            // Real datagram sockets never block (blocking confuses the TLS library),
            // but they do drop. A full send buffer surfaces as WouldBlock on Linux and
            // ENOBUFS on macOS; both are just a drop, so report success and let DTLS
            // retransmit rather than propagating a fatal socket error to wolfSSL.
            Err(_) => IOCallbackResult::Ok(buf.len()),
        }
    }

    fn send_gso(&self, _bufs: &[std::io::IoSlice<'_>], _gso_size: u16) -> IOCallbackResult<usize> {
        IOCallbackResult::Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    fn peer_addr(&self) -> SocketAddr {
        // A UnixDatagram has no IP peer; expresslane key publishes carry
        // the value opaquely.
        SocketAddr::from(([127, 0, 0, 1], 0))
    }

    fn enable_pmtud_probe(&self) -> std::io::Result<()> {
        todo!()
    }

    fn disable_pmtud_probe(&self) -> std::io::Result<()> {
        todo!()
    }
}

pub struct TestStreamSock(pub tokio::net::UnixStream);

#[async_trait]
impl TestSock for TestStreamSock {
    fn connection_type(&self) -> ConnectionType {
        ConnectionType::Stream
    }

    fn into_io_send_callback(self: Arc<Self>) -> OutsideIOSendCallbackArg {
        self
    }

    async fn writable(&self) -> std::io::Result<()> {
        self.0.writable().await
    }

    async fn readable(&self) -> std::io::Result<()> {
        self.0.readable().await
    }

    fn try_recv_buf<B: BufMut>(&self, buf: &mut B) -> std::io::Result<usize> {
        self.0.try_read_buf(buf)
    }
}

impl OutsideIOSendCallback for TestStreamSock {
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        match self.0.try_write(buf) {
            Ok(nr) => IOCallbackResult::Ok(nr),
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                IOCallbackResult::WouldBlock
            }
            Err(err) => IOCallbackResult::Err(err),
        }
    }

    fn send_gso(&self, _bufs: &[std::io::IoSlice<'_>], _gso_size: u16) -> IOCallbackResult<usize> {
        IOCallbackResult::Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    fn peer_addr(&self) -> SocketAddr {
        todo!()
    }
}

pub async fn server<S: TestSock>(
    sock: Arc<S>,
    auth: Arc<TestAuth>,
    pqc: PQCrypto,
    expresslane: Option<std::time::Duration>,
    conn_out: Option<oneshot::Sender<Arc<Mutex<lightway_core::Connection<ConnectionTicker>>>>>,
    metrics: Option<ExpresslaneMetricsType>,
) {
    let pki = gen_shared_testing_pki();
    let server_key = Secret::Asn1Buffer(&pki.server.key_der);
    let server_cert = Secret::Asn1Buffer(&pki.server.cert_der);
    let ip_pool = Arc::new(StaticIpPool);

    let (tun, mut inside_rx) = ChannelTun::new();
    let mut last_inside_rx = std::time::Instant::now();

    let packet_codec = TestPacketCodecFactory::default().build();
    let (packet_codec, mut encoded_pkt_receiver, mut decoded_pkt_receiver) = (
        Some((packet_codec.encoder, packet_codec.decoder)),
        packet_codec.encoded_pkt_receiver,
        packet_codec.decoded_pkt_receiver,
    );

    let connection_type = sock.connection_type();
    let server_ctx = ServerContextBuilder::<ConnectionTicker>::new(
        connection_type,
        server_cert,
        server_key,
        auth,
        ip_pool,
        Arc::new(tun),
        connection_ticker_cb,
    )
    .unwrap()
    .with_minimum_protocol_version(Version::MINIMUM)
    .unwrap()
    .with_maximum_protocol_version(Version::MAXIMUM)
    .unwrap();

    let server_ctx = server_ctx.when(pqc.enable_server(), |s| s.enable_pq_crypto().unwrap());

    let server_ctx = server_ctx
        .when_some(expresslane, |s, interval| s.with_expresslane(interval))
        .when_some(metrics, |s, m| s.with_expresslane_metrics(m))
        .build()
        .unwrap();

    let (ticker, ticker_task) = ConnectionTicker::new();
    // Use Version::MAXIMUM to match default client version
    // This mirrors the real server which reads version from client packet header
    let version = Version::MAXIMUM;
    let conn = Arc::new(Mutex::new(
        server_ctx
            .start_accept(version, sock.clone().into_io_send_callback())
            .unwrap()
            .with_inside_pkt_codec(packet_codec)
            .accept(ticker)
            .unwrap(),
    ));

    if let Some(tx) = conn_out {
        let _ = tx.send(conn.clone());
    }

    let mut join_set = JoinSet::new();

    ticker_task.spawn_in(Arc::downgrade(&conn), &mut join_set);
    loop {
        tokio::select! {
            // Inside data received
            Some(buf) = inside_rx.recv() => {
                let mut conn = conn.lock().unwrap();

                assert!(matches!(conn.state(), State::Online));
                // Reflect back to the client
                let mut reply: BytesMut = BytesMut::from(&buf[..]);

                assert_ge!(
                    conn.activity().last_data_traffic_from_peer,
                    last_inside_rx,
                    "ConnectionActivity.last_data_traffic_from_peer should be updated"
                );
                last_inside_rx = std::time::Instant::now();

                conn.inside_data_received(&mut reply).expect("Reflect data");

                // https://github.com/wolfSSL/wolfssl/pull/6771 means
                // this currently returns None.
                // When this is fixed this will fail, replace `if let` with `unwrap`.
                if let Some(curve) = conn.current_curve() {
                    assert_eq!(curve, pqc.expected_curve());
                }
            },

            // Encoded packet received (inside -> outside)
            Some(mut encoded_packet) = encoded_pkt_receiver.recv() => {
                let mut conn = conn.lock().unwrap();
                conn.send_to_outside(&mut encoded_packet, true).expect("Reflect data");
            }

            // Outside event loop
            is_readable = sock.readable() => {
                is_readable.expect("Server socket to become readable");

                let mut buf = BytesMut::with_capacity(MAX_OUTSIDE_MTU);

                match sock.try_recv_buf(&mut buf) {
                    Ok(0) => {
                        panic!("EOF");
                    }
                    Ok(_nr) => {}
                    Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                        // Spuriously failed to read, keep waiting
                        continue;
                    }
                    Err(err) => panic!("read for sock {err}"),
                };

                let now = std::time::Instant::now();

                let mut conn = conn.lock().unwrap();

                assert_le!(conn.activity().last_outside_data_received, now,
                           "ConnectionActivity.last_outside_data_received should be in the past");

                let pkt = OutsidePacket::Wire(&mut buf, connection_type);
                let r = conn.outside_data_received(pkt);

                assert_ge!(conn.activity().last_outside_data_received, now,
                           "ConnectionActivity.last_outside_data_received should be updated");

                match r {
                    Err(ConnectionError::Goodbye) => {
                        println!("Server: Client said goodbye");
                        return;
                    },
                    Err(err) => panic!("{err}"),
                    Ok(_) => continue,
                }
            }

            // Decoded packet received (outside -> inside)
            Some(decoded_packet) = decoded_pkt_receiver.recv() => {
                let mut conn = conn.lock().unwrap();
                conn.send_to_inside(decoded_packet).expect("server decoded pkt outside to inside");
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Client;

impl ClientIpConfig<ConnectionState> for Client {
    fn ip_config(&self, _state: &mut ConnectionState, ip_config: InsideIpConfig) {
        println!("Got IP from server: {ip_config:?}");
    }
}

pub struct ConnectionState {
    pub ticker: ConnectionTicker,
}

impl ConnectionTickerState for ConnectionState {
    fn connection_ticker(&self) -> &ConnectionTicker {
        &self.ticker
    }
}

// In each test, the client act as a state machine
// with three states.
//
// Note: if inside packet codec is not enabled, the
// "PendingCodecResponse" state will be skipped.
pub enum ClientTestState {
    // Lightway just changed state to Connected, and
    // Has not yet send the encoding request or the
    // message packet from TUN.
    Initial,

    // Lightway has already sent an encoding request
    // to the server, and is waiiting for an encoding
    // response to arrive.
    PendingCodecResponse,

    // Waiting for Expresslane to be active
    PendingActiveExpresslane,

    // Lightway has already sent the message packet.
    MessageSent,
}

pub async fn client<S: TestSock>(
    sock: Arc<S>,
    cipher: Option<Cipher>,
    pqc: PQCrypto,
    server_dn: Option<&str>,
    enable_codec: bool,
    enable_expresslane: bool,
    use_versioned_token: bool,
) {
    let ca_cert = RootCertificate::Asn1Buffer(&gen_shared_testing_pki().ca_cert_der);
    let (tun, mut inside_rx) = ChannelTun::new();
    let client = Arc::new(Client);

    let mut join_set = JoinSet::new();

    let (event_cb, mut event_stream) = EventStreamCallback::new();

    let packet_codec = TestPacketCodecFactory::default().build();
    let encoder = packet_codec.encoder.clone();
    let (packet_codec, mut encoded_pkt_receiver, mut decoded_pkt_receiver) = (
        Some((packet_codec.encoder, packet_codec.decoder)),
        packet_codec.encoded_pkt_receiver,
        packet_codec.decoded_pkt_receiver,
    );

    let (ticker, ticker_task) = ConnectionTicker::new();

    let state = ConnectionState { ticker };

    let client = ClientContextBuilder::new(
        sock.connection_type(),
        ca_cert,
        Some(Arc::new(tun)),
        client,
        connection_ticker_cb,
    )
    .unwrap()
    .when_some(cipher, |b, cipher| b.with_cipher(cipher).unwrap())
    .when(enable_expresslane, |b| {
        b.with_expresslane(DEFAULT_EXPRESSLANE_KEYS_ROTATION_INTERVAL)
    });

    let client = client.enable_pq_crypto().unwrap();

    let client = client
        .build()
        .start_connect(sock.clone().into_io_send_callback(), MAX_OUTSIDE_MTU)
        .unwrap()
        .when(use_versioned_token, |b| {
            b.with_auth_versioned_token("LET ME IN", Version::MAXIMUM)
        })
        .when(!use_versioned_token, |b| b.with_auth_token("LET ME IN"))
        .with_event_cb(Box::new(event_cb))
        .with_inside_pkt_codec(packet_codec);

    let client = client.when_some(pqc.client_keyshare(), |b, ks| b.with_pq_crypto(ks));

    let client = client
        .when_some(server_dn, |b, sdn| {
            b.with_server_domain_name_validation(sdn)
        })
        .connect(state)
        .unwrap();
    let client = Arc::new(Mutex::new(client));

    ticker_task.spawn_in(Arc::downgrade(&client), &mut join_set);

    let event_client = client.clone();

    let mut is_first_packet_received = false;
    let last_expresslane_state: Arc<Mutex<Option<ExpresslaneState>>> = Arc::new(Mutex::new(None));
    let expresslane_event = last_expresslane_state.clone();
    let expresslane_notify = Arc::new(tokio::sync::Notify::new());
    let expresslane_notify_event = expresslane_notify.clone();
    let event_handler_handle = tokio::spawn(async move {
        let client = event_client;
        while let Some(event) = event_stream.next().await {
            println!("Client state changed to {event:?}");
            match event {
                Event::StateChanged(State::Online) => {
                    let mut client = client.lock().unwrap();
                    let conn_type = client.connection_type();
                    let session_id = client.session_id();
                    let protocol = client.tls_protocol_version();
                    let cipher = client.current_cipher().unwrap();
                    let curve = client.current_curve().unwrap();
                    eprintln!(
                        "{conn_type:?} connection is Online with {session_id:?}, negotiated protocol {protocol:?}, {cipher} & {curve}"
                    );
                }
                Event::StateChanged(state) => eprintln!("Connection change to {state:?}"),
                Event::KeepaliveReply => eprintln!("Got keepalive reply"),
                Event::SessionIdRotationStarted { .. } => {
                    eprintln!("Got SessionIdRotationStarted")
                }
                Event::SessionIdRotationAcknowledged { .. } => {
                    eprintln!("Got SessionIdRotationAcknowledged")
                }
                Event::TlsKeysUpdateStart => println!("Got TlsKeysUpdateStart"),
                Event::TlsKeysUpdateCompleted => println!("Got TlsKeysUpdateEnd"),
                Event::FirstPacketReceived => {
                    assert!(!is_first_packet_received);
                    println!("First packet received");
                    is_first_packet_received = true;
                }
                Event::ExpresslaneStateChanged(state) => {
                    println!("Expresslane state change to {state:?}");
                    expresslane_event.lock().unwrap().replace(state);
                    expresslane_notify_event.notify_one();
                }
                Event::EncodingStateChanged { enabled } => {
                    println!("Encoding state change to {enabled}")
                }
                Event::PmtudStateChanged(status) => {
                    println!("PMTUD status change to {status:?}")
                }
            }
        }
    });

    let mut client_test_state = ClientTestState::Initial;

    // Inside packet codec is only supported for Lightway UDP
    let enable_codec = sock.connection_type().is_datagram() && enable_codec;

    loop {
        // This has to look enough like an ipv4 packet to
        // make it through. In practice for now that means
        // the version (the first nibble in the packet)
        // needs to be ok.
        //
        // (Note that 'H' is ASCII 0x48 so that happens to
        // work as the first byte too, but be more
        // explicit to avoid a confusing surprise for some
        // future developer).
        let mut message_packet: BytesMut = BytesMut::from(&b"\x40Hello World!"[..]);

        if event_handler_handle.is_finished() {
            // Event handler returning early. Fatal error.
            let result = event_handler_handle.await;
            panic!("Event handler returning early. Fatal error. {result:?}");
        }

        tokio::select! {

            // Inside data received
            Some(buf) = inside_rx.recv() => {
                let mut client = client.lock().unwrap();
                assert!(matches!(client.state(), State::Online));
                assert!(matches!(client_test_state, ClientTestState::MessageSent));

                assert_eq!(&buf[..], message_packet[..].as_ref());

                let curve = client.current_curve().unwrap();
                assert_eq!(curve, pqc.expected_curve());

                // All done!
                println!("Client: Disconnecting");
                client.disconnect().unwrap();

                return
            },

            // Encoded packet received (inside -> outside)
            Some(mut encoded_packet) = encoded_pkt_receiver.recv() => {
                let mut client = client.lock().unwrap();
                client.send_to_outside(&mut encoded_packet, true).expect("Send my message");
            }

            // Outside event loop
            is_readable = sock.readable() => {
                is_readable.expect("Server socket to become readable");

                let mut buf = BytesMut::with_capacity(MAX_OUTSIDE_MTU);

                match sock.try_recv_buf(&mut buf) {
                    Ok(0) => {
                        panic!("EOF");
                    }
                    Ok(_nr) => {}
                    Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                        // Spuriously failed to read, keep waiting
                        continue;
                    }
                    Err(err) => panic!("read for sock {err}"),
                };

                let mut client = client.lock().unwrap();

                let pkt = OutsidePacket::Wire(&mut buf, sock.connection_type());
                if let Err(err) = client.outside_data_received(pkt) {
                    // TODO: fatal vs non-fatal;
                    panic!("{err}")
                }

                println!("Client: {:?}", client.state());
                if !matches!(client.state(), State::Online) {
                    continue
                }

                match client_test_state {
                    ClientTestState::Initial => {
                        // Send a ping
                        eprintln!("Sending keepalive");
                        client.keepalive().unwrap();

                        if enable_codec {
                            // Send an encoding request
                            client.set_encoding(true).expect("client set encoding");
                            eprintln!("Sending encoding request");
                            client_test_state = ClientTestState::PendingCodecResponse;
                        } else if enable_expresslane {
                            client_test_state = ClientTestState::PendingActiveExpresslane;
                        }
                        else {
                            // Directly send the message
                            eprintln!("Sending message: {message_packet:?}");
                            client.inside_data_received(&mut message_packet).expect("Send my message");
                            client_test_state = ClientTestState::MessageSent;
                        }
                    }
                    ClientTestState::PendingCodecResponse => {
                        if !encoder.get_encoding_state() {
                            eprintln!("awaiting encoding response from the server");
                            // Encoding response not yet received. Keep waiting.
                            continue
                        }

                        eprintln!("Sending message: {message_packet:?}");
                        client.inside_data_received(&mut message_packet).expect("Send my message");
                        client_test_state = ClientTestState::MessageSent;
                    }
                    ClientTestState::PendingActiveExpresslane | ClientTestState::MessageSent => {},
                }
            }

            // A new expresslane state change
            _ = expresslane_notify.notified(), if matches!(client_test_state, ClientTestState::PendingActiveExpresslane) => {
                let state = last_expresslane_state.lock().unwrap();
                if matches!(*state, Some(ExpresslaneState::Active)) {
                    drop(state);
                    let mut client = client.lock().unwrap();
                    eprintln!("Sending message: {message_packet:?}");
                    client.inside_data_received(&mut message_packet).expect("Send my message");
                    client_test_state = ClientTestState::MessageSent;
                }
            }

            // Decoded packet received (outside -> inside)
            Some(decoded_packet) = decoded_pkt_receiver.recv() => {
                let mut client = client.lock().unwrap();
                if let Err(err) = client.send_to_inside(decoded_packet) {
                    // TODO: fatal vs non-fatal;
                    panic!("{err}")
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
pub struct PQCrypto {
    pub server_pqc: bool,
    pub keyshare: Option<KeyShare>,
}

impl PQCrypto {
    fn enable_server(&self) -> bool {
        self.server_pqc
    }

    fn client_keyshare(&self) -> Option<KeyShare> {
        self.keyshare
    }

    pub fn expected_curve(&self) -> &str {
        cfg_if::cfg_if! {
            if #[cfg(boringssl)] {
                if !self.server_pqc {
                    "P-256"
                } else {
                    // BoringSSL only exposes X25519MLKEM768 as a PQ key share group.
                    // P521 hybrids and other ML-KEM variants are not supported.
                    "X25519MLKEM768"
                }
            } else {
                if !self.server_pqc {
                    "SECP256R1"
                } else {
                    match self.keyshare {
                        Some(KeyShare::P521MLKEM1024) => "SecP521r1MLKEM1024",
                        Some(KeyShare::X25519MLKEM768) => "X25519MLKEM768",
                        // Test cases should always set a keyshare when server_pqc is on;
                        // None falls back to KeyShare::default(), which on wolfSSL is
                        // P521MLKEM1024.
                        None => "SecP521r1MLKEM1024",
                    }
                }
            }
        }
    }
}

impl Default for PQCrypto {
    fn default() -> Self {
        Self {
            server_pqc: true,
            keyshare: Some(KeyShare::default()),
        }
    }
}
