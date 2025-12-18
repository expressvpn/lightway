use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use more_asserts::*;
use test_case::test_case;
use tokio::{
    net::{UnixDatagram, UnixStream},
    sync::mpsc,
    task::JoinSet,
};
use tokio_stream::StreamExt;

use lightway_app_utils::{
    ConnectionTicker, ConnectionTickerState, EventStreamCallback, PacketCodecFactory,
    connection_ticker_cb,
};
use lightway_core::*;

mod packet_codec;
use packet_codec::TestPacketCodecFactory;

const CA_CERT: &[u8] = &include!("data/ca_cert_der_2048");
const SERVER_CERT: &[u8] = &include!("data/server_cert_der_2048");
const SERVER_KEY: &[u8] = &include!("data/server_key_der_2048");

struct TestAuth;

impl ServerAuth<ConnectionTicker> for TestAuth {
    fn authorize_token(&self, _token: &str, _app_state: &mut ConnectionTicker) -> ServerAuthResult {
        ServerAuthResult::Granted {
            handle: Some(Box::new(TestAuthHandle)),
            tunnel_protocol_version: None,
        }
    }
}

#[derive(Debug)]
struct TestAuthHandle;

impl ServerAuthHandle for TestAuthHandle {
    fn expired(&self) -> bool {
        false
    }

    fn features(&self) -> HashSet<LightwayFeature> {
        HashSet::from([LightwayFeature::InsidePktCodec])
    }
}

struct ChannelTun(mpsc::UnboundedSender<Bytes>);

impl ChannelTun {
    fn new() -> (Self, mpsc::UnboundedReceiver<Bytes>) {
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
struct StaticIpPool;

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
trait TestSock {
    fn connection_type(&self) -> ConnectionType;

    fn into_io_send_callback(self: Arc<Self>) -> OutsideIOSendCallbackArg;

    async fn writable(&self) -> std::io::Result<()>;
    async fn readable(&self) -> std::io::Result<()>;

    fn try_recv_buf<B: BufMut>(&self, buf: &mut B) -> std::io::Result<usize>;
}

struct TestDatagramSock(tokio::net::UnixDatagram);

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
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                // Real sockets never block (and doing so confuses WolfSSL!), but they do drop, so we do too!
                IOCallbackResult::Ok(buf.len())
            }
            Err(err) => IOCallbackResult::Err(err),
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        todo!()
    }

    fn enable_pmtud_probe(&self) -> std::io::Result<()> {
        todo!()
    }

    fn disable_pmtud_probe(&self) -> std::io::Result<()> {
        todo!()
    }
}

struct TestStreamSock(tokio::net::UnixStream);

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

    fn peer_addr(&self) -> SocketAddr {
        todo!()
    }
}

async fn server<S: TestSock>(sock: Arc<S>, pqc: PQCrypto) {
    let server_key = Secret::Asn1Buffer(SERVER_KEY);
    let server_cert = Secret::Asn1Buffer(SERVER_CERT);
    let auth = Arc::new(TestAuth);
    let ip_pool = Arc::new(StaticIpPool);

    let (tun, mut inside_rx) = ChannelTun::new();
    let mut last_inside_rx = std::time::Instant::now();

    let packet_codec = TestPacketCodecFactory::default().build();
    let (packet_codec, mut encoded_pkt_receiver, mut decoded_pkt_receiver) = {
        (
            Some((packet_codec.encoder, packet_codec.decoder)),
            packet_codec.encoded_pkt_receiver,
            packet_codec.decoded_pkt_receiver,
        )
    };

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
    .unwrap()
    .when(pqc.enable_server(), |s| s.with_pq_crypto().unwrap())
    .build()
    .unwrap();

    let (ticker, ticker_task) = ConnectionTicker::new();
    // Use Version(1, 2) to match default client version (when expresslane is not enabled)
    // This mirrors the real server which reads version from client packet header
    let conn = Arc::new(Mutex::new(
        server_ctx
            .start_accept(
                Version::try_new(1, 2).unwrap(),
                sock.clone().into_io_send_callback(),
            )
            .unwrap()
            .with_inside_pkt_codec(packet_codec)
            .accept(ticker)
            .unwrap(),
    ));

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

                let curve = conn.current_curve().unwrap();
                assert_eq!(curve, pqc.expected_curve());
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
struct Client;

impl ClientIpConfig<ConnectionState> for Client {
    fn ip_config(&self, _state: &mut ConnectionState, ip_config: InsideIpConfig) {
        println!("Got IP from server: {ip_config:?}");
    }
}

struct ConnectionState {
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
enum ClientTestState {
    // Lightway just changed state to Connected, and
    // Has not yet send the encoding request or the
    // message packet from TUN.
    Initial,

    // Lightway has already sent an encoding request
    // to the server, and is waiiting for an encoding
    // response to arrive.
    PendingCodecResponse,

    // Lightway has already sent the message packet.
    MessageSent,
}

async fn client<S: TestSock>(
    sock: Arc<S>,
    cipher: Option<Cipher>,
    pqc: PQCrypto,
    server_dn: Option<&str>,
    enable_codec: bool,
) {
    let ca_cert = RootCertificate::Asn1Buffer(CA_CERT);
    let (tun, mut inside_rx) = ChannelTun::new();
    let client = Arc::new(Client);

    let mut join_set = JoinSet::new();

    let (event_cb, mut event_stream) = EventStreamCallback::new();

    let packet_codec = TestPacketCodecFactory::default().build();
    let encoder = packet_codec.encoder.clone();
    let (packet_codec, mut encoded_pkt_receiver, mut decoded_pkt_receiver) = {
        (
            Some((packet_codec.encoder, packet_codec.decoder)),
            packet_codec.encoded_pkt_receiver,
            packet_codec.decoded_pkt_receiver,
        )
    };

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
    .build()
    .start_connect(sock.clone().into_io_send_callback(), MAX_OUTSIDE_MTU)
    .unwrap()
    .with_auth_token("LET ME IN")
    .with_event_cb(Box::new(event_cb))
    .with_inside_pkt_codec(packet_codec)
    .when(pqc.enable_client(), |b| b.with_pq_crypto())
    .when_some(server_dn, |b, sdn| {
        b.with_server_domain_name_validation(sdn.to_string())
    })
    .connect(state)
    .unwrap();
    let client = Arc::new(Mutex::new(client));

    ticker_task.spawn_in(Arc::downgrade(&client), &mut join_set);

    let event_client = client.clone();

    let mut is_first_packet_received = false;
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
                Event::EncodingStateChanged { enabled } => {
                    println!("Encoding state change to {enabled}")
                }
            }
        }
    });

    let mut client_test_state = ClientTestState::Initial;

    // Inside packet codec is only supported for Lightway UDP
    let enable_codec = sock.connection_type().is_datagram() && enable_codec;

    loop {
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

                assert_eq!(&buf[..], b"\x40Hello World!");

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
                        } else {
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
                    ClientTestState::MessageSent => {}
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
enum PQCrypto {
    // PQC enabled client and server
    Enabled,
    // PQC disabled client and server
    Disabled,
    // PQC available on server, but not on client
    ServerOnly,
    // PQC not enabled on server, but client tries to use
    ClientOnly,
}

impl PQCrypto {
    fn enable_server(&self) -> bool {
        match self {
            PQCrypto::Enabled => true,
            PQCrypto::Disabled => false,
            PQCrypto::ServerOnly => true,
            PQCrypto::ClientOnly => false,
        }
    }

    fn enable_client(&self) -> bool {
        match self {
            PQCrypto::Enabled => true,
            PQCrypto::Disabled => false,
            PQCrypto::ServerOnly => false,
            PQCrypto::ClientOnly => true,
        }
    }

    fn expected_curve(&self) -> &str {
        match self {
            #[cfg(not(feature = "kyber_only"))]
            PQCrypto::Enabled => "SecP521r1MLKEM1024",
            #[cfg(feature = "kyber_only")]
            PQCrypto::Enabled => "P521_KYBER_LEVEL5",
            PQCrypto::Disabled => "SECP256R1",
            PQCrypto::ServerOnly => "SECP256R1",
            PQCrypto::ClientOnly => "SECP256R1",
        }
    }
}

fn get_test_timeout() -> u64 {
    #[cfg(target_arch = "riscv64")]
    return 5000;
    2000
}

async fn run_test_tcp<S: TestSock>(
    cipher: Option<Cipher>,
    pqc: PQCrypto,
    server_sock: Arc<S>,
    client_sock: Arc<S>,
) {
    // Inside packet codec is only supported by Lightway UDP
    run_test(cipher, pqc, server_sock, client_sock, false).await;
}

async fn run_test<S: TestSock>(
    cipher: Option<Cipher>,
    pqc: PQCrypto,
    server_sock: Arc<S>,
    client_sock: Arc<S>,
    enable_codec: bool,
) {
    let test = async move {
        tokio::join!(
            server(server_sock, pqc),
            client(client_sock, cipher, pqc, None, enable_codec)
        )
    };

    tokio::time::timeout(std::time::Duration::from_millis(get_test_timeout()), test)
        .await
        .expect("Timed out");
}

#[test_case(None,                   PQCrypto::Enabled,    false; "Default cipher + PQC")]
#[test_case(Some(Cipher::Aes256),   PQCrypto::Enabled,    false; "aes + PQC")]
#[test_case(Some(Cipher::Chacha20), PQCrypto::Enabled,    false; "chacha20 +_PQC")]
#[test_case(None,                   PQCrypto::Disabled,   false; "PQC disabled")]
#[test_case(None,                   PQCrypto::ServerOnly, false; "PQC server only")]
#[test_case(None,                   PQCrypto::ClientOnly, false; "PQC client only")]
#[test_case(Some(Cipher::Aes256),   PQCrypto::Enabled,     true; "Inside packet codec")]
#[tokio::test]
async fn test_datagram_connection(cipher: Option<Cipher>, pqc: PQCrypto, enable_codec: bool) {
    // Communicate over a local datagram socket for simplicity
    let (client_sock, server_sock) = UnixDatagram::pair().expect("UnixDatagram");
    let socket = socket2::SockRef::from(&client_sock);
    socket.set_recv_buffer_size(1024 * 256).unwrap();
    let socket = socket2::SockRef::from(&server_sock);
    socket.set_recv_buffer_size(1024 * 256).unwrap();

    let server_sock = Arc::new(TestDatagramSock(server_sock));
    let client_sock = Arc::new(TestDatagramSock(client_sock));

    run_test(cipher, pqc, server_sock, client_sock, enable_codec).await;
}

#[test_case(None,                   PQCrypto::Enabled;    "Default cipher + PQC")]
#[test_case(Some(Cipher::Aes256),   PQCrypto::Enabled;    "aes + PQC")]
#[test_case(Some(Cipher::Chacha20), PQCrypto::Enabled;    "chacha20 + PQC")]
#[test_case(None,                   PQCrypto::Disabled;   "PQC disabled")]
#[test_case(None,                   PQCrypto::ServerOnly; "PQC server only")]
#[test_case(None,                   PQCrypto::ClientOnly; "PQC client only")]
#[tokio::test]
async fn test_stream_connection(cipher: Option<Cipher>, pqc: PQCrypto) {
    // Communicate over a local stream socket for simplicity
    let (client_sock, server_sock) = UnixStream::pair().expect("UnixStream");
    let server_sock = Arc::new(TestStreamSock(server_sock));
    let client_sock = Arc::new(TestStreamSock(client_sock));

    // We need the server end to be ready to receive before we can get
    // started, else we'll get a `WouldBlock`.
    let _ = client_sock.writable().await;

    run_test_tcp(cipher, pqc, server_sock, client_sock).await;
}

#[test_case(None; "No server domain name")]
#[test_case(Some("example.com"); "Valid server domain name")]
#[test_case(Some("invalid") => panics "WolfSSL Error: Fatal: Domain name mismatch"; "Invalid server domain name")]
#[tokio::test]
async fn test_server_dn(server_dn: Option<&str>) {
    // Communicate over a local stream socket for simplicity
    let (client_sock, server_sock) = UnixStream::pair().expect("UnixStream");
    let server_sock = Arc::new(TestStreamSock(server_sock));
    let client_sock = Arc::new(TestStreamSock(client_sock));

    // We need the server end to be ready to receive before we can get
    // started, else we'll get a `WouldBlock`.
    let _ = client_sock.writable().await;

    let test = async move {
        tokio::join!(
            server(server_sock, PQCrypto::Enabled),
            client(client_sock, None, PQCrypto::Enabled, server_dn, false)
        )
    };

    tokio::time::timeout(std::time::Duration::from_millis(get_test_timeout()), test)
        .await
        .expect("Timed out");
}
