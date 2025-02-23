use std::{
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

use lightway_app_utils::{ConnectionTicker, EventStreamCallback, connection_ticker_cb};
use lightway_core::*;

const CA_CERT: &[u8] = &include!("data/ca_cert_der_2048");
const SERVER_CERT: &[u8] = &include!("data/server_cert_der_2048");
const SERVER_KEY: &[u8] = &include!("data/server_key_der_2048");

struct TestAuth;

impl ServerAuth<ConnectionTicker> for TestAuth {
    fn authorize_token(&self, _token: &str, _app_state: &mut ConnectionTicker) -> ServerAuthResult {
        ServerAuthResult::Granted {
            handle: None,
            tunnel_protocol_version: None,
        }
    }
}

struct ChannelTun(mpsc::UnboundedSender<Bytes>);

impl ChannelTun {
    fn new() -> (Self, mpsc::UnboundedReceiver<Bytes>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self(tx), rx)
    }
}
impl InsideIOSendCallback<ConnectionTicker> for ChannelTun {
    fn send(&self, buf: BytesMut, _state: &mut ConnectionTicker) -> IOCallbackResult<usize> {
        let buf_len = buf.len();
        self.0.send(buf.freeze()).expect("Send");
        IOCallbackResult::Ok(buf_len)
    }

    fn mtu(&self) -> usize {
        1350
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

    let connection_type = sock.connection_type();
    let server_ctx = ServerContextBuilder::<ConnectionTicker>::new(
        connection_type,
        server_cert,
        server_key,
        auth,
        ip_pool,
        Arc::new(tun),
    )
    .unwrap()
    .with_schedule_tick_cb(connection_ticker_cb)
    .with_minimum_protocol_version(Version::MAXIMUM)
    .unwrap()
    .with_maximum_protocol_version(Version::MAXIMUM)
    .unwrap()
    .when(pqc.enable_server(), |s| s.with_pq_crypto().unwrap())
    .build()
    .unwrap();

    let (ticker, ticker_task) = ConnectionTicker::new();
    let conn = Arc::new(Mutex::new(
        server_ctx
            .start_accept(Version::MAXIMUM, sock.clone().into_io_send_callback())
            .unwrap()
            .accept(ticker)
            .unwrap(),
    ));

    let mut join_set = JoinSet::new();

    ticker_task.spawn(Arc::downgrade(&conn), &mut join_set);
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
        }
    }
}

#[derive(Debug, Copy, Clone)]
struct Client;

impl ClientIpConfig<ConnectionTicker> for Client {
    fn ip_config(&self, _state: &mut ConnectionTicker, ip_config: InsideIpConfig) {
        println!("Got IP from server: {ip_config:?}");
    }
}

async fn client<S: TestSock>(
    sock: Arc<S>,
    cipher: Option<Cipher>,
    pqc: PQCrypto,
    server_dn: Option<&str>,
) {
    let ca_cert = RootCertificate::Asn1Buffer(CA_CERT);
    let (tun, mut inside_rx) = ChannelTun::new();
    let client = Arc::new(Client);

    let mut join_set = JoinSet::new();

    let (event_cb, mut event_stream) = EventStreamCallback::new();

    let (ticker, ticker_task) = ConnectionTicker::new();
    let client = ClientContextBuilder::new(sock.connection_type(), ca_cert, Arc::new(tun), client)
        .unwrap()
        .with_schedule_tick_cb(connection_ticker_cb)
        .when_some(cipher, |b, cipher| b.with_cipher(cipher).unwrap())
        .build()
        .start_connect(sock.clone().into_io_send_callback(), MAX_OUTSIDE_MTU)
        .unwrap()
        .with_auth_token("LET ME IN")
        .with_event_cb(Box::new(event_cb))
        .when(pqc.enable_client(), |b| b.with_pq_crypto())
        .when_some(server_dn, |b, sdn| {
            b.with_server_domain_name_validation(sdn.to_string())
        })
        .connect(ticker)
        .unwrap();
    let client = Arc::new(Mutex::new(client));

    ticker_task.spawn(Arc::downgrade(&client), &mut join_set);

    let event_client = client.clone();

    let mut is_first_packet_received = false;
    let event_handler_handle = tokio::spawn(async move {
        let client = event_client;
        while let Some(event) = event_stream.next().await {
            println!("Client state changed to {:?}", event);
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
            }
        }
    });

    let mut message_sent = false;

    loop {
        if event_handler_handle.is_finished() {
            // Event handler returning early. Fatal error.
            let result = event_handler_handle.await;
            panic!("Event handler returning early. Fatal error. {:?}", result);
        }

        tokio::select! {

            // Inside data received
            Some(buf) = inside_rx.recv() => {
                let mut client = client.lock().unwrap();
                assert!(matches!(client.state(), State::Online));
                assert!(message_sent);

                assert_eq!(&buf[..], b"\x40Hello World!But Bigger");

                let curve = client.current_curve().unwrap();
                assert_eq!(curve, pqc.expected_curve());

                // All done!
                println!("Client: Disconnecting");
                client.disconnect().unwrap();

                return
            },

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
                if matches!(client.state(), State::Online) && !message_sent {
                    // Send a ping
                    eprintln!("Sending keepalive");
                    client.keepalive().unwrap();

                    // This has to look enough like an ipv4 packet to
                    // make it through. In practice for now that means
                    // the version (the first nibble in the packet)
                    // needs to be ok.
                    //
                    // (Note that 'H' is ASCII 0x48 so that happens to
                    // work as the first byte too, but be more
                    // explicit to avoid a confusing surprise for some
                    // future developer).
                    // Hi, future developer here, this is an invalid ipv4 size,
                    // now the code sends 20 bytes so we don't fail any validations
                    let mut buf: BytesMut = BytesMut::from(&b"\x40Hello World!But Bigger"[..]);
                    eprintln!("Sending message: {buf:?}");
                    client.inside_data_received(&mut buf).expect("Send my message");
                    message_sent = true;
                };
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
            PQCrypto::Enabled => "P521_ML_KEM_1024",
            #[cfg(feature = "kyber_only")]
            PQCrypto::Enabled => "P521_KYBER_LEVEL5",
            PQCrypto::Disabled => "SECP256R1",
            PQCrypto::ServerOnly => "SECP256R1",
            PQCrypto::ClientOnly => "SECP256R1",
        }
    }
}

async fn run_test<S: TestSock>(
    cipher: Option<Cipher>,
    pqc: PQCrypto,
    server_sock: Arc<S>,
    client_sock: Arc<S>,
) {
    let test = async move {
        tokio::join!(
            server(server_sock, pqc),
            client(client_sock, cipher, pqc, None)
        )
    };

    tokio::time::timeout(std::time::Duration::from_millis(2000), test)
        .await
        .expect("Timed out");
}

#[test_case(None,                   PQCrypto::Enabled;    "Default cipher + PQC")]
#[test_case(Some(Cipher::Aes256),   PQCrypto::Enabled;    "aes + PQC")]
#[test_case(Some(Cipher::Chacha20), PQCrypto::Enabled;    "chacha20 +_PQC")]
#[test_case(None,                   PQCrypto::Disabled;   "PQC disabled")]
#[test_case(None,                   PQCrypto::ServerOnly; "PQC server only")]
#[test_case(None,                   PQCrypto::ClientOnly; "PQC client only")]
#[tokio::test]
async fn test_datagram_connection(cipher: Option<Cipher>, pqc: PQCrypto) {
    // Communicate over a local datagram socket for simplicity
    let (client_sock, server_sock) = UnixDatagram::pair().expect("UnixDatagram");
    let server_sock = Arc::new(TestDatagramSock(server_sock));
    let client_sock = Arc::new(TestDatagramSock(client_sock));

    run_test(cipher, pqc, server_sock, client_sock).await;
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

    run_test(cipher, pqc, server_sock, client_sock).await;
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
            client(client_sock, None, PQCrypto::Enabled, server_dn)
        )
    };

    tokio::time::timeout(std::time::Duration::from_millis(2000), test)
        .await
        .expect("Timed out");
}
