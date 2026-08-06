use bytes::BytesMut;
use lightway_app_utils::{
    ConnectionTicker, EventStreamCallback, PacketCodecFactory, connection_ticker_cb,
};
use lightway_core::*;
use std::sync::{Arc, Mutex};
use test_case::test_case;
use tokio::{
    net::{UnixDatagram, UnixStream},
    task::JoinSet,
};
use tokio_stream::StreamExt;
pub mod common;
use crate::common::packet_codec::BlackHolePacketCodecFactory;
use crate::common::{connection::*, get_test_timeout};

async fn run_test_tcp<S: TestSock>(
    cipher: Option<Cipher>,
    pqc: PQCrypto,
    server_sock: Arc<S>,
    client_sock: Arc<S>,
) -> Arc<Mutex<Option<AuthMethod>>> {
    // Inside packet codec is only supported by Lightway UDP
    run_test(cipher, pqc, server_sock, client_sock, false, false, false).await
}

async fn run_test<S: TestSock>(
    cipher: Option<Cipher>,
    pqc: PQCrypto,
    server_sock: Arc<S>,
    client_sock: Arc<S>,
    enable_codec: bool,
    enable_expresslane: bool,
    use_versioned_token: bool,
) -> Arc<Mutex<Option<AuthMethod>>> {
    let (auth, last_method) = TestAuth::new();

    let test = async move {
        tokio::join!(
            server(server_sock, auth, pqc, enable_expresslane),
            client(
                client_sock,
                cipher,
                pqc,
                None,
                enable_codec,
                enable_expresslane,
                use_versioned_token,
            )
        )
    };

    tokio::time::timeout(std::time::Duration::from_millis(get_test_timeout()), test)
        .await
        .expect("Timed out");

    last_method
}

#[cfg_attr(feature = "postquantum",
    test_case(None,                   PQCrypto { server_pqc: true,  keyshare: Some(KeyShare::P521MLKEM1024) },  false, false; "PQC P521MLKEM1024"),
    test_case(None,                   PQCrypto { server_pqc: true,  keyshare: Some(KeyShare::X25519MLKEM768) }, false, false; "PQC X25519MLKEM768"),
    test_case(Some(Cipher::Aes256),   PQCrypto { server_pqc: true,  keyshare: Some(KeyShare::P521MLKEM1024) },  false, false; "aes + PQC"),
    test_case(Some(Cipher::Chacha20), PQCrypto { server_pqc: true,  keyshare: Some(KeyShare::P521MLKEM1024) },  false, false; "chacha20 + PQC"),
    test_case(None,                   PQCrypto { server_pqc: false, keyshare: Some(KeyShare::P521MLKEM1024) },  false, false; "server PQC disabled"),
    test_case(None,                   PQCrypto { server_pqc: false, keyshare: Some(KeyShare::X25519MLKEM768) }, false, false; "server PQC disabled + X25519MLKEM768"),
    test_case(None,                   PQCrypto { server_pqc: true,  keyshare: None },                           false, false; "PQC wolfSSL default"),
    test_case(Some(Cipher::Aes256),   PQCrypto { server_pqc: true,  keyshare: Some(KeyShare::P521MLKEM1024) },   true, false; "Inside packet codec"),
    test_case(None,                   PQCrypto { server_pqc: true,  keyshare: Some(KeyShare::P521MLKEM1024) },  false,  true; "PQC + Expresslane"),
)]
#[test_case(None,                   PQCrypto { server_pqc: false, keyshare: None }, false, false; "no PQC")]
#[test_case(Some(Cipher::Aes256),   PQCrypto { server_pqc: false, keyshare: None }, false, false; "no PQC + aes")]
#[test_case(Some(Cipher::Chacha20), PQCrypto { server_pqc: false, keyshare: None }, false, false; "no PQC + chacha20")]
#[test_case(Some(Cipher::Aes256),   PQCrypto { server_pqc: false, keyshare: None },  true, false; "no PQC + Inside packet codec")]
#[test_case(None,                   PQCrypto { server_pqc: false, keyshare: None }, false,  true; "no PQC + Expresslane")]
#[tokio::test]
async fn test_datagram_connection(
    cipher: Option<Cipher>,
    pqc: PQCrypto,
    enable_codec: bool,
    enable_expresslane: bool,
) {
    // Communicate over a local datagram socket for simplicity
    let (client_sock, server_sock) = UnixDatagram::pair().expect("UnixDatagram");
    let socket = socket2::SockRef::from(&client_sock);
    socket.set_recv_buffer_size(1024 * 256).unwrap();
    let socket = socket2::SockRef::from(&server_sock);
    socket.set_recv_buffer_size(1024 * 256).unwrap();

    let server_sock = Arc::new(TestDatagramSock(server_sock));
    let client_sock = Arc::new(TestDatagramSock(client_sock));

    run_test(
        cipher,
        pqc,
        server_sock,
        client_sock,
        enable_codec,
        enable_expresslane,
        false,
    )
    .await;
}

/// A black-hole inside packet codec accepts every outbound packet but never
/// emits it, so once encoding is enabled the data plane silently stalls while
/// control frames (which bypass the codec) keep the tunnel alive. Verify the
/// client detects the stall via `downgrade_inside_pkt_codec_if_stalled` and
/// disables the codec, rather than depending on keepalive which cannot observe
/// a codec-level black-hole.
#[tokio::test]
async fn inside_pkt_codec_stall_triggers_codec_downgrade() {
    const STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(50);

    let (client_sock, server_sock) = UnixDatagram::pair().expect("UnixDatagram");
    let server_sock = Arc::new(TestDatagramSock(server_sock));
    let client_sock = Arc::new(TestDatagramSock(client_sock));

    let (auth, _last_method) = TestAuth::new();
    let pqc = PQCrypto {
        server_pqc: false,
        keyshare: None,
    };

    // Server reflects inside data and ACKs the client's encoding requests.
    let mut server_task = tokio::spawn(server(server_sock, auth, pqc, false));

    let ca_cert = RootCertificate::Asn1Buffer(CA_CERT);
    let (tun, _inside_rx) = ChannelTun::new();
    let (event_cb, mut event_stream) = EventStreamCallback::new();

    let packet_codec = BlackHolePacketCodecFactory::default().build();
    let encoder = packet_codec.encoder.clone();
    let (packet_codec, mut encoded_pkt_receiver, mut decoded_pkt_receiver) = (
        Some((packet_codec.encoder, packet_codec.decoder)),
        packet_codec.encoded_pkt_receiver,
        packet_codec.decoded_pkt_receiver,
    );

    let (ticker, ticker_task) = ConnectionTicker::new();
    let state = ConnectionState { ticker };

    let client = ClientContextBuilder::new(
        client_sock.connection_type(),
        ca_cert,
        Some(Arc::new(tun)),
        Arc::new(Client),
        connection_ticker_cb,
    )
    .unwrap()
    .build()
    .start_connect(client_sock.clone().into_io_send_callback(), MAX_OUTSIDE_MTU)
    .unwrap()
    .with_auth_token("LET ME IN")
    .with_event_cb(Box::new(event_cb))
    .with_inside_pkt_codec(packet_codec)
    .connect(state)
    .unwrap();
    let client = Arc::new(Mutex::new(client));

    let mut join_set = JoinSet::new();
    ticker_task.spawn_in(Arc::downgrade(&client), &mut join_set);

    // Drain events so the stream never backpressures the connection.
    tokio::spawn(async move { while event_stream.next().await.is_some() {} });

    #[derive(PartialEq, Debug)]
    enum Step {
        Connecting,
        EncodingRequested,
        MessageSent,
        Downgraded,
    }
    let mut step = Step::Connecting;
    let mut stall_check = tokio::time::interval(std::time::Duration::from_millis(10));

    let driver = async {
        loop {
            tokio::select! {
                // inside -> outside: the black-hole encoder never emits, so this stays
                // silent once encoding is enabled.
                Some(mut encoded) = encoded_pkt_receiver.recv() => {
                    client.lock().unwrap().send_to_outside(&mut encoded, true).expect("send encoded");
                }
                Some(decoded) = decoded_pkt_receiver.recv() => {
                    client.lock().unwrap().send_to_inside(decoded).expect("send decoded");
                }
                is_readable = client_sock.readable() => {
                    is_readable.expect("client socket readable");
                    let mut buf = BytesMut::with_capacity(MAX_OUTSIDE_MTU);
                    match client_sock.try_recv_buf(&mut buf) {
                        Ok(0) => panic!("EOF"),
                        Ok(_) => {}
                        Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock) => continue,
                        Err(e) => panic!("client recv: {e}"),
                    }
                    let mut c = client.lock().unwrap();
                    let pkt = OutsidePacket::Wire(&mut buf, client_sock.connection_type());
                    c.outside_data_received(pkt).expect("outside data received");
                    if !matches!(c.state(), State::Online) {
                        continue;
                    }
                    match step {
                        Step::Connecting => {
                            c.set_encoding(true).expect("enable encoding");
                            step = Step::EncodingRequested;
                        }
                        Step::EncodingRequested if encoder.get_encoding_state() => {
                            // Codec is enabled: push a packet the black-hole encoder drops.
                            let mut msg = BytesMut::from(&b"\x40Hello World!"[..]);
                            c.inside_data_received(&mut msg).expect("send message");
                            step = Step::MessageSent;
                        }
                        _ => {}
                    }
                }
                _ = stall_check.tick() => {
                    let mut c = client.lock().unwrap();
                    match step {
                        Step::MessageSent => {
                            if c
                                .downgrade_inside_pkt_codec_if_stalled(STALL_TIMEOUT)
                                .expect("stall check")
                            {
                                step = Step::Downgraded;
                            }
                        }
                        // Server ACKed the disable: the codec is off, fix confirmed.
                        Step::Downgraded if !encoder.get_encoding_state() => return,
                        _ => {}
                    }
                }
            }
        }
    };

    tokio::time::timeout(
        std::time::Duration::from_millis(get_test_timeout()),
        async {
            tokio::select! {
                _ = driver => {}
                r = &mut server_task => panic!("server task ended early: {r:?}"),
            }
        },
    )
    .await
    .expect("test timed out");
}

#[cfg_attr(feature = "postquantum",
    test_case(None,                   PQCrypto { server_pqc: true,  keyshare: Some(KeyShare::P521MLKEM1024) };  "PQC P521MLKEM1024"),
    test_case(None,                   PQCrypto { server_pqc: true,  keyshare: Some(KeyShare::X25519MLKEM768) }; "PQC X25519MLKEM768"),
    test_case(Some(Cipher::Aes256),   PQCrypto { server_pqc: true,  keyshare: Some(KeyShare::P521MLKEM1024) };  "aes + PQC"),
    test_case(Some(Cipher::Chacha20), PQCrypto { server_pqc: true,  keyshare: Some(KeyShare::P521MLKEM1024) };  "chacha20 + PQC"),
    test_case(None,                   PQCrypto { server_pqc: false, keyshare: Some(KeyShare::P521MLKEM1024) };  "server PQC disabled"),
    test_case(None,                   PQCrypto { server_pqc: false, keyshare: Some(KeyShare::X25519MLKEM768) }; "server PQC disabled + X25519MLKEM768"),
    test_case(None,                   PQCrypto { server_pqc: true,  keyshare: None };                           "PQC wolfSSL default"),
)]
#[test_case(None,                   PQCrypto { server_pqc: false, keyshare: None }; "no PQC")]
#[test_case(Some(Cipher::Aes256),   PQCrypto { server_pqc: false, keyshare: None }; "no PQC + aes")]
#[test_case(Some(Cipher::Chacha20), PQCrypto { server_pqc: false, keyshare: None }; "no PQC + chacha20")]
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

/// Drive an end-to-end UDP connection that uses
/// [`ClientConnectionBuilder::with_auth_versioned_token`] and assert
/// the server received an [`AuthMethod::VersionedToken`] carrying the
/// client's [`Version::MAXIMUM`].
#[tokio::test]
async fn test_datagram_connection_versioned_token() {
    let (client_sock, server_sock) = UnixDatagram::pair().expect("UnixDatagram");
    let socket = socket2::SockRef::from(&client_sock);
    socket.set_recv_buffer_size(1024 * 256).unwrap();
    let socket = socket2::SockRef::from(&server_sock);
    socket.set_recv_buffer_size(1024 * 256).unwrap();

    let server_sock = Arc::new(TestDatagramSock(server_sock));
    let client_sock = Arc::new(TestDatagramSock(client_sock));

    let pqc = PQCrypto {
        server_pqc: false,
        keyshare: None,
    };
    let last_method = run_test(
        None,
        pqc,
        server_sock,
        client_sock,
        false,
        false,
        true, // use_versioned_token
    )
    .await;

    let method = last_method.lock().unwrap().clone().expect("Auth seen");
    assert_eq!(
        method,
        AuthMethod::VersionedToken {
            version: Version::MAXIMUM,
            token: "LET ME IN".to_string(),
        }
    );
}

/// Drive an end-to-end TCP connection that uses
/// [`ClientConnectionBuilder::with_auth_versioned_token`] and assert
/// the server received an [`AuthMethod::VersionedToken`] carrying the
/// client's [`Version::MAXIMUM`].
#[tokio::test]
async fn test_stream_connection_versioned_token() {
    let (client_sock, server_sock) = UnixStream::pair().expect("UnixStream");
    let server_sock = Arc::new(TestStreamSock(server_sock));
    let client_sock = Arc::new(TestStreamSock(client_sock));

    let _ = client_sock.writable().await;

    let pqc = PQCrypto {
        server_pqc: false,
        keyshare: None,
    };
    let last_method = run_test(
        None,
        pqc,
        server_sock,
        client_sock,
        false,
        false,
        true, // use_versioned_token
    )
    .await;

    let method = last_method.lock().unwrap().clone().expect("Auth seen");
    assert_eq!(
        method,
        AuthMethod::VersionedToken {
            version: Version::MAXIMUM,
            token: "LET ME IN".to_string(),
        }
    );
}

#[test_case(None; "No server domain name")]
#[test_case(Some("example.com"); "Valid server domain name")]
#[test_case(Some("invalid") => panics "TLS Error: Fatal: Domain name mismatch"; "Invalid server domain name")]
#[tokio::test]
async fn test_server_dn(server_dn: Option<&str>) {
    // Communicate over a local stream socket for simplicity
    let (client_sock, server_sock) = UnixStream::pair().expect("UnixStream");
    let server_sock = Arc::new(TestStreamSock(server_sock));
    let client_sock = Arc::new(TestStreamSock(client_sock));
    let pqc = PQCrypto::default();
    // We need the server end to be ready to receive before we can get
    // started, else we'll get a `WouldBlock`.
    let _ = client_sock.writable().await;

    let auth = Arc::new(TestAuth::default());
    let test = async move {
        tokio::join!(
            server(server_sock, auth, pqc, false),
            client(client_sock, None, pqc, server_dn, false, false, false)
        )
    };

    tokio::time::timeout(std::time::Duration::from_millis(get_test_timeout()), test)
        .await
        .expect("Timed out");
}

/// Builds a `Connection` by reusing the `client()` construction pattern
/// above (`ClientContextBuilder` -> `start_connect` -> `with_auth_token` ->
/// `connect`), trimmed down to just the construction step - no handshake is
/// driven. `Connection::new` performs one (pending) TLS negotiation attempt
/// internally, which is enough to exercise `mark_offload_activity` without
/// needing the full client/server event loop.
#[tokio::test]
async fn mark_offload_activity_bumps_by_rule() {
    let (client_sock, _server_sock) = UnixStream::pair().expect("UnixStream");
    let client_sock = Arc::new(TestStreamSock(client_sock));

    let ca_cert = RootCertificate::Asn1Buffer(CA_CERT);
    let (ticker, _ticker_task) = ConnectionTicker::new();
    let state = ConnectionState { ticker };

    let mut conn = ClientContextBuilder::new(
        client_sock.connection_type(),
        ca_cert,
        None,
        Arc::new(Client),
        connection_ticker_cb,
    )
    .unwrap()
    .build()
    .start_connect(client_sock.clone().into_io_send_callback(), MAX_OUTSIDE_MTU)
    .unwrap()
    .with_auth_token("LET ME IN")
    .connect(state)
    .unwrap();

    let before = conn.activity();
    std::thread::sleep(std::time::Duration::from_millis(2));

    conn.mark_offload_activity(false, true); // tx only
    let after_tx = conn.activity();
    assert!(after_tx.last_outside_data_received > before.last_outside_data_received);
    assert_eq!(
        after_tx.last_data_traffic_from_peer,
        before.last_data_traffic_from_peer
    );

    std::thread::sleep(std::time::Duration::from_millis(2));
    conn.mark_offload_activity(true, false); // rx bumps both
    let after_rx = conn.activity();
    assert!(after_rx.last_data_traffic_from_peer > before.last_data_traffic_from_peer);
    assert!(after_rx.last_outside_data_received > after_tx.last_outside_data_received);
}
