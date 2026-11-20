use bytes::BytesMut;
use lightway_app_utils::{
    ConnectionTicker, EventStreamCallback, PacketCodecFactory, connection_ticker_cb,
};
use lightway_core::*;
use rcgen::RsaKeySize;
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};
use test_case::test_case;
use tokio::{
    net::{UnixDatagram, UnixStream},
    sync::oneshot,
    task::JoinSet,
};
use tokio_stream::StreamExt;
pub mod common;
use crate::common::{certgen::TestPki, packet_codec::BlackHolePacketCodecFactory};
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

    // Take the shared test PKI before the timeout window: RSA keygen is very
    // slow on QEMU (especially on RISCV) and only happens on first use.
    let pki = TestPki::get_valid(2, RsaKeySize::_2048);

    let test = async move {
        let (cert, key) = pki.server_secrets();
        tokio::join!(
            server(
                server_sock,
                TestServerConfig {
                    auth,
                    pqc,
                    expresslane: enable_expresslane
                        .then_some(DEFAULT_EXPRESSLANE_KEYS_ROTATION_INTERVAL),
                    conn_out: None,
                    metrics: None,
                    expresslane_cb: None,
                    cert,
                    key,
                },
            ),
            client(
                client_sock,
                TestClientConfig {
                    cipher,
                    pqc,
                    server_dn: None,
                    enable_codec,
                    enable_expresslane,
                    use_versioned_token,
                    root_ca: pki.root_ca(),
                },
            )
        )
    };

    tokio::time::timeout(std::time::Duration::from_millis(get_test_timeout()), test)
        .await
        .expect("Timed out");

    last_method
}

#[cfg_attr(wolfssl,
    test_case(None,                   PQCrypto { server_pqc: true,  keyshare: Some(KeyShare::P521MLKEM1024) },  false, false; "PQC P521MLKEM1024"),
    test_case(Some(Cipher::Aes256),   PQCrypto { server_pqc: true,  keyshare: Some(KeyShare::P521MLKEM1024) },  false, false; "aes + PQC"),
    test_case(Some(Cipher::Chacha20), PQCrypto { server_pqc: true,  keyshare: Some(KeyShare::P521MLKEM1024) },  false, false; "chacha20 + PQC"),
    test_case(None,                   PQCrypto { server_pqc: false, keyshare: Some(KeyShare::P521MLKEM1024) },  false, false; "server PQC disabled"),
    test_case(Some(Cipher::Aes256),   PQCrypto { server_pqc: true,  keyshare: Some(KeyShare::P521MLKEM1024) },   true, false; "Inside packet codec"),
    test_case(None,                   PQCrypto { server_pqc: true,  keyshare: Some(KeyShare::P521MLKEM1024) },  false,  true; "PQC + Expresslane"),
)]
#[test_case(None,                   PQCrypto { server_pqc: true,  keyshare: Some(KeyShare::X25519MLKEM768) }, false, false; "PQC X25519MLKEM768")]
#[test_case(None,                   PQCrypto { server_pqc: false, keyshare: Some(KeyShare::X25519MLKEM768) }, false, false; "server PQC disabled + X25519MLKEM768")]
#[test_case(None,                   PQCrypto { server_pqc: true,  keyshare: Some(KeyShare::default()) },      false, false; "PQC default keyshare")]
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
    let pki = TestPki::get_valid(2, RsaKeySize::_2048);
    let (cert, key) = pki.server_secrets();
    let mut server_task = tokio::spawn(server(
        server_sock,
        TestServerConfig {
            auth,
            pqc,
            expresslane: None,
            conn_out: None,
            metrics: None,
            expresslane_cb: None,
            cert,
            key,
        },
    ));

    let ca_cert = pki.root_ca();
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

#[cfg_attr(wolfssl,
    test_case(None,                   PQCrypto { server_pqc: true,  keyshare: Some(KeyShare::P521MLKEM1024) };  "PQC P521MLKEM1024"),
    test_case(Some(Cipher::Aes256),   PQCrypto { server_pqc: true,  keyshare: Some(KeyShare::P521MLKEM1024) };  "aes + PQC"),
    test_case(Some(Cipher::Chacha20), PQCrypto { server_pqc: true,  keyshare: Some(KeyShare::P521MLKEM1024) };  "chacha20 + PQC"),
    test_case(None,                   PQCrypto { server_pqc: false, keyshare: Some(KeyShare::P521MLKEM1024) };  "server PQC disabled"),
)]
#[test_case(None,                   PQCrypto { server_pqc: true,  keyshare: Some(KeyShare::X25519MLKEM768) }; "PQC X25519MLKEM768")]
#[test_case(None,                   PQCrypto { server_pqc: false, keyshare: Some(KeyShare::X25519MLKEM768) }; "server PQC disabled + X25519MLKEM768")]
#[test_case(None,                   PQCrypto { server_pqc: true,  keyshare: Some(KeyShare::default()) };      "PQC default keyshare")]
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
#[test_case(Some(TestPki::SERVER_DOMAIN); "Valid server domain name")]
#[cfg_attr(boringssl, test_case(Some("invalid") => panics "TLS Error: Fatal error: DomainNameMismatch"; "Invalid server domain name"))]
#[cfg_attr(wolfssl, test_case(Some("invalid") => panics "TLS Error: Fatal: Domain name mismatch"; "Invalid server domain name"))]
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

    // Take the shared test PKI *before the timed window* to prevent flaky tests. (see run_test).
    let pki = TestPki::get_valid(2, RsaKeySize::_2048);

    let test = async move {
        tokio::join!(
            {
                let (cert, key) = pki.server_secrets();
                server(
                    server_sock,
                    TestServerConfig {
                        auth,
                        pqc,
                        expresslane: None,
                        conn_out: None,
                        metrics: None,
                        expresslane_cb: None,
                        cert,
                        key,
                    },
                )
            },
            client(
                client_sock,
                TestClientConfig {
                    cipher: None,
                    pqc,
                    server_dn,
                    enable_codec: false,
                    enable_expresslane: false,
                    use_versioned_token: false,
                    root_ca: pki.root_ca(),
                },
            )
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

    let ca_cert = TestPki::get_valid(2, RsaKeySize::_2048).root_ca();
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

#[test_case(true, ExpresslaneState::Inactive; "expresslane enabled")]
#[test_case(false, ExpresslaneState::Disabled; "expresslane disabled")]
#[tokio::test]
async fn expresslane_state_reports_initial_client_state(
    enable_expresslane: bool,
    expected: ExpresslaneState,
) {
    let (client_sock, _server_sock) = UnixDatagram::pair().expect("UnixDatagram");
    let client_sock = Arc::new(TestDatagramSock(client_sock));

    let ca_cert = TestPki::get_valid(2, RsaKeySize::_2048).root_ca();
    let (ticker, _ticker_task) = ConnectionTicker::new();
    let state = ConnectionState { ticker };

    let conn = ClientContextBuilder::new(
        client_sock.connection_type(),
        ca_cert,
        None,
        Arc::new(Client),
        connection_ticker_cb,
    )
    .unwrap()
    .when(enable_expresslane, |b| {
        b.with_expresslane(DEFAULT_EXPRESSLANE_KEYS_ROTATION_INTERVAL)
    })
    .build()
    .start_connect(client_sock.clone().into_io_send_callback(), MAX_OUTSIDE_MTU)
    .unwrap()
    .with_auth_token("LET ME IN")
    .connect(state)
    .unwrap();

    assert_eq!(conn.expresslane_state(), expected);
}

/// Proves the offload-nudge chain end to end: a server-side
/// `mark_offload_activity` call (exactly what the offload-stats poller
/// does) rotates the expresslane key on both ends while the client sees
/// no inside/outside traffic of its own.
#[tokio::test]
async fn server_nudge_rotates_both_ends_while_client_is_idle() {
    const INTERVAL: std::time::Duration = std::time::Duration::from_millis(300);

    let (client_sock, server_sock) = UnixDatagram::pair().expect("UnixDatagram");
    let server_sock = Arc::new(TestDatagramSock(server_sock));
    let client_sock = Arc::new(TestDatagramSock(client_sock));

    // Collects the distinct real (non-sentinel) self keys the client publishes.
    struct KeyCollector(Mutex<HashSet<Vec<u8>>>);
    impl<T> ExpresslaneCb<T> for KeyCollector {
        fn update(&self, _sid: SessionId, data: ExpresslaneCbData, _s: &T) {
            if !data.self_key.is_invalid() {
                self.0.lock().unwrap().insert(data.self_key.0.to_vec());
            }
        }
    }
    let keys = Arc::new(KeyCollector(Mutex::new(HashSet::new())));

    let (conn_tx, conn_rx) = oneshot::channel();

    let auth = Arc::new(TestAuth::default());
    let pki = TestPki::get_valid(2, RsaKeySize::_2048);
    let (cert, key) = pki.server_secrets();
    let server_task = server(
        server_sock,
        TestServerConfig {
            auth,
            pqc: PQCrypto {
                server_pqc: false,
                keyshare: None,
            },
            expresslane: Some(INTERVAL),
            conn_out: Some(conn_tx),
            metrics: None,
            expresslane_cb: None,
            cert,
            key,
        },
    );

    let client_task = async move {
        // The server sends this before any handshake traffic, so this
        // cannot deadlock.
        let server_conn = conn_rx.await.expect("server conn handle");

        let ca_cert = pki.root_ca();
        let (tun, _inside_rx) = ChannelTun::new();
        let (ticker, ticker_task) = ConnectionTicker::new();
        let state = ConnectionState { ticker };

        let conn = ClientContextBuilder::new(
            client_sock.connection_type(),
            ca_cert,
            Some(Arc::new(tun)),
            Arc::new(Client),
            connection_ticker_cb,
        )
        .unwrap()
        .with_expresslane(INTERVAL)
        .with_expresslane_cb(keys.clone())
        .build()
        .start_connect(client_sock.clone().into_io_send_callback(), MAX_OUTSIDE_MTU)
        .unwrap()
        .with_auth_token("LET ME IN")
        .connect(state)
        .unwrap();
        let conn = Arc::new(Mutex::new(conn));

        let mut join_set = JoinSet::new();
        ticker_task.spawn_in(Arc::downgrade(&conn), &mut join_set);

        let mut phase = 1u8;
        let mut phase1_at: Option<std::time::Instant> = None;
        let mut ticks = tokio::time::interval(std::time::Duration::from_millis(50));

        loop {
            tokio::select! {
                is_readable = client_sock.readable() => {
                    is_readable.expect("client socket readable");

                    let mut buf = BytesMut::with_capacity(MAX_OUTSIDE_MTU);
                    match client_sock.try_recv_buf(&mut buf) {
                        Ok(0) => panic!("EOF"),
                        Ok(_nr) => {}
                        Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                            continue;
                        }
                        Err(err) => panic!("read for sock {err}"),
                    };

                    let mut conn = conn.lock().unwrap();
                    let pkt = OutsidePacket::Wire(&mut buf, client_sock.connection_type());
                    if let Err(err) = conn.outside_data_received(pkt) {
                        panic!("{err}")
                    }
                }

                _ = ticks.tick() => {
                    let key_count = keys.0.lock().unwrap().len();
                    match phase {
                        1 => {
                            // Initial exchange done.
                            if key_count >= 1 {
                                phase1_at = Some(std::time::Instant::now());
                                phase = 2;
                            }
                        }
                        2 => {
                            // More than 2 rotation intervals of pure idle.
                            if phase1_at.unwrap().elapsed()
                                >= std::time::Duration::from_millis(700)
                            {
                                assert_eq!(
                                    key_count, 1,
                                    "an idle offloaded client must not rotate on its own - that is the point"
                                );
                                phase = 3;
                            }
                        }
                        3 => {
                            // Exactly the call the offload-stats poller makes
                            // when offload counters show traffic.
                            server_conn.lock().unwrap().mark_offload_activity(true, false);
                            phase = 4;
                        }
                        4 => {
                            if key_count >= 2 {
                                conn.lock().unwrap().disconnect().unwrap();
                                return;
                            }
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }
    };

    let test = async move { tokio::join!(server_task, client_task) };

    tokio::time::timeout(std::time::Duration::from_secs(10), test)
        .await
        .expect("server nudge did not cascade into a client rotation");
}

/// Pins the forcing gate through a real connection pair: a second
/// `rotate_expresslane_key_now()` while the first is still outstanding must
/// not push a second key, and a third call after the first is acked must.
///
/// Counts the client's own promoted self keys (as `server_nudge_...` does)
/// cannot tell a suppressed second call apart from an accepted one - the
/// client's own reflexive counter-rotation only ever fires once regardless,
/// which collapses both cases to the same final count. Distinct peer keys
/// the client observes (i.e. distinct keys the server actually advertised)
/// does not have that blind spot, so that is the observable here. The
/// server side is built manually, like the client below, so it can carry
/// its own callback - the shared `server()` helper has no way to attach one.
#[tokio::test]
async fn rotate_now_suppressed_while_outstanding_reopens_after_ack() {
    // Larger than this test's runtime, so neither side's periodic reflexive
    // rotation ever fires on its own - only the explicit
    // rotate_expresslane_key_now() calls below produce any wire traffic.
    const INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

    let (client_sock, server_sock) = UnixDatagram::pair().expect("UnixDatagram");
    let server_sock = Arc::new(TestDatagramSock(server_sock));
    let client_sock = Arc::new(TestDatagramSock(client_sock));

    // Records every distinct self/peer key an endpoint has held.
    struct KeyObserver {
        self_keys: Mutex<HashSet<Vec<u8>>>,
        peer_keys: Mutex<HashSet<Vec<u8>>>,
    }
    impl KeyObserver {
        fn new() -> Self {
            Self {
                self_keys: Mutex::new(HashSet::new()),
                peer_keys: Mutex::new(HashSet::new()),
            }
        }
    }
    impl<T> ExpresslaneCb<T> for KeyObserver {
        fn update(&self, _sid: SessionId, data: ExpresslaneCbData, _s: &T) {
            if !data.self_key.is_invalid() {
                self.self_keys
                    .lock()
                    .unwrap()
                    .insert(data.self_key.0.to_vec());
            }
            if !data.peer_key.is_invalid() {
                self.peer_keys
                    .lock()
                    .unwrap()
                    .insert(data.peer_key.0.to_vec());
            }
        }
    }
    let client_obs = Arc::new(KeyObserver::new());
    let server_obs = Arc::new(KeyObserver::new());

    let pki = TestPki::get_valid(2, RsaKeySize::_2048);
    let (server_cert, server_key) = pki.server_secrets();

    let test = async move {
        let ip_pool = Arc::new(StaticIpPool);
        let (server_tun, _server_inside_rx) = ChannelTun::new();
        let auth = Arc::new(TestAuth::default());

        let server_ctx = ServerContextBuilder::<ConnectionTicker>::new(
            server_sock.connection_type(),
            server_cert,
            server_key,
            auth,
            ip_pool,
            Arc::new(server_tun),
            connection_ticker_cb,
        )
        .unwrap()
        .with_minimum_protocol_version(Version::MINIMUM)
        .unwrap()
        .with_maximum_protocol_version(Version::MAXIMUM)
        .unwrap()
        .with_expresslane(INTERVAL)
        .with_expresslane_cb(server_obs.clone())
        .build()
        .unwrap();

        let (server_ticker, server_ticker_task) = ConnectionTicker::new();
        let server_conn = Arc::new(Mutex::new(
            server_ctx
                .start_accept(
                    Version::MAXIMUM,
                    server_sock.clone().into_io_send_callback(),
                )
                .unwrap()
                .accept(server_ticker)
                .unwrap(),
        ));

        let ca_cert = pki.root_ca();
        let (client_tun, _client_inside_rx) = ChannelTun::new();
        let (client_ticker, client_ticker_task) = ConnectionTicker::new();
        let state = ConnectionState {
            ticker: client_ticker,
        };

        let conn = ClientContextBuilder::new(
            client_sock.connection_type(),
            ca_cert,
            Some(Arc::new(client_tun)),
            Arc::new(Client),
            connection_ticker_cb,
        )
        .unwrap()
        .with_expresslane(INTERVAL)
        .with_expresslane_cb(client_obs.clone())
        .build()
        .start_connect(client_sock.clone().into_io_send_callback(), MAX_OUTSIDE_MTU)
        .unwrap()
        .with_auth_token("LET ME IN")
        .connect(state)
        .unwrap();
        let conn = Arc::new(Mutex::new(conn));

        let mut join_set = JoinSet::new();
        server_ticker_task.spawn_in(Arc::downgrade(&server_conn), &mut join_set);
        client_ticker_task.spawn_in(Arc::downgrade(&conn), &mut join_set);

        let mut phase = 1u8;
        let mut ticks = tokio::time::interval(std::time::Duration::from_millis(50));

        loop {
            tokio::select! {
                is_readable = server_sock.readable() => {
                    is_readable.expect("server socket readable");

                    let mut buf = BytesMut::with_capacity(MAX_OUTSIDE_MTU);
                    match server_sock.try_recv_buf(&mut buf) {
                        Ok(0) => panic!("EOF"),
                        Ok(_nr) => {}
                        Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                            continue;
                        }
                        Err(err) => panic!("read for server sock {err}"),
                    };

                    let mut server_conn = server_conn.lock().unwrap();
                    let pkt = OutsidePacket::Wire(&mut buf, server_sock.connection_type());
                    if let Err(err) = server_conn.outside_data_received(pkt) {
                        panic!("{err}")
                    }
                }

                is_readable = client_sock.readable() => {
                    is_readable.expect("client socket readable");

                    let mut buf = BytesMut::with_capacity(MAX_OUTSIDE_MTU);
                    match client_sock.try_recv_buf(&mut buf) {
                        Ok(0) => panic!("EOF"),
                        Ok(_nr) => {}
                        Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                            continue;
                        }
                        Err(err) => panic!("read for client sock {err}"),
                    };

                    let mut conn = conn.lock().unwrap();
                    let pkt = OutsidePacket::Wire(&mut buf, client_sock.connection_type());
                    if let Err(err) = conn.outside_data_received(pkt) {
                        panic!("{err}")
                    }
                }

                _ = ticks.tick() => {
                    let server_self_keys = server_obs.self_keys.lock().unwrap().len();
                    let client_peer_keys = client_obs.peer_keys.lock().unwrap().len();

                    match phase {
                        1 => {
                            // Initial handshake key exchange acked on both ends -
                            // nothing outstanding yet.
                            if server_self_keys >= 1 && client_peer_keys >= 1 {
                                phase = 2;
                            }
                        }
                        2 => {
                            let mut server_conn = server_conn.lock().unwrap();
                            assert!(
                                server_conn
                                    .rotate_expresslane_key_now()
                                    .expect("first forced rotation must start"),
                                "a started rotation reports true"
                            );
                            // Immediately after, with no await in between: the
                            // exchange above is still outstanding.
                            assert!(
                                !server_conn
                                    .rotate_expresslane_key_now()
                                    .expect("a suppressed call still returns Ok, it just does nothing"),
                                "a suppressed rotation must be distinguishable from a started one"
                            );
                            phase = 3;
                        }
                        3 => {
                            if server_self_keys >= 2 {
                                assert_eq!(
                                    client_peer_keys, 2,
                                    "second immediate call must not push a second key while the first is outstanding"
                                );
                                phase = 4;
                            }
                        }
                        4 => {
                            assert!(
                                server_conn
                                    .lock()
                                    .unwrap()
                                    .rotate_expresslane_key_now()
                                    .expect("a call after the first exchange acked must be allowed again"),
                                "the reopened gate reports a started rotation"
                            );
                            phase = 5;
                        }
                        5 => {
                            if server_self_keys >= 3 {
                                assert_eq!(
                                    client_peer_keys, 3,
                                    "the gate must reopen once the outstanding exchange resolves"
                                );
                                return;
                            }
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }
    };

    tokio::time::timeout(std::time::Duration::from_secs(10), test)
        .await
        .expect("forced rotation gate did not behave as expected");
}

/// Drives a client/server pair through repeated keepalive windows and
/// reports how the client's expresslane health check reacted: the final
/// state, which window (if any) first saw it go Degraded, how many
/// probe packets came back reflected (proof traffic actually flowed), and
/// the server's final state.
async fn expresslane_health_probe(
    client_metrics: Option<Arc<dyn ExpresslaneMetrics + Send + Sync>>,
    server_metrics: Option<ExpresslaneMetricsType>,
) -> (ExpresslaneState, Option<usize>, usize, ExpresslaneState) {
    // Comfortably above MIN_PACKETS_FOR_LOSS_CHECK (10) so a bad window is
    // unambiguous; WINDOWS above EXPRESSLANE_MISSING_STATS_LIMIT (3) so
    // "degrades at the limit, not before" is observable.
    const WINDOWS: usize = 5;
    const BURST: usize = 12;

    // A small yield between sends, rather than one lock held over the whole
    // burst: the server needs several of its own select! iterations (decode,
    // deliver, reflect) to drain one packet, and firing all BURST packets
    // back-to-back can outrun that pipeline faster than it drains.
    async fn send_burst(conn: &Arc<Mutex<lightway_core::Connection<ConnectionState>>>) {
        for _ in 0..BURST {
            let mut pkt = BytesMut::from(&b"\x40Health probe"[..]);
            conn.lock()
                .unwrap()
                .inside_data_received(&mut pkt)
                .expect("send probe packet");
            tokio::time::sleep(std::time::Duration::from_micros(200)).await;
        }
    }

    let (client_sock, server_sock) = UnixDatagram::pair().expect("UnixDatagram");
    let server_sock = Arc::new(TestDatagramSock(server_sock));
    let client_sock = Arc::new(TestDatagramSock(client_sock));

    let pqc = PQCrypto {
        server_pqc: false,
        keyshare: None,
    };

    let auth = Arc::new(TestAuth::default());
    // A long rotation interval on purpose: rotation must not interfere with
    // the health-check windows this probe measures.
    let pki = TestPki::get_valid(2, RsaKeySize::_2048);
    let (cert, key) = pki.server_secrets();
    let (server_conn_tx, server_conn_rx) = oneshot::channel();
    let server_task = server(
        server_sock,
        TestServerConfig {
            auth,
            pqc,
            expresslane: Some(DEFAULT_EXPRESSLANE_KEYS_ROTATION_INTERVAL),
            conn_out: Some(server_conn_tx),
            metrics: server_metrics,
            expresslane_cb: None,
            cert,
            key,
        },
    );

    let client_task = async move {
        let ca_cert = pki.root_ca();
        let (tun, mut inside_rx) = ChannelTun::new();
        let (ticker, ticker_task) = ConnectionTicker::new();
        let state = ConnectionState { ticker };
        let (event_cb, mut event_stream) = EventStreamCallback::new();

        let client = ClientContextBuilder::new(
            client_sock.connection_type(),
            ca_cert,
            Some(Arc::new(tun)),
            Arc::new(Client),
            connection_ticker_cb,
        )
        .unwrap()
        .with_expresslane(DEFAULT_EXPRESSLANE_KEYS_ROTATION_INTERVAL)
        .when_some(client_metrics, |b, m| b.with_expresslane_metrics(m));

        // Match the shared client helper: the server asserts the negotiated
        // curve against PQCrypto::expected_curve, which assumes this.
        let client = client.enable_pq_crypto().unwrap();

        let conn = client
            .build()
            .start_connect(client_sock.clone().into_io_send_callback(), MAX_OUTSIDE_MTU)
            .unwrap()
            .with_auth_token("LET ME IN")
            .with_event_cb(Box::new(event_cb))
            .connect(state)
            .unwrap();
        let conn = Arc::new(Mutex::new(conn));

        let mut join_set = JoinSet::new();
        ticker_task.spawn_in(Arc::downgrade(&conn), &mut join_set);

        let mut el_state = ExpresslaneState::Disabled;
        let mut windows_done = 0usize;
        let mut degraded_at: Option<usize> = None;
        let mut reflected = 0usize;
        let mut grace = 0usize;
        let mut keepalive_countdown: Option<usize> = None;
        let mut ticks = tokio::time::interval(std::time::Duration::from_millis(50));

        loop {
            tokio::select! {
                is_readable = client_sock.readable() => {
                    is_readable.expect("client socket readable");

                    let mut buf = BytesMut::with_capacity(MAX_OUTSIDE_MTU);
                    match client_sock.try_recv_buf(&mut buf) {
                        Ok(0) => panic!("EOF"),
                        Ok(_nr) => {}
                        Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                            continue;
                        }
                        Err(err) => panic!("read for sock {err}"),
                    };

                    let mut conn = conn.lock().unwrap();
                    let pkt = OutsidePacket::Wire(&mut buf, client_sock.connection_type());
                    if let Err(err) = conn.outside_data_received(pkt) {
                        panic!("{err}")
                    }
                }

                Some(event) = event_stream.next() => {
                    match event {
                        Event::ExpresslaneStateChanged(s) => {
                            if matches!(s, ExpresslaneState::Active)
                                && !matches!(el_state, ExpresslaneState::Active)
                                && windows_done == 0
                            {
                                send_burst(&conn).await;
                                keepalive_countdown = Some(3);
                            }
                            if matches!(s, ExpresslaneState::Degraded) && degraded_at.is_none() {
                                degraded_at = Some(windows_done);
                            }
                            el_state = s;
                        }
                        Event::KeepaliveReply => {
                            windows_done += 1;
                            if windows_done < WINDOWS {
                                send_burst(&conn).await;
                                keepalive_countdown = Some(3);
                            }
                        }
                        _ => {}
                    }
                }

                Some(_buf) = inside_rx.recv() => {
                    reflected += 1;
                }

                _ = ticks.tick() => {
                    // The reflecting server counts through an async channel,
                    // so the countdown gives the whole burst time to land
                    // before the pong that snapshots it goes out.
                    if let Some(n) = keepalive_countdown {
                        if n == 0 {
                            keepalive_countdown = None;
                            conn.lock().unwrap().keepalive().expect("send keepalive");
                        } else {
                            keepalive_countdown = Some(n - 1);
                        }
                    }

                    if matches!(el_state, ExpresslaneState::Degraded) {
                        grace += 1;
                        if grace >= 2 {
                            break;
                        }
                    } else if windows_done >= WINDOWS {
                        grace += 1;
                        if grace >= 4 {
                            break;
                        }
                    }
                }
            }
        }

        let server_conn = server_conn_rx.await.expect("server connection");
        let server_state = server_conn.lock().unwrap().expresslane_state();

        conn.lock().unwrap().disconnect().unwrap();
        (el_state, degraded_at, reflected, server_state)
    };

    // Emulated targets requires much more time to run this,
    // sometimes >15s. So we use the platform-aware base timeout, scaled up.
    let (_, result) = tokio::time::timeout(
        std::time::Duration::from_millis(get_test_timeout() * 8),
        async move { tokio::join!(server_task, client_task) },
    )
    .await
    .expect("expresslane health probe timed out");

    result
}

/// A provider that is always reachable but always reports total loss.
/// Distinguishes it from a missing reading: the health check must treat
/// persistent zeros as a real 100% loss window, not as "no data yet".
struct AlwaysZeroStats;
impl ExpresslaneMetrics for AlwaysZeroStats {
    fn get_stats(
        &self,
        _session_id: SessionId,
    ) -> Result<ExpresslanePacketStats, ExpresslaneStatsError> {
        Ok(ExpresslanePacketStats::default())
    }
}

/// A provider that always fails to produce a reading.
struct AlwaysUnavailableStats;
impl ExpresslaneMetrics for AlwaysUnavailableStats {
    fn get_stats(
        &self,
        _session_id: SessionId,
    ) -> Result<ExpresslanePacketStats, ExpresslaneStatsError> {
        Err(ExpresslaneStatsError::Unavailable)
    }
}

/// A provider returning zeros - a claim of total loss - degrades exactly
/// like real total loss would. This is the behavior the error return exists
/// to be distinguishable from: an installed provider that has genuinely
/// nothing to report must say so, not fabricate zeros.
#[tokio::test]
async fn zero_stats_readings_degrade_as_total_loss() {
    let (state, _degraded_at, reflected, _) =
        expresslane_health_probe(Some(Arc::new(AlwaysZeroStats)), None).await;

    assert_eq!(
        state,
        ExpresslaneState::Degraded,
        "persistent zeros ARE a reading, read as 100% loss - the safe default \
         the error return exists to be distinguishable from"
    );
    assert!(
        reflected >= 12,
        "a probe that carried no traffic proves nothing"
    );
}

/// A provider that cannot read is tolerated for two windows (skip, touch no
/// snapshots) and fail-safes on the third, never earlier.
#[tokio::test]
async fn failed_local_readings_skip_briefly_then_degrade() {
    let (state, degraded_at, reflected, _) =
        expresslane_health_probe(Some(Arc::new(AlwaysUnavailableStats)), None).await;

    assert_eq!(state, ExpresslaneState::Degraded);
    assert!(
        reflected >= 12,
        "a probe that carried no traffic proves nothing"
    );
    assert_eq!(
        degraded_at,
        Some(3),
        "the first two windows must be tolerated (skip) and the third fail-safe"
    );
}

/// A peer that stops reporting its own stats is exactly as untrustworthy as
/// one that has gone dark: the client must count the missing reports itself
/// and degrade, even though its own local counters read fine throughout.
#[tokio::test]
async fn peer_that_stops_reporting_degrades() {
    let (state, degraded_at, reflected, _) =
        expresslane_health_probe(None, Some(Arc::new(AlwaysUnavailableStats))).await;

    assert_eq!(state, ExpresslaneState::Degraded);
    assert!(
        reflected >= 12,
        "a probe that carried no traffic proves nothing"
    );
    assert_eq!(
        degraded_at,
        Some(3),
        "the first two windows must be tolerated (skip) and the third fail-safe"
    );
}

/// A client that degrades notifies the server, which must degrade too
/// rather than fall back to Inactive and keep offering expresslane.
#[tokio::test]
async fn server_follows_client_degrade() {
    let (state, _degraded_at, _reflected, server_state) =
        expresslane_health_probe(Some(Arc::new(AlwaysZeroStats)), None).await;

    assert_eq!(state, ExpresslaneState::Degraded);
    assert_eq!(server_state, ExpresslaneState::Degraded);
}

/// A server with expresslane disabled must not take up a client's
/// expresslane config: no key install or publish, no state change. It
/// still acks, so the client does not keep retransmitting.
#[tokio::test]
async fn disabled_server_ignores_expresslane_config() {
    struct CallCount(std::sync::atomic::AtomicUsize);
    impl<T> ExpresslaneCb<T> for CallCount {
        fn update(&self, _sid: SessionId, _data: ExpresslaneCbData, _s: &T) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    // Set once the client's own key is promoted, i.e. the server acked.
    struct AckSeen(std::sync::atomic::AtomicBool);
    impl<T> ExpresslaneCb<T> for AckSeen {
        fn update(&self, _sid: SessionId, data: ExpresslaneCbData, _s: &T) {
            if !data.self_key.is_invalid() {
                self.0.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    let (client_sock, server_sock) = UnixDatagram::pair().expect("UnixDatagram");
    let server_sock = Arc::new(TestDatagramSock(server_sock));
    let client_sock = Arc::new(TestDatagramSock(client_sock));

    let server_cb = Arc::new(CallCount(Default::default()));
    let client_cb = Arc::new(AckSeen(Default::default()));
    let (conn_tx, conn_rx) = oneshot::channel();

    let auth = Arc::new(TestAuth::default());
    let pki = TestPki::get_valid(2, RsaKeySize::_2048);
    let (cert, key) = pki.server_secrets();
    let server_task = server(
        server_sock,
        TestServerConfig {
            auth,
            pqc: PQCrypto {
                server_pqc: false,
                keyshare: None,
            },
            expresslane: None,
            conn_out: Some(conn_tx),
            metrics: None,
            expresslane_cb: Some(server_cb.clone()),
            cert,
            key,
        },
    );

    let client_task = async move {
        let server_conn = conn_rx.await.expect("server conn handle");

        let ca_cert = pki.root_ca();
        let (tun, _inside_rx) = ChannelTun::new();
        let (ticker, ticker_task) = ConnectionTicker::new();
        let state = ConnectionState { ticker };

        let conn = ClientContextBuilder::new(
            client_sock.connection_type(),
            ca_cert,
            Some(Arc::new(tun)),
            Arc::new(Client),
            connection_ticker_cb,
        )
        .unwrap()
        .with_expresslane(DEFAULT_EXPRESSLANE_KEYS_ROTATION_INTERVAL)
        .with_expresslane_cb(client_cb.clone())
        .build()
        .start_connect(client_sock.clone().into_io_send_callback(), MAX_OUTSIDE_MTU)
        .unwrap()
        .with_auth_token("LET ME IN")
        .connect(state)
        .unwrap();
        let conn = Arc::new(Mutex::new(conn));

        let mut join_set = JoinSet::new();
        ticker_task.spawn_in(Arc::downgrade(&conn), &mut join_set);

        let mut ticks = tokio::time::interval(std::time::Duration::from_millis(50));

        loop {
            tokio::select! {
                is_readable = client_sock.readable() => {
                    is_readable.expect("client socket readable");

                    let mut buf = BytesMut::with_capacity(MAX_OUTSIDE_MTU);
                    match client_sock.try_recv_buf(&mut buf) {
                        Ok(0) => panic!("EOF"),
                        Ok(_nr) => {}
                        Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                            continue;
                        }
                        Err(err) => panic!("read for sock {err}"),
                    };

                    let mut conn = conn.lock().unwrap();
                    let pkt = OutsidePacket::Wire(&mut buf, client_sock.connection_type());
                    if let Err(err) = conn.outside_data_received(pkt) {
                        panic!("{err}")
                    }
                }

                _ = ticks.tick() => {
                    if client_cb.0.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                }
            }
        }

        assert_eq!(
            server_conn.lock().unwrap().expresslane_state(),
            ExpresslaneState::Disabled
        );
        assert_eq!(
            server_cb.0.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a disabled server must not install or publish the client key"
        );
        assert_eq!(
            conn.lock().unwrap().expresslane_state(),
            ExpresslaneState::Inactive
        );

        conn.lock().unwrap().disconnect().unwrap();
    };

    tokio::time::timeout(
        std::time::Duration::from_millis(get_test_timeout()),
        async move { tokio::join!(server_task, client_task) },
    )
    .await
    .expect("client never saw its expresslane config acked");
}

/// The server announces a session id rotation with a ping stamped with the
/// new id. An idle client's pong to it has to carry the new id already, so
/// that it completes the rotation without waiting for other traffic.
#[tokio::test]
async fn idle_client_acknowledges_session_id_rotation_with_its_pong() {
    let (client_sock, server_sock) = UnixDatagram::pair().expect("UnixDatagram");
    let server_sock = Arc::new(TestDatagramSock(server_sock));
    let client_sock = Arc::new(TestDatagramSock(client_sock));

    let (conn_tx, conn_rx) = oneshot::channel();

    let auth = Arc::new(TestAuth::default());
    let pki = TestPki::get_valid(2, RsaKeySize::_2048);
    let (cert, key) = pki.server_secrets();
    let server_task = server(
        server_sock,
        TestServerConfig {
            auth,
            pqc: PQCrypto {
                server_pqc: false,
                keyshare: None,
            },
            expresslane: None,
            conn_out: Some(conn_tx),
            metrics: None,
            expresslane_cb: None,
            cert,
            key,
        },
    );

    let client_task = async move {
        let server_conn = conn_rx.await.expect("server conn handle");

        let ca_cert = pki.root_ca();
        let (tun, _inside_rx) = ChannelTun::new();
        let (ticker, ticker_task) = ConnectionTicker::new();
        let state = ConnectionState { ticker };

        let conn = ClientContextBuilder::new(
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
        .connect(state)
        .unwrap();
        let conn = Arc::new(Mutex::new(conn));

        let mut join_set = JoinSet::new();
        ticker_task.spawn_in(Arc::downgrade(&conn), &mut join_set);

        let mut ticks = tokio::time::interval(std::time::Duration::from_millis(50));
        let mut rotated_to = None;

        loop {
            tokio::select! {
                is_readable = client_sock.readable() => {
                    is_readable.expect("client socket readable");

                    let mut buf = BytesMut::with_capacity(MAX_OUTSIDE_MTU);
                    match client_sock.try_recv_buf(&mut buf) {
                        Ok(0) => panic!("EOF"),
                        Ok(_nr) => {}
                        Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                            continue;
                        }
                        Err(err) => panic!("read for sock {err}"),
                    };

                    let mut conn = conn.lock().unwrap();
                    let pkt = OutsidePacket::Wire(&mut buf, client_sock.connection_type());
                    if let Err(err) = conn.outside_data_received(pkt) {
                        panic!("{err}")
                    }
                }

                _ = ticks.tick() => {
                    let mut server = server_conn.lock().unwrap();
                    match rotated_to {
                        None if server.state() == State::Online
                            && conn.lock().unwrap().state() == State::Online =>
                        {
                            rotated_to = Some(server.rotate_session_id().unwrap());
                        }
                        Some(new) if server.session_id() == new => {
                            assert_eq!(server.pending_session_id(), None);
                            assert_eq!(conn.lock().unwrap().session_id(), new);
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        conn.lock().unwrap().disconnect().unwrap();
    };

    tokio::time::timeout(
        std::time::Duration::from_millis(get_test_timeout()),
        async move { tokio::join!(server_task, client_task) },
    )
    .await
    .expect("the client's pong never completed the session id rotation");
}

/// The session id in a packet's header is only adopted once the packet's
/// record decrypts. A replayed datagram, or one whose record fails to
/// decrypt, must not move the client to the id in its header.
#[tokio::test]
async fn client_ignores_session_id_of_replayed_or_corrupted_packets() {
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum Phase {
        Connecting,
        AwaitPing,
        AwaitSecondPing,
        Done,
    }

    fn with_session(raw: &BytesMut, session: SessionId) -> BytesMut {
        let mut pkt = raw.clone();
        pkt[8..16].copy_from_slice(session.as_bytes());
        pkt
    }

    let (client_sock, server_sock) = UnixDatagram::pair().expect("UnixDatagram");
    let server_sock = Arc::new(TestDatagramSock(server_sock));
    let client_sock = Arc::new(TestDatagramSock(client_sock));

    let (conn_tx, conn_rx) = oneshot::channel();

    let auth = Arc::new(TestAuth::default());
    let pki = TestPki::get_valid(2, RsaKeySize::_2048);
    let (cert, key) = pki.server_secrets();
    let server_task = server(
        server_sock,
        TestServerConfig {
            auth,
            pqc: PQCrypto {
                server_pqc: false,
                keyshare: None,
            },
            expresslane: None,
            conn_out: Some(conn_tx),
            metrics: None,
            expresslane_cb: None,
            cert,
            key,
        },
    );

    let client_task = async move {
        let server_conn = conn_rx.await.expect("server conn handle");

        let ca_cert = pki.root_ca();
        let (tun, _inside_rx) = ChannelTun::new();
        let (ticker, ticker_task) = ConnectionTicker::new();
        let state = ConnectionState { ticker };

        let conn = ClientContextBuilder::new(
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
        .connect(state)
        .unwrap();
        let conn = Arc::new(Mutex::new(conn));

        let mut join_set = JoinSet::new();
        ticker_task.spawn_in(Arc::downgrade(&conn), &mut join_set);

        let bogus = SessionId::from_const([0x42; 8]);
        let mut phase = Phase::Connecting;
        let mut ticks = tokio::time::interval(std::time::Duration::from_millis(50));

        while phase != Phase::Done {
            tokio::select! {
                is_readable = client_sock.readable() => {
                    is_readable.expect("client socket readable");

                    let mut buf = BytesMut::with_capacity(MAX_OUTSIDE_MTU);
                    match client_sock.try_recv_buf(&mut buf) {
                        Ok(0) => panic!("EOF"),
                        Ok(_nr) => {}
                        Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                            continue;
                        }
                        Err(err) => panic!("read for sock {err}"),
                    };
                    let raw = buf.clone();

                    let mut conn = conn.lock().unwrap();
                    let session = conn.session_id();
                    match phase {
                        Phase::Connecting => {}
                        Phase::AwaitPing => {
                            // Deliver the ping, then replay it under another id.
                            let pkt = OutsidePacket::Wire(&mut buf, client_sock.connection_type());
                            conn.outside_data_received(pkt).unwrap();
                            let mut replay = with_session(&raw, bogus);
                            let pkt = OutsidePacket::Wire(&mut replay, client_sock.connection_type());
                            let _ = conn.outside_data_received(pkt);
                            assert_eq!(conn.session_id(), session, "adopted a replayed packet's id");
                            phase = Phase::AwaitSecondPing;
                            server_conn.lock().unwrap().keepalive().unwrap();
                            continue;
                        }
                        Phase::AwaitSecondPing => {
                            // Corrupt the record, then deliver the original.
                            let mut corrupted = with_session(&raw, bogus);
                            let last = corrupted.len() - 1;
                            corrupted[last] ^= 0xff;
                            let pkt = OutsidePacket::Wire(&mut corrupted, client_sock.connection_type());
                            let _ = conn.outside_data_received(pkt);
                            assert_eq!(conn.session_id(), session, "adopted a corrupted packet's id");
                            phase = Phase::Done;
                        }
                        Phase::Done => unreachable!(),
                    }
                    let pkt = OutsidePacket::Wire(&mut buf, client_sock.connection_type());
                    if let Err(err) = conn.outside_data_received(pkt) {
                        panic!("{err}")
                    }
                }

                _ = ticks.tick() => {
                    if phase == Phase::Connecting
                        && conn.lock().unwrap().state() == State::Online
                        && server_conn.lock().unwrap().state() == State::Online
                    {
                        phase = Phase::AwaitPing;
                        server_conn.lock().unwrap().keepalive().unwrap();
                    }
                }
            }
        }

        conn.lock().unwrap().disconnect().unwrap();
    };

    tokio::time::timeout(
        std::time::Duration::from_millis(get_test_timeout()),
        async move { tokio::join!(server_task, client_task) },
    )
    .await
    .expect("test never reached the replayed and corrupted packets");
}

/// A GSO aggregate whose segments fit the inside MTU but not the PMTUD
/// estimate is fragmented like any other oversized packet: no datagram it
/// puts on the wire is larger than the probe that confirmed the estimate.
/// Once the estimate covers the segments, they are batched again.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn pmtud_fragments_gso_segments_above_the_estimate() {
    /// IPv4 + TCP header of the aggregate built below.
    const HDR_LEN: usize = 40;
    /// One segment is 1300 bytes: within `ChannelTun`'s 1350-byte inside
    /// MTU, above the 1247-byte payload the base PLPMTU of 1250 allows.
    const GSO_SIZE: usize = 1260;
    const SEGS: usize = 2;

    /// PMTUD events and outside datagrams, in the order the connection
    /// produced them.
    #[derive(Debug, Clone, Copy)]
    enum Entry {
        Pmtud(PmtudStatus),
        /// One datagram, sent alone or as part of a GSO batch.
        Send {
            len: usize,
            gso: bool,
        },
    }
    type Log = Arc<Mutex<Vec<Entry>>>;

    /// Keeps the default `gso_enabled() == true`, so the connection batches
    /// whenever it decides it may.
    struct RecordingSock {
        inner: Arc<TestDatagramSock>,
        log: Log,
    }

    impl OutsideIOSendCallback for RecordingSock {
        fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
            let len = buf.len();
            self.log
                .lock()
                .unwrap()
                .push(Entry::Send { len, gso: false });
            self.inner.send(buf)
        }

        // Record the datagrams the kernel would cut the batch into. Nothing
        // after the batch needs it delivered.
        fn send_gso(
            &self,
            bufs: &[std::io::IoSlice<'_>],
            gso_size: u16,
        ) -> IOCallbackResult<usize> {
            let total: usize = bufs.iter().map(|b| b.len()).sum();
            let stride = gso_size as usize;
            let mut log = self.log.lock().unwrap();
            for offset in (0..total).step_by(stride) {
                let len = stride.min(total - offset);
                log.push(Entry::Send { len, gso: true });
            }
            IOCallbackResult::Ok(total)
        }

        fn peer_addr(&self) -> std::net::SocketAddr {
            self.inner.peer_addr()
        }

        // Unix datagram sockets have no DF bit; accept the probe bracket.
        fn enable_pmtud_probe(&self) -> std::io::Result<()> {
            Ok(())
        }

        fn disable_pmtud_probe(&self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct RecordingEvents(Log);

    impl EventCallback for RecordingEvents {
        fn event(&mut self, event: Event) {
            if let Event::PmtudStateChanged(status) = event {
                self.0.lock().unwrap().push(Entry::Pmtud(status));
            }
        }
    }

    /// An IPv4/TCP aggregate of `SEGS` full segments, as TUN hands it over
    /// with TSO enabled.
    fn tcp_aggregate() -> (BytesMut, VirtioNetHdr) {
        let total = HDR_LEN + SEGS * GSO_SIZE;
        let mut pkt = BytesMut::zeroed(total);
        pkt[0] = 0x45; // IPv4, 20-byte header
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[8] = 64; // TTL
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[10, 125, 0, 2]);
        pkt[16..20].copy_from_slice(&[10, 125, 0, 1]);
        pkt[32] = 0x50; // 20-byte TCP header
        pkt[33] = 0x10; // ACK
        let hdr = VirtioNetHdr {
            flags: gso::VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: 1, // VIRTIO_NET_HDR_GSO_TCPV4
            hdr_len: HDR_LEN as u16,
            gso_size: GSO_SIZE as u16,
            csum_start: 20,
            csum_offset: 16,
        };
        (pkt, hdr)
    }

    // Take the shared test PKI before the timeout window (RSA keygen is very
    // slow on QEMU, and only happens on first use).
    let pki = TestPki::get_valid(2, RsaKeySize::_2048);

    let (client_sock, server_sock) = UnixDatagram::pair().expect("UnixDatagram");
    let server_sock = Arc::new(TestDatagramSock(server_sock));
    let client_sock = Arc::new(TestDatagramSock(client_sock));

    let (auth, _last_method) = TestAuth::new();
    let (cert, key) = pki.server_secrets();
    let mut server_task = tokio::spawn(server(
        server_sock,
        TestServerConfig {
            auth,
            pqc: PQCrypto {
                server_pqc: false,
                keyshare: None,
            },
            expresslane: None,
            conn_out: None,
            metrics: None,
            expresslane_cb: None,
            cert,
            key,
        },
    ));

    let log: Log = Default::default();
    let (tun, _inside_rx) = ChannelTun::new();
    let (ticker, ticker_task) = ConnectionTicker::new();
    let (pmtud_timer, pmtud_timer_task) = lightway_app_utils::DplpmtudTimer::new();
    let outside: OutsideIOSendCallbackArg = Arc::new(RecordingSock {
        inner: client_sock.clone(),
        log: log.clone(),
    });

    let client = ClientContextBuilder::new(
        client_sock.connection_type(),
        pki.root_ca(),
        Some(Arc::new(tun)),
        Arc::new(Client),
        connection_ticker_cb,
    )
    .unwrap()
    // As the shared test client does: the server checks the negotiated
    // curve when inside data reaches it.
    .enable_pq_crypto()
    .unwrap()
    .build()
    .start_connect(outside, MAX_OUTSIDE_MTU)
    .unwrap()
    .with_auth_token("LET ME IN")
    .with_event_cb(Box::new(RecordingEvents(log.clone())))
    .with_pmtud_timer(pmtud_timer)
    .connect(ConnectionState { ticker })
    .unwrap();
    let client = Arc::new(Mutex::new(client));

    let mut join_set = JoinSet::new();
    ticker_task.spawn_in(Arc::downgrade(&client), &mut join_set);
    pmtud_timer_task.spawn(Arc::downgrade(&client), &mut join_set);

    // Pump the client until the base probe is confirmed, then send the
    // aggregate under the same lock: the estimate is the base PLPMTU and
    // nothing else reaches the outside I/O meanwhile. Returns where the
    // aggregate's datagrams start in the log.
    // Then again once the search has completed above the segment size.
    // Returns the log ranges of both aggregates' datagrams.
    let driver = async {
        let mut small = None;
        loop {
            client_sock
                .readable()
                .await
                .expect("client socket readable");
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
            let Some(status) = c.pmtud_status() else {
                continue;
            };
            let Some(mps) = status.max_packet_size else {
                continue;
            };
            let send_aggregate = |c: &mut Connection<ConnectionState>| {
                let (mut pkt, hdr) = tcp_aggregate();
                let start = log.lock().unwrap().len();
                c.inside_data_received_gso(&mut pkt, &hdr)
                    .expect("aggregate sent");
                start..log.lock().unwrap().len()
            };
            match small {
                None => {
                    assert!(HDR_LEN + GSO_SIZE > mps, "segments must exceed {mps}");
                    small = Some(send_aggregate(&mut c));
                }
                Some(ref small) if status.state == PmtudState::SearchComplete => {
                    assert!(HDR_LEN + GSO_SIZE <= mps, "segments must fit {mps}");
                    return (small.clone(), send_aggregate(&mut c));
                }
                Some(_) => {}
            }
        }
    };

    let (small, large) = tokio::time::timeout(
        std::time::Duration::from_millis(get_test_timeout()),
        async {
            tokio::select! {
                ranges = driver => ranges,
                r = &mut server_task => panic!("server task ended early: {r:?}"),
            }
        },
    )
    .await
    .expect("test timed out");

    let log = log.lock().unwrap().clone();

    // Each PMTUD event precedes the probe it requests, so the datagram right
    // after `Base` is the probe that confirmed the estimate.
    let base = log
        .iter()
        .position(|e| matches!(e, Entry::Pmtud(s) if s.state == PmtudState::Base))
        .expect("Base was reported");
    let Some(Entry::Send { len: limit, .. }) = log.get(base + 1) else {
        panic!("expected the base probe right after Base: {log:?}");
    };

    let sent = &log[small];
    assert!(sent.len() >= SEGS, "aggregate not sent: {sent:?}");
    for e in sent {
        let Entry::Send { len, gso } = e else {
            panic!("unexpected {e:?} while sending the aggregate");
        };
        assert!(
            len <= limit,
            "{len}-byte datagram (gso: {gso}) exceeds the {limit}-byte base probe: {sent:?}"
        );
    }
    // Once the estimate covers the segments they go out as one batch again.
    let sent = &log[large];
    assert!(
        sent.len() == SEGS
            && sent
                .iter()
                .all(|e| matches!(e, Entry::Send { gso: true, .. })),
        "aggregate not batched: {sent:?}"
    );
}

/// PMTUD reports its progress to the application: `Event::PmtudStateChanged`
/// fires once per state or estimate change (never for a no-op step), the
/// getter agrees with the last event, and for every step that requests a
/// probe the event is delivered before that probe reaches the outside I/O.
#[tokio::test]
async fn pmtud_reports_status_changes() {
    /// One entry per PMTUD event and per outside send, in the order the
    /// connection produced them: both happen synchronously inside the call
    /// that drives the state machine, so the log preserves their ordering.
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum Entry {
        Online,
        Pmtud(PmtudStatus),
        Send(usize),
    }
    type Log = Arc<Mutex<Vec<Entry>>>;

    struct RecordingSock {
        inner: Arc<TestDatagramSock>,
        log: Log,
    }

    impl OutsideIOSendCallback for RecordingSock {
        fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
            self.log.lock().unwrap().push(Entry::Send(buf.len()));
            self.inner.send(buf)
        }

        fn send_gso(
            &self,
            bufs: &[std::io::IoSlice<'_>],
            gso_size: u16,
        ) -> IOCallbackResult<usize> {
            self.inner.send_gso(bufs, gso_size)
        }

        fn peer_addr(&self) -> std::net::SocketAddr {
            self.inner.peer_addr()
        }

        // Unix datagram sockets have no DF bit; accept the probe bracket.
        fn enable_pmtud_probe(&self) -> std::io::Result<()> {
            Ok(())
        }

        fn disable_pmtud_probe(&self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct RecordingEvents {
        inner: EventStreamCallback,
        log: Log,
    }

    impl EventCallback for RecordingEvents {
        fn event(&mut self, event: Event) {
            match &event {
                Event::StateChanged(State::Online) => self.log.lock().unwrap().push(Entry::Online),
                Event::PmtudStateChanged(status) => {
                    self.log.lock().unwrap().push(Entry::Pmtud(*status))
                }
                _ => {}
            }
            self.inner.event(event);
        }
    }

    // Take the shared test PKI before the timeout window (RSA keygen is very
    // slow on QEMU, and only happens on first use).
    let pki = TestPki::get_valid(2, RsaKeySize::_2048);

    let (client_sock, server_sock) = UnixDatagram::pair().expect("UnixDatagram");
    let server_sock = Arc::new(TestDatagramSock(server_sock));
    let client_sock = Arc::new(TestDatagramSock(client_sock));

    let (auth, _last_method) = TestAuth::new();
    let pqc = PQCrypto {
        server_pqc: false,
        keyshare: None,
    };

    // The server answers every probe Ping with a Pong.
    let (cert, key) = pki.server_secrets();
    let mut server_task = tokio::spawn(server(
        server_sock,
        TestServerConfig {
            auth,
            pqc,
            expresslane: None,
            conn_out: None,
            metrics: None,
            expresslane_cb: None,
            cert,
            key,
        },
    ));

    let log: Log = Default::default();
    let ca_cert = pki.root_ca();
    let (tun, _inside_rx) = ChannelTun::new();
    let (event_cb, mut event_stream) = EventStreamCallback::new();
    let (ticker, ticker_task) = ConnectionTicker::new();
    let (pmtud_timer, pmtud_timer_task) = lightway_app_utils::DplpmtudTimer::new();
    let state = ConnectionState { ticker };
    let outside: OutsideIOSendCallbackArg = Arc::new(RecordingSock {
        inner: client_sock.clone(),
        log: log.clone(),
    });

    let client = ClientContextBuilder::new(
        client_sock.connection_type(),
        ca_cert,
        Some(Arc::new(tun)),
        Arc::new(Client),
        connection_ticker_cb,
    )
    .unwrap()
    .build()
    .start_connect(outside, MAX_OUTSIDE_MTU)
    .unwrap()
    .with_auth_token("LET ME IN")
    .with_event_cb(Box::new(RecordingEvents {
        inner: event_cb,
        log: log.clone(),
    }))
    .with_pmtud_timer(pmtud_timer)
    .connect(state)
    .unwrap();
    let client = Arc::new(Mutex::new(client));

    let mut join_set = JoinSet::new();
    ticker_task.spawn_in(Arc::downgrade(&client), &mut join_set);
    pmtud_timer_task.spawn(Arc::downgrade(&client), &mut join_set);

    // Drain events so the stream never backpressures the connection.
    tokio::spawn(async move { while event_stream.next().await.is_some() {} });

    // Pump the client until the search converges. Nothing is lost on the
    // socket pair, so no probe timer ever fires and every probe is confirmed.
    let driver = async {
        loop {
            client_sock
                .readable()
                .await
                .expect("client socket readable");
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
            if c.pmtud_status()
                .is_some_and(|s| s.state == PmtudState::SearchComplete)
            {
                return;
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

    let log = log.lock().unwrap().clone();
    let online = log
        .iter()
        .position(|e| *e == Entry::Online)
        .expect("Online was reported");
    let pmtud: Vec<(usize, PmtudStatus)> = log
        .iter()
        .enumerate()
        .filter_map(|(i, e)| match e {
            Entry::Pmtud(s) => Some((i, *s)),
            _ => None,
        })
        .collect();
    assert!(
        pmtud.first().is_some_and(|(i, _)| *i > online),
        "discovery starts once Online: {log:?}"
    );

    // One event per change, none for a no-op step: base 1250 (unconfirmed
    // in Base; confirming it changes only the state), big steps of 32 up to
    // max_dtls_mtu(MAX_OUTSIDE_MTU) = 1419, at which point the search
    // converges without an intermediate Searching(1419).
    let expected = [
        (PmtudState::Base, Some(1250)),
        (PmtudState::Searching, Some(1250)),
        (PmtudState::Searching, Some(1282)),
        (PmtudState::Searching, Some(1314)),
        (PmtudState::Searching, Some(1346)),
        (PmtudState::Searching, Some(1378)),
        (PmtudState::Searching, Some(1410)),
        (PmtudState::SearchComplete, Some(1419)),
    ];
    let observed: Vec<_> = pmtud.iter().map(|(_, s)| (s.state, s.plpmtu)).collect();
    assert_eq!(observed, expected, "full log: {log:?}");
    for (_, s) in &pmtud {
        // wire::Data frame overhead: kind byte plus 2-byte length.
        assert_eq!(s.max_packet_size, s.plpmtu.map(|p| p as usize - 3), "{s:?}");
    }

    // The getter reports the same snapshot as the last event.
    assert_eq!(
        client.lock().unwrap().pmtud_status(),
        pmtud.last().map(|(_, s)| *s)
    );

    // Every snapshot that requests a probe is delivered BEFORE that probe
    // is sent: the next log entry after it is the probe itself (an
    // encrypted datagram at least as large as the probed PLPMTU, which here
    // is never below the base).
    for (i, s) in &pmtud {
        if s.state == PmtudState::SearchComplete {
            continue;
        }
        match log.get(i + 1) {
            Some(Entry::Send(len)) => {
                assert!(*len >= 1250, "probe after {s:?} was only {len} bytes")
            }
            other => panic!("expected the probe send right after {s:?}, found {other:?}"),
        }
    }
}

/// What [`PmtudLink`] did with a datagram.
#[derive(Debug, Clone, Copy, PartialEq)]
enum PmtudLinkOutcome {
    Sent,
    /// `EMSGSIZE`: larger than the interface MTU, with DF set.
    Refused,
    /// `WouldBlock`.
    Blocked,
}

#[derive(Debug, Clone, Copy)]
struct PmtudLinkSend {
    len: usize,
    df: bool,
    outcome: PmtudLinkOutcome,
}

/// Faults to inject into a [`PmtudLink`].
#[derive(Default)]
struct PmtudLinkFaults {
    /// The socket cannot be switched to probe mode.
    enable_fails: bool,
    /// The socket cannot be switched back out of probe mode.
    disable_fails: bool,
    /// The first DF datagram of at least this size finds the socket not
    /// writable.
    block_once_from: Option<usize>,
}

/// Outside link with a 1400-byte interface MTU. With DF set the kernel
/// refuses a larger datagram; without it, the kernel fragments the
/// datagram and the peer reassembles it, so it arrives whole.
struct PmtudLink {
    inner: Arc<TestDatagramSock>,
    faults: PmtudLinkFaults,
    df: std::sync::atomic::AtomicBool,
    blocked: std::sync::atomic::AtomicBool,
    /// While set, every DF datagram finds the socket not writable.
    block_df: std::sync::atomic::AtomicBool,
    /// The next this many non-DF datagrams find the socket not writable.
    block_plain: std::sync::atomic::AtomicUsize,
    sends: Mutex<Vec<PmtudLinkSend>>,
    /// Sends and PMTUD status changes, in order, to explain a failure.
    trace: Mutex<Vec<String>>,
}

impl PmtudLink {
    /// Interface MTU (IP packet size).
    const MTU: usize = 1400;
    /// IPv4 and UDP headers the kernel adds to each datagram.
    const IP_UDP_HEADERS: usize = 28;

    fn trace(&self, entry: String) {
        self.trace.lock().unwrap().push(entry);
    }

    fn sends(&self) -> Vec<PmtudLinkSend> {
        self.sends.lock().unwrap().clone()
    }

    fn count(&self, outcome: PmtudLinkOutcome) -> usize {
        self.sends().iter().filter(|s| s.outcome == outcome).count()
    }

    /// Datagram size of a probe for `plpmtu`. The wire bytes a probe adds
    /// on top of its PLPMTU are measured from the first probe (the base
    /// probe at 1250).
    fn probe_len(&self, plpmtu: u16) -> usize {
        let base = self.sends().into_iter().find(|s| s.df);
        plpmtu as usize + base.expect("a probe was sent").len - 1250
    }

    /// Whether a probe for `plpmtu` fits the interface.
    fn fits(&self, plpmtu: u16) -> bool {
        self.probe_len(plpmtu) + Self::IP_UDP_HEADERS <= Self::MTU
    }

    /// Datagrams which were refused or blocked with DF set and left
    /// later without it: the kernel fragments them, the server answers
    /// them, and the search believes the answer. (Oversized non-probe
    /// sends, e.g. the ClientHello, may fragment.)
    fn leaked_probes(&self) -> Vec<PmtudLinkSend> {
        let sends = self.sends();
        sends
            .iter()
            .enumerate()
            .filter(|(i, s)| {
                s.outcome == PmtudLinkOutcome::Sent
                    && !s.df
                    && sends[..*i]
                        .iter()
                        .any(|r| r.outcome != PmtudLinkOutcome::Sent && r.len == s.len)
            })
            .map(|(_, s)| *s)
            .collect()
    }
}

impl OutsideIOSendCallback for PmtudLink {
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        use std::sync::atomic::Ordering;

        let df = self.df.load(Ordering::SeqCst);
        let outcome = if df && buf.len() + Self::IP_UDP_HEADERS > Self::MTU {
            PmtudLinkOutcome::Refused
        } else if (df && self.block_df.load(Ordering::SeqCst))
            || (!df
                && self
                    .block_plain
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .is_ok())
            || (df
                && self.faults.block_once_from.is_some_and(|n| buf.len() >= n)
                && !self.blocked.swap(true, Ordering::SeqCst))
        {
            PmtudLinkOutcome::Blocked
        } else {
            PmtudLinkOutcome::Sent
        };
        self.sends.lock().unwrap().push(PmtudLinkSend {
            len: buf.len(),
            df,
            outcome,
        });
        self.trace(format!("send {} bytes, df={df} -> {outcome:?}", buf.len()));
        match outcome {
            PmtudLinkOutcome::Sent => self.inner.send(buf),
            // lightway-client's UDP socket passes EMSGSIZE up unchanged.
            PmtudLinkOutcome::Refused => {
                IOCallbackResult::Err(std::io::Error::from_raw_os_error(libc::EMSGSIZE))
            }
            PmtudLinkOutcome::Blocked => IOCallbackResult::WouldBlock,
        }
    }

    fn send_gso(&self, bufs: &[std::io::IoSlice<'_>], gso_size: u16) -> IOCallbackResult<usize> {
        self.inner.send_gso(bufs, gso_size)
    }

    fn peer_addr(&self) -> std::net::SocketAddr {
        self.inner.peer_addr()
    }

    fn enable_pmtud_probe(&self) -> std::io::Result<()> {
        if self.faults.enable_fails {
            self.trace("enable probe mode -> Err".to_string());
            return Err(std::io::Error::other("enable failed"));
        }
        self.df.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn disable_pmtud_probe(&self) -> std::io::Result<()> {
        if self.faults.disable_fails {
            self.trace("disable probe mode -> Err".to_string());
            return Err(std::io::Error::other("disable failed"));
        }
        self.df.store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

/// A client running PMTUD over a [`PmtudLink`] to a server which answers
/// every probe.
struct PmtudLinkTest {
    link: Arc<PmtudLink>,
    client: Arc<Mutex<Connection<ConnectionState>>>,
    client_sock: Arc<TestDatagramSock>,
    server_task: tokio::task::JoinHandle<()>,
    /// Every status delivered with `Event::PmtudStateChanged`.
    statuses: Arc<Mutex<Vec<PmtudStatus>>>,
    /// Received packets the connection failed to process.
    failed_reads: usize,
    _tasks: JoinSet<()>,
}

impl PmtudLinkTest {
    fn start(faults: PmtudLinkFaults) -> Self {
        struct RecordingEvents {
            link: Arc<PmtudLink>,
            statuses: Arc<Mutex<Vec<PmtudStatus>>>,
        }

        impl EventCallback for RecordingEvents {
            fn event(&mut self, event: Event) {
                if let Event::PmtudStateChanged(status) = event {
                    self.link.trace(format!(
                        "pmtud {:?} plpmtu={:?}",
                        status.state, status.plpmtu
                    ));
                    self.statuses.lock().unwrap().push(status);
                }
            }
        }

        // Take the shared test PKI before the timeout window (RSA keygen is
        // very slow on QEMU, and only happens on first use).
        let pki = TestPki::get_valid(2, RsaKeySize::_2048);

        let (client_sock, server_sock) = UnixDatagram::pair().expect("UnixDatagram");
        let server_sock = Arc::new(TestDatagramSock(server_sock));
        let client_sock = Arc::new(TestDatagramSock(client_sock));

        let (auth, _last_method) = TestAuth::new();
        let pqc = PQCrypto {
            server_pqc: false,
            keyshare: None,
        };

        // The server answers every probe Ping with a Pong.
        let (cert, key) = pki.server_secrets();
        let server_task = tokio::spawn(server(
            server_sock,
            TestServerConfig {
                auth,
                pqc,
                expresslane: None,
                conn_out: None,
                metrics: None,
                expresslane_cb: None,
                cert,
                key,
            },
        ));

        let link = Arc::new(PmtudLink {
            inner: client_sock.clone(),
            faults,
            df: Default::default(),
            blocked: Default::default(),
            block_df: Default::default(),
            block_plain: Default::default(),
            sends: Default::default(),
            trace: Default::default(),
        });
        let outside: OutsideIOSendCallbackArg = link.clone();
        let statuses: Arc<Mutex<Vec<PmtudStatus>>> = Default::default();

        let ca_cert = pki.root_ca();
        let (tun, _inside_rx) = ChannelTun::new();
        let (ticker, ticker_task) = ConnectionTicker::new();
        let (pmtud_timer, pmtud_timer_task) = lightway_app_utils::DplpmtudTimer::new();
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
        .start_connect(outside, MAX_OUTSIDE_MTU)
        .unwrap()
        .with_auth_token("LET ME IN")
        .with_event_cb(Box::new(RecordingEvents {
            link: link.clone(),
            statuses: statuses.clone(),
        }))
        .with_pmtud_timer(pmtud_timer)
        .connect(state)
        .unwrap();
        let client = Arc::new(Mutex::new(client));

        let mut tasks = JoinSet::new();
        ticker_task.spawn_in(Arc::downgrade(&client), &mut tasks);
        pmtud_timer_task.spawn(Arc::downgrade(&client), &mut tasks);

        Self {
            link,
            client,
            client_sock,
            server_task,
            statuses,
            failed_reads: 0,
            _tasks: tasks,
        }
    }

    /// Feed the client one packet from the server, then let `step` use
    /// the connection. Returns what `step` returned.
    async fn receive<T>(&mut self, step: impl FnOnce(&mut Connection<ConnectionState>) -> T) -> T {
        let mut buf = BytesMut::with_capacity(MAX_OUTSIDE_MTU);
        loop {
            tokio::select! {
                r = self.client_sock.readable() => r.expect("client socket readable"),
                r = &mut self.server_task => panic!("server task ended early: {r:?}"),
            }
            match self.client_sock.try_recv_buf(&mut buf) {
                Ok(0) => panic!("EOF"),
                Ok(_) => break,
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock) => continue,
                Err(e) => panic!("client recv: {e}"),
            }
        }
        let mut c = self.client.lock().unwrap();
        let pkt = OutsidePacket::Wire(&mut buf, self.client_sock.connection_type());
        if let Err(e) = c.outside_data_received(pkt) {
            self.failed_reads += 1;
            self.link
                .trace(format!("outside_data_received -> Err({e:?})"));
        }
        step(&mut c)
    }

    /// Feed the client what the server sends until `step` returns true.
    /// Returns false if that takes longer than the test timeout.
    async fn run_until(
        &mut self,
        mut step: impl FnMut(&mut Connection<ConnectionState>, &PmtudLink) -> bool,
    ) -> bool {
        let link = self.link.clone();
        let timeout = std::time::Duration::from_millis(get_test_timeout());
        tokio::time::timeout(timeout, async {
            while !self.receive(|c| step(c, &link)).await {}
        })
        .await
        .is_ok()
    }

    /// Feed the client everything the server still has to say.
    async fn settle(&mut self) {
        let idle = std::time::Duration::from_millis(200);
        while tokio::time::timeout(idle, self.receive(|_| ()))
            .await
            .is_ok()
        {}
    }

    fn status(&self) -> PmtudStatus {
        let c = self.client.lock().unwrap();
        c.pmtud_status().expect("PMTUD enabled")
    }

    fn trace(&self) -> String {
        self.link.trace.lock().unwrap().join("\n  ")
    }
}

/// A PMTUD probe larger than the local interface is refused with EMSGSIZE
/// while DF is set (Linux `IP_PMTUDISC_PROBE`, Apple `IP_DONTFRAG`). That
/// probe is lost: it must never reach the wire without DF, the search must
/// settle on a PLPMTU the interface can carry without waiting for probe
/// timeouts, and the connection must keep receiving.
///
/// `writes_after_refusal` is how many ordinary writes (keepalives here; data
/// behaves the same) the client makes after the refusal: a busy connection
/// writes more than once before the next packet arrives.
#[test_case(1; "one write after the refusal")]
#[test_case(2; "two writes after the refusal")]
#[tokio::test]
async fn pmtud_probe_refused_with_emsgsize_is_not_confirmed(writes_after_refusal: usize) {
    let mut t = PmtudLinkTest::start(PmtudLinkFaults::default());

    let mut refused_seen = 0;
    let finished = t
        .run_until(|c, link| {
            // A probe was just refused. The connection carries on, so its
            // next ordinary writes go out with DF clear again.
            let refused = link.count(PmtudLinkOutcome::Refused);
            if refused > refused_seen {
                refused_seen = refused;
                for _ in 0..writes_after_refusal {
                    let r = c.keepalive();
                    link.trace(format!("keepalive after refusal -> {r:?}"));
                }
            }

            let status = c.pmtud_status().expect("PMTUD enabled");
            status.state == PmtudState::SearchComplete
                || status.plpmtu.is_some_and(|p| !link.fits(p))
        })
        .await;

    let trace = t.trace();
    eprintln!("trace ({writes_after_refusal} write(s) after the refusal):\n  {trace}");
    assert!(finished, "test timed out");

    let sends = t.link.sends();
    assert!(
        t.link.count(PmtudLinkOutcome::Refused) > 0,
        "no probe exceeded the interface MTU: {sends:?}"
    );
    assert_eq!(
        t.link.leaked_probes().len(),
        0,
        "probes refused with DF set were later sent without it: {sends:?}"
    );
    assert_eq!(t.failed_reads, 0, "received packets could not be processed");

    // 1346 is refused, so small steps from 1314: 1322 and 1330 fit, 1338
    // is refused. Nothing waits for a probe timer.
    let observed: Vec<_> = t
        .statuses
        .lock()
        .unwrap()
        .iter()
        .map(|s| (s.state, s.plpmtu))
        .collect();
    let expected = [
        (PmtudState::Base, Some(1250)),
        (PmtudState::Searching, Some(1250)),
        (PmtudState::Searching, Some(1282)),
        (PmtudState::Searching, Some(1314)),
        (PmtudState::Searching, Some(1322)),
        (PmtudState::Searching, Some(1330)),
        (PmtudState::SearchComplete, Some(1330)),
    ];
    assert_eq!(observed, expected);
    assert!(t.link.fits(1330) && !t.link.fits(1338));

    // No size was tried again once the interface had refused it.
    let refused: Vec<_> = sends
        .iter()
        .filter(|s| s.outcome == PmtudLinkOutcome::Refused)
        .map(|s| s.len)
        .collect();
    let expected = [t.link.probe_len(1346), t.link.probe_len(1338)];
    assert_eq!(refused, expected, "{sends:?}");
}

/// A probe sent while DF cannot be set proves nothing about the path. When
/// the socket cannot be switched into probe mode PMTUD stops for the
/// connection, says so, and the connection carries on without it.
#[tokio::test]
async fn pmtud_stops_when_probe_mode_cannot_be_enabled() {
    let mut t = PmtudLinkTest::start(PmtudLinkFaults {
        enable_fails: true,
        ..Default::default()
    });

    let online = t.run_until(|c, _| matches!(c.state(), State::Online)).await;
    t.client.lock().unwrap().keepalive().expect("keepalive");
    t.settle().await;

    eprintln!("trace:\n  {}", t.trace());
    assert!(online, "test timed out");
    assert_eq!(t.failed_reads, 0);

    let status = t.status();
    assert_eq!((status.state, status.plpmtu), (PmtudState::Disabled, None));
    let observed: Vec<_> = t
        .statuses
        .lock()
        .unwrap()
        .iter()
        .map(|s| (s.state, s.plpmtu))
        .collect();
    assert_eq!(
        observed,
        [(PmtudState::Base, Some(1250)), (PmtudState::Disabled, None)]
    );

    // No probe left. The handshake's first flight is larger than any
    // probe.
    let sends = t.link.sends();
    let handshake = sends.iter().map(|s| s.len).max().unwrap();
    let probes: Vec<_> = sends
        .iter()
        .filter(|s| (1250..handshake).contains(&s.len))
        .collect();
    assert!(probes.is_empty(), "{sends:?}");
    assert!(sends.iter().all(|s| !s.df), "{sends:?}");
}

/// When DF cannot be cleared after a probe, that probe still went out with
/// DF set and counts. PMTUD carries on, so packets stay within what the
/// path carries with DF set, and the connection keeps working.
#[tokio::test]
async fn pmtud_continues_when_probe_mode_cannot_be_disabled() {
    let mut t = PmtudLinkTest::start(PmtudLinkFaults {
        disable_fails: true,
        ..Default::default()
    });

    let finished = t
        .run_until(|c, _| {
            c.pmtud_status()
                .is_some_and(|s| s.state == PmtudState::SearchComplete)
        })
        .await;
    t.client.lock().unwrap().keepalive().expect("keepalive");
    t.settle().await;

    eprintln!("trace:\n  {}", t.trace());
    assert!(finished, "test timed out");
    assert_eq!(t.failed_reads, 0);
    let status = t.status();
    assert_eq!(
        (status.state, status.plpmtu),
        (PmtudState::SearchComplete, Some(1330))
    );
    assert!(t.link.fits(1330) && !t.link.fits(1338));
}

/// A probe whose write blocks is still pending in the TLS library when DF
/// is cleared again. It must not be sent by a later write: it is lost, and
/// the probe timer sends that size again with DF set.
#[tokio::test]
async fn pmtud_probe_blocked_is_not_sent_later() {
    // Datagram size: blocks the first search probe (1282), not the base
    // probe (1250).
    let mut t = PmtudLinkTest::start(PmtudLinkFaults {
        block_once_from: Some(1300),
        ..Default::default()
    });

    let mut ticked = false;
    let finished = t
        .run_until(|c, link| {
            if !ticked && link.count(PmtudLinkOutcome::Blocked) > 0 {
                ticked = true;
                // An ordinary write follows, then the probe times out.
                let r = c.keepalive();
                link.trace(format!("keepalive after block -> {r:?}"));
                let r = c.pmtud_tick();
                link.trace(format!("pmtud_tick -> {r:?}"));
            }
            let status = c.pmtud_status().expect("PMTUD enabled");
            status.state == PmtudState::SearchComplete
        })
        .await;

    eprintln!("trace:\n  {}", t.trace());
    assert!(finished, "test timed out");
    assert_eq!(t.failed_reads, 0);

    let sends = t.link.sends();
    let blocked = sends
        .iter()
        .position(|s| s.outcome == PmtudLinkOutcome::Blocked)
        .expect("a probe was blocked");
    let probe_len = t.link.probe_len(1282);
    assert_eq!(sends[blocked].len, probe_len);
    assert_eq!(
        t.link.leaked_probes().len(),
        0,
        "a blocked probe was later sent without DF: {sends:?}"
    );
    // The keepalive was not held up behind the probe, and the retry
    // carried DF.
    let later: Vec<_> = sends[blocked + 1..]
        .iter()
        .take(2)
        .map(|s| (s.len < 1250, s.len == probe_len, s.df, s.outcome))
        .collect();
    assert_eq!(
        later,
        [
            (true, false, false, PmtudLinkOutcome::Sent),
            (false, true, true, PmtudLinkOutcome::Sent)
        ],
        "{sends:?}"
    );
    // The search went on from there.
    let status = t.status();
    assert_eq!(
        (status.state, status.plpmtu),
        (PmtudState::SearchComplete, Some(1330))
    );
}

/// A probe is not started while an earlier write is still blocked: that
/// write would go out first, with DF set, and a refusal of it would be
/// blamed on the probe. The probe goes out on the next tick instead.
#[tokio::test]
async fn pmtud_probe_waits_for_an_earlier_blocked_write() {
    use std::sync::atomic::Ordering;

    let mut t = PmtudLinkTest::start(PmtudLinkFaults::default());
    let mut blocked = false;
    let finished = t
        .run_until(|c, link| {
            let status = c.pmtud_status().expect("PMTUD enabled");
            if !blocked && status.state == PmtudState::Searching {
                blocked = true;
                // The keepalive blocks, and so does its retry before the
                // probe: it is still queued when the probe is due.
                link.block_plain.store(2, Ordering::SeqCst);
                let r = c.keepalive();
                link.trace(format!("keepalive (blocked) -> {r:?}"));
                let r = c.pmtud_tick();
                link.trace(format!("pmtud_tick -> {r:?}"));
                let r = c.pmtud_tick();
                link.trace(format!("pmtud_tick -> {r:?}"));
            }
            status.state == PmtudState::SearchComplete
        })
        .await;

    eprintln!("trace:\n  {}", t.trace());
    assert!(finished, "test timed out");
    assert_eq!(t.failed_reads, 0);
    let sends = t.link.sends();
    let small_df: Vec<_> = sends.iter().filter(|s| s.df && s.len < 1250).collect();
    assert!(
        small_df.is_empty(),
        "ordinary datagrams sent with DF: {small_df:?}"
    );
    // The probe went out again, with DF, once the keepalive had.
    let probe_len = t.link.probe_len(1282);
    assert!(
        sends.iter().filter(|s| s.df && s.len == probe_len).count() >= 2,
        "{sends:?}"
    );
}

/// A probe the socket could not take never reached the path, so it is not
/// counted as lost: a busy socket when the confirm probes are due does not
/// look like a black hole.
#[tokio::test]
async fn pmtud_probe_not_sent_is_not_counted() {
    use std::sync::atomic::Ordering;

    let mut t = PmtudLinkTest::start(PmtudLinkFaults::default());
    let finished = t
        .run_until(|c, _| {
            c.pmtud_status()
                .is_some_and(|s| s.state == PmtudState::SearchComplete)
        })
        .await;
    assert!(finished, "test timed out");
    let converged = t.status();
    assert_eq!(converged.plpmtu, Some(1330));

    // The raise timer fires (a confirm probe), then more probe timeouts
    // than MAX_PROBES, every probe finding the socket not writable.
    t.link.block_df.store(true, Ordering::SeqCst);
    for _ in 0..5 {
        let r = t.client.lock().unwrap().pmtud_tick();
        t.link.trace(format!("pmtud_tick -> {r:?}"));
    }

    eprintln!("trace:\n  {}", t.trace());
    assert!(t.link.count(PmtudLinkOutcome::Blocked) >= 5);
    assert_eq!(t.status(), converged);
}

/// A change of outside path restarts PMTUD: the estimate learned on the old
/// path is dropped, a fresh base probe goes out at once and the search runs
/// to completion again. `set_outside_io` does the same, probing through the
/// new outside I/O.
#[tokio::test]
async fn pmtud_restarts_when_outside_path_changes() {
    /// PMTUD events and outside sends (tagged with the socket that carried
    /// them) in the order the connection produced them.
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum Entry {
        Pmtud(PmtudStatus),
        Send { sock: u8, len: usize },
    }
    type Log = Arc<Mutex<Vec<Entry>>>;

    struct RecordingSock {
        inner: Arc<TestDatagramSock>,
        id: u8,
        log: Log,
    }

    impl OutsideIOSendCallback for RecordingSock {
        fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
            let entry = Entry::Send {
                sock: self.id,
                len: buf.len(),
            };
            self.log.lock().unwrap().push(entry);
            self.inner.send(buf)
        }

        fn send_gso(
            &self,
            bufs: &[std::io::IoSlice<'_>],
            gso_size: u16,
        ) -> IOCallbackResult<usize> {
            self.inner.send_gso(bufs, gso_size)
        }

        fn peer_addr(&self) -> std::net::SocketAddr {
            self.inner.peer_addr()
        }

        // Unix datagram sockets have no DF bit; accept the probe bracket.
        fn enable_pmtud_probe(&self) -> std::io::Result<()> {
            Ok(())
        }

        fn disable_pmtud_probe(&self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct RecordingEvents {
        inner: EventStreamCallback,
        log: Log,
    }

    impl EventCallback for RecordingEvents {
        fn event(&mut self, event: Event) {
            if let Event::PmtudStateChanged(status) = &event {
                self.log.lock().unwrap().push(Entry::Pmtud(*status));
            }
            self.inner.event(event);
        }
    }

    // Take the shared test PKI before the timeout window (RSA keygen is very
    // slow on QEMU, and only happens on first use).
    let pki = TestPki::get_valid(2, RsaKeySize::_2048);

    let (client_sock, server_sock) = UnixDatagram::pair().expect("UnixDatagram");
    let server_sock = Arc::new(TestDatagramSock(server_sock));
    let client_sock = Arc::new(TestDatagramSock(client_sock));

    let (auth, _last_method) = TestAuth::new();
    let pqc = PQCrypto {
        server_pqc: false,
        keyshare: None,
    };

    // The server answers every probe Ping with a Pong.
    let (cert, key) = pki.server_secrets();
    let mut server_task = tokio::spawn(server(
        server_sock,
        TestServerConfig {
            auth,
            pqc,
            expresslane: None,
            conn_out: None,
            metrics: None,
            expresslane_cb: None,
            cert,
            key,
        },
    ));

    let log: Log = Default::default();
    let recording_sock = |id| -> OutsideIOSendCallbackArg {
        Arc::new(RecordingSock {
            inner: client_sock.clone(),
            id,
            log: log.clone(),
        })
    };
    let ca_cert = pki.root_ca();
    let (tun, _inside_rx) = ChannelTun::new();
    let (event_cb, mut event_stream) = EventStreamCallback::new();
    let (ticker, ticker_task) = ConnectionTicker::new();
    let (pmtud_timer, pmtud_timer_task) = lightway_app_utils::DplpmtudTimer::new();
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
    .start_connect(recording_sock(0), MAX_OUTSIDE_MTU)
    .unwrap()
    .with_auth_token("LET ME IN")
    .with_event_cb(Box::new(RecordingEvents {
        inner: event_cb,
        log: log.clone(),
    }))
    .with_pmtud_timer(pmtud_timer)
    .connect(state)
    .unwrap();
    let client = Arc::new(Mutex::new(client));

    let mut join_set = JoinSet::new();
    ticker_task.spawn_in(Arc::downgrade(&client), &mut join_set);
    pmtud_timer_task.spawn(Arc::downgrade(&client), &mut join_set);

    // Drain events so the stream never backpressures the connection.
    tokio::spawn(async move { while event_stream.next().await.is_some() {} });

    // Pump the client until the search converges. Nothing is lost on the
    // socket pair, so no probe timer ever fires and every probe is confirmed.
    let search_complete = || async {
        loop {
            client_sock
                .readable()
                .await
                .expect("client socket readable");
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
            if c.pmtud_status()
                .is_some_and(|s| s.state == PmtudState::SearchComplete)
            {
                return;
            }
        }
    };

    // The PMTUD states reported from log entry `from` onwards.
    let states_since = |from: usize| -> Vec<PmtudState> {
        let log = log.lock().unwrap();
        log[from..]
            .iter()
            .filter_map(|e| match e {
                Entry::Pmtud(s) => Some(s.state),
                _ => None,
            })
            .collect()
    };

    let run = async {
        // Before the connection is online a path change starts nothing.
        client.lock().unwrap().pmtud_path_changed().unwrap();
        assert!(states_since(0).is_empty());
        assert_eq!(
            client.lock().unwrap().pmtud_status().map(|s| s.state),
            Some(PmtudState::Disabled)
        );

        search_complete().await;

        // What a search from scratch looks like on this path.
        let first_search = states_since(0);
        assert_eq!(first_search.first(), Some(&PmtudState::Base));
        assert_eq!(first_search.last(), Some(&PmtudState::SearchComplete));
        let converged = client.lock().unwrap().pmtud_status();
        let base_probe_len = {
            let log = log.lock().unwrap();
            let base = log
                .iter()
                .position(|e| matches!(e, Entry::Pmtud(s) if s.state == PmtudState::Base))
                .expect("Base was reported");
            match log[base + 1] {
                Entry::Send { len, .. } => len,
                other => panic!("expected the base probe, found {other:?}"),
            }
        };
        // A datagram carrying the 1250 byte base PLPMTU.
        assert!(
            (1250..1300).contains(&base_probe_len),
            "base probe was {base_probe_len} bytes"
        );

        // Same outside I/O, new path: back to Base with a fresh base probe.
        let mark = log.lock().unwrap().len();
        client.lock().unwrap().pmtud_path_changed().unwrap();
        {
            let log = log.lock().unwrap();
            assert!(
                matches!(
                    log[mark..],
                    [Entry::Pmtud(s), Entry::Send { sock: 0, len }]
                        if s.state == PmtudState::Base && len == base_probe_len
                ),
                "after path change: {:?}",
                &log[mark..]
            );
        }
        assert_eq!(
            client.lock().unwrap().pmtud_status().map(|s| s.state),
            Some(PmtudState::Base)
        );

        search_complete().await;
        assert_eq!(states_since(mark), first_search);
        assert_eq!(client.lock().unwrap().pmtud_status(), converged);

        // New outside I/O: the same restart, probing through the new one.
        let mark = log.lock().unwrap().len();
        client.lock().unwrap().set_outside_io(recording_sock(1));
        {
            let log = log.lock().unwrap();
            assert!(
                matches!(
                    log[mark..],
                    [Entry::Pmtud(s), Entry::Send { sock: 1, len }]
                        if s.state == PmtudState::Base && len == base_probe_len
                ),
                "after outside I/O change: {:?}",
                &log[mark..]
            );
        }

        search_complete().await;
        assert_eq!(states_since(mark), first_search);
        assert_eq!(client.lock().unwrap().pmtud_status(), converged);
    };

    tokio::time::timeout(
        std::time::Duration::from_millis(get_test_timeout()),
        async {
            tokio::select! {
                _ = run => {}
                r = &mut server_task => panic!("server task ended early: {r:?}"),
            }
        },
    )
    .await
    .expect("test timed out");
}
