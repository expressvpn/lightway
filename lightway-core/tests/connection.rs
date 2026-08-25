use bytes::BytesMut;
use lightway_app_utils::{
    ConnectionTicker, EventStreamCallback, PacketCodecFactory, connection_ticker_cb,
};
use lightway_core::*;
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
use crate::common::{certgen::gen_shared_testing_pki, packet_codec::BlackHolePacketCodecFactory};
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

    // Generate the shared test PKI before the timeout window.
    // RSA keygen is very slow on QEMU. (especially on RISCV).
    gen_shared_testing_pki();

    let test = async move {
        tokio::join!(
            server(
                server_sock,
                auth,
                pqc,
                enable_expresslane.then_some(DEFAULT_EXPRESSLANE_KEYS_ROTATION_INTERVAL),
                None,
                None,
            ),
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
    let mut server_task = tokio::spawn(server(server_sock, auth, pqc, None, None, None));

    let ca_cert = RootCertificate::Asn1Buffer(&gen_shared_testing_pki().ca_cert_der);
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
#[test_case(Some(common::certgen::TEST_SERVER_DOMAIN); "Valid server domain name")]
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

    // Generate the shared test PKI *before the timed window* to prevent flaky tests. (see run_test).
    gen_shared_testing_pki();

    let test = async move {
        tokio::join!(
            server(server_sock, auth, pqc, None, None, None),
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

    let ca_cert = RootCertificate::Asn1Buffer(&gen_shared_testing_pki().ca_cert_der);
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
    let server_task = server(
        server_sock,
        auth,
        PQCrypto {
            server_pqc: false,
            keyshare: None,
        },
        Some(INTERVAL),
        Some(conn_tx),
        None,
    );

    let client_task = async move {
        // The server sends this before any handshake traffic, so this
        // cannot deadlock.
        let server_conn = conn_rx.await.expect("server conn handle");

        let ca_cert = RootCertificate::Asn1Buffer(&gen_shared_testing_pki().ca_cert_der);
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

/// Drives a client/server pair through repeated keepalive windows and
/// reports how the client's expresslane health check reacted: the final
/// state, which window (if any) first saw it go Degraded, and how many
/// probe packets came back reflected (proof traffic actually flowed).
async fn expresslane_health_probe(
    client_metrics: Option<Arc<dyn ExpresslaneMetrics + Send + Sync>>,
    server_metrics: Option<ExpresslaneMetricsType>,
) -> (ExpresslaneState, Option<usize>, usize) {
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
    let server_task = server(
        server_sock,
        auth,
        pqc,
        Some(DEFAULT_EXPRESSLANE_KEYS_ROTATION_INTERVAL),
        None,
        server_metrics,
    );

    let client_task = async move {
        let ca_cert = RootCertificate::Asn1Buffer(&gen_shared_testing_pki().ca_cert_der);
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

        conn.lock().unwrap().disconnect().unwrap();
        (el_state, degraded_at, reflected)
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
    let (state, _degraded_at, reflected) =
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
    let (state, degraded_at, reflected) =
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
    let (state, degraded_at, reflected) =
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
