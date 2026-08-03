//! A packet crosses the engine in both directions, over a real TUN queue and a
//! real UDP socket. Needs CAP_BPF + CAP_NET_ADMIN.
//!
//! Both directions go through the kernel, because that is the only way either
//! one is real:
//!
//! ```text
//!   TX  UdpSocket::send_to(10.9.10.2)  -> routed at the TUN -> lw_steer picks
//!       the engine queue -> the TX loop reads it, encrypts, sends to the peer
//!   RX  peer sends an encrypted datagram -> the RX loop decrypts and writes
//!       the inside packet into the TUN -> the kernel delivers it locally
//! ```
//!
//! Writing into a queue fd is *ingress*, not egress, so a test that wrote a
//! packet in and expected to read it back out of the same queue would be
//! testing nothing at all: the steering program never runs on that path and the
//! kernel never hands the bytes back. The traffic therefore originates from an
//! ordinary socket, and the decrypted packet is checked where the kernel
//! delivers it.
#![cfg(target_os = "linux")]

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lightway_bpf_steering::InsideSplit;
use lightway_expresslane::{EXPRESSLANE_KEY_SIZE, ExpresslaneKey};
use lightway_offload_engine::engine::Engine;
use lightway_offload_engine::ipc::ControlMsg;
use lightway_offload_engine::packet::PacketLoops;

/// The privilege gate the other integration tests use.
#[macro_use]
mod common;

const DEVICE: &str = "lwloop0";
/// The device's own address, and the inside peer beyond it. A different /24
/// from `lightway-bpf-steering`'s tests, which may be running at the same time.
const HOST: Ipv4Addr = Ipv4Addr::new(10, 9, 10, 1);
const INSIDE_PEER: Ipv4Addr = Ipv4Addr::new(10, 9, 10, 2);
const HOST_PORT: u16 = 3333;
const PEER_PORT: u16 = 4444;

const SID: [u8; 8] = [0x5A; 8];
const TX_PAYLOAD: &[u8] = b"out through the tunnel";
const RX_PAYLOAD: &[u8] = b"back from the server";

/// Long enough that a slow scheduler is not mistaken for a lost packet.
const ARRIVE: Duration = Duration::from_secs(5);
/// How long one receive parks before the deadline is re-checked.
const SLICE: Duration = Duration::from_millis(200);

fn ip(args: &[&str]) {
    let status = Command::new("ip")
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("ip {args:?}: {e}"));
    assert!(status.success(), "ip {args:?} failed: {status}");
}

/// Give the device its address, and with it the route that puts the test's
/// datagram on this interface.
///
/// IPv6 is silenced first: autoconfiguration puts router solicitations and MLD
/// reports out a device the moment it comes up, and every one of them would be
/// steered to the engine queue and encrypted like real traffic.
fn bring_up() {
    let _ = std::fs::write(
        format!("/proc/sys/net/ipv6/conf/{DEVICE}/disable_ipv6"),
        b"1\n",
    );
    // Up first: the prefix route is installed only for a device already IFF_UP.
    ip(&["link", "set", DEVICE, "up"]);
    ip(&["addr", "add", "10.9.10.1/24", "dev", DEVICE]);
}

fn keyed(engine: &Engine, peer: SocketAddr) {
    let k = ExpresslaneKey([0x21; EXPRESSLANE_KEY_SIZE]);
    engine.apply(&ControlMsg::PushKeys {
        session_id: SID,
        version: 2,
        lightway_version: [1, 3],
        self_key: k,
        peer_key: k,
        peer,
    });
}

/// The one's-complement sum the IPv4 header carries. A packet with the wrong
/// one is dropped before it reaches a socket, which would read exactly like a
/// loop that never wrote it.
fn checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for pair in header.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// A complete IPv4/UDP packet, as the inside of the tunnel carries it.
///
/// The UDP checksum is left zero, which IPv4 defines as "not computed".
fn ipv4_udp(src: (Ipv4Addr, u16), dst: (Ipv4Addr, u16), payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total = 20 + udp_len;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    pkt[8] = 64; // ttl
    pkt[9] = 17; // udp
    pkt[12..16].copy_from_slice(&src.0.octets());
    pkt[16..20].copy_from_slice(&dst.0.octets());
    let ip_csum = checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    pkt[20..22].copy_from_slice(&src.1.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst.1.to_be_bytes());
    pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    pkt
}

fn tx_dropped(engine: &Engine) -> u64 {
    let Some(ControlMsg::StatsReply { tx_dropped, .. }) =
        engine.apply(&ControlMsg::StatsRequest { session_id: SID })
    else {
        panic!("expected a StatsReply")
    };
    tx_dropped
}

fn sent(engine: &Engine) -> u64 {
    let Some(ControlMsg::StatsReply { sent, .. }) =
        engine.apply(&ControlMsg::StatsRequest { session_id: SID })
    else {
        panic!("expected a StatsReply")
    };
    sent
}

/// Is this the inside packet `TX_PAYLOAD` produced, rather than one of the
/// host's own strays?
fn is_our_inside_packet(pkt: &[u8]) -> bool {
    pkt.len() == 28 + TX_PAYLOAD.len()
        && pkt[0] >> 4 == 4
        && pkt[9] == 17
        && pkt[16..20] == INSIDE_PEER.octets()
        && u16::from_be_bytes([pkt[22], pkt[23]]) == PEER_PORT
        && &pkt[28..] == TX_PAYLOAD
}

/// An inside packet the kernel routes at the TUN comes out of the engine's
/// socket encrypted, and a datagram sent back to that socket is decrypted and
/// delivered inside.
#[test]
fn a_packet_crosses_the_engine_both_ways() {
    let split = skip_unless_privileged!(InsideSplit::create(DEVICE));
    bring_up();
    // Without this the steering program keeps the inside path on queue 0 and
    // the engine queue stays empty however much is sent.
    split.set_offload_active(true).unwrap();

    // The engine's socket, and a stand-in for the server on the other end.
    let engine_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let engine_addr = engine_sock.local_addr().unwrap();
    let peer_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    peer_sock.set_read_timeout(Some(SLICE)).unwrap();
    let peer_addr = peer_sock.local_addr().unwrap();

    // Two engines with the same key: one under test, one standing in for the
    // server, so what crosses the wire is checked by decrypting it rather than
    // by trusting the sender.
    let engine = Arc::new(Engine::new());
    keyed(&engine, peer_addr);
    let server = Engine::new();
    keyed(&server, engine_addr);

    // The socket on the inside of the tunnel: it sends the packet the TX loop
    // must carry, and receives the one the RX loop must deliver.
    let inside = UdpSocket::bind(SocketAddrV4::new(HOST, HOST_PORT)).unwrap();
    inside.set_read_timeout(Some(SLICE)).unwrap();

    let loops = PacketLoops::spawn(
        engine.clone(),
        split.clone_engine_queue().unwrap(),
        engine_sock.try_clone().unwrap(),
    )
    .unwrap();

    // Keys but no `SetActive`: an engine that has not been told to carry
    // traffic must not encrypt any, however much the kernel steers at it. The
    // packet has to be accounted for rather than merely absent.
    inside
        .send_to(b"while stood down", (INSIDE_PEER, PEER_PORT))
        .expect("no route out the tun");
    std::thread::sleep(SLICE);
    let mut buf = [0u8; 4096];
    assert!(
        matches!(peer_sock.recv(&mut buf), Err(e) if e.kind() == io::ErrorKind::WouldBlock),
        "a stood-down engine put a packet on the wire"
    );
    assert!(
        tx_dropped(&engine) > 0,
        "the packet was dropped without being counted"
    );

    engine.apply(&ControlMsg::SetActive { active: true });

    // TX: the kernel routes this at the TUN, so it reaches the engine queue.
    inside
        .send_to(TX_PAYLOAD, (INSIDE_PEER, PEER_PORT))
        .expect("no route out the tun");

    // The device is not private - the host's own daemons put mDNS and IGMP out
    // of it - so look for our packet among whatever else was steered.
    let deadline = Instant::now() + ARRIVE;
    let mut seen = 0usize;
    loop {
        assert!(
            Instant::now() < deadline,
            "the inside packet never reached the peer encrypted ({seen} datagrams seen)"
        );
        let n = match peer_sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => panic!("receiving on the peer socket: {e}"),
        };
        seen += 1;
        let datagram = &buf[..n];
        assert_eq!(&datagram[..2], b"He", "not a Lightway datagram");
        assert_eq!(datagram[5], 1, "expresslane flag not set");

        let mut owned = bytes::BytesMut::from(datagram);
        let Some(inner) = server.decrypt(&mut owned) else {
            continue; // a stray the host put out the device
        };
        if !is_our_inside_packet(&inner) {
            continue;
        }
        assert!(
            !datagram.windows(inner.len()).any(|w| w == &inner[..]),
            "the inside packet crossed in the clear"
        );
        break;
    }

    // Only the loop pairs the send with the counting, and it counts after the
    // socket has taken the datagram: a `sent` that stayed at zero here means
    // nothing charges the session for traffic the peer really received, and
    // lightway-core degrades on that comparison.
    assert!(
        sent(&engine) > 0,
        "a datagram that reached the peer was never counted as sent"
    );

    // RX: an encrypted datagram addressed to the engine's socket must surface
    // inside, decrypted, where the kernel delivers it.
    let reply = ipv4_udp((INSIDE_PEER, PEER_PORT), (HOST, HOST_PORT), RX_PAYLOAD);
    let datagram = server.encrypt(SID, &reply, [7; 12]).expect("encrypt");
    peer_sock.send_to(&datagram, engine_addr).unwrap();

    let deadline = Instant::now() + ARRIVE;
    let (n, from) = loop {
        assert!(
            Instant::now() < deadline,
            "nothing was delivered on the inside of the tunnel"
        );
        match inside.recv_from(&mut buf) {
            Ok(v) => break v,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => panic!("receiving inside the tunnel: {e}"),
        }
    };
    assert_eq!(&buf[..n], RX_PAYLOAD);
    assert_eq!(from, SocketAddr::from((INSIDE_PEER, PEER_PORT)));

    // And it returns: both loops are parked in `poll` at this point.
    loops.shutdown();
}
