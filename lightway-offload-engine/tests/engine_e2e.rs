//! Drives the engine the way the VPN process will: hand it descriptors, push
//! keys, then prove a packet crosses. Needs CAP_BPF + CAP_NET_ADMIN.
#![cfg(target_os = "linux")]

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use lightway_bpf_steering::{InsideSplit, OutsideSplit};
use lightway_expresslane::{EXPRESSLANE_KEY_SIZE, ExpresslaneKey};
use lightway_offload_engine::control::{EXPECTED_FDS, run_engine};
use lightway_offload_engine::engine::Engine;
use lightway_offload_engine::fdpass::{recv_with_fds, send_with_fds};
use lightway_offload_engine::ipc::ControlMsg;

/// The privilege gate, byte-for-byte the one `lightway-bpf-steering`'s tests
/// use. These tests need the same capabilities for the same reason, and two
/// gates that read `LW_BPF_REQUIRE_PRIVILEGED` differently would mean a CI job
/// could be vacuous in one crate and loud in the other.
#[macro_use]
mod common;

const SID: [u8; 8] = [0xA5; 8];
const LW_VERSION: [u8; 2] = [1, 3];

fn push_keys(engine: &Engine, key: ExpresslaneKey) {
    engine.apply(&ControlMsg::PushKeys {
        session_id: SID,
        version: 2,
        lightway_version: LW_VERSION,
        self_key: key,
        peer_key: key,
    });
}

#[test]
fn the_engine_decrypts_a_datagram_the_kernel_steered_to_it() {
    let split = skip_unless_privileged!(OutsideSplit::bind(SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        0
    ))));
    let dst = split.local_addr().unwrap();
    split
        .engine
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    // The peer side: an engine that encrypts.
    let key = ExpresslaneKey([0x33; EXPRESSLANE_KEY_SIZE]);
    let peer = Engine::new();
    push_keys(&peer, key);
    let local = Engine::new();
    push_keys(&local, key);

    let datagram = peer
        .encrypt(SID, b"steered inside packet", [9; 12])
        .unwrap();

    let tx = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    tx.send_to(&datagram, dst).unwrap();

    // The kernel must have routed it to the engine socket, not the control one.
    let mut buf = [0u8; 2048];
    let n = split
        .engine
        .recv(&mut buf)
        .expect("kernel did not steer the datagram to the engine socket");

    let mut received = bytes::BytesMut::from(&buf[..n]);
    let inside = local
        .decrypt(&mut received)
        .expect("engine could not decrypt");
    assert_eq!(&inside[..], b"steered inside packet");

    let counts = split.counts().unwrap();
    assert_eq!(counts, [0, 1, 0], "kernel counters disagree");

    // What the kernel steered here has to reconcile against what the engine
    // says it did: the engine-socket count is accounted for by exactly one
    // accepted packet and nothing refused.
    let Some(ControlMsg::StatsReply {
        received, refused, ..
    }) = local.apply(&ControlMsg::StatsRequest { session_id: SID })
    else {
        panic!("expected StatsReply")
    };
    assert_eq!(
        received + refused,
        counts[1],
        "the engine cannot account for what the kernel steered to it"
    );
    assert_eq!(refused, 0);
}

/// The attach sequence against the loop that will really run it, with the real
/// TUN queue and UDP socket crossing - not a socket pair talking to a decoder.
///
/// What this proves that the unit tests do not: descriptors of the two kinds
/// the kernel actually steers to survive the crossing into a running
/// `run_engine`, and keys pushed afterwards over the same socket reach the
/// engine behind it - answered by the engine itself, not by the test.
#[test]
fn real_descriptors_and_keys_cross_into_a_running_engine() {
    let inside = skip_unless_privileged!(InsideSplit::create("lwoffl0"));
    let outside = skip_unless_privileged!(OutsideSplit::bind(SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        0
    ))));

    let (parent, child) = UnixStream::pair().unwrap();

    // The engine side, exactly as the binary runs it: one shared engine, the
    // descriptors leaving through the attach callback.
    let (delivered_tx, delivered_rx) = std::sync::mpsc::channel();
    let engine_side = std::thread::spawn(move || {
        let engine = Engine::new();
        run_engine(&child, &engine, |fds| delivered_tx.send(fds).unwrap())
    });

    // Exactly what the VPN process will do at attach time.
    let mut payload = Vec::new();
    ControlMsg::Attach.encode(&mut payload);
    send_with_fds(
        &parent,
        &payload,
        &[inside.engine_queue.as_raw_fd(), outside.engine.as_raw_fd()],
    )
    .unwrap();

    // The descriptors reach the callback, which is where a packet loop would
    // take them - not an out-parameter the control loop keeps borrowed.
    let handed_over = delivered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the attach callback never fired");
    assert_eq!(
        handed_over.len(),
        EXPECTED_FDS,
        "both descriptors must cross"
    );

    // Keys follow over the same channel, with no packet ever crossing it.
    let mut payload = Vec::new();
    ControlMsg::PushKeys {
        session_id: SID,
        version: 2,
        lightway_version: LW_VERSION,
        self_key: ExpresslaneKey([1; EXPRESSLANE_KEY_SIZE]),
        peer_key: ExpresslaneKey([2; EXPRESSLANE_KEY_SIZE]),
    }
    .encode(&mut payload);
    ControlMsg::StatsRequest { session_id: SID }.encode(&mut payload);
    send_with_fds(&parent, &payload, &[]).unwrap();

    // The engine's own answer is the evidence the keys landed: an engine that
    // never got them reports no session.
    let mut buf = [0u8; 256];
    let mut fds = Vec::new();
    let n = recv_with_fds(&parent, &mut buf, &mut fds).unwrap();
    assert!(fds.is_empty(), "a reply must never carry descriptors");
    let (reply, _) = ControlMsg::decode(&buf[..n]).unwrap();
    let ControlMsg::StatsReply {
        session_id,
        known_session,
        ..
    } = reply
    else {
        panic!("expected StatsReply, got {reply:?}")
    };
    assert_eq!(
        session_id, SID,
        "the reply must name the session asked about"
    );
    assert!(known_session, "the keys never reached the engine");

    // Flipping the steering flag has to keep working on a device whose engine
    // queue now belongs to someone else as well. (What the flag does to inside
    // traffic is lightway-bpf-steering's own test to make; nothing here sends
    // an inside packet, so nothing here may claim it.)
    inside.set_offload_active(true).unwrap();

    parent.shutdown(std::net::Shutdown::Write).unwrap();
    engine_side
        .join()
        .unwrap()
        .expect("a closed parent is the fallback signal, not an error");

    // Still the descriptors the kernel steers to, after the loop that passed
    // them has exited: the callback owns them, so they outlive it.
    drop(handed_over);
}
