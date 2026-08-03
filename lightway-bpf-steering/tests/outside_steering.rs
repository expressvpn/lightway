//! Proves the outside split with synthetic datagrams. No VPN involved.
//!
//! Every assertion is on the kernel's own counters as well as on what each
//! socket read, so a test cannot pass because delivery happened to land right.
//! `counts()[2]` is the kernel refusing the program's choice, which would
//! leave the split silently inactive - so every test checks it stayed zero.
#![cfg(target_os = "linux")]

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use lightway_bpf_steering::{OutsideSplit, is_expresslane_datagram};

#[macro_use]
mod common;

fn lightway_datagram(expresslane: bool, tag: u8) -> Vec<u8> {
    let mut d = vec![0u8; 20];
    d[0] = b'H';
    d[1] = b'e';
    d[2] = 1;
    d[3] = 3;
    d[5] = expresslane as u8;
    d[16] = tag;
    d
}

/// Send `d`, checking first that Task 1's Rust classifier calls it the way
/// this test expects the kernel to route it.
///
/// `is_expresslane_datagram` and `outside.bpf.c` hardcode the same offsets in
/// two languages with nothing linking them. Asserting both at each send is
/// what makes a divergence show up here, as a failing test, rather than in a
/// tunnel that mysteriously stops offloading.
fn send(tx: &UdpSocket, dst: SocketAddr, d: &[u8], expect_engine: bool) {
    assert_eq!(
        is_expresslane_datagram(d),
        expect_engine,
        "the Rust classifier and this test disagree about where the kernel sends {d:02x?}"
    );
    tx.send_to(d, dst).unwrap();
}

#[test]
fn expresslane_goes_to_the_engine_and_dtls_to_the_control_plane() {
    let split = skip_unless_privileged!(OutsideSplit::bind(SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        0
    ))));
    let dst = split.local_addr().unwrap();

    let timeout = Some(Duration::from_millis(500));
    split.control.set_read_timeout(timeout).unwrap();
    split.engine.set_read_timeout(timeout).unwrap();

    let tx = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    send(&tx, dst, &lightway_datagram(true, 0xE1), true);
    send(&tx, dst, &lightway_datagram(false, 0xD7), false);

    let mut buf = [0u8; 64];
    let n = split.engine.recv(&mut buf).expect("engine got no packet");
    assert_eq!(buf[16], 0xE1, "engine received the wrong datagram");
    assert_eq!(n, 20);

    let n = split.control.recv(&mut buf).expect("control got no packet");
    assert_eq!(buf[16], 0xD7, "control received the wrong datagram");
    assert_eq!(n, 20);

    assert_eq!(
        split.counts().unwrap(),
        [1, 1, 0],
        "kernel counters disagree"
    );
}

#[test]
fn a_non_lightway_datagram_goes_to_the_control_plane() {
    let split = skip_unless_privileged!(OutsideSplit::bind(SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        0
    ))));
    let dst = split.local_addr().unwrap();
    split
        .control
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    let tx = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    send(&tx, dst, &[0xFFu8; 32], false);

    let mut buf = [0u8; 64];
    split.control.recv(&mut buf).expect("control got no packet");
    assert_eq!(split.counts().unwrap(), [1, 0, 0]);
}

/// A datagram too short to hold the flag must not be classified as
/// ExpressLane - the BPF bounds check is what stops it reading past data_end.
#[test]
fn a_truncated_datagram_goes_to_the_control_plane() {
    let split = skip_unless_privileged!(OutsideSplit::bind(SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        0
    ))));
    let dst = split.local_addr().unwrap();
    split
        .control
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    let tx = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    send(&tx, dst, b"He", false);

    let mut buf = [0u8; 64];
    split.control.recv(&mut buf).expect("control got no packet");
    assert_eq!(split.counts().unwrap(), [1, 0, 0]);
}

/// Both sockets must answer on one address, or the engine's replies would
/// carry a different source port and the peer would read them as a roam.
#[test]
fn both_sockets_share_one_address() {
    let split = skip_unless_privileged!(OutsideSplit::bind(SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        0
    ))));
    let addr = split.local_addr().unwrap();
    assert_eq!(split.control.local_addr().unwrap(), addr);
    assert_eq!(split.engine.local_addr().unwrap(), addr);
    assert_ne!(addr.port(), 0, "kernel assigned no port");
    assert_eq!(
        split.counts().unwrap(),
        [0, 0, 0],
        "nothing was sent, so the kernel should have steered nothing"
    );
}
