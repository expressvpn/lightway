//! The gate that makes a silent fallback loud. Needs CAP_BPF + CAP_NET_ADMIN.
//!
//! Both tests exist to pin the gate against the two ways it could be useless.
//! A gate that always says "offloaded" cannot catch the fallback it was built
//! for; a gate that never says it turns every run red and gets switched off.
//! One test fails on each mutation.
#![cfg(target_os = "linux")]

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use lightway_bpf_steering::{
    EXPRESSLANE_FLAG_OFFSET, HEADER_LEN, InsideSplit, MAGIC, OutsideSplit, is_expresslane_datagram,
};
use lightway_offload_engine::gate::{self, ArmingLog};

/// The privilege gate the rest of this crate's integration tests share.
#[macro_use]
mod common;

/// A datagram the outside splitter must classify as ExpressLane, built from
/// the crate's own constants rather than hand-numbered bytes.
fn expresslane_datagram() -> Vec<u8> {
    let mut d = vec![0u8; HEADER_LEN];
    d[..MAGIC.len()].copy_from_slice(&MAGIC);
    d[EXPRESSLANE_FLAG_OFFSET] = 1;
    assert!(is_expresslane_datagram(&d));
    d
}

/// With no traffic offloaded, the gate must report failure - otherwise it
/// could never catch a silent fallback, which is the only reason it exists.
#[test]
fn the_gate_fails_when_nothing_was_offloaded() {
    let inside = skip_unless_privileged!(InsideSplit::create("lwgate0"));
    let outside = skip_unless_privileged!(OutsideSplit::bind(SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        0
    ))));

    let verdict = gate::verdict(&inside, &outside, &ArmingLog::default());
    assert!(
        !verdict.offloaded(),
        "gate claims offload with zero steered packets: {verdict:?}"
    );
    assert_eq!(verdict.inside_engine, 0);
    assert_eq!(verdict.outside_engine, 0);
}

/// A datagram the kernel actually steered must flip the verdict, so the gate
/// is not simply always-false.
#[test]
fn the_gate_passes_once_the_kernel_steers_something() {
    let inside = skip_unless_privileged!(InsideSplit::create("lwgate1"));
    let outside = skip_unless_privileged!(OutsideSplit::bind(SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        0
    ))));
    let dst = outside.local_addr().unwrap();

    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .send_to(&expresslane_datagram(), dst)
        .unwrap();

    let mut buf = [0u8; 64];
    outside
        .engine
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    outside.engine.recv(&mut buf).expect("kernel did not steer");

    let verdict = gate::verdict(&inside, &outside, &ArmingLog::default());
    assert_eq!(verdict.outside_engine, 1);
    assert_eq!(
        verdict.outside_failed, 0,
        "reuseport selection fell back to the kernel hash"
    );
    assert!(
        verdict.offloaded(),
        "gate did not notice a steered datagram: {verdict:?}"
    );
}
