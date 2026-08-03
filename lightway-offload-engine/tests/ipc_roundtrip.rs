//! The codec and descriptor passing, exercised over a real socketpair.
#![cfg(target_os = "linux")]

use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

use lightway_expresslane::{EXPRESSLANE_KEY_SIZE, ExpresslaneKey};
use lightway_offload_engine::fdpass::{recv_with_fds, send_with_fds};
use lightway_offload_engine::ipc::ControlMsg;

#[test]
fn a_descriptor_survives_the_crossing_and_still_works() {
    let (a, b) = UnixStream::pair().unwrap();

    // A pipe gives us a descriptor whose identity we can prove afterwards.
    let (rx, mut tx) = std::io::pipe().unwrap();

    let mut payload = Vec::new();
    ControlMsg::Attach.encode(&mut payload);
    send_with_fds(&a, &payload, &[rx.as_raw_fd()]).unwrap();
    drop(rx);

    let mut buf = [0u8; 256];
    let mut fds: Vec<OwnedFd> = Vec::new();
    let n = recv_with_fds(&b, &mut buf, &mut fds).unwrap();

    let (msg, used) = ControlMsg::decode(&buf[..n]).unwrap();
    assert_eq!(msg, ControlMsg::Attach);
    assert_eq!(used, n);
    assert_eq!(fds.len(), 1, "exactly one descriptor should cross");

    // Prove it is the same pipe, not merely some descriptor.
    tx.write_all(b"ping").unwrap();
    drop(tx);
    let mut received = String::new();
    let mut got: std::fs::File = fds.pop().unwrap().into();
    std::io::Read::read_to_string(&mut got, &mut received).unwrap();
    assert_eq!(received, "ping", "the descriptor is not the pipe we sent");
}

#[test]
fn two_descriptors_cross_together_in_order() {
    let (a, b) = UnixStream::pair().unwrap();
    let (rx1, mut tx1) = std::io::pipe().unwrap();
    let (rx2, mut tx2) = std::io::pipe().unwrap();

    let mut payload = Vec::new();
    ControlMsg::StatsRequest { session_id: [1; 8] }.encode(&mut payload);
    send_with_fds(&a, &payload, &[rx1.as_raw_fd(), rx2.as_raw_fd()]).unwrap();
    drop(rx1);
    drop(rx2);

    let mut buf = [0u8; 256];
    let mut fds: Vec<OwnedFd> = Vec::new();
    recv_with_fds(&b, &mut buf, &mut fds).unwrap();
    assert_eq!(fds.len(), 2);

    // Order must be preserved: first sent is first received.
    tx1.write_all(b"one").unwrap();
    drop(tx1);
    tx2.write_all(b"two").unwrap();
    drop(tx2);

    let mut s = String::new();
    let mut f: std::fs::File = fds.remove(0).into();
    std::io::Read::read_to_string(&mut f, &mut s).unwrap();
    assert_eq!(s, "one", "descriptor order was not preserved");

    // Both, not just the first: checking one alone would pass even if the
    // receiver had pushed the same descriptor twice.
    let mut s = String::new();
    let mut f: std::fs::File = fds.remove(0).into();
    std::io::Read::read_to_string(&mut f, &mut s).unwrap();
    assert_eq!(s, "two", "the second descriptor is not the second pipe");
}

#[test]
fn a_message_with_no_descriptors_is_fine() {
    let (a, b) = UnixStream::pair().unwrap();
    let mut payload = Vec::new();
    ControlMsg::PushKeys {
        session_id: [3; 8],
        version: 2,
        lightway_version: [1, 3],
        self_key: ExpresslaneKey([5; EXPRESSLANE_KEY_SIZE]),
        peer_key: ExpresslaneKey([6; EXPRESSLANE_KEY_SIZE]),
    }
    .encode(&mut payload);
    send_with_fds(&a, &payload, &[]).unwrap();

    let mut buf = [0u8; 256];
    let mut fds: Vec<OwnedFd> = Vec::new();
    let n = recv_with_fds(&b, &mut buf, &mut fds).unwrap();
    assert!(fds.is_empty());
    let (msg, _) = ControlMsg::decode(&buf[..n]).unwrap();
    assert!(matches!(msg, ControlMsg::PushKeys { .. }));
}
