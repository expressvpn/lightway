//! Proves the inside split by making the kernel transmit a real IP packet out
//! a two-queue TUN and reading it back off the queue the flag chose.
//!
//! The packet path each test drives, end to end:
//!
//! ```text
//!   UdpSocket::send_to(10.9.9.2:2222)         a plain socket, no TUN fd involved
//!     -> ip_route_output       10.9.9.0/24 is on the device, so egress is lwsteerN
//!     -> __dev_queue_xmit -> netdev_core_pick_tx    (real_num_tx_queues == 2)
//!     -> tun_select_queue -> tun_ebpf_select_queue           (tun.c:560, tun.c:543)
//!          lw_steer(skb): reads offload_active[0], bumps inside_counts[q], returns q
//!     -> tun_net_xmit: tfile = tun->tfiles[q % numqueues]         (tun.c:1064)
//!     -> read(2) on that queue's fd yields the bare IPv4 packet     (IFF_NO_PI)
//! ```
//!
//! Note the direction. Writing into a queue fd would prove nothing: that is
//! *ingress*, a packet handed to the stack, and the steering program never
//! runs on it. Only what the stack transmits gets steered, so the traffic has
//! to originate from an ordinary socket routed at the device.
#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::{self, Read as _};
use std::net::{Ipv4Addr, UdpSocket};
use std::process::Command;
use std::time::{Duration, Instant};

use lightway_bpf_steering::InsideSplit;

#[macro_use]
mod common;

/// Long enough that a slow scheduler is not mistaken for a misrouted packet.
const ARRIVE: Duration = Duration::from_millis(500);
/// How long a queue that should be empty is given to prove otherwise.
const IDLE: Duration = Duration::from_millis(50);

const PEER: Ipv4Addr = Ipv4Addr::new(10, 9, 9, 2);
const PORT: u16 = 2222;
/// 20 bytes of IPv4 header, 8 of UDP, one byte of payload.
const PACKET_LEN: usize = 29;

fn run(args: &[&str]) {
    let status = Command::new("ip")
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("ip {args:?}: {e}"));
    assert!(status.success(), "ip {args:?} failed: {status}");
}

/// Silence IPv6 on a device the moment it exists.
///
/// Autoconfiguration puts MLD reports and router solicitations out an
/// interface as soon as anything brings it up - including a network manager
/// that decides to adopt it - and the program steers and counts those like any
/// other egress packet. Every test device gets this, not just the one this
/// file brings up itself.
///
/// Best effort: a kernel built without IPv6 has no such file, and nothing to
/// silence.
fn quiet_ipv6(name: &str) {
    let _ = std::fs::write(
        format!("/proc/sys/net/ipv6/conf/{name}/disable_ipv6"),
        b"1\n",
    );
}

/// Give the device an address, and with it the route that puts the test's
/// datagram on this interface.
fn bring_up(name: &str) {
    quiet_ipv6(name);

    // Up first: fib_add_ifaddr installs the prefix route only for a device
    // that is already IFF_UP.
    run(&["link", "set", name, "up"]);
    run(&["addr", "add", "10.9.9.1/24", "dev", name]);
}

/// Make the kernel transmit one UDP datagram out the TUN, tagged with `tag`.
fn send_out_the_tun(tag: u8) {
    let tx = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).expect("bind sender");
    tx.send_to(&[tag], (PEER, PORT))
        .expect("no route out the tun");
}

/// Read one packet, or `None` if none arrives before the deadline.
///
/// `InsideSplit::create` opens both queues `O_NONBLOCK`, so this polls instead
/// of parking: a packet steered to the wrong queue must fail the test, not
/// hang it.
fn read_packet(queue: &mut File, wait: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now() + wait;
    let mut buf = [0u8; 2048];
    loop {
        match queue.read(&mut buf) {
            Ok(n) if n > 0 => return Some(buf[..n].to_vec()),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("reading a queue: {e}"),
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn drain(queue: &mut File) {
    while read_packet(queue, Duration::ZERO).is_some() {}
}

/// Is this the datagram `send_out_the_tun(tag)` produced?
fn is_tagged_datagram(pkt: &[u8], tag: u8) -> bool {
    pkt.len() == PACKET_LEN
        && pkt[0] >> 4 == 4
        && pkt[9] == 17
        && pkt[16..20] == PEER.octets()
        && u16::from_be_bytes([pkt[22], pkt[23]]) == PORT
        && pkt[28] == tag
}

/// Wait for the datagram tagged `tag`, ignoring anything else on the way.
///
/// A fresh interface is not private: host daemons join mDNS and LLMNR on it
/// the moment it comes up, and the kernel puts IGMPv3 reports out the device
/// for them. Those are steered and counted like any other egress packet, so
/// the test looks for its own rather than assuming it is alone. What no amount
/// of stray traffic can fake is the assertion next to every call of this: the
/// queue that is *not* selected receives nothing at all, because while the
/// flag is held every egress packet belongs to the other one.
fn expect_tagged(queue: &mut File, tag: u8) {
    let deadline = Instant::now() + ARRIVE;
    loop {
        match read_packet(queue, deadline.saturating_duration_since(Instant::now())) {
            Some(p) if is_tagged_datagram(&p, tag) => return,
            Some(p) => eprintln!("ignoring unrelated egress packet: {p:02x?}"),
            None => panic!("queue never delivered the {tag:#04x} datagram"),
        }
    }
}

#[test]
fn the_active_flag_moves_traffic_between_queues() {
    let mut split = skip_unless_privileged!(InsideSplit::create("lwsteer0"));
    bring_up("lwsteer0");

    // Flag clear: the control queue owns the inside path.
    split.set_offload_active(false).unwrap();
    drain(&mut split.control_queue);
    drain(&mut split.engine_queue);
    let before = split.counts().unwrap();
    send_out_the_tun(0xC0);

    expect_tagged(&mut split.control_queue, 0xC0);
    assert!(
        read_packet(&mut split.engine_queue, IDLE).is_none(),
        "engine queue must be idle while offload is inactive"
    );
    let after = split.counts().unwrap();
    assert_eq!(
        after[1], before[1],
        "kernel steered something to the engine queue with the flag clear"
    );
    assert!(
        after[0] > before[0],
        "kernel counted no packet to the control queue"
    );

    // Flag set: the engine queue does, on the strength of one map write.
    split.set_offload_active(true).unwrap();
    drain(&mut split.control_queue);
    drain(&mut split.engine_queue);
    let before = split.counts().unwrap();
    send_out_the_tun(0xE1);

    expect_tagged(&mut split.engine_queue, 0xE1);
    assert!(
        read_packet(&mut split.control_queue, IDLE).is_none(),
        "control queue must see nothing while offload is active"
    );
    let after = split.counts().unwrap();
    assert_eq!(
        after[0], before[0],
        "kernel steered something to the control queue with the flag set"
    );
    assert!(
        after[1] > before[1],
        "kernel counted no packet to the engine queue"
    );
}

#[test]
fn flipping_the_flag_is_the_whole_fallback() {
    let split = skip_unless_privileged!(InsideSplit::create("lwsteer1"));
    quiet_ipv6("lwsteer1");
    split.set_offload_active(true).unwrap();
    split.set_offload_active(false).unwrap();
    split.set_offload_active(true).unwrap();
    // The point is that fallback costs one map write, with no teardown and no
    // reattach - so the only thing worth asserting is that the device stayed
    // quiet throughout: no queue changed hands, nothing was resteered.
    assert_eq!(
        split.counts().unwrap(),
        [0, 0],
        "nothing was sent, so the kernel should have steered nothing"
    );
}

/// A `%d` in the name is filled in by the kernel, so everything after the
/// first `TUNSETIFF` has to use the name that came *back* - `if_nametoindex`
/// on the pattern itself would find nothing, and a second `TUNSETIFF` with the
/// pattern would make a second device rather than a second queue.
#[test]
fn a_pattern_name_resolves_to_the_device_the_kernel_chose() {
    let split = skip_unless_privileged!(InsideSplit::create("lwpat%d"));
    let idx = split.if_index().expect("the pattern was never resolved");

    let mut matching = Vec::new();
    for entry in std::fs::read_dir("/sys/class/net").unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        if name.starts_with("lwpat") {
            matching.push(name);
        }
    }
    assert_eq!(matching.len(), 1, "expected one device, found {matching:?}");

    let sysfs = std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", matching[0])).unwrap();
    assert_eq!(idx, sysfs.trim().parse::<u32>().unwrap());
}

/// Both opens must have joined *one* device. If the second had created a
/// second netdev instead, the steering program would be picking between the
/// queues of a device carrying no traffic.
#[test]
fn the_two_queues_belong_to_one_device() {
    let split = skip_unless_privileged!(InsideSplit::create("lwsteer2"));
    quiet_ipv6("lwsteer2");
    let sysfs = std::fs::read_to_string("/sys/class/net/lwsteer2/ifindex").expect("no such device");
    assert_eq!(
        split.if_index().unwrap(),
        sysfs.trim().parse::<u32>().unwrap()
    );
}
